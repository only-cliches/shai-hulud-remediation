#!/usr/bin/env bash
# Shai Hulud / Keyv supply-chain remediation for macOS and Linux.
# Designed for unattended execution by RMM/EDR agents.

set -u
set -o pipefail

VERSION="2.1.0"
IOC_URL="https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/refs/heads/main/reports/keyv-packages.csv"
MODE="remediate"
IOC_FILE=""
REPORT_DIR=""
CONFIG_BACKUP_DIR=""
CONFIG_BACKUP_MANIFEST=""
CUSTOM_SCOPE=0
ERRORS=0
NODE_MODULES_FOUND=0
NODE_MODULES_REMOVED=0
CACHES_FOUND=0
CACHES_REMOVED=0
CONFIGS_NEEDED=0
CONFIGS_UPDATED=0
PACKAGES_SCANNED=0
FINDINGS=0
IDE_HOOKS_SCANNED=0
IDE_HOOKS_FOUND=0
IDE_HOOKS_REMOVED=0
PERSISTENCE_FOUND=0
PERSISTENCE_REMOVED=0

usage() {
  cat <<'EOF'
Usage: remediate-shai-hulud.sh [options]

Runs remediation without prompting. Remediation is the default mode.

Options:
  --audit-only          Scan and report without changing the endpoint
  --ioc-file PATH       Use a pre-staged IOC CSV instead of downloading it
  --report-dir PATH     Write reports to PATH
  --scan-root PATH      Scan only PATH (repeatable); also bounds cache/config work
  --help                Show this help

Exit codes:
   0  Completed; no IOC dependency declarations or operational errors
  10  IOC dependency declarations found, or audit found cleanup work
  20  One or more operational errors occurred
  30  Invalid arguments, unsupported OS, or insufficient privileges
EOF
}

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/shai-hulud.XXXXXX")" || exit 30
ROOTS_FILE="$WORK_DIR/roots.txt"
HOMES_FILE="$WORK_DIR/homes.txt"
PACKAGES_FILE="$WORK_DIR/package-files.bin"
FINDINGS_FILE="$WORK_DIR/findings.csv"
FIND_ERRORS="$WORK_DIR/find-errors.log"
HOOKS_FILE="$WORK_DIR/hooks.bin"
PERSISTENCE_CSV="$WORK_DIR/persistence.csv"
PAYLOAD_REFS_FILE="$WORK_DIR/payload-refs.bin"
HOOK_METADATA="$WORK_DIR/hook-metadata.json"
: > "$ROOTS_FILE"
: > "$HOMES_FILE"
: > "$PACKAGES_FILE"
: > "$FIND_ERRORS"
: > "$HOOKS_FILE"
: > "$PAYLOAD_REFS_FILE"

cleanup() {
  rm -rf -- "$WORK_DIR"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

while [ "$#" -gt 0 ]; do
  case "$1" in
    --audit-only)
      MODE="audit"
      ;;
    --ioc-file)
      [ "$#" -ge 2 ] || { usage >&2; exit 30; }
      IOC_FILE="$2"
      shift
      ;;
    --report-dir)
      [ "$#" -ge 2 ] || { usage >&2; exit 30; }
      REPORT_DIR="$2"
      shift
      ;;
    --scan-root)
      [ "$#" -ge 2 ] || { usage >&2; exit 30; }
      case "$2" in
        /*) ;;
        *) printf 'ERROR: --scan-root must be an absolute path: %s\n' "$2" >&2; exit 30 ;;
      esac
      [ -d "$2" ] || { printf 'ERROR: scan root does not exist: %s\n' "$2" >&2; exit 30; }
      NORMALIZED_ROOT="${2%/}"
      [ -n "$NORMALIZED_ROOT" ] || NORMALIZED_ROOT="/"
      printf '%s\n' "$NORMALIZED_ROOT" >> "$ROOTS_FILE"
      CUSTOM_SCOPE=1
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      printf 'ERROR: unknown option: %s\n' "$1" >&2
      usage >&2
      exit 30
      ;;
  esac
  shift
done

OS_NAME="$(uname -s 2>/dev/null || true)"
case "$OS_NAME" in
  Linux|Darwin) ;;
  *) printf 'ERROR: unsupported operating system: %s\n' "$OS_NAME" >&2; exit 30 ;;
esac

if [ "$CUSTOM_SCOPE" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
  printf 'ERROR: full-disk operation requires root. Use sudo or an elevated RMM agent.\n' >&2
  exit 30
fi

default_report_dir() {
  if [ "$OS_NAME" = "Darwin" ]; then
    local console_user console_home
    console_user="$(stat -f '%Su' /dev/console 2>/dev/null || true)"
    if [ -n "$console_user" ] && [ "$console_user" != "root" ] && [ "$console_user" != "loginwindow" ]; then
      console_home="$(dscl . -read "/Users/$console_user" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
      if [ -n "$console_home" ]; then
        printf '%s/Desktop\n' "$console_home"
        return
      fi
    fi
    printf '/Users/Shared\n'
  else
    printf '%s/Desktop\n' "${HOME:-/root}"
  fi
}

if [ -z "$REPORT_DIR" ]; then
  REPORT_DIR="$(default_report_dir)"
fi
if ! mkdir -p -- "$REPORT_DIR" 2>/dev/null; then
  REPORT_DIR="/var/tmp/Shai-Hulud-Remediation"
  mkdir -p -- "$REPORT_DIR" || { printf 'ERROR: cannot create a report directory.\n' >&2; exit 30; }
fi

RUN_ID="$(date -u '+%Y%m%dT%H%M%SZ')-$$"
REPORT_FILE="$REPORT_DIR/Shai-Hulud-Remediation-$RUN_ID.log"
SUMMARY_FILE="$REPORT_DIR/Shai-Hulud-Remediation-$RUN_ID.json"
FINAL_FINDINGS_FILE="$REPORT_DIR/Shai-Hulud-Dependencies-$RUN_ID.csv"
FINAL_PERSISTENCE_FILE="$REPORT_DIR/Shai-Hulud-Persistence-$RUN_ID.csv"
CONFIG_BACKUP_DIR="$REPORT_DIR/Shai-Hulud-Config-Backups-$RUN_ID"
CONFIG_BACKUP_MANIFEST="$CONFIG_BACKUP_DIR/manifest.tsv"
mkdir -p -- "$CONFIG_BACKUP_DIR" || { printf 'ERROR: cannot create config backup directory.\n' >&2; exit 30; }
: > "$CONFIG_BACKUP_MANIFEST"
touch "$REPORT_FILE" || { printf 'ERROR: cannot create report: %s\n' "$REPORT_FILE" >&2; exit 30; }
exec > >(tee -a "$REPORT_FILE") 2>&1

log() {
  printf '%s [%s] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$1" "$2"
}

record_error() {
  ERRORS=$((ERRORS + 1))
  log "ERROR" "$1"
}

discover_roots() {
  local candidate
  if [ "$CUSTOM_SCOPE" -eq 1 ]; then
    return
  fi

  # Default scope is intentionally broad across user and common CI workspaces,
  # but avoids scanning installed applications and entire system volumes.
  if [ "$OS_NAME" = "Darwin" ]; then
    for candidate in /Users/* /var/root /Library/Developer /Library/CI /opt/ci /opt/build; do
      [ -d "$candidate" ] && printf '%s\n' "$candidate" >> "$ROOTS_FILE"
    done
  else
    for candidate in /home/* /root /srv /opt/ci /opt/build /var/lib/jenkins /var/lib/gitlab-runner /var/lib/buildkite-agent /var/lib/github-runner; do
      [ -d "$candidate" ] && printf '%s\n' "$candidate" >> "$ROOTS_FILE"
    done
  fi

  [ -s "$ROOTS_FILE" ] || { printf 'ERROR: no default scan roots were discovered; use --scan-root.\n' >&2; exit 30; }
}

discover_homes() {
  [ "$CUSTOM_SCOPE" -eq 0 ] || return
  [ -n "${HOME:-}" ] && printf '%s\n' "$HOME" >> "$HOMES_FILE"
  if [ "$OS_NAME" = "Darwin" ]; then
    [ -d /var/root ] && printf '/var/root\n' >> "$HOMES_FILE"
    for candidate in /Users/*; do
      [ -d "$candidate" ] && printf '%s\n' "$candidate" >> "$HOMES_FILE"
    done
  else
    [ -d /root ] && printf '/root\n' >> "$HOMES_FILE"
    for candidate in /home/*; do
      [ -d "$candidate" ] && printf '%s\n' "$candidate" >> "$HOMES_FILE"
    done
    if [ -r /etc/passwd ]; then
      awk -F: '$3 == 0 || $3 >= 1000 { if ($6 ~ /^\//) print $6 }' /etc/passwd | while IFS= read -r candidate; do
        [ -d "$candidate" ] && printf '%s\n' "$candidate" >> "$HOMES_FILE"
      done
    fi
  fi
}

dedupe_path_file() {
  awk 'NF && !seen[$0]++' "$1" > "$1.tmp" && mv -- "$1.tmp" "$1"
}

remove_directory() {
  local target kind
  target="$1"
  kind="$2"
  [ -d "$target" ] || [ -L "$target" ] || [ -f "$target" ] || return

  if [ "$kind" = "node_modules" ]; then
    NODE_MODULES_FOUND=$((NODE_MODULES_FOUND + 1))
  elif [ "$kind" = "malicious artifact" ]; then
    PERSISTENCE_FOUND=$((PERSISTENCE_FOUND + 1))
  else
    CACHES_FOUND=$((CACHES_FOUND + 1))
  fi

  if [ "$MODE" = "audit" ]; then
    log "AUDIT" "Would remove $kind: $target"
    return
  fi

  if rm -rf -- "$target" && [ ! -e "$target" ] && [ ! -L "$target" ]; then
    if [ "$kind" = "node_modules" ]; then
      NODE_MODULES_REMOVED=$((NODE_MODULES_REMOVED + 1))
    elif [ "$kind" = "malicious artifact" ]; then
      PERSISTENCE_REMOVED=$((PERSISTENCE_REMOVED + 1))
    else
      CACHES_REMOVED=$((CACHES_REMOVED + 1))
    fi
    log "INFO" "Removed $kind: $target"
  else
    record_error "Failed to remove $kind: $target"
  fi
}

scan_node_modules_and_projects() {
  local root target package_file
  while IFS= read -r root; do
    [ -d "$root" ] || { record_error "Scan root is no longer available: $root"; continue; }
    log "INFO" "Scanning filesystem: $root"

    while IFS= read -r -d '' target; do
      [ "${target##*/}" = "node_modules" ] || { record_error "Safety check rejected unexpected deletion target: $target"; continue; }
      remove_directory "$target" "node_modules"
    done < <(find "$root" -xdev \( -type d -o -type l \) -name node_modules -prune -print0 2>> "$FIND_ERRORS")

    while IFS= read -r -d '' package_file; do
      printf '%s\0' "$package_file" >> "$PACKAGES_FILE"
    done < <(find "$root" -xdev -type d -name node_modules -prune -o -type f -name package.json -print0 2>> "$FIND_ERRORS")
  done < "$ROOTS_FILE"
}

clean_known_caches() {
  local user_home cache_path root project_cache
  if [ "$CUSTOM_SCOPE" -eq 0 ]; then
    while IFS= read -r user_home; do
      for cache_path in \
        "$user_home/.npm" \
        "$user_home/.npm-cache" \
        "$user_home/.local/share/pnpm/store" \
        "$user_home/.cache/pnpm" \
        "$user_home/.cache/yarn" \
        "$user_home/.cache/node/corepack" \
        "$user_home/.cache/node-gyp" \
        "$user_home/.bun/install/cache" \
        "$user_home/Library/Caches/npm" \
        "$user_home/Library/Caches/pnpm" \
        "$user_home/Library/Caches/Yarn" \
        "$user_home/Library/Caches/node/corepack" \
        "$user_home/Library/pnpm/store"; do
        remove_directory "$cache_path" "package cache"
      done
    done < "$HOMES_FILE"

    for cache_path in /var/cache/npm /var/cache/pnpm /usr/local/share/.cache/yarn; do
      remove_directory "$cache_path" "package cache"
    done
  fi

}

config_is_compliant() {
  local file match_regex correct_regex casefold
  file="$1"
  match_regex="$2"
  correct_regex="$3"
  casefold="$4"
  [ -f "$file" ] && awk -v match_regex="$match_regex" -v correct_regex="$correct_regex" -v casefold="$casefold" '
    {
      line = $0
      if (casefold == "true") line = tolower(line)
      if (line ~ match_regex) {
        matches++
        if (line !~ correct_regex) incorrect=1
      }
    }
    END { exit !(matches > 0 && !incorrect) }
  ' "$file"
}

backup_config_file() {
  local file encoded backup
  file="$1"
  [ -e "$file" ] || [ -L "$file" ] || return 0
  if [ -L "$file" ]; then
    record_error "Refusing to modify symlinked config: $file"
    return 1
  fi
  encoded="$(printf '%s' "$file" | tr '/:' '__')"
  backup="$CONFIG_BACKUP_DIR/$encoded"
  if cp -p -- "$file" "$backup" 2>/dev/null; then
    printf '%s\t%s\n' "$file" "$backup" >> "$CONFIG_BACKUP_MANIFEST"
    log "INFO" "Backed up config: $file -> $backup"
    return 0
  fi
  record_error "Could not back up config: $file"
  return 1
}

apply_config_metadata() {
  local temporary destination parent reference owner group mode
  temporary="$1"; destination="$2"; parent="$3"
  reference="$parent"
  [ -e "$destination" ] && reference="$destination"
  if [ "$OS_NAME" = "Darwin" ]; then
    owner="$(stat -f '%u' "$reference" 2>/dev/null || true)"
    group="$(stat -f '%g' "$reference" 2>/dev/null || true)"
    if [ -e "$destination" ]; then mode="$(stat -f '%Lp' "$destination" 2>/dev/null || printf 644)"; else mode=644; fi
  else
    owner="$(stat -c '%u' "$reference" 2>/dev/null || true)"
    group="$(stat -c '%g' "$reference" 2>/dev/null || true)"
    if [ -e "$destination" ]; then mode="$(stat -c '%a' "$destination" 2>/dev/null || printf 644)"; else mode=644; fi
  fi
  chmod "$mode" "$temporary" 2>/dev/null || record_error "Could not preserve mode for config: $destination"
  if [ -n "$owner" ] && [ -n "$group" ]; then
    chown "$owner:$group" "$temporary" 2>/dev/null || record_error "Could not preserve ownership for config: $destination"
  fi
}

write_equals_config() {
  local file key value label dir tmp input
  file="$1"; key="$2"; value="$3"; label="$4"
  if config_is_compliant "$file" "^[[:space:]]*$key[[:space:]]*=" "^[[:space:]]*$key[[:space:]]*=[[:space:]]*$value[[:space:]]*(#.*)?$" "true"; then return; fi
  CONFIGS_NEEDED=$((CONFIGS_NEEDED + 1))
  [ "$MODE" = "remediate" ] || { log "AUDIT" "Would enforce $label in $file"; return; }
  [ ! -L "$file" ] || { record_error "Refusing to modify symlinked config: $file"; return; }
  backup_config_file "$file" || { [ -e "$file" ] || return; }
  dir="${file%/*}"; [ "$dir" = "$file" ] && dir="."
  mkdir -p -- "$dir" 2>/dev/null || { record_error "Cannot create config directory: $dir"; return; }
  tmp="$(mktemp "$dir/.shai-hulud-config.XXXXXX")" || { record_error "Cannot create temporary config for $file"; return; }
  input="$file"
  if [ -e "$file" ] && [ ! -r "$file" ]; then rm -f -- "$tmp"; record_error "Cannot read config: $file"; return; fi
  [ -f "$input" ] || input="/dev/null"
  awk -v key="$key" -v value="$value" '
    BEGIN { found=0 }
    tolower($0) ~ "^[[:space:]]*" key "[[:space:]]*=" {
      if (!found) print key "=" value
      found=1
      next
    }
    { print }
    END { if (!found) print key "=" value }
  ' "$input" > "$tmp" || { rm -f -- "$tmp"; record_error "Failed to transform config: $file"; return; }
  apply_config_metadata "$tmp" "$file" "$dir"
  if mv -- "$tmp" "$file"; then
    CONFIGS_UPDATED=$((CONFIGS_UPDATED + 1)); log "INFO" "Enforced $label in $file"
  else
    rm -f -- "$tmp"; record_error "Failed to update config: $file"
  fi
}

write_space_config() {
  local file key value label dir tmp input
  file="$1"; key="$2"; value="$3"; label="$4"
  if config_is_compliant "$file" "^[[:space:]]*$key[[:space:]]+" "^[[:space:]]*$key[[:space:]]+$value[[:space:]]*(#.*)?$" "false"; then return; fi
  CONFIGS_NEEDED=$((CONFIGS_NEEDED + 1))
  [ "$MODE" = "remediate" ] || { log "AUDIT" "Would enforce $label in $file"; return; }
  [ ! -L "$file" ] || { record_error "Refusing to modify symlinked config: $file"; return; }
  backup_config_file "$file" || { [ -e "$file" ] || return; }
  dir="${file%/*}"; [ "$dir" = "$file" ] && dir="."
  mkdir -p -- "$dir" 2>/dev/null || { record_error "Cannot create config directory: $dir"; return; }
  tmp="$(mktemp "$dir/.shai-hulud-config.XXXXXX")" || { record_error "Cannot create temporary config for $file"; return; }
  input="$file"
  if [ -e "$file" ] && [ ! -r "$file" ]; then rm -f -- "$tmp"; record_error "Cannot read config: $file"; return; fi
  [ -f "$input" ] || input="/dev/null"
  awk -v key="$key" -v value="$value" '
    BEGIN { found=0 }
    $0 ~ "^[[:space:]]*" key "[[:space:]]+" {
      if (!found) print key " " value
      found=1
      next
    }
    { print }
    END { if (!found) print key " " value }
  ' "$input" > "$tmp" || { rm -f -- "$tmp"; record_error "Failed to transform config: $file"; return; }
  apply_config_metadata "$tmp" "$file" "$dir"
  if mv -- "$tmp" "$file"; then
    CONFIGS_UPDATED=$((CONFIGS_UPDATED + 1)); log "INFO" "Enforced $label in $file"
  else
    rm -f -- "$tmp"; record_error "Failed to update config: $file"
  fi
}

write_colon_config() {
  local file key value label dir tmp input
  file="$1"; key="$2"; value="$3"; label="$4"
  if config_is_compliant "$file" "^[[:space:]]*$key[[:space:]]*:" "^[[:space:]]*$key[[:space:]]*:[[:space:]]*$value[[:space:]]*(#.*)?$" "false"; then return; fi
  CONFIGS_NEEDED=$((CONFIGS_NEEDED + 1))
  [ "$MODE" = "remediate" ] || { log "AUDIT" "Would enforce $label in $file"; return; }
  [ ! -L "$file" ] || { record_error "Refusing to modify symlinked config: $file"; return; }
  backup_config_file "$file" || { [ -e "$file" ] || return; }
  dir="${file%/*}"; [ "$dir" = "$file" ] && dir="."
  mkdir -p -- "$dir" 2>/dev/null || { record_error "Cannot create config directory: $dir"; return; }
  tmp="$(mktemp "$dir/.shai-hulud-config.XXXXXX")" || { record_error "Cannot create temporary config for $file"; return; }
  input="$file"
  if [ -e "$file" ] && [ ! -r "$file" ]; then rm -f -- "$tmp"; record_error "Cannot read config: $file"; return; fi
  [ -f "$input" ] || input="/dev/null"
  awk -v key="$key" -v value="$value" '
    BEGIN { found=0 }
    $0 ~ "^[[:space:]]*" key "[[:space:]]*:" {
      if (!found) print key ": " value
      found=1
      next
    }
    { print }
    END { if (!found) print key ": " value }
  ' "$input" > "$tmp" || { rm -f -- "$tmp"; record_error "Failed to transform config: $file"; return; }
  apply_config_metadata "$tmp" "$file" "$dir"
  if mv -- "$tmp" "$file"; then
    CONFIGS_UPDATED=$((CONFIGS_UPDATED + 1)); log "INFO" "Enforced $label in $file"
  else
    rm -f -- "$tmp"; record_error "Failed to update config: $file"
  fi
}

write_bun_config() {
  local file dir tmp input
  file="$1"
  if [ -f "$file" ] && awk '
    /^\[install\][[:space:]]*$/ {inside=1; next}
    /^\[/ {inside=0}
    inside && /^[[:space:]]*ignoreScripts[[:space:]]*=/ {
      matches++
      if ($0 !~ /^[[:space:]]*ignoreScripts[[:space:]]*=[[:space:]]*true([[:space:]]*(#.*)?)?$/) incorrect=1
    }
    END {exit !(matches > 0 && !incorrect)}
  ' "$file"; then return; fi
  CONFIGS_NEEDED=$((CONFIGS_NEEDED + 1))
  [ "$MODE" = "remediate" ] || { log "AUDIT" "Would disable Bun lifecycle scripts in $file"; return; }
  [ ! -L "$file" ] || { record_error "Refusing to modify symlinked config: $file"; return; }
  backup_config_file "$file" || { [ -e "$file" ] || return; }
  dir="${file%/*}"; [ "$dir" = "$file" ] && dir="."
  mkdir -p -- "$dir" 2>/dev/null || { record_error "Cannot create config directory: $dir"; return; }
  tmp="$(mktemp "$dir/.shai-hulud-config.XXXXXX")" || { record_error "Cannot create temporary config for $file"; return; }
  input="$file"
  if [ -e "$file" ] && [ ! -r "$file" ]; then rm -f -- "$tmp"; record_error "Cannot read config: $file"; return; fi
  [ -f "$input" ] || input="/dev/null"
  awk '
    BEGIN { inside=0; section=0; found=0 }
    /^\[install\][[:space:]]*$/ { inside=1; section=1; print; next }
    /^\[/ {
      if (inside && !found) { print "ignoreScripts = true"; found=1 }
      inside=0
    }
    inside && /^[[:space:]]*ignoreScripts[[:space:]]*=/ {
      if (!found) print "ignoreScripts = true"
      found=1
      next
    }
    { print }
    END {
      if (inside && !found) print "ignoreScripts = true"
      else if (!section) { print ""; print "[install]"; print "ignoreScripts = true" }
    }
  ' "$input" > "$tmp" || { rm -f -- "$tmp"; record_error "Failed to transform config: $file"; return; }
  apply_config_metadata "$tmp" "$file" "$dir"
  if mv -- "$tmp" "$file"; then
    CONFIGS_UPDATED=$((CONFIGS_UPDATED + 1)); log "INFO" "Disabled Bun lifecycle scripts in $file"
  else
    rm -f -- "$tmp"; record_error "Failed to update config: $file"
  fi
}

secure_config_directory() {
  local directory
  directory="$1"
  write_equals_config "$directory/.npmrc" "ignore-scripts" "true" "npm/pnpm lifecycle-script blocking"
  write_space_config "$directory/.yarnrc" "--install.ignore-scripts" "true" "Yarn Classic lifecycle-script blocking"
  write_colon_config "$directory/.yarnrc.yml" "enableScripts" "false" "Yarn lifecycle-script blocking"
  write_bun_config "$directory/.bunfig.toml"
}

enforce_script_blocking() {
  local user_home
  if [ "$CUSTOM_SCOPE" -eq 0 ]; then
    write_equals_config "/etc/npmrc" "ignore-scripts" "true" "system npm lifecycle-script blocking"
    while IFS= read -r user_home; do
      secure_config_directory "$user_home"
    done < "$HOMES_FILE"
  else
    log "INFO" "Custom scan scope selected; package-manager policy files were not changed"
  fi
}

verify_package_manager_controls() {
  local output
  if command -v npm >/dev/null 2>&1; then
    output="$(npm config get ignore-scripts 2>&1 || true)"
    if [ "$output" = "true" ]; then
      log "INFO" "Verified npm ignore-scripts=true"
    elif [ "$CUSTOM_SCOPE" -eq 1 ]; then
      # Custom scope deliberately leaves system/user policy files untouched,
      # so a non-compliant pre-existing value is informational, not an error.
      log "WARN" "npm ignore-scripts is not set (custom scan scope does not modify policy files); current value: $output"
    else
      record_error "npm ignore-scripts verification returned: $output"
    fi
  fi
  if command -v pnpm >/dev/null 2>&1; then
    output="$(pnpm config get ignore-scripts 2>&1 || true)"
    [ "$output" = "true" ] && log "INFO" "Verified pnpm ignore-scripts=true" || log "WARN" "pnpm ignore-scripts verification returned: $output"
  fi
  if command -v yarn >/dev/null 2>&1; then
    output="$(yarn config get enableScripts 2>&1 || true)"
    case "$output" in false|0) log "INFO" "Verified Yarn lifecycle scripts disabled" ;; *) log "WARN" "Yarn verification returned: $output" ;; esac
  fi
  if command -v bun >/dev/null 2>&1; then
    log "INFO" "Bun detected; user-level bunfig.toml policy was applied where profiles were discovered"
  fi
}

obtain_iocs() {
  local downloaded
  if [ -n "$IOC_FILE" ]; then
    [ -r "$IOC_FILE" ] || { record_error "IOC file is not readable: $IOC_FILE"; IOC_FILE=""; return; }
  else
    downloaded="$WORK_DIR/keyv-packages.csv"
    if command -v curl >/dev/null 2>&1 && curl -fsSL --retry 2 --connect-timeout 10 --max-time 60 "$IOC_URL" -o "$downloaded"; then
      IOC_FILE="$downloaded"
    elif command -v wget >/dev/null 2>&1 && wget -q -T 60 -O "$downloaded" "$IOC_URL"; then
      IOC_FILE="$downloaded"
    else
      record_error "Could not download IOC list; use --ioc-file for offline execution"
      IOC_FILE=""
      return
    fi
  fi

  if ! head -n 1 "$IOC_FILE" 2>/dev/null | tr -d '\r' | grep -q '^Package,Malicious Versions$'; then
    record_error "IOC CSV has an unexpected header: $IOC_FILE"
    IOC_FILE=""
  fi
}

scan_manifests() {
  local scanner scan_metadata
  [ -n "$IOC_FILE" ] || return
  scanner=""
  if [ "${SHAI_HULUD_MANIFEST_PARSER:-auto}" = "node" ] && command -v node >/dev/null 2>&1; then
    scanner="node"
  elif [ "${SHAI_HULUD_MANIFEST_PARSER:-auto}" = "python3" ] && command -v python3 >/dev/null 2>&1; then
    scanner="python3"
  elif [ "${SHAI_HULUD_MANIFEST_PARSER:-auto}" = "auto" ]; then
    command -v python3 >/dev/null 2>&1 && scanner="python3"
    if [ -z "$scanner" ] && command -v node >/dev/null 2>&1; then scanner="node"; fi
  fi
  if [ -z "$scanner" ]; then
    record_error "python3 or node is required for safe package.json parsing on macOS/Linux"
    return
  fi

  scan_metadata="$WORK_DIR/scan-metadata.json"
  if [ "$scanner" = "python3" ]; then
    "$scanner" - "$IOC_FILE" "$PACKAGES_FILE" "$FINDINGS_FILE" "$scan_metadata" <<'PY'
import csv
import json
import os
import sys

ioc_path, package_list_path, output_path, metadata_path = sys.argv[1:]
iocs = {}
with open(ioc_path, newline="", encoding="utf-8-sig") as handle:
    for row in csv.DictReader(handle):
        name = (row.get("Package") or "").strip()
        versions = (row.get("Malicious Versions") or "").strip()
        if name:
            iocs[name] = versions

with open(package_list_path, "rb") as handle:
    paths = [os.fsdecode(item) for item in handle.read().split(b"\0") if item]

sections = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
rows = []
parse_errors = []

def csv_safe(value):
    text = str(value)
    return "'" + text if text.lstrip(" \t\r\n").startswith(("=", "+", "-", "@")) else text

for path in paths:
    try:
        with open(path, encoding="utf-8-sig") as handle:
            manifest = json.load(handle)
        if not isinstance(manifest, dict):
            raise ValueError("manifest is not a JSON object")
    except Exception as exc:
        parse_errors.append((path, str(exc)))
        continue
    for section in sections:
        values = manifest.get(section, {})
        if not isinstance(values, dict):
            continue
        for name, declared in values.items():
            if name in iocs:
                declared_text = str(declared)
                bad_versions = [v.strip() for v in iocs[name].split(",")]
                normalized = declared_text.strip().lstrip("=v")
                confidence = "exact" if normalized in bad_versions else "review-range"
                rows.append(tuple(csv_safe(value) for value in (path, section, name, declared_text, iocs[name], confidence)))

with open(output_path, "w", newline="", encoding="utf-8") as handle:
    writer = csv.writer(handle)
    writer.writerow(("Manifest", "Section", "Package", "Declared", "Malicious Versions", "Match"))
    writer.writerows(rows)

with open(metadata_path, "w", encoding="utf-8") as handle:
    json.dump({"packages_scanned": len(paths), "findings": len(rows), "parse_errors": parse_errors}, handle)
PY
  else
    "$scanner" - "$IOC_FILE" "$PACKAGES_FILE" "$FINDINGS_FILE" "$scan_metadata" <<'JS'
const fs = require('fs');
const [iocPath, packageListPath, outputPath, metadataPath] = process.argv.slice(2);

function parseCsv(text) {
  const rows = [];
  let row = [], field = '', quoted = false;
  for (let i = 0; i < text.length; i += 1) {
    const char = text[i];
    if (quoted) {
      if (char === '"' && text[i + 1] === '"') { field += '"'; i += 1; }
      else if (char === '"') quoted = false;
      else field += char;
    } else if (char === '"') quoted = true;
    else if (char === ',') { row.push(field); field = ''; }
    else if (char === '\n') { row.push(field.replace(/\r$/, '')); rows.push(row); row = []; field = ''; }
    else field += char;
  }
  if (field.length || row.length) { row.push(field.replace(/\r$/, '')); rows.push(row); }
  return rows;
}

function csvField(value) {
  let text = String(value);
  if (/^[\t\r ]*[=+\-@]/.test(text)) text = `'${text}`;
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

const csvRows = parseCsv(fs.readFileSync(iocPath, 'utf8').replace(/^\uFEFF/, ''));
const header = csvRows.shift() || [];
const packageIndex = header.indexOf('Package');
const versionsIndex = header.indexOf('Malicious Versions');
if (packageIndex < 0 || versionsIndex < 0) throw new Error('Unexpected IOC CSV header');
const iocs = new Map();
for (const row of csvRows) {
  const name = (row[packageIndex] || '').trim();
  if (name) iocs.set(name, (row[versionsIndex] || '').trim());
}

const paths = fs.readFileSync(packageListPath).toString('utf8').split('\0').filter(Boolean);
const sections = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'];
const rows = [];
const parseErrors = [];
for (const manifestPath of paths) {
  let manifest;
  try {
    manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8').replace(/^\uFEFF/, ''));
    if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) throw new Error('manifest is not a JSON object');
  }
  catch (error) { parseErrors.push([manifestPath, error.message]); continue; }
  for (const section of sections) {
    const values = manifest[section];
    if (!values || typeof values !== 'object' || Array.isArray(values)) continue;
    for (const [name, declaredValue] of Object.entries(values)) {
      if (!iocs.has(name)) continue;
      const declared = String(declaredValue);
      const malicious = iocs.get(name);
      const badVersions = malicious.split(',').map(value => value.trim());
      const normalized = declared.trim().replace(/^[=v]+/, '');
      const confidence = badVersions.includes(normalized) ? 'exact' : 'review-range';
      rows.push([manifestPath, section, name, declared, malicious, confidence]);
    }
  }
}

const reportRows = [['Manifest', 'Section', 'Package', 'Declared', 'Malicious Versions', 'Match'], ...rows];
fs.writeFileSync(outputPath, reportRows.map(row => row.map(csvField).join(',')).join('\n') + '\n', 'utf8');
fs.writeFileSync(metadataPath, JSON.stringify({packages_scanned: paths.length, findings: rows.length, parse_errors: parseErrors}), 'utf8');
JS
  fi
  if [ "$?" -ne 0 ] || [ ! -s "$scan_metadata" ]; then
    record_error "The package.json scanner failed"
    return
  fi

  if [ "$scanner" = "python3" ]; then
    PACKAGES_SCANNED="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["packages_scanned"])' "$scan_metadata" 2>/dev/null || printf 0)"
    FINDINGS="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["findings"])' "$scan_metadata" 2>/dev/null || printf 0)"
    PARSE_ERRORS="$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["parse_errors"]))' "$scan_metadata" 2>/dev/null || printf 0)"
  else
    PACKAGES_SCANNED="$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1])).packages_scanned)' "$scan_metadata" 2>/dev/null || printf 0)"
    FINDINGS="$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1])).findings)' "$scan_metadata" 2>/dev/null || printf 0)"
    PARSE_ERRORS="$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1])).parse_errors.length)' "$scan_metadata" 2>/dev/null || printf 0)"
  fi
  if [ "$PARSE_ERRORS" -gt 0 ] 2>/dev/null; then
    record_error "$PARSE_ERRORS package.json file(s) could not be parsed"
    if [ "$scanner" = "python3" ]; then
      python3 -c 'import json,sys; [print("  " + p + ": " + e) for p,e in json.load(open(sys.argv[1]))["parse_errors"]]' "$scan_metadata"
    else
      node -e 'for (const [p,e] of JSON.parse(require("fs").readFileSync(process.argv[1])).parse_errors) console.log("  " + p + ": " + e)' "$scan_metadata"
    fi
  fi
}

scan_ide_persistence() {
  local root hook_file payload_file payload_dir parser

  # Find Claude Code and VS Code hook configs plus the worm's stage-2 files.
  # Hook configs are edited surgically (payload-referencing entries only);
  # stage-2 payload files are removed outright.
  while IFS= read -r root; do
    [ -d "$root" ] || { record_error "Persistence scan root is no longer available: $root"; continue; }

    while IFS= read -r -d '' hook_file; do
      printf '%s\0' "$hook_file" >> "$HOOKS_FILE"
    done < <(find "$root" -xdev -type d -name node_modules -prune -o -type f \( -path '*/.claude/settings.json' -o -path '*/.vscode/tasks.json' \) -print0 2>> "$FIND_ERRORS")

    while IFS= read -r -d '' payload_file; do
      remove_directory "$payload_file" "malicious artifact"
    done < <(find "$root" -xdev -type d -name node_modules -prune -o -type f \( -name 'Math_Symbol.js' -o -name 'math_init.js' \) -print0 2>> "$FIND_ERRORS")

    while IFS= read -r -d '' payload_dir; do
      remove_directory "$payload_dir" "malicious artifact"
    done < <(find "$root" -xdev -type d -name 'bun-dl-*' -prune -print0 2>> "$FIND_ERRORS")
  done < "$ROOTS_FILE"

  [ -s "$HOOKS_FILE" ] || return
  LC_ALL=C sort -z -u -o "$HOOKS_FILE" "$HOOKS_FILE" 2>/dev/null || true

  parser=""
  if [ "${SHAI_HULUD_MANIFEST_PARSER:-auto}" = "node" ] && command -v node >/dev/null 2>&1; then
    parser="node"
  elif [ "${SHAI_HULUD_MANIFEST_PARSER:-auto}" = "python3" ] && command -v python3 >/dev/null 2>&1; then
    parser="python3"
  elif [ "${SHAI_HULUD_MANIFEST_PARSER:-auto}" = "auto" ]; then
    command -v python3 >/dev/null 2>&1 && parser="python3"
    if [ -z "$parser" ] && command -v node >/dev/null 2>&1; then parser="node"; fi
  fi
  if [ -z "$parser" ]; then
    record_error "python3 or node is required for IDE persistence scanning on macOS/Linux"
    return
  fi

  if [ "$parser" = "python3" ]; then
    SHAI_HULUD_MODE="$MODE" "$parser" - "$HOOKS_FILE" "$PERSISTENCE_CSV" "$PAYLOAD_REFS_FILE" "$HOOK_METADATA" <<'PY'
import csv
import json
import os
import re
import stat
import sys

hooks_path, output_path, refs_path, metadata_path = sys.argv[1:]
payload = re.compile(r"(setup\.mjs|Math_Symbol(\.js)?|math_init(\.js)?|bun-dl-)", re.IGNORECASE)
remediate = os.environ.get("SHAI_HULUD_MODE", "remediate") == "remediate"

with open(hooks_path, "rb") as handle:
    paths = [os.fsdecode(item) for item in handle.read().split(b"\0") if item]

rows = []
errors = []
hooks_found = 0
hooks_removed = 0
payload_refs = []

def csv_safe(value):
    text = str(value)
    return "'" + text if text.lstrip(" \t\r\n").startswith(("=", "+", "-", "@")) else text

def collect_setup_refs(config_path, command):
    # Resolve setup.mjs files the removed hooks would have executed. The
    # payload sits in the repo root, so look next to the config and one level up.
    index = command.find("setup.mjs")
    if index == -1:
        return
    start = index
    while start > 0 and command[start - 1] not in " \t\r\n\"'`&;|<>()":
        start -= 1
    ref = command[start:index + len("setup.mjs")]
    directory = os.path.dirname(config_path)
    candidates = []
    if ref.startswith("/"):
        candidates.append(ref)
    else:
        candidates.append(os.path.join(directory, os.path.basename(ref)))
        candidates.append(os.path.join(directory, ref))
        candidates.append(os.path.join(os.path.dirname(directory), os.path.basename(ref)))
    for candidate in candidates:
        if os.path.isfile(candidate) and candidate not in payload_refs:
            payload_refs.append(candidate)

def write_json(path, data):
    mode = stat.S_IMODE(os.stat(path).st_mode)
    temp = path + ".shai-hulud.tmp"
    with open(temp, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
        handle.write("\n")
    os.chmod(temp, mode)
    os.replace(temp, path)

for path in paths:
    try:
        if os.path.islink(path):
            path = os.path.realpath(path)
        with open(path, encoding="utf-8-sig") as handle:
            data = json.load(handle)
        if not isinstance(data, dict):
            raise ValueError("not a JSON object")
    except Exception as exc:
        errors.append((path, str(exc)))
        rows.append((path, "error", "", str(exc), "skipped"))
        continue

    file_found = 0
    if path.endswith(".claude/settings.json"):
        hooks = data.get("hooks")
        if isinstance(hooks, dict):
            for event, entries in list(hooks.items()):
                if not isinstance(entries, list):
                    continue
                kept_entries = []
                for entry in entries:
                    if not isinstance(entry, dict) or not isinstance(entry.get("hooks"), list):
                        kept_entries.append(entry)
                        continue
                    kept_hooks = []
                    for hook in entry["hooks"]:
                        command = str(hook.get("command", "")) if isinstance(hook, dict) else ""
                        if payload.search(command):
                            file_found += 1
                            collect_setup_refs(path, command)
                            rows.append((path, "claude-hook", event, command, "removed" if remediate else "would-remove"))
                        else:
                            kept_hooks.append(hook)
                    if kept_hooks:
                        entry["hooks"] = kept_hooks
                        kept_entries.append(entry)
                if kept_entries:
                    hooks[event] = kept_entries
                else:
                    del hooks[event]
            if not hooks:
                del data["hooks"]
    elif path.endswith(".vscode/tasks.json"):
        tasks = data.get("tasks")
        if isinstance(tasks, list):
            kept_tasks = []
            for task in tasks:
                if not isinstance(task, dict):
                    kept_tasks.append(task)
                    continue
                blob = json.dumps(task)
                if payload.search(blob):
                    file_found += 1
                    collect_setup_refs(path, blob)
                    command = str(task.get("command") or " ".join(str(a) for a in (task.get("args") or [])) or task.get("label") or "")
                    run_options = task.get("runOptions")
                    event = str(run_options.get("runOn", "")) if isinstance(run_options, dict) else ""
                    label = str(task.get("label", ""))
                    rows.append((path, "vscode-task", event or label, command, "removed" if remediate else "would-remove"))
                else:
                    kept_tasks.append(task)
            if len(kept_tasks) != len(tasks):
                data["tasks"] = kept_tasks

    if file_found > 0:
        hooks_found += file_found
        if remediate:
            try:
                write_json(path, data)
                hooks_removed += file_found
            except Exception as exc:
                errors.append((path, "rewrite failed: " + str(exc)))
                rows.append((path, "error", "", str(exc), "rewrite-failed"))

with open(output_path, "w", newline="", encoding="utf-8") as handle:
    writer = csv.writer(handle)
    writer.writerow(("File", "Kind", "Event", "Command", "Action"))
    for row in rows:
        writer.writerow(tuple(csv_safe(value) for value in row))

if remediate and payload_refs:
    with open(refs_path, "wb") as handle:
        handle.write(b"\0".join(os.fsencode(item) for item in payload_refs) + b"\0")

with open(metadata_path, "w", encoding="utf-8") as handle:
    json.dump({"hooks_scanned": len(paths), "hooks_found": hooks_found, "hooks_removed": hooks_removed, "errors": errors}, handle)
PY
  else
    SHAI_HULUD_MODE="$MODE" "$parser" - "$HOOKS_FILE" "$PERSISTENCE_CSV" "$PAYLOAD_REFS_FILE" "$HOOK_METADATA" <<'JS'
const fs = require('fs');
const pathMod = require('path');
const [hooksPath, outputPath, refsPath, metadataPath] = process.argv.slice(2);
const remediate = process.env.SHAI_HULUD_MODE !== 'audit';
const payload = /(setup\.mjs|Math_Symbol(\.js)?|math_init(\.js)?|bun-dl-)/i;

const paths = fs.readFileSync(hooksPath).toString('utf8').split('\0').filter(Boolean);
const rows = [];
const errors = [];
const payloadRefs = [];
let hooksFound = 0;
let hooksRemoved = 0;

function csvField(value) {
  let text = String(value);
  if (/^[\t\r ]*[=+\-@]/.test(text)) text = `'${text}`;
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

function collectSetupRefs(configPath, command) {
  const needle = 'setup.mjs';
  const index = command.indexOf(needle);
  if (index === -1) return;
  let start = index;
  while (start > 0 && !/[\s`'"|&;<>()]/.test(command[start - 1])) start -= 1;
  const ref = command.slice(start, index + needle.length);
  const directory = pathMod.dirname(configPath);
  const candidates = [];
  if (ref.startsWith('/')) candidates.push(ref);
  else {
    candidates.push(pathMod.join(directory, pathMod.basename(ref)));
    candidates.push(pathMod.join(directory, ref));
    candidates.push(pathMod.join(pathMod.dirname(directory), pathMod.basename(ref)));
  }
  for (const candidate of candidates) {
    if (payloadRefs.includes(candidate)) continue;
    try { if (fs.statSync(candidate).isFile()) payloadRefs.push(candidate); } catch (error) { /* absent */ }
  }
}

function writeJson(path, data) {
  const mode = fs.statSync(path).mode & 0o7777;
  const temp = path + '.shai-hulud.tmp';
  fs.writeFileSync(temp, JSON.stringify(data, null, 2) + '\n', 'utf8');
  fs.chmodSync(temp, mode);
  fs.renameSync(temp, path);
}

for (const path of paths) {
  let data;
  try {
    const realPath = fs.lstatSync(path).isSymbolicLink() ? fs.realpathSync(path) : path;
    data = JSON.parse(fs.readFileSync(realPath, 'utf8').replace(/^\uFEFF/, ''));
    if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('not a JSON object');
  } catch (error) {
    errors.push([path, error.message]);
    rows.push([path, 'error', '', error.message, 'skipped']);
    continue;
  }

  let fileFound = 0;
  if (path.endsWith('.claude/settings.json')) {
    const hooks = data.hooks;
    if (hooks && typeof hooks === 'object') {
      for (const [event, entries] of Object.entries(hooks)) {
        if (!Array.isArray(entries)) continue;
        const keptEntries = [];
        for (const entry of entries) {
          if (!entry || typeof entry !== 'object' || !Array.isArray(entry.hooks)) { keptEntries.push(entry); continue; }
          const keptHooks = [];
          for (const hook of entry.hooks) {
            const command = hook && typeof hook.command === 'string' ? hook.command : '';
            if (payload.test(command)) {
              fileFound += 1;
              collectSetupRefs(path, command);
              rows.push([path, 'claude-hook', event, command, remediate ? 'removed' : 'would-remove']);
            } else {
              keptHooks.push(hook);
            }
          }
          if (keptHooks.length) { entry.hooks = keptHooks; keptEntries.push(entry); }
        }
        if (keptEntries.length) hooks[event] = keptEntries; else delete hooks[event];
      }
      if (Object.keys(hooks).length === 0) delete data.hooks;
    }
  } else if (path.endsWith('.vscode/tasks.json')) {
    const tasks = data.tasks;
    if (Array.isArray(tasks)) {
      const keptTasks = [];
      for (const task of tasks) {
        if (!task || typeof task !== 'object') { keptTasks.push(task); continue; }
        const blob = JSON.stringify(task);
        if (payload.test(blob)) {
          fileFound += 1;
          collectSetupRefs(path, blob);
          const command = String(task.command || (task.args || []).join(' ') || task.label || '');
          const runOptions = task.runOptions;
          const event = runOptions && typeof runOptions === 'object' ? String(runOptions.runOn || '') : '';
          const label = String(task.label || '');
          rows.push([path, 'vscode-task', event || label, command, remediate ? 'removed' : 'would-remove']);
        } else {
          keptTasks.push(task);
        }
      }
      if (keptTasks.length !== tasks.length) data.tasks = keptTasks;
    }
  }

  if (fileFound > 0) {
    hooksFound += fileFound;
    if (remediate) {
      try {
        writeJson(path, data);
        hooksRemoved += fileFound;
      } catch (error) {
        errors.push([path, 'rewrite failed: ' + error.message]);
        rows.push([path, 'error', '', error.message, 'rewrite-failed']);
      }
    }
  }
}

fs.writeFileSync(outputPath, [['File', 'Kind', 'Event', 'Command', 'Action'], ...rows].map(row => row.map(csvField).join(',')).join('\n') + '\n', 'utf8');
if (remediate && payloadRefs.length) fs.writeFileSync(refsPath, payloadRefs.join('\0') + '\0', 'utf8');
fs.writeFileSync(metadataPath, JSON.stringify({hooks_scanned: paths.length, hooks_found: hooksFound, hooks_removed: hooksRemoved, errors}), 'utf8');
JS
  fi
  if [ "$?" -ne 0 ] || [ ! -s "$HOOK_METADATA" ]; then
    record_error "The IDE persistence scanner failed"
    return
  fi

  if [ "$MODE" = "remediate" ] && [ -s "$PAYLOAD_REFS_FILE" ]; then
    while IFS= read -r -d '' payload_ref; do
      remove_directory "$payload_ref" "malicious artifact"
    done < "$PAYLOAD_REFS_FILE"
  fi

  if [ "$parser" = "python3" ]; then
    IDE_HOOKS_SCANNED="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["hooks_scanned"])' "$HOOK_METADATA" 2>/dev/null || printf 0)"
    IDE_HOOKS_FOUND="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["hooks_found"])' "$HOOK_METADATA" 2>/dev/null || printf 0)"
    IDE_HOOKS_REMOVED="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["hooks_removed"])' "$HOOK_METADATA" 2>/dev/null || printf 0)"
  else
    IDE_HOOKS_SCANNED="$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1])).hooks_scanned)' "$HOOK_METADATA" 2>/dev/null || printf 0)"
    IDE_HOOKS_FOUND="$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1])).hooks_found)' "$HOOK_METADATA" 2>/dev/null || printf 0)"
    IDE_HOOKS_REMOVED="$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1])).hooks_removed)' "$HOOK_METADATA" 2>/dev/null || printf 0)"
  fi
}

discover_roots
discover_homes
dedupe_path_file "$ROOTS_FILE"
dedupe_path_file "$HOMES_FILE"

log "INFO" "Shai Hulud remediation v$VERSION started (mode=$MODE, host=$(hostname 2>/dev/null || printf unknown), os=$OS_NAME)"
log "INFO" "Report: $REPORT_FILE"

scan_node_modules_and_projects
clean_known_caches
enforce_script_blocking
verify_package_manager_controls
scan_ide_persistence
obtain_iocs

scan_manifests

if [ ! -f "$FINDINGS_FILE" ]; then
  printf 'Manifest,Section,Package,Declared,Malicious Versions,Match\n' > "$FINDINGS_FILE"
fi
if cp -- "$FINDINGS_FILE" "$FINAL_FINDINGS_FILE"; then
  log "INFO" "Dependency report: $FINAL_FINDINGS_FILE"
else
  record_error "Could not publish dependency report: $FINAL_FINDINGS_FILE"
fi

if [ -s "$PERSISTENCE_CSV" ]; then
  if cp -- "$PERSISTENCE_CSV" "$FINAL_PERSISTENCE_FILE"; then
    log "INFO" "Persistence report: $FINAL_PERSISTENCE_FILE"
  else
    record_error "Could not publish persistence report: $FINAL_PERSISTENCE_FILE"
  fi
else
  printf 'File,Kind,Event,Command,Action\n' > "$FINAL_PERSISTENCE_FILE"
fi

if [ -s "$FIND_ERRORS" ]; then
  FIND_ERROR_COUNT="$(wc -l < "$FIND_ERRORS" | tr -d ' ')"
  record_error "Filesystem scan reported $FIND_ERROR_COUNT access or traversal error(s)"
  sed 's/^/  /' "$FIND_ERRORS"
fi

AUDIT_WORK=$((NODE_MODULES_FOUND + CACHES_FOUND + CONFIGS_NEEDED + PERSISTENCE_FOUND + IDE_HOOKS_FOUND))
EXIT_CODE=0
STATUS="completed"
if [ "$ERRORS" -gt 0 ]; then
  EXIT_CODE=20
  STATUS="completed_with_errors"
elif [ "$FINDINGS" -gt 0 ] || [ "$PERSISTENCE_FOUND" -gt 0 ] || [ "$IDE_HOOKS_FOUND" -gt 0 ] || { [ "$MODE" = "audit" ] && [ "$AUDIT_WORK" -gt 0 ]; }; then
  EXIT_CODE=10
  STATUS="attention_required"
fi

cat > "$SUMMARY_FILE" <<EOF
{
  "schema_version": 1,
  "tool_version": "$VERSION",
  "run_id": "$RUN_ID",
  "mode": "$MODE",
  "status": "$STATUS",
  "exit_code": $EXIT_CODE,
  "node_modules_found": $NODE_MODULES_FOUND,
  "node_modules_removed": $NODE_MODULES_REMOVED,
  "caches_found": $CACHES_FOUND,
  "caches_removed": $CACHES_REMOVED,
  "configs_needing_change": $CONFIGS_NEEDED,
  "configs_updated": $CONFIGS_UPDATED,
  "package_json_scanned": $PACKAGES_SCANNED,
  "dependency_findings": $FINDINGS,
  "ide_hooks_scanned": $IDE_HOOKS_SCANNED,
  "ide_hooks_found": $IDE_HOOKS_FOUND,
  "ide_hooks_removed": $IDE_HOOKS_REMOVED,
  "persistence_artifacts_found": $PERSISTENCE_FOUND,
  "persistence_artifacts_removed": $PERSISTENCE_REMOVED,
  "operational_errors": $ERRORS
}
EOF

log "SUMMARY" "status=$STATUS exit_code=$EXIT_CODE node_modules_found=$NODE_MODULES_FOUND node_modules_removed=$NODE_MODULES_REMOVED caches_found=$CACHES_FOUND caches_removed=$CACHES_REMOVED configs_needed=$CONFIGS_NEEDED configs_updated=$CONFIGS_UPDATED manifests_scanned=$PACKAGES_SCANNED dependency_findings=$FINDINGS ide_hooks_scanned=$IDE_HOOKS_SCANNED ide_hooks_found=$IDE_HOOKS_FOUND ide_hooks_removed=$IDE_HOOKS_REMOVED persistence_found=$PERSISTENCE_FOUND persistence_removed=$PERSISTENCE_REMOVED errors=$ERRORS"
log "INFO" "Machine-readable summary: $SUMMARY_FILE"
exit "$EXIT_CODE"

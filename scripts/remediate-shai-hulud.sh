#!/usr/bin/env bash
# Shai Hulud / Keyv supply-chain remediation for macOS and Linux.
# Designed for unattended execution by RMM/EDR agents.

set -u
set -o pipefail
umask 077

VERSION="2.1.0"
IOC_URL="https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/refs/heads/main/reports/keyv-packages.csv"
MODE="remediate"
IOC_FILE=""
REPORT_DIR=""
BACKUP_DIR=""
CONFIG_BACKUP_DIR=""
CONFIG_BACKUP_MANIFEST=""
CONFIG_BACKUP_SEQUENCE=0
SYSTEM_NPM_CONFIG=""
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

if [ "$(id -u)" -eq 0 ]; then
  SHAI_RUNTIME_TMP="/tmp"
else
  SHAI_RUNTIME_TMP="${TMPDIR:-/tmp}"
fi

usage() {
  cat <<'EOF'
Usage: remediate-shai-hulud.sh [options]

Runs remediation without prompting. Remediation is the default mode.

Options:
  --audit-only          Scan and report without changing the endpoint
  --ioc-file PATH       Use a pre-staged IOC CSV instead of downloading it
  --report-dir PATH     Write reports to PATH
  --backup-dir PATH     Store restricted configuration backups in PATH
  --scan-root PATH      Scan only PATH (repeatable); bounds cleanup/config work
  --help                Show this help

Exit codes:
   0  Completed; no IOC dependency declarations or operational errors
  10  IOC dependency declarations found, or audit found cleanup work
  20  One or more operational errors occurred
  30  Invalid arguments, unsupported OS, or insufficient privileges
EOF
}

WORK_DIR="$(mktemp -d "$SHAI_RUNTIME_TMP/shai-hulud.XXXXXX")" || exit 30
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
    --backup-dir)
      [ "$#" -ge 2 ] || { usage >&2; exit 30; }
      case "$2" in
        /*) BACKUP_DIR="$2" ;;
        *) printf 'ERROR: --backup-dir must be an absolute path: %s\n' "$2" >&2; exit 30 ;;
      esac
      shift
      ;;
    --scan-root)
      [ "$#" -ge 2 ] || { usage >&2; exit 30; }
      case "$2" in
        /*) ;;
        *) printf 'ERROR: --scan-root must be an absolute path: %s\n' "$2" >&2; exit 30 ;;
      esac
      [ -d "$2" ] || { printf 'ERROR: scan root does not exist: %s\n' "$2" >&2; exit 30; }
      [ ! -L "$2" ] || { printf 'ERROR: scan root must not be a symbolic link: %s\n' "$2" >&2; exit 30; }
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
  printf 'ERROR: default-scope remediation requires root. Use sudo or an elevated RMM agent.\n' >&2
  exit 30
fi

default_report_dir() {
  if [ "$(id -u)" -eq 0 ]; then
    if [ "$OS_NAME" = "Darwin" ]; then
      printf '/Library/Logs/Shai-Hulud-Remediation\n'
    else
      printf '/var/log/Shai-Hulud-Remediation\n'
    fi
  elif [ -n "${HOME:-}" ] && [ -d "$HOME" ] && [ ! -L "$HOME" ]; then
    printf '%s/.local/state/Shai-Hulud-Remediation/Reports\n' "$HOME"
  else
    mktemp -d "$SHAI_RUNTIME_TMP/shai-hulud-reports.XXXXXX"
  fi
}

if [ -z "$REPORT_DIR" ]; then
  REPORT_DIR="$(default_report_dir)"
fi
if ! mkdir -p -- "$REPORT_DIR" 2>/dev/null; then
  REPORT_DIR="$(mktemp -d "$SHAI_RUNTIME_TMP/shai-hulud-reports.XXXXXX")" || { printf 'ERROR: cannot create a report directory.\n' >&2; exit 30; }
fi
[ ! -L "$REPORT_DIR" ] || { printf 'ERROR: report directory must not be a symbolic link: %s\n' "$REPORT_DIR" >&2; exit 30; }

RUN_ID="$(date -u '+%Y%m%dT%H%M%SZ')-$$"
REPORT_FILE="$REPORT_DIR/Shai-Hulud-Remediation-$RUN_ID.log"
SUMMARY_FILE="$REPORT_DIR/Shai-Hulud-Remediation-$RUN_ID.json"
FINAL_FINDINGS_FILE="$REPORT_DIR/Shai-Hulud-Dependencies-$RUN_ID.csv"
FINAL_PERSISTENCE_FILE="$REPORT_DIR/Shai-Hulud-Persistence-$RUN_ID.csv"
if [ -n "$BACKUP_DIR" ]; then
  CONFIG_BACKUP_DIR="$BACKUP_DIR/$RUN_ID"
elif [ "$(id -u)" -eq 0 ]; then
  if [ "$OS_NAME" = "Darwin" ]; then
    CONFIG_BACKUP_DIR="/Library/Application Support/Shai-Hulud-Remediation/Backups/$RUN_ID"
  else
    CONFIG_BACKUP_DIR="/var/lib/Shai-Hulud-Remediation/Backups/$RUN_ID"
  fi
elif [ -n "${HOME:-}" ] && [ -d "$HOME" ] && [ ! -L "$HOME" ]; then
  CONFIG_BACKUP_DIR="$HOME/.local/state/Shai-Hulud-Remediation/Backups/$RUN_ID"
else
  CONFIG_BACKUP_DIR="$SHAI_RUNTIME_TMP/shai-hulud-backups-$RUN_ID"
fi
CONFIG_BACKUP_MANIFEST="$CONFIG_BACKUP_DIR/manifest.tsv"
if [ "$MODE" = "remediate" ]; then
  CONFIG_BACKUP_PARENT="${CONFIG_BACKUP_DIR%/*}"
  mkdir -p -- "$CONFIG_BACKUP_PARENT" || { printf 'ERROR: cannot create config backup parent directory.\n' >&2; exit 30; }
  [ ! -L "$CONFIG_BACKUP_PARENT" ] || { printf 'ERROR: config backup parent must not be a symbolic link: %s\n' "$CONFIG_BACKUP_PARENT" >&2; exit 30; }
  [ ! -e "$CONFIG_BACKUP_DIR" ] || { printf 'ERROR: config backup run directory already exists: %s\n' "$CONFIG_BACKUP_DIR" >&2; exit 30; }
  mkdir -p -m 700 -- "$CONFIG_BACKUP_DIR" || { printf 'ERROR: cannot create restricted config backup directory.\n' >&2; exit 30; }
  chmod 700 "$CONFIG_BACKUP_DIR" || { printf 'ERROR: cannot restrict config backup directory.\n' >&2; exit 30; }
  printf 'Action\tTarget\tBackupOrValue\n' > "$CONFIG_BACKUP_MANIFEST" || { printf 'ERROR: cannot create config backup manifest.\n' >&2; exit 30; }
fi
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
    for candidate in /Users/* /var/root /Library/Developer /Library/CI /opt/ci /opt/build /workspace /workspaces /builds /Volumes/*/workspace /Volumes/*/workspaces /Volumes/*/builds /Volumes/*/agent/_work; do
      [ -d "$candidate" ] && [ ! -L "$candidate" ] && printf '%s\n' "$candidate" >> "$ROOTS_FILE"
    done
  else
    for candidate in /home/* /root /srv /opt/ci /opt/build /var/lib/jenkins /var/lib/gitlab-runner /var/lib/buildkite-agent /var/lib/github-runner /workspace /workspaces /builds /mnt/*/workspace /mnt/*/workspaces /mnt/*/builds /mnt/*/agent/_work; do
      [ -d "$candidate" ] && [ ! -L "$candidate" ] && printf '%s\n' "$candidate" >> "$ROOTS_FILE"
    done
  fi

  # Include non-standard profile locations discovered from the account database.
  while IFS= read -r candidate; do
    [ -d "$candidate" ] && [ ! -L "$candidate" ] && printf '%s\n' "$candidate" >> "$ROOTS_FILE"
  done < "$HOMES_FILE"

  [ -s "$ROOTS_FILE" ] || { printf 'ERROR: no default scan roots were discovered; use --scan-root.\n' >&2; exit 30; }
}

discover_homes() {
  [ "$CUSTOM_SCOPE" -eq 0 ] || return
  [ -n "${HOME:-}" ] && [ -d "$HOME" ] && [ ! -L "$HOME" ] && printf '%s\n' "$HOME" >> "$HOMES_FILE"
  if [ "$OS_NAME" = "Darwin" ]; then
    [ -d /var/root ] && [ ! -L /var/root ] && printf '/var/root\n' >> "$HOMES_FILE"
    for candidate in /Users/*; do
      [ -d "$candidate" ] && [ ! -L "$candidate" ] && printf '%s\n' "$candidate" >> "$HOMES_FILE"
    done
  else
    [ -d /root ] && [ ! -L /root ] && printf '/root\n' >> "$HOMES_FILE"
    for candidate in /home/*; do
      [ -d "$candidate" ] && [ ! -L "$candidate" ] && printf '%s\n' "$candidate" >> "$HOMES_FILE"
    done
    if [ -r /etc/passwd ]; then
      awk -F: '$3 == 0 || $3 >= 1000 { if ($6 ~ /^\//) print $6 }' /etc/passwd | while IFS= read -r candidate; do
        [ -d "$candidate" ] && [ ! -L "$candidate" ] && printf '%s\n' "$candidate" >> "$HOMES_FILE"
      done
    fi
  fi
}

dedupe_path_file() {
  awk 'NF && !seen[$0]++' "$1" > "$1.tmp" && mv -- "$1.tmp" "$1"
}

discover_npm_prefixes() {
  # npm's global config is $PREFIX/etc/npmrc, not /etc/npmrc. A Node only reads
  # /etc/npmrc when its prefix is /usr or /usr/local; Homebrew, fnm, nvm, asdf,
  # volta, n, nodenv, and source builds all live under other prefixes and never
  # see it. Emit every real prefix we can find (identified by a surviving
  # bin/node, which is not itself under node_modules) so the system-wide block
  # also covers Nodes reinstalled into those same prefixes after cleanup.
  local user_home candidate prefix resolved
  {
    for candidate in /usr /usr/local /opt/homebrew /opt/local \
      /opt/homebrew/opt/node@* /usr/local/opt/node@* \
      /usr/local/n/versions/node/*; do
      printf '%s\n' "$candidate"
    done
    if command -v node >/dev/null 2>&1; then
      resolved="$(cd "$(dirname "$(command -v node)")/.." 2>/dev/null && pwd)"
      [ -n "$resolved" ] && printf '%s\n' "$resolved"
    fi
    while IFS= read -r user_home; do
      for candidate in \
        "$user_home"/.nvm/versions/node/* \
        "$user_home"/.local/share/fnm/node-versions/*/installation \
        "$user_home"/.fnm/node-versions/*/installation \
        "$user_home"/.asdf/installs/nodejs/* \
        "$user_home"/.volta/tools/image/node/* \
        "$user_home"/.nodenv/versions/* \
        "$user_home"/n \
        "$user_home"/.n \
        "$user_home"/.local; do
        printf '%s\n' "$candidate"
      done
    done < "$HOMES_FILE"
  } | while IFS= read -r prefix; do
    [ -e "$prefix/bin/node" ] && printf '%s\n' "$prefix"
  done | awk 'NF && !seen[$0]++'
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
  local user_home cache_path
  if [ "$CUSTOM_SCOPE" -eq 0 ]; then
    while IFS= read -r user_home; do
      for cache_path in \
        "$user_home/.npm" \
        "$user_home/.npm-cache" \
        "$user_home/.pnpm-store" \
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

clean_project_caches() {
  local root project_cache
  while IFS= read -r root; do
    while IFS= read -r -d '' project_cache; do
      remove_directory "$project_cache" "project package cache"
    done < <(find "$root" -xdev \( -type d -o -type l \) \( -path '*/.yarn/cache' -o -name .pnpm-store \) -prune -print0 2>> "$FIND_ERRORS")
  done < "$ROOTS_FILE"
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

record_config_rollback() {
  local file backup
  file="$1"
  if [ ! -e "$file" ] && [ ! -L "$file" ]; then
    if printf 'DELETE_FILE\t%s\t-\n' "$file" >> "$CONFIG_BACKUP_MANIFEST"; then
      return 0
    fi
    record_error "Could not record rollback action for new config: $file"
    return 1
  fi
  if [ -L "$file" ]; then
    record_error "Refusing to modify symlinked config: $file"
    return 1
  fi
  CONFIG_BACKUP_SEQUENCE=$((CONFIG_BACKUP_SEQUENCE + 1))
  backup="$CONFIG_BACKUP_DIR/$(printf '%06d.bak' "$CONFIG_BACKUP_SEQUENCE")"
  if cp -p -- "$file" "$backup" 2>/dev/null; then
    if printf 'RESTORE_FILE\t%s\t%s\n' "$file" "$backup" >> "$CONFIG_BACKUP_MANIFEST"; then
      log "INFO" "Backed up config: $file -> $backup"
      return 0
    fi
    rm -f -- "$backup"
    record_error "Could not record backup manifest entry for config: $file"
    return 1
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
  if ! chmod "$mode" "$temporary" 2>/dev/null; then
    record_error "Could not preserve mode for config: $destination"
    return 1
  fi
  if [ -n "$owner" ] && [ -n "$group" ]; then
    if ! chown "$owner:$group" "$temporary" 2>/dev/null; then
      record_error "Could not preserve ownership for config: $destination"
      return 1
    fi
  fi
  return 0
}

write_equals_config() {
  local file key value label dir tmp input
  file="$1"; key="$2"; value="$3"; label="$4"
  if config_is_compliant "$file" "^[[:space:]]*$key[[:space:]]*=" "^[[:space:]]*$key[[:space:]]*=[[:space:]]*$value[[:space:]]*(#.*)?$" "true"; then return; fi
  CONFIGS_NEEDED=$((CONFIGS_NEEDED + 1))
  [ "$MODE" = "remediate" ] || { log "AUDIT" "Would enforce $label in $file"; return; }
  [ ! -L "$file" ] || { record_error "Refusing to modify symlinked config: $file"; return; }
  record_config_rollback "$file" || return
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
  apply_config_metadata "$tmp" "$file" "$dir" || { rm -f -- "$tmp"; return; }
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
  record_config_rollback "$file" || return
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
  apply_config_metadata "$tmp" "$file" "$dir" || { rm -f -- "$tmp"; return; }
  if mv -- "$tmp" "$file"; then
    CONFIGS_UPDATED=$((CONFIGS_UPDATED + 1)); log "INFO" "Enforced $label in $file"
  else
    rm -f -- "$tmp"; record_error "Failed to update config: $file"
  fi
}

write_colon_config() {
  local file key value label dir tmp input
  file="$1"; key="$2"; value="$3"; label="$4"
  if config_is_compliant "$file" "^$key[[:space:]]*:" "^$key[[:space:]]*:[[:space:]]*$value[[:space:]]*(#.*)?$" "false"; then return; fi
  CONFIGS_NEEDED=$((CONFIGS_NEEDED + 1))
  [ "$MODE" = "remediate" ] || { log "AUDIT" "Would enforce $label in $file"; return; }
  [ ! -L "$file" ] || { record_error "Refusing to modify symlinked config: $file"; return; }
  record_config_rollback "$file" || return
  dir="${file%/*}"; [ "$dir" = "$file" ] && dir="."
  mkdir -p -- "$dir" 2>/dev/null || { record_error "Cannot create config directory: $dir"; return; }
  tmp="$(mktemp "$dir/.shai-hulud-config.XXXXXX")" || { record_error "Cannot create temporary config for $file"; return; }
  input="$file"
  if [ -e "$file" ] && [ ! -r "$file" ]; then rm -f -- "$tmp"; record_error "Cannot read config: $file"; return; fi
  [ -f "$input" ] || input="/dev/null"
  awk -v key="$key" -v value="$value" '
    BEGIN { found=0 }
    $0 ~ "^" key "[[:space:]]*:" {
      if (!found) print key ": " value
      found=1
      next
    }
    { print }
    END { if (!found) print key ": " value }
  ' "$input" > "$tmp" || { rm -f -- "$tmp"; record_error "Failed to transform config: $file"; return; }
  apply_config_metadata "$tmp" "$file" "$dir" || { rm -f -- "$tmp"; return; }
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
  record_config_rollback "$file" || return
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
  apply_config_metadata "$tmp" "$file" "$dir" || { rm -f -- "$tmp"; return; }
  if mv -- "$tmp" "$file"; then
    CONFIGS_UPDATED=$((CONFIGS_UPDATED + 1)); log "INFO" "Disabled Bun lifecycle scripts in $file"
  else
    rm -f -- "$tmp"; record_error "Failed to update config: $file"
  fi
}

secure_config_directory() {
  local directory scope
  directory="$1"
  scope="${2:-profile}"
  write_equals_config "$directory/.npmrc" "ignore-scripts" "true" "npm/pnpm lifecycle-script blocking"
  write_space_config "$directory/.yarnrc" "--install.ignore-scripts" "true" "Yarn Classic lifecycle-script blocking"
  write_colon_config "$directory/.yarnrc.yml" "enableScripts" "false" "Yarn lifecycle-script blocking"
  write_bun_config "$directory/.bunfig.toml"
  if [ "$scope" = "project" ] && [ -f "$directory/pnpm-workspace.yaml" ]; then
    write_colon_config "$directory/pnpm-workspace.yaml" "ignoreScripts" "true" "pnpm lifecycle-script blocking"
  fi
}

resolve_npm_global_config() {
  local resolved
  resolved=""
  if command -v npm >/dev/null 2>&1; then
    resolved="$(cd / && npm config get globalconfig --userconfig=/dev/null 2>/dev/null || true)"
  fi
  case "$resolved" in
    /*) printf '%s\n' "$resolved" ;;
    *) printf '/etc/npmrc\n' ;;
  esac
}

enforce_script_blocking() {
  local user_home package_file project_dir prefix
  if [ "$CUSTOM_SCOPE" -eq 0 ]; then
    write_equals_config "$SYSTEM_NPM_CONFIG" "ignore-scripts" "true" "system npm lifecycle-script blocking"
    while IFS= read -r prefix; do
      write_equals_config "$prefix/etc/npmrc" "ignore-scripts" "true" "prefix npm lifecycle-script blocking ($prefix)"
    done < <(discover_npm_prefixes)
    while IFS= read -r user_home; do
      secure_config_directory "$user_home" "profile"
    done < "$HOMES_FILE"
  fi

  while IFS= read -r -d '' package_file; do
    project_dir="${package_file%/*}"
    secure_config_directory "$project_dir" "project"
  done < "$PACKAGES_FILE"
}

verify_config_directory() {
  local directory scope
  directory="$1"
  scope="${2:-profile}"
  config_is_compliant "$directory/.npmrc" "^[[:space:]]*ignore-scripts[[:space:]]*=" "^[[:space:]]*ignore-scripts[[:space:]]*=[[:space:]]*true[[:space:]]*(#.*)?$" "true" || record_error "npm/pnpm policy verification failed: $directory/.npmrc"
  config_is_compliant "$directory/.yarnrc" "^[[:space:]]*--install.ignore-scripts[[:space:]]+" "^[[:space:]]*--install.ignore-scripts[[:space:]]+true[[:space:]]*(#.*)?$" "false" || record_error "Yarn Classic policy verification failed: $directory/.yarnrc"
  config_is_compliant "$directory/.yarnrc.yml" "^enableScripts[[:space:]]*:" "^enableScripts[[:space:]]*:[[:space:]]*false[[:space:]]*(#.*)?$" "false" || record_error "Yarn policy verification failed: $directory/.yarnrc.yml"
  if ! [ -f "$directory/.bunfig.toml" ] || ! awk '
    /^\[install\][[:space:]]*$/ {inside=1; next}
    /^\[/ {inside=0}
    inside && /^[[:space:]]*ignoreScripts[[:space:]]*=[[:space:]]*true([[:space:]]*(#.*)?)?$/ {found=1}
    END {exit !found}
  ' "$directory/.bunfig.toml"; then
    record_error "Bun policy verification failed: $directory/.bunfig.toml"
  fi
  if [ "$scope" = "project" ] && [ -f "$directory/pnpm-workspace.yaml" ]; then
    config_is_compliant "$directory/pnpm-workspace.yaml" "^ignoreScripts[[:space:]]*:" "^ignoreScripts[[:space:]]*:[[:space:]]*true[[:space:]]*(#.*)?$" "false" || record_error "pnpm policy verification failed: $directory/pnpm-workspace.yaml"
  fi
}

verify_package_manager_controls() {
  local user_home package_file project_dir
  [ "$MODE" = "remediate" ] || return
  if [ "$CUSTOM_SCOPE" -eq 0 ]; then
    config_is_compliant "$SYSTEM_NPM_CONFIG" "^[[:space:]]*ignore-scripts[[:space:]]*=" "^[[:space:]]*ignore-scripts[[:space:]]*=[[:space:]]*true[[:space:]]*(#.*)?$" "true" || record_error "System npm policy verification failed: $SYSTEM_NPM_CONFIG"
    while IFS= read -r user_home; do
      verify_config_directory "$user_home" "profile"
    done < "$HOMES_FILE"
  fi
  while IFS= read -r -d '' package_file; do
    project_dir="${package_file%/*}"
    verify_config_directory "$project_dir" "project"
  done < "$PACKAGES_FILE"
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

discover_homes
dedupe_path_file "$HOMES_FILE"
discover_roots
dedupe_path_file "$ROOTS_FILE"
SYSTEM_NPM_CONFIG="$(resolve_npm_global_config)"

log "INFO" "Shai Hulud remediation v$VERSION started (mode=$MODE, host=$(hostname 2>/dev/null || printf unknown), os=$OS_NAME)"
log "INFO" "Report: $REPORT_FILE"
[ "$MODE" = "remediate" ] && log "INFO" "Restricted configuration backups: $CONFIG_BACKUP_DIR"

obtain_iocs
if [ -n "$IOC_FILE" ]; then
  scan_node_modules_and_projects
  clean_known_caches
  clean_project_caches
  enforce_script_blocking
  verify_package_manager_controls
  scan_manifests
else
  log "ERROR" "IOC data is unavailable; no cleanup or configuration changes were attempted"
fi

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

set_final_status() {
  AUDIT_WORK=$((NODE_MODULES_FOUND + CACHES_FOUND + CONFIGS_NEEDED))
  EXIT_CODE=0
  STATUS="completed"
  if [ "$ERRORS" -gt 0 ]; then
    EXIT_CODE=20
    STATUS="completed_with_errors"
  elif [ "$FINDINGS" -gt 0 ] || { [ "$MODE" = "audit" ] && [ "$AUDIT_WORK" -gt 0 ]; }; then
    EXIT_CODE=10
    STATUS="attention_required"
  fi
}

write_summary() {
  local summary_tmp
  summary_tmp="$REPORT_DIR/.Shai-Hulud-Remediation-$RUN_ID.json.tmp"
  if ! cat > "$summary_tmp" <<EOF
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
  then
    rm -f -- "$summary_tmp"
    return 1
  fi
  mv -- "$summary_tmp" "$SUMMARY_FILE"
}

set_final_status
if ! write_summary; then
  record_error "Could not write machine-readable summary: $SUMMARY_FILE"
  set_final_status
fi

log "SUMMARY" "status=$STATUS exit_code=$EXIT_CODE node_modules_found=$NODE_MODULES_FOUND node_modules_removed=$NODE_MODULES_REMOVED caches_found=$CACHES_FOUND caches_removed=$CACHES_REMOVED configs_needed=$CONFIGS_NEEDED configs_updated=$CONFIGS_UPDATED manifests_scanned=$PACKAGES_SCANNED dependency_findings=$FINDINGS ide_hooks_scanned=$IDE_HOOKS_SCANNED ide_hooks_found=$IDE_HOOKS_FOUND ide_hooks_removed=$IDE_HOOKS_REMOVED persistence_found=$PERSISTENCE_FOUND persistence_removed=$PERSISTENCE_REMOVED errors=$ERRORS"
log "INFO" "Machine-readable summary: $SUMMARY_FILE"
exit "$EXIT_CODE"

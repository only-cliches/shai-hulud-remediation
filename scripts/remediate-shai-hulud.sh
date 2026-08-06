#!/usr/bin/env bash
# Shai Hulud / Keyv supply-chain remediation for macOS and Linux.
# Designed for unattended execution by RMM/EDR agents.

set -u
set -o pipefail
umask 077

VERSION="3.1.5"
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
INCLUDE_APPLICATION_DIRS=0
ERRORS=0
FIND_ATTEMPT_SEQUENCE=0
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

Runs evidence-driven remediation without prompting. Remediation is the default mode.

Options:
  --audit-only          Scan and report without changing the endpoint
  --ioc-file PATH       Use a pre-staged IOC CSV instead of downloading it
  --report-dir PATH     Write reports to PATH
  --backup-dir PATH     Store restricted configuration backups in PATH
  --scan-root PATH      Scan only PATH (repeatable); bounds cleanup/config work
  --include-application-dirs
                        Include known application/state directories in scans
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
NODE_MODULE_TARGETS_FILE="$WORK_DIR/node-modules-targets.bin"
REMOVALS_FILE="$WORK_DIR/node-modules-actions.csv"
FIND_ERRORS="$WORK_DIR/find-errors.log"
HOOKS_FILE="$WORK_DIR/hooks.bin"
PERSISTENCE_CSV="$WORK_DIR/persistence.csv"
PAYLOAD_REFS_FILE="$WORK_DIR/payload-refs.bin"
HOOK_METADATA="$WORK_DIR/hook-metadata.json"
HOOK_TRANSFORMS_FILE="$WORK_DIR/hook-transforms.bin"
HOOK_STAGE_DIR="$WORK_DIR/hook-staged"
PERSISTENCE_ARTIFACTS_FILE="$WORK_DIR/persistence-artifacts.bin"
: > "$ROOTS_FILE"
: > "$HOMES_FILE"
: > "$PACKAGES_FILE"
: > "$NODE_MODULE_TARGETS_FILE"
printf 'Node Modules,Action\n' > "$REMOVALS_FILE"
: > "$FIND_ERRORS"
: > "$HOOKS_FILE"
: > "$PAYLOAD_REFS_FILE"
: > "$HOOK_TRANSFORMS_FILE"
: > "$PERSISTENCE_ARTIFACTS_FILE"

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
    --include-application-dirs)
      INCLUDE_APPLICATION_DIRS=1
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

# These directories commonly contain application bundles, managed IDE
# extensions, package-manager caches, or other tool-owned state. They are not
# source workspaces and changing dependency trees inside them can damage an
# installed application. The IDE persistence scanner uses a second list that
# permits only the narrow .claude/settings.json and .vscode/tasks.json checks.
APPLICATION_DIR_FIND_TEST=(
  -name .cache -o -name .config -o -name .local -o -name .npm
  -o -name .pnpm-store -o -name .yarn -o -name .bun -o -name .corepack
  -o -name .nvm -o -name .fnm -o -name .volta -o -name .asdf -o -name .nodenv -o -name .node-gyp
  -o -name .cargo -o -name .gradle -o -name .m2 -o -name .terraform -o -name .tox
  -o -name .venv -o -path '*/pkg/mod'
  -o -name .vscode -o -name .vscode-insiders -o -name .vscode-oss
  -o -name .vscode-server -o -name .vscode-server-insiders
  -o -name .cursor -o -name .cursor-server -o -name .windsurf -o -name .windsurf-server
  -o -name .claude -o -name .codex -o -name .opencode
  -o -name Applications
)
APPLICATION_DIR_EXCEPT_IDE_FIND_TEST=(
  -name .cache -o -name .config -o -name .local -o -name .npm
  -o -name .pnpm-store -o -name .yarn -o -name .bun -o -name .corepack
  -o -name .nvm -o -name .fnm -o -name .volta -o -name .asdf -o -name .nodenv -o -name .node-gyp
  -o -name .cargo -o -name .gradle -o -name .m2 -o -name .terraform -o -name .tox
  -o -name .venv -o -path '*/pkg/mod'
  -o -name .vscode-insiders -o -name .vscode-oss
  -o -name .vscode-server -o -name .vscode-server-insiders
  -o -name .cursor -o -name .cursor-server -o -name .windsurf -o -name .windsurf-server
  -o -name .codex -o -name .opencode
  -o -name Applications
)
# Some platform-owned locations are not useful incident-response scan targets
# and commonly reject traversal even for an elevated process. Keep these
# exclusions in effect when --include-application-dirs is used.
ALWAYS_EXCLUDED_DIR_FIND_TEST=(-name '')
if [ "$OS_NAME" = "Darwin" ]; then
  APPLICATION_DIR_FIND_TEST+=(
    -o -name Library -o -name '*.app'
    -o -path /System -o -path /Library -o -path /Applications
  )
  APPLICATION_DIR_EXCEPT_IDE_FIND_TEST+=(
    -o -name Library -o -name '*.app'
    -o -path /System -o -path /Library -o -path /Applications
  )
  ALWAYS_EXCLUDED_DIR_FIND_TEST+=(
    -o -name .Trash -o -name .Trashes -o -name .Spotlight-V100 -o -name .fseventsd
    -o -name .DocumentRevisions-V100 -o -name .TemporaryItems -o -name .MobileBackups
    -o -path /private/var/db -o -path /private/var/folders -o -path /private/var/protected -o -path /private/var/root
    -o -path /var/db -o -path /var/folders -o -path /var/protected -o -path /var/root
  )
else
  APPLICATION_DIR_FIND_TEST+=(
    -o -name .var -o -name snap
    -o -path /usr -o -path /opt -o -path /snap
    -o -path /var/lib -o -path /var/cache -o -path /var/snap
  )
  APPLICATION_DIR_EXCEPT_IDE_FIND_TEST+=(
    -o -name .var -o -name snap
    -o -path /usr -o -path /opt -o -path /snap
    -o -path /var/lib -o -path /var/cache -o -path /var/snap
  )
fi

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
    printf '%s/.local/state/Shai-Hulud-Remediation\n' "$HOME"
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
FINAL_REMOVALS_FILE="$REPORT_DIR/Shai-Hulud-NodeModules-$RUN_ID.csv"
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

python3_usable() {
  command -v python3 >/dev/null 2>&1 && python3 -c 'import json' >/dev/null 2>&1
}

node_usable() {
  command -v node >/dev/null 2>&1 && node -e 'process.exit(0)' >/dev/null 2>&1
}

run_find_nul() {
  local output attempt_errors attempt
  output="$1"
  shift
  attempt=1
  while [ "$attempt" -le 2 ]; do
    FIND_ATTEMPT_SEQUENCE=$((FIND_ATTEMPT_SEQUENCE + 1))
    attempt_errors="$WORK_DIR/find-attempt-$FIND_ATTEMPT_SEQUENCE.err"
    : > "$output"
    : > "$attempt_errors"
    if find "$@" -print0 > "$output" 2> "$attempt_errors"; then
      if [ ! -s "$attempt_errors" ]; then
        return 0
      fi
      # A few macOS find builds can return success while still reporting a
      # transient EINTR. Retry it just as we do for a non-zero find status.
      if [ "$attempt" -eq 1 ] && ! grep -qvF 'fts_read: Interrupted system call' "$attempt_errors"; then
        attempt=2
        continue
      fi
      cat "$attempt_errors" >> "$FIND_ERRORS"
      return 0
    fi
    # macOS find can report a transient EINTR while a nearby cache or
    # application tree changes. Retry that specific condition once; retain
    # all other traversal errors for the final operational-error report.
    if [ "$attempt" -eq 1 ] && ! grep -qvF 'fts_read: Interrupted system call' "$attempt_errors"; then
      attempt=2
      continue
    fi
    cat "$attempt_errors" >> "$FIND_ERRORS"
    return 1
  done
  return 1
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
  [ -n "${HOME:-}" ] && [ "$HOME" != "/" ] && [ -d "$HOME" ] && [ ! -L "$HOME" ] && printf '%s\n' "$HOME" >> "$HOMES_FILE"
  if [ "$OS_NAME" = "Darwin" ]; then
    [ -d /var/root ] && [ ! -L /var/root ] && printf '/var/root\n' >> "$HOMES_FILE"
    for candidate in /Users/*; do
      [ "$candidate" != "/" ] && [ -d "$candidate" ] && [ ! -L "$candidate" ] && printf '%s\n' "$candidate" >> "$HOMES_FILE"
    done
  else
    [ -d /root ] && [ ! -L /root ] && printf '/root\n' >> "$HOMES_FILE"
    for candidate in /home/*; do
      [ -d "$candidate" ] && [ ! -L "$candidate" ] && printf '%s\n' "$candidate" >> "$HOMES_FILE"
    done
    if [ -r /etc/passwd ]; then
      awk -F: '$3 == 0 || $3 >= 1000 { if ($6 ~ /^\//) print $6 }' /etc/passwd | while IFS= read -r candidate; do
        [ "$candidate" != "/" ] && [ -d "$candidate" ] && [ ! -L "$candidate" ] && printf '%s\n' "$candidate" >> "$HOMES_FILE"
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

append_node_modules_action() {
  local target action target_csv
  target="$1"
  action="$2"
  target_csv="$(printf '%s' "$target" | sed 's/"/""/g')"
  if ! printf '"%s","%s"\n' "$target_csv" "$action" >> "$REMOVALS_FILE"; then
    record_error "Could not append node_modules action to the report: $target"
  fi
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
    if [ "$kind" = "node_modules" ]; then
      append_node_modules_action "$target" "would-remove"
    elif [ "$kind" = "malicious artifact" ]; then
      printf '%s\0%s\0' "$target" "would-remove" >> "$PERSISTENCE_ARTIFACTS_FILE"
    fi
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
    if [ "$kind" = "malicious artifact" ]; then
      printf '%s\0%s\0' "$target" "removed" >> "$PERSISTENCE_ARTIFACTS_FILE"
    elif [ "$kind" = "node_modules" ]; then
      append_node_modules_action "$target" "removed"
    fi
    log "INFO" "Removed $kind: $target"
  else
    if [ "$kind" = "node_modules" ]; then
      append_node_modules_action "$target" "remove-failed"
    elif [ "$kind" = "malicious artifact" ]; then
      printf '%s\0%s\0' "$target" "remove-failed" >> "$PERSISTENCE_ARTIFACTS_FILE"
    fi
    record_error "Failed to remove $kind: $target"
  fi
}

scan_package_manifests() {
  local root package_file find_output
  while IFS= read -r root; do
    [ -d "$root" ] || { record_error "Scan root is no longer available: $root"; continue; }
    log "INFO" "Scanning filesystem: $root"

    find_output="$WORK_DIR/find-$FIND_ATTEMPT_SEQUENCE.bin"
    if [ "$INCLUDE_APPLICATION_DIRS" -eq 1 ]; then
      run_find_nul "$find_output" "$root" -xdev \
        \( -type d \( -name node_modules -o "${ALWAYS_EXCLUDED_DIR_FIND_TEST[@]}" \) -prune \) \
        -o -type f -name package.json || true
    else
      run_find_nul "$find_output" "$root" -xdev \
        \( -type d \( -name node_modules -o "${APPLICATION_DIR_FIND_TEST[@]}" -o "${ALWAYS_EXCLUDED_DIR_FIND_TEST[@]}" \) -prune \) \
        -o -type f -name package.json || true
    fi
    while IFS= read -r -d '' package_file; do
      printf '%s\0' "$package_file" >> "$PACKAGES_FILE"
    done < "$find_output"
  done < "$ROOTS_FILE"
}

remove_targeted_node_modules() {
  local target
  while IFS= read -r -d '' target; do
    [ "${target##*/}" = "node_modules" ] || { record_error "Safety check rejected unexpected deletion target: $target"; continue; }
    remove_directory "$target" "node_modules"
  done < "$NODE_MODULE_TARGETS_FILE"
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
  local root project_cache find_output
  while IFS= read -r root; do
    find_output="$WORK_DIR/find-$FIND_ATTEMPT_SEQUENCE.bin"
    run_find_nul "$find_output" "$root" -xdev \( -type d -o -type l \) \( -path '*/.yarn/cache' -o -name .pnpm-store \) -prune || true
    while IFS= read -r -d '' project_cache; do
      remove_directory "$project_cache" "project package cache"
    done < "$find_output"
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

package_directory() {
  local package_file directory
  package_file="$1"
  directory="${package_file%/*}"
  [ "$directory" = "//" ] && directory="/"
  printf '%s\n' "$directory"
}

prune_missing_package_paths() {
  local package_file existing_packages
  existing_packages="$WORK_DIR/package-files-existing.bin"
  : > "$existing_packages"
  while IFS= read -r -d '' package_file; do
    [ -f "$package_file" ] && printf '%s\0' "$package_file" >> "$existing_packages"
  done < "$PACKAGES_FILE"
  mv -- "$existing_packages" "$PACKAGES_FILE"
}

secure_config_directory() {
  local directory scope
  directory="$1"
  scope="${2:-profile}"
  [ "$directory" != "/" ] || { record_error "Refusing to modify lifecycle policy at filesystem root"; return; }
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
    project_dir="$(package_directory "$package_file")"
    secure_config_directory "$project_dir" "project"
  done < "$PACKAGES_FILE"
}

verify_config_directory() {
  local directory scope
  directory="$1"
  scope="${2:-profile}"
  [ "$directory" != "/" ] || { record_error "Refusing to verify lifecycle policy at filesystem root"; return; }
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
    project_dir="$(package_directory "$package_file")"
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
  prune_missing_package_paths
  scanner=""
  if [ "${SHAI_HULUD_MANIFEST_PARSER:-auto}" = "node" ] && node_usable; then
    scanner="node"
  elif [ "${SHAI_HULUD_MANIFEST_PARSER:-auto}" = "python3" ] && python3_usable; then
    scanner="python3"
  elif [ "${SHAI_HULUD_MANIFEST_PARSER:-auto}" = "auto" ]; then
    python3_usable && scanner="python3"
    if [ -z "$scanner" ] && node_usable; then scanner="node"; fi
  fi
  if [ -z "$scanner" ]; then
    record_error "a working python3 or node executable is required for safe package.json parsing on macOS/Linux"
    return
  fi

  scan_metadata="$WORK_DIR/scan-metadata.json"
  if [ "$scanner" = "python3" ]; then
    "$scanner" - "$IOC_FILE" "$PACKAGES_FILE" "$ROOTS_FILE" "$FINDINGS_FILE" "$NODE_MODULE_TARGETS_FILE" "$scan_metadata" <<'PY'
import csv
import json
import os
import sys

ioc_path, package_list_path, roots_path, output_path, targets_path, metadata_path = sys.argv[1:]
iocs = {}
with open(ioc_path, newline="", encoding="utf-8-sig") as handle:
    for row in csv.DictReader(handle):
        name = (row.get("Package") or "").strip()
        versions = (row.get("Malicious Versions") or "").strip()
        if name:
            iocs[name] = versions

with open(package_list_path, "rb") as handle:
    paths = list(dict.fromkeys(os.fsdecode(item) for item in handle.read().split(b"\0") if item))

with open(roots_path, encoding="utf-8") as handle:
    roots = [os.path.abspath(line.rstrip("\n")) for line in handle if line.rstrip("\n")]

sections = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
rows = []
parse_errors = []
targets = set()

def normalize_jsonc(text):
    output = []
    index = 0
    in_string = False
    escaped = False
    while index < len(text):
        char = text[index]
        if in_string:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            output.append(char)
            index += 1
            continue
        if char == "/" and index + 1 < len(text) and text[index + 1] == "/":
            output.extend((" ", " "))
            index += 2
            while index < len(text) and text[index] not in "\r\n":
                output.append(" ")
                index += 1
            continue
        if char == "/" and index + 1 < len(text) and text[index + 1] == "*":
            output.extend((" ", " "))
            index += 2
            closed = False
            while index < len(text):
                if index + 1 < len(text) and text[index] == "*" and text[index + 1] == "/":
                    output.extend((" ", " "))
                    index += 2
                    closed = True
                    break
                output.append(text[index] if text[index] in "\r\n" else " ")
                index += 1
            if not closed:
                raise ValueError("unterminated block comment")
            continue
        output.append(char)
        index += 1

    comment_free = "".join(output)
    output = []
    index = 0
    in_string = False
    escaped = False
    while index < len(comment_free):
        char = comment_free[index]
        if in_string:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
        elif char == ",":
            lookahead = index + 1
            while lookahead < len(comment_free) and comment_free[lookahead].isspace():
                lookahead += 1
            if lookahead < len(comment_free) and comment_free[lookahead] in "}]":
                output.append(" ")
                index += 1
                continue
        output.append(char)
        index += 1
    return "".join(output)

def parse_scanned_json(text):
    normalized = normalize_jsonc(text)
    return {} if not normalized.strip() else json.loads(normalized)

def csv_safe(value):
    text = str(value)
    return "'" + text if text.lstrip(" \t\r\n").startswith(("=", "+", "-", "@")) else text

def package_components(name):
    parts = name.split("/")
    if name.startswith("@"):
        return parts if len(parts) == 2 and all(part not in ("", ".", "..") for part in parts) else None
    return parts if len(parts) == 1 and parts[0] not in ("", ".", "..") else None

def containing_root(path):
    candidates = []
    absolute = os.path.abspath(path)
    for root in roots:
        try:
            if os.path.commonpath((absolute, root)) == root:
                candidates.append(root)
        except ValueError:
            continue
    return max(candidates, key=len) if candidates else None

def installed_locations(manifest_path, package_name, bad_versions):
    components = package_components(package_name)
    root = containing_root(manifest_path)
    if components is None or root is None:
        return []
    current = os.path.dirname(os.path.abspath(manifest_path))
    locations = []
    while True:
        node_modules = os.path.join(current, "node_modules")
        package_path = os.path.join(node_modules, *components)
        if os.path.lexists(package_path) and (os.path.isdir(node_modules) or os.path.islink(node_modules)):
            installed_version = "unknown"
            try:
                with open(os.path.join(package_path, "package.json"), encoding="utf-8-sig") as handle:
                    installed_manifest = parse_scanned_json(handle.read())
                value = installed_manifest.get("version") if isinstance(installed_manifest, dict) else None
                if value is not None and str(value).strip():
                    installed_version = str(value).strip()
            except Exception:
                pass
            status = "unknown" if installed_version == "unknown" else ("malicious" if installed_version in bad_versions else "not-listed")
            locations.append((node_modules, installed_version, status))
            if status in ("malicious", "unknown"):
                targets.add(node_modules)
        if current == root:
            break
        parent = os.path.dirname(current)
        if parent == current or os.path.commonpath((parent, root)) != root:
            break
        current = parent
    return locations

for path in paths:
    try:
        with open(path, encoding="utf-8-sig") as handle:
            manifest = parse_scanned_json(handle.read())
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
                bad_versions = [v.strip() for v in iocs[name].split(",") if v.strip()]
                normalized = declared_text.strip().lstrip("=v")
                confidence = "exact" if normalized in bad_versions else "review-range"
                locations = installed_locations(path, name, bad_versions)
                modules = " | ".join(item[0] for item in locations)
                versions = " | ".join(item[1] for item in locations)
                installed_status = " | ".join(item[2] for item in locations) if locations else "not-installed"
                rows.append(tuple(csv_safe(value) for value in (path, section, name, declared_text, iocs[name], confidence, modules, versions, installed_status)))

with open(output_path, "w", newline="", encoding="utf-8") as handle:
    writer = csv.writer(handle)
    writer.writerow(("Manifest", "Section", "Package", "Declared", "Malicious Versions", "Match", "Node Modules", "Installed Versions", "Installed Status"))
    writer.writerows(rows)

with open(targets_path, "wb") as handle:
    if targets:
        handle.write(b"\0".join(os.fsencode(item) for item in sorted(targets)) + b"\0")

with open(metadata_path, "w", encoding="utf-8") as handle:
    json.dump({"packages_scanned": len(paths), "findings": len(rows), "parse_errors": parse_errors}, handle)
PY
  else
    "$scanner" - "$IOC_FILE" "$PACKAGES_FILE" "$ROOTS_FILE" "$FINDINGS_FILE" "$NODE_MODULE_TARGETS_FILE" "$scan_metadata" <<'JS'
const fs = require('fs');
const pathMod = require('path');
const [iocPath, packageListPath, rootsPath, outputPath, targetsPath, metadataPath] = process.argv.slice(2);

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

const paths = [...new Set(fs.readFileSync(packageListPath).toString('utf8').split('\0').filter(Boolean))];
const roots = fs.readFileSync(rootsPath, 'utf8').split(/\r?\n/).filter(Boolean).map(root => pathMod.resolve(root));
const sections = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'];
const rows = [];
const parseErrors = [];
const targets = new Set();

function normalizeJsonc(text) {
  const output = [];
  let index = 0;
  let inString = false;
  let escaped = false;
  while (index < text.length) {
    const char = text[index];
    if (inString) {
      output.push(char);
      if (escaped) escaped = false;
      else if (char === '\\') escaped = true;
      else if (char === '"') inString = false;
      index += 1;
      continue;
    }
    if (char === '"') {
      inString = true;
      output.push(char);
      index += 1;
      continue;
    }
    if (char === '/' && text[index + 1] === '/') {
      output.push(' ', ' ');
      index += 2;
      while (index < text.length && text[index] !== '\r' && text[index] !== '\n') { output.push(' '); index += 1; }
      continue;
    }
    if (char === '/' && text[index + 1] === '*') {
      output.push(' ', ' ');
      index += 2;
      let closed = false;
      while (index < text.length) {
        if (text[index] === '*' && text[index + 1] === '/') {
          output.push(' ', ' ');
          index += 2;
          closed = true;
          break;
        }
        output.push(text[index] === '\r' || text[index] === '\n' ? text[index] : ' ');
        index += 1;
      }
      if (!closed) throw new Error('unterminated block comment');
      continue;
    }
    output.push(char);
    index += 1;
  }

  const commentFree = output.join('');
  output.length = 0;
  index = 0;
  inString = false;
  escaped = false;
  while (index < commentFree.length) {
    const char = commentFree[index];
    if (inString) {
      output.push(char);
      if (escaped) escaped = false;
      else if (char === '\\') escaped = true;
      else if (char === '"') inString = false;
      index += 1;
      continue;
    }
    if (char === '"') inString = true;
    if (char === ',') {
      let lookahead = index + 1;
      while (lookahead < commentFree.length && /\s/.test(commentFree[lookahead])) lookahead += 1;
      if (lookahead < commentFree.length && (commentFree[lookahead] === '}' || commentFree[lookahead] === ']')) {
        output.push(' ');
        index += 1;
        continue;
      }
    }
    output.push(char);
    index += 1;
  }
  return output.join('');
}

function parseScannedJson(text) {
  const normalized = normalizeJsonc(text.replace(/^\uFEFF/, ''));
  return normalized.trim() ? JSON.parse(normalized) : {};
}

function packageComponents(name) {
  const parts = name.split('/');
  if (name.startsWith('@')) return parts.length === 2 && parts.every(part => part && part !== '.' && part !== '..') ? parts : null;
  return parts.length === 1 && parts[0] && parts[0] !== '.' && parts[0] !== '..' ? parts : null;
}

function isWithin(candidate, root) {
  const relative = pathMod.relative(root, candidate);
  return relative === '' || (!relative.startsWith('..' + pathMod.sep) && relative !== '..' && !pathMod.isAbsolute(relative));
}

function containingRoot(candidate) {
  const absolute = pathMod.resolve(candidate);
  const candidates = roots.filter(root => isWithin(absolute, root));
  return candidates.sort((left, right) => right.length - left.length)[0] || null;
}

function pathExists(candidate) {
  try { fs.lstatSync(candidate); return true; } catch (error) { return false; }
}

function installedLocations(manifestPath, packageName, badVersions) {
  const components = packageComponents(packageName);
  const root = containingRoot(manifestPath);
  if (!components || !root) return [];
  let current = pathMod.dirname(pathMod.resolve(manifestPath));
  const locations = [];
  while (true) {
    const nodeModules = pathMod.join(current, 'node_modules');
    const packagePath = pathMod.join(nodeModules, ...components);
    if (pathExists(packagePath) && pathExists(nodeModules)) {
      let installedVersion = 'unknown';
      try {
        const installedManifest = parseScannedJson(fs.readFileSync(pathMod.join(packagePath, 'package.json'), 'utf8'));
        if (installedManifest && typeof installedManifest === 'object' && !Array.isArray(installedManifest) && installedManifest.version != null && String(installedManifest.version).trim()) {
          installedVersion = String(installedManifest.version).trim();
        }
      } catch (error) { /* unknown remains conservatively actionable */ }
      const status = installedVersion === 'unknown' ? 'unknown' : (badVersions.includes(installedVersion) ? 'malicious' : 'not-listed');
      locations.push([nodeModules, installedVersion, status]);
      if (status === 'malicious' || status === 'unknown') targets.add(nodeModules);
    }
    if (current === root) break;
    const parent = pathMod.dirname(current);
    if (parent === current || !isWithin(parent, root)) break;
    current = parent;
  }
  return locations;
}

for (const manifestPath of paths) {
  let manifest;
  try {
    manifest = parseScannedJson(fs.readFileSync(manifestPath, 'utf8'));
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
      const badVersions = malicious.split(',').map(value => value.trim()).filter(Boolean);
      const normalized = declared.trim().replace(/^[=v]+/, '');
      const confidence = badVersions.includes(normalized) ? 'exact' : 'review-range';
      const locations = installedLocations(manifestPath, name, badVersions);
      const nodeModules = locations.map(item => item[0]).join(' | ');
      const installedVersions = locations.map(item => item[1]).join(' | ');
      const installedStatus = locations.length ? locations.map(item => item[2]).join(' | ') : 'not-installed';
      rows.push([manifestPath, section, name, declared, malicious, confidence, nodeModules, installedVersions, installedStatus]);
    }
  }
}

const reportRows = [['Manifest', 'Section', 'Package', 'Declared', 'Malicious Versions', 'Match', 'Node Modules', 'Installed Versions', 'Installed Status'], ...rows];
fs.writeFileSync(outputPath, reportRows.map(row => row.map(csvField).join(',')).join('\n') + '\n', 'utf8');
fs.writeFileSync(targetsPath, targets.size ? [...targets].sort().join('\0') + '\0' : '', 'utf8');
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

append_persistence_rows() {
  local rows_file
  rows_file="$1"
  if ! cat -- "$rows_file" >> "$PERSISTENCE_CSV"; then
    record_error "Could not append IDE persistence report rows: $rows_file"
    return 1
  fi
}

append_persistence_artifact_rows() {
  local parser artifact_file artifact_action artifact_file_csv artifact_action_csv
  parser="$1"
  [ -s "$PERSISTENCE_ARTIFACTS_FILE" ] || return
  if [ "$parser" = "python3" ]; then
    if ! python3 - "$PERSISTENCE_ARTIFACTS_FILE" "$PERSISTENCE_CSV" <<'PY'
import csv
import os
import sys

events_path, output_path = sys.argv[1:]
with open(events_path, "rb") as handle:
    values = [os.fsdecode(value) for value in handle.read().split(b"\0") if value]

def csv_safe(value):
    text = str(value)
    return "'" + text if text.lstrip(" \t\r\n").startswith(("=", "+", "-", "@")) else text

with open(output_path, "a", newline="", encoding="utf-8") as handle:
    writer = csv.writer(handle)
    for index in range(0, len(values) - 1, 2):
        writer.writerow(tuple(csv_safe(value) for value in (values[index], "payload", "", "", values[index + 1])))
PY
    then
      record_error "Could not append malicious artifact rows to the persistence report"
    fi
  elif [ "$parser" = "node" ]; then
    if ! node - "$PERSISTENCE_ARTIFACTS_FILE" "$PERSISTENCE_CSV" <<'JS'
const fs = require('fs');
const [eventsPath, outputPath] = process.argv.slice(2);
const values = fs.readFileSync(eventsPath).toString('utf8').split('\0').filter(Boolean);

function csvField(value) {
  let text = String(value);
  if (/^[\t\r ]*[=+\-@]/.test(text)) text = `'${text}`;
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

const rows = [];
for (let index = 0; index + 1 < values.length; index += 2) {
  rows.push([values[index], 'payload', '', '', values[index + 1]].map(csvField).join(','));
}
if (rows.length) fs.appendFileSync(outputPath, rows.join('\n') + '\n', 'utf8');
JS
    then
      record_error "Could not append malicious artifact rows to the persistence report"
    fi
  else
    # Direct payload artifacts can still be reported when neither JSON parser
    # is usable. Keep the rows CSV-safe without invoking the unavailable tool.
    while IFS= read -r -d '' artifact_file && IFS= read -r -d '' artifact_action; do
      artifact_file_csv="$(printf '%s' "$artifact_file" | sed 's/"/""/g')"
      artifact_action_csv="$(printf '%s' "$artifact_action" | sed 's/"/""/g')"
      printf '"%s",payload,,,"%s"\n' "$artifact_file_csv" "$artifact_action_csv" >> "$PERSISTENCE_CSV"
    done < "$PERSISTENCE_ARTIFACTS_FILE"
  fi
}

scan_ide_persistence() {
  local root hook_file payload_file payload_dir payload_ref parser find_output
  local hook_path staged_file removed_rows audit_rows failed_rows hook_count
  local hook_dir hook_tmp hook_error_count

  printf 'File,Kind,Event,Command,Action\n' > "$PERSISTENCE_CSV"
  mkdir -p -m 700 -- "$HOOK_STAGE_DIR" || { record_error "Could not create the private IDE scanner staging directory"; return; }

  parser=""
  if [ "${SHAI_HULUD_MANIFEST_PARSER:-auto}" = "node" ] && node_usable; then
    parser="node"
  elif [ "${SHAI_HULUD_MANIFEST_PARSER:-auto}" = "python3" ] && python3_usable; then
    parser="python3"
  elif [ "${SHAI_HULUD_MANIFEST_PARSER:-auto}" = "auto" ]; then
    python3_usable && parser="python3"
    if [ -z "$parser" ] && node_usable; then parser="node"; fi
  fi
  # Collect IDE configuration files and remove only the incident's known
  # payload basenames. setup.mjs is removed only when referenced by a matched
  # malicious hook or task.
  while IFS= read -r root; do
    [ -d "$root" ] || { record_error "Persistence scan root is no longer available: $root"; continue; }

    find_output="$WORK_DIR/find-$FIND_ATTEMPT_SEQUENCE.bin"
    if [ "$INCLUDE_APPLICATION_DIRS" -eq 1 ]; then
      run_find_nul "$find_output" "$root" -xdev \
        \( -type d \( -name node_modules -o "${ALWAYS_EXCLUDED_DIR_FIND_TEST[@]}" \) -prune \) \
        -o -type f \( -path '*/.claude/settings.json' -o -path '*/.vscode/tasks.json' \) || true
      while IFS= read -r -d '' hook_file; do
        printf '%s\0' "$hook_file" >> "$HOOKS_FILE"
      done < "$find_output"
    else
      # Emit each workspace IDE directory itself, then derive the one config
      # file we inspect. This finds the narrow persistence surface without
      # descending through IDE extension/application state.
      run_find_nul "$find_output" "$root" -xdev \
        \( -type d \( -name node_modules -o "${APPLICATION_DIR_EXCEPT_IDE_FIND_TEST[@]}" -o "${ALWAYS_EXCLUDED_DIR_FIND_TEST[@]}" \) -prune \) \
        -o \( -type d \( -name .claude -o -name .vscode \) -prune \) || true
      while IFS= read -r -d '' hook_file; do
        case "${hook_file##*/}" in
          .claude) hook_file="$hook_file/settings.json" ;;
          .vscode) hook_file="$hook_file/tasks.json" ;;
          *) continue ;;
        esac
        [ -f "$hook_file" ] && [ ! -L "$hook_file" ] && printf '%s\0' "$hook_file" >> "$HOOKS_FILE"
      done < "$find_output"
    fi

    find_output="$WORK_DIR/find-$FIND_ATTEMPT_SEQUENCE.bin"
    if [ "$INCLUDE_APPLICATION_DIRS" -eq 1 ]; then
      run_find_nul "$find_output" "$root" -xdev \
        \( -type d \( -name node_modules -o "${ALWAYS_EXCLUDED_DIR_FIND_TEST[@]}" \) -prune \) \
        -o -type f \( -name 'Math_Symbol.js' -o -name 'math_init.js' \) || true
    else
      run_find_nul "$find_output" "$root" -xdev \
        \( -type d \( -name node_modules -o "${APPLICATION_DIR_FIND_TEST[@]}" -o "${ALWAYS_EXCLUDED_DIR_FIND_TEST[@]}" \) -prune \) \
        -o -type f \( -name 'Math_Symbol.js' -o -name 'math_init.js' \) || true
    fi
    while IFS= read -r -d '' payload_file; do
      remove_directory "$payload_file" "malicious artifact"
    done < "$find_output"

    find_output="$WORK_DIR/find-$FIND_ATTEMPT_SEQUENCE.bin"
    if [ "$INCLUDE_APPLICATION_DIRS" -eq 1 ]; then
      run_find_nul "$find_output" "$root" -xdev \
        \( -type d \( "${ALWAYS_EXCLUDED_DIR_FIND_TEST[@]}" \) -prune \) \
        -o -type d -name 'bun-dl-*' -prune || true
    else
      run_find_nul "$find_output" "$root" -xdev \
        \( -type d \( "${APPLICATION_DIR_FIND_TEST[@]}" -o "${ALWAYS_EXCLUDED_DIR_FIND_TEST[@]}" \) -prune \) \
        -o -type d -name 'bun-dl-*' -prune || true
    fi
    while IFS= read -r -d '' payload_dir; do
      remove_directory "$payload_dir" "malicious artifact"
    done < "$find_output"
  done < "$ROOTS_FILE"

  if [ -z "$parser" ]; then
    record_error "a working python3 or node executable is required for IDE hook/task scanning on macOS/Linux"
    append_persistence_artifact_rows "$parser"
    return
  fi

  if [ ! -s "$HOOKS_FILE" ]; then
    append_persistence_artifact_rows "$parser"
    return
  fi

  if [ "$parser" = "python3" ]; then
    if ! python3 - "$HOOKS_FILE" "$PERSISTENCE_CSV" "$PAYLOAD_REFS_FILE" "$HOOK_METADATA" "$HOOK_TRANSFORMS_FILE" "$HOOK_STAGE_DIR" <<'PY'
import csv
import json
import os
import re
import stat
import sys

hooks_path, output_path, refs_path, metadata_path, transforms_path, stage_dir = sys.argv[1:]
payload = re.compile(r"(setup\.mjs|Math_Symbol(\.js)?|math_init(\.js)?|bun-dl-)", re.IGNORECASE)

with open(hooks_path, "rb") as handle:
    discovered_paths = [os.fsdecode(item) for item in handle.read().split(b"\0") if item]
paths = list(dict.fromkeys(discovered_paths))

errors = []
error_rows = []
payload_refs = []
transforms = []
hooks_found = 0

def csv_safe(value):
    text = str(value)
    return "'" + text if text.lstrip(" \t\r\n").startswith(("=", "+", "-", "@")) else text

def write_rows(path, rows, action):
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        for row in rows:
            writer.writerow(tuple(csv_safe(value) for value in (*row, action)))

def collect_setup_refs(config_path, command):
    lowered = command.lower()
    index = lowered.find("setup.mjs")
    if index == -1:
        return
    start = index
    while start > 0 and command[start - 1] not in " \t\r\n\"'`&;|<>()":
        start -= 1
    ref = command[start:index + len("setup.mjs")]
    directory = os.path.dirname(config_path)
    if os.path.isabs(ref):
        candidates = [ref]
    else:
        candidates = [
            os.path.join(directory, os.path.basename(ref)),
            os.path.join(directory, ref),
            os.path.join(os.path.dirname(directory), os.path.basename(ref)),
        ]
    for candidate in candidates:
        if (os.path.isfile(candidate) or os.path.islink(candidate)) and candidate not in payload_refs:
            payload_refs.append(candidate)

def normalize_jsonc(text):
    """Convert VS Code JSONC to strict JSON without touching string content."""
    output = []
    index = 0
    in_string = False
    escaped = False
    while index < len(text):
        char = text[index]
        if in_string:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            output.append(char)
            index += 1
            continue
        if char == "/" and index + 1 < len(text) and text[index + 1] == "/":
            output.extend((" ", " "))
            index += 2
            while index < len(text) and text[index] not in "\r\n":
                output.append(" ")
                index += 1
            continue
        if char == "/" and index + 1 < len(text) and text[index + 1] == "*":
            output.extend((" ", " "))
            index += 2
            closed = False
            while index < len(text):
                if index + 1 < len(text) and text[index] == "*" and text[index + 1] == "/":
                    output.extend((" ", " "))
                    index += 2
                    closed = True
                    break
                output.append(text[index] if text[index] in "\r\n" else " ")
                index += 1
            if not closed:
                raise ValueError("unterminated block comment")
            continue
        output.append(char)
        index += 1

    comment_free = "".join(output)
    output = []
    index = 0
    in_string = False
    escaped = False
    while index < len(comment_free):
        char = comment_free[index]
        if in_string:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
        elif char == ",":
            lookahead = index + 1
            while lookahead < len(comment_free) and comment_free[lookahead].isspace():
                lookahead += 1
            if lookahead < len(comment_free) and comment_free[lookahead] in "}]":
                output.append(" ")
                index += 1
                continue
        output.append(char)
        index += 1
    return "".join(output)

for config_path in paths:
    try:
        item = os.lstat(config_path)
        if stat.S_ISLNK(item.st_mode) or not stat.S_ISREG(item.st_mode):
            raise ValueError("not a regular, non-symlinked file")
        with open(config_path, encoding="utf-8-sig") as handle:
            config_text = handle.read()
        config_text = normalize_jsonc(config_text)
        data = {} if not config_text.strip() else json.loads(config_text)
        if not isinstance(data, dict):
            raise ValueError("not a JSON object")
    except Exception as exc:
        errors.append((config_path, str(exc)))
        error_rows.append((config_path, "error", "", str(exc), "skipped"))
        continue

    config_rows = []
    if config_path.endswith("/.claude/settings.json"):
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
                            collect_setup_refs(config_path, command)
                            config_rows.append((config_path, "claude-hook", event, command))
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
    elif config_path.endswith("/.vscode/tasks.json"):
        tasks = data.get("tasks")
        if isinstance(tasks, list):
            kept_tasks = []
            for task in tasks:
                if not isinstance(task, dict):
                    kept_tasks.append(task)
                    continue
                blob = json.dumps(task)
                if payload.search(blob):
                    collect_setup_refs(config_path, blob)
                    command = str(task.get("command") or " ".join(str(arg) for arg in (task.get("args") or [])) or task.get("label") or "")
                    run_options = task.get("runOptions")
                    event = str(run_options.get("runOn", "")) if isinstance(run_options, dict) else ""
                    config_rows.append((config_path, "vscode-task", event or str(task.get("label", "")), command))
                else:
                    kept_tasks.append(task)
            if len(kept_tasks) != len(tasks):
                data["tasks"] = kept_tasks

    if not config_rows:
        continue

    hooks_found += len(config_rows)
    index = len(transforms)
    staged = os.path.join(stage_dir, f"{index:06d}.json")
    removed_rows = os.path.join(stage_dir, f"{index:06d}.removed.csv")
    audit_rows = os.path.join(stage_dir, f"{index:06d}.audit.csv")
    failed_rows = os.path.join(stage_dir, f"{index:06d}.failed.csv")
    with open(staged, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
        handle.write("\n")
    write_rows(removed_rows, config_rows, "removed")
    write_rows(audit_rows, config_rows, "would-remove")
    write_rows(failed_rows, config_rows, "rewrite-failed")
    transforms.append((config_path, staged, removed_rows, audit_rows, failed_rows, str(len(config_rows))))

with open(output_path, "w", newline="", encoding="utf-8") as handle:
    writer = csv.writer(handle)
    writer.writerow(("File", "Kind", "Event", "Command", "Action"))
    for row in error_rows:
        writer.writerow(tuple(csv_safe(value) for value in row))

with open(refs_path, "wb") as handle:
    if payload_refs:
        handle.write(b"\0".join(os.fsencode(item) for item in payload_refs) + b"\0")

with open(transforms_path, "wb") as handle:
    flattened = [value for transform in transforms for value in transform]
    if flattened:
        handle.write(b"\0".join(os.fsencode(value) for value in flattened) + b"\0")

with open(metadata_path, "w", encoding="utf-8") as handle:
    json.dump({"hooks_scanned": len(paths), "hooks_found": hooks_found, "errors": errors}, handle)
PY
    then
      record_error "The Python IDE persistence scanner failed"
      append_persistence_artifact_rows "$parser"
      return
    fi
  else
    if ! node - "$HOOKS_FILE" "$PERSISTENCE_CSV" "$PAYLOAD_REFS_FILE" "$HOOK_METADATA" "$HOOK_TRANSFORMS_FILE" "$HOOK_STAGE_DIR" <<'JS'
const fs = require('fs');
const pathMod = require('path');
const [hooksPath, outputPath, refsPath, metadataPath, transformsPath, stageDir] = process.argv.slice(2);
const payload = /(setup\.mjs|Math_Symbol(\.js)?|math_init(\.js)?|bun-dl-)/i;
const paths = [...new Set(fs.readFileSync(hooksPath).toString('utf8').split('\0').filter(Boolean))];
const errors = [];
const errorRows = [];
const payloadRefs = [];
const transforms = [];
let hooksFound = 0;

function csvField(value) {
  let text = String(value);
  if (/^[\t\r ]*[=+\-@]/.test(text)) text = `'${text}`;
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

function writeRows(path, rows, action) {
  const content = rows.map(row => [...row, action].map(csvField).join(',')).join('\n');
  fs.writeFileSync(path, content ? content + '\n' : '', 'utf8');
}

function collectSetupRefs(configPath, command) {
  const needle = 'setup.mjs';
  const index = command.toLowerCase().indexOf(needle);
  if (index === -1) return;
  let start = index;
  while (start > 0 && !/[\s`'"|&;<>()]/.test(command[start - 1])) start -= 1;
  const ref = command.slice(start, index + needle.length);
  const directory = pathMod.dirname(configPath);
  const candidates = pathMod.isAbsolute(ref)
    ? [ref]
    : [pathMod.join(directory, pathMod.basename(ref)), pathMod.join(directory, ref), pathMod.join(pathMod.dirname(directory), pathMod.basename(ref))];
  for (const candidate of candidates) {
    if (payloadRefs.includes(candidate)) continue;
    try {
      const item = fs.lstatSync(candidate);
      if (item.isFile() || item.isSymbolicLink()) payloadRefs.push(candidate);
    } catch (error) { /* absent */ }
  }
}

function normalizeJsonc(text) {
  const output = [];
  let index = 0;
  let inString = false;
  let escaped = false;
  while (index < text.length) {
    const char = text[index];
    if (inString) {
      output.push(char);
      if (escaped) escaped = false;
      else if (char === '\\') escaped = true;
      else if (char === '"') inString = false;
      index += 1;
      continue;
    }
    if (char === '"') {
      inString = true;
      output.push(char);
      index += 1;
      continue;
    }
    if (char === '/' && text[index + 1] === '/') {
      output.push(' ', ' ');
      index += 2;
      while (index < text.length && text[index] !== '\r' && text[index] !== '\n') { output.push(' '); index += 1; }
      continue;
    }
    if (char === '/' && text[index + 1] === '*') {
      output.push(' ', ' ');
      index += 2;
      let closed = false;
      while (index < text.length) {
        if (text[index] === '*' && text[index + 1] === '/') {
          output.push(' ', ' ');
          index += 2;
          closed = true;
          break;
        }
        output.push(text[index] === '\r' || text[index] === '\n' ? text[index] : ' ');
        index += 1;
      }
      if (!closed) throw new Error('unterminated block comment');
      continue;
    }
    output.push(char);
    index += 1;
  }

  const commentFree = output.join('');
  output.length = 0;
  index = 0;
  inString = false;
  escaped = false;
  while (index < commentFree.length) {
    const char = commentFree[index];
    if (inString) {
      output.push(char);
      if (escaped) escaped = false;
      else if (char === '\\') escaped = true;
      else if (char === '"') inString = false;
      index += 1;
      continue;
    }
    if (char === '"') inString = true;
    if (char === ',') {
      let lookahead = index + 1;
      while (lookahead < commentFree.length && /\s/.test(commentFree[lookahead])) lookahead += 1;
      if (lookahead < commentFree.length && (commentFree[lookahead] === '}' || commentFree[lookahead] === ']')) {
        output.push(' ');
        index += 1;
        continue;
      }
    }
    output.push(char);
    index += 1;
  }
  return output.join('');
}

for (const configPath of paths) {
  let data;
  try {
    const item = fs.lstatSync(configPath);
    if (item.isSymbolicLink() || !item.isFile()) throw new Error('not a regular, non-symlinked file');
    let configText = fs.readFileSync(configPath, 'utf8').replace(/^\uFEFF/, '');
    configText = normalizeJsonc(configText);
    data = !configText.trim() ? {} : JSON.parse(configText);
    if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('not a JSON object');
  } catch (error) {
    errors.push([configPath, error.message]);
    errorRows.push([configPath, 'error', '', error.message, 'skipped']);
    continue;
  }

  const configRows = [];
  if (configPath.endsWith('/.claude/settings.json')) {
    const hooks = data.hooks;
    if (hooks && typeof hooks === 'object' && !Array.isArray(hooks)) {
      for (const [event, entries] of Object.entries(hooks)) {
        if (!Array.isArray(entries)) continue;
        const keptEntries = [];
        for (const entry of entries) {
          if (!entry || typeof entry !== 'object' || !Array.isArray(entry.hooks)) { keptEntries.push(entry); continue; }
          const keptHooks = [];
          for (const hook of entry.hooks) {
            const command = hook && typeof hook.command === 'string' ? hook.command : '';
            if (payload.test(command)) {
              collectSetupRefs(configPath, command);
              configRows.push([configPath, 'claude-hook', event, command]);
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
  } else if (configPath.endsWith('/.vscode/tasks.json')) {
    const tasks = data.tasks;
    if (Array.isArray(tasks)) {
      const keptTasks = [];
      for (const task of tasks) {
        if (!task || typeof task !== 'object') { keptTasks.push(task); continue; }
        const blob = JSON.stringify(task);
        if (payload.test(blob)) {
          collectSetupRefs(configPath, blob);
          const command = String(task.command || (task.args || []).join(' ') || task.label || '');
          const runOptions = task.runOptions;
          const event = runOptions && typeof runOptions === 'object' ? String(runOptions.runOn || '') : '';
          configRows.push([configPath, 'vscode-task', event || String(task.label || ''), command]);
        } else {
          keptTasks.push(task);
        }
      }
      if (keptTasks.length !== tasks.length) data.tasks = keptTasks;
    }
  }

  if (!configRows.length) continue;
  hooksFound += configRows.length;
  const index = transforms.length;
  const prefix = pathMod.join(stageDir, String(index).padStart(6, '0'));
  const staged = prefix + '.json';
  const removedRows = prefix + '.removed.csv';
  const auditRows = prefix + '.audit.csv';
  const failedRows = prefix + '.failed.csv';
  fs.writeFileSync(staged, JSON.stringify(data, null, 2) + '\n', 'utf8');
  writeRows(removedRows, configRows, 'removed');
  writeRows(auditRows, configRows, 'would-remove');
  writeRows(failedRows, configRows, 'rewrite-failed');
  transforms.push([configPath, staged, removedRows, auditRows, failedRows, String(configRows.length)]);
}

const header = ['File', 'Kind', 'Event', 'Command', 'Action'];
fs.writeFileSync(outputPath, [header, ...errorRows].map(row => row.map(csvField).join(',')).join('\n') + '\n', 'utf8');
fs.writeFileSync(refsPath, payloadRefs.length ? payloadRefs.join('\0') + '\0' : '', 'utf8');
fs.writeFileSync(transformsPath, transforms.length ? transforms.flat().join('\0') + '\0' : '', 'utf8');
fs.writeFileSync(metadataPath, JSON.stringify({hooks_scanned: paths.length, hooks_found: hooksFound, errors}), 'utf8');
JS
    then
      record_error "The Node.js IDE persistence scanner failed"
      append_persistence_artifact_rows "$parser"
      return
    fi
  fi

  if [ ! -s "$HOOK_METADATA" ]; then
    record_error "The IDE persistence scanner did not produce metadata"
    append_persistence_artifact_rows "$parser"
    return
  fi

  if [ "$parser" = "python3" ]; then
    IDE_HOOKS_SCANNED="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["hooks_scanned"])' "$HOOK_METADATA" 2>/dev/null || printf 0)"
    IDE_HOOKS_FOUND="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["hooks_found"])' "$HOOK_METADATA" 2>/dev/null || printf 0)"
    hook_error_count="$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["errors"]))' "$HOOK_METADATA" 2>/dev/null || printf 0)"
  else
    IDE_HOOKS_SCANNED="$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1])).hooks_scanned)' "$HOOK_METADATA" 2>/dev/null || printf 0)"
    IDE_HOOKS_FOUND="$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1])).hooks_found)' "$HOOK_METADATA" 2>/dev/null || printf 0)"
    hook_error_count="$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1])).errors.length)' "$HOOK_METADATA" 2>/dev/null || printf 0)"
  fi
  if [ "$hook_error_count" -gt 0 ] 2>/dev/null; then
    record_error "$hook_error_count IDE persistence config file(s) could not be safely parsed"
    if [ "$parser" = "python3" ]; then
      python3 -c 'import json,sys; [print("  " + repr(path) + ": " + error) for path,error in json.load(open(sys.argv[1]))["errors"]]' "$HOOK_METADATA"
    else
      node -e 'for (const [path,error] of JSON.parse(require("fs").readFileSync(process.argv[1])).errors) console.log("  " + JSON.stringify(path) + ": " + error)' "$HOOK_METADATA"
    fi
  fi

  while IFS= read -r -d '' hook_path &&
        IFS= read -r -d '' staged_file &&
        IFS= read -r -d '' removed_rows &&
        IFS= read -r -d '' audit_rows &&
        IFS= read -r -d '' failed_rows &&
        IFS= read -r -d '' hook_count; do
    if [ "$MODE" = "audit" ]; then
      append_persistence_rows "$audit_rows"
      continue
    fi
    if [ ! -f "$hook_path" ] || [ -L "$hook_path" ]; then
      record_error "Refusing to rewrite missing, non-regular, or symlinked IDE config: $hook_path"
      append_persistence_rows "$failed_rows"
      continue
    fi
    if ! record_config_rollback "$hook_path"; then
      append_persistence_rows "$failed_rows"
      continue
    fi
    hook_dir="${hook_path%/*}"
    hook_tmp="$(mktemp "$hook_dir/.shai-hulud-persistence.XXXXXX")" || {
      record_error "Cannot create temporary IDE config for $hook_path"
      append_persistence_rows "$failed_rows"
      continue
    }
    if ! cp -- "$staged_file" "$hook_tmp"; then
      rm -f -- "$hook_tmp"
      record_error "Could not stage remediated IDE config: $hook_path"
      append_persistence_rows "$failed_rows"
      continue
    fi
    if ! apply_config_metadata "$hook_tmp" "$hook_path" "$hook_dir"; then
      rm -f -- "$hook_tmp"
      append_persistence_rows "$failed_rows"
      continue
    fi
    if mv -- "$hook_tmp" "$hook_path"; then
      IDE_HOOKS_REMOVED=$((IDE_HOOKS_REMOVED + hook_count))
      append_persistence_rows "$removed_rows"
      log "INFO" "Removed malicious IDE persistence entries from: $hook_path"
    else
      rm -f -- "$hook_tmp"
      record_error "Failed to update IDE config: $hook_path"
      append_persistence_rows "$failed_rows"
    fi
  done < "$HOOK_TRANSFORMS_FILE"

  if [ -s "$PAYLOAD_REFS_FILE" ]; then
    while IFS= read -r -d '' payload_ref; do
      remove_directory "$payload_ref" "malicious artifact"
    done < "$PAYLOAD_REFS_FILE"
  fi
  append_persistence_artifact_rows "$parser"
}

discover_homes
dedupe_path_file "$HOMES_FILE"
discover_roots
dedupe_path_file "$ROOTS_FILE"

log "INFO" "Shai Hulud remediation v$VERSION started (mode=$MODE, host=$(hostname 2>/dev/null || printf unknown), os=$OS_NAME)"
log "INFO" "Report: $REPORT_FILE"
[ "$INCLUDE_APPLICATION_DIRS" -eq 0 ] && log "INFO" "Known application and tool-state directories are excluded from traversal"
[ "$MODE" = "remediate" ] && log "INFO" "Restricted configuration backups: $CONFIG_BACKUP_DIR"

obtain_iocs
if [ -n "$IOC_FILE" ]; then
  scan_package_manifests
  scan_manifests
  remove_targeted_node_modules
  scan_ide_persistence
else
  log "ERROR" "IOC data is unavailable; no cleanup or configuration changes were attempted"
fi

if [ ! -f "$FINDINGS_FILE" ]; then
  printf 'Manifest,Section,Package,Declared,Malicious Versions,Match,Node Modules,Installed Versions,Installed Status\n' > "$FINDINGS_FILE"
fi
if cp -- "$FINDINGS_FILE" "$FINAL_FINDINGS_FILE"; then
  log "INFO" "Dependency report: $FINAL_FINDINGS_FILE"
else
  record_error "Could not publish dependency report: $FINAL_FINDINGS_FILE"
fi

if cp -- "$REMOVALS_FILE" "$FINAL_REMOVALS_FILE"; then
  log "INFO" "Node modules action report: $FINAL_REMOVALS_FILE"
else
  record_error "Could not publish node_modules action report: $FINAL_REMOVALS_FILE"
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
[ -f "$SUMMARY_FILE" ] && log "INFO" "Machine-readable summary: $SUMMARY_FILE"
exit "$EXIT_CODE"

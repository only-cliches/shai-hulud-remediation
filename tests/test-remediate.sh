#!/usr/bin/env bash

set -u
set -o pipefail

TEST_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$TEST_DIR/.." && pwd)"
SCRIPT_PATH="$REPO_DIR/scripts/remediate-shai-hulud.sh"
RUN_DIR="$(mktemp -d "${TMPDIR:-/tmp}/shai-hulud-test.XXXXXX")"
CRASH_DIR=""
trap '[ -n "$CRASH_DIR" ] && rm -rf -- "$CRASH_DIR"; rm -rf -- "$RUN_DIR"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

cp -R "$TEST_DIR/fixtures/project" "$RUN_DIR/project"
chmod 640 "$RUN_DIR/project/.claude/settings.json" "$RUN_DIR/project/.vscode/tasks.json"
mkdir -p "$RUN_DIR/project/node_modules/bad-package" "$RUN_DIR/project/.yarn/cache/archive" "$RUN_DIR/reports"
mkdir -p "$RUN_DIR/linked-node-modules-target" "$RUN_DIR/project/linked"
touch "$RUN_DIR/linked-node-modules-target/keep"
ln -s "$RUN_DIR/linked-node-modules-target" "$RUN_DIR/project/linked/node_modules"

set +e
SHAI_HULUD_MANIFEST_PARSER=node "$SCRIPT_PATH" \
  --scan-root "$RUN_DIR/project" \
  --report-dir "$RUN_DIR/reports" \
  --backup-dir "$RUN_DIR/backups" \
  --ioc-file "$TEST_DIR/fixtures/iocs.csv" >/dev/null
FIRST_EXIT=$?
set -e

[ "$FIRST_EXIT" -eq 10 ]
[ ! -e "$RUN_DIR/project/node_modules" ]
[ ! -L "$RUN_DIR/project/linked/node_modules" ]
[ -f "$RUN_DIR/linked-node-modules-target/keep" ]
[ ! -e "$RUN_DIR/project/.yarn/cache" ]
grep -qx 'ignore-scripts=true' "$RUN_DIR/project/.npmrc"
grep -qx -- '--install.ignore-scripts true' "$RUN_DIR/project/.yarnrc"
grep -qx 'enableScripts: false' "$RUN_DIR/project/.yarnrc.yml"
[ "$(grep -c '^ignoreScripts = true$' "$RUN_DIR/project/.bunfig.toml")" -eq 1 ]
grep -qx 'ignoreScripts: true' "$RUN_DIR/project/pnpm-workspace.yaml"
grep -q ',bad-package,1.2.3,"1.2.3, 1.2.4",exact' "$RUN_DIR"/reports/*Dependencies*.csv
grep -q ",'@bad/scoped,\^4.5.0,4.5.6,review-range" "$RUN_DIR"/reports/*Dependencies*.csv

# IDE persistence: malicious hooks removed, unrelated config preserved,
# payload files (Math_Symbol.js and hook-referenced setup.mjs) deleted.
[ ! -e "$RUN_DIR/project/Math_Symbol.js" ]
[ ! -e "$RUN_DIR/project/setup.mjs" ]
[ -f "$RUN_DIR/project/.claude/settings.json" ]
grep -q '"command": "true"' "$RUN_DIR/project/.claude/settings.json"
! grep -q 'setup.mjs' "$RUN_DIR/project/.claude/settings.json"
[ -f "$RUN_DIR/project/.vscode/tasks.json" ]
grep -q 'pnpm build' "$RUN_DIR/project/.vscode/tasks.json"
! grep -q 'setup.mjs' "$RUN_DIR/project/.vscode/tasks.json"
grep -q ',claude-hook,SessionStart,node setup.mjs,removed' "$RUN_DIR"/reports/*Persistence*.csv
grep -q ',vscode-task,folderOpen,node setup.mjs,removed' "$RUN_DIR"/reports/*Persistence*.csv

FIRST_SUMMARY="$(find "$RUN_DIR/reports" -name '*.json' -type f -print -quit)"
grep -q '"node_modules_removed": 2' "$FIRST_SUMMARY"
grep -q '"caches_removed": 1' "$FIRST_SUMMARY"
grep -q '"configs_updated": 9' "$FIRST_SUMMARY"
grep -q '"package_json_scanned": 2' "$FIRST_SUMMARY"
grep -q '"dependency_findings": 2' "$FIRST_SUMMARY"
grep -q '"ide_hooks_removed": 2' "$FIRST_SUMMARY"
grep -q '"persistence_artifacts_removed": 2' "$FIRST_SUMMARY"
FIRST_MANIFEST="$(find "$RUN_DIR/backups" -name manifest.tsv -type f -print -quit)"
[ -n "$FIRST_MANIFEST" ]
FIRST_BACKUP_DIRECTORY="${FIRST_MANIFEST%/*}"
case "$(uname -s)" in
  Darwin)
    [ "$(stat -f '%Lp' "$FIRST_BACKUP_DIRECTORY")" = "700" ]
    [ "$(stat -f '%Lp' "$RUN_DIR/project/.claude/settings.json")" = "640" ]
    ;;
  *)
    [ "$(stat -c '%a' "$FIRST_BACKUP_DIRECTORY")" = "700" ]
    [ "$(stat -c '%a' "$RUN_DIR/project/.claude/settings.json")" = "640" ]
    ;;
esac
[ "$(grep -c '^RESTORE_FILE' "$FIRST_MANIFEST")" -eq 7 ]
[ "$(grep -c '^DELETE_FILE' "$FIRST_MANIFEST")" -eq 4 ]
[ "$(find "$RUN_DIR/backups" -name '*.bak' -type f | wc -l | tr -d ' ')" -eq 7 ]
NPM_BACKUP="$(awk -F '\t' -v target="$RUN_DIR/project/.npmrc" '$1 == "RESTORE_FILE" && $2 == target {print $3}' "$FIRST_MANIFEST")"
CLAUDE_BACKUP="$(awk -F '\t' -v target="$RUN_DIR/project/.claude/settings.json" '$1 == "RESTORE_FILE" && $2 == target {print $3}' "$FIRST_MANIFEST")"
cmp "$TEST_DIR/fixtures/project/.npmrc" "$NPM_BACKUP"
cmp "$TEST_DIR/fixtures/project/.claude/settings.json" "$CLAUDE_BACKUP"
[ -f "$RUN_DIR/project/subproject/.npmrc" ]
[ -f "$RUN_DIR/project/subproject/.yarnrc" ]
[ -f "$RUN_DIR/project/subproject/.yarnrc.yml" ]
[ -f "$RUN_DIR/project/subproject/.bunfig.toml" ]

# Audit mode must report persistence without mutating it.
mkdir -p "$RUN_DIR/project/node_modules/recreated"
cp "$TEST_DIR/fixtures/project/.claude/settings.json" "$RUN_DIR/project/.claude/settings.json"
cp "$TEST_DIR/fixtures/project/.vscode/tasks.json" "$RUN_DIR/project/.vscode/tasks.json"
touch "$RUN_DIR/project/Math_Symbol.js"
set +e
"$SCRIPT_PATH" \
  --audit-only \
  --scan-root "$RUN_DIR/project" \
  --report-dir "$RUN_DIR/audit-reports" \
  --backup-dir "$RUN_DIR/audit-backups" \
  --ioc-file "$TEST_DIR/fixtures/iocs.csv" >/dev/null
AUDIT_EXIT=$?
set -e

[ "$AUDIT_EXIT" -eq 10 ]
[ -d "$RUN_DIR/project/node_modules/recreated" ]
[ ! -e "$RUN_DIR/audit-backups" ]
[ -e "$RUN_DIR/project/Math_Symbol.js" ]
grep -q 'setup.mjs' "$RUN_DIR/project/.claude/settings.json"
AUDIT_SUMMARY="$(find "$RUN_DIR/audit-reports" -name '*.json' -type f -print -quit)"
grep -q '"mode": "audit"' "$AUDIT_SUMMARY"
grep -q '"node_modules_removed": 0' "$AUDIT_SUMMARY"
grep -q '"dependency_findings": 2' "$AUDIT_SUMMARY"
grep -q ",'@bad/scoped,\^4.5.0,4.5.6,review-range" "$RUN_DIR"/audit-reports/*Dependencies*.csv
grep -q ',claude-hook,SessionStart,node setup.mjs,would-remove' "$RUN_DIR"/audit-reports/*Persistence*.csv
grep -q ',payload,,,would-remove' "$RUN_DIR"/audit-reports/*Persistence*.csv
grep -q '"ide_hooks_found": 2' "$AUDIT_SUMMARY"
grep -q '"ide_hooks_removed": 0' "$AUDIT_SUMMARY"
grep -q '"persistence_artifacts_removed": 0' "$AUDIT_SUMMARY"

# Reintroduce unsafe duplicate policy values. The next remediation must
# normalize them while also removing the persistence recreated for audit.
printf '\nIGNORE-SCRIPTS=false\n' >> "$RUN_DIR/project/.npmrc"
printf '\n--install.ignore-scripts false\n' >> "$RUN_DIR/project/.yarnrc"
printf '\nenableScripts: true\n' >> "$RUN_DIR/project/.yarnrc.yml"
printf '\nignoreScripts = false\n' >> "$RUN_DIR/project/.bunfig.toml"

set +e
"$SCRIPT_PATH" \
  --scan-root "$RUN_DIR/project" \
  --report-dir "$RUN_DIR/second-reports" \
  --backup-dir "$RUN_DIR/second-backups" \
  --ioc-file "$TEST_DIR/fixtures/iocs.csv" >/dev/null
SECOND_EXIT=$?
set -e

[ "$SECOND_EXIT" -eq 10 ]
SECOND_SUMMARY="$(find "$RUN_DIR/second-reports" -name '*.json' -type f -print -quit)"
grep -q '"configs_needing_change": 4' "$SECOND_SUMMARY"
grep -q '"node_modules_removed": 1' "$SECOND_SUMMARY"
grep -q '"caches_removed": 0' "$SECOND_SUMMARY"
grep -q '"ide_hooks_removed": 2' "$SECOND_SUMMARY"
grep -q '"persistence_artifacts_removed": 1' "$SECOND_SUMMARY"
[ "$(grep -Eic '^[[:space:]]*ignore-scripts[[:space:]]*=' "$RUN_DIR/project/.npmrc")" -eq 1 ]
grep -Eqi '^[[:space:]]*ignore-scripts[[:space:]]*=[[:space:]]*true' "$RUN_DIR/project/.npmrc"
[ "$(grep -Ec '^[[:space:]]*--install\.ignore-scripts[[:space:]]+' "$RUN_DIR/project/.yarnrc")" -eq 1 ]
grep -Eq '^[[:space:]]*--install\.ignore-scripts[[:space:]]+true' "$RUN_DIR/project/.yarnrc"
[ "$(grep -Ec '^[[:space:]]*enableScripts[[:space:]]*:' "$RUN_DIR/project/.yarnrc.yml")" -eq 1 ]
grep -Eq '^[[:space:]]*enableScripts[[:space:]]*:[[:space:]]*false' "$RUN_DIR/project/.yarnrc.yml"
[ "$(grep -Ec '^[[:space:]]*ignoreScripts[[:space:]]*=' "$RUN_DIR/project/.bunfig.toml")" -eq 1 ]
grep -Eq '^[[:space:]]*ignoreScripts[[:space:]]*=[[:space:]]*true' "$RUN_DIR/project/.bunfig.toml"

set +e
"$SCRIPT_PATH" \
  --scan-root "$RUN_DIR/project" \
  --report-dir "$RUN_DIR/final-reports" \
  --backup-dir "$RUN_DIR/final-backups" \
  --ioc-file "$TEST_DIR/fixtures/iocs.csv" >/dev/null
FINAL_EXIT=$?
set -e

[ "$FINAL_EXIT" -eq 10 ]
FINAL_SUMMARY="$(find "$RUN_DIR/final-reports" -name '*.json' -type f -print -quit)"
grep -q '"configs_needing_change": 0' "$FINAL_SUMMARY"

# Persistence alone must produce the automation attention exit code.
mkdir -p "$RUN_DIR/persistence-only/.claude"
cp "$TEST_DIR/fixtures/project/.claude/settings.json" "$RUN_DIR/persistence-only/.claude/settings.json"
cp "$TEST_DIR/fixtures/project/setup.mjs" "$RUN_DIR/persistence-only/setup.mjs"
set +e
"$SCRIPT_PATH" \
  --audit-only \
  --scan-root "$RUN_DIR/persistence-only" \
  --report-dir "$RUN_DIR/persistence-only-reports" \
  --ioc-file "$TEST_DIR/fixtures/iocs.csv" >/dev/null
PERSISTENCE_ONLY_EXIT=$?
set -e
[ "$PERSISTENCE_ONLY_EXIT" -eq 10 ]
PERSISTENCE_ONLY_SUMMARY="$(find "$RUN_DIR/persistence-only-reports" -name '*.json' -type f -print -quit)"
grep -q '"dependency_findings": 0' "$PERSISTENCE_ONLY_SUMMARY"
grep -q '"ide_hooks_found": 1' "$PERSISTENCE_ONLY_SUMMARY"
[ -e "$RUN_DIR/persistence-only/setup.mjs" ]

cp -R "$TEST_DIR/fixtures/project" "$RUN_DIR/invalid-ioc-project"
mkdir -p "$RUN_DIR/invalid-ioc-project/node_modules/keep"
set +e
"$SCRIPT_PATH" \
  --scan-root "$RUN_DIR/invalid-ioc-project" \
  --report-dir "$RUN_DIR/invalid-ioc-reports" \
  --backup-dir "$RUN_DIR/invalid-ioc-backups" \
  --ioc-file "$TEST_DIR/fixtures/invalid-iocs.csv" >/dev/null
INVALID_IOC_EXIT=$?
set -e
[ "$INVALID_IOC_EXIT" -eq 20 ]
[ -d "$RUN_DIR/invalid-ioc-project/node_modules/keep" ]
grep -qx 'ignore-scripts=false' "$RUN_DIR/invalid-ioc-project/.npmrc"

ln -s "$RUN_DIR/invalid-ioc-project" "$RUN_DIR/symlink-scan-root"
set +e
"$SCRIPT_PATH" \
  --scan-root "$RUN_DIR/symlink-scan-root" \
  --report-dir "$RUN_DIR/symlink-root-reports" \
  --ioc-file "$TEST_DIR/fixtures/iocs.csv" >/dev/null 2>&1
SYMLINK_ROOT_EXIT=$?
set -e
[ "$SYMLINK_ROOT_EXIT" -eq 30 ]
[ -d "$RUN_DIR/invalid-ioc-project/node_modules/keep" ]

# Regression: valid JSON that is not an object must be reported as a parse
# error without aborting either parser before valid manifests are scanned.
CRASH_DIR="$(mktemp -d "${TMPDIR:-/tmp}/shai-hulud-crash.XXXXXX")"
mkdir -p "$CRASH_DIR/proj/sub" "$CRASH_DIR/proj/sub2" "$CRASH_DIR/reports-node" "$CRASH_DIR/reports-py"
printf '%s\n' '{"dependencies": {"bad-package": "1.2.3"}}' > "$CRASH_DIR/proj/package.json"
printf 'null\n' > "$CRASH_DIR/proj/sub/package.json"
printf '[]\n' > "$CRASH_DIR/proj/sub2/package.json"

set +e
SHAI_HULUD_MANIFEST_PARSER=node "$SCRIPT_PATH" \
  --scan-root "$CRASH_DIR/proj" --report-dir "$CRASH_DIR/reports-node" \
  --backup-dir "$CRASH_DIR/backups-node" --ioc-file "$TEST_DIR/fixtures/iocs.csv" >/dev/null
NODE_CRASH_EXIT=$?
set -e
[ "$NODE_CRASH_EXIT" -eq 20 ]
grep -q 'bad-package' "$CRASH_DIR"/reports-node/*Dependencies*.csv
grep -q '"package_json_scanned": 3' "$CRASH_DIR"/reports-node/*.json
grep -q '"dependency_findings": 1' "$CRASH_DIR"/reports-node/*.json

if command -v python3 >/dev/null 2>&1; then
  set +e
  SHAI_HULUD_MANIFEST_PARSER=python3 "$SCRIPT_PATH" \
    --scan-root "$CRASH_DIR/proj" --report-dir "$CRASH_DIR/reports-py" \
    --backup-dir "$CRASH_DIR/backups-py" --ioc-file "$TEST_DIR/fixtures/iocs.csv" >/dev/null
  PY_CRASH_EXIT=$?
  set -e
  [ "$PY_CRASH_EXIT" -eq 20 ]
  grep -q 'bad-package' "$CRASH_DIR"/reports-py/*Dependencies*.csv
  grep -q '"package_json_scanned": 3' "$CRASH_DIR"/reports-py/*.json
  grep -q '"dependency_findings": 1' "$CRASH_DIR"/reports-py/*.json
fi

printf 'remediate-shai-hulud.sh tests passed\n'

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
grep -q '"caches_removed": 0' "$FIRST_SUMMARY"
grep -q '"dependency_findings": 2' "$FIRST_SUMMARY"
grep -q '"ide_hooks_removed": 2' "$FIRST_SUMMARY"
grep -q '"persistence_artifacts_removed": 2' "$FIRST_SUMMARY"

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
[ -e "$RUN_DIR/project/Math_Symbol.js" ]
grep -q 'setup.mjs' "$RUN_DIR/project/.claude/settings.json"
AUDIT_SUMMARY="$(find "$RUN_DIR/audit-reports" -name '*.json' -type f -print -quit)"
grep -q '"mode": "audit"' "$AUDIT_SUMMARY"
grep -q '"node_modules_removed": 0' "$AUDIT_SUMMARY"
grep -q '"dependency_findings": 2' "$AUDIT_SUMMARY"
grep -q ",'@bad/scoped,\^4.5.0,4.5.6,review-range" "$RUN_DIR"/audit-reports/*Dependencies*.csv
grep -q ',claude-hook,SessionStart,node setup.mjs,would-remove' "$RUN_DIR"/audit-reports/*Persistence*.csv
grep -q '"ide_hooks_found": 2' "$AUDIT_SUMMARY"
grep -q '"ide_hooks_removed": 0' "$AUDIT_SUMMARY"
grep -q '"persistence_artifacts_removed": 0' "$AUDIT_SUMMARY"

# v2.0.0: custom scan scope never modifies package-manager policy files or
# project caches, so a re-run only re-removes recreated node_modules.
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
grep -q '"configs_needing_change": 0' "$SECOND_SUMMARY"
grep -q '"node_modules_removed": 1' "$SECOND_SUMMARY"
grep -q '"caches_removed": 0' "$SECOND_SUMMARY"

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

printf 'remediate-shai-hulud.sh tests passed\n'

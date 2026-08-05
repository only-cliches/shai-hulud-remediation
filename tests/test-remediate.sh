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
printf '%s\n' '/* installed metadata */ {"name":"bad-package","version":"1.2.3",}' > "$RUN_DIR/project/node_modules/bad-package/package.json"
printf '%s\n' '{"name":"stale-cache-entry"}' > "$RUN_DIR/project/.yarn/cache/archive/package.json"
mkdir -p "$RUN_DIR/project/.vscode/extensions/excluded-app/node_modules/bad-package"
printf '%s\n' '{"dependencies":{"bad-package":"1.2.3"}}' > "$RUN_DIR/project/.vscode/extensions/excluded-app/package.json"
printf '%s\n' '{"name":"bad-package","version":"1.2.3"}' > "$RUN_DIR/project/.vscode/extensions/excluded-app/node_modules/bad-package/package.json"
touch "$RUN_DIR/project/.vscode/extensions/excluded-app/Math_Symbol.js"
# Go's module cache can contain upstream .vscode JSONC/JSON files and package
# manifests, but it is tool-owned immutable state rather than a workspace.
mkdir -p "$RUN_DIR/project/go/pkg/mod/example/.vscode" "$RUN_DIR/project/go/pkg/mod/example/node_modules/bad-package"
printf '%s\n' '{not valid JSON' > "$RUN_DIR/project/go/pkg/mod/example/.vscode/tasks.json"
printf '%s\n' '{"dependencies":{"bad-package":"1.2.3"}}' > "$RUN_DIR/project/go/pkg/mod/example/package.json"
printf '%s\n' '{"name":"bad-package","version":"1.2.3"}' > "$RUN_DIR/project/go/pkg/mod/example/node_modules/bad-package/package.json"
mkdir -p "$RUN_DIR/project/empty-workspace/.vscode" "$RUN_DIR/project/empty-workspace/.claude"
printf '%s\n' '// Intentionally empty VS Code task file.' > "$RUN_DIR/project/empty-workspace/.vscode/tasks.json"
printf '%s\n' '/* Intentionally inactive Claude settings file. */' > "$RUN_DIR/project/empty-workspace/.claude/settings.json"
printf '%s\n' '// Intentionally empty package manifest.' > "$RUN_DIR/project/empty-workspace/package.json"
mkdir -p "$RUN_DIR/project/subproject/node_modules/safe-package/node_modules/bad-package"
printf '%s\n' '{"name":"bad-package","version":"1.2.3"}' > "$RUN_DIR/project/subproject/node_modules/safe-package/node_modules/bad-package/package.json"
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
[ -L "$RUN_DIR/project/linked/node_modules" ]
[ -f "$RUN_DIR/linked-node-modules-target/keep" ]
[ -d "$RUN_DIR/project/subproject/node_modules/safe-package" ]
[ -d "$RUN_DIR/project/subproject/node_modules/safe-package/node_modules/bad-package" ]
[ -e "$RUN_DIR/project/.yarn/cache/archive/package.json" ]
[ -d "$RUN_DIR/project/.vscode/extensions/excluded-app/node_modules/bad-package" ]
[ -e "$RUN_DIR/project/.vscode/extensions/excluded-app/Math_Symbol.js" ]
[ -d "$RUN_DIR/project/go/pkg/mod/example/node_modules/bad-package" ]
cmp "$TEST_DIR/fixtures/project/.npmrc" "$RUN_DIR/project/.npmrc"
cmp "$TEST_DIR/fixtures/project/.yarnrc" "$RUN_DIR/project/.yarnrc"
cmp "$TEST_DIR/fixtures/project/.yarnrc.yml" "$RUN_DIR/project/.yarnrc.yml"
cmp "$TEST_DIR/fixtures/project/.bunfig.toml" "$RUN_DIR/project/.bunfig.toml"
cmp "$TEST_DIR/fixtures/project/pnpm-workspace.yaml" "$RUN_DIR/project/pnpm-workspace.yaml"
grep -q ',bad-package,1.2.3,"1.2.3, 1.2.4",exact' "$RUN_DIR"/reports/*Dependencies*.csv
grep -q 'node_modules,1.2.3,malicious' "$RUN_DIR"/reports/*Dependencies*.csv
grep -q ",'@bad/scoped,\^4.5.0,4.5.6,review-range" "$RUN_DIR"/reports/*Dependencies*.csv
grep -q 'node_modules.*removed' "$RUN_DIR"/reports/*NodeModules*.csv
! grep -q '/.vscode/extensions/excluded-app/' "$RUN_DIR"/reports/*Dependencies*.csv
! grep -q '/go/pkg/mod/' "$RUN_DIR"/reports/*Dependencies*.csv

# IDE persistence: malicious hooks removed, unrelated config preserved,
# payload files (Math_Symbol.js and hook-referenced setup.mjs) deleted.
[ ! -e "$RUN_DIR/project/Math_Symbol.js" ]
[ ! -e "$RUN_DIR/project/setup.mjs" ]
[ -f "$RUN_DIR/project/.claude/settings.json" ]
grep -q '"command": "true"' "$RUN_DIR/project/.claude/settings.json"
! grep -q 'setup.mjs' "$RUN_DIR/project/.claude/settings.json"
[ -f "$RUN_DIR/project/.vscode/tasks.json" ]
grep -q 'pnpm build' "$RUN_DIR/project/.vscode/tasks.json"
grep -Fq 'https://example.invalid/a/*literal*/,}' "$RUN_DIR/project/.vscode/tasks.json"
! grep -q 'setup.mjs' "$RUN_DIR/project/.vscode/tasks.json"
grep -q ',claude-hook,SessionStart,node setup.mjs,removed' "$RUN_DIR"/reports/*Persistence*.csv
grep -q ',vscode-task,folderOpen,node setup.mjs,removed' "$RUN_DIR"/reports/*Persistence*.csv

FIRST_SUMMARY="$(find "$RUN_DIR/reports" -name '*.json' -type f -print -quit)"
FIRST_LOG="$(find "$RUN_DIR/reports" -name '*.log' -type f -print -quit)"
! grep -q '/go/pkg/mod/' "$FIRST_LOG"
! grep -q 'empty-workspace' "$FIRST_LOG"
grep -q ' errors=0$' "$FIRST_LOG"
grep -q '"node_modules_removed": 1' "$FIRST_SUMMARY"
grep -q '"caches_removed": 0' "$FIRST_SUMMARY"
grep -q '"configs_updated": 0' "$FIRST_SUMMARY"
grep -q '"package_json_scanned": 3' "$FIRST_SUMMARY"
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
[ "$(grep -c '^RESTORE_FILE' "$FIRST_MANIFEST")" -eq 2 ]
[ "$(grep -c '^DELETE_FILE' "$FIRST_MANIFEST" || true)" -eq 0 ]
[ "$(find "$RUN_DIR/backups" -name '*.bak' -type f | wc -l | tr -d ' ')" -eq 2 ]
CLAUDE_BACKUP="$(awk -F '\t' -v target="$RUN_DIR/project/.claude/settings.json" '$1 == "RESTORE_FILE" && $2 == target {print $3}' "$FIRST_MANIFEST")"
cmp "$TEST_DIR/fixtures/project/.claude/settings.json" "$CLAUDE_BACKUP"
[ ! -e "$RUN_DIR/project/subproject/.npmrc" ]
[ ! -e "$RUN_DIR/project/subproject/.yarnrc" ]
[ ! -e "$RUN_DIR/project/subproject/.yarnrc.yml" ]
[ ! -e "$RUN_DIR/project/subproject/.bunfig.toml" ]

# Known application/tool state is excluded by default, but an explicit
# incident-response override can include it in dependency remediation.
mkdir -p "$RUN_DIR/include-app-project/.vscode/extensions/actionable/node_modules/bad-package"
printf '%s\n' '{"dependencies":{"bad-package":"1.2.3"}}' > "$RUN_DIR/include-app-project/.vscode/extensions/actionable/package.json"
printf '%s\n' '{"name":"bad-package","version":"1.2.3"}' > "$RUN_DIR/include-app-project/.vscode/extensions/actionable/node_modules/bad-package/package.json"
set +e
"$SCRIPT_PATH" \
  --include-application-dirs \
  --scan-root "$RUN_DIR/include-app-project" \
  --report-dir "$RUN_DIR/include-app-reports" \
  --backup-dir "$RUN_DIR/include-app-backups" \
  --ioc-file "$TEST_DIR/fixtures/iocs.csv" >/dev/null
INCLUDE_APP_EXIT=$?
set -e
[ "$INCLUDE_APP_EXIT" -eq 10 ]
[ ! -e "$RUN_DIR/include-app-project/.vscode/extensions/actionable/node_modules" ]
grep -q '/.vscode/extensions/actionable/package.json' "$RUN_DIR"/include-app-reports/*Dependencies*.csv

# Audit mode must report persistence without mutating it.
mkdir -p "$RUN_DIR/project/node_modules/bad-package"
printf '%s\n' '{"name":"bad-package","version":"1.2.3"}' > "$RUN_DIR/project/node_modules/bad-package/package.json"
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
[ -d "$RUN_DIR/project/node_modules/bad-package" ]
[ ! -e "$RUN_DIR/audit-backups" ]
[ -e "$RUN_DIR/project/Math_Symbol.js" ]
grep -q 'setup.mjs' "$RUN_DIR/project/.claude/settings.json"
AUDIT_SUMMARY="$(find "$RUN_DIR/audit-reports" -name '*.json' -type f -print -quit)"
grep -q '"mode": "audit"' "$AUDIT_SUMMARY"
grep -q '"node_modules_removed": 0' "$AUDIT_SUMMARY"
grep -q 'node_modules.*would-remove' "$RUN_DIR"/audit-reports/*NodeModules*.csv
grep -q '"dependency_findings": 2' "$AUDIT_SUMMARY"
grep -q ",'@bad/scoped,\^4.5.0,4.5.6,review-range" "$RUN_DIR"/audit-reports/*Dependencies*.csv
grep -q ',claude-hook,SessionStart,node setup.mjs,would-remove' "$RUN_DIR"/audit-reports/*Persistence*.csv
grep -q ',payload,,,would-remove' "$RUN_DIR"/audit-reports/*Persistence*.csv
grep -q '"ide_hooks_found": 2' "$AUDIT_SUMMARY"
grep -q '"ide_hooks_removed": 0' "$AUDIT_SUMMARY"
grep -q '"persistence_artifacts_removed": 0' "$AUDIT_SUMMARY"

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
grep -q '"ide_hooks_removed": 2' "$SECOND_SUMMARY"
grep -q '"persistence_artifacts_removed": 1' "$SECOND_SUMMARY"
cmp "$TEST_DIR/fixtures/project/.npmrc" "$RUN_DIR/project/.npmrc"
cmp "$TEST_DIR/fixtures/project/.yarnrc" "$RUN_DIR/project/.yarnrc"
cmp "$TEST_DIR/fixtures/project/.yarnrc.yml" "$RUN_DIR/project/.yarnrc.yml"
cmp "$TEST_DIR/fixtures/project/.bunfig.toml" "$RUN_DIR/project/.bunfig.toml"

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

# A readable installed version absent from the IOC version list is reported
# but must not cause its containing dependency tree to be removed.
mkdir -p "$RUN_DIR/safe-version-project/node_modules/bad-package"
printf '%s\n' '{"dependencies":{"bad-package":"*"}}' > "$RUN_DIR/safe-version-project/package.json"
printf '%s\n' '// installed metadata' '{"name":"bad-package","version":"9.9.9",}' > "$RUN_DIR/safe-version-project/node_modules/bad-package/package.json"
set +e
"$SCRIPT_PATH" \
  --scan-root "$RUN_DIR/safe-version-project" \
  --report-dir "$RUN_DIR/safe-version-reports" \
  --backup-dir "$RUN_DIR/safe-version-backups" \
  --ioc-file "$TEST_DIR/fixtures/iocs.csv" >/dev/null
SAFE_VERSION_EXIT=$?
set -e
[ "$SAFE_VERSION_EXIT" -eq 10 ]
[ -d "$RUN_DIR/safe-version-project/node_modules/bad-package" ]
grep -q '9.9.9,not-listed' "$RUN_DIR/safe-version-reports"/*Dependencies*.csv
[ "$(wc -l < "$RUN_DIR/safe-version-reports"/*NodeModules*.csv | tr -d ' ')" -eq 1 ]

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

# Regression: an unusable macOS developer-tool shim must not prevent direct
# incident-named payloads from being removed, even though JSON-dependent scans
# correctly return an operational error.
NO_PARSER_BIN="$RUN_DIR/no-parser-bin"
mkdir -p "$NO_PARSER_BIN" "$RUN_DIR/no-parser-project" "$RUN_DIR/no-parser-reports"
printf '%s\n' '#!/bin/sh' 'exit 1' > "$NO_PARSER_BIN/python3"
printf '%s\n' '#!/bin/sh' 'exit 1' > "$NO_PARSER_BIN/node"
chmod 755 "$NO_PARSER_BIN/python3" "$NO_PARSER_BIN/node"
touch "$RUN_DIR/no-parser-project/Math_Symbol.js"
set +e
PATH="$NO_PARSER_BIN:/usr/bin:/bin" "$SCRIPT_PATH" \
  --scan-root "$RUN_DIR/no-parser-project" \
  --report-dir "$RUN_DIR/no-parser-reports" \
  --backup-dir "$RUN_DIR/no-parser-backups" \
  --ioc-file "$TEST_DIR/fixtures/iocs.csv" >/dev/null
NO_PARSER_EXIT=$?
set -e
[ "$NO_PARSER_EXIT" -eq 20 ]
[ ! -e "$RUN_DIR/no-parser-project/Math_Symbol.js" ]
grep -q 'payload.*removed' "$RUN_DIR/no-parser-reports"/*Persistence*.csv

# Regression: valid JSON that is not an object must be reported as a parse
# error without aborting either parser before valid manifests are scanned.
CRASH_DIR="$(mktemp -d "${TMPDIR:-/tmp}/shai-hulud-crash.XXXXXX")"
mkdir -p "$CRASH_DIR/proj/sub" "$CRASH_DIR/proj/sub2" "$CRASH_DIR/proj/.claude" "$CRASH_DIR/reports-node" "$CRASH_DIR/reports-py"
printf '%s\n' '{"dependencies": {"bad-package": "1.2.3"}}' > "$CRASH_DIR/proj/package.json"
printf 'null\n' > "$CRASH_DIR/proj/sub/package.json"
printf '[]\n' > "$CRASH_DIR/proj/sub2/package.json"
printf '%s\n' '/* leading comment */ {"hooks":' > "$CRASH_DIR/proj/.claude/settings.json"

set +e
SHAI_HULUD_MANIFEST_PARSER=node "$SCRIPT_PATH" \
  --scan-root "$CRASH_DIR/proj" --report-dir "$CRASH_DIR/reports-node" \
  --backup-dir "$CRASH_DIR/backups-node" --ioc-file "$TEST_DIR/fixtures/iocs.csv" >/dev/null
NODE_CRASH_EXIT=$?
set -e
[ "$NODE_CRASH_EXIT" -eq 20 ]
grep -q 'bad-package' "$CRASH_DIR"/reports-node/*Dependencies*.csv
grep -q '.claude/settings.json,error' "$CRASH_DIR"/reports-node/*Persistence*.csv
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
  grep -q '.claude/settings.json,error' "$CRASH_DIR"/reports-py/*Persistence*.csv
  grep -q '"package_json_scanned": 3' "$CRASH_DIR"/reports-py/*.json
  grep -q '"dependency_findings": 1' "$CRASH_DIR"/reports-py/*.json
fi

printf 'remediate-shai-hulud.sh tests passed\n'

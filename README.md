# Shai Hulud Remediation

Unattended macOS, Linux, and Windows remediation for the npm supply-chain incident described by [Wiz](https://www.wiz.io/blog/keyv-and-cacheable-npm-supply-chain-attack) and [Aikido](https://www.aikido.dev/blog/keyv-and-friends-compromised-in-npm-supply-chain-attack).

The scripts are designed for non-interactive execution from NinjaOne, CrowdStrike Falcon, or a comparable RMM/EDR platform. Remediation is the default; use audit mode when no endpoint changes are desired.

For incident background and additional campaign indicators, see [JFrog Security Research: Major Shai Hulud campaign strikes npm again](https://research.jfrog.com/post/shai-hulud-is-back-august/).

> **Destructive operation:** remediation removes only `node_modules` trees containing a top-level IOC package whose installed version is malicious or cannot be verified, plus incident-specific payload artifacts. It may modify matched IDE configuration files inside source repositories. Stop affected Node applications and pause affected build agents before deployment. Deleted dependency trees and payload artifacts are not backed up; modified IDE configuration files are backed up.

## Remediation workflow

Both Windows & MacOS/Linux implementations perform the following workflow:

1. Obtain and validate the IOC CSV before making endpoint changes. If IOC acquisition fails, the run exits with an operational error without performing cleanup.
2. Scan every `package.json` beneath discovered user profiles and common CI/build roots, while pruning existing `node_modules`, known application/tool-state directories, symlinks, and Windows reparse points. macOS/Linux traversal stays on each selected filesystem; pass mounted workspaces as additional scan roots when needed.
3. Report direct IOC package declarations and inspect matching packages installed at the top level of the manifest's local or ancestor `node_modules`. Known malicious installed versions and packages whose installed metadata cannot be verified are actionable; known versions absent from the IOC version list are reported but retained.
4. Remove only the actionable containing `node_modules` directories. Unrelated dependency trees and npm, pnpm, Yarn, Bun, Corepack, and node-gyp caches are left intact.
5. Remove Claude Code hooks and VS Code tasks that reference the incident payloads (`setup.mjs`, `Math_Symbol.js`, `math_init.js`, or `bun-dl-*`) while preserving unrelated hooks, tasks, and settings. Remove `Math_Symbol.js`, `math_init.js`, and `bun-dl-*` artifacts by their incident-specific names; remove `setup.mjs` only when a matched hook or task references it.
6. Write dependency, `node_modules` action, persistence, log, and JSON reports suitable for RMM collection.

## Automated deployment

Pre-stage the appropriate script and, preferably, a reviewed IOC CSV in the management platform. Do not use `curl | sh` for an incident-response workflow.

macOS/Linux, as root:

```bash
/bin/bash ./scripts/remediate-shai-hulud.sh
```

Windows, as SYSTEM or Administrator using 64-bit Windows PowerShell 5.1 or PowerShell 7:

```powershell
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\scripts\Remediate-ShaiHulud.ps1
```

The macOS/Linux script requires a working `python3` or Node.js executable for JSON manifest and IDE hook/task parsing. On macOS, install or select the Command Line Tools (or provide another trusted interpreter on `PATH`) before deployment; the `/usr/bin` developer-tool shim is not sufficient. If no usable parser is available, the script still removes direct incident-named payload artifacts, records an operational error, and leaves dependency and hook/task results incomplete until a parser is installed.

On .NET Framework 4.6.2 or newer, the Windows scanner opts its own process into modern path handling and uses extended-length filesystem paths internally. This lets Windows PowerShell 5.1 traverse, inspect, and remove actionable dependency trees beyond the legacy 260-character limit without changing machine policy. Logs and reports retain ordinary drive-letter or UNC paths; no `\\?\` prefixes are exposed to operators.

Omitting the IOC option downloads the current [Wiz IOC list](https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/refs/heads/main/reports/keyv-packages.csv) over HTTPS. Egress-restricted or tightly controlled environments should always use a pre-staged file.

Recommended rollout:

1. Run audit mode against a representative endpoint.
2. Run targeted remediation against a disposable fixture or test workspace.
3. Pause build agents and applications that use Node dependencies.
4. Deploy full remediation and collect the JSON summary plus logs.
5. Review IOC declarations, update affected manifests and lockfiles, then reinstall only the removed dependency trees from trusted lockfiles.

## Scope and targeted testing

Default scope includes:

- macOS/Linux user homes, including non-standard Linux homes from `/etc/passwd`;
- common Jenkins, GitHub Actions, GitLab Runner, Buildkite, generic build, workspace, and CI roots;
- corresponding named CI roots on every Windows fixed drive;
- Windows profiles discovered from the registry and `Users` directory; and
- non-standard top-level directories on the Windows system drive (normally `C:\`), such as `C:\src`, `C:\repos`, and `C:\projects`.

When discovering Windows system-drive roots, the script excludes standard operating-system, profile, recovery, and application directories, including Windows, Users, Program Files, ProgramData, Recovery, PerfLogs, `$Recycle.Bin`, and System Volume Information. Hidden, system, and reparse-point directories are also excluded. This discovery runs only in default scope; supplying `-ScanRoot` continues to restrict the run to exactly the requested roots.

The default deliberately does not sweep every directory on every fixed disk. Within selected roots, it also prunes known application and tool-owned state so dependencies embedded in installed applications, IDE extensions, and caches are not treated as source workspaces:

- all platforms: common cache/package/runtime-manager state (`.cache`, `.config`, `.local`, `.npm`, `.pnpm-store`, `.yarn`, `.bun`, `.corepack`, `.nvm`, `.fnm`, `.volta`, `.asdf`, `.nodenv`, `.node-gyp`, `.cargo`, `.gradle`, `.m2`, `.terraform`, `.tox`, `.venv`, and Go `pkg/mod` trees), IDE/agent state (`.vscode*`, `.cursor*`, `.windsurf*`, `.claude`, `.codex`, and `.opencode`), and `Applications`;
- macOS: `Library`, application bundles (`*.app`), `/System`, `/Library`, `/Applications`, user/volume trash (`.Trash` and `.Trashes`), Spotlight and filesystem metadata, temporary-item stores, and protected `/private/var` state; protected and metadata locations remain excluded even with the application-directory override;
- Linux: `.var`, `snap`, `/usr`, `/opt`, `/snap`, `/var/lib`, `/var/cache`, and `/var/snap`; and
- Windows: `AppData`, `Application Data`, `Local Settings`, `Programs`, `scoop`, Windows, Program Files, and ProgramData roots.

The scripts still inspect workspace `.claude/settings.json` and `.vscode/tasks.json` for the narrow incident-persistence patterns, but they do not descend into those directories for dependency or payload cleanup. To investigate application-owned trees deliberately, add `--include-application-dirs` or `-IncludeApplicationDirectories`. Use that override only with tightly bounded scan roots: it can remove an application or IDE extension's `node_modules` when the installed top-level version is actionable.

Every inspected JSON file—including `package.json`, installed-package metadata, Claude settings, and VS Code tasks—is read with JSONC tolerance. Line comments, block comments, trailing commas, and empty or comment-only files therefore do not generate scanner errors. Empty documents are treated as empty objects and cannot produce dependency or persistence findings. Genuinely malformed nonempty files and valid JSON values that are not objects are still skipped and reported. This tolerance belongs to the remediation scanner; package managers or IDEs may still reject JSONC where their own format requires strict JSON.

Add each additional mounted workspace explicitly with a repeatable `--scan-root` or a PowerShell array passed to `-ScanRoot`.

Targeted runs do not require elevation. They use the same evidence-driven behavior beneath only the supplied roots: unrelated dependency trees and package caches are retained, and package-manager configuration is not changed.

```bash
/bin/bash ./scripts/remediate-shai-hulud.sh \
  --scan-root /tmp/remediation-fixture \
  --report-dir /tmp/remediation-report \
  --backup-dir /tmp/remediation-backups \
  --ioc-file ./keyv-packages.csv
```

```powershell
.\scripts\Remediate-ShaiHulud.ps1 `
  -ScanRoot C:\remediation-fixture `
  -ReportDirectory C:\remediation-report `
  -BackupDirectory C:\remediation-backups `
  -IocFile .\keyv-packages.csv
```

Audit mode inventories the same scope but does not delete targeted dependency trees or payloads, and does not change IDE configuration. It still writes reports, which is the only intentional endpoint mutation:

```bash
/bin/bash ./scripts/remediate-shai-hulud.sh --audit-only --ioc-file ./keyv-packages.csv
```

```powershell
powershell.exe -NoProfile -NonInteractive -File .\scripts\Remediate-ShaiHulud.ps1 -AuditOnly -IocFile .\keyv-packages.csv
```

## Reports, backups, and rollback

Default report and backup locations are:

| Platform | Elevated/default-scope reports | Non-elevated targeted reports | Restricted configuration backups |
| --- | --- | --- | --- |
| Linux | `/var/log/Shai-Hulud-Remediation` | `$HOME/.local/state/Shai-Hulud-Remediation` | `/var/lib/Shai-Hulud-Remediation/Backups/<run-id>` |
| macOS | `/Library/Logs/Shai-Hulud-Remediation` | `$HOME/.local/state/Shai-Hulud-Remediation` | `/Library/Application Support/Shai-Hulud-Remediation/Backups/<run-id>` |
| Windows | `C:\Users\Public\Shai-Hulud-Remediation` (fallback: `%ProgramData%\Shai-Hulud-Remediation`) | `C:\Users\Public\Shai-Hulud-Remediation` (fallback: `%ProgramData%\Shai-Hulud-Remediation`) | `%ProgramData%\Shai-Hulud-Remediation\Backups\<run-id>` |

If a non-elevated Unix run cannot use `$HOME`, it allocates a private temporary report directory and prints the path. On Windows, if the default public report directory cannot be safely created, is inaccessible, or is a reparse point, the script automatically uses `%ProgramData%\Shai-Hulud-Remediation` and prints a warning containing the selected path. An explicitly supplied `-ReportDirectory` remains strict and does not fall back. Override locations with `--report-dir` / `-ReportDirectory` and `--backup-dir` / `-BackupDirectory`. Backup directories are created with restrictive permissions or ACLs even when their parent was supplied by the operator.

Each run writes:

- `Shai-Hulud-Remediation-<run-id>.log` — activity, warnings, and errors;
- `Shai-Hulud-Dependencies-<run-id>.csv` — matching declarations, associated top-level installations, installed versions, and disposition status;
- `Shai-Hulud-NodeModules-<run-id>.csv` — each targeted dependency tree and whether it was removed, would be removed in audit mode, or failed removal;
- `Shai-Hulud-Persistence-<run-id>.csv` — IDE hooks, tasks, payload artifacts, parse failures, and the action taken or proposed; and
- `Shai-Hulud-Remediation-<run-id>.json` — stable fields for RMM ingestion.

Remediation runs also create `manifest.tsv` in the restricted backup directory. IDE configuration files are backed up before modification. Backups use short sequence names, avoiding path collisions and component-length failures. Manifest actions are:

| Action | Rollback meaning |
| --- | --- |
| `RESTORE_FILE` | Replace `Target` with the file in `BackupOrValue` |
| `DELETE_FILE` | `Target` did not exist before the run; remove it during rollback |
| `RESTORE_ENV` | Restore the Windows machine variable to the Base64-encoded UTF-8 value |
| `DELETE_ENV` | The Windows machine variable did not exist; remove it during rollback |

Apply rollback entries in reverse order. Inspect whether an IDE configuration file has been edited since remediation before overwriting or deleting it. The manifest contains enough information to restore pre-run configuration state, but it cannot recover deleted dependency trees or payload artifacts.

IDE configuration backups may contain commands or environment details. Never move the backup directory to a public share or attach it to an unrestricted ticket.

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | Completed without IOC declarations, persistence findings, or operational errors |
| `10` | Attention required: IOC declarations or IDE persistence found, or audit found remediation work |
| `20` | One or more operational errors occurred; inspect the log |
| `30` | Invalid invocation, unsupported OS, initialization failure, or insufficient privileges |

Configure the RMM job so `10` is collected as an attention state rather than treated as an execution failure. The stdout `SUMMARY` line mirrors the final status even if the JSON summary itself cannot be written.

## Options

| macOS/Linux | Windows | Purpose |
| --- | --- | --- |
| `--audit-only` | `-AuditOnly` | Report without endpoint cleanup or configuration changes |
| `--ioc-file PATH` | `-IocFile PATH` | Use a pre-staged IOC CSV |
| `--report-dir PATH` | `-ReportDirectory PATH` | Override report destination |
| `--backup-dir PATH` | `-BackupDirectory PATH` | Override restricted backup parent |
| `--scan-root PATH` | `-ScanRoot PATH` | Add explicit bounded roots; repeat/pass an array |
| `--include-application-dirs` | `-IncludeApplicationDirectories` | Include normally pruned application and tool-state directories |
| `--help` | `Get-Help .\scripts\Remediate-ShaiHulud.ps1 -Full` | Display help |

## Detection limitations

Dependency declarations are reported rather than rewritten. The scanner checks direct declarations in `dependencies`, `devDependencies`, `optionalDependencies`, and `peerDependencies`, then checks matching packages installed directly beneath local or ancestor `node_modules`. It does not inspect lockfiles, prove whether a transitive or cached package was installed, evaluate every semver range, or inspect default-excluded application directories unless the explicit override is used. Application owners must review lockfiles and perform their normal software-composition analysis before declaring an endpoint clean.

An installed version exactly present in the IOC list is marked `malicious`; unreadable or missing installed package metadata is marked `unknown`, and both cause the containing dependency tree to be targeted. A readable installed version absent from the IOC list is marked `not-listed` and retained. A declaration without a corresponding top-level installation is marked `not-installed`.

The incident payload names `Math_Symbol.js`, `math_init.js`, and `bun-dl-*` are treated as deletion IOCs anywhere beneath the selected roots. `setup.mjs` is not deleted by name alone and must be referenced by a matched Claude Code hook or VS Code task. Review and tightly bound `--scan-root` / `-ScanRoot` during testing if legitimate content could use one of the incident-specific names.

## Local validation

The bounded Unix integration test operates only in temporary fixture directories. It exercises remediation and audit modes, both JSON parsers, targeted dependency-tree removal, retention of unrelated trees and caches, symlink safety, IDE-persistence removal, persistence-only exit status, non-object manifests, IOC reporting, and rollback manifests:

```bash
./tests/test-remediate.sh
```

The equivalent Windows integration test uses a separate PowerShell process so it can validate automation exit codes. It also creates a project beyond the legacy `MAX_PATH` boundary and verifies manifest discovery, reporting, and targeted dependency-tree removal. Run it from Windows PowerShell 5.1 or PowerShell 7 on Windows:

```powershell
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\tests\test-remediate.ps1
```

Both tests are bounded to disposable temporary fixtures and validate the same persistence behavior, reporting fields, rollback protection, and fail-closed IOC handling.

## After remediation

Treat an endpoint as potentially compromised until the investigation is complete. After the script finishes:

1. Reboot the machine. This stops surviving processes and starts applications and developer tools in a clean session.
2. Preserve the JSON summary, logs, dependency report, `node_modules` action report, persistence report, and backup manifest for the incident record. Record any exit code `10` or `20` for follow-up.
3. From a trusted machine, rotate and revoke credentials that may have been available on the endpoint: npm and package-registry tokens, GitHub/GitLab tokens, cloud keys, CI/CD secrets, SSH keys, API keys, and active sessions. Review package-publish and repository activity for unauthorized changes.
4. Review every dependency finding and update manifests and lockfiles to known-good versions. Reinstall removed dependencies from trusted lockfiles using the package manager's clean or frozen install mode. Consider disabling lifecycle scripts during reinstall until the application owner and incident team approve them.
5. Inventory global npm modules with `npm root -g` and `npm ls -g --depth=0`. Remove and reinstall required global modules from trusted sources and pinned versions; do not assume global modules were safe merely because the script completed.
6. Review installed IDE and developer-tool extensions, including VS Code, Claude Code, JetBrains, editor plugins, and globally installed developer CLIs. Remove suspicious extensions and reinstall required extensions from their official marketplaces or trusted packages. The persistence scan covers workspace hook/task files, not every installed extension.
7. Recreate or reinstall build-agent and CI dependencies only after their credentials have been rotated. Review CI workspace hooks, package-manager configuration, and repository changes before allowing builds or publishing to resume.
8. Run the script again in audit mode and confirm that the reports contain no unresolved persistence or dependency findings. Keep generated IDE configuration backups restricted.

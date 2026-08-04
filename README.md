# Shai Hulud Remediation

Unattended macOS, Linux, and Windows remediation for the npm supply-chain incident described by [Wiz](https://www.wiz.io/blog/keyv-and-cacheable-npm-supply-chain-attack) and [Aikido](https://www.aikido.dev/blog/keyv-and-friends-compromised-in-npm-supply-chain-attack).

The scripts are designed for non-interactive execution from NinjaOne, CrowdStrike Falcon, or a comparable RMM/EDR platform. Remediation is the default; use audit mode when no endpoint changes are desired.

For incident background and additional campaign indicators, see [JFrog Security Research: Major Shai Hulud campaign strikes npm again](https://research.jfrog.com/post/shai-hulud-is-back-august/).

> **Destructive operation:** remediation removes dependency trees, package caches, and incident-specific payload artifacts, and may modify package-manager and IDE configuration files inside source repositories, leaving working trees dirty. Stop Node applications and pause build agents before deployment. Applications must reinstall their dependencies afterward. Deleted dependency trees, caches, and payload artifacts are not backed up; modified configuration files are backed up.

## Remediation workflow

Both Windows & MacOS/Linux implementations perform the following workflow:

1. Obtain and validate the IOC CSV before making endpoint changes. If IOC acquisition fails, the run exits with an operational error without performing cleanup or changing package-manager policy.
2. Scan discovered user profiles and common CI/build roots without following symlinks or Windows reparse points. macOS/Linux traversal stays on each selected filesystem; pass mounted workspaces as additional scan roots when needed.
3. Remove every `node_modules`, project `.yarn/cache`, and project `.pnpm-store` beneath the selected roots. Full-scope runs also clear known npm, pnpm, Yarn, Bun, Corepack, and node-gyp user/system caches, including the historical `~/.pnpm-store` location.
4. Remove Claude Code hooks and VS Code tasks that reference the incident payloads (`setup.mjs`, `Math_Symbol.js`, `math_init.js`, or `bun-dl-*`) while preserving unrelated hooks, tasks, and settings. Remove `Math_Symbol.js`, `math_init.js`, and `bun-dl-*` artifacts by their incident-specific names; remove `setup.mjs` only when a matched hook or task references it.
5. Disable third-party dependency lifecycle scripts at machine, profile, and discovered-project scope. Existing `pnpm-workspace.yaml` files receive `ignoreScripts: true`; project-local files are included because they can override profile policy.
6. Verify the files and Windows machine environment values that were actually changed. Verification does not depend on the RMM account's current working directory or installed package-manager shims.
7. Report IOC package declarations and IDE-persistence activity, and write log, CSV, and JSON output suitable for RMM collection.

The lifecycle controls are intentionally persistent until an administrator rolls them back. Modern Yarn's `enableScripts: false` blocks third-party package postinstall scripts but does not suppress workspace postinstall scripts; use `yarn install --mode=skip-builds` when workspace scripts must also be skipped.

## Automated deployment

Pre-stage the appropriate script and, preferably, a reviewed IOC CSV in the management platform. Do not use `curl | sh` for an incident-response workflow.

macOS/Linux, as root:

```bash
/bin/bash ./scripts/remediate-shai-hulud.sh --ioc-file ./keyv-packages.csv
```

Windows, as SYSTEM or Administrator using 64-bit Windows PowerShell 5.1 or PowerShell 7:

```powershell
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\scripts\Remediate-ShaiHulud.ps1 -IocFile .\keyv-packages.csv
```

Omitting the IOC option downloads the current [Wiz IOC list](https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/refs/heads/main/reports/keyv-packages.csv) over HTTPS. Egress-restricted or tightly controlled environments should always use a pre-staged file.

Recommended rollout:

1. Run audit mode against a representative endpoint.
2. Run targeted remediation against a disposable fixture or test workspace.
3. Pause build agents and applications that use Node dependencies.
4. Deploy full remediation and collect the JSON summary plus logs.
5. Review IOC declarations, update affected manifests and lockfiles, then reinstall dependencies while lifecycle scripts remain disabled.

## Scope and targeted testing

Default scope includes:

- macOS/Linux user homes, including non-standard Linux homes from `/etc/passwd`;
- common Jenkins, GitHub Actions, GitLab Runner, Buildkite, generic build, workspace, and CI roots;
- corresponding named CI roots on every Windows fixed drive; and
- Windows profiles discovered from the registry and `Users` directory.

The default deliberately does not sweep every directory on every fixed disk, which avoids deleting dependencies embedded in unrelated installed applications. Add each additional application or mounted workspace explicitly with a repeatable `--scan-root` or a PowerShell array passed to `-ScanRoot`.

Targeted runs do not require elevation. They remove dependency trees/project caches and update package-manager configuration only beside `package.json` files beneath the supplied roots. They do not clear profile/system caches or change machine-wide policy.

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

Audit mode inventories the same scope but does not delete caches, dependencies, or payloads, and does not change package-manager or IDE configuration. It still writes reports, which is the only intentional endpoint mutation:

```bash
/bin/bash ./scripts/remediate-shai-hulud.sh --audit-only --ioc-file ./keyv-packages.csv
```

```powershell
powershell.exe -NoProfile -NonInteractive -File .\scripts\Remediate-ShaiHulud.ps1 -AuditOnly -IocFile .\keyv-packages.csv
```

## Reports, backups, and rollback

Elevated default locations are private machine state rather than a user's or Public Desktop:

| Platform | Reports | Restricted configuration backups |
| --- | --- | --- |
| Linux | `/var/log/Shai-Hulud-Remediation` | `/var/lib/Shai-Hulud-Remediation/Backups/<run-id>` |
| macOS | `/Library/Logs/Shai-Hulud-Remediation` | `/Library/Application Support/Shai-Hulud-Remediation/Backups/<run-id>` |
| Windows | `%ProgramData%\Shai-Hulud-Remediation\Reports` | `%ProgramData%\Shai-Hulud-Remediation\Backups\<run-id>` |

Non-elevated targeted Windows runs use `%LOCALAPPDATA%`; non-elevated Unix runs use `$HOME/.local/state` when available and otherwise allocate a private temporary directory. Override locations with `--report-dir` / `-ReportDirectory` and `--backup-dir` / `-BackupDirectory`. Backup directories are created with restrictive permissions or ACLs even when their parent was supplied by the operator.

Each run writes:

- `Shai-Hulud-Remediation-<run-id>.log` — activity, warnings, and errors;
- `Shai-Hulud-Dependencies-<run-id>.csv` — matching dependency declarations;
- `Shai-Hulud-Persistence-<run-id>.csv` — IDE hooks, tasks, payload artifacts, parse failures, and the action taken or proposed; and
- `Shai-Hulud-Remediation-<run-id>.json` — stable fields for RMM ingestion.

Remediation runs also create `manifest.tsv` in the restricted backup directory. Package-manager files and IDE configuration files are backed up before modification. Backups use short sequence names, avoiding path collisions and component-length failures. Manifest actions are:

| Action | Rollback meaning |
| --- | --- |
| `RESTORE_FILE` | Replace `Target` with the file in `BackupOrValue` |
| `DELETE_FILE` | `Target` did not exist before the run; remove it during rollback |
| `RESTORE_ENV` | Restore the Windows machine variable to the Base64-encoded UTF-8 value |
| `DELETE_ENV` | The Windows machine variable did not exist; remove it during rollback |

Apply rollback entries in reverse order. Stop package-manager activity first and inspect whether a configuration file has been edited since remediation before overwriting or deleting it. The manifest contains enough information to restore pre-run configuration and Windows environment state, but it cannot recover deleted dependency trees, caches, or payload artifacts.

Because `.npmrc` may contain registry credentials, never move the backup directory to a public share or attach it to an unrestricted ticket.

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
| `--audit-only` | `-AuditOnly` | Report without cleanup or policy changes |
| `--ioc-file PATH` | `-IocFile PATH` | Use a pre-staged IOC CSV |
| `--report-dir PATH` | `-ReportDirectory PATH` | Override report destination |
| `--backup-dir PATH` | `-BackupDirectory PATH` | Override restricted backup parent |
| `--scan-root PATH` | `-ScanRoot PATH` | Add explicit bounded roots; repeat/pass an array |
| `--help` | `Get-Help .\scripts\Remediate-ShaiHulud.ps1 -Full` | Display help |

## Detection limitations

Dependency declarations are reported rather than rewritten. The scanner checks direct declarations in `dependencies`, `devDependencies`, `optionalDependencies`, and `peerDependencies`; it does not prove whether a transitive or cached package was installed. Application owners must review lockfiles and perform their normal software-composition analysis before declaring an endpoint clean.

The incident payload names `Math_Symbol.js`, `math_init.js`, and `bun-dl-*` are treated as deletion IOCs anywhere beneath the selected roots. `setup.mjs` is not deleted by name alone and must be referenced by a matched Claude Code hook or VS Code task. Review and tightly bound `--scan-root` / `-ScanRoot` during testing if legitimate content could use one of the incident-specific names.

## Local validation

The bounded Unix integration test operates only in temporary fixture directories. It exercises remediation and audit modes, both JSON parsers, symlink safety, project-cache cleanup, IDE-persistence removal, persistence-only exit status, policy idempotency, non-object manifests, IOC reporting, and rollback manifests:

```bash
./tests/test-remediate.sh
```

The equivalent Windows integration test uses a separate PowerShell process so it can validate automation exit codes. Run it from Windows PowerShell 5.1 or PowerShell 7 on Windows:

```powershell
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\tests\test-remediate.ps1
```

Both tests are bounded to disposable temporary fixtures and validate the same persistence behavior, reporting fields, rollback protection, and fail-closed IOC handling.

## After remediation

Treat an endpoint as potentially compromised until the investigation is complete. After the script finishes:

1. Reboot the machine. This stops surviving processes and ensures the lifecycle-script policy and environment changes are applied to new sessions.
2. Preserve the JSON summary, logs, dependency report, persistence report, and backup manifest for the incident record. Record any exit code `10` or `20` for follow-up.
3. From a trusted machine, rotate and revoke credentials that may have been available on the endpoint: npm and package-registry tokens, GitHub/GitLab tokens, cloud keys, CI/CD secrets, SSH keys, API keys, and active sessions. Review package-publish and repository activity for unauthorized changes.
4. Review every dependency finding and update manifests and lockfiles to known-good versions. Reinstall dependencies from trusted lockfiles using the package manager's clean or frozen install mode while lifecycle scripts remain disabled. Do not re-enable lifecycle scripts until the application owner and incident team approve it.
5. Inventory global npm modules with `npm root -g` and `npm ls -g --depth=0`. Remove and reinstall required global modules from trusted sources and pinned versions; do not assume global modules were safe merely because the script completed.
6. Review installed IDE and developer-tool extensions, including VS Code, Claude Code, JetBrains, editor plugins, and globally installed developer CLIs. Remove suspicious extensions and reinstall required extensions from their official marketplaces or trusted packages. The persistence scan covers workspace hook/task files, not every installed extension.
7. Recreate or reinstall build-agent and CI dependencies only after their credentials have been rotated. Review CI workspace hooks, package-manager configuration, and repository changes before allowing builds or publishing to resume.
8. Run the script again in audit mode and confirm that the reports contain no unresolved persistence or dependency findings. Keep the generated configuration backups restricted; they may contain registry credentials.

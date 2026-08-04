# Shai Hulud Remediation

Unattended macOS, Linux, and Windows remediation for the npm supply-chain incident described by [Wiz](https://www.wiz.io/blog/keyv-and-cacheable-npm-supply-chain-attack) and [Aikido](https://www.aikido.dev/blog/keyv-and-friends-compromised-in-npm-supply-chain-attack).

The scripts are designed for non-interactive execution from NinjaOne, CrowdStrike Falcon, or a comparable RMM/EDR platform. Remediation is the default; use audit mode when no endpoint changes are desired.

> **Destructive operation:** remediation removes dependency trees and package caches and may modify package-manager files inside source repositories, leaving working trees dirty. Stop Node applications and pause build agents before deployment. Applications must reinstall their dependencies afterward. Deleted dependency trees and caches are not backed up.

## Remediation workflow

Both Windows & MacOS/Linux implementations perform the following workflow:

1. Obtain and validate the IOC CSV before making endpoint changes. If IOC acquisition fails, the run exits with an operational error without performing cleanup or changing package-manager policy.
2. Scan discovered user profiles and common CI/build roots without following symlinks or Windows reparse points. macOS/Linux traversal stays on each selected filesystem; pass mounted workspaces as additional scan roots when needed.
3. Remove every `node_modules`, project `.yarn/cache`, and project `.pnpm-store` beneath the selected roots. Full-scope runs also clear known npm, pnpm, Yarn, Bun, Corepack, and node-gyp user/system caches, including the historical `~/.pnpm-store` location.
4. Disable third-party dependency lifecycle scripts at machine, profile, and discovered-project scope. The machine-scope npm/pnpm block is written to the resolved global npmrc and to the `etc/npmrc` of every discovered Node prefix (Homebrew, fnm, nvm, asdf, volta, n, nodenv, source builds), since a prefix-installed Node never reads `/etc/npmrc`; this also covers Nodes reinstalled into those prefixes afterward. Existing `pnpm-workspace.yaml` files receive `ignoreScripts: true`; project-local files are included because they can override profile policy.
5. Verify the files and Windows machine environment values that were actually changed. Verification does not depend on the RMM account's current working directory or installed package-manager shims.
6. Report IOC package declarations from `package.json` with vulnerable packages and write log, CSV, and JSON output suitable for RMM collection.

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

Audit mode inventories the same scope but does not delete caches/dependencies or change policy. It still writes reports, which is the only intentional endpoint mutation:

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
- `Shai-Hulud-Dependencies-<run-id>.csv` — matching dependency declarations; and
- `Shai-Hulud-Remediation-<run-id>.json` — stable fields for RMM ingestion.

Remediation runs also create `manifest.tsv` in the restricted backup directory. Backups use short sequence names, avoiding path collisions and component-length failures. Manifest actions are:

| Action | Rollback meaning |
| --- | --- |
| `RESTORE_FILE` | Replace `Target` with the file in `BackupOrValue` |
| `DELETE_FILE` | `Target` did not exist before the run; remove it during rollback |
| `RESTORE_ENV` | Restore the Windows machine variable to the Base64-encoded UTF-8 value |
| `DELETE_ENV` | The Windows machine variable did not exist; remove it during rollback |

Apply rollback entries in reverse order. Stop package-manager activity first and inspect whether a configuration file has been edited since remediation before overwriting or deleting it. The manifest contains enough information to restore pre-run configuration and Windows environment state, but it cannot recover deleted dependency trees or caches.

Because `.npmrc` may contain registry credentials, never move the backup directory to a public share or attach it to an unrestricted ticket.

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | Completed without IOC declarations or operational errors |
| `10` | Attention required: IOC declarations found, or audit found remediation work |
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

## Local validation

The bounded Unix integration test operates only in temporary fixture directories. It exercises remediation and audit modes, both JSON parsers, symlink safety, project-cache cleanup, policy idempotency, IOC reporting, and rollback manifests:

```bash
./tests/test-remediate.sh
```

Run the PowerShell script's targeted mode on a disposable Windows fixture before fleet rollout; the Unix test does not execute the Windows implementation.

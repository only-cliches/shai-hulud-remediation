# Shai Hulud Remediation

Unattended macOS, Linux, and Windows remediation for the npm supply-chain incident described by [Wiz](https://www.wiz.io/blog/keyv-and-cacheable-npm-supply-chain-attack) and [Aikido](https://www.aikido.dev/blog/keyv-and-friends-compromised-in-npm-supply-chain-attack).

The scripts are intended for elevated deployment from NinjaOne, CrowdStrike Falcon, or a comparable RMM/EDR platform. They do not prompt. **Remediation is the default**, because an agent-run script cannot answer confirmation prompts.

## What it does

Each implementation performs the same workflow:

1. Enumerates user profiles, home directories, common CI workspace locations (Jenkins, GitHub Actions, GitLab Runner, Buildkite), and any explicitly supplied scan roots, removing every `node_modules` directory found there without following symlinks/reparse points or crossing filesystem boundaries.
2. Removes npm, pnpm, Yarn, Bun, Corepack, and node-gyp caches from every discovered user profile plus known system cache locations.
3. Blocks package lifecycle scripts for npm/pnpm, Yarn Classic, modern Yarn, and Bun at machine and user-profile scope, backing up every modified policy file and recording the backups in a manifest.
4. Hunts the worm's IDE persistence: surgically removes Claude Code hooks and VS Code `folderOpen` tasks whose commands reference the known payloads (`setup.mjs`, `Math_Symbol.js`, `math_init.js`, `bun-dl-*`), and deletes those payload files. Unrelated hooks, tasks, and settings are preserved; a `setup.mjs` referenced by a removed hook is deleted, while other files merely named `setup.mjs` are left untouched (the name alone is not a reliable IOC).
5. Downloads the current [Wiz IOC package list](https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/refs/heads/main/reports/keyv-packages.csv), parses every remaining `package.json`, and reports matching dependency declarations. Exact malicious versions are labeled `exact`; ranges and aliases are conservatively labeled `review-range`.
6. Writes a timestamped execution log, dependency CSV, persistence CSV, and machine-readable JSON summary to the desktop report directory and emits progress to stdout for the RMM job log.

The cleanup is idempotent. Re-running it removes anything recreated since the previous run and leaves compliant configuration unchanged.

> **Operational warning:** remediation deliberately deletes dependency trees and package caches across all local fixed disks. Applications must reinstall dependencies afterward. Lifecycle scripts remain disabled until an administrator intentionally reverses the policy.

## Automated deployment

Upload the appropriate script as an RMM/EDR component and run it as root on macOS/Linux or SYSTEM/Administrator on Windows. Do not use `curl | sh` for a security response workflow; pre-stage and integrity-check the file in your management platform.

macOS/Linux:

```bash
/bin/bash ./scripts/remediate-shai-hulud.sh
```

Windows (64-bit Windows PowerShell 5.1 or PowerShell 7):

```powershell
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\scripts\Remediate-ShaiHulud.ps1
```

Both commands remediate immediately and require no input. On Windows, launch the 64-bit PowerShell host so fixed-drive and profile discovery see the normal system registry view.

For offline or egress-restricted endpoints, pre-stage the IOC CSV with the script:

```bash
/bin/bash ./scripts/remediate-shai-hulud.sh --ioc-file ./keyv-packages.csv
```

```powershell
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\scripts\Remediate-ShaiHulud.ps1 -IocFile .\keyv-packages.csv
```

## Audit and targeted testing

Audit-only mode is non-mutating:

```bash
/bin/bash ./scripts/remediate-shai-hulud.sh --audit-only
```

```powershell
powershell.exe -NoProfile -NonInteractive -File .\scripts\Remediate-ShaiHulud.ps1 -AuditOnly
```

`--scan-root PATH` / `-ScanRoot PATH` restricts traversal, cache cleanup, and configuration changes to discovered projects beneath one or more test roots. This is useful for validation before fleet rollout and does not require elevation:

```bash
/bin/bash ./scripts/remediate-shai-hulud.sh --scan-root /tmp/remediation-fixture --report-dir /tmp/remediation-report --ioc-file ./keyv-packages.csv
```

```powershell
.\scripts\Remediate-ShaiHulud.ps1 -ScanRoot C:\remediation-fixture -ReportDirectory C:\remediation-report -IocFile .\keyv-packages.csv
```

## Reports and exit codes

The default report location is the active user's Desktop on macOS, the agent account's Desktop on Linux, and the Public Desktop on Windows. If that location is unavailable, the scripts use an OS-appropriate shared temporary/program-data directory. Override it with `--report-dir` or `-ReportDirectory`.

Each run creates:

- `Shai-Hulud-Remediation-<run-id>.log` — full activity and errors
- `Shai-Hulud-Dependencies-<run-id>.csv` — matched dependency declarations
- `Shai-Hulud-Persistence-<run-id>.csv` — removed (or would-remove) IDE hooks and worm payload files
- `Shai-Hulud-Config-Backups-<run-id>/` — pre-modification copies of every policy file the run rewrote, with `manifest.tsv`
- `Shai-Hulud-Remediation-<run-id>.json` — stable summary fields for RMM custom-field ingestion

To make the CSV safe to open in spreadsheet software, any report cell beginning with whitespace and a formula trigger (`=`, `+`, `-`, or `@`) is prefixed with an apostrophe. This affects display only; the JSON summary remains intended for automated ingestion.

Exit codes are designed for automation:

| Code | Meaning |
| ---: | --- |
| `0` | Completed without IOC declarations or operational errors |
| `10` | Attention required: IOC declarations found, worm IDE persistence found, or audit found cleanup work |
| `20` | Completed with one or more operational errors; inspect the log |
| `30` | Invocation error, unsupported OS, or full-disk run was not elevated |

Dependency declarations are reported rather than rewritten. Package version changes require application-owner review; after updating manifests/lockfiles to known-good releases, reinstall with lifecycle scripts still disabled and only re-enable scripts after the incident-response team approves it.

## Options

| macOS/Linux | Windows | Purpose |
| --- | --- | --- |
| `--audit-only` | `-AuditOnly` | Scan without modifying the endpoint |
| `--ioc-file PATH` | `-IocFile PATH` | Use a pre-staged IOC CSV |
| `--report-dir PATH` | `-ReportDirectory PATH` | Override report destination |
| `--scan-root PATH` | `-ScanRoot PATH` | Restrict scope; repeat/pass an array for multiple roots |
| `--help` | `Get-Help .\scripts\Remediate-ShaiHulud.ps1 -Full` | Display usage/help |

## Local validation

The bounded integration test creates an isolated temporary project, exercises remediation and audit modes through both Unix JSON-parser paths, verifies IDE-persistence removal (and audit preservation), covers the non-object-manifest scanner regression, checks idempotency, validates all report formats, and removes its temporary data:

```bash
./tests/test-remediate.sh
```

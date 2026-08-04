#requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$TestDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepositoryDirectory = Split-Path -Parent $TestDirectory
$ScriptPath = Join-Path $RepositoryDirectory 'scripts\Remediate-ShaiHulud.ps1'
$PowerShellExecutable = Join-Path $PSHOME (if ($PSVersionTable.PSEdition -eq 'Core') { 'pwsh.exe' } else { 'powershell.exe' })
$RunDirectory = Join-Path ([IO.Path]::GetTempPath()) "shai-hulud-test-$([Guid]::NewGuid().ToString('N'))"

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "Assertion failed: $Message" }
}

function Invoke-TestRemediation {
    param(
        [string]$ScanRoot,
        [string]$ReportDirectory,
        [string]$BackupDirectory,
        [switch]$AuditOnly,
        [string]$IocFile = (Join-Path $TestDirectory 'fixtures\iocs.csv')
    )
    $arguments = @(
        '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-File', $ScriptPath,
        '-ScanRoot', $ScanRoot,
        '-ReportDirectory', $ReportDirectory,
        '-BackupDirectory', $BackupDirectory,
        '-IocFile', $IocFile
    )
    if ($AuditOnly) { $arguments += '-AuditOnly' }
    & $PowerShellExecutable @arguments | Out-Null
    return $LASTEXITCODE
}

try {
    [void][IO.Directory]::CreateDirectory($RunDirectory)
    $project = Join-Path $RunDirectory 'project'
    Copy-Item -LiteralPath (Join-Path $TestDirectory 'fixtures\project') -Destination $project -Recurse
    [void][IO.Directory]::CreateDirectory((Join-Path $project 'node_modules\bad-package'))
    [void][IO.Directory]::CreateDirectory((Join-Path $project '.yarn\cache\archive'))

    $firstReports = Join-Path $RunDirectory 'reports'
    $firstBackups = Join-Path $RunDirectory 'backups'
    $firstExit = Invoke-TestRemediation $project $firstReports $firstBackups
    Assert-True ($firstExit -eq 10) "first remediation exit was $firstExit"
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $project 'node_modules'))) 'node_modules was not removed'
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $project '.yarn\cache'))) 'project Yarn cache was not removed'
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $project 'Math_Symbol.js'))) 'Math_Symbol.js was not removed'
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $project 'setup.mjs'))) 'referenced setup.mjs was not removed'

    $claudeConfig = Join-Path $project '.claude\settings.json'
    $vscodeConfig = Join-Path $project '.vscode\tasks.json'
    Assert-True (([IO.File]::ReadAllText($claudeConfig)) -notmatch 'setup\.mjs') 'Claude persistence was not removed'
    Assert-True (([IO.File]::ReadAllText($claudeConfig)) -match '"command"\s*:\s*"true"') 'unrelated Claude hook was removed'
    Assert-True (([IO.File]::ReadAllText($vscodeConfig)) -notmatch 'setup\.mjs') 'VS Code persistence was not removed'
    Assert-True (([IO.File]::ReadAllText($vscodeConfig)) -match 'pnpm build') 'unrelated VS Code task was removed'

    $firstSummaryPath = @(Get-ChildItem -LiteralPath $firstReports -Filter '*.json')[0].FullName
    $firstSummary = Get-Content -LiteralPath $firstSummaryPath -Raw | ConvertFrom-Json
    Assert-True ($firstSummary.node_modules_removed -eq 1) 'node_modules counter is incorrect'
    Assert-True ($firstSummary.caches_removed -eq 1) 'cache counter is incorrect'
    Assert-True ($firstSummary.configs_updated -eq 9) 'config counter is incorrect'
    Assert-True ($firstSummary.dependency_findings -eq 2) 'dependency counter is incorrect'
    Assert-True ($firstSummary.ide_hooks_removed -eq 2) 'IDE hook counter is incorrect'
    Assert-True ($firstSummary.persistence_artifacts_removed -eq 2) 'persistence artifact counter is incorrect'

    $persistenceCsv = @(Get-ChildItem -LiteralPath $firstReports -Filter '*Persistence*.csv')[0]
    $persistenceRows = @(Import-Csv -LiteralPath $persistenceCsv.FullName)
    Assert-True (@($persistenceRows | Where-Object { $_.Kind -eq 'claude-hook' -and $_.Action -eq 'removed' }).Count -eq 1) 'Claude report row is missing'
    Assert-True (@($persistenceRows | Where-Object { $_.Kind -eq 'vscode-task' -and $_.Action -eq 'removed' }).Count -eq 1) 'VS Code report row is missing'
    Assert-True (@($persistenceRows | Where-Object { $_.Kind -eq 'payload' -and $_.Action -eq 'removed' }).Count -eq 2) 'payload report rows are missing'

    $manifest = @(Get-ChildItem -LiteralPath $firstBackups -Filter 'manifest.tsv' -Recurse)[0]
    $manifestLines = @([IO.File]::ReadAllLines($manifest.FullName))
    Assert-True (@($manifestLines | Where-Object { $_ -like "RESTORE_FILE`t*" }).Count -eq 7) 'RESTORE_FILE manifest count is incorrect'
    Assert-True (@($manifestLines | Where-Object { $_ -like "DELETE_FILE`t*" }).Count -eq 4) 'DELETE_FILE manifest count is incorrect'
    Assert-True (@(Get-ChildItem -LiteralPath $firstBackups -Filter '*.bak' -Recurse).Count -eq 7) 'backup file count is incorrect'

    # Audit must report recreated persistence without changing it or creating backups.
    Copy-Item -LiteralPath (Join-Path $TestDirectory 'fixtures\project\.claude\settings.json') -Destination $claudeConfig -Force
    Copy-Item -LiteralPath (Join-Path $TestDirectory 'fixtures\project\.vscode\tasks.json') -Destination $vscodeConfig -Force
    [IO.File]::WriteAllText((Join-Path $project 'Math_Symbol.js'), '// recreated')
    [void][IO.Directory]::CreateDirectory((Join-Path $project 'node_modules\recreated'))
    $auditReports = Join-Path $RunDirectory 'audit-reports'
    $auditBackups = Join-Path $RunDirectory 'audit-backups'
    $auditExit = Invoke-TestRemediation $project $auditReports $auditBackups -AuditOnly
    Assert-True ($auditExit -eq 10) "audit exit was $auditExit"
    Assert-True (Test-Path -LiteralPath (Join-Path $project 'node_modules\recreated')) 'audit removed node_modules'
    Assert-True (Test-Path -LiteralPath (Join-Path $project 'Math_Symbol.js')) 'audit removed a persistence artifact'
    Assert-True (([IO.File]::ReadAllText($claudeConfig)) -match 'setup\.mjs') 'audit rewrote Claude settings'
    Assert-True (-not (Test-Path -LiteralPath $auditBackups)) 'audit created a backup directory'

    # Persistence by itself must produce the automation attention status.
    $persistenceOnly = Join-Path $RunDirectory 'persistence-only'
    [void][IO.Directory]::CreateDirectory((Join-Path $persistenceOnly '.claude'))
    Copy-Item -LiteralPath (Join-Path $TestDirectory 'fixtures\project\.claude\settings.json') -Destination (Join-Path $persistenceOnly '.claude\settings.json')
    Copy-Item -LiteralPath (Join-Path $TestDirectory 'fixtures\project\setup.mjs') -Destination (Join-Path $persistenceOnly 'setup.mjs')
    $persistenceOnlyExit = Invoke-TestRemediation $persistenceOnly (Join-Path $RunDirectory 'persistence-only-reports') (Join-Path $RunDirectory 'persistence-only-backups') -AuditOnly
    Assert-True ($persistenceOnlyExit -eq 10) "persistence-only audit exit was $persistenceOnlyExit"

    # Non-object package manifests must not stop valid manifests from being reported.
    $nonObjectRoot = Join-Path $RunDirectory 'non-object'
    [void][IO.Directory]::CreateDirectory((Join-Path $nonObjectRoot 'sub'))
    [void][IO.Directory]::CreateDirectory((Join-Path $nonObjectRoot 'sub2'))
    [IO.File]::WriteAllText((Join-Path $nonObjectRoot 'package.json'), '{"dependencies":{"bad-package":"1.2.3"}}')
    [IO.File]::WriteAllText((Join-Path $nonObjectRoot 'sub\package.json'), 'null')
    [IO.File]::WriteAllText((Join-Path $nonObjectRoot 'sub2\package.json'), '[]')
    $nonObjectReports = Join-Path $RunDirectory 'non-object-reports'
    $nonObjectExit = Invoke-TestRemediation $nonObjectRoot $nonObjectReports (Join-Path $RunDirectory 'non-object-backups')
    Assert-True ($nonObjectExit -eq 20) "non-object manifest exit was $nonObjectExit"
    $nonObjectSummary = Get-Content -LiteralPath (@(Get-ChildItem -LiteralPath $nonObjectReports -Filter '*.json')[0].FullName) -Raw | ConvertFrom-Json
    Assert-True ($nonObjectSummary.package_json_scanned -eq 3) 'not all package manifests were scanned'
    Assert-True ($nonObjectSummary.dependency_findings -eq 1) 'valid package manifest finding was lost'

    # Invalid IOC input must fail closed before cleanup or persistence changes.
    $invalidRoot = Join-Path $RunDirectory 'invalid-ioc-project'
    Copy-Item -LiteralPath (Join-Path $TestDirectory 'fixtures\project') -Destination $invalidRoot -Recurse
    [void][IO.Directory]::CreateDirectory((Join-Path $invalidRoot 'node_modules\keep'))
    $invalidExit = Invoke-TestRemediation $invalidRoot (Join-Path $RunDirectory 'invalid-reports') (Join-Path $RunDirectory 'invalid-backups') -IocFile (Join-Path $TestDirectory 'fixtures\invalid-iocs.csv')
    Assert-True ($invalidExit -eq 20) "invalid IOC exit was $invalidExit"
    Assert-True (Test-Path -LiteralPath (Join-Path $invalidRoot 'node_modules\keep')) 'invalid IOC run performed cleanup'
    Assert-True (Test-Path -LiteralPath (Join-Path $invalidRoot 'Math_Symbol.js')) 'invalid IOC run removed persistence'

    Write-Output 'Remediate-ShaiHulud.ps1 tests passed'
} finally {
    if ([IO.Directory]::Exists($RunDirectory)) { Remove-Item -LiteralPath $RunDirectory -Recurse -Force -ErrorAction SilentlyContinue }
}

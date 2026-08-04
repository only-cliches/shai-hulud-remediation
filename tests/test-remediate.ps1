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
        [switch]$IncludeApplicationDirectories,
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
    if ($IncludeApplicationDirectories) { $arguments += '-IncludeApplicationDirectories' }
    & $PowerShellExecutable @arguments | Out-Null
    return $LASTEXITCODE
}

try {
    [void][IO.Directory]::CreateDirectory($RunDirectory)
    $project = Join-Path $RunDirectory 'project'
    Copy-Item -LiteralPath (Join-Path $TestDirectory 'fixtures\project') -Destination $project -Recurse
    [void][IO.Directory]::CreateDirectory((Join-Path $project 'node_modules\bad-package'))
    [IO.File]::WriteAllText((Join-Path $project 'node_modules\bad-package\package.json'), '{"name":"bad-package","version":"1.2.3"}')
    [void][IO.Directory]::CreateDirectory((Join-Path $project '.yarn\cache\archive'))
    [void][IO.Directory]::CreateDirectory((Join-Path $project 'AppData\Local\ExcludedApp\node_modules\bad-package'))
    [IO.File]::WriteAllText((Join-Path $project 'AppData\Local\ExcludedApp\package.json'), '{"dependencies":{"bad-package":"1.2.3"}}')
    [IO.File]::WriteAllText((Join-Path $project 'AppData\Local\ExcludedApp\node_modules\bad-package\package.json'), '{"name":"bad-package","version":"1.2.3"}')
    [IO.File]::WriteAllText((Join-Path $project 'AppData\Local\ExcludedApp\Math_Symbol.js'), '// legitimate application file with an incident-like basename')
    [void][IO.Directory]::CreateDirectory((Join-Path $project 'subproject\node_modules\safe-package\node_modules\bad-package'))
    [IO.File]::WriteAllText((Join-Path $project 'subproject\node_modules\safe-package\node_modules\bad-package\package.json'), '{"name":"bad-package","version":"1.2.3"}')

    $firstReports = Join-Path $RunDirectory 'reports'
    $firstBackups = Join-Path $RunDirectory 'backups'
    $firstExit = Invoke-TestRemediation $project $firstReports $firstBackups
    Assert-True ($firstExit -eq 10) "first remediation exit was $firstExit"
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $project 'node_modules'))) 'node_modules was not removed'
    Assert-True (Test-Path -LiteralPath (Join-Path $project '.yarn\cache\archive')) 'unrelated project Yarn cache was removed'
    Assert-True (Test-Path -LiteralPath (Join-Path $project 'AppData\Local\ExcludedApp\node_modules\bad-package')) 'excluded application dependency tree was removed'
    Assert-True (Test-Path -LiteralPath (Join-Path $project 'AppData\Local\ExcludedApp\Math_Symbol.js')) 'incident-like file inside an excluded application directory was removed'
    Assert-True (Test-Path -LiteralPath (Join-Path $project 'subproject\node_modules\safe-package')) 'safe node_modules was removed'
    Assert-True (Test-Path -LiteralPath (Join-Path $project 'subproject\node_modules\safe-package\node_modules\bad-package')) 'nested transitive dependency caused a top-level tree removal'
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
    $firstLogPath = @(Get-ChildItem -LiteralPath $firstReports -Filter '*.log')[0].FullName
    $firstLogText = [IO.File]::ReadAllText($firstLogPath)
    Assert-True ($firstSummary.operational_errors -eq 0) 'unexpected operational errors in first remediation'
    Assert-True ($firstLogText -notmatch "Could not parse package manifest '.*Scanning filesystem") 'log output contaminated manifest scanning'
    Assert-True ($firstLogText -notmatch "config ''") 'empty configuration path was processed'
    Assert-True ($firstSummary.node_modules_removed -eq 1) 'node_modules counter is incorrect'
    Assert-True ($firstSummary.caches_removed -eq 0) 'cache counter is incorrect'
    Assert-True ($firstSummary.configs_updated -eq 0) 'config counter is incorrect'
    Assert-True ($firstSummary.dependency_findings -eq 2) 'dependency counter is incorrect'
    Assert-True ($firstSummary.ide_hooks_removed -eq 2) 'IDE hook counter is incorrect'
    Assert-True ($firstSummary.persistence_artifacts_removed -eq 2) 'persistence artifact counter is incorrect'

    $nodeModulesCsv = @(Get-ChildItem -LiteralPath $firstReports -Filter '*NodeModules*.csv')[0]
    $nodeModulesRows = @(Import-Csv -LiteralPath $nodeModulesCsv.FullName)
    Assert-True (@($nodeModulesRows | Where-Object { $_.Action -eq 'removed' }).Count -eq 1) 'node_modules removal report row is missing'
    $dependencyRows = @(Import-Csv -LiteralPath (@(Get-ChildItem -LiteralPath $firstReports -Filter '*Dependencies*.csv')[0].FullName))
    Assert-True (@($dependencyRows | Where-Object { $_.Package -eq 'bad-package' -and $_.'Installed Status' -eq 'malicious' }).Count -eq 1) 'malicious installed dependency status is missing'
    Assert-True (@($dependencyRows | Where-Object { $_.Manifest -like '*AppData*ExcludedApp*' }).Count -eq 0) 'excluded application manifest was scanned'

    foreach ($configName in @('.npmrc','.yarnrc','.yarnrc.yml','.bunfig.toml','pnpm-workspace.yaml')) {
        Assert-True ([IO.File]::ReadAllText((Join-Path $project $configName)) -eq [IO.File]::ReadAllText((Join-Path $TestDirectory "fixtures\project\$configName"))) "unrelated config was changed: $configName"
    }

    $persistenceCsv = @(Get-ChildItem -LiteralPath $firstReports -Filter '*Persistence*.csv')[0]
    $persistenceRows = @(Import-Csv -LiteralPath $persistenceCsv.FullName)
    Assert-True (@($persistenceRows | Where-Object { $_.Kind -eq 'claude-hook' -and $_.Action -eq 'removed' }).Count -eq 1) 'Claude report row is missing'
    Assert-True (@($persistenceRows | Where-Object { $_.Kind -eq 'vscode-task' -and $_.Action -eq 'removed' }).Count -eq 1) 'VS Code report row is missing'
    Assert-True (@($persistenceRows | Where-Object { $_.Kind -eq 'payload' -and $_.Action -eq 'removed' }).Count -eq 2) 'payload report rows are missing'

    $manifest = @(Get-ChildItem -LiteralPath $firstBackups -Filter 'manifest.tsv' -Recurse)[0]
    $manifestLines = @([IO.File]::ReadAllLines($manifest.FullName))
    Assert-True (@($manifestLines | Where-Object { $_ -like "RESTORE_FILE`t*" }).Count -eq 2) 'RESTORE_FILE manifest count is incorrect'
    Assert-True (@($manifestLines | Where-Object { $_ -like "DELETE_FILE`t*" }).Count -eq 0) 'DELETE_FILE manifest count is incorrect'
    Assert-True (@(Get-ChildItem -LiteralPath $firstBackups -Filter '*.bak' -Recurse).Count -eq 2) 'backup file count is incorrect'

    # Operators can deliberately include a known application tree when the
    # incident scope requires it.
    $includeAppRoot = Join-Path $RunDirectory 'include-app'
    [void][IO.Directory]::CreateDirectory((Join-Path $includeAppRoot 'AppData\Local\Actionable\node_modules\bad-package'))
    [IO.File]::WriteAllText((Join-Path $includeAppRoot 'AppData\Local\Actionable\package.json'), '{"dependencies":{"bad-package":"1.2.3"}}')
    [IO.File]::WriteAllText((Join-Path $includeAppRoot 'AppData\Local\Actionable\node_modules\bad-package\package.json'), '{"name":"bad-package","version":"1.2.3"}')
    $includeAppReports = Join-Path $RunDirectory 'include-app-reports'
    $includeAppExit = Invoke-TestRemediation $includeAppRoot $includeAppReports (Join-Path $RunDirectory 'include-app-backups') -IncludeApplicationDirectories
    Assert-True ($includeAppExit -eq 10) "include-app remediation exit was $includeAppExit"
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $includeAppRoot 'AppData\Local\Actionable\node_modules'))) 'application-directory override did not remove an actionable dependency tree'

    # Audit must report recreated persistence without changing it or creating backups.
    Copy-Item -LiteralPath (Join-Path $TestDirectory 'fixtures\project\.claude\settings.json') -Destination $claudeConfig -Force
    Copy-Item -LiteralPath (Join-Path $TestDirectory 'fixtures\project\.vscode\tasks.json') -Destination $vscodeConfig -Force
    [IO.File]::WriteAllText((Join-Path $project 'Math_Symbol.js'), '// recreated')
    [void][IO.Directory]::CreateDirectory((Join-Path $project 'node_modules\bad-package'))
    [IO.File]::WriteAllText((Join-Path $project 'node_modules\bad-package\package.json'), '{"name":"bad-package","version":"1.2.3"}')
    $auditReports = Join-Path $RunDirectory 'audit-reports'
    $auditBackups = Join-Path $RunDirectory 'audit-backups'
    $auditExit = Invoke-TestRemediation $project $auditReports $auditBackups -AuditOnly
    Assert-True ($auditExit -eq 10) "audit exit was $auditExit"
    Assert-True (Test-Path -LiteralPath (Join-Path $project 'node_modules\bad-package')) 'audit removed node_modules'
    Assert-True (Test-Path -LiteralPath (Join-Path $project 'Math_Symbol.js')) 'audit removed a persistence artifact'
    Assert-True (([IO.File]::ReadAllText($claudeConfig)) -match 'setup\.mjs') 'audit rewrote Claude settings'
    Assert-True (-not (Test-Path -LiteralPath $auditBackups)) 'audit created a backup directory'
    $auditNodeModulesRows = @(Import-Csv -LiteralPath (@(Get-ChildItem -LiteralPath $auditReports -Filter '*NodeModules*.csv')[0].FullName))
    Assert-True (@($auditNodeModulesRows | Where-Object { $_.Action -eq 'would-remove' }).Count -eq 1) 'audit node_modules report row is missing'

    # Persistence by itself must produce the automation attention status.
    $persistenceOnly = Join-Path $RunDirectory 'persistence-only'
    [void][IO.Directory]::CreateDirectory((Join-Path $persistenceOnly '.claude'))
    Copy-Item -LiteralPath (Join-Path $TestDirectory 'fixtures\project\.claude\settings.json') -Destination (Join-Path $persistenceOnly '.claude\settings.json')
    Copy-Item -LiteralPath (Join-Path $TestDirectory 'fixtures\project\setup.mjs') -Destination (Join-Path $persistenceOnly 'setup.mjs')
    $persistenceOnlyExit = Invoke-TestRemediation $persistenceOnly (Join-Path $RunDirectory 'persistence-only-reports') (Join-Path $RunDirectory 'persistence-only-backups') -AuditOnly
    Assert-True ($persistenceOnlyExit -eq 10) "persistence-only audit exit was $persistenceOnlyExit"

    # A known installed version absent from the IOC list is reported but retained.
    $safeVersionRoot = Join-Path $RunDirectory 'safe-version'
    [void][IO.Directory]::CreateDirectory((Join-Path $safeVersionRoot 'node_modules\bad-package'))
    [IO.File]::WriteAllText((Join-Path $safeVersionRoot 'package.json'), '{"dependencies":{"bad-package":"*"}}')
    [IO.File]::WriteAllText((Join-Path $safeVersionRoot 'node_modules\bad-package\package.json'), '{"name":"bad-package","version":"9.9.9"}')
    $safeVersionReports = Join-Path $RunDirectory 'safe-version-reports'
    $safeVersionExit = Invoke-TestRemediation $safeVersionRoot $safeVersionReports (Join-Path $RunDirectory 'safe-version-backups')
    Assert-True ($safeVersionExit -eq 10) "safe-version remediation exit was $safeVersionExit"
    Assert-True (Test-Path -LiteralPath (Join-Path $safeVersionRoot 'node_modules\bad-package')) 'known-safe installed version was removed'
    $safeVersionFinding = @(Import-Csv -LiteralPath (@(Get-ChildItem -LiteralPath $safeVersionReports -Filter '*Dependencies*.csv')[0].FullName))[0]
    Assert-True ($safeVersionFinding.'Installed Status' -eq 'not-listed') 'known-safe installed version status is incorrect'
    $safeVersionActions = @(Import-Csv -LiteralPath (@(Get-ChildItem -LiteralPath $safeVersionReports -Filter '*NodeModules*.csv')[0].FullName))
    Assert-True ($safeVersionActions.Count -eq 0) 'known-safe installed version produced a removal action'

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

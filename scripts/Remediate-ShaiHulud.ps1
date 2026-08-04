#requires -Version 5.1
<#
.SYNOPSIS
Unattended Shai Hulud / Keyv supply-chain remediation for Windows.

.DESCRIPTION
Remediation is the default. Use -AuditOnly for a read-only assessment. The
script is designed for SYSTEM execution by RMM and EDR tools and never prompts.
#>
[CmdletBinding()]
param(
    [switch]$AuditOnly,
    [string]$IocFile,
    [string]$ReportDirectory,
    [string[]]$ScanRoot
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'
$ToolVersion = '1.0.1'
$IocUrl = 'https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/refs/heads/main/reports/keyv-packages.csv'
$Mode = if ($AuditOnly) { 'audit' } else { 'remediate' }
$CustomScope = $null -ne $ScanRoot -and $ScanRoot.Count -gt 0
$Stats = [ordered]@{
    node_modules_found = 0
    node_modules_removed = 0
    caches_found = 0
    caches_removed = 0
    configs_needing_change = 0
    configs_updated = 0
    package_json_scanned = 0
    dependency_findings = 0
    operational_errors = 0
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not $CustomScope -and -not (Test-IsAdministrator)) {
    Write-Error 'Full-disk operation requires Administrator or SYSTEM.'
    exit 30
}
if ($CustomScope) {
    $validatedRoots = New-Object 'System.Collections.Generic.List[string]'
    foreach ($root in $ScanRoot) {
        try {
            if (-not [IO.Path]::IsPathRooted($root)) { throw 'Path must be absolute' }
            $fullRoot = [IO.Path]::GetFullPath($root)
            if (-not [IO.Directory]::Exists($fullRoot)) { throw 'Directory does not exist' }
            $validatedRoots.Add($fullRoot)
        } catch {
            Write-Error "Invalid -ScanRoot '$root': $($_.Exception.Message)"
            exit 30
        }
    }
    $ScanRoot = @($validatedRoots)
}

if ([string]::IsNullOrWhiteSpace($ReportDirectory)) {
    $ReportDirectory = [Environment]::GetFolderPath('CommonDesktopDirectory')
    if ([string]::IsNullOrWhiteSpace($ReportDirectory)) {
        $ReportDirectory = Join-Path $env:ProgramData 'Shai-Hulud-Remediation'
    }
}
try {
    [void][IO.Directory]::CreateDirectory($ReportDirectory)
} catch {
    Write-Error "Cannot create report directory '$ReportDirectory': $($_.Exception.Message)"
    exit 30
}

$RunId = '{0}-{1}' -f ([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')), $PID
$ReportFile = Join-Path $ReportDirectory "Shai-Hulud-Remediation-$RunId.log"
$SummaryFile = Join-Path $ReportDirectory "Shai-Hulud-Remediation-$RunId.json"
$FindingsFile = Join-Path $ReportDirectory "Shai-Hulud-Dependencies-$RunId.csv"
$WorkingDirectory = Join-Path ([IO.Path]::GetTempPath()) "shai-hulud-$([Guid]::NewGuid().ToString('N'))"
try {
    [void][IO.Directory]::CreateDirectory($WorkingDirectory)
    [IO.File]::WriteAllText($ReportFile, '', (New-Object Text.UTF8Encoding($false)))
} catch {
    Write-Error "Cannot initialize remediation files: $($_.Exception.Message)"
    exit 30
}

function Write-Log {
    param([string]$Level, [string]$Message)
    $line = '{0} [{1}] {2}' -f ([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')), $Level, $Message
    Write-Output $line
    try { [IO.File]::AppendAllText($script:ReportFile, $line + [Environment]::NewLine, (New-Object Text.UTF8Encoding($false))) } catch {}
}

function Add-OperationalError {
    param([string]$Message)
    $script:Stats.operational_errors++
    Write-Log 'ERROR' $Message
}

function Remove-RemediationDirectory {
    param([string]$Path, [ValidateSet('node_modules','package cache','project package cache')][string]$Kind)
    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    } catch { return }
    $isReparsePoint = ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
    if (-not $item.PSIsContainer -and -not $isReparsePoint) {
        Add-OperationalError "Safety check rejected non-directory $Kind target '$Path'"
        return
    }
    if ($Kind -eq 'node_modules') { $script:Stats.node_modules_found++ } else { $script:Stats.caches_found++ }
    if ($script:Mode -eq 'audit') {
        Write-Log 'AUDIT' "Would remove ${Kind}: $Path"
        return
    }
    try {
        if ($isReparsePoint) {
            Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
        } else {
            Remove-Item -LiteralPath $Path -Force -Recurse -ErrorAction Stop
        }
        if (Test-Path -LiteralPath $Path) { throw 'Target still exists after removal' }
        if ($Kind -eq 'node_modules') { $script:Stats.node_modules_removed++ } else { $script:Stats.caches_removed++ }
        Write-Log 'INFO' "Removed ${Kind}: $Path"
    } catch {
        Add-OperationalError "Failed to remove $Kind '$Path': $($_.Exception.Message)"
    }
}

function Get-LocalScanRoots {
    if ($script:CustomScope) {
        foreach ($root in $script:ScanRoot) {
            try {
                $full = [IO.Path]::GetFullPath($root)
                if (-not [IO.Directory]::Exists($full)) { throw 'Directory does not exist' }
                $full
            } catch {
                Add-OperationalError "Invalid scan root '$root': $($_.Exception.Message)"
            }
        }
        return
    }
    try {
        @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop | ForEach-Object { "$($_.DeviceID)\" })
    } catch {
        Write-Log 'WARN' "Could not enumerate fixed drives with CIM; using SystemDrive: $($_.Exception.Message)"
        "$env:SystemDrive\"
    }
}

function Get-UserProfiles {
    $profiles = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    if ($script:CustomScope) { return $profiles }
    try {
        Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' -ErrorAction Stop | ForEach-Object {
            $path = [Environment]::ExpandEnvironmentVariables([string]$_.ProfileImagePath)
            if ([IO.Directory]::Exists($path)) { [void]$profiles.Add([IO.Path]::GetFullPath($path)) }
        }
    } catch {
        Add-OperationalError "Could not enumerate profile registry entries: $($_.Exception.Message)"
    }
    if ([IO.Directory]::Exists("$env:SystemDrive\Users")) {
        try {
            [IO.Directory]::EnumerateDirectories("$env:SystemDrive\Users") | ForEach-Object { [void]$profiles.Add($_) }
        } catch { Add-OperationalError "Could not enumerate user profiles: $($_.Exception.Message)" }
    }
    return $profiles
}

function Get-TreeInventory {
    param([string[]]$Roots)
    $manifests = New-Object 'System.Collections.Generic.List[string]'
    foreach ($root in $Roots) {
        Write-Log 'INFO' "Scanning filesystem: $root"
        $stack = New-Object 'System.Collections.Generic.Stack[string]'
        $stack.Push($root)
        while ($stack.Count -gt 0) {
            $current = $stack.Pop()
            $manifest = Join-Path $current 'package.json'
            if ([IO.File]::Exists($manifest)) { $manifests.Add($manifest) }
            try {
                foreach ($directoryPath in [IO.Directory]::EnumerateDirectories($current)) {
                    $directory = New-Object IO.DirectoryInfo($directoryPath)
                    if ($directory.Name -ieq 'node_modules') {
                        Remove-RemediationDirectory $directory.FullName 'node_modules'
                        continue
                    }
                    if ($directory.Name -ieq '.pnpm-store' -or
                        ($directory.Name -ieq 'cache' -and $directory.Parent.Name -ieq '.yarn')) {
                        Remove-RemediationDirectory $directory.FullName 'project package cache'
                        continue
                    }
                    if (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
                    $stack.Push($directory.FullName)
                }
            } catch [System.UnauthorizedAccessException] {
                Add-OperationalError "Access denied while scanning '$current'"
            } catch [System.IO.IOException] {
                Add-OperationalError "I/O error while scanning '$current': $($_.Exception.Message)"
            } catch {
                Add-OperationalError "Could not scan '$current': $($_.Exception.Message)"
            }
        }
    }
    return $manifests
}

function Remove-KnownCaches {
    param($Profiles)
    if ($script:CustomScope) { return }
    foreach ($profile in $Profiles) {
        $paths = @(
            (Join-Path $profile '.npm'),
            (Join-Path $profile '.npm-cache'),
            (Join-Path $profile '.pnpm-store'),
            (Join-Path $profile '.cache\pnpm'),
            (Join-Path $profile '.cache\yarn'),
            (Join-Path $profile '.cache\node\corepack'),
            (Join-Path $profile '.yarn\cache'),
            (Join-Path $profile '.bun\install\cache'),
            (Join-Path $profile 'AppData\Local\npm-cache'),
            (Join-Path $profile 'AppData\Local\pnpm\store'),
            (Join-Path $profile 'AppData\Local\Yarn\Cache'),
            (Join-Path $profile 'AppData\Local\node\corepack'),
            (Join-Path $profile 'AppData\Local\node-gyp\Cache'),
            (Join-Path $profile 'AppData\Local\bun\install\cache')
        )
        foreach ($path in $paths) { Remove-RemediationDirectory $path 'package cache' }
    }
    foreach ($path in @(
        (Join-Path $env:ProgramData 'npm-cache'),
        (Join-Path $env:ProgramData 'pnpm\store'),
        (Join-Path $env:ProgramData 'Yarn\Cache')
    )) { Remove-RemediationDirectory $path 'package cache' }
}

function Set-TextConfig {
    param(
        [string]$Path,
        [string]$MatchPattern,
        [string]$CorrectPattern,
        [string]$Replacement,
        [string]$Label
    )
    $lines = @()
    if ([IO.File]::Exists($Path)) {
        try { $lines = @([IO.File]::ReadAllLines($Path)) } catch { Add-OperationalError "Cannot read config '$Path': $($_.Exception.Message)"; return }
    }
    $matchingLines = @($lines | Where-Object { $_ -match $MatchPattern })
    if ($matchingLines.Count -gt 0 -and @($matchingLines | Where-Object { $_ -notmatch $CorrectPattern }).Count -eq 0) { return }
    $script:Stats.configs_needing_change++
    if ($script:Mode -eq 'audit') { Write-Log 'AUDIT' "Would enforce $Label in $Path"; return }
    $newLines = New-Object 'System.Collections.Generic.List[string]'
    $found = $false
    foreach ($line in $lines) {
        if ($line -match $MatchPattern) {
            if (-not $found) { $newLines.Add($Replacement); $found = $true }
        } else { $newLines.Add($line) }
    }
    if (-not $found) { $newLines.Add($Replacement) }
    try {
        $parent = Split-Path -Parent $Path
        if (-not [string]::IsNullOrWhiteSpace($parent)) { [void][IO.Directory]::CreateDirectory($parent) }
        [IO.File]::WriteAllLines($Path, $newLines, (New-Object Text.UTF8Encoding($false)))
        $script:Stats.configs_updated++
        Write-Log 'INFO' "Enforced $Label in $Path"
    } catch { Add-OperationalError "Failed to update config '$Path': $($_.Exception.Message)" }
}

function Set-BunConfig {
    param([string]$Path)
    $lines = @()
    if ([IO.File]::Exists($Path)) {
        try { $lines = @([IO.File]::ReadAllLines($Path)) } catch { Add-OperationalError "Cannot read Bun config '$Path': $($_.Exception.Message)"; return }
    }
    $inside = $false
    $matchingLines = 0
    $unsafeLines = 0
    foreach ($line in $lines) {
        if ($line -match '^\s*\[install\]\s*$') { $inside = $true; continue }
        if ($line -match '^\s*\[') { $inside = $false }
        if ($inside -and $line -match '^\s*ignoreScripts\s*=') {
            $matchingLines++
            if ($line -notmatch '^\s*ignoreScripts\s*=\s*true\s*(?:#.*)?$') { $unsafeLines++ }
        }
    }
    if ($matchingLines -gt 0 -and $unsafeLines -eq 0) { return }
    $script:Stats.configs_needing_change++
    if ($script:Mode -eq 'audit') { Write-Log 'AUDIT' "Would disable Bun lifecycle scripts in $Path"; return }
    $result = New-Object 'System.Collections.Generic.List[string]'
    $inside = $false; $sectionFound = $false; $written = $false
    foreach ($line in $lines) {
        if ($line -match '^\s*\[install\]\s*$') {
            $inside = $true; $sectionFound = $true; $result.Add($line); continue
        }
        if ($line -match '^\s*\[') {
            if ($inside -and -not $written) { $result.Add('ignoreScripts = true'); $written = $true }
            $inside = $false
        }
        if ($inside -and $line -match '^\s*ignoreScripts\s*=') {
            if (-not $written) { $result.Add('ignoreScripts = true'); $written = $true }
            continue
        }
        $result.Add($line)
    }
    if ($inside -and -not $written) { $result.Add('ignoreScripts = true'); $written = $true }
    if (-not $sectionFound) { $result.Add(''); $result.Add('[install]'); $result.Add('ignoreScripts = true') }
    try {
        $parent = Split-Path -Parent $Path
        if (-not [string]::IsNullOrWhiteSpace($parent)) { [void][IO.Directory]::CreateDirectory($parent) }
        [IO.File]::WriteAllLines($Path, $result, (New-Object Text.UTF8Encoding($false)))
        $script:Stats.configs_updated++
        Write-Log 'INFO' "Disabled Bun lifecycle scripts in $Path"
    } catch { Add-OperationalError "Failed to update Bun config '$Path': $($_.Exception.Message)" }
}

function Protect-ConfigDirectory {
    param([string]$Directory)
    Set-TextConfig (Join-Path $Directory '.npmrc') '^\s*ignore-scripts\s*=' '^\s*ignore-scripts\s*=\s*true\s*$' 'ignore-scripts=true' 'npm/pnpm lifecycle-script blocking'
    Set-TextConfig (Join-Path $Directory '.yarnrc') '^\s*--install\.ignore-scripts\s+' '^\s*--install\.ignore-scripts\s+true\s*$' '--install.ignore-scripts true' 'Yarn Classic lifecycle-script blocking'
    Set-TextConfig (Join-Path $Directory '.yarnrc.yml') '^\s*enableScripts\s*:' '^\s*enableScripts\s*:\s*false\s*$' 'enableScripts: false' 'Yarn lifecycle-script blocking'
    Set-BunConfig (Join-Path $Directory '.bunfig.toml')
}

function Protect-LifecycleScripts {
    param($Profiles, [string[]]$Manifests)
    if (-not $script:CustomScope) {
        if ($script:Mode -eq 'audit') {
            if ([Environment]::GetEnvironmentVariable('NPM_CONFIG_IGNORE_SCRIPTS', 'Machine') -ne 'true') { $script:Stats.configs_needing_change++; Write-Log 'AUDIT' 'Would set machine NPM_CONFIG_IGNORE_SCRIPTS=true' }
            if ([Environment]::GetEnvironmentVariable('YARN_ENABLE_SCRIPTS', 'Machine') -ne 'false') { $script:Stats.configs_needing_change++; Write-Log 'AUDIT' 'Would set machine YARN_ENABLE_SCRIPTS=false' }
        } else {
            if ([Environment]::GetEnvironmentVariable('NPM_CONFIG_IGNORE_SCRIPTS', 'Machine') -ne 'true') {
                $script:Stats.configs_needing_change++
                try { [Environment]::SetEnvironmentVariable('NPM_CONFIG_IGNORE_SCRIPTS', 'true', 'Machine'); $script:Stats.configs_updated++; Write-Log 'INFO' 'Set machine NPM_CONFIG_IGNORE_SCRIPTS=true' } catch { Add-OperationalError "Could not set machine npm policy: $($_.Exception.Message)" }
            }
            if ([Environment]::GetEnvironmentVariable('YARN_ENABLE_SCRIPTS', 'Machine') -ne 'false') {
                $script:Stats.configs_needing_change++
                try { [Environment]::SetEnvironmentVariable('YARN_ENABLE_SCRIPTS', 'false', 'Machine'); $script:Stats.configs_updated++; Write-Log 'INFO' 'Set machine YARN_ENABLE_SCRIPTS=false' } catch { Add-OperationalError "Could not set machine Yarn policy: $($_.Exception.Message)" }
            }
        }
        Set-TextConfig (Join-Path $env:ProgramData 'npm\etc\npmrc') '^\s*ignore-scripts\s*=' '^\s*ignore-scripts\s*=\s*true\s*$' 'ignore-scripts=true' 'system npm/pnpm lifecycle-script blocking'
        foreach ($profile in $Profiles) { Protect-ConfigDirectory $profile }
    }
    $projectDirectories = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($manifest in $Manifests) { [void]$projectDirectories.Add((Split-Path -Parent $manifest)) }
    foreach ($directory in $projectDirectories) { Protect-ConfigDirectory $directory }
}

function Get-IocRows {
    if (-not [string]::IsNullOrWhiteSpace($script:IocFile)) {
        if (-not [IO.File]::Exists($script:IocFile)) { Add-OperationalError "IOC file does not exist: $($script:IocFile)"; return @() }
        $path = $script:IocFile
    } else {
        $path = Join-Path $script:WorkingDirectory 'keyv-packages.csv'
        try {
            Invoke-WebRequest -Uri $script:IocUrl -OutFile $path -UseBasicParsing -TimeoutSec 60 -ErrorAction Stop
        } catch {
            Add-OperationalError "Could not download IOC list; use -IocFile for offline execution: $($_.Exception.Message)"
            return @()
        }
    }
    try {
        $rows = @(Import-Csv -LiteralPath $path -ErrorAction Stop)
        if ($rows.Count -eq 0 -or -not ($rows[0].PSObject.Properties.Name -contains 'Package') -or -not ($rows[0].PSObject.Properties.Name -contains 'Malicious Versions')) { throw 'Unexpected CSV header' }
        return $rows
    } catch { Add-OperationalError "Invalid IOC CSV '$path': $($_.Exception.Message)"; return @() }
}

function Find-VulnerableDeclarations {
    param([string[]]$Manifests, $IocRows)
    $iocMap = @{}
    foreach ($row in $IocRows) { $iocMap[[string]$row.Package] = [string]$row.'Malicious Versions' }
    $findings = New-Object 'System.Collections.Generic.List[object]'
    foreach ($manifestPath in $Manifests) {
        $script:Stats.package_json_scanned++
        try {
            $manifest = Get-Content -LiteralPath $manifestPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        } catch {
            Add-OperationalError "Could not parse package manifest '$manifestPath': $($_.Exception.Message)"
            continue
        }
        foreach ($section in @('dependencies','devDependencies','optionalDependencies','peerDependencies')) {
            $property = $manifest.PSObject.Properties[$section]
            if ($null -eq $property -or $null -eq $property.Value) { continue }
            foreach ($dependency in $property.Value.PSObject.Properties) {
                if (-not $iocMap.ContainsKey($dependency.Name)) { continue }
                $declared = [string]$dependency.Value
                $badVersions = @($iocMap[$dependency.Name] -split ',' | ForEach-Object { $_.Trim() })
                $normalized = $declared.Trim().TrimStart('=','v')
                $confidence = if ($badVersions -contains $normalized) { 'exact' } else { 'review-range' }
                $findings.Add([PSCustomObject][ordered]@{
                    Manifest = $manifestPath
                    Section = $section
                    Package = $dependency.Name
                    Declared = $declared
                    'Malicious Versions' = $iocMap[$dependency.Name]
                    Match = $confidence
                })
            }
        }
    }
    $script:Stats.dependency_findings = $findings.Count
    return $findings
}

function ConvertTo-CsvSafeValue {
    param($Value)
    $text = [string]$Value
    if ($text -match '^\s*[=+\-@]') { return "'$text" }
    return $text
}

function Export-DependencyFindings {
    param([object[]]$Findings, [string]$Path)
    if ($Findings.Count -eq 0) {
        [IO.File]::WriteAllText($Path, '"Manifest","Section","Package","Declared","Malicious Versions","Match"' + [Environment]::NewLine, (New-Object Text.UTF8Encoding($false)))
        return
    }
    $Findings | ForEach-Object {
        [PSCustomObject][ordered]@{
            Manifest = ConvertTo-CsvSafeValue $_.Manifest
            Section = ConvertTo-CsvSafeValue $_.Section
            Package = ConvertTo-CsvSafeValue $_.Package
            Declared = ConvertTo-CsvSafeValue $_.Declared
            'Malicious Versions' = ConvertTo-CsvSafeValue $_.'Malicious Versions'
            Match = ConvertTo-CsvSafeValue $_.Match
        }
    } | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8 -Force -ErrorAction Stop
}

try {
    Write-Log 'INFO' "Shai Hulud remediation v$ToolVersion started (mode=$Mode, host=$env:COMPUTERNAME, user=$env:USERNAME)"
    Write-Log 'INFO' "Report: $ReportFile"
    $Roots = @(Get-LocalScanRoots | Select-Object -Unique)
    if ($Roots.Count -eq 0) { Add-OperationalError 'No scan roots were discovered.' }
    $Profiles = Get-UserProfiles
    $Manifests = @(Get-TreeInventory $Roots | Select-Object -Unique)
    Remove-KnownCaches $Profiles
    Protect-LifecycleScripts $Profiles $Manifests
    $IocRows = @(Get-IocRows)
    $Findings = @(Find-VulnerableDeclarations $Manifests $IocRows)
    try {
        Export-DependencyFindings $Findings $FindingsFile
        Write-Log 'INFO' "Dependency report: $FindingsFile"
    } catch { Add-OperationalError "Could not publish dependency report: $($_.Exception.Message)" }
} catch {
    Add-OperationalError "Unhandled remediation error: $($_.Exception.Message)"
}

$AuditWork = $Stats.node_modules_found + $Stats.caches_found + $Stats.configs_needing_change
$ExitCode = 0
$Status = 'completed'
if ($Stats.operational_errors -gt 0) { $ExitCode = 20; $Status = 'completed_with_errors' }
elseif ($Stats.dependency_findings -gt 0 -or ($Mode -eq 'audit' -and $AuditWork -gt 0)) { $ExitCode = 10; $Status = 'attention_required' }

$summary = [ordered]@{
    schema_version = 1
    tool_version = $ToolVersion
    run_id = $RunId
    mode = $Mode
    status = $Status
    exit_code = $ExitCode
}
foreach ($entry in $Stats.GetEnumerator()) { $summary[$entry.Key] = $entry.Value }
try { [IO.File]::WriteAllText($SummaryFile, ($summary | ConvertTo-Json), (New-Object Text.UTF8Encoding($false))) } catch { Write-Log 'ERROR' "Could not write summary JSON: $($_.Exception.Message)"; $ExitCode = 20 }

Write-Log 'SUMMARY' "status=$Status exit_code=$ExitCode node_modules_found=$($Stats.node_modules_found) node_modules_removed=$($Stats.node_modules_removed) caches_found=$($Stats.caches_found) caches_removed=$($Stats.caches_removed) configs_needed=$($Stats.configs_needing_change) configs_updated=$($Stats.configs_updated) manifests_scanned=$($Stats.package_json_scanned) dependency_findings=$($Stats.dependency_findings) errors=$($Stats.operational_errors)"
Write-Log 'INFO' "Machine-readable summary: $SummaryFile"
try { Remove-Item -LiteralPath $WorkingDirectory -Recurse -Force -ErrorAction SilentlyContinue } catch {}
exit $ExitCode

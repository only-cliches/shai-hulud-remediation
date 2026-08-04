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
    [string]$BackupDirectory,
    [string[]]$ScanRoot
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'
$ToolVersion = '2.2.0'
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
    ide_hooks_scanned = 0
    ide_hooks_found = 0
    ide_hooks_removed = 0
    persistence_artifacts_found = 0
    persistence_artifacts_removed = 0
    operational_errors = 0
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-IsSafeDirectoryPath {
    param([string]$Path)
    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        return $item.PSIsContainer -and (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0)
    } catch { return $false }
}

$IsAdministrator = Test-IsAdministrator
if (-not $CustomScope -and -not $IsAdministrator) {
    Write-Error 'Default-scope remediation requires Administrator or SYSTEM.'
    exit 30
}
if ($CustomScope) {
    $validatedRoots = New-Object 'System.Collections.Generic.List[string]'
    foreach ($root in $ScanRoot) {
        try {
            if (-not [IO.Path]::IsPathRooted($root)) { throw 'Path must be absolute' }
            $fullRoot = [IO.Path]::GetFullPath($root)
            if (-not (Test-IsSafeDirectoryPath $fullRoot)) { throw 'Directory does not exist or is a reparse point' }
            $validatedRoots.Add($fullRoot)
        } catch {
            Write-Error "Invalid -ScanRoot '$root': $($_.Exception.Message)"
            exit 30
        }
    }
    $ScanRoot = @($validatedRoots)
}
if (-not [string]::IsNullOrWhiteSpace($BackupDirectory) -and -not [IO.Path]::IsPathRooted($BackupDirectory)) {
    Write-Error '-BackupDirectory must be an absolute path.'
    exit 30
}

function Set-PrivateDirectoryAcl {
    param([string]$Path, [bool]$AdministratorScope)
    try {
        $security = New-Object Security.AccessControl.DirectorySecurity
        $security.SetAccessRuleProtection($true, $false)
        $inheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
        $propagation = [Security.AccessControl.PropagationFlags]::None
        $allow = [Security.AccessControl.AccessControlType]::Allow
        $identities = if ($AdministratorScope) {
            @((New-Object Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-18'), (New-Object Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-32-544'))
        } else {
            @([Security.Principal.WindowsIdentity]::GetCurrent().User)
        }
        foreach ($identity in $identities) {
            $rule = New-Object Security.AccessControl.FileSystemAccessRule($identity, [Security.AccessControl.FileSystemRights]::FullControl, $inheritance, $propagation, $allow)
            [void]$security.AddAccessRule($rule)
        }
        Set-Acl -LiteralPath $Path -AclObject $security -ErrorAction Stop
    } catch {
        throw "Could not restrict directory '$Path': $($_.Exception.Message)"
    }
}

$UsingDefaultReportDirectory = [string]::IsNullOrWhiteSpace($ReportDirectory)
if ($UsingDefaultReportDirectory) {
    $stateRoot = if ($IsAdministrator) { $env:ProgramData } elseif (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) { $env:LOCALAPPDATA } else { [IO.Path]::GetTempPath() }
    $ReportDirectory = Join-Path $stateRoot 'Shai-Hulud-Remediation\Reports'
}
try {
    [void][IO.Directory]::CreateDirectory($ReportDirectory)
    if (-not (Test-IsSafeDirectoryPath $ReportDirectory)) { throw 'Report directory is a reparse point' }
    if ($UsingDefaultReportDirectory) { Set-PrivateDirectoryAcl $ReportDirectory $IsAdministrator }
} catch {
    Write-Error "Cannot create report directory '$ReportDirectory': $($_.Exception.Message)"
    exit 30
}

$RunId = '{0}-{1}' -f ([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')), $PID
$ReportFile = Join-Path $ReportDirectory "Shai-Hulud-Remediation-$RunId.log"
$SummaryFile = Join-Path $ReportDirectory "Shai-Hulud-Remediation-$RunId.json"
$FindingsFile = Join-Path $ReportDirectory "Shai-Hulud-Dependencies-$RunId.csv"
$PersistenceFile = Join-Path $ReportDirectory "Shai-Hulud-Persistence-$RunId.csv"
$UsingDefaultBackupDirectory = [string]::IsNullOrWhiteSpace($BackupDirectory)
if ($UsingDefaultBackupDirectory) {
    $backupStateRoot = if ($IsAdministrator) { $env:ProgramData } elseif (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) { $env:LOCALAPPDATA } else { [IO.Path]::GetTempPath() }
    $BackupDirectory = Join-Path $backupStateRoot 'Shai-Hulud-Remediation\Backups'
}
$ConfigBackupDirectory = Join-Path $BackupDirectory $RunId
$ConfigBackupManifest = Join-Path $ConfigBackupDirectory "manifest.tsv"
$ConfigBackupSequence = 0
$IdeConfigFiles = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
$PersistenceEvents = New-Object 'System.Collections.Generic.List[object]'
$WorkingDirectory = Join-Path ([IO.Path]::GetTempPath()) "shai-hulud-$([Guid]::NewGuid().ToString('N'))"
try {
    [void][IO.Directory]::CreateDirectory($WorkingDirectory)
    if ($Mode -eq 'remediate') {
        [void][IO.Directory]::CreateDirectory($BackupDirectory)
        if (-not (Test-IsSafeDirectoryPath $BackupDirectory)) { throw 'Backup directory is a reparse point' }
        if ([IO.Directory]::Exists($ConfigBackupDirectory) -or [IO.File]::Exists($ConfigBackupDirectory)) { throw "Config backup run directory already exists: $ConfigBackupDirectory" }
        [void][IO.Directory]::CreateDirectory($ConfigBackupDirectory)
        Set-PrivateDirectoryAcl $ConfigBackupDirectory $IsAdministrator
        [IO.File]::WriteAllText($ConfigBackupManifest, "Action`tTarget`tBackupOrValue" + [Environment]::NewLine, (New-Object Text.UTF8Encoding($false)))
    }
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

function Add-PersistenceEvent {
    param(
        [string]$File,
        [string]$Kind,
        [string]$Event,
        [string]$Command,
        [string]$Action
    )
    $script:PersistenceEvents.Add([PSCustomObject][ordered]@{
        File = $File
        Kind = $Kind
        Event = $Event
        Command = $Command
        Action = $Action
    })
}

function Remove-MaliciousArtifact {
    param([string]$Path)
    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    } catch { return }

    $isReparsePoint = ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
    $isKnownDirectory = $item.PSIsContainer -and $item.Name -like 'bun-dl-*'
    $isKnownFile = -not $item.PSIsContainer -and @('Math_Symbol.js', 'math_init.js', 'setup.mjs') -contains $item.Name
    if (-not $isKnownDirectory -and -not $isKnownFile) {
        Add-OperationalError "Safety check rejected unexpected persistence target '$Path'"
        return
    }

    $script:Stats.persistence_artifacts_found++
    if ($script:Mode -eq 'audit') {
        Add-PersistenceEvent $Path 'payload' '' '' 'would-remove'
        Write-Log 'AUDIT' "Would remove malicious artifact: $Path"
        return
    }
    try {
        if ($item.PSIsContainer -and -not $isReparsePoint) {
            Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
        } else {
            Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
        }
        if (Test-Path -LiteralPath $Path) { throw 'Target still exists after removal' }
        $script:Stats.persistence_artifacts_removed++
        Add-PersistenceEvent $Path 'payload' '' '' 'removed'
        Write-Log 'INFO' "Removed malicious artifact: $Path"
    } catch {
        Add-PersistenceEvent $Path 'payload' '' '' 'remove-failed'
        Add-OperationalError "Failed to remove malicious artifact '$Path': $($_.Exception.Message)"
    }
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
    param($Profiles)
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

    $roots = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($profile in $Profiles) {
        if (Test-IsSafeDirectoryPath $profile) { [void]$roots.Add([IO.Path]::GetFullPath($profile)) }
    }
    $fixedDrives = @()
    try {
        $fixedDrives = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop | ForEach-Object { [string]$_.DeviceID })
    } catch {
        Write-Log 'WARN' "Could not enumerate fixed drives for CI root discovery: $($_.Exception.Message)"
        $fixedDrives = @($env:SystemDrive)
    }
    foreach ($drive in $fixedDrives) {
        foreach ($relative in @('Builds', 'agent\_work', 'actions-runner\_work', 'gitlab-runner\builds', 'workspace', 'workspaces')) {
            $candidate = Join-Path "$drive\" $relative
            if (Test-IsSafeDirectoryPath $candidate) { [void]$roots.Add([IO.Path]::GetFullPath($candidate)) }
        }
    }
    foreach ($candidate in @((Join-Path $env:ProgramData 'Jenkins'), (Join-Path $env:ProgramData 'Buildkite-Agent\builds'))) {
        if (Test-IsSafeDirectoryPath $candidate) { [void]$roots.Add([IO.Path]::GetFullPath($candidate)) }
    }
    return $roots
}

function Get-UserProfiles {
    $profiles = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    if ($script:CustomScope) { return $profiles }
    try {
        Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' -ErrorAction Stop | ForEach-Object {
            $path = [Environment]::ExpandEnvironmentVariables([string]$_.ProfileImagePath)
            if (Test-IsSafeDirectoryPath $path) { [void]$profiles.Add([IO.Path]::GetFullPath($path)) }
        }
    } catch {
        Add-OperationalError "Could not enumerate profile registry entries: $($_.Exception.Message)"
    }
    if ([IO.Directory]::Exists("$env:SystemDrive\Users")) {
        try {
            [IO.Directory]::EnumerateDirectories("$env:SystemDrive\Users") | Where-Object { Test-IsSafeDirectoryPath $_ } | ForEach-Object { [void]$profiles.Add($_) }
        } catch { Add-OperationalError "Could not enumerate user profiles: $($_.Exception.Message)" }
    }
    return $profiles
}

function Get-TreeInventory {
    param([string[]]$Roots)
    $manifests = New-Object 'System.Collections.Generic.List[string]'
    foreach ($root in $Roots) {
        if (-not (Test-IsSafeDirectoryPath $root)) { Add-OperationalError "Refusing to scan missing or reparse-point root '$root'"; continue }
        Write-Log 'INFO' "Scanning filesystem: $root"
        $stack = New-Object 'System.Collections.Generic.Stack[string]'
        $stack.Push($root)
        while ($stack.Count -gt 0) {
            $current = $stack.Pop()
            $manifest = Join-Path $current 'package.json'
            if ([IO.File]::Exists($manifest)) { $manifests.Add($manifest) }
            $currentLeaf = Split-Path -Leaf $current
            $ideConfig = $null
            if ($currentLeaf -ieq '.claude') { $ideConfig = Join-Path $current 'settings.json' }
            elseif ($currentLeaf -ieq '.vscode') { $ideConfig = Join-Path $current 'tasks.json' }
            if ($null -ne $ideConfig -and [IO.File]::Exists($ideConfig)) {
                try {
                    $configItem = Get-Item -LiteralPath $ideConfig -Force -ErrorAction Stop
                    if (($configItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 -and -not $configItem.PSIsContainer) {
                        [void]$script:IdeConfigFiles.Add($configItem.FullName)
                    }
                } catch { Add-OperationalError "Could not inspect IDE persistence config '$ideConfig': $($_.Exception.Message)" }
            }
            foreach ($payloadName in @('Math_Symbol.js', 'math_init.js')) {
                $payloadPath = Join-Path $current $payloadName
                if ([IO.File]::Exists($payloadPath)) { Remove-MaliciousArtifact $payloadPath }
            }
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
                    if ($directory.Name -like 'bun-dl-*') {
                        Remove-MaliciousArtifact $directory.FullName
                        continue
                    }
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

function Backup-ConfigFile {
    param([string]$Path)
    $item = $null
    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    } catch [System.Management.Automation.ItemNotFoundException] {
        try {
            [IO.File]::AppendAllText($script:ConfigBackupManifest, "DELETE_FILE`t$Path`t-" + [Environment]::NewLine, (New-Object Text.UTF8Encoding($false)))
            return $true
        } catch {
            Add-OperationalError "Could not record rollback action for new config '$Path': $($_.Exception.Message)"
            return $false
        }
    } catch {
        Add-OperationalError "Could not inspect config '$Path' before backup: $($_.Exception.Message)"
        return $false
    }
    try {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Add-OperationalError "Refusing to modify reparse-point config '$Path'"
            return $false
        }
        if ($item.PSIsContainer) {
            Add-OperationalError "Refusing to replace directory with config file '$Path'"
            return $false
        }
        $script:ConfigBackupSequence++
        $backup = Join-Path $script:ConfigBackupDirectory ('{0:D6}.bak' -f $script:ConfigBackupSequence)
        Copy-Item -LiteralPath $Path -Destination $backup -ErrorAction Stop
        try {
            [IO.File]::AppendAllText($script:ConfigBackupManifest, "RESTORE_FILE`t$Path`t$backup" + [Environment]::NewLine, (New-Object Text.UTF8Encoding($false)))
        } catch {
            Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue
            throw
        }
        Write-Log 'INFO' "Backed up config: $Path -> $backup"
        return $true
    } catch {
        Add-OperationalError "Could not back up config '$Path': $($_.Exception.Message)"
        return $false
    }
}

function Backup-MachineEnvironmentVariable {
    param([string]$Name)
    try {
        $current = [Environment]::GetEnvironmentVariable($Name, 'Machine')
        if ($null -eq $current) {
            $entry = "DELETE_ENV`t$Name`t-"
        } else {
            $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($current))
            $entry = "RESTORE_ENV`t$Name`t$encoded"
        }
        [IO.File]::AppendAllText($script:ConfigBackupManifest, $entry + [Environment]::NewLine, (New-Object Text.UTF8Encoding($false)))
        return $true
    } catch {
        Add-OperationalError "Could not record previous machine environment value '$Name': $($_.Exception.Message)"
        return $false
    }
}

function Write-AtomicTextFile {
    param([string]$Path, [string[]]$Lines)
    $parent = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($parent)) { [void][IO.Directory]::CreateDirectory($parent) }
    $temp = Join-Path $parent ('.shai-hulud-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    try {
        [IO.File]::WriteAllLines($temp, $Lines, (New-Object Text.UTF8Encoding($false)))
        if ([IO.File]::Exists($Path)) {
            try {
                [IO.File]::Replace($temp, $Path, $null, $true)
            } catch [System.PlatformNotSupportedException] {
                Move-Item -LiteralPath $temp -Destination $Path -Force -ErrorAction Stop
            } catch [System.IO.IOException] {
                Move-Item -LiteralPath $temp -Destination $Path -Force -ErrorAction Stop
            }
        } else {
            [IO.File]::Move($temp, $Path)
        }
    } finally {
        if ([IO.File]::Exists($temp)) { Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue }
    }
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
    if (-not (Backup-ConfigFile $Path)) { return }
    $newLines = New-Object 'System.Collections.Generic.List[string]'
    $found = $false
    foreach ($line in $lines) {
        if ($line -match $MatchPattern) {
            if (-not $found) { $newLines.Add($Replacement); $found = $true }
        } else { $newLines.Add($line) }
    }
    if (-not $found) { $newLines.Add($Replacement) }
    try {
        Write-AtomicTextFile $Path $newLines
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
    if (-not (Backup-ConfigFile $Path)) { return }
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
        Write-AtomicTextFile $Path $result
        $script:Stats.configs_updated++
        Write-Log 'INFO' "Disabled Bun lifecycle scripts in $Path"
    } catch { Add-OperationalError "Failed to update Bun config '$Path': $($_.Exception.Message)" }
}

function Protect-ConfigDirectory {
    param([string]$Directory, [ValidateSet('profile','project')][string]$Scope = 'profile')
    Set-TextConfig (Join-Path $Directory '.npmrc') '^\s*ignore-scripts\s*=' '^\s*ignore-scripts\s*=\s*true\s*$' 'ignore-scripts=true' 'npm/pnpm lifecycle-script blocking'
    Set-TextConfig (Join-Path $Directory '.yarnrc') '^\s*--install\.ignore-scripts\s+' '^\s*--install\.ignore-scripts\s+true\s*$' '--install.ignore-scripts true' 'Yarn Classic lifecycle-script blocking'
    Set-TextConfig (Join-Path $Directory '.yarnrc.yml') '^enableScripts\s*:' '^enableScripts\s*:\s*false\s*$' 'enableScripts: false' 'Yarn lifecycle-script blocking'
    Set-BunConfig (Join-Path $Directory '.bunfig.toml')
    $pnpmWorkspace = Join-Path $Directory 'pnpm-workspace.yaml'
    if ($Scope -eq 'project' -and [IO.File]::Exists($pnpmWorkspace)) {
        Set-TextConfig $pnpmWorkspace '^ignoreScripts\s*:' '^ignoreScripts\s*:\s*true\s*$' 'ignoreScripts: true' 'pnpm lifecycle-script blocking'
    }
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
                if (Backup-MachineEnvironmentVariable 'NPM_CONFIG_IGNORE_SCRIPTS') {
                    try {
                        [Environment]::SetEnvironmentVariable('NPM_CONFIG_IGNORE_SCRIPTS', 'true', 'Machine')
                        [Environment]::SetEnvironmentVariable('NPM_CONFIG_IGNORE_SCRIPTS', 'true', 'Process')
                        $script:Stats.configs_updated++
                        Write-Log 'INFO' 'Set machine NPM_CONFIG_IGNORE_SCRIPTS=true'
                    } catch { Add-OperationalError "Could not set machine npm policy: $($_.Exception.Message)" }
                }
            }
            if ([Environment]::GetEnvironmentVariable('YARN_ENABLE_SCRIPTS', 'Machine') -ne 'false') {
                $script:Stats.configs_needing_change++
                if (Backup-MachineEnvironmentVariable 'YARN_ENABLE_SCRIPTS') {
                    try {
                        [Environment]::SetEnvironmentVariable('YARN_ENABLE_SCRIPTS', 'false', 'Machine')
                        [Environment]::SetEnvironmentVariable('YARN_ENABLE_SCRIPTS', 'false', 'Process')
                        $script:Stats.configs_updated++
                        Write-Log 'INFO' 'Set machine YARN_ENABLE_SCRIPTS=false'
                    } catch { Add-OperationalError "Could not set machine Yarn policy: $($_.Exception.Message)" }
                }
            }
        }
        Set-TextConfig (Join-Path $env:ProgramData 'npm\etc\npmrc') '^\s*ignore-scripts\s*=' '^\s*ignore-scripts\s*=\s*true\s*$' 'ignore-scripts=true' 'system npm lifecycle-script blocking'
        foreach ($profile in $Profiles) { Protect-ConfigDirectory $profile 'profile' }
    }
    $projectDirectories = @($Manifests | ForEach-Object { Split-Path -Parent $_ } | Select-Object -Unique)
    foreach ($projectDirectory in $projectDirectories) { Protect-ConfigDirectory $projectDirectory 'project' }
}

function Test-TextConfigCompliance {
    param([string]$Path, [string]$MatchPattern, [string]$CorrectPattern)
    if (-not [IO.File]::Exists($Path)) { return $false }
    try {
        $matching = @([IO.File]::ReadAllLines($Path) | Where-Object { $_ -match $MatchPattern })
        return $matching.Count -gt 0 -and @($matching | Where-Object { $_ -notmatch $CorrectPattern }).Count -eq 0
    } catch { return $false }
}

function Test-BunConfigCompliance {
    param([string]$Path)
    if (-not [IO.File]::Exists($Path)) { return $false }
    try {
        $inside = $false; $found = $false
        foreach ($line in [IO.File]::ReadAllLines($Path)) {
            if ($line -match '^\s*\[install\]\s*$') { $inside = $true; continue }
            if ($line -match '^\s*\[') { $inside = $false }
            if ($inside -and $line -match '^\s*ignoreScripts\s*=\s*true\s*(?:#.*)?$') { $found = $true }
        }
        return $found
    } catch { return $false }
}

function Verify-ConfigDirectory {
    param([string]$Directory, [ValidateSet('profile','project')][string]$Scope = 'profile')
    if (-not (Test-TextConfigCompliance (Join-Path $Directory '.npmrc') '^\s*ignore-scripts\s*=' '^\s*ignore-scripts\s*=\s*true\s*$')) { Add-OperationalError "npm/pnpm policy verification failed: $(Join-Path $Directory '.npmrc')" }
    if (-not (Test-TextConfigCompliance (Join-Path $Directory '.yarnrc') '^\s*--install\.ignore-scripts\s+' '^\s*--install\.ignore-scripts\s+true\s*$')) { Add-OperationalError "Yarn Classic policy verification failed: $(Join-Path $Directory '.yarnrc')" }
    if (-not (Test-TextConfigCompliance (Join-Path $Directory '.yarnrc.yml') '^enableScripts\s*:' '^enableScripts\s*:\s*false\s*$')) { Add-OperationalError "Yarn policy verification failed: $(Join-Path $Directory '.yarnrc.yml')" }
    if (-not (Test-BunConfigCompliance (Join-Path $Directory '.bunfig.toml'))) { Add-OperationalError "Bun policy verification failed: $(Join-Path $Directory '.bunfig.toml')" }
    $pnpmWorkspace = Join-Path $Directory 'pnpm-workspace.yaml'
    if ($Scope -eq 'project' -and [IO.File]::Exists($pnpmWorkspace) -and -not (Test-TextConfigCompliance $pnpmWorkspace '^ignoreScripts\s*:' '^ignoreScripts\s*:\s*true\s*$')) {
        Add-OperationalError "pnpm policy verification failed: $pnpmWorkspace"
    }
}

function Verify-PackageManagerControls {
    param($Profiles, [string[]]$Manifests)
    if ($script:Mode -eq 'audit') { return }
    if (-not $script:CustomScope) {
        if ([Environment]::GetEnvironmentVariable('NPM_CONFIG_IGNORE_SCRIPTS', 'Machine') -ne 'true') { Add-OperationalError 'Machine npm policy verification failed' }
        if ([Environment]::GetEnvironmentVariable('YARN_ENABLE_SCRIPTS', 'Machine') -ne 'false') { Add-OperationalError 'Machine Yarn policy verification failed' }
        $systemNpmrc = Join-Path $env:ProgramData 'npm\etc\npmrc'
        if (-not (Test-TextConfigCompliance $systemNpmrc '^\s*ignore-scripts\s*=' '^\s*ignore-scripts\s*=\s*true\s*$')) { Add-OperationalError "System npm policy verification failed: $systemNpmrc" }
        foreach ($profile in $Profiles) { Verify-ConfigDirectory $profile 'profile' }
    }
    $projectDirectories = @($Manifests | ForEach-Object { Split-Path -Parent $_ } | Select-Object -Unique)
    foreach ($projectDirectory in $projectDirectories) { Verify-ConfigDirectory $projectDirectory 'project' }
}

function Add-SetupPayloadReference {
    param(
        [string]$ConfigPath,
        [string]$Command,
        [System.Collections.Generic.HashSet[string]]$References
    )
    $match = [regex]::Match($Command, '(?i)(?<reference>[^\s`"''|&;<>()]*setup\.mjs)')
    if (-not $match.Success) { return }
    $reference = $match.Groups['reference'].Value
    $configDirectory = Split-Path -Parent $ConfigPath
    $candidates = New-Object 'System.Collections.Generic.List[string]'
    if ([IO.Path]::IsPathRooted($reference)) {
        $candidates.Add($reference)
    } else {
        $candidates.Add((Join-Path $configDirectory ([IO.Path]::GetFileName($reference))))
        $candidates.Add((Join-Path $configDirectory $reference))
        $candidates.Add((Join-Path (Split-Path -Parent $configDirectory) ([IO.Path]::GetFileName($reference))))
    }
    foreach ($candidate in $candidates) {
        try {
            $fullPath = [IO.Path]::GetFullPath($candidate)
            $item = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
            if (-not $item.PSIsContainer -and $item.Name -ieq 'setup.mjs') { [void]$References.Add($item.FullName) }
        } catch [System.Management.Automation.ItemNotFoundException] {
            continue
        } catch {
            Add-OperationalError "Could not inspect referenced setup.mjs '$candidate': $($_.Exception.Message)"
        }
    }
}

function Remove-IdePersistence {
    param([string[]]$ConfigFiles)
    $payloadPattern = '(?i)(setup\.mjs|Math_Symbol(?:\.js)?|math_init(?:\.js)?|bun-dl-)'
    $payloadReferences = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)

    foreach ($configPath in @($ConfigFiles | Select-Object -Unique)) {
        $script:Stats.ide_hooks_scanned++
        try {
            $item = Get-Item -LiteralPath $configPath -Force -ErrorAction Stop
            if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'not a regular, non-reparse-point file' }
            $data = Get-Content -LiteralPath $configPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            if ($null -eq $data -or $data -is [Array] -or -not ($data -is [PSCustomObject])) { throw 'not a JSON object' }
        } catch {
            Add-PersistenceEvent $configPath 'error' '' $_.Exception.Message 'skipped'
            Add-OperationalError "Could not safely parse IDE persistence config '$configPath': $($_.Exception.Message)"
            continue
        }

        $configFindings = New-Object 'System.Collections.Generic.List[object]'
        if ((Split-Path -Leaf $configPath) -ieq 'settings.json' -and (Split-Path -Leaf (Split-Path -Parent $configPath)) -ieq '.claude') {
            $hooksProperty = $data.PSObject.Properties['hooks']
            if ($null -ne $hooksProperty -and $hooksProperty.Value -is [PSCustomObject]) {
                $hooks = $hooksProperty.Value
                foreach ($eventProperty in @($hooks.PSObject.Properties)) {
                    if (-not ($eventProperty.Value -is [Array])) { continue }
                    $keptEntries = New-Object 'System.Collections.Generic.List[object]'
                    foreach ($entry in $eventProperty.Value) {
                        if ($null -eq $entry -or -not ($entry -is [PSCustomObject])) { $keptEntries.Add($entry); continue }
                        $entryHooksProperty = $entry.PSObject.Properties['hooks']
                        if ($null -eq $entryHooksProperty -or -not ($entryHooksProperty.Value -is [Array])) { $keptEntries.Add($entry); continue }
                        $keptHooks = New-Object 'System.Collections.Generic.List[object]'
                        foreach ($hook in $entryHooksProperty.Value) {
                            $command = ''
                            if ($null -ne $hook -and $hook -is [PSCustomObject]) {
                                $commandProperty = $hook.PSObject.Properties['command']
                                if ($null -ne $commandProperty) { $command = [string]$commandProperty.Value }
                            }
                            if ($command -match $payloadPattern) {
                                Add-SetupPayloadReference $configPath $command $payloadReferences
                                $configFindings.Add([PSCustomObject]@{ File = $configPath; Kind = 'claude-hook'; Event = $eventProperty.Name; Command = $command })
                            } else {
                                $keptHooks.Add($hook)
                            }
                        }
                        if ($keptHooks.Count -gt 0) {
                            $entryHooksProperty.Value = @($keptHooks | ForEach-Object { $_ })
                            $keptEntries.Add($entry)
                        }
                    }
                    if ($keptEntries.Count -gt 0) {
                        $eventProperty.Value = @($keptEntries | ForEach-Object { $_ })
                    } else {
                        $hooks.PSObject.Properties.Remove($eventProperty.Name)
                    }
                }
                if ($hooks.PSObject.Properties.Count -eq 0) { $data.PSObject.Properties.Remove('hooks') }
            }
        } elseif ((Split-Path -Leaf $configPath) -ieq 'tasks.json' -and (Split-Path -Leaf (Split-Path -Parent $configPath)) -ieq '.vscode') {
            $tasksProperty = $data.PSObject.Properties['tasks']
            if ($null -ne $tasksProperty -and $tasksProperty.Value -is [Array]) {
                $keptTasks = New-Object 'System.Collections.Generic.List[object]'
                foreach ($task in $tasksProperty.Value) {
                    if ($null -eq $task -or -not ($task -is [PSCustomObject])) { $keptTasks.Add($task); continue }
                    $blob = $task | ConvertTo-Json -Depth 100 -Compress
                    if ($blob -match $payloadPattern) {
                        Add-SetupPayloadReference $configPath $blob $payloadReferences
                        $command = ''
                        $commandProperty = $task.PSObject.Properties['command']
                        if ($null -ne $commandProperty) { $command = [string]$commandProperty.Value }
                        if ([string]::IsNullOrWhiteSpace($command)) {
                            $argsProperty = $task.PSObject.Properties['args']
                            if ($null -ne $argsProperty -and $argsProperty.Value -is [Array]) { $command = [string]::Join(' ', [string[]]$argsProperty.Value) }
                        }
                        $labelProperty = $task.PSObject.Properties['label']
                        $label = if ($null -ne $labelProperty) { [string]$labelProperty.Value } else { '' }
                        if ([string]::IsNullOrWhiteSpace($command)) { $command = $label }
                        $event = $label
                        $runOptionsProperty = $task.PSObject.Properties['runOptions']
                        if ($null -ne $runOptionsProperty -and $runOptionsProperty.Value -is [PSCustomObject]) {
                            $runOnProperty = $runOptionsProperty.Value.PSObject.Properties['runOn']
                            if ($null -ne $runOnProperty -and -not [string]::IsNullOrWhiteSpace([string]$runOnProperty.Value)) { $event = [string]$runOnProperty.Value }
                        }
                        $configFindings.Add([PSCustomObject]@{ File = $configPath; Kind = 'vscode-task'; Event = $event; Command = $command })
                    } else {
                        $keptTasks.Add($task)
                    }
                }
                if ($keptTasks.Count -ne $tasksProperty.Value.Count) { $tasksProperty.Value = @($keptTasks | ForEach-Object { $_ }) }
            }
        }

        if ($configFindings.Count -eq 0) { continue }
        $script:Stats.ide_hooks_found += $configFindings.Count
        if ($script:Mode -eq 'audit') {
            foreach ($finding in $configFindings) { Add-PersistenceEvent $finding.File $finding.Kind $finding.Event $finding.Command 'would-remove' }
            continue
        }
        if (-not (Backup-ConfigFile $configPath)) {
            foreach ($finding in $configFindings) { Add-PersistenceEvent $finding.File $finding.Kind $finding.Event $finding.Command 'rewrite-failed' }
            continue
        }
        try {
            $json = $data | ConvertTo-Json -Depth 100
            Write-AtomicTextFile $configPath @($json)
            $script:Stats.ide_hooks_removed += $configFindings.Count
            foreach ($finding in $configFindings) { Add-PersistenceEvent $finding.File $finding.Kind $finding.Event $finding.Command 'removed' }
            Write-Log 'INFO' "Removed malicious IDE persistence entries from: $configPath"
        } catch {
            foreach ($finding in $configFindings) { Add-PersistenceEvent $finding.File $finding.Kind $finding.Event $finding.Command 'rewrite-failed' }
            Add-OperationalError "Failed to update IDE config '$configPath': $($_.Exception.Message)"
        }
    }

    foreach ($payloadReference in $payloadReferences) { Remove-MaliciousArtifact $payloadReference }
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
            if ($null -eq $manifest -or $manifest -is [Array] -or -not ($manifest -is [PSCustomObject])) { throw 'manifest is not a JSON object' }
        } catch {
            Add-OperationalError "Could not parse package manifest '$manifestPath': $($_.Exception.Message)"
            continue
        }
        foreach ($section in @('dependencies','devDependencies','optionalDependencies','peerDependencies')) {
            $property = $manifest.PSObject.Properties[$section]
            if ($null -eq $property -or $null -eq $property.Value -or $property.Value -is [Array] -or -not ($property.Value -is [PSCustomObject])) { continue }
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

function Export-PersistenceEvents {
    param([object[]]$Events, [string]$Path)
    if ($Events.Count -eq 0) {
        [IO.File]::WriteAllText($Path, '"File","Kind","Event","Command","Action"' + [Environment]::NewLine, (New-Object Text.UTF8Encoding($false)))
        return
    }
    $Events | ForEach-Object {
        [PSCustomObject][ordered]@{
            File = ConvertTo-CsvSafeValue $_.File
            Kind = ConvertTo-CsvSafeValue $_.Kind
            Event = ConvertTo-CsvSafeValue $_.Event
            Command = ConvertTo-CsvSafeValue $_.Command
            Action = ConvertTo-CsvSafeValue $_.Action
        }
    } | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8 -Force -ErrorAction Stop
}

try {
    Write-Log 'INFO' "Shai Hulud remediation v$ToolVersion started (mode=$Mode, host=$env:COMPUTERNAME, user=$env:USERNAME)"
    Write-Log 'INFO' "Report: $ReportFile"
    if ($Mode -eq 'remediate') { Write-Log 'INFO' "Restricted configuration backups: $ConfigBackupDirectory" }
    $IocRows = @(Get-IocRows)
    $Findings = @()
    if ($IocRows.Count -gt 0) {
        $Profiles = Get-UserProfiles
        $Roots = @(Get-LocalScanRoots $Profiles | Select-Object -Unique)
        if ($Roots.Count -eq 0) {
            Add-OperationalError 'No scan roots were discovered; no cleanup or configuration changes were attempted.'
        } else {
            $Manifests = @(Get-TreeInventory $Roots | Select-Object -Unique)
            Remove-KnownCaches $Profiles
            Protect-LifecycleScripts $Profiles $Manifests
            Verify-PackageManagerControls $Profiles $Manifests
            Remove-IdePersistence @($IdeConfigFiles)
            $Findings = @(Find-VulnerableDeclarations $Manifests $IocRows)
        }
    } else {
        Write-Log 'ERROR' 'IOC data is unavailable; no cleanup or configuration changes were attempted'
    }
    try {
        Export-DependencyFindings $Findings $FindingsFile
        Write-Log 'INFO' "Dependency report: $FindingsFile"
    } catch { Add-OperationalError "Could not publish dependency report: $($_.Exception.Message)" }
    try {
        Export-PersistenceEvents @($PersistenceEvents) $PersistenceFile
        Write-Log 'INFO' "Persistence report: $PersistenceFile"
    } catch { Add-OperationalError "Could not publish persistence report: $($_.Exception.Message)" }
} catch {
    Add-OperationalError "Unhandled remediation error: $($_.Exception.Message)"
}

$AuditWork = $Stats.node_modules_found + $Stats.caches_found + $Stats.configs_needing_change + $Stats.persistence_artifacts_found + $Stats.ide_hooks_found
$ExitCode = 0
$Status = 'completed'
if ($Stats.operational_errors -gt 0) { $ExitCode = 20; $Status = 'completed_with_errors' }
elseif ($Stats.dependency_findings -gt 0 -or $Stats.persistence_artifacts_found -gt 0 -or $Stats.ide_hooks_found -gt 0 -or ($Mode -eq 'audit' -and $AuditWork -gt 0)) { $ExitCode = 10; $Status = 'attention_required' }

$summary = [ordered]@{
    schema_version = 1
    tool_version = $ToolVersion
    run_id = $RunId
    mode = $Mode
    status = $Status
    exit_code = $ExitCode
}
foreach ($entry in $Stats.GetEnumerator()) { $summary[$entry.Key] = $entry.Value }
try {
    [IO.File]::WriteAllText($SummaryFile, ($summary | ConvertTo-Json), (New-Object Text.UTF8Encoding($false)))
} catch {
    Add-OperationalError "Could not write summary JSON: $($_.Exception.Message)"
    $ExitCode = 20
    $Status = 'completed_with_errors'
}

Write-Log 'SUMMARY' "status=$Status exit_code=$ExitCode node_modules_found=$($Stats.node_modules_found) node_modules_removed=$($Stats.node_modules_removed) caches_found=$($Stats.caches_found) caches_removed=$($Stats.caches_removed) configs_needed=$($Stats.configs_needing_change) configs_updated=$($Stats.configs_updated) manifests_scanned=$($Stats.package_json_scanned) dependency_findings=$($Stats.dependency_findings) ide_hooks_scanned=$($Stats.ide_hooks_scanned) ide_hooks_found=$($Stats.ide_hooks_found) ide_hooks_removed=$($Stats.ide_hooks_removed) persistence_found=$($Stats.persistence_artifacts_found) persistence_removed=$($Stats.persistence_artifacts_removed) errors=$($Stats.operational_errors)"
if ([IO.File]::Exists($SummaryFile)) { Write-Log 'INFO' "Machine-readable summary: $SummaryFile" }
try { Remove-Item -LiteralPath $WorkingDirectory -Recurse -Force -ErrorAction SilentlyContinue } catch {}
exit $ExitCode

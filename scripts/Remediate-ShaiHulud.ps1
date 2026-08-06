#requires -Version 5.1
<#
.SYNOPSIS
Unattended Shai Hulud / Keyv supply-chain remediation for Windows.

.DESCRIPTION
Remediation is the default. It inventories manifests first and removes only
dependency trees containing an actionable top-level IOC package. Use
-AuditOnly for a read-only assessment. The script is designed for SYSTEM
execution by RMM and EDR tools and never prompts.
#>
[CmdletBinding()]
param(
    [switch]$AuditOnly,
    [string]$IocFile,
    [string]$ReportDirectory,
    [string]$BackupDirectory,
    [string[]]$ScanRoot,
    [switch]$IncludeApplicationDirectories
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'
# Windows PowerShell 5.1 targets an older .NET Framework compatibility mode.
# Opt this process into the .NET 4.6.2+ path behavior before any filesystem
# access; extended-length paths below then work without changing machine policy.
try {
    [System.AppContext]::SetSwitch('Switch.System.IO.UseLegacyPathHandling', $false)
    [System.AppContext]::SetSwitch('Switch.System.IO.BlockLongPaths', $false)
} catch {}
$ToolVersion = '3.1.5'
$IocUrl = 'https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/refs/heads/main/reports/keyv-packages.csv'
$Mode = if ($AuditOnly) { 'audit' } else { 'remediate' }
if ($null -eq $ScanRoot) {
    $ScanRoot = @()
} else {
    # Windows PowerShell can expose a single array-typed command-line argument
    # as a scalar under strict mode. Normalize it before using collection APIs.
    $ScanRoot = @($ScanRoot)
}
$CustomScope = @($ScanRoot).Count -gt 0
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

function ConvertTo-ExtendedLengthPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }
    if ($Path.StartsWith('\\?\', [StringComparison]::Ordinal)) { return $Path }
    $absolutePath = if ([IO.Path]::IsPathRooted($Path)) { $Path } else { [IO.Path]::GetFullPath($Path) }
    if ($absolutePath.StartsWith('\\', [StringComparison]::Ordinal)) {
        return '\\?\UNC\' + $absolutePath.Substring(2)
    }
    return '\\?\' + $absolutePath
}

function ConvertFrom-ExtendedLengthPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }
    if ($Path.StartsWith('\\?\UNC\', [StringComparison]::OrdinalIgnoreCase)) {
        return '\\' + $Path.Substring(8)
    }
    if ($Path.StartsWith('\\?\', [StringComparison]::Ordinal)) { return $Path.Substring(4) }
    return $Path
}

function Get-NormalizedFileSystemPath {
    param([string]$Path)
    return ConvertFrom-ExtendedLengthPath ([IO.Path]::GetFullPath((ConvertTo-ExtendedLengthPath $Path)))
}

function Join-FileSystemPath {
    param([string]$Parent, [string]$Child)
    if ([string]::IsNullOrWhiteSpace($Parent)) { return $Child }
    return $Parent.TrimEnd([char[]]@('\','/')) + [IO.Path]::DirectorySeparatorChar + $Child.TrimStart([char[]]@('\','/'))
}

function Get-FileSystemLeafName {
    param([string]$Path)
    $normalPath = (ConvertFrom-ExtendedLengthPath $Path).TrimEnd([char[]]@('\','/'))
    $separatorIndex = [Math]::Max($normalPath.LastIndexOf('\'), $normalPath.LastIndexOf('/'))
    if ($separatorIndex -lt 0) { return $normalPath }
    return $normalPath.Substring($separatorIndex + 1)
}

function Get-FileSystemParentPath {
    param([string]$Path)
    $extendedParent = [IO.Path]::GetDirectoryName((ConvertTo-ExtendedLengthPath $Path))
    if ([string]::IsNullOrWhiteSpace($extendedParent)) { return $null }
    return ConvertFrom-ExtendedLengthPath $extendedParent
}

function Get-FileSystemAttributes {
    param([string]$Path)
    return [IO.File]::GetAttributes((ConvertTo-ExtendedLengthPath $Path))
}

function Test-FileSystemFile {
    param([string]$Path)
    try {
        $attributes = Get-FileSystemAttributes $Path
        return ($attributes -band [IO.FileAttributes]::Directory) -eq 0
    } catch { return $false }
}

function Test-FileSystemDirectory {
    param([string]$Path)
    try {
        $attributes = Get-FileSystemAttributes $Path
        return ($attributes -band [IO.FileAttributes]::Directory) -ne 0
    } catch { return $false }
}

function Remove-ExtendedDirectoryTree {
    param([string]$ExtendedPath)
    $pending = New-Object 'System.Collections.Generic.Stack[object]'
    $pending.Push([PSCustomObject]@{ Path = $ExtendedPath; Visited = $false })
    while ($pending.Count -gt 0) {
        $entry = $pending.Pop()
        try {
            $attributes = [IO.File]::GetAttributes($entry.Path)
        } catch [System.IO.FileNotFoundException], [System.IO.DirectoryNotFoundException] {
            continue
        }
        $isReparsePoint = ($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
        if ($isReparsePoint) {
            [IO.Directory]::Delete($entry.Path, $false)
            continue
        }
        if ($entry.Visited) {
            $forceAttributes = [IO.FileAttributes]::ReadOnly -bor [IO.FileAttributes]::Hidden -bor [IO.FileAttributes]::System
            if (($attributes -band $forceAttributes) -ne 0) {
                $cleanAttributes = [IO.FileAttributes](([int]$attributes) -band (-bnot ([int]$forceAttributes)))
                [IO.File]::SetAttributes($entry.Path, $cleanAttributes)
            }
            [IO.Directory]::Delete($entry.Path, $false)
            continue
        }

        $pending.Push([PSCustomObject]@{ Path = $entry.Path; Visited = $true })
        foreach ($childDirectory in [IO.Directory]::EnumerateDirectories($entry.Path)) {
            $pending.Push([PSCustomObject]@{ Path = $childDirectory; Visited = $false })
        }
        foreach ($childFile in [IO.Directory]::EnumerateFiles($entry.Path)) {
            $fileAttributes = [IO.File]::GetAttributes($childFile)
            $forceAttributes = [IO.FileAttributes]::ReadOnly -bor [IO.FileAttributes]::Hidden -bor [IO.FileAttributes]::System
            if (($fileAttributes -band $forceAttributes) -ne 0) {
                $cleanAttributes = [IO.FileAttributes](([int]$fileAttributes) -band (-bnot ([int]$forceAttributes)))
                if ($cleanAttributes -eq 0) { $cleanAttributes = [IO.FileAttributes]::Normal }
                [IO.File]::SetAttributes($childFile, $cleanAttributes)
            }
            [IO.File]::Delete($childFile)
        }
    }
}

function Remove-FileSystemPath {
    param([string]$Path, [bool]$Recursive)
    $extendedPath = ConvertTo-ExtendedLengthPath $Path
    $attributes = [IO.File]::GetAttributes($extendedPath)
    $isDirectory = ($attributes -band [IO.FileAttributes]::Directory) -ne 0
    $isReparsePoint = ($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
    if ($isDirectory) {
        if ($Recursive -and -not $isReparsePoint) {
            try {
                [IO.Directory]::Delete($extendedPath, $true)
            } catch {
                Remove-ExtendedDirectoryTree $extendedPath
            }
        } else {
            [IO.Directory]::Delete($extendedPath, $false)
        }
    } else {
        if (($attributes -band [IO.FileAttributes]::ReadOnly) -ne 0) {
            [IO.File]::SetAttributes($extendedPath, ($attributes -band (-bnot [IO.FileAttributes]::ReadOnly)))
        }
        [IO.File]::Delete($extendedPath)
    }
}

function Test-IsSafeDirectoryPath {
    param([string]$Path)
    try {
        $attributes = Get-FileSystemAttributes $Path
        return (($attributes -band [IO.FileAttributes]::Directory) -ne 0) -and (($attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0)
    } catch { return $false }
}

function Test-IsKnownApplicationDirectory {
    param([string]$Path)
    if ($script:IncludeApplicationDirectories) { return $false }
    try {
        $trimCharacters = [char[]]@([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
        $fullPath = (Get-NormalizedFileSystemPath $Path).TrimEnd($trimCharacters)
        $leaf = Get-FileSystemLeafName $fullPath
        $knownNames = @(
            'AppData', 'Application Data', 'Local Settings', 'Applications', 'Programs', 'scoop',
            '.cache', '.config', '.local', '.npm', '.pnpm-store', '.yarn', '.bun', '.corepack',
            '.nvm', '.fnm', '.volta', '.asdf', '.nodenv', '.node-gyp',
            '.cargo', '.gradle', '.m2', '.terraform', '.tox', '.venv',
            '.vscode', '.vscode-insiders', '.vscode-oss', '.vscode-server', '.vscode-server-insiders',
            '.cursor', '.cursor-server', '.windsurf', '.windsurf-server', '.claude', '.codex', '.opencode'
        )
        if ($knownNames -icontains $leaf) { return $true }
        $normalizedSeparators = $fullPath.Replace('/', '\')
        if ($normalizedSeparators.EndsWith('\pkg\mod', [StringComparison]::OrdinalIgnoreCase)) { return $true }

        foreach ($systemPath in @($env:windir, $env:ProgramFiles, [Environment]::GetEnvironmentVariable('ProgramFiles(x86)'), $env:ProgramData)) {
            if ([string]::IsNullOrWhiteSpace($systemPath)) { continue }
            $normalizedSystemPath = (Get-NormalizedFileSystemPath $systemPath).TrimEnd($trimCharacters)
            if ($fullPath -ieq $normalizedSystemPath) { return $true }
        }
    } catch {
        return $false
    }
    return $false
}

function Add-IdeConfigurationFromDirectory {
    param([string]$Directory)
    $leaf = Get-FileSystemLeafName $Directory
    $ideConfig = $null
    if ($leaf -ieq '.claude') { $ideConfig = Join-FileSystemPath $Directory 'settings.json' }
    elseif ($leaf -ieq '.vscode') { $ideConfig = Join-FileSystemPath $Directory 'tasks.json' }
    if ($null -eq $ideConfig -or -not (Test-FileSystemFile $ideConfig)) { return }
    try {
        $attributes = Get-FileSystemAttributes $ideConfig
        if (($attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 -and ($attributes -band [IO.FileAttributes]::Directory) -eq 0) {
            [void]$script:IdeConfigFiles.Add((Get-NormalizedFileSystemPath $ideConfig))
        }
    } catch { Add-OperationalError "Could not inspect IDE persistence config '$ideConfig': $($_.Exception.Message)" }
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
            $fullRoot = Get-NormalizedFileSystemPath $root
            if (-not (Test-IsSafeDirectoryPath $fullRoot)) { throw 'Directory does not exist or is a reparse point' }
            $validatedRoots.Add($fullRoot)
        } catch {
            Write-Error "Invalid -ScanRoot '$root': $($_.Exception.Message)"
            exit 30
        }
    }
    $ScanRoot = @($validatedRoots.ToArray())
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
    # Keep reports in a predictable, operator-accessible Windows location for
    # both interactive and SYSTEM/RMM executions. Do not use C:\Users itself:
    # Set-PrivateDirectoryAcl must only apply to this dedicated subdirectory.
    $preferredReportDirectory = 'C:\Users\Public\Shai-Hulud-Remediation'
    $fallbackStateRoot = if (-not [string]::IsNullOrWhiteSpace($env:ProgramData)) { $env:ProgramData } else { 'C:\ProgramData' }
    $fallbackReportDirectory = Join-Path $fallbackStateRoot 'Shai-Hulud-Remediation'
    $reportDirectoryErrors = New-Object 'System.Collections.Generic.List[string]'
    $ReportDirectory = $null
    foreach ($candidate in @($preferredReportDirectory, $fallbackReportDirectory)) {
        if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
        if ($null -ne $ReportDirectory) { break }
        try {
            if ([IO.File]::Exists($candidate)) { throw 'Path exists as a file' }
            [void][IO.Directory]::CreateDirectory($candidate)
            if (-not (Test-IsSafeDirectoryPath $candidate)) { throw 'Directory is a reparse point or is not safely accessible' }
            Set-PrivateDirectoryAcl $candidate $IsAdministrator
            $ReportDirectory = $candidate
        } catch {
            $reportDirectoryErrors.Add("'$candidate': $($_.Exception.Message)")
        }
    }
    if ([string]::IsNullOrWhiteSpace($ReportDirectory)) {
        Write-Error "Cannot create a safe default report directory. $([string]::Join('; ', $reportDirectoryErrors.ToArray()))"
        exit 30
    }
    if (-not $ReportDirectory.Equals($preferredReportDirectory, [StringComparison]::OrdinalIgnoreCase)) {
        Write-Warning "Preferred report directory '$preferredReportDirectory' is unavailable. Using fallback report directory '$ReportDirectory'."
    }
} else {
    try {
        if ([IO.File]::Exists($ReportDirectory)) { throw 'Path exists as a file' }
        [void][IO.Directory]::CreateDirectory($ReportDirectory)
        if (-not (Test-IsSafeDirectoryPath $ReportDirectory)) { throw 'Directory is a reparse point or is not safely accessible' }
    } catch {
        Write-Error "Cannot create report directory '$ReportDirectory': $($_.Exception.Message)"
        exit 30
    }
}

$RunId = '{0}-{1}' -f ([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')), $PID
$ReportFile = Join-Path $ReportDirectory "Shai-Hulud-Remediation-$RunId.log"
$SummaryFile = Join-Path $ReportDirectory "Shai-Hulud-Remediation-$RunId.json"
$FindingsFile = Join-Path $ReportDirectory "Shai-Hulud-Dependencies-$RunId.csv"
$NodeModulesFile = Join-Path $ReportDirectory "Shai-Hulud-NodeModules-$RunId.csv"
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
$NodeModulesEvents = New-Object 'System.Collections.Generic.List[object]'
$VulnerableNodeModules = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
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
    # Write directly to the host instead of the success pipeline. Returning
    # log lines from this function contaminates callers that collect objects,
    # such as the manifest list returned by Get-TreeInventory.
    try { [Console]::Out.WriteLine($line) } catch { Write-Host $line }
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

function Add-NodeModulesEvent {
    param([string]$Path, [string]$Action)
    $script:NodeModulesEvents.Add([PSCustomObject][ordered]@{
        'Node Modules' = $Path
        Action = $Action
    })
}

function Remove-MaliciousArtifact {
    param([string]$Path)
    try {
        $attributes = Get-FileSystemAttributes $Path
    } catch { return }

    $isDirectory = ($attributes -band [IO.FileAttributes]::Directory) -ne 0
    $isReparsePoint = ($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
    $leafName = Get-FileSystemLeafName $Path
    $isKnownDirectory = $isDirectory -and $leafName -like 'bun-dl-*'
    $isKnownFile = -not $isDirectory -and @('Math_Symbol.js', 'math_init.js', 'setup.mjs') -contains $leafName
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
        Remove-FileSystemPath $Path ($isDirectory -and -not $isReparsePoint)
        if ((Test-FileSystemFile $Path) -or (Test-FileSystemDirectory $Path)) { throw 'Target still exists after removal' }
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
        $attributes = Get-FileSystemAttributes $Path
    } catch { return }
    $isDirectory = ($attributes -band [IO.FileAttributes]::Directory) -ne 0
    $isReparsePoint = ($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
    if (-not $isDirectory -and -not $isReparsePoint) {
        Add-OperationalError "Safety check rejected non-directory $Kind target '$Path'"
        return
    }
    if ($Kind -eq 'node_modules') { $script:Stats.node_modules_found++ } else { $script:Stats.caches_found++ }
    if ($script:Mode -eq 'audit') {
        if ($Kind -eq 'node_modules') { Add-NodeModulesEvent $Path 'would-remove' }
        Write-Log 'AUDIT' "Would remove ${Kind}: $Path"
        return
    }
    try {
        Remove-FileSystemPath $Path (-not $isReparsePoint)
        if ((Test-FileSystemFile $Path) -or (Test-FileSystemDirectory $Path)) { throw 'Target still exists after removal' }
        if ($Kind -eq 'node_modules') {
            $script:Stats.node_modules_removed++
            Add-NodeModulesEvent $Path 'removed'
        } else { $script:Stats.caches_removed++ }
        Write-Log 'INFO' "Removed ${Kind}: $Path"
    } catch {
        if ($Kind -eq 'node_modules') { Add-NodeModulesEvent $Path 'remove-failed' }
        Add-OperationalError "Failed to remove $Kind '$Path': $($_.Exception.Message)"
    }
}

function Get-LocalScanRoots {
    param($Profiles)
    if ($script:CustomScope) {
        foreach ($root in $script:ScanRoot) {
            try {
                $full = Get-NormalizedFileSystemPath $root
                if (-not (Test-FileSystemDirectory $full)) { throw 'Directory does not exist' }
                $full
            } catch {
                Add-OperationalError "Invalid scan root '$root': $($_.Exception.Message)"
            }
        }
        return
    }

    $roots = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($profile in $Profiles) {
        if (Test-IsSafeDirectoryPath $profile) { [void]$roots.Add((Get-NormalizedFileSystemPath $profile)) }
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
            if (Test-IsSafeDirectoryPath $candidate) { [void]$roots.Add((Get-NormalizedFileSystemPath $candidate)) }
        }
    }

    # User and build data is frequently placed directly under C:\ in folders
    # such as C:\src, C:\repos, or C:\projects. Include every ordinary,
    # non-reparse-point top-level directory on the Windows system drive while
    # explicitly excluding standard OS, profile, recovery, and application
    # roots. Custom -ScanRoot invocations return above and never reach this.
    $systemDriveRoot = $null
    try {
        if (-not [string]::IsNullOrWhiteSpace($env:SystemDrive)) {
            $systemDriveRoot = [IO.Path]::GetFullPath("$($env:SystemDrive)\")
        } elseif (-not [string]::IsNullOrWhiteSpace($env:windir)) {
            $systemDriveRoot = [IO.Path]::GetPathRoot([IO.Path]::GetFullPath($env:windir))
        }
        if (-not [string]::IsNullOrWhiteSpace($systemDriveRoot) -and [IO.Directory]::Exists($systemDriveRoot)) {
            $standardRootNames = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
            foreach ($name in @(
                '$Recycle.Bin', 'Boot', 'Config.Msi', 'Documents and Settings', 'EFI', 'ESD',
                'MSOCache', 'PerfLogs', 'Program Files', 'Program Files (x86)', 'ProgramData',
                'Recovery', 'System Volume Information', 'Users', 'Windows', 'Windows.old'
            )) { [void]$standardRootNames.Add($name) }

            foreach ($directoryPath in [IO.Directory]::EnumerateDirectories($systemDriveRoot)) {
                try {
                    $directory = New-Object IO.DirectoryInfo($directoryPath)
                    if ($standardRootNames.Contains($directory.Name)) { continue }
                    if (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
                    if (($directory.Attributes -band [IO.FileAttributes]::System) -ne 0) { continue }
                    if (($directory.Attributes -band [IO.FileAttributes]::Hidden) -ne 0) { continue }
                    if (Test-IsKnownApplicationDirectory $directory.FullName) { continue }
                    if (Test-IsSafeDirectoryPath $directory.FullName) {
                        $fullDirectory = Get-NormalizedFileSystemPath $directory.FullName
                        # A top-level root subsumes any previously discovered
                        # named CI root beneath it. Remove those descendants to
                        # prevent duplicate scans and duplicate report rows.
                        foreach ($existingRoot in @($roots)) {
                            if (-not $existingRoot.Equals($fullDirectory, [StringComparison]::OrdinalIgnoreCase) -and (Test-PathWithinRoot $existingRoot $fullDirectory)) {
                                [void]$roots.Remove($existingRoot)
                            }
                        }
                        [void]$roots.Add($fullDirectory)
                    }
                } catch {
                    Write-Log 'WARN' "Could not inspect system-drive directory '$directoryPath': $($_.Exception.Message)"
                }
            }
        }
    } catch {
        Add-OperationalError "Could not enumerate non-standard directories on the Windows system drive: $($_.Exception.Message)"
    }

    foreach ($candidate in @((Join-Path $env:ProgramData 'Jenkins'), (Join-Path $env:ProgramData 'Buildkite-Agent\builds'))) {
        if (Test-IsSafeDirectoryPath $candidate) { [void]$roots.Add((Get-NormalizedFileSystemPath $candidate)) }
    }
    return $roots
}

function Get-UserProfiles {
    $profiles = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    if ($script:CustomScope) { return $profiles }
    try {
        Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' -ErrorAction Stop | ForEach-Object {
            $path = [Environment]::ExpandEnvironmentVariables([string]$_.ProfileImagePath)
            if (Test-IsSafeDirectoryPath $path) { [void]$profiles.Add((Get-NormalizedFileSystemPath $path)) }
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
        if (Test-IsKnownApplicationDirectory $root) {
            Add-IdeConfigurationFromDirectory $root
            Write-Log 'INFO' "Skipping known application directory: $root"
            continue
        }
        Write-Log 'INFO' "Scanning filesystem: $root"
        $stack = New-Object 'System.Collections.Generic.Stack[string]'
        $stack.Push($root)
        while ($stack.Count -gt 0) {
            $current = $stack.Pop()
            $manifest = Join-FileSystemPath $current 'package.json'
            if (Test-FileSystemFile $manifest) {
                try {
                    $manifestAttributes = Get-FileSystemAttributes $manifest
                    if (($manifestAttributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 -and ($manifestAttributes -band [IO.FileAttributes]::Directory) -eq 0) {
                        [void]$manifests.Add((Get-NormalizedFileSystemPath $manifest))
                    }
                } catch { Add-OperationalError "Could not inspect package manifest '$manifest': $($_.Exception.Message)" }
            }
            Add-IdeConfigurationFromDirectory $current
            foreach ($payloadName in @('Math_Symbol.js', 'math_init.js')) {
                $payloadPath = Join-FileSystemPath $current $payloadName
                if (Test-FileSystemFile $payloadPath) { Remove-MaliciousArtifact $payloadPath }
            }
            try {
                foreach ($enumeratedPath in [IO.Directory]::EnumerateDirectories((ConvertTo-ExtendedLengthPath $current))) {
                    $directoryPath = ConvertFrom-ExtendedLengthPath $enumeratedPath
                    $directoryName = Get-FileSystemLeafName $directoryPath
                    $directoryAttributes = Get-FileSystemAttributes $directoryPath
                    if ($directoryName -ieq 'node_modules') {
                        continue
                    }
                    if (($directoryAttributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
                    if (Test-IsKnownApplicationDirectory $directoryPath) {
                        Add-IdeConfigurationFromDirectory $directoryPath
                        continue
                    }
                    if ($directoryName -like 'bun-dl-*') {
                        Remove-MaliciousArtifact $directoryPath
                        continue
                    }
                    $stack.Push($directoryPath)
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
    try {
        $attributes = Get-FileSystemAttributes $Path
    } catch [System.IO.FileNotFoundException], [System.IO.DirectoryNotFoundException] {
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
        if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Add-OperationalError "Refusing to modify reparse-point config '$Path'"
            return $false
        }
        if (($attributes -band [IO.FileAttributes]::Directory) -ne 0) {
            Add-OperationalError "Refusing to replace directory with config file '$Path'"
            return $false
        }
        $script:ConfigBackupSequence++
        $backup = Join-Path $script:ConfigBackupDirectory ('{0:D6}.bak' -f $script:ConfigBackupSequence)
        [IO.File]::Copy((ConvertTo-ExtendedLengthPath $Path), (ConvertTo-ExtendedLengthPath $backup), $false)
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
    if ([string]::IsNullOrWhiteSpace($Path)) { throw 'Cannot atomically write an empty path' }
    $parent = Get-FileSystemParentPath $Path
    if (-not [string]::IsNullOrWhiteSpace($parent)) { [void][IO.Directory]::CreateDirectory((ConvertTo-ExtendedLengthPath $parent)) }
    $temp = Join-FileSystemPath $parent ('.shai-hulud-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    $extendedTemp = ConvertTo-ExtendedLengthPath $temp
    $extendedPath = ConvertTo-ExtendedLengthPath $Path
    try {
        [IO.File]::WriteAllLines($extendedTemp, $Lines, (New-Object Text.UTF8Encoding($false)))
        if (Test-FileSystemFile $Path) {
            try {
                [IO.File]::Replace($extendedTemp, $extendedPath, $null, $true)
            } catch [System.Exception] {
                # Windows PowerShell/.NET can reject a null backup path or
                # certain application-managed files. Fall back to same-volume
                # replacement so a compatible host can still complete safely.
                [IO.File]::Copy($extendedTemp, $extendedPath, $true)
                [IO.File]::Delete($extendedTemp)
            }
        } else {
            [IO.File]::Move($extendedTemp, $extendedPath)
        }
    } finally {
        if ([IO.File]::Exists($extendedTemp)) {
            try { [IO.File]::Delete($extendedTemp) } catch {}
        }
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
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
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
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
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
    if ([string]::IsNullOrWhiteSpace($Directory)) { return }
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
    $projectDirectories = @($Manifests | Where-Object {
        if ($_ -isnot [string] -or [string]::IsNullOrWhiteSpace($_)) { return $false }
        try { return [IO.File]::Exists($_) -and ([IO.Path]::GetFileName($_) -ieq 'package.json') } catch { return $false }
    } | ForEach-Object { Split-Path -Parent $_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
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
    if ([string]::IsNullOrWhiteSpace($Directory)) { return }
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
    $projectDirectories = @($Manifests | Where-Object {
        if ($_ -isnot [string] -or [string]::IsNullOrWhiteSpace($_)) { return $false }
        try { return [IO.File]::Exists($_) -and ([IO.Path]::GetFileName($_) -ieq 'package.json') } catch { return $false }
    } | ForEach-Object { Split-Path -Parent $_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
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
    $configDirectory = Get-FileSystemParentPath $ConfigPath
    $candidates = New-Object 'System.Collections.Generic.List[string]'
    if ([IO.Path]::IsPathRooted($reference)) {
        $candidates.Add($reference)
    } else {
        $referenceLeaf = Get-FileSystemLeafName $reference
        $candidates.Add((Join-FileSystemPath $configDirectory $referenceLeaf))
        $candidates.Add((Join-FileSystemPath $configDirectory $reference))
        $candidates.Add((Join-FileSystemPath (Get-FileSystemParentPath $configDirectory) $referenceLeaf))
    }
    foreach ($candidate in $candidates) {
        try {
            $fullPath = Get-NormalizedFileSystemPath $candidate
            $attributes = Get-FileSystemAttributes $fullPath
            if (($attributes -band [IO.FileAttributes]::Directory) -eq 0 -and (Get-FileSystemLeafName $fullPath) -ieq 'setup.mjs') { [void]$References.Add($fullPath) }
        } catch [System.IO.FileNotFoundException], [System.IO.DirectoryNotFoundException] {
            continue
        } catch {
            Add-OperationalError "Could not inspect referenced setup.mjs '$candidate': $($_.Exception.Message)"
        }
    }
}

function ConvertFrom-JsoncComments {
    param([string]$Text)

    # VS Code task files use JSON with Comments (JSONC). Convert comments and
    # trailing commas to whitespace so ConvertFrom-Json can safely consume the
    # document without changing quoted strings or line positions.
    $withoutComments = New-Object System.Text.StringBuilder
    $index = 0
    $inString = $false
    $escaped = $false
    while ($index -lt $Text.Length) {
        $character = $Text[$index]
        if ($inString) {
            [void]$withoutComments.Append($character)
            if ($escaped) { $escaped = $false }
            elseif ($character -eq [char]'\') { $escaped = $true }
            elseif ($character -eq [char]'"') { $inString = $false }
            $index++
            continue
        }
        if ($character -eq [char]'"') {
            $inString = $true
            [void]$withoutComments.Append($character)
            $index++
            continue
        }
        if ($character -eq [char]'/' -and ($index + 1) -lt $Text.Length -and $Text[$index + 1] -eq [char]'/') {
            [void]$withoutComments.Append('  ')
            $index += 2
            while ($index -lt $Text.Length -and $Text[$index] -ne [char]13 -and $Text[$index] -ne [char]10) {
                [void]$withoutComments.Append(' ')
                $index++
            }
            continue
        }
        if ($character -eq [char]'/' -and ($index + 1) -lt $Text.Length -and $Text[$index + 1] -eq [char]'*') {
            [void]$withoutComments.Append('  ')
            $index += 2
            $closed = $false
            while ($index -lt $Text.Length) {
                if (($index + 1) -lt $Text.Length -and $Text[$index] -eq [char]'*' -and $Text[$index + 1] -eq [char]'/') {
                    [void]$withoutComments.Append('  ')
                    $index += 2
                    $closed = $true
                    break
                }
                if ($Text[$index] -eq [char]13 -or $Text[$index] -eq [char]10) {
                    [void]$withoutComments.Append($Text[$index])
                } else {
                    [void]$withoutComments.Append(' ')
                }
                $index++
            }
            if (-not $closed) { throw 'unterminated block comment' }
            continue
        }
        [void]$withoutComments.Append($character)
        $index++
    }

    $commentFree = $withoutComments.ToString()
    $strictJson = New-Object System.Text.StringBuilder
    $index = 0
    $inString = $false
    $escaped = $false
    while ($index -lt $commentFree.Length) {
        $character = $commentFree[$index]
        if ($inString) {
            [void]$strictJson.Append($character)
            if ($escaped) { $escaped = $false }
            elseif ($character -eq [char]'\') { $escaped = $true }
            elseif ($character -eq [char]'"') { $inString = $false }
            $index++
            continue
        }
        if ($character -eq [char]'"') { $inString = $true }
        elseif ($character -eq [char]',') {
            $lookahead = $index + 1
            while ($lookahead -lt $commentFree.Length -and [char]::IsWhiteSpace($commentFree[$lookahead])) { $lookahead++ }
            if ($lookahead -lt $commentFree.Length -and ($commentFree[$lookahead] -eq [char]'}' -or $commentFree[$lookahead] -eq [char]']')) {
                [void]$strictJson.Append(' ')
                $index++
                continue
            }
        }
        [void]$strictJson.Append($character)
        $index++
    }
    return $strictJson.ToString()
}

function ConvertFrom-ScannedJson {
    param([string]$Text)
    $strictJson = ConvertFrom-JsoncComments $Text
    if ([string]::IsNullOrWhiteSpace($strictJson)) { $strictJson = '{}' }
    return (ConvertFrom-Json -InputObject $strictJson -ErrorAction Stop)
}

function Remove-IdePersistence {
    param([string[]]$ConfigFiles)
    $payloadPattern = '(?i)(setup\.mjs|Math_Symbol(?:\.js)?|math_init(?:\.js)?|bun-dl-)'
    $payloadReferences = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)

    foreach ($configPath in @($ConfigFiles | Select-Object -Unique)) {
        $script:Stats.ide_hooks_scanned++
        $configParent = Get-FileSystemParentPath $configPath
        $isClaudeSettings = (Get-FileSystemLeafName $configPath) -ieq 'settings.json' -and (Get-FileSystemLeafName $configParent) -ieq '.claude'
        $isVsCodeTasks = (Get-FileSystemLeafName $configPath) -ieq 'tasks.json' -and (Get-FileSystemLeafName $configParent) -ieq '.vscode'
        try {
            $attributes = Get-FileSystemAttributes $configPath
            if (($attributes -band [IO.FileAttributes]::Directory) -ne 0 -or ($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'not a regular, non-reparse-point file' }
            $configText = [IO.File]::ReadAllText((ConvertTo-ExtendedLengthPath $configPath))
            $data = ConvertFrom-ScannedJson $configText
            if ($null -eq $data -or $data -is [Array] -or -not ($data -is [PSCustomObject])) { throw 'not a JSON object' }
        } catch {
            Add-PersistenceEvent $configPath 'error' '' $_.Exception.Message 'skipped'
            Add-OperationalError "Could not safely parse IDE persistence config '$configPath': $($_.Exception.Message)"
            continue
        }

        $configFindings = New-Object 'System.Collections.Generic.List[object]'
        if ($isClaudeSettings) {
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
                if (@($hooks.PSObject.Properties).Count -eq 0) { $data.PSObject.Properties.Remove('hooks') }
            }
        } elseif ($isVsCodeTasks) {
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
                if ($keptTasks.Count -ne @($tasksProperty.Value).Count) { $tasksProperty.Value = @($keptTasks | ForEach-Object { $_ }) }
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

function Test-PathWithinRoot {
    param([string]$Path, [string]$Root)
    try {
        $candidate = Get-NormalizedFileSystemPath $Path
        $rootPath = Get-NormalizedFileSystemPath $Root
        if ($candidate.Equals($rootPath, [StringComparison]::OrdinalIgnoreCase)) { return $true }
        $separator = [string][IO.Path]::DirectorySeparatorChar
        $prefix = if ($rootPath.EndsWith($separator, [StringComparison]::Ordinal)) { $rootPath } else { $rootPath + $separator }
        return $candidate.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)
    } catch { return $false }
}

function Get-InstalledDependencyLocations {
    param(
        [string]$ManifestPath,
        [string]$PackageName,
        [string[]]$BadVersions,
        [string[]]$Roots
    )
    $parts = @($PackageName -split '/')
    $validName = if ($PackageName.StartsWith('@')) { $parts.Count -eq 2 } else { $parts.Count -eq 1 }
    $invalidParts = @($parts | Where-Object { [string]::IsNullOrWhiteSpace($_) -or $_ -eq '.' -or $_ -eq '..' })
    if (-not $validName -or $invalidParts.Count -gt 0) { return @() }

    $manifestDirectory = Get-FileSystemParentPath (Get-NormalizedFileSystemPath $ManifestPath)
    $containingRoots = @($Roots | Where-Object { Test-PathWithinRoot $manifestDirectory $_ } | Sort-Object { $_.Length } -Descending)
    if ($containingRoots.Count -eq 0) { return @() }
    $root = Get-NormalizedFileSystemPath $containingRoots[0]
    $current = $manifestDirectory
    $locations = New-Object 'System.Collections.Generic.List[object]'

    while ($true) {
        $nodeModules = Join-FileSystemPath $current 'node_modules'
        $packagePath = $nodeModules
        foreach ($part in $parts) { $packagePath = Join-FileSystemPath $packagePath $part }
        if ((Test-FileSystemDirectory $nodeModules) -and ((Test-FileSystemDirectory $packagePath) -or (Test-FileSystemFile $packagePath))) {
            $installedVersion = 'unknown'
            try {
                $installedManifestPath = Join-FileSystemPath $packagePath 'package.json'
                $installedManifestText = [IO.File]::ReadAllText((ConvertTo-ExtendedLengthPath $installedManifestPath))
                $installedManifest = ConvertFrom-ScannedJson $installedManifestText
                if ($null -ne $installedManifest -and $null -ne $installedManifest.PSObject.Properties['version'] -and -not [string]::IsNullOrWhiteSpace([string]$installedManifest.version)) {
                    $installedVersion = ([string]$installedManifest.version).Trim()
                }
            } catch {}
            $status = if ($installedVersion -eq 'unknown') { 'unknown' } elseif ($BadVersions -contains $installedVersion) { 'malicious' } else { 'not-listed' }
            $locations.Add([PSCustomObject][ordered]@{
                NodeModules = $nodeModules
                InstalledVersion = $installedVersion
                Status = $status
            })
            if ($status -eq 'malicious' -or $status -eq 'unknown') { [void]$script:VulnerableNodeModules.Add($nodeModules) }
        }
        if ($current.Equals($root, [StringComparison]::OrdinalIgnoreCase)) { break }
        $parent = Get-FileSystemParentPath $current
        if ($null -eq $parent -or -not (Test-PathWithinRoot $parent $root)) { break }
        $current = $parent
    }
    return $locations
}

function Find-VulnerableDeclarations {
    param([string[]]$Manifests, $IocRows, [string[]]$Roots)
    $iocMap = @{}
    foreach ($row in $IocRows) { $iocMap[[string]$row.Package] = [string]$row.'Malicious Versions' }
    $findings = New-Object 'System.Collections.Generic.List[object]'
    $validManifests = @($Manifests | Where-Object {
        if ($_ -isnot [string] -or [string]::IsNullOrWhiteSpace($_)) { return $false }
        try { return (Test-FileSystemFile $_) -and ((Get-FileSystemLeafName $_) -ieq 'package.json') } catch { return $false }
    })
    foreach ($manifestPath in $validManifests) {
        $script:Stats.package_json_scanned++
        try {
            $manifestText = [IO.File]::ReadAllText((ConvertTo-ExtendedLengthPath $manifestPath))
            $manifest = ConvertFrom-ScannedJson $manifestText
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
                $locations = @(Get-InstalledDependencyLocations $manifestPath $dependency.Name $badVersions $Roots)
                $findings.Add([PSCustomObject][ordered]@{
                    Manifest = $manifestPath
                    Section = $section
                    Package = $dependency.Name
                    Declared = $declared
                    'Malicious Versions' = $iocMap[$dependency.Name]
                    Match = $confidence
                    'Node Modules' = (@($locations | ForEach-Object { $_.NodeModules }) -join ' | ')
                    'Installed Versions' = (@($locations | ForEach-Object { $_.InstalledVersion }) -join ' | ')
                    'Installed Status' = if ($locations.Count -gt 0) { @($locations | ForEach-Object { $_.Status }) -join ' | ' } else { 'not-installed' }
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
    $validFindings = @($Findings | Where-Object { $null -ne $_ -and $null -ne $_.PSObject.Properties['Manifest'] })
    if ($validFindings.Count -eq 0) {
        [IO.File]::WriteAllText($Path, '"Manifest","Section","Package","Declared","Malicious Versions","Match","Node Modules","Installed Versions","Installed Status"' + [Environment]::NewLine, (New-Object Text.UTF8Encoding($false)))
        return
    }
    $validFindings | ForEach-Object {
        [PSCustomObject][ordered]@{
            Manifest = ConvertTo-CsvSafeValue $_.Manifest
            Section = ConvertTo-CsvSafeValue $_.Section
            Package = ConvertTo-CsvSafeValue $_.Package
            Declared = ConvertTo-CsvSafeValue $_.Declared
            'Malicious Versions' = ConvertTo-CsvSafeValue $_.'Malicious Versions'
            Match = ConvertTo-CsvSafeValue $_.Match
            'Node Modules' = ConvertTo-CsvSafeValue $_.'Node Modules'
            'Installed Versions' = ConvertTo-CsvSafeValue $_.'Installed Versions'
            'Installed Status' = ConvertTo-CsvSafeValue $_.'Installed Status'
        }
    } | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8 -Force -ErrorAction Stop
}

function Export-NodeModulesEvents {
    param([object[]]$Events, [string]$Path)
    $validEvents = @($Events | Where-Object { $null -ne $_ -and $null -ne $_.PSObject.Properties['Node Modules'] })
    if ($validEvents.Count -eq 0) {
        [IO.File]::WriteAllText($Path, '"Node Modules","Action"' + [Environment]::NewLine, (New-Object Text.UTF8Encoding($false)))
        return
    }
    $validEvents | ForEach-Object {
        [PSCustomObject][ordered]@{
            'Node Modules' = ConvertTo-CsvSafeValue $_.'Node Modules'
            Action = ConvertTo-CsvSafeValue $_.Action
        }
    } | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8 -Force -ErrorAction Stop
}

function Export-PersistenceEvents {
    param([object[]]$Events, [string]$Path)
    $validEvents = @($Events | Where-Object { $null -ne $_ -and $null -ne $_.PSObject.Properties['File'] })
    if ($validEvents.Count -eq 0) {
        [IO.File]::WriteAllText($Path, '"File","Kind","Event","Command","Action"' + [Environment]::NewLine, (New-Object Text.UTF8Encoding($false)))
        return
    }
    $validEvents | ForEach-Object {
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
    if (-not $IncludeApplicationDirectories) { Write-Log 'INFO' 'Known application and tool-state directories are excluded from traversal' }
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
            $Findings = @(Find-VulnerableDeclarations $Manifests $IocRows $Roots)
            foreach ($nodeModules in $VulnerableNodeModules) { Remove-RemediationDirectory $nodeModules 'node_modules' }
            Remove-IdePersistence @($IdeConfigFiles)
        }
    } else {
        Write-Log 'ERROR' 'IOC data is unavailable; no cleanup or configuration changes were attempted'
    }
    try {
        Export-DependencyFindings $Findings $FindingsFile
        Write-Log 'INFO' "Dependency report: $FindingsFile"
    } catch { Add-OperationalError "Could not publish dependency report: $($_.Exception.Message)" }
    try {
        Export-NodeModulesEvents -Events @($NodeModulesEvents.ToArray()) -Path $NodeModulesFile
        Write-Log 'INFO' "Node modules action report: $NodeModulesFile"
    } catch { Add-OperationalError "Could not publish node_modules action report: $($_.Exception.Message)" }
    try {
        Export-PersistenceEvents -Events @($PersistenceEvents.ToArray()) -Path $PersistenceFile
        Write-Log 'INFO' "Persistence report: $PersistenceFile"
    } catch { Add-OperationalError "Could not publish persistence report: $($_.Exception.Message)" }
} catch {
    $failureLocation = if ([string]::IsNullOrWhiteSpace($_.ScriptStackTrace)) { '' } else { " Location: $($_.ScriptStackTrace -replace '[\r\n]+', ' <- ')" }
    Add-OperationalError "Unhandled remediation error: $($_.Exception.Message)$failureLocation"
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
    report_directory = $ReportDirectory
    log_file = $ReportFile
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

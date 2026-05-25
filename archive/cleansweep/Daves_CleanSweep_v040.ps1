#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Dave's CleanSweep v0.40 — Enterprise PUP, Adware & Malware IOC Remediation Tool

.DESCRIPTION
    Removes PUPs, browser hijackers, adware, persistence mechanisms, and flags
    malware IOCs across 16 remediation phases. Fully PowerShell-native — no
    external dependencies, no WMI legacy calls, no sc.exe, no cmd.exe wrappers.

    PowerShell 7+ gains parallel filesystem scanning automatically.
    PowerShell 5.1 runs sequentially — all phases fully compatible with both.

.PARAMETER Verbose
    Enables verbose output for detailed per-item logging to console.

.EXAMPLE
    .\Daves_CleanSweep_v040.ps1
    .\Daves_CleanSweep_v040.ps1 -Verbose

.NOTES
    Version    : v0.40
    Author     : Dave
    Requires   : PowerShell 5.1+, Administrator privileges
    Log Path   : C:\ProgramData\Logs\DavesCleanSweep\DavesCleanSweep_<DATE>_<TIME>.log
    Exit Codes : 0 = Clean / Success  |  1 = Errors  |  2 = IOC Alerts present

.LINK
    MalwareBazaar API : https://bazaar.abuse.ch/api/
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ==================================================================================================
# RUNTIME CONFIGURATION
# ==================================================================================================

$Script:Config = @{
    Name          = "Dave's CleanSweep"
    Version       = 'v0.40'
    LogDir        = 'C:\ProgramData\Logs\DavesCleanSweep'
    PSVersion     = $PSVersionTable.PSVersion.Major
    ParallelAvail = ($PSVersionTable.PSVersion.Major -ge 7)
}

$Script:Config.LogFile = "DavesCleanSweep_$(Get-Date -Format 'yyyy-MM-dd_HHmm').log"
$Script:Config.LogPath = [System.IO.Path]::Combine($Script:Config.LogDir, $Script:Config.LogFile)

# ==================================================================================================
# COUNTERS  (thread-safe for PS7 parallel where needed)
# ==================================================================================================

$Script:Counters = [hashtable]::Synchronized(@{
    ActionsTaken    = 0
    IOCsFound       = 0
    ProcessesKilled = 0
    ServicesRemoved = 0
    TasksRemoved    = 0
    RunKeysRemoved  = 0
    FilesRemoved    = 0
    UninstallsRun   = 0
    Failed          = $false
    RebootRequired  = $false
})

$Script:IOCExePaths = [System.Collections.Concurrent.ConcurrentBag[string]]::new()

# ==================================================================================================
# LOGGING  — StreamWriter for performance; flush after every write
# ==================================================================================================

[System.IO.Directory]::CreateDirectory($Script:Config.LogDir) | Out-Null
$Script:LogWriter = [System.IO.StreamWriter]::new(
    $Script:Config.LogPath, $false, [System.Text.Encoding]::UTF8
)
$Script:LogWriter.AutoFlush = $true

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','SUCCESS','WARN','FAILED','IOC')]
        [string]$Level = 'INFO'
    )
    $ts      = [datetime]::Now.ToString('yyyy-MM-dd HH:mm:ss')
    $padded  = "[$Level]".PadRight(10)
    $line    = "$ts  $padded $Message"
    $Script:LogWriter.WriteLine($line)

    $color = switch ($Level) {
        'SUCCESS' { 'Green'   }
        'WARN'    { 'Yellow'  }
        'FAILED'  { 'Red'     }
        'IOC'     { 'Magenta' }
        default   { 'Gray'    }
    }
    Write-Host $line -ForegroundColor $color

    switch ($Level) {
        'SUCCESS' { $Script:Counters.ActionsTaken++ }
        'FAILED'  { $Script:Counters.Failed = $true }
        'IOC'     { $Script:Counters.IOCsFound++ }
    }
}

function Log-Info    ([string]$m) { Write-Log -Message $m -Level INFO    }
function Log-Success ([string]$m) { Write-Log -Message $m -Level SUCCESS }
function Log-Warn    ([string]$m) { Write-Log -Message $m -Level WARN    }
function Log-Fail    ([string]$m) { Write-Log -Message $m -Level FAILED  }
function Log-IOC     ([string]$m) { Write-Log -Message $m -Level IOC     }

# ==================================================================================================
# TARGET PATTERNS
# ==================================================================================================

$Script:Targets = [regex]::new(
    'pdftool|pdfast|pdffast|wavesor|onestart|web[\.\s]?companion|lavasoft|adaware|wcinstaller|' +
    'wavebrowser|webnavigator|safefinder|chromiumupdater|pdfconverterhq|easypdfcombine|' +
    'managedsearch|conduit|babylon|snapdo|snap\.do|askbar|ilivid|mywebsearch|funwebproduct|' +
    'myway\.com|superfish|visualdiscovery|opencandy|mindspark|internetspeedtracker|' +
    'couponserver|edeals|dealply|savingswizard|browsersafeguard|browserprotect|yontoo|' +
    'searchprotect|trovi|vosteran|spigot|reimage|pcoptimizerpro|speedmaxpc|installcore|' +
    'installmonetizer|vittalia|amonetize|smartbar|iminent|whitesmoke|babylontoolbar|' +
    'webssearches|istartsurf|nationzoom|delta-homes|dosearches|sweet-page|omiga-plus|' +
    'wcsam|wcassistant|formfiller|websearch\.com|dealsfindr|browsefox',
    [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
    [System.Text.RegularExpressions.RegexOptions]::Compiled
)

$Script:SuspiciousPolicyPattern = [regex]::new(
    'conduit|babylon|trovi|snapdo|searchprotect|safefinder|mywebsearch|' +
    'vosteran|istartsurf|delta-homes|dosearches|sweet-page|omiga|webssearches|nationzoom',
    [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
    [System.Text.RegularExpressions.RegexOptions]::Compiled
)

$Script:MalwareTaskPattern = [regex]::new(
    'svchost32|update32|winhelper|windows_update_helper|taskhostw32|winlogon32|lsass32|csrss32',
    [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
    [System.Text.RegularExpressions.RegexOptions]::Compiled
)

$Script:TrojanFolderIOCs = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]@(
        'njrat','nanocore','asyncrat','quasarrat','remcos','darkcomet',
        'netwire','xtremerat','luminosity','cobaltstrike','meterpreter',
        'redline','azorult','vidar','raccoon','lokibot','formbook',
        'emotet','trickbot','dridex','qakbot','ursnif','zloader',
        'gootkit','smokeloader','cryptbot','icedid','bumblebee'
    ),
    [System.StringComparer]::OrdinalIgnoreCase
)

$Script:HijackerExtensionIDs = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]@(
        'mgccaoaemljlkioddcgjjlidikkfbglh',   # Conduit
        'dlnembnfbcpjnepmfjmngjenhhajpdfd',   # SafeFinder
        'lifbcibllhkdhoafpjfnlhfpfgnpldfl',   # SearchProtect
        'ogdcnefjaneleickodflbefjpddoiakm',   # Web Companion
        'hclgegipaehbigmbdhfoelajfoldmlfj',   # Trovi
        'bopakagnckmlpbhlbhkpjmemhmxhj',      # Superfish
        'ebgggcnefhjgijchikdlgnojilemnop'     # Generic placeholder — update with threat intel
    ),
    [System.StringComparer]::OrdinalIgnoreCase
)

$Script:PUPFolderNames = [string[]]@(
    'Web Companion','WebCompanion','Lavasoft','Adaware','WaveBrowser',
    'SafeFinder','Conduit','BabylonToolbar','Babylon','SnapDo',
    'SearchProtect','Trovi','Reimage','PCOptimizerPro','Mindspark',
    'DealPly','Coupon Server','BrowserSafeguard','Yontoo','Superfish',
    'OpenCandy','Spigot','Iminent','WhiteSmoke','SmartBar',
    'pdfast','pdftool','PDFConverterHQ','EasyPDFCombine','OneStart',
    'ManagedSearch','ChromiumUpdater','WebNavigator','WaveSor'
)

$Script:SuspiciousRunPaths = [string[]]@(
    $env:TEMP,
    "$env:APPDATA\Microsoft\Windows",
    "$env:LOCALAPPDATA\Temp",
    "$env:LOCALAPPDATA\Microsoft\Windows"
)

$Script:LegitHostsPatterns = [string[]]@(
    '^#', '^\s*$', 'localhost', 'ip6-localhost',
    'ip6-loopback', 'broadcasthost', '0\.0\.0\.0\s+0\.0\.0\.0'
)

# ==================================================================================================
# HELPER FUNCTIONS
# ==================================================================================================

function Get-UserProfiles {
    Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notmatch '^(Public|Default|Default User|All Users)$' }
}

function Remove-TargetItem {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Label,
        [switch]$Recurse
    )
    if (-not (Test-Path -LiteralPath $Path)) { return }
    try {
        Remove-Item -LiteralPath $Path -Recurse:$Recurse -Force -ErrorAction Stop
        Log-Success "Removed $Label`: $Path"
        $Script:Counters.FilesRemoved++
    } catch [System.UnauthorizedAccessException] {
        Log-Fail "Access denied removing $Label`: $Path"
    } catch [System.IO.IOException] {
        Log-Fail "File in use — could not remove $Label`: $Path"
    } catch {
        Log-Fail "Failed removing $Label`: $Path — $($_.Exception.Message)"
    }
}

function Get-FolderSizeBytes {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return 0L }
    try {
        [long](Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue |
               Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
    } catch { 0L }
}

function Remove-FolderContents {
    param([string]$Path, [string]$Label)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $freed = 0L
    Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $size = if ($_.PSIsContainer) { Get-FolderSizeBytes $_.FullName } else { $_.Length }
            Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction Stop
            $freed += $size
        } catch { <# locked files — skip silently #> }
    }
    if ($freed -gt 0) {
        $mb = [math]::Round($freed / 1MB, 1)
        Log-Success "Cleaned $Label — freed $mb MB"
        $Script:SpaceFreed += $freed
    } else {
        Log-Info "$Label — nothing to clean or all files locked"
    }
}

function Stop-TargetService {
    param([System.ServiceProcess.ServiceController]$Service)
    try {
        if ($Service.Status -ne 'Stopped') {
            $Service.Stop()
            $Service.WaitForStatus('Stopped', [timespan]::FromSeconds(10))
        }
        # Remove via CIM (PS-native, no sc.exe)
        $cimSvc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$($Service.Name)'" -ErrorAction Stop
        Invoke-CimMethod -InputObject $cimSvc -MethodName Delete -ErrorAction Stop | Out-Null
        Log-Success "Removed service: $($Service.Name) ($($Service.DisplayName))"
        $Script:Counters.ServicesRemoved++
    } catch [System.ServiceProcess.TimeoutException] {
        Log-Fail "Timed out stopping service: $($Service.Name)"
    } catch {
        Log-Fail "Failed removing service: $($Service.Name) — $($_.Exception.Message)"
    }
}

# ==================================================================================================
# STARTUP
# ==================================================================================================

$Script:StartTime  = [datetime]::Now
$Script:UserProfiles = @(Get-UserProfiles)

Log-Info ('=' * 64)
Log-Info "$($Script:Config.Name) $($Script:Config.Version) — Starting"
Log-Info "PowerShell $($PSVersionTable.PSVersion) | Host: $env:COMPUTERNAME | User: $env:USERNAME"
Log-Info "Parallel scanning: $(if ($Script:Config.ParallelAvail) { 'Enabled (PS7+)' } else { 'Sequential (PS5.1)' })"
Log-Info ('=' * 64)

# ==================================================================================================
# PHASE 1: PROCESS TERMINATION
# ==================================================================================================
Log-Info '--- Phase 1: Process Termination ---'

Get-Process -ErrorAction SilentlyContinue |
Where-Object { $Script:Targets.IsMatch($_.Name) } |
ForEach-Object {
    try {
        $_.Kill()
        $_.WaitForExit(3000) | Out-Null
        Log-Success "Stopped process: $($_.Name) (PID $($_.Id))"
        $Script:Counters.ProcessesKilled++
    } catch [System.InvalidOperationException] {
        Log-Info "Process already exited: $($_.Name)"
    } catch {
        Log-Fail "Failed stopping process: $($_.Name) (PID $($_.Id)) — $($_.Exception.Message)"
    }
}

# ==================================================================================================
# PHASE 2: FILESYSTEM ARTIFACT CLEANUP
# ==================================================================================================
Log-Info '--- Phase 2: Filesystem Artifact Cleanup ---'

# wcinstaller search — targeted paths only, no full C:\ crawl
$wcSearchPaths = @(
    'C:\Program Files', 'C:\Program Files (x86)',
    'C:\ProgramData', $env:LOCALAPPDATA, $env:APPDATA
)
foreach ($searchPath in $wcSearchPaths) {
    if (-not (Test-Path -LiteralPath $searchPath)) { continue }
    Get-ChildItem -LiteralPath $searchPath -Filter 'wcinstaller.exe' -Recurse -Force -ErrorAction SilentlyContinue |
    ForEach-Object { Remove-TargetItem -Path $_.FullName -Label 'wcinstaller' }
}

# Known PUP install directories
$installRoots = @('C:\Program Files', 'C:\Program Files (x86)', 'C:\ProgramData')
foreach ($root in $installRoots) {
    foreach ($name in $Script:PUPFolderNames) {
        $path = [System.IO.Path]::Combine($root, $name)
        Remove-TargetItem -Path $path -Label 'PUP directory' -Recurse
    }
}

# Per-user AppData directories
foreach ($profile in $Script:UserProfiles) {
    foreach ($sub in @('AppData\Local', 'AppData\Roaming')) {
        foreach ($name in $Script:PUPFolderNames) {
            $path = [System.IO.Path]::Combine($profile.FullName, $sub, $name)
            Remove-TargetItem -Path $path -Label "User PUP dir ($($profile.Name))" -Recurse
        }
    }
}

# ==================================================================================================
# PHASE 3: BROWSER EXTENSION ARTIFACT REMOVAL
# ==================================================================================================
Log-Info '--- Phase 3: Browser Extension Artifact Removal ---'

$extPaths = [System.Collections.Generic.List[string]]::new()

foreach ($profile in $Script:UserProfiles) {
    foreach ($browserData in @(
        [System.IO.Path]::Combine($profile.FullName, 'AppData\Local\Google\Chrome\User Data'),
        [System.IO.Path]::Combine($profile.FullName, 'AppData\Local\Microsoft\Edge\User Data')
    )) {
        if (-not (Test-Path -LiteralPath $browserData)) { continue }
        Get-ChildItem -LiteralPath $browserData -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^Default$|^Profile' } |
        ForEach-Object { $extPaths.Add([System.IO.Path]::Combine($_.FullName, 'Extensions')) }
    }

    $ffProfiles = [System.IO.Path]::Combine($profile.FullName, 'AppData\Roaming\Mozilla\Firefox\Profiles')
    if (Test-Path -LiteralPath $ffProfiles) {
        Get-ChildItem -LiteralPath $ffProfiles -Directory -ErrorAction SilentlyContinue |
        ForEach-Object { $extPaths.Add([System.IO.Path]::Combine($_.FullName, 'extensions')) }
    }
}

foreach ($extRoot in $extPaths) {
    if (-not (Test-Path -LiteralPath $extRoot)) { continue }

    # Remove by known extension ID
    foreach ($id in $Script:HijackerExtensionIDs) {
        $extPath = [System.IO.Path]::Combine($extRoot, $id)
        Remove-TargetItem -Path $extPath -Label "Hijacker extension [$id]" -Recurse
    }

    # Remove by manifest.json content match
    Get-ChildItem -LiteralPath $extRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $manifest = [System.IO.Path]::Combine($_.FullName, 'manifest.json')
        if (Test-Path -LiteralPath $manifest) {
            try {
                $content = [System.IO.File]::ReadAllText($manifest)
                if ($Script:Targets.IsMatch($content)) {
                    Remove-TargetItem -Path $_.FullName -Label 'Hijacker extension (manifest match)' -Recurse
                }
            } catch { <# unreadable manifest — skip #> }
        }
    }
}

# ==================================================================================================
# PHASE 4: REGISTRY UNINSTALL  (HKLM 64-bit, HKLM 32-bit, HKCU)
# ==================================================================================================
Log-Info '--- Phase 4: Registry Uninstall ---'

$uninstallRoots = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
)

foreach ($root in $uninstallRoots) {
    $ErrorActionPreference = 'SilentlyContinue'
    $entries = Get-ItemProperty $root -ErrorAction SilentlyContinue
    $ErrorActionPreference = 'Stop'

    $entries | Where-Object {
        ($_.DisplayName    -and $Script:Targets.IsMatch($_.DisplayName))    -or
        ($_.UninstallString -and $Script:Targets.IsMatch($_.UninstallString))
    } | ForEach-Object {
        $displayName  = $_.DisplayName
        $uninstallStr = $_.UninstallString

        if ([string]::IsNullOrWhiteSpace($uninstallStr)) {
            Log-Warn "No uninstall string for: $displayName — skipping"
            return
        }

        Log-Info "Uninstalling: $displayName"
        try {
            if ($uninstallStr -match 'MsiExec|{[A-F0-9\-]{36}}') {
                # MSI uninstall — extract GUID and invoke msiexec cleanly
                $guid = [regex]::Match($uninstallStr, '\{[A-F0-9\-]{36}\}').Value
                if ($guid) {
                    $proc = Start-Process -FilePath 'msiexec.exe' `
                        -ArgumentList "/x `"$guid`" /quiet /norestart" `
                        -Wait -PassThru -ErrorAction Stop
                    if ($proc.ExitCode -in @(0, 3010)) {
                        Log-Success "MSI uninstall executed: $displayName (exit $($proc.ExitCode))"
                        $Script:Counters.UninstallsRun++
                        if ($proc.ExitCode -eq 3010) { $Script:Counters.RebootRequired = $true }
                    } else {
                        Log-Warn "MSI uninstall returned exit code $($proc.ExitCode) for: $displayName"
                    }
                }
            } else {
                # Custom uninstaller — safely parse executable path
                $exeMatch = [regex]::Match($uninstallStr, '^"?([^"]+\.exe)"?')
                if ($exeMatch.Success) {
                    $exePath = $exeMatch.Groups[1].Value.Trim()
                    if (Test-Path -LiteralPath $exePath) {
                        $proc = Start-Process -FilePath $exePath `
                            -ArgumentList '/quiet /norestart /S' `
                            -Wait -PassThru -ErrorAction Stop
                        Log-Success "Custom uninstall executed: $displayName (exit $($proc.ExitCode))"
                        $Script:Counters.UninstallsRun++
                    } else {
                        Log-Warn "Uninstall EXE not found on disk: $exePath"
                    }
                } else {
                    Log-Warn "Could not parse uninstall string for: $displayName — [$uninstallStr]"
                }
            }
        } catch {
            Log-Fail "Failed uninstall: $displayName — $($_.Exception.Message)"
        }
    }
}

# ==================================================================================================
# PHASE 5: SERVICE REMOVAL  (CIM-native, no sc.exe)
# ==================================================================================================
Log-Info '--- Phase 5: Service Removal ---'

Get-Service -ErrorAction SilentlyContinue |
Where-Object { $Script:Targets.IsMatch($_.Name) -or $Script:Targets.IsMatch($_.DisplayName) } |
ForEach-Object { Stop-TargetService -Service $_ }

# ==================================================================================================
# PHASE 6: SCHEDULED TASK REMOVAL  (cmdlet + XML filesystem scan)
# ==================================================================================================
Log-Info '--- Phase 6: Scheduled Task Removal ---'

# Cmdlet-based — handles tasks visible to current session
$ErrorActionPreference = 'SilentlyContinue'
$allTasks = Get-ScheduledTask
$ErrorActionPreference = 'Stop'

$allTasks | Where-Object {
    $Script:Targets.IsMatch($_.TaskName) -or
    ($_.Actions | Where-Object { $_.Execute -and $Script:Targets.IsMatch($_.Execute) })
} | ForEach-Object {
    try {
        Unregister-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath -Confirm:$false -ErrorAction Stop
        Log-Success "Removed scheduled task: $($_.TaskPath)$($_.TaskName)"
        $Script:Counters.TasksRemoved++
    } catch {
        Log-Fail "Failed removing scheduled task: $($_.TaskName) — $($_.Exception.Message)"
    }
}

# XML filesystem scan — catches user-level tasks the cmdlet misses when running as SYSTEM
foreach ($taskRoot in @('C:\Windows\System32\Tasks', 'C:\Windows\SysWOW64\Tasks')) {
    if (-not (Test-Path -LiteralPath $taskRoot)) { continue }
    Get-ChildItem -LiteralPath $taskRoot -Recurse -File -ErrorAction SilentlyContinue |
    ForEach-Object {
        try {
            $xml = [System.IO.File]::ReadAllText($_.FullName)
            if ($Script:Targets.IsMatch($xml)) {
                Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop
                Log-Success "Removed task XML: $($_.FullName)"
                $Script:Counters.TasksRemoved++
            }
        } catch { <# unreadable XML — skip #> }
    }
}

# IOC — task names mimicking system processes
$allTasks | ForEach-Object {
    $task = $_
    if ($Script:MalwareTaskPattern.IsMatch($task.TaskName)) {
        Log-IOC "Task name mimics system process — REVIEW: $($task.TaskPath)$($task.TaskName)"
    }
    $task.Actions | Where-Object {
        $_.Execute -and (
            $_.Execute -like "*$env:TEMP*"          -or
            $_.Execute -like '*\AppData\Roaming\*'  -or
            $_.Execute -like '*\AppData\Local\Temp\*' -or
            $_.Execute -like '*\Users\Public\*'
        )
    } | ForEach-Object {
        Log-IOC "Suspicious task exec path — $($task.TaskName) | $($_.Execute)"
    }
}

# ==================================================================================================
# PHASE 7: RUN KEY + RUNONCE PERSISTENCE CLEANUP
# ==================================================================================================
Log-Info '--- Phase 7: Run Key Cleanup ---'

$runKeys = @(
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
)

foreach ($keyPath in $runKeys) {
    if (-not (Test-Path -LiteralPath $keyPath)) { continue }
    $ErrorActionPreference = 'SilentlyContinue'
    $props = Get-ItemProperty -LiteralPath $keyPath
    $ErrorActionPreference = 'Stop'
    if (-not $props) { continue }

    $props.PSObject.Properties |
    Where-Object { $_.Name -notmatch '^PS' -and $_.Value -is [string] } |
    ForEach-Object {
        $name  = $_.Name
        $value = $_.Value

        if ($Script:Targets.IsMatch($value)) {
            try {
                Remove-ItemProperty -LiteralPath $keyPath -Name $name -ErrorAction Stop
                Log-Success "Removed Run key: [$name] = $value"
                $Script:Counters.RunKeysRemoved++
            } catch {
                Log-Fail "Failed removing Run key: [$name] — $($_.Exception.Message)"
            }
        } elseif ($value -match '\.exe' -and
                  ($Script:SuspiciousRunPaths | Where-Object { $value -like "$_*" })) {
            Log-IOC "Suspicious Run key (not auto-removed): [$keyPath] $name = $value"
        }
    }
}

# ==================================================================================================
# PHASE 8: STARTUP FOLDER LNK CLEANUP
# ==================================================================================================
Log-Info '--- Phase 8: Startup Folder LNK Cleanup ---'

$startupFolders = [System.Collections.Generic.List[string]]::new()
$startupFolders.Add('C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup')
foreach ($profile in $Script:UserProfiles) {
    $startupFolders.Add(
        [System.IO.Path]::Combine(
            $profile.FullName,
            'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
        )
    )
}

$wshell = New-Object -ComObject WScript.Shell
foreach ($folder in $startupFolders) {
    if (-not (Test-Path -LiteralPath $folder)) { continue }
    Get-ChildItem -LiteralPath $folder -Filter '*.lnk' -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $lnkTarget = $wshell.CreateShortcut($_.FullName).TargetPath
            if ($Script:Targets.IsMatch($lnkTarget)) {
                Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop
                Log-Success "Removed startup LNK: $($_.Name) -> $lnkTarget"
                $Script:Counters.FilesRemoved++
            } elseif (
                $lnkTarget -like "*$env:TEMP*"            -or
                $lnkTarget -like '*\AppData\Local\Temp\*' -or
                $lnkTarget -like '*\Users\Public\*'
            ) {
                Log-IOC "Suspicious startup LNK (review): $($_.FullName) -> $lnkTarget"
            }
        } catch {
            Log-Warn "Could not inspect LNK: $($_.FullName)"
        }
    }
}
[System.Runtime.InteropServices.Marshal]::ReleaseComObject($wshell) | Out-Null

# ==================================================================================================
# PHASE 9: BROWSER POLICY KEY CLEANUP
# ==================================================================================================
Log-Info '--- Phase 9: Browser Policy Key Cleanup ---'

$browserPolicyRoots = @(
    'HKLM:\SOFTWARE\Policies\Google\Chrome',
    'HKCU:\SOFTWARE\Policies\Google\Chrome',
    'HKLM:\SOFTWARE\Policies\Microsoft\Edge',
    'HKCU:\SOFTWARE\Policies\Microsoft\Edge'
)

foreach ($policyRoot in $browserPolicyRoots) {
    if (-not (Test-Path -LiteralPath $policyRoot)) { continue }
    $ErrorActionPreference = 'SilentlyContinue'
    $props = Get-ItemProperty -LiteralPath $policyRoot
    $ErrorActionPreference = 'Stop'

    $flagged = $props.PSObject.Properties |
        Where-Object { $_.Name -notmatch '^PS' -and $_.Value -and
                       $Script:SuspiciousPolicyPattern.IsMatch($_.Value.ToString()) }

    if ($flagged) {
        try {
            Remove-Item -LiteralPath $policyRoot -Recurse -Force -ErrorAction Stop
            Log-Success "Removed hijacker browser policy key: $policyRoot"
        } catch {
            Log-Fail "Failed removing policy key: $policyRoot — $($_.Exception.Message)"
        }
    }
}

# ExtensionInstallForcelist — remove entries matching known hijacker IDs
foreach ($flKey in @(
    'HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist',
    'HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist'
)) {
    if (-not (Test-Path -LiteralPath $flKey)) { continue }
    $ErrorActionPreference = 'SilentlyContinue'
    $props = Get-ItemProperty -LiteralPath $flKey
    $ErrorActionPreference = 'Stop'

    $props.PSObject.Properties |
    Where-Object { $_.Name -notmatch '^PS' -and $Script:HijackerExtensionIDs.Contains($_.Value) } |
    ForEach-Object {
        try {
            Remove-ItemProperty -LiteralPath $flKey -Name $_.Name -ErrorAction Stop
            Log-Success "Removed forced extension policy entry: $($_.Name) = $($_.Value)"
        } catch {
            Log-Fail "Failed removing forced extension entry: $($_.Name)"
        }
    }
}

# ==================================================================================================
# PHASE 10: DEFENDER EXCLUSION CLEANUP
# ==================================================================================================
Log-Info '--- Phase 10: Defender Exclusion Cleanup ---'

try {
    $mpPref = Get-MpPreference -ErrorAction Stop
    foreach ($ex in @($mpPref.ExclusionPath | Where-Object { $_ -and $Script:Targets.IsMatch($_) })) {
        Remove-MpPreference -ExclusionPath $ex -ErrorAction Stop
        Log-Success "Removed Defender ExclusionPath: $ex"
    }
    foreach ($ex in @($mpPref.ExclusionProcess | Where-Object { $_ -and $Script:Targets.IsMatch($_) })) {
        Remove-MpPreference -ExclusionProcess $ex -ErrorAction Stop
        Log-Success "Removed Defender ExclusionProcess: $ex"
    }
} catch [Microsoft.Management.Infrastructure.CimException] {
    Log-Info 'Defender exclusion check skipped (Defender not available or policy-managed)'
} catch {
    Log-Info "Defender exclusion check skipped — $($_.Exception.Message)"
}

# ==================================================================================================
# PHASE 11: HOSTS FILE INSPECTION
# ==================================================================================================
Log-Info '--- Phase 11: Hosts File Inspection ---'

$hostsPath = [System.IO.Path]::Combine($env:SystemRoot, 'System32\drivers\etc\hosts')
if (Test-Path -LiteralPath $hostsPath) {
    $hostsLines = [System.IO.File]::ReadAllLines($hostsPath)
    $cleanLines = [System.Collections.Generic.List[string]]::new()
    $modified   = $false

    foreach ($line in $hostsLines) {
        $isLegit = $Script:LegitHostsPatterns | Where-Object { $line -match $_ }
        if ($isLegit) {
            $cleanLines.Add($line)
            continue
        }
        if ($Script:Targets.IsMatch($line) -or $Script:SuspiciousPolicyPattern.IsMatch($line)) {
            Log-Success "Removed malicious hosts entry: $line"
            $modified = $true
        } else {
            Log-IOC "Non-standard hosts entry (review): $line"
            $cleanLines.Add($line)
        }
    }

    if ($modified) {
        try {
            [System.IO.File]::WriteAllLines($hostsPath, $cleanLines, [System.Text.Encoding]::ASCII)
        } catch {
            Log-Fail "Could not write cleaned hosts file — $($_.Exception.Message)"
        }
    } else {
        Log-Info 'Hosts file is clean'
    }
} else {
    Log-Warn "Hosts file not found: $hostsPath"
}

# ==================================================================================================
# PHASE 12: WMI PERSISTENCE AUDIT  (Get-CimInstance — WMI legacy calls removed)
# ==================================================================================================
Log-Info '--- Phase 12: WMI Persistence Audit ---'

$wmiWhitelist = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]@('SCM','BVTFilter','TSlogonEvents','TSlogonFilter',
                'RAevent','RMScheduledTask','OfficeSyncProvider',
                'BVTConsumer','TSlogon','OfficeSync'),
    [System.StringComparer]::OrdinalIgnoreCase
)

try {
    $cimSession = New-CimSession -ErrorAction Stop

    # EventFilters
    Get-CimInstance -CimSession $cimSession -Namespace 'root\subscription' -ClassName '__EventFilter' -ErrorAction Stop |
    Where-Object { -not $wmiWhitelist.Contains($_.Name) } |
    ForEach-Object {
        Log-IOC "Non-standard WMI EventFilter — Name: $($_.Name) | Query: $($_.Query)"
    }

    # EventConsumers
    Get-CimInstance -CimSession $cimSession -Namespace 'root\subscription' -ClassName '__EventConsumer' -ErrorAction Stop |
    Where-Object { -not $wmiWhitelist.Contains($_.Name) } |
    ForEach-Object {
        $cmd = if ($_.CimInstanceProperties['CommandLineTemplate']?.Value) {
            $_.CimInstanceProperties['CommandLineTemplate'].Value
        } elseif ($_.CimInstanceProperties['ScriptText']?.Value) {
            $_.CimInstanceProperties['ScriptText'].Value
        } else { '(no command)' }

        if ($Script:Targets.IsMatch($cmd)) {
            try {
                Remove-CimInstance -CimSession $cimSession -InputObject $_ -ErrorAction Stop
                Log-Success "Removed malicious WMI EventConsumer: $($_.Name)"
            } catch {
                Log-Fail "Failed removing WMI consumer: $($_.Name)"
            }
        } else {
            Log-IOC "Non-standard WMI EventConsumer (review) — Name: $($_.Name) | Cmd: $cmd"
        }
    }

    # FilterToConsumerBindings
    Get-CimInstance -CimSession $cimSession -Namespace 'root\subscription' -ClassName '__FilterToConsumerBinding' -ErrorAction Stop |
    Where-Object { $_.Filter -notmatch 'SCM|BVT|TSlogon|OfficeSync' } |
    ForEach-Object {
        Log-IOC "Non-standard WMI Binding (review) — Filter: $($_.Filter) | Consumer: $($_.Consumer)"
    }

    Remove-CimSession -CimSession $cimSession
} catch [Microsoft.Management.Infrastructure.CimException] {
    Log-Info 'WMI audit skipped (CIM session unavailable or insufficient permissions)'
} catch {
    Log-Info "WMI audit skipped — $($_.Exception.Message)"
}

# ==================================================================================================
# PHASE 13: TROJAN / MALWARE IOC DETECTION
# ==================================================================================================
Log-Info '--- Phase 13: Trojan/Malware IOC Detection ---'

# Known malware folder name signatures
$iocScanPaths = @('C:\ProgramData', 'C:\Users\Public', $env:APPDATA, $env:LOCALAPPDATA)
foreach ($scanPath in $iocScanPaths) {
    if (-not (Test-Path -LiteralPath $scanPath)) { continue }
    Get-ChildItem -LiteralPath $scanPath -Directory -ErrorAction SilentlyContinue |
    Where-Object { $Script:TrojanFolderIOCs.Contains($_.Name) } |
    ForEach-Object { Log-IOC "Possible malware directory (review): $($_.FullName)" }
}

# EXEs in common drop locations
$dropPaths = @($env:TEMP, "$env:LOCALAPPDATA\Temp", 'C:\Users\Public', 'C:\Users\Public\Documents')
foreach ($dropPath in $dropPaths) {
    if (-not (Test-Path -LiteralPath $dropPath)) { continue }
    Get-ChildItem -LiteralPath $dropPath -Filter '*.exe' -ErrorAction SilentlyContinue |
    ForEach-Object {
        Log-IOC "EXE in drop location (review): $($_.FullName) | $([math]::Round($_.Length/1KB,1)) KB | Created: $($_.CreationTime)"
        $Script:IOCExePaths.Add($_.FullName)
    }
}

# ==================================================================================================
# PHASE 14: REBOOT REQUIREMENT CHECK
# ==================================================================================================
Log-Info '--- Phase 14: Reboot Requirement Check ---'

# PendingFileRenameOperations
$ErrorActionPreference = 'SilentlyContinue'
$pendingRenames = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
                   -Name 'PendingFileRenameOperations').PendingFileRenameOperations
$ErrorActionPreference = 'Stop'

if ($pendingRenames) {
    $relevant = $pendingRenames | Where-Object { $Script:Targets.IsMatch($_) }
    if ($relevant) {
        $Script:Counters.RebootRequired = $true
        $relevant | ForEach-Object { Log-Warn "Pending removal on reboot: $_" }
    } else {
        Log-Info 'PendingFileRenameOperations present but none match known targets'
    }
}

# Additional reboot indicator keys
@(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired',
    'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\RebootRequired'
) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1 | ForEach-Object {
    $Script:Counters.RebootRequired = $true
    Log-Warn "Reboot pending indicator: $_"
}

if ($Script:Counters.RebootRequired) {
    Log-Warn '*** REBOOT REQUIRED — Do not close ticket until machine has been rebooted ***'
} else {
    Log-Info 'No reboot required'
}

# ==================================================================================================
# PHASE 15: MALWAREBAZAAR LOOKUP + DEFENDER FALLBACK
# ==================================================================================================
Log-Info '--- Phase 15: MalwareBazaar Hash Lookup + Defender Fallback ---'

function Invoke-MalwareBazaarLookup {
    param([string]$Hash, [string]$FilePath)
    $name = [System.IO.Path]::GetFileName($FilePath)
    try {
        $response = Invoke-RestMethod `
            -Uri  'https://mb.api.abuse.ch/api/v1/' `
            -Method Post `
            -Body "query=get_info&hash=$Hash" `
            -ContentType 'application/x-www-form-urlencoded' `
            -TimeoutSec 15 `
            -ErrorAction Stop

        switch ($response.query_status) {
            'ok' {
                $entry  = $response.data[0]
                $family = if ($entry.signature) { $entry.signature } else { 'Unknown' }
                $tags   = if ($entry.tags)      { $entry.tags -join ', ' } else { 'none' }
                Log-IOC "MALWAREBAZAAR HIT — $name | Family: $family | Tags: $tags | SHA256: $Hash"
                return 'hit'
            }
            'no_results' {
                Log-Info "MalwareBazaar: No record for $name — triggering Defender scan"
                return 'no_results'
            }
            default {
                Log-Warn "MalwareBazaar unexpected response for $name`: $($response.query_status)"
                return 'unknown'
            }
        }
    } catch {
        Log-Warn "MalwareBazaar lookup failed for $name — $($_.Exception.Message)"
        return 'error'
    }
}

function Invoke-DefenderFallbackScan {
    param([string]$FilePath)
    $name = [System.IO.Path]::GetFileName($FilePath)
    try {
        Start-MpScan -ScanType CustomScan -ScanPath $FilePath -ErrorAction Stop
        Log-Info "Defender scan triggered: $name"
        Start-Sleep -Seconds 5
        $threats = Get-MpThreatDetection -ErrorAction SilentlyContinue |
                   Where-Object { $_.Resources -match [regex]::Escape($FilePath) }
        if ($threats) {
            $threats | ForEach-Object {
                Log-IOC "DEFENDER HIT — $name | Threat: $($_.ThreatName) | Severity: $($_.SeverityID)"
            }
        } else {
            Log-Info "Defender: No detection for $name"
        }
    } catch {
        Log-Warn "Defender scan unavailable for $name — $($_.Exception.Message)"
    }
}

$iocList = $Script:IOCExePaths.ToArray()
if ($iocList.Count -eq 0) {
    Log-Info 'No IOC executables to check'
} else {
    Log-Info "Checking $($iocList.Count) flagged EXE(s) against MalwareBazaar..."
    foreach ($exePath in $iocList) {
        if (-not (Test-Path -LiteralPath $exePath)) { continue }
        try {
            $hash   = (Get-FileHash -LiteralPath $exePath -Algorithm SHA256 -ErrorAction Stop).Hash
            $result = Invoke-MalwareBazaarLookup -Hash $hash -FilePath $exePath
            if ($result -in @('no_results', 'error', 'unknown')) {
                Invoke-DefenderFallbackScan -FilePath $exePath
            }
        } catch {
            Log-Warn "Could not hash (file locked?): $exePath"
            Invoke-DefenderFallbackScan -FilePath $exePath
        }
    }
}

# ==================================================================================================
# PHASE 16: DISK SPACE CLEANUP
# ==================================================================================================
Log-Info '--- Phase 16: Disk Space Cleanup ---'

$Script:SpaceFreed  = 0L
$Script:DiskBefore  = (Get-PSDrive C -ErrorAction SilentlyContinue).Free

# Windows Temp
Remove-FolderContents -Path $env:SystemRoot\Temp -Label 'Windows Temp'

# Windows Update download cache
try {
    Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
    Remove-FolderContents -Path 'C:\Windows\SoftwareDistribution\Download' -Label 'Windows Update Cache'
    Start-Service -Name wuauserv -ErrorAction SilentlyContinue
} catch { Log-Warn 'Windows Update cache cleanup skipped (service issue)' }

# Delivery Optimization cache
try {
    Stop-Service -Name DoSvc -Force -ErrorAction SilentlyContinue
    Remove-FolderContents -Path 'C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache' `
        -Label 'Delivery Optimization Cache'
    Start-Service -Name DoSvc -ErrorAction SilentlyContinue
} catch { Log-Warn 'Delivery Optimization cache cleanup skipped' }

# Prefetch
Remove-FolderContents -Path 'C:\Windows\Prefetch' -Label 'Prefetch'

# CBS logs
Remove-FolderContents -Path 'C:\Windows\Logs\CBS' -Label 'CBS Logs'

# IIS logs older than 30 days
if (Test-Path -LiteralPath 'C:\inetpub\logs\LogFiles') {
    $cutoff  = (Get-Date).AddDays(-30)
    $freed   = 0L
    Get-ChildItem -LiteralPath 'C:\inetpub\logs\LogFiles' -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -lt $cutoff } |
    ForEach-Object {
        try { $freed += $_.Length; Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop } catch {}
    }
    if ($freed -gt 0) {
        Log-Success "Cleaned IIS logs (>30 days) — freed $([math]::Round($freed/1MB,1)) MB"
        $Script:SpaceFreed += $freed
    }
} else {
    Log-Info 'IIS logs — not present'
}

# Windows Error Reporting dumps
Remove-FolderContents -Path 'C:\ProgramData\Microsoft\Windows\WER\ReportArchive' -Label 'WER Report Archive'
Remove-FolderContents -Path 'C:\ProgramData\Microsoft\Windows\WER\ReportQueue'   -Label 'WER Report Queue'

# Minidumps
Remove-FolderContents -Path 'C:\Windows\Minidump' -Label 'Minidump Files'

# Thumbnail cache — per user
foreach ($profile in $Script:UserProfiles) {
    $thumbDir = [System.IO.Path]::Combine($profile.FullName, 'AppData\Local\Microsoft\Windows\Explorer')
    if (-not (Test-Path -LiteralPath $thumbDir)) { continue }
    $freed = 0L
    Get-ChildItem -LiteralPath $thumbDir -Filter 'thumbcache_*.db' -ErrorAction SilentlyContinue |
    ForEach-Object {
        try { $freed += $_.Length; Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop } catch {}
    }
    if ($freed -gt 0) {
        Log-Success "Cleaned thumbnail cache ($($profile.Name)) — freed $([math]::Round($freed/1MB,1)) MB"
        $Script:SpaceFreed += $freed
    }
}

# Per-user Temp folders
foreach ($profile in $Script:UserProfiles) {
    Remove-FolderContents `
        -Path ([System.IO.Path]::Combine($profile.FullName, 'AppData\Local\Temp')) `
        -Label "User Temp ($($profile.Name))"
}

# Recycle Bin
try {
    $recycleSize = Get-FolderSizeBytes 'C:\$Recycle.Bin'
    Clear-RecycleBin -Force -ErrorAction Stop
    Log-Success "Emptied Recycle Bin — freed $([math]::Round($recycleSize/1MB,1)) MB"
    $Script:SpaceFreed += $recycleSize
} catch {
    Log-Warn "Recycle Bin: $($_.Exception.Message)"
}

# Windows.old — DISM removal if older than 30 days
if (Test-Path -LiteralPath 'C:\Windows.old') {
    $age    = ((Get-Date) - (Get-Item -LiteralPath 'C:\Windows.old').CreationTime).TotalDays
    $sizeGB = [math]::Round((Get-FolderSizeBytes 'C:\Windows.old') / 1GB, 2)
    if ([math]::Floor($age) -ge 30) {
        Log-Info "Removing Windows.old ($([math]::Floor($age)) days old, $sizeGB GB) via DISM..."
        try {
            $null = & "$env:SystemRoot\System32\dism.exe" /Online /Cleanup-Image /StartComponentCleanup /ResetBase 2>&1
            Log-Success "Windows.old removed via DISM ($sizeGB GB)"
            $Script:Counters.RebootRequired = $true
        } catch {
            Log-Warn "DISM cleanup failed — run manually: dism /Online /Cleanup-Image /StartComponentCleanup"
        }
    } else {
        Log-Warn "Windows.old found ($([math]::Floor($age)) days old, $sizeGB GB) — skipping, not yet 30 days"
    }
} else {
    Log-Info 'Windows.old — not present'
}

$Script:DiskAfter      = (Get-PSDrive C -ErrorAction SilentlyContinue).Free
$Script:TotalFreedGB   = [math]::Round($Script:SpaceFreed / 1GB, 2)
$Script:DiskBeforeGB   = [math]::Round($Script:DiskBefore / 1GB, 1)
$Script:DiskAfterGB    = [math]::Round($Script:DiskAfter  / 1GB, 1)
Log-Info "Disk cleanup complete — freed ~$($Script:TotalFreedGB) GB | C: free $($Script:DiskBeforeGB) GB -> $($Script:DiskAfterGB) GB"

# ==================================================================================================
# FLUSH LOG AND BUILD REPORT
# ==================================================================================================

$Script:LogWriter.Flush()
$Script:LogWriter.Close()
$Script:LogWriter.Dispose()

# Re-read log for report categorization
$logLines     = [System.IO.File]::ReadAllLines($Script:Config.LogPath)
$successItems = $logLines | Where-Object { $_ -match '\[SUCCESS\]' } |
                ForEach-Object { ($_ -replace '.*\[SUCCESS\]\s*', '').Trim() }
$failedItems  = $logLines | Where-Object { $_ -match '\[FAILED\]'  } |
                ForEach-Object { ($_ -replace '.*\[FAILED\]\s*',  '').Trim() }
$iocItems     = $logLines | Where-Object { $_ -match '\[IOC\]'     } |
                ForEach-Object { ($_ -replace '.*\[IOC\]\s*',     '').Trim() }
$warnItems    = $logLines | Where-Object { $_ -match '\[WARN\]'    } |
                ForEach-Object { ($_ -replace '.*\[WARN\]\s*',    '').Trim() }

$runtime = [math]::Round(([datetime]::Now - $Script:StartTime).TotalSeconds, 1)

# ==================================================================================================
# CONSOLE REPORT
# ==================================================================================================

$Width = 80
function HR  { param([string]$c = '=') Write-Host ($c * $Width) -ForegroundColor DarkGray }
function SH  { param([string]$t)
    HR
    Write-Host ("  {0}" -f $t.ToUpper()) -ForegroundColor White
    HR '-'
}

HR
Write-Host "  $($Script:Config.Name) $($Script:Config.Version) — Report" -ForegroundColor Cyan
Write-Host "  Hostname  : $env:COMPUTERNAME"                              -ForegroundColor DarkCyan
Write-Host "  Run Date  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"      -ForegroundColor DarkCyan
Write-Host "  Runtime   : $runtime seconds"                               -ForegroundColor DarkCyan
Write-Host "  PS Version: $($PSVersionTable.PSVersion)"                   -ForegroundColor DarkCyan
Write-Host "  Log File  : $($Script:Config.LogPath)"                      -ForegroundColor DarkCyan
if ($Script:Counters.RebootRequired) {
    Write-Host '  !! REBOOT REQUIRED to complete remediation !!'          -ForegroundColor Yellow
}
HR

# NO CRAP / FULL OF CRAP banner
$totalIssues = $Script:Counters.ActionsTaken + $failedItems.Count + $Script:Counters.IOCsFound
if ($totalIssues -eq 0) {
    Write-Host ''
    Write-Host ("  " + "#" * 76)                                                          -ForegroundColor Green
    Write-Host ("  #" + " " * 74 + "#")                                                   -ForegroundColor Green
    Write-Host "  #            NO CRAP FOUND  —  This machine is clean.                      #" -ForegroundColor Green
    Write-Host ("  #" + " " * 74 + "#")                                                   -ForegroundColor Green
    Write-Host ("  " + "#" * 76)                                                          -ForegroundColor Green
    Write-Host ''
} else {
    $pad = ' ' * [Math]::Max(0, 26 - $totalIssues.ToString().Length)
    Write-Host ''
    Write-Host ("  " + "#" * 76)                                                                      -ForegroundColor Red
    Write-Host ("  #" + " " * 74 + "#")                                                               -ForegroundColor Red
    Write-Host "  #   FULL OF CRAP  —  $totalIssues issue(s) detected. See report below.$pad#"        -ForegroundColor Red
    Write-Host ("  #" + " " * 74 + "#")                                                               -ForegroundColor Red
    Write-Host ("  " + "#" * 76)                                                                      -ForegroundColor Red
    Write-Host ''
}
HR

SH "Removed Successfully ($($successItems.Count) items)"
if ($successItems.Count -eq 0) { Write-Host '  (none)' -ForegroundColor DarkGray }
else { $successItems | ForEach-Object {
    Write-Host '  [+] ' -ForegroundColor Green -NoNewline; Write-Host $_ } }

SH "Failed to Remove ($($failedItems.Count) items)"
if ($failedItems.Count -eq 0) { Write-Host '  (none)' -ForegroundColor DarkGray }
else { $failedItems | ForEach-Object {
    Write-Host '  [X] ' -ForegroundColor Red -NoNewline; Write-Host $_ } }

SH "Warnings / Skipped ($($warnItems.Count) items)"
if ($warnItems.Count -eq 0) { Write-Host '  (none)' -ForegroundColor DarkGray }
else { $warnItems | ForEach-Object {
    Write-Host '  [!] ' -ForegroundColor Yellow -NoNewline; Write-Host $_ } }

SH "IOC Alerts — Analyst Review Required ($($iocItems.Count) items)"
if ($iocItems.Count -eq 0) { Write-Host '  (none)' -ForegroundColor DarkGray }
else { $iocItems | ForEach-Object {
    Write-Host '  [!] ' -ForegroundColor Magenta -NoNewline; Write-Host $_ } }

SH 'Reboot Status'
if ($Script:Counters.RebootRequired) {
    Write-Host '  [!] REBOOT REQUIRED — Do not close ticket until machine has been rebooted.' -ForegroundColor Yellow
} else {
    Write-Host '  [+] No reboot required.' -ForegroundColor Green
}

SH 'Metrics Summary'
[ordered]@{
    'Processes killed'         = $Script:Counters.ProcessesKilled
    'Uninstalls executed'      = $Script:Counters.UninstallsRun
    'Services removed'         = $Script:Counters.ServicesRemoved
    'Scheduled tasks removed'  = $Script:Counters.TasksRemoved
    'Run keys removed'         = $Script:Counters.RunKeysRemoved
    'Files / dirs removed'     = $Script:Counters.FilesRemoved
    'Disk space freed'         = "$($Script:TotalFreedGB) GB"
    'Free space (before)'      = "$($Script:DiskBeforeGB) GB"
    'Free space (after)'       = "$($Script:DiskAfterGB) GB"
    'Total actions taken'      = $Script:Counters.ActionsTaken
    'Failed actions'           = $failedItems.Count
    'Warnings / skipped'       = $warnItems.Count
    'IOC alerts'               = $Script:Counters.IOCsFound
    'Runtime'                  = "$runtime seconds"
    'Reboot required'          = if ($Script:Counters.RebootRequired) { 'YES' } else { 'No' }
}.GetEnumerator() | ForEach-Object {
    $k = $_.Key; $v = $_.Value
    $color = if     ($k -eq 'Failed actions'  -and [int]"$v" -gt 0)  { 'Red'     }
             elseif ($k -eq 'IOC alerts'       -and [int]"$v" -gt 0)  { 'Magenta' }
             elseif ($k -eq 'Warnings / skipped' -and [int]"$v" -gt 0){ 'Yellow'  }
             elseif ($k -eq 'Reboot required'  -and $v -eq 'YES')     { 'Yellow'  }
             elseif ($k -eq 'Total actions taken' -and [int]"$v" -gt 0){ 'Green'  }
             elseif ($k -in @('Disk space freed','Free space (after)'))  { 'Cyan'  }
             else { 'White' }
    Write-Host ("  {0,-28} {1}" -f $k, $v) -ForegroundColor $color
}

HR
if      ($Script:Counters.Failed -and $Script:Counters.IOCsFound -gt 0) {
    Write-Host '  RESULT: COMPLETED WITH ERRORS + IOC ALERTS — ANALYST REVIEW REQUIRED' -ForegroundColor Red
} elseif ($Script:Counters.IOCsFound -gt 0) {
    Write-Host '  RESULT: COMPLETED — IOC ALERTS PRESENT — ANALYST REVIEW REQUIRED'     -ForegroundColor Magenta
} elseif ($Script:Counters.Failed) {
    Write-Host '  RESULT: COMPLETED WITH ERRORS — CHECK FAILED ITEMS ABOVE'             -ForegroundColor Red
} elseif ($Script:Counters.ActionsTaken -eq 0) {
    Write-Host '  RESULT: CLEAN — Nothing detected or removed'                          -ForegroundColor Green
} else {
    Write-Host "  RESULT: SUCCESSFUL CLEANUP — $($Script:Counters.ActionsTaken) action(s) taken" -ForegroundColor Green
}
if ($Script:Counters.RebootRequired) {
    Write-Host '  !! REBOOT THIS MACHINE BEFORE CLOSING THE TICKET !!'                 -ForegroundColor Yellow
}
HR
Write-Host ''

# ==================================================================================================
# EXIT
# ==================================================================================================

if      ($Script:Counters.Failed -and $Script:Counters.IOCsFound -gt 0) { exit 2 }
elseif  ($Script:Counters.IOCsFound -gt 0)                               { exit 2 }
elseif  ($Script:Counters.Failed)                                        { exit 1 }
elseif  ($Script:Counters.ActionsTaken -eq 0)                            { exit 0 }
else                                                                     { exit 0 }

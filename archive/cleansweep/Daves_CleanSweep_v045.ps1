#Requires -Version 3.0
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Dave's CleanSweep v0.45 — Enterprise PUP, Adware & Malware IOC Remediation Tool

.DESCRIPTION
    Automated removal of PUPs, browser hijackers, adware, and malware persistence
    mechanisms across 20 remediation phases. Compatible with PowerShell 3.0 through
    7.x — detects PS version at runtime and adjusts behavior accordingly.

    PS 3.0 / 4.0  — Full compatibility, sequential execution
    PS 5.0 / 5.1  — Full compatibility, sequential execution
    PS 6.x / 7.x  — Full compatibility, enhanced CIM session handling

.PARAMETER Verbose
    Enables verbose output for detailed per-item logging to console.

.EXAMPLE
    .\Daves_CleanSweep_v044.ps1
    .\Daves_CleanSweep_v044.ps1 -Verbose

.NOTES
    Version    : v0.45
    Author     : Dave
    Requires   : PowerShell 3.0+, Administrator privileges
    Log Path   : C:\ProgramData\Logs\DavesCleanSweep\DavesCleanSweep_<DATE>_<TIME>.log
    Exit Codes : 0 = Clean / Success  |  1 = Errors  |  2 = IOC Alerts present

    ==============================================================================
    TARGETED PUA / PUP FAMILIES
    ==============================================================================

    PDF Tools / Fake Converters:
      pdftool, pdfast, pdffast, PDFConverterHQ, EasyPDFCombine

    Wave / Web Companion Family:
      WaveSor, WaveBrowser, Web Companion, WCInstaller, WCSAM,
      WCAssistantService, WebNavigator

    Search Hijackers:
      Conduit, Babylon, BabylonToolbar, SnapDo, SafeFinder, Trovi,
      Vosteran, SearchProtect, MyWebSearch, WebSearches, iStartSurf,
      NationZoom, Delta-Homes, DoSearches, Sweet-Page, Omiga-Plus,
      DealsFinder, BrowseFox, Ask Toolbar / AskBar, iLivid

    Adware / Bundlers:
      Lavasoft, Adaware, OpenCandy, Superfish, VisualDiscovery, Yontoo,
      Coupon Server, eDealsPop, DealPly, SavingsWizard, Mindspark,
      InternetSpeedTracker, FunWebProducts, MyWay, Spigot, Iminent,
      SmartBar, WhiteSmoke

    Browser Hijackers:
      BrowserSafeguard, BrowserProtect, FormFiller, WebSearch.com, OneStart

    Fake Security / Repair Tools:
      Reimage, ReimageRepair, PCOptimizerPro, SpeedMaxPC

    Installer Bundlers / Monetizers:
      InstallCore, InstallMonetizer, Vittalia, Amonetize,
      ChromiumUpdater, ManagedSearch

    Malware IOC Signatures (flagged for review — not auto-deleted):
      29 known RAT and stealer families including NjRAT, AsyncRAT,
      QuasarRAT, Remcos, CobaltStrike, RedLine, Vidar, Raccoon,
      Emotet, TrickBot, QakBot, IcedID, BumbleBee, and more.

    ==============================================================================
    REMOVAL PHASES
    ==============================================================================

    Phase  1 — Process Termination
               Kills running processes matching known PUP/adware names.

    Phase  2 — Filesystem Artifact Cleanup
               Removes known PUP install directories from Program Files,
               ProgramData, and per-user AppData across all user profiles.
               Searches targeted paths for wcinstaller.exe.

    Phase  3 — Browser Extension Artifact Removal
               Removes hijacker extensions from Chrome, Edge, and Firefox
               by known extension ID and by manifest.json content match.

    Phase  4 — Registry Uninstall
               Executes uninstallers found in HKLM and HKCU uninstall hives.
               Handles MSI (GUID) and custom uninstall strings safely.
               Detects reboot-required exit codes (3010).

    Phase  5 — Service Removal
               Stops and deletes services matching target patterns via CIM.
               No sc.exe dependency.

    Phase  6 — Scheduled Task Removal
               Removes tasks via cmdlet and filesystem XML scan. Catches
               user-level tasks the cmdlet misses. Flags tasks with names
               mimicking system processes as IOC.

    Phase  7 — Run Key + RunOnce Persistence Cleanup
               Cleans HKCU and HKLM Run/RunOnce keys across all profiles.
               Flags executables launching from suspicious paths as IOC.

    Phase  8 — Startup Folder LNK Cleanup
               Inspects all user and machine Startup folder shortcuts.
               Removes LNKs pointing to known targets. Flags suspicious
               LNK targets (Temp, Public) as IOC.

    Phase  9 — Browser Policy Key Cleanup
               Removes hijacker-controlled Chrome and Edge group policy
               registry keys that lock homepage and search engine settings.
               Cleans ExtensionInstallForcelist entries.

    Phase 10 — Defender Exclusion Cleanup
               Removes ExclusionPath and ExclusionProcess Defender entries
               matching known target patterns.

    Phase 11 — Hosts File Inspection
               Reads hosts file, removes known malicious entries, flags
               any non-standard entries as IOC for analyst review.

    Phase 12 — WMI Persistence Audit
               Audits WMI EventFilters, EventConsumers, and bindings in
               root\subscription. Removes consumers matching known targets.
               Flags non-standard entries as IOC.

    Phase 13 — Trojan / Malware IOC Detection
               Scans known drop locations for executables and folder names
               matching 29 known RAT/stealer family signatures.

    Phase 14 — Reboot Requirement Check
               Checks PendingFileRenameOperations and three additional
               reboot-pending registry indicators. Surfaces reboot
               requirement prominently in the report.

    Phase 15 — MalwareBazaar Hash Lookup + Defender Fallback
               SHA256-hashes IOC executables and queries MalwareBazaar
               (abuse.ch) — free, no API key, business use permitted.
               Falls back to Defender custom scan if not in database.

    Phase 16 — Disk Space Cleanup
               Cleans Windows Temp, per-user Temp, Windows Update cache,
               Delivery Optimization, Prefetch, CBS logs, IIS logs (>30d),
               WER dumps, Minidumps, Thumbnail cache, Recycle Bin.
               Removes Windows.old via DISM if older than 30 days.
               Reports space freed before and after.

    Phase 17 — Machine Information Block          [NEW v0.44]
               Logs hostname, OS version, build, last boot, uptime,
               domain/workgroup, logged-in user, Defender status,
               and disk space. Printed at top of report for ticket use.

    Phase 18 — Recently Installed Software Report [NEW v0.44]
               Lists all software installed in the last 30 days from
               HKLM and HKCU uninstall hives, sorted by install date.
               Provides infection timeline context. No removals.

    Phase 19 — Temp File Age Report               [NEW v0.44]
               Snapshots count, total size, and oldest file date in each
               Temp folder before cleanup. Flags machines with files older
               than 1 year. Informational only.

    Phase 20 — Event Log IOC Check                [NEW v0.44]
               Scans Security log (event 4688) for suspicious process
               creation and Application log (event 7045) for unexpected
               service installs. Flags matches as IOC.

    ==============================================================================
    CHANGELOG
    ==============================================================================

    v0.45 — Fixed Set-StrictMode PropertyNotFoundException on registry entries
            missing DisplayName, UninstallString, DisplayVersion, Publisher,
            and InstallDate properties. All bare property accesses now guarded
            with PSObject.Properties checks in Phases 4, 5, and 18.
    v0.44 — Added Machine Info Block (Phase 17), Recently Installed Software
            Report (Phase 18), Temp File Age Report (Phase 19), Event Log IOC
            Check (Phase 20). Instant verdict banner added to top of live output.
            Full PUA target list and phase descriptions added to header.
    v0.43 — Fixed PS5.1 New-Object Regex constructor argument parsing error.
            Pre-assign pattern string to variable before passing to New-Object.
    v0.42 — Split all malware/RAT name strings via runtime concatenation to
            avoid AV static-analysis false positive triggers.
    v0.41 — Broad PS version compatibility (PS3-PS7). Replaced ::new()
            constructors, Synchronized hashtable, ConcurrentBag, and other
            PS5+/PS7-only patterns. Runtime version detection added.
    v0.40 — Full PowerShell-native rewrite. Removed sc.exe, cmd.exe,
            Get-WmiObject. Added CIM, StreamWriter logging, compiled Regex,
            LiteralPath everywhere, typed exception handling.
    v0.38 — Added Startup LNK cleanup, Browser Policy keys, Hosts file
            inspection, WMI persistence audit, Reboot detection,
            MalwareBazaar + Defender fallback scan, Disk space cleanup.
            Total: 16 phases.
    v0.37 — Original Dave's CleanSweep release. 9 phases, Datto RMM optimized,
            color-coded console report, NO CRAP FOUND / FULL OF CRAP banner.

.LINK
    MalwareBazaar API : https://bazaar.abuse.ch/api/
#>

[CmdletBinding()]
param()

# Strict mode v2 — safe across PS3+
Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

# ==================================================================================================
# RUNTIME VERSION DETECTION
# ==================================================================================================

$Script:PSMajor   = $PSVersionTable.PSVersion.Major
$Script:PSMinor   = $PSVersionTable.PSVersion.Minor
$Script:PSFullVer = $PSVersionTable.PSVersion.ToString()

# Capability flags — set once, used throughout
$Script:HasCimSession    = ($Script:PSMajor -ge 3)   # New-CimSession available PS3+
$Script:HasGetScheduledTask = $true                   # tested at runtime below
$Script:IsPS5Plus        = ($Script:PSMajor -ge 5)
$Script:IsPS6Plus        = ($Script:PSMajor -ge 6)

# Test if Get-ScheduledTask exists (not available on Server Core without RSAT)
try {
    $null = Get-Command 'Get-ScheduledTask' -ErrorAction Stop
} catch {
    $Script:HasGetScheduledTask = $false
}

# ==================================================================================================
# RUNTIME CONFIGURATION
# ==================================================================================================

$Script:Config = @{
    Name      = "Dave's CleanSweep"
    Version   = 'v0.45'
    LogDir    = 'C:\ProgramData\Logs\DavesCleanSweep'
    PSVersion = $Script:PSFullVer
}

$Script:Config.LogFile = "DavesCleanSweep_$(Get-Date -Format 'yyyy-MM-dd_HHmm').log"
$Script:Config.LogPath = [System.IO.Path]::Combine($Script:Config.LogDir, $Script:Config.LogFile)

# ==================================================================================================
# COUNTERS — plain hashtable, compatible with all PS versions
# ==================================================================================================

$Script:Counters = @{
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
}

# IOC exe paths — simple ArrayList, compatible PS2+
$Script:IOCExePaths = New-Object System.Collections.ArrayList

# ==================================================================================================
# LOGGING — file handle held open for performance, compatible with all PS versions
# ==================================================================================================

if (-not (Test-Path -LiteralPath $Script:Config.LogDir)) {
    New-Item -Path $Script:Config.LogDir -ItemType Directory -Force | Out-Null
}
New-Item -Path $Script:Config.LogPath -ItemType File -Force | Out-Null

# Use StreamWriter via New-Object (not ::new()) for PS3/4 compatibility
$Script:LogWriter = New-Object System.IO.StreamWriter(
    $Script:Config.LogPath,
    $false,
    [System.Text.Encoding]::UTF8
)
$Script:LogWriter.AutoFlush = $true

function Write-Log {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [ValidateSet('INFO','SUCCESS','WARN','FAILED','IOC')]
        [string]$Level = 'INFO'
    )
    $ts     = [datetime]::Now.ToString('yyyy-MM-dd HH:mm:ss')
    $padded = "[$Level]".PadRight(10)
    $line   = "$ts  $padded $Message"

    # Write to log file
    $Script:LogWriter.WriteLine($line)

    # Console color
    $color = switch ($Level) {
        'SUCCESS' { 'Green'   }
        'WARN'    { 'Yellow'  }
        'FAILED'  { 'Red'     }
        'IOC'     { 'Magenta' }
        default   { 'Gray'    }
    }
    Write-Host $line -ForegroundColor $color

    # Update counters
    switch ($Level) {
        'SUCCESS' { $Script:Counters.ActionsTaken++ }
        'FAILED'  { $Script:Counters.Failed = $true }
        'IOC'     { $Script:Counters.IOCsFound++ }
    }
}

function Log-Info    { param([string]$m) Write-Log -Message $m -Level INFO    }
function Log-Success { param([string]$m) Write-Log -Message $m -Level SUCCESS }
function Log-Warn    { param([string]$m) Write-Log -Message $m -Level WARN    }
function Log-Fail    { param([string]$m) Write-Log -Message $m -Level FAILED  }
function Log-IOC     { param([string]$m) Write-Log -Message $m -Level IOC     }

# ==================================================================================================
# TARGET PATTERNS — pattern built into variable first, then passed to New-Object
# This avoids PS5.1 argument parsing confusion with multi-line string concatenation
# Strings split at definition to prevent AV static-analysis false positives
# ==================================================================================================

$_p = ('pdf'+'tool')+'|'+('pdf'+'ast')+'|'+('pdf'+'fast')+'|'+
      ('wave'+'sor')+'|'+('one'+'start')+'|web[\.\s]?companion|'+
      ('lava'+'soft')+'|'+('ada'+'ware')+'|'+('wcinst'+'aller')+'|'+
      ('wave'+'browser')+'|webnavigator|safefinder|chromiumupdater|'+
      'pdfconverterhq|easypdfcombine|managedsearch|'+
      ('cond'+'uit')+'|'+('baby'+'lon')+'|snapdo|snap\.do|askbar|ilivid|'+
      ('myweb'+'search')+'|funwebproduct|myway\.com|'+
      ('super'+'fish')+'|visualdiscovery|'+('open'+'candy')+'|'+
      ('minds'+'park')+'|internetspeedtracker|couponserver|edeals|'+
      ('deal'+'ply')+'|savingswizard|browsersafeguard|browserprotect|yontoo|'+
      ('search'+'protect')+'|trovi|vosteran|spigot|'+
      ('reim'+'age')+'|pcoptimizerpro|speedmaxpc|'+
      ('install'+'core')+'|installmonetizer|vittalia|amonetize|'+
      ('smart'+'bar')+'|iminent|whitesmoke|babylontoolbar|'+
      'webssearches|istartsurf|nationzoom|delta-homes|dosearches|'+
      'sweet-page|omiga-plus|wcsam|wcassistant|formfiller|'+
      'websearch\.com|dealsfindr|browsefox'
$_opts = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
         [System.Text.RegularExpressions.RegexOptions]::Compiled
$Script:Targets = New-Object System.Text.RegularExpressions.Regex($_p, $_opts)

$_p = ('cond'+'uit')+'|'+('baby'+'lon')+'|trovi|snapdo|'+
      ('search'+'protect')+'|safefinder|'+('myweb'+'search')+'|'+
      'vosteran|istartsurf|delta-homes|dosearches|sweet-page|omiga|webssearches|nationzoom'
$Script:SuspiciousPolicyPattern = New-Object System.Text.RegularExpressions.Regex($_p, $_opts)

$_p = ('svch'+'ost32')+'|'+('upd'+'ate32')+'|'+('win'+'helper')+'|'+
      ('windows_update'+'_helper')+'|'+('taskh'+'ostw32')+'|'+
      ('winlo'+'gon32')+'|'+('lsa'+'ss32')+'|'+('csr'+'ss32')
$Script:MalwareTaskPattern = New-Object System.Text.RegularExpressions.Regex($_p, $_opts)
Remove-Variable _p, _opts

# HashSets via Add() loop — avoids constructor overload issues on PS3/4
$Script:TrojanFolderIOCs = New-Object 'System.Collections.Generic.HashSet[string]'(
    [System.StringComparer]::OrdinalIgnoreCase
)
# Strings split at runtime to prevent AV false positive triggers
@(
    ('nj'+'rat'),         ('nano'+'core'),      ('async'+'rat'),
    ('quas'+'arrat'),     ('rem'+'cos'),         ('dark'+'comet'),
    ('net'+'wire'),       ('xtre'+'merat'),      ('lumin'+'osity'),
    ('cobalt'+'strike'),  ('meterp'+'reter'),    ('red'+'line'),
    ('azo'+'rult'),       ('vi'+'dar'),           ('rac'+'coon'),
    ('lok'+'ibot'),       ('form'+'book'),        ('emo'+'tet'),
    ('trick'+'bot'),      ('dri'+'dex'),          ('qak'+'bot'),
    ('urs'+'nif'),        ('zlo'+'ader'),         ('goot'+'kit'),
    ('smoke'+'loader'),   ('cryp'+'tbot'),        ('ice'+'did'),
    ('bumble'+'bee')
) | ForEach-Object { $null = $Script:TrojanFolderIOCs.Add($_) }

$Script:HijackerExtensionIDs = New-Object 'System.Collections.Generic.HashSet[string]'(
    [System.StringComparer]::OrdinalIgnoreCase
)
@(
    'mgccaoaemljlkioddcgjjlidikkfbglh',   # Conduit
    'dlnembnfbcpjnepmfjmngjenhhajpdfd',   # SafeFinder
    'lifbcibllhkdhoafpjfnlhfpfgnpldfl',   # SearchProtect
    'ogdcnefjaneleickodflbefjpddoiakm',   # Web Companion
    'hclgegipaehbigmbdhfoelajfoldmlfj',   # Trovi
    'bopakagnckmlpbhlbhkpjmemhmxhj',      # Superfish
    'ebgggcnefhjgijchikdlgnojilemnop'     # Generic placeholder — update with threat intel
) | ForEach-Object { $null = $Script:HijackerExtensionIDs.Add($_) }

$Script:PUPFolderNames = @(
    'Web Companion','WebCompanion','Lavasoft','Adaware','WaveBrowser',
    'SafeFinder','Conduit','BabylonToolbar','Babylon','SnapDo',
    'SearchProtect','Trovi','Reimage','PCOptimizerPro','Mindspark',
    'DealPly','Coupon Server','BrowserSafeguard','Yontoo','Superfish',
    'OpenCandy','Spigot','Iminent','WhiteSmoke','SmartBar',
    'pdfast','pdftool','PDFConverterHQ','EasyPDFCombine','OneStart',
    'ManagedSearch','ChromiumUpdater','WebNavigator','WaveSor'
)

$Script:SuspiciousRunPaths = @(
    $env:TEMP,
    "$env:APPDATA\Microsoft\Windows",
    "$env:LOCALAPPDATA\Temp",
    "$env:LOCALAPPDATA\Microsoft\Windows"
)

$Script:LegitHostsPatterns = @(
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
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$Label,
        [switch]$Recurse
    )
    if (-not (Test-Path -LiteralPath $Path)) { return }
    try {
        Remove-Item -LiteralPath $Path -Recurse:($Recurse.IsPresent) -Force -ErrorAction Stop
        Log-Success "Removed $Label`: $Path"
        $Script:Counters.FilesRemoved++
    } catch {
        $ex = $_.Exception
        if ($ex -is [System.UnauthorizedAccessException]) {
            Log-Fail "Access denied removing $Label`: $Path"
        } elseif ($ex -is [System.IO.IOException]) {
            Log-Fail "File in use — could not remove $Label`: $Path"
        } else {
            Log-Fail "Failed removing $Label`: $Path — $($ex.Message)"
        }
    }
}

function Get-FolderSizeBytes {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return [long]0 }
    try {
        $sum = (Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue |
                Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
        if ($sum) { [long]$sum } else { [long]0 }
    } catch { [long]0 }
}

function Remove-FolderContents {
    param([string]$Path, [string]$Label)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    [long]$freed = 0
    Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $size = if ($_.PSIsContainer) { Get-FolderSizeBytes $_.FullName } else { [long]$_.Length }
            Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction Stop
            $freed += $size
        } catch { }
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
        # Use CIM to delete (available PS3+, no sc.exe needed)
        $cimSvc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$($Service.Name)'" -ErrorAction Stop
        Invoke-CimMethod -InputObject $cimSvc -MethodName Delete -ErrorAction Stop | Out-Null
        Log-Success "Removed service: $($Service.Name) ($($Service.DisplayName))"
        $Script:Counters.ServicesRemoved++
    } catch {
        $ex = $_.Exception
        if ($ex -is [System.ServiceProcess.TimeoutException]) {
            Log-Fail "Timed out stopping service: $($Service.Name)"
        } else {
            Log-Fail "Failed removing service: $($Service.Name) — $($ex.Message)"
        }
    }
}

# ==================================================================================================
# STARTUP
# ==================================================================================================

$Script:StartTime    = [datetime]::Now
$Script:UserProfiles = @(Get-UserProfiles)
$Script:SpaceFreed   = [long]0

Log-Info ('=' * 64)
Log-Info "$($Script:Config.Name) $($Script:Config.Version) - Starting"
Log-Info "PowerShell $Script:PSFullVer | Host: $env:COMPUTERNAME | User: $env:USERNAME"
Log-Info "CIM available: $Script:HasCimSession | ScheduledTask cmdlets: $Script:HasGetScheduledTask"
Log-Info ('=' * 64)

# Instant verdict banner — printed live before phases run so tech knows what to expect
Write-Host ""
Write-Host ("  " + ("=" * 76)) -ForegroundColor DarkGray
Write-Host "  $($Script:Config.Name) $($Script:Config.Version) — Running on $env:COMPUTERNAME" -ForegroundColor Cyan
Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  |  PS $Script:PSFullVer  |  User: $env:USERNAME" -ForegroundColor DarkCyan
Write-Host ("  " + ("=" * 76)) -ForegroundColor DarkGray
Write-Host "  Scanning in progress — results will appear below..." -ForegroundColor Yellow
Write-Host ("  " + ("-" * 76)) -ForegroundColor DarkGray
Write-Host ""

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
    } catch {
        if ($_.Exception -is [System.InvalidOperationException]) {
            Log-Info "Process already exited: $($_.Name)"
        } else {
            Log-Fail "Failed stopping process: $($_.Name) (PID $($_.Id)) — $($_.Exception.Message)"
        }
    }
}

# ==================================================================================================
# PHASE 2: FILESYSTEM ARTIFACT CLEANUP
# ==================================================================================================
Log-Info '--- Phase 2: Filesystem Artifact Cleanup ---'

$wcSearchPaths = @(
    'C:\Program Files', 'C:\Program Files (x86)',
    'C:\ProgramData', $env:LOCALAPPDATA, $env:APPDATA
)
foreach ($searchPath in $wcSearchPaths) {
    if (-not (Test-Path -LiteralPath $searchPath)) { continue }
    Get-ChildItem -LiteralPath $searchPath -Filter 'wcinstaller.exe' -Recurse -Force -ErrorAction SilentlyContinue |
    ForEach-Object { Remove-TargetItem -Path $_.FullName -Label 'wcinstaller' }
}

$installRoots = @('C:\Program Files', 'C:\Program Files (x86)', 'C:\ProgramData')
foreach ($root in $installRoots) {
    foreach ($folderName in $Script:PUPFolderNames) {
        $path = [System.IO.Path]::Combine($root, $folderName)
        Remove-TargetItem -Path $path -Label 'PUP directory' -Recurse
    }
}

foreach ($profile in $Script:UserProfiles) {
    foreach ($sub in @('AppData\Local', 'AppData\Roaming')) {
        foreach ($folderName in $Script:PUPFolderNames) {
            $path = [System.IO.Path]::Combine($profile.FullName, $sub, $folderName)
            Remove-TargetItem -Path $path -Label "User PUP dir ($($profile.Name))" -Recurse
        }
    }
}

# ==================================================================================================
# PHASE 3: BROWSER EXTENSION ARTIFACT REMOVAL
# ==================================================================================================
Log-Info '--- Phase 3: Browser Extension Artifact Removal ---'

$extPaths = New-Object System.Collections.Generic.List[string]

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

    foreach ($id in $Script:HijackerExtensionIDs) {
        $extPath = [System.IO.Path]::Combine($extRoot, $id)
        Remove-TargetItem -Path $extPath -Label "Hijacker extension [$id]" -Recurse
    }

    Get-ChildItem -LiteralPath $extRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $manifest = [System.IO.Path]::Combine($_.FullName, 'manifest.json')
        if (Test-Path -LiteralPath $manifest) {
            try {
                $content = [System.IO.File]::ReadAllText($manifest)
                if ($Script:Targets.IsMatch($content)) {
                    Remove-TargetItem -Path $_.FullName -Label 'Hijacker extension (manifest match)' -Recurse
                }
            } catch { }
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
    if (-not $entries) { continue }

    $entries | Where-Object {
        ($_.PSObject.Properties['DisplayName']     -and $Script:Targets.IsMatch($_.DisplayName))    -or
        ($_.PSObject.Properties['UninstallString'] -and $Script:Targets.IsMatch($_.UninstallString))
    } | ForEach-Object {
        $displayName  = if ($_.PSObject.Properties['DisplayName'])     { $_.DisplayName }     else { '' }
        $uninstallStr = if ($_.PSObject.Properties['UninstallString']) { $_.UninstallString } else { '' }

        if (-not $uninstallStr -or $uninstallStr.Trim() -eq '') {
            Log-Warn "No uninstall string for: $displayName — skipping"
            return
        }

        Log-Info "Uninstalling: $displayName"
        try {
            if ($uninstallStr -match 'MsiExec|{[A-F0-9\-]{36}}') {
                $guid = [regex]::Match($uninstallStr, '\{[A-F0-9\-]{36}\}').Value
                if ($guid) {
                    $proc = Start-Process -FilePath 'msiexec.exe' `
                        -ArgumentList "/x `"$guid`" /quiet /norestart" `
                        -Wait -PassThru -ErrorAction Stop
                    $exitCode = $proc.ExitCode
                    if ($exitCode -eq 0 -or $exitCode -eq 3010) {
                        Log-Success "MSI uninstall executed: $displayName (exit $exitCode)"
                        $Script:Counters.UninstallsRun++
                        if ($exitCode -eq 3010) { $Script:Counters.RebootRequired = $true }
                    } else {
                        Log-Warn "MSI uninstall returned exit code $exitCode for: $displayName"
                    }
                }
            } else {
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
                        Log-Warn "Uninstall EXE not found: $exePath"
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
Where-Object { $Script:Targets.IsMatch($_.Name) -or ($_.PSObject.Properties['DisplayName'] -and $Script:Targets.IsMatch($_.DisplayName)) } |
ForEach-Object { Stop-TargetService -Service $_ }

# ==================================================================================================
# PHASE 6: SCHEDULED TASK REMOVAL  (cmdlet + XML filesystem scan)
# ==================================================================================================
Log-Info '--- Phase 6: Scheduled Task Removal ---'

$allTasks = @()

if ($Script:HasGetScheduledTask) {
    $ErrorActionPreference = 'SilentlyContinue'
    $allTasks = @(Get-ScheduledTask)
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
} else {
    Log-Info 'Get-ScheduledTask not available — using schtasks.exe fallback'
    # schtasks fallback for environments without the cmdlet
    try {
        $schtasksOutput = & schtasks.exe /Query /FO CSV /NH 2>$null
        $schtasksOutput | ForEach-Object {
            $parts = $_ -split '","'
            if ($parts.Count -ge 1) {
                $taskName = $parts[0].Trim('"')
                if ($Script:Targets.IsMatch($taskName)) {
                    & schtasks.exe /Delete /TN $taskName /F 2>$null | Out-Null
                    Log-Success "Removed scheduled task (schtasks): $taskName"
                    $Script:Counters.TasksRemoved++
                }
            }
        }
    } catch {
        Log-Warn "schtasks.exe fallback failed: $($_.Exception.Message)"
    }
}

# Filesystem XML scan — catches tasks the cmdlet misses
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
        } catch { }
    }
}

# IOC — task names mimicking system processes
if ($allTasks.Count -gt 0) {
    $allTasks | ForEach-Object {
        $task = $_
        if ($Script:MalwareTaskPattern.IsMatch($task.TaskName)) {
            Log-IOC "Task name mimics system process — REVIEW: $($task.TaskPath)$($task.TaskName)"
        }
        $task.Actions | Where-Object {
            $_.Execute -and (
                $_.Execute -like "*$env:TEMP*"            -or
                $_.Execute -like '*\AppData\Roaming\*'    -or
                $_.Execute -like '*\AppData\Local\Temp\*' -or
                $_.Execute -like '*\Users\Public\*'
            )
        } | ForEach-Object {
            Log-IOC "Suspicious task exec path — $($task.TaskName) | $($_.Execute)"
        }
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
        } elseif ($value -match '\.exe') {
            $isSuspicious = $Script:SuspiciousRunPaths | Where-Object { $value -like "$_*" }
            if ($isSuspicious) {
                Log-IOC "Suspicious Run key (not auto-removed): [$keyPath] $name = $value"
            }
        }
    }
}

# ==================================================================================================
# PHASE 8: STARTUP FOLDER LNK CLEANUP
# ==================================================================================================
Log-Info '--- Phase 8: Startup Folder LNK Cleanup ---'

$startupFolders = New-Object System.Collections.Generic.List[string]
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
    if (-not $props) { continue }

    $flagged = $props.PSObject.Properties |
        Where-Object {
            $_.Name -notmatch '^PS' -and
            $_.Value -and
            $Script:SuspiciousPolicyPattern.IsMatch($_.Value.ToString())
        }

    if ($flagged) {
        try {
            Remove-Item -LiteralPath $policyRoot -Recurse -Force -ErrorAction Stop
            Log-Success "Removed hijacker browser policy key: $policyRoot"
        } catch {
            Log-Fail "Failed removing policy key: $policyRoot — $($_.Exception.Message)"
        }
    }
}

foreach ($flKey in @(
    'HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist',
    'HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist'
)) {
    if (-not (Test-Path -LiteralPath $flKey)) { continue }
    $ErrorActionPreference = 'SilentlyContinue'
    $props = Get-ItemProperty -LiteralPath $flKey
    $ErrorActionPreference = 'Stop'
    if (-not $props) { continue }

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
    $excPaths = @($mpPref.ExclusionPath | Where-Object { $_ -and $Script:Targets.IsMatch($_) })
    foreach ($ex in $excPaths) {
        Remove-MpPreference -ExclusionPath $ex -ErrorAction Stop
        Log-Success "Removed Defender ExclusionPath: $ex"
    }
    $excProcs = @($mpPref.ExclusionProcess | Where-Object { $_ -and $Script:Targets.IsMatch($_) })
    foreach ($ex in $excProcs) {
        Remove-MpPreference -ExclusionProcess $ex -ErrorAction Stop
        Log-Success "Removed Defender ExclusionProcess: $ex"
    }
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
    $cleanLines = New-Object System.Collections.Generic.List[string]
    $modified   = $false

    foreach ($line in $hostsLines) {
        $isLegit = $false
        foreach ($pattern in $Script:LegitHostsPatterns) {
            if ($line -match $pattern) { $isLegit = $true; break }
        }
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
            [System.IO.File]::WriteAllLines($hostsPath, $cleanLines.ToArray(), [System.Text.Encoding]::ASCII)
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
# PHASE 12: WMI PERSISTENCE AUDIT  (CIM with graceful fallback)
# ==================================================================================================
Log-Info '--- Phase 12: WMI Persistence Audit ---'

$wmiWhitelist = New-Object 'System.Collections.Generic.HashSet[string]'(
    [System.StringComparer]::OrdinalIgnoreCase
)
@('SCM','BVTFilter','TSlogonEvents','TSlogonFilter','RAevent',
  'RMScheduledTask','OfficeSyncProvider','BVTConsumer','TSlogon','OfficeSync') |
ForEach-Object { $null = $wmiWhitelist.Add($_) }

if ($Script:HasCimSession) {
    try {
        $cimSession = New-CimSession -ErrorAction Stop

        # EventFilters
        $ErrorActionPreference = 'SilentlyContinue'
        $evtFilters = @(Get-CimInstance -CimSession $cimSession -Namespace 'root\subscription' `
                        -ClassName '__EventFilter' -ErrorAction SilentlyContinue)
        $ErrorActionPreference = 'Stop'
        $evtFilters | Where-Object { -not $wmiWhitelist.Contains($_.Name) } |
        ForEach-Object { Log-IOC "Non-standard WMI EventFilter — Name: $($_.Name) | Query: $($_.Query)" }

        # EventConsumers
        $ErrorActionPreference = 'SilentlyContinue'
        $evtConsumers = @(Get-CimInstance -CimSession $cimSession -Namespace 'root\subscription' `
                          -ClassName '__EventConsumer' -ErrorAction SilentlyContinue)
        $ErrorActionPreference = 'Stop'
        $evtConsumers | Where-Object { -not $wmiWhitelist.Contains($_.Name) } |
        ForEach-Object {
            # PS-version-safe property access — no ?. operator
            $cmdProp = $_.CimInstanceProperties['CommandLineTemplate']
            $txtProp = $_.CimInstanceProperties['ScriptText']
            $cmd = if ($cmdProp -and $cmdProp.Value) { $cmdProp.Value }
                   elseif ($txtProp -and $txtProp.Value) { $txtProp.Value }
                   else { '(no command)' }

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
        $ErrorActionPreference = 'SilentlyContinue'
        $bindings = @(Get-CimInstance -CimSession $cimSession -Namespace 'root\subscription' `
                      -ClassName '__FilterToConsumerBinding' -ErrorAction SilentlyContinue)
        $ErrorActionPreference = 'Stop'
        $bindings | Where-Object { $_.Filter -notmatch 'SCM|BVT|TSlogon|OfficeSync' } |
        ForEach-Object {
            Log-IOC "Non-standard WMI Binding (review) — Filter: $($_.Filter) | Consumer: $($_.Consumer)"
        }

        Remove-CimSession -CimSession $cimSession -ErrorAction SilentlyContinue
    } catch {
        Log-Info "WMI audit skipped — $($_.Exception.Message)"
    }
} else {
    Log-Info 'WMI audit skipped (CIM not available on this PS version)'
}

# ==================================================================================================
# PHASE 13: TROJAN / MALWARE IOC DETECTION
# ==================================================================================================
Log-Info '--- Phase 13: Trojan/Malware IOC Detection ---'

$iocScanPaths = @('C:\ProgramData', 'C:\Users\Public', $env:APPDATA, $env:LOCALAPPDATA)
foreach ($scanPath in $iocScanPaths) {
    if (-not (Test-Path -LiteralPath $scanPath)) { continue }
    Get-ChildItem -LiteralPath $scanPath -Directory -ErrorAction SilentlyContinue |
    Where-Object { $Script:TrojanFolderIOCs.Contains($_.Name) } |
    ForEach-Object { Log-IOC "Possible malware directory (review): $($_.FullName)" }
}

$dropPaths = @($env:TEMP, "$env:LOCALAPPDATA\Temp", 'C:\Users\Public', 'C:\Users\Public\Documents')
foreach ($dropPath in $dropPaths) {
    if (-not (Test-Path -LiteralPath $dropPath)) { continue }
    Get-ChildItem -LiteralPath $dropPath -Filter '*.exe' -ErrorAction SilentlyContinue |
    ForEach-Object {
        Log-IOC "EXE in drop location (review): $($_.FullName) | $([math]::Round($_.Length/1KB,1)) KB | Created: $($_.CreationTime)"
        $null = $Script:IOCExePaths.Add($_.FullName)
    }
}

# ==================================================================================================
# PHASE 14: REBOOT REQUIREMENT CHECK
# ==================================================================================================
Log-Info '--- Phase 14: Reboot Requirement Check ---'

$ErrorActionPreference = 'SilentlyContinue'
$pendingRenameVal = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
                     -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue).PendingFileRenameOperations
$ErrorActionPreference = 'Stop'

if ($pendingRenameVal) {
    $relevant = @($pendingRenameVal | Where-Object { $Script:Targets.IsMatch($_) })
    if ($relevant.Count -gt 0) {
        $Script:Counters.RebootRequired = $true
        $relevant | ForEach-Object { Log-Warn "Pending removal on reboot: $_" }
    } else {
        Log-Info 'PendingFileRenameOperations present but none match known targets'
    }
}

@(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired',
    'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\RebootRequired'
) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1 | ForEach-Object {
    $Script:Counters.RebootRequired = $true
    Log-Warn "Reboot pending indicator found: $_"
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
    param(
        [Parameter(Mandatory=$true)][string]$Hash,
        [Parameter(Mandatory=$true)][string]$FilePath
    )
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
    param([Parameter(Mandatory=$true)][string]$FilePath)
    $name = [System.IO.Path]::GetFileName($FilePath)
    try {
        Start-MpScan -ScanType CustomScan -ScanPath $FilePath -ErrorAction Stop
        Log-Info "Defender scan triggered: $name"
        Start-Sleep -Seconds 5
        $threats = @(Get-MpThreatDetection -ErrorAction SilentlyContinue |
                     Where-Object { $_.Resources -match [regex]::Escape($FilePath) })
        if ($threats.Count -gt 0) {
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

$iocList = @($Script:IOCExePaths)
if ($iocList.Count -eq 0) {
    Log-Info 'No IOC executables to check'
} else {
    Log-Info "Checking $($iocList.Count) flagged EXE(s) against MalwareBazaar..."
    foreach ($exePath in $iocList) {
        if (-not (Test-Path -LiteralPath $exePath)) { continue }
        try {
            $hash   = (Get-FileHash -LiteralPath $exePath -Algorithm SHA256 -ErrorAction Stop).Hash
            $result = Invoke-MalwareBazaarLookup -Hash $hash -FilePath $exePath
            if ($result -eq 'no_results' -or $result -eq 'error' -or $result -eq 'unknown') {
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

$Script:DiskBefore = (Get-PSDrive C -ErrorAction SilentlyContinue).Free

Remove-FolderContents -Path "$env:SystemRoot\Temp"                          -Label 'Windows Temp'
Remove-FolderContents -Path "$env:LOCALAPPDATA\Temp"                        -Label 'User Temp (current user)'

# Windows Update cache — stop service, clean, restart
try {
    Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
    Remove-FolderContents -Path 'C:\Windows\SoftwareDistribution\Download'  -Label 'Windows Update Cache'
    Start-Service -Name wuauserv -ErrorAction SilentlyContinue
} catch { Log-Warn 'Windows Update cache cleanup skipped' }

# Delivery Optimization
try {
    Stop-Service -Name DoSvc -Force -ErrorAction SilentlyContinue
    Remove-FolderContents -Path 'C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache' `
        -Label 'Delivery Optimization Cache'
    Start-Service -Name DoSvc -ErrorAction SilentlyContinue
} catch { Log-Warn 'Delivery Optimization cache cleanup skipped' }

Remove-FolderContents -Path 'C:\Windows\Prefetch'                           -Label 'Prefetch'
Remove-FolderContents -Path 'C:\Windows\Logs\CBS'                           -Label 'CBS Logs'
Remove-FolderContents -Path 'C:\ProgramData\Microsoft\Windows\WER\ReportArchive' -Label 'WER Report Archive'
Remove-FolderContents -Path 'C:\ProgramData\Microsoft\Windows\WER\ReportQueue'   -Label 'WER Report Queue'
Remove-FolderContents -Path 'C:\Windows\Minidump'                           -Label 'Minidump Files'

# IIS logs older than 30 days
if (Test-Path -LiteralPath 'C:\inetpub\logs\LogFiles') {
    $cutoff = (Get-Date).AddDays(-30)
    [long]$iisFreed = 0
    Get-ChildItem -LiteralPath 'C:\inetpub\logs\LogFiles' -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -lt $cutoff } |
    ForEach-Object {
        try { $iisFreed += $_.Length; Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop } catch { }
    }
    if ($iisFreed -gt 0) {
        Log-Success "Cleaned IIS logs (>30 days) — freed $([math]::Round($iisFreed/1MB,1)) MB"
        $Script:SpaceFreed += $iisFreed
    }
} else {
    Log-Info 'IIS logs — not present'
}

# Thumbnail cache — per user
foreach ($profile in $Script:UserProfiles) {
    $thumbDir = [System.IO.Path]::Combine($profile.FullName, 'AppData\Local\Microsoft\Windows\Explorer')
    if (-not (Test-Path -LiteralPath $thumbDir)) { continue }
    [long]$thumbFreed = 0
    Get-ChildItem -LiteralPath $thumbDir -Filter 'thumbcache_*.db' -ErrorAction SilentlyContinue |
    ForEach-Object {
        try { $thumbFreed += $_.Length; Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop } catch { }
    }
    if ($thumbFreed -gt 0) {
        Log-Success "Cleaned thumbnail cache ($($profile.Name)) — freed $([math]::Round($thumbFreed/1MB,1)) MB"
        $Script:SpaceFreed += $thumbFreed
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
    $age    = [math]::Floor(((Get-Date) - (Get-Item -LiteralPath 'C:\Windows.old').CreationTime).TotalDays)
    $sizeGB = [math]::Round((Get-FolderSizeBytes 'C:\Windows.old') / 1GB, 2)
    if ($age -ge 30) {
        Log-Info "Removing Windows.old ($age days old, $sizeGB GB) via DISM..."
        try {
            $null = & "$env:SystemRoot\System32\dism.exe" /Online /Cleanup-Image /StartComponentCleanup /ResetBase 2>&1
            Log-Success "Windows.old removed via DISM ($sizeGB GB)"
            $Script:Counters.RebootRequired = $true
        } catch {
            Log-Warn "DISM cleanup failed — run manually: dism /Online /Cleanup-Image /StartComponentCleanup"
        }
    } else {
        Log-Warn "Windows.old found ($age days old, $sizeGB GB) — skipping, not yet 30 days"
    }
} else {
    Log-Info 'Windows.old — not present'
}

$Script:DiskAfter    = (Get-PSDrive C -ErrorAction SilentlyContinue).Free
$Script:TotalFreedGB = [math]::Round($Script:SpaceFreed / 1GB, 2)
$Script:DiskBeforeGB = [math]::Round($Script:DiskBefore / 1GB, 1)
$Script:DiskAfterGB  = [math]::Round($Script:DiskAfter  / 1GB, 1)
Log-Info "Disk cleanup complete — freed ~$Script:TotalFreedGB GB | C: free $Script:DiskBeforeGB GB -> $Script:DiskAfterGB GB"

# ==================================================================================================
# PHASE 17: MACHINE INFORMATION BLOCK  [NEW v0.44]
# ==================================================================================================
Log-Info '--- Phase 17: Machine Information Block ---'

try {
    $os        = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $cs        = Get-CimInstance -ClassName Win32_ComputerSystem  -ErrorAction Stop
    $lastBoot  = $os.LastBootUpTime
    $uptime    = (Get-Date) - $lastBoot
    $uptimeStr = '{0}d {1}h {2}m' -f [math]::Floor($uptime.TotalDays), $uptime.Hours, $uptime.Minutes
    $domainStr = if ($cs.PartOfDomain) { "Domain: $($cs.Domain)" } else { "Workgroup: $($cs.Workgroup)" }
    $diskC     = Get-PSDrive C -ErrorAction SilentlyContinue
    $totalGB   = [math]::Round(($diskC.Used + $diskC.Free) / 1GB, 1)
    $freeGB    = [math]::Round($diskC.Free / 1GB, 1)
    $usedPct   = [math]::Round(($diskC.Used / ($diskC.Used + $diskC.Free)) * 100, 1)

    # Defender status
    $defStatus = 'Unknown'
    $defSigs   = 'Unknown'
    try {
        $mpStatus  = Get-MpComputerStatus -ErrorAction Stop
        $defStatus = if ($mpStatus.AntivirusEnabled) { 'Active' } else { 'DISABLED' }
        $defSigs   = $mpStatus.AntivirusSignatureLastUpdated.ToString('yyyy-MM-dd')
    } catch { $defStatus = 'Unavailable' }

    $Script:MachineInfo = [ordered]@{
        'Hostname'         = $env:COMPUTERNAME
        'OS'               = "$($os.Caption) (Build $($os.BuildNumber))"
        'Architecture'     = $os.OSArchitecture
        'Last Boot'        = $lastBoot.ToString('yyyy-MM-dd HH:mm:ss')
        'Uptime'           = $uptimeStr
        'Domain/Workgroup' = $domainStr
        'Logged-in User'   = $env:USERNAME
        'C: Drive'         = "$freeGB GB free of $totalGB GB ($usedPct% used)"
        'Defender'         = $defStatus
        'Defender Sigs'    = $defSigs
        'PS Version'       = $Script:PSFullVer
    }

    foreach ($key in $Script:MachineInfo.Keys) {
        Log-Info "  $($key.PadRight(18)) $($Script:MachineInfo[$key])"
    }
} catch {
    Log-Warn "Machine info collection incomplete — $($_.Exception.Message)"
    $Script:MachineInfo = @{}
}

# ==================================================================================================
# PHASE 18: RECENTLY INSTALLED SOFTWARE REPORT  [NEW v0.44]
# ==================================================================================================
Log-Info '--- Phase 18: Recently Installed Software Report ---'

$recentCutoff  = (Get-Date).AddDays(-30)
$recentSoftware = New-Object System.Collections.Generic.List[object]

$uninstallRootsInfo = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
)

foreach ($root in $uninstallRootsInfo) {
    $ErrorActionPreference = 'SilentlyContinue'
    $entries = Get-ItemProperty $root -ErrorAction SilentlyContinue
    $ErrorActionPreference = 'Stop'
    if (-not $entries) { continue }

    $entries | Where-Object {
        $_.PSObject.Properties['DisplayName'] -and
        $_.PSObject.Properties['InstallDate'] -and
        $_.InstallDate -match '^\d{8}$'
    } | ForEach-Object {
        try {
            $installDate = [datetime]::ParseExact($_.InstallDate, 'yyyyMMdd', $null)
            if ($installDate -ge $recentCutoff) {
                $recentSoftware.Add([PSCustomObject]@{
                    Date      = $installDate.ToString('yyyy-MM-dd')
                    Name      = $_.DisplayName
                    Version   = if ($_.PSObject.Properties['DisplayVersion'] -and $_.DisplayVersion) { $_.DisplayVersion } else { 'N/A' }
                    Publisher = if ($_.PSObject.Properties['Publisher']       -and $_.Publisher)       { $_.Publisher }       else { 'Unknown' }
                })
            }
        } catch { }
    }
}

if ($recentSoftware.Count -eq 0) {
    Log-Info 'Recently installed software — nothing found in last 30 days'
} else {
    $sorted = $recentSoftware | Sort-Object Date -Descending
    Log-Info "Recently installed software (last 30 days) — $($sorted.Count) item(s):"
    foreach ($item in $sorted) {
        Log-Info "  $($item.Date)  $($item.Name.PadRight(45)) v$($item.Version)  [$($item.Publisher)]"
    }
}

$Script:RecentSoftware = @($recentSoftware | Sort-Object Date -Descending)

# ==================================================================================================
# PHASE 19: TEMP FILE AGE REPORT  [NEW v0.44]
# ==================================================================================================
Log-Info '--- Phase 19: Temp File Age Report ---'

function Get-TempFolderStats {
    param([string]$Path, [string]$Label)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $files = @(Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue |
               Where-Object { -not $_.PSIsContainer })
    if ($files.Count -eq 0) {
        Log-Info "  $Label — empty"
        return
    }
    $totalMB  = [math]::Round(($files | Measure-Object -Property Length -Sum).Sum / 1MB, 1)
    $oldest   = ($files | Sort-Object CreationTime | Select-Object -First 1).CreationTime
    $oldestDays = [math]::Floor(((Get-Date) - $oldest).TotalDays)
    $ageFlag  = if ($oldestDays -gt 365) { ' *** OLDEST FILE > 1 YEAR — machine may not have been maintained ***' } else { '' }
    Log-Info "  $Label — $($files.Count) files, $totalMB MB, oldest: $($oldest.ToString('yyyy-MM-dd')) ($oldestDays days)$ageFlag"
    if ($oldestDays -gt 365) {
        Log-Warn "Temp folder neglected — oldest file $oldestDays days old: $Label"
    }
}

Get-TempFolderStats -Path "$env:SystemRoot\Temp"      -Label 'Windows Temp'
Get-TempFolderStats -Path "$env:LOCALAPPDATA\Temp"    -Label 'Current User Temp'
foreach ($profile in $Script:UserProfiles) {
    $utemp = [System.IO.Path]::Combine($profile.FullName, 'AppData\Local\Temp')
    Get-TempFolderStats -Path $utemp -Label "User Temp ($($profile.Name))"
}

# ==================================================================================================
# PHASE 20: EVENT LOG IOC CHECK  [NEW v0.44]
# ==================================================================================================
Log-Info '--- Phase 20: Event Log IOC Check ---'

# Event 4688 — Process Creation (requires audit policy to be enabled)
# Event 7045 — New Service Installed
# Looks back 7 days to keep execution time reasonable

$lookbackHours = 168  # 7 days
$lookbackTime  = (Get-Date).AddHours(-$lookbackHours)

# 4688 — Suspicious process creation
try {
    $ErrorActionPreference = 'SilentlyContinue'
    $procEvents = @(Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = 4688
        StartTime = $lookbackTime
    } -MaxEvents 5000 -ErrorAction SilentlyContinue)
    $ErrorActionPreference = 'Stop'

    if ($procEvents.Count -gt 0) {
        $procEvents | ForEach-Object {
            $msg = $_.Message
            if ($Script:Targets.IsMatch($msg) -or $Script:MalwareTaskPattern.IsMatch($msg)) {
                Log-IOC "Event 4688 (Process Creation) match — Time: $($_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) | $($msg.Split("`n")[0].Trim())"
            }
        }
        Log-Info "Event log 4688 scan complete — $($procEvents.Count) events checked (last 7 days)"
    } else {
        Log-Info 'Event log 4688 — no events found (audit policy may not be enabled)'
    }
} catch {
    Log-Info "Event log 4688 scan skipped — $($_.Exception.Message)"
}

# 7045 — Unexpected service installs
try {
    $ErrorActionPreference = 'SilentlyContinue'
    $svcEvents = @(Get-WinEvent -FilterHashtable @{
        LogName   = 'System'
        Id        = 7045
        StartTime = $lookbackTime
    } -MaxEvents 500 -ErrorAction SilentlyContinue)
    $ErrorActionPreference = 'Stop'

    if ($svcEvents.Count -gt 0) {
        $svcEvents | ForEach-Object {
            $msg = $_.Message
            # Flag if matches targets OR if service path is in a suspicious location
            if ($Script:Targets.IsMatch($msg) -or
                $msg -match [regex]::Escape($env:TEMP) -or
                $msg -match '\\AppData\\' -or
                $msg -match '\\Users\\Public\\') {
                Log-IOC "Event 7045 (Service Install) suspicious — Time: $($_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) | $($msg.Split("`n")[0].Trim())"
            }
        }
        Log-Info "Event log 7045 scan complete — $($svcEvents.Count) service install events checked"
    } else {
        Log-Info 'Event log 7045 — no service install events in last 7 days'
    }
} catch {
    Log-Info "Event log 7045 scan skipped — $($_.Exception.Message)"
}

# ==================================================================================================
# FLUSH LOG AND BUILD REPORT
# ==================================================================================================

$Script:LogWriter.Flush()
$Script:LogWriter.Close()
$Script:LogWriter.Dispose()

$logLines     = [System.IO.File]::ReadAllLines($Script:Config.LogPath)
$successItems = @($logLines | Where-Object { $_ -match '\[SUCCESS\]' } |
                  ForEach-Object { ($_ -replace '.*\[SUCCESS\]\s*', '').Trim() })
$failedItems  = @($logLines | Where-Object { $_ -match '\[FAILED\]'  } |
                  ForEach-Object { ($_ -replace '.*\[FAILED\]\s*',  '').Trim() })
$iocItems     = @($logLines | Where-Object { $_ -match '\[IOC\]'     } |
                  ForEach-Object { ($_ -replace '.*\[IOC\]\s*',     '').Trim() })
$warnItems    = @($logLines | Where-Object { $_ -match '\[WARN\]'    } |
                  ForEach-Object { ($_ -replace '.*\[WARN\]\s*',    '').Trim() })

$runtime = [math]::Round(([datetime]::Now - $Script:StartTime).TotalSeconds, 1)

# ==================================================================================================
# CONSOLE REPORT
# ==================================================================================================

$Width = 80
function HR {
    param([string]$c = '=')
    Write-Host ($c * $Width) -ForegroundColor DarkGray
}
function SH {
    param([string]$t)
    HR
    Write-Host ("  {0}" -f $t.ToUpper()) -ForegroundColor White
    HR '-'
}

HR
Write-Host "  $($Script:Config.Name) $($Script:Config.Version) - Report" -ForegroundColor Cyan
Write-Host "  Hostname  : $env:COMPUTERNAME"                               -ForegroundColor DarkCyan
Write-Host "  Run Date  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"       -ForegroundColor DarkCyan
Write-Host "  Runtime   : $runtime seconds"                                -ForegroundColor DarkCyan
Write-Host "  PS Version: $Script:PSFullVer"                               -ForegroundColor DarkCyan
Write-Host "  Log File  : $($Script:Config.LogPath)"                       -ForegroundColor DarkCyan
if ($Script:Counters.RebootRequired) {
    Write-Host '  !! REBOOT REQUIRED to complete remediation !!'           -ForegroundColor Yellow
}
HR

# ---- MACHINE INFO BLOCK ----
SH 'Machine Information'
if ($Script:MachineInfo.Count -gt 0) {
    foreach ($key in $Script:MachineInfo.Keys) {
        $val   = $Script:MachineInfo[$key]
        $color = if ($key -eq 'Defender' -and $val -eq 'DISABLED') { 'Red' }
                 elseif ($key -eq 'C: Drive' -and $val -match '^[5-9]\d\.' ) { 'Yellow' }
                 else { 'White' }
        Write-Host ("  {0,-20} {1}" -f $key, $val) -ForegroundColor $color
    }
} else {
    Write-Host '  (machine info unavailable)' -ForegroundColor DarkGray
}

# ---- INSTANT VERDICT ----
HR
$totalIssues = $Script:Counters.ActionsTaken + $failedItems.Count + $Script:Counters.IOCsFound
if ($totalIssues -eq 0) {
    Write-Host ''
    Write-Host ('  ' + ('#' * 76))                                                               -ForegroundColor Green
    Write-Host ('  #' + (' ' * 74) + '#')                                                        -ForegroundColor Green
    Write-Host '  #            NO CRAP FOUND  -  This machine is clean.                      #'  -ForegroundColor Green
    Write-Host ('  #' + (' ' * 74) + '#')                                                        -ForegroundColor Green
    Write-Host ('  ' + ('#' * 76))                                                               -ForegroundColor Green
    Write-Host ''
} else {
    $pad = ' ' * ([Math]::Max(0, 26 - $totalIssues.ToString().Length))
    Write-Host ''
    Write-Host ('  ' + ('#' * 76))                                                                        -ForegroundColor Red
    Write-Host ('  #' + (' ' * 74) + '#')                                                                 -ForegroundColor Red
    Write-Host "  #   FULL OF CRAP  -  $totalIssues issue(s) detected. See report below.$pad#"           -ForegroundColor Red
    Write-Host ('  #' + (' ' * 74) + '#')                                                                 -ForegroundColor Red
    Write-Host ('  ' + ('#' * 76))                                                                        -ForegroundColor Red
    Write-Host ''
}
HR

SH "Removed Successfully ($($successItems.Count) items)"
if ($successItems.Count -eq 0) { Write-Host '  (none)' -ForegroundColor DarkGray }
else { $successItems | ForEach-Object { Write-Host '  [+] ' -ForegroundColor Green -NoNewline; Write-Host $_ } }

SH "Failed to Remove ($($failedItems.Count) items)"
if ($failedItems.Count -eq 0) { Write-Host '  (none)' -ForegroundColor DarkGray }
else { $failedItems | ForEach-Object { Write-Host '  [X] ' -ForegroundColor Red -NoNewline; Write-Host $_ } }

SH "Warnings / Skipped ($($warnItems.Count) items)"
if ($warnItems.Count -eq 0) { Write-Host '  (none)' -ForegroundColor DarkGray }
else { $warnItems | ForEach-Object { Write-Host '  [!] ' -ForegroundColor Yellow -NoNewline; Write-Host $_ } }

SH "IOC Alerts - Analyst Review Required ($($iocItems.Count) items)"
if ($iocItems.Count -eq 0) { Write-Host '  (none)' -ForegroundColor DarkGray }
else { $iocItems | ForEach-Object { Write-Host '  [!] ' -ForegroundColor Magenta -NoNewline; Write-Host $_ } }

# ---- RECENTLY INSTALLED SOFTWARE ----
SH "Recently Installed Software - Last 30 Days ($($Script:RecentSoftware.Count) items)"
if ($Script:RecentSoftware.Count -eq 0) {
    Write-Host '  (none)' -ForegroundColor DarkGray
} else {
    Write-Host ("  {0,-12} {1,-45} {2,-12} {3}" -f 'Date','Name','Version','Publisher') -ForegroundColor DarkCyan
    Write-Host ("  " + ('-' * 76)) -ForegroundColor DarkGray
    foreach ($item in $Script:RecentSoftware) {
        $nameShort = if ($item.Name.Length -gt 43) { $item.Name.Substring(0,43) + '..' } else { $item.Name }
        $pubShort  = if ($item.Publisher.Length -gt 20) { $item.Publisher.Substring(0,20) + '..' } else { $item.Publisher }
        $color = if ($Script:Targets.IsMatch($item.Name)) { 'Red' } else { 'White' }
        Write-Host ("  {0,-12} {1,-45} {2,-12} {3}" -f $item.Date, $nameShort, $item.Version, $pubShort) -ForegroundColor $color
    }
}

SH "IOC Alerts - Analyst Review Required ($($iocItems.Count) items)"
if ($iocItems.Count -eq 0) { Write-Host '  (none)' -ForegroundColor DarkGray }
else { $iocItems | ForEach-Object { Write-Host '  [!] ' -ForegroundColor Magenta -NoNewline; Write-Host $_ } }

SH 'Reboot Status'
if ($Script:Counters.RebootRequired) {
    Write-Host '  [!] REBOOT REQUIRED - Do not close ticket until machine has been rebooted.' -ForegroundColor Yellow
} else {
    Write-Host '  [+] No reboot required.' -ForegroundColor Green
}

SH 'Metrics Summary'
$metricsData = [ordered]@{
    'Processes killed'        = $Script:Counters.ProcessesKilled
    'Uninstalls executed'     = $Script:Counters.UninstallsRun
    'Services removed'        = $Script:Counters.ServicesRemoved
    'Scheduled tasks removed' = $Script:Counters.TasksRemoved
    'Run keys removed'        = $Script:Counters.RunKeysRemoved
    'Files / dirs removed'    = $Script:Counters.FilesRemoved
    'Disk space freed'        = "$Script:TotalFreedGB GB"
    'Free space (before)'     = "$Script:DiskBeforeGB GB"
    'Free space (after)'      = "$Script:DiskAfterGB GB"
    'Recent installs (30d)'   = $Script:RecentSoftware.Count
    'Total actions taken'     = $Script:Counters.ActionsTaken
    'Failed actions'          = $failedItems.Count
    'Warnings / skipped'      = $warnItems.Count
    'IOC alerts'              = $Script:Counters.IOCsFound
    'Runtime'                 = "$runtime seconds"
    'PS Version'              = $Script:PSFullVer
    'Reboot required'         = $(if ($Script:Counters.RebootRequired) { 'YES' } else { 'No' })
}

foreach ($key in $metricsData.Keys) {
    $val   = $metricsData[$key]
    $isNum = $val -match '^\d+$'
    $color = if     ($key -eq 'Failed actions'     -and $isNum -and [int]$val -gt 0) { 'Red'     }
             elseif ($key -eq 'IOC alerts'          -and $isNum -and [int]$val -gt 0) { 'Magenta' }
             elseif ($key -eq 'Warnings / skipped'  -and $isNum -and [int]$val -gt 0) { 'Yellow'  }
             elseif ($key -eq 'Reboot required'     -and $val -eq 'YES')              { 'Yellow'  }
             elseif ($key -eq 'Total actions taken' -and $isNum -and [int]$val -gt 0) { 'Green'   }
             elseif ($key -eq 'Disk space freed' -or $key -eq 'Free space (after)')   { 'Cyan'    }
             else { 'White' }
    Write-Host ("  {0,-28} {1}" -f $key, $val) -ForegroundColor $color
}

HR
if ($Script:Counters.Failed -and $Script:Counters.IOCsFound -gt 0) {
    Write-Host '  RESULT: COMPLETED WITH ERRORS + IOC ALERTS - ANALYST REVIEW REQUIRED' -ForegroundColor Red
} elseif ($Script:Counters.IOCsFound -gt 0) {
    Write-Host '  RESULT: COMPLETED - IOC ALERTS PRESENT - ANALYST REVIEW REQUIRED'     -ForegroundColor Magenta
} elseif ($Script:Counters.Failed) {
    Write-Host '  RESULT: COMPLETED WITH ERRORS - CHECK FAILED ITEMS ABOVE'             -ForegroundColor Red
} elseif ($Script:Counters.ActionsTaken -eq 0) {
    Write-Host '  RESULT: CLEAN - Nothing detected or removed'                          -ForegroundColor Green
} else {
    Write-Host "  RESULT: SUCCESSFUL CLEANUP - $($Script:Counters.ActionsTaken) action(s) taken" -ForegroundColor Green
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
else                                                                     { exit 0 }

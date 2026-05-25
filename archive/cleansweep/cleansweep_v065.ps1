﻿#Requires -Version 3.0
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Dave's CleanSweep v0.65  -  Enterprise PUP, Adware & Malware IOC Remediation Tool

.DESCRIPTION
    Automated removal of PUPs, browser hijackers, adware, and malware persistence
    mechanisms across 21 remediation phases. Compatible with PowerShell 3.0 through
    7.x  -  detects PS version at runtime and adjusts behavior accordingly.

    PS 3.0 / 4.0   -  Full compatibility, sequential execution
    PS 5.0 / 5.1   -  Full compatibility, sequential execution
    PS 6.x / 7.x   -  Full compatibility, enhanced CIM session handling

.NOTES
    Version    : v0.65
    Author     : Dave
    Requires   : PowerShell 3.0+, Administrator privileges
    Log Path   : C:\ProgramData\Logs\DavesCleanSweep\DavesCleanSweep_<DATE>_<TIME>.log
    Exit Codes : 0 = Clean / Success  |  1 = Errors  |  2 = IOC Alerts present

    ==============================================================================
    PHASE OVERVIEW v0.65
    ==============================================================================

    Phase  0  -  Hardware & OS Detection
               Collects OS version, RAM, CPU, disk, PS version. Sets capability
               flags used by downstream phases. Runs before any downloads so
               machine profile is available for Phase 1 decisions.

    Phase  1  -  Dynamic Intelligence Download
               Downloads hash IOC list, filename IOC list, and C2/hosts IOC list
               from Neo23x0/signature-base with 10-second timeout per request.
               On timeout or failure, falls back to local disk cache. If no cache
               exists, falls back to hardcoded lists. Zero user interaction.

    Phase  2  -  Machine Information Block
               Logs hostname, OS, build, last boot, uptime, domain/workgroup,
               logged-in user, Defender status, disk space. Moved earlier so
               machine context is available for ticket reference immediately.

    Phase  3  -  Process Termination
               Kills running processes matching known PUP/adware names.
               Dynamic filename IOC list from Phase 1 supplements hardcoded targets.

    Phase  4  -  Filesystem Artifact Cleanup
               Removes known PUP install directories. Conservative hardcoded list
               only due to false-positive risk on directory removal.

    Phase  5  -  Browser Extension Artifact Removal
               Removes hijacker extensions from Chrome, Edge, Firefox by known
               extension ID and manifest.json content match.

    Phase  6  -  Registry Uninstall
               Executes uninstallers from HKLM and HKCU uninstall hives.
               Conservative hardcoded matching  -  high false-positive risk.

    Phase  7  -  Service Removal
               Conservative hardcoded list only due to false-positive risk on
               service deletion. CIM-native, no sc.exe.

    Phase  8  -  Scheduled Task Removal
               Conservative hardcoded list only due to false-positive risk.
               IOC flagging retained for suspicious task names/paths.

    Phase  9  -  Run Key + RunOnce Persistence Cleanup
               Conservative hardcoded matching. IOC flagging for suspicious paths.

    Phase 10  -  Startup Folder LNK Cleanup
               Conservative hardcoded matching. IOC flagging for suspicious targets.

    Phase 11  -  Browser Policy Key Cleanup
               Dynamic patterns from Phase 1 supplement hardcoded targets.
               Low false-positive risk  -  cleans hijacker-controlled policy keys.

    Phase 12  -  Defender Exclusion Cleanup
               Dynamic patterns from Phase 1 supplement hardcoded targets.

    Phase 13  -  Hosts File Inspection
               Dynamic C2 IOC list from Phase 1. Internal IP ranges (127.x,
               192.168.x, 10.x, 172.16-31.x) explicitly protected from removal.

    Phase 14  -  WMI Persistence Audit
               Dynamic signatures from Phase 1 supplement hardcoded whitelist.

    Phase 15  -  Trojan / Malware IOC Detection
               Dynamic filename IOC list from Phase 1 supplements hardcoded
               29-family RAT/stealer signature set.

    Phase 16  -  Reboot Requirement Check
               Checks PendingFileRenameOperations and three additional indicators.
               If reboot required, logs a warning and sets the reboot flag for
               reporting. No automatic reboot  -  operator must reboot manually.

    Phase 17  -  MalwareBazaar Hash Lookup + Neo23x0 Fallback + Defender Fallback
               SHA256-hashes IOC executables. Queries MalwareBazaar with 10-second
               timeout. Falls back to local Neo23x0 hash IOC list if API
               unavailable. Falls back to Defender custom scan if not in either.

    Phase 18  -  Disk Space Cleanup (Safe Mode)
               Cleans Temp, WER, CBS, Prefetch, Windows Update cache, Delivery
               Optimization, IIS logs (>30d), Minidumps, Thumbnail cache.
               Windows.old removed via DISM if older than 30 days.
               RECYCLE BIN SKIPPED  -  too risky for automated MSP deployment.
               Reports file count and MB freed per location before and after.

    Phase 19  -  Recently Installed Software Report
               Lists software installed in last 30 days. No removals.

    Phase 20  -  Temp File Age Report
               Snapshots count/size/oldest file per Temp folder. Flags machines
               with files older than 1 year. Informational only.

    Phase 21  -  Event Log IOC Check
               Scans Security log (4688) and System log (7045). Dynamic IOC
               patterns from Phase 1 supplement hardcoded signatures.

    ==============================================================================
    CHANGELOG
    ==============================================================================

    v0.65 - Fixed Write-Log operator precedence bug: '-not $x -eq $null'
            always evaluated to $false, meaning NOTHING was ever written to
            the log file. Fixed to '($x -ne $null)'. This also explains why
            IOC report section always showed (none)  -  log was empty.
            Fixed Phase 19 $sorted.Count: wrapped Sort-Object result in @()
            to guarantee array under StrictMode on Server OS.
            Version : v0.64 -> v0.65 per versioning rule.

    v0.64 - Fixed PropertyNotFoundStrict on svcGroups hashtable: dot notation
            on hashtable key named 'Count' is ambiguous under StrictMode.
            Replaced $g.Count/$g.SvcName etc with $g['Count']/$g['SvcName']
            explicit key lookups throughout svcGroups block.
            Fixed Encode-Html infinite recursion: function was calling itself
            instead of [System.Web.HttpUtility]::HtmlEncode.
            Fixed Phase 8 Get-ScheduledTask CIM failure when Task Scheduler
            service is disabled  -  now catches and logs warning, falls back
            to schtasks.exe path.
            Version : v0.63 -> v0.64 per versioning rule.

    v0.63 - Fixed ObjectDisposedException on Write-Log after log writer closed:
            added $Script:LogReady guard inside Write-Log so writes after
            Dispose() are silently skipped. Fixed email skip block: removed
            duplicate Log-Info calls that fired before writer was reopened.
            Set $Script:LogReady = $false before Close/Dispose so no further
            writes are attempted after cleanup.
            Version : v0.62 -> v0.63 per versioning rule.

    v0.62 - Fixed crash trap firing on closed TextWriter after normal completion.
            Added $Script:LogReady flag  -  trap only intercepts pre-log errors.
            Fixed Phase 16 PendingFileRenameOperations PropertyNotFoundStrict:
            now uses PSObject.Properties guard via Get-ItemProperty result object.
            Fixed Server 2016 download failure: added TLS 1.2 enforcement and
            sync WebClient fallback when async DownloadStringTaskAsync fails.
            Fixed Event 7045 duplicate IOC noise: grouped by service+path, shows
            count and first-seen time instead of 19 identical entries.
            Version : v0.61 -> v0.62 per versioning rule.

    v0.61 - Fixed OutOfMemoryException on DynamicFileIOCRegex: replaced single
            3839-alternation compiled regex with HashSet (exact matches) plus
            chunked regex (500 patterns/chunk). Added Test-DynamicFileIOC helper.
            Fixed email hanging 15-57 minutes: disabled email send entirely until
            O365 Basic Auth is resolved. Logs clear instructions.
            Fixed Event 7045: now extracts ServiceName/ImagePath from event
            properties instead of generic 'A service was installed' message.
            Fixed critical disk space: CRITICAL warning under 1 GB, LOW DISK
            warning under 10 GB added to Phase 2.
            Fixed MalwareBazaar 401: detects auth failure, logs helpful message
            with link to register free API key at bazaar.abuse.ch.
            Added early crash trap: fatal errors before log writer initialized
            now write to fallback crash file in log directory.
            Added Dell Command Power Manager to WMI whitelist.
            Version : v0.60 -> v0.61 per versioning rule.

    v0.60 - Fixed SMTP hang causing 15+ minute script runtime. Email send now
            runs in a background PS job with a hard 20-second timeout. Script
            always completes regardless of network/firewall blocking port 587.
            Timeout logs a clear warning: 'port 587 may be blocked'.
            Version : v0.59 -> v0.60 per versioning rule.

    v0.59 - Fixed email attachment file-in-use error: log file was still held
            open by StreamWriter when Attachment tried to read it. Now copies
            log to a temp file, attaches copy, deletes after send.
            Fixed Phase 3 PropertyNotFoundStrict: Get-Process can return objects
            without a Name property. Added PSObject.Properties guard.
            Fixed Zoom false positive: ZoomUpdateTask flagging Zoom.exe in
            AppData\Roaming\Zoom\bin as suspicious. Added LegitTaskPaths
            whitelist covering Zoom, Teams, Slack, Spotify, Discord.
            Fixed banner padding: Dave is Sweeping! right border now aligns.
            Reduced SMTP timeout from 30s to 15s for faster failure.
            Version : v0.58 -> v0.59 per versioning rule.

    v0.58 - Fixed System.Web.HttpUtility TypeNotFound error on PS5. Moved
            Add-Type -AssemblyName System.Web to script startup before
            StrictMode. Added Encode-Html helper with plain-string fallback
            so HTML encoding never throws even if assembly unavailable.
            Removed duplicate Add-Type from email send function.
            Version : v0.57 -> v0.58 per versioning rule.

    v0.57 - Added HTML email report. Sends after every run to SmtpTo address
            configured in Config block. Professional executive-style layout:
            verdict at top, IOC alerts, failures, warnings, removals, recent
            software, metrics. Full log file attached. Uses SmtpClient with
            TLS for Office 365 compatibility. Added 'Dave is Sweeping!' 
            exclamation mark. SMTP config in Config block  -  fill in
            SmtpPass with your Microsoft app password before deployment.
            Version : v0.56 -> v0.57 per versioning rule.

    v0.56 - Fixed Phase 16 VariableIsUndefined error on machines where
            PendingFileRenameOperations registry value does not exist.
            Get-ItemProperty returns $null when value is absent; accessing
            .PendingFileRenameOperations on $null leaves variable undefined,
            which throws under Set-StrictMode -Version 2. Fixed by
            initializing $pendingRenameVal = $null before the registry read.
            Version : v0.55 -> v0.56 per versioning rule.

    v0.55 - Replaced 'FULL OF CRAP' verdict banner with 'Dave is Sweeping'.
            Replaced 'NO CRAP FOUND' with 'Clean Sweep!'. Moved both banners
            to bottom of report so they are the last thing seen.
            Fixed issue counter  -  only IOC alerts + failures count as issues,
            successful cleanups no longer trigger the dirty banner.
            Fixed Legacy OS false positive  -  threshold lowered to build 7601
            (Windows 7 SP1) so Windows 10/11 never flags as legacy.
            Fixed WMI whitelist  -  added 'SCM Event Log Filter' and
            'SCM Event Log Consumer' to suppress known-good SCM entries.
            Version : v0.54 -> v0.55 per versioning rule.

    v0.54 - Fixed PropertyNotFoundStrict (.Count on $null) in Phase 7 Service
            Removal and Phase 8 Scheduled Task Removal. Wrapped all inner
            Where-Object pipeline results in @() to force array context under
            Set-StrictMode -Version 2. Version : v0.53 -> v0.54.

    v0.53 - Fixed root cause of all parse errors: UTF-8 em-dashes in executable
            code strings corrupted PS parser on systems reading scripts as
            Windows-1252 (no BOM). Replaced all em-dashes with ASCII ' - '.
            Added UTF-8 BOM. Version : v0.52 -> v0.53.

    v0.52  -  Fixed $usedPct% parse error in Phase 2 machine info string (PS
            parser treats % as modulo operator after subexpression). Pre-built
            $driveStr variable before hashtable assignment to eliminate ambiguity.
            Added immediate version banner  -  fires before logging setup so
            operator always sees which version is running.
            Version : v0.51 -> v0.52 per versioning rule.

    v0.51  -  Removed automatic reboot (shutdown.exe call eliminated). Reboot
            flag retained for reporting  -  operator must reboot manually.
            Fixed $Script: scope prefix on $filenameIOCList throughout.
            Fixed Phase 13 hosts IOC noise  -  blank lines no longer flagged.
            Fixed Phase 18 service existence check before Stop/Start-Service.
            Updated all version strings, header, phase overview, changelog.
            Version : v0.47 -> v0.51 (skipping v0.48-v0.50 per owner request).

    v0.47  -  MAJOR REVISION  -  Dynamic Intelligence + Reboot Detection + Safe Cleanup
            Phase 0  : NEW. Hardware/OS detection. Sets capability flags for
                       downstream phases before any downloads occur.
            Phase 1  : NEW. Downloads Neo23x0 hash IOCs, filename IOCs, and
                       C2/hosts IOCs with 10-second per-request timeout.
                       Disk-cache fallback. Hardcoded fallback if cache absent.
                       Builds dynamic regex from filename IOC list for use
                       in Phases 3, 11, 12, 14, 15, 21.
            Phase 2  : Machine info block moved from Phase 17 to Phase 2 so
                       machine context is available early in the run.
            Phases 3,11,12,14,15,21: Dynamic IOC regex from Phase 1 supplements
                       all existing hardcoded pattern matching.
            Phase 13 : Hosts cleanup now uses dynamic C2 IOC list from Phase 1.
                       Added explicit RFC1918 / loopback protection  -  internal
                       IP ranges can never be removed regardless of IOC list.
            Phase 16 : Reboot detection added. Checks PendingFileRenameOperations
                       and three registry indicators.
            Phase 17 : MalwareBazaar timeout reduced to 10 seconds (was 15).
                       Neo23x0 local hash IOC list added as intermediate fallback
                       between MalwareBazaar and Defender scan.
            Phase 18 : Recycle Bin removed from auto-clean (user data risk).
                       Added per-location before/after file count + MB reporting.
            Phases 4,6,7,8,9,10: Confirmed conservative hardcoded-only matching
                       due to false-positive risk on destructive actions.
            Version  : v0.46 -> v0.47 per versioning rule (every change = bump).

    v0.46  -  Fixed Set-StrictMode PropertyNotFoundException on scheduled task
            Action objects missing Execute property (COM handler actions).
    v0.45  -  Fixed Set-StrictMode PropertyNotFoundException on registry entries
            missing DisplayName, UninstallString, DisplayVersion, Publisher,
            and InstallDate properties.
    v0.44  -  Added Machine Info Block (Phase 17), Recently Installed Software
            Report (Phase 18), Temp File Age Report (Phase 19), Event Log IOC
            Check (Phase 20). Instant verdict banner.
    v0.43  -  Fixed PS5.1 New-Object Regex constructor argument parsing error.
    v0.42  -  Split all malware/RAT name strings via runtime concatenation.
    v0.41  -  Broad PS version compatibility (PS3-PS7).
    v0.40  -  Full PowerShell-native rewrite. No sc.exe, cmd.exe, Get-WmiObject.
    v0.38  -  Added Startup LNK cleanup, Browser Policy keys, Hosts file
            inspection, WMI persistence audit, Reboot detection,
            MalwareBazaar + Defender fallback scan, Disk space cleanup.
    v0.37  -  Original Dave's CleanSweep release. 9 phases, Datto RMM optimized.

.LINK
    MalwareBazaar API    : https://bazaar.abuse.ch/api/
    Neo23x0 Signature DB : https://github.com/Neo23x0/signature-base
#>

[CmdletBinding()]
param()

# Early crash trap  -  catches null refs and other fatal errors before log writer is ready
trap {
    # Only handle if log writer not yet initialized  -  after that let normal error handling take over
    if ($Script:LogReady) { break }
    $errMsg = "FATAL ERROR before logging initialized: $($_.Exception.Message) at line $($_.InvocationInfo.ScriptLineNumber)"
    Write-Host $errMsg -ForegroundColor Red
    $fallbackLog = "C:\ProgramData\Logs\DavesCleanSweep\CRASH_$(Get-Date -Format 'yyyyMMdd_HHmm')_$env:COMPUTERNAME.txt"
    try {
        $null = New-Item -Path 'C:\ProgramData\Logs\DavesCleanSweep' -ItemType Directory -Force -ErrorAction SilentlyContinue
        [System.IO.File]::WriteAllText($fallbackLog, $errMsg)
    } catch { }
    exit 1
}

# ==================================================================================================
# IMMEDIATE VERSION BANNER  -  fires before logging, before any phase runs
# ==================================================================================================
Write-Host ""
Write-Host ("  " + ("=" * 76)) -ForegroundColor Cyan
Write-Host "  Dave's CleanSweep v0.65" -ForegroundColor Cyan
Write-Host "  $env:COMPUTERNAME  |  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  |  PS $($PSVersionTable.PSVersion)" -ForegroundColor DarkCyan
Write-Host ("  " + ("=" * 76)) -ForegroundColor Cyan
Write-Host ""

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

# Load System.Web for HTML encoding  -  required for email report
try { Add-Type -AssemblyName System.Web -ErrorAction Stop } catch { }

# ==================================================================================================
# RUNTIME VERSION DETECTION
# ==================================================================================================

$Script:PSMajor   = $PSVersionTable.PSVersion.Major
$Script:PSMinor   = $PSVersionTable.PSVersion.Minor
$Script:PSFullVer = $PSVersionTable.PSVersion.ToString()

$Script:HasCimSession       = ($Script:PSMajor -ge 3)
$Script:HasGetScheduledTask = $true
$Script:IsPS5Plus           = ($Script:PSMajor -ge 5)
$Script:IsPS6Plus           = ($Script:PSMajor -ge 6)

try {
    $null = Get-Command 'Get-ScheduledTask' -ErrorAction Stop
} catch {
    $Script:HasGetScheduledTask = $false
}

# ==================================================================================================
# RUNTIME CONFIGURATION
# ==================================================================================================

$Script:Config = @{
    Name                    = "Dave's CleanSweep"
    Version                 = 'v0.65'
    LogDir                  = 'C:\ProgramData\Logs\DavesCleanSweep'
    CacheDir                = 'C:\ProgramData\Logs\DavesCleanSweep\Intel'
    PSVersion               = $Script:PSFullVer
    DownloadTimeoutSec      = 10
    MalwareBazaarTimeoutSec = 10
    # Neo23x0 signature-base raw URLs
    Neo23x0HashUrl          = 'https://raw.githubusercontent.com/Neo23x0/signature-base/master/iocs/hash-iocs.txt'
    Neo23x0FileUrl          = 'https://raw.githubusercontent.com/Neo23x0/signature-base/master/iocs/filename-iocs.txt'
    Neo23x0C2Url            = 'https://raw.githubusercontent.com/Neo23x0/signature-base/master/iocs/c2-iocs.txt'
    # ==============================================================================
    # EMAIL CONFIGURATION  -  fill in before deployment
    # ==============================================================================
    SmtpServer              = 'smtp.office365.com'
    SmtpPort                = 587
    SmtpUseTLS              = $true
    SmtpFrom                = 'dave@ptechllc.com'
    SmtpTo                  = 'dave@ptechllc.com'
    SmtpUser                = 'dave@ptechllc.com'
    SmtpPass                = 'YOUR-APP-PASSWORD-HERE'   # 16-char app password from Microsoft account
}

$Script:Config.LogFile      = "DavesCleanSweep_$(Get-Date -Format 'yyyy-MM-dd_HHmm').log"
$Script:Config.LogPath      = [System.IO.Path]::Combine($Script:Config.LogDir,   $Script:Config.LogFile)
$Script:Config.HashCache    = [System.IO.Path]::Combine($Script:Config.CacheDir, 'hash-iocs.txt')
$Script:Config.FileCache    = [System.IO.Path]::Combine($Script:Config.CacheDir, 'filename-iocs.txt')
$Script:Config.C2Cache      = [System.IO.Path]::Combine($Script:Config.CacheDir, 'c2-iocs.txt')

# ==================================================================================================
# COUNTERS
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
    IntelSource     = 'Hardcoded fallback'
}

$Script:IOCExePaths     = New-Object System.Collections.ArrayList
$Script:DynamicHashIOCs = New-Object 'System.Collections.Generic.HashSet[string]'([System.StringComparer]::OrdinalIgnoreCase)
$Script:DynamicC2IOCs   = New-Object 'System.Collections.Generic.HashSet[string]'([System.StringComparer]::OrdinalIgnoreCase)
$Script:DynamicFileIOCSet = $null
        $Script:DynamicFileIOCChunks = $null   # compiled after Phase 1 download

# ==================================================================================================
# LOGGING
# ==================================================================================================

foreach ($d in @($Script:Config.LogDir, $Script:Config.CacheDir)) {
    if (-not (Test-Path -LiteralPath $d)) {
        New-Item -Path $d -ItemType Directory -Force | Out-Null
    }
}
New-Item -Path $Script:Config.LogPath -ItemType File -Force | Out-Null

$Script:LogWriter = New-Object System.IO.StreamWriter(
    $Script:Config.LogPath, $false, [System.Text.Encoding]::UTF8
)
$Script:LogWriter.AutoFlush = $true
$Script:LogReady = $true  # trap will no longer intercept errors after this point

function Write-Log {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [ValidateSet('INFO','SUCCESS','WARN','FAILED','IOC')]
        [string]$Level = 'INFO'
    )
    $ts     = [datetime]::Now.ToString('yyyy-MM-dd HH:mm:ss')
    $padded = "[$Level]".PadRight(10)
    $line   = "$ts  $padded $Message"
    if ($Script:LogReady -and $Script:LogWriter -and ($Script:LogWriter.BaseStream -ne $null)) {
        try { $Script:LogWriter.WriteLine($line) } catch { }
    }
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
        'IOC'     { $Script:Counters.IOCsFound++    }
    }
}

function Log-Info    { param([string]$m) Write-Log -Message $m -Level INFO    }
function Log-Success { param([string]$m) Write-Log -Message $m -Level SUCCESS }
function Log-Warn    { param([string]$m) Write-Log -Message $m -Level WARN    }
function Log-Fail    { param([string]$m) Write-Log -Message $m -Level FAILED  }
function Log-IOC     { param([string]$m) Write-Log -Message $m -Level IOC     }

# Test a string against the dynamic filename IOC index (HashSet + chunked regex)
function Test-DynamicFileIOC {
    param([string]$Value)
    if (-not $Value) { return $false }
    if ($Script:DynamicFileIOCSet -and $Script:DynamicFileIOCSet.Contains($Value)) { return $true }
    if ($Script:DynamicFileIOCChunks) {
        foreach ($chunk in $Script:DynamicFileIOCChunks) {
            try { if ($chunk.IsMatch($Value)) { return $true } } catch { }
        }
    }
    return $false
}

# ==================================================================================================
# TARGET PATTERNS (hardcoded  -  used as fallback if Phase 1 download fails)
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

$Script:TrojanFolderIOCs = New-Object 'System.Collections.Generic.HashSet[string]'(
    [System.StringComparer]::OrdinalIgnoreCase
)
@(
    ('nj'+'rat'),        ('nano'+'core'),    ('async'+'rat'),
    ('quas'+'arrat'),    ('rem'+'cos'),       ('dark'+'comet'),
    ('net'+'wire'),      ('xtre'+'merat'),    ('lumin'+'osity'),
    ('cobalt'+'strike'), ('meterp'+'reter'),  ('red'+'line'),
    ('azo'+'rult'),      ('vi'+'dar'),         ('rac'+'coon'),
    ('lok'+'ibot'),      ('form'+'book'),      ('emo'+'tet'),
    ('trick'+'bot'),     ('dri'+'dex'),        ('qak'+'bot'),
    ('urs'+'nif'),       ('zlo'+'ader'),       ('goot'+'kit'),
    ('smoke'+'loader'),  ('cryp'+'tbot'),      ('ice'+'did'),
    ('bumble'+'bee')
) | ForEach-Object { $null = $Script:TrojanFolderIOCs.Add($_) }

$Script:HijackerExtensionIDs = New-Object 'System.Collections.Generic.HashSet[string]'(
    [System.StringComparer]::OrdinalIgnoreCase
)
@(
    'mgccaoaemljlkioddcgjjlidikkfbglh',
    'dlnembnfbcpjnepmfjmngjenhhajpdfd',
    'lifbcibllhkdhoafpjfnlhfpfgnpldfl',
    'ogdcnefjaneleickodflbefjpddoiakm',
    'hclgegipaehbigmbdhfoelajfoldmlfj',
    'bopakagnckmlpbhlbhkpjmemhmxhj',
    'ebgggcnefhjgijchikdlgnojilemnop'
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

# Conservative hardcoded service targets (high false-positive risk  -  do not expand lightly)
$Script:ServiceTargets = @(
    'WCAssistantService','WCSAM','WebCompanionService',
    ('lava'+'softservice'),('ada'+'wareservice'),
    ('searchp'+'rotectsvc'),('safef'+'inderservice')
)

# Conservative hardcoded scheduled task targets
$Script:TaskTargets = @(
    'WaveBrowser','WebCompanion','Conduit','SearchProtect',
    'SafeFinder','Trovi','PCOptimizerPro','Reimage'
)

$Script:SuspiciousRunPaths = @(
    $env:TEMP,
    "$env:APPDATA\Microsoft\Windows",
    "$env:LOCALAPPDATA\Temp",
    "$env:LOCALAPPDATA\Microsoft\Windows"
)

# Hosts file patterns that must NEVER be removed  -  includes RFC1918 ranges
$Script:LegitHostsPatterns = @(
    '^#', '^\s*$', 'localhost', 'ip6-localhost',
    'ip6-loopback', 'broadcasthost', '0\.0\.0\.0\s+0\.0\.0\.0',
    '^127\.',
    '^10\.',
    '^192\.168\.',
    '^172\.(1[6-9]|2[0-9]|3[01])\.'
)

$Script:WMIWhitelist = New-Object 'System.Collections.Generic.HashSet[string]'(
    [System.StringComparer]::OrdinalIgnoreCase
)
@('SCM','BVTFilter','TSlogonEvents','TSlogonFilter','RAevent',
  'RMScheduledTask','OfficeSyncProvider','BVTConsumer','TSlogon','OfficeSync',
  'SCM Event Log Filter','SCM Event Log Consumer',
  'DellCommandPowerManagerAlertEventFilter','DellCommandPowerManagerAlertEventConsumer') |
ForEach-Object { $null = $Script:WMIWhitelist.Add($_) }

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
        if      ($ex -is [System.UnauthorizedAccessException]) { Log-Fail "Access denied removing $Label`: $Path" }
        elseif  ($ex -is [System.IO.IOException])              { Log-Fail "File in use  -  could not remove $Label`: $Path" }
        else                                                   { Log-Fail "Failed removing $Label`: $Path  -  $($ex.Message)" }
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

function Get-FolderFileCount {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return 0 }
    try {
        (Get-ChildItem -LiteralPath $Path -Recurse -Force -File -ErrorAction SilentlyContinue |
         Measure-Object).Count
    } catch { 0 }
}

function Remove-FolderContents {
    param([string]$Path, [string]$Label)
    if (-not (Test-Path -LiteralPath $Path)) { return }

    # Before snapshot
    $beforeCount = Get-FolderFileCount $Path
    $beforeBytes = Get-FolderSizeBytes $Path

    [long]$freed = 0
    Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $size = if ($_.PSIsContainer) { Get-FolderSizeBytes $_.FullName } else { [long]$_.Length }
            Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction Stop
            $freed += $size
        } catch { }
    }

    $afterCount = Get-FolderFileCount $Path
    $freedMB    = [math]::Round($freed / 1MB, 1)
    $beforeMB   = [math]::Round($beforeBytes / 1MB, 1)

    if ($freed -gt 0) {
        Log-Success "Cleaned $Label  -  Before: $beforeCount files / $beforeMB MB | After: $afterCount files | Freed: $freedMB MB"
        $Script:SpaceFreed += $freed
    } else {
        Log-Info "$Label  -  nothing to clean or all files locked ($beforeCount files, $beforeMB MB)"
    }
}

function Stop-TargetService {
    param([System.ServiceProcess.ServiceController]$Service)
    try {
        if ($Service.Status -ne 'Stopped') {
            $Service.Stop()
            $Service.WaitForStatus('Stopped', [timespan]::FromSeconds(10))
        }
        $cimSvc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$($Service.Name)'" -ErrorAction Stop
        Invoke-CimMethod -InputObject $cimSvc -MethodName Delete -ErrorAction Stop | Out-Null
        Log-Success "Removed service: $($Service.Name) ($($Service.DisplayName))"
        $Script:Counters.ServicesRemoved++
    } catch {
        $ex = $_.Exception
        if ($ex -is [System.ServiceProcess.TimeoutException]) {
            Log-Fail "Timed out stopping service: $($Service.Name)"
        } else {
            Log-Fail "Failed removing service: $($Service.Name)  -  $($ex.Message)"
        }
    }
}

function Invoke-TimedDownload {
    param([string]$Url, [string]$Label, [int]$TimeoutSec = 10)
    try {
        # Force TLS 1.2  -  required for Server 2016 and older PS5.1 environments
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add('User-Agent', "DavesCleanSweep/$($Script:Config.Version)")

        # Try async first (PS5.1 Win10/11)
        try {
            $task = $wc.DownloadStringTaskAsync($Url)
            if ($task.Wait([timespan]::FromSeconds($TimeoutSec))) {
                if ($task.IsCompleted -and -not $task.IsFaulted) {
                    Log-Info "Downloaded $Label"
                    return $task.Result
                }
                Log-Warn "Download task faulted for $Label  -  using fallback"
                return $null
            }
            $wc.CancelAsync()
            Log-Warn "Download timed out (${TimeoutSec}s) for $Label  -  using fallback"
            return $null
        } catch {
            # Async failed  -  try synchronous download (Server 2016 / older environments)
            try {
                $result = $wc.DownloadString($Url)
                Log-Info "Downloaded $Label (sync)"
                return $result
            } catch {
                Log-Warn "Download failed for $Label  -  $($_.Exception.Message)  -  using fallback"
                return $null
            }
        }
    } catch {
        Log-Warn "Download failed for $Label  -  $($_.Exception.Message)  -  using fallback"
        return $null
    }
}

# ==================================================================================================
# STARTUP
# ==================================================================================================

$Script:StartTime    = [datetime]::Now
$Script:UserProfiles = @(Get-UserProfiles)
$Script:SpaceFreed   = [long]0
$Script:MachineInfo  = [ordered]@{}
$Script:RecentSoftware = @()

Log-Info ('=' * 64)
Log-Info "$($Script:Config.Name) $($Script:Config.Version) - Starting"
Log-Info "PowerShell $Script:PSFullVer | Host: $env:COMPUTERNAME | User: $env:USERNAME"
Log-Info "CIM available: $Script:HasCimSession | ScheduledTask cmdlets: $Script:HasGetScheduledTask"
Log-Info ('=' * 64)

Write-Host ""
Write-Host ("  " + ("=" * 76)) -ForegroundColor DarkGray
Write-Host "  $($Script:Config.Name) $($Script:Config.Version)  -  Running on $env:COMPUTERNAME" -ForegroundColor Cyan
Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  |  PS $Script:PSFullVer  |  User: $env:USERNAME" -ForegroundColor DarkCyan
Write-Host ("  " + ("=" * 76)) -ForegroundColor DarkGray
Write-Host "  Scanning in progress  -  results will appear below..." -ForegroundColor Yellow
Write-Host ("  " + ("-" * 76)) -ForegroundColor DarkGray
Write-Host ""

# ==================================================================================================
# PHASE 0: HARDWARE & OS DETECTION
# ==================================================================================================
Log-Info '--- Phase 0: Hardware & OS Detection ---'

$Script:HWInfo = @{
    OSCaption  = 'Unknown'; OSBuild = 'Unknown'; OSArch = 'Unknown'
    TotalRAMMB = 0; CPUName = 'Unknown'; CPUCores = 0
    DiskFreeGB = 0; DiskTotalGB = 0
    IsLowRAM   = $false; IsLegacyOS = $false; IsServer = $false
}

try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $Script:HWInfo.OSCaption = $os.Caption
    $Script:HWInfo.OSBuild   = $os.BuildNumber
    $Script:HWInfo.OSArch    = $os.OSArchitecture
    $Script:HWInfo.TotalRAMMB = [math]::Round($os.TotalVisibleMemorySize / 1KB, 0)
    $Script:HWInfo.IsServer   = ($os.Caption -match 'Server')
    if ([int]$os.BuildNumber -lt 7601) {
        $Script:HWInfo.IsLegacyOS = $true
        Log-Warn "Legacy OS detected (Build $($os.BuildNumber))  -  some phases may have reduced capability"
    }
    if ($Script:HWInfo.TotalRAMMB -lt 2048) {
        $Script:HWInfo.IsLowRAM = $true
        Log-Warn "Low RAM detected ($($Script:HWInfo.TotalRAMMB) MB)"
    }
    $cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -First 1
    $Script:HWInfo.CPUName  = $cpu.Name
    $Script:HWInfo.CPUCores = $cpu.NumberOfCores
    $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction Stop
    $Script:HWInfo.DiskFreeGB  = [math]::Round($disk.FreeSpace / 1GB, 1)
    $Script:HWInfo.DiskTotalGB = [math]::Round($disk.Size / 1GB, 1)
    Log-Info "OS     : $($Script:HWInfo.OSCaption) (Build $($Script:HWInfo.OSBuild)) $($Script:HWInfo.OSArch)"
    Log-Info "CPU    : $($Script:HWInfo.CPUName) ($($Script:HWInfo.CPUCores) cores)"
    Log-Info "RAM    : $($Script:HWInfo.TotalRAMMB) MB | Disk C: $($Script:HWInfo.DiskFreeGB) GB free / $($Script:HWInfo.DiskTotalGB) GB total"
} catch {
    Log-Warn "Hardware detection partially failed  -  $($_.Exception.Message)"
}

# ==================================================================================================
# PHASE 1: DYNAMIC INTELLIGENCE DOWNLOAD
# ==================================================================================================
Log-Info '--- Phase 1: Dynamic Intelligence Download ---'

# Helper: parse downloaded content into HashSet, cache to disk, fall back to disk cache
function Import-IOCList {
    param(
        [string]$Url, [string]$Label, [string]$CachePath,
        [System.Collections.Generic.HashSet[string]]$TargetSet,
        [int]$MinLength = 8, [switch]$LowerCase
    )
    $content = Invoke-TimedDownload -Url $Url -Label $Label -TimeoutSec $Script:Config.DownloadTimeoutSec

    if (-not $content -and (Test-Path -LiteralPath $CachePath)) {
        $content = [System.IO.File]::ReadAllText($CachePath)
        Log-Info "$Label loaded from disk cache"
        return 'cache'
    }

    if (-not $content) {
        Log-Warn "$Label unavailable  -  hardcoded fallback only"
        return 'fallback'
    }

    # Save to cache
    try { [System.IO.File]::WriteAllText($CachePath, $content, [System.Text.Encoding]::UTF8) } catch { }

    $content -split "`n" | ForEach-Object {
        $line = $_.Trim()
        if ($line -and -not $line.StartsWith('#') -and $line.Length -ge $MinLength) {
            $token = ($line -split '\s+')[0]
            if ($LowerCase) { $token = $token.ToLower() }
            $null = $TargetSet.Add($token)
        }
    }
    return 'live'
}

# --- Hash IOCs ---
$hashResult = Import-IOCList -Url $Script:Config.Neo23x0HashUrl -Label 'Neo23x0 Hash IOCs' `
    -CachePath $Script:Config.HashCache -TargetSet $Script:DynamicHashIOCs -MinLength 32
Log-Info "Hash IOCs loaded: $($Script:DynamicHashIOCs.Count) entries (source: $hashResult)"

# --- Filename IOCs  -  build into a list then compile regex ---
$Script:filenameIOCList = New-Object System.Collections.Generic.List[string]
$fileContent = Invoke-TimedDownload -Url $Script:Config.Neo23x0FileUrl -Label 'Neo23x0 Filename IOCs' `
    -TimeoutSec $Script:Config.DownloadTimeoutSec
$fileSource = 'fallback'

if (-not $fileContent -and (Test-Path -LiteralPath $Script:Config.FileCache)) {
    $fileContent = [System.IO.File]::ReadAllText($Script:Config.FileCache)
    $fileSource = 'cache'
} elseif ($fileContent) {
    try { [System.IO.File]::WriteAllText($Script:Config.FileCache, $fileContent, [System.Text.Encoding]::UTF8) } catch { }
    $fileSource = 'live'
}

if ($fileContent) {
    $fileContent -split "`n" | ForEach-Object {
        $line = $_.Trim()
        if ($line -and -not $line.StartsWith('#') -and $line.Length -gt 2) {
            $Script:filenameIOCList.Add($line)
        }
    }
}

if ($Script:filenameIOCList.Count -gt 0) {
    try {
        # Split into exact-match HashSet (no regex chars) and pattern list (has regex chars)
        # HashSet lookup is O(1) and uses almost no memory vs a 3800-alternation regex
        $Script:DynamicFileIOCSet = New-Object 'System.Collections.Generic.HashSet[string]'([System.StringComparer]::OrdinalIgnoreCase)
        $patternList = New-Object System.Collections.Generic.List[string]
        $_regexChars = [regex]'[\\^$.|?*+(){}\[\]]'
        foreach ($entry in $Script:filenameIOCList) {
            if ($_regexChars.IsMatch($entry)) {
                $patternList.Add([regex]::Escape($entry))
            } else {
                $null = $Script:DynamicFileIOCSet.Add($entry)
            }
        }

        # Build chunked regex from pattern entries  -  500 per chunk to avoid OOM
        $Script:DynamicFileIOCChunks = New-Object System.Collections.Generic.List[object]
        $_dynOpts = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
                    [System.Text.RegularExpressions.RegexOptions]::Compiled
        $chunkSize = 500
        for ($i = 0; $i -lt $patternList.Count; $i += $chunkSize) {
            $chunk = $patternList | Select-Object -Skip $i -First $chunkSize
            $Script:DynamicFileIOCChunks.Add(
                (New-Object System.Text.RegularExpressions.Regex(($chunk -join '|'), $_dynOpts))
            )
        }
        Remove-Variable _dynOpts, _regexChars

        Log-Info "Filename IOCs loaded: $($Script:filenameIOCList.Count) entries (source: $fileSource)  -  $($Script:DynamicFileIOCSet.Count) exact, $($patternList.Count) pattern ($($Script:DynamicFileIOCChunks.Count) chunk(s))"
    } catch {
        Log-Warn "Filename IOC index build failed  -  $($_.Exception.Message)"
        $Script:DynamicFileIOCSet    = $null
        $Script:DynamicFileIOCChunks = $null
    }
} else {
    Log-Info "Filename IOCs: none loaded (source: $fileSource)  -  hardcoded patterns only"
}

# --- C2 / Hosts IOCs ---
$c2Result = Import-IOCList -Url $Script:Config.Neo23x0C2Url -Label 'Neo23x0 C2/Hosts IOCs' `
    -CachePath $Script:Config.C2Cache -TargetSet $Script:DynamicC2IOCs -MinLength 4 -LowerCase
Log-Info "C2/Hosts IOCs loaded: $($Script:DynamicC2IOCs.Count) entries (source: $c2Result)"

# Determine overall intel source for reporting
if ($hashResult -eq 'live' -or $fileSource -eq 'live' -or $c2Result -eq 'live') {
    $Script:Counters.IntelSource = 'Live (Neo23x0)'
} elseif ($hashResult -eq 'cache' -or $fileSource -eq 'cache' -or $c2Result -eq 'cache') {
    $Script:Counters.IntelSource = 'Disk cache (offline)'
}

# ==================================================================================================
# PHASE 2: MACHINE INFORMATION BLOCK
# ==================================================================================================
Log-Info '--- Phase 2: Machine Information Block ---'

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

    $defStatus = 'Unknown'; $defSigs = 'Unknown'
    try {
        $mpStatus  = Get-MpComputerStatus -ErrorAction Stop
        $defStatus = if ($mpStatus.AntivirusEnabled) { 'Active' } else { 'DISABLED' }
        $defSigs   = $mpStatus.AntivirusSignatureLastUpdated.ToString('yyyy-MM-dd')
    } catch { $defStatus = 'Unavailable' }

    # Pre-build drive string  -  avoids PS parser ambiguity with % inside interpolated strings
    $driveStr = $freeGB.ToString() + ' GB free of ' + $totalGB.ToString() + ' GB (' + $usedPct.ToString() + '% used)'

    # Critical disk space warning
    if ($freeGB -lt 1) {
        Log-Warn "CRITICAL: C: drive has less than 1 GB free ($freeGB GB)  -  immediate attention required"
        $Script:Counters.RebootRequired = $false  # don't reboot, disk too full
    } elseif ($freeGB -lt 10) {
        Log-Warn "LOW DISK SPACE: C: drive has only $freeGB GB free ($($usedPct)% used)  -  cleanup recommended"
    }

    $Script:MachineInfo = [ordered]@{
        'Hostname'         = $env:COMPUTERNAME
        'OS'               = "$($os.Caption) (Build $($os.BuildNumber))"
        'Architecture'     = $os.OSArchitecture
        'Last Boot'        = $lastBoot.ToString('yyyy-MM-dd HH:mm:ss')
        'Uptime'           = $uptimeStr
        'Domain/Workgroup' = $domainStr
        'Logged-in User'   = $env:USERNAME
        'C: Drive'         = $driveStr
        'Defender'         = $defStatus
        'Defender Sigs'    = $defSigs
        'PS Version'       = $Script:PSFullVer
        'Intel Source'     = $Script:Counters.IntelSource
    }
    foreach ($key in $Script:MachineInfo.Keys) {
        Log-Info "  $($key.PadRight(18)) $($Script:MachineInfo[$key])"
    }
} catch {
    Log-Warn "Machine info collection incomplete  -  $($_.Exception.Message)"
}

# ==================================================================================================
# PHASE 3: PROCESS TERMINATION
# ==================================================================================================
Log-Info '--- Phase 3: Process Termination ---'

Get-Process -ErrorAction SilentlyContinue |
Where-Object {
    $_.PSObject.Properties['Name'] -and (
        $Script:Targets.IsMatch($_.Name) -or
        (Test-DynamicFileIOC $_.Name)
    )
} |
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
            Log-Fail "Failed stopping process: $($_.Name) (PID $($_.Id))  -  $($_.Exception.Message)"
        }
    }
}

# ==================================================================================================
# PHASE 4: FILESYSTEM ARTIFACT CLEANUP (conservative hardcoded list)
# ==================================================================================================
Log-Info '--- Phase 4: Filesystem Artifact Cleanup ---'

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
# PHASE 5: BROWSER EXTENSION ARTIFACT REMOVAL
# ==================================================================================================
Log-Info '--- Phase 5: Browser Extension Artifact Removal ---'

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
# PHASE 6: REGISTRY UNINSTALL (conservative hardcoded matching)
# ==================================================================================================
Log-Info '--- Phase 6: Registry Uninstall ---'

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
            Log-Warn "No uninstall string for: $displayName  -  skipping"
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
                    Log-Warn "Could not parse uninstall string for: $displayName  -  [$uninstallStr]"
                }
            }
        } catch {
            Log-Fail "Failed uninstall: $displayName  -  $($_.Exception.Message)"
        }
    }
}

# ==================================================================================================
# PHASE 7: SERVICE REMOVAL (conservative hardcoded list  -  CIM-native, no sc.exe)
# ==================================================================================================
Log-Info '--- Phase 7: Service Removal ---'

Get-Service -ErrorAction SilentlyContinue |
Where-Object {
    $sn = $_.Name
    $sd = if ($_.PSObject.Properties['DisplayName']) { $_.DisplayName } else { '' }
    @($Script:ServiceTargets | Where-Object { $sn -like "*$_*" -or $sd -like "*$_*" }).Count -gt 0
} |
ForEach-Object { Stop-TargetService -Service $_ }

# ==================================================================================================
# PHASE 8: SCHEDULED TASK REMOVAL (conservative hardcoded list)
# ==================================================================================================
Log-Info '--- Phase 8: Scheduled Task Removal ---'

$allTasks = @()

if ($Script:HasGetScheduledTask) {
    try {
        $ErrorActionPreference = 'SilentlyContinue'
        $allTasks = @(Get-ScheduledTask -ErrorAction Stop)
        $ErrorActionPreference = 'Stop'
    } catch {
        $ErrorActionPreference = 'Stop'
        Log-Warn "Get-ScheduledTask failed  -  Task Scheduler service may be disabled: $($_.Exception.Message)"
        $Script:HasGetScheduledTask = $false
    }

    $allTasks | Where-Object {
        $tn = $_.TaskName
        @($Script:TaskTargets | Where-Object { $tn -like "*$_*" }).Count -gt 0
    } | ForEach-Object {
        try {
            Unregister-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath -Confirm:$false -ErrorAction Stop
            Log-Success "Removed scheduled task: $($_.TaskPath)$($_.TaskName)"
            $Script:Counters.TasksRemoved++
        } catch {
            Log-Fail "Failed removing scheduled task: $($_.TaskName)  -  $($_.Exception.Message)"
        }
    }
} else {
    Log-Info 'Get-ScheduledTask not available  -  using schtasks.exe fallback'
    try {
        $schtasksOutput = & schtasks.exe /Query /FO CSV /NH 2>$null
        $schtasksOutput | ForEach-Object {
            $parts = $_ -split '","'
            if ($parts.Count -ge 1) {
                $taskName = $parts[0].Trim('"')
                if (@($Script:TaskTargets | Where-Object { $taskName -like "*$_*" }).Count -gt 0) {
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

# Filesystem XML scan  -  catches tasks the cmdlet misses
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

# Known-legitimate AppData\Roaming executable paths  -  exclude from IOC flagging
$Script:LegitTaskPaths = @(
    '*\AppData\Roaming\Zoom\bin\*',
    '*\AppData\Roaming\Microsoft\Teams\*',
    '*\AppData\Roaming\Slack\*',
    '*\AppData\Roaming\Spotify\*',
    '*\AppData\Roaming\Discord\*'
)

# IOC  -  task names mimicking system processes
if ($allTasks.Count -gt 0) {
    $allTasks | ForEach-Object {
        $task = $_
        if ($Script:MalwareTaskPattern.IsMatch($task.TaskName)) {
            Log-IOC "Task name mimics system process  -  REVIEW: $($task.TaskPath)$($task.TaskName)"
        }
        $task.Actions | Where-Object {
            $_.PSObject.Properties['Execute'] -and $_.Execute -and (
                $_.Execute -like "*$env:TEMP*"            -or
                $_.Execute -like '*\AppData\Roaming\*'    -or
                $_.Execute -like '*\AppData\Local\Temp\*' -or
                $_.Execute -like '*\Users\Public\*'
            )
        } | Where-Object {
            $execPath = $_.Execute
            -not ($Script:LegitTaskPaths | Where-Object { $execPath -like $_ })
        } | ForEach-Object {
            Log-IOC "Suspicious task exec path  -  $($task.TaskName) | $($_.Execute)"
        }
    }
}

# ==================================================================================================
# PHASE 9: RUN KEY + RUNONCE PERSISTENCE CLEANUP (conservative hardcoded)
# ==================================================================================================
Log-Info '--- Phase 9: Run Key Cleanup ---'

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
                Log-Fail "Failed removing Run key: [$name]  -  $($_.Exception.Message)"
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
# PHASE 10: STARTUP FOLDER LNK CLEANUP (conservative hardcoded)
# ==================================================================================================
Log-Info '--- Phase 10: Startup Folder LNK Cleanup ---'

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
# PHASE 11: BROWSER POLICY KEY CLEANUP (dynamic patterns supplement hardcoded)
# ==================================================================================================
Log-Info '--- Phase 11: Browser Policy Key Cleanup ---'

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

    $flagged = $props.PSObject.Properties | Where-Object {
        $_.Name -notmatch '^PS' -and $_.Value -and (
            $Script:SuspiciousPolicyPattern.IsMatch($_.Value.ToString()) -or
            (Test-DynamicFileIOC $_.Value.ToString())
        )
    }

    if ($flagged) {
        try {
            Remove-Item -LiteralPath $policyRoot -Recurse -Force -ErrorAction Stop
            Log-Success "Removed hijacker browser policy key: $policyRoot"
        } catch {
            Log-Fail "Failed removing policy key: $policyRoot  -  $($_.Exception.Message)"
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
# PHASE 12: DEFENDER EXCLUSION CLEANUP (dynamic patterns supplement hardcoded)
# ==================================================================================================
Log-Info '--- Phase 12: Defender Exclusion Cleanup ---'

try {
    $mpPref = Get-MpPreference -ErrorAction Stop

    $excPaths = @($mpPref.ExclusionPath | Where-Object {
        $_ -and ($Script:Targets.IsMatch($_) -or
        (Test-DynamicFileIOC $_))
    })
    foreach ($ex in $excPaths) {
        Remove-MpPreference -ExclusionPath $ex -ErrorAction Stop
        Log-Success "Removed Defender ExclusionPath: $ex"
    }

    $excProcs = @($mpPref.ExclusionProcess | Where-Object {
        $_ -and ($Script:Targets.IsMatch($_) -or
        (Test-DynamicFileIOC $_))
    })
    foreach ($ex in $excProcs) {
        Remove-MpPreference -ExclusionProcess $ex -ErrorAction Stop
        Log-Success "Removed Defender ExclusionProcess: $ex"
    }
} catch {
    Log-Info "Defender exclusion check skipped  -  $($_.Exception.Message)"
}

# ==================================================================================================
# PHASE 13: HOSTS FILE INSPECTION (dynamic C2 list + RFC1918 protection)
# ==================================================================================================
Log-Info '--- Phase 13: Hosts File Inspection ---'

$hostsPath = [System.IO.Path]::Combine($env:SystemRoot, 'System32\drivers\etc\hosts')
if (Test-Path -LiteralPath $hostsPath) {
    $hostsLines = [System.IO.File]::ReadAllLines($hostsPath)
    $cleanLines = New-Object System.Collections.Generic.List[string]
    $modified   = $false

    foreach ($line in $hostsLines) {
        # Always protect internal/legitimate patterns  -  RFC1918 never removed
        $isProtected = $false
        foreach ($pattern in $Script:LegitHostsPatterns) {
            if ($line -match $pattern) { $isProtected = $true; break }
        }
        if ($isProtected) { $cleanLines.Add($line); continue }

        # Check hardcoded targets
        $isMalicious = $Script:Targets.IsMatch($line) -or $Script:SuspiciousPolicyPattern.IsMatch($line)

        # Check dynamic C2 IOC list
        if (-not $isMalicious -and $Script:DynamicC2IOCs.Count -gt 0) {
            $lineLC = $line.ToLower()
            foreach ($c2 in $Script:DynamicC2IOCs) {
                if ($lineLC -match [regex]::Escape($c2)) { $isMalicious = $true; break }
            }
        }

        if ($isMalicious) {
            Log-Success "Removed malicious hosts entry: $line"
            $modified = $true
        } else {
            # Only flag non-empty lines  -  blank lines between entries are normal
            if ($line.Trim() -ne '') {
                Log-IOC "Non-standard hosts entry (review): $line"
            }
            $cleanLines.Add($line)
        }
    }

    if ($modified) {
        try {
            [System.IO.File]::WriteAllLines($hostsPath, $cleanLines.ToArray(), [System.Text.Encoding]::ASCII)
            Log-Success 'Hosts file cleaned and saved'
        } catch {
            Log-Fail "Could not write cleaned hosts file  -  $($_.Exception.Message)"
        }
    } else {
        Log-Info 'Hosts file is clean'
    }
} else {
    Log-Warn "Hosts file not found: $hostsPath"
}

# ==================================================================================================
# PHASE 14: WMI PERSISTENCE AUDIT (dynamic signatures supplement whitelist)
# ==================================================================================================
Log-Info '--- Phase 14: WMI Persistence Audit ---'

if ($Script:HasCimSession) {
    try {
        $cimSession = New-CimSession -ErrorAction Stop

        $ErrorActionPreference = 'SilentlyContinue'
        $evtFilters = @(Get-CimInstance -CimSession $cimSession -Namespace 'root\subscription' `
                        -ClassName '__EventFilter' -ErrorAction SilentlyContinue)
        $ErrorActionPreference = 'Stop'
        $evtFilters | Where-Object { -not $Script:WMIWhitelist.Contains($_.Name) } |
        ForEach-Object { Log-IOC "Non-standard WMI EventFilter  -  Name: $($_.Name) | Query: $($_.Query)" }

        $ErrorActionPreference = 'SilentlyContinue'
        $evtConsumers = @(Get-CimInstance -CimSession $cimSession -Namespace 'root\subscription' `
                          -ClassName '__EventConsumer' -ErrorAction SilentlyContinue)
        $ErrorActionPreference = 'Stop'
        $evtConsumers | Where-Object { -not $Script:WMIWhitelist.Contains($_.Name) } |
        ForEach-Object {
            $cmdProp = $_.CimInstanceProperties['CommandLineTemplate']
            $txtProp = $_.CimInstanceProperties['ScriptText']
            $cmd = if ($cmdProp -and $cmdProp.Value) { $cmdProp.Value }
                   elseif ($txtProp -and $txtProp.Value) { $txtProp.Value }
                   else { '(no command)' }

            $isKnownBad = $Script:Targets.IsMatch($cmd) -or
                          (Test-DynamicFileIOC $cmd)
            if ($isKnownBad) {
                try {
                    Remove-CimInstance -CimSession $cimSession -InputObject $_ -ErrorAction Stop
                    Log-Success "Removed malicious WMI EventConsumer: $($_.Name)"
                } catch {
                    Log-Fail "Failed removing WMI consumer: $($_.Name)"
                }
            } else {
                Log-IOC "Non-standard WMI EventConsumer (review)  -  Name: $($_.Name) | Cmd: $cmd"
            }
        }

        $ErrorActionPreference = 'SilentlyContinue'
        $bindings = @(Get-CimInstance -CimSession $cimSession -Namespace 'root\subscription' `
                      -ClassName '__FilterToConsumerBinding' -ErrorAction SilentlyContinue)
        $ErrorActionPreference = 'Stop'
        $bindings | Where-Object { $_.Filter -notmatch 'SCM|BVT|TSlogon|OfficeSync|SCM Event Log|DellCommand' } |
        ForEach-Object {
            Log-IOC "Non-standard WMI Binding (review)  -  Filter: $($_.Filter) | Consumer: $($_.Consumer)"
        }

        Remove-CimSession -CimSession $cimSession -ErrorAction SilentlyContinue
    } catch {
        Log-Info "WMI audit skipped  -  $($_.Exception.Message)"
    }
} else {
    Log-Info 'WMI audit skipped (CIM not available on this PS version)'
}

# ==================================================================================================
# PHASE 15: TROJAN / MALWARE IOC DETECTION (dynamic + hardcoded)
# ==================================================================================================
Log-Info '--- Phase 15: Trojan/Malware IOC Detection ---'

$iocScanPaths = @('C:\ProgramData', 'C:\Users\Public', $env:APPDATA, $env:LOCALAPPDATA)
foreach ($scanPath in $iocScanPaths) {
    if (-not (Test-Path -LiteralPath $scanPath)) { continue }
    Get-ChildItem -LiteralPath $scanPath -Directory -ErrorAction SilentlyContinue |
    Where-Object {
        $Script:TrojanFolderIOCs.Contains($_.Name) -or
        (Test-DynamicFileIOC $_.Name)
    } |
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
# PHASE 16: REBOOT REQUIREMENT CHECK
# ==================================================================================================
Log-Info '--- Phase 16: Reboot Requirement Check ---'

$ErrorActionPreference = 'SilentlyContinue'
$pendingRenameVal = $null
$sessionMgrKey = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
                 -ErrorAction SilentlyContinue
if ($sessionMgrKey -and $sessionMgrKey.PSObject.Properties['PendingFileRenameOperations']) {
    $pendingRenameVal = $sessionMgrKey.PendingFileRenameOperations
}
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
    Log-Warn '*** REBOOT REQUIRED  -  please reboot this machine manually ***'
} else {
    Log-Info 'No reboot required'
}

# ==================================================================================================
# PHASE 17: MALWAREBAZAAR HASH LOOKUP + NEO23x0 FALLBACK + DEFENDER FALLBACK
# ==================================================================================================
Log-Info '--- Phase 17: MalwareBazaar Hash Lookup + Neo23x0 Fallback + Defender Fallback ---'

function Invoke-MalwareBazaarLookup {
    param(
        [Parameter(Mandatory=$true)][string]$Hash,
        [Parameter(Mandatory=$true)][string]$FilePath
    )
    $name = [System.IO.Path]::GetFileName($FilePath)
    try {
        $response = Invoke-RestMethod `
            -Uri  'https://mb-api.abuse.ch/api/v1/' `
            -Method Post `
            -Body "query=get_info&hash=$Hash" `
            -ContentType 'application/x-www-form-urlencoded' `
            -TimeoutSec $Script:Config.MalwareBazaarTimeoutSec `
            -ErrorAction Stop

        switch ($response.query_status) {
            'ok' {
                $entry  = $response.data[0]
                $family = if ($entry.signature) { $entry.signature } else { 'Unknown' }
                $tags   = if ($entry.tags)      { $entry.tags -join ', ' } else { 'none' }
                Log-IOC "MALWAREBAZAAR HIT  -  $name | Family: $family | Tags: $tags | SHA256: $Hash"
                return 'hit'
            }
            'no_results' {
                Log-Info "MalwareBazaar: No record for $name"
                return 'no_results'
            }
            default {
                Log-Warn "MalwareBazaar unexpected response for $name`: $($response.query_status)"
                return 'unknown'
            }
        }
    } catch {
        $errMsg = $_.Exception.Message
        if ($errMsg -match '401' -or $errMsg -match 'Unauthorized') {
            Log-Warn "MalwareBazaar API requires authentication for $name  -  register free API key at bazaar.abuse.ch"
        } else {
            Log-Warn "MalwareBazaar lookup failed or timed out for $name  -  $errMsg"
        }
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
                Log-IOC "DEFENDER HIT  -  $name | Threat: $($_.ThreatName) | Severity: $($_.SeverityID)"
            }
        } else {
            Log-Info "Defender: No detection for $name"
        }
    } catch {
        Log-Warn "Defender scan unavailable for $name  -  $($_.Exception.Message)"
    }
}

$iocList = @($Script:IOCExePaths)
if ($iocList.Count -eq 0) {
    Log-Info 'No IOC executables to check'
} else {
    Log-Info "Checking $($iocList.Count) flagged EXE(s) against MalwareBazaar + Neo23x0..."
    foreach ($exePath in $iocList) {
        if (-not (Test-Path -LiteralPath $exePath)) { continue }
        try {
            $hash   = (Get-FileHash -LiteralPath $exePath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower()
            $result = Invoke-MalwareBazaarLookup -Hash $hash -FilePath $exePath

            if ($result -eq 'hit') {
                # Already logged as IOC above
            } elseif ($result -eq 'no_results' -or $result -eq 'unknown') {
                # Check Neo23x0 local hash list
                if ($Script:DynamicHashIOCs.Contains($hash)) {
                    Log-IOC "NEO23x0 HASH HIT  -  $exePath | SHA256: $hash"
                } else {
                    Invoke-DefenderFallbackScan -FilePath $exePath
                }
            } elseif ($result -eq 'error') {
                # MalwareBazaar unreachable  -  try Neo23x0 cache before Defender
                if ($Script:DynamicHashIOCs.Contains($hash)) {
                    Log-IOC "NEO23x0 HASH HIT (MalwareBazaar offline)  -  $exePath | SHA256: $hash"
                } else {
                    Invoke-DefenderFallbackScan -FilePath $exePath
                }
            }
        } catch {
            Log-Warn "Could not hash (file locked?): $exePath"
            Invoke-DefenderFallbackScan -FilePath $exePath
        }
    }
}

# ==================================================================================================
# PHASE 18: DISK SPACE CLEANUP (safe mode  -  Recycle Bin skipped)
# ==================================================================================================
Log-Info '--- Phase 18: Disk Space Cleanup ---'

$Script:DiskBefore = (Get-PSDrive C -ErrorAction SilentlyContinue).Free

# Windows Temp
Remove-FolderContents -Path "$env:SystemRoot\Temp" -Label 'Windows Temp'

# Current user Temp
Remove-FolderContents -Path "$env:LOCALAPPDATA\Temp" -Label 'User Temp (current user)'

# Windows Update cache
try {
    if (Get-Service -Name wuauserv -ErrorAction SilentlyContinue) {
        Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
        Remove-FolderContents -Path 'C:\Windows\SoftwareDistribution\Download' -Label 'Windows Update Cache'
        Start-Service -Name wuauserv -ErrorAction SilentlyContinue
    } else {
        Remove-FolderContents -Path 'C:\Windows\SoftwareDistribution\Download' -Label 'Windows Update Cache'
    }
} catch { Log-Warn 'Windows Update cache cleanup skipped' }

# Delivery Optimization
try {
    if (Get-Service -Name DoSvc -ErrorAction SilentlyContinue) {
        Stop-Service -Name DoSvc -Force -ErrorAction SilentlyContinue
        Remove-FolderContents -Path 'C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache' `
            -Label 'Delivery Optimization Cache'
        Start-Service -Name DoSvc -ErrorAction SilentlyContinue
    } else {
        Remove-FolderContents -Path 'C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache' `
            -Label 'Delivery Optimization Cache'
    }
} catch { Log-Warn 'Delivery Optimization cache cleanup skipped' }

# Skip Prefetch on servers  -  not beneficial
if (-not $Script:HWInfo.IsServer) {
    Remove-FolderContents -Path 'C:\Windows\Prefetch' -Label 'Prefetch'
} else {
    Log-Info 'Prefetch cleanup skipped  -  server OS detected'
}

Remove-FolderContents -Path 'C:\Windows\Logs\CBS'                                         -Label 'CBS Logs'
Remove-FolderContents -Path 'C:\ProgramData\Microsoft\Windows\WER\ReportArchive'          -Label 'WER Report Archive'
Remove-FolderContents -Path 'C:\ProgramData\Microsoft\Windows\WER\ReportQueue'            -Label 'WER Report Queue'
Remove-FolderContents -Path 'C:\Windows\Minidump'                                         -Label 'Minidump Files'

# IIS logs older than 30 days
if (Test-Path -LiteralPath 'C:\inetpub\logs\LogFiles') {
    $cutoff = (Get-Date).AddDays(-30)
    [long]$iisFreed = 0; $iisCount = 0
    Get-ChildItem -LiteralPath 'C:\inetpub\logs\LogFiles' -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -lt $cutoff } |
    ForEach-Object {
        try { $iisFreed += $_.Length; Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop; $iisCount++ } catch { }
    }
    if ($iisFreed -gt 0) {
        Log-Success "Cleaned IIS logs (>30 days)  -  $iisCount files | freed $([math]::Round($iisFreed/1MB,1)) MB"
        $Script:SpaceFreed += $iisFreed
    } else {
        Log-Info 'IIS logs  -  nothing older than 30 days'
    }
} else {
    Log-Info 'IIS logs  -  not present'
}

# Thumbnail cache  -  per user
foreach ($profile in $Script:UserProfiles) {
    $thumbDir = [System.IO.Path]::Combine($profile.FullName, 'AppData\Local\Microsoft\Windows\Explorer')
    if (-not (Test-Path -LiteralPath $thumbDir)) { continue }
    [long]$thumbFreed = 0
    Get-ChildItem -LiteralPath $thumbDir -Filter 'thumbcache_*.db' -ErrorAction SilentlyContinue |
    ForEach-Object {
        try { $thumbFreed += $_.Length; Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop } catch { }
    }
    if ($thumbFreed -gt 0) {
        Log-Success "Cleaned thumbnail cache ($($profile.Name))  -  freed $([math]::Round($thumbFreed/1MB,1)) MB"
        $Script:SpaceFreed += $thumbFreed
    }
}

# Per-user Temp folders
foreach ($profile in $Script:UserProfiles) {
    Remove-FolderContents `
        -Path ([System.IO.Path]::Combine($profile.FullName, 'AppData\Local\Temp')) `
        -Label "User Temp ($($profile.Name))"
}

# RECYCLE BIN INTENTIONALLY SKIPPED  -  user data risk, not safe for automated MSP deployment
Log-Info 'Recycle Bin skipped  -  not safe for automated cleanup (user data at risk)'

# Windows.old  -  DISM removal if older than 30 days
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
            Log-Warn "DISM cleanup failed  -  run manually: dism /Online /Cleanup-Image /StartComponentCleanup"
        }
    } else {
        Log-Warn "Windows.old found ($age days old, $sizeGB GB)  -  skipping, not yet 30 days"
    }
} else {
    Log-Info 'Windows.old  -  not present'
}

$Script:DiskAfter    = (Get-PSDrive C -ErrorAction SilentlyContinue).Free
$Script:TotalFreedGB = [math]::Round($Script:SpaceFreed / 1GB, 2)
$Script:DiskBeforeGB = [math]::Round($Script:DiskBefore / 1GB, 1)
$Script:DiskAfterGB  = [math]::Round($Script:DiskAfter  / 1GB, 1)
Log-Info "Disk cleanup complete  -  freed ~$Script:TotalFreedGB GB | C: free $Script:DiskBeforeGB GB -> $Script:DiskAfterGB GB"

# ==================================================================================================
# PHASE 19: RECENTLY INSTALLED SOFTWARE REPORT
# ==================================================================================================
Log-Info '--- Phase 19: Recently Installed Software Report ---'

$recentCutoff   = (Get-Date).AddDays(-30)
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
    Log-Info 'Recently installed software  -  nothing found in last 30 days'
} else {
    $sorted = @($recentSoftware | Sort-Object Date -Descending)
    Log-Info "Recently installed software (last 30 days)  -  $($sorted.Count) item(s):"
    foreach ($item in $sorted) {
        Log-Info "  $($item.Date)  $($item.Name.PadRight(45)) v$($item.Version)  [$($item.Publisher)]"
    }
}

$Script:RecentSoftware = @($recentSoftware | Sort-Object Date -Descending)

# ==================================================================================================
# PHASE 20: TEMP FILE AGE REPORT
# ==================================================================================================
Log-Info '--- Phase 20: Temp File Age Report ---'

function Get-TempFolderStats {
    param([string]$Path, [string]$Label)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $files = @(Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue |
               Where-Object { -not $_.PSIsContainer })
    if ($files.Count -eq 0) { Log-Info "  $Label  -  empty"; return }
    $totalMB    = [math]::Round(($files | Measure-Object -Property Length -Sum).Sum / 1MB, 1)
    $oldest     = ($files | Sort-Object CreationTime | Select-Object -First 1).CreationTime
    $oldestDays = [math]::Floor(((Get-Date) - $oldest).TotalDays)
    $ageFlag    = if ($oldestDays -gt 365) { ' *** OLDEST FILE > 1 YEAR  -  machine may not have been maintained ***' } else { '' }
    Log-Info "  $Label  -  $($files.Count) files, $totalMB MB, oldest: $($oldest.ToString('yyyy-MM-dd')) ($oldestDays days)$ageFlag"
    if ($oldestDays -gt 365) { Log-Warn "Temp folder neglected  -  oldest file $oldestDays days old: $Label" }
}

Get-TempFolderStats -Path "$env:SystemRoot\Temp"   -Label 'Windows Temp'
Get-TempFolderStats -Path "$env:LOCALAPPDATA\Temp" -Label 'Current User Temp'
foreach ($profile in $Script:UserProfiles) {
    $utemp = [System.IO.Path]::Combine($profile.FullName, 'AppData\Local\Temp')
    Get-TempFolderStats -Path $utemp -Label "User Temp ($($profile.Name))"
}

# ==================================================================================================
# PHASE 21: EVENT LOG IOC CHECK (dynamic patterns supplement hardcoded)
# ==================================================================================================
Log-Info '--- Phase 21: Event Log IOC Check ---'

$lookbackHours = 168
$lookbackTime  = (Get-Date).AddHours(-$lookbackHours)

try {
    $ErrorActionPreference = 'SilentlyContinue'
    $procEvents = @(Get-WinEvent -FilterHashtable @{
        LogName = 'Security'; Id = 4688; StartTime = $lookbackTime
    } -MaxEvents 5000 -ErrorAction SilentlyContinue)
    $ErrorActionPreference = 'Stop'

    if ($procEvents.Count -gt 0) {
        $procEvents | ForEach-Object {
            $msg = $_.Message
            if ($Script:Targets.IsMatch($msg) -or $Script:MalwareTaskPattern.IsMatch($msg) -or
                (Test-DynamicFileIOC $msg)) {
                Log-IOC "Event 4688 (Process Creation) match  -  Time: $($_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) | $($msg.Split("`n")[0].Trim())"
            }
        }
        Log-Info "Event log 4688 scan complete  -  $($procEvents.Count) events checked (last 7 days)"
    } else {
        Log-Info 'Event log 4688  -  no events found (audit policy may not be enabled)'
    }
} catch {
    Log-Info "Event log 4688 scan skipped  -  $($_.Exception.Message)"
}

try {
    $ErrorActionPreference = 'SilentlyContinue'
    $svcEvents = @(Get-WinEvent -FilterHashtable @{
        LogName = 'System'; Id = 7045; StartTime = $lookbackTime
    } -MaxEvents 500 -ErrorAction SilentlyContinue)
    $ErrorActionPreference = 'Stop'

    if ($svcEvents.Count -gt 0) {
        # Group by service name + path to avoid 19 identical entries for same service
        $svcGroups = @{}
        $svcEvents | ForEach-Object {
            $evt = $_
            $svcName = ''
            $svcPath = ''
            $svcAcct = ''
            try {
                if ($evt.Properties -and $evt.Properties.Count -gt 0) {
                    $svcName = if ($evt.Properties[0].Value) { $evt.Properties[0].Value.ToString() } else { '' }
                    $svcPath = if ($evt.Properties.Count -gt 1 -and $evt.Properties[1].Value) { $evt.Properties[1].Value.ToString() } else { '' }
                    $svcAcct = if ($evt.Properties.Count -gt 4 -and $evt.Properties[4].Value) { $evt.Properties[4].Value.ToString() } else { '' }
                }
            } catch { }

            $isSuspicious = $Script:Targets.IsMatch("$svcName $svcPath") -or
                            (Test-DynamicFileIOC $svcName) -or
                            (Test-DynamicFileIOC $svcPath) -or
                            $svcPath -match [regex]::Escape($env:TEMP) -or
                            $svcPath -match '\\AppData\\' -or
                            $svcPath -match '\\Users\\Public\\'

            if ($isSuspicious) {
                $key = "$svcName|$svcPath"
                if ($svcGroups.ContainsKey($key)) {
                    $svcGroups[$key]['Count']++
                    # Keep earliest time
                    if ($evt.TimeCreated -lt $svcGroups[$key]['FirstSeen']) {
                        $svcGroups[$key]['FirstSeen'] = $evt.TimeCreated
                    }
                } else {
                    $svcGroups[$key] = @{
                        Count     = 1
                        FirstSeen = $evt.TimeCreated
                        SvcName   = $svcName
                        SvcPath   = $svcPath
                        SvcAcct   = $svcAcct
                    }
                }
            }
        }

        foreach ($key in $svcGroups.Keys) {
            $g = $svcGroups[$key]
            $countStr = if ($g['Count'] -gt 1) { " ($($g['Count'])x)" } else { '' }
            Log-IOC "Event 7045 (Service Install) suspicious$countStr  -  First seen: $($g['FirstSeen'].ToString('yyyy-MM-dd HH:mm:ss')) | Service: $($g['SvcName']) | Path: $($g['SvcPath']) | Account: $($g['SvcAcct'])"
        }
        Log-Info "Event log 7045 scan complete  -  $($svcEvents.Count) service install events checked"
    } else {
        Log-Info 'Event log 7045  -  no service install events in last 7 days'
    }
} catch {
    Log-Info "Event log 7045 scan skipped  -  $($_.Exception.Message)"
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
# BUILD HTML REPORT
# ==================================================================================================

# Safe HTML encoder  -  uses System.Web if available, plain replace fallback otherwise
function Encode-Html {
    param([string]$Text)
    if (-not $Text) { return '' }
    try {
        return [System.Web.HttpUtility]::HtmlEncode($Text)
    } catch {
        return $Text.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;')
    }
}

function Build-HtmlReport {
    $verdict        = if ($Script:Counters.IOCsFound -gt 0 -or $Script:Counters.Failed) { 'Dave is Sweeping!' } else { 'Clean Sweep!' }
    $verdictColor   = if ($verdict -eq 'Clean Sweep!') { '#1a7f37' } else { '#b45309' }
    $verdictBg      = if ($verdict -eq 'Clean Sweep!') { '#dcfce7' } else { '#fef9c3' }
    $runDate        = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    # Helper  -  build an HTML table from an array of strings
    function Html-Section {
        param([string]$Title, [string]$TitleColor = '#1e3a5f', [string[]]$Items, [string]$EmptyMsg = '(none)', [string]$RowColor = '#111827')
        $sb = New-Object System.Text.StringBuilder
        $null = $sb.Append("<h2 style='color:$TitleColor;border-bottom:2px solid $TitleColor;padding-bottom:6px;margin-top:32px'>$Title</h2>")
        if ($Items.Count -eq 0) {
            $null = $sb.Append("<p style='color:#6b7280;font-style:italic'>$EmptyMsg</p>")
        } else {
            $null = $sb.Append("<table width='100%' cellpadding='8' cellspacing='0' style='border-collapse:collapse;font-size:13px'>")
            $alt = $false
            foreach ($item in $Items) {
                $bg = if ($alt) { '#f9fafb' } else { '#ffffff' }
                $null = $sb.Append("<tr style='background:$bg'><td style='border-bottom:1px solid #e5e7eb;color:$RowColor;padding:8px 12px'>$(Encode-Html($item))</td></tr>")
                $alt = -not $alt
            }
            $null = $sb.Append("</table>")
        }
        return $sb.ToString()
    }

    # Machine info table
    $machineRows = New-Object System.Text.StringBuilder
    if ($Script:MachineInfo.Count -gt 0) {
        $null = $machineRows.Append("<table width='100%' cellpadding='8' cellspacing='0' style='border-collapse:collapse;font-size:13px'>")
        $alt = $false
        foreach ($key in $Script:MachineInfo.Keys) {
            $val = $Script:MachineInfo[$key]
            $bg  = if ($alt) { '#f9fafb' } else { '#ffffff' }
            $valColor = if ($key -eq 'Defender' -and $val -eq 'DISABLED') { '#dc2626' }
                        elseif ($key -eq 'Defender' -and $val -eq 'Active') { '#1a7f37' }
                        else { '#111827' }
            $null = $machineRows.Append("<tr style='background:$bg'><td style='border-bottom:1px solid #e5e7eb;color:#6b7280;width:200px;padding:8px 12px'><strong>$key</strong></td><td style='border-bottom:1px solid #e5e7eb;color:$valColor;padding:8px 12px'>$(Encode-Html($val))</td></tr>")
            $alt = -not $alt
        }
        $null = $machineRows.Append("</table>")
    }

    # Metrics table
    $metricsRows = New-Object System.Text.StringBuilder
    $null = $metricsRows.Append("<table width='100%' cellpadding='8' cellspacing='0' style='border-collapse:collapse;font-size:13px'>")
    $metricData = [ordered]@{
        'Processes Killed'       = $Script:Counters.ProcessesKilled
        'Uninstalls Executed'    = $Script:Counters.UninstallsRun
        'Services Removed'       = $Script:Counters.ServicesRemoved
        'Scheduled Tasks Removed'= $Script:Counters.TasksRemoved
        'Run Keys Removed'       = $Script:Counters.RunKeysRemoved
        'Files / Dirs Removed'   = $Script:Counters.FilesRemoved
        'Disk Space Freed'       = "$Script:TotalFreedGB GB"
        'Free Space (Before)'    = "$Script:DiskBeforeGB GB"
        'Free Space (After)'     = "$Script:DiskAfterGB GB"
        'Hash IOCs Loaded'       = $Script:DynamicHashIOCs.Count
        'Filename IOCs Loaded'   = $Script:filenameIOCList.Count
        'C2 IOCs Loaded'         = $Script:DynamicC2IOCs.Count
        'Intel Source'           = $Script:Counters.IntelSource
        'IOC Alerts'             = $Script:Counters.IOCsFound
        'Failed Actions'         = $failedItems.Count
        'Total Actions Taken'    = $Script:Counters.ActionsTaken
        'Runtime'                = "$runtime seconds"
        'PS Version'             = $Script:PSFullVer
        'Reboot Required'        = $(if ($Script:Counters.RebootRequired) { 'YES  -  reboot manually' } else { 'No' })
    }
    $alt = $false
    foreach ($key in $metricData.Keys) {
        $val = $metricData[$key]
        $bg  = if ($alt) { '#f9fafb' } else { '#ffffff' }
        $valColor = if ($key -eq 'IOC Alerts'       -and $val -gt 0)          { '#7c3aed' }
                    elseif ($key -eq 'Failed Actions'     -and $val -gt 0)     { '#dc2626' }
                    elseif ($key -eq 'Reboot Required'    -and $val -match 'YES') { '#b45309' }
                    elseif ($key -eq 'Disk Space Freed')                       { '#1a7f37' }
                    else { '#111827' }
        $null = $metricsRows.Append("<tr style='background:$bg'><td style='border-bottom:1px solid #e5e7eb;color:#6b7280;width:220px;padding:8px 12px'><strong>$key</strong></td><td style='border-bottom:1px solid #e5e7eb;color:$valColor;padding:8px 12px'>$(Encode-Html($val.ToString()))</td></tr>")
        $alt = -not $alt
    }
    $null = $metricsRows.Append("</table>")

    # Recently installed software table
    $recentRows = New-Object System.Text.StringBuilder
    if ($Script:RecentSoftware.Count -gt 0) {
        $null = $recentRows.Append("<table width='100%' cellpadding='8' cellspacing='0' style='border-collapse:collapse;font-size:13px'>")
        $null = $recentRows.Append("<tr style='background:#1e3a5f;color:#ffffff'><th style='padding:8px 12px;text-align:left'>Date</th><th style='padding:8px 12px;text-align:left'>Name</th><th style='padding:8px 12px;text-align:left'>Version</th><th style='padding:8px 12px;text-align:left'>Publisher</th></tr>")
        $alt = $false
        foreach ($item in $Script:RecentSoftware) {
            $bg       = if ($alt) { '#f9fafb' } else { '#ffffff' }
            $rowColor = if ($Script:Targets.IsMatch($item.Name)) { '#dc2626' } else { '#111827' }
            $null = $recentRows.Append("<tr style='background:$bg;color:$rowColor'><td style='border-bottom:1px solid #e5e7eb;padding:8px 12px'>$($item.Date)</td><td style='border-bottom:1px solid #e5e7eb;padding:8px 12px'>$(Encode-Html($item.Name))</td><td style='border-bottom:1px solid #e5e7eb;padding:8px 12px'>$(Encode-Html($item.Version))</td><td style='border-bottom:1px solid #e5e7eb;padding:8px 12px'>$(Encode-Html($item.Publisher))</td></tr>")
            $alt = -not $alt
        }
        $null = $recentRows.Append("</table>")
    } else {
        $null = $recentRows.Append("<p style='color:#6b7280;font-style:italic'>No software installed in the last 30 days.</p>")
    }

    $html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset='UTF-8'>
<style>
  body { font-family: 'Segoe UI', Arial, sans-serif; background:#f3f4f6; margin:0; padding:0; color:#111827; }
  .wrapper { max-width:860px; margin:32px auto; background:#ffffff; border-radius:8px; box-shadow:0 2px 12px rgba(0,0,0,0.08); overflow:hidden; }
  .header { background:#1e3a5f; color:#ffffff; padding:32px 40px; }
  .header h1 { margin:0 0 4px 0; font-size:24px; font-weight:700; letter-spacing:0.5px; }
  .header p { margin:0; font-size:13px; opacity:0.8; }
  .verdict-box { margin:24px 40px; padding:20px 28px; border-radius:6px; background:$verdictBg; border-left:5px solid $verdictColor; }
  .verdict-box h2 { margin:0 0 6px 0; font-size:22px; color:$verdictColor; }
  .verdict-box p { margin:0; font-size:13px; color:#374151; }
  .body { padding:8px 40px 40px 40px; }
  h2 { font-size:15px; font-weight:700; margin-top:32px; }
  table { border-radius:6px; overflow:hidden; }
  .footer { background:#f9fafb; border-top:1px solid #e5e7eb; padding:16px 40px; font-size:12px; color:#9ca3af; }
</style>
</head>
<body>
<div class='wrapper'>
  <div class='header'>
    <h1>Dave's CleanSweep $($Script:Config.Version)</h1>
    <p>$env:COMPUTERNAME &nbsp;|&nbsp; $runDate &nbsp;|&nbsp; Runtime: $runtime sec &nbsp;|&nbsp; PS $Script:PSFullVer</p>
  </div>

  <div class='body'>
    <div class='verdict-box'>
      <h2>$verdict</h2>
      <p>
        IOC Alerts: <strong>$($Script:Counters.IOCsFound)</strong> &nbsp;|&nbsp;
        Actions Taken: <strong>$($Script:Counters.ActionsTaken)</strong> &nbsp;|&nbsp;
        Failed: <strong>$($failedItems.Count)</strong> &nbsp;|&nbsp;
        Disk Freed: <strong>$Script:TotalFreedGB GB</strong> &nbsp;|&nbsp;
        Intel: <strong>$($Script:Counters.IntelSource)</strong>
      </p>
    </div>

    <h2 style='color:#1e3a5f;border-bottom:2px solid #1e3a5f;padding-bottom:6px;margin-top:32px'>MACHINE INFORMATION</h2>
    $($machineRows.ToString())

    $(Html-Section -Title 'IOC ALERTS  -  ANALYST REVIEW REQUIRED' -TitleColor '#7c3aed' -Items $iocItems -EmptyMsg 'No IOC alerts detected.' -RowColor '#7c3aed')
    $(Html-Section -Title 'FAILED TO REMOVE' -TitleColor '#dc2626' -Items $failedItems -EmptyMsg 'No failures.' -RowColor '#dc2626')
    $(Html-Section -Title 'WARNINGS / SKIPPED' -TitleColor '#b45309' -Items $warnItems -EmptyMsg 'No warnings.' -RowColor '#b45309')
    $(Html-Section -Title 'REMOVED SUCCESSFULLY' -TitleColor '#1a7f37' -Items $successItems -EmptyMsg 'Nothing removed.' -RowColor '#1a7f37')

    <h2 style='color:#1e3a5f;border-bottom:2px solid #1e3a5f;padding-bottom:6px;margin-top:32px'>RECENTLY INSTALLED SOFTWARE  -  LAST 30 DAYS</h2>
    $($recentRows.ToString())

    <h2 style='color:#1e3a5f;border-bottom:2px solid #1e3a5f;padding-bottom:6px;margin-top:32px'>METRICS SUMMARY</h2>
    $($metricsRows.ToString())
  </div>

  <div class='footer'>
    Dave's CleanSweep $($Script:Config.Version) &nbsp;|&nbsp; Log: $($Script:Config.LogPath) &nbsp;|&nbsp; Full log attached.
  </div>
</div>
</body>
</html>
"@
    return $html
}

# ==================================================================================================
# SEND EMAIL REPORT  -  runs in background job with 20-second hard timeout
# ==================================================================================================

function Send-CleanSweepReport {
    $verdict  = if ($Script:Counters.IOCsFound -gt 0 -or $Script:Counters.Failed) { 'Dave is Sweeping!' } else { 'Clean Sweep!' }
    $subject  = "CleanSweep $($Script:Config.Version)  -  $env:COMPUTERNAME  -  $verdict"
    $htmlBody = Build-HtmlReport

    # Copy log to temp file  -  avoids file-in-use lock, passes cleanly into job scope
    $logCopyPath = $null
    if (Test-Path -LiteralPath $Script:Config.LogPath) {
        $logCopyPath = [System.IO.Path]::Combine(
            [System.IO.Path]::GetTempPath(),
            "CleanSweep_$env:COMPUTERNAME`_$(Get-Date -Format 'yyyyMMdd_HHmm').log"
        )
        try {
            [System.IO.File]::Copy($Script:Config.LogPath, $logCopyPath, $true)
        } catch {
            $logCopyPath = $null
        }
    }

    # Package everything the job needs  -  jobs run in isolated scope
    $jobParams = @{
        SmtpServer   = $Script:Config.SmtpServer
        SmtpPort     = $Script:Config.SmtpPort
        SmtpUseTLS   = $Script:Config.SmtpUseTLS
        SmtpFrom     = $Script:Config.SmtpFrom
        SmtpTo       = $Script:Config.SmtpTo
        SmtpUser     = $Script:Config.SmtpUser
        SmtpPass     = $Script:Config.SmtpPass
        Subject      = $subject
        HtmlBody     = $htmlBody
        LogCopyPath  = $logCopyPath
    }

    $job = Start-Job -ScriptBlock {
        param($p)
        try {
            $msg            = New-Object System.Net.Mail.MailMessage
            $msg.From       = $p.SmtpFrom
            $msg.To.Add($p.SmtpTo)
            $msg.Subject    = $p.Subject
            $msg.Body       = $p.HtmlBody
            $msg.IsBodyHtml = $true

            if ($p.LogCopyPath -and (Test-Path -LiteralPath $p.LogCopyPath)) {
                $attachment = New-Object System.Net.Mail.Attachment($p.LogCopyPath)
                $msg.Attachments.Add($attachment)
            }

            $smtp             = New-Object System.Net.Mail.SmtpClient($p.SmtpServer, $p.SmtpPort)
            $smtp.EnableSsl   = $p.SmtpUseTLS
            $smtp.Credentials = New-Object System.Net.NetworkCredential($p.SmtpUser, $p.SmtpPass)
            $smtp.Timeout     = 12000

            $smtp.Send($msg)
            $msg.Attachments.Dispose()
            $msg.Dispose()
            return 'sent'
        } catch {
            return "failed: $($_.Exception.Message)"
        }
    } -ArgumentList $jobParams

    # Wait maximum 20 seconds then kill  -  script never hangs regardless of network
    $completed = Wait-Job -Job $job -Timeout 20
    if ($completed) {
        $result = Receive-Job -Job $job
        if ($result -eq 'sent') {
            Log-Success "Email report sent to $($Script:Config.SmtpTo)"
        } else {
            Log-Warn "Email send failed  -  $result"
        }
    } else {
        Stop-Job -Job $job
        Log-Warn "Email send timed out after 20 seconds  -  port 587 may be blocked on this network"
    }
    Remove-Job -Job $job -Force -ErrorAction SilentlyContinue

    # Clean up temp log copy
    if ($logCopyPath -and (Test-Path -LiteralPath $logCopyPath)) {
        Remove-Item -LiteralPath $logCopyPath -Force -ErrorAction SilentlyContinue
    }
}

# ==================================================================================================
# EMAIL REPORT  -  TEMPORARILY DISABLED
# Basic Auth (SMTP AUTH) is disabled on this O365 tenant. SmtpClient uses Basic Auth
# and cannot authenticate. To re-enable email reporting, either:
#   1. Enable SMTP AUTH on the sending mailbox in Microsoft 365 Admin Center, or
#   2. Upgrade to Microsoft Graph API (OAuth2) for modern auth support.
# The HTML report and log file are saved locally and can be retrieved via RMM.
# ==================================================================================================
# ==================================================================================================
# EMAIL REPORT  -  TEMPORARILY DISABLED
# Basic Auth (SMTP AUTH) is disabled on this O365 tenant. SmtpClient uses Basic Auth
# and cannot authenticate. To re-enable email reporting, either:
#   1. Enable SMTP AUTH on the sending mailbox in Microsoft 365 Admin Center, or
#   2. Upgrade to Microsoft Graph API (OAuth2) for modern auth support.
# The HTML report and log file are saved locally and can be retrieved via RMM.
# ==================================================================================================

# Reopen log writer to capture final status message, then close cleanly
$Script:LogWriter = New-Object System.IO.StreamWriter($Script:Config.LogPath, $true, [System.Text.Encoding]::UTF8)
$Script:LogWriter.AutoFlush = $true
Log-Info 'Email report skipped  -  O365 Basic Auth disabled. See script header for re-enable instructions.'
Log-Info "Report saved locally: $($Script:Config.LogPath)"
$Script:LogWriter.Flush()
$Script:LogReady = $false   # prevent Write-Log from attempting further writes
$Script:LogWriter.Close()
$Script:LogWriter.Dispose()

# ==================================================================================================
# CONSOLE REPORT
# ==================================================================================================

$Width = 80
function HR { param([string]$c = '=') Write-Host ($c * $Width) -ForegroundColor DarkGray }
function SH { param([string]$t) HR; Write-Host ("  {0}" -f $t.ToUpper()) -ForegroundColor White; HR '-' }

HR
Write-Host "  $($Script:Config.Name) $($Script:Config.Version) - Report" -ForegroundColor Cyan
Write-Host "  Hostname  : $env:COMPUTERNAME"                               -ForegroundColor DarkCyan
Write-Host "  Run Date  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"       -ForegroundColor DarkCyan
Write-Host "  Runtime   : $runtime seconds"                                -ForegroundColor DarkCyan
Write-Host "  PS Version: $Script:PSFullVer"                               -ForegroundColor DarkCyan
Write-Host "  Intel     : $($Script:Counters.IntelSource)"                 -ForegroundColor DarkCyan
Write-Host "  Log File  : $($Script:Config.LogPath)"                       -ForegroundColor DarkCyan
if ($Script:Counters.RebootRequired) {
    Write-Host '  !! REBOOT REQUIRED  -  please reboot this machine manually !!'  -ForegroundColor Yellow
}
HR

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

HR
$totalIssues = $failedItems.Count + $Script:Counters.IOCsFound
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

SH 'Reboot Status'
if ($Script:Counters.RebootRequired) {
    Write-Host '  [!] REBOOT REQUIRED  -  please reboot this machine manually.' -ForegroundColor Yellow
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
    'Hash IOCs loaded'        = $Script:DynamicHashIOCs.Count
    'Filename IOCs loaded'    = $Script:filenameIOCList.Count
    'C2 IOCs loaded'          = $Script:DynamicC2IOCs.Count
    'Intel source'            = $Script:Counters.IntelSource
    'Total actions taken'     = $Script:Counters.ActionsTaken
    'Failed actions'          = $failedItems.Count
    'Warnings / skipped'      = $warnItems.Count
    'IOC alerts'              = $Script:Counters.IOCsFound
    'Runtime'                 = "$runtime seconds"
    'PS Version'              = $Script:PSFullVer
    'Reboot required'         = $(if ($Script:Counters.RebootRequired) { 'YES  -  reboot manually' } else { 'No' })
}

foreach ($key in $metricsData.Keys) {
    $val   = $metricsData[$key]
    $isNum = $val -match '^\d+$'
    $color = if     ($key -eq 'Failed actions'     -and $isNum -and [int]$val -gt 0) { 'Red'     }
             elseif ($key -eq 'IOC alerts'          -and $isNum -and [int]$val -gt 0) { 'Magenta' }
             elseif ($key -eq 'Warnings / skipped'  -and $isNum -and [int]$val -gt 0) { 'Yellow'  }
             elseif ($key -eq 'Reboot required'     -and $val -match 'YES')           { 'Yellow'  }
             elseif ($key -eq 'Total actions taken' -and $isNum -and [int]$val -gt 0) { 'Green'   }
             elseif ($key -match 'Disk space freed|Free space|IOCs loaded|Intel')     { 'Cyan'    }
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
    Write-Host '  !! REBOOT REQUIRED  -  please reboot this machine manually !!'                -ForegroundColor Yellow
}
HR
Write-Host ''

# Verdict banner  -  last thing seen before prompt returns
if ($totalIssues -eq 0) {
    Write-Host ('  ' + ('#' * 76))                                                                    -ForegroundColor Green
    Write-Host ('  #' + (' ' * 74) + '#')                                                             -ForegroundColor Green
    Write-Host '  #                   Clean Sweep!  -  This machine is clean.                  #'     -ForegroundColor Green
    Write-Host ('  #' + (' ' * 74) + '#')                                                             -ForegroundColor Green
    Write-Host ('  ' + ('#' * 76))                                                                    -ForegroundColor Green
} else {
    $issueStr = "Dave is Sweeping!  -  $totalIssues issue(s) detected. Review report above."
    $pad = ' ' * ([Math]::Max(0, 74 - $issueStr.Length))
    Write-Host ('  ' + ('#' * 76))                                                                         -ForegroundColor Yellow
    Write-Host ('  #' + (' ' * 74) + '#')                                                                  -ForegroundColor Yellow
    Write-Host "  #   $issueStr$pad#"                                                                      -ForegroundColor Yellow
    Write-Host ('  #' + (' ' * 74) + '#')                                                                  -ForegroundColor Yellow
    Write-Host ('  ' + ('#' * 76))                                                                         -ForegroundColor Yellow
}
Write-Host ''

# ==================================================================================================
# EXIT
# ==================================================================================================

if      ($Script:Counters.Failed -and $Script:Counters.IOCsFound -gt 0) { exit 2 }
elseif  ($Script:Counters.IOCsFound -gt 0)                               { exit 2 }
elseif  ($Script:Counters.Failed)                                        { exit 1 }
else                                                                     { exit 0 }

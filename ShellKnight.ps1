#Requires -Version 3.0
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    ShellKnight v2026.07.03.007  -  Enterprise Endpoint Security & Remediation Tool

.DESCRIPTION
    Automated endpoint security remediation, threat detection, hardening, and
    reporting across 8 intelligent engines. Requires PowerShell 3.0 or later
    on Windows 8 / Server 2012 or later. Some engines (Process, Defender,
    Scheduled Tasks) require Windows 8+ cmdlets and will silently skip on
    older OS versions. Designed for silent, headless deployment via Datto RMM /
    CentraStage and other MSP RMM platforms.

    Built for MSPs, IT Administrators, and Security Professionals.

.AUTHOR
    C. David Burgess  -  PTech LLC

.VERSION
    Version    : v2026.07.03.007
    Released   : 2026-07-03
    Prior      : v2026.07.03.006

.ENGINES
    Phase 1  -  Intel Engine        : Threat intelligence download and cache
    Phase 2  -  Assessment Engine   : Machine baseline and vulnerability assessment
    Phase 3  -  Hardening Engine    : Security hardening and configuration
    Phase 4  -  Process Engine      : Process, service, and scheduled task remediation
    Phase 5  -  Persistence Engine  : Persistence mechanism detection and removal
    Phase 6  -  Filesystem Engine   : Artifact cleanup and disk remediation
    Phase 7  -  Detection Engine    : Threat detection and IOC scanning
    Phase 8  -  Reporting Engine    : Reporting, trending, and extended checks

.CHANGELOG
    v2026.07.03.007 - Battlefield push (ADR 0001/0002). At end of run the
             report JSON is POSTed to the Battlefield ingest endpoint with
             an X-API-Key tenant header. Gated OFF by default
             (SK_Battlefield_Enabled) - enable per-deployment via the Datto
             component once the HTTPS endpoint is confirmed reachable. Push
             failure is logged as WARN and never affects the run/exit code;
             the on-disk JSON remains the source of truth.
    v2026.07.03.006 - Field batch from PCH-DT-CJP2ZC3 test run.
             BUG FIX: Get-ProfileScan sizes came back ~0 GB - AllDirectories
             enumeration throws on the first access-denied directory (every
             profile has denied junctions) and aborted the walk, also
             blinding the large-file finder. Replaced with a stack-based
             walker that skips denied dirs and reparse points but keeps
             walking.
             Defender ACTIVE detections now register as High findings in
             the REAL ISSUES table (an active trojan was WARN-only while
             benign 7045 events ranked High).
             Event 7045 whitelist: googleupdater path (Chrome updater
             re-registers its services on every Chrome update).
    v2026.07.03.005 - TLS 1.2 enforcement for all outbound web calls (review
             finding 6b). Field hit: Datto download one-liner failed with
             "Could not create SSL/TLS secure channel" on an older box -
             the same failure would silently degrade Intel Engine feeds
             to the hardcoded fallback list. OR'd into existing protocols
             so TLS 1.3 remains available where the OS supports it.
    v2026.07.03.004 - Per-user persistence coverage (review findings 3a/3b).
             Run/RunOnce keys now scanned for every loaded user hive under
             HKEY_USERS (S-1-5-21-* SIDs; SYSTEM-context HKCU only ever saw
             SYSTEM's own hive). SID resolved to username for logging.
             Startup folder scan now enumerates every profile under
             C:\Users (filesystem - covers logged-off users too), not just
             SYSTEM's AppData + ProgramData.
    v2026.07.03.003 - Honesty batch: fixed or removed features that claimed to
             work but did not (code review findings 1c/1d/1h/1i/5e).
             C2 check now REAL: DNS client cache checked against the C2
             domain feed (old check compared remote IPs to domain names -
             could never match).
             Logged-in User now reports the console user via CIM/quser
             (was hardcoded to the machine account string).
             CVE check stub REMOVED (queried MSRC, logged success, parsed
             nothing since v1.001).
             MalwareBazaar renamed to Hash IOC scan - it never called the
             MB API; ApiKey config removed, SK_HashIOCScan_Enabled added.
             Email/syslog config REMOVED - no implementation existed
             behind the options; alerting arrives with Battlefield.
    v2026.07.03.002 - REAL ISSUES WORTH ACTING ON report section.
             New findings ledger (Add-Finding) collects prioritized High/
             Medium/Low issues during the run; report prints them grouped
             by severity with a recommended action per line. Every IOC
             auto-registers as a High finding. Instrumented: RDP/NLA,
             SMBv1, NetBIOS, local admins (Domain Users = High), BitLocker,
             Defender exclusions, stale profiles (aggregate), large files
             (aggregate), pending updates, CIS password length.
             JSON: new 'findings' array + 'failed_actions' count;
             ConvertTo-Json now -Depth 4.
    v2026.07.03.001 - Field FP batch + SC removal safety (RAS1 2026-06-02,
             HOPECENTER 2026-06-24 runs).
             Event 7045 whitelist: CentraStage svc/path (Datto RMM + bundled
             UltraVNC), HitmanPro, Silver Bullet Technology, PaniniUSB.
             New config: SK_Svc7045_ExtraNames / SK_Svc7045_ExtraPaths for
             per-deployment whitelist additions without editing engine code.
             SC auto-removal now DEFAULT OFF (detect+report only) after it
             half-deleted our own managed instance on HOPECENTER; managed
             instance ID 32f7367870097776 now shipped in config.
             SC delete path guard: >=3 segments deep + leaf must contain
             'screenconnect' before any Remove-Item -Recurse fires.
             Failed counter now displays actual count (was 'Yes'/'1').
    v2026.06.16.001 - Version scheme migration to date-based versioning.
             Phase 6 perf: C:\Users now walked ONCE (single-pass Get-ProfileScan
             via .NET enumerator) instead of twice — feeds both stale-profile
             sizing and the large-file finder. Large-file display capped at 50.
    v1.05 - Fleet feedback batch — false positive reduction and counter fixes.
             NVDisplay/Intel feed FP: added CIM Win32_Process fallback when
             Get-Process.Path returns null; fail-safe to SKIP (not kill) when
             path is unavailable; path comparison upgraded to OrdinalIgnoreCase.
             Scheduled task whitelist: Microsoft SMBv1 removal tasks
             (\Microsoft\Windows\SMB\UninstallSMB1*) no longer flagged or deleted.
             RiskWare miner pattern: changed bare 'miner' substring match to
             word-boundary \bminer to prevent false positives on filenames
             containing 'remineralization' or similar legitimate words.
             Event 7045 whitelist expanded: Datto EDR Agent, Pml Driver HPZ12,
             Net Driver HPZ12, IntelTACD, RapportIaso now suppressed.
             IOC counter bug fix: browser extension removals and Event 7045
             detections now correctly increment $Script:Counters.IOCsFound.
             Local admin report: Domain Admins group suppressed (expected in
             domain environments; not a false-positive admin account).
             Stale profile exclusions: TEMP, UMFD-*, Font Driver Host, DWM-*
             Windows system service profiles added to exclusion list.
             Registry uninstall scan: replaced per-key Get-ItemProperty loop
             with single wildcard batch query for performance on weak endpoints.
             Counter init: Failed counter changed from $false to 0 to prevent
             type inconsistency in JSON output.
             Version : v1.04 -> v1.05.

    v1.04 - False positive fix: Intel feed filename IOC matches now check process
             executable path before flagging and killing. Processes running from
             C:\Windows\, C:\Program Files\, or C:\Program Files (x86)\ are
             skipped as legitimate system/vendor binaries (e.g. NVDisplay.Container
             is a real NVIDIA driver process that appears in threat intel feeds as
             a known impersonation target). Malware running from AppData/Temp/user
             dirs is still caught and killed.
             Version : v1.03 -> v1.04.

    v1.03 - Compatibility and stability release.
             PS 3.0/4.0: all ::new() constructor calls replaced with New-Object.
             PS 3.0-6.x: ?? null-coalescing operator replaced with if/else.
             $ErrorActionPreference reverted to SilentlyContinue (Stop was too
             aggressive with Set-StrictMode -Version 2 active; Invoke-SafeBlock
             provides targeted error handling per-block).
             Phase 6 Filesystem Engine: null-guard added to registry DisplayName
             property access to prevent crash on keys without DisplayName value.
             Versioning scheme updated to .01 increments.
             Version : v1.02 -> v1.03.

    v1.02 - Bug fix release over v1.01.
             Log-Fail now correctly increments Counters.Failed so exit code 1
             and the Failed actions metric fire as intended.
             Remote access service and process matching fixed — inner
             Where-Object now uses captured $svc/$proc variable, not $_.
             Executive Summary added to screen output (before grade section).
             LogWriter null-guard added to Write-Log.
             Version : v1.01 -> v1.02.

    v1.001 - Ground-up rewrite as ShellKnight 2.0. Eight-engine modular architecture.
             Intel Engine: pluggable source framework, HEAD check, single consolidated
             cache, configurable per source.
             Assessment Engine: CVE vulnerability check via Microsoft Security Update
             Guide, Critical/High/Medium severity, KB article references.
             Hardening Engine: LAN Manager auth auto-remediation, Firewall auto-enable,
             SMBv1/LLMNR/NLA/NetBIOS hardening, all configurable.
             Process Engine: full process/service/task inventory, screen shows suspicious
             only, log shows all verbosely.
             Persistence Engine: Run/RunOnce keys, startup folders, WMI subscriptions,
             browser policies, Defender exclusions.
             Filesystem Engine: artifact cleanup, temp files, cache, stale profiles,
             browser extensions, registry uninstall keys.
             Detection Engine: IOC detection, MalwareBazaar, ransomware canary,
             hosts file, network connections, remote access inventory, RISKWARE-RAT.
             Reporting Engine: Windows Update names, trend tracking, event log IOCs,
             reboot check, recent software, extended checks, compliance.
             Performance: Generic List collections, hash table IOC lookups, Filter Left,
             foreach loops, splatting, single-query caching, Invoke-SafeBlock pattern.
             Version : v0.83 -> v1.001 per versioning rule.

    v0.83 - PowerShell script block audit, startup enabled/disabled state,
            LAN Manager auth remediation, Windows Firewall auto-enable,
            memory/CPU/disk health, listening ports, software versions,
            printer audit, license check, local admin audit, credential
            exposure, scheduled task deep inspection.
    v0.82 - UltraVNC CentraStage whitelist (Datto false positive fix).
    v0.81 - Phase 21 SC targeted removal via Event 7045 exact path,
            Defender threat history active/historical split,
            LAN Manager/Firewall in security score.
    v0.80 - Remote access inventory (20 tools), RISKWARE-RAT classification,
            redirected folder scan, Hyper-V detection, VHD exclusions.
    v0.79 - Phase progress indicator, CIS Benchmark Lite, startup classification.
    v0.78 - Defender integration, PS script block audit, magic bytes audit,
            HIPAA/CJIS checks, Windows Update names.
    v0.77 - Risk delta reporting, large file finder, browser credential check,
            N-able detection, HIPAA/acceptable use audit.
    v0.76 - SMBv1/LLMNR/NLA/NetBIOS auto-remediation.
    v0.75 - RiskWare detection, SC AppData scan, 31 new PUA targets.
    v0.74 - Hardening action separation, stale profile deletion.
    v0.73 - Account auto-disable, 14 new PUAs, whitelists.
    v0.72 - Scan depth framework, Phases 22-28.
    v0.71 - AV dedup, Dell CPM WMI whitelist.
    v0.70 - ProgramData path, MalwareBazaar Auth-Key.
    v0.69 - Top-of-file config, email/syslog, PUA expansion.
    v0.68 - ShellKnight rename, A-F grading, JSON output.

.LINK
    Neo23x0 Signature DB : https://github.com/Neo23x0/signature-base
    GitHub               : https://github.com/cdburgess75/ShellKnight
#>

[CmdletBinding()]
param()


# ==============================================================================
# SHELLKNIGHT v2026.07.03.007 CONFIGURATION
# All settings are configured here. No external config files required.
# Each engine can be independently enabled or disabled.
# ==============================================================================

# --- INTEL ENGINE (Phase 1) ---
# Downloads and consolidates threat intelligence from configured sources.
# Maintains a single local cache file updated in place for zero disk bloat.
# Uses HTTP HEAD check to skip downloads when remote source has not changed.
# Falls back to local cache automatically when offline or download fails.
$SK_IntelEngine_Enabled          = $true    # Enable/disable Intel Engine entirely
$SK_IntelEngine_CheckForUpdates  = $true    # Check remote before downloading (saves bandwidth)
$SK_IntelEngine_CacheDir         = 'C:\ProgramData\ShellKnight\Intel\'
$SK_IntelEngine_PrimarySource    = 'Neo23x0'  # Primary IOC source (future: add more)
$SK_IntelEngine_CacheAgeDays     = 7        # Force refresh cache after this many days

# --- ASSESSMENT ENGINE (Phase 2) ---
# Establishes machine baseline including hardware, OS, uptime, domain membership,
# antivirus detection, Windows Update status, and BitLocker state.
# Queries Microsoft Security Update Guide for CVEs applicable to this Windows build.
# Severity levels: Critical, High, Medium reported. KB references included.
$SK_AssessmentEngine_Enabled     = $true    # Enable/disable Assessment Engine
$SK_AssessmentEngine_MinSeverity = 'Medium' # Minimum severity to report (Critical/High/Medium)

# --- HARDENING ENGINE (Phase 3) ---
# Checks and optionally remediates security configuration weaknesses.
# All auto-remediation options default to false for safety.
# Enable per-client after verifying no legacy devices will be impacted.
$SK_HardeningEngine_Enabled      = $true    # Enable/disable Hardening Engine
$SK_DisableSMBv1                 = $false   # Auto-disable SMBv1 (WARNING: verify no legacy devices)
$SK_DisableLLMNR                 = $false   # Auto-disable LLMNR via registry
$SK_EnforceRDP_NLA               = $false   # Auto-enforce NLA on RDP if RDP is enabled
$SK_DisableNetBIOS               = $false   # Auto-disable NetBIOS over TCP/IP on all adapters
$SK_SetLMAuthLevel               = $false   # Auto-set LAN Manager authentication level
$SK_LMAuthLevel                  = 5        # Target LM auth level (5 = NTLMv2 only, refuse LM/NTLM)
                                             # WARNING: level 5 may break legacy devices/printers
$SK_EnableFirewall               = $false   # Auto-enable Windows Firewall on all disabled profiles
$SK_VerboseScreen                = $false   # Show summary INFO messages on screen (default: clean output)

# --- PROCESS ENGINE (Phase 4) ---
# Enumerates all running processes, Windows services, and scheduled tasks.
# Flags and kills malware processes, stops and removes malicious services,
# removes malicious scheduled tasks with full forensic reporting.
# Screen shows only suspicious items. Log contains full verbose inventory.
$SK_ProcessEngine_Enabled        = $true    # Enable/disable Process Engine

# --- PERSISTENCE ENGINE (Phase 5) ---
# Detects and removes all autostart and persistence mechanisms used by malware
# to survive reboots. Uses high-confidence IOC whitelist to minimize false positives.
$SK_PersistenceEngine_Enabled    = $true    # Enable/disable Persistence Engine

# --- FILESYSTEM ENGINE (Phase 6) ---
# Comprehensive filesystem cleanup and remediation. Deletes known-bad software
# folders, registry uninstall keys, browser extension artifacts, temporary files,
# cache files, and stale user profiles. Reports temp file age and stale profiles.
# Also scans redirected home directories on non-C: drives (file servers).
$SK_FilesystemEngine_Enabled     = $true    # Enable/disable Filesystem Engine
$SK_AggressiveTempClean          = $true    # Clean temp files aggressively
$SK_TempCleanAgeThresholdDays    = 30       # Only clean temp files older than this many days
$SK_DeleteStaleProfiles          = $false   # Auto-delete stale user profiles
$SK_DeleteStaleProfileDays       = 1095     # Profile inactive this many days = stale (default: 3 years)
$SK_DeleteStaleProfileOnServer   = $false   # Allow stale profile deletion on servers
$SK_DeleteStaleProfileMinSizeGB  = 0.1     # Minimum profile size to consider for deletion (GB)
$SK_ScanRedirectedFolders        = $true    # Scan non-C: drives for redirected user home PUAs
$SK_LargeFileThresholdGB         = 2.0      # Flag files larger than this size in GB (0 = disable)
$SK_LargeOSTThresholdGB          = 10.0     # Flag Outlook OST files larger than this size in GB
$SK_LargeFileScanPaths           = @("$env:SystemDrive\Users")
$SK_MagicBytesAudit              = $false   # Enable file extension magic bytes audit (Deep tier only)
$SK_MagicBytesMaxFiles           = 5000     # Maximum files to scan in magic bytes audit
$SK_AbortFreeSpaceGB             = 0.5      # Abort cleanup if free space falls below this (GB)
$SK_MinFreeSpaceGB               = 2.0      # Warn if free space is below this (GB)

# --- DETECTION ENGINE (Phase 7) ---
# Comprehensive threat detection. Scans for trojan and malware IOCs, detects
# riskware and exploit tools, performs SHA256 hash-IOC scans against the
# intel feed, checks for ransomware canary patterns, inspects hosts file and
# DNS cache for C2 domains, audits network connections, and inventories all
# remote access tools.
$SK_DetectionEngine_Enabled      = $true    # Enable/disable Detection Engine
$SK_HashIOCScan_Enabled          = $true    # SHA256-hash files in IOC scan paths against the local intel hash list
                                            # (renamed from MalwareBazaar_Enabled - it never called the MB API,
                                            # it checks against the Neo23x0 hash feed loaded by the Intel Engine)
$SK_RemoteAccessInventory        = $true    # Inventory all remote access tools found
$SK_RemoteAccessWarnUnknown      = $true    # WARN on remote tools not in Add/Remove Programs
$SK_ScreenConnect_InstanceID     = '32f7367870097776' # Your managed ScreenConnect instance ID
$SK_RemoveRogueScreenConnect     = $false   # Auto-remove non-managed ScreenConnect instances
                                            # DEFAULT OFF: detect + report only. Field incident
                                            # 2026-06-24 (HOPECENTER): auto-removal fired on our
                                            # own SC instance and half-deleted it (locked DLL).
$SK_Svc7045_ExtraNames           = @()      # Per-deployment additions to the Event 7045 service-name whitelist
$SK_Svc7045_ExtraPaths           = @()      # Per-deployment additions to the Event 7045 service-path whitelist (substring match)
$SK_ScanDepth                    = 'Standard' # Standard, Deep, Compliance

# --- REPORTING ENGINE (Phase 8) ---
# Comprehensive reporting and trend analysis. Reports pending Windows updates
# with KB titles and severity, tracks grade trends against previous runs,
# checks for pending reboots, reports recently installed software, performs
# event log IOC checks, USB audit, and all extended compliance checks.
$SK_ReportingEngine_Enabled      = $true    # Enable/disable Reporting Engine
$SK_AutoDisableInactiveAccounts  = $false   # Auto-disable inactive local accounts
$SK_AutoDisableThresholdDays     = 547      # Accounts inactive this many days = disable candidate
$SK_AutoDisableOnServers         = $false   # Allow auto-disable on servers (default: workstations only)
$SK_AutoDisableExclusions        = @('Administrator','Guest','DefaultAccount','WDAGUtilityAccount')

# NOTE: Email and syslog alerting were removed in the v1.001 rewrite and the
# config options had no implementation behind them (review finding 5e) - they
# were deleted rather than left as silent no-ops. Centralized alerting arrives
# with the Battlefield dashboard (JSON POST ingest, see docs/adr/0001).

# --- BATTLEFIELD DASHBOARD (JSON push) ---
# POST the run report JSON to the Battlefield ingest endpoint at end of run
# (ADR 0001/0002). Gated OFF by default - enable per-deployment (e.g. set the
# variables in the Datto RMM component) once the HTTPS endpoint is confirmed
# reachable. API key identifies the tenant; keep it out of the public repo.
$SK_Battlefield_Enabled          = $false
$SK_Battlefield_URL              = 'https://battlefield.ptechllc.com/api/v1/runs'
$SK_Battlefield_ApiKey           = ''


# ==============================================================================
# STRICT MODE & RUNTIME INITIALIZATION
# ==============================================================================
Set-StrictMode -Version 2
$ErrorActionPreference = 'SilentlyContinue'
$Script:RunStart = Get-Date

# Force TLS 1.2+ for all outbound web calls (Intel Engine feeds, future
# Battlefield POST). Older Windows/PS defaults to TLS 1.0, which GitHub and
# most modern endpoints reject - without this, intel downloads silently fall
# back to the hardcoded IOC list (review finding 6b; field hit 2026-07-03).
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { }

# Runtime Config Object - single source of truth for all engines
$Script:Config = [PSCustomObject]@{
    Version                  = 'v2026.07.03.007'
    # Intel Engine
    IntelEngine_Enabled      = $SK_IntelEngine_Enabled
    IntelEngine_CheckUpdates = $SK_IntelEngine_CheckForUpdates
    IntelEngine_CacheDir     = $SK_IntelEngine_CacheDir
    IntelEngine_CacheAgeDays = $SK_IntelEngine_CacheAgeDays
    # Assessment Engine
    AssessmentEngine_Enabled = $SK_AssessmentEngine_Enabled
    MinSeverity              = $SK_AssessmentEngine_MinSeverity
    # Hardening Engine
    HardeningEngine_Enabled  = $SK_HardeningEngine_Enabled
    DisableSMBv1             = $SK_DisableSMBv1
    DisableLLMNR             = $SK_DisableLLMNR
    EnforceRDP_NLA           = $SK_EnforceRDP_NLA
    DisableNetBIOS           = $SK_DisableNetBIOS
    SetLMAuthLevel           = $SK_SetLMAuthLevel
    LMAuthLevel              = $SK_LMAuthLevel
    EnableFirewall           = $SK_EnableFirewall
    VerboseScreen            = $SK_VerboseScreen
    # Process Engine
    ProcessEngine_Enabled    = $SK_ProcessEngine_Enabled
    # Persistence Engine
    PersistenceEngine_Enabled= $SK_PersistenceEngine_Enabled
    # Filesystem Engine
    FilesystemEngine_Enabled = $SK_FilesystemEngine_Enabled
    AggressiveTempClean      = $SK_AggressiveTempClean
    TempCleanAgeDays         = $SK_TempCleanAgeThresholdDays
    DeleteStaleProfiles      = $SK_DeleteStaleProfiles
    DeleteStaleProfileDays   = $SK_DeleteStaleProfileDays
    DeleteStaleOnServer      = $SK_DeleteStaleProfileOnServer
    DeleteStaleMinSizeGB     = $SK_DeleteStaleProfileMinSizeGB
    ScanRedirectedFolders    = $SK_ScanRedirectedFolders
    LargeFileThresholdGB     = $SK_LargeFileThresholdGB
    LargeOSTThresholdGB      = $SK_LargeOSTThresholdGB
    LargeFileScanPaths       = $SK_LargeFileScanPaths
    MagicBytesAudit          = $SK_MagicBytesAudit
    MagicBytesMaxFiles       = $SK_MagicBytesMaxFiles
    AbortFreeSpaceGB         = $SK_AbortFreeSpaceGB
    MinFreeSpaceGB           = $SK_MinFreeSpaceGB
    # Detection Engine
    DetectionEngine_Enabled  = $SK_DetectionEngine_Enabled
    HashScanEnabled          = $SK_HashIOCScan_Enabled
    BattlefieldEnabled       = $SK_Battlefield_Enabled
    BattlefieldURL           = $SK_Battlefield_URL
    BattlefieldApiKey        = $SK_Battlefield_ApiKey
    RemoteAccessInventory    = $SK_RemoteAccessInventory
    RemoteAccessWarnUnknown  = $SK_RemoteAccessWarnUnknown
    SCInstanceID             = $SK_ScreenConnect_InstanceID
    SCRemoveRogue            = $SK_RemoveRogueScreenConnect
    Svc7045_ExtraNames       = $SK_Svc7045_ExtraNames
    Svc7045_ExtraPaths       = $SK_Svc7045_ExtraPaths
    ScanDepth                = $SK_ScanDepth
    # Reporting Engine
    ReportingEngine_Enabled  = $SK_ReportingEngine_Enabled
    AutoDisable              = $SK_AutoDisableInactiveAccounts
    AutoDisableDays          = $SK_AutoDisableThresholdDays
    AutoDisableOnServers     = $SK_AutoDisableOnServers
    AutoDisableExclusions    = $SK_AutoDisableExclusions
    # Email
    # Syslog
}

# ==============================================================================
# COUNTERS & STATE
# ==============================================================================
$Script:Counters = @{
    ActionsTaken     = 0
    HardeningDone    = 0
    IOCsFound        = 0
    ProcessesKilled  = 0
    ServicesRemoved  = 0
    TasksRemoved     = 0
    RunKeysRemoved   = 0
    FilesRemoved     = 0
    UninstallsRun    = 0
    Failed           = 0
    RebootRequired   = $false
    IntelSource      = 'Hardcoded fallback'
}
$Script:SpaceFreed                = 0L
$Script:RogueScreenConnectRemoved = $false
$Script:HWInfo                    = @{ IsServer = $false; IsHyperVHost = $false }
$Script:SecurityScore             = 100
$Script:PerformanceScore          = 100
$Script:LogReady                  = $false
$Script:PSVer                     = $PSVersionTable.PSVersion.Major
$Script:PSFullVer                 = "$($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor).$($PSVersionTable.PSVersion.Build).$($PSVersionTable.PSVersion.Revision)"

# Pre-compiled IOC collections (populated by Intel Engine)
$Script:HashIOCs     = (New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase))
$Script:FilenameIOCs = (New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase))
$Script:C2IOCs       = (New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase))
$Script:FolderIOCs   = (New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase))

# Single-query caches - populated once, reused across all engines
$Script:Cache_ARP        = $null   # Add/Remove Programs - populated in Assessment Engine
$Script:Cache_Services   = $null   # All services - populated in Process Engine
$Script:Cache_Processes  = $null   # All processes - populated in Process Engine
$Script:Cache_Tasks      = $null   # All scheduled tasks - populated in Process Engine

# Legitimate process/task whitelists
$Script:LegitProcessNames = (New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase))
@(
    'CricutTaskbarApplication','CricutDesignSpace',
    'Zoom','Teams','Slack','Spotify','Discord','OneDrive','Dropbox','GoogleDrive','Box',
    'DYMOConnectLauncher','DYMOConnect','DYMO.DLS.Printing.Host','DYMLabelWriter'
) | ForEach-Object { $null = $Script:LegitProcessNames.Add($_) }

$Script:LegitTaskPaths = @(
    '*AppData\Roaming\Zoom\bin\*','*Teams\*','*Slack\*','*Spotify\*',
    '*Discord\*','*Cricut*','*AppData\Roaming\PCDr\*','*BundleApplicationRepairTool.exe*'
)

# Task Scheduler path prefixes for known-legitimate Microsoft system tasks.
# Tasks living under these paths are skipped regardless of their command line.
# Prevents false positives on OS-built-in tasks that use -ExecutionPolicy or -NoProfile.
$Script:LegitTaskSchedulerPaths = @(
    '\Microsoft\Windows\SMB\'     # SMBv1 auto-removal tasks (OS security feature)
)

# Known legitimate VNC paths (RMM-bundled components)
$Script:LegitVNCPaths = @('CentraStage','Kaseya','LabTech','ConnectWise','NinjaRMM','Atera','N-able')

# Stale profile exclusions
$Script:StaleProfileExclusions = @(
    '.NET v4.5','.NET v4.5 Classic','Classic .NET AppPool','DefaultAppPool',
    'defaultuser0','defaultuser1','defaultuser100000',
    'QBDataServiceUser20','QBDataServiceUser21','QBDataServiceUser22',
    'QBDataServiceUser23','QBDataServiceUser24','QBDataServiceUser25',
    'QBDataServiceUser26','QBDataServiceUser27','QBDataServiceUser28',
    'QBDataServiceUser29','QBDataServiceUser30','QBDataServiceUser31',
    'QBDataServiceUser32','QBDataServiceUser33','QBDataServiceUser34',
    'QBDataServiceUser35',
    # Windows system service profiles - not real user profiles
    '^TEMP$',       # Windows TEMP service account profile
    '^UMFD-',       # User Mode Font Driver service profiles (UMFD-0, UMFD-1, etc.)
    '^DWM-',        # Desktop Window Manager service profiles (DWM-1, DWM-2, etc.)
    'Font Driver Host'  # Font Driver Host service profile
)

# Ransomware canary whitelist
$Script:CanaryWhitelist = @(
    '*Intel\Wireless\WLANProfiles\*.enc','*damsi\*.enc',
    '*SystemCertificates\*','*DPAPI\*'
)

# Hosts file whitelist
$Script:HostsWhitelist = @(
    'granicus.com','mediavault.granicus','idrac.local','drac.local',
    'ilo.local','mssplus.mcafee.com'
)

# WMI subscription whitelist
$Script:WMIWhitelist = @(
    'SCM','BVTFilter','TSlogon','RAevent','RMScheduledTask','OfficeSyncProvider',
    'BVTConsumer','OfficeSync','SCM Event Log Filter','SCM Event Log Consumer',
    'DellCommandPowerManagerAlertEventFilter','DellCommandPowerManagerAlertEventConsumer',
    'DellCommandPowerManagerPolicyChangeEventFilter','DellCommandPowerManagerPolicyChangeEventConsumer'
)

# Legit drop files (never flag these)
$Script:LegitDropFiles = @(
    'Citrix*','AgentInstall.exe','handle.exe','handle64.exe',
    'PsExec.exe','PsExec64.exe','MBSetup.exe'
)


# ==============================================================================
# LOGGING SYSTEM
# ==============================================================================
$Script:LogPath = ''

function Initialize-Logging {
    $logDir = 'C:\ProgramData\ShellKnight\Logs'
    $jsonDir = 'C:\ProgramData\ShellKnight\JSON'
    $intelDir = $Script:Config.IntelEngine_CacheDir
    foreach ($dir in @($logDir, $jsonDir, $intelDir)) {
        if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
    }
    $stamp = Get-Date -Format 'yyyy-MM-dd_HHmm'
    $Script:LogPath = "$logDir\ShellKnight_$stamp.log"
    $Script:LogWriter = New-Object System.IO.StreamWriter -ArgumentList @($Script:LogPath, $false, [System.Text.Encoding]::UTF8)
    $Script:LogReady = $true
}

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $ts = [datetime]::Now.ToString('yyyy-MM-dd HH:mm:ss')
    $line = "$ts  [$($Level.PadRight(7))]  $Message"
    if ($Script:LogReady -and $null -ne $Script:LogWriter) { $Script:LogWriter.WriteLine($line) }

    switch ($Level) {
        'SUCCESS'      { Write-Host $line -ForegroundColor Green }
        'WARN'         { Write-Host $line -ForegroundColor Yellow }
        'FAILED'       { Write-Host $line -ForegroundColor Red }
        'IOC'          { Write-Host $line -ForegroundColor Magenta }
        'HARDEN'       { Write-Host $line -ForegroundColor Cyan }
        'RISKWARE-RAT' { Write-Host $line -ForegroundColor Magenta }
        'SUMMARY'      {
            if ($Script:Config.VerboseScreen) {
                Write-Host $line -ForegroundColor White
            }
        }
        default        { } # INFO goes to log only
    }
}

function Log-Info        { param([string]$m) Write-Log -Message $m -Level 'INFO'    }
function Log-Success     { param([string]$m) Write-Log -Message $m -Level 'SUCCESS' }
function Log-Warn        { param([string]$m) Write-Log -Message $m -Level 'WARN'    }
function Log-Fail        { param([string]$m) Write-Log -Message $m -Level 'FAILED'; $Script:Counters.Failed++  }
function Log-IOC         {
    param([string]$m)
    Write-Log -Message $m -Level 'IOC'
    # Indented lines are continuations of the previous IOC - don't double-count
    if ($m -notmatch '^\s') {
        Add-Finding -Severity High -Title "IOC: $m" -Action 'Investigate; if legitimate software, whitelist via SK_Svc7045_ExtraNames/ExtraPaths'
    }
}
function Log-Harden      { param([string]$m) Write-Log -Message $m -Level 'HARDEN'  }
function Log-RiskwareRAT { param([string]$m) Write-Log -Message $m -Level 'RISKWARE-RAT' }
function Log-Summary     { param([string]$m) Write-Log -Message $m -Level 'SUMMARY' }

# ------------------------------------------------------------------------------
# Findings ledger - feeds the "REAL ISSUES WORTH ACTING ON" report section.
# Engines call Add-Finding when a check produces something an operator should
# review; the Reporting Engine prints them grouped High/Medium/Low.
# ------------------------------------------------------------------------------
$Script:Findings = (New-Object 'System.Collections.Generic.List[object]')
function Add-Finding {
    param(
        [ValidateSet('High','Medium','Low')][string]$Severity,
        [string]$Title,     # short label, e.g. 'RDP enabled, NLA not enforced'
        [string]$Action     # recommended next step for the operator
    )
    $Script:Findings.Add([PSCustomObject]@{
        Severity = $Severity
        Title    = $Title
        Action   = $Action
    })
}

# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

# Phase progress indicator
function Write-PhaseProgress {
    param([int]$PhaseNum, [int]$TotalPhases = 8, [string]$PhaseName)
    $elapsed = [math]::Round(((Get-Date) - $Script:RunStart).TotalSeconds)
    $mins    = [math]::Floor($elapsed / 60)
    $secs    = $elapsed % 60
    $elStr   = ([string]$mins).PadLeft(2,'0') + ':' + ([string]$secs).PadLeft(2,'0')
    Write-Host "  [$elStr | Phase $PhaseNum/$TotalPhases]  $PhaseName..." -ForegroundColor Cyan
}

# Standardized error handler - Invoke-SafeBlock pattern
function Invoke-SafeBlock {
    param([scriptblock]$Block, [string]$Label)
    try { & $Block }
    catch { Log-Info "$Label skipped  -  $($_.Exception.Message)" }
}

# Get folder size in bytes
function Get-FolderSizeBytes {
    param([string]$Path)
    try {
        $gciParams = @{ LiteralPath = $Path; Recurse = $true; Force = $true; ErrorAction = 'SilentlyContinue'; File = $true }
        (Get-ChildItem @gciParams | Measure-Object -Property Length -Sum).Sum
    } catch { 0L }
}

# Fast single-pass scan of a user-profiles root.
# Walks the tree ONCE via the .NET enumerator (3-6x faster than Get-ChildItem -Recurse)
# and returns BOTH per-top-level-folder byte totals and files over a threshold.
# Replaces two separate full traversals (stale-profile sizing + large-file finder).
function Get-ProfileScan {
    param(
        [string]$Root,
        [long]$LargeThresholdBytes,
        [System.Collections.Generic.HashSet[string]]$ExcludeExts
    )
    $sizes = @{}                                              # profileName -> total bytes
    $large = New-Object 'System.Collections.Generic.List[object]'
    if (-not [System.IO.Directory]::Exists($Root)) {
        return [PSCustomObject]@{ Sizes = $sizes; Large = $large }
    }
    foreach ($profileDir in [System.IO.Directory]::EnumerateDirectories($Root)) {
        $profileName = [System.IO.Path]::GetFileName($profileDir)
        $total = 0L
        # Manual stack-based walk. AllDirectories enumeration THROWS on the
        # first access-denied directory and aborts the remaining walk - and
        # every profile contains denied junctions (Application Data etc.), so
        # sizes came back ~0 in the field (PCH-DT-CJP2ZC3 2026-07-03). This
        # walker skips denied dirs and reparse points but keeps walking.
        $dirStack = New-Object 'System.Collections.Generic.Stack[string]'
        $dirStack.Push($profileDir)
        while ($dirStack.Count -gt 0) {
            $dir = $dirStack.Pop()
            try {
                foreach ($sub in [System.IO.Directory]::EnumerateDirectories($dir)) {
                    try {
                        $attr = [System.IO.File]::GetAttributes($sub)
                        if ($attr -band [System.IO.FileAttributes]::ReparsePoint) { continue }  # skip junctions - loops/double-count
                    } catch { continue }
                    $dirStack.Push($sub)
                }
                foreach ($file in [System.IO.Directory]::EnumerateFiles($dir)) {
                    try { $len = (New-Object System.IO.FileInfo $file).Length } catch { continue }
                    $total += $len
                    if ($len -gt $LargeThresholdBytes) {
                        $ext = [System.IO.Path]::GetExtension($file).ToLower()
                        if (-not $ExcludeExts.Contains($ext)) {
                            $large.Add([PSCustomObject]@{ FullName = $file; Length = $len; Extension = $ext })
                        }
                    }
                }
            } catch { }  # denied dir: skip it, continue with the rest of the stack
        }
        $sizes[$profileName] = $total
    }
    [PSCustomObject]@{ Sizes = $sizes; Large = $large }
}

# Remove folder contents with before/after reporting
function Remove-FolderContents {
    param([string]$Path, [string]$Label)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $gciParams = @{ LiteralPath = $Path; Recurse = $true; Force = $true; ErrorAction = 'SilentlyContinue'; File = $true }
    $before = @(Get-ChildItem @gciParams)
    $beforeCount = $before.Count
    $beforeBytes = ($before | Measure-Object -Property Length -Sum).Sum
    $removed = 0
    foreach ($f in $before) {
        try { Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop; $removed++ } catch { }
    }
    if ($removed -gt 0) {
        $freedMB = [math]::Round($beforeBytes / 1MB, 1)
        $afterCount = $beforeCount - $removed
        Log-Success "Cleaned $Label  -  Before: $beforeCount files / $freedMB MB | After: $afterCount files | Freed: $freedMB MB"
        $Script:SpaceFreed += $beforeBytes
        $Script:Counters.ActionsTaken++
        $Script:Counters.FilesRemoved += $removed
    }
}

# Separator lines
function Write-SectionHeader { param([string]$Title)
    $line = '=' * 80
    Log-Info $line
    Log-Info "  $Title"
    Log-Info ('-' * 80)
}


# ==============================================================================
# SCRIPT INITIALIZATION
# ==============================================================================
Initialize-Logging

# Detect PS version compatibility
$Script:UseNewPSFeatures = $Script:PSVer -ge 5

# Banner
$bannerWidth = 78
$version     = 'ShellKnight v2026.07.03.007'
$hostname    = $env:COMPUTERNAME
$timestamp   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$psver       = "PS $($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor)"
$line        = '=' * $bannerWidth

Write-Host ''
Write-Host "  $line" -ForegroundColor Cyan
Write-Host "  $version  |  $hostname  |  $timestamp  |  $psver" -ForegroundColor Cyan
Write-Host "  $line" -ForegroundColor Cyan
Write-Host ''
Write-Host "  Full log: $Script:LogPath"
Write-Host "  $('-' * $bannerWidth)"

Log-Info $line
Log-Info "  $version  |  $hostname  |  $timestamp  |  $psver"
Log-Info $line

# ==============================================================================
# PHASE 1: INTEL ENGINE
# Threat intelligence download, consolidation, and caching
# ==============================================================================
Write-PhaseProgress -PhaseNum 1 -PhaseName 'Intel Engine'
Log-Info '--- Phase 1: Intel Engine ---'

$Script:HashIOCsLoaded    = 0
$Script:FilenameIOCsLoaded = 0
$Script:C2IOCsLoaded      = 0

# Hardcoded fallback IOC patterns (used if download fails and no cache exists)
$Script:FallbackFolderIOCs = (New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase))
@(
    'njrat','asyncrat','redline','vidar','lokibot','qakbot','remcos',
    'nanocore','darkcomet','adwind','jrat','limeRAT','quasar',
    'agent tesla','raccoon','azorult','formbook','emotet','trickbot',
    'lavasoft','webcompanion','conduit','babylon','sweetim',
    'opencandy','wajam','crossrider','mypcsecurity','pckeeper',
    'reimage','iminlikewithyou','dealply','browsefox'
) | ForEach-Object { $null = $Script:FallbackFolderIOCs.Add($_) }

if ($Script:Config.IntelEngine_Enabled) {
    Invoke-SafeBlock -Label 'Intel Engine' -Block {
        $cacheDir  = $Script:Config.IntelEngine_CacheDir
        $cacheFile = Join-Path $cacheDir 'neo23x0_consolidated.json'
        $cacheAge  = $Script:Config.IntelEngine_CacheAgeDays

        # Neo23x0 IOC sources
        $sources = @(
            @{ Name = 'Filename IOCs'; Url = 'https://raw.githubusercontent.com/Neo23x0/signature-base/master/iocs/filename-iocs.txt' }
            @{ Name = 'Hash IOCs';     Url = 'https://raw.githubusercontent.com/Neo23x0/signature-base/master/iocs/hash-iocs.txt' }
            @{ Name = 'C2 IOCs';       Url = 'https://raw.githubusercontent.com/Neo23x0/signature-base/master/iocs/c2-iocs.txt' }
        )

        $useCache    = $false
        $cacheExists = Test-Path -LiteralPath $cacheFile

        if ($cacheExists) {
            $cacheDate = (Get-Item -LiteralPath $cacheFile).LastWriteTime
            $cacheOld  = ((Get-Date) - $cacheDate).TotalDays -gt $cacheAge

            if (-not $cacheOld -and $Script:Config.IntelEngine_CheckUpdates) {
                # HEAD check - only download if remote has changed
                try {
                    $headResp = Invoke-WebRequest -Uri $sources[0].Url -Method Head -TimeoutSec 5 -ErrorAction Stop
                    $remoteDate = [datetime]::Parse($headResp.Headers['Last-Modified'])
                    $useCache = $remoteDate -le $cacheDate
                    if ($useCache) { Log-Summary "Intel Engine  -  cache current, skipping download" }
                } catch { $useCache = $true }
            } elseif (-not $cacheOld) {
                $useCache = $true
            }
        }

        if (-not $useCache) {
            # Download and consolidate all sources into single cache
            $consolidated = @{
                Filename = (New-Object 'System.Collections.Generic.List[string]')
                Hashes   = (New-Object 'System.Collections.Generic.List[string]')
                C2       = (New-Object 'System.Collections.Generic.List[string]')
                Updated  = (Get-Date).ToString('o')
                Source   = $Script:Config.IntelEngine_PrimarySource
            }

            foreach ($source in $sources) {
                try {
                    $content = (Invoke-WebRequest -Uri $source.Url -TimeoutSec 30 -ErrorAction Stop).Content
                    $lines   = $content -split "`n" | Where-Object { $_ -and -not $_.StartsWith('#') }
                    switch -Wildcard ($source.Name) {
                        'Filename*' { foreach ($l in $lines) { $consolidated.Filename.Add($l.Trim()) } }
                        'Hash*'     { foreach ($l in $lines) { $consolidated.Hashes.Add($l.Trim().ToLower()) } }
                        'C2*'       { foreach ($l in $lines) { $consolidated.C2.Add($l.Trim().ToLower()) } }
                    }
                    Log-Info "Intel Engine  -  downloaded $($source.Name)"
                } catch {
                    Log-Warn "Intel Engine  -  failed to download $($source.Name): $($_.Exception.Message)"
                }
            }

            # Write single consolidated cache file (replace in place)
            $consolidated | ConvertTo-Json -Compress | Set-Content -LiteralPath $cacheFile -Encoding UTF8 -Force
            $Script:Counters.IntelSource = 'Live (Neo23x0)'
            Log-Summary "Intel Engine  -  cache updated from Neo23x0"
        } else {
            $Script:Counters.IntelSource = 'Cache (current)'
        }

        # Load consolidated cache into hash sets for O(1) lookup
        if (Test-Path -LiteralPath $cacheFile) {
            $cache = Get-Content -LiteralPath $cacheFile -Raw | ConvertFrom-Json
            if ($cache.Hashes)   { foreach ($h in $cache.Hashes)   { $null = $Script:HashIOCs.Add($h) } }
            if ($cache.Filename) { foreach ($f in $cache.Filename) { $null = $Script:FilenameIOCs.Add($f) } }
            if ($cache.C2)       { foreach ($c in $cache.C2)       { $null = $Script:C2IOCs.Add($c) } }
            $Script:HashIOCsLoaded     = $Script:HashIOCs.Count
            $Script:FilenameIOCsLoaded = $Script:FilenameIOCs.Count
            $Script:C2IOCsLoaded       = $Script:C2IOCs.Count
            Log-Summary "Intel Engine  -  $($Script:HashIOCsLoaded) hash IOCs | $($Script:FilenameIOCsLoaded) filename IOCs | $($Script:C2IOCsLoaded) C2 IOCs loaded"
        }
    }
} else {
    Log-Info "Intel Engine  -  disabled, using fallback IOCs only"
    $Script:Counters.IntelSource = 'Disabled (fallback only)'
}


# ==============================================================================
# PHASE 2: ASSESSMENT ENGINE
# Machine baseline, hardware, OS, AV, vulnerabilities
# ==============================================================================
Write-PhaseProgress -PhaseNum 2 -PhaseName 'Assessment Engine'
Log-Info '--- Phase 2: Assessment Engine ---'

$Script:MachineInfo = [ordered]@{}
$bitlockerWarn      = $false
$osEolWarn          = $false
$wuLastWarn         = $false
$avProduct          = 'NONE DETECTED'
$defStatus          = 'Unknown'
$inactiveAccounts   = (New-Object 'System.Collections.Generic.List[object]')
$Script:MinPasswordLen = 0

if ($Script:Config.AssessmentEngine_Enabled) {
    Invoke-SafeBlock -Label 'Assessment Engine' -Block {

        # Hardware & OS Detection
        $os  = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $cs  = Get-CimInstance Win32_ComputerSystem  -ErrorAction Stop
        $bios= Get-CimInstance Win32_BIOS            -ErrorAction Stop

        $osName    = $os.Caption
        $osBuild   = $os.BuildNumber
        $arch      = if ($os.OSArchitecture -match '64') { '64-bit' } else { '32-bit' }
        $biosDate  = [datetime]::ParseExact($bios.ReleaseDate.Split('.')[0],'yyyyMMdd',$null)
        $pcAgeYrs  = [math]::Round(((Get-Date) - $biosDate).TotalDays / 365.25, 1)
        $lastBoot  = $os.LastBootUpTime
        $uptime    = (Get-Date) - $lastBoot
        $uptimeStr = "$([math]::Floor($uptime.TotalDays))d $($uptime.Hours)h $($uptime.Minutes)m"
        $domain    = if ($cs.PartOfDomain) { "Domain: $($cs.Domain)" } else { "Workgroup: $($cs.Workgroup)" }
        # Console user via CIM; running as SYSTEM, $env:USERNAME would be the machine account
        $loggedIn  = if ($cs.UserName) { $cs.UserName } else {
            $quserLine = (& quser 2>$null | Select-Object -Skip 1 | Select-Object -First 1)
            if ($quserLine) { ($quserLine.Trim() -split '\s+')[0].TrimStart('>') } else { '(none)' }
        }

        # Server detection
        $Script:HWInfo.IsServer = $osName -match 'Server'

        # Disk space
        $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction SilentlyContinue
        $diskFreeGB  = if ($disk) { [math]::Round($disk.FreeSpace / 1GB, 1) } else { 0 }
        $diskTotalGB = if ($disk) { [math]::Round($disk.Size / 1GB, 1) } else { 0 }
        $diskUsedPct = if ($diskTotalGB -gt 0) { [math]::Round((($diskTotalGB - $diskFreeGB) / $diskTotalGB) * 100, 1) } else { 0 }

        # BitLocker
        $blStatus = 'Not available'
        try {
            $bl = Get-BitLockerVolume -MountPoint 'C:' -ErrorAction Stop
            $blStatus = $bl.ProtectionStatus
            if ($blStatus -ne 'On') { $bitlockerWarn = $true; $blStatus = 'Off' } else { $blStatus = 'On' }
        } catch {
            try {
                $blWmi = Get-CimInstance -Namespace 'Root\CIMV2\Security\MicrosoftVolumeEncryption' `
                         -ClassName 'Win32_EncryptableVolume' -Filter "DriveLetter='C:'" -ErrorAction Stop
                $blStatus = if ($blWmi.ProtectionStatus -eq 1) { 'On' } else { 'Off'; $bitlockerWarn = $true }
            } catch { }
        }

        # OS EOL check
        $eolDates = @{
            '7601'  = [datetime]'2020-01-14'; '9200' = [datetime]'2023-10-10'
            '9600'  = [datetime]'2023-10-10'; '10240'= [datetime]'2025-10-14'
            '10586' = [datetime]'2017-10-10'; '14393'= [datetime]'2027-01-12'
            '15063' = [datetime]'2018-10-09'; '16299'= [datetime]'2019-04-09'
            '17134' = [datetime]'2019-11-12'; '17763'= [datetime]'2029-01-09'
            '18362' = [datetime]'2020-05-12'; '18363'= [datetime]'2021-05-11'
            '19041' = [datetime]'2025-10-14'; '19042'= [datetime]'2025-10-14'
            '19043' = [datetime]'2025-10-14'; '19044'= [datetime]'2026-10-13'
            '19045' = [datetime]'2030-10-14'; '20348'= [datetime]'2031-10-14'
            '22000' = [datetime]'2026-10-14'; '22621'= [datetime]'2027-10-12'
            '22631' = [datetime]'2028-10-10'; '26100'= [datetime]'2029-10-14'
        }
        $eolDate   = $eolDates[$osBuild]
        $eolStr    = if ($eolDate) {
            if ((Get-Date) -gt $eolDate) { $osEolWarn = $true; "END OF LIFE (since $($eolDate.ToString('yyyy-MM-dd')))"}
            else { "Supported until $($eolDate.ToString('yyyy-MM-dd'))" }
        } else { 'Unknown' }

        # RAM
        $ramGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)

        # AV Detection
        $avProducts = (New-Object 'System.Collections.Generic.List[string]')
        try {
            $avList = Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName 'AntiVirusProduct' -ErrorAction Stop
            foreach ($av in $avList) {
                $avName = $av.displayName
                if ($avName -notmatch 'Windows Defender') { $avProducts.Add($avName) }
            }
        } catch { }

        # Datto AV / RMM / EDR detection
        $dattoServices = @{
            'EndpointProtectionService2' = 'Datto AV'
            'CagService'                 = 'Datto RMM'
            'HUNTAgent'                  = 'Datto EDR / Huntress'
        }
        foreach ($svcName in $dattoServices.Keys) {
            $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
            if ($svc) { $avProducts.Add($dattoServices[$svcName]) }
        }

        if ($avProducts.Count -gt 0) { $avProduct = $avProducts -join ', ' }

        # Defender status
        try {
            $mp = Get-MpComputerStatus -ErrorAction Stop
            $defStatus = if ($mp.AMServiceEnabled -and $mp.RealTimeProtectionEnabled) { 'Active' } else { 'DISABLED' }
            $defSigs   = $mp.AntivirusSignatureLastUpdated.ToString('yyyy-MM-dd')
        } catch { $defSigs = 'Unknown' }

        # Windows Update last install
        $wuDate = $null
        try {
            $wu = New-Object -ComObject Microsoft.Update.Session -ErrorAction Stop
            $searcher = $wu.CreateUpdateSearcher()
            $history  = $searcher.QueryHistory(0, 1)
            if ($history.Count -gt 0) {
                $wuDate    = $history.Item(0).Date
                $wuDaysAgo = ([datetime]::Now - $wuDate).Days
                $wuStr     = "$($wuDate.ToString('yyyy-MM-dd')) ($wuDaysAgo days ago)"
                if ($wuDaysAgo -gt 30) { $wuLastWarn = $true }
            }
        } catch { $wuStr = 'Unknown' }

        # Populate ARP cache once for all engines
        $Script:Cache_ARP = @(Get-ItemProperty `
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' `
            -ErrorAction SilentlyContinue |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation, UninstallString)

        # Build machine info
        $Script:MachineInfo = [ordered]@{
            'Hostname'        = $env:COMPUTERNAME
            'OS'              = "$osName (Build $osBuild)"
            'OS EOL'          = $eolStr
            'Architecture'    = $arch
            'PC Age'          = "$pcAgeYrs years (BIOS: $($biosDate.ToString('yyyy-MM-dd')))"
            'RAM'             = "$ramGB GB"
            'Last Boot'       = $lastBoot.ToString('yyyy-MM-dd HH:mm:ss')
            'Uptime'          = $uptimeStr
            'Domain/Workgroup'= $domain
            'Logged-in User'  = $loggedIn
            'C: Drive'        = "$diskFreeGB GB free of $diskTotalGB GB ($diskUsedPct% used)"
            'BitLocker'       = $blStatus
            'Antivirus'       = $avProduct
            'Defender'        = $defStatus
            'Defender Sigs'   = $defSigs
            'Last WU Install' = $wuStr
            'PS Version'      = $Script:PSFullVer
            'Intel Source'    = $Script:Counters.IntelSource
        }

        # Log machine info block
        $sepLine = '=' * 80
        Log-Info $sepLine
        Log-Info '  MACHINE INFORMATION'
        Log-Info ('-' * 80)
        foreach ($key in $Script:MachineInfo.Keys) {
            Log-Info ('  {0,-20} {1}' -f $key, $Script:MachineInfo[$key])
        }
        Log-Info $sepLine

        # Screen summary
        Write-Host "  Hostname: $($env:COMPUTERNAME)  |  OS: $osName  |  RAM: $ramGB GB  |  Disk: $diskFreeGB GB free" -ForegroundColor White
        if ($osEolWarn)    { Log-Warn "OS EOL: $eolStr" }
        if ($bitlockerWarn){
            Log-Warn "BitLocker: C: drive is NOT encrypted"
            Add-Finding -Severity Medium -Title 'BitLocker not enabled on C:' -Action 'Enable BitLocker (required for HIPAA/CJIS clients; escrow recovery key in AD/RMM)'
        }
        if ($pcAgeYrs -gt 5){ Log-Warn "Aging hardware: PC is $pcAgeYrs years (BIOS: $($biosDate.ToString('yyyy-MM-dd')))" }
        if ($wuLastWarn)   { Log-Warn "Windows Update: last install was $wuDaysAgo days ago" }

        # Hyper-V detection
        Invoke-SafeBlock -Label 'Hyper-V detection' -Block {
            $hvFeature = Get-WindowsOptionalFeature -Online -FeatureName 'Microsoft-Hyper-V' -ErrorAction SilentlyContinue
            if ($hvFeature -and $hvFeature.State -eq 'Enabled') {
                $vms = @(Get-VM -ErrorAction SilentlyContinue)
                $vmList = if ($vms.Count -gt 0) {
                    ($vms | ForEach-Object { "$($_.Name) [$($_.State)]" }) -join ', '
                } else { 'none running' }
                $Script:MachineInfo['Hyper-V Host'] = "Yes  -  $($vms.Count) VM(s): $vmList"
                $Script:HWInfo.IsHyperVHost = $true
                Log-Summary "Hyper-V host  -  $($vms.Count) VM(s): $vmList"
            }
        }

        # Password policy
        Invoke-SafeBlock -Label 'Password policy' -Block {
            $passOut = & net accounts 2>$null
            $minLenLine = $passOut | Where-Object { $_ -match 'Minimum password length' }
            if ($minLenLine) {
                $Script:MinPasswordLen = [int]($minLenLine -replace '[^\d]','')
                if ($Script:MinPasswordLen -eq 0)      { Log-Warn "Password policy: minimum length is 0  -  recommend 12 or more" }
                elseif ($Script:MinPasswordLen -lt 8)  { Log-Warn "Password policy: minimum length is $Script:MinPasswordLen  -  recommend 12 or more" }
                elseif ($Script:MinPasswordLen -lt 12) { Log-Warn "Password policy: minimum length is $Script:MinPasswordLen  -  recommend 12 or more" }
                else { Log-Summary "Password policy: minimum length $Script:MinPasswordLen (OK)" }
            }
        }

        # Inactive accounts
        Invoke-SafeBlock -Label 'Inactive accounts' -Block {
            $cutoff = (Get-Date).AddDays(-90)
            $excludePatterns = @('^SM_','^HealthMailbox','^QBDataServiceUser\d+$','^defaultuser\d*$','^machine\$')
            $localUsers = Get-LocalUser -ErrorAction Stop
            foreach ($u in $localUsers) {
                $skip = $excludePatterns | Where-Object { $u.Name -match $_ }
                if ($skip -or -not $u.Enabled) { continue }
                $lastLogon = $u.LastLogon
                if ($null -eq $lastLogon -or $lastLogon -lt $cutoff) {
                    $daysAgo = if ($lastLogon) { ([datetime]::Now - $lastLogon).Days } else { 9999 }
                    $lastStr = if ($lastLogon) { $lastLogon.ToString('yyyy-MM-dd') } else { 'never' }
                    $inactiveAccounts.Add([PSCustomObject]@{ Name=$u.Name; LastLogon=$lastStr; DaysAgo=$daysAgo })
                }
            }
            if ($inactiveAccounts.Count -gt 0) {
                Log-Warn "Inactive local accounts (90+ days)  -  $($inactiveAccounts.Count) found:"
                foreach ($ia in $inactiveAccounts) {
                    Log-Warn "  $($ia.Name) (last logon: $($ia.LastLogon)  -  $($ia.DaysAgo) days ago)"
                }
            } else { Log-Summary "Local accounts  -  no inactive accounts found" }
        }

        Log-Summary "Assessment Engine complete"
    }
} else {
    Log-Info "Assessment Engine  -  disabled"
}


# ==============================================================================
# PHASE 3: HARDENING ENGINE
# Security configuration hardening and remediation
# ==============================================================================
Write-PhaseProgress -PhaseNum 3 -PhaseName 'Hardening Engine'
Log-Info '--- Phase 3: Hardening Engine ---'

if ($Script:Config.HardeningEngine_Enabled) {

    # RDP / NLA check
    Invoke-SafeBlock -Label 'RDP check' -Block {
        $rdpEnabled = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' `
                       -Name 'fDenyTSConnections' -ErrorAction Stop).fDenyTSConnections -eq 0
        if ($rdpEnabled) {
            $nlaEnabled = (Get-ItemProperty `
                'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
                -Name 'UserAuthentication' -ErrorAction SilentlyContinue).UserAuthentication -eq 1
            if (-not $nlaEnabled -and $Script:Config.EnforceRDP_NLA) {
                Set-ItemProperty `
                    'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
                    -Name 'UserAuthentication' -Value 1 -Type DWord -Force
                Log-Harden "RDP NLA enforced  -  Network Level Authentication now required"
            } elseif ($nlaEnabled) {
                Log-Summary "RDP is ENABLED  -  NLA enforced (OK)"
            } else {
                Log-Warn "RDP is ENABLED  -  NLA NOT enforced  -  recommend enabling"
                Add-Finding -Severity Medium -Title 'RDP enabled, NLA not enforced' -Action 'Enable NLA via GPO: Computer Config > Admin Templates > Remote Desktop Services'
            }
        } else {
            Log-Summary "RDP  -  disabled (OK)"
        }
    }

    # SMBv1
    Invoke-SafeBlock -Label 'SMBv1 check' -Block {
        $smb1 = Get-SmbServerConfiguration -ErrorAction Stop | Select-Object -ExpandProperty EnableSMB1Protocol
        if ($smb1) {
            if ($Script:Config.DisableSMBv1) {
                Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop
                Log-Harden "SMBv1 disabled  -  legacy protocol eliminated"
            } else {
                Log-Warn "SMBv1 is ENABLED  -  critical vulnerability, recommend disabling"
                Add-Finding -Severity High -Title 'SMBv1 protocol enabled' -Action 'Disable SMBv1 (set $SK_DisableSMBv1=$true or disable manually); verify no legacy devices need it'
            }
        } else { Log-Summary "SMBv1  -  disabled (OK)" }
    }

    # LLMNR
    Invoke-SafeBlock -Label 'LLMNR check' -Block {
        $llmnr = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' `
                  -Name 'EnableMulticast' -ErrorAction SilentlyContinue).EnableMulticast
        if ($llmnr -ne 0) {
            if ($Script:Config.DisableLLMNR) {
                $regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
                if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
                Set-ItemProperty -Path $regPath -Name 'EnableMulticast' -Value 0 -Type DWord -Force
                Log-Harden "LLMNR disabled  -  MITM attack vector eliminated"
            } else { Log-Warn "LLMNR may be enabled  -  recommend disabling via GPO" }
        } else { Log-Summary "LLMNR  -  disabled (OK)" }
    }

    # NetBIOS
    Invoke-SafeBlock -Label 'NetBIOS check' -Block {
        $adapters = Get-CimInstance Win32_NetworkAdapterConfiguration -ErrorAction Stop | Where-Object { $_.IPEnabled }
        $netbiosOn = @($adapters | Where-Object { $_.TcpipNetbiosOptions -ne 2 })
        if ($netbiosOn.Count -gt 0) {
            if ($Script:Config.DisableNetBIOS) {
                $disabled = 0
                foreach ($adapter in $netbiosOn) {
                    try { $r = $adapter.SetTcpipNetbios(2); if ($r.ReturnValue -eq 0) { $disabled++ } } catch { }
                }
                if ($disabled -gt 0) { Log-Harden "NetBIOS disabled on $disabled adapter(s)" }
            } else {
                Log-Warn "NetBIOS over TCP/IP may be enabled on $($netbiosOn.Count) adapter(s)  -  recommend disabling"
                Add-Finding -Severity Medium -Title "NetBIOS over TCP/IP enabled ($($netbiosOn.Count) adapter(s))" -Action 'Disable via DHCP scope option or adapter WINS settings'
            }
        } else { Log-Summary "NetBIOS  -  disabled on all adapters (OK)" }
    }

    # LAN Manager auth level
    Invoke-SafeBlock -Label 'LAN Manager auth check' -Block {
        $lmPath    = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        $lmCurrent = (Get-ItemProperty $lmPath -Name 'LmCompatibilityLevel' -ErrorAction SilentlyContinue).LmCompatibilityLevel
        if ($null -eq $lmCurrent -or $lmCurrent -lt 3) {
            if ($Script:Config.SetLMAuthLevel) {
                Set-ItemProperty -Path $lmPath -Name 'LmCompatibilityLevel' -Value $Script:Config.LMAuthLevel -Type DWord -Force
                Log-Harden "LAN Manager auth level set to $($Script:Config.LMAuthLevel) (NTLMv2 only)"
            } else { Log-Warn "LAN Manager auth level is $lmCurrent  -  recommend setting to 5 (NTLMv2 only)" }
        } else { Log-Summary "LAN Manager auth level: $lmCurrent (OK)" }
    }

    # Windows Firewall
    Invoke-SafeBlock -Label 'Firewall check' -Block {
        $fwProfiles = @(Get-NetFirewallProfile -ErrorAction Stop)
        $fwDisabled = @($fwProfiles | Where-Object { $_.Enabled -eq $false })
        if ($fwDisabled.Count -gt 0) {
            if ($Script:Config.EnableFirewall) {
                foreach ($p in $fwDisabled) { Set-NetFirewallProfile -Name $p.Name -Enabled True -ErrorAction SilentlyContinue }
                Log-Harden "Windows Firewall enabled on: $($fwDisabled.Profile -join ', ')"
            } else { Log-Warn "Windows Firewall disabled on: $($fwDisabled.Profile -join ', ')" }
        } else { Log-Summary "Windows Firewall  -  enabled on all profiles (OK)" }
    }

    # Local admins
    Invoke-SafeBlock -Label 'Local admin check' -Block {
        $admins = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop)
        if ($admins.Count -gt 1) {
            Log-Warn "Local admins found ($($admins.Count) total)  -  review unexpected accounts:"
            # Domain Admins group is expected on domain-joined machines - suppress noise
            $suppressedAdminPatterns = @('Administrator$', '\\Domain Admins$')
            foreach ($a in $admins) {
                $isSuppressed = $suppressedAdminPatterns | Where-Object { $a.Name -match $_ }
                if (-not $isSuppressed) {
                    Log-Warn "  $($a.Name)  -  REVIEW: should this account be an admin?"
                    if ($a.Name -match '\\Domain Users$') {
                        # Every domain user is a local admin - worst case
                        Add-Finding -Severity High -Title "'$($a.Name)' is in local Administrators (ALL domain users have admin)" -Action 'Remove Domain Users from Administrators; grant admin per-user only where required'
                    } else {
                        Add-Finding -Severity Medium -Title "Local admin: $($a.Name)" -Action 'Confirm this account requires admin rights; remove if not'
                    }
                }
            }
        } else { Log-Summary "Local admins  -  $($admins.Count) account(s) (OK)" }
    }

    # Process creation auditing
    Invoke-SafeBlock -Label 'Process auditing' -Block {
        $auditVal = (auditpol /get /subcategory:"Process Creation" 2>$null) -join ''
        if ($auditVal -notmatch 'Success') {
            auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable 2>$null | Out-Null
            Log-Harden "Process creation auditing enabled  -  event 4688 will now log"
        } else { Log-Summary "Process creation auditing  -  already enabled (OK)" }
    }

    Log-Summary "Hardening Engine complete"
} else {
    Log-Info "Hardening Engine  -  disabled"
}


# ==============================================================================
# PHASE 4: PROCESS ENGINE
# Process, service, and scheduled task enumeration and remediation
# ==============================================================================
Write-PhaseProgress -PhaseNum 4 -PhaseName 'Process Engine'
Log-Info '--- Phase 4: Process Engine ---'

if ($Script:Config.ProcessEngine_Enabled) {

    # Single query - cache all processes, services, tasks
    $Script:Cache_Processes = @(Get-Process -ErrorAction SilentlyContinue)
    $Script:Cache_Services  = @(Get-Service -ErrorAction SilentlyContinue)
    $Script:Cache_Tasks     = @(Get-ScheduledTask -ErrorAction SilentlyContinue)

    # Known malware process patterns
    $malwareProcPatterns = (New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase))
    @(
        'njrat','asyncrat','redlinestealer','vidar','lokibot','remcos',
        'nanocore','darkcomet','adwind','quasar','limerat','agent tesla',
        'raccoon','azorult','formbook','emotet','trickbot','dcrat','darkgate',
        'hijackloader','netbus','subseven','bifrost','poison ivy',
        'cryptolocker','wannacry','notpetya','ryuk','conti','lockbit',
        'revil','darkside','blackcat','play','clop','akira'
    ) | ForEach-Object { $null = $malwareProcPatterns.Add($_) }

    # Known malware service patterns
    $malwareSvcPatterns = (New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase))
    @(
        'winvnc','ultravnc','ammyy','netsupport','remotepc','gotomypc',
        'logmein123','teamviewerqs','atera','meshagent','rustdesk',
        'action1','simplehelp'
    ) | ForEach-Object { $null = $malwareSvcPatterns.Add($_) }

    # Process enumeration - log all, screen only suspicious
    Log-Info "Process Engine  -  $($Script:Cache_Processes.Count) processes running"
    # Paths that indicate a legitimate system or vendor binary - Intel IOC filename
    # matches running from these locations are false positives (malware impersonation
    # check: real malware runs from AppData/Temp/user dirs, not Program Files/System32)
    $legitProcRoots = @(
        'C:\Windows\',
        'C:\Program Files\',
        'C:\Program Files (x86)\'
    )

    $killedProcs = 0
    foreach ($proc in $Script:Cache_Processes) {
        if ($Script:LegitProcessNames.Contains($proc.Name)) { continue }
        $isMalware    = $malwareProcPatterns | Where-Object { $proc.Name -match $_ }
        $inFilenameIOC = $Script:FilenameIOCs.Contains($proc.Name)
        if ($isMalware -or $inFilenameIOC) {
            # For Intel feed filename matches, verify the process isn't a legit binary
            # running from a system path before flagging and killing.
            # Get-Process.Path returns null for some kernel/driver processes (e.g. NVIDIA).
            # Fall back to CIM Win32_Process for those cases. If path is still unavailable,
            # fail safe: skip rather than kill.
            if ($inFilenameIOC -and -not $isMalware) {
                $procPath = try { (Get-Process -Id $proc.Id -ErrorAction Stop).Path } catch { $null }
                if (-not $procPath) {
                    $procPath = try { (Get-CimInstance Win32_Process -Filter "ProcessId=$($proc.Id)" -ErrorAction Stop).ExecutablePath } catch { $null }
                }
                if (-not $procPath) {
                    Log-Summary "Intel IOC name match: $($proc.Name) - path unavailable, skipping (fail-safe)"
                    continue
                }
                $resolvedPath = try { [System.IO.Path]::GetFullPath($procPath) } catch { $procPath }
                if ($legitProcRoots | Where-Object { $resolvedPath.StartsWith($_, [System.StringComparison]::OrdinalIgnoreCase) }) {
                    Log-Summary "Intel IOC name match: $($proc.Name) running from system path - likely legit, skipping ($resolvedPath)"
                    continue
                }
            }
            Log-IOC "Malware process detected: $($proc.Name) (PID: $($proc.Id))"
            try {
                Stop-Process -Id $proc.Id -Force -ErrorAction Stop
                Log-Success "Killed process: $($proc.Name) (PID: $($proc.Id))"
                $killedProcs++
                $Script:Counters.ProcessesKilled++
                $Script:Counters.IOCsFound++
            } catch { Log-Fail "Could not kill process: $($proc.Name)  -  $($_.Exception.Message)" }
        } else {
            Log-Info "  [PROC] $($proc.Name) (PID: $($proc.Id)) CPU: $([math]::Round($proc.CPU,1))s"
        }
    }
    if ($killedProcs -eq 0) { Log-Summary "Process Engine  -  no malware processes found" }

    # Service enumeration - log all, screen only suspicious
    Log-Info "Process Engine  -  $($Script:Cache_Services.Count) services found"
    $removedSvcs = 0

    # Known malware service names (high confidence)
    $malwareSvcNames = @(
        'winnc','nvsvc32','MSUpdater','WindowsUpdaterService',
        'JavaUpdater','AdobeFlashUpdate'
    )
    $malwareSvcHash = (New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase))
    foreach ($s in $malwareSvcNames) { $null = $malwareSvcHash.Add($s) }

    foreach ($svc in $Script:Cache_Services) {
        $isMalware = $malwareSvcHash.Contains($svc.Name)
        if ($isMalware) {
            Log-IOC "Malware service detected: $($svc.DisplayName) [$($svc.Status)]"
            try {
                if ($svc.Status -eq 'Running') { Stop-Service -Name $svc.Name -Force -ErrorAction Stop }
                & sc.exe delete $svc.Name 2>$null | Out-Null
                Log-Success "Removed service: $($svc.DisplayName)"
                $removedSvcs++
                $Script:Counters.ServicesRemoved++
                $Script:Counters.IOCsFound++
            } catch { Log-Fail "Could not remove service: $($svc.Name)  -  $($_.Exception.Message)" }
        } else {
            Log-Info "  [SVC] $($svc.DisplayName) [$($svc.Status)] - $($svc.StartType)"
        }
    }
    if ($removedSvcs -eq 0) { Log-Summary "Process Engine  -  no malware services found" }

    # Scheduled task enumeration with forensic inspection
    $obfuscPattern = New-Object System.Text.RegularExpressions.Regex -ArgumentList @(
        'encodedcommand|frombase64|invoke-expression|iex |downloadstring|webclient|bypass|hidden|noprofile|-enc ',
        ([System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Compiled))

    $activeTasks = @($Script:Cache_Tasks | Where-Object { $_.State -ne 'Disabled' })
    Log-Info "Process Engine  -  $($activeTasks.Count) active scheduled tasks"
    $suspectTasks = 0

    foreach ($task in $activeTasks) {
        # Skip known-legitimate Microsoft system task scheduler paths entirely
        $isLegitSchedulerPath = $Script:LegitTaskSchedulerPaths | Where-Object { $task.TaskPath -like "$_*" }
        if ($isLegitSchedulerPath) {
            Log-Info "  [TASK][SYSTEM] $($task.TaskName) - Microsoft system task path, skipping"
            continue
        }
        foreach ($action in $task.Actions) {
            if (-not $action.PSObject.Properties['Execute']) { continue }
            $cmdLine  = "$($action.Execute) $($action.Arguments)"
            $isLegit  = $Script:LegitTaskPaths | Where-Object { $cmdLine -like $_ }
            $isObfusc = $obfuscPattern.IsMatch($cmdLine)

            if ($isObfusc -and -not $isLegit) {
                Log-IOC "Suspicious scheduled task: $($task.TaskName)"
                Log-IOC "  Path: $($task.TaskPath)  |  Cmd: $($cmdLine.Substring(0,[Math]::Min(120,$cmdLine.Length)))"
                $suspectTasks++
                $Script:Counters.IOCsFound++
                try {
                    Unregister-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -Confirm:$false -ErrorAction Stop
                    Log-Success "Removed suspicious task: $($task.TaskName)"
                    $Script:Counters.TasksRemoved++
                } catch { Log-Fail "Could not remove task: $($task.TaskName)" }
            } else {
                # Startup enabled/disabled state
                $approvedPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"
                $stateTag = '[ENABLED]'
                $isHigh   = @('OneDrive','Dropbox','Steam','Discord','Spotify','Teams','Slack','Nvidia','GeForce','Adobe') |
                            Where-Object { $task.TaskName -match $_ }
                $isMed    = @('Chrome','Edge','Zoom','QuickBooks','Acrobat') | Where-Object { $task.TaskName -match $_ }
                $tier     = if ($isHigh) { 'HIGH' } elseif ($isMed) { 'MED' } else { 'LOW' }
                Log-Info "  [TASK][$tier]$stateTag $($task.TaskName)  -  $cmdLine"
            }
        }
    }
    if ($suspectTasks -eq 0) { Log-Summary "Process Engine  -  no suspicious scheduled tasks found" }

    Log-Summary "Process Engine complete  -  $killedProcs process(es) killed, $removedSvcs service(s) removed"
} else {
    Log-Info "Process Engine  -  disabled"
}


# ==============================================================================
# PHASE 5: PERSISTENCE ENGINE
# All autostart and persistence mechanism detection and removal
# ==============================================================================
Write-PhaseProgress -PhaseNum 5 -PhaseName 'Persistence Engine'
Log-Info '--- Phase 5: Persistence Engine ---'

if ($Script:Config.PersistenceEngine_Enabled) {

    # Known malware Run key executables
    $malwareRunPatterns = (New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase))
    @(
        'njrat','asyncrat','remcos','nanocore','darkcomet','quasar',
        'formbook','emotet','trickbot','agent tesla','raccoon',
        'lavasoft','webcompanion','conduit','babylon','sweetim',
        'opencandy','wajam','crossrider','dealply','browsefox',
        'cbsidlm','installiq','gamevan','arcadecandy','shophome'
    ) | ForEach-Object { $null = $malwareRunPatterns.Add($_) }

    # Run / RunOnce key cleanup
    $runKeyPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
    )

    $runKeysRemoved = 0
    foreach ($keyPath in $runKeyPaths) {
        if (-not (Test-Path $keyPath)) { continue }
        Invoke-SafeBlock -Label "Run key $keyPath" -Block {
            $props = Get-ItemProperty $keyPath -ErrorAction Stop
            $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                $name = $_.Name
                $val  = $_.Value
                $isMalware = $malwareRunPatterns | Where-Object { $name -match $_ -or $val -match $_ }
                $inIOC     = $Script:FilenameIOCs | Where-Object { $val -match [regex]::Escape($_) }
                if ($isMalware -or $inIOC) {
                    Log-IOC "Malware Run key: $name = $val"
                    Remove-ItemProperty -Path $keyPath -Name $name -Force -ErrorAction SilentlyContinue
                    Log-Success "Removed Run key: $name"
                    $Script:Counters.RunKeysRemoved++
                    $Script:Counters.IOCsFound++
                    $runKeysRemoved++
                } else {
                    Log-Info "  [RUN] $name = $val"
                }
            }
        }
    }
    if ($runKeysRemoved -eq 0) { Log-Summary "Persistence Engine  -  no malware Run keys found" }

    # Per-user Run / RunOnce keys via HKEY_USERS.
    # Running as SYSTEM, HKCU above is SYSTEM's own hive - real users' Run keys
    # live under HKU\<SID> and were previously never scanned (review finding 3a).
    # Covers hives currently loaded (logged-on users + recently active); offline
    # hives would require reg load of each NTUSER.DAT and are intentionally skipped.
    Invoke-SafeBlock -Label 'Per-user Run keys (HKU)' -Block {
        if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
            $null = New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -Scope Script
        }
        # S-1-5-21-* = real local/domain accounts; skip service SIDs and _Classes hives
        $userSids = @(Get-ChildItem 'HKU:\' -ErrorAction Stop |
                      Where-Object { $_.PSChildName -match '^S-1-5-21-' -and $_.PSChildName -notmatch '_Classes$' })
        $hkuScanned = 0
        foreach ($sidKey in $userSids) {
            $sid = $sidKey.PSChildName
            # Resolve SID to username for readable logging; fall back to raw SID
            $who = try { (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value } catch { $sid }
            foreach ($sub in @('SOFTWARE\Microsoft\Windows\CurrentVersion\Run','SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce')) {
                $keyPath = "HKU:\$sid\$sub"
                if (-not (Test-Path $keyPath)) { continue }
                $hkuScanned++
                $props = Get-ItemProperty $keyPath -ErrorAction SilentlyContinue
                if (-not $props) { continue }
                $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                    $name = $_.Name
                    $val  = $_.Value
                    $isMalware = $malwareRunPatterns | Where-Object { $name -match $_ -or $val -match $_ }
                    $inIOC     = $Script:FilenameIOCs | Where-Object { $val -match [regex]::Escape($_) }
                    if ($isMalware -or $inIOC) {
                        Log-IOC "Malware Run key (user: $who): $name = $val"
                        Remove-ItemProperty -Path $keyPath -Name $name -Force -ErrorAction SilentlyContinue
                        Log-Success "Removed per-user Run key: $name ($who)"
                        $Script:Counters.RunKeysRemoved++
                        $Script:Counters.IOCsFound++
                    } else {
                        Log-Info "  [RUN:$who] $name = $val"
                    }
                }
            }
        }
        Log-Summary "Persistence Engine  -  per-user Run keys: $($userSids.Count) loaded hive(s) scanned (offline hives not loaded)"
    }

    # Startup folder LNK cleanup.
    # $env:APPDATA under SYSTEM is SYSTEM's own profile - per-user Startup
    # folders are enumerated from C:\Users so ALL profiles are covered,
    # including users who are not logged on (review finding 3b).
    $startupFolders = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup'
    )
    $startupFolders += @(Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue |
                         Where-Object { $_.Name -notmatch '^(Public|Default|All Users)$' } |
                         ForEach-Object { Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' })
    $lnksRemoved = 0
    foreach ($folder in $startupFolders) {
        if (-not (Test-Path $folder)) { continue }
        $lnks = @(Get-ChildItem -LiteralPath $folder -Filter '*.lnk' -Force -ErrorAction SilentlyContinue)
        foreach ($lnk in $lnks) {
            $isMalware = $malwareRunPatterns | Where-Object { $lnk.Name -match $_ }
            $inIOC     = $Script:FilenameIOCs.Contains($lnk.BaseName)
            if ($isMalware -or $inIOC) {
                Log-IOC "Malware startup LNK: $($lnk.FullName)"
                Remove-Item -LiteralPath $lnk.FullName -Force -ErrorAction SilentlyContinue
                Log-Success "Removed startup LNK: $($lnk.Name)"
                $lnksRemoved++
                $Script:Counters.IOCsFound++
            } else {
                Log-Info "  [LNK] $($lnk.Name)"
            }
        }
    }
    if ($lnksRemoved -eq 0) { Log-Summary "Persistence Engine  -  no malware startup LNKs found" }

    # WMI persistence audit
    Invoke-SafeBlock -Label 'WMI persistence' -Block {
        $wmiFilters   = @(Get-CimInstance -Namespace root\subscription -ClassName __EventFilter   -ErrorAction Stop)
        $wmiConsumers = @(Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction Stop)
        $wmiBound     = @(Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction Stop)

        $wmiSuspect = 0
        foreach ($filter in $wmiFilters) {
            $isWhitelisted = $Script:WMIWhitelist | Where-Object { $filter.Name -match $_ }
            if (-not $isWhitelisted) {
                Log-IOC "Suspicious WMI Event Filter: $($filter.Name)  -  Query: $($filter.Query)"
                $wmiSuspect++
                $Script:Counters.IOCsFound++
            } else {
                Log-Info "  [WMI] Filter: $($filter.Name) (whitelisted)"
            }
        }
        if ($wmiSuspect -eq 0) { Log-Summary "Persistence Engine  -  no suspicious WMI subscriptions found" }
    }

    # Browser policy key cleanup
    $browserPolicyPaths = @(
        'HKLM:\SOFTWARE\Policies\Google\Chrome',
        'HKLM:\SOFTWARE\Policies\Microsoft\Edge',
        'HKCU:\SOFTWARE\Policies\Google\Chrome',
        'HKCU:\SOFTWARE\Policies\Microsoft\Edge'
    )
    $policyRemoved = 0
    foreach ($policyPath in $browserPolicyPaths) {
        if (-not (Test-Path $policyPath)) { continue }
        Invoke-SafeBlock -Label "Browser policy $policyPath" -Block {
            $props = Get-ItemProperty $policyPath -ErrorAction Stop
            $suspectPolicies = @('ExtensionInstallForcelist','HomepageLocation','RestoreOnStartupURLs')
            $props.PSObject.Properties | Where-Object { $_.Name -in $suspectPolicies } | ForEach-Object {
                Log-IOC "Suspicious browser policy: $($_.Name) = $($_.Value)"
                Remove-ItemProperty -Path $policyPath -Name $_.Name -Force -ErrorAction SilentlyContinue
                Log-Success "Removed browser policy key: $($_.Name)"
                $policyRemoved++
                $Script:Counters.IOCsFound++
            }
        }
    }
    if ($policyRemoved -eq 0) { Log-Summary "Persistence Engine  -  no browser policy hijacks found" }

    # Defender exclusion audit
    Invoke-SafeBlock -Label 'Defender exclusions' -Block {
        $excl = Get-MpPreference -ErrorAction Stop
        $suspectExclusions = (New-Object 'System.Collections.Generic.List[string]')
        $legitimateExclPaths = @('C:\Windows','C:\Program Files','C:\ProgramData\Datto','C:\ProgramData\ShellKnight')

        foreach ($path in $excl.ExclusionPath) {
            $isLegit = $legitimateExclPaths | Where-Object { $path -like "$_*" }
            if (-not $isLegit) {
                Log-Warn "Suspicious Defender exclusion path: $path"
                Add-Finding -Severity High -Title "Suspicious Defender exclusion: $path" -Action 'Verify legitimacy; remove via Remove-MpPreference -ExclusionPath if not intentional'
                $suspectExclusions.Add($path)
            } else {
                Log-Info "  [EXCL] $path (legitimate)"
            }
        }
        if ($suspectExclusions.Count -eq 0) { Log-Summary "Persistence Engine  -  no suspicious Defender exclusions found" }
    }

    Log-Summary "Persistence Engine complete"
} else {
    Log-Info "Persistence Engine  -  disabled"
}


# ==============================================================================
# PHASE 6: FILESYSTEM ENGINE
# Artifact cleanup, temp files, cache, stale profiles, browser extensions
# ==============================================================================
Write-PhaseProgress -PhaseNum 6 -PhaseName 'Filesystem Engine'
Log-Info '--- Phase 6: Filesystem Engine ---'

if ($Script:Config.FilesystemEngine_Enabled) {

    # Abort if disk is critically low
    $diskNow = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction SilentlyContinue
    $freeNow  = if ($diskNow) { [math]::Round($diskNow.FreeSpace / 1GB, 1) } else { 99 }
    if ($freeNow -lt $Script:Config.AbortFreeSpaceGB) {
        Log-Warn "Filesystem Engine  -  ABORTED: only $freeNow GB free (threshold: $($Script:Config.AbortFreeSpaceGB) GB)"
    } else {

        # Known PUA/malware drop locations
        $dropLocations = (New-Object 'System.Collections.Generic.List[string]')
        @(
            "$env:TEMP","$env:WINDIR\Temp",
            "$env:LOCALAPPDATA\Temp",
            'C:\Users\Public',
            'C:\Users\Public\Downloads'
        ) | ForEach-Object { $dropLocations.Add($_) }

        # Known PUA folder names (high confidence)
        $puaFolders = (New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase))
        @(
            'Lavasoft','WebCompanion','Conduit','Babylon','SweetIM','OpenCandy',
            'Wajam','Crossrider','DealPly','BrowseFox','MyPCBackup','PCKeeper',
            'Reimage','SearchProtect','SupTab','WebBar','YTDownloader',
            'Incredibar','Iminent','Bandoo','iLivid','Facemoods',
            'BabylonToolbar','Delta','Qvo6','Istartsurf','Trovi'
        ) | ForEach-Object { $null = $puaFolders.Add($_) }

        # Scan user AppData for PUA folders
        $puaRemoved = 0
        $userDirs   = @(Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue |
                        Where-Object { $_.Name -notmatch '^(Public|Default|All Users)$' })

        foreach ($userDir in $userDirs) {
            $appDataPaths = @(
                (Join-Path $userDir.FullName 'AppData\Local'),
                (Join-Path $userDir.FullName 'AppData\Roaming')
            )
            foreach ($adPath in $appDataPaths) {
                if (-not (Test-Path $adPath)) { continue }
                $subDirs = @(Get-ChildItem -LiteralPath $adPath -Directory -Force -ErrorAction SilentlyContinue)
                foreach ($sub in $subDirs) {
                    if ($puaFolders.Contains($sub.Name)) {
                        Log-IOC "PUA folder found ($($userDir.Name)): $($sub.FullName)"
                        try {
                            Remove-Item -LiteralPath $sub.FullName -Recurse -Force -ErrorAction Stop
                            Log-Success "Removed User PUP dir ($($userDir.Name)): $($sub.FullName)"
                            $puaRemoved++
                            $Script:Counters.IOCsFound++
                        } catch { Log-Fail "Could not remove: $($sub.FullName)" }
                    }
                }
            }
        }
        if ($puaRemoved -eq 0) { Log-Summary "Filesystem Engine  -  no PUA folders found" }

        # Browser extension cleanup
        $extRemoved = 0
        $badExtIDs = (New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase))
        @('cfhdojbkjhnklbpkdaibdccddilifddb','flliilndjeohchalpbbcdekjklbdgfkk') |
            ForEach-Object { $null = $badExtIDs.Add($_) }

        foreach ($userDir in $userDirs) {
            $extPaths = @(
                (Join-Path $userDir.FullName 'AppData\Local\Google\Chrome\User Data\Default\Extensions'),
                (Join-Path $userDir.FullName 'AppData\Local\Microsoft\Edge\User Data\Default\Extensions')
            )
            foreach ($extPath in $extPaths) {
                if (-not (Test-Path $extPath)) { continue }
                $extDirs = @(Get-ChildItem -LiteralPath $extPath -Directory -ErrorAction SilentlyContinue)
                foreach ($ext in $extDirs) {
                    if ($badExtIDs.Contains($ext.Name)) {
                        Log-IOC "Malware browser extension: $($ext.Name) in $extPath"
                        $Script:Counters.IOCsFound++
                        Remove-Item -LiteralPath $ext.FullName -Recurse -Force -ErrorAction SilentlyContinue
                        Log-Success "Removed browser extension: $($ext.Name)"
                        $extRemoved++
                    }
                }
            }
        }
        if ($extRemoved -eq 0) { Log-Summary "Filesystem Engine  -  no malware browser extensions found" }

        # Registry uninstall key cleanup (matches ARP entries for removed PUAs)
        $arpRemoved = 0
        $uninstallPaths = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        )
        foreach ($unPath in $uninstallPaths) {
            if (-not (Test-Path $unPath)) { continue }
            # Batch all subkey properties in one query instead of per-key Get-ItemProperty calls
            $allEntries = @(Get-ItemProperty -Path "$unPath\*" -ErrorAction SilentlyContinue)
            foreach ($entry in $allEntries) {
                if (-not $entry.PSObject.Properties['DisplayName']) { continue }
                $dispName = $entry.DisplayName
                if ($dispName -and ($puaFolders | Where-Object { $dispName -match $_ })) {
                    Log-IOC "PUA registry uninstall entry: $dispName"
                    Remove-Item -LiteralPath $entry.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                    Log-Success "Removed PUA uninstall key: $dispName"
                    $arpRemoved++
                }
            }
        }
        if ($arpRemoved -eq 0) { Log-Summary "Filesystem Engine  -  no PUA uninstall keys found" }

        # Disk cleanup - WER, CBS, caches, prefetch, thumbnails
        $gciParams = @{ Recurse = $true; Force = $true; ErrorAction = 'SilentlyContinue'; File = $true }
        $cleanupTargets = @(
            @{ Path = 'C:\ProgramData\Microsoft\Windows\WER\ReportArchive'; Label = 'WER Report Archive'; FastDelete = $true }
            @{ Path = 'C:\ProgramData\Microsoft\Windows\WER\ReportQueue';   Label = 'WER Report Queue';   FastDelete = $true }
            @{ Path = 'C:\Windows\Logs\CBS';                                 Label = 'CBS Logs';           FastDelete = $false }
        )

        foreach ($target in $cleanupTargets) {
            if (-not (Test-Path -LiteralPath $target.Path)) { continue }
            if ($target.FastDelete) {
                $beforeSize  = Get-FolderSizeBytes $target.Path
                $beforeCount = @(Get-ChildItem -LiteralPath $target.Path -Recurse -Force -ErrorAction SilentlyContinue -File).Count
                try {
                    Remove-Item -LiteralPath $target.Path -Recurse -Force -ErrorAction Stop
                    New-Item -Path $target.Path -ItemType Directory -Force | Out-Null
                    $freedMB = [math]::Round($beforeSize / 1MB, 1)
                    Log-Success "Cleaned $($target.Label)  -  Before: $beforeCount files / $freedMB MB | After: 0 files | Freed: $freedMB MB"
                    $Script:SpaceFreed += $beforeSize
                    $Script:Counters.ActionsTaken++
                } catch { Remove-FolderContents -Path $target.Path -Label $target.Label }
            } else {
                Remove-FolderContents -Path $target.Path -Label $target.Label
            }
        }

        # Windows Update Cache with file count safety
        Invoke-SafeBlock -Label 'Windows Update Cache' -Block {
            $wuPath  = 'C:\Windows\SoftwareDistribution\Download'
            $wuSvcs  = @('wuauserv','bits','UsoSvc') | ForEach-Object { Get-Service -Name $_ -ErrorAction SilentlyContinue }
            foreach ($svc in $wuSvcs) { if ($svc -and $svc.Status -eq 'Running') { Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue } }
            Start-Sleep -Seconds 2
            $wuCount = @(Get-ChildItem -LiteralPath $wuPath -Recurse -Force -ErrorAction SilentlyContinue -File).Count
            if ($wuCount -gt 50000) {
                $wuSize = Get-FolderSizeBytes $wuPath
                Remove-Item -LiteralPath $wuPath -Recurse -Force -ErrorAction SilentlyContinue
                New-Item -Path $wuPath -ItemType Directory -Force | Out-Null
                $freedMB = [math]::Round($wuSize / 1MB, 1)
                Log-Success "Cleaned Windows Update Cache  -  $wuCount files / $freedMB MB | Freed: $freedMB MB (fast delete)"
            } else {
                Remove-FolderContents -Path $wuPath -Label 'Windows Update Cache'
            }
            foreach ($svc in $wuSvcs) { if ($svc) { Start-Service -Name $svc.Name -ErrorAction SilentlyContinue } }
        }

        # Delivery Optimization Cache
        Invoke-SafeBlock -Label 'Delivery Optimization' -Block {
            $doPath = "$env:WINDIR\SoftwareDistribution\DeliveryOptimization"
            if (Test-Path $doPath) { Remove-FolderContents -Path $doPath -Label 'Delivery Optimization Cache' }
        }

        # Prefetch
        Invoke-SafeBlock -Label 'Prefetch' -Block {
            Remove-FolderContents -Path 'C:\Windows\Prefetch' -Label 'Prefetch'
        }

        # Thumbnail caches
        foreach ($userDir in $userDirs) {
            $thumbPath = Join-Path $userDir.FullName 'AppData\Local\Microsoft\Windows\Explorer'
            if (-not (Test-Path $thumbPath)) { continue }
            $thumbFiles = @(Get-ChildItem -LiteralPath $thumbPath -Filter 'thumbcache_*.db' -Force -ErrorAction SilentlyContinue)
            if ($thumbFiles.Count -gt 0) {
                $thumbSize = ($thumbFiles | Measure-Object -Property Length -Sum).Sum
                foreach ($f in $thumbFiles) { Remove-Item -LiteralPath $f.FullName -Force -ErrorAction SilentlyContinue }
                $thumbMB = [math]::Round($thumbSize / 1MB, 1)
                Log-Success "Cleaned thumbnail cache ($($userDir.Name))  -  freed $thumbMB MB"
                $Script:SpaceFreed += $thumbSize
            }
        }

        # User Temp files (age-based)
        $cutoffDate = (Get-Date).AddDays(-$Script:Config.TempCleanAgeDays)
        foreach ($userDir in $userDirs) {
            $tempPath = Join-Path $userDir.FullName 'AppData\Local\Temp'
            if (-not (Test-Path $tempPath)) { continue }
            $oldFiles = @(Get-ChildItem -LiteralPath $tempPath @gciParams | Where-Object { $_.LastWriteTime -lt $cutoffDate })
            if ($oldFiles.Count -gt 0) {
                $oldSize  = ($oldFiles | Measure-Object -Property Length -Sum).Sum
                $removed  = 0
                foreach ($f in $oldFiles) { try { Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop; $removed++ } catch { } }
                if ($removed -gt 0) {
                    $freedMB = [math]::Round($oldSize / 1MB, 1)
                    Log-Success "Cleaned User Temp ($($userDir.Name))  -  Before: $($oldFiles.Count) files / $freedMB MB | After: $($oldFiles.Count - $removed) files | Freed: $freedMB MB"
                    $Script:SpaceFreed += $oldSize
                }
            }
        }

        # Windows Temp (age-based)
        Invoke-SafeBlock -Label 'Windows Temp' -Block {
            $wtPath  = 'C:\Windows\Temp'
            $oldWT   = @(Get-ChildItem -LiteralPath $wtPath @gciParams | Where-Object { $_.LastWriteTime -lt $cutoffDate })
            if ($oldWT.Count -gt 0) {
                $wtSize = ($oldWT | Measure-Object -Property Length -Sum).Sum
                $removed = 0
                foreach ($f in $oldWT) { try { Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop; $removed++ } catch { } }
                if ($removed -gt 0) {
                    $freedMB = [math]::Round($wtSize / 1MB, 1)
                    Log-Success "Cleaned Windows Temp  -  Before: $($oldWT.Count) files / $freedMB MB | After: $($oldWT.Count - $removed) files | Freed: $freedMB MB"
                    $Script:SpaceFreed += $wtSize
                }
            }
        }

        # Single-pass scan of C:\Users — feeds BOTH stale-profile sizing and the
        # large-file finder below, replacing two full recursive traversals with one.
        $largeThreshBytes = if ($Script:Config.LargeFileThresholdGB -gt 0) {
            [long]($Script:Config.LargeFileThresholdGB * 1GB)
        } else { [long]::MaxValue }   # threshold disabled: still collect sizes, skip large files
        $vhdExts = (New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase))
        @('.vhd','.vhdx','.vmrs','.vmdk','.vdi','.ova','.ovf') | ForEach-Object { $null = $vhdExts.Add($_) }
        $Script:ProfileScan = Get-ProfileScan -Root 'C:\Users' -LargeThresholdBytes $largeThreshBytes -ExcludeExts $vhdExts

        # Stale profile report
        $staleProfiles = (New-Object 'System.Collections.Generic.List[object]')
        $staleCutoff   = (Get-Date).AddDays(-180)
        foreach ($userDir in $userDirs) {
            # Skip 8.3 short filename artifacts
            if ($userDir.Name -match '~') { continue }
            $excluded = $Script:StaleProfileExclusions | Where-Object { $userDir.Name -match $_ }
            if ($excluded) { continue }
            # Skip Exchange service accounts
            if ($userDir.Name -match '^(SM_|HealthMailbox)') { continue }
            $lastActivity = $userDir.LastWriteTime
            if ($lastActivity -lt $staleCutoff) {
                $cachedBytes = if ($Script:ProfileScan.Sizes.ContainsKey($userDir.Name)) { $Script:ProfileScan.Sizes[$userDir.Name] } else { Get-FolderSizeBytes $userDir.FullName }
                $sizeGB  = [math]::Round($cachedBytes / 1GB, 2)
                $daysOld = ([datetime]::Now - $lastActivity).Days
                $staleProfiles.Add([PSCustomObject]@{
                    Name         = $userDir.Name
                    LastActivity = $lastActivity.ToString('yyyy-MM-dd')
                    DaysAgo      = $daysOld
                    SizeGB       = $sizeGB
                    Path         = $userDir.FullName
                })
                Log-Warn "Stale profile: $($userDir.Name)  -  last activity: $($lastActivity.ToString('yyyy-MM-dd')) ($daysOld days ago) | Size: $sizeGB GB"
            }
        }
        if ($staleProfiles.Count -eq 0) { Log-Summary "Filesystem Engine  -  no stale profiles found" }
        else {
            $staleTotalGB = [math]::Round(($staleProfiles | Measure-Object -Property SizeGB -Sum).Sum, 1)
            $staleTop = ($staleProfiles | Sort-Object SizeGB -Descending | Select-Object -First 3 | ForEach-Object { "$($_.Name) $($_.SizeGB)GB" }) -join ', '
            Add-Finding -Severity Low -Title "$($staleProfiles.Count) stale profile(s) using $staleTotalGB GB (top: $staleTop)" -Action 'Confirm users are gone, then remove profiles via System Properties or Delprof2'
        }

        # Redirected folder scan
        if ($Script:Config.ScanRedirectedFolders) {
            Invoke-SafeBlock -Label 'Redirected folder scan' -Block {
                $redirectedDrives = @(Get-PSDrive -PSProvider FileSystem -ErrorAction Stop |
                                      Where-Object { $_.Root -notmatch '^C:\\' -and (Test-Path "$($_.Root)Users") })
                if ($redirectedDrives.Count -gt 0) {
                    Log-Summary "Redirected folder scan  -  $($redirectedDrives.Count) non-C: drive(s) with Users folders"
                    $puaExts     = @('.exe','.bat','.cmd','.vbs','.js','.ps1','.msi','.scr')
                    $scanSubFolders = @('Downloads','Desktop','AppData\Local\Temp')
                    $puaPattern  = New-Object System.Text.RegularExpressions.Regex -ArgumentList @(
                        'toolbar|hijack|adware|pup|bundl|newssetup|crawler|conduit|babylon|sweet.?im',
                        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

                    foreach ($drive in $redirectedDrives) {
                        $usersPath  = "$($drive.Root)Users"
                        $userFolders= @(Get-ChildItem -LiteralPath $usersPath -Directory -ErrorAction SilentlyContinue)
                        foreach ($uf in $userFolders) {
                            foreach ($sub in $scanSubFolders) {
                                $scanPath = Join-Path $uf.FullName $sub
                                if (-not (Test-Path $scanPath)) { continue }
                                $suspFiles = @(Get-ChildItem -LiteralPath $scanPath -Force -File -ErrorAction SilentlyContinue |
                                               Where-Object { $puaExts -contains $_.Extension.ToLower() })
                                foreach ($f in $suspFiles) {
                                    if ($puaPattern.IsMatch($f.Name) -or $Script:FilenameIOCs.Contains($f.Name)) {
                                        Log-IOC "PUA in redirected folder  -  User: $($uf.Name)  -  File: $($f.Name)"
                                        Log-IOC "  Path: $($f.FullName)"
                                        try {
                                            Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop
                                            Log-Success "Removed PUA from redirected folder: $($f.FullName)"
                                        } catch { Log-Fail "Could not remove: $($f.FullName)" }
                                        $Script:Counters.IOCsFound++
                                    }
                                }
                            }
                        }
                    }
                } else { Log-Summary "Redirected folder scan  -  no non-C: drives with Users folders found" }
            }
        }

        # Large file finder (VHD/VHDX excluded)
        if ($Script:Config.LargeFileThresholdGB -gt 0) {
            Invoke-SafeBlock -Label 'Large file finder' -Block {
                $threshBytes   = [long]($Script:Config.LargeFileThresholdGB * 1GB)
                $ostThreshBytes= [long]($Script:Config.LargeOSTThresholdGB * 1GB)
                $vhdExts       = (New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase))
                @('.vhd','.vhdx','.vmrs','.vmdk','.vdi','.ova','.ovf') | ForEach-Object { $null = $vhdExts.Add($_) }

                $largeFiles = (New-Object 'System.Collections.Generic.List[object]')
                foreach ($scanPath in $Script:Config.LargeFileScanPaths) {
                    if (-not (Test-Path $scanPath)) { continue }
                    # C:\Users was already walked once above — reuse those results instead of re-scanning.
                    if ($scanPath -eq 'C:\Users' -and $Script:ProfileScan) {
                        foreach ($f in $Script:ProfileScan.Large) { $largeFiles.Add($f) }
                        continue
                    }
                    $found = @(Get-ChildItem -LiteralPath $scanPath -Recurse -Force -File -ErrorAction SilentlyContinue |
                               Where-Object { $_.Length -gt $threshBytes -and -not $vhdExts.Contains($_.Extension.ToLower()) })
                    foreach ($f in $found) { $largeFiles.Add($f) }
                }
                if ($largeFiles.Count -gt 0) {
                    Log-Warn "Large files (>$($Script:Config.LargeFileThresholdGB) GB) found  -  $($largeFiles.Count) file(s):"
                    $lfTotalGB = [math]::Round((($largeFiles | Measure-Object -Property Length -Sum).Sum) / 1GB, 1)
                    Add-Finding -Severity Low -Title "$($largeFiles.Count) file(s) over $($Script:Config.LargeFileThresholdGB) GB ($lfTotalGB GB total)" -Action 'Review list in log; archive oversized OSTs, delete leftover installers/images'
                    if ($largeFiles.Count -gt 50) { Log-Warn "  (showing largest 50 of $($largeFiles.Count))" }
                    foreach ($f in $largeFiles | Sort-Object Length -Descending | Select-Object -First 50) {
                        $sizeGB = [math]::Round($f.Length / 1GB, 2)
                        $isOST  = $f.Extension -eq '.ost' -and $f.Length -gt $ostThreshBytes
                        $isPST  = $f.Extension -eq '.pst' -and $f.FullName -match 'OneDrive|SharePoint|Dropbox'
                        if ($isOST) { Log-Warn "  $sizeGB GB  -  $($f.FullName)  [LARGE OST - consider archiving]" }
                        elseif ($isPST) { Log-Warn "  $sizeGB GB  -  $($f.FullName)  [PST ON CLOUD - unsupported by Microsoft]" }
                        else { Log-Warn "  $sizeGB GB  -  $($f.FullName)" }
                    }
                } else { Log-Summary "Large file finder  -  no files over $($Script:Config.LargeFileThresholdGB) GB found" }
            }
        }

        # Temp file age report
        Invoke-SafeBlock -Label 'Temp age report' -Block {
            $wuTemp  = 'C:\Windows\Temp'
            if (Test-Path $wuTemp) {
                $oldest = @(Get-ChildItem -LiteralPath $wuTemp -Recurse -Force -File -ErrorAction SilentlyContinue |
                            Sort-Object LastWriteTime | Select-Object -First 1)
                if ($oldest -and $oldest.Count -gt 0) {
                    $daysOld = ([datetime]::Now - $oldest[0].LastWriteTime).Days
                    if ($daysOld -gt 30) { Log-Warn "Temp folder neglected  -  oldest file $daysOld days old: Windows Temp" }
                }
            }
        }

        $freedGB = [math]::Round($Script:SpaceFreed / 1GB, 2)
        Log-Summary "Filesystem Engine complete  -  $freedGB GB freed"
    }
} else {
    Log-Info "Filesystem Engine  -  disabled"
}


# ==============================================================================
# PHASE 7: DETECTION ENGINE
# IOC detection, hash-IOC scan, ransomware canary, hosts file, DNS cache, network, remote access
# ==============================================================================
Write-PhaseProgress -PhaseNum 7 -PhaseName 'Detection Engine'
Log-Info '--- Phase 7: Detection Engine ---'

if ($Script:Config.DetectionEngine_Enabled) {

    # Trojan/Malware folder IOC detection
    $trojanFolderNames = (New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase))
    @(
        'njrat','asyncrat','redlinestealer','vidar','lokibot','qakbot',
        'remcos','nanocore','darkcomet','adwind','jrat','limerat',
        'quasar','agent tesla','raccoon','azorult','formbook','dcrat','darkgate'
    ) | ForEach-Object { $null = $trojanFolderNames.Add($_) }
    foreach ($f in $Script:FallbackFolderIOCs) { $null = $trojanFolderNames.Add($f) }

    $userDirs = @(Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue |
                  Where-Object { $_.Name -notmatch '^(Public|Default|All Users)$' })

    $iocScanPaths = (New-Object 'System.Collections.Generic.List[string]')
    @('C:\Users\Public','C:\Windows\Temp','C:\ProgramData') | ForEach-Object { $iocScanPaths.Add($_) }
    foreach ($ud in $userDirs) {
        $iocScanPaths.Add((Join-Path $ud.FullName 'AppData\Local\Temp'))
        $iocScanPaths.Add((Join-Path $ud.FullName 'AppData\Roaming'))
        $iocScanPaths.Add((Join-Path $ud.FullName 'Downloads'))
    }

    $trojanHits = 0
    foreach ($scanPath in $iocScanPaths) {
        if (-not (Test-Path $scanPath)) { continue }
        $subDirs = @(Get-ChildItem -LiteralPath $scanPath -Directory -Force -ErrorAction SilentlyContinue)
        foreach ($sub in $subDirs) {
            if ($trojanFolderNames.Contains($sub.Name)) {
                Log-IOC "Trojan folder IOC: $($sub.FullName)"
                $Script:Counters.IOCsFound++
                $trojanHits++
            }
        }
        # Filename IOC scan
        $files = @(Get-ChildItem -LiteralPath $scanPath -Force -File -ErrorAction SilentlyContinue |
                   Where-Object { $Script:LegitDropFiles -notcontains $_.Name })
        foreach ($f in $files) {
            if ($Script:FilenameIOCs.Contains($f.Name)) {
                Log-IOC "Filename IOC: $($f.FullName)"
                $Script:Counters.IOCsFound++
                $trojanHits++
            }
        }
    }
    if ($trojanHits -eq 0) { Log-Summary "Detection Engine  -  no trojan/malware IOC folders found" }

    # RiskWare detection
    # Note: patterns are used as regex via -match. Use word boundaries (\b) to prevent
    # substring false positives (e.g. 'miner' matching 'remineralization' in PDF filenames).
    $riskwareNames = (New-Object 'System.Collections.Generic.List[string]')
    @('gamecrack','coinminer','\bminer','xmrig','minerd') | ForEach-Object { $riskwareNames.Add($_) }

    $rwHits = 0
    foreach ($scanPath in $iocScanPaths) {
        if (-not (Test-Path $scanPath)) { continue }
        $files = @(Get-ChildItem -LiteralPath $scanPath -Force -File -ErrorAction SilentlyContinue)
        foreach ($f in $files) {
            if ($riskwareNames | Where-Object { $f.Name -match $_ }) {
                Log-IOC "RiskWare file: $($f.FullName)"
                $Script:Counters.IOCsFound++
                $rwHits++
            }
        }
    }
    if ($rwHits -eq 0) { Log-Summary "Detection Engine  -  no riskware detected" }

    # Hash IOC scan - SHA256 files in IOC scan paths against the local intel hash list
    if ($Script:Config.HashScanEnabled) {
        Invoke-SafeBlock -Label 'Hash IOC scan' -Block {
            $mbHits = 0
            $hashFiles = (New-Object 'System.Collections.Generic.List[object]')
            foreach ($scanPath in $iocScanPaths) {
                if (-not (Test-Path $scanPath)) { continue }
                $exeFiles = @(Get-ChildItem -LiteralPath $scanPath -Force -File -ErrorAction SilentlyContinue |
                              Where-Object { $_.Extension -match '\.(exe|dll|ps1|vbs|js|bat|cmd)$' } |
                              Select-Object -First 50)
                foreach ($f in $exeFiles) { $hashFiles.Add($f) }
            }

            foreach ($f in $hashFiles | Select-Object -First 100) {
                try {
                    $hash = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower()
                    if ($Script:HashIOCs.Contains($hash)) {
                        Log-IOC "Hash IOC match: $($f.Name)  -  SHA256: $hash"
                        $Script:Counters.IOCsFound++
                        $mbHits++
                    }
                } catch { }
            }
            if ($mbHits -eq 0) { Log-Summary "Detection Engine  -  Hash IOC scan: $($hashFiles.Count) files checked, 0 hits" }
        }
    }

    # Hosts file inspection
    Invoke-SafeBlock -Label 'Hosts file' -Block {
        $hostsPath = 'C:\Windows\System32\drivers\etc\hosts'
        $hostsLines = @(Get-Content -LiteralPath $hostsPath -ErrorAction Stop |
                        Where-Object { $_ -and -not $_.TrimStart().StartsWith('#') })
        $hostsHits = 0
        foreach ($line in $hostsLines) {
            $isWhitelisted = $Script:HostsWhitelist | Where-Object { $line -match $_ }
            if (-not $isWhitelisted -and $line -match '\S') {
                if ($Script:C2IOCs | Where-Object { $line -match [regex]::Escape($_) }) {
                    Log-IOC "Hosts file C2 entry: $line"
                    $Script:Counters.IOCsFound++
                    $hostsHits++
                } elseif ($line -notmatch '^127\.0\.0\.1\s+localhost' -and $line -notmatch '^::1') {
                    Log-Warn "Hosts file custom entry: $line"
                }
            }
        }
        if ($hostsHits -eq 0) { Log-Summary "Detection Engine  -  hosts file clean" }
    }

    # Ransomware canary check
    Invoke-SafeBlock -Label 'Ransomware canary' -Block {
        $encPattern = New-Object System.Text.RegularExpressions.Regex -ArgumentList @(
            '\.(locked|encrypted|crypted|crypt|enc|ryk|wncry|wannacry|cerber|locky|zepto|thor|aaa|abc|xyz|zzz)$',
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

        $canaryPaths = @('C:\Users\Public','C:\Windows\Temp')
        $canaryHits  = 0
        foreach ($cp in $canaryPaths) {
            if (-not (Test-Path $cp)) { continue }
            $encFiles = @(Get-ChildItem -LiteralPath $cp -Recurse -Force -File -ErrorAction SilentlyContinue |
                          Where-Object { $encPattern.IsMatch($_.Name) })
            foreach ($f in $encFiles) {
                $isCanaryWhitelisted = $Script:CanaryWhitelist | Where-Object { $f.FullName -like $_ }
                if (-not $isCanaryWhitelisted) {
                    Log-IOC "Ransomware canary: encrypted file pattern found: $($f.FullName)"
                    $Script:Counters.IOCsFound++
                    $canaryHits++
                }
            }
        }
        if ($canaryHits -eq 0) { Log-Summary "Detection Engine  -  no ransomware canary patterns found" }
    }

    # Network connection audit + listening ports inventory
    Invoke-SafeBlock -Label 'Network audit' -Block {
        $suspectOwners = (New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase))
        @('powershell','cmd','wscript','cscript','mshta','regsvr32','rundll32','nc','ncat','netcat') |
            ForEach-Object { $null = $suspectOwners.Add($_) }

        $ratPorts = (New-Object 'System.Collections.Generic.HashSet[int]')
        @(4444,4445,1234,31337,8888,9999,6666,1337,50050,60000,65535) |
            ForEach-Object { $null = $ratPorts.Add($_) }

        $listeners    = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Sort-Object LocalPort)
        $suspectFound = 0
        Log-Info "Network audit  -  $($listeners.Count) listening TCP ports:"

        foreach ($l in $listeners) {
            $proc      = Get-Process -Id $l.OwningProcess -ErrorAction SilentlyContinue
            $procName  = if ($proc) { $proc.Name } else { "PID $($l.OwningProcess)" }
            $isRATPort = $ratPorts.Contains($l.LocalPort)
            $isSuspect = $suspectOwners.Contains($procName)
            $portStr   = "$($l.LocalAddress):$($l.LocalPort)"

            if ($isRATPort -or $isSuspect) {
                $reason = if ($isRATPort) { 'known RAT/C2 port' } else { 'suspicious process owner' }
                Log-IOC "Suspicious listener: $portStr  -  $procName  -  $reason"
                $Script:Counters.IOCsFound++
                $suspectFound++
            } else {
                Log-Info "  [TCP] $portStr  -  $procName"
            }
        }
        if ($suspectFound -eq 0) { Log-Summary "Detection Engine  -  no suspicious listeners found ($($listeners.Count) ports checked)" }

        # C2 domain check via DNS client cache.
        # The C2 intel feed contains DOMAINS; comparing them to remote IPs from
        # Get-NetTCPConnection could never match (review finding 1d). The DNS
        # cache shows what this machine recently RESOLVED - an honest signal
        # that something on the box reached out to a C2 domain.
        $c2Hits = 0
        $dnsEntries = @(Get-DnsClientCache -ErrorAction SilentlyContinue)
        foreach ($entry in $dnsEntries) {
            $dnsName = $entry.Entry
            if ($dnsName -and $Script:C2IOCs.Contains($dnsName.TrimEnd('.'))) {
                Log-IOC "C2 domain in DNS cache: $dnsName  -  resolved to: $($entry.Data)"
                $Script:Counters.IOCsFound++
                $c2Hits++
            }
        }
        if ($c2Hits -eq 0) { Log-Summary "Detection Engine  -  no C2 domains in DNS cache ($($dnsEntries.Count) entries checked)" }
    }

    # Remote access tool inventory with RISKWARE-RAT classification
    if ($Script:Config.RemoteAccessInventory) {
        Invoke-SafeBlock -Label 'Remote access inventory' -Block {
            $remoteTools = @(
                @{ Name='ScreenConnect';        Services=@('ScreenConnect*');             Procs=@('ScreenConnect*');       ARP='ScreenConnect';              Tier='LEGIT' }
                @{ Name='TeamViewer';           Services=@('TeamViewer*');                Procs=@('TeamViewer*');          ARP='TeamViewer';                 Tier='LEGIT' }
                @{ Name='AnyDesk';              Services=@('AnyDesk');                    Procs=@('AnyDesk');              ARP='AnyDesk';                    Tier='LEGIT' }
                @{ Name='Splashtop';            Services=@('SplashtopRemote*','SRD*');    Procs=@('Splashtop*');          ARP='Splashtop';                  Tier='LEGIT' }
                @{ Name='LogMeIn';              Services=@('LogMeIn*','LMIGuardian');     Procs=@('LogMeIn*');            ARP='LogMeIn';                    Tier='LEGIT' }
                @{ Name='BeyondTrust';          Services=@('BomgarBroker*');              Procs=@('BomgarBroker*');        ARP='BeyondTrust|Bomgar';         Tier='LEGIT' }
                @{ Name='Kaseya VSA';           Services=@('AgentMon','KaseyaAgent');     Procs=@('AgentMon');            ARP='Kaseya';                     Tier='LEGIT' }
                @{ Name='NinjaRMM';             Services=@('NinjaRMMAgent');              Procs=@('NinjaRMM*');            ARP='NinjaRMM|NinjaOne';          Tier='LEGIT' }
                @{ Name='ConnectWise Automate'; Services=@('LTService','LTSvcMon');       Procs=@('ltsvc*');              ARP='LabTech|ConnectWise Automate'; Tier='LEGIT' }
                @{ Name='Atera';                Services=@('AteraAgent');                 Procs=@('AteraAgent');           ARP='Atera';                      Tier='LEGIT' }
                @{ Name='Pulseway';             Services=@('PCMonitorSrv');               Procs=@('PCMonitor*');           ARP='Pulseway';                   Tier='LEGIT' }
                @{ Name='Zoho Assist';          Services=@('ZohoMeeting*');               Procs=@('ZohoMeeting*');         ARP='Zoho Assist';                Tier='LEGIT' }
                @{ Name='N-able';               Services=@('NableAgent','RpcAgentSvc');   Procs=@('NableAgent');          ARP='N-able|N-central';           Tier='LEGIT' }
                @{ Name='MeshAgent';            Services=@('Mesh Agent','MeshAgent');     Procs=@('MeshAgent');           ARP='MeshAgent|MeshCentral';      Tier='RAT'   }
                @{ Name='Rustdesk';             Services=@('Rustdesk');                   Procs=@('rustdesk');             ARP='Rustdesk';                   Tier='RAT'   }
                @{ Name='Action1';              Services=@('Action1*');                   Procs=@('Action1*');             ARP='Action1';                    Tier='RAT'   }
                @{ Name='SimpleHelp';           Services=@('SimpleHelp*');                Procs=@('SimpleHelp*');          ARP='SimpleHelp';                 Tier='RAT'   }
                @{ Name='Ammyy Admin';          Services=@('Remote Utilities*');          Procs=@('AA_v3*','rutserv');    ARP='Ammyy';                      Tier='RAT'   }
                @{ Name='NetSupport';           Services=@('NetSupport*');                Procs=@('client32','pcicl32');  ARP='NetSupport';                 Tier='RAT'   }
                @{ Name='UltraVNC';             Services=@('uvnc_service');               Procs=@('winvnc*');              ARP='UltraVNC|TightVNC|RealVNC';  Tier='RAT'   }
            )

            $foundTools = (New-Object 'System.Collections.Generic.List[string]')

            foreach ($tool in $remoteTools) {
                $found = $false; $inARP = $false
                $svcStatus = 'Not found'; $procStatus = 'Not running'
                $version = ''; $instanceIDs = (New-Object 'System.Collections.Generic.List[string]')

                # Use cached services - no re-query
                $svcs = @($Script:Cache_Services | Where-Object {
                    $svc = $_
                    $tool.Services | Where-Object { $svc.Name -like $_ -or $svc.DisplayName -like $_ }
                })
                if ($svcs.Count -gt 0) {
                    $found     = $true
                    $svcStatus = ($svcs | ForEach-Object { "$($_.DisplayName) [$($_.Status)]" }) -join ', '
                    if ($tool.Name -eq 'ScreenConnect') {
                        foreach ($svc in $svcs) {
                            if ($svc.DisplayName -match '\(([a-f0-9\-]{8,})\)') { $instanceIDs.Add($Matches[1]) }
                        }
                    }
                }

                # Use cached processes
                $procs = @($Script:Cache_Processes | Where-Object {
                    $proc = $_
                    $tool.Procs | Where-Object { $proc.Name -like $_ }
                })
                if ($procs.Count -gt 0) { $found = $true; $procStatus = "Running (PID: $(($procs.Id) -join ','))" }

                # Use cached ARP
                $arpMatch = @($Script:Cache_ARP | Where-Object { $_.DisplayName -match $tool.ARP })
                if ($arpMatch.Count -gt 0) { $inARP = $true; $version = $arpMatch[0].DisplayVersion }

                if (-not $found) { continue }
                $foundTools.Add($tool.Name)
                $idStr = if ($instanceIDs.Count -gt 0) { "  Instance: $($instanceIDs -join ', ')" } else { '' }

                if ($tool.Tier -eq 'RAT') {
                    # Check for RMM-bundled VNC (legitimate)
                    $isRMMBundled = $false
                    foreach ($svc in $svcs) {
                        try {
                            $svcWmi = Get-CimInstance Win32_Service -Filter "Name='$($svc.Name)'" -ErrorAction SilentlyContinue
                            if ($svcWmi -and ($Script:LegitVNCPaths | Where-Object { $svcWmi.PathName -match [regex]::Escape($_) })) {
                                $isRMMBundled = $true; break
                            }
                        } catch { }
                    }
                    if ($isRMMBundled) {
                        Log-Summary "[REMOTE ACCESS]  $($tool.Name)  -  RMM-bundled component (legitimate)"
                    } else {
                        Log-RiskwareRAT "[RISKWARE-RAT]  $($tool.Name) detected  -  IMMEDIATE REVIEW REQUIRED"
                        Log-RiskwareRAT "  Service: $svcStatus  |  Process: $procStatus  |  In ARP: $(if ($inARP) { 'Yes' } else { 'No' })"
                        Log-RiskwareRAT "  Actively exploited in ransomware attack chains  -  verify with client immediately"
                        $Script:Counters.IOCsFound++
                    }
                } else {
                    if (-not $inARP -and $Script:Config.RemoteAccessWarnUnknown) {
                        Log-Warn "[REMOTE ACCESS]  $($tool.Name)  -  NOT in Add/Remove Programs$idStr"
                        Log-Warn "  Service: $svcStatus  |  Process: $procStatus"
                    } else {
                        Log-Summary "[REMOTE ACCESS]  $($tool.Name)$idStr  -  In ARP: $(if ($inARP) { 'Yes' } else { 'No' })  |  Ver: $version"
                        Log-Info "  Service: $svcStatus"
                    }
                }
            }

            if ($foundTools.Count -eq 0) {
                Log-Summary "Detection Engine  -  no remote access tools detected"
            } else {
                Log-Summary "Detection Engine  -  $($foundTools.Count) remote access tool(s) found: $($foundTools -join ', ')"
            }
        }
    }

    # ScreenConnect Phase 15b - AppData scan for rogue instances
    Invoke-SafeBlock -Label 'ScreenConnect AppData scan' -Block {
        foreach ($userDir in $userDirs) {
            $scAppDataPath = Join-Path $userDir.FullName 'AppData\Local\Apps\2.0'
            if (-not (Test-Path $scAppDataPath)) { continue }
            $scExes = @(Get-ChildItem -LiteralPath $scAppDataPath -Recurse -Filter 'ScreenConnect.ClientService.exe' -Force -ErrorAction SilentlyContinue)
            foreach ($scExe in $scExes) {
                # Check if this specific instance is in ARP
                $scFolder  = Split-Path $scExe.FullName -Parent
                $inARP     = $false
                $arpEntries= @($Script:Cache_ARP | Where-Object { $_.DisplayName -match 'screenconnect' })
                foreach ($arp in $arpEntries) {
                    if ($arp.InstallLocation -and $scFolder -like "*$($arp.InstallLocation)*") { $inARP = $true; break }
                }
                if ($inARP) { Log-Info "ScreenConnect AppData instance in ARP  -  leaving alone"; continue }

                Log-IOC "Rogue ScreenConnect AppData instance: $($scExe.FullName)"
                if ($Script:Config.SCRemoveRogue) {
                    try {
                        Remove-Item -LiteralPath $scFolder -Recurse -Force -ErrorAction Stop
                        Log-Success "Removed rogue ScreenConnect folder: $scFolder"
                        $Script:RogueScreenConnectRemoved = $true
                    } catch { Log-Fail "Could not remove SC folder: $scFolder" }
                }
                $Script:Counters.IOCsFound++
            }
        }
    }

    Log-Summary "Detection Engine complete  -  $($Script:Counters.IOCsFound) IOC(s) found"

    # Trigger Defender Quick Scan if IOCs found
    if ($Script:Counters.IOCsFound -gt 0) {
        Invoke-SafeBlock -Label 'Defender Quick Scan' -Block {
            $mp = Get-MpComputerStatus -ErrorAction Stop
            if ($mp.AMServiceEnabled -and $mp.RealTimeProtectionEnabled) {
                Start-MpScan -ScanType QuickScan -AsJob -ErrorAction Stop | Out-Null
                Log-Info "Defender Quick Scan initiated in background (IOCs detected)"
            }
        }
    }

} else {
    Log-Info "Detection Engine  -  disabled"
}


# ==============================================================================
# PHASE 8: REPORTING ENGINE
# Windows Update, trend tracking, event log IOCs, reboot, software, compliance
# ==============================================================================
Write-PhaseProgress -PhaseNum 8 -PhaseName 'Reporting Engine'
Log-Info '--- Phase 8: Reporting Engine ---'

if ($Script:Config.ReportingEngine_Enabled) {

    # Reboot check
    Invoke-SafeBlock -Label 'Reboot check' -Block {
        $rebootKeys = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired',
            'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations'
        )
        $rebootNeeded = $false
        foreach ($key in $rebootKeys) {
            if (Test-Path $key) {
                Log-Warn "Reboot pending indicator found: $key"
                $rebootNeeded = $true
                $Script:Counters.RebootRequired = $true
            }
        }
        if (-not $rebootNeeded) { Log-Summary "Reboot check  -  no reboot required" }
    }

    # Windows Update pending with names
    Invoke-SafeBlock -Label 'Windows Update' -Block {
        $wu      = New-Object -ComObject Microsoft.Update.Session -ErrorAction Stop
        $search  = $wu.CreateUpdateSearcher()
        $results = $search.Search("IsInstalled=0 and Type='Software'")
        $pending = $results.Updates.Count
        if ($pending -gt 0) {
            $critCount = @($results.Updates | Where-Object { $_.MsrcSeverity -eq 'Critical' }).Count
            Log-Warn "Windows Update: $pending update(s) pending ($critCount critical)"
            $wuSev = if ($critCount -gt 0) { 'Medium' } else { 'Low' }
            Add-Finding -Severity $wuSev -Title "Windows Update: $pending pending ($critCount critical)" -Action 'Approve/deploy via Datto RMM update policy'
            foreach ($update in $results.Updates) {
                $sev = if ($update.MsrcSeverity) { "[$($update.MsrcSeverity)]" } else { '[None]' }
                Log-Info "  $sev $($update.Title)"
            }
        } else { Log-Summary "Windows Update  -  no pending updates" }
    }

    # Recently installed software
    Invoke-SafeBlock -Label 'Recent software' -Block {
        $cutoff30 = (Get-Date).AddDays(-30)
        $torrentPUA = (New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase))
        @('utorrent','bittorrent','vuze','limewire','frostwire','ares','bearshare','kazaa') |
            ForEach-Object { $null = $torrentPUA.Add($_) }

        $recentSoftware = @($Script:Cache_ARP |
                            Where-Object { $_.DisplayName -and $_.InstallDate } |
                            Where-Object {
                                try { [datetime]::ParseExact($_.InstallDate,'yyyyMMdd',$null) -gt $cutoff30 } catch { $false }
                            } |
                            Sort-Object InstallDate -Descending)

        if ($recentSoftware.Count -gt 0) {
            Log-Summary "Recently installed software (last 30 days)  -  $($recentSoftware.Count) items:"
            foreach ($sw in $recentSoftware) {
                $isTorrent = $torrentPUA | Where-Object { $sw.DisplayName -match $_ }
                if ($isTorrent) { Log-Warn "  [PUA] $($sw.InstallDate)  $($sw.DisplayName)  $($sw.DisplayVersion)" }
                else            { Log-Info  "  $($sw.InstallDate)  $($sw.DisplayName)  $($sw.DisplayVersion)  $($sw.Publisher)" }
            }
        } else { Log-Summary "Recent software  -  no software installed in last 30 days" }
    }

    # Event log IOC check (Event 7045 - Service installs)
    Invoke-SafeBlock -Label 'Event log IOC' -Block {
        $sevenDaysAgo = (Get-Date).AddDays(-7)
        $svcEvents    = @(Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 7045
            StartTime = $sevenDaysAgo
        } -ErrorAction Stop | Select-Object -First 200)

        $knownGoodSvcs = (New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase))
        @(
            'CagService','HUNTAgent','EndpointProtectionService2','WinDefend','MpsSvc','wuauserv',
            # HP printer driver services (installed with any HP printer software)
            'Pml Driver HPZ12','Net Driver HPZ12',
            # Datto EDR / Infocyte agent (may reinstall on update cycles)
            'Datto EDR Agent',
            # Intel driver update service
            'IntelTACD',
            # Trusteer Rapport banking security (high-frequency reinstall by design)
            'RapportIaso',
            # Datto RMM agent service (reinstalls on agent updates) - field FP 2026-06-24
            'CentraStage',
            # Sophos HitmanPro support driver - field FP 2026-06-24
            'HitmanPro 3.7 Support Driver'
        ) | ForEach-Object { $null = $knownGoodSvcs.Add($_) }
        # Per-deployment additions from config
        foreach ($extra in @($Script:Config.Svc7045_ExtraNames)) {
            if ($extra) { $null = $knownGoodSvcs.Add($extra) }
        }

        # Path-based whitelist for known-good vendor paths (catches name variations)
        $knownGoodSvcPaths = @(
            'infocyte',                  # Datto EDR / Infocyte agent path
            'centrastage',               # Datto RMM install tree incl. bundled UltraVNC (uvnc_service) - field FP 2026-06-24
            'hitmanpro',                 # Sophos HitmanPro driver - field FP 2026-06-24
            'silver bullet technology',  # SBT check-scanning suite (SBTKernel, Ranger) - field FP 2026-06-02 RAS1
            'paniniusb',                 # Panini check scanner USB driver - field FP 2026-06-02 RAS1
            'googleupdater'              # Chrome updater re-registers services on every Chrome update - field FP 2026-07-03 PCH-DT
        ) + @($Script:Config.Svc7045_ExtraPaths | Where-Object { $_ })

        $svcGroups = @{}
        foreach ($evt in $svcEvents) {
            $svcName = $evt.Properties[0].Value
            $svcPath = $evt.Properties[1].Value
            $svcAcct = $evt.Properties[4].Value
            if ($knownGoodSvcs.Contains($svcName)) { continue }
            # Path-based whitelist - skip events from known-good vendor install paths
            $isKnownGoodPath = $knownGoodSvcPaths | Where-Object { $svcPath -match $_ }
            if ($isKnownGoodPath) { continue }
            $key = "$svcName|$svcPath"
            if ($svcGroups.ContainsKey($key)) {
                $svcGroups[$key]['Count']++
            } else {
                $svcGroups[$key] = @{ SvcName=$svcName; SvcPath=$svcPath; SvcAcct=$svcAcct; Count=1; FirstSeen=$evt.TimeCreated }
            }
        }

        foreach ($key in $svcGroups.Keys) {
            $g = $svcGroups[$key]
            $countStr = if ($g['Count'] -gt 1) { " ($($g['Count'])x)" } else { '' }

            # ScreenConnect targeted removal via Event 7045 exact path
            if ($g['SvcPath'] -match 'screenconnect' -and -not $Script:RogueScreenConnectRemoved) {
                $eventInstanceID = $null
                if ($g['SvcName'] -match '\(([a-f0-9\-]{8,})\)') { $eventInstanceID = $Matches[1] }
                $isManagedSC = $eventInstanceID -and $Script:Config.SCInstanceID -and
                               ($eventInstanceID -eq $Script:Config.SCInstanceID)
                if (-not $isManagedSC) {
                    Log-IOC "Event 7045 ScreenConnect  -  non-managed instance: $eventInstanceID"
                    Log-IOC "  Service: $($g['SvcName'])  |  Path: $($g['SvcPath'])"
                    if ($Script:Config.SCRemoveRogue) {
                        try {
                            Stop-Service -Name $g['SvcName'] -Force -ErrorAction SilentlyContinue
                            & sc.exe delete $g['SvcName'] 2>$null | Out-Null
                            $exePath   = ($g['SvcPath'] -split '"')[1]
                            if (-not $exePath) { $exePath = $g['SvcPath'].Trim('"').Split(' ')[0] }
                            $exeFolder = Split-Path $exePath -Parent
                            # Safety guard: only delete a folder that (a) is at least 3 path
                            # segments deep and (b) has 'screenconnect' in its leaf name.
                            # Prevents a malformed event path from parsing to C:\ or C:\Windows.
                            $segCount = @($exeFolder -split '\\' | Where-Object { $_ }).Count
                            $leafOk   = (Split-Path $exeFolder -Leaf) -match 'screenconnect'
                            if ($exeFolder -and $segCount -ge 3 -and $leafOk -and (Test-Path -LiteralPath $exeFolder)) {
                                Remove-Item -LiteralPath $exeFolder -Recurse -Force -ErrorAction Stop
                                Log-Success "Removed rogue SC via Event 7045: $exeFolder"
                                $Script:RogueScreenConnectRemoved = $true
                            } elseif ($exeFolder) {
                                Log-Warn "SC removal skipped  -  path failed safety guard: $exeFolder"
                            }
                        } catch { Log-Fail "SC removal failed: $($_.Exception.Message)" }
                    }
                    $Script:Counters.IOCsFound++
                }
                continue
            }

            if ($Script:RogueScreenConnectRemoved -and $g['SvcPath'] -match 'screenconnect') {
                Log-Info "Event 7045 SC  -  suppressed (removed in Detection Engine)"
                continue
            }

            Log-IOC "Event 7045 (Service Install) suspicious$countStr  -  First: $($g['FirstSeen'].ToString('yyyy-MM-dd HH:mm:ss')) | Svc: $($g['SvcName']) | Path: $($g['SvcPath'])"
            $Script:Counters.IOCsFound++
        }
        if ($svcGroups.Count -eq 0) { Log-Summary "Event log  -  no suspicious service installs in last 7 days" }
    }

    # USB/Removable media audit
    Invoke-SafeBlock -Label 'USB audit' -Block {
        $removable = @(Get-CimInstance Win32_DiskDrive -ErrorAction Stop |
                       Where-Object { $_.MediaType -match 'Removable|External' -or $_.InterfaceType -eq 'USB' })
        if ($removable.Count -gt 0) {
            Log-Warn "USB/Removable media detected  -  $($removable.Count) device(s):"
            foreach ($r in $removable) { Log-Warn "  $($r.Model)  -  $([math]::Round($r.Size/1GB,1)) GB" }
        } else { Log-Summary "USB audit  -  no removable media detected" }
    }

    # Defender threat history - active vs historical
    Invoke-SafeBlock -Label 'Defender threat history' -Block {
        $defThreats = @(Get-MpThreatDetection -ErrorAction Stop |
                        Where-Object { $_.InitialDetectionTime -gt (Get-Date).AddDays(-30) })
        if ($defThreats.Count -gt 0) {
            $archivePatterns = @('~Old Users','archive','backup','quarantine','AdwCleaner')
            $activeThreats   = (New-Object 'System.Collections.Generic.List[object]')
            $historicalThreats = (New-Object 'System.Collections.Generic.List[object]')

            foreach ($t in $defThreats) {
                $threat = Get-MpThreat -ThreatID $t.ThreatID -ErrorAction SilentlyContinue
                $name   = if ($threat) { $threat.ThreatName } else { "ThreatID $($t.ThreatID)" }
                $res    = ($t.Resources -join ', ')
                $isHistorical = $archivePatterns | Where-Object { $res -match [regex]::Escape($_) }
                $entry  = @{ Date=$t.InitialDetectionTime; Name=$name; Resources=$res }
                if ($isHistorical) { $historicalThreats.Add($entry) } else { $activeThreats.Add($entry) }
            }

            if ($activeThreats.Count -gt 0) {
                Log-Warn "Defender threat history  -  $($activeThreats.Count) active detection(s) in last 30 days:"
                foreach ($t in $activeThreats | Sort-Object { $_.Date } -Descending | Select-Object -First 10) {
                    Log-Warn "  $($t.Date.ToString('yyyy-MM-dd'))  $($t.Name)  -  $($t.Resources)"
                    # Active malware detections belong at the top of the findings table
                    # (field gap 2026-07-03: an active trojan was WARN-only while benign
                    # 7045 events ranked High)
                    Add-Finding -Severity High -Title "Defender active detection ($($t.Date.ToString('yyyy-MM-dd'))): $($t.Name) - $($t.Resources)" -Action 'Verify Defender remediated it; investigate how it arrived (user download? email?); consider full scan'
                }
            }
            if ($historicalThreats.Count -gt 0) {
                Log-Info "Defender threat history  -  $($historicalThreats.Count) historical detection(s) in archive paths:"
                foreach ($t in $historicalThreats | Sort-Object { $_.Date } -Descending | Select-Object -First 10) {
                    Log-Info "  $($t.Date.ToString('yyyy-MM-dd'))  $($t.Name)  -  $($t.Resources)"
                }
            }
        } else { Log-Summary "Defender threat history  -  no detections in last 30 days" }
    }

    # Memory pressure report
    Invoke-SafeBlock -Label 'Memory report' -Block {
        $osMemory = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $totalMB  = [math]::Round($osMemory.TotalVisibleMemorySize / 1024)
        $freeMB   = [math]::Round($osMemory.FreePhysicalMemory / 1024)
        $usedMB   = $totalMB - $freeMB
        $usedPct  = [math]::Round(($usedMB / $totalMB) * 100)
        if ($usedPct -gt 85) { Log-Warn "Memory pressure: $usedPct% used ($usedMB MB of $totalMB MB)  -  consider upgrade" }
        else { Log-Summary "Memory: $usedPct% used ($usedMB MB of $totalMB MB)  -  OK" }

        # Top CPU consumers (from cache)
        $topProcs = @($Script:Cache_Processes | Where-Object { $_.CPU -gt 0 } |
                      Sort-Object CPU -Descending | Select-Object -First 5 Name, Id, CPU)
        if ($topProcs.Count -gt 0) {
            Log-Info "Top CPU consumers at scan time:"
            foreach ($p in $topProcs) { Log-Info "  $($p.Name) (PID $($p.Id))  -  $([math]::Round($p.CPU,1)) CPU seconds" }
        }
    }

    # Disk health
    Invoke-SafeBlock -Label 'Disk health' -Block {
        $diskStatus = @(Get-CimInstance -Namespace root\wmi -ClassName MSStorageDriver_FailurePredictStatus -ErrorAction Stop)
        $failPredicted = $false
        foreach ($disk in $diskStatus) {
            if ($disk.PredictFailure) {
                Log-Warn "DISK FAILURE PREDICTED  -  immediate backup and replacement recommended"
                $failPredicted = $true
                $Script:Counters.IOCsFound++
            }
        }
        if (-not $failPredicted) { Log-Summary "Disk health  -  no failure predicted (OK)" }
    }

    # PowerShell script block audit (4104 events)
    Invoke-SafeBlock -Label 'PS script block audit' -Block {
        $sbPath    = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
        $sbEnabled = (Get-ItemProperty $sbPath -Name 'EnableScriptBlockLogging' -ErrorAction SilentlyContinue).EnableScriptBlockLogging
        if ($sbEnabled -ne 1) {
            if (-not (Test-Path $sbPath)) { New-Item -Path $sbPath -Force | Out-Null }
            Set-ItemProperty -Path $sbPath -Name 'EnableScriptBlockLogging' -Value 1 -Type DWord -Force
            Log-Harden "PowerShell script block logging (4104) enabled  -  audit available on next run"
        } else {
            $obfuscKeywords = @('EncodedCommand','FromBase64String','IEX','Invoke-Expression',
                                'DownloadString','WebClient','bypass','hidden','noprofile')
            $sbEvents = @(Get-WinEvent -FilterHashtable @{
                LogName   = 'Microsoft-Windows-PowerShell/Operational'
                Id        = 4104
                StartTime = (Get-Date).AddDays(-7)
            } -ErrorAction Stop | Select-Object -First 500)

            $obfuscated = @($sbEvents | Where-Object {
                $msg = $_.Message.ToLower()
                $obfuscKeywords | Where-Object { $msg -match $_.ToLower() }
            })
            if ($obfuscated.Count -gt 0) {
                Log-IOC "PowerShell obfuscation: $($obfuscated.Count) suspicious script block(s) in last 7 days"
                foreach ($e in $obfuscated | Select-Object -First 5) {
                    Log-IOC "  $($e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))  $($e.Message.Substring(0,[Math]::Min(120,$e.Message.Length)))"
                }
                $Script:Counters.IOCsFound += $obfuscated.Count
            } else { Log-Summary "PS script block audit  -  $($sbEvents.Count) events checked, no obfuscation found" }
        }
    }

    # Credential exposure check
    Invoke-SafeBlock -Label 'Credential exposure' -Block {
        $wdigest = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' `
                    -Name 'UseLogonCredential' -ErrorAction SilentlyContinue).UseLogonCredential
        if ($wdigest -eq 1) {
            Log-IOC "WDigest ENABLED: plaintext credentials stored in memory  -  attackers can dump passwords"
            $Script:Counters.IOCsFound++
        } else { Log-Summary "WDigest  -  plaintext credential caching disabled (OK)" }

        $lsaProtect = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
                       -Name 'RunAsPPL' -ErrorAction SilentlyContinue).RunAsPPL
        if ($lsaProtect -ne 1) { Log-Warn "LSA protection (RunAsPPL) not enabled  -  recommend enabling" }
        else { Log-Summary "LSA protection  -  enabled (OK)" }

        $credGuard = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' `
                      -Name 'EnableVirtualizationBasedSecurity' -ErrorAction SilentlyContinue).EnableVirtualizationBasedSecurity
        if ($credGuard -eq 1) { Log-Summary "Credential Guard  -  enabled (OK)" }
        else { Log-Info "Credential Guard  -  not enabled (consider enabling on modern hardware)" }
    }

    # Software version audit
    Invoke-SafeBlock -Label 'Software versions' -Block {
        $softwareVersions = @{
            'Google Chrome'  = '124.0'; 'Microsoft Edge' = '124.0'
            'Adobe Acrobat'  = '24.0';  'Adobe Reader'   = '24.0'
            '7-Zip'          = '23.0';  'VLC'            = '3.0.20'
            'Zoom'           = '6.0';   'Java'           = '21.0'
        }
        $outdated = (New-Object 'System.Collections.Generic.List[string]')
        foreach ($swName in $softwareVersions.Keys) {
            $match = @($Script:Cache_ARP | Where-Object { $_.DisplayName -match [regex]::Escape($swName) })
            if ($match.Count -gt 0 -and $match[0].DisplayVersion) {
                $ver    = $match[0].DisplayVersion.Split(' ')[0]
                $minVer = $softwareVersions[$swName]
                $vParsed = $null; $mParsed = $null
                if ([version]::TryParse($ver, [ref]$vParsed) -and [version]::TryParse($minVer, [ref]$mParsed)) {
                    if ($vParsed -lt $mParsed) {
                        Log-Warn "Outdated software: $swName v$ver  -  recommend updating"
                        $outdated.Add($swName)
                    }
                }
            }
        }
        if ($outdated.Count -eq 0) { Log-Summary "Software versions  -  all checked software is current" }
    }

    # License check
    Invoke-SafeBlock -Label 'License check' -Block {
        $winLicense = Get-CimInstance SoftwareLicensingProduct -ErrorAction Stop |
                      Where-Object { $_.Name -match 'Windows' -and $_.PartialProductKey }
        if ($winLicense) {
            $licStatus = switch ($winLicense.LicenseStatus) {
                1 { 'Licensed' }; 2 { 'OOBEGrace' }; 3 { 'OOTGrace' }
                4 { 'NonGenuineGrace' }; 5 { 'Notification' }; default { 'Unlicensed' }
            }
            if ($winLicense.LicenseStatus -ne 1) { Log-Warn "Windows activation: $licStatus  -  verify licensing" }
            else { Log-Summary "Windows activation  -  Licensed (OK)" }
        }
    }

    # CIS Benchmark Lite - Level 1
    Invoke-SafeBlock -Label 'CIS Benchmark' -Block {
        $cisIssues = 0
        Log-Info '--- CIS Benchmark Lite (Level 1) ---'

        # 1.1.1 Password minimum length
        if ($Script:MinPasswordLen -lt 8) {
            Log-Warn "  [CIS 1.1.1] Password minimum length is $Script:MinPasswordLen  -  recommend 8+ (Level 1)"
            Add-Finding -Severity High -Title "Password minimum length is $Script:MinPasswordLen (CIS 1.1.1)" -Action 'Set MinimumPasswordLength >= 8 via domain GPO (local secedit is overridden on domain members)'
            $cisIssues++
        } else { Log-Info "  [CIS 1.1.1] Password minimum length: $Script:MinPasswordLen (OK)" }

        # 2.2 Guest account
        $guest = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
        if ($guest -and $guest.Enabled) { Log-Warn "  [CIS 2.2] Guest account ENABLED  -  disable it"; $cisIssues++ }
        else { Log-Info "  [CIS 2.2] Guest account disabled (OK)" }

        # 2.3 LAN Manager auth
        $lmAuth = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -ErrorAction SilentlyContinue).LmCompatibilityLevel
        if ($null -eq $lmAuth -or $lmAuth -lt 3) { Log-Warn "  [CIS 2.3] LAN Manager auth level is $lmAuth  -  recommend 5"; $cisIssues++ }
        else { Log-Info "  [CIS 2.3] LAN Manager auth level: $lmAuth (OK)" }

        # 2.5 Windows Firewall
        $fwOff = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq $false })
        if ($fwOff.Count -gt 0) { Log-Warn "  [CIS 2.5] Windows Firewall disabled on: $($fwOff.Profile -join ', ')"; $cisIssues++ }
        else { Log-Info "  [CIS 2.5] Windows Firewall enabled on all profiles (OK)" }

        # 2.6 SMBv1
        $smb1 = Get-SmbServerConfiguration -ErrorAction SilentlyContinue | Select-Object -ExpandProperty EnableSMB1Protocol
        if ($smb1) { Log-Warn "  [CIS 2.6] SMBv1 is ENABLED  -  critical vulnerability"; $cisIssues++ }
        else { Log-Info "  [CIS 2.6] SMBv1 disabled (OK)" }

        # 2.7 Remote Registry
        $remReg = Get-Service -Name 'RemoteRegistry' -ErrorAction SilentlyContinue
        if ($remReg -and $remReg.StartType -ne 'Disabled') { Log-Warn "  [CIS 2.7] Remote Registry is $($remReg.StartType)  -  recommend Disabled"; $cisIssues++ }
        else { Log-Info "  [CIS 2.7] Remote Registry disabled (OK)" }

        # 2.8 AutoRun
        $autoRun = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -ErrorAction SilentlyContinue).NoDriveTypeAutoRun
        if ($autoRun -ne 255) { Log-Warn "  [CIS 2.8] AutoRun not fully disabled  -  recommend NoDriveTypeAutoRun=255"; $cisIssues++ }
        else { Log-Info "  [CIS 2.8] AutoRun disabled (OK)" }

        # 2.9 Defender
        $mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if (-not $mp -or -not $mp.AMServiceEnabled) { Log-Warn "  [CIS 2.9] Windows Defender not enabled"; $cisIssues++ }
        else { Log-Info "  [CIS 2.9] Windows Defender enabled (OK)" }

        if ($cisIssues -eq 0) { Log-Summary "CIS Benchmark Lite  -  all Level 1 checks passed" }
        else { Log-Warn "CIS Benchmark Lite  -  $cisIssues check(s) failed  -  review above" }
    }

    # Trend tracking - compare to previous run JSON
    Invoke-SafeBlock -Label 'Trend tracking' -Block {
        $jsonDir = 'C:\ProgramData\ShellKnight\JSON'
        $prevFiles = @(Get-ChildItem -LiteralPath $jsonDir -Filter "*_$($env:COMPUTERNAME).json" -ErrorAction Stop |
                       Sort-Object LastWriteTime -Descending | Select-Object -Skip 1 -First 1)
        if ($prevFiles.Count -gt 0) {
            $prev = Get-Content -LiteralPath $prevFiles[0].FullName -Raw | ConvertFrom-Json
            $prevDate = $prevFiles[0].LastWriteTime.ToString('yyyy-MM-dd')
            $prevSec  = if ($null -ne $prev.security_score)   { [int]$prev.security_score   } else { 0 }
            $prevPerf = if ($null -ne $prev.performance_score) { [int]$prev.performance_score } else { 0 }
            $prevIOC  = if ($null -ne $prev.ioc_alerts)        { [int]$prev.ioc_alerts        } else { 0 }

            $secDelta  = $Script:SecurityScore - $prevSec
            $perfDelta = $Script:PerformanceScore - $prevPerf
            $iocDelta  = $Script:Counters.IOCsFound - $prevIOC

            $secStr  = if ($secDelta -gt 0) { "+$secDelta (improved)" } elseif ($secDelta -lt 0) { "$secDelta (declined)" } else { "unchanged" }
            $perfStr = if ($perfDelta -gt 0) { "+$perfDelta (improved)" } elseif ($perfDelta -lt 0) { "$perfDelta (declined)" } else { "unchanged" }

            Log-Summary "Trend tracking  -  vs previous run ($prevDate):"
            Log-Summary "  Security score: $secStr  |  Performance: $perfStr  |  IOCs: $iocDelta"
            if ($secDelta -lt 0)   { Log-Warn "Security grade declined since last run  -  review changes" }
            if ($iocDelta -gt 0)   { Log-Warn "IOC count increased since last run  -  immediate review recommended" }
        } else { Log-Info "Trend tracking  -  no previous run data for comparison" }
    }

    Log-Summary "Reporting Engine complete"
} else {
    Log-Info "Reporting Engine  -  disabled"
}


# ==============================================================================
# SECURITY & PERFORMANCE SCORING
# ==============================================================================
# Security Score
$Script:SecurityScore = 100
if ($Script:Counters.IOCsFound -gt 0)            { $Script:SecurityScore -= [math]::Min(50, $Script:Counters.IOCsFound * 15) }
if ($Script:Counters.Failed)                      { $Script:SecurityScore -= 10 }
if ($avProduct -eq 'NONE DETECTED')               { $Script:SecurityScore -= 25 }
if ($defStatus -eq 'DISABLED')                    { $Script:SecurityScore -= 20 }
if ($osEolWarn)                                   { $Script:SecurityScore -= 20 }
if ($bitlockerWarn)                               { $Script:SecurityScore -= 15 }
if ($wuLastWarn)                                  { $Script:SecurityScore -= 15 }
if ($inactiveAccounts.Count -gt 0)               { $Script:SecurityScore -= [math]::Min(15, $inactiveAccounts.Count * 5) }
try { $smb1Sc = Get-SmbServerConfiguration -ErrorAction Stop | Select-Object -ExpandProperty EnableSMB1Protocol
      if ($smb1Sc) { $Script:SecurityScore -= 20 } } catch { }
try { $lmSc = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -ErrorAction Stop).LmCompatibilityLevel
      if ($null -eq $lmSc -or $lmSc -lt 3) { $Script:SecurityScore -= 15 } } catch { }
try { $fwSc = @(Get-NetFirewallProfile -ErrorAction Stop | Where-Object { $_.Enabled -eq $false })
      if ($fwSc.Count -gt 0) { $Script:SecurityScore -= 15 } } catch { }
if ($Script:MinPasswordLen -eq 0)    { $Script:SecurityScore -= 20 }
elseif ($Script:MinPasswordLen -lt 8){ $Script:SecurityScore -= 10 }
elseif ($Script:MinPasswordLen -lt 12){ $Script:SecurityScore -= 5 }
$Script:SecurityScore = [math]::Max(0, $Script:SecurityScore)

# Performance Score
$Script:PerformanceScore = 100
$disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction SilentlyContinue
$freeGB = if ($disk) { [math]::Round($disk.FreeSpace / 1GB, 1) } else { 99 }
if ($freeGB -lt 5)         { $Script:PerformanceScore -= 40 }
elseif ($freeGB -lt 10)    { $Script:PerformanceScore -= 25 }
elseif ($freeGB -lt 25)    { $Script:PerformanceScore -= 10 }

$cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
$ramGB = if ($cs) { [math]::Round($cs.TotalPhysicalMemory / 1GB, 1) } else { 16 }
if ($ramGB -lt 4)          { $Script:PerformanceScore -= 30 }
elseif ($ramGB -lt 8)      { $Script:PerformanceScore -= 15 }

$os2 = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
$uptimeDays = if ($os2) { ((Get-Date) - $os2.LastBootUpTime).TotalDays } else { 0 }
if ($uptimeDays -gt 60)    { $Script:PerformanceScore -= 20 }
elseif ($uptimeDays -gt 30){ $Script:PerformanceScore -= 10 }

$biosDate2 = try { [datetime]::ParseExact((Get-CimInstance Win32_BIOS).ReleaseDate.Split('.')[0],'yyyyMMdd',$null) } catch { (Get-Date) }
$pcAge2    = ((Get-Date) - $biosDate2).TotalDays / 365.25
if ($pcAge2 -gt 5)         { $Script:PerformanceScore -= 15 }
$Script:PerformanceScore = [math]::Max(0, $Script:PerformanceScore)

function Get-Grade { param([int]$Score)
    if ($Score -ge 90) { 'A' } elseif ($Score -ge 80) { 'B' } elseif ($Score -ge 70) { 'C' }
    elseif ($Score -ge 60) { 'D' } else { 'F' }
}
$secGrade  = Get-Grade $Script:SecurityScore
$perfGrade = Get-Grade $Script:PerformanceScore

# ==============================================================================
# FINAL REPORT
# ==============================================================================
$runtime   = [math]::Round(((Get-Date) - $Script:RunStart).TotalSeconds, 1)
$freedGB   = [math]::Round($Script:SpaceFreed / 1GB, 2)
$freedGBGross = $freedGB

# Space before/after
$diskAfter = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction SilentlyContinue
$freeAfterGB = if ($diskAfter) { [math]::Round($diskAfter.FreeSpace / 1GB, 1) } else { $freeGB }

$sepLine = '=' * 80

Log-Info $sepLine
Log-Info "  ShellKnight v2026.07.03.007 - Report"
Log-Info "  Hostname  : $($env:COMPUTERNAME)"
Log-Info "  Run Date  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Log-Info "  Runtime   : $runtime seconds"
Log-Info "  PS Version: $Script:PSFullVer"
Log-Info "  Intel     : $($Script:Counters.IntelSource)"
Log-Info "  Log File  : $Script:LogPath"
if ($Script:Counters.RebootRequired) { Log-Info "  !! REBOOT REQUIRED  -  please reboot this machine manually !!" }
Log-Info $sepLine

$bannerWidth2 = 78
Write-Host ''
Write-Host "  $sepLine" -ForegroundColor Cyan
Write-Host "  ShellKnight v2026.07.03.007 - Report" -ForegroundColor Cyan
Write-Host "  Hostname  : $($env:COMPUTERNAME)" -ForegroundColor White
Write-Host "  Run Date  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
Write-Host "  Runtime   : $runtime seconds" -ForegroundColor White
Write-Host "  $sepLine" -ForegroundColor Cyan

# Executive Summary (screen)
Write-Host ''
Write-Host "  ============================================================================" -ForegroundColor Cyan
Write-Host "  EXECUTIVE SUMMARY  -  BEFORE / AFTER" -ForegroundColor Cyan
Write-Host "  ============================================================================" -ForegroundColor Cyan
Write-Host "  Disk Free   : $freeGB GB  ->  $freeAfterGB GB  (+$([math]::Round($freeAfterGB - $freeGB,1)) GB net)" -ForegroundColor White
Write-Host "  IOC Alerts  : $($Script:Counters.IOCsFound)" -ForegroundColor $(if ($Script:Counters.IOCsFound -gt 0) { 'Red' } else { 'Green' })
Write-Host "  Actions Done: $($Script:Counters.ActionsTaken)" -ForegroundColor White
Write-Host "  Failed      : $($Script:Counters.Failed)" -ForegroundColor $(if ($Script:Counters.Failed) { 'Red' } else { 'White' })
Write-Host "  ============================================================================" -ForegroundColor Cyan

# Executive Summary (log)
Log-Info ''
Log-Info '  ============================================================================'
Log-Info '  EXECUTIVE SUMMARY  -  BEFORE / AFTER'
Log-Info '  ============================================================================'
Log-Info "  BEFORE                                  AFTER"
Log-Info "  ------                                  -----"
Log-Info "  Disk Free    : $freeGB GB                Disk Free    : $freeAfterGB GB  (+$([math]::Round($freeAfterGB - $freeGB,1)) GB net / $freedGBGross GB gross freed)"
Log-Info "  IOC Alerts   : $($Script:Counters.IOCsFound)"
Log-Info "  Warnings     :                           Actions Done : $($Script:Counters.ActionsTaken)"
Log-Info "  Failed       : $($Script:Counters.Failed)"
Log-Info '  ============================================================================'

# Metrics
Log-Info ''
Log-Info '  METRICS SUMMARY'
Log-Info ('-' * 80)
Log-Info "  Processes killed         $($Script:Counters.ProcessesKilled)"
Log-Info "  Services removed         $($Script:Counters.ServicesRemoved)"
Log-Info "  Tasks removed            $($Script:Counters.TasksRemoved)"
Log-Info "  Run keys removed         $($Script:Counters.RunKeysRemoved)"
Log-Info "  Files removed            $($Script:Counters.FilesRemoved)"
Log-Info "  Disk space freed         $freedGB GB"
Log-Info "  Hash IOCs loaded         $($Script:HashIOCsLoaded)"
Log-Info "  Filename IOCs loaded     $($Script:FilenameIOCsLoaded)"
Log-Info "  C2 IOCs loaded           $($Script:C2IOCsLoaded)"
Log-Info "  Intel source             $($Script:Counters.IntelSource)"
Log-Info "  Total actions taken      $($Script:Counters.ActionsTaken)"
Log-Info "  Failed actions           $($Script:Counters.Failed)"
Log-Info "  IOC alerts               $($Script:Counters.IOCsFound)"
Log-Info "  Runtime                  $runtime seconds"
Log-Info "  PS Version               $Script:PSFullVer"
Log-Info "  Reboot required          $(if ($Script:Counters.RebootRequired) { 'YES  -  reboot manually' } else { 'No' })"
Log-Info $sepLine

if ($Script:Counters.IOCsFound -gt 0) {
    Log-Info "  RESULT: COMPLETED - IOC ALERTS PRESENT - ANALYST REVIEW REQUIRED"
} else {
    Log-Info "  RESULT: SUCCESSFUL CLEANUP - $($Script:Counters.ActionsTaken) action(s) taken"
}

Log-Info $sepLine
Log-Info ''
Log-Info "  SECURITY GRADE:     $secGrade  ($Script:SecurityScore/100)"
Log-Info "  PERFORMANCE GRADE:  $perfGrade  ($Script:PerformanceScore/100)"
Log-Info ''

# ------------------------------------------------------------------------------
# REAL ISSUES WORTH ACTING ON - prioritized findings ledger (log + screen)
# ------------------------------------------------------------------------------
if ($Script:Findings.Count -gt 0) {
    $sevOrder = @{ High = 0; Medium = 1; Low = 2 }
    $sevColor = @{ High = 'Red'; Medium = 'Yellow'; Low = 'White' }
    $sorted   = $Script:Findings | Sort-Object { $sevOrder[$_.Severity] }
    $hi  = @($Script:Findings | Where-Object Severity -eq 'High').Count
    $med = @($Script:Findings | Where-Object Severity -eq 'Medium').Count
    $low = @($Script:Findings | Where-Object Severity -eq 'Low').Count

    $fHeader = "  REAL ISSUES WORTH ACTING ON  -  $hi High / $med Medium / $low Low"
    Log-Info '  ============================================================================'
    Log-Info $fHeader
    Log-Info '  ============================================================================'
    Write-Host ''
    Write-Host '  ============================================================================' -ForegroundColor Cyan
    Write-Host $fHeader -ForegroundColor Cyan
    Write-Host '  ============================================================================' -ForegroundColor Cyan
    foreach ($f in $sorted) {
        $line1 = "  [$($f.Severity.ToUpper().PadRight(6))] $($f.Title)"
        $line2 = "           -> $($f.Action)"
        Log-Info $line1
        Log-Info $line2
        Write-Host $line1 -ForegroundColor $sevColor[$f.Severity]
        Write-Host $line2 -ForegroundColor DarkGray
    }
    Log-Info '  ============================================================================'
    Write-Host '  ============================================================================' -ForegroundColor Cyan
}

# Screen summary
Write-Host ''
Write-Host "  ============================================================================" -ForegroundColor Cyan
Write-Host "  SECURITY GRADE:     $secGrade  ($Script:SecurityScore/100)" -ForegroundColor $(if ($secGrade -in 'A','B') { 'Green' } elseif ($secGrade -eq 'C') { 'Yellow' } else { 'Red' })
Write-Host "  PERFORMANCE GRADE:  $perfGrade  ($Script:PerformanceScore/100)" -ForegroundColor $(if ($perfGrade -in 'A','B') { 'Green' } elseif ($perfGrade -eq 'C') { 'Yellow' } else { 'Red' })
Write-Host "  ============================================================================" -ForegroundColor Cyan

# Banner message
$bannerMsg = if ($Script:Counters.IOCsFound -gt 0) {
    "ShellKnight: Action Required  -  $($Script:Counters.IOCsFound) issue(s) detected. Review report."
} elseif ($Script:Counters.RebootRequired) {
    "ShellKnight: Complete  -  Reboot Required"
} else {
    "ShellKnight: All Clear!"
}
$bannerColor = if ($Script:Counters.IOCsFound -gt 0) { 'Red' } elseif ($Script:Counters.RebootRequired) { 'Yellow' } else { 'Green' }
Write-Host ''
Write-Host "  $('#' * 78)" -ForegroundColor $bannerColor
Write-Host "  #$(' ' * 76)#" -ForegroundColor $bannerColor
Write-Host "  #   $($bannerMsg.PadRight(73))#" -ForegroundColor $bannerColor
Write-Host "  #$(' ' * 76)#" -ForegroundColor $bannerColor
Write-Host "  $('#' * 78)" -ForegroundColor $bannerColor
Write-Host ''

# JSON output
$jsonDir  = 'C:\ProgramData\ShellKnight\JSON'
$jsonStamp= Get-Date -Format 'yyyy-MM-dd_HHmm'
$jsonPath = "$jsonDir\ShellKnight_${jsonStamp}_$($env:COMPUTERNAME).json"

$jsonData = [ordered]@{
    version          = 'v2026.07.03.007'
    hostname         = $env:COMPUTERNAME
    run_date         = (Get-Date -Format 'o')
    runtime_seconds  = $runtime
    ps_version       = $Script:PSFullVer
    intel_source     = $Script:Counters.IntelSource
    os               = $Script:MachineInfo['OS']
    os_eol           = $Script:MachineInfo['OS EOL']
    pc_age_years     = $Script:MachineInfo['PC Age']
    ram              = $Script:MachineInfo['RAM']
    disk_free_gb     = $freeGB
    disk_free_after  = $freeAfterGB
    bitlocker        = $Script:MachineInfo['BitLocker']
    antivirus        = $avProduct
    defender         = $defStatus
    security_score   = $Script:SecurityScore
    security_grade   = $secGrade
    performance_score= $Script:PerformanceScore
    performance_grade= $perfGrade
    ioc_alerts       = $Script:Counters.IOCsFound
    actions_taken    = $Script:Counters.ActionsTaken
    disk_freed_gb    = $freedGB
    reboot_required  = $Script:Counters.RebootRequired
    processes_killed = $Script:Counters.ProcessesKilled
    services_removed = $Script:Counters.ServicesRemoved
    tasks_removed    = $Script:Counters.TasksRemoved
    run_keys_removed = $Script:Counters.RunKeysRemoved
    files_removed    = $Script:Counters.FilesRemoved
    hash_iocs_loaded = $Script:HashIOCsLoaded
    filename_iocs    = $Script:FilenameIOCsLoaded
    c2_iocs          = $Script:C2IOCsLoaded
    failed_actions   = $Script:Counters.Failed
    findings         = @($Script:Findings | ForEach-Object { [ordered]@{ severity = $_.Severity; title = $_.Title; action = $_.Action } })
    log_path         = $Script:LogPath
}

$jsonBody = $jsonData | ConvertTo-Json -Depth 4
$jsonBody | Set-Content -LiteralPath $jsonPath -Encoding UTF8 -Force
Log-Info "JSON report saved: $jsonPath"

# Battlefield push (ADR 0001/0002) - POST the same JSON to the ingest endpoint.
# Failure here never affects the run outcome; the on-disk report is the source
# of truth and a later run will re-report current state.
if ($Script:Config.BattlefieldEnabled) {
    if (-not $Script:Config.BattlefieldApiKey) {
        Log-Warn "Battlefield enabled but no API key set  -  skipping push"
    } else {
        try {
            $headers = @{ 'X-API-Key' = $Script:Config.BattlefieldApiKey }
            $resp = Invoke-RestMethod -Uri $Script:Config.BattlefieldURL -Method Post `
                        -Body $jsonBody -ContentType 'application/json' `
                        -Headers $headers -TimeoutSec 20 -ErrorAction Stop
            Log-Success "Battlefield push OK  -  run_id: $($resp.run_id) | tenant: $($resp.tenant)"
        } catch {
            Log-Warn "Battlefield push failed  -  $($_.Exception.Message)"
        }
    }
}

# Exit code
$exitCode = if ($Script:Counters.IOCsFound -gt 0) { 2 } elseif ($Script:Counters.Failed) { 1 } else { 0 }

# Cleanup logging
if ($Script:LogReady) {
    $Script:LogWriter.Flush()
    $Script:LogWriter.Dispose()
    $Script:LogReady = $false
}

exit $exitCode

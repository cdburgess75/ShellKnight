# ShellKnight Changelog

## [v1.05] - 2026-05-25

- **Process Engine — NVDisplay/Intel feed false positive fix (critical):** Added CIM `Win32_Process` fallback when `Get-Process.Path` returns null (occurs on NVIDIA driver processes and other kernel-adjacent processes). If path is still unavailable after CIM fallback, fail-safe to **skip** rather than kill. Path comparison upgraded to `OrdinalIgnoreCase` via `StartsWith`.
- **Process Engine — Scheduled task whitelist:** Microsoft SMBv1 auto-removal tasks (`\Microsoft\Windows\SMB\UninstallSMB1ClientTask`, `\Microsoft\Windows\SMB\UninstallSMB1ServerTask`) are now whitelisted by task scheduler path. These are legitimate OS security tasks — previous builds incorrectly flagged and deleted them due to `-NoProfile` in their command line.
- **Detection Engine — RiskWare miner pattern:** Changed bare `miner` substring match to `\bminer` (word-boundary regex) to prevent false positives on filenames containing `remineralization`, `rminerva`, or other legitimate words with `miner` as a substring. Confirmed false positive: dental research PDFs on PROVIDER1.
- **Reporting Engine — Event 7045 whitelist expanded:** `Datto EDR Agent`, `Pml Driver HPZ12`, `Net Driver HPZ12`, `IntelTACD`, `RapportIaso` added to known-good service list. Infocyte agent path added as path-based whitelist. Prevents ShellKnight from flagging its own deployment platform's EDR agent and common HP printer drivers.
- **IOC counter fix — browser extensions:** `$Script:Counters.IOCsFound` now increments on malware browser extension removals. Previously exit code showed 0 even when hijacker extensions were found and removed.
- **IOC counter fix — Event 7045:** `$Script:Counters.IOCsFound` now increments on suspicious Event 7045 service installs. Previously exit code showed 0 on machines with IOC-level service events.
- **Hardening Engine — Domain Admins suppression:** `DOMAIN\Domain Admins` group no longer flagged in local admin report. Expected on all domain-joined machines; was generating noise on every domain endpoint.
- **Filesystem Engine — Stale profile exclusions:** Windows system service profiles (`TEMP`, `UMFD-*`, `DWM-*`, `Font Driver Host`) added to exclusion list. These are OS service account profiles, not real user profiles.
- **Filesystem Engine — Registry uninstall scan optimization:** Replaced per-subkey `Get-ItemProperty` loop with single `Get-ItemProperty -Path "$unPath\*"` batch query. Reduces disk/CPU overhead on endpoints with many installed applications.
- **Counter init fix:** `$Script:Counters.Failed` changed from `$false` to `0` — prevents type inconsistency in JSON output on first run.

## [v1.04] - 2026-05-25

- Process Engine: Intel feed filename IOC matches now verify the process executable path before flagging and killing. Processes running from `C:\Windows\`, `C:\Program Files\`, or `C:\Program Files (x86)\` are treated as legitimate system/vendor binaries and skipped. Catches the `NVDisplay.Container` false positive (legitimate NVIDIA driver process that appears in threat intel as a known malware impersonation target). Malware running from `AppData`, `Temp`, or user directories is still caught and killed.

## [v1.03] - 2026-05-25

- PS 3.0/4.0 compatibility: all 39 `::new()` constructor calls replaced with `New-Object` — `::new()` is PS 5.0+ syntax.
- PS 3.0–6.x compatibility: `??` null-coalescing operator replaced with `if/else` — `??` is PS 7.0+ syntax.
- `$ErrorActionPreference` reverted to `SilentlyContinue` — `Stop` combined with `Set-StrictMode -Version 2` caused every `.Property` access on a potentially-null object to be terminating. `Invoke-SafeBlock` with per-cmdlet `-ErrorAction Stop` is the correct error-handling pattern for this script.
- Phase 6 (Filesystem Engine): null-guard added to registry uninstall key `DisplayName` access — keys without a `DisplayName` value no longer crash the engine.
- Versioning scheme updated: increments of `.01` going forward (v1.03, v1.04, v1.05…).

## [v1.02] - 2026-05-25

- `Log-Fail` now increments `$Script:Counters.Failed` — exit code 1 and the "Failed actions" metric now fire correctly.
- Remote access inventory: fixed service and process matching in Detection Engine — inner `Where-Object` now captures `$svc`/`$proc` via variable, resolving broken wildcard matching against all 22 remote tools.
- Executive Summary added to screen output — before/after disk free, IOC count, actions taken, and failed actions now visible on console without opening the log file.
- `Write-Log` null-guard: `$Script:LogWriter` null check added alongside `$Script:LogReady` flag.
- Script renamed to `ShellKnight.ps1` (canonical filename going forward).
- Archive: v0.81, v0.82, v0.83 added to `archive/`.

## [v1.01] - 2026-05-22

- Ground-up rewrite as ShellKnight 2.0. Eight-engine modular architecture replacing 29-phase design.
- Intel Engine: pluggable source framework, HEAD check, single consolidated cache.
- Assessment Engine: CVE check via Microsoft Security Update Guide (Critical/High/Medium), KB references.
- Hardening Engine: LAN Manager auth auto-remediation, Firewall auto-enable, SMBv1/LLMNR/NLA/NetBIOS hardening.
- Process Engine: full process/service/task inventory, suspicious-only screen output, verbose log.
- Persistence Engine: Run/RunOnce keys, startup folders, WMI subscriptions, browser policies, Defender exclusions.
- Filesystem Engine: artifact cleanup, temp files, cache, stale profiles, browser extensions, registry uninstall keys.
- Detection Engine: IOC detection, MalwareBazaar, ransomware canary, hosts file, network connections, remote access inventory, RISKWARE-RAT.
- Reporting Engine: Windows Update names, trend tracking, event log IOCs, reboot check, recent software, extended checks, compliance.
- Performance: Generic List/HashSet collections, hash table IOC lookups, Filter Left, `foreach` loops, splatting, single-query caching, `Invoke-SafeBlock` pattern.

- Ground-up rewrite as ShellKnight 2.0. Eight-engine modular architecture replacing 29-phase design.
- Intel Engine: pluggable source framework, HEAD check, single consolidated cache.
- Assessment Engine: CVE check via Microsoft Security Update Guide (Critical/High/Medium), KB references.
- Hardening Engine: LAN Manager auth auto-remediation, Firewall auto-enable, SMBv1/LLMNR/NLA/NetBIOS hardening.
- Process Engine: full process/service/task inventory, suspicious-only screen output, verbose log.
- Persistence Engine: Run/RunOnce keys, startup folders, WMI subscriptions, browser policies, Defender exclusions.
- Filesystem Engine: artifact cleanup, temp files, cache, stale profiles, browser extensions, registry uninstall keys.
- Detection Engine: IOC detection, MalwareBazaar, ransomware canary, hosts file, network connections, remote access inventory, RISKWARE-RAT.
- Reporting Engine: Windows Update names, trend tracking, event log IOCs, reboot check, recent software, extended checks, compliance.
- Performance: Generic List/HashSet collections, hash table IOC lookups, Filter Left, `foreach` loops, splatting, single-query caching, `Invoke-SafeBlock` pattern.

## [v0.73]

- Fixed LegitProcessNames StrictMode VariableIsUndefined error: moved definition before Phase 3 (was defined after Phase 8).
- PUA target expansion: PulseBrowser, BrightData, BlazerBrowser, ShiftBrowser, EpiBrowser, CustomSearchBar, ActiveSearchBar, VOPackage, SearchEngineHijack, Avanquest, DriverSupport, WinZipDiskTools, AuslogicsDriverUpdater, pdfsparkware added.
- Torrent clients flagged as WARN in Phase 19 (not auto-removed).
- Account management: $SK_AutoDisableInactiveAccounts, $SK_AutoDisableThresholdDays (547 days / 18 months), $SK_AutoDisableOnServers (default off).
- Never-logged-in accounts always report-only.
- Machine accounts (ending in $) filtered from inactive report.
- Ransomware canary: Intel Wireless WLANProfiles .enc whitelisted.
- Ransomware canary: damsi\keywords.enc whitelisted (known app).
- Stale profiles: .NET framework profiles excluded.
- Hosts whitelist: iDRAC entries suppressed.
- Version : v0.72 -> v0.73 per versioning rule.

## [v0.72]

- Scan depth framework: $SK_ScanDepth (Standard/Deep/Compliance). Default: Compliance. Gates new phases by depth setting.
- Low disk failsafe: $SK_MinFreeSpaceGB (warn+reduce, default 2.0) and $SK_AbortFreeSpaceGB (abort, default 0.5) added to config.
- Script aborts cleanly if disk critically low at startup.
- New Phase 22: Local admin audit, guest account check, password policy check, RDP exposure check, legacy protocol detection (SMBv1/LLMNR/NetBIOS), audit policy check.
- New Phase 23: USB/removable media audit (event 6416).
- New Phase 24: Network connection audit (Get-NetTCPConnection).
- New Phase 25: Ransomware canary check.
- New Phase 26: Windows Update pending count.
- New Phase 27: Stale profile report (180+ days).
- New Phase 28: Trend tracking vs previous JSON run.
- Disk report: shows gross freed vs net disk gain with note that Windows writes during scan.
- Broken CIM detection: flags unreliable grades when WMI fails.
- Cricut process/startup whitelist added.
- JSON save line suppressed from screen output.
- Version : v0.71 -> v0.72 per versioning rule.

## [v0.71]

- Deduplicated AV product names: Layer 2 broad fallback no longer returns duplicates. AV list deduped before join.
- Dell Command Power Manager added to WMI whitelist: DellCommandPowerManagerPolicyChangeEventFilter and DellCommandPowerManagerPolicyChangeEventConsumer suppressed.
- MalwareBazaar: hash_not_found treated as no_results, not unexpected response.
- Phase 3: OneBrowser process killed before Phase 4 cleanup.
- Phase 18: BITS/DoSvc stop/start wrapped with -WarningAction SilentlyContinue to suppress console noise.
- Before/After: IOC unchanged line suppressed when IOCs = 0.
- All Clear banner: text shortened to fit 76-char box.
- Startup header: single clean box with log path prominent.
- Screen output: INFO suppressed from console during run.
- WARN/SUCCESS/FAILED/IOC display on screen; INFO to log only.
- Version : v0.70 -> v0.71 per versioning rule.

## [v0.70]

- Path restructure: C:\ProgramData\ShellKnight\Logs|Intel|JSON (previously C:\ProgramData\Logs\ShellKnight\).
- MalwareBazaar: added Auth-Key header support, $SK_MalwareBazaar_Enabled and $SK_MalwareBazaar_ApiKey config variables. Hash lookups now fully authenticated and functional.
- AV detection: fixed service names for Datto AV (EndpointProtectionService), Datto RMM (CagService), Datto EDR (HUNTAgent). Removed incorrect CagraService/DattoAV/HUNTRESSAgent.
- Added broad Datto fallback scan by DisplayName.
- Fixed JSON save line firing after log closed – now uses Write-Host directly.
- Fixed v1.0 changelog note – was a naming error, actual build was v0.68.
- Version : v0.69 -> v0.70 per versioning rule.

## [v0.69]

- Top-of-file config section: all configurables ($SK_Email_*, $SK_Syslog_*, $SK_Mode) with enable/disable toggles. Email wired to $SK_Email_Enabled. Syslog wired to $SK_Syslog_Enabled.
- Syslog output: sends structured RFC3164 syslog after each run via UDP or TCP. Skipped silently if server blank or disabled.
- JSON output moved to C:\ProgramData\ShellKnight\JSON\
- PUA/PUP target expansion: OneBrowser, OneWebSearch, Awesomehp, SweetIM, CoolWebSearch, SearchDimension, CouponPrinter, CouponXplorer, BaiduPCFaster, HolaVPN, PCCleanerPro, MyCleanPC, AdvancedSystemCare, PCAcceleratePro, DriverBooster, SlimDrivers, DriverPackSolution, SpyHunter, ByteFence, Segurazo, TotalAV, KMSPico, KMSAuto added to Targets, Folders, Services, and Tasks.
- Before/After executive summary added to console report.
- Fixed 0x%1!x! formatting artifact in Defender error message.
- Version : v0.68 -> v0.69 per versioning rule.

## [v0.68]

- Fixed StrictMode scoping: all Phase 2 variables ($freeGB, $uptime, $avProduct, $osEolWarn, $pcAgeWarn, $wuLastWarn, $bitlockerWarn, $defStatus, $inactiveAccounts etc) now initialized to safe defaults before Phase 2 try block so grading never throws if Phase 2 fails.
- Fixed $Script:HWInfo.RAM -> $Script:HWInfo.TotalRAMMB in perf score.
- Removed duplicate email disabled comment block.
- Enhanced AV detection: 3-layer approach – SecurityCenter2 (Layer 1), known MSP/enterprise service scan covering Datto AV, Webroot, Malwarebytes, Huntress, SentinelOne, CrowdStrike, Cylance, ESET, Sophos, Kaspersky, Carbon Black, Trend Micro (Layer 2), process scan fallback (Layer 3). Datto AV now detected correctly.
- Version : v0.67 -> v0.68 per versioning rule.

## [v1.0] - [NAMING ERROR - actual build was v0.68]

- PROJECT RENAMED: Dave's CleanSweep -> ShellKnight.
- Log path: C:\ProgramData\ShellKnight\Logs\
- Log prefix: ShellKnight_YYYY-MM-DD_HHMM.log
- Phase 2 expanded into full health assessment:
  - PC age from BIOS date (flag if over 5 years)
  - OS End of Life check with hardcoded EOL dates
  - BitLocker status detection
  - Windows Update last install date (flag if over 30 days)
  - AV/Defender detection via SecurityCenter2
  - Uptime warning if over 30 days
  - Last 3 interactive logons from event log 4624
- Inactive local account report (90+ days, report only).
- Security Grade (A-F) scoring system.
- Performance Grade (A-F) scoring system.
- JSON report output saved alongside log file.
- Granicus hosts whitelist (government platform).
- Windows Update Cache: stop BITS + UsoSvc + wuauserv.
- Version : v0.66 -> v0.68 (ShellKnight release).

## [v0.66]

- Phase 21: skip 4688 event scan on Server OS (too noisy/slow).
- Reduced MaxEvents from 5000 to 500 on workstations.
- Phase 15: whitelisted known Citrix installer filenames in drop locations (CitrixReceiver.exe, ReceiverCleanupUtility-New.exe and variants) – no longer flagged as IOCs.
- MalwareBazaar 401: demoted from WARN to INFO – expected behaviour without API key, not an error.
- Phase 18 wuauserv: added 30-second wait loop for service to fully stop before cleaning SoftwareDistribution\Download.
- Version : v0.65 -> v0.66 per versioning rule.

## [v0.65]

- Fixed Write-Log operator precedence bug: '-not $x -eq $null' always evaluated to $false, meaning NOTHING was ever written to the log file. Fixed to '($x -ne $null)'. This also explains why IOC report section always showed (none) – log was empty.
- Fixed Phase 19 $sorted.Count: wrapped Sort-Object result in @() to guarantee array under StrictMode on Server OS.
- Version : v0.64 -> v0.65 per versioning rule.

## [v0.64]

- Fixed PropertyNotFoundStrict on svcGroups hashtable: dot notation on hashtable key named 'Count' is ambiguous under StrictMode. Replaced $g.Count/$g.SvcName etc with $g['Count']/$g['SvcName'] explicit key lookups throughout svcGroups block.
- Fixed Encode-Html infinite recursion: function was calling itself instead of [System.Web.HttpUtility]::HtmlEncode.
- Fixed Phase 8 Get-ScheduledTask CIM failure when Task Scheduler service is disabled – now catches and logs warning, falls back to schtasks.exe path.
- Version : v0.63 -> v0.64 per versioning rule.

## [v0.63]

- Fixed ObjectDisposedException on Write-Log after log writer closed: added $Script:LogReady guard inside Write-Log so writes after Dispose() are silently skipped. Fixed email skip block: removed duplicate Log-Info calls that fired before writer was reopened.
- Set $Script:LogReady = $false before Close/Dispose so no further writes are attempted after cleanup.
- Version : v0.62 -> v0.63 per versioning rule.

## [v0.62]

- Fixed crash trap firing on closed TextWriter after normal completion. Added $Script:LogReady flag – trap only intercepts pre-log errors.
- Fixed Phase 16 PendingFileRenameOperations PropertyNotFoundStrict: now uses PSObject.Properties guard via Get-ItemProperty result object.
- Fixed Server 2016 download failure: added TLS 1.2 enforcement and sync WebClient fallback when async DownloadStringTaskAsync fails.
- Fixed Event 7045 duplicate IOC noise: grouped by service+path, shows count and first-seen time instead of 19 identical entries.
- Version : v0.61 -> v0.62 per versioning rule.

## [v0.61]

- Fixed OutOfMemoryException on DynamicFileIOCRegex: replaced single 3839-alternation compiled regex with HashSet (exact matches) plus chunked regex (500 patterns/chunk). Added Test-DynamicFileIOC helper.
- Fixed email hanging 15-57 minutes: disabled email send entirely until O365 Basic Auth is resolved. Logs clear instructions.
- Fixed Event 7045: now extracts ServiceName/ImagePath from event properties instead of generic 'A service was installed' message.
- Fixed critical disk space: CRITICAL warning under 1 GB, LOW DISK warning under 10 GB added to Phase 2.
- Fixed MalwareBazaar 401: detects auth failure, logs helpful message with link to register free API key at bazaar.abuse.ch.
- Added early crash trap: fatal errors before log writer initialized now write to fallback crash file in log directory.
- Added Dell Command Power Manager to WMI whitelist.
- Version : v0.60 -> v0.61 per versioning rule.

## [v0.60]

- Fixed SMTP hang causing 15+ minute script runtime. Email send now runs in a background PS job with a hard 20-second timeout. Script always completes regardless of network/firewall blocking port 587.
- Timeout logs a clear warning: 'port 587 may be blocked'.
- Version : v0.59 -> v0.60 per versioning rule.

## [v0.59]

- Fixed email attachment file-in-use error: log file was still held open by StreamWriter when Attachment tried to read it. Now copies log to a temp file, attaches copy, deletes after send.
- Fixed Phase 3 PropertyNotFoundStrict: Get-Process can return objects without a Name property. Added PSObject.Properties guard.
- Fixed Zoom false positive: ZoomUpdateTask flagging Zoom.exe in AppData\Roaming\Zoom\bin as suspicious. Added LegitTaskPaths whitelist covering Zoom, Teams, Slack, Spotify, Discord.
- Fixed banner padding: ShellKnight is Sweeping! right border now aligns.
- Reduced SMTP timeout from 30s to 15s for faster failure.
- Version : v0.58 -> v0.59 per versioning rule.

## [v0.58]

- Fixed System.Web.HttpUtility TypeNotFound error on PS5. Moved Add-Type -AssemblyName System.Web to script startup before StrictMode. Added Encode-Html helper with plain-string fallback so HTML encoding never throws even if assembly unavailable.
- Removed duplicate Add-Type from email send function.
- Version : v0.57 -> v0.58 per versioning rule.

## [v0.57]

- Added HTML email report. Sends after every run to SmtpTo address configured in Config block. Professional executive-style layout: verdict at top, IOC alerts, failures, warnings, removals, recent software, metrics. Full log file attached. Uses SmtpClient with TLS for Office 365 compatibility.
- Added 'ShellKnight is Sweeping!' exclamation mark.
- SMTP config in Config block – fill in SmtpPass with your Microsoft app password before deployment.
- Version : v0.56 -> v0.57 per versioning rule.

## [v0.56]

- Fixed Phase 16 VariableIsUndefined error on machines where PendingFileRenameOperations registry value does not exist. Get-ItemProperty returns $null when value is absent; accessing .PendingFileRenameOperations on $null leaves variable undefined, which throws under Set-StrictMode -Version 2. Fixed by initializing $pendingRenameVal = $null before the registry read.
- Version : v0.55 -> v0.56 per versioning rule.

## [v0.55]

- Replaced 'FULL OF CRAP' verdict banner with 'Dave is Sweeping'.
- Replaced 'NO CRAP FOUND' with 'ShellKnight: All Clear!'. Moved both banners to bottom of report so they are the last thing seen.
- Fixed issue counter – only IOC alerts + failures count as issues, successful cleanups no longer trigger the dirty banner.
- Fixed Legacy OS false positive – threshold lowered to build 7601 (Windows 7 SP1) so Windows 10/11 never flags as legacy.
- Fixed WMI whitelist – added 'SCM Event Log Filter' and 'SCM Event Log Consumer' to suppress known-good SCM entries.
- Version : v0.54 -> v0.55 per versioning rule.

## [v0.54]

- Fixed PropertyNotFoundStrict (.Count on $null) in Phase 7 Service Removal and Phase 8 Scheduled Task Removal. Wrapped all inner Where-Object pipeline results in @() to force array context under Set-StrictMode -Version 2.
- Version : v0.53 -> v0.54.

## [v0.53]

- Fixed root cause of all parse errors: UTF-8 em-dashes in executable code strings corrupted PS parser on systems reading scripts as Windows-1252 (no BOM). Replaced all em-dashes with ASCII ' - '.
- Added UTF-8 BOM.
- Version : v0.52 -> v0.53.

## [v0.52]

- Fixed $usedPct% parse error in Phase 2 machine info string (PS parser treats % as modulo operator after subexpression). Pre-built $driveStr variable before hashtable assignment to eliminate ambiguity.
- Added immediate version banner – fires before logging setup so operator always sees which version is running.
- Version : v0.51 -> v0.52 per versioning rule.

## [v0.51]

- Removed automatic reboot (shutdown.exe call eliminated). Reboot flag retained for reporting – operator must reboot manually.
- Fixed $Script: scope prefix on $filenameIOCList throughout.
- Fixed Phase 13 hosts IOC noise – blank lines no longer flagged.
- Fixed Phase 18 service existence check before Stop/Start-Service.
- Updated all version strings, header, phase overview, changelog.
- Version : v0.47 -> v0.51 (skipping v0.48-v0.50 per owner request).

## [v0.47]

- MAJOR REVISION – Dynamic Intelligence + Reboot Detection + Safe Cleanup
- Phase 0 : NEW. Hardware/OS detection. Sets capability flags for downstream phases before any downloads occur.
- Phase 1 : NEW. Downloads Neo23x0 hash IOCs, filename IOCs, and C2/hosts IOCs with 10-second per-request timeout. Disk-cache fallback. Hardcoded fallback if cache absent. Builds dynamic regex from filename IOC list for use in Phases 3, 11, 12, 14, 15, 21.
- Phase 2 : Machine info block moved from Phase 17 to Phase 2 so machine context is available early in the run.
- Phases 3,11,12,14,15,21: Dynamic IOC regex from Phase 1 supplements all existing hardcoded pattern matching.
- Phase 13 : Hosts cleanup now uses dynamic C2 IOC list from Phase 1. Added explicit RFC1918 / loopback protection – internal IP ranges can never be removed regardless of IOC list.
- Phase 16 : Reboot detection added. Checks PendingFileRenameOperations and three registry indicators.
- Phase 17 : MalwareBazaar timeout reduced to 10 seconds (was 15). Neo23x0 local hash IOC list added as intermediate fallback between MalwareBazaar and Defender scan.
- Phase 18 : Recycle Bin removed from auto-clean (user data risk). Added per-location before/after file count + MB reporting.
- Phases 4,6,7,8,9,10: Confirmed conservative hardcoded-only matching due to false-positive risk on destructive actions.
- Version : v0.46 -> v0.47 per versioning rule (every change = bump).

## [v0.46]

- Fixed Set-StrictMode PropertyNotFoundException on scheduled task Action objects missing Execute property (COM handler actions).

## [v0.45]

- Fixed Set-StrictMode PropertyNotFoundException on registry entries missing DisplayName, UninstallString, DisplayVersion, Publisher, and InstallDate properties.

## [v0.44]

- Added Machine Info Block (Phase 17), Recently Installed Software Report (Phase 18), Temp File Age Report (Phase 19), Event Log IOC Check (Phase 20). Instant verdict banner.

## [v0.43]

- Fixed PS5.1 New-Object Regex constructor argument parsing error.

## [v0.42]

- Split all malware/RAT name strings via runtime concatenation.

## [v0.41]

- Broad PS version compatibility (PS3-PS7).

## [v0.40]

- Full PowerShell-native rewrite. No sc.exe, cmd.exe, Get-WmiObject.

## [v0.38]

- Added Startup LNK cleanup, Browser Policy keys, Hosts file inspection, WMI persistence audit, Reboot detection, MalwareBazaar + Defender fallback scan, Disk space cleanup.

## [v0.37]

- Original ShellKnight release. 9 phases, Datto RMM optimized.

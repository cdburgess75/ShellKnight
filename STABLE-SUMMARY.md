# ShellKnight v0.73

**Enterprise Endpoint Security & Remediation Tool**

---

## Overview

ShellKnight v0.73 is a comprehensive PowerShell-based endpoint security and remediation tool designed to detect and remove potentially unwanted programs (PUPs), browser hijackers, adware, malware persistence mechanisms, and perform system hardening on Windows systems.

- **Compatible:** PowerShell 3.0 through 7.x (runtime detection and adaptive behavior)
- **Scope:** 21+ distinct remediation and audit phases
- **Requirement:** Administrator privileges
- **Output:** Structured logs, JSON reports, optional email/syslog integration

---

## Purpose

Automates malware and PUP remediation, system auditing, and endpoint hardening across Windows environments through:

- Sequential multi-phase detection and cleanup workflows
- Dynamic threat intelligence integration (Neo23x0 signature-base, MalwareBazaar API)
- Extensive hardcoded and dynamically-augmented IOC (Indicators of Compromise) coverage
- Detailed audit trails, summary banners, and configurable reporting
- Enterprise-grade fail-safes and compatibility checks

---

## Key Features

### Multi-Phase Remediation
Orchestrates detection and cleanup across 21+ sequential phases covering:
- Hardware/OS detection
- Dynamic IOC downloads
- Process and file cleanup
- Registry and scheduled task cleanup
- Service removal
- Hosts file inspection
- Malware hash lookups
- System auditing and reporting

### Dynamic Threat Intelligence
- Integrates with external sources (Neo23x0 signature-base, MalwareBazaar API)
- Retrieves up-to-date IOCs with 10-second timeout per request
- Disk-cache fallback if downloads fail
- Hardcoded fallback lists if cache unavailable

### Extensive IOC Coverage
Maintains hardcoded whitelists/blacklists for:
- File names and executables
- Registry keys and policies
- Browser extensions
- Services and scheduled tasks
- Startup shortcuts and Run keys
- Dynamically augments using downloaded intelligence

### Comprehensive Audit & Reporting
- Detailed action logging (file+console output with color-coded levels)
- System inventory and health assessment
- JSON report output
- Optional HTML email reports
- Optional RFC3164 syslog integration
- Security Grade (A-F) and Performance Grade (A-F) scoring

### Configurable & Extensible
Central configuration block for:
- Email reporting (SMTP/Office 365 compatible)
- Syslog output (UDP/TCP)
- Scan depth (Standard, Deep, Compliance)
- Account management (inactive account auto-disable with thresholds)
- Disk safety (abort/reduce scope if low disk space)
- MalwareBazaar API integration

### Enterprise Fail-safes
- Runtime PowerShell version detection and adaptive behavior
- Safe cleanup to avoid accidental critical data loss
- Low-disk detection and abort logic
- Robust error handling and logging
- Early crash trapping for pre-initialization failures

---

## Major Remediation Phases

| Phase | Name | Description |
|-------|------|-------------|
| 0 | Hardware & OS Detection | Collects system profile, sets capability flags for downstream phases |
| 1 | Dynamic Intelligence Download | Downloads hash/filename/C2 IOC lists from Neo23x0 with timeout fallback |
| 2 | Machine Information Block | Logs hostname, OS, uptime, user, Defender status, disk space, health metrics |
| 3 | Process Termination | Kills running processes matching known PUP/adware names |
| 4 | Filesystem Artifact Cleanup | Removes known PUP install directories (conservative hardcoded list) |
| 5 | Browser Extension Removal | Removes hijacker extensions from Chrome, Edge, Firefox by ID and manifest |
| 6 | Registry Uninstall | Executes uninstallers from HKLM and HKCU uninstall hives |
| 7 | Service Removal | Conservative hardcoded service targets with CIM-native deletion |
| 8 | Scheduled Task Removal | Removes suspicious scheduled tasks (conservative hardcoded list) |
| 9 | Run Key & RunOnce Cleanup | Removes persistence from registry Run/RunOnce keys |
| 10 | Startup Folder Cleanup | Removes suspicious .LNK files from Startup folders |
| 11 | Browser Policy Key Cleanup | Removes hijacker-controlled policy keys; uses dynamic patterns |
| 12 | Defender Exclusion Cleanup | Removes suspicious Defender exclusions |
| 13 | Hosts File Inspection | Dynamic C2 IOC cleanup with RFC1918/loopback protection |
| 14 | WMI Persistence Audit | Detects WMI Event Filters and Consumers with whitelist |
| 15 | Trojan/Malware IOC Detection | Dynamic filename IOC list + 29-family RAT/stealer signatures |
| 16 | Reboot Requirement Check | Checks PendingFileRenameOperations and related indicators |
| 17 | MalwareBazaar Hash Lookup | SHA256 hash scanning with MalwareBazaar API, Neo23x0, and Defender fallback |
| 18 | Disk Space Cleanup | Cleans Temp, WER, CBS, Prefetch, Windows Update cache, etc. |
| 19 | Recently Installed Software Report | Lists software installed in last 30 days (report-only) |
| 20 | Temp File Age Report | Snapshots count/size/oldest file per Temp folder |
| 21 | Event Log IOC Check | Scans Security (4688) and System (7045) logs for IOC patterns |
| 22+ | Advanced Auditing | Local admin audit, guest account check, RDP exposure, USB audit, ransomware canaries, stale profiles, trend tracking, Windows Update status |

---

## Configuration

Edit the **SHELLKNIGHT CONFIGURATION** section at the top of the script before deployment:

```powershell
# EMAIL REPORT
$SK_Email_Enabled   = $false                    # Enable/disable
$SK_Email_Server    = 'smtp.office365.com'
$SK_Email_Port      = 587
$SK_Email_TLS       = $true
$SK_Email_From      = 'alerts@yourdomain.com'
$SK_Email_To        = 'alerts@yourdomain.com'
$SK_Email_User      = 'alerts@yourdomain.com'
$SK_Email_Pass      = ''                        # Microsoft app password

# SYSLOG
$SK_Syslog_Enabled  = $false
$SK_Syslog_Server   = ''                        # e.g. '192.168.1.100'
$SK_Syslog_Port     = 514
$SK_Syslog_Protocol = 'UDP'                     # UDP or TCP
$SK_Syslog_Facility = 16                        # 16 = local0

# MALWAREBAZAAR
$SK_MalwareBazaar_Enabled = $true
$SK_MalwareBazaar_ApiKey  = ''

# ACCOUNT MANAGEMENT
$SK_AutoDisableInactiveAccounts = $false
$SK_AutoDisableThresholdDays    = 547           # 18 months
$SK_AutoDisableOnServers        = $false

# SCAN DEPTH
$SK_ScanDepth = 'Compliance'                    # Standard, Deep, or Compliance

# DISK SAFETY
$SK_MinFreeSpaceGB   = 2.0                      # Warn and reduce scope
$SK_AbortFreeSpaceGB = 0.5                      # Abort run

# MODE
$SK_Mode = 'Auto'                               # Auto, Workstation, or Server
```

---

## System Requirements

- **PowerShell Version:** 3.0 or higher (tested through 7.x)
- **Privileges:** Administrator-level access required
- **OS:** Windows Vista SP1 or later (typically Windows 7 SP1+)
- **Network:** Optional (for dynamic IOC downloads)

---

## Output & Logging

- **Log Directory:** `C:\ProgramData\ShellKnight\Logs\`
- **Log File Format:** `ShellKnight_YYYY-MM-DD_HHMM.log`
- **Cache Directory:** `C:\ProgramData\ShellKnight\Intel\`
- **JSON Reports:** `C:\ProgramData\ShellKnight\JSON\`

### Log Levels

| Level | Purpose | Console Output |
|-------|---------|-----------------|
| SUCCESS | Successful remediation action | Green |
| WARN | Non-critical warning | Yellow |
| FAILED | Remediation/scan failure | Red |
| IOC | Indicator of Compromise detected | Magenta |
| INFO | Informational message | Log-only |

### Exit Codes

- **0** – Clean / Success
- **1** – Errors encountered
- **2** – IOC Alerts present

---

## PUP/PUA Detection Coverage (v0.73)

**Categories:**
- PDF converter toolbars and hijackers
- Browser hijackers (OneStart, Babylon, Conduit, Delta Homes, etc.)
- Search engine hijackers (WebCompanion, SafeFinder, Trovi, etc.)
- Fake optimizers and scareware (PCCleanerPro, AdvancedSystemCare, etc.)
- Driver updaters (DriverBooster, SlimDrivers, etc.)
- Rogue security products (SpyHunter, ByteFence, Segurazo, TotalAV)
- Riskware and activation tools (KMSPico, KMSAuto)
- Modern PUA additions (PulseBrowser, BrightData, BlazerBrowser, ShiftBrowser, EpiBrowser, etc.)

---

## Notable Features (v0.73)

- **Fixed LegitProcessNames StrictMode error** – Moved definition before Phase 3
- **Expanded PUA targets** – Added 13 new browser and software variants
- **Torrent client flagging** – WARN-level in Phase 19 (report-only, not auto-removed)
- **Account management** – Optional auto-disable for inactive local accounts with age threshold
- **Ransomware canary whitelisting** – Protects known legitimate .enc files
- **Stale profile reporting** – .NET framework profiles excluded
- **Hosts whitelist refinement** – iDRAC entries suppressed

---

## Version History Highlights

| Version | Key Changes |
|---------|------------|
| v0.73 | Fixed StrictMode, expanded PUA targets, account management, ransomware canary whitelisting |
| v0.72 | Scan depth framework, low-disk failsafe, phases 22-28 (advanced auditing) |
| v0.71 | AV deduplication, MalwareBazaar improvements, console noise reduction |
| v0.70 | Path restructure, MalwareBazaar Auth-Key support, Datto AV/RMM/EDR detection fixes |
| v0.69 | Config block, email/syslog integration, PUA expansion |
| v0.61 | MalwareBazaar API, Event 7045 extraction, early crash trap |
| v0.60 | SMTP job timeout (20s), prevents hanging |
| v0.59 | Email attachment fix, Zoom false-positive fix, LegitTaskPaths whitelist |
| v0.58 | System.Web.HttpUtility fix for PS5 |
| v0.57 | HTML email reports, professional formatting |
| v0.40 | Full PowerShell-native rewrite (no sc.exe/cmd.exe/WMI) |

---

## Usage

1. **Review and customize** the configuration section at the top
2. **Deploy** to target systems with Administrator privileges
3. **Execute:**
   ```powershell
   .\shellknight\ v073.ps1
   ```
4. **Monitor** logs in `C:\ProgramData\ShellKnight\Logs\`
5. **Review** JSON report and optional email summary

---

## Enterprise Integration

- **Email Reports:** Configure SMTP credentials for automated reporting to SOC/ticket systems
- **Syslog Output:** Forward events to centralized logging/SIEM (RFC3164 format)
- **MalwareBazaar API:** Register free API key at [bazaar.abuse.ch](https://bazaar.abuse.ch) for enhanced hash lookups
- **Scheduled Execution:** Integrate with RMM, Group Policy, or scheduled tasks for regular runs

---

## Links & References

- **MalwareBazaar API:** https://bazaar.abuse.ch/api/
- **Neo23x0 Signature Database:** https://github.com/Neo23x0/signature-base
- **Source Repository:** [GitHub - cdburgess75/ShellKnight](https://github.com/cdburgess75/ShellKnight)

---

## Author

**Dave**

**License & Support:**  
See repository for detailed licensing and support information.

---

*ShellKnight is Sweeping!*

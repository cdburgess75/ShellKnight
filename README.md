<!-- LOGO (auto switches for GitHub light/dark mode) -->
<p align="center">
  <picture>
    <source srcset="assets/sk-logo-light.png" media="(prefers-color-scheme: dark)">
    <img src="assets/sk-logo-light.png" width="600">
  </picture>
</p>

<div align="center">
  <p><strong>Enterprise Endpoint Security & Remediation Tool</strong></p>

  <img src="https://img.shields.io/badge/PowerShell-3.0%2B-blue?style=for-the-badge" alt="PowerShell"/>
  <img src="https://img.shields.io/badge/Version-1.03-success?style=for-the-badge" alt="v1.03"/>
  <img src="https://img.shields.io/badge/Platform-Windows-0078D4?style=for-the-badge" alt="Windows"/>
  <img src="https://img.shields.io/badge/RMM-Datto%20%7C%20CentraStage-orange?style=for-the-badge" alt="Datto"/>
  <img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge" alt="MIT"/>

  <br><br>
  <strong>Automated removal of PUPs, browser hijackers, adware, and malware persistence mechanisms.<br>
  Built for MSPs, IT Administrators, and Security Professionals.</strong>
</div>

---

## What is ShellKnight?

ShellKnight is a fully silent, headless PowerShell endpoint remediation tool designed for MSP and RMM deployment. It runs 29 intelligent phases covering everything from PUP removal and malware IOC detection to hardening checks, compliance assessments, and security grading — all without any user interaction.

Built and maintained by **C. David Burgess — PTech LLC**.

---

## Contents

1. [Features](#features)
2. [Phase Overview](#phase-overview)
3. [Quick Start](#quick-start)
4. [Configuration](#configuration)
5. [Output & Reporting](#output--reporting)
6. [Grading System](#grading-system)
7. [RMM Deployment](#rmm-deployment)
8. [Requirements](#requirements)
9. [Version History](#version-history)

---

## Features

- **29-phase intelligent remediation pipeline**
- Dynamic IOC downloads from [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base)
- MalwareBazaar SHA256 hash lookup with API key support
- Multi-layered AV/EDR detection — Datto AV, Huntress EDR, Windows Defender, COMODO, N-able, and more
- Remote access tool full inventory — ScreenConnect (all instances), TeamViewer, AnyDesk, MeshAgent, and more
- **[RISKWARE-RAT]** classification for tools actively exploited in ransomware attack chains
- Security & Performance A–F grading with delta reporting (compares to last run)
- HIPAA Technical Safeguards assessment when healthcare software is detected
- CJIS compliance checks when law enforcement software is detected
- CIS Benchmark Lite (Level 1) — 9 key controls checked every run
- PowerShell script block logging — enables 4104 auditing and scans for obfuscation
- Windows Defender threat history and automatic Quick Scan on IOC detection
- Phase progress indicator — real-time elapsed time per phase
- Stale profile detection with optional safe auto-deletion
- Inactive account auto-disable with configurable threshold and server protection
- Age-based temp file cleanup — only removes files older than configurable threshold
- Large file finder — flags Outlook OST/PST issues, ISO files, unexpected large files
- SMBv1, LLMNR, NetBIOS, NLA — detect and optionally auto-remediate
- ScreenConnect rogue instance detection and removal
- JSON output per run for fleet trend tracking
- Zero dependencies — pure PowerShell, no external modules required
- PowerShell 3.0 – 7.x compatible

---

## Phase Overview

| Phase | Name | Description |
|-------|------|-------------|
| 0 | Hardware & OS Detection | System profiling, EOL detection, hardware age |
| 1 | Dynamic Intelligence | Downloads latest hash, filename, and C2 IOCs from Neo23x0 |
| 2 | Machine Assessment | Full health check, AV detection, uptime, BitLocker |
| 3 | Process Termination | Kills PUP and adware processes |
| 4 | Filesystem Cleanup | Removes PUP folders, drop-location EXEs |
| 5 | Browser Extension Removal | Removes hijacker extensions |
| 6 | Registry Uninstall | Removes PUP registry entries |
| 7 | Service Removal | Removes PUP and malware services |
| 8 | Scheduled Task Removal | Removes malicious scheduled tasks |
| 9 | Run Key Cleanup | Removes malicious Run/RunOnce registry keys |
| 10 | Startup Folder Cleanup | Removes malicious LNK startup entries |
| 11 | Browser Policy Cleanup | Removes forced browser policy keys |
| 12 | Defender Exclusion Cleanup | Removes suspicious Defender exclusions |
| 13 | Hosts File Inspection | Detects C2 and hijacker domains in hosts file |
| 14 | WMI Persistence Audit | Detects WMI-based malware persistence |
| 15 | Trojan/Malware IOC Detection | RAT/stealer folder and filename IOC hunting |
| 15b | RiskWare/Exploit/ScreenConnect | GameHack, CoinMiner, Dell CVE, rogue SC removal |
| 16 | Reboot Check | Detects pending reboots from CBS/registry |
| 17 | MalwareBazaar Hash Lookup | SHA256 analysis — MalwareBazaar → Neo23x0 → Defender |
| 18 | Disk Space Cleanup | Temp, caches, CBS logs, WER, prefetch, thumbnails |
| 19 | Recent Software Report | Last 30 days installs with torrent/PUP flagging |
| 20 | Temp File Age Report | Flags neglected temp folders |
| 21 | Event Log IOC Check | Event 7045 service install audit |
| 22 | Hardening Checks | Password policy, RDP/NLA, SMBv1, LLMNR, NetBIOS, auditing |
| 23 | USB/Removable Media Audit | Detects removable storage activity |
| 24 | Network Connection Audit | Reviews active network connections |
| 25 | Ransomware Canary | Detects encrypted file extension patterns |
| 26 | Windows Update Check | Pending updates with KB titles and severity |
| 27 | Stale Profile Report | Inactive profiles with optional safe deletion |
| 28 | Trend Tracking | Compares grades to previous run JSON |
| 29 | Extended Checks | Large files, browser creds, N-able detection, HIPAA, CJIS, CIS, magic bytes, Defender history |

---

## Quick Start

**Run directly from GitHub — paste into an elevated PowerShell prompt:**

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force; $f="$env:TEMP\ShellKnight.ps1"; irm https://raw.githubusercontent.com/cdburgess75/ShellKnight/main/ShellKnight.ps1 -OutFile $f; & $f
```

**Or if already on disk:**

```powershell
# Run as Administrator
Set-ExecutionPolicy Bypass -Scope Process -Force
.\ShellKnight.ps1
```

Output is written to:
- **Log:** `C:\ProgramData\ShellKnight\Logs\ShellKnight_YYYY-MM-DD_HHMM.log`
- **JSON:** `C:\ProgramData\ShellKnight\JSON\ShellKnight_YYYY-MM-DD_HHMM_HOSTNAME.json`

---

## Configuration

All configuration is at the top of the script in clearly labeled sections. No external config files needed.

```powershell
# --- EMAIL ALERTS ---
$SK_Email_Enabled         = $false
$SK_Email_Server          = 'smtp.office365.com'

# --- MALWAREBAZAAR ---
$SK_MalwareBazaar_Enabled = $true
$SK_MalwareBazaar_ApiKey  = 'your-api-key-here'

# --- SCAN DEPTH ---
$SK_ScanDepth             = 'Standard'   # Standard, Deep, Compliance

# --- HARDENING OPTIONS ---
$SK_DisableSMBv1          = $false   # Auto-disable SMBv1 when found
$SK_DisableLLMNR          = $false   # Disable LLMNR via registry
$SK_EnforceRDP_NLA        = $false   # Enforce NLA on RDP
$SK_DisableNetBIOS        = $false   # Disable NetBIOS on all adapters

# --- ACCOUNT MANAGEMENT ---
$SK_AutoDisableInactiveAccounts = $false   # Auto-disable inactive accounts
$SK_AutoDisableThresholdDays    = 547      # 18 months default
$SK_AutoDisableOnServers        = $false   # Never auto-disable on servers

# --- STALE PROFILE DELETION ---
$SK_DeleteStaleProfiles         = $false   # Auto-delete stale profiles
$SK_DeleteStaleProfileDays      = 1095     # 3 years default

# --- SCREENCONNECT ---
$SK_ScreenConnect_InstanceID    = ''       # Your managed SC instance ID
$SK_RemoveRogueScreenConnect    = $true    # Remove non-matching AppData instances
```

---

## Output & Reporting

### Screen Output
| Tag | Color | Meaning |
|-----|-------|---------|
| `[SUCCESS]` | Green | Action completed successfully |
| `[WARN]` | Yellow | Needs attention, no action taken |
| `[FAILED]` | Red | Action attempted but failed |
| `[IOC]` | Magenta | Indicator of compromise — analyst review required |
| `[HARDEN]` | Cyan | Hardening action applied |
| `[RISKWARE-RAT]` | Magenta | Remote access tool exploited in ransomware chains |

### Exit Codes
| Code | Meaning |
|------|---------|
| 0 | Clean — no issues found |
| 1 | Errors or failed actions |
| 2 | IOC alerts present — analyst review required |

---

## Grading System

ShellKnight assigns A–F grades for Security and Performance.

### Security Grade Deductions
| Finding | Deduction |
|---------|-----------|
| IOC found | -15 each (max -50) |
| No AV detected | -25 |
| Defender disabled | -20 |
| OS End of Life | -20 |
| SMBv1 enabled | -20 |
| BitLocker off | -15 |
| Windows Update stale | -15 |
| RDP without NLA | -15 |
| Password minimum 0 | -20 |
| Password under 8 | -10 |
| Password under 12 | -5 |

### Performance Grade Deductions
| Finding | Deduction |
|---------|-----------|
| Disk < 5 GB free | -40 |
| Disk < 10 GB free | -25 |
| RAM < 4 GB | -30 |
| Uptime > 60 days | -20 |
| PC age > 5 years | -15 |

---

## RMM Deployment

### Datto RMM / CentraStage

1. Upload `shellknight.ps1` as a Component
2. Set execution policy: `-ExecutionPolicy Bypass`
3. Run as: `SYSTEM`
4. Capture stdout for report review
5. Check exit code — alert on `2` (IOC present)

ShellKnight is fully silent and headless — no user interaction, no popups, no reboots triggered automatically.

---

## Requirements

- Windows 7 / Server 2008 R2 or later
- PowerShell 3.0 or later
- Administrator / SYSTEM privileges
- Internet access for Phase 1 Intel download (falls back to hardcoded IOCs if unavailable)

---

## Version History

| Version | Date | Highlights |
|---------|------|------------|
| v1.03 | May 2026 | PS 3.0/4.0 compatibility (`::new()` → `New-Object`), `??` operator fix, ErrorActionPreference stabilized, Phase 6 null-guard |
| v1.02 | May 2026 | Log-Fail counter fix, remote access matching fix, Executive Summary on screen |
| v1.01 | May 2026 | Ground-up 8-engine rewrite — Intel, Assessment, Hardening, Process, Persistence, Filesystem, Detection, Reporting |
| v0.79 | May 2026 | Phase progress indicator, CIS Benchmark Lite, startup impact classification |
| v0.78 | May 2026 | Defender integration, PS script block audit, magic bytes audit, HIPAA/CJIS checks, WU names |
| v0.77 | May 2026 | Risk delta reporting, large file finder, browser credential check, N-able detection, HIPAA/acceptable use |
| v0.76 | May 2026 | SMBv1/LLMNR/NLA/NetBIOS auto-remediation, MBSetup/PCDr whitelists, COMODO detection |
| v0.75 | May 2026 | RiskWare detection (GameHack/CoinMiner/Dell CVE), SC AppData scan, 31 new PUA targets |
| v0.74 | May 2026 | Hardening action separation, stale profile deletion, age-based temp cleanup, score improvements |
| v0.73 | May 2026 | Account auto-disable, 14 new PUA targets, ransomware/hosts/profile whitelists |
| v0.72 | May 2026 | Scan depth framework, low disk failsafe, Phases 22-28, performance cap |
| v0.71 | May 2026 | AV dedup, Dell CPM WMI whitelist, simplified header, INFO suppressed from screen |
| v0.70 | May 2026 | Path restructure, MalwareBazaar Auth-Key, Datto AV service names fixed |
| v0.69 | May 2026 | Top-of-file config, email/syslog wired, PUA expansion, Before/After summary |
| v0.68 | May 2026 | ShellKnight rename, full health assessment, A-F grading, JSON output |

Full changelog: [CHANGELOG.md](CHANGELOG.md)

---

## Author

**C. David Burgess**


---

⭐ If ShellKnight helps you keep machines clean, please star this repository!

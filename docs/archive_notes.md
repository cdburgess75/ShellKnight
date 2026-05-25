<div align="center">

<img src="CleanSweep.png" alt="Dave's CleanSweep Logo" width="160"/>

# Dave's CleanSweep

**Enterprise PUP, Adware & Malware IOC Remediation Tool**  
*Automated. Silent. RMM-Ready.*

[![Version](https://img.shields.io/badge/version-v0.66-blue?style=flat-square)](https://github.com/cdburgess75/cleansweep/releases)
[![PowerShell](https://img.shields.io/badge/PowerShell-3.0%2B-5391FE?style=flat-square&logo=powershell)](https://docs.microsoft.com/en-us/powershell/)
[![Platform](https://img.shields.io/badge/platform-Windows-0078D6?style=flat-square&logo=windows)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)

</div>

---

## What is CleanSweep?

Dave's CleanSweep is a fully automated, silent PowerShell remediation tool built for MSP/RMM deployment. It scans and cleans Windows endpoints across 22 phases — removing PUPs, browser hijackers, adware, malware persistence mechanisms, and collecting actionable intelligence — all without any user interaction or pop-ups.

Designed for real-world MSP use: tested across Windows 10, Windows 11, Windows Server 2012 R2 through 2022, PowerShell 4.0+.

---

## ✨ Key Features

- **22-phase remediation pipeline** — process termination through event log IOC analysis
- **Live threat intelligence** — downloads Neo23x0 signature-base IOCs on every run (hash, filename, C2)
- **Dynamic IOC matching** — 3,800+ filename patterns compiled into memory-safe chunked regex
- **Professional reporting** — machine info, removed items, IOC alerts, recently installed software, metrics summary
- **Verdict banners** — `Clean Sweep!` or `Dave is Sweeping!` at the bottom so you know instantly
- **RMM-native** — fully headless, no user interaction, exit codes 0/1/2 for automation
- **Server-aware** — skips workstation-only operations on Server OS, handles PS 4.0 compatibility

---

## 🛡️ What It Detects & Removes

| Category | Examples |
|----------|---------|
| Browser hijackers | WaveBrowser, SafeFinder, Trovi, Vosteran, Conduit |
| PUPs & adware | PDFtool, OpenCandy, Superfish, InstallCore, Amonetize |
| Malware persistence | Scheduled tasks, Run/RunOnce keys, startup LNKs, WMI subscriptions |
| Trojan indicators | njRAT, AsyncRAT, Cobalt Strike, RedLine, Emotet, TrickBot (folder IOCs) |
| Browser policy hijacks | Forced extensions, managed Chrome/Edge policy keys |
| Defender exclusion abuse | Unauthorized Defender exclusions added by malware |
| Hosts file tampering | C2 domains injected into hosts file |
| Drop-location EXEs | Executables in `%TEMP%`, `C:\Users\Public` |
| Suspicious services | Services installed from user temp or AppData paths |

---

## 🔄 22-Phase Pipeline

| Phase | Description |
|-------|-------------|
| 0 | Hardware & OS detection — sets capability flags |
| 1 | Dynamic intel download (Neo23x0 hash, filename, C2 IOCs) |
| 2 | Machine information block |
| 3 | Process termination |
| 4 | Filesystem artifact cleanup |
| 5 | Browser extension artifact removal |
| 6 | Registry uninstall cleanup |
| 7 | Service removal |
| 8 | Scheduled task removal |
| 9 | Run/RunOnce key cleanup |
| 10 | Startup folder LNK cleanup |
| 11 | Browser policy key cleanup |
| 12 | Defender exclusion cleanup |
| 13 | Hosts file inspection & C2 cleanup |
| 14 | WMI persistence audit |
| 15 | Trojan/malware IOC detection |
| 16 | Reboot requirement check |
| 17 | MalwareBazaar hash lookup + Neo23x0 + Defender fallback |
| 18 | Disk space cleanup (temp, WU cache, prefetch, CBS, WER) |
| 19 | Recently installed software report (last 30 days) |
| 20 | Temp file age report |
| 21 | Event log IOC check (4688 process creation, 7045 service install) |

---

## 📋 Requirements

- **OS:** Windows 7 SP1 / Server 2008 R2 or newer
- **PowerShell:** 3.0+ (5.1 recommended)
- **Privileges:** Administrator (required)
- **Network:** Optional — downloads live IOC intel on each run, falls back to disk cache or hardcoded patterns if offline

---

## 🚀 Usage

### Direct execution
```powershell
.\cleansweep.ps1
```

### RMM / Datto / CentraStage deployment
Deploy as a script component with administrator context. No parameters required. Fully silent.

### Exit codes
| Code | Meaning |
|------|---------|
| `0` | Clean — nothing detected |
| `1` | Completed with errors |
| `2` | IOC alerts present — analyst review recommended |

---

## 📁 Output

| Path | Contents |
|------|----------|
| `C:\ProgramData\Logs\DavesCleanSweep\` | Run logs (`DavesCleanSweep_YYYY-MM-DD_HHMM.log`) |
| `C:\ProgramData\Logs\DavesCleanSweep\Intel\` | Cached IOC lists from Neo23x0 |

---

## 📧 Email Reporting (Optional)

CleanSweep can send an HTML report with the full log attached after every run. Configure SMTP in the `$Script:Config` block at the top of the script:

```powershell
SmtpServer  = 'smtp.office365.com'
SmtpPort    = 587
SmtpUseTLS  = $true
SmtpFrom    = 'cleansweep@yourdomain.com'
SmtpTo      = 'you@yourdomain.com'
SmtpUser    = 'cleansweep@yourdomain.com'
SmtpPass    = 'your-app-password'
```

> **Note:** Office 365 requires SMTP AUTH enabled on the sending mailbox.  
> Microsoft 365 Admin Center → Users → Active Users → [user] → Mail → Manage email apps → Authenticated SMTP ✓

---

## 🔍 Sample Report Output

```
================================================================================
  Dave's CleanSweep v0.66 - Report
  Hostname  : WORKSTATION01
  Run Date  : 2026-05-09 10:02:55
  Runtime   : 37.1 seconds
================================================================================
  REMOVED SUCCESSFULLY (3 ITEMS)
  [+] Cleaned Prefetch  -  Before: 22 files / 0.2 MB | Freed: 0.2 MB
  [+] Cleaned CBS Logs  -  Before: 1 files / 0.8 MB | Freed: 0.8 MB
  [+] Cleaned User Temp (user)  -  Before: 9 files / 2.7 MB | Freed: 0 MB

  IOC ALERTS - ANALYST REVIEW REQUIRED (1 ITEMS)
  [!] Event 7045 suspicious (19x) - Service: eapihdrv | Path: C:\Users\...\Temp\ehdrv.sys

  ############################################################################
  #                                                                          #
  #                   Clean Sweep!  -  This machine is clean.                #
  #                                                                          #
  ############################################################################
```

---

## 🚧 Roadmap

- [ ] Before/After executive summary in report
- [ ] HTML email report with professional layout
- [ ] Detection scoring system (0–100 risk score per machine)
- [ ] Config-driven cleanup profiles (workstation / server / kiosk)
- [ ] Integration hooks (EDR / SIEM structured JSON output)
- [ ] GitHub Actions CI for syntax validation

---

## ⚠️ Safety Notice

CleanSweep performs system-level modifications including registry changes, scheduled task removal, service removal, and file system cleanup. Conservative matching is used for all destructive operations to minimize false positives.

**Always test in a controlled environment before broad deployment.**

Recycle Bin is never touched. User data is never removed. All destructive actions are logged.

---

## 📜 Changelog Highlights

| Version | Key Changes |
|---------|-------------|
| v0.66 | Phase 21 server performance fix, Citrix whitelist, wuauserv aggressive stop |
| v0.65 | Fixed Write-Log operator precedence bug (log file was empty since v0.63) |
| v0.64 | Fixed svcGroups .Count StrictMode crash, Encode-Html recursion bug |
| v0.63 | Fixed closed TextWriter error, LogReady flag |
| v0.62 | Fixed Phase 16 PendingFileRenameOperations, Server 2016 TLS, event 7045 dedup |
| v0.61 | Fixed OutOfMemoryException on regex (HashSet + chunked), early crash trap |
| v0.60 | Email background job with hard timeout |
| v0.57 | HTML email report with log attachment |
| v0.47 | Dynamic Neo23x0 intel, Phase 0 hardware detection, 22-phase architecture |

Full changelog in script header.

---

## 👤 Author

**C. David Burgess**  
[PTech LLC](https://ptechllc.com) — Managed IT Services  
dave@ptechllc.com

---

<div align="center">
<sub>Built for MSPs. Tested in the field. Improved one bug at a time.</sub>
</div>

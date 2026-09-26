# 0010: OS end of life is Microsoft's date for the build and edition; ESU does not extend it

**Status:** Accepted

**Date:** 2026-09-25

## Context

ShellKnight reports `os_eol` for every device: `END OF LIFE (since <date>)`, `Supported until
<date>`, or `Unknown`. Battlefield prints it in two places:

- **The customer report.** `bf/report.py` counts a host as supported unless the string contains
  `END OF LIFE`. The report's "every operating system is within its supported lifetime" positive
  depends on that count.
- **The device page.**

From v2026.09.25.001 an end-of-life OS also costs the device 20 points.

Until v2026.09.25.003 the date came from a table keyed by build number alone, with one date per
build. That design had two problems.

**The dates were wrong.** Several were years past Microsoft's:

| Build | Table said | Microsoft |
|---|---|---|
| 19045 (Windows 10 22H2) | 2030-10-14 | 2025-10-14 |
| 22621 (Windows 11 22H2) | 2027-10-12 | 2024-10-08 (Home/Pro), 2025-10-14 (Enterprise/Education) |
| 22631 (Windows 11 23H2) | 2028-10-10 | 2025-11-11 (Home/Pro), 2026-11-10 (Enterprise/Education) |

**One date per build cannot be right.**

- **Home/Pro and Enterprise/Education are serviced for different lengths.** On Windows 11,
  Home/Pro gets 24 months and Enterprise/Education gets 36.
- **Some builds are several products at once:**
  - 14393, 17763, 19044 and 26100 are each also an LTSB/LTSC release;
  - 14393, 17763 and 26100 are also Windows Server 2016, 2019 and 2025;
  - 7601, 9200 and 9600 are both a client and a server release.
- **The dates within one build can be years apart.** Build 26100 ends on:
  - 2026-10-13 for Windows 11 24H2 Home/Pro;
  - 2027-10-12 for 24H2 Enterprise/Education;
  - 2029-10-09 for Enterprise LTSC 2024;
  - 2034-10-10 for IoT Enterprise LTSC 2024;
  - 2034-11-14 for Windows Server 2025.

**Windows 10 ended on 2025-10-14, for every edition.** Microsoft sells Extended Security Updates
(ESU) past that date.
- **Commercial ESU** is licensed per device, in one-year terms ending 2026-10-13, 2027-10-12 and
  2028-10-10. It covers Pro, Enterprise and Education in commercial use, on 22H2 only.
- **Consumer ESU** is documented only outside Microsoft Learn; the Learn ESU pages send home users
  to microsoft.com. Nothing here relies on its terms.
- **Windows 365 and Azure-hosted Windows 10** get ESU without a key.

## Decision

**The date is Microsoft's, looked up by build *and* edition.**
- `Get-OsEolDate` holds one row per build, with a date for each edition family that build ships as:
  - Home/Pro;
  - Enterprise/Education;
  - LTSB/LTSC;
  - IoT Enterprise LTSC;
  - Server.
- The source is Microsoft Learn:
  - the release-health pages for Windows 10, Windows 11 and Windows Server;
  - `learn.microsoft.com/lifecycle/products/...` for retired versions, LTSB/LTSC and Server.
- **Which date a row holds:**
  - GA-channel versions use their end-of-servicing date.
  - LTSB/LTSC and Server use their end of extended support.
  - The date is the Patch Tuesday of the last update. The lifecycle pages show it as the next day
    at 6:59:59 AM.
- **The edition families follow Microsoft's own edition lists.**
  - Home/Pro includes Pro Education, Pro for Workstations and SE.
  - Enterprise/Education includes IoT Enterprise (GA channel) and Enterprise multi-session.

**The edition comes from `Win32_OperatingSystem.Caption`.**
- The caption is tested in this order:
  1. `Server`;
  2. `LTSB`/`LTSC`, split by `IoT`;
  3. the words `Pro`, `Home` or `SE`;
  4. `Enterprise` or `Education`.
- The order matters. An LTSC caption also says Enterprise, and "Pro Education" is on the Home/Pro
  timeline.

**A caption that cannot be placed is given a date only when the date is true whatever the edition
is.**
- This covers a localized caption and an edition the build does not ship as.
- The lookup considers every edition the machine could be, on its side of the client/server line.
  - If they all share one date, it uses that date.
  - If they have all ended, it uses the latest date.
  - Otherwise the result is `Unknown`, which is not scored.
- This is [ADR 0009](0009-customer-facing-security-score.md) applied to edition detection. Failing
  to identify the edition must never cost a device points.

**Windows 10 ESU does not extend end of life.** A Windows 10 22H2 device reports `END OF LIFE (since
2025-10-14)` and takes the -20, whether or not it is enrolled in ESU. The same rule already applied
to Windows 7, Server 2008 R2 and Server 2012/2012 R2, which all had ESU.

- **This is Microsoft's own position.** Windows 10 reached end of support on 2025-10-14. ESU is a
  paid bridge with a fixed end, and it carries security fixes only. The score asks whether the OS
  is supported, and for Windows 10 the answer is no.
- **ESU is a licence on one device, not a fact about the OS.**
  - To see it, ShellKnight would need a new licensing probe.
  - Microsoft documents `slmgr /dlv` with the ESU activation IDs for commercial MAK activation.
  - It documents no local check for consumer ESU, and none for the Windows 365 and Azure grants.
  - So a probe would score two identical devices differently, depending only on how their ESU was
    bought.
- **An exemption would make the penalty depend on a probe.** A device whose ESU check failed or
  could not see its licence would lose the 20 points. That is a collection failure moving a risk
  score, which ADR 0009 rules out.
- **Timing.** Commercial ESU Year 1 ends on 2026-10-13, 18 days after this decision. An exemption
  for it would expire about when it shipped. Only paid Year 2 and Year 3 licences would benefit.

## Consequences

**Good:**

- The report and the score now agree with the dates Microsoft publishes. The PR that makes this
  change lists every date and its source, and `tests/Test-OsEol.ps1` pins them.
- **A server or LTSC build is no longer given a client's date, and a client is no longer given
  theirs.**
  - Server 2016 and Server 2019 keep their later dates.
  - Windows 10 1607/1809 Pro no longer reports "supported until 2027/2029".
  - Windows 11 24H2 Pro no longer reads 2029-10-14; its date is 2026-10-13.
- A misread edition can only cost the device a date. It can never cost it points.

**Bad:**

- **More devices take the -20 from the day this ships:**
  - every Windows 10 22H2 device;
  - every Windows 11 22H2 device;
  - Windows 11 23H2 Home/Pro;
  - the GA-channel releases of Windows 10 21H2, 1809 and 1607, and of Windows 11 21H2;
  - Windows Server 23H2 (build 25398), which the old table did not know.

  The calendar then adds more:
  - Windows 11 24H2 Home/Pro and Windows 10 2016 LTSB on 2026-10-13;
  - Windows 11 23H2 Enterprise/Education on 2026-11-10;
  - Windows 10 Enterprise LTSC 2021 and Windows Server 2016 on 2027-01-12.

  Grades will drop with no change on the endpoints, so explain this before a scorecard goes out.
- **An ESU-enrolled Windows 10 device loses 20 points and shows END OF LIFE.** That device is
  receiving security updates. Its patch state is still visible in the Windows Update field and
  rule.
- **Every new Windows release needs a table row.** Until it gets one, the device reads `Unknown` and
  is not scored. `Test-OsEol` checks that every date is a Patch Tuesday, which catches most typos.
- **The caption can be localized.** On a non-English Windows, devices fall back to the
  unplaced-caption rule and read `Unknown` more often. The PR's impact query shows each device's
  edition family, so an unplaced caption in the fleet shows up as an empty `family`.

**Revisit ESU if ParaTech sells ESU Year 2 or Year 3 (after 2026-10-13) to a customer.**
- Detect the commercial licence by its documented activation ID and report it as its own field.
- Only then decide whether a detected licence should soften the score, weighing that against the
  probe-dependence argument above.

## Alternatives considered

### Treat ESU-eligible Windows 10 as supported until the ESU end date

Rejected. Most Windows 10 devices are not enrolled. It would hide the largest end-of-life population
in the fleet behind a licence nobody bought.

### Detect ESU and exempt enrolled devices

Rejected for now, for the reasons under **Decision**:
- consumer ESU and the Windows 365 and Azure grants cannot be seen locally;
- a failed probe would cost points;
- an exemption for Year 1 licences would expire on 2026-10-13.

### Keep one date per build, choosing the latest or the earliest

Rejected, because both choices are wrong for some devices.
- **The latest date** puts every Windows 11 24H2 Pro device on Server 2025's 2034 date.
- **The earliest date** takes 20 points from every Server 2016 and 2019 box, and from every LTSC
  device.

### Detect the edition from `OperatingSystemSKU` instead of the caption

Deferred.
- **For:** the SKU number is documented and not localized.
- **Against:**
  - The mapping is long: every N, evaluation and IoT variant has its own number.
  - The fleet is expected to be English-language, and the impact query shows whether it is.
  - A caption that cannot be placed already falls back to a date that is safe for every edition.

It is the natural next step if non-English devices appear.

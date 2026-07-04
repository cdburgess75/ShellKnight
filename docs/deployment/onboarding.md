# Onboarding a device / site to Battlefield

This is the **one and only** time Datto (or any RMM) is involved. After the
bootstrap run, the device self-schedules and reports on its own — no agent, no
service, no further RMM dependency. See ADR 0007 (self-scheduling) and ADR 0008
(pull-queue remediation).

## How it works

1. Datto runs the **bootstrap component** once on the device.
2. The component runs `ShellKnight.ps1` with the site's Battlefield key in the
   environment.
3. ShellKnight writes `C:\ProgramData\ShellKnight\config.json` (Battlefield URL,
   key, 8h cadence) and creates a native Windows Scheduled Task **"ShellKnight"**
   (every 8 hours, per-device jitter, runs as SYSTEM, always downloads latest).
4. From then on, the Scheduled Task re-runs ShellKnight on cadence. Each run
   posts its report to Battlefield and pulls any queued remediation commands.

Datto is never needed for that device again. The bootstrap can later be moved
from Datto to GPO or Intune without changing anything on the endpoint.

## Steps to onboard a new customer/site

1. **Create the tenant** in Battlefield and note its API key (each customer =
   one tenant = one key).
2. **Datto component**: create/edit a component whose command is
   `deploy/bootstrap-template.ps1`. Add a **masked** component variable
   `BF_APIKEY` set to that site's key. (Per-site: use a Datto *site-level*
   variable so one component serves every customer with the right key.)
3. **Run it once** against the device (or attach to a "new device" policy so new
   machines onboard automatically).
4. **Verify** — the component prints:
   ```
   Scheduled task : PRESENT
   config.json    : PRESENT
   ```
   and the device appears in the Battlefield fleet grid within a few minutes.

## Verifying on the endpoint (optional)

```powershell
schtasks /Query /TN "ShellKnight" /FO LIST          # shows the 8h task
Get-Content C:\ProgramData\ShellKnight\config.json   # URL + cadence (key present)
```

## Changing cadence

Set `SK_SCHEDULE_HOURS` in the bootstrap (or edit `config.json` + re-run). The
cadence also bounds how quickly queued remediation applies (ADR 0008).

## Removing a device

Delete the Scheduled Task (`schtasks /Delete /TN "ShellKnight" /F`) and
`C:\ProgramData\ShellKnight\`. With nothing re-running it, the device goes stale
in Battlefield (flagged after the staleness window) and can be removed there.

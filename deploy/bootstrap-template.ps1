# ==============================================================================
# ShellKnight - Battlefield onboarding (bootstrap)
# ==============================================================================
# Paste this as the command of a Datto RMM component and run it ONCE per device
# (or once via a "new device" policy). It runs ShellKnight a single time with the
# site's Battlefield key; ShellKnight then writes C:\ProgramData\ShellKnight\
# config.json and creates a self-perpetuating Windows Scheduled Task (every 8h).
#
# After this one run the device is fully self-sufficient: it re-runs itself,
# reports to Battlefield, and pulls queued remediation - with NO agent and NO
# further Datto involvement. Re-running the component is harmless (idempotent).
#
# SET PER SITE:
#   BF_APIKEY  - the Battlefield tenant (site) API key. In Datto, store this as a
#                masked component variable named BF_APIKEY so it stays out of git
#                and is masked in the console. Do NOT hardcode a real key here.
# ==============================================================================

[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

# Battlefield settings consumed by ShellKnight on this bootstrap run.
$env:SK_BATTLEFIELD_ENABLED = "1"
$env:SK_BATTLEFIELD_URL     = "https://battlefield.ptechllc.com/api/v1/runs"
$env:SK_BATTLEFIELD_APIKEY  = $env:BF_APIKEY   # from the masked Datto component variable
$env:SK_SCHEDULE_HOURS      = "8"              # cadence for the self-created task

if (-not $env:SK_BATTLEFIELD_APIKEY) {
    Write-Error "BF_APIKEY not set - add it as a masked component variable. Aborting."
    exit 1
}

$f = "$env:windir\Temp\ShellKnight.ps1"
Invoke-RestMethod -Uri "https://raw.githubusercontent.com/cdburgess75/ShellKnight/main/ShellKnight.ps1" -OutFile $f -TimeoutSec 60
& $f

# --- Verify the bootstrap took ---
Write-Host ""
Write-Host "=== Bootstrap verification ==="
$task = schtasks.exe /Query /TN "ShellKnight" /FO LIST 2>$null
if ($task) { Write-Host "Scheduled task : PRESENT" } else { Write-Host "Scheduled task : MISSING (check errors above)" }
if (Test-Path "C:\ProgramData\ShellKnight\config.json") { Write-Host "config.json    : PRESENT" } else { Write-Host "config.json    : MISSING" }
Write-Host "Onboarded. This device is now self-scheduling; Datto is no longer required for it."

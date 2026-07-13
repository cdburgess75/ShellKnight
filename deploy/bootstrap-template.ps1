# ==============================================================================
# ShellKnight - Battlefield onboarding (bootstrap)  -  ONE component, all customers
# ==============================================================================
# Paste this as the command of a SINGLE Datto RMM component and run it once per
# device (or via a "new device" policy). ShellKnight writes
# C:\ProgramData\ShellKnight\config.json and creates a self-perpetuating Windows
# Scheduled Task (every 8h). After that one run the device is self-sufficient -
# NO agent, NO further Datto involvement. Re-running is harmless (idempotent).
#
# ONE SHARED enrollment key onboards EVERY customer. Battlefield auto-creates the
# company from SK_SITE_NAME (or the machine's AD domain if unset); rename it later
# in the Battlefield web UI. No per-customer script, tenant, or key needed.
#
# SET (Datto):
#   BF_ENROLL_KEY - the shared Battlefield enrollment key (Sites page -> Enrollment
#                   key). Store as a masked ACCOUNT variable so every site inherits it.
#   SK_SITE_NAME  - OPTIONAL company name, set as a per-SITE variable for a clean
#                   name up front. If blank, Battlefield uses the AD domain and you
#                   rename in the UI.
# ==============================================================================

[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$env:SK_BATTLEFIELD_ENABLED = "1"
$env:SK_BATTLEFIELD_URL     = "https://battlefield.ptechllc.com/api/v1/runs"
$env:SK_BATTLEFIELD_APIKEY  = $env:BF_ENROLL_KEY   # shared enrollment key (masked Datto var)
$env:SK_SCHEDULE_HOURS      = "8"
if ($env:SK_SITE_NAME) { $env:SK_SITE_NAME = $env:SK_SITE_NAME }  # optional per-site company name

if (-not $env:SK_BATTLEFIELD_APIKEY) {
    Write-Error "BF_ENROLL_KEY not set - add the enrollment key as a masked Datto variable. Aborting."
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
Write-Host "Onboarded. Self-scheduling now; Datto not required. Company appears in Battlefield on first report."

# ==============================================================================
# ShellKnight - Health Check (read-only)
# ==============================================================================
# Confirms a box is actually self-sufficient. Run it from Datto RMM (or a GPO /
# any remote-exec) across the fleet and eyeball the output: it tells you, per
# machine, whether the agentless loop is intact BEFORE the dashboard would
# otherwise show it drifting stale days later.
#
# Checks:            PASS/WARN/FAIL
#   * Scheduled task 'ShellKnight' present + enabled (+ next run time)
#   * config.json present + valid (has Battlefield URL + key; shows site/interval)
#   * Last run recency (newest JSON report vs the configured interval)
#   * Installed version (from the newest JSON report)
#
# Exit code:  0 = healthy   1 = warning(s)   2 = failure(s)
#   (so Datto can flag non-zero results automatically)
#
# This script only READS. It changes nothing and sends nothing.
# ==============================================================================

$Root       = 'C:\ProgramData\ShellKnight'
$ConfigPath = Join-Path $Root 'config.json'
$JsonDir    = Join-Path $Root 'JSON'
$TaskName   = 'ShellKnight'

$fails = 0; $warns = 0
$lines = @()
function Add-Line([string]$state, [string]$label, [string]$detail) {
    $script:lines += ('  [{0}] {1,-22}: {2}' -f $state, $label, $detail)
    if ($state -eq 'FAIL') { $script:fails++ }
    elseif ($state -eq 'WARN') { $script:warns++ }
}

# --- config.json ---------------------------------------------------------------
$cfg = $null
$scheduleHours = 8
if (Test-Path $ConfigPath) {
    try {
        $cfg = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
        $hasUrl = [bool]$cfg.BattlefieldURL
        $hasKey = [bool]$cfg.BattlefieldApiKey
        if ($cfg.ScheduleHours) { $scheduleHours = [int]$cfg.ScheduleHours }
        if ($hasUrl -and $hasKey) {
            $site = if ($cfg.SiteName) { $cfg.SiteName } else { '(none - falls back to domain)' }
            Add-Line 'PASS' 'config.json' "valid  |  site '$site'  |  every ${scheduleHours}h"
        } else {
            Add-Line 'FAIL' 'config.json' 'present but missing Battlefield URL or key -> re-bootstrap'
        }
    } catch {
        Add-Line 'FAIL' 'config.json' "present but unreadable/corrupt -> re-bootstrap ($($_.Exception.Message))"
    }
} else {
    Add-Line 'FAIL' 'config.json' 'MISSING -> never onboarded here; run the install command'
}

# --- scheduled task ------------------------------------------------------------
$taskState = $null; $nextRun = $null
try {
    $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
    $taskState = "$($t.State)"
    try { $nextRun = (Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction Stop).NextRunTime } catch {}
} catch {
    # Fallback for older hosts without the ScheduledTasks module.
    $raw = & schtasks.exe /Query /TN $TaskName /FO LIST /V 2>$null
    if ($LASTEXITCODE -eq 0 -and $raw) {
        $taskState = 'Present'
        $nr = ($raw | Select-String 'Next Run Time:') -replace '.*Next Run Time:\s*', ''
        if ($nr) { $nextRun = "$nr".Trim() }
    }
}
if (-not $taskState) {
    Add-Line 'FAIL' "task '$TaskName'" 'MISSING -> not self-scheduling; re-bootstrap to restore it'
} elseif ($taskState -eq 'Disabled') {
    Add-Line 'FAIL' "task '$TaskName'" 'present but DISABLED -> enable or re-bootstrap'
} else {
    $nr = if ($nextRun) { "next run $nextRun" } else { 'next run unknown' }
    Add-Line 'PASS' "task '$TaskName'" "$taskState, $nr"
}

# --- last run recency + version (from newest JSON report) ----------------------
$newest = $null
if (Test-Path $JsonDir) {
    $newest = Get-ChildItem -LiteralPath $JsonDir -Filter '*.json' -ErrorAction SilentlyContinue |
              Sort-Object LastWriteTime -Descending | Select-Object -First 1
}
if ($newest) {
    $ageH = [math]::Round(((Get-Date) - $newest.LastWriteTime).TotalHours, 1)
    $when = $newest.LastWriteTime.ToString('yyyy-MM-dd HH:mm')
    # Allow up to 2x the interval + a little slack before calling it late.
    $threshold = ($scheduleHours * 2) + 2
    if ($ageH -gt $threshold) {
        Add-Line 'WARN' 'last run' "$when (${ageH}h ago) -> exceeds ${threshold}h; box may be offline or task not firing"
    } else {
        Add-Line 'PASS' 'last run' "$when (${ageH}h ago)"
    }
    $ver = $null
    try { $ver = (Get-Content -LiteralPath $newest.FullName -Raw | ConvertFrom-Json).version } catch {}
    if ($ver) { Add-Line 'PASS' 'installed version' "$ver" }
    else      { Add-Line 'WARN' 'installed version' 'unknown (report had no version field)' }
} else {
    Add-Line 'WARN' 'last run' 'no run reports found yet (has it completed a run?)'
}

# --- verdict -------------------------------------------------------------------
$result = if ($fails) { 'UNHEALTHY' } elseif ($warns) { 'DEGRADED' } else { 'HEALTHY' }
$stamp  = (Get-Date).ToString('yyyy-MM-dd HH:mm')
Write-Host ''
Write-Host "  ShellKnight Health Check  |  $env:COMPUTERNAME  |  $stamp"
Write-Host '  ------------------------------------------------------------------------'
$lines | ForEach-Object { Write-Host $_ }
Write-Host '  ------------------------------------------------------------------------'
Write-Host "  RESULT: $result  ($fails fail, $warns warn)"
Write-Host ''

if ($fails) { exit 2 } elseif ($warns) { exit 1 } else { exit 0 }

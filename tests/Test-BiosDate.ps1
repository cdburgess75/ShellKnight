<#
.SYNOPSIS
    Regression test for ConvertTo-BiosDate.

.DESCRIPTION
    v2026.07.30.001 fixed a bug where Win32_BIOS.ReleaseDate — a DateTime under
    Get-CimInstance — was parsed as the legacy WMI string. The resulting
    MethodNotFound error aborted the entire Assessment Engine four statements
    in, and Invoke-SafeBlock swallowed it as an informational log line, so the
    failure was invisible: the run still completed, still scored, still
    reported. It just reported "NONE DETECTED" for antivirus on every endpoint
    and a null device_id, silently, for as long as it took anyone to notice.

    That is the failure mode this test exists to prevent. It does not need a
    Windows host — ConvertTo-BiosDate is pure, so it runs on the CI Linux
    runner alongside the parse gate.

    ShellKnight.ps1 is a monolith that executes on load, so the function is
    extracted textually rather than dot-sourced.
#>
Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

$scriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'ShellKnight.ps1'
$source = Get-Content -LiteralPath $scriptPath -Raw

# Pull out just `function ConvertTo-BiosDate { ... }` up to its closing brace.
$match = [regex]::Match($source, '(?ms)^function ConvertTo-BiosDate \{.*?^\}')
if (-not $match.Success) {
    throw "ConvertTo-BiosDate not found in ShellKnight.ps1 - did it get renamed or removed?"
}
Invoke-Expression $match.Value

$failures = 0
function Assert-BiosDate {
    param($Input_, $Expected, [string]$Label)
    try {
        $actual = ConvertTo-BiosDate $Input_
    } catch {
        Write-Host "  FAIL  $Label  -  threw: $($_.Exception.Message)" -ForegroundColor Red
        $script:failures++
        return
    }
    if ($actual -isnot [datetime]) {
        Write-Host "  FAIL  $Label  -  returned $($actual.GetType().Name), expected DateTime" -ForegroundColor Red
        $script:failures++
        return
    }
    if ($Expected -and $actual.ToString('yyyy-MM-dd') -ne $Expected) {
        Write-Host "  FAIL  $Label  -  got $($actual.ToString('yyyy-MM-dd')), expected $Expected" -ForegroundColor Red
        $script:failures++
        return
    }
    Write-Host "  ok    $Label" -ForegroundColor Green
}

Write-Host ''
Write-Host '  ConvertTo-BiosDate'
Write-Host '  ------------------------------------------------------------'

# The real-world case: Get-CimInstance hands back a DateTime. This is the one
# that was crashing.
Assert-BiosDate ([datetime]'2020-01-15') '2020-01-15' 'CIM DateTime passes through'

# Legacy Get-WmiObject shape: CIM_DATETIME 'yyyymmddHHMMSS.mmmmmmsUUU'.
Assert-BiosDate '20200115000000.000000+000' '2020-01-15' 'legacy CIM_DATETIME string parses'

# Degenerate inputs must yield a usable date, never throw — an unknown BIOS
# date is worth losing a PC-age estimate, not the whole engine.
Assert-BiosDate $null      $null 'null does not throw'
Assert-BiosDate ''         $null 'empty string does not throw'
Assert-BiosDate 'garbage'  $null 'unparseable string does not throw'
Assert-BiosDate 12345      $null 'unexpected type does not throw'

Write-Host ''
if ($failures -gt 0) {
    Write-Host "  FAILED - $failures assertion(s)" -ForegroundColor Red
    exit 1
}
Write-Host '  PASS - all assertions' -ForegroundColor Green
exit 0

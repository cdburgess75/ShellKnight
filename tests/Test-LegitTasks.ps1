<#
.SYNOPSIS
    Regression test for the scheduled-task allow-list.

.DESCRIPTION
    The Process Engine removes any scheduled task whose command line matches
    its obfuscation pattern unless the command is in LegitTaskPaths. On an
    Azure VM that removed Windows Admin Center's heartbeat and troubleshoot
    tasks, which run PowerShell -WindowStyle Hidden from the Azure extension
    folder. This checks those commands are allowed and that the allow-list
    entry is narrow: the same flags from anywhere else are still caught.

    ShellKnight.ps1 executes on load, so the list and the pattern are
    extracted textually rather than dot-sourced.
#>
Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

$scriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'ShellKnight.ps1'
$source = Get-Content -LiteralPath $scriptPath -Raw

$list = [regex]::Match($source, '(?ms)^\$Script:LegitTaskPaths = @\(.*?^\)')
if (-not $list.Success) { throw 'LegitTaskPaths not found in ShellKnight.ps1' }
Invoke-Expression $list.Value

$pat = [regex]::Match($source, "(?m)^\s*'(encodedcommand\|[^']+)',\s*$")
if (-not $pat.Success) { throw 'Scheduled-task obfuscation pattern not found in ShellKnight.ps1' }
$obfusc = New-Object System.Text.RegularExpressions.Regex -ArgumentList @(
    $pat.Groups[1].Value, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

function Test-Removed([string]$CmdLine) {
    $isLegit = $Script:LegitTaskPaths | Where-Object { $CmdLine -like $_ }
    return [bool]($obfusc.IsMatch($CmdLine) -and -not $isLegit)
}

$failures = 0
function Assert-Removed {
    param([string]$CmdLine, [bool]$Expected, [string]$Label)
    $actual = Test-Removed $CmdLine
    if ($actual -eq $Expected) {
        Write-Host "  PASS  $Label"
    } else {
        Write-Host "  FAIL  $Label  -  removed=$actual, expected $Expected" -ForegroundColor Red
        $script:failures++
    }
}

# Real command lines from an Azure Virtual Desktop session host (2026-10-13).
$wac = 'C:\Packages\Plugins\Microsoft.AdminCenter.AdminCenter\0.76.0.0\Sme.VmExtension'
Assert-Removed "Powershell.exe -WindowStyle Hidden -File `"$wac\HeartbeatCheck.ps1`"" $false 'WAC heartbeat task is kept'
Assert-Removed "Powershell.exe -WindowStyle Hidden -File `"$wac\Troubleshoot.ps1`"" $false 'WAC troubleshoot task is kept'
Assert-Removed "powershell.exe -WindowStyle Hidden -File `"C:\Packages\Plugins\Microsoft.AdminCenter.AdminCenter\0.80.0.0\x.ps1`"" $false 'a later WAC version is kept'

# The same flags from anywhere else are still caught.
Assert-Removed 'powershell.exe -WindowStyle Hidden -File "C:\Users\Public\x.ps1"' $true 'hidden PowerShell elsewhere is removed'
Assert-Removed 'powershell.exe -WindowStyle Hidden -File "C:\Packages\Plugins\Other.Vendor\x.ps1"' $true 'another extension folder is not allowed'
Assert-Removed 'powershell.exe -enc SQBFAFgA' $true 'encoded command is removed'
Assert-Removed 'C:\Windows\System32\cleanmgr.exe /autoclean' $false 'ordinary task is left alone'

Write-Host ''
if ($failures -gt 0) {
    Write-Host "  FAILED - $failures assertion(s)" -ForegroundColor Red
    exit 1
}
Write-Host '  PASS - all assertions' -ForegroundColor Green
exit 0

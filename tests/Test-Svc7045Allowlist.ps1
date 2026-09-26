<#
.SYNOPSIS
    Regression test: the Event 7045 (service install) check allows the Claude,
    ChatGPT/Codex and Malwarebytes services it saw on CustomerF, and still alerts
    on anything that only looks like them.

.DESCRIPTION
    On 2026-09-26 the first run on CustomerF's HOST-F1 reported 10
    IOCs. Eight were Event 7045 service installs by legitimate software that
    re-registers its services on every update: Claude's cowork-svc and OpenAI's
    Codex sandbox service (both Microsoft Store packages under
    C:\Program Files\WindowsApps), and three Malwarebytes kernel drivers. Each
    IOC costs the device 15 points (capped at 50), so the PC scored F (0/100).

    v2026.09.26.001 allows them, but keyed on what cannot be borrowed:
    - The Store apps by package folder, anchored at X:\Program Files\WindowsApps
      and ending in the publisher ID the signing certificate determines.
    - The Malwarebytes drivers by service name AND exact driver file in the real
      system32\drivers directory.
    A service merely named "Claude", another publisher's package, a folder
    called WindowsApps somewhere else, or mbam.sys under another name or in
    another directory must still raise an IOC.

    This runs the 'Event log IOC' block verbatim from ShellKnight.ps1 under
    StrictMode 2, with Get-WinEvent mocked to return one event per scenario.
    It does not replace a real Windows run.

    ShellKnight.ps1 is a monolith that executes on load, so the code is
    extracted textually rather than dot-sourced.
#>
Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

$scriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'ShellKnight.ps1'
$source = Get-Content -LiteralPath $scriptPath -Raw

function Get-Section {
    param([string]$Pattern, [string]$What)
    $m = [regex]::Match($source, $Pattern)
    if (-not $m.Success) { throw "$What not found in ShellKnight.ps1 - did it get renamed or moved?" }
    $m.Value
}

$safeBlock = Get-Section '(?ms)^function Invoke-SafeBlock \{.*?^\}' 'Invoke-SafeBlock'
$block     = Get-Section "(?ms)^    Invoke-SafeBlock -Label 'Event log IOC' -Block \{.*?^    \}" "the 'Event log IOC' block"

# --- Mocks. Functions take precedence over cmdlets of the same name. ---------
function Say { param([string]$m, [string]$c = 'Gray') Microsoft.PowerShell.Utility\Write-Host $m -ForegroundColor $c }
function Write-Host { }
$Script:Logged = New-Object 'System.Collections.Generic.List[string]'
$Script:IOCs   = New-Object 'System.Collections.Generic.List[string]'
function Log-Info    { param([string]$m) $Script:Logged.Add($m) }
function Log-Summary { param([string]$m) $Script:Logged.Add($m) }
function Log-Warn    { param([string]$m) $Script:Logged.Add($m) }
function Log-Success { param([string]$m) $Script:Logged.Add($m) }
function Log-Fail    { param([string]$m) $Script:Logged.Add($m) }
function Log-IOC     { param([string]$m) $Script:IOCs.Add($m) }
# The ScreenConnect branch must not act in this test (SCRemoveRogue is off).
function Stop-Service { throw 'test: Stop-Service must not be called' }
function Remove-Item  { throw 'test: Remove-Item must not be called' }
$Script:Config = [pscustomobject]@{ Svc7045_ExtraNames = @(); Svc7045_ExtraPaths = @(); SCInstanceID = ''; SCRemoveRogue = $false }
$Script:RogueScreenConnectRemoved = $false

$Script:Events = @()
function Get-WinEvent { param($FilterHashtable, $ErrorAction) $Script:Events }
function New-SvcEvent([string]$Name, [string]$Path) {
    # Event 7045 Properties: 0 service name, 1 image path, 2 type, 3 start, 4 account.
    [pscustomobject]@{
        TimeCreated = (Get-Date).AddDays(-1)
        Properties  = @($Name, $Path, 'kernel mode driver', 'demand start', 'LocalSystem' | ForEach-Object { [pscustomobject]@{ Value = $_ } })
    }
}

Invoke-Expression $safeBlock

$failures = 0
function Fail([string]$Label, [string]$Why) {
    Say "  FAIL  $Label  -  $Why" Red
    $script:failures++
}

function Invoke-Check([object[]]$Events) {
    $Script:Events = $Events
    $Script:Counters = @{ IOCsFound = 0; Failed = 0 }
    $Script:Logged.Clear(); $Script:IOCs.Clear()
    $ErrorActionPreference = 'SilentlyContinue'   # as ShellKnight.ps1 runs
    try { Invoke-Expression $block } finally { $ErrorActionPreference = 'Stop' }
    $skipped = @($Script:Logged | Where-Object { $_ -match '^Event log IOC skipped' })
    if ($skipped.Count) { throw "the block aborted: $($skipped -join ' | ')" }
    $Script:Counters.IOCsFound
}

# --- Scenarios --------------------------------------------------------------
# Name | Path (as the event records it) | expected IOCs | why
$wa = 'C:\Program Files\WindowsApps'
$cases = @(
    # CustomerF, HOST-F1, 2026-09-26: the eight events, verbatim.
    ,@('Claude',  "`"$wa\Claude_2.2553.13.0_x64__pzs8sxrjxfjjc\app\resources\cowork-svc.exe`"", 0, 'Claude cowork-svc (CustomerF)')
    ,@('Claude',  "`"$wa\Claude_2.9939.2.0_x64__pzs8sxrjxfjjc\app\resources\cowork-svc.exe`"",  0, 'Claude cowork-svc, next version (CustomerF)')
    ,@('Claude',  "`"$wa\Claude_2.7032.0.0_x64__pzs8sxrjxfjjc\app\resources\cowork-svc.exe`"",  0, 'Claude cowork-svc, another version (CustomerF)')
    ,@('ChatGPT', "`"$wa\OpenAI.Codex_26.917.9434.0_x64__2p2nqsd0c76g0\app\resources\codex-windows-sandbox-service.exe`"", 0, 'Codex sandbox service (CustomerF)')
    ,@('ChatGPT', "`"$wa\OpenAI.Codex_26.915.4065.0_x64__2p2nqsd0c76g0\app\resources\codex-windows-sandbox-service.exe`"", 0, 'Codex sandbox service, other version (CustomerF)')
    ,@('MBAMWebProtection',         'C:\WINDOWS\system32\DRIVERS\mwac.sys', 0, 'Malwarebytes web protection driver (CustomerF)')
    ,@('Malwarebytes Anti-Exploit', 'C:\WINDOWS\system32\drivers\mbae.sys', 0, 'Malwarebytes anti-exploit driver (CustomerF)')
    ,@('MBAMProtection',            'C:\WINDOWS\system32\DRIVERS\mbam.sys', 0, 'Malwarebytes protection driver (CustomerF)')
    # The other forms a kernel-driver event records.
    ,@('MBAMProtection', '\SystemRoot\System32\drivers\mbam.sys',     0, 'driver path as \SystemRoot\...')
    ,@('MBAMProtection', 'System32\drivers\mbam.sys',                 0, 'driver path as a bare System32\...')
    ,@('MBAMProtection', '\??\C:\WINDOWS\system32\drivers\mbam.sys',  0, 'driver path as \??\C:\...')
    ,@('mbamprotection', 'c:\windows\system32\drivers\MBAM.SYS',      0, 'names and paths compare case-insensitively')
    # Same publisher, another OpenAI package: allowed by publisher, as intended.
    ,@('ChatGPT', "`"$wa\OpenAI.ChatGPT-Desktop_1.2026.100.0_x64__2p2nqsd0c76g0\app\ChatGPT.exe`"", 0, 'OpenAI ChatGPT desktop package')
    # Existing entries still work.
    ,@('CentraStage', 'C:\Program Files (x86)\CentraStage\CagService.exe', 0, 'existing name entry (Datto RMM)')
    ,@('GoogleUpdaterService140.0', '"C:\Program Files (x86)\Google\GoogleUpdater\140.0\updater.exe" --system --windows-service', 0, 'existing path entry (googleupdater)')
    # Look-alikes that must still alert.
    ,@('Claude',  'C:\Users\Public\cowork-svc.exe',                                        1, 'named "Claude", outside WindowsApps')
    ,@('Claude',  "`"$wa\Claude_2.0.0.0_x64__abcdefghijklm\cowork-svc.exe`"",              1, 'Claude package from another publisher ID')
    ,@('Claude',  "`"$wa\Claude_2.0.0.0_x64__pzs8sxrjxfjjcX\cowork-svc.exe`"",             1, 'publisher ID with a suffix')
    ,@('Claude',  '"C:\Users\Public\Program Files\WindowsApps\Claude_1_x64__pzs8sxrjxfjjc\x.exe"', 1, 'a folder called WindowsApps somewhere else')
    ,@('Claude',  '"C:\ProgramData\WindowsApps\Claude_1_x64__pzs8sxrjxfjjc\x.exe"',        1, 'WindowsApps outside Program Files')
    ,@('ChatGPT', 'C:\Temp\codex.exe',                                                     1, 'named "ChatGPT", outside WindowsApps')
    ,@('ChatGPT', "`"$wa\OpenAI.Codex_1.0.0.0_x64__zzzzzzzzzzzzz\codex.exe`"",             1, 'OpenAI-looking package from another publisher ID')
    ,@('MBAMProtection', 'C:\ProgramData\mbam.sys',                                        1, 'Malwarebytes name, driver outside system32')
    ,@('MBAMProtection', 'C:\evil\system32\drivers\mbam.sys',                              1, 'Malwarebytes name, a system32\drivers copy elsewhere')
    ,@('MBAMProtection', 'C:\WINDOWS\system32\drivers\evil.sys',                           1, 'Malwarebytes name, wrong driver file')
    ,@('MBAMProtection', 'C:\WINDOWS\system32\drivers\mbam.sys.bak',                       1, 'driver file with a suffix')
    ,@('EvilSvc',        'C:\WINDOWS\system32\drivers\mbam.sys',                           1, 'the Malwarebytes driver file under another name')
    ,@('UpdateHelperSvc', 'C:\Users\Public\helper.exe',                                    1, 'an unknown service')
)

Say ''
Say '  Event 7045 allow-list: one event per scenario (StrictMode 2)'
Say '  ------------------------------------------------------------'
foreach ($c in $cases) {
    $name, $path, $want, $why = $c
    $label = "$(if ($want) { 'alerts ' } else { 'allowed' })  $why"
    try { $got = Invoke-Check @(New-SvcEvent $name $path) } catch { Fail $label $_.Exception.Message; continue }
    if ($got -ne $want) { Fail $label "IOCs $got, expected $want  ($name | $path)"; continue }
    if ($want -and -not @($Script:IOCs | Where-Object { $_ -like "*Svc: $name*" }).Count) { Fail $label 'counted, but no Log-IOC line names the service'; continue }
    Say "  ok    $label" Green
}

# CustomerF's eight together, plus one unknown: exactly one IOC.
$customerf = @($cases | Select-Object -First 8 | ForEach-Object { New-SvcEvent $_[0] $_[1] }) + @(New-SvcEvent 'UpdateHelperSvc' 'C:\Users\Public\helper.exe')
try {
    $got = Invoke-Check $customerf
    if ($got -ne 1) { Fail 'customerf-run' "IOCs $got, expected 1 (the unknown service only)" }
    else { Say '  ok    CustomerF''s eight events plus one unknown service -> 1 IOC' Green }
} catch { Fail 'customerf-run' $_.Exception.Message }

Say ''
if ($failures -gt 0) {
    Say "  FAILED - $failures assertion(s)" Red
    exit 1
}
Say '  PASS - all assertions' Green
exit 0

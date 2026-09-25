<#
.SYNOPSIS
    Regression test: the OS end-of-life date is Microsoft's, for this build AND
    this edition.

.DESCRIPTION
    Up to v2026.09.25.002 the Assessment Engine looked up end of life by build
    number only, with one date per build. Several were years past Microsoft's
    (19045, Windows 10 22H2, read 2030-10-14 for 2025-10-14), and one date
    cannot be right for a build that ships as several products: Home/Pro and
    Enterprise/Education end on different days, and 14393, 17763, 19044 and
    26100 are also LTSB/LTSC and Windows Server, which run for years longer.
    The date is printed in customer reports (os_eol) and, from v2026.09.25.001,
    an end-of-life build costs 20 points.

    This checks, all verbatim from ShellKnight.ps1:
    - Get-OsEolDate against Microsoft's dates for every build and edition
      family it knows, with real Win32_OperatingSystem captions. The expected
      dates are restated here from Microsoft Learn, not read from the script.
    - A caption it cannot place (a localized one, say): a date only when it
      holds for every edition the machine could be, otherwise unknown, which
      is not scored (ADR 0009).
    - The engine's 'OS EOL' lines and the -20 rule, with the clock pinned
      either side of an end date, and the os_eol text Battlefield depends on
      (bf/report.py counts a host as supported unless it says 'END OF LIFE').
    - The table itself: every build the old table knew is still known, and
      every date is a Patch Tuesday (a mistyped day almost never is).

    Every expectation uses a pinned date, so the test does not age. The whole
    engine runs in tests/Test-EngineScope.ps1; this does not replace a real
    Windows run.

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

$osEolFn  = Get-Section '(?ms)^function Get-OsEolDate \{.*?^\}' 'Get-OsEolDate'
# The engine's lines from the lookup to the 'OS EOL' string.
$engine   = Get-Section ("(?ms)^        \`$eolDate   = Get-OsEolDate -Caption \`$osName -Build \`$osBuild\s*$.*?" +
                         "^        \} else \{ 'Unknown' \}") "the engine's OS EOL check"
$rule     = Get-Section '(?m)^if \(\$Script:OsEolWarn\)\s+\{ \$Script:SecurityScore -= 20 \}' 'the OS EOL scoring rule'
# ...and what the engine feeds it.
$null     = Get-Section '(?m)^        \$osName    = \$os\.Caption\s*$'     'the engine taking $osName from $os.Caption'
$null     = Get-Section '(?m)^        \$osBuild   = \$os\.BuildNumber\s*$' 'the engine taking $osBuild from $os.BuildNumber'

# --- Mocks. Functions take precedence over cmdlets of the same name. ---------
function Say { param([string]$m, [string]$c = 'Gray') Microsoft.PowerShell.Utility\Write-Host $m -ForegroundColor $c }
# The clock. Get-OsEolDate's default -Now and the engine's verdict both call it.
$Script:Today = [datetime]'2026-09-25'
function Get-Date { $Script:Today }

Invoke-Expression $osEolFn

$failures = 0
function Fail([string]$Label, [string]$Why) {
    Say "  FAIL  $Label  -  $Why" Red
    $script:failures++
}
function Show($v) { if ($null -eq $v) { '<null>' } else { "'$v'" } }

# --- 1. Get-OsEolDate: Microsoft's date for each build and edition ----------
# Caption | Build | expected date ($null: unknown) | why. Sources, all Microsoft
# Learn: windows/release-health/release-information (Windows 10),
# .../windows11-release-information, .../windows-server-release-info, and
# lifecycle/products/<product> for retired versions, LTSB/LTSC and Server.
$cases = @(
    # The dates the old build-only table got wrong.
    ,@('Microsoft Windows 10 Pro',                    '19045', '2025-10-14', '10 22H2: was 2030-10-14')
    ,@('Microsoft Windows 10 Enterprise',             '19045', '2025-10-14', '10 22H2 Enterprise: same day; ESU does not extend it (ADR 0010)')
    ,@('Microsoft Windows 11 Pro',                    '22621', '2024-10-08', '11 22H2 Home/Pro: was 2027-10-12')
    ,@('Microsoft Windows 11 Enterprise',             '22621', '2025-10-14', '11 22H2 Enterprise')
    ,@('Microsoft Windows 11 Pro',                    '22631', '2025-11-11', '11 23H2 Home/Pro: was 2028-10-10')
    ,@('Microsoft Windows 11 Enterprise',             '22631', '2026-11-10', '11 23H2 Enterprise')
    ,@('Microsoft Windows 11 Pro',                    '26100', '2026-10-13', '11 24H2 Home/Pro: was 2029-10-14')
    ,@('Microsoft Windows 11 Enterprise',             '26100', '2027-10-12', '11 24H2 Enterprise')
    ,@('Microsoft Windows 11 Enterprise LTSC',        '26100', '2029-10-09', '11 Enterprise LTSC 2024 (no extended phase)')
    ,@('Microsoft Windows 11 IoT Enterprise LTSC',    '26100', '2034-10-10', '11 IoT Enterprise LTSC 2024')
    ,@('Microsoft Windows Server 2025 Standard',      '26100', '2034-11-14', 'Server 2025')
    ,@('Microsoft Windows 11 Pro',                    '22000', '2023-10-10', '11 21H2 Home/Pro: was 2026-10-14')
    ,@('Microsoft Windows 11 Education',              '22000', '2024-10-08', '11 21H2 Education')
    ,@('Microsoft Windows 10 Pro',                    '19044', '2023-06-13', '10 21H2 Home/Pro: was 2026-10-13')
    ,@('Microsoft Windows 10 Enterprise',             '19044', '2024-06-11', '10 21H2 Enterprise')
    ,@('Microsoft Windows 10 Enterprise LTSC',        '19044', '2027-01-12', '10 Enterprise LTSC 2021 (no extended phase)')
    ,@('Microsoft Windows 10 IoT Enterprise LTSC',    '19044', '2032-01-13', '10 IoT Enterprise LTSC 2021')
    ,@('Microsoft Windows 10 Pro',                    '14393', '2018-04-10', '10 1607 Home/Pro: was 2027-01-12')
    ,@('Microsoft Windows 10 Enterprise',             '14393', '2019-04-09', '10 1607 Enterprise')
    ,@('Microsoft Windows 10 Enterprise 2016 LTSB',   '14393', '2026-10-13', '10 Enterprise 2016 LTSB')
    ,@('Microsoft Windows 10 IoT Enterprise 2016 LTSB','14393','2026-10-13', '10 IoT Enterprise 2016 LTSB')
    ,@('Microsoft Windows Server 2016 Standard',      '14393', '2027-01-12', 'Server 2016')
    ,@('Microsoft Windows 10 Pro',                    '17763', '2020-11-10', '10 1809 Home/Pro: was 2029-01-09')
    ,@('Microsoft Windows 10 Enterprise',             '17763', '2021-05-11', '10 1809 Enterprise')
    ,@('Microsoft Windows 10 Enterprise LTSC',        '17763', '2029-01-09', '10 Enterprise LTSC 2019')
    ,@('Microsoft Windows 10 IoT Enterprise LTSC',    '17763', '2029-01-09', '10 IoT Enterprise LTSC 2019')
    ,@('Microsoft Windows Server 2019 Datacenter',    '17763', '2029-01-09', 'Server 2019')
    ,@('Microsoft Hyper-V Server 2019',               '17763', '2029-01-09', 'Hyper-V Server 2019 follows Server 2019')
    ,@('Microsoft Windows 10 Pro',                    '10240', '2017-05-09', '10 1507: was 2025-10-14, the LTSB date')
    ,@('Microsoft Windows 10 Enterprise 2015 LTSB',   '10240', '2025-10-14', '10 Enterprise 2015 LTSB')
    ,@('Microsoft Windows 10 Home',                   '18362', '2020-12-08', '10 1903: was 2020-05-12')
    ,@('Microsoft Windows 10 Enterprise',             '19041', '2021-12-14', '10 2004: was 2025-10-14')
    ,@('Microsoft Windows 10 Enterprise',             '19042', '2023-05-09', '10 20H2 Enterprise: was 2025-10-14')
    ,@('Microsoft Windows 10 Pro',                    '19043', '2022-12-13', '10 21H1: was 2025-10-14')
    ,@('Microsoft Windows 10 Enterprise',             '16299', '2020-10-13', '10 1709 Enterprise: was 2019-04-09, the Home/Pro date')
    ,@('Microsoft Windows 8 Pro',                     '9200',  '2016-01-12', 'Windows 8: was 2023-10-10, the Server 2012 date')
    ,@('Microsoft Windows 8.1 Pro',                   '9600',  '2023-01-10', 'Windows 8.1: was 2023-10-10, the Server 2012 R2 date')
    # The rest of the table.
    ,@('Microsoft Windows Server 2008 R2 Standard',   '7601',  '2020-01-14', 'Server 2008 R2')
    ,@('Microsoft Windows 7 Enterprise ',             '7601',  '2020-01-14', 'Windows 7 SP1 (caption as documented, trailing space)')
    ,@('Microsoft Windows Server 2012 Datacenter',    '9200',  '2023-10-10', 'Server 2012')
    ,@('Microsoft Windows Server 2012 R2 Standard',   '9600',  '2023-10-10', 'Server 2012 R2')
    ,@('Microsoft Windows 10 Education',              '10586', '2017-10-10', '10 1511')
    ,@('Microsoft Windows 10 Pro',                    '15063', '2018-10-09', '10 1703 Home/Pro')
    ,@('Microsoft Windows 10 Education',              '15063', '2019-10-08', '10 1703 Education')
    ,@('Microsoft Windows 10 Pro',                    '16299', '2019-04-09', '10 1709 Home/Pro')
    ,@('Microsoft Windows 10 Pro',                    '17134', '2019-11-12', '10 1803 Home/Pro')
    ,@('Microsoft Windows 10 Enterprise',             '17134', '2021-05-11', '10 1803 Enterprise')
    ,@('Microsoft Windows 10 Pro',                    '18363', '2021-05-11', '10 1909 Home/Pro')
    ,@('Microsoft Windows 10 Enterprise',             '18363', '2022-05-10', '10 1909 Enterprise')
    ,@('Microsoft Windows 10 Pro',                    '19042', '2022-05-10', '10 20H2 Home/Pro')
    ,@('Microsoft Windows Server 2022 Standard',      '20348', '2031-10-14', 'Server 2022')
    ,@('Microsoft Windows Server Datacenter',         '25398', '2025-10-24', 'Server 23H2, Annual Channel')
    ,@('Microsoft Windows 11 Pro',                    '26200', '2027-10-12', '11 25H2 Home/Pro')
    ,@('Microsoft Windows 11 Enterprise',             '26200', '2028-10-10', '11 25H2 Enterprise')
    ,@('Microsoft Windows 11 Pro',                    '28000', '2028-03-14', '11 26H1 Home/Pro')
    ,@('Microsoft Windows 11 Enterprise',             '28000', '2029-03-13', '11 26H1 Enterprise')
    # Which timeline each edition follows (Microsoft's own edition lists).
    ,@('Microsoft Windows 10 Home Single Language',   '22631', '2025-11-11', 'Home Single Language: Home/Pro')
    ,@('Microsoft Windows 11 Pro for Workstations',   '22631', '2025-11-11', 'Pro for Workstations: Home/Pro')
    ,@('Microsoft Windows 11 Pro Education',          '22631', '2025-11-11', 'Pro Education: Home/Pro, though it says Education')
    ,@('Microsoft Windows 11 SE',                     '26100', '2026-10-13', 'SE: Home/Pro')
    ,@('Microsoft Windows 11 Education',              '22631', '2026-11-10', 'Education: Enterprise/Education')
    ,@('Microsoft Windows 11 Enterprise multi-session','22631','2026-11-10', 'Enterprise multi-session: Enterprise/Education')
    ,@('Microsoft Windows 11 IoT Enterprise',         '22631', '2026-11-10', 'IoT Enterprise (GA, not LTSC): Enterprise/Education')
    ,@('Microsoft Windows 10 Enterprise N',           '19044', '2024-06-11', 'N edition: its base edition')
    # A caption it cannot place (as of 2026-09-25): a date only if it holds for
    # every edition the machine could be.
    ,@('Microsoft Windows 10 Professionnel',          '19043', '2022-12-13', 'unplaced, every edition ended the same day')
    ,@('Microsoft Windows 10 Professionnel',          '17134', '2021-05-11', 'unplaced, every edition past: the latest date')
    ,@('Microsoft Windows 11 Professionnel',          '22631', $null,        'unplaced, Enterprise 23H2 still supported: unknown')
    ,@('Microsoft Windows 11 Entreprise',             '26100', $null,        'unplaced 24H2: could be anything from Pro to IoT LTSC')
    ,@('Microsoft Windows 10 Professionnel',          '17763', $null,        'unplaced 1809: could be LTSC 2019 (2029)')
    ,@('Microsoft Windows 7 Professional',            '7601',  '2020-01-14', 'unplaced ("Professional" is not "Pro"), every client edition ended the same day')
    ,@('Microsoft Windows 8.1',                       '9600',  '2023-01-10', 'unplaced core 8.1: client date, not the Server 2012 R2 one')
    ,@('',                                            '19045', '2025-10-14', 'no caption at all, every edition ended the same day')
    ,@('Microsoft Windows 10 Enterprise LTSC',        '19045', '2025-10-14', 'an edition this build does not ship as: treated as unplaced')
    ,@('Microsoft Windows Server 2022 Standard',      '22631', $null,        'a server caption on a client-only build: unknown')
    ,@('Microsoft Azure Stack HCI',                   '20348', $null,        'a client-side caption on a server-only build: unknown')
    # Builds it does not know.
    ,@('Microsoft Windows Server 2008 Standard',      '6003',  $null,        'build not in the table')
    ,@('Microsoft Windows 11 Pro',                    '',      $null,        'no build')
)

Say ''
Say '  Get-OsEolDate: Microsoft end of servicing by build and edition (as of 2026-09-25)'
Say '  --------------------------------------------------------------------------------'
foreach ($c in $cases) {
    $caption, $build, $want, $why = $c
    $label = "$build $(Show $caption)"
    try {
        $got = Get-OsEolDate -Caption $caption -Build $build
    } catch { Fail $label "threw: $($_.Exception.Message)"; continue }
    if ($null -ne $got -and $got -isnot [datetime]) { Fail $label "returned $($got.GetType().Name), expected DateTime or null"; continue }
    $gotS = if ($null -eq $got) { $null } else { $got.ToString('yyyy-MM-dd') }
    if ($gotS -ne $want -or ($null -eq $gotS) -ne ($null -eq $want)) { Fail $label "$(Show $gotS), expected $(Show $want)  ($why)"; continue }
    Say "  ok    $label -> $(Show $gotS)  ($why)" Green
}

# The unplaced rule is about "now": the same machine becomes known once even
# the longest-lived edition it could be has ended.
$Script:Today = [datetime]'2026-11-11'
$got = Get-OsEolDate -Caption 'Microsoft Windows 11 Professionnel' -Build '22631'
if ("$got" -eq '' -or $got.ToString('yyyy-MM-dd') -ne '2026-11-10') { Fail 'unplaced 22631 on 2026-11-11' "$(Show $got), expected '2026-11-10'" }
else { Say "  ok    unplaced 22631 on 2026-11-11 -> '2026-11-10' (every client edition has ended)" Green }
$Script:Today = [datetime]'2026-09-25'

# --- 2. The engine's os_eol and the -20 --------------------------------------
# Caption | Build | clock | os_eol exactly | penalty
$engineCases = @(
    ,@('Microsoft Windows 10 Pro',               '19045', '2026-09-25', 'END OF LIFE (since 2025-10-14)', 20)
    ,@('Microsoft Windows 10 Enterprise',        '19045', '2026-09-25', 'END OF LIFE (since 2025-10-14)', 20)
    ,@('Microsoft Windows 11 Pro',               '22631', '2026-09-25', 'END OF LIFE (since 2025-11-11)', 20)
    ,@('Microsoft Windows 11 Enterprise',        '22631', '2026-09-25', 'Supported until 2026-11-10', 0)
    ,@('Microsoft Windows 11 Enterprise',        '22631', '2026-11-11', 'END OF LIFE (since 2026-11-10)', 20)
    ,@('Microsoft Windows 11 Pro',               '26100', '2026-10-12', 'Supported until 2026-10-13', 0)
    ,@('Microsoft Windows 11 Pro',               '26100', '2026-10-14', 'END OF LIFE (since 2026-10-13)', 20)
    ,@('Microsoft Windows 11 IoT Enterprise LTSC','26100','2026-10-14', 'Supported until 2034-10-10', 0)
    ,@('Microsoft Windows Server 2025 Standard', '26100', '2026-10-14', 'Supported until 2034-11-14', 0)
    ,@('Microsoft Windows Server 2016 Standard', '14393', '2026-09-25', 'Supported until 2027-01-12', 0)
    ,@('Microsoft Windows 10 Pro',               '14393', '2026-09-25', 'END OF LIFE (since 2018-04-10)', 20)
    ,@('Microsoft Windows 11 Entreprise',        '26100', '2026-09-25', 'Unknown', 0)
    ,@('Microsoft Windows 11 Pro',               '99999', '2026-09-25', 'Unknown', 0)
)

Say ''
Say '  Engine: os_eol and the OS EOL rule (StrictMode 2)'
Say '  -------------------------------------------------'
foreach ($c in $engineCases) {
    $osName, $osBuild, $today, $want, $penalty = $c
    $label = "$osBuild $(Show $osName) on $today"
    $Script:Today = [datetime]$today
    $Script:OsEolWarn = $false
    $Script:SecurityScore = 100
    $ErrorActionPreference = 'SilentlyContinue'   # as ShellKnight.ps1 runs
    try {
        Invoke-Expression $engine
        Invoke-Expression $rule
    } finally { $ErrorActionPreference = 'Stop' }
    $before = $failures
    if ($eolStr -cne $want) { Fail $label "os_eol $(Show $eolStr), expected $(Show $want)" }
    if ($Script:SecurityScore -ne 100 - $penalty) { Fail $label "score $($Script:SecurityScore), expected $(100 - $penalty)" }
    # bf/report.py: a host is "supported" unless os_eol contains END OF LIFE.
    if (($eolStr -clike '*END OF LIFE*') -ne [bool]$penalty) { Fail $label "Battlefield would count this host as $(if ($penalty) { 'supported' } else { 'end of life' })" }
    if ($eolStr -cnotmatch '^(END OF LIFE \(since \d{4}-\d{2}-\d{2}\)|Supported until \d{4}-\d{2}-\d{2}|Unknown)$') { Fail $label "os_eol $(Show $eolStr) is not one of the three forms Battlefield has always received" }
    if ($failures -eq $before) { Say "  ok    $label -> $(Show $eolStr), -$penalty" Green }
}
$Script:Today = [datetime]'2026-09-25'

# --- 3. The table ------------------------------------------------------------
Say ''
Say '  Get-OsEolDate table'
Say '  -------------------'
$rows = @{}
foreach ($r in [regex]::Matches($osEolFn, "(?m)^\s*'(\d{4,5})'\s*=\s*@\{([^}]*)\}")) {
    $rows[$r.Groups[1].Value] = @([regex]::Matches($r.Groups[2].Value, "(\w+)\s*=\s*'([^']*)'") | ForEach-Object {
        [pscustomobject]@{ Family = $_.Groups[1].Value; Date = $_.Groups[2].Value } })
}
if ($rows.Count -lt 20) { Fail 'table' "found $($rows.Count) builds - did the table's layout change? (this check reads it textually)" }

# No build the old table knew may fall back to 'Unknown'.
$oldBuilds = '7601 9200 9600 10240 10586 14393 15063 16299 17134 17763 18362 18363 19041 19042 19043 19044 19045 20348 22000 22621 22631 26100' -split ' '
$missing = @($oldBuilds | Where-Object { -not $rows.ContainsKey($_) })
if ($missing.Count) { Fail 'table' "builds the old table knew are gone: $($missing -join ', ')" }
else { Say "  ok    all $($oldBuilds.Count) builds of the old table are still known ($($rows.Count) in all)" Green }

# Families are the five the caption can produce; dates are Patch Tuesdays
# (the second Tuesday), except the Server Annual Channel, whose end is fixed.
$families = 'HomePro', 'EntEdu', 'LTSC', 'IoTLTSC', 'Server'
$notPatchTuesday = @{ '25398/Server' = '2025-10-24' }
$bad = 0
foreach ($b in $rows.Keys) {
    foreach ($e in $rows[$b]) {
        $key = "$b/$($e.Family)"
        if ($e.Family -notin $families) { Fail 'table' "$key - unknown edition family"; $bad++; continue }
        $d = [datetime]::MinValue
        if (-not [datetime]::TryParseExact($e.Date, 'yyyy-MM-dd', [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$d)) { Fail 'table' "$key - '$($e.Date)' is not a yyyy-MM-dd date"; $bad++; continue }
        $pt = $d.DayOfWeek -eq 'Tuesday' -and $d.Day -ge 8 -and $d.Day -le 14
        if (-not $pt -and $notPatchTuesday[$key] -ne $e.Date) { Fail 'table' "$key - $($e.Date) is a $($d.DayOfWeek), not a Patch Tuesday (typo?)"; $bad++ }
    }
}
if (-not $bad) { Say '  ok    every date is a real date and a Patch Tuesday (Server 23H2 excepted, as documented)' Green }

Say ''
if ($failures -gt 0) {
    Say "  FAILED - $failures assertion(s)" Red
    exit 1
}
Say '  PASS - all assertions' Green
exit 0

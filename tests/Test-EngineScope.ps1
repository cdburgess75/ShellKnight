<#
.SYNOPSIS
    Regression test: what the Assessment Engine detects reaches the payload and
    the security score.

.DESCRIPTION
    Invoke-SafeBlock runs its block with '& $Block', which is a child scope. Up
    to v2026.09.24.001 the engine set $avProduct, $edrProduct, $defStatus,
    $bitlockerWarn, $osEolWarn and $wuLastWarn with bare assignments. Each one
    made a local copy that was discarded when the block returned, so the
    payload reported antivirus 'NONE DETECTED', edr 'None detected' and
    defender 'Unknown' on every device, and the BitLocker, OS EOL and Windows
    Update penalties never applied. MachineInfo, built inside the block, was
    right the whole time, which is why nobody noticed from the log.

    Up to v2026.09.25.001 the password minimum length also started at 0, and
    only the engine's 'net accounts' check set it. An engine that aborted or
    was disabled, or a 'net accounts' with no length, was therefore scored -20
    and reported as the High finding 'Password minimum length is 0 (CIS
    1.1.1)', which Battlefield alerts on. An unknown length must cost nothing
    and raise nothing (ADR 0009), and the payload's password_min_length must
    say null for it, not 0.

    Up to v2026.09.26.001 the CIS block read LmCompatibilityLevel with
    (Get-ItemProperty ...).LmCompatibilityLevel. Where the value is not set,
    which is Windows' default, that threw under StrictMode 2 and the block
    stopped after 1.1.1 (HOST-A1 2026-09-26). Not set is Windows' default
    level 3, so it must neither stop the block nor cost the -15 LAN Manager
    rule; an explicit level below 3 still does. The Antivirus field must name
    each product once: SecurityCenter2 and the Datto service check can each
    report Datto AV ('Datto AV, Datto AV' on the same box).

    This runs the whole of Phase 2, the CIS Benchmark block, the security
    scoring, and the payload's machine fields, all verbatim from
    ShellKnight.ps1. They run under the script's own StrictMode 2 /
    SilentlyContinue settings, with the Windows cmdlets replaced by mocks, so
    the test runs on the CI Linux runner. It does not replace a real Windows
    run.

    It also parses the whole script and fails on the general form of the bug:
    a variable assigned bare inside an Invoke-SafeBlock body and then read
    somewhere that body does not enclose.

    ShellKnight.ps1 is a monolith that executes on load, so the code is
    extracted textually rather than dot-sourced.
#>
Set-StrictMode -Version 2
# The test's own logic stops on any error, so a broken assertion fails loudly
# instead of being skipped. Only the extracted ShellKnight code runs under the
# script's own 'SilentlyContinue' (see the scenario loop).
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
$regValue  = Get-Section '(?ms)^function Get-RegistryValue \{.*?^\}' 'Get-RegistryValue'
$biosDate  = Get-Section '(?ms)^function ConvertTo-BiosDate \{.*?^\}' 'ConvertTo-BiosDate'
$osEol     = Get-Section '(?ms)^function Get-OsEolDate \{.*?^\}' 'Get-OsEolDate'
# Phase 2 from the MachineInfo reset to the end of the engine's if/else.
$phase2    = Get-Section ('(?ms)^\$Script:MachineInfo = \[ordered\]@\{\}\s*$.*?' +
                          '^    Log-Info "Assessment Engine  -  disabled"\s*^\}') 'Phase 2 (the Assessment Engine)'
# The Reporting Engine's CIS block, which raises the CIS 1.1.1 finding.
$cis       = Get-Section "(?ms)^    Invoke-SafeBlock -Label 'CIS Benchmark' -Block \{.*?^    \}" 'CIS Benchmark block'
$scoring   = Get-Section ('(?ms)^\$Script:SecurityScore = 100\s*$.*?' +
                          '^\$Script:SecurityScore = \[math\]::Max\(0, \$Script:SecurityScore\)') 'Security scoring'
# The payload's machine fields, evaluated as a hashtable of their own.
$fields    = [regex]::Matches($source, '(?m)^    (bitlocker|os_eol|antivirus|edr|defender|password_min_length)\s+=.*$')
if ($fields.Count -ne 6) { throw "expected 6 payload fields (bitlocker, os_eol, antivirus, edr, defender, password_min_length), found $($fields.Count)" }
$payloadSrc = "[ordered]@{`n" + (($fields | ForEach-Object { $_.Value }) -join "`n") + "`n}"

# --- Mocks. Functions take precedence over cmdlets of the same name. ---------
function Say { param([string]$m, [string]$c = 'Gray') Microsoft.PowerShell.Utility\Write-Host $m -ForegroundColor $c }
function Write-Host { }
$Script:Logged   = New-Object 'System.Collections.Generic.List[string]'
$Script:Findings = New-Object 'System.Collections.Generic.List[object]'
function Log-Info    { param([string]$m) $Script:Logged.Add($m) }
function Log-Warn    { param([string]$m) $Script:Logged.Add($m) }
function Log-Summary { param([string]$m) }
function Add-Finding { param($Severity, $Title, $Action) $Script:Findings.Add([pscustomobject]@{ Severity = $Severity; Title = $Title }) }
$Script:Config    = [pscustomobject]@{ AssessmentEngine_Enabled = $true }
$Script:Counters  = @{ IntelSource = 'test'; IOCsFound = 0; Failed = 0 }
$Script:HWInfo    = @{ IsServer = $false; IsHyperVHost = $false }
$Script:PSFullVer = '5.1.22621.5697'
$origComputerName = $env:COMPUTERNAME     # process-wide: restored at the end
$env:COMPUTERNAME = 'SK-TEST-PC'

# The scenario being run. Every mock reads it.
$Script:S = $null

function Get-CimInstance {
    param($ClassName, $Namespace, $Filter, $ErrorAction)
    $s = $Script:S
    switch ($ClassName) {
        'Win32_OperatingSystem' {
            if ($s.Engine -eq 'aborts') { throw 'Invalid class (WMI repository damaged)' }
            return [pscustomobject]@{ Caption = $s.Caption; BuildNumber = $s.Build
                                      OSArchitecture = '64-bit'; LastBootUpTime = (Get-Date).AddDays(-2) }
        }
        'Win32_ComputerSystem' {
            return [pscustomobject]@{ PartOfDomain = $true; Domain = 'corp.local'; Workgroup = $null
                                      UserName = 'CORP\user'; TotalPhysicalMemory = 17179869184 }
        }
        'Win32_BIOS'        { return [pscustomobject]@{ ReleaseDate = [datetime]'2023-03-01' } }
        'Win32_LogicalDisk' { return [pscustomobject]@{ FreeSpace = 100GB; Size = 250GB } }
        'AntiVirusProduct'  { return @($s.AvList | ForEach-Object { [pscustomobject]@{ displayName = $_ } }) }
        'MSFT_MpComputerStatus' {
            if ($s.Defender -eq 'removed') { throw 'Invalid namespace' }
            return [pscustomobject]@{ AMServiceEnabled = $true; RealTimeProtectionEnabled = ($s.Defender -eq 'active')
                                      AntivirusSignatureLastUpdated = (Get-Date).AddHours(-5) }
        }
        'Win32_ComputerSystemProduct' { return [pscustomobject]@{ UUID = '12345678-ABCD-4EF0-9876-0123456789AB' } }
        'Win32_SystemEnclosure'       { return [pscustomobject]@{ ChassisTypes = @(3) } }
        'Win32_EncryptableVolume' {
            if ($s.BitLocker -eq 'unavailable') { throw 'Invalid namespace' }
            $ps = if ($s.BitLocker -eq 'On') { 1 } else { 0 }
            return [pscustomobject]@{ ProtectionStatus = $ps }
        }
        default { throw "unmocked CIM class $ClassName" }
    }
}
function Get-MpComputerStatus {
    param($ErrorAction)
    if ($Script:S.Defender -eq 'removed') { throw 'Get-MpComputerStatus: module could not be loaded (SYSTEM, -NoProfile)' }
    [pscustomobject]@{ AMServiceEnabled = $true; RealTimeProtectionEnabled = ($Script:S.Defender -eq 'active')
                       AntivirusSignatureLastUpdated = (Get-Date).AddHours(-3) }
}
function Get-Service {
    param($Name, $ErrorAction)
    if ($Name -eq 'WinDefend') {
        if ($Script:S.Defender -eq 'removed') { return $null }
        return [pscustomobject]@{ Name = 'WinDefend'; Status = 'Running' }
    }
    if ($Script:S.Services -contains $Name) { return [pscustomobject]@{ Name = $Name; Status = 'Running' } }
    return $null
}
function Get-BitLockerVolume {
    param($MountPoint, $ErrorAction)
    # 'Off-cim' and 'unavailable': the BitLocker module is not there, so the
    # engine falls back to Win32_EncryptableVolume.
    if ($Script:S.BitLocker -in 'Off-cim', 'unavailable') { throw "The term 'Get-BitLockerVolume' is not recognized" }
    [pscustomobject]@{ ProtectionStatus = $Script:S.BitLocker }
}
function Get-ItemProperty {
    param($Path, $Name, $ErrorAction)
    if ("$Path" -match 'Cryptography')         { return [pscustomobject]@{ MachineGuid = 'b1e2c3d4-0000-1111-2222-333344445555' } }
    if ("$Path" -match 'Real-Time Protection') { throw 'Property DisableRealtimeMonitoring does not exist' }
    # Lm 'not-set': the Lsa key read back without LmCompatibilityLevel, as on
    # a box where nothing has set it.
    if ("$Path" -match 'Control\\Lsa') {
        if ($Script:S.Lm -eq 'not-set') { return [pscustomobject]@{ RunAsPPL = 0; PSChildName = 'Lsa' } }
        return [pscustomobject]@{ LmCompatibilityLevel = $Script:S.Lm }
    }
    return $null
}
function New-Object {
    param($TypeName, $ComObject, $ArgumentList, $ErrorAction)
    if ($ComObject) {
        $days = $Script:S.WuDays
        $hist = [pscustomobject]@{ Count = 1 }
        $hist | Add-Member ScriptMethod Item { param($i) [pscustomobject]@{ Date = (Get-Date).AddDays(-$days) } }.GetNewClosure()
        $srch = [pscustomobject]@{}
        $srch | Add-Member ScriptMethod QueryHistory { param($a, $b) $hist }.GetNewClosure()
        $sess = [pscustomobject]@{}
        $sess | Add-Member ScriptMethod CreateUpdateSearcher { $srch }.GetNewClosure()
        return $sess
    }
    Microsoft.PowerShell.Utility\New-Object -TypeName $TypeName
}
# The engine's nested checks, and the scoring's own probes, all answer "fine",
# so the only deductions left are the ones under test.
function Get-WindowsOptionalFeature { param([switch]$Online, $FeatureName, $ErrorAction) $null }
function Get-LocalUser { param($Name, $ErrorAction) @() }
# 'net accounts' as English Windows prints it, with the scenario's length.
# Net 'empty': no output at all. 'no-length-line': the rest of it without the
# length line (a localized Windows prints no English 'Minimum password length').
function net {
    $s = $Script:S
    if ($s.Net -eq 'empty') { return }
    $out = @(
        'Force user logoff how long after time expires?:       Never'
        'Minimum password age (days):                          0'
        'Maximum password age (days):                          42'
        "Minimum password length:                              $($s.PwLen)"
        'Length of password history maintained:                None'
        'Lockout threshold:                                    Never'
        'Computer role:                                        WORKSTATION'
        'The command completed successfully.'
    )
    if ($s.Net -eq 'no-length-line') { $out = @($out | Where-Object { $_ -notmatch 'Minimum password length' }) }
    $out
}
function Get-SmbServerConfiguration { param($ErrorAction) [pscustomobject]@{ EnableSMB1Protocol = $false } }
function Get-NetFirewallProfile { param($ErrorAction) @([pscustomobject]@{ Profile = 'Domain'; Enabled = $true }) }

Invoke-Expression $safeBlock
Invoke-Expression $regValue
Invoke-Expression $biosDate
Invoke-Expression $osEol

# --- Scenarios --------------------------------------------------------------
# The machine each mock describes, and what the payload and the score must say.
# Penalty: points the six rules under test must take off 100 (AV -25, OS EOL
# -20, BitLocker -15, Windows Update -15, password length -20/-10/-5, LAN
# Manager auth level below 3 -15). $null
# for Av/Edr/Def means the engine did not run, so the payload has no value to
# report. Pw is the CIS 1.1.1 finding's title, or $null for none. Len is the
# payload's password_min_length: the length read, or $null when it was not.
# The healthy machine's OS is supported until 2034-10-10 (Get-OsEolDate), so
# this fixture does not age into end of life. Tests/Test-OsEol.ps1 covers the
# edition dates themselves.
$healthy = @{ Engine = 'runs'; Caption = 'Microsoft Windows 11 IoT Enterprise LTSC'; Build = '26100'; BitLocker = 'On'; WuDays = 6
              AvList = @('Windows Defender'); Defender = 'active'; Services = @(); Net = 'ok'; PwLen = 14; Lm = 5 }
function New-Scenario([string]$Name, [hashtable]$Machine, [hashtable]$Expect) {
    $m = $healthy.Clone(); foreach ($k in $Machine.Keys) { $m[$k] = $Machine[$k] }
    $e = @{ Av = 'Windows Defender'; Edr = 'None detected'; Def = 'Active'; Penalty = 0; Finding = $false; Pw = $null; Len = 14; Eol = $false }
    foreach ($k in $Expect.Keys) { $e[$k] = $Expect[$k] }
    $m.Name = $Name; $m.Expect = $e; $m
}
$scenarios = @(
    New-Scenario 'healthy'               @{}                                   @{}
    New-Scenario 'bitlocker-off'         @{ BitLocker = 'Off' }                @{ Penalty = 15; Finding = $true }
    New-Scenario 'bitlocker-off-cim'     @{ BitLocker = 'Off-cim' }            @{ Penalty = 15; Finding = $true }
    # Neither probe answers: unknown, so no penalty (ADR 0009).
    New-Scenario 'bitlocker-unavailable' @{ BitLocker = 'unavailable' }        @{}
    New-Scenario 'os-eol'                @{ Caption = 'Microsoft Windows 10 Pro'; Build = '19043' } @{ Penalty = 20; Eol = $true }
    # One build, two editions, two answers: the engine must look up the
    # caption it read, not just the build. Stable until 2029-01-09.
    New-Scenario 'os-eol-1809-pro'       @{ Caption = 'Microsoft Windows 10 Pro'; Build = '17763' } @{ Penalty = 20; Eol = $true }
    New-Scenario 'os-eol-1809-ltsc'      @{ Caption = 'Microsoft Windows 10 Enterprise LTSC'; Build = '17763' } @{}
    New-Scenario 'wu-stale'              @{ WuDays = 45 }                      @{ Penalty = 15 }
    New-Scenario 'all-three'             @{ BitLocker = 'Off'; Caption = 'Microsoft Windows 10 Pro'; Build = '19043'; WuDays = 45 } @{ Penalty = 50; Finding = $true; Eol = $true }
    # Windows turns Defender off when a third-party AV registers. Protected:
    # no penalty (the old Defender DISABLED rule would have taken 20).
    New-Scenario 'third-party-av'        @{ AvList = @('Windows Defender', 'Bitdefender Endpoint Security Tools'); Defender = 'off' } @{ Av = 'Bitdefender Endpoint Security Tools'; Def = 'DISABLED' }
    New-Scenario 'edr'                   @{ Services = @('SentinelAgent', 'CSFalconService') } @{ Edr = 'CrowdStrike Falcon, SentinelOne' }
    # Datto AV twice in SecurityCenter2 and once more from its service: named once.
    New-Scenario 'av-duplicates'         @{ AvList = @('Windows Defender', 'Datto AV', 'Datto AV'); Services = @('EndpointProtectionService2'); Defender = 'off' } @{ Av = 'Datto AV'; Def = 'DISABLED' }
    New-Scenario 'no-av'                 @{ AvList = @(); Defender = 'removed' } @{ Av = 'NONE DETECTED'; Def = 'Unknown'; Penalty = 25 }
    # Defender off and nothing else: -25 once, not -25 and -20.
    New-Scenario 'defender-off-no-av'    @{ Defender = 'off' }                 @{ Av = 'Windows Defender (status DISABLED)'; Def = 'DISABLED'; Penalty = 25 }
    # A password length that was read is scored and reported as before. A real
    # 0 keeps the exact title Battlefield maps to 'password-policy-blank'.
    New-Scenario 'password-length-0'     @{ PwLen = 0 }                        @{ Penalty = 20; Pw = 'Password minimum length is 0 (CIS 1.1.1)'; Len = 0 }
    New-Scenario 'password-length-6'     @{ PwLen = 6 }                        @{ Penalty = 10; Pw = 'Password minimum length is 6 (CIS 1.1.1)'; Len = 6 }
    New-Scenario 'password-length-10'    @{ PwLen = 10 }                       @{ Penalty = 5; Len = 10 }
    # One that was not read is unknown: no penalty, no finding, null in the
    # payload (ADR 0009).
    New-Scenario 'net-accounts-empty'    @{ Net = 'empty' }                    @{ Len = $null }
    New-Scenario 'net-accounts-no-length' @{ Net = 'no-length-line' }          @{ Len = $null }
    # A length line with no number: [int]'' is 0, so this must not parse as 0.
    New-Scenario 'net-accounts-no-number' @{ PwLen = '' }                      @{ Len = $null }
    # LmCompatibilityLevel not set is Windows' default, 3: not scored, and the
    # CIS block must run past 2.3. An explicit level below 3 is still -15.
    New-Scenario 'lm-not-set'            @{ Lm = 'not-set' }                   @{}
    New-Scenario 'lm-2'                  @{ Lm = 2 }                           @{ Penalty = 15 }
    # The engine produced nothing, so none of the five rules may fire, though
    # the machine has every problem they look for.
    New-Scenario 'engine-aborts'         @{ Engine = 'aborts'; BitLocker = 'Off'; WuDays = 45; PwLen = 0 } @{ Av = $null; Edr = $null; Def = $null; Len = $null }
    New-Scenario 'engine-disabled'       @{ Engine = 'disabled'; BitLocker = 'Off'; WuDays = 45; PwLen = 0 } @{ Av = $null; Edr = $null; Def = $null; Len = $null }
)

$failures = 0
function Fail([string]$Label, [string]$Why) {
    Say "  FAIL  $Label  -  $Why" Red
    $script:failures++
}
function Show($v) { if ($null -eq $v) { '<null>' } else { "'$v'" } }

Say ''
Say '  Assessment Engine results reach the payload and the score (StrictMode 2)'
Say '  ------------------------------------------------------------------------'

foreach ($sc in $scenarios) {
    $Script:S = $sc
    $x = $sc.Expect
    $label = $sc.Name
    $before = $failures
    $Script:Config.AssessmentEngine_Enabled = ($sc.Engine -ne 'disabled')
    $Script:Logged.Clear()
    $Script:Findings.Clear()

    $ErrorActionPreference = 'SilentlyContinue'   # as ShellKnight.ps1 runs
    try {
        Invoke-Expression $phase2
        Invoke-Expression $cis
        Invoke-Expression $scoring
        $payload = Invoke-Expression $payloadSrc
    } finally { $ErrorActionPreference = 'Stop' }

    # The CIS block may stop at its last check, 2.9, only where the mock for
    # Get-MpComputerStatus throws (Defender removed). Anywhere else a stop is a
    # failure, and 2.3 must have run.
    $skipped = @($Script:Logged | Where-Object { $_ -match 'skipped' -and $_ -notmatch '^CIS Benchmark skipped' })
    $cisSkipped = @($Script:Logged | Where-Object { $_ -match '^CIS Benchmark skipped' })
    if ($cisSkipped.Count -and $sc.Defender -ne 'removed') { Fail $label "the CIS block aborted: $($cisSkipped -join ' | ')" }
    if (-not @($Script:Logged | Where-Object { $_ -match '\[CIS 2\.3\]' }).Count) { Fail $label 'the CIS 2.3 check did not run' }
    if ($sc.Engine -eq 'runs' -and $skipped.Count) { Fail $label "a block aborted: $($skipped -join ' | ')" }
    if ($sc.Engine -eq 'aborts' -and -not @($skipped | Where-Object { $_ -match '^Assessment Engine skipped' }).Count) {
        Fail $label 'expected the engine to abort in this scenario (test harness check)'
    }

    foreach ($f in @(@('antivirus', $x.Av), @('edr', $x.Edr), @('defender', $x.Def))) {
        $got = $payload[$f[0]]
        if ($got -ne $f[1] -or ($null -eq $got) -ne ($null -eq $f[1])) {
            Fail $label "payload $($f[0]) = $(Show $got), expected $(Show $f[1])"
        }
    }
    if ($sc.Engine -eq 'runs') {
        # The payload's evidence must agree with what was scored.
        $wantBl = if ($sc.BitLocker -eq 'On') { 'On' } elseif ($sc.BitLocker -eq 'unavailable') { 'Not available' } else { 'Off' }
        if ($payload['bitlocker'] -ne $wantBl) { Fail $label "payload bitlocker = $(Show $payload['bitlocker']), expected '$wantBl'" }
        $eol = "$($payload['os_eol'])" -like 'END OF LIFE*'
        if ($eol -ne $x.Eol) { Fail $label "payload os_eol = $(Show $payload['os_eol']), expected $(if ($x.Eol) { 'END OF LIFE' } else { 'not END OF LIFE' })" }
    }

    $score = 100 - $x.Penalty
    if ($Script:SecurityScore -ne $score) { Fail $label "security score $($Script:SecurityScore), expected $score" }

    $blFinding = @($Script:Findings | Where-Object { $_.Title -like 'BitLocker not enabled*' }).Count -gt 0
    if ($blFinding -ne $x.Finding) { Fail $label "BitLocker finding present: $blFinding, expected $($x.Finding)" }

    $pwFindings = @($Script:Findings | Where-Object { $_.Title -like '*(CIS 1.1.1)' })
    # Without this, a CIS block that never reached 1.1.1 would pass as "no finding".
    if (-not @($Script:Logged | Where-Object { $_ -match '\[CIS 1\.1\.1\]' }).Count -and -not $pwFindings.Count) {
        Fail $label 'the CIS 1.1.1 check did not run (test harness check)'
    }
    $pw = if ($pwFindings.Count) { ($pwFindings | ForEach-Object { $_.Title }) -join ' | ' } else { $null }
    if ($pw -ne $x.Pw -or ($null -eq $pw) -ne ($null -eq $x.Pw)) { Fail $label "CIS 1.1.1 finding = $(Show $pw), expected $(Show $x.Pw)" }

    # As Battlefield receives it: a JSON number when read, null when not.
    $lenJson  = @{ password_min_length = $payload['password_min_length'] } | ConvertTo-Json -Compress
    $wantJson = if ($null -eq $x.Len) { '{"password_min_length":null}' } else { "{`"password_min_length`":$($x.Len)}" }
    if ($lenJson -ne $wantJson) { Fail $label "payload $lenJson, expected $wantJson" }

    if ($failures -eq $before) {
        Say "  ok    $label  -  score $($Script:SecurityScore); antivirus=$(Show $payload['antivirus']) edr=$(Show $payload['edr']) defender=$(Show $payload['defender']) password_min_length=$(Show $payload['password_min_length'])" Green
    }
}

# --- Static: no engine result is stranded in a child scope ------------------
# Invoke-SafeBlock does '& $Block', so a bare '$x = ...' inside its body is a
# local that is gone when the body returns. Flag every read whose most recent
# write (in source order) is such a local, in a body that does not enclose
# the read. A $Script: write reaches everywhere; a $Script: read always sees
# the script-level variable. Code in functions is out of scope: it runs when
# called, not where it sits.
$tokens = $null; $parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw "ShellKnight.ps1 does not parse: $($parseErrors[0].Message)" }
$L = 'System.Management.Automation.Language'
$bodies = @($ast.FindAll({ param($n)
    $n -is [System.Management.Automation.Language.ScriptBlockExpressionAst] -and
    $n.Parent -is [System.Management.Automation.Language.CommandAst] -and
    $n.Parent.GetCommandName() -eq 'Invoke-SafeBlock' }, $true))
$functions = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true))
function Test-Within($Node, $Outer) {
    $Node.Extent.StartOffset -ge $Outer.Extent.StartOffset -and $Node.Extent.EndOffset -le $Outer.Extent.EndOffset
}
function Get-Body($Node) {    # innermost Invoke-SafeBlock body holding $Node
    $best = $null
    foreach ($b in $bodies) { if ((Test-Within $Node $b) -and (-not $best -or (Test-Within $b $best))) { $best = $b } }
    $best
}
$ignore = @('null', '_', 'psitem', 'true', 'false', 'matches', 'lastexitcode', 'args', 'input', 'this', 'error',
            'erroractionpreference', 'progresspreference', 'warningpreference', 'verbosepreference', 'confirmpreference')
$writes = @{}; $reads = New-Object 'System.Collections.Generic.List[object]'
foreach ($v in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] }, $true)) {
    $vp = $v.VariablePath
    if (-not ($vp.IsUnqualified -or $vp.IsScript)) { continue }
    $name = ($vp.UserPath -replace '^(?i)script:', '').ToLower()
    if ($name -in $ignore) { continue }
    if (@($functions | Where-Object { Test-Within $v $_ }).Count) { continue }
    $p = $v.Parent
    if ($p -is "$L.ConvertExpressionAst" -and $p.Child -eq $v) { $v2 = $p; $p = $p.Parent } else { $v2 = $v }
    $isWrite = ($p -is "$L.AssignmentStatementAst" -and $p.Left -eq $v2) -or
               ($p -is "$L.ForEachStatementAst" -and $p.Variable -eq $v) -or
               ($p -is "$L.UnaryExpressionAst" -and "$($p.TokenKind)" -match 'PlusPlus|MinusMinus')
    $body = if ($vp.IsScript) { $null } else { Get-Body $v }
    $rec = [pscustomobject]@{ Name = $name; Line = $v.Extent.StartLineNumber; Offset = $v.Extent.StartOffset; Body = $body; Bare = -not $vp.IsScript }
    if ($isWrite) { if (-not $writes[$name]) { $writes[$name] = New-Object 'System.Collections.Generic.List[object]' }; $writes[$name].Add($rec) }
    else          { $reads.Add($rec) }
}
$stranded = New-Object 'System.Collections.Generic.List[string]'
foreach ($r in $reads) {
    if (-not $writes[$r.Name]) { continue }
    $last = $writes[$r.Name] | Where-Object { $_.Offset -lt $r.Offset } | Select-Object -Last 1
    if (-not $last -or -not $last.Bare -or -not $last.Body) { continue }
    $sees = $r.Body -and ($r.Body -eq $last.Body -or (Test-Within $r.Body $last.Body))
    if (-not $sees) { $stranded.Add("`$$($r.Name) read at line $($r.Line), last set at line $($last.Line) inside an Invoke-SafeBlock that does not enclose the read") }
}
if ($stranded.Count) {
    foreach ($s in ($stranded | Select-Object -Unique)) { Fail 'scope' $s }
} else { Say '  ok    scope  -  nothing set inside an Invoke-SafeBlock is read from outside it' Green }

$env:COMPUTERNAME = $origComputerName

Say ''
if ($failures -gt 0) {
    Say "  FAILED - $failures assertion(s)" Red
    exit 1
}
Say '  PASS - all assertions' Green
exit 0

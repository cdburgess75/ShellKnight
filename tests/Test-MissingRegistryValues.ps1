<#
.SYNOPSIS
    Regression test: a registry value that is not set, a cmdlet that cannot
    answer, or an empty folder no longer stops a whole check.

.DESCRIPTION
    Invoke-SafeBlock catches whatever its block throws, logs '<label> skipped'
    and drops the rest of the block. Up to v2026.09.26.001 most checks read a
    registry value as (Get-ItemProperty $key -Name X -ErrorAction
    SilentlyContinue).X. Where X is not set, which is Windows' default for
    most policies, Get-ItemProperty returns nothing, and .X on nothing throws
    under Set-StrictMode -Version 2. A real run on HOST-A3 (Windows 11 Pro
    22621, 2026-09-26) logged:

        LLMNR check skipped            - 'EnableMulticast' cannot be found
        LAN Manager auth check skipped - 'LmCompatibilityLevel' cannot be found
        CIS Benchmark skipped          - 'LmCompatibilityLevel' (after 1.1.1)
        PS script block audit skipped  - 'EnableScriptBlockLogging'
        Credential exposure skipped    - 'UseLogonCredential'
        Windows Update Cache skipped   - 'Sum' (Measure-Object over no files)
        Local admin check skipped      - error code = 1789 (Get-LocalGroupMember)
        Defender exclusions skipped    - 0x%1!x! (Defender off, Datto AV)

    Each block here runs verbatim from ShellKnight.ps1 against mocks that
    return a registry key without the value asked for (the object Windows would
    return for the key, missing that property), or no key at all. It asserts
    that each block runs to its end and never logs 'skipped', and it checks what
    a value that is not set is taken to mean. Windows' default is used where it
    is documented: LmCompatibilityLevel 3, LLMNR on, WDigest off, script block
    logging off. Otherwise the value is unknown, and unknown raises no finding
    and costs no score (ADR 0009). It checks every write each block makes. It
    also covers the LAN Manager scoring rule, Get-RegistryValue itself,
    Remove-FolderContents on an empty folder, and the Windows Update services
    being started again when the cleanup throws.

    It also parses the whole script and fails on the general form of the bug: a
    property read straight off (Get-ItemProperty ...), unless that call is
    -ErrorAction Stop inside a try that handles the missing value.

    The Windows cmdlets are mocked (the filesystem is a real temp tree), so
    this runs on the CI Linux runner. It does not replace a real Windows run.
    ShellKnight.ps1 is a monolith that executes on load, so the code is
    extracted textually rather than dot-sourced.
#>
Set-StrictMode -Version 2
# The test's own logic stops on any error. Only the extracted ShellKnight code
# runs under the script's own 'SilentlyContinue' (see Test-Case).
$ErrorActionPreference = 'Stop'

$scriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'ShellKnight.ps1'
$source = Get-Content -LiteralPath $scriptPath -Raw

function Get-Section {
    param([string]$Pattern, [string]$What)
    $m = [regex]::Match($source, $Pattern)
    if (-not $m.Success) { throw "$What not found in ShellKnight.ps1 - did it get renamed or moved?" }
    $m.Value
}
function Get-Block([string]$Label, [string]$Indent = '    ') {
    Get-Section "(?ms)^$Indent`Invoke-SafeBlock -Label '$([regex]::Escape($Label))' -Block \{.*?^$Indent\}" "the '$Label' block"
}

$safeBlock   = Get-Section '(?ms)^function Invoke-SafeBlock \{.*?^\}' 'Invoke-SafeBlock'
$regValueFn  = Get-Section '(?ms)^function Get-RegistryValue \{.*?^\}' 'Get-RegistryValue'
$adminNameFn = Get-Section '(?ms)^function Get-LocalAdminName \{.*?^\}' 'Get-LocalAdminName'
$folderFn    = Get-Section '(?ms)^function Remove-FolderContents \{.*?^\}' 'Remove-FolderContents'
$rdp         = Get-Block 'RDP check'
$llmnr       = Get-Block 'LLMNR check'
$lmAuth      = Get-Block 'LAN Manager auth check'
$localAdmin  = Get-Block 'Local admin check'
$exclusions  = Get-Block 'Defender exclusions'
$wuCache     = Get-Block 'Windows Update Cache' '        '
$sbAudit     = Get-Block 'PS script block audit'
$credential  = Get-Block 'Credential exposure'
$cis         = Get-Block 'CIS Benchmark'
# The scoring's LAN Manager rule: the read and the deduction.
$lmScore     = Get-Section '(?m)^\$lmSc = .*\r?\n^if \(.*\$lmSc.*$' 'the LAN Manager scoring rule'

# --- Mocks. Functions take precedence over cmdlets of the same name. ---------
function Say { param([string]$m, [string]$c = 'Gray') Microsoft.PowerShell.Utility\Write-Host $m -ForegroundColor $c }
function Write-Host { }
# Every log line as 'LEVEL|message', so a case can assert the level too.
$Script:Logged   = New-Object 'System.Collections.Generic.List[string]'
$Script:Findings = New-Object 'System.Collections.Generic.List[object]'
$Script:Writes   = New-Object 'System.Collections.Generic.List[string]'   # registry writes and service starts/stops
function Log-Info    { param([string]$m) $Script:Logged.Add("INFO|$m") }
function Log-Warn    { param([string]$m) $Script:Logged.Add("WARN|$m") }
function Log-Summary { param([string]$m) $Script:Logged.Add("SUMMARY|$m") }
function Log-Harden  { param([string]$m) $Script:Logged.Add("HARDEN|$m") }
function Log-IOC     { param([string]$m) $Script:Logged.Add("IOC|$m") }
function Log-Success { param([string]$m) $Script:Logged.Add("SUCCESS|$m") }
function Add-Finding { param($Severity, $Title, $Action) $Script:Findings.Add([pscustomobject]@{ Severity = $Severity; Title = $Title }) }

$Script:Config   = [pscustomobject]@{ DisableLLMNR = $false; SetLMAuthLevel = $false; LMAuthLevel = 5
                                      EnforceRDP_NLA = $false; EnableScriptBlockLogging = $false }
$Script:Counters = @{ IOCsFound = 0; ActionsTaken = 0; FilesRemoved = 0 }
$Script:SpaceFreed     = 0L
$Script:MinPasswordLen = 14
$Script:SecurityScore  = 100

# The registry: key path -> hashtable of the values set on it. A key that is
# not in $Script:Reg does not exist; 'throw' makes reading it fail (access
# denied). Asked for a value the key does not have, the mock returns the key's
# other values: a registry object missing that property.
$Script:Reg = @{}
function Get-ItemProperty {
    param($Path, $Name, $ErrorAction)
    $key = "$Path"
    if (-not $Script:Reg.ContainsKey($key)) { return }
    if ($Script:Reg[$key] -eq 'throw') { throw "Requested registry access is not allowed. (mock: $key)" }
    $o = [ordered]@{ PSPath = "Microsoft.PowerShell.Core\Registry::$key"; PSChildName = ($key -split '\\')[-1] }
    foreach ($k in $Script:Reg[$key].Keys) { $o[$k] = $Script:Reg[$key][$k] }
    [pscustomobject]$o
}
function Set-ItemProperty {
    param([Parameter(Position = 0)]$Path, $Name, $Value, $Type, [switch]$Force)
    $Script:Writes.Add("set $Path|$Name=$Value")
}
function New-Item {
    param([Parameter(Position = 0)]$Path, $ItemType, [switch]$Force)
    $Script:Writes.Add("new $Path")
}
function Test-Path {
    param([Parameter(Position = 0)]$Path, $LiteralPath)
    $p = if ($LiteralPath) { "$LiteralPath" } else { "$Path" }
    if ($p -like 'HKLM:*') { return $Script:Reg.ContainsKey($p) }
    Microsoft.PowerShell.Management\Test-Path -LiteralPath $p
}

# The scenario for the non-registry mocks.
$Script:W = @{}
function Get-LocalGroupMember {
    param($SID, $Group, $ErrorAction)
    $Script:Writes.Add("Get-LocalGroupMember SID=$SID Group=$Group")
    if ($Script:W.Lgm -eq 'throw') { throw 'An unspecified error occurred: error code = 1789' }
    foreach ($n in $Script:W.Lgm) { [pscustomobject]@{ Name = $n; ObjectClass = 'User' } }
}
# ADSI does not exist off Windows; the real Get-LocalAdminAdsPath is not loaded.
function Get-LocalAdminAdsPath {
    if ($Script:W.Adsi -eq 'throw') { throw 'Exception calling "Invoke" with "1" argument(s): (mock ADSI failure)' }
    foreach ($p in $Script:W.Adsi) { $p }
}
function Get-MpPreference {
    param($ErrorAction)
    switch ($Script:W.Mp) {
        'throw'       { throw 'Operation failed with the following error: 0x%1!x!' }
        'no-property' { return [pscustomobject]@{ DisableRealtimeMonitoring = $false } }
        default       { return [pscustomobject]@{ ExclusionPath = $Script:W.Mp } }
    }
}
function Get-Service {
    param($Name, $ErrorAction)
    if ($Name -in 'wuauserv', 'bits', 'UsoSvc') { return [pscustomobject]@{ Name = $Name; Status = 'Running' } }
    if ($Name -eq 'RemoteRegistry') { return [pscustomobject]@{ Name = $Name; Status = 'Stopped'; StartType = 'Disabled' } }
    return $null
}
function Stop-Service  { param($Name, [switch]$Force, $ErrorAction) $Script:Writes.Add("stop $Name") }
function Start-Service { param($Name, $ErrorAction) $Script:Writes.Add("start $Name") }
function Start-Sleep   { param($Seconds) }
function Get-WinEvent  { param($FilterHashtable, $ErrorAction) @($Script:W.Events) }
function Get-LocalUser { param($Name, $ErrorAction) $null }
function Get-NetFirewallProfile     { param($ErrorAction) @([pscustomobject]@{ Profile = 'Domain'; Enabled = $true }) }
function Get-SmbServerConfiguration { param($ErrorAction) [pscustomobject]@{ EnableSMB1Protocol = $false } }
function Get-MpComputerStatus       { param($ErrorAction) [pscustomobject]@{ AMServiceEnabled = $true } }

Invoke-Expression $safeBlock
Invoke-Expression $regValueFn
Invoke-Expression $adminNameFn
Invoke-Expression $folderFn

# --- Registry fixtures -------------------------------------------------------
$lsa      = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$dns      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
$sbKey    = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
$wdigest  = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
$devGuard = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
$explorer = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
$ts       = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$rdpTcp   = "$ts\WinStations\RDP-Tcp"
# As HOST-A3 read: the keys exist, the values under test are not set, and
# the policy keys nothing has written are absent.
function New-HostA3Registry {
    @{
        $lsa      = @{ LimitBlankPasswordUse = 1; NoLmHash = 1 }
        $wdigest  = @{ Negotiate = 0; UTF8HTTP = 1 }
        $devGuard = @{}
        $explorer = @{}
        $ts       = @{ fDenyTSConnections = 1 }
    }
}
function With-Reg([hashtable]$Reg, [string]$Key, [hashtable]$Values) {
    $r = @{}; foreach ($k in $Reg.Keys) { $r[$k] = $Reg[$k] }
    $r[$Key] = $Values; $r
}

# --- Harness -----------------------------------------------------------------
$failures = 0
$Script:CaseFail = New-Object 'System.Collections.Generic.List[string]'
function Fail([string]$Label, [string]$Why) {
    Say "  FAIL  $Label  -  $Why" Red
    $script:failures++
}
function Want([bool]$Ok, [string]$Why) { if (-not $Ok) { $Script:CaseFail.Add($Why) } }
function Want-Log([string]$Pattern) {
    Want (@($Script:Logged | Where-Object { $_ -match $Pattern }).Count -gt 0) "no log line matches /$Pattern/; got: $($Script:Logged -join ' || ')"
}
function Want-NoLog([string]$Pattern) {
    $hit = @($Script:Logged | Where-Object { $_ -match $Pattern })
    Want ($hit.Count -eq 0) "unexpected log line: $($hit -join ' || ')"
}
function Want-Writes([string[]]$Expected) {
    $got = @($Script:Writes | Where-Object { $_ -match '^(set|new) ' })
    Want ((@($got) -join ';') -eq (@($Expected) -join ';')) "registry writes: [$($got -join '; ')], expected [$(@($Expected) -join '; ')]"
}
function Want-Findings([string[]]$Expected) {
    $got = @($Script:Findings | ForEach-Object { "$($_.Severity): $($_.Title)" })
    Want ((@($got) -join ';') -eq (@($Expected) -join ';')) "findings: [$($got -join '; ')], expected [$(@($Expected) -join '; ')]"
}

# Runs $Code as ShellKnight.ps1 runs it (SilentlyContinue), then $Expect. The
# block must reach its end: no 'skipped' line, unless -MayAbort.
function Test-Case {
    param([string]$Name, [string]$Code, [hashtable]$Reg = @{}, [hashtable]$Config = @{},
          [hashtable]$With = @{}, [scriptblock]$Expect, [switch]$MayAbort)
    $Script:Reg = $Reg
    $Script:W   = $With
    $Script:Logged.Clear(); $Script:Findings.Clear(); $Script:Writes.Clear(); $Script:CaseFail.Clear()
    $Script:Counters.IOCsFound = 0
    $Script:SecurityScore = 100
    $Script:Config.DisableLLMNR = $false; $Script:Config.SetLMAuthLevel = $false
    $Script:Config.EnforceRDP_NLA = $false; $Script:Config.EnableScriptBlockLogging = $false
    foreach ($k in $Config.Keys) { $Script:Config.$k = $Config[$k] }

    $ErrorActionPreference = 'SilentlyContinue'   # as ShellKnight.ps1 runs
    try { Invoke-Expression $Code } finally { $ErrorActionPreference = 'Stop' }

    if (-not $MayAbort) { Want-NoLog '^INFO\|.* skipped  -  ' }
    & $Expect
    if ($Script:CaseFail.Count) { foreach ($w in $Script:CaseFail) { Fail $Name $w } }
    else { Say "  ok    $Name" Green }
}

Say ''
Say '  A value that is not set no longer stops a check (StrictMode 2)'
Say '  --------------------------------------------------------------'

# --- Get-RegistryValue -------------------------------------------------------
$Script:Reg = @{ $lsa = @{ LmCompatibilityLevel = 0; RunAsPPL = 1; Name = 'text' }; $wdigest = 'throw' }
$cases = @(
    ,@('value 0 is 0, not $null', $lsa,     'LmCompatibilityLevel', 0)
    ,@('value 1',                 $lsa,     'RunAsPPL',             1)
    ,@('string value',            $lsa,     'Name',                 'text')
    ,@('value not set',           $lsa,     'NoSuchValue',          $null)
    ,@('key absent',              $dns,     'EnableMulticast',      $null)
    ,@('key unreadable',          $wdigest, 'UseLogonCredential',   $null)
)
# Each row is an array of its own (the leading commas), not flattened into $cases.
foreach ($c in $cases) {
    $want = $c[3]
    try { $got = Get-RegistryValue -Path $c[1] -Name $c[2] }
    catch { Fail "Get-RegistryValue: $($c[0])" "threw: $($_.Exception.Message)"; continue }
    if (($null -eq $got) -ne ($null -eq $want) -or ($null -ne $want -and $got -ne $want)) {
        Fail "Get-RegistryValue: $($c[0])" "returned $(if ($null -eq $got) { '<null>' } else { "'$got'" })"
    } else { Say "  ok    Get-RegistryValue: $($c[0])" Green }
}

# --- Phase 3: RDP -------------------------------------------------------------
Test-Case 'rdp: disabled' $rdp -Reg (New-HostA3Registry) -Expect {
    Want-Log '^SUMMARY\|RDP  -  disabled \(OK\)'; Want-Findings @()
}
Test-Case 'rdp: enabled, NLA enforced' $rdp -Reg (With-Reg (With-Reg (New-HostA3Registry) $ts @{ fDenyTSConnections = 0 }) $rdpTcp @{ UserAuthentication = 1 }) -Expect {
    Want-Log 'NLA enforced \(OK\)'; Want-Findings @()
}
Test-Case 'rdp: enabled, NLA off' $rdp -Reg (With-Reg (With-Reg (New-HostA3Registry) $ts @{ fDenyTSConnections = 0 }) $rdpTcp @{ UserAuthentication = 0 }) -Expect {
    Want-Findings @('Medium: RDP enabled, NLA not enforced'); Want-Writes @()
}
# Not read is unknown: no 'NLA not enforced' finding, and no write even when
# enforcing NLA is switched on.
Test-Case 'rdp: enabled, UserAuthentication not set' $rdp -Reg (With-Reg (With-Reg (New-HostA3Registry) $ts @{ fDenyTSConnections = 0 }) $rdpTcp @{ PortNumber = 3389 }) -Config @{ EnforceRDP_NLA = $true } -Expect {
    Want-Log '^INFO\|RDP is ENABLED  -  NLA setting \(UserAuthentication\) not found; not checked'
    Want-Findings @(); Want-Writes @()
}
Test-Case 'rdp: fDenyTSConnections not set' $rdp -Reg (With-Reg (New-HostA3Registry) $ts @{ TSUserEnabled = 0 }) -Expect {
    Want-Log '^INFO\|RDP  -  fDenyTSConnections not found; not checked'; Want-Findings @()
}

# --- Phase 3: LLMNR -----------------------------------------------------------
# Not set is Windows' default: LLMNR on. A warning, never a finding or a write
# unless $SK_DisableLLMNR asks for one.
Test-Case 'llmnr: policy key absent' $llmnr -Reg (New-HostA3Registry) -Expect {
    Want-Log '^WARN\|LLMNR enabled \(policy not set; Windows default is on\)'; Want-Writes @(); Want-Findings @()
}
Test-Case 'llmnr: policy key without EnableMulticast' $llmnr -Reg (With-Reg (New-HostA3Registry) $dns @{ EnableMDNS = 0 }) -Expect {
    Want-Log '^WARN\|LLMNR enabled \(policy not set'; Want-Writes @()
}
Test-Case 'llmnr: disabled by policy' $llmnr -Reg (With-Reg (New-HostA3Registry) $dns @{ EnableMulticast = 0 }) -Expect {
    Want-Log '^SUMMARY\|LLMNR  -  disabled \(OK\)'; Want-Writes @()
}
Test-Case 'llmnr: enabled by policy' $llmnr -Reg (With-Reg (New-HostA3Registry) $dns @{ EnableMulticast = 1 }) -Expect {
    Want-Log '^WARN\|LLMNR enabled by policy \(EnableMulticast = 1\)'; Want-Writes @()
}
Test-Case 'llmnr: not set, DisableLLMNR on' $llmnr -Reg (New-HostA3Registry) -Config @{ DisableLLMNR = $true } -Expect {
    Want-Writes @("new $dns", "set $dns|EnableMulticast=0"); Want-Log '^HARDEN\|LLMNR disabled'
}

# --- Phase 3: LAN Manager auth ------------------------------------------------
# Not set is Windows' default, 3: OK, and $SK_SetLMAuthLevel does not touch it
# (it raises levels below 3, as it always has for a level that is set).
Test-Case 'lm: not set' $lmAuth -Reg (New-HostA3Registry) -Expect {
    Want-Log '^SUMMARY\|LAN Manager auth level: not set, Windows default 3'; Want-NoLog '^WARN\|'; Want-Writes @()
}
Test-Case 'lm: not set, SetLMAuthLevel on' $lmAuth -Reg (New-HostA3Registry) -Config @{ SetLMAuthLevel = $true } -Expect {
    Want-Writes @()
}
Test-Case 'lm: 2' $lmAuth -Reg (With-Reg (New-HostA3Registry) $lsa @{ LmCompatibilityLevel = 2 }) -Expect {
    Want-Log '^WARN\|LAN Manager auth level is 2'; Want-Writes @()
}
Test-Case 'lm: 2, SetLMAuthLevel on' $lmAuth -Reg (With-Reg (New-HostA3Registry) $lsa @{ LmCompatibilityLevel = 2 }) -Config @{ SetLMAuthLevel = $true } -Expect {
    Want-Writes @("set $lsa|LmCompatibilityLevel=5")
}
Test-Case 'lm: 5' $lmAuth -Reg (With-Reg (New-HostA3Registry) $lsa @{ LmCompatibilityLevel = 5 }) -Expect {
    Want-Log '^SUMMARY\|LAN Manager auth level: 5 \(OK\)'
}

# --- Phase 3: local Administrators --------------------------------------------
Test-Case 'admins: Get-LocalGroupMember answers' $localAdmin -With @{ Lgm = @('HOST-A3\Administrator', 'CORP\Domain Admins', 'CORP\Domain Users', 'CORP\jdoe') } -Expect {
    Want-Findings @("High: 'CORP\Domain Users' is in local Administrators (ALL domain users have admin)", 'Medium: Local admin: CORP\jdoe')
    # By SID, so a localized group name (Administratoren) is found too.
    Want (@($Script:Writes | Where-Object { $_ -eq 'Get-LocalGroupMember SID=S-1-5-32-544 Group=' }).Count -eq 1) "Get-LocalGroupMember not called by SID: $($Script:Writes -join '; ')"
}
# HOST-A3: error 1789. The WinNT provider lists the members unresolved.
Test-Case 'admins: error 1789, ADSI fallback' $localAdmin -With @{ Lgm = 'throw'; Adsi = @(
        'WinNT://WORKGROUP/HOST-A3/Administrator', 'WinNT://CORP/Domain Admins',
        'WinNT://CORP/jdoe', 'WinNT://S-1-5-21-1111-2222-3333-1105') } -Expect {
    Want-Log '^WARN\|Local admins found \(4 total\)'
    Want-Findings @('Medium: Local admin: CORP\jdoe', 'Medium: Local admin: S-1-5-21-1111-2222-3333-1105')
}
# A one-member list must stay a list (Count 1), not become a bare string.
Test-Case 'admins: error 1789, only Administrator' $localAdmin -With @{ Lgm = 'throw'; Adsi = @('WinNT://WORKGROUP/HOST-A3/Administrator') } -Expect {
    Want-Log '^SUMMARY\|Local admins  -  1 account\(s\) \(OK\)'; Want-Findings @()
}
# An empty list is an answer (0 members), not unknown.
Test-Case 'admins: group is empty' $localAdmin -With @{ Lgm = @() } -Expect {
    Want-Log '^SUMMARY\|Local admins  -  0 account\(s\) \(OK\)'; Want-NoLog 'could not be listed'
}
Test-Case 'admins: neither can list them' $localAdmin -With @{ Lgm = 'throw'; Adsi = 'throw' } -Expect {
    Want-Log '^INFO\|Local admins  -  could not be listed'; Want-Findings @()
}

# --- Phase 5: Defender exclusions ---------------------------------------------
Test-Case 'exclusions: Defender off (Datto AV)' $exclusions -With @{ Mp = 'throw' } -Expect {
    Want-Log '^INFO\|Defender exclusions  -  not checked'; Want-Findings @()
}
Test-Case 'exclusions: one suspicious' $exclusions -With @{ Mp = @('C:\Program Files\Vendor', 'C:\Users\Public\x') } -Expect {
    Want-Findings @('High: Suspicious Defender exclusion: C:\Users\Public\x')
}
Test-Case 'exclusions: none set' $exclusions -With @{ Mp = $null } -Expect {
    Want-Log '^SUMMARY\|Persistence Engine  -  no suspicious Defender exclusions found'; Want-Findings @()
}
Test-Case 'exclusions: no ExclusionPath property' $exclusions -With @{ Mp = 'no-property' } -Expect {
    Want-Log 'no suspicious Defender exclusions found'; Want-Findings @()
}

# --- Phase 6: Windows Update cache (a real temp folder) -----------------------
$tmpRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('sk-missing-values-test-' + [guid]::NewGuid().ToString('N'))
try {
    $wuDir = Join-Path $tmpRoot 'Download'
    [void](Microsoft.PowerShell.Management\New-Item -ItemType Directory -Path $wuDir -Force)
    $wuLive = "'C:\Windows\SoftwareDistribution\Download'"
    if (-not $wuCache.Contains($wuLive)) { throw "the Windows Update Cache block no longer names $wuLive (test harness check)" }
    $wuHere = $wuCache.Replace($wuLive, "'$wuDir'")
    $svcCycle = @('stop wuauserv', 'stop bits', 'stop UsoSvc', 'start wuauserv', 'start bits', 'start UsoSvc')

    Test-Case 'wu cache: empty folder' $wuHere -Expect {
        Want-NoLog '^SUCCESS\|'
        Want ((@($Script:Writes) -join ';') -eq ($svcCycle -join ';')) "services: [$($Script:Writes -join '; ')]"
    }
    foreach ($n in 1..3) { Set-Content -LiteralPath (Join-Path $wuDir "update$n.cab") -Value ('x' * 1024) }
    Test-Case 'wu cache: three files' $wuHere -Expect {
        Want-Log '^SUCCESS\|Cleaned Windows Update Cache  -  Before: 3 files'
        Want (@(Get-ChildItem -LiteralPath $wuDir -File).Count -eq 0) 'files were not removed'
        Want ((@($Script:Writes) -join ';') -eq ($svcCycle -join ';')) "services: [$($Script:Writes -join '; ')]"
    }
    # Whatever the cleanup throws, the services it stopped are started again.
    function Remove-FolderContents { param([string]$Path, [string]$Label) throw 'cleanup failed (mock)' }
    Test-Case 'wu cache: cleanup throws' $wuHere -MayAbort -Expect {
        Want-Log '^INFO\|Windows Update Cache skipped  -  cleanup failed'
        Want ((@($Script:Writes) -join ';') -eq ($svcCycle -join ';')) "services not started again: [$($Script:Writes -join '; ')]"
    }
    Invoke-Expression $folderFn   # the real one again

    # Called outside any Invoke-SafeBlock, under the test's own 'Stop'.
    try { Remove-FolderContents -Path $wuDir -Label 'empty'; Say '  ok    Remove-FolderContents: empty folder' Green }
    catch { Fail 'Remove-FolderContents: empty folder' $_.Exception.Message }
}
finally {
    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $tmpRoot) { Remove-Item -LiteralPath $tmpRoot -Recurse -Force -ErrorAction SilentlyContinue }
}

# --- Phase 8: PowerShell script block audit -----------------------------------
# Not set is Windows' default: off. Turning it on is opt-in
# ($SK_EnableScriptBlockLogging, default $false); the unconditional write the
# old read never let run must not start running now.
Test-Case 'script block: policy key absent' $sbAudit -Reg (New-HostA3Registry) -Expect {
    Want-Log '^INFO\|PS script block audit  -  script block logging \(4104\) is off \(policy not set\)'; Want-Writes @()
}
Test-Case 'script block: policy key without the value' $sbAudit -Reg (With-Reg (New-HostA3Registry) $sbKey @{ EnableScriptBlockInvocationLogging = 0 }) -Expect {
    Want-Log 'is off \(policy not set\)'; Want-Writes @()
}
Test-Case 'script block: off by policy' $sbAudit -Reg (With-Reg (New-HostA3Registry) $sbKey @{ EnableScriptBlockLogging = 0 }) -Expect {
    Want-Log 'is off \(EnableScriptBlockLogging = 0\)'; Want-Writes @()
}
Test-Case 'script block: not set, opted in' $sbAudit -Reg (New-HostA3Registry) -Config @{ EnableScriptBlockLogging = $true } -Expect {
    Want-Writes @("new $sbKey", "set $sbKey|EnableScriptBlockLogging=1"); Want-Log '^HARDEN\|PowerShell script block logging \(4104\) enabled'
}
Test-Case 'script block: on, events audited' $sbAudit -Reg (With-Reg (New-HostA3Registry) $sbKey @{ EnableScriptBlockLogging = 1 }) -With @{ Events = @(
        [pscustomobject]@{ TimeCreated = (Get-Date); Message = 'Get-ChildItem C:\' }
        [pscustomobject]@{ TimeCreated = (Get-Date); Message = 'Write-Output ok' }) } -Expect {
    Want-Log '^SUMMARY\|PS script block audit  -  2 events checked, no obfuscation found'; Want-Writes @()
}

# --- Phase 8: credential exposure ---------------------------------------------
# Not set: WDigest off (8.1 / 2012 R2 on), LSA protection and VBS off. Only an
# explicit UseLogonCredential = 1 is the IOC.
foreach ($c in @(@('credential: values not set', (New-HostA3Registry)), @('credential: keys absent', @{}))) {
    Test-Case $c[0] $credential -Reg $c[1] -Expect {
        Want-Log '^SUMMARY\|WDigest  -  plaintext credential caching disabled \(OK\)'
        Want-Log '^WARN\|LSA protection \(RunAsPPL\) not enabled'
        Want-Log '^INFO\|Credential Guard  -  not enabled'
        Want ($Script:Counters.IOCsFound -eq 0) "IOCsFound = $($Script:Counters.IOCsFound)"
    }
}
Test-Case 'credential: WDigest on' $credential -Reg (With-Reg (New-HostA3Registry) $wdigest @{ UseLogonCredential = 1 }) -Expect {
    Want-Log '^IOC\|WDigest ENABLED'; Want ($Script:Counters.IOCsFound -eq 1) "IOCsFound = $($Script:Counters.IOCsFound)"
}

# --- Phase 8: CIS Benchmark ---------------------------------------------------
# HOST-A3 stopped after 1.1.1. It must reach its summary line.
Test-Case 'cis: values not set' $cis -Reg (New-HostA3Registry) -Expect {
    Want-Log '^INFO\|  \[CIS 2\.3\] LAN Manager auth level: not set, Windows default 3 \(OK\)'
    Want-Log '^WARN\|  \[CIS 2\.8\] AutoRun not fully disabled'
    Want-Log '^INFO\|  \[CIS 2\.9\] Windows Defender enabled \(OK\)'
    Want-Log '^WARN\|CIS Benchmark Lite  -  1 check\(s\) failed'
}
Test-Case 'cis: LAN Manager 2, AutoRun 255' $cis -Reg (With-Reg (With-Reg (New-HostA3Registry) $lsa @{ LmCompatibilityLevel = 2 }) $explorer @{ NoDriveTypeAutoRun = 255 }) -Expect {
    Want-Log '^WARN\|  \[CIS 2\.3\] LAN Manager auth level is 2'
    Want-Log '^INFO\|  \[CIS 2\.8\] AutoRun disabled \(OK\)'
    Want-Log '^WARN\|CIS Benchmark Lite  -  1 check\(s\) failed'
}

# --- Scoring: LAN Manager rule ------------------------------------------------
# Only a level that is set and below 3 costs 15 (ADR 0009).
foreach ($c in @(@('not set', (New-HostA3Registry), 100), @('key unreadable', @{ $lsa = 'throw' }, 100),
                 @('level 2', (With-Reg (New-HostA3Registry) $lsa @{ LmCompatibilityLevel = 2 }), 85),
                 @('level 0', (With-Reg (New-HostA3Registry) $lsa @{ LmCompatibilityLevel = 0 }), 85),
                 @('level 3', (With-Reg (New-HostA3Registry) $lsa @{ LmCompatibilityLevel = 3 }), 100))) {
    $want = $c[2]
    Test-Case "score: LAN Manager $($c[0])" $lmScore -Reg $c[1] -Expect {
        Want ($Script:SecurityScore -eq $want) "security score $($Script:SecurityScore), expected $want"
    }
}

# --- Static: fleet-safety defaults and the bug in general form ----------------
if ($source -match '(?m)^\$SK_EnableScriptBlockLogging\s+=\s+\$false\b') { Say '  ok    config  -  $SK_EnableScriptBlockLogging defaults to $false' Green }
else { Fail 'config' '$SK_EnableScriptBlockLogging must default to $false (it writes HKLM policy on every endpoint)' }

# A property read straight off (Get-ItemProperty ...) throws under StrictMode
# 2 when the value is not set. It is allowed only as -ErrorAction Stop inside a
# try, where a missing value lands in that try's catch.
$tokens = $null; $parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw "ShellKnight.ps1 does not parse: $($parseErrors[0].Message)" }
$L = 'System.Management.Automation.Language'
$bad = New-Object 'System.Collections.Generic.List[string]'
foreach ($m in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.MemberExpressionAst] }, $true)) {
    if ($m.Expression -isnot "$L.ParenExpressionAst") { continue }
    $gip = @($m.Expression.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and
                                     $n.GetCommandName() -eq 'Get-ItemProperty' }, $true))
    if (-not $gip.Count) { continue }
    $stop = "$($gip[0].Extent.Text)" -match '-ErrorAction\s+Stop\b'
    $inTry = $false
    for ($p = $m.Parent; $p; $p = $p.Parent) {
        if ($p -is "$L.TryStatementAst" -and $p.Body.Extent.StartOffset -le $m.Extent.StartOffset -and
            $m.Extent.EndOffset -le $p.Body.Extent.EndOffset) { $inTry = $true; break }
    }
    if (-not ($stop -and $inTry)) { $bad.Add("line $($m.Extent.StartLineNumber): $($m.Extent.Text -replace '\s+', ' ')") }
}
if ($bad.Count) { foreach ($b in $bad) { Fail 'static' "property read off Get-ItemProperty (use Get-RegistryValue): $b" } }
else { Say '  ok    static  -  no property is read straight off Get-ItemProperty outside a handled try' Green }

Say ''
if ($failures -gt 0) {
    Say "  FAILED - $failures assertion(s)" Red
    exit 1
}
Say '  PASS - all assertions' Green
exit 0

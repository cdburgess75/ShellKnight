<#
.SYNOPSIS
    Regression test: a Run always reports a real device_id, and the Assessment
    Engine survives Defender and Windows Update probes that come back empty.

.DESCRIPTION
    v2026.09.24.001 fixed two linked bugs. v2026.09.08.001 left $defSigs unset
    whenever every Defender probe failed, so reading it in the MachineInfo
    literal threw under Set-StrictMode -Version 2 and aborted the whole engine.
    Device identity was computed inside that engine, so the report went out
    with device_id null, Battlefield fell back to host:<name>, and under frozen
    enrollment a device enrolled by hardware UUID was silently "ignored".

    This runs the Phase 2 code taken verbatim from ShellKnight.ps1 (from the
    MachineInfo reset through the end of the MachineInfo literal) under the
    script's own StrictMode 2 / SilentlyContinue settings, with the Windows
    cmdlets replaced by mocks, so it runs on the CI Linux runner. It does not
    replace a real Windows run.

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
$biosDate  = Get-Section '(?ms)^function ConvertTo-BiosDate \{.*?^\}' 'ConvertTo-BiosDate'
$osEol     = Get-Section '(?ms)^function Get-OsEolDate \{.*?^\}' 'Get-OsEolDate'
# Phase 2 init, the device identity block, and the engine up to the end of the
# MachineInfo literal. The engine's Invoke-SafeBlock and if are closed by hand.
$phase2    = Get-Section ('(?ms)^\$Script:MachineInfo = \[ordered\]@\{\}\s*$.*?' +
                          '^        \$Script:MachineInfo = \[ordered\]@\{.*?^        \}\s*$') 'Phase 2 through the MachineInfo literal'
$phase2   += "`n    }`n}`n"

# --- Mocks. Functions take precedence over cmdlets of the same name. ---------
$Script:Scenario = ''
$Script:Logged   = New-Object 'System.Collections.Generic.List[string]'
function Log-Info { param([string]$m) $Script:Logged.Add($m) }
function Log-Warn { param([string]$m) }
$Script:Config    = [pscustomobject]@{ AssessmentEngine_Enabled = $true }
$Script:Counters  = @{ IntelSource = 'test' }
$Script:HWInfo    = @{ IsServer = $false }
$Script:PSFullVer = '5.1.22621.5697'
$origComputerName = $env:COMPUTERNAME     # process-wide: restored at the end
$env:COMPUTERNAME = 'SK-TEST-PC'

$Script:Uuid        = '4C4C4544-0042-5810-8052-B4C04F4B4C33'
$Script:MachineGuid = 'b1e2c3d4-0000-1111-2222-333344445555'

function Get-CimInstance {
    param($ClassName, $Namespace, $Filter, $ErrorAction)
    $s = $Script:Scenario
    switch ($ClassName) {
        'Win32_OperatingSystem' {
            if ($s -in 'engine-aborts', 'wmi-down') { throw 'Invalid class (WMI repository damaged)' }
            return [pscustomobject]@{ Caption = 'Microsoft Windows 11 Pro'; BuildNumber = '22621'
                                      OSArchitecture = '64-bit'; LastBootUpTime = (Get-Date).AddDays(-2) }
        }
        'Win32_ComputerSystem' {
            return [pscustomobject]@{ PartOfDomain = $true; Domain = 'corp.local'; Workgroup = $null
                                      UserName = 'CORP\user'; TotalPhysicalMemory = 17179869184 }
        }
        'Win32_BIOS'        { return [pscustomobject]@{ ReleaseDate = [datetime]'2021-03-01' } }
        'Win32_LogicalDisk' { return [pscustomobject]@{ FreeSpace = 100GB; Size = 250GB } }
        'AntiVirusProduct'  {
            return @([pscustomobject]@{ displayName = 'Windows Defender' },
                     [pscustomobject]@{ displayName = 'Bitdefender Endpoint Security Tools' })
        }
        'MSFT_MpComputerStatus' {
            if ($s -eq 'defender-stopped') { throw 'The service cannot be started (0x800106ba)' }
            if ($s -eq 'defender-removed') { throw 'Invalid namespace' }
            $sig = if ($s -eq 'cim-no-sig-date') { $null } else { (Get-Date).AddHours(-5) }
            return [pscustomobject]@{ AMServiceEnabled = $true; RealTimeProtectionEnabled = $true
                                      AntivirusSignatureLastUpdated = $sig }
        }
        'Win32_ComputerSystemProduct' {
            if ($s -in 'no-uuid', 'no-uuid-no-guid', 'wmi-down') { throw 'Generic failure' }
            if ($s -eq 'zero-uuid') { return [pscustomobject]@{ UUID = '00000000-0000-0000-0000-000000000000' } }
            return [pscustomobject]@{ UUID = $Script:Uuid }
        }
        'Win32_SystemEnclosure'   { return [pscustomobject]@{ ChassisTypes = @(3) } }
        'Win32_EncryptableVolume' { return [pscustomobject]@{ ProtectionStatus = 1 } }
        default { throw "unmocked CIM class $ClassName" }
    }
}
function Get-MpComputerStatus {
    param($ErrorAction)
    if ($Script:Scenario -eq 'healthy') {
        return [pscustomobject]@{ AMServiceEnabled = $true; RealTimeProtectionEnabled = $true
                                  AntivirusSignatureLastUpdated = (Get-Date).AddHours(-3) }
    }
    throw 'Get-MpComputerStatus: module could not be loaded (SYSTEM, -NoProfile)'
}
function Get-Service {
    param($Name, $ErrorAction)
    if ($Name -eq 'WinDefend') {
        if ($Script:Scenario -eq 'defender-removed') { return $null }
        $st = if ($Script:Scenario -eq 'defender-stopped') { 'Stopped' } else { 'Running' }
        return [pscustomobject]@{ Name = 'WinDefend'; Status = $st }
    }
    return $null
}
function Get-BitLockerVolume { param($MountPoint, $ErrorAction) [pscustomobject]@{ ProtectionStatus = 'On' } }
function Get-ItemProperty {
    param($Path, $Name, $ErrorAction)
    if ("$Path" -match 'Cryptography') {
        if ($Script:Scenario -eq 'no-uuid-no-guid') { throw 'Cannot find path' }
        return [pscustomobject]@{ MachineGuid = $Script:MachineGuid }
    }
    if ("$Path" -match 'Real-Time Protection') { throw 'Property DisableRealtimeMonitoring does not exist' }
    return $null
}
function New-Object {
    param($TypeName, $ComObject, $ArgumentList, $ErrorAction)
    if ($ComObject) {
        $count = if ($Script:Scenario -eq 'wu-history-empty') { 0 } else { 1 }
        $hist = [pscustomobject]@{ Count = $count }
        $hist | Add-Member ScriptMethod Item { param($i) [pscustomobject]@{ Date = (Get-Date).AddDays(-6) } }
        $srch = [pscustomobject]@{}
        $srch | Add-Member ScriptMethod QueryHistory { param($a, $b) $hist }.GetNewClosure()
        $sess = [pscustomobject]@{}
        $sess | Add-Member ScriptMethod CreateUpdateSearcher { $srch }.GetNewClosure()
        return $sess
    }
    Microsoft.PowerShell.Utility\New-Object -TypeName $TypeName
}

Invoke-Expression $safeBlock
Invoke-Expression $biosDate
Invoke-Expression $osEol

# --- Scenarios --------------------------------------------------------------
# EngineRuns: whether MachineInfo should be populated. Sigs/Wu: expected
# 'Defender Sigs' / 'Last WU Install' ('date' = any yyyy-MM-dd value).
$scenarios = @(
    @{ Name = 'healthy';          Id = $Script:Uuid;        EngineRuns = $true;  Sigs = 'date';    Wu = 'date' }
    @{ Name = 'defender-stopped'; Id = $Script:Uuid;        EngineRuns = $true;  Sigs = 'Unknown'; Wu = 'date' }
    @{ Name = 'defender-removed'; Id = $Script:Uuid;        EngineRuns = $true;  Sigs = 'Unknown'; Wu = 'date' }
    @{ Name = 'cim-no-sig-date';  Id = $Script:Uuid;        EngineRuns = $true;  Sigs = 'Unknown'; Wu = 'date' }
    @{ Name = 'wu-history-empty'; Id = $Script:Uuid;        EngineRuns = $true;  Sigs = 'date';    Wu = 'Unknown' }
    @{ Name = 'engine-aborts';    Id = $Script:Uuid;        EngineRuns = $false }
    @{ Name = 'engine-disabled';  Id = $Script:Uuid;        EngineRuns = $false }
    @{ Name = 'zero-uuid';        Id = $Script:MachineGuid; EngineRuns = $true;  Sigs = 'date';    Wu = 'date' }
    @{ Name = 'no-uuid';          Id = $Script:MachineGuid; EngineRuns = $true;  Sigs = 'date';    Wu = 'date' }
    @{ Name = 'no-uuid-no-guid';  Id = 'host:SK-TEST-PC';   EngineRuns = $true;  Sigs = 'date';    Wu = 'date' }
    # WMI down: the old in-engine code never reached MachineGuid here, so the
    # id must stay host:<name> rather than re-enroll under a new id.
    @{ Name = 'wmi-down';         Id = 'host:SK-TEST-PC';   EngineRuns = $false }
)

$failures = 0
function Fail([string]$Label, [string]$Why) {
    Write-Host "  FAIL  $Label  -  $Why" -ForegroundColor Red
    $script:failures++
}

Write-Host ''
Write-Host '  Device identity and Assessment Engine (Phase 2, StrictMode 2)'
Write-Host '  ------------------------------------------------------------'

foreach ($sc in $scenarios) {
    $Script:Scenario = $sc.Name
    $Script:Config.AssessmentEngine_Enabled = ($sc.Name -ne 'engine-disabled')
    $Script:Logged.Clear()
    Remove-Variable -Name DeviceId -Scope Script -ErrorAction SilentlyContinue

    $ErrorActionPreference = 'SilentlyContinue'   # as ShellKnight.ps1 runs
    try     { Invoke-Expression $phase2 }
    finally { $ErrorActionPreference = 'Stop' }
    $label = $sc.Name
    $before = $failures

    # device_id as the payload builds it (read without throwing if unset).
    $payloadId = Get-Variable -Name DeviceId -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if ($null -eq $payloadId -or "$payloadId" -eq '') { Fail $label 'device_id is null/empty' }
    elseif ($payloadId -ne $sc.Id) { Fail $label "device_id '$payloadId', expected '$($sc.Id)'" }

    $skipped = @($Script:Logged | Where-Object { $_ -match 'skipped' })
    if ($sc.EngineRuns) {
        if ($skipped.Count) { Fail $label "engine aborted: $($skipped -join ' | ')" }
        elseif ($Script:MachineInfo.Count -eq 0) { Fail $label 'MachineInfo is empty' }
        else {
            if ($Script:MachineInfo['Device ID'] -ne $payloadId) { Fail $label "MachineInfo 'Device ID' '$($Script:MachineInfo['Device ID'])' differs from device_id" }
            foreach ($pair in @(@('Defender Sigs', $sc.Sigs), @('Last WU Install', $sc.Wu))) {
                $v = "$($Script:MachineInfo[$pair[0]])"
                $ok = if ($pair[1] -eq 'date') { $v -match '^\d{4}-\d{2}-\d{2}' } else { $v -eq $pair[1] }
                if (-not $ok) { Fail $label "'$($pair[0])' = '$v', expected $($pair[1])" }
            }
        }
    } elseif ($sc.Name -in 'engine-aborts', 'wmi-down' -and -not $skipped.Count) {
        Fail $label 'expected the engine to abort in this scenario (test harness check)'
    }

    if ($failures -eq $before) {
        $note = if ($sc.EngineRuns) { "engine ok, sigs=$($Script:MachineInfo['Defender Sigs'])" } else { "engine did not run; MachineInfo.Count=$($Script:MachineInfo.Count)" }
        Write-Host "  ok    $label  -  device_id=$payloadId; $note" -ForegroundColor Green
    }
}

# --- Static wiring: the payload and the POST --------------------------------
if ($source -notmatch '(?m)^\s+device_id\s+=\s+\$Script:DeviceId\s*$') {
    Fail 'payload' 'device_id is not read from $Script:DeviceId'
} else { Write-Host '  ok    payload  -  device_id = $Script:DeviceId' -ForegroundColor Green }

$post = [regex]::Match($source, '(?s)Invoke-RestMethod -Uri \$Script:Config\.BattlefieldURL -Method Post.*?-ErrorAction Stop')
if (-not $post.Success) {
    Fail 'POST' 'Battlefield Invoke-RestMethod call not found'
} elseif ($post.Value -notmatch [regex]::Escape('-Body ([System.Text.Encoding]::UTF8.GetBytes($jsonBody))') -or
          $post.Value -notmatch [regex]::Escape("-ContentType 'application/json; charset=utf-8'")) {
    Fail 'POST' 'report is not sent as UTF-8 bytes with charset=utf-8 (PS 5.1 would send ISO-8859-1)'
} else { Write-Host '  ok    POST  -  UTF-8 byte[] body, charset=utf-8' -ForegroundColor Green }

$env:COMPUTERNAME = $origComputerName

Write-Host ''
if ($failures -gt 0) {
    Write-Host "  FAILED - $failures assertion(s)" -ForegroundColor Red
    exit 1
}
Write-Host '  PASS - all assertions' -ForegroundColor Green
exit 0

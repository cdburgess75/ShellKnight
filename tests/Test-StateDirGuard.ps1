<#
.SYNOPSIS
    Regression test: the state directory is hardened before anything on disk is
    trusted, and only SYSTEM- or Administrators-owned state is trusted.

.DESCRIPTION
    C:\ProgramData\ShellKnight holds config.json (read at startup), run.ps1 (the
    native ShellKnight scheduled task executes it as SYSTEM every 8 h) and the
    Logs, JSON and Intel folders. By default ProgramData lets BUILTIN\Users
    create files and folders in its subfolders, and CREATOR OWNER gets full
    control of what they create, so on a box where ShellKnight had never run a
    standard user could pre-create the folder (or run.ps1 / config.json) and own
    it - then choose the code SYSTEM runs, or redirect the run report and its API
    key through config.json.

    v2026.09.26.001 adds a guard that runs during config load, ahead of
    Initialize-Logging: it creates or repairs C:\ProgramData\ShellKnight with an
    explicit ACL (SYSTEM and Administrators full control, Users read only, no
    inherited create rights), rebuilds a folder a user already owns, and deletes
    any config.json or run.ps1 not owned by SYSTEM or Administrators before it is
    read or executed.

    This runs the extracted guard verbatim from ShellKnight.ps1 under
    StrictMode 2, with Get-Acl and icacls mocked and real temp directories for
    the filesystem operations. It asserts the create / repair / rebuild
    decisions, the owner checks on config.json and run.ps1, and that the icacls
    arguments carry the three SIDs with the '*' prefix and no localized
    principal. From the script's own source it asserts the guard runs before the
    config.json read and that the SID constants are the expected values.

    It does NOT replace a real Windows run: Get-Acl, icacls and NTFS inheritance
    are Windows behaviours this test mocks. ShellKnight.ps1 is a monolith that
    executes on load, so the code is extracted textually rather than dot-sourced.
#>
Set-StrictMode -Version 2
# The test's own logic stops on any error. Only the extracted ShellKnight code
# runs under the script's own 'SilentlyContinue' (see Invoke-Verbatim).
$ErrorActionPreference = 'Stop'

$scriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'ShellKnight.ps1'
$source = Get-Content -LiteralPath $scriptPath -Raw

function Get-Section {
    param([string]$Pattern, [string]$What)
    $m = [regex]::Match($source, $Pattern)
    if (-not $m.Success) { throw "$What not found in ShellKnight.ps1 - did it get renamed or moved?" }
    $m.Value
}

$sidBlock = Get-Section '(?ms)^\$Script:SID_System\s+=.*?^\$Script:TrustedOwnerSids\s+=[^\r\n]*' 'the state-guard SID constants'
$icaclsFn = Get-Section '(?ms)^function Invoke-Icacls\s+\{.*?^\}' 'function Invoke-Icacls'
$functions = foreach ($fn in 'Add-StateGuardNote', 'Get-OwnerSid', 'Test-TrustedOwner',
                             'Set-StateDirAcl', 'Protect-StateDirectory', 'Remove-UntrustedStateFile') {
    Get-Section "(?ms)^function $fn\s+\{.*?^\}" "function $fn"
}

# --- Mocks -------------------------------------------------------------------
function Say { param([string]$m, [string]$c = 'Gray') Microsoft.PowerShell.Utility\Write-Host $m -ForegroundColor $c }
function Write-Host { }

# The filesystem is real (a temp tree). Get-Acl and icacls are not: Get-Acl does
# not exist off Windows, and icacls changes nothing here. Owner is looked up per
# path; a path in $Script:AclThrows reads as an unreadable owner.
$Script:OwnerByPath = @{}
$Script:AclThrows   = @{}
$Script:DefaultOwner = 'S-1-5-18'   # SYSTEM, unless a path overrides it
function Key([string]$Path) { [System.IO.Path]::GetFullPath($Path) }
function Set-Owner([string]$Path, [string]$Sid) { $Script:OwnerByPath[(Key $Path)] = $Sid }
function Set-Unreadable([string]$Path) { $Script:AclThrows[(Key $Path)] = $true }

function Get-Acl {
    param($LiteralPath, $ErrorAction)
    $key = Key $LiteralPath
    if ($Script:AclThrows.ContainsKey($key) -and $Script:AclThrows[$key]) {
        throw 'the owner could not be read (mock)'
    }
    $sid = if ($Script:OwnerByPath.ContainsKey($key)) { $Script:OwnerByPath[$key] } else { $Script:DefaultOwner }
    $acl = [pscustomobject]@{}
    $acl | Add-Member -MemberType ScriptMethod -Name GetOwner `
        -Value ({ param($Type) [pscustomobject]@{ Value = $sid } }).GetNewClosure()
    $acl
}

$Script:IcaclsCalls = New-Object 'System.Collections.Generic.List[object]'
function Invoke-Icacls {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    $Script:IcaclsCalls.Add([pscustomobject]@{ Args = $Arguments })
    0
}

# The guard's own note buffer, initialised as the script does.
$Script:StateGuardNotes = New-Object 'System.Collections.Generic.List[string]'

# Bring the SID constants and the guard functions into scope, then check the
# SIDs are the ones the ACL depends on.
Invoke-Expression $sidBlock
foreach ($f in $functions) { Invoke-Expression $f }

function Invoke-Verbatim([string]$Code) {
    # Not used for the guard (its functions are already defined above), kept for
    # symmetry with the other Test-*.ps1 harnesses.
    $ErrorActionPreference = 'SilentlyContinue'
    . ([scriptblock]::Create($Code))
}

$failures = 0
function Fail([string]$Label, [string]$Why) {
    Say "  FAIL  $Label  -  $Why" Red
    $script:failures++
}

Say ''
Say '  State directory: hardened before anything on disk is trusted (StrictMode 2)'
Say '  ---------------------------------------------------------------------------'

# --- SID constants ------------------------------------------------------------
$before = $failures
if ($Script:SID_System         -ne 'S-1-5-18')     { Fail 'sids' "SID_System is '$($Script:SID_System)', expected S-1-5-18" }
if ($Script:SID_Administrators -ne 'S-1-5-32-544') { Fail 'sids' "SID_Administrators is '$($Script:SID_Administrators)', expected S-1-5-32-544" }
if ($Script:SID_Users          -ne 'S-1-5-32-545') { Fail 'sids' "SID_Users is '$($Script:SID_Users)', expected S-1-5-32-545" }
if (@($Script:TrustedOwnerSids) -join ',' -ne 'S-1-5-18,S-1-5-32-544') { Fail 'sids' "TrustedOwnerSids is '$($Script:TrustedOwnerSids -join ',')'" }
if ($failures -eq $before) { Say '  ok    sids  -  SYSTEM S-1-5-18, Administrators S-1-5-32-544, Users S-1-5-32-545; trusted = SYSTEM + Administrators' Green }

$tmpRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('sk-statedir-test-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $tmpRoot -Force
try {
    $USER = 'S-1-5-21-100-200-300-1001'   # a made-up local user
    $n = 0
    function New-Case { $script:n++; Join-Path $tmpRoot "case$script:n" }
    function Reset-Guard {
        $Script:OwnerByPath = @{}; $Script:AclThrows = @{}; $Script:DefaultOwner = 'S-1-5-18'
        $Script:StateGuardNotes.Clear(); $Script:IcaclsCalls.Clear()
    }
    function New-Sentinel([string]$Dir) {
        $null = New-Item -ItemType Directory -Path $Dir -Force
        $s = Join-Path $Dir 'sentinel.txt'; Set-Content -LiteralPath $s -Value 'keep' ; $s
    }
    function Had-Note([string]$Text) { @($Script:StateGuardNotes | Where-Object { $_ -like "*$Text*" }).Count -gt 0 }

    # --- Protect-StateDirectory --------------------------------------------------

    # Fresh box: the folder does not exist and is created.
    Reset-Guard
    $before = $failures
    $dir = New-Case
    $g = Protect-StateDirectory -Path $dir
    if (-not (Test-Path -LiteralPath $dir)) { Fail 'fresh box' 'the folder was not created' }
    if (-not $g.Created)   { Fail 'fresh box' 'Created should be true' }
    if ($g.Recreated)      { Fail 'fresh box' 'Recreated should be false (nothing was there)' }
    if (-not $g.AclApplied){ Fail 'fresh box' 'AclApplied should be true' }
    if ($Script:StateGuardNotes.Count) { Fail 'fresh box' "unexpected note(s): $($Script:StateGuardNotes -join ' | ')" }
    if ($Script:IcaclsCalls.Count -lt 3) { Fail 'fresh box' 'expected icacls to be invoked to set the ACL' }
    if ($failures -eq $before) { Say '  ok    fresh box  -  folder created and ACL applied, no repair' Green }

    # Steady state: SYSTEM owns the folder, so it and its contents are kept.
    Reset-Guard
    $before = $failures
    $dir = New-Case; $sentinel = New-Sentinel $dir; Set-Owner $dir 'S-1-5-18'
    $g = Protect-StateDirectory -Path $dir
    if (-not (Test-Path -LiteralPath $sentinel)) { Fail 'steady state' 'the folder contents were removed' }
    if (-not $g.Existed)      { Fail 'steady state' 'Existed should be true' }
    if (-not $g.OwnerTrusted) { Fail 'steady state' 'OwnerTrusted should be true for SYSTEM' }
    if ($g.Recreated)         { Fail 'steady state' 'Recreated should be false' }
    if ($g.Created)           { Fail 'steady state' 'Created should be false' }
    if (-not $g.AclApplied)   { Fail 'steady state' 'AclApplied should be true (ACL re-asserted)' }
    if ($Script:StateGuardNotes.Count) { Fail 'steady state' "unexpected note(s): $($Script:StateGuardNotes -join ' | ')" }
    if ($failures -eq $before) { Say '  ok    steady state  -  SYSTEM-owned folder kept, ACL re-asserted' Green }

    # Administrators-owned folder is trusted just the same.
    Reset-Guard
    $before = $failures
    $dir = New-Case; $sentinel = New-Sentinel $dir; Set-Owner $dir 'S-1-5-32-544'
    $g = Protect-StateDirectory -Path $dir
    if (-not (Test-Path -LiteralPath $sentinel)) { Fail 'admins-owned' 'the folder contents were removed' }
    if (-not $g.OwnerTrusted) { Fail 'admins-owned' 'OwnerTrusted should be true for Administrators' }
    if ($g.Recreated)         { Fail 'admins-owned' 'Recreated should be false' }
    if ($failures -eq $before) { Say '  ok    admins-owned  -  Administrators-owned folder kept' Green }

    # A user owns the folder: it and its contents are removed and recreated.
    Reset-Guard
    $before = $failures
    $dir = New-Case; $sentinel = New-Sentinel $dir; Set-Owner $dir $USER
    $g = Protect-StateDirectory -Path $dir
    if (Test-Path -LiteralPath $sentinel)     { Fail 'user-owned' 'the user-owned contents were NOT removed' }
    if (-not (Test-Path -LiteralPath $dir))   { Fail 'user-owned' 'the folder was not recreated' }
    if ($g.OwnerTrusted)  { Fail 'user-owned' 'OwnerTrusted should be false for a user SID' }
    if (-not $g.Recreated){ Fail 'user-owned' 'Recreated should be true' }
    if (-not $g.Created)  { Fail 'user-owned' 'Created should be true (recreated)' }
    if (-not (Had-Note 'not SYSTEM or Administrators')) { Fail 'user-owned' 'expected a note that the owner is not SYSTEM or Administrators' }
    if ($failures -eq $before) { Say '  ok    user-owned  -  folder rebuilt, contents dropped, note logged' Green }

    # The owner cannot be read (Get-Acl throws): treated as untrusted, rebuilt.
    Reset-Guard
    $before = $failures
    $dir = New-Case; $sentinel = New-Sentinel $dir; Set-Unreadable $dir
    $g = Protect-StateDirectory -Path $dir
    if (Test-Path -LiteralPath $sentinel) { Fail 'unreadable owner' 'the contents were NOT removed' }
    if ($null -ne $g.OwnerSid) { Fail 'unreadable owner' "OwnerSid should be null, was '$($g.OwnerSid)'" }
    if (-not $g.Recreated)     { Fail 'unreadable owner' 'Recreated should be true' }
    if (-not (Had-Note 'an unknown account')) { Fail 'unreadable owner' "expected a note naming 'an unknown account'" }
    if ($failures -eq $before) { Say '  ok    unreadable owner  -  treated as untrusted and rebuilt' Green }

    # --- Remove-UntrustedStateFile (config.json / run.ps1) -----------------------

    foreach ($case in @(
        @{ Label = 'config.json'; Name = 'config.json' },
        @{ Label = 'run.ps1';     Name = 'run.ps1' }
    )) {
        $label = $case.Label

        # Trusted owner: kept, not read.
        Reset-Guard
        $before = $failures
        $dir = New-Case; $null = New-Item -ItemType Directory -Path $dir -Force
        $file = Join-Path $dir $case.Name; Set-Content -LiteralPath $file -Value '{}' ; Set-Owner $file 'S-1-5-32-544'
        $removed = Remove-UntrustedStateFile -Path $file -Label $label
        if ($removed)                        { Fail "$label trusted" 'a trusted file should not be removed' }
        if (-not (Test-Path -LiteralPath $file)) { Fail "$label trusted" 'the trusted file was deleted' }
        if ($Script:StateGuardNotes.Count)   { Fail "$label trusted" 'no note should be logged for a trusted file' }
        if ($failures -eq $before) { Say "  ok    $label trusted  -  Administrators-owned, kept" Green }

        # User owner: deleted, note logged.
        Reset-Guard
        $before = $failures
        $dir = New-Case; $null = New-Item -ItemType Directory -Path $dir -Force
        $file = Join-Path $dir $case.Name; Set-Content -LiteralPath $file -Value 'evil' ; Set-Owner $file $USER
        $removed = Remove-UntrustedStateFile -Path $file -Label $label
        if (-not $removed)                { Fail "$label user" 'a user-owned file should be removed' }
        if (Test-Path -LiteralPath $file) { Fail "$label user" 'the user-owned file was NOT deleted' }
        if (-not (Had-Note "$label owned by $USER")) { Fail "$label user" 'expected a note naming the file and owner' }
        if ($failures -eq $before) { Say "  ok    $label user-owned  -  deleted, note logged" Green }

        # Unreadable owner: deleted as untrusted.
        Reset-Guard
        $before = $failures
        $dir = New-Case; $null = New-Item -ItemType Directory -Path $dir -Force
        $file = Join-Path $dir $case.Name; Set-Content -LiteralPath $file -Value 'evil' ; Set-Unreadable $file
        $removed = Remove-UntrustedStateFile -Path $file -Label $label
        if (-not $removed)                { Fail "$label unknown" 'an unreadable-owner file should be removed' }
        if (Test-Path -LiteralPath $file) { Fail "$label unknown" 'the file was NOT deleted' }
        if (-not (Had-Note 'an unknown account')) { Fail "$label unknown" "expected a note naming 'an unknown account'" }
        if ($failures -eq $before) { Say "  ok    $label unknown-owner  -  deleted, note logged" Green }

        # Absent file: nothing to do.
        Reset-Guard
        $before = $failures
        $dir = New-Case; $null = New-Item -ItemType Directory -Path $dir -Force
        $file = Join-Path $dir $case.Name
        if (Remove-UntrustedStateFile -Path $file -Label $label) { Fail "$label absent" 'an absent file should return false' }
        if ($failures -eq $before) { Say "  ok    $label absent  -  nothing removed" Green }
    }

    # --- Test-TrustedOwner -------------------------------------------------------
    Reset-Guard
    $before = $failures
    $dir = New-Case; $null = New-Item -ItemType Directory -Path $dir -Force
    $p = Join-Path $dir 'x'; Set-Content -LiteralPath $p -Value '.'
    Set-Owner $p 'S-1-5-18';     if (-not (Test-TrustedOwner -Path $p)) { Fail 'trusted-owner' 'SYSTEM should be trusted' }
    Set-Owner $p 'S-1-5-32-544'; if (-not (Test-TrustedOwner -Path $p)) { Fail 'trusted-owner' 'Administrators should be trusted' }
    Set-Owner $p $USER;          if (Test-TrustedOwner -Path $p)        { Fail 'trusted-owner' 'a user should NOT be trusted' }
    $missing = Join-Path $dir 'does-not-exist'
    if (Test-TrustedOwner -Path $missing) { Fail 'trusted-owner' 'a missing path should NOT be trusted' }
    if ($failures -eq $before) { Say '  ok    trusted-owner  -  SYSTEM/Administrators trusted; user and missing not' Green }

    # --- icacls arguments: SIDs, not names --------------------------------------
    Reset-Guard
    $before = $failures
    $dir = New-Case
    $null = Protect-StateDirectory -Path $dir
    $allArgs = @($Script:IcaclsCalls | ForEach-Object { $_.Args })
    if (-not ($allArgs -contains '/inheritance:r')) { Fail 'icacls' 'expected /inheritance:r to drop inherited ACEs' }
    if (-not ($allArgs -contains '/setowner'))      { Fail 'icacls' 'expected /setowner to reclaim ownership' }
    if (-not ($allArgs -contains '/grant:r'))       { Fail 'icacls' 'expected /grant:r to replace the DACL' }
    $grantArgs = @($allArgs | Where-Object { $_ -match ':\((OI|CI)' })
    if ($grantArgs.Count -ne 3) { Fail 'icacls' "expected 3 grant entries, saw $($grantArgs.Count): $($grantArgs -join ' ')" }
    foreach ($ga in $grantArgs) {
        if ($ga -notmatch '^\*S-1-') { Fail 'icacls' "grant principal is not a '*'-prefixed SID: '$ga'" }
    }
    foreach ($want in @('*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F', '*S-1-5-32-545:(OI)(CI)RX')) {
        if (-not ($grantArgs -contains $want)) { Fail 'icacls' "missing grant entry $want" }
    }
    # /setowner target is the Administrators SID, not a name.
    $ownerCall = @($Script:IcaclsCalls | Where-Object { $_.Args -contains '/setowner' })[0]
    if ($ownerCall) {
        $oi = [array]::IndexOf([array]$ownerCall.Args, '/setowner')
        if ($ownerCall.Args[$oi + 1] -ne '*S-1-5-32-544') { Fail 'icacls' "setowner target is '$($ownerCall.Args[$oi + 1])', expected *S-1-5-32-544" }
    }
    # No localized principal anywhere in the icacls arguments.
    foreach ($bad in 'Administrators', 'Users', 'SYSTEM', 'BUILTIN', 'Everyone', 'Authenticated') {
        if (@($allArgs | Where-Object { $_ -like "*$bad*" }).Count) { Fail 'icacls' "a localized name '$bad' was passed to icacls" }
    }
    if ($failures -eq $before) { Say '  ok    icacls  -  ACL set by SID (*S-1-5-18/544/545), owner reclaimed, no localized name' Green }

    # --- Source order: the guard runs before config.json is read -----------------
    $before = $failures
    $iGuard  = $source.IndexOf('Protect-StateDirectory -Path $Script:StateDir')
    $iCfgRun = $source.IndexOf('$Script:StateGuardFilesRemoved++')
    $iRead   = $source.IndexOf('if (Test-Path $Script:ConfigPath) {')
    if ($iGuard -lt 0)  { Fail 'source order' 'the Protect-StateDirectory call was not found' }
    if ($iRead  -lt 0)  { Fail 'source order' 'the config.json read block was not found' }
    if ($iGuard -ge 0 -and $iRead -ge 0 -and $iGuard -ge $iRead) { Fail 'source order' 'the folder guard must run before config.json is read' }
    if ($iCfgRun -ge 0 -and $iRead -ge 0 -and $iCfgRun -ge $iRead) { Fail 'source order' 'the config.json / run.ps1 owner check must run before config.json is read' }
    if ($failures -eq $before) { Say '  ok    source order  -  folder guard and file checks run before config.json is read' Green }

    # --- Invoke-Icacls wrapper is sane (text) ------------------------------------
    $before = $failures
    if ($icaclsFn -notmatch 'icacls') { Fail 'wrapper' 'Invoke-Icacls does not call icacls' }
    if ($icaclsFn -notmatch 'LASTEXITCODE') { Fail 'wrapper' 'Invoke-Icacls does not return the exit code' }
    if ($failures -eq $before) { Say '  ok    wrapper  -  Invoke-Icacls runs icacls and returns its exit code' Green }
}
finally {
    if (Test-Path -LiteralPath $tmpRoot) { Remove-Item -LiteralPath $tmpRoot -Recurse -Force -ErrorAction SilentlyContinue }
}

Say ''
if ($failures -gt 0) {
    Say "  FAILED - $failures assertion(s)" Red
    exit 1
}
Say '  PASS - all assertions' Green
exit 0

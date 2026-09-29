<#
.SYNOPSIS
    Regression test: the Intel Engine loads threat intel, and every intel match
    is report-only.

.DESCRIPTION
    From v1.002 to v2026.09.25.003 the Intel Engine read
    $Script:Config.IntelEngine_PrimarySource, which the Config object did not
    have. Under StrictMode 2 that threw inside the Invoke-SafeBlock, before any
    download, cache write or IntelSource, so every device on every run reported
    intel_source 'Hardcoded fallback' and 0 hash, filename and C2 IOCs. The
    parser behind it kept whole lines ('hash;comment', 'regex;score'), which no
    hash or file name could ever equal.

    Loading intel for the first time turns on detections that have never run in
    the field, next to consumers that kill processes and delete Run values,
    shortcuts and files. So an intel match is report-only: counted, logged,
    listed in the payload's intel object and (the first 20) a Low finding, but
    never an IOC, never a kill or a removal.

    This runs Phase 1 verbatim from ShellKnight.ps1 under StrictMode 2, with
    Invoke-WebRequest mocked to serve lists in the real Neo23x0 formats, and
    asserts the cache, IntelSource and the counts. It then runs every intel
    consumer verbatim - the Process Engine's process loop, the Persistence
    Engine's Run keys and startup shortcuts, the redirected-folder scan and
    the Detection Engine's filename, hash, hosts file and DNS checks - against
    mocked Windows cmdlets, and asserts each match it reports and each action
    it takes. It does not replace a real Windows run.

    It also parses the whole script and fails on any $Script:Config.<Name>
    that the Config literal does not define: the general form of the bug.

    ShellKnight.ps1 is a monolith that executes on load, so the code is
    extracted textually rather than dot-sourced.
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

$settings   = Get-Section '(?ms)^# --- INTEL ENGINE \(Phase 1\) ---.*?(?=^\$Script:ConfigPath)' 'the $SK_ settings'
$configLit  = Get-Section '(?ms)^\$Script:Config = \[PSCustomObject\]@\{.*?^\}' 'the $Script:Config literal'
$countersLit= Get-Section '(?ms)^\$Script:Counters = @\{.*?^\}' 'the $Script:Counters literal'
$intelState = Get-Section '(?ms)^\$Script:HashIOCs     = .*?^\$Script:IntelMatches\s+=[^\r\n]*' 'the intel collections and state'
$functions  = foreach ($fn in 'Invoke-SafeBlock', 'ConvertFrom-IntelFeed', 'Find-IntelFilenameMatch', 'Find-IntelC2Match', 'Add-IntelHit', 'Log-IOC') {
    Get-Section "(?ms)^function $fn\s+\{.*?^\}" "function $fn"
}
$phase1     = Get-Section ('(?ms)^\$Script:HashIOCsLoaded    = 0.*?' +
                           '^    \$Script:Counters.IntelSource = ''Disabled \(fallback only\)''\s*^\}') 'Phase 1 (the Intel Engine)'
$procLoop   = Get-Section '(?ms)^    # Known malware process patterns.*?^    if \(\$killedProcs -eq 0\) \{[^\r\n]*\}' 'the Process Engine process loop'
$persist    = Get-Section '(?ms)^    # Known malware Run key executables.*?^    if \(\$lnksRemoved -eq 0\) \{[^\r\n]*\}' 'the Persistence Engine Run key and startup checks'
$redirected = Get-Section "(?ms)^            Invoke-SafeBlock -Label 'Redirected folder scan' -Block \{.*?^            \}" 'the redirected folder scan'
$detection  = Get-Section ('(?ms)^    # Trojan/Malware folder IOC detection.*?' +
                           '^        if \(\$c2Hits -eq 0\) \{[^\r\n]*\}\s*^    \}') 'the Detection Engine IOC checks'

# --- Mocks common to every part ----------------------------------------------
function Say { param([string]$m, [string]$c = 'Gray') Microsoft.PowerShell.Utility\Write-Host $m -ForegroundColor $c }
function Write-Host { }
$Script:Logged   = New-Object 'System.Collections.Generic.List[string]'
$Script:Findings = New-Object 'System.Collections.Generic.List[object]'
function Write-Log   { param([string]$Message, [string]$Level) $Script:Logged.Add("$($Level): $Message") }
function Log-Info    { param([string]$m) $Script:Logged.Add("INFO: $m") }
function Log-Warn    { param([string]$m) $Script:Logged.Add("WARN: $m") }
function Log-Summary { param([string]$m) $Script:Logged.Add("SUMMARY: $m") }
function Log-Success { param([string]$m) $Script:Logged.Add("SUCCESS: $m") }
function Log-Fail    { param([string]$m) $Script:Logged.Add("FAILED: $m") }
function Add-Finding { param($Severity, $Title, $Action) $Script:Findings.Add([pscustomobject]@{ Severity = $Severity; Title = $Title }) }

# The web: one entry per list file name. A string is served as the body; $null
# fails the request. A HEAD answers like raw.githubusercontent.com: no
# Last-Modified.
$Script:Web      = @{}
$Script:WebCalls = New-Object 'System.Collections.Generic.List[object]'
function Invoke-WebRequest {
    param($Uri, $Method = 'Get', $TimeoutSec, $ErrorAction, [switch]$UseBasicParsing)
    $leaf = ([string]$Uri).Split('/')[-1]
    $Script:WebCalls.Add([pscustomobject]@{ Leaf = $leaf; Method = $Method; Basic = [bool]$UseBasicParsing })
    if ($Method -eq 'Head') { return [pscustomobject]@{ Headers = @{ ETag = '"abc"' }; Content = '' } }
    if ($null -eq $Script:Web[$leaf]) { throw 'The remote server returned an error: (503) Server Unavailable.' }
    [pscustomobject]@{ Content = $Script:Web[$leaf]; Headers = @{} }
}
# The cache file's owner, as a SID. Get-Acl does not exist off Windows.
$Script:CacheOwner = 'S-1-5-18'
function Get-Acl {
    param($LiteralPath, $ErrorAction)
    $acl = [pscustomobject]@{}
    $acl | Add-Member ScriptMethod GetOwner { param($Type) [pscustomobject]@{ Value = $Script:CacheOwner } }
    $acl
}
function Get-AuthenticodeSignature {
    param($LiteralPath, $ErrorAction)
    [pscustomobject]@{ Status = 'Valid'; SignerCertificate = [pscustomobject]@{ Subject = 'CN=SKTEST Vendor' } }
}

foreach ($f in $functions) { Invoke-Expression $f }

# Run ShellKnight code as the script runs it: StrictMode 2 (the test's own)
# and SilentlyContinue. Dot-sourced into this function's scope, so the
# preference is this scope's and ends with it; $Script: writes reach the test.
function Invoke-Verbatim([string]$Code) {
    $ErrorActionPreference = 'SilentlyContinue'
    . ([scriptblock]::Create($Code))
}

$failures = 0
function Fail([string]$Label, [string]$Why) {
    Say "  FAIL  $Label  -  $Why" Red
    $script:failures++
}

# --- Lists in the real Neo23x0 formats ---------------------------------------
# Every kind of line the real files have (see each file's own header), plus
# fillers so each list clears the engine's 100-entry sanity floor, plus the
# over-broad and known-good entries the engine must leave out. The indicators
# are made up; none is a real IOC.
$sha = [System.Security.Cryptography.SHA256]::Create()
function Get-TestHash([string]$Seed) { -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Seed)) | ForEach-Object { $_.ToString('x2') }) }
$hashEvil   = Get-TestHash 'sktest-hashed.dll'
$hashUpper  = (Get-TestHash 'upper').ToUpper()
$hashScored = Get-TestHash 'scored'
$hashEmpty  = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'

function New-Feed([string]$Kind, [string]$Nl = "`n", [int]$Fill = 120) {
    $lines = switch ($Kind) {
        'filename-iocs.txt' {
            '#'; '# LOKI File Name Characteristics'
            '# Every line is treated as REGEX case sensitive. Prepend (?i) to make it case insensitive'
            '# REGEX;SCORE[;EXCLUDE FALSE POSITIVE REGEX]'; '#'; ''
            '# SKTEST family'
            '\\sktest-evil\.exe;80'
            '\\sktest-weak\.exe;45'                  # below the minimum score (60)
            '(?i)\\SKTEST-CASE\.dll;70'              # case-insensitive by its own (?i)
            '\\sktest-case2\.dll;70'                 # case-sensitive, like every line without (?i)
            '\\sktest-fp\.exe;75;\\Vendor\\'          # not a match under \Vendor\
            '\\Startup\\sktest-shortcut\.lnk;70'
            '/tmp/sktest-unix;80'                    # a Unix path: dropped
            '\\sktest-broken(\.exe;80'               # not a valid regex: left out, counted
            '(?i)\\windows\\;90'                     # over-broad: matches known-good paths
            '\\;70'                                  # over-broad: any backslash
            ''
            foreach ($i in 1..$Fill) { '\\sktest-filler-{0:d5}\.exe;60' -f $i }
        }
        'hash-iocs.txt' {
            '#'; '# LOKI CUSTOM EVIL HASHES'; '# MD5;COMMENT'; '# SHA1;COMMENT'; '# SHA256;COMMENT'; '#'; ''
            "$hashEvil;SKTEST family - PE32 executable (DLL) (GUI) Intel 80386"
            "$hashUpper;SKTEST upper case"
            'd41d8cd98f00b204e9800998ecf8427e;an MD5, which the SHA256 scan cannot use'
            'da39a3ee5e6b4b0d3255bfef95601890afd80709;a SHA1, likewise'
            "$hashScored;55;Vulnerable library ./lib/sktest-1.0.jar"
            "$hashEmpty;the empty file: known good"
            ''
            foreach ($i in 1..$Fill) { "$(Get-TestHash "filler$i");SKTEST filler $i" }
        }
        'c2-iocs.txt' {
            '#'; '# LOKI C2 IOCs'; '# c2-server.tld'; '# ip-address'; '#'; ''
            '# SKTEST family'
            'sktest-c2.example'
            '203.0.113.7'
            '198.51.100.9;65'
            'Sktest-Upper.Example.'
            'not a domain'
            'microsoft.com'                           # known good
            ''
            foreach ($i in 1..$Fill) { 'sktest-filler-{0:d5}.example' -f $i }
        }
    }
    $lines -join $Nl
}
$leaves = 'filename-iocs.txt', 'hash-iocs.txt', 'c2-iocs.txt'
function Set-Web([string]$Nl = "`n") { foreach ($l in $leaves) { $Script:Web[$l] = New-Feed $l $Nl } }
# Loaded from the feeds above: filename = 5 named at 70-80 + 120 fillers at 60
# (the 45 is below the minimum, the broken one does not compile, the two
# over-broad ones match known-good paths, the Unix one is dropped); hashes = 3
# SHA256 + 120 (MD5, SHA1 and the empty file left out); C2 = 4 + 120
# (microsoft.com left out).
$want = @{ Hash = 123; Filename = 125; C2 = 124 }
$leftOut = 'left out: 1 filename IOCs scored below 60, 1 not valid \.NET regex, 2 matching a known-good path; 2 known-good hashes or C2 entries'

# What the pre-v2026.09.25.004 parser would have cached: whole trimmed lines,
# hashes and C2 lower-cased. $Only keeps one list's key and empties the rest.
function New-LegacyCache([string]$Path, [string]$Empty) {
    $old = @{}
    foreach ($pair in @(@('Filename', 'filename-iocs.txt', $false), @('Hashes', 'hash-iocs.txt', $true), @('C2', 'c2-iocs.txt', $true))) {
        $old[$pair[0]] = @((New-Feed $pair[1]) -split "`n" | Where-Object { $_ -and -not $_.StartsWith('#') } |
                           ForEach-Object { if ($pair[2]) { $_.Trim().ToLower() } else { $_.Trim() } })
    }
    if ($Empty) { $old[$Empty] = @() }
    $old.Updated = (Get-Date).ToString('o'); $old.Source = 'Neo23x0'
    $old | ConvertTo-Json -Compress | Set-Content -LiteralPath $Path -Encoding UTF8
}

# --- Phase 1 ------------------------------------------------------------------
# Only Phase 1 touches disk: its cache lives in a temp directory that the
# finally below deletes. Everything after it uses the sets it loaded.
$tmpRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('sk-intel-test-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $tmpRoot
try {
    Invoke-Expression $settings
    $SK_IntelEngine_CacheDir = $tmpRoot
    $cacheFile = Join-Path $tmpRoot 'neo23x0_consolidated.json'

    function Reset-Intel {
        Invoke-Expression $configLit
        Invoke-Expression $countersLit
        Invoke-Expression $intelState
        $Script:Logged.Clear(); $Script:Findings.Clear(); $Script:WebCalls.Clear()
    }
    function Get-CacheStamp { if (Test-Path -LiteralPath $cacheFile) { (Get-Item -LiteralPath $cacheFile).LastWriteTimeUtc.Ticks } else { $null } }
    # No cache to date means Phase 1 did not write one; the scenario's own
    # assertions report that, and the rest of the test still runs.
    function Set-CacheAge([int]$Days) { if (Test-Path -LiteralPath $cacheFile) { (Get-Item -LiteralPath $cacheFile).LastWriteTime = (Get-Date).AddDays(-$Days) } }
    # A good cache, written by Phase 1 itself.
    function New-GoodCache { Set-Web; Reset-Intel; Invoke-Verbatim $phase1; Reset-Intel }

    # Each scenario: Setup (web and cache), then what must hold after Phase 1.
    # Source: IntelSource. Counts: 'full' ($want), 'none' (all 0), or a hashtable.
    # Cache: 'written' (new or replaced), 'kept' (untouched), 'absent'.
    # Log: a line that must have been logged.
    $scenarios = @(
        @{ Name = 'fresh download'; Setup = { Set-Web };
           Source = 'Live (Neo23x0)'; Counts = 'full'; Cache = 'written'; Gets = 3 }
        # A CRLF file's blank lines are "`r", and whitespace-only lines must not
        # become an empty entry that matches every path.
        @{ Name = 'CRLF and whitespace lines'; Setup = { Set-Web "`r`n"; foreach ($l in $leaves) { $Script:Web[$l] = $Script:Web[$l] + "`r`n   `r`n`t`r`n" } };
           Source = 'Live (Neo23x0)'; Counts = 'full'; Cache = 'written'; Gets = 3 }
        @{ Name = 'cache current'; Setup = { New-GoodCache };
           Source = 'Cache (current)'; Counts = 'full'; Cache = 'kept'; Gets = 0 }
        # A partial refresh does not rewrite the cache, so it keeps its age and
        # the next run tries again.
        @{ Name = 'cache aged, one list fails'; Setup = { New-GoodCache; Set-CacheAge 10; $Script:Web['hash-iocs.txt'] = $null };
           Source = 'Live (Neo23x0, 2 of 3 lists)'; Counts = 'full'; Cache = 'kept'; Gets = 3 }
        @{ Name = 'cache aged, all lists fail'; Setup = { New-GoodCache; Set-CacheAge 10; $Script:Web.Clear() };
           Source = 'Cache (download failed)'; Counts = 'full'; Cache = 'kept'; Gets = 3 }
        @{ Name = 'cache dated in the future'; Setup = { New-GoodCache; Set-CacheAge -30 };
           Source = 'Live (Neo23x0)'; Counts = 'full'; Cache = 'written'; Gets = 3 }
        # A local user can create the cache in ProgramData and own it.
        @{ Name = 'cache owned by a user'; Setup = { New-GoodCache; $Script:CacheOwner = 'S-1-5-21-1-2-3-1001' };
           Source = 'Live (Neo23x0)'; Counts = 'full'; Cache = 'written'; Gets = 3; Log = 'not SYSTEM or Administrators: deleting it' }
        @{ Name = 'cache empty file'; Setup = { Set-Web; [System.IO.File]::WriteAllText($cacheFile, '') };
           Source = 'Live (Neo23x0)'; Counts = 'full'; Cache = 'written'; Gets = 3; Log = 'cache not usable' }
        @{ Name = 'cache {}'; Setup = { Set-Web; [System.IO.File]::WriteAllText($cacheFile, '{}') };
           Source = 'Live (Neo23x0)'; Counts = 'full'; Cache = 'written'; Gets = 3; Log = 'cache not usable' }
        @{ Name = 'cache corrupt'; Setup = { Set-Web; [System.IO.File]::WriteAllText($cacheFile, '{"Filename":["\\x.exe;80"') };
           Source = 'Live (Neo23x0)'; Counts = 'full'; Cache = 'written'; Gets = 3; Log = 'cache not usable' }
        @{ Name = 'cache current, one list empty'; Setup = { Set-Web; New-LegacyCache $cacheFile 'Hashes' };
           Source = 'Live (Neo23x0)'; Counts = 'full'; Cache = 'written'; Gets = 3; Log = 'cache not usable' }
        @{ Name = 'legacy whole-line cache'; Setup = { New-LegacyCache $cacheFile };
           Source = 'Cache (current)'; Counts = 'full'; Cache = 'kept'; Gets = 0 }
        @{ Name = 'no cache, all lists fail'; Setup = { $Script:Web.Clear() };
           Source = 'Hardcoded fallback'; Counts = 'none'; Cache = 'absent'; Gets = 3 }
        # A captive portal or proxy error page parses to nothing: below the floor.
        @{ Name = 'error page'; Setup = { foreach ($l in $leaves) { $Script:Web[$l] = "<!DOCTYPE html>`n<html><body><h1>502 Bad Gateway</h1></body></html>" } };
           Source = 'Hardcoded fallback'; Counts = 'none'; Cache = 'absent'; Gets = 3 }
        # Over a limit, that list is not used; with no cached copy the other
        # two are used this run and the cache is not written.
        @{ Name = 'over 20,000 entries'; Setup = { Set-Web; $Script:Web['filename-iocs.txt'] = New-Feed 'filename-iocs.txt' "`n" 20001 };
           Source = 'Live (Neo23x0, 2 of 3 lists)'; Counts = @{ Hash = 123; Filename = 0; C2 = 124 }; Cache = 'absent'; Gets = 3; Log = 'outside the expected' }
        @{ Name = 'over 5 MB'; Setup = { Set-Web; $Script:Web['filename-iocs.txt'] = $Script:Web['filename-iocs.txt'] + "`n#" + ('x' * 5300000) };
           Source = 'Live (Neo23x0, 2 of 3 lists)'; Counts = @{ Hash = 123; Filename = 0; C2 = 124 }; Cache = 'absent'; Gets = 3; Log = 'over the 5 MB limit' }
        @{ Name = 'engine disabled'; Setup = { Set-Web; $Script:Config.IntelEngine_Enabled = $false };
           Source = 'Disabled (fallback only)'; Counts = 'none'; Cache = 'absent'; Gets = 0 }
    )

    Say ''
    Say '  Intel Engine: intel loads, and every match is report-only (StrictMode 2)'
    Say '  -------------------------------------------------------------------------'

    foreach ($sc in $scenarios) {
        $label = "phase 1: $($sc.Name)"
        $before = $failures
        if (Test-Path -LiteralPath $cacheFile) { Remove-Item -LiteralPath $cacheFile -Force }
        $Script:Web.Clear()
        $Script:CacheOwner = 'S-1-5-18'
        Reset-Intel
        & $sc.Setup
        $stampBefore = Get-CacheStamp
        $Script:WebCalls.Clear()

        Invoke-Verbatim $phase1

        $skipped = @($Script:Logged | Where-Object { $_ -match 'Intel Engine skipped' })
        if ($skipped.Count) { Fail $label "the engine aborted: $($skipped -join ' | ')" }
        if ($Script:Counters.IntelSource -ne $sc.Source) { Fail $label "IntelSource '$($Script:Counters.IntelSource)', expected '$($sc.Source)'" }

        $counts = if ($sc.Counts -eq 'full') { $want } elseif ($sc.Counts -eq 'none') { @{ Hash = 0; Filename = 0; C2 = 0 } } else { $sc.Counts }
        $got = @{ Hash = $Script:HashIOCsLoaded; Filename = $Script:FilenameIOCsLoaded; C2 = $Script:C2IOCsLoaded }
        foreach ($k in 'Hash', 'Filename', 'C2') {
            if ($got[$k] -ne $counts[$k]) { Fail $label "$k IOCs loaded = $($got[$k]), expected $($counts[$k])" }
        }
        # The counts are the sets, and the sets hold usable entries only.
        if ($Script:HashIOCs.Count -ne $got.Hash -or $Script:FilenameIOCs.Count -ne $got.Filename -or $Script:C2IOCs.Count -ne $got.C2) {
            Fail $label 'the *IOCsLoaded counts do not match the loaded sets'
        }
        $badHash = @($Script:HashIOCs | Where-Object { $_ -notmatch '^[0-9a-f]{64}$' -or $_ -eq $hashEmpty })
        $badC2   = @($Script:C2IOCs | Where-Object { -not $_ -or $_.Contains(';') -or $_.Contains(' ') -or $_ -eq 'microsoft.com' })
        $badFn   = @($Script:FilenameIOCs | Where-Object { -not $_.Pattern -or $_.Pattern.Contains(';') -or $_.Score -lt 60 -or $_.Off })
        if ($badHash.Count) { Fail $label "hash entries that are not a SHA256, or known good: $($badHash[0])" }
        if ($badC2.Count)   { Fail $label "C2 entries that are not a bare name or address, or known good: '$($badC2[0])'" }
        if ($badFn.Count)   { Fail $label "filename entries with a ';', under the minimum score, or off: $($badFn[0].Pattern)" }

        $stampAfter = Get-CacheStamp
        switch ($sc.Cache) {
            'written' { if ($null -eq $stampAfter -or $stampAfter -eq $stampBefore) { Fail $label 'expected the cache to be written' } }
            'kept'    { if ($null -eq $stampAfter -or $stampAfter -ne $stampBefore) { Fail $label 'expected the cache to be left as it was' } }
            'absent'  { if ($null -ne $stampAfter) { Fail $label 'expected no cache file' } }
        }
        $gets = @($Script:WebCalls | Where-Object { $_.Method -ne 'Head' })
        if ($gets.Count -ne $sc.Gets) { Fail $label "$($gets.Count) list downloads, expected $($sc.Gets)" }
        # Without -UseBasicParsing, 5.1 hands the response to Internet Explorer's
        # engine, which fails under SYSTEM where IE's first run was never completed.
        if (@($Script:WebCalls | Where-Object { -not $_.Basic }).Count) { Fail $label 'a web request without -UseBasicParsing' }
        if ($sc.ContainsKey('Log') -and -not @($Script:Logged | Where-Object { $_ -like "*$($sc.Log)*" }).Count) {
            Fail $label "expected a log line containing '$($sc.Log)'"
        }
        if ($sc.Counts -eq 'full' -and -not @($Script:Logged | Where-Object { $_ -match $leftOut }).Count) {
            Fail $label "expected the log to say what was left out and why: '$leftOut'"
        }

        if ($failures -eq $before) {
            Say "  ok    $label  -  $($Script:Counters.IntelSource); hash $($got.Hash), filename $($got.Filename), C2 $($got.C2)" Green
        }
    }

    # --- Add-IntelHit: report-only ----------------------------------------------
    Reset-Intel
    $af = $failures
    $evidence = Join-Path $tmpRoot 'sktest-evidence.exe'
    [System.IO.File]::WriteAllText($evidence, 'sktest evidence')
    $evidenceSha = (Get-TestHash 'sktest evidence')
    Add-IntelHit -Kind 'filename' -Source 'process' -Target "$evidence (PID 1)" -File $evidence -Indicator '\\sktest-evidence\.exe' -Score 80 -WouldHave 'kills the process'
    foreach ($i in 2..60) { Add-IntelHit -Kind 'C2' -Source 'DNS cache' -Target "x$i.example -> 203.0.113.7" -Indicator '203.0.113.7' }
    if ($Script:Counters.IntelHits -ne 60) { Fail 'Add-IntelHit' "IntelHits = $($Script:Counters.IntelHits), expected 60" }
    if ($Script:Counters.IOCsFound -ne 0) { Fail 'Add-IntelHit' "IOCsFound = $($Script:Counters.IOCsFound): an intel match must not be an IOC alert" }
    $intelF = @($Script:Findings | Where-Object { $_.Title -like 'Intel match (report-only):*' })
    if ($intelF.Count -ne 21) { Fail 'Add-IntelHit' "$($intelF.Count) findings, expected 20 and one 'more than 20'" }
    if (@($Script:Findings | Where-Object { $_.Severity -ne 'Low' -or $_.Title -match '^(?i)IOC' }).Count) {
        Fail 'Add-IntelHit' 'a finding that is not Low, or whose title starts with IOC (Battlefield alerts on both)'
    }
    if ($Script:IntelMatches.Count -ne 50) { Fail 'Add-IntelHit' "$($Script:IntelMatches.Count) entries in intel.matches, expected the cap of 50" }
    $first = $Script:IntelMatches[0]
    if ($first.sha256 -ne $evidenceSha -or $first.signer -ne 'CN=SKTEST Vendor' -or $first.signature -ne 'Valid' -or
        $first.would_have -ne 'kills the process' -or $first.score -ne 80 -or $first.source -ne 'process') {
        Fail 'Add-IntelHit' "the first match's evidence is wrong: $(($first.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; ')"
    }
    if ($null -ne $Script:IntelMatches[1].sha256 -or $null -ne $Script:IntelMatches[1].would_have) { Fail 'Add-IntelHit' 'evidence or would_have filled in for a match with no file or action' }
    if ($failures -eq $af) { Say '  ok    Add-IntelHit  -  counted, 50 in intel.matches with SHA256 and signer, 20 Low findings, never an IOC' Green }

    # Fresh load: the matcher and consumer tests below use these sets.
    if (Test-Path -LiteralPath $cacheFile) { Remove-Item -LiteralPath $cacheFile -Force }
    Reset-Intel; Set-Web; Invoke-Verbatim $phase1
} finally {
    # .NET, not Remove-Item: the consumer tests below mock Remove-Item.
    if ([System.IO.Directory]::Exists($tmpRoot)) { [System.IO.Directory]::Delete($tmpRoot, $true) }
}

# --- Find-IntelFilenameMatch: LOKI's rule --------------------------------------
$matchCases = @(
    @('C:\Users\bob\AppData\Local\Temp\sktest-evil.exe', '\\sktest-evil\.exe', 'a full path'),
    @('sktest-evil.exe',                                  $null,               'a bare name: patterns anchor on \'),
    @('C:\Users\bob\sktest-weak.exe',                     $null,               'a pattern under the minimum score'),
    @('C:\Users\bob\SKTEST-CASE.DLL',                     '(?i)\\SKTEST-CASE\.dll', 'its own (?i)'),
    @('C:\Users\bob\SKTEST-CASE2.DLL',                    $null,               'case-sensitive by default'),
    @('C:\Users\bob\sktest-case2.dll',                    '\\sktest-case2\.dll', 'exact case'),
    @('C:\Program Files\Vendor\sktest-fp.exe',            $null,               'its false-positive regex'),
    @('C:\Users\bob\Downloads\sktest-fp.exe',             '\\sktest-fp\.exe',  'outside the false-positive path'),
    @('"C:\Users\Public\sktest-evil.exe" /quiet',         '\\sktest-evil\.exe', 'a command line'),
    @('C:\Windows\System32\svchost.exe',                  $null,               'a known-good path (the over-broad entries are out)'),
    @('',                                                 $null,               'an empty path')
)
$mf = $failures
foreach ($c in $matchCases) {
    $m = Find-IntelFilenameMatch -Path $c[0]
    $got = if ($m) { $m.Pattern } else { $null }
    if ($got -ne $c[1]) { Fail "match: $($c[2])" "'$($c[0])' matched $(if ($got) { "'$got'" } else { 'nothing' }), expected $(if ($c[1]) { "'$($c[1])'" } else { 'nothing' })" }
}
# A regex that times out is switched off after its first timeout.
$slow = [pscustomobject]@{ Pattern = '^(a+)+b$'; Score = 60; Exclude = $null; Off = $false
                           Regex = (New-Object System.Text.RegularExpressions.Regex -ArgumentList '^(a+)+b$', ([System.Text.RegularExpressions.RegexOptions]::None), ([timespan]::FromMilliseconds(5))) }
$Script:FilenameIOCs.Insert(0, $slow)
$null = Find-IntelFilenameMatch -Path (('a' * 40) + '!')
$null = Find-IntelFilenameMatch -Path (('a' * 40) + '!')
if (-not $slow.Off -or $Script:IntelRegexTimeouts -ne 1) { Fail 'match: timeout' "a timed-out regex is not switched off (Off=$($slow.Off), timeouts=$($Script:IntelRegexTimeouts))" }
$Script:FilenameIOCs.RemoveAt(0)
# The per-run caps: paths, then time.
$Script:IntelPathBudget = $Script:IntelPathsChecked + 1
$first  = Find-IntelFilenameMatch -Path 'C:\Users\bob\sktest-evil.exe'
$second = Find-IntelFilenameMatch -Path 'C:\Users\bob\sktest-evil.exe'
if (-not $first -or $second -or $Script:IntelPathsSkipped -ne 1) { Fail 'match: path cap' "the path after the cap was checked, or not counted as skipped ($($Script:IntelPathsSkipped))" }
$Script:IntelPathBudget = 3000; $Script:IntelTimeBudget = 0
if ((Find-IntelFilenameMatch -Path 'C:\Users\bob\sktest-evil.exe') -or $Script:IntelPathsSkipped -ne 2) { Fail 'match: time cap' 'a path was checked after the time budget ran out' }
$Script:IntelTimeBudget = 30
if ($failures -eq $mf) { Say "  ok    matcher  -  full paths, case, (?i), false-positive regex, command lines, timeouts, and the per-run caps" Green }

# --- Find-IntelC2Match: whole labels, subdomains, addresses ---------------------
$c2Cases = @(
    @('sktest-c2.example',          'sktest-c2.example'),
    @('SKTEST-C2.Example.',         'sktest-c2.example'),
    @('beacon.sktest-c2.example',   'sktest-c2.example'),
    @('a.b.sktest-c2.example',      'sktest-c2.example'),
    @('notsktest-c2.example',       $null),
    @('sktest-c2.example.evil',     $null),
    @('203.0.113.7',                '203.0.113.7'),
    @('1.203.0.113.7',              $null),
    @('microsoft.com',              $null),
    @('www.microsoft.com',          $null),
    @('',                           $null)
)
$cf = $failures
foreach ($c in $c2Cases) {
    $got = Find-IntelC2Match $c[0]
    if ($got -ne $c[1]) { Fail "C2 match: '$($c[0])'" "matched $(if ($got) { "'$got'" } else { 'nothing' }), expected $(if ($c[1]) { "'$($c[1])'" } else { 'nothing' })" }
}
if ($failures -eq $cf) { Say '  ok    C2 matcher  -  exact and subdomains by whole labels, addresses exactly, known-good left out' Green }

# --- The consumers ---------------------------------------------------------------
# Only the checks' own inputs are mocked. Every match against the SKTEST intel
# must be reported through Add-IntelHit and acted on nowhere; a match against
# a hard-coded list must still be acted on as before.
$Script:Actions = New-Object 'System.Collections.Generic.List[string]'
$Script:Dirs    = @{}     # directory -> child directory names
$Script:Files   = @{}     # directory -> file names
$Script:Reg     = @{}     # registry key -> values
$Script:Procs   = @()     # pscustomobject Name, Id, Path
$Script:Hosts   = @()
$Script:Dns     = @()
$Script:FileHashes = @{}
$Script:HashCalls  = 0
$Script:HkuSids = @()

function Join-Path { param([Parameter(Position = 0)]$Path, [Parameter(Position = 1)]$ChildPath) "$(([string]$Path).TrimEnd('\'))\$ChildPath" }
function Test-Path {
    param([Parameter(Position = 0)]$Path, $LiteralPath, $PathType)
    $p = if ($LiteralPath) { $LiteralPath } else { $Path }
    $Script:Dirs.ContainsKey($p) -or $Script:Files.ContainsKey($p) -or $Script:Reg.ContainsKey($p)
}
function Get-ChildItem {
    param([Parameter(Position = 0)]$Path, $LiteralPath, $Filter, [switch]$Directory, [switch]$File, [switch]$Force, [switch]$Recurse)
    $p = if ($LiteralPath) { $LiteralPath } else { $Path }
    if ($p -eq 'HKU:\') { return @($Script:HkuSids | ForEach-Object { [pscustomobject]@{ PSChildName = $_ } }) }
    if ($Recurse) { return @() }          # the ransomware canary walk: nothing encrypted
    if ($Directory) { return @(@($Script:Dirs[$p]) | Where-Object { $_ } | ForEach-Object { [pscustomobject]@{ Name = $_; FullName = "$p\$_" } }) }
    $names = @(@($Script:Files[$p]) | Where-Object { $_ })
    if ($Filter) { $names = @($names | Where-Object { $_ -like $Filter }) }
    @($names | ForEach-Object {
        [pscustomobject]@{ Name = $_; BaseName = [System.IO.Path]::GetFileNameWithoutExtension($_)
                           Extension = [System.IO.Path]::GetExtension($_); FullName = "$p\$_" } })
}
function Get-ItemProperty { param([Parameter(Position = 0)]$Path, $Name) if ($Script:Reg[$Path]) { [pscustomobject]$Script:Reg[$Path] } }
function Remove-ItemProperty { param($Path, $Name, [switch]$Force, $ErrorAction) $Script:Actions.Add("remove value $Path\$Name") }
function Remove-Item { param([Parameter(Position = 0)]$Path, $LiteralPath, [switch]$Force, [switch]$Recurse) $Script:Actions.Add("delete $LiteralPath$Path") }
function Stop-Process { param($Id, [switch]$Force, $ErrorAction) $Script:Actions.Add("kill $Id") }
function Get-Process {
    param($Id, $ErrorAction)
    $p = @($Script:Procs | Where-Object { $_.Id -eq $Id })
    if ($p.Count) { $p[0] } elseif ($ErrorAction -eq 'Stop') { throw "no process $Id" }
}
function Get-CimInstance {
    param([Parameter(Position = 0)]$ClassName, $Filter, $Namespace)
    if ($ClassName -ne 'Win32_Process') { throw "unmocked CIM class $ClassName" }
    $all = @($Script:Procs | ForEach-Object { [pscustomobject]@{ ProcessId = [uint32]$_.Id; ExecutablePath = $_.Path } })
    if ($Filter -match 'ProcessId=(\d+)') { $all = @($all | Where-Object { $_.ProcessId -eq [uint32]$Matches[1] }) }
    $all
}
function Get-PSDrive {
    param($Name, $PSProvider, $ErrorAction)
    if ($Name -eq 'HKU') { return [pscustomobject]@{ Name = 'HKU' } }
    @([pscustomobject]@{ Root = 'C:\' }, [pscustomobject]@{ Root = 'D:\' })
}
function New-PSDrive { throw 'New-PSDrive should not be needed: the HKU drive is mocked as present' }
function Get-FileHash {
    param($LiteralPath, $Algorithm, $ErrorAction)
    $Script:HashCalls++
    [pscustomobject]@{ Hash = $(if ($Script:FileHashes[$LiteralPath]) { $Script:FileHashes[$LiteralPath].ToUpper() } else { 'AB' * 32 }) }
}
function Get-Content { param($LiteralPath, $ErrorAction, [switch]$Raw) if ($LiteralPath -like '*\drivers\etc\hosts') { $Script:Hosts } else { throw "unmocked file $LiteralPath" } }
function Get-NetTCPConnection { param($State, $ErrorAction) @() }
function Get-DnsClientCache { param($ErrorAction) $Script:Dns }

$Script:LegitProcessNames = New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase)
$null = $Script:LegitProcessNames.Add('Zoom')
$Script:LegitDropFiles = @('PsExec.exe')
$Script:HostsWhitelist = @('granicus.com')
$Script:CanaryWhitelist = @()

function Reset-World {
    Invoke-Expression $countersLit
    $Script:IntelPathBudget = 3000; $Script:IntelTimeBudget = 30
    $Script:IntelPathsChecked = 0; $Script:IntelPathsSkipped = 0; $Script:IntelRegexTimeouts = 0
    $Script:IntelMatchClock.Reset(); $Script:IntelMatches.Clear()
    $Script:Logged.Clear(); $Script:Findings.Clear(); $Script:Actions.Clear()
    $Script:Dirs = @{}; $Script:Files = @{}; $Script:Reg = @{}; $Script:Procs = @(); $Script:Hosts = @(); $Script:Dns = @()
    $Script:FileHashes = @{}; $Script:HashCalls = 0; $Script:HkuSids = @()
}

$detectionFiles = {
    $Script:Dirs['C:\Users'] = @('bob')
    $Script:Dirs['C:\Users\bob\Downloads'] = @()
    $Script:Files['C:\Users\bob\Downloads'] = @('sktest-evil.exe', 'sktest-hashed.dll', 'invoice.pdf')
    $Script:FileHashes['C:\Users\bob\Downloads\sktest-hashed.dll'] = $hashEvil
}

# Each consumer: the world it sees, the code, and every intel match it must
# report ('kind|source|target|would_have', -like patterns), the actions it must
# take (hard-coded matches only) and its IOC count. Blocks: how many hosts
# lines must be logged as blocking a C2 name. HashCalls: files hashed.
$consumers = @(
    @{ Name = 'Process Engine'; Code = $procLoop
       Setup = {
           $Script:Procs = @(
               [pscustomobject]@{ Name = 'sktest-evil'; Id = 4101; CPU = 1.0; Path = 'C:\Users\bob\AppData\Local\Temp\sktest-evil.exe' }
               [pscustomobject]@{ Name = 'njrat';       Id = 4102; CPU = 1.0; Path = 'C:\Users\bob\AppData\Roaming\njrat.exe' }
               [pscustomobject]@{ Name = 'NVDisplay.Container'; Id = 4103; CPU = 1.0; Path = 'C:\Program Files\NVIDIA Corporation\Display.NvContainer\NVDisplay.Container.exe' }
               [pscustomobject]@{ Name = 'sktest-evil'; Id = 4104; CPU = 1.0; Path = 'C:\Program Files\SkVendor\sktest-evil.exe' }
           )
           $Script:Cache_Processes = $Script:Procs
       }
       Matches = @('filename|process|C:\Users\bob\AppData\Local\Temp\sktest-evil.exe (PID 4101)|kills the process'
                   'filename|process|C:\Program Files\SkVendor\sktest-evil.exe (PID 4104)|is only reported (vendor path)')
       Actions = @('kill 4102'); Iocs = 1 }
    @{ Name = 'Persistence Engine'; Code = $persist
       Setup = {
           $run = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
           $Script:Reg[$run] = [ordered]@{ SkEvil = '"C:\Users\Public\sktest-evil.exe" /q'; Njrat = 'C:\ProgramData\njrat.exe'
                                           OneDrive = '"C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background' }
           $Script:HkuSids = @('S-1-5-21-1-2-3-1001', 'S-1-5-21-1-2-3-1001_Classes', 'S-1-5-18')
           $Script:Reg['HKU:\S-1-5-21-1-2-3-1001\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'] = [ordered]@{ SkEvilUser = 'C:\Users\bob\AppData\Roaming\sktest-evil.exe' }
           $Script:Dirs['C:\Users'] = @('bob', 'Public')
           $startup = 'C:\Users\bob\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
           $Script:Files[$startup] = @('sktest-shortcut.lnk', 'Send to OneNote.lnk')
       }
       Matches = @('filename|Run value|HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SkEvil = "C:\Users\Public\sktest-evil.exe" /q|removes the Run value'
                   'filename|Run value|HKU:\S-1-5-21-1-2-3-1001\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SkEvilUser = C:\Users\bob\AppData\Roaming\sktest-evil.exe (user: *)|removes the Run value'
                   'filename|startup shortcut|C:\Users\bob\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\sktest-shortcut.lnk|deletes the shortcut')
       Actions = @('remove value HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Njrat'); Iocs = 1 }
    @{ Name = 'Redirected folder scan'; Code = $redirected
       Setup = {
           $Script:Dirs['D:\Users'] = @('bob')
           $Script:Files['D:\Users\bob\Downloads'] = @('sktest-evil.exe', 'toolbar-setup.exe', 'report.pdf')
       }
       Matches = @('filename|redirected folder|D:\Users\bob\Downloads\sktest-evil.exe|deletes the file')
       Actions = @('delete D:\Users\bob\Downloads\toolbar-setup.exe'); Iocs = 1 }
    @{ Name = 'Detection Engine'; Code = $detection
       Setup = {
           & $detectionFiles
           $Script:Hosts = @(
               '# Copyright (c) 1993-2009 Microsoft Corp.'
               '127.0.0.1       localhost'
               '10.0.0.6        sktest-c2.example      # C2, pointed at a routable address'
               "10.0.0.8`tgood.local`tapi.sktest-c2.example"
               '203.0.113.7     printer.local          # a C2 address'
               '0.0.0.0         sktest-c2.example      # blocked'
               '::1             sktest-c2.example      # blocked'
               '0:0:0:0:0:0:0:0 sktest-c2.example      # blocked'
               '10.0.0.5        notsktest-c2.example   # a longer name ending the same way: no match'
               '10.0.0.9        fine.local             # in a comment, no match: sktest-c2.example'
               '10.0.0.7        intranet.corp.local'
           )
           $Script:Dns = @([pscustomobject]@{ Entry = 'sktest-c2.example.';       Data = '10.1.1.1' },
                           [pscustomobject]@{ Entry = 'beacon.sktest-c2.example'; Data = '10.1.1.2' },
                           [pscustomobject]@{ Entry = 'cdn.benign.example';       Data = '203.0.113.7' },
                           [pscustomobject]@{ Entry = 'www.microsoft.com';        Data = '23.1.2.3' })
       }
       Matches = @('filename|scanned file|C:\Users\bob\Downloads\sktest-evil.exe|'
                   'hash|scanned file|C:\Users\bob\Downloads\sktest-hashed.dll|'
                   'C2|hosts file|10.0.0.6        sktest-c2.example      # C2, pointed at a routable address|'
                   "C2|hosts file|10.0.0.8`tgood.local`tapi.sktest-c2.example|"
                   'C2|hosts file|203.0.113.7     printer.local          # a C2 address|'
                   'C2|DNS cache|sktest-c2.example. -> 10.1.1.1|'
                   'C2|DNS cache|beacon.sktest-c2.example -> 10.1.1.2|'
                   'C2|DNS cache|cdn.benign.example -> 203.0.113.7|')
       Actions = @(); Iocs = 0; Blocks = 3; HashCalls = 2 }
    # With no hash intel loaded, no file is hashed.
    @{ Name = 'Detection Engine, no hash intel'; Code = $detection
       Setup = { & $detectionFiles; $Script:HashIOCs.Clear() }
       Matches = @('filename|scanned file|C:\Users\bob\Downloads\sktest-evil.exe|')
       Actions = @(); Iocs = 0; Blocks = 0; HashCalls = 0 }
)

foreach ($c in $consumers) {
    $label = "consumer: $($c.Name)"
    $before = $failures
    Reset-World
    & $c.Setup
    Invoke-Verbatim $c.Code

    $skipped = @($Script:Logged | Where-Object { $_ -match ' skipped  -  ' })
    if ($skipped.Count) { Fail $label "a block aborted: $($skipped -join ' | ')" }
    if ($Script:Counters.IntelHits -ne $c.Matches.Count) { Fail $label "$($Script:Counters.IntelHits) intel matches counted, expected $($c.Matches.Count)" }
    $got = @($Script:IntelMatches | ForEach-Object { "$($_.kind)|$($_.source)|$($_.target)|$($_.would_have)" })
    $missing = @($c.Matches | Where-Object { $p = $_; -not @($got | Where-Object { $_ -like $p }).Count })
    $extra   = @($got | Where-Object { $g = $_; -not @($c.Matches | Where-Object { $g -like $_ }).Count })
    if ($missing.Count) { Fail $label "intel matches not reported: $($missing -join ' || ')" }
    if ($extra.Count)   { Fail $label "unexpected intel matches: $($extra -join ' || ')" }
    $acts = @($Script:Actions)
    if (($acts -join '|') -ne ($c.Actions -join '|')) {
        Fail $label "actions taken: [$($acts -join '; ')], expected [$($c.Actions -join '; ')] (hard-coded matches only)"
    }
    if ($Script:Counters.IOCsFound -ne $c.Iocs) { Fail $label "IOCsFound = $($Script:Counters.IOCsFound), expected $($c.Iocs) (hard-coded matches only)" }
    $intelF = @($Script:Findings | Where-Object { $_.Title -like 'Intel match (report-only):*' })
    if ($intelF.Count -ne $c.Matches.Count -or @($intelF | Where-Object { $_.Severity -ne 'Low' }).Count) {
        Fail $label "$($intelF.Count) Low intel findings, expected $($c.Matches.Count)"
    }
    if ($c.ContainsKey('Blocks')) {
        $blocks = @($Script:Logged | Where-Object { $_ -like 'INFO: Hosts file blocks C2 name(s) sktest-c2.example:*' }).Count
        if ($blocks -ne $c.Blocks) { Fail $label "$blocks hosts lines logged as blocking a C2 name, expected $($c.Blocks)" }
    }
    if ($c.ContainsKey('HashCalls') -and $Script:HashCalls -ne $c.HashCalls) { Fail $label "$($Script:HashCalls) files hashed, expected $($c.HashCalls)" }
    if ($failures -eq $before) {
        Say "  ok    $label  -  $($c.Matches.Count) intel match(es) reported, none acted on; hard-coded actions: $(if ($acts.Count) { $acts -join '; ' } else { 'none' })" Green
    }
}

# --- Static: every $Script:Config.<Name> exists in the Config literal ----------
# Under StrictMode 2, reading a property a PSCustomObject does not have throws,
# and Invoke-SafeBlock turns that into a skipped engine with one INFO line in
# the log. That is how the Intel Engine went unnoticed from v1.002 on.
$tokens = $null; $parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw "ShellKnight.ps1 does not parse: $($parseErrors[0].Message)" }
$isConfig = { param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] -and $n.VariablePath.UserPath -eq 'Script:Config' }
$cfgAssign = @($ast.FindAll({ param($n)
    $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and (& $isConfig $n.Left) }, $true))
if ($cfgAssign.Count -ne 1) { throw "expected one assignment to `$Script:Config, found $($cfgAssign.Count)" }
$literal = $cfgAssign[0].Right.Find({ param($n) $n -is [System.Management.Automation.Language.HashtableAst] }, $true)
if (-not $literal) { throw 'the $Script:Config assignment has no hashtable literal' }
$defined = @($literal.KeyValuePairs | ForEach-Object { $_.Item1.Value })
$undefined = New-Object 'System.Collections.Generic.List[string]'
foreach ($m in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.MemberExpressionAst] -and (& $isConfig $n.Expression) }, $true)) {
    if ($m.Member -isnot [System.Management.Automation.Language.StringConstantExpressionAst]) {
        $undefined.Add("line $($m.Extent.StartLineNumber): a computed member '$($m.Member.Extent.Text)' cannot be checked"); continue
    }
    if ($m.Member.Value -notin $defined) { $undefined.Add("line $($m.Extent.StartLineNumber): `$Script:Config.$($m.Member.Value) is not in the Config literal") }
}
if ($undefined.Count) { foreach ($u in $undefined) { Fail 'config' $u } }
else { Say "  ok    config  -  every `$Script:Config.<Name> the script reads is in the Config literal ($($defined.Count) defined)" Green }

Say ''
if ($failures -gt 0) {
    Say "  FAILED - $failures assertion(s)" Red
    exit 1
}
Say '  PASS - all assertions' Green
exit 0

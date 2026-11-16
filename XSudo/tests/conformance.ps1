#requires -Version 7
<#
.SYNOPSIS
  Read-only conformance probes for a MinSudo-compatible launcher (MinSudo.exe or XSudo.exe).

.DESCRIPTION
  Runs the probe matrix against -Exe and writes normalized
  results to -Out (results.txt, results.json, work\ helper scripts). Run it once with
  MinSudo.exe and once with XSudo.exe into two folders, then compare:

      Compare-Object (Get-Content A\results.txt) (Get-Content B\results.txt)

  Every probe header line carries an EXPECTED-DIFF marker when a difference is intended
  (exit-code forwarding, banner/message wording). A difference in a probe WITHOUT a marker
  is a real incompatibility.

  Must run from an elevated (High integrity) PowerShell 7. Child commands are read-only
  (whoami, echo, cmd /c exit N, ping 127.0.0.1, powershell read-only expressions).
  Files are written only under -Out.

.EXAMPLE
  pwsh -File conformance.ps1 -Exe .\target\release\XSudo.exe -Out .\tests\out-xsudo
#>
param(
    [Parameter(Mandatory)][string]$Exe,
    [Parameter(Mandatory)][string]$Out,
    [switch]$SkipSlow
)
$ErrorActionPreference = 'Stop'
$Exe = (Resolve-Path -LiteralPath $Exe).Path
New-Item -ItemType Directory -Force $Out | Out-Null
$Out = (Resolve-Path -LiteralPath $Out).Path
$Work = Join-Path $Out 'work'
New-Item -ItemType Directory -Force $Work | Out-Null
$SpaceDir = Join-Path $Work 'sp dir'
New-Item -ItemType Directory -Force $SpaceDir | Out-Null

# ---------------------------------------------------------------- helper child scripts
@'
$id=[Security.Principal.WindowsIdentity]::GetCurrent()
"user=" + $id.Name
"sid=" + $id.User.Value
"owner=" + $id.Owner.Value
"session=" + (Get-Process -Id $PID).SessionId
$g = whoami /groups /fo csv | ConvertFrom-Csv
"integrity=" + ($g | ? {$_.'Group Name' -like 'Mandatory Label*'}).'Group Name'
"groups=" + (($g | % { $_.'Group Name' } | sort) -join ';')
"privs=" + ((whoami /priv /fo csv | ConvertFrom-Csv | sort 'Privilege Name' | % { $_.'Privilege Name' + ':' + $_.State }) -join ';')
foreach($v in 'USERNAME','USERDOMAIN','USERPROFILE','APPDATA','LOCALAPPDATA','TEMP','TMP','HOMEPATH','COMPUTERNAME','SESSIONNAME','LOGONSERVER'){ "env.$v=" + [Environment]::GetEnvironmentVariable($v) }
$p=[Environment]::GetEnvironmentVariable('PATH'); "env.PATH.first=" + $p.Split(';')[0]; "env.PATH.endsWithSemicolon=" + $p.EndsWith(';')
"env.XSUDO_PROBE=" + $env:XSUDO_PROBE
$par = Get-CimInstance Win32_Process -Filter ("ProcessId=" + (Get-CimInstance Win32_Process -Filter "ProcessId=$PID").ParentProcessId)
"parent=" + $par.Name
'@ | Set-Content (Join-Path $Work 'ident.ps1') -Encoding ASCII

@'
Add-Type -Namespace X -Name K -MemberDefinition @"
[System.Runtime.InteropServices.DllImport("kernel32.dll")] public static extern System.IntPtr GetConsoleWindow();
[System.Runtime.InteropServices.DllImport("kernel32.dll")] public static extern uint GetConsoleProcessList(uint[] l, uint n);
[System.Runtime.InteropServices.DllImport("kernel32.dll")] public static extern System.IntPtr GetStdHandle(int n);
[System.Runtime.InteropServices.DllImport("kernel32.dll")] public static extern uint GetFileType(System.IntPtr h);
"@
$l=New-Object 'uint32[]' 64
$n=[X.K]::GetConsoleProcessList($l,64)
"consoleProcs=" + (($l[0..([Math]::Max($n,1)-1)] | % { try{(Get-Process -Id $_ -EA Stop).ProcessName}catch{"?"} } | sort) -join ',')
"stdin.type=" + [X.K]::GetFileType([X.K]::GetStdHandle(-10)) + " stdout.type=" + [X.K]::GetFileType([X.K]::GetStdHandle(-11)) + " stderr.type=" + [X.K]::GetFileType([X.K]::GetStdHandle(-12))
"inputRedirected=" + [Console]::IsInputRedirected + " outputRedirected=" + [Console]::IsOutputRedirected + " errRedirected=" + [Console]::IsErrorRedirected
'@ | Set-Content (Join-Path $Work 'console.ps1') -Encoding ASCII

@'
"[" + [Environment]::CommandLine + "]"
"argc=" + $args.Count
'@ | Set-Content (Join-Path $Work 'cl.ps1') -Encoding ASCII

Set-Content (Join-Path $SpaceDir 't.cmd') "@echo off`r`necho cmdfile %1 %2" -Encoding ASCII
Set-Content (Join-Path $SpaceDir 't.bat') "@echo off`r`necho batfile %1" -Encoding ASCII
Set-Content (Join-Path $SpaceDir 't.ps1') 'Write-Output "ps1file $args"' -Encoding ASCII
Copy-Item "$env:WINDIR\System32\whoami.exe" (Join-Path $SpaceDir 'who ami.exe') -Force
$ps = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"

# ---------------------------------------------------------------- runner and normalizer
function Invoke-Probe {
    param([string]$ArgLine, [string]$Stdin = $null, [string]$Cwd = $null, [int]$TimeoutMs = 60000)
    $psi = [Diagnostics.ProcessStartInfo]::new($Exe, $ArgLine)
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.RedirectStandardInput = $true
    if ($Cwd) { $psi.WorkingDirectory = $Cwd }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $p = [Diagnostics.Process]::Start($psi)
    $ot = $p.StandardOutput.ReadToEndAsync(); $et = $p.StandardError.ReadToEndAsync()
    if ($Stdin) { $p.StandardInput.Write($Stdin) }
    $p.StandardInput.Close()
    $timedOut = $false
    if (-not $p.WaitForExit($TimeoutMs)) { try { $p.Kill($true) } catch {}; $timedOut = $true }
    $p.WaitForExit()
    [pscustomobject]@{ Exit = $p.ExitCode; Ms = $sw.ElapsedMilliseconds; TimedOut = $timedOut; Out = $ot.Result; Err = $et.Result }
}

function Normalize([string]$t) {
    if ($null -eq $t) { return '' }
    $t = $t -replace "`r`n", "`n"
    # banner lines (name, version, copyright) of either tool
    $t = ($t -split "`n" | Where-Object { $_ -notmatch '^(MinSudo|XSudo) \d' -and $_ -notmatch '^\(c\) ' }) -join "`n"
    $t = $t.Replace($Work, '<WORK>').Replace($Out, '<OUT>')
    $t = [regex]::Replace($t, '(?i)\b(minsudo|xsudo)(\.exe)?\b', '<EXE>')
    $t = [regex]::Replace($t, '\b\d{1,2}:\d{2}:\d{2}(\.\d+)?\b', '<TIME>')
    $t = [regex]::Replace($t, '(?i)pid[ =:]+\d+', 'pid=<PID>')
    $t = [regex]::Replace($t, '\[Version \d+\.\d+\.\d+\.\d+\]', '[Version <V>]')
    $t = ($t -split "`n" | ForEach-Object {
            if ($_ -match '^consoleProcs=(.*)$') {
                'consoleProcs=' + (($Matches[1] -split ',' | Sort-Object) -join ',')
            } else { $_ }
        }) -join "`n"
    $t = ($t -split "`n" | ForEach-Object { $_.TrimEnd() }) -join "`n"
    return $t.Trim("`n")
}

$script:Results = New-Object System.Collections.Generic.List[object]
$script:Text = New-Object System.Text.StringBuilder

# Diff: '' (must match), 'exit' (exit code intentionally differs), 'text' (wording intentionally differs), 'both'
function Add-Probe {
    param([string]$Id, [string]$What, [string]$ArgLine, [string]$Stdin = $null, [string]$Cwd = $null,
          [string]$Diff = '', [switch]$NoOut, [switch]$NoErr, [switch]$NoExit, [int]$MinMs = -1, [int]$MaxMs = -1)
    if (-not $Cwd) { $Cwd = $Work }
    $r = Invoke-Probe -ArgLine $ArgLine -Stdin $Stdin -Cwd $Cwd
    $o = Normalize $r.Out; $e = Normalize $r.Err
    $timing = ''
    if ($MinMs -ge 0 -and $MaxMs -ge 0) { $timing = if ($r.Ms -ge $MinMs -and $r.Ms -le $MaxMs) { 'wait=ok' } else { 'wait=OUT-OF-RANGE' } }
    $marker = if ($Diff) { " [EXPECTED-DIFF:$Diff]" } else { '' }
    [void]$script:Text.AppendLine("=== $Id $What$marker")
    [void]$script:Text.AppendLine("args: " + (Normalize $ArgLine))
    if (-not $NoExit) { [void]$script:Text.AppendLine("exit: $($r.Exit)") }
    if ($timing) { [void]$script:Text.AppendLine($timing) }
    if ($r.TimedOut) { [void]$script:Text.AppendLine('TIMED-OUT') }
    if (-not $NoOut) { [void]$script:Text.AppendLine("stdout:"); [void]$script:Text.AppendLine($o) }
    if (-not $NoErr) { [void]$script:Text.AppendLine("stderr:"); [void]$script:Text.AppendLine($e) }
    $script:Results.Add([pscustomobject]@{ id = $Id; what = $What; args = (Normalize $ArgLine); expectedDiff = $Diff; exit = $r.Exit; ms = $r.Ms; stdout = $o; stderr = $e })
    Write-Host ("{0,-6} exit={1,-12} {2}" -f $Id, $r.Exit, $What)
}

$id1 = Join-Path $Work 'ident.ps1'; $con = Join-Path $Work 'console.ps1'; $cl = Join-Path $Work 'cl.ps1'
$env:XSUDO_PROBE = 'probe-value-1'
$NL = "`n"

# ---------------------------------------------------------------- G: grammar
Add-Probe G01 'help via -? (single arg)' '-?' -Diff text -NoOut
Add-Probe G02 'help via /? , -H, --Help, -help are equal exit' '/?' -Diff text -NoOut
Add-Probe G03 'help --HELP case-insensitive' '--HELP' -Diff text -NoOut
Add-Probe G04 'version single arg' '--version' -Diff text
Add-Probe G05 'version alias -Ver' '-Ver' -Diff text
Add-Probe G06 'version alias /VER' '/VER' -Diff text
Add-Probe G07 'unknown option alone is a usage error' '--bogus' -Diff both
Add-Probe G08 'unknown option alone, slash form' '/bogus' -Diff both
Add-Probe G09 '-WD alone (no value, no command) is a usage error' '-WD' -Diff both
Add-Probe G10 '-WD= alone (empty value) is a usage error' '-WD=' -Diff both
Add-Probe G11 'two unknown options, no command' '--bogus --bogus' -Diff both
Add-Probe G12 'unknown option before a command is ignored' '--NoLogo --bogus cmd /c echo x'
Add-Probe G13 'unknown option with =value before a command is ignored' '--NoLogo --bogus=1 cmd /c echo y'
Add-Probe G14 'unknown option then no command runs default shell' '--NoLogo --bogus' -Stdin "echo shell-ran${NL}exit${NL}"
Add-Probe G15 '--version before a command is ignored, command runs' '--NoLogo --version cmd /c echo q'
Add-Probe G16 '--help after other args is ignored, command runs' '--NoLogo --help cmd /c echo q'
Add-Probe G17 '--version first arg but a command follows: command runs' '--version cmd /c echo q' -Diff text
Add-Probe G18 'no arguments runs default shell (stdin fed)' '' -Stdin "echo shell-ran${NL}exit${NL}"
Add-Probe G19 '-NoL alias' '-nol cmd /c echo a'
Add-Probe G20 '/nologo alias' '/nologo cmd /c echo a'
Add-Probe G21 '--nologo=1 (value ignored)' '--nologo=1 cmd /c echo a'
Add-Probe G22 '--NoLogo:1 (value ignored)' '--NoLogo:1 cmd /c echo a'
Add-Probe G23 'banner shown without --NoLogo (banner lines normalized away)' 'cmd /c echo a' -Diff text
Add-Probe G24 '-- ends options? (first arg)' '-- cmd /c echo dd' -Diff text
Add-Probe G25 '-- after -NoLogo is consumed' '-NoLogo -- cmd /c echo dd2'
Add-Probe G26 'option after command goes to child' '--NoLogo cmd /c echo -P --NoLogo'
Add-Probe G27 'quoted option accepted' '--NoLogo "-S" whoami'
Add-Probe G28 'quoted program accepted' '--NoLogo "whoami"'
Add-Probe G29 'empty token (double space) ends option parsing; remainder becomes the command (fails)' '--NoLogo  -S whoami' -Diff text
Add-Probe G30 'multiple spaces before command are skipped' '--NoLogo -S    whoami'
Add-Probe G31 'tab as separator' ("--NoLogo`t-S whoami")
Add-Probe G32 'single-arg: -help' '-help' -Diff text -NoOut
Add-Probe G33 'single-arg: -P alone runs default shell' '-P' -Stdin "exit${NL}" -Diff text
Add-Probe G34 'single-arg: -x unknown' '-x' -Diff both
Add-Probe G35 'single-arg: bare dash' '-' -Diff both
Add-Probe G36 'single-arg: -TrustedInstaller long name with single dash' '-TrustedInstaller' -Stdin "echo %USERNAME%${NL}exit${NL}" -Diff text
Add-Probe G37 'single-arg: /System' '/System' -Stdin "exit${NL}" -Diff text

# ---------------------------------------------------------------- I: identity per mode
foreach ($mode in @('', '-S', '-TI')) {
    foreach ($pv in @('', '-P')) {
        $tag = ('{0}{1}' -f $(if ($mode) { $mode.TrimStart('-') } else { 'ADM' }), $(if ($pv) { '+P' } else { '' }))
        Add-Probe "I-$tag" "identity mode=[$mode $pv]" (("--NoLogo $mode $pv powershell -NoProfile -ExecutionPolicy Bypass -File `"$id1`"") -replace ' {2,}', ' ')
    }
}
Add-Probe 'I-SESS' 'session id of child equals caller session' "--NoLogo -TI powershell -NoProfile -Command `"(Get-Process -Id `$PID).SessionId`""
Add-Probe 'I-WHO-S' 'whoami as System' '--NoLogo -S whoami'
Add-Probe 'I-WHO-TI' 'whoami as TI' '--NoLogo -TI whoami'
Add-Probe 'I-WHO-ADM' 'whoami default' '--NoLogo whoami'

# ---------------------------------------------------------------- E: environment
$envCmd = "powershell -NoProfile -Command `"'PATH.head='+(`$env:PATH.Split(';')[0]); 'PATH.endsSemi='+`$env:PATH.EndsWith(';'); 'TEMP='+`$env:TEMP; 'USERNAME='+`$env:USERNAME; 'X='+`$env:XSUDO_X; 'SESSIONNAME='+`$env:SESSIONNAME`""
$saved = @{ PATH = $env:PATH; TEMP = $env:TEMP; USERNAME = $env:USERNAME; SESSIONNAME = $env:SESSIONNAME }
$env:PATH = 'C:\Windows\System32;C:\Windows;C:\Windows\System32\WindowsPowerShell\v1.0'
$env:TEMP = 'C:\FakeTemp'; $env:USERNAME = 'fakeuser'; $env:XSUDO_X = '1'; $env:SESSIONNAME = 'Fake'
foreach ($mode in @('', '-S', '-TI')) {
    $t = if ($mode) { $mode.TrimStart('-') } else { 'ADM' }
    Add-Probe "E-$t" "env: process-only var kept, TEMP/USERNAME/SESSIONNAME re-derived, caller PATH first [$mode]" (("--NoLogo $mode $envCmd") -replace ' {2,}', ' ')
}
$env:PATH = $saved.PATH; $env:TEMP = $saved.TEMP; $env:USERNAME = $saved.USERNAME
if ($null -eq $saved.SESSIONNAME) { Remove-Item Env:SESSIONNAME -ErrorAction SilentlyContinue } else { $env:SESSIONNAME = $saved.SESSIONNAME }
Remove-Item Env:XSUDO_X -ErrorAction SilentlyContinue

# E-OVR: caller profile-var overrides must resolve identically to MinSudo (must NOT differ)
$ovrCmd = "powershell -NoProfile -Command `"'TEMP='+`$env:TEMP; 'USERNAME='+`$env:USERNAME; 'USERPROFILE='+`$env:USERPROFILE; 'CUSTOM='+`$env:XSUDO_OVR`""
$ovrSaved = @{ TEMP = $env:TEMP; USERNAME = $env:USERNAME; USERPROFILE = $env:USERPROFILE }
$env:TEMP = 'C:\customtempzz'; $env:USERNAME = 'fakeuser'; $env:USERPROFILE = 'C:\fakeprofile'; $env:XSUDO_OVR = 'ovr123'
foreach ($mode in @('', '-S', '-TI')) {
    $t = if ($mode) { $mode.TrimStart('-') } else { 'ADM' }
    Add-Probe "E-OVR-$t" "caller TEMP/USERNAME/USERPROFILE overrides resolve like MinSudo, custom var kept [$mode]" (("--NoLogo $mode $ovrCmd") -replace ' {2,}', ' ')
}
$env:TEMP = $ovrSaved.TEMP; $env:USERNAME = $ovrSaved.USERNAME; $env:USERPROFILE = $ovrSaved.USERPROFILE
Remove-Item Env:XSUDO_OVR -ErrorAction SilentlyContinue

# ---------------------------------------------------------------- X: exit codes (EXPECTED to differ: MinSudo always returns 0 here)
foreach ($mode in @('', '-S', '-TI')) {
    $t = if ($mode) { $mode.TrimStart('-') } else { 'ADM' }
    foreach ($n in 0, 1, 5, 259, -1, 2147483647, 3010) {
        Add-Probe "X-$t-$n" "child exit $n in mode [$mode]" (("--NoLogo $mode cmd /c exit $n") -replace ' {2,}', ' ') -Diff exit
    }
}
Add-Probe 'X-PS42' 'powershell exit 42' '--NoLogo powershell -NoProfile -Command "exit 42"' -Diff exit
Add-Probe 'X-WAIT-ADM' 'waits for the child (ping -n 3 about 2s)' '--NoLogo ping -n 3 127.0.0.1' -NoOut -MinMs 1800 -MaxMs 6000
Add-Probe 'X-WAIT-S' 'waits for the child (-S)' '--NoLogo -S ping -n 3 127.0.0.1' -NoOut -MinMs 1800 -MaxMs 6000
Add-Probe 'X-WAIT-TI' 'waits for the child (-TI)' '--NoLogo -TI ping -n 3 127.0.0.1' -NoOut -MinMs 1800 -MaxMs 6000

# ---------------------------------------------------------------- C: console / IO
foreach ($mode in @('', '-S', '-TI')) {
    $t = if ($mode) { $mode.TrimStart('-') } else { 'ADM' }
    Add-Probe "C-$t" "child shares the caller's console and inherits std handles [$mode]" (("--NoLogo $mode powershell -NoProfile -File `"$con`"") -replace ' {2,}', ' ')
}
Add-Probe 'C-STDIN' 'stdin is passed through' '--NoLogo findstr h' -Stdin "hello${NL}world${NL}"
Add-Probe 'C-STDIN-TI' 'stdin is passed through (-TI)' '--NoLogo -TI findstr w' -Stdin "hello${NL}world${NL}"
Add-Probe 'C-SPLIT' 'child stdout and stderr stay on separate streams' '--NoLogo cmd /c "echo out& echo err 1>&2"'
Add-Probe 'C-SPLIT-TI' 'child stdout and stderr stay on separate streams (-TI)' '--NoLogo -TI cmd /c "echo out& echo err 1>&2"'
$redir = Join-Path $Work 'redir.txt'
Add-Probe 'C-REDIR' 'redirect inside the child command line' "--NoLogo -TI cmd /c echo hi > `"$redir`"" -NoOut
[void]$script:Text.AppendLine("redir.txt: " + $(if (Test-Path $redir) { (Get-Content $redir -Raw).Trim() } else { '<missing>' }))

# ---------------------------------------------------------------- A: command passing (verbatim)
$cases = @(
    @('A01', 'plain', "powershell -NoProfile -File `"$cl`" a b"),
    @('A02', 'internal extra spaces preserved', "powershell   -NoProfile    -File `"$cl`"   a    b"),
    @('A03', 'quotes, caret, ampersand inside quotes', "powershell -NoProfile -File `"$cl`" `"a b`" `"c^d`" `"e&f`" x"),
    @('A04', 'program quoted', "`"powershell`" -NoProfile -File `"$cl`" z"),
    @('A05', 'full path to exe', "`"$ps`" -NoProfile -File `"$cl`" z"),
    @('A06', 'program with .exe', "powershell.exe -NoProfile -File `"$cl`" z"),
    @('A07', 'child-looking options after command are not parsed', "powershell -NoProfile -File `"$cl`" -P --NoLogo -S -TI -WD=C:\Windows")
)
foreach ($c in $cases) {
    Add-Probe $c[0] ("verbatim cmdline: " + $c[1]) ("--NoLogo " + $c[2])
    Add-Probe ($c[0] + '-TI') ("verbatim cmdline (-TI -P): " + $c[1]) ("--NoLogo -TI -P " + $c[2])
}

# ---------------------------------------------------------------- R: program resolution and errors
Add-Probe 'R01' 'missing program (error, launch failure)' '--NoLogo bogus.exe' -Diff both
Add-Probe 'R02' 'missing program, verbose' '--NoLogo -V nosuchprog' -Diff both
Add-Probe 'R03' 'bare name resolves via PATH, .exe implied' '--NoLogo whoami'
Add-Probe 'R04' 'uppercase program' '--NoLogo WHOAMI'
Add-Probe 'R05' 'full path with spaces, quoted' "--NoLogo `"$SpaceDir\who ami.exe`""
Add-Probe 'R06' 'full path with spaces, quoted, no extension' "--NoLogo `"$SpaceDir\who ami`""
Add-Probe 'R07' 'cmd file by full path' "--NoLogo `"$SpaceDir\t.cmd`" a b"
Add-Probe 'R08' 'bat file by full path' "--NoLogo `"$SpaceDir\t.bat`" a"
Add-Probe 'R09' '.ps1 is not directly executable' "--NoLogo `"$SpaceDir\t.ps1`" a" -Diff both
Add-Probe 'R10' 'relative cmd name not on PATH' '--NoLogo t.cmd' -Diff both
Add-Probe 'R11' 'empty quoted program' '--NoLogo ""' -Diff both
Add-Probe 'R12' 'nonexistent directory in path' '--NoLogo "C:\NoDir\x.exe"' -Diff both
Add-Probe 'R13' 'a directory as program' "--NoLogo $Work" -Diff both
Add-Probe 'R14' 'relative name found via -WD does not resolve (search uses caller cwd)' "--NoLogo -WD=`"$SpaceDir`" t.cmd z" -Diff both

# ---------------------------------------------------------------- W: working directory
Add-Probe 'W01' 'default cwd is the caller cwd' '--NoLogo cmd /c cd' -Cwd $SpaceDir
Add-Probe 'W02' '-WD=path' '--NoLogo -WD=C:\Windows cmd /c cd'
Add-Probe 'W03' '/WD:path' '--NoLogo /WD:C:\Windows\System32 cmd /c cd'
Add-Probe 'W04' '--WorkDir=path' '--NoLogo --WorkDir=C:\Windows cmd /c cd'
Add-Probe 'W05' '--workdir:path lower case' '--NoLogo --workdir:C:\Windows cmd /c cd'
Add-Probe 'W06' '--WorkDir path (space, no separator): value is NOT consumed' '--NoLogo --WorkDir C:\Windows cmd /c cd' -Diff both
Add-Probe 'W07' 'nonexistent work dir' '--NoLogo --WorkDir=C:\NoSuchDirXYZ cmd /c cd' -Diff both
Add-Probe 'W08' 'empty --WorkDir= before a command' '--NoLogo --WorkDir= cmd /c cd' -Cwd $SpaceDir
Add-Probe 'W09' 'quoted work dir with space' '--NoLogo --WorkDir="C:\Program Files" cmd /c cd'
Add-Probe 'W10' 'quoted whole option with space' '--NoLogo "--WorkDir=C:\Program Files" cmd /c cd'
Add-Probe 'W11' 'unquoted space in work dir breaks the command' '--NoLogo --WorkDir=C:\Program Files cmd /c cd' -Diff both
Add-Probe 'W12' '-WD with no value before a command is ignored' '--NoLogo -WD cmd /c cd' -Cwd $SpaceDir
Add-Probe 'W13' '-WD in System mode' '--NoLogo -S -WD=C:\Windows cmd /c cd'
Add-Probe 'W14' '-WD in TI mode' '--NoLogo -TI -WD=C:\Windows cmd /c cd'

# ---------------------------------------------------------------- V: verbose and banner (wording is expected to differ)
Add-Probe 'V01' '-V output stream and shape (info lines on stdout)' '--NoLogo -V cmd /c echo out' -Diff text
Add-Probe 'V02' '-V with -S -P -WD' '--NoLogo -V -S -P -WD=C:\Windows cmd /c echo x' -Diff text
Add-Probe 'V03' '-V does not move child stderr' '--NoLogo -V cmd /c "echo e 1>&2"' -Diff text
Add-Probe 'V04' 'banner goes to stdout, not stderr' 'cmd /c echo a' -Diff text

# ---------------------------------------------------------------- S: TrustedInstaller service (observation only)
$before = (& sc.exe query TrustedInstaller | Out-String)
Add-Probe 'S01' 'TI run (service state recorded around it)' '--NoLogo -TI cmd /c echo ti' -Diff exit
$after = (& sc.exe query TrustedInstaller | Out-String)
[void]$script:Text.AppendLine("sc.before: " + ((($before -split "`n") | Where-Object { $_ -match 'STATE' }) -join ' ').Trim())
[void]$script:Text.AppendLine("sc.after:  " + ((($after -split "`n") | Where-Object { $_ -match 'STATE' }) -join ' ').Trim())

# ---------------------------------------------------------------- write results
$resFile = Join-Path $Out 'results.txt'
[IO.File]::WriteAllText($resFile, ($script:Text.ToString() -replace "`r`n", "`n"), [Text.UTF8Encoding]::new($false))
$script:Results | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $Out 'results.json') -Encoding utf8
$diffIds = ($script:Results | Where-Object expectedDiff | ForEach-Object { "$($_.id)=$($_.expectedDiff)" }) -join "`n"
[IO.File]::WriteAllText((Join-Path $Out 'expected-diff-ids.txt'), $diffIds + "`n", [Text.UTF8Encoding]::new($false))
Write-Host "Wrote $resFile ($($script:Results.Count) probes). Compare two runs with Compare-Object on results.txt."

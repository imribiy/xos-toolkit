<# Contains code from LeanAndMean, code modified to match with XOS Playbook needs.
Copyright (c) 2021 AveYo
Licensed under MIT License #>

$logDir = Join-Path $env:ProgramData 'AME\Logs'
if (!(Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
$logFile = Join-Path $logDir 'DefenderOFF.log'
function Log($msg) { $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'; "[$ts] [PID:$PID] $msg" | Out-File -FilePath $logFile -Append -Encoding utf8 }

Log '=== DefenderOFF.ps1 started ==='
$me = [Security.Principal.WindowsIdentity]::GetCurrent()
Log "Account: $(if ($me.User.Value -ne 'S-1-5-18') { 'interactive user' } elseif ($me.Groups.Value -contains 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464') { 'TrustedInstaller' } else { 'SYSTEM' })"
Log "PID: $PID"
Log "PSVersion: $($PSVersionTable.PSVersion)"
Log "WorkingDir: $(Get-Location)"
try {
 $os = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
 $product = [string]$os.ProductName
 if ([int]$os.CurrentBuildNumber -ge 22000) { $product = $product -replace '^Windows 10', 'Windows 11' }
 Log "Windows: $product $($os.DisplayVersion) build $($os.CurrentBuildNumber).$($os.UBR)"
} catch { Log "Windows version query FAILED: $($_.Exception.Message)" }

$op = "Disable"
$O1 = 0
$O2 = 1
$TOGGLE_SMARTSCREENFILTER = $O2
$id = "Defender"
$key = 'HKLM:'

try {
 $I=[int32]; $M=$I.module.gettype("System.Runtime.Interop`Services.Mar`shal"); $P=$I.module.gettype("System.Int`Ptr"); $S=[string]
 $D=@(); $DM=[AppDomain]::CurrentDomain."DefineDynami`cAssembly"(1,1)."DefineDynami`cModule"(1); $U=[uintptr]; $Z=[uintptr]::size
 0..5|% {$D += $DM."Defin`eType"("AveYo_$_",1179913,[ValueType])}; $D += $U; 4..6|% {$D += $D[$_]."MakeByR`efType"()}; $F=@()
 $F+='kernel','CreateProcess',($S,$S,$I,$I,$I,$I,$I,$S,$D[7],$D[8]), 'advapi','RegOpenKeyEx',($U,$S,$I,$I,$D[9])
 $F+='advapi','RegSetValueEx',($U,$S,$I,$I,[byte[]],$I),'advapi','RegFlushKey',($U),'advapi','RegCloseKey',($U)
 0..4|% {$9=$D[0]."DefinePInvok`eMethod"($F[3*$_+1], $F[3*$_]+"32", 8214,1,$S, $F[3*$_+2], 1,4)}
 $DF=($P,$I,$P),($I,$I,$I,$I,$P,$D[1]),($I,$S,$S,$S,$I,$I,$I,$I,$I,$I,$I,$I,[int16],[int16],$P,$P,$P,$P),($D[3],$P),($P,$P,$I,$I)
 1..5|% {$k=$_; $n=1; $DF[$_-1]|% {$9=$D[$k]."Defin`eField"("f" + $n++, $_, 6)}}; $T=@(); 0..5|% {$T += $D[$_]."Creat`eType"()}
 0..5|% {nv "A$_" ([Activator]::CreateInstance($T[$_])) -fo}; function F ($1,$2) {$T[0]."G`etMethod"($1).invoke(0,$2)}
 function M ($1,$2,$3) {$M."G`etMethod"($1,[type[]]$2).invoke(0,$3)}; $H=@(); $Z,(4*$Z+16)|% {$H += M "AllocHG`lobal" $I $_}
 Log 'P/Invoke setup OK'
} catch {
 Log "P/Invoke setup FAILED: $_"
}

try {
 if ([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18') {
   Log 'Not running as SYSTEM, creating TI process...'
    $TI="Trusted`Installer"; Start-Service -Name $TI -ErrorAction SilentlyContinue; $As=$null; for($wait=0; $wait -lt 20 -and $null -eq $As; $wait++){ $As=Get-Process -Name $TI -ErrorAction SilentlyContinue | Select-Object -First 1; if($null -eq $As){ Start-Sleep -Milliseconds 250 } }; if($null -eq $As){ throw 'TrustedInstaller process did not start' }
   M "WriteInt`Ptr" ($P,$P) ($H[0],$As.Handle); $A1.f1=131072; $A1.f2=$Z; $A1.f3=$H[0]; $A2.f1=1; $A2.f2=1; $A2.f3=1; $A2.f4=1
   $A2.f6=$A1; $A3.f1=10*$Z+32; $A3.f12=1; $A3.f13=0; $A4.f1=$A3; $A4.f2=$H[1]; M "StructureTo`Ptr" ($D[2],$P,[boolean]) (($A2 -as $D[2]),$A4.f2,$false)
   $R=@($null, "powershell -WindowStyle Hidden -NoLogo -NoProfile -NonInteractive -nop -c iex(`$env:R); # $id", 0, 0, 0, 0x0E080610, 0, $null, ($A4 -as $T[4]), ($A5 -as $T[5]))
   F 'CreateProcess' $R; Log 'TI process created, returning'; return
 }
 Log 'Running as SYSTEM, continuing inline'
 $env:R=''; rp $key $id -force -ea 0; $e=[diagnostics.process]."GetM`ember"('SetPrivilege',42)[0]
 Log "SetPrivilege method: $($e -ne $null)"
 'SeSecurityPrivilege','SeTakeOwnershipPrivilege','SeBackupPrivilege','SeRestorePrivilege' |% {
   try { $e.Invoke($null,@("$_",2)); Log "Privilege OK: $_" } catch { Log "Privilege FAILED: $_ - $($_.Exception.Message)" }
 }
} catch {
 Log "Privilege/TI section FAILED: $_"
}
function Invoke-NativeResult ($name, $arguments) {
  try { return [int](F $name $arguments) } catch { return -1 }
}
function RegSetDwords ($hive, $key, [array]$values, [array]$dword, $REG_TYPE=4, $REG_ACCESS=2, $REG_OPTION=0) {
  $rok = ($hive, $key, $REG_OPTION, $REG_ACCESS, ($hive -as $D[9]));
  $openResult = Invoke-NativeResult "RegOpenKeyEx" $rok;
  $rsv = $rok[4];
  $handle = if ($null -ne $rsv) { $rsv[0] } else { [IntPtr]::Zero };
  Log "RegOpenKeyEx '$key' rc=$openResult handle=$handle";
  $handleIsZero = $null -eq $handle
  if (-not $handleIsZero) {
    $handleIsZero = if ($handle -is [UIntPtr]) { $handle.ToUInt64() -eq 0 } else { $handle.ToInt64() -eq 0 }
  }
  if ($openResult -ne 0 -or $handleIsZero) { throw "RegOpenKeyEx failed for '$key' (code $openResult)" }
  try {
    $i = 0;
    foreach ($value in $values) {
      $setResult = Invoke-NativeResult "RegSetValueEx" ($handle, [string]$value, 0, $REG_TYPE, [byte[]]($dword[$i]), 4);
      if ($setResult -ne 0) { throw "RegSetValueEx failed for '$key\\$value' (code $setResult)" }
      $i++;
    }
    $flushResult = Invoke-NativeResult "RegFlushKey" @($rsv);
    if ($flushResult -ne 0) { throw "RegFlushKey failed for '$key' (code $flushResult)" }
  } finally {
    $closeResult = Invoke-NativeResult "RegCloseKey" @($rsv);
    if ($closeResult -ne 0) { Log "RegCloseKey failed for '$key' (code $closeResult)" }
    $rok = $null; $rsv = $null;
  }
}

 $toggle = @(0,1)[$op -eq "Disable"]; $toggle_rev = @(0,1)[$op -eq "Enable"]
 $ENABLE_TAMPER_PROTECTION = $O1; $TOGGLE_SMARTSCREENFILTER = $O2

 rnp "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" "Disabled" "Disabled_Old" -force -ea 0
 sp "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" "Disabled" 1 -type Dword -force -ea 0
 Log 'Stopping wscsvc (max 15 seconds)'
 try {
   $wsc = Get-Service -Name 'wscsvc' -ErrorAction Stop
   if ($wsc.Status -ne 'Stopped') {
     try { $wsc.Stop() } catch { Log "wscsvc stop request refused: $($_.Exception.Message)" }
     try { $wsc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(15)) } catch { }
     $wsc.Refresh()
   }
   Log "wscsvc status: $($wsc.Status)"
 } catch { Log "wscsvc not stopped: $($_.Exception.Message)" }
 kill -name "OFFmeansOFF","MpCmdRun" -force -ea 0

 $HKLM = [uintptr][uint32]2147483650; $HKU = [uintptr][uint32]2147483651
 $VALUES = "ServiceKeepAlive","PreviousRunningMode","IsServiceRunning","DisableAntiSpyware","DisableAntiVirus","PassiveMode"
 $DWORDS = 0, 0, 0, $toggle, $toggle, $toggle
 Log "RegSetDwords pass 1: Policies\Microsoft\Windows Defender"
 RegSetDwords $HKLM "SOFTWARE\Policies\Microsoft\Windows Defender" $VALUES $DWORDS
 Log "RegSetDwords pass 1: Microsoft\Windows Defender"
 RegSetDwords $HKLM "SOFTWARE\Microsoft\Windows Defender" $VALUES $DWORDS
 [GC]::Collect(); sleep 1

 $defDir = "$env:programfiles\Windows Defender"
 Log "Defender dir exists: $(Test-Path $defDir)"
 pushd $defDir -ea 0
 Log "Current dir after pushd: $(Get-Location)"

 if ($op -eq "Disable") {
   $dirs = @()
   if (Test-Path $defDir) { $dirs += $defDir }
   $svcImage = (gp "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" ImagePath -ea 0).ImagePath
   if ($svcImage) {
     $svcDir = split-path $svcImage.Trim('"') -ea 0
     if ($svcDir -and (Test-Path $svcDir) -and ($dirs -notcontains $svcDir)) { $dirs += $svcDir }
   }
   $platDir = Join-Path $env:ProgramData 'Microsoft\Windows Defender\Platform'
   if (Test-Path $platDir) {
     Get-ChildItem $platDir -Directory -ea 0 | ForEach-Object {
       if ($dirs -notcontains $_.FullName) { $dirs += $_.FullName }
     }
   }
   foreach ($dir in $dirs) {
     $off = Join-Path $dir 'OFFmeansOFF.exe'
     $on  = Join-Path $dir 'MpCmdRun.exe'
     try {
       $names = (Get-ChildItem -LiteralPath $dir -Filter '*.exe' -ea 0 |
                 Where-Object { $_.Name -match 'MpCmdRun|OFFmeansOFF' } |
                 ForEach-Object { $_.Name + '(' + $_.Length + ')' }) -join ', '
       Log "Listing ${dir}: $($names -replace '^$','none')"
     } catch { Log "Listing ${dir} failed: $($_.Exception.Message)" }
     Log "  Test-Path MpCmdRun=$(Test-Path $on); Test-Path OFFmeansOFF=$(Test-Path $off)"
     if ((Test-Path $off) -and -not (Test-Path $on)) {
       try { Rename-Item -LiteralPath $off -NewName 'MpCmdRun.exe' -Force -ErrorAction Stop
             Log "Restored MpCmdRun.exe in $dir" } catch { Log "Could not restore MpCmdRun.exe in $dir" }
     }
   }
 }

 $attempted = $false
 foreach ($candidate in @((Join-Path $defDir 'MpCmdRun.exe'), (Join-Path $defDir 'OFFmeansOFF.exe'))) {
   Log "Trying $candidate (Test-Path=$(Test-Path $candidate))"
   try {
     start -wait $candidate -args "-DisableService -HighPriority" -ea Stop
     Log "MpCmdRun completed: $candidate"
     $attempted = $true
     break
   } catch {
     Log "Could not run ${candidate}: $($_.Exception.Message)"
   }
 }
 if (-not $attempted) {
   $svcImage3 = (gp "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" ImagePath -ea 0).ImagePath
   if ($svcImage3) {
     $svcDir3 = split-path $svcImage3.Trim('"') -ea 0
     foreach ($name in @('MpCmdRun.exe','OFFmeansOFF.exe')) {
       $p = Join-Path $svcDir3 $name
       try { start -wait $p -args "-DisableService -HighPriority" -ea Stop
             Log "MpCmdRun completed from service dir: $p"; $attempted = $true; break
       } catch { Log "Service-dir attempt failed for ${p}: $($_.Exception.Message)" }
     }
   }
 }
 if (-not $attempted) { Log "DISABLE SERVICE NOT ATTEMPTED: no runnable MpCmdRun binary found" }
 $wait=@(3,14)[$op -eq "Disable"]
 Log "Waiting for MsMpEng to exit (max $wait seconds)"
 while ((get-process -name "MsMpEng" -ea 0) -and $wait -gt 0) {$wait--; sleep 1}
 $msmpenRunning = [bool](get-process -name "MsMpEng" -ea 0)
 Log "MsMpEng still running: $msmpenRunning"

 $svcImagePath = (gp "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" ImagePath -ea 0).ImagePath
 Log "WinDefend ImagePath: $svcImagePath"
if ($svcImagePath) {
  pushd (split-path $svcImagePath.Trim('"')) -ea 0
  Log "Platform dir: $(Get-Location)"
  if ($op -eq "Disable") {
    if (Test-Path -LiteralPath 'MpCmdRun.exe') {
      $renamed = $false
      for ($attempt = 1; $attempt -le 10 -and -not $renamed; $attempt++) {
        if (-not (Test-Path -LiteralPath 'MpCmdRun.exe') -or (Test-Path -LiteralPath 'OFFmeansOFF.exe')) { Log "MpCmdRun.exe rename stopped at attempt ${attempt}: MpCmdRun.exe present=$(Test-Path -LiteralPath 'MpCmdRun.exe'); OFFmeansOFF.exe present=$(Test-Path -LiteralPath 'OFFmeansOFF.exe')"; break }
        try { Rename-Item -LiteralPath 'MpCmdRun.exe' -NewName 'OFFmeansOFF.exe' -Force -ErrorAction Stop; $renamed = $true; Log "Renamed MpCmdRun.exe -> OFFmeansOFF.exe (attempt $attempt)" }
        catch {
          if ($attempt -eq 10) { Log "MpCmdRun.exe rename FAILED after $attempt attempts: $($_.Exception.Message)" }
          else { kill -name 'MpCmdRun' -force -ea 0; sleep 3 }
        }
      }
    } elseif (Test-Path -LiteralPath 'OFFmeansOFF.exe') {
      Log 'MpCmdRun.exe is already normalized as OFFmeansOFF.exe'
    } else {
      Log 'No MpCmdRun.exe or OFFmeansOFF.exe found in the Defender service directory'
    }
  } else {
    if (Test-Path -LiteralPath 'OFFmeansOFF.exe') {
      try { Rename-Item -LiteralPath 'OFFmeansOFF.exe' -NewName 'MpCmdRun.exe' -Force -ErrorAction Stop; Log 'Renamed OFFmeansOFF.exe -> MpCmdRun.exe' }
      catch { Log "OFFmeansOFF.exe restore FAILED: $($_.Exception.Message)" }
    } elseif (Test-Path -LiteralPath 'MpCmdRun.exe') {
      Log 'MpCmdRun.exe is already restored'
    } else {
      Log 'No OFFmeansOFF.exe or MpCmdRun.exe found in the Defender service directory'
    }
  }
} else {
   Log 'WinDefend ImagePath not found, skipping rename'
 }

 gi "Registry::HKU\S-1-5-21-*\Software\Microsoft\Windows\CurrentVersion" |% {
   $n1=join-path $_.PSPath "Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance"
   ni $n1 -force -ea 0|out-null; ri $n1.replace("Settings","Current") -recurse -force -ea 0
   if ($op -eq "Enable") {rp $n1 "Enabled" -force -ea 0} else {sp $n1 "Enabled" 0 -type Dword -force -ea 0}
   ri "HKLM:\Software\Microsoft\Windows Security Health\State\Persist" -recurse -force -ea 0
 }

 if ($op -eq "Disable") {del "$env:ProgramData\Microsoft\Windows Defender\Scans\mpenginedb.db" -force -ea 0}
 if ($op -eq "Disable") {del "$env:ProgramData\Microsoft\Windows Defender\Scans\History\Service" -recurse -force -ea 0}

 Log "RegSetDwords pass 2: Policies\Microsoft\Windows Defender"
 RegSetDwords $HKLM "SOFTWARE\Policies\Microsoft\Windows Defender" $VALUES $DWORDS
 Log "RegSetDwords pass 2: Microsoft\Windows Defender"
 RegSetDwords $HKLM "SOFTWARE\Microsoft\Windows Defender" $VALUES $DWORDS

 if ($TOGGLE_SMARTSCREENFILTER -ne 0) {
   sp "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy" 'VerifiedAndReputablePolicyState' 0 -type Dword -force -ea 0
   sp "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" 'SmartScreenEnabled' @('Off','Warn')[$toggle -eq 0] -force -ea 0
   gi Registry::HKEY_Users\S-1-5-21*\Software\Microsoft -ea 0 |% {
     sp "$($_.PSPath)\Windows\CurrentVersion\AppHost" 'EnableWebContentEvaluation' $toggle_rev -type Dword -force -ea 0
     sp "$($_.PSPath)\Windows\CurrentVersion\AppHost" 'PreventOverride' $toggle_rev -type Dword -force -ea 0
     ni "$($_.PSPath)\Edge\SmartScreenEnabled" -Force -ea 0 > $null
     sp "$($_.PSPath)\Edge\SmartScreenEnabled" "(Default)" $toggle_rev -ea 0
   }
   if ($toggle_rev -eq 0) {
     kill -name smartscreen -force -ea 0
     ren "$env:SystemRoot\System32\smartscreen.exe" 'smartscreen.old' -force -ea 0
     Log 'smartscreen.exe renamed to smartscreen.old'
   } else {
     $ssOld = "$env:SystemRoot\System32\smartscreen.old"
     if (Test-Path $ssOld) { ren $ssOld 'smartscreen.exe' -force -ea 0; Log 'smartscreen.old renamed back to smartscreen.exe' }
   }
   Log 'SmartScreen toggled'
 }

 if ($ENABLE_TAMPER_PROTECTION -ne 0 -and $op -eq "Enable") {
   RegSetDwords $HKLM "SOFTWARE\Microsoft\Windows Defender\Features" ("TamperProtection","TamperProtectionSource") (1,5)
 }

 if ($op -eq "Enable") {start-service "windefend" -ea 0}
 start-service "wscsvc" -ea 0 >$null 2>$null
 if ($op -eq "Enable") {rnp "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" "Disabled_Old" "Disabled" -force -ea 0}

Log '=== DefenderOFF.ps1 finished ==='

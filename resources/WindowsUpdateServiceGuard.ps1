param([Parameter(Mandatory=$true)][ValidateSet('Apply','Remove','CompleteRemove')][string]$Action,[Parameter(Mandatory=$true)][string]$Nonce,[Parameter(Mandatory=$true)][string]$ResultPath,[Parameter(Mandatory=$true)][long]$DeadlineUtcTicks,[string]$ExpectedJournalHash)
$ErrorActionPreference='Stop'
function AssertDeadline {
    $now=[DateTime]::UtcNow.Ticks
    if ($DeadlineUtcTicks -le $now -or $DeadlineUtcTicks -gt [DateTime]::MaxValue.Ticks -or $DeadlineUtcTicks -gt $now+[TimeSpan]::FromSeconds(300).Ticks) {throw 'Service guard worker deadline expired or invalid'}
}
AssertDeadline
$targets=@('wuauserv','BITS','DoSvc','UsoSvc','WaaSMedicSvc','uhssvc')
$journalPath='SOFTWARE\XOSToolkit\UpdateServiceGuard'
$access=[Security.AccessControl.AccessControlSections]::Access
$sid=[Security.Principal.SecurityIdentifier]'S-1-5-18'
$parsed=[Guid]::Empty
if (-not [Guid]::TryParseExact($Nonce,'N',[ref]$parsed) -or $parsed.ToString('N') -cne $Nonce -or [IO.Path]::GetFullPath($ResultPath) -cne [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "WindowsUpdateServiceGuard-$Nonce.result"))) {throw 'Invalid service guard result location'}
if ($Action -cne 'Apply' -and $ExpectedJournalHash -cnotmatch '^[a-f0-9]{64}$') {throw 'Invalid expected service guard journal hash'}
AssertDeadline
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
public static class XosServiceGuardWorkerV1
{
    private static readonly SecurityIdentifier Sid = new SecurityIdentifier("S-1-5-18");
    private static IntPtr Open(string name, uint rights, bool optional)
    {
        IntPtr manager = OpenSCManager(null, null, 1);
        if (manager == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            IntPtr service = OpenService(manager, name, rights);
            if (service != IntPtr.Zero) return service;
            int error = Marshal.GetLastWin32Error();
            if (optional && error == 1060) return IntPtr.Zero;
            throw new Win32Exception(error, name);
        }
        finally { CloseServiceHandle(manager); }
    }
    public static int StartType(string name)
    {
        IntPtr service = Open(name, 1, true);
        if (service == IntPtr.Zero) return -1;
        try
        {
            uint needed;
            bool sizing = QueryServiceConfig(service, IntPtr.Zero, 0, out needed);
            int error = Marshal.GetLastWin32Error();
            if (sizing || error != 122 || needed == 0 || needed > 8192) throw new Win32Exception(error);
            IntPtr buffer = Marshal.AllocHGlobal((int)needed);
            try
            {
                uint actual;
                if (!QueryServiceConfig(service, buffer, needed, out actual)) throw new Win32Exception(Marshal.GetLastWin32Error());
                return Marshal.ReadInt32(buffer, 4);
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        finally { CloseServiceHandle(service); }
    }
    public static string Read(string name)
    {
        string value = ReadIfPresent(name);
        if (value == null) throw new Win32Exception(1060, name);
        return value;
    }
    public static string ReadRegistryIfPresent(string name)
    {
        IntPtr key;
        int error = RegOpenKeyEx(new IntPtr(unchecked((int)0x80000002)), @"SYSTEM\CurrentControlSet\Services\" + name, 0, 0x20100, out key);
        if (error == 2 || error == 3) return null;
        if (error != 0) throw new Win32Exception(error, "Open service registry DACL " + name);
        using (var handle = new Microsoft.Win32.SafeHandles.SafeRegistryHandle(key, true))
        using (Microsoft.Win32.RegistryKey registry = Microsoft.Win32.RegistryKey.FromHandle(handle, Microsoft.Win32.RegistryView.Registry64))
            return registry.GetAccessControl(AccessControlSections.Access).GetSecurityDescriptorSddlForm(AccessControlSections.Access);
    }
    public static string ReadIfPresent(string name)
    {
        IntPtr service = Open(name, 0x20000, true);
        if (service == IntPtr.Zero) return null;
        try
        {
            uint needed;
            bool sizing = QueryServiceObjectSecurity(service, 4, null, 0, out needed);
            int error = Marshal.GetLastWin32Error();
            if (sizing || error != 122 || needed == 0 || needed > 65536) throw new Win32Exception(error);
            byte[] buffer = new byte[needed];
            uint actual;
            if (!QueryServiceObjectSecurity(service, 4, buffer, needed, out actual)) throw new Win32Exception(Marshal.GetLastWin32Error());
            return new RawSecurityDescriptor(buffer, 0).GetSddlForm(AccessControlSections.Access);
        }
        finally { CloseServiceHandle(service); }
    }
    public static void Write(string name, string sddl, long deadlineUtcTicks)
    {
        var raw = Parse(sddl);
        byte[] buffer = new byte[raw.BinaryLength];
        raw.GetBinaryForm(buffer, 0);
        IntPtr service = Open(name, 0x40000, false);
        try
        {
            if (DateTime.UtcNow.Ticks >= deadlineUtcTicks) throw new TimeoutException("Service guard worker deadline expired before native service DACL write");
            if (!SetServiceObjectSecurity(service, 4, buffer)) throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        finally { CloseServiceHandle(service); }
    }
    private static RawSecurityDescriptor Parse(string sddl)
    {
        var raw = new RawSecurityDescriptor(sddl);
        if (raw.Owner != null || raw.Group != null || raw.SystemAcl != null || raw.DiscretionaryAcl == null ||
            raw.GetSddlForm(AccessControlSections.Access) != sddl || !new CommonSecurityDescriptor(false, false, raw).IsDiscretionaryAclCanonical)
            throw new InvalidOperationException("Noncanonical or non-DACL security descriptor");
        return raw;
    }
    private static bool Overlaps(GenericAce ace, int mask)
    {
        var deny = ace as QualifiedAce;
        return deny != null && deny.AceQualifier == AceQualifier.AccessDenied && deny.SecurityIdentifier == Sid &&
            (deny.AccessMask & (mask | unchecked((int)0x50000000) | (mask == 0x12 ? 0x20000000 : 0))) != 0;
    }
    public static string Protect(string sddl, int mask)
    {
        var raw = Parse(sddl);
        foreach (GenericAce ace in raw.DiscretionaryAcl)
            if (Overlaps(ace, mask)) throw new InvalidOperationException("Existing overlapping SYSTEM deny is not owned");
        raw.DiscretionaryAcl.InsertAce(0, new CommonAce(AceFlags.None, AceQualifier.AccessDenied, mask, Sid, false, null));
        return raw.GetSddlForm(AccessControlSections.Access);
    }
    public static string Remove(string current, int mask)
    {
        var raw = Parse(current);
        int found = -1;
        for (int i = 0; i < raw.DiscretionaryAcl.Count; i++)
        {
            GenericAce item = raw.DiscretionaryAcl[i];
            if (!Overlaps(item, mask)) continue;
            var ace = item as CommonAce;
            if (found != -1 || ace == null || ace.AceFlags != AceFlags.None || ace.AccessMask != mask || ace.IsCallback || ace.OpaqueLength != 0)
                throw new InvalidOperationException("Edited, foreign or duplicate SYSTEM guard deny preserved");
            found = i;
        }
        if (found != -1) raw.DiscretionaryAcl.RemoveAce(found);
        return raw.GetSddlForm(AccessControlSections.Access);
    }
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode)] private static extern int RegOpenKeyEx(IntPtr key, string subkey, uint options, uint access, out IntPtr result);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] private static extern IntPtr OpenSCManager(string machine, string database, uint access);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] private static extern IntPtr OpenService(IntPtr manager, string name, uint access);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] private static extern bool QueryServiceConfig(IntPtr service, IntPtr buffer, uint size, out uint needed);
    [DllImport("advapi32.dll", SetLastError=true)] private static extern bool QueryServiceObjectSecurity(IntPtr service, uint information, byte[] buffer, uint size, out uint needed);
    [DllImport("advapi32.dll", SetLastError=true)] private static extern bool SetServiceObjectSecurity(IntPtr service, uint information, byte[] buffer);
    [DllImport("advapi32.dll")] private static extern bool CloseServiceHandle(IntPtr handle);
}
'@
AssertDeadline
function SameNames($left,$right) {return ([string]::Join('|',@($left | Sort-Object -CaseSensitive)) -ceq [string]::Join('|',@($right | Sort-Object -CaseSensitive)))}
function OpenServiceKey($name,$write) {
    $rights=[Security.AccessControl.RegistryRights]::ReadPermissions
    $mode=[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadSubTree
    if ($write) {$rights=$rights -bor [Security.AccessControl.RegistryRights]::ChangePermissions;$mode=[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree}
    $key=$base.OpenSubKey("SYSTEM\CurrentControlSet\Services\$name",$mode,$rights)
    if (-not $key) {throw "Service registry key missing: $name"}
    return $key
}
function ReadRegistryDacl($name) {
    $key=OpenServiceKey $name $false
    try {return $key.GetAccessControl($access).GetSecurityDescriptorSddlForm($access)} finally {$key.Dispose()}
}
function WriteRegistryDacl($name,$expected,$current) {
    $key=OpenServiceKey $name $true
    try {
        if ($key.GetAccessControl($access).GetSecurityDescriptorSddlForm($access) -cne $current) {throw "Registry DACL changed before write: $name"}
        $acl=New-Object Security.AccessControl.RegistrySecurity
        $acl.SetSecurityDescriptorSddlForm($expected,$access)
        AssertDeadline
        $key.SetAccessControl($acl)
    } finally {$key.Dispose()}
    if ((ReadRegistryDacl $name) -cne $expected) {throw "Registry DACL write readback failed: $name"}
}
function PresentDisabled {
    $present=@()
    foreach ($name in $targets) {
        $start=[XosServiceGuardWorkerV1]::StartType($name)
        if ($start -eq -1) {continue}
        $key=$base.OpenSubKey("SYSTEM\CurrentControlSet\Services\$name",[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadSubTree,[Security.AccessControl.RegistryRights]::QueryValues)
        if (-not $key) {throw "Service registry key missing: $name"}
        try {if ($start -ne 4 -or $key.GetValueKind('Start') -ne [Microsoft.Win32.RegistryValueKind]::DWord -or $key.GetValue('Start') -isnot [int] -or $key.GetValue('Start') -ne 4) {throw "Service must already be disabled: $name"}} finally {$key.Dispose()}
        $present+=$name
    }
    if ($present.Count -eq 0) {throw 'No update services present'}
    return $present
}
function ReadJournal {
    $key=$base.OpenSubKey($journalPath,$false)
    if (-not $key) {return $null}
    try {
        if ($key.GetSubKeyNames().Length -ne 0) {throw 'Foreign service guard journal subkeys'}
        $values=@($key.GetValueNames())
        if ($values.Length -eq 0) {return @{Targets=@();Records=@{}}}
        if (-not (SameNames $values @('State')) -or $key.GetValueKind('State') -ne [Microsoft.Win32.RegistryValueKind]::MultiString) {throw 'Malformed service guard state value'}
        return ParseState ([string[]]$key.GetValue('State'))
    } finally {$key.Dispose()}
}
function ParseState([string[]]$data) {
    if (-not $data -or $data.Length -lt 3 -or $data[0] -cne 'V2') {throw 'Malformed serialized service guard state'}
    foreach ($value in $data) {if ([string]::IsNullOrEmpty($value) -or $value.IndexOf([char]0) -ge 0) {throw 'Invalid serialized state string'}}
    $state=@{Targets=@();Records=@{}}
    $index=1
    while ($index -lt $data.Length) {
        $name=$data[$index++]
        if ($targets -cnotcontains $name -or $state.Targets -ccontains $name -or $index -ge $data.Length) {throw 'Invalid serialized service guard target'}
        $state.Targets+=,$name
        $status=$data[$index++]
        if ($status -ceq 'N') {continue}
        if ($status -cne 'R' -or $index+4 -gt $data.Length) {throw 'Incomplete serialized service guard record'}
        $item=@{}
        foreach ($field in @('ServiceOriginal','ServiceExpected','RegistryOriginal','RegistryExpected')) {$item[$field]=$data[$index++]}
        if ([XosServiceGuardWorkerV1]::Protect($item.ServiceOriginal,0x12) -cne $item.ServiceExpected -or [XosServiceGuardWorkerV1]::Protect($item.RegistryOriginal,0x10006) -cne $item.RegistryExpected) {throw "Invalid serialized ownership fingerprint: $name"}
        $state.Records[$name]=$item
    }
    if ([string]::Join('|',$state.Targets) -cne [string]::Join('|',@($targets | Where-Object {$state.Targets -ccontains $_}))) {throw 'Serialized target inventory is not canonical'}
    return $state
}
function SerializeState($state) {
    $fields=New-Object 'Collections.Generic.List[string]'
    $fields.Add('V2')
    foreach ($name in $state.Targets) {
        $fields.Add($name)
        if (-not $state.Records.ContainsKey($name)) {$fields.Add('N');continue}
        $fields.Add('R')
        foreach ($field in @('ServiceOriginal','ServiceExpected','RegistryOriginal','RegistryExpected')) {$fields.Add([string]$state.Records[$name][$field])}
    }
    return $fields.ToArray()
}
function JournalHash($state) {
    $algorithm=[Security.Cryptography.SHA256]::Create()
    try {return [BitConverter]::ToString($algorithm.ComputeHash([Text.Encoding]::UTF8.GetBytes([string]::Join([string][char]0,[string[]]@(SerializeState $state))))).Replace('-','').ToLowerInvariant()} finally {$algorithm.Dispose()}
}
function PublishState($state,$priorHash) {
    $data=[string[]]@(SerializeState $state)
    $validated=ParseState $data
    $root=$base.OpenSubKey($journalPath,$true)
    if (-not $root) {throw 'Service guard journal disappeared before publication'}
    try {
        $current=ReadJournal
        if (-not $current -or (JournalHash $current) -cne $priorHash) {throw 'Service guard journal changed before atomic publication'}
        AssertDeadline
        $root.SetValue('State',$data,[Microsoft.Win32.RegistryValueKind]::MultiString)
        AssertDeadline
        $root.Flush()
    } finally {$root.Dispose()}
    $saved=ReadJournal
    if (-not $saved -or (JournalHash $saved) -cne (JournalHash $validated)) {throw 'Atomic service guard state did not persist'}
}
function SaveRecord($name,$item,$priorHash) {
    $current=ReadJournal
    if (-not $current -or (JournalHash $current) -cne $priorHash -or $current.Targets -cnotcontains $name -or $current.Records.ContainsKey($name)) {throw "Refusing to overwrite changed or owned journal record: $name"}
    $current.Records[$name]=$item
    PublishState $current $priorHash
}
$mutex=New-Object Threading.Mutex($false,'Global\XOSToolkit.UpdateServiceGuard.V1')
$locked=$false
$base=$null
try {
    try {$locked=$mutex.WaitOne(30000)} catch [Threading.AbandonedMutexException] {$locked=$true}
    if (-not $locked) {throw 'Timed out waiting for service guard worker'}
    AssertDeadline
    $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
    $state=ReadJournal
    if ($Action -cne 'Apply' -and (-not $state -or (JournalHash $state) -cne $ExpectedJournalHash)) {throw 'Service guard journal differs from captured parent ownership'}
    if ($Action -ceq 'Apply') {
        $present=@(PresentDisabled)
        if (-not $state) {
            $existing=$base.OpenSubKey($journalPath,$false)
            if ($existing) {$existing.Dispose();throw 'Service guard journal appeared before creation'}
            AssertDeadline
            $root=$base.CreateSubKey($journalPath,$true)
            $root.Dispose()
            $state=ReadJournal
        }
        if ($state.Targets.Count -eq 0) {
            foreach ($name in $present) {[XosServiceGuardWorkerV1]::Protect([XosServiceGuardWorkerV1]::Read($name),0x12) | Out-Null;[XosServiceGuardWorkerV1]::Protect((ReadRegistryDacl $name),0x10006) | Out-Null}
            PublishState @{Targets=$present;Records=@{}} (JournalHash $state)
            $state=ReadJournal
        }
        if ([string]::Join('|',$state.Targets) -cne [string]::Join('|',$present)) {throw 'Guard inventory changed; cleanup required before apply'}
        foreach ($name in $state.Targets) {
            if (-not $state.Records.ContainsKey($name)) {
                $serviceOriginal=[XosServiceGuardWorkerV1]::Read($name)
                $registryOriginal=ReadRegistryDacl $name
                $item=@{ServiceOriginal=$serviceOriginal;ServiceExpected=[XosServiceGuardWorkerV1]::Protect($serviceOriginal,0x12);RegistryOriginal=$registryOriginal;RegistryExpected=[XosServiceGuardWorkerV1]::Protect($registryOriginal,0x10006)}
                SaveRecord $name $item (JournalHash $state)
                $state=ReadJournal
            }
            $item=$state.Records[$name]
            $serviceCurrent=[XosServiceGuardWorkerV1]::Read($name)
            $registryCurrent=ReadRegistryDacl $name
            if (($serviceCurrent -cne $item.ServiceOriginal -and $serviceCurrent -cne $item.ServiceExpected) -or ($registryCurrent -cne $item.RegistryOriginal -and $registryCurrent -cne $item.RegistryExpected)) {throw "Foreign DACL edit preserved: $name"}
            if ($serviceCurrent -ceq $item.ServiceOriginal) {
                if ([XosServiceGuardWorkerV1]::Read($name) -cne $serviceCurrent) {throw "Service DACL changed before write: $name"}
                AssertDeadline
                [XosServiceGuardWorkerV1]::Write($name,$item.ServiceExpected,$DeadlineUtcTicks)
                if ([XosServiceGuardWorkerV1]::Read($name) -cne $item.ServiceExpected) {throw "Service DACL write readback failed: $name"}
            }
            if ($registryCurrent -ceq $item.RegistryOriginal) {WriteRegistryDacl $name $item.RegistryExpected $registryCurrent}
        }
        $check=ReadJournal
        if ($check.Records.Count -ne $check.Targets.Count -or [string]::Join('|',@(PresentDisabled)) -cne [string]::Join('|',$check.Targets)) {throw 'Incomplete service guard apply'}
        foreach ($name in $check.Targets) {if ([XosServiceGuardWorkerV1]::Read($name) -cne $check.Records[$name].ServiceExpected -or (ReadRegistryDacl $name) -cne $check.Records[$name].RegistryExpected) {throw "Final guard mismatch: $name"}}
    } elseif ($state) {
        if ($Action -ceq 'Remove') {foreach ($name in $state.Targets) {
            if (-not $state.Records.ContainsKey($name)) {continue}
            $registryCurrent=[XosServiceGuardWorkerV1]::ReadRegistryIfPresent($name)
            $serviceCurrent=[XosServiceGuardWorkerV1]::ReadIfPresent($name)
            if ($null -ne $registryCurrent) {
                $registryRestored=[XosServiceGuardWorkerV1]::Remove($registryCurrent,0x10006)
                if ($registryRestored -cne $registryCurrent) {WriteRegistryDacl $name $registryRestored $registryCurrent}
            }
            if ($null -ne $serviceCurrent) {
                $serviceRestored=[XosServiceGuardWorkerV1]::Remove($serviceCurrent,0x12)
            }
            if ($null -ne $serviceCurrent -and $serviceRestored -cne $serviceCurrent) {
                if ([XosServiceGuardWorkerV1]::Read($name) -cne $serviceCurrent) {throw "Service DACL changed before cleanup: $name"}
                AssertDeadline
                [XosServiceGuardWorkerV1]::Write($name,$serviceRestored,$DeadlineUtcTicks)
                if ([XosServiceGuardWorkerV1]::Read($name) -cne $serviceRestored) {throw "Service cleanup readback failed: $name"}
            }
        }}
        foreach ($name in $targets) {
            $serviceCurrent=[XosServiceGuardWorkerV1]::ReadIfPresent($name)
            $registryCurrent=[XosServiceGuardWorkerV1]::ReadRegistryIfPresent($name)
            if (-not $state.Records.ContainsKey($name)) {
                if ($null -ne $serviceCurrent) {[XosServiceGuardWorkerV1]::Protect($serviceCurrent,0x12) | Out-Null}
                if ($null -ne $registryCurrent) {[XosServiceGuardWorkerV1]::Protect($registryCurrent,0x10006) | Out-Null}
                continue
            }
            if (($null -ne $serviceCurrent -and [XosServiceGuardWorkerV1]::Remove($serviceCurrent,0x12) -cne $serviceCurrent) -or ($null -ne $registryCurrent -and [XosServiceGuardWorkerV1]::Remove($registryCurrent,0x10006) -cne $registryCurrent)) {throw "Owned guard remains: $name"}
        }
        $fresh=ReadJournal
        if (-not $fresh -or (JournalHash $fresh) -cne $ExpectedJournalHash) {throw 'Journal changed during cleanup'}
        foreach ($name in $state.Records.Keys) {foreach ($field in @('ServiceOriginal','ServiceExpected','RegistryOriginal','RegistryExpected')) {if ($fresh.Records[$name][$field] -cne $state.Records[$name][$field]) {throw 'Journal record changed during cleanup'}}}
        if ($Action -ceq 'CompleteRemove') {
            AssertDeadline
            $base.DeleteSubKey($journalPath,$false)
            if (ReadJournal) {throw 'Service guard journal remains after cleanup'}
        }
    }
    AssertDeadline
    $stream=[IO.File]::Open($ResultPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {$bytes=[Text.Encoding]::UTF8.GetBytes("V1|$Nonce|$Action|OK");$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)} finally {$stream.Dispose()}
    exit 0
} catch {[Console]::Error.WriteLine($_.Exception.ToString());exit 1} finally {if ($base) {$base.Dispose()};if ($locked) {$mutex.ReleaseMutex()};$mutex.Dispose()}

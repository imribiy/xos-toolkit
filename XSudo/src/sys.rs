use core::ffi::c_void;
use core::ptr::null;
use core::ptr::null_mut;

use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::Foundation::LUID;
use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
use windows_sys::Win32::Security::AdjustTokenPrivileges;
use windows_sys::Win32::Security::DuplicateTokenEx;
use windows_sys::Win32::Security::GetTokenInformation;
use windows_sys::Win32::Security::ImpersonateLoggedOnUser;
use windows_sys::Win32::Security::LookupPrivilegeValueW;
use windows_sys::Win32::System::Threading::OpenThreadToken;
use windows_sys::Win32::Security::RevertToSelf;
use windows_sys::Win32::Security::SecurityImpersonation;
use windows_sys::Win32::Security::SetTokenInformation;
use windows_sys::Win32::Security::TokenElevation;
use windows_sys::Win32::Security::TokenPrimary;
use windows_sys::Win32::Security::TokenPrivileges;
use windows_sys::Win32::Security::TokenSessionId;
use windows_sys::Win32::Security::SE_PRIVILEGE_ENABLED;
use windows_sys::Win32::Security::TOKEN_ADJUST_PRIVILEGES;
use windows_sys::Win32::Security::TOKEN_ALL_ACCESS;
use windows_sys::Win32::Security::TOKEN_DUPLICATE;
use windows_sys::Win32::Security::TOKEN_ELEVATION;
use windows_sys::Win32::Security::TOKEN_PRIVILEGES;
use windows_sys::Win32::Security::TOKEN_QUERY;
use windows_sys::Win32::System::Diagnostics::ToolHelp::CreateToolhelp32Snapshot;
use windows_sys::Win32::System::Diagnostics::ToolHelp::Process32FirstW;
use windows_sys::Win32::System::Diagnostics::ToolHelp::Process32NextW;
use windows_sys::Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32W;
use windows_sys::Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPPROCESS;
use windows_sys::Win32::System::Environment::CreateEnvironmentBlock;
use windows_sys::Win32::System::Environment::DestroyEnvironmentBlock;
use windows_sys::Win32::System::Services::OpenSCManagerW;
use windows_sys::Win32::System::Services::OpenServiceW;
use windows_sys::Win32::System::Services::QueryServiceStatusEx;
use windows_sys::Win32::System::Services::StartServiceW;
use windows_sys::Win32::System::Services::SC_HANDLE;
use windows_sys::Win32::System::Services::SC_MANAGER_CONNECT;
use windows_sys::Win32::System::Services::SC_STATUS_PROCESS_INFO;
use windows_sys::Win32::System::Services::SERVICE_QUERY_STATUS;
use windows_sys::Win32::System::Services::SERVICE_RUNNING;
use windows_sys::Win32::System::Services::SERVICE_START;
use windows_sys::Win32::System::Services::SERVICE_STATUS_PROCESS;
use windows_sys::Win32::System::Services::SERVICE_STOP_PENDING;
use windows_sys::Win32::System::Threading::CreateProcessAsUserW;
use windows_sys::Win32::System::Threading::CreateProcessW;
use windows_sys::Win32::System::Threading::GetCurrentProcess;
use windows_sys::Win32::System::Threading::GetCurrentThread;
use windows_sys::Win32::System::Threading::GetExitCodeProcess;
use windows_sys::Win32::System::Threading::OpenProcess;
use windows_sys::Win32::System::Threading::OpenProcessToken;
use windows_sys::Win32::System::Threading::WaitForSingleObject;
use windows_sys::Win32::System::Threading::CREATE_UNICODE_ENVIRONMENT;
use windows_sys::Win32::System::Threading::INFINITE;
use windows_sys::Win32::System::Threading::PROCESS_INFORMATION;
use windows_sys::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION;
use windows_sys::Win32::System::Threading::STARTF_USESTDHANDLES;
use windows_sys::Win32::System::Threading::STARTUPINFOW;
use windows_sys::Win32::System::Console::GetStdHandle;
use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;
use windows_sys::Win32::System::Console::SetStdHandle;
use windows_sys::Win32::System::Console::STD_ERROR_HANDLE;
use windows_sys::Win32::System::Console::STD_INPUT_HANDLE;
use windows_sys::Win32::System::Console::STD_OUTPUT_HANDLE;
use windows_sys::Win32::Foundation::DuplicateHandle;
use windows_sys::Win32::Foundation::DUPLICATE_SAME_ACCESS;
use windows_sys::Win32::Foundation::ERROR_SERVICE_DISABLED;
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::TokenUser;
use windows_sys::Win32::System::Threading::GetCurrentProcessId;
use windows_sys::Win32::System::Threading::PROCESS_DUP_HANDLE;
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows_sys::Win32::Foundation::GENERIC_READ;
use windows_sys::Win32::Foundation::GENERIC_WRITE;
use windows_sys::Win32::Storage::FileSystem::CreateFileW;
use windows_sys::Win32::Storage::FileSystem::GetFileType;
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_NORMAL;
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE;
use windows_sys::Win32::Storage::FileSystem::FILE_TYPE_CHAR;
use windows_sys::Win32::Storage::FileSystem::OPEN_EXISTING;
use windows_sys::Win32::System::Console::AttachConsole;
use windows_sys::Win32::System::Console::FreeConsole;
use windows_sys::Win32::System::Console::GetConsoleMode;
use windows_sys::Win32::System::Environment::FreeEnvironmentStringsW;
use windows_sys::Win32::System::Environment::GetCurrentDirectoryW;
use windows_sys::Win32::System::Environment::GetEnvironmentStringsW;
use windows_sys::Win32::System::Environment::SetEnvironmentVariableW;
use windows_sys::Win32::System::Memory::CreateFileMappingW;
use windows_sys::Win32::System::Memory::MapViewOfFile;
use windows_sys::Win32::System::Memory::OpenFileMappingW;
use windows_sys::Win32::System::Memory::UnmapViewOfFile;
use windows_sys::Win32::System::Memory::FILE_MAP_READ;
use windows_sys::Win32::System::Memory::FILE_MAP_WRITE;
use windows_sys::Win32::System::Memory::PAGE_READWRITE;

pub struct Handle(pub HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

pub struct ScHandle(pub SC_HANDLE);

impl Drop for ScHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                windows_sys::Win32::System::Services::CloseServiceHandle(self.0);
            }
        }
    }
}

pub struct EnvBlock(pub *mut c_void);

impl Drop for EnvBlock {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                DestroyEnvironmentBlock(self.0);
            }
        }
    }
}

pub struct Impersonation;

impl Drop for Impersonation {
    fn drop(&mut self) {
        unsafe {
            RevertToSelf();
        }
    }
}

pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(core::iter::once(0)).collect()
}

pub fn last_error() -> u32 {
    unsafe { GetLastError() }
}

pub fn get_command_line() -> Vec<u16> {
    unsafe {
        let p = windows_sys::Win32::System::Environment::GetCommandLineW();
        let mut len = 0usize;
        while *p.add(len) != 0 {
            len += 1;
        }
        core::slice::from_raw_parts(p, len).to_vec()
    }
}

pub fn is_elevated() -> bool {
    unsafe {
        let mut token: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let token = Handle(token);
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut ret = 0u32;
        let ok = GetTokenInformation(
            token.0,
            TokenElevation,
            &mut elevation as *mut _ as *mut c_void,
            core::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret,
        );
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

pub fn caller_token_query() -> Option<Handle> {
    unsafe {
        let mut token: HANDLE = null_mut();
        let access = TOKEN_QUERY | TOKEN_DUPLICATE;
        if OpenProcessToken(GetCurrentProcess(), access, &mut token) == 0 {
            return None;
        }
        Some(Handle(token))
    }
}

pub fn caller_session_id() -> u32 {
    unsafe {
        let mut token: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return 0;
        }
        let token = Handle(token);
        let mut session = 0u32;
        let mut ret = 0u32;
        GetTokenInformation(
            token.0,
            TokenSessionId,
            &mut session as *mut _ as *mut c_void,
            4,
            &mut ret,
        );
        session
    }
}

pub fn find_all_process_ids(exe_name_lower: &str) -> Vec<u32> {
    unsafe {
        let mut ids = Vec::new();
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return ids;
        }
        let snap = Handle(snap);
        let mut entry: PROCESSENTRY32W = core::mem::zeroed();
        entry.dwSize = core::mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snap.0, &mut entry) != 0 {
            loop {
                let mut n = 0usize;
                while n < entry.szExeFile.len() && entry.szExeFile[n] != 0 {
                    n += 1;
                }
                let name = String::from_utf16_lossy(&entry.szExeFile[..n]).to_ascii_lowercase();
                if name == exe_name_lower {
                    ids.push(entry.th32ProcessID);
                }
                if Process32NextW(snap.0, &mut entry) == 0 {
                    break;
                }
            }
        }
        ids
    }
}

pub fn token_privilege_count(token: HANDLE) -> u32 {
    unsafe {
        let mut needed = 0u32;
        GetTokenInformation(token, TokenPrivileges, null_mut(), 0, &mut needed);
        if needed < 4 {
            return 0;
        }
        let mut buf = vec![0u8; needed as usize];
        if GetTokenInformation(
            token,
            TokenPrivileges,
            buf.as_mut_ptr() as *mut c_void,
            needed,
            &mut needed,
        ) == 0
        {
            return 0;
        }
        u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]])
    }
}

pub fn open_source_token(pid: u32) -> Option<Handle> {
    unsafe {
        let proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if proc.is_null() {
            return None;
        }
        let proc = Handle(proc);
        let mut token: HANDLE = null_mut();
        let access = TOKEN_DUPLICATE | TOKEN_QUERY;
        if OpenProcessToken(proc.0, access, &mut token) == 0 {
            return None;
        }
        let token = Handle(token);
        if !token_user_is_system(token.0) {
            return None;
        }
        Some(token)
    }
}

pub fn token_user_is_system(token: HANDLE) -> bool {
    unsafe {
        let mut needed = 0u32;
        GetTokenInformation(token, TokenUser, null_mut(), 0, &mut needed);
        if needed == 0 {
            return false;
        }
        let mut buf = vec![0u8; needed as usize];
        if GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr() as *mut c_void,
            needed,
            &mut needed,
        ) == 0
        {
            return false;
        }
        let sid = *(buf.as_ptr() as *const *mut c_void);
        if sid.is_null() {
            return false;
        }
        let mut str_ptr: *mut u16 = null_mut();
        if ConvertSidToStringSidW(sid, &mut str_ptr) == 0 {
            return false;
        }
        let mut len = 0usize;
        while *str_ptr.add(len) != 0 {
            len += 1;
        }
        let s = String::from_utf16_lossy(core::slice::from_raw_parts(str_ptr, len));
        windows_sys::Win32::Foundation::LocalFree(str_ptr as *mut c_void);
        s == "S-1-5-18"
    }
}

pub fn duplicate_primary(src: HANDLE) -> Option<Handle> {
    unsafe {
        let mut dup: HANDLE = null_mut();
        let access = TOKEN_ALL_ACCESS;
        if DuplicateTokenEx(
            src,
            access,
            null(),
            SecurityImpersonation,
            TokenPrimary,
            &mut dup,
        ) == 0
        {
            return None;
        }
        Some(Handle(dup))
    }
}

pub fn impersonate(token: HANDLE) -> Option<Impersonation> {
    unsafe {
        if ImpersonateLoggedOnUser(token) == 0 {
            None
        } else {
            Some(Impersonation)
        }
    }
}

pub fn set_session(token: HANDLE, session: u32) -> bool {
    unsafe {
        let mut value = session;
        SetTokenInformation(
            token,
            TokenSessionId,
            &mut value as *mut _ as *const c_void,
            4,
        ) != 0
    }
}

pub fn enable_all_privileges(token: HANDLE) -> bool {
    unsafe {
        let mut needed = 0u32;
        GetTokenInformation(token, TokenPrivileges, null_mut(), 0, &mut needed);
        if needed == 0 {
            return false;
        }
        let mut buf = vec![0u8; needed as usize];
        if GetTokenInformation(
            token,
            TokenPrivileges,
            buf.as_mut_ptr() as *mut c_void,
            needed,
            &mut needed,
        ) == 0
        {
            return false;
        }
        let count = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        let entry_size = core::mem::size_of::<LUID>() + 4;
        for i in 0..count {
            let attr_off = 4 + i * entry_size + core::mem::size_of::<LUID>();
            buf[attr_off..attr_off + 4].copy_from_slice(&SE_PRIVILEGE_ENABLED.to_ne_bytes());
        }
        AdjustTokenPrivileges(
            token,
            0,
            buf.as_ptr() as *const TOKEN_PRIVILEGES,
            needed,
            null_mut(),
            null_mut(),
        ) != 0
    }
}

fn enable_named(token: HANDLE, name: &str) -> bool {
    unsafe {
        let wname = wide(name);
        let mut luid = LUID {
            LowPart: 0,
            HighPart: 0,
        };
        if LookupPrivilegeValueW(null(), wname.as_ptr(), &mut luid) == 0 {
            return false;
        }
        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [windows_sys::Win32::Security::LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        AdjustTokenPrivileges(token, 0, &tp, 0, null_mut(), null_mut()) != 0
            && last_error() == 0
    }
}

pub fn enable_privilege(name: &str) -> bool {
    unsafe {
        let mut token: HANDLE = null_mut();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        ) == 0
        {
            return false;
        }
        let token = Handle(token);
        enable_named(token.0, name)
    }
}

pub fn enable_thread_privileges_for_launch() -> bool {
    unsafe {
        let mut token: HANDLE = null_mut();
        if OpenThreadToken(
            GetCurrentThread(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            0,
            &mut token,
        ) == 0
        {
            return false;
        }
        let token = Handle(token);
        let a = enable_named(token.0, "SeAssignPrimaryTokenPrivilege");
        let b = enable_named(token.0, "SeIncreaseQuotaPrivilege");
        enable_named(token.0, "SeDebugPrivilege");
        enable_named(token.0, "SeTcbPrivilege");
        enable_named(token.0, "SeImpersonatePrivilege");
        a && b
    }
}

pub fn make_env_block(token: HANDLE) -> Option<EnvBlock> {
    unsafe {
        let mut env: *mut c_void = null_mut();
        if CreateEnvironmentBlock(&mut env, token, 1) == 0 {
            return None;
        }
        Some(EnvBlock(env))
    }
}

fn std_handles() -> (HANDLE, HANDLE, HANDLE) {
    unsafe {
        (
            GetStdHandle(STD_INPUT_HANDLE),
            GetStdHandle(STD_OUTPUT_HANDLE),
            GetStdHandle(STD_ERROR_HANDLE),
        )
    }
}

fn startupinfo() -> STARTUPINFOW {
    let (si, so, se) = std_handles();
    let mut info: STARTUPINFOW = unsafe { core::mem::zeroed() };
    info.cb = core::mem::size_of::<STARTUPINFOW>() as u32;
    info.dwFlags = STARTF_USESTDHANDLES;
    info.hStdInput = si;
    info.hStdOutput = so;
    info.hStdError = se;
    info
}

pub struct Launched {
    pub process: Handle,
}

pub fn spawn_plain(
    cmdline: &mut [u16],
    workdir: Option<&[u16]>,
    env: *const c_void,
) -> Result<Launched, u32> {
    unsafe {
        let si = startupinfo();
        let mut pi: PROCESS_INFORMATION = core::mem::zeroed();
        let cwd = workdir.map(|w| w.as_ptr()).unwrap_or(null());
        let ok = CreateProcessW(
            null(),
            cmdline.as_mut_ptr(),
            null(),
            null(),
            1,
            CREATE_UNICODE_ENVIRONMENT,
            env,
            cwd,
            &si,
            &mut pi,
        );
        if ok == 0 {
            return Err(last_error());
        }
        let _thread = Handle(pi.hThread);
        Ok(Launched {
            process: Handle(pi.hProcess),
        })
    }
}

pub fn spawn_as_user(
    token: HANDLE,
    cmdline: &mut [u16],
    workdir: Option<&[u16]>,
    env: *const c_void,
) -> Result<Launched, u32> {
    unsafe {
        let mut si = startupinfo();
        let mut desktop = wide("winsta0\\default");
        si.lpDesktop = desktop.as_mut_ptr();
        let mut pi: PROCESS_INFORMATION = core::mem::zeroed();
        let cwd = workdir.map(|w| w.as_ptr()).unwrap_or(null());
        let ok = CreateProcessAsUserW(
            token,
            null(),
            cmdline.as_mut_ptr(),
            null(),
            null(),
            1,
            CREATE_UNICODE_ENVIRONMENT,
            env,
            cwd,
            &si,
            &mut pi,
        );
        if ok == 0 {
            return Err(last_error());
        }
        let _thread = Handle(pi.hThread);
        Ok(Launched {
            process: Handle(pi.hProcess),
        })
    }
}

pub fn wait_for_exit(process: HANDLE) -> Option<u32> {
    unsafe {
        if WaitForSingleObject(process, INFINITE) != WAIT_OBJECT_0 {
            return None;
        }
        let mut code = 0u32;
        if GetExitCodeProcess(process, &mut code) == 0 {
            return None;
        }
        Some(code)
    }
}

fn query_ti_status(svc: SC_HANDLE) -> Option<SERVICE_STATUS_PROCESS> {
    unsafe {
        let mut status: SERVICE_STATUS_PROCESS = core::mem::zeroed();
        let mut needed = 0u32;
        if QueryServiceStatusEx(
            svc,
            SC_STATUS_PROCESS_INFO,
            &mut status as *mut _ as *mut u8,
            core::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut needed,
        ) == 0
        {
            None
        } else {
            Some(status)
        }
    }
}

pub fn ensure_trustedinstaller_running() -> Result<u32, u32> {
    unsafe {
        let scm = OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT);
        if scm.is_null() {
            return Err(crate::exitcode::ERR_IDENTITY);
        }
        let scm = ScHandle(scm);
        let name = wide("TrustedInstaller");
        let svc = OpenServiceW(scm.0, name.as_ptr(), SERVICE_QUERY_STATUS | SERVICE_START);
        if svc.is_null() {
            return Err(crate::exitcode::ERR_IDENTITY);
        }
        let svc = ScHandle(svc);

        let mut tries = 0;
        loop {
            let status = query_ti_status(svc.0).ok_or(crate::exitcode::ERR_IDENTITY)?;
            match status.dwCurrentState {
                SERVICE_RUNNING => return Ok(status.dwProcessId),
                SERVICE_STOP_PENDING => {
                    sleep_ms(100);
                }
                _ => {
                    if StartServiceW(svc.0, 0, null()) == 0
                        && last_error() == ERROR_SERVICE_DISABLED
                    {
                        return Err(crate::exitcode::ERR_IDENTITY);
                    }
                    sleep_ms(100);
                }
            }
            tries += 1;
            if tries > 200 {
                return Err(crate::exitcode::ERR_IDENTITY);
            }
        }
    }
}

pub fn install_passthrough_ctrl_handler() {
    unsafe {
        SetConsoleCtrlHandler(None, 1);
    }
}

pub fn current_process_id() -> u32 {
    unsafe { GetCurrentProcessId() }
}

pub fn system_shell_cmdline() -> Vec<u16> {
    unsafe {
        let mut buf = vec![0u16; 260];
        let n = GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32);
        let dir = if n == 0 || n as usize >= buf.len() {
            String::from("C:\\Windows\\System32")
        } else {
            String::from_utf16_lossy(&buf[..n as usize])
        };
        wide(&format!("{dir}\\cmd.exe"))
    }
}

pub fn sleep_ms(ms: u32) {
    unsafe {
        windows_sys::Win32::System::Threading::Sleep(ms);
    }
}

pub fn get_std_triple() -> (HANDLE, HANDLE, HANDLE) {
    std_handles()
}

pub fn is_console_handle(h: HANDLE) -> bool {
    unsafe {
        if h.is_null() || h == INVALID_HANDLE_VALUE {
            return false;
        }
        if GetFileType(h) != FILE_TYPE_CHAR {
            return false;
        }
        let mut mode = 0u32;
        GetConsoleMode(h, &mut mode) != 0
    }
}

pub fn current_directory() -> Vec<u16> {
    unsafe {
        let len = GetCurrentDirectoryW(0, null_mut());
        if len == 0 {
            return wide("");
        }
        let mut buf = vec![0u16; len as usize];
        let n = GetCurrentDirectoryW(len, buf.as_mut_ptr());
        buf.truncate(n as usize);
        buf.push(0);
        buf
    }
}

pub fn parent_process_id() -> Option<u32> {
    unsafe {
        let me = GetCurrentProcessId();
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return None;
        }
        let snap = Handle(snap);
        let mut entry: PROCESSENTRY32W = core::mem::zeroed();
        entry.dwSize = core::mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snap.0, &mut entry) != 0 {
            loop {
                if entry.th32ProcessID == me {
                    return Some(entry.th32ParentProcessID);
                }
                if Process32NextW(snap.0, &mut entry) == 0 {
                    break;
                }
            }
        }
        None
    }
}

pub fn open_for_dup(pid: u32) -> Option<Handle> {
    unsafe {
        let h = OpenProcess(PROCESS_DUP_HANDLE, 0, pid);
        if h.is_null() {
            None
        } else {
            Some(Handle(h))
        }
    }
}

pub fn dup_from(parent: HANDLE, value: usize) -> Option<HANDLE> {
    unsafe {
        let mut out: HANDLE = null_mut();
        if DuplicateHandle(
            parent,
            value as HANDLE,
            GetCurrentProcess(),
            &mut out,
            0,
            1,
            DUPLICATE_SAME_ACCESS,
        ) == 0
        {
            None
        } else {
            Some(out)
        }
    }
}

pub fn set_std_input(h: HANDLE) {
    unsafe {
        SetStdHandle(STD_INPUT_HANDLE, h);
    }
}

pub fn set_std_output(h: HANDLE) {
    unsafe {
        SetStdHandle(STD_OUTPUT_HANDLE, h);
    }
}

pub fn set_std_error(h: HANDLE) {
    unsafe {
        SetStdHandle(STD_ERROR_HANDLE, h);
    }
}

pub fn reattach_to_console(pid: u32) {
    unsafe {
        FreeConsole();
        AttachConsole(pid);
    }
}

pub fn console_input_handle() -> HANDLE {
    open_console("CONIN$")
}

pub fn console_output_handle() -> HANDLE {
    open_console("CONOUT$")
}

fn open_console(name: &str) -> HANDLE {
    unsafe {
        let w = wide(name);
        CreateFileW(
            w.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        )
    }
}

pub fn create_env_mapping(name: &str) -> Option<Handle> {
    unsafe {
        let env = GetEnvironmentStringsW();
        if env.is_null() {
            return None;
        }
        let mut len = 0usize;
        loop {
            if *env.add(len) == 0 && *env.add(len + 1) == 0 {
                break;
            }
            len += 1;
        }
        len += 2;
        let bytes = len * 2;
        let wname = wide(name);
        let map = CreateFileMappingW(
            INVALID_HANDLE_VALUE,
            null(),
            PAGE_READWRITE,
            0,
            bytes as u32,
            wname.as_ptr(),
        );
        if map.is_null() {
            FreeEnvironmentStringsW(env);
            return None;
        }
        let view = MapViewOfFile(map, FILE_MAP_WRITE, 0, 0, bytes);
        if view.Value.is_null() {
            CloseHandle(map);
            FreeEnvironmentStringsW(env);
            return None;
        }
        core::ptr::copy_nonoverlapping(env as *const u8, view.Value as *mut u8, bytes);
        UnmapViewOfFile(view);
        FreeEnvironmentStringsW(env);
        Some(Handle(map))
    }
}

pub fn apply_env_from_mapping(name: &str) -> bool {
    unsafe {
        let wname = wide(name);
        let map = OpenFileMappingW(FILE_MAP_READ, 0, wname.as_ptr());
        if map.is_null() {
            return false;
        }
        let map = Handle(map);
        let view = MapViewOfFile(map.0, FILE_MAP_READ, 0, 0, 0);
        if view.Value.is_null() {
            return false;
        }
        let base = view.Value as *const u16;
        let mut i = 0usize;
        loop {
            if *base.add(i) == 0 {
                break;
            }
            let mut j = i;
            while *base.add(j) != 0 {
                j += 1;
            }
            let entry = String::from_utf16_lossy(core::slice::from_raw_parts(base.add(i), j - i));
            if let Some(eq) = entry.find('=') {
                if eq > 0 {
                    let k = wide(&entry[..eq]);
                    let v = wide(&entry[eq + 1..]);
                    SetEnvironmentVariableW(k.as_ptr(), v.as_ptr());
                }
            }
            i = j + 1;
        }
        UnmapViewOfFile(view);
        true
    }
}

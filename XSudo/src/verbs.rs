use core::ffi::c_void;
use core::ptr::null;
use core::ptr::null_mut;

use windows_sys::Win32::Foundation::BOOL;
use windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND;
use windows_sys::Win32::Foundation::ERROR_NO_TOKEN;
use windows_sys::Win32::Foundation::ERROR_PATH_NOT_FOUND;
use windows_sys::Win32::Foundation::ERROR_TIMEOUT;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::Foundation::LPARAM;
use windows_sys::Win32::Foundation::SetHandleInformation;
use windows_sys::Win32::Foundation::HANDLE_FLAG_INHERIT;
use windows_sys::Win32::Foundation::WAIT_ABANDONED;
use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
use windows_sys::Win32::Globalization::MultiByteToWideChar;
use windows_sys::Win32::Globalization::CP_OEMCP;
use windows_sys::Win32::Security::ImpersonateLoggedOnUser;
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Security::TOKEN_IMPERSONATE;
use windows_sys::Win32::Security::TOKEN_QUERY;
use windows_sys::Win32::Storage::FileSystem::GetFileAttributesW;
use windows_sys::Win32::Storage::FileSystem::ReadFile;
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_DIRECTORY;
use windows_sys::Win32::Storage::FileSystem::INVALID_FILE_ATTRIBUTES;
use windows_sys::Win32::System::Console::FreeConsole;
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Registry::HKEY_LOCAL_MACHINE;
use windows_sys::Win32::System::Registry::HKEY_USERS;
use windows_sys::Win32::System::Threading::CreateMutexW;
use windows_sys::Win32::System::Threading::CreateProcessAsUserW;
use windows_sys::Win32::System::Threading::GetCurrentThread;
use windows_sys::Win32::System::Threading::GetExitCodeProcess;
use windows_sys::Win32::System::Threading::OpenProcess;
use windows_sys::Win32::System::Threading::OpenProcessToken;
use windows_sys::Win32::System::Threading::OpenThreadToken;
use windows_sys::Win32::System::Threading::ReleaseMutex;
use windows_sys::Win32::System::Threading::SetThreadToken;
use windows_sys::Win32::System::Threading::WaitForSingleObject;
use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;
use windows_sys::Win32::System::Threading::CREATE_UNICODE_ENVIRONMENT;
use windows_sys::Win32::System::Threading::PROCESS_INFORMATION;
use windows_sys::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION;
use windows_sys::Win32::System::Threading::STARTF_USESHOWWINDOW;
use windows_sys::Win32::System::Threading::STARTF_USESTDHANDLES;
use windows_sys::Win32::System::Threading::STARTUPINFOW;
use windows_sys::Win32::UI::WindowsAndMessaging::EnumWindows;
use windows_sys::Win32::UI::WindowsAndMessaging::GetClassNameW;
use windows_sys::Win32::UI::WindowsAndMessaging::GetShellWindow;
use windows_sys::Win32::UI::WindowsAndMessaging::GetWindowThreadProcessId;
use windows_sys::Win32::UI::WindowsAndMessaging::IsWindowVisible;
use windows_sys::Win32::UI::WindowsAndMessaging::MB_ICONERROR;
use windows_sys::Win32::UI::WindowsAndMessaging::MB_ICONINFORMATION;
use windows_sys::Win32::UI::WindowsAndMessaging::MB_SETFOREGROUND;
use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

use crate::cli;
use crate::exitcode::as_process_code;
use crate::exitcode::ERR_CHILD;
use crate::exitcode::ERR_USAGE;
use crate::launch;
use crate::launch::Failure;
use crate::reg;
use crate::sys;

pub const RUNAS_KEY: &str = "SOFTWARE\\Classes\\AppID\\{CDCBCFCA-3CDC-436f-A4E2-0E02075250C2}";
pub const STOCK_RUNAS: &str = "Interactive User";
pub const SYSTEM_HIVE: &str = "S-1-5-18";
pub const STOCK_SYSTEM_LINK: &str = "\\Registry\\User\\.Default";
const STATE_MUTEX: &str = "Global\\XSudo.ShellState";
const MUTEX_WAIT_MS: u32 = 120_000;
const WINDOW_WAIT_MS: u32 = 30_000;
const WINDOW_SETTLE_MS: u32 = 1_500;
const IMPORT_WAIT_MS: u32 = 300_000;
const FOLDER_CLASSES: [&str; 2] = ["CabinetWClass", "ExploreWClass"];

pub fn is_import_switch(text: &str) -> bool {
    text.eq_ignore_ascii_case("--Import")
}

pub fn is_open_folder_switch(text: &str) -> bool {
    text.eq_ignore_ascii_case("--OpenFolder")
}

pub fn clean_argument(text: &str) -> String {
    let t = text.trim();
    let t = t.strip_prefix('"').unwrap_or(t);
    let t = t.strip_suffix('"').unwrap_or(t);
    t.trim().to_string()
}

pub fn folder_target(argument: &str) -> String {
    let t = clean_argument(argument);
    let b = t.as_bytes();
    if b.len() == 2 && b[1] == b':' && b[0].is_ascii_alphabetic() {
        return format!("{t}\\");
    }
    let trimmed = t.trim_end_matches(['\\', '/']);
    let tb = trimmed.as_bytes();
    if trimmed.is_empty() || (tb.len() == 2 && tb[1] == b':') {
        t
    } else {
        trimmed.to_string()
    }
}

pub fn is_shell_name(target: &str) -> bool {
    target.starts_with("::")
        || target
            .get(..6)
            .map(|p| p.eq_ignore_ascii_case("shell:"))
            .unwrap_or(false)
}

pub fn explorer_command(windir: &str, target: &str) -> String {
    let windir = windir.trim_end_matches('\\');
    if target.ends_with('\\') {
        format!("\"{windir}\\explorer.exe\" {target}")
    } else {
        format!("\"{windir}\\explorer.exe\" \"{target}\"")
    }
}

pub fn import_command(sysdir: &str, file: &str) -> String {
    let sysdir = sysdir.trim_end_matches('\\');
    format!("\"{sysdir}\\reg.exe\" import \"{file}\"")
}

pub fn user_link(sid: &str) -> String {
    format!("\\Registry\\User\\{sid}")
}

pub fn runas_to_restore(original: Option<&str>) -> String {
    match original {
        Some(v) if !v.trim().is_empty() => v.to_string(),
        _ => STOCK_RUNAS.to_string(),
    }
}

pub fn link_to_restore(original: Option<&str>) -> String {
    match original {
        Some(v) if v.eq_ignore_ascii_case(STOCK_SYSTEM_LINK) => v.to_string(),
        _ => STOCK_SYSTEM_LINK.to_string(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Found {
    Missing,
    File,
    Directory,
    Unreadable,
}

fn probe(path: &str) -> Found {
    let w = sys::wide(path);
    let attrs = unsafe { GetFileAttributesW(w.as_ptr()) };
    if attrs == INVALID_FILE_ATTRIBUTES {
        match sys::last_error() {
            ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => Found::Missing,
            _ => Found::Unreadable,
        }
    } else if attrs & FILE_ATTRIBUTE_DIRECTORY != 0 {
        Found::Directory
    } else {
        Found::File
    }
}

fn exit(code: u32) -> ! {
    std::process::exit(as_process_code(code));
}

struct StateMutex(sys::Handle);

impl StateMutex {
    fn acquire() -> Result<StateMutex, Failure> {
        unsafe {
            let name = sys::wide(STATE_MUTEX);
            let h = CreateMutexW(null(), 0, name.as_ptr());
            if h.is_null() {
                return Err(Failure::new(
                    ERR_CHILD,
                    sys::last_error(),
                    "XSudo could not create its lock.",
                ));
            }
            let h = sys::Handle(h);
            let w = WaitForSingleObject(h.0, MUTEX_WAIT_MS);
            if w == WAIT_OBJECT_0 || w == WAIT_ABANDONED {
                Ok(StateMutex(h))
            } else {
                Err(Failure::new(
                    ERR_CHILD,
                    ERROR_TIMEOUT,
                    "Another 'Open as TrustedInstaller' or 'Import as TrustedInstaller' is still running. Try again in a moment.",
                ))
            }
        }
    }
}

impl Drop for StateMutex {
    fn drop(&mut self) {
        unsafe {
            ReleaseMutex(self.0 .0);
        }
    }
}

fn current_thread_token() -> Result<sys::Handle, u32> {
    unsafe {
        let mut previous: HANDLE = null_mut();
        for open_as_self in [1, 0] {
            if OpenThreadToken(
                GetCurrentThread(),
                TOKEN_IMPERSONATE,
                open_as_self,
                &mut previous,
            ) != 0
            {
                return Ok(sys::Handle(previous));
            }
            if sys::last_error() == ERROR_NO_TOKEN {
                return Ok(sys::Handle(null_mut()));
            }
        }
        Err(sys::last_error())
    }
}

fn with_token<R>(token: HANDLE, f: impl FnOnce() -> Result<R, u32>) -> Result<R, u32> {
    let previous = current_thread_token()?;
    unsafe {
        if ImpersonateLoggedOnUser(token) == 0 {
            let e = sys::last_error();
            SetThreadToken(null(), previous.0);
            return Err(e);
        }
        let r = f();
        SetThreadToken(null(), previous.0);
        r
    }
}

fn process_user_sid(pid: u32) -> Option<String> {
    unsafe {
        let p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if p.is_null() {
            return None;
        }
        let p = sys::Handle(p);
        let mut t: HANDLE = null_mut();
        if OpenProcessToken(p.0, TOKEN_QUERY, &mut t) == 0 {
            return None;
        }
        let t = sys::Handle(t);
        sys::token_user_sid(t.0)
    }
}

fn interactive_user_sid() -> Option<String> {
    let shell = unsafe { GetShellWindow() };
    let mut pid = 0u32;
    if !shell.is_null() {
        unsafe {
            GetWindowThreadProcessId(shell, &mut pid);
        }
    }
    let from_shell = if pid != 0 { process_user_sid(pid) } else { None };
    from_shell
        .or_else(|| sys::caller_token_query().and_then(|t| sys::token_user_sid(t.0)))
        .filter(|sid| sid != SYSTEM_HIVE && reg::exists(HKEY_USERS, sid))
}

struct Swap<'a> {
    ti: &'a sys::Handle,
    runas: Option<Option<String>>,
    link: Option<Option<String>>,
}

impl<'a> Swap<'a> {
    fn begin(ti: &'a sys::Handle, runas: bool, link: Option<&str>) -> Result<Swap<'a>, Failure> {
        let mut swap = Swap {
            ti,
            runas: None,
            link: None,
        };
        let failed = |e: u32| {
            Failure::new(
                ERR_CHILD,
                e,
                "XSudo could not prepare Windows for a TrustedInstaller Explorer window or import.",
            )
        };
        let result = with_token(ti.0, || -> Result<(), u32> {
            if runas {
                let key = reg::open_values(HKEY_LOCAL_MACHINE, RUNAS_KEY)?;
                let original = reg::read_string(&key, "RunAs");
                swap.runas = Some(original);
                reg::set_string(&key, "RunAs", "")?;
            }
            if let Some(target) = link {
                let key = reg::open_link(HKEY_USERS, SYSTEM_HIVE)?;
                let original = reg::read_link(&key);
                swap.link = Some(original);
                reg::set_link(&key, target)?;
            }
            Ok(())
        });
        match result {
            Ok(()) => Ok(swap),
            Err(e) => {
                let _ = swap.restore();
                Err(failed(e))
            }
        }
    }

    fn restore(&mut self) -> Result<(), Failure> {
        let runas = self.runas.take();
        let link = self.link.take();
        let result = with_token(self.ti.0, || -> Result<(), u32> {
            let mut first: Option<u32> = None;
            if let Some(original) = runas {
                let want = runas_to_restore(original.as_deref());
                let r = reg::open_values(HKEY_LOCAL_MACHINE, RUNAS_KEY).and_then(|key| {
                    reg::set_string(&key, "RunAs", &want)?;
                    if reg::read_string(&key, "RunAs").as_deref() == Some(want.as_str()) {
                        Ok(())
                    } else {
                        Err(ERROR_FILE_NOT_FOUND)
                    }
                });
                if let Err(e) = r {
                    first.get_or_insert(e);
                }
            }
            if let Some(original) = link {
                let want = link_to_restore(original.as_deref());
                let r = reg::open_link(HKEY_USERS, SYSTEM_HIVE).and_then(|key| {
                    reg::set_link(&key, &want)?;
                    match reg::read_link(&key) {
                        Some(v) if v.eq_ignore_ascii_case(&want) => Ok(()),
                        _ => Err(ERROR_FILE_NOT_FOUND),
                    }
                });
                if let Err(e) = r {
                    first.get_or_insert(e);
                }
            }
            match first {
                None => Ok(()),
                Some(e) => Err(e),
            }
        });
        result.map_err(|e| {
            Failure::new(
                ERR_CHILD,
                e,
                "XSudo could not restore the Explorer RunAs setting or the SYSTEM profile link. Restart Windows, and if 'Open as TrustedInstaller' still misbehaves, run it once more: it restores both before it finishes.",
            )
        })
    }
}

impl Drop for Swap<'_> {
    fn drop(&mut self) {
        if self.runas.is_some() || self.link.is_some() {
            let _ = self.restore();
        }
    }
}

unsafe extern "system" fn collect_window(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let list = &mut *(lparam as *mut Vec<usize>);
    list.push(hwnd as usize);
    1
}

fn window_class(hwnd: HWND) -> String {
    let mut buf = [0u16; 64];
    let n = unsafe { GetClassNameW(hwnd, buf.as_mut_ptr(), buf.len() as i32) };
    String::from_utf16_lossy(&buf[..n.max(0) as usize])
}

fn system_folder_windows() -> Vec<usize> {
    let mut all: Vec<usize> = Vec::new();
    unsafe {
        EnumWindows(Some(collect_window), &mut all as *mut Vec<usize> as LPARAM);
    }
    all.into_iter()
        .filter(|&w| {
            let hwnd = w as HWND;
            if unsafe { IsWindowVisible(hwnd) } == 0 {
                return false;
            }
            let class = window_class(hwnd);
            if !FOLDER_CLASSES.iter().any(|c| class.eq_ignore_ascii_case(c)) {
                return false;
            }
            let mut pid = 0u32;
            unsafe {
                GetWindowThreadProcessId(hwnd, &mut pid);
            }
            pid != 0 && sys::open_source_token(pid).is_some()
        })
        .collect()
}

fn wait_for_new_window(before: &[usize]) -> bool {
    let mut waited = 0u32;
    while waited < WINDOW_WAIT_MS {
        sys::sleep_ms(250);
        waited += 250;
        if system_folder_windows().iter().any(|w| !before.contains(w)) {
            return true;
        }
    }
    false
}

pub fn open_folder(target: &str) -> Result<(), Failure> {
    let _lock = StateMutex::acquire()?;
    let windir = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    let line = explorer_command(&windir, target);
    let mut cmdbuf = sys::wide(&line);
    let wd = sys::wide(&launch::system_dir());
    let caller = sys::caller_token_query();
    let env = caller.as_ref().and_then(|c| sys::make_env_block(c.0));
    let envptr = env.as_ref().map(|e| e.0 as *const c_void).unwrap_or(null());

    let ti = launch::trustedinstaller_session()?;
    let user = interactive_user_sid().map(|s| user_link(&s));
    let before = system_folder_windows();
    let mut swap = Swap::begin(&ti.primary, true, user.as_deref())?;
    let started = launch::spawn_detached(
        ti.primary.0,
        &mut cmdbuf,
        &wd,
        envptr,
        SW_SHOWNORMAL as u16,
    );
    let appeared = started.is_ok() && wait_for_new_window(&before);
    if appeared {
        sys::sleep_ms(WINDOW_SETTLE_MS);
    }
    let restored = swap.restore();
    drop(swap);
    drop(ti);
    restored?;
    match started {
        Err(code) => Err(Failure::new(
            ERR_CHILD,
            code,
            "Explorer could not be started as TrustedInstaller.",
        )),
        Ok(_) if appeared => Ok(()),
        Ok(_) => Err(Failure::new(
            ERR_CHILD,
            ERROR_TIMEOUT,
            format!(
                "Explorer did not open a TrustedInstaller window for this folder within 30 seconds:\n{target}"
            ),
        )),
    }
}

fn decode_output(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    unsafe {
        let n = MultiByteToWideChar(
            CP_OEMCP,
            0,
            bytes.as_ptr(),
            bytes.len() as i32,
            null_mut(),
            0,
        );
        if n <= 0 {
            return String::from_utf8_lossy(bytes).into_owned();
        }
        let mut buf = vec![0u16; n as usize];
        MultiByteToWideChar(
            CP_OEMCP,
            0,
            bytes.as_ptr(),
            bytes.len() as i32,
            buf.as_mut_ptr(),
            n,
        );
        String::from_utf16_lossy(&buf).trim().to_string()
    }
}

fn run_captured(
    token: HANDLE,
    line: &str,
    workdir: &str,
    env: *const c_void,
) -> Result<Option<(u32, String)>, u32> {
    unsafe {
        let sa = SECURITY_ATTRIBUTES {
            nLength: core::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: null_mut(),
            bInheritHandle: 1,
        };
        let mut read: HANDLE = null_mut();
        let mut write: HANDLE = null_mut();
        if CreatePipe(&mut read, &mut write, &sa, 1 << 20) == 0 {
            return Err(sys::last_error());
        }
        let read = sys::Handle(read);
        let write = sys::Handle(write);
        SetHandleInformation(read.0, HANDLE_FLAG_INHERIT, 0);
        let mut si: STARTUPINFOW = core::mem::zeroed();
        si.cb = core::mem::size_of::<STARTUPINFOW>() as u32;
        si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE as u16;
        si.hStdOutput = write.0;
        si.hStdError = write.0;
        let mut desktop = sys::wide("winsta0\\default");
        si.lpDesktop = desktop.as_mut_ptr();
        let mut cmd = sys::wide(line);
        let wd = sys::wide(workdir);
        let mut pi: PROCESS_INFORMATION = core::mem::zeroed();
        let ok = CreateProcessAsUserW(
            token,
            null(),
            cmd.as_mut_ptr(),
            null(),
            null(),
            1,
            CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
            env,
            wd.as_ptr(),
            &si,
            &mut pi,
        );
        if ok == 0 {
            return Err(sys::last_error());
        }
        drop(write);
        let _thread = sys::Handle(pi.hThread);
        let process = sys::Handle(pi.hProcess);
        if WaitForSingleObject(process.0, IMPORT_WAIT_MS) != WAIT_OBJECT_0 {
            return Ok(None);
        }
        let mut code = 0u32;
        GetExitCodeProcess(process.0, &mut code);
        let mut out: Vec<u8> = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let mut n = 0u32;
            if ReadFile(read.0, buf.as_mut_ptr(), buf.len() as u32, &mut n, null_mut()) == 0
                || n == 0
            {
                break;
            }
            out.extend_from_slice(&buf[..n as usize]);
            if out.len() > 65536 {
                break;
            }
        }
        Ok(Some((code, decode_output(&out))))
    }
}

pub fn import(file: &str) -> Result<String, Failure> {
    let path = std::path::Path::new(file);
    if file.is_empty() || matches!(probe(file), Found::Missing | Found::Directory) {
        return Err(Failure::new(
            ERR_CHILD,
            ERROR_FILE_NOT_FOUND,
            format!("The file was not found:\n{file}"),
        ));
    }
    let resolved = std::path::absolute(path)
        .map(|a| a.to_string_lossy().into_owned())
        .unwrap_or_else(|_| file.to_string());
    let _lock = StateMutex::acquire()?;
    let sysdir = launch::system_dir();
    let line = import_command(&sysdir, &resolved);
    let caller = sys::caller_token_query();
    let env = caller.as_ref().and_then(|c| sys::make_env_block(c.0));
    let envptr = env.as_ref().map(|e| e.0 as *const c_void).unwrap_or(null());

    let ti = launch::trustedinstaller_session()?;
    let user = interactive_user_sid().map(|s| user_link(&s));
    let mut swap = Swap::begin(&ti.primary, false, user.as_deref())?;
    let outcome = run_captured(ti.primary.0, &line, &sysdir, envptr);
    let restored = swap.restore();
    drop(swap);
    drop(ti);
    restored?;
    match outcome {
        Err(code) => Err(Failure::new(
            ERR_CHILD,
            code,
            format!("reg.exe could not be started as TrustedInstaller to import:\n{resolved}"),
        )),
        Ok(None) => Err(Failure::new(
            ERR_CHILD,
            ERROR_TIMEOUT,
            format!("reg.exe did not finish importing within 5 minutes:\n{resolved}"),
        )),
        Ok(Some((0, _))) => Ok(resolved),
        Ok(Some((code, text))) => {
            let mut summary = format!("The file could not be imported:\n{resolved}");
            if !text.is_empty() {
                summary.push_str("\n\n");
                summary.push_str(&text);
            }
            summary.push_str(&format!("\n\nreg.exe exit code {code}"));
            Err(Failure::new(ERR_CHILD, 0, summary))
        }
    }
}

fn switch_argument(raw: &[u16], tokens: &[cli::Token]) -> String {
    match tokens.get(2) {
        Some(t) => clean_argument(&String::from_utf16_lossy(&raw[t.start..])),
        None => String::new(),
    }
}

fn usage_and_exit(text: &str) -> ! {
    launch::message_box(null_mut(), text, MB_ICONERROR | MB_SETFOREGROUND);
    exit(ERR_USAGE);
}

pub fn import_switch(raw: &[u16]) -> ! {
    unsafe {
        FreeConsole();
    }
    let tried = launch::take_elevation_marker();
    let tokens = cli::tokenize(raw);
    let file = switch_argument(raw, &tokens);
    if file.is_empty() {
        usage_and_exit("Usage: XSudo --Import <file.reg>\n\nImports the file as TrustedInstaller and shows the result.");
    }
    launch::elevate_or_exit(raw, &tokens, tried);
    match import(&file) {
        Ok(done) => {
            launch::message_box(
                null_mut(),
                &format!("The file was imported as TrustedInstaller:\n{done}"),
                MB_ICONINFORMATION | MB_SETFOREGROUND,
            );
            exit(0);
        }
        Err(f) => {
            launch::show_failure(null_mut(), &f);
            exit(f.code);
        }
    }
}

pub fn open_folder_switch(raw: &[u16]) -> ! {
    unsafe {
        FreeConsole();
    }
    let tried = launch::take_elevation_marker();
    let tokens = cli::tokenize(raw);
    let target = folder_target(&switch_argument(raw, &tokens));
    if target.is_empty() {
        usage_and_exit("Usage: XSudo --OpenFolder <folder>\n\nOpens the folder in an Explorer window that runs as TrustedInstaller.");
    }
    if !is_shell_name(&target) && matches!(probe(&target), Found::Missing | Found::File) {
        launch::show_failure(
            null_mut(),
            &Failure::new(
                ERR_CHILD,
                ERROR_PATH_NOT_FOUND,
                format!("The folder was not found:\n{target}"),
            ),
        );
        exit(ERR_CHILD);
    }
    launch::elevate_or_exit(raw, &tokens, tried);
    match open_folder(&target) {
        Ok(()) => exit(0),
        Err(f) => {
            launch::show_failure(null_mut(), &f);
            exit(f.code);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn switch_names() {
        assert!(is_import_switch("--Import"));
        assert!(is_import_switch("--IMPORT"));
        assert!(!is_import_switch("-Import"));
        assert!(!is_import_switch("/Import"));
        assert!(is_open_folder_switch("--openfolder"));
        assert!(!is_open_folder_switch("--OpenFolders"));
        assert!(!is_open_folder_switch("-OpenFolder"));
    }

    #[test]
    fn arguments_lose_their_quotes() {
        assert_eq!(clean_argument("\"C:\\a b\\t.reg\""), "C:\\a b\\t.reg");
        assert_eq!(clean_argument("  C:\\x.reg  "), "C:\\x.reg");
        assert_eq!(clean_argument("\"C:\\\""), "C:\\");
        assert_eq!(clean_argument(""), "");
        assert_eq!(clean_argument("\"\""), "");
    }

    #[test]
    fn drive_roots_and_trailing_separators() {
        assert_eq!(folder_target("\"C:\\\""), "C:\\");
        assert_eq!(folder_target("C:"), "C:\\");
        assert_eq!(folder_target("\"D:\""), "D:\\");
        assert_eq!(folder_target("\"C:\\a b\\\""), "C:\\a b");
        assert_eq!(folder_target("C:\\Windows"), "C:\\Windows");
        assert_eq!(folder_target("\\\\srv\\share\\"), "\\\\srv\\share");
        assert_eq!(
            folder_target("::{20D04FE0-3AEA-1069-A2D8-08002B30309D}"),
            "::{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
        );
        assert!(is_shell_name("::{20D04FE0-3AEA-1069-A2D8-08002B30309D}"));
        assert!(is_shell_name("Shell:Downloads"));
        assert!(!is_shell_name("C:\\shell:x"));
        assert!(!is_shell_name("This PC"));
    }

    #[test]
    fn drive_root_survives_the_command_line() {
        let raw: Vec<u16> = "\"C:\\Program Files\\XSudo\\XSudo.exe\" --OpenFolder \"C:\\\""
            .encode_utf16()
            .collect();
        let tokens = cli::tokenize(&raw);
        assert_eq!(tokens.len(), 3);
        assert_eq!(folder_target(&switch_argument(&raw, &tokens)), "C:\\");
        let raw: Vec<u16> = "XSudo.exe --OpenFolder \"C:\\a b\\c d\""
            .encode_utf16()
            .collect();
        let tokens = cli::tokenize(&raw);
        assert_eq!(folder_target(&switch_argument(&raw, &tokens)), "C:\\a b\\c d");
    }

    #[test]
    fn child_command_lines() {
        assert_eq!(
            explorer_command("C:\\Windows", "C:\\a b"),
            "\"C:\\Windows\\explorer.exe\" \"C:\\a b\""
        );
        assert_eq!(
            explorer_command("C:\\Windows\\", "C:\\"),
            "\"C:\\Windows\\explorer.exe\" C:\\"
        );
        assert_eq!(
            explorer_command("C:\\Windows", "C:\\a,b"),
            "\"C:\\Windows\\explorer.exe\" \"C:\\a,b\""
        );
        assert_eq!(
            import_command("C:\\Windows\\System32", "C:\\my files\\t.reg"),
            "\"C:\\Windows\\System32\\reg.exe\" import \"C:\\my files\\t.reg\""
        );
    }

    #[test]
    fn missing_targets_are_told_apart() {
        assert_eq!(probe("C:\\definitely\\not\\here\\x.reg"), Found::Missing);
        assert_eq!(probe(&launch::system_dir()), Found::Directory);
        assert_eq!(
            probe(&format!("{}\\reg.exe", launch::system_dir())),
            Found::File
        );
    }

    #[test]
    fn restore_values() {
        assert_eq!(runas_to_restore(Some("Interactive User")), "Interactive User");
        assert_eq!(runas_to_restore(Some("")), "Interactive User");
        assert_eq!(runas_to_restore(None), "Interactive User");
        assert_eq!(runas_to_restore(Some("Launching User")), "Launching User");
        assert_eq!(
            link_to_restore(Some("\\REGISTRY\\USER\\.DEFAULT")),
            "\\REGISTRY\\USER\\.DEFAULT"
        );
        assert_eq!(
            link_to_restore(Some("\\Registry\\User\\S-1-5-21-1-2-3-1001")),
            "\\Registry\\User\\.Default"
        );
        assert_eq!(link_to_restore(None), "\\Registry\\User\\.Default");
        assert_eq!(
            user_link("S-1-5-21-1-2-3-1001"),
            "\\Registry\\User\\S-1-5-21-1-2-3-1001"
        );
    }
}

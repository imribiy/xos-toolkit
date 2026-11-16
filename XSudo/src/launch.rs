use core::ffi::c_void;
use core::ptr::null;
use core::ptr::null_mut;

use windows_sys::Win32::Foundation::ERROR_BAD_EXE_FORMAT;
use windows_sys::Win32::Foundation::ERROR_CANCELLED;
use windows_sys::Win32::Foundation::ERROR_DIRECTORY;
use windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::Storage::FileSystem::SearchPathW;
use windows_sys::Win32::System::Console::FreeConsole;
use windows_sys::Win32::System::Diagnostics::Debug::FormatMessageW;
use windows_sys::Win32::System::Diagnostics::Debug::FORMAT_MESSAGE_FROM_SYSTEM;
use windows_sys::Win32::System::Diagnostics::Debug::FORMAT_MESSAGE_IGNORE_INSERTS;
use windows_sys::Win32::System::Environment::SetEnvironmentVariableW;
use windows_sys::Win32::System::LibraryLoader::GetModuleFileNameW;
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows_sys::Win32::System::Threading::CreateProcessAsUserW;
use windows_sys::Win32::System::Threading::CREATE_NEW_CONSOLE;
use windows_sys::Win32::System::Threading::CREATE_UNICODE_ENVIRONMENT;
use windows_sys::Win32::System::Threading::PROCESS_INFORMATION;
use windows_sys::Win32::System::Threading::STARTF_USESHOWWINDOW;
use windows_sys::Win32::System::Threading::STARTUPINFOW;
use windows_sys::Win32::UI::Shell::ShellExecuteExW;
use windows_sys::Win32::UI::Shell::SEE_MASK_FLAG_NO_UI;
use windows_sys::Win32::UI::Shell::SEE_MASK_NOASYNC;
use windows_sys::Win32::UI::Shell::SHELLEXECUTEINFOW;
use windows_sys::Win32::UI::WindowsAndMessaging::MessageBoxW;
use windows_sys::Win32::UI::WindowsAndMessaging::MB_ICONERROR;
use windows_sys::Win32::UI::WindowsAndMessaging::MB_SETFOREGROUND;
use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

use crate::cli;
use crate::exitcode::as_process_code;
use crate::exitcode::ERR_CHILD;
use crate::exitcode::ERR_ELEVATION;
use crate::exitcode::ERR_IDENTITY;
use crate::exitcode::ERR_USAGE;
use crate::exitcode::ERR_WORKDIR;
use crate::run;
use crate::settings::Show;
use crate::sys;

pub const TITLE: &str = "XSudo";
const ELEVATION_MARKER: &str = "XSUDO_ELEVATION_REQUESTED";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Direct,
    Batch,
    PowerShell,
    Console,
}

pub fn kind_of(path: &str) -> Kind {
    let name = path.rsplit(['\\', '/']).next().unwrap_or(path);
    let ext = match name.rfind('.') {
        Some(i) => name[i + 1..].to_ascii_lowercase(),
        None => String::new(),
    };
    match ext.as_str() {
        "bat" | "cmd" => Kind::Batch,
        "ps1" => Kind::PowerShell,
        "msc" => Kind::Console,
        _ => Kind::Direct,
    }
}

fn with_params(mut line: String, params: &str) -> String {
    if !params.trim().is_empty() {
        line.push(' ');
        line.push_str(params);
    }
    line
}

pub fn command_line(file: &str, params: &str, sysdir: &str) -> String {
    let sysdir = sysdir.trim_end_matches('\\');
    match kind_of(file) {
        Kind::Direct => with_params(format!("\"{file}\""), params),
        Kind::Batch => {
            let inner = with_params(format!("\"{file}\""), params);
            format!("\"{sysdir}\\cmd.exe\" /c \"{inner}\"")
        }
        Kind::PowerShell => with_params(
            format!(
                "\"{sysdir}\\WindowsPowerShell\\v1.0\\powershell.exe\" -NoProfile -ExecutionPolicy Bypass -File \"{file}\""
            ),
            params,
        ),
        Kind::Console => with_params(format!("\"{sysdir}\\mmc.exe\" \"{file}\""), params),
    }
}

pub fn expand_env_with<F: Fn(&str) -> Option<String>>(text: &str, lookup: F) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%') {
            None => {
                out.push_str(&rest[start..]);
                return out;
            }
            Some(end) => {
                let name = &after[..end];
                match if name.is_empty() { None } else { lookup(name) } {
                    Some(value) => {
                        out.push_str(&value);
                        rest = &after[end + 1..];
                    }
                    None => {
                        out.push('%');
                        out.push_str(name);
                        rest = &after[end..];
                    }
                }
            }
        }
    }
    out.push_str(rest);
    out
}

pub fn expand_env(text: &str) -> String {
    expand_env_with(text, |name| std::env::var(name).ok())
}

pub fn parent_dir(path: &str) -> String {
    match path.rfind(['\\', '/']) {
        Some(0) => path[..1].to_string(),
        Some(i) if i == 2 && path.as_bytes().get(1) == Some(&b':') => path[..3].to_string(),
        Some(i) => path[..i].to_string(),
        None => String::new(),
    }
}

pub fn file_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub code: u32,
    pub win32: u32,
    pub summary: String,
}

impl Failure {
    fn new(code: u32, win32: u32, summary: impl Into<String>) -> Failure {
        Failure {
            code,
            win32,
            summary: summary.into(),
        }
    }
}

pub fn failure_text(f: &Failure, windows_text: &str) -> String {
    let mut text = format!("{}\n\nXSudo code 0x{:08X}", f.summary, f.code);
    if f.win32 != 0 {
        text.push_str(&format!(
            "\nWindows error {}: {}",
            f.win32,
            windows_text.trim()
        ));
    }
    text
}

pub fn windows_error_text(code: u32) -> String {
    unsafe {
        let mut buf = vec![0u16; 1024];
        let n = FormatMessageW(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            null(),
            code,
            0,
            buf.as_mut_ptr(),
            buf.len() as u32,
            null(),
        );
        if n == 0 {
            return String::from("(no description)");
        }
        String::from_utf16_lossy(&buf[..n as usize])
            .trim()
            .to_string()
    }
}

pub fn system_dir() -> String {
    unsafe {
        let mut buf = vec![0u16; 260];
        let n = GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32);
        if n == 0 || n as usize >= buf.len() {
            String::from("C:\\Windows\\System32")
        } else {
            String::from_utf16_lossy(&buf[..n as usize])
        }
    }
}

pub fn self_path() -> String {
    unsafe {
        let mut buf = vec![0u16; 32768];
        let n = GetModuleFileNameW(null_mut(), buf.as_mut_ptr(), buf.len() as u32);
        String::from_utf16_lossy(&buf[..n as usize])
    }
}

fn search_path(name: &str) -> Option<String> {
    unsafe {
        let wname = sys::wide(name);
        let ext = sys::wide(".exe");
        let mut buf = vec![0u16; 32768];
        let n = SearchPathW(
            null(),
            wname.as_ptr(),
            ext.as_ptr(),
            buf.len() as u32,
            buf.as_mut_ptr(),
            null_mut(),
        );
        if n == 0 || n as usize >= buf.len() {
            None
        } else {
            Some(String::from_utf16_lossy(&buf[..n as usize]))
        }
    }
}

pub fn resolve_file(file: &str) -> Result<String, Failure> {
    let expanded = expand_env(file.trim());
    let expanded = expanded.trim().trim_matches('"').to_string();
    if expanded.is_empty() {
        return Err(Failure::new(
            ERR_CHILD,
            ERROR_FILE_NOT_FOUND,
            "No file was given.",
        ));
    }
    let has_dir = expanded.contains(['\\', '/', ':']);
    let candidate = if has_dir {
        let p = std::path::Path::new(&expanded);
        if p.is_file() {
            Some(
                std::path::absolute(p)
                    .map(|a| a.to_string_lossy().into_owned())
                    .unwrap_or_else(|_| expanded.clone()),
            )
        } else {
            None
        }
    } else {
        search_path(&expanded).filter(|p| std::path::Path::new(p).is_file())
    };
    candidate.ok_or_else(|| {
        Failure::new(
            ERR_CHILD,
            ERROR_FILE_NOT_FOUND,
            format!("The file was not found:\n{expanded}"),
        )
    })
}

pub fn resolve_start_dir(start_dir: &str, resolved_file: &str) -> Result<String, Failure> {
    let expanded = expand_env(start_dir.trim());
    let expanded = expanded.trim().trim_matches('"').to_string();
    let dir = if expanded.is_empty() {
        parent_dir(resolved_file)
    } else {
        expanded
    };
    if !dir.is_empty() && std::path::Path::new(&dir).is_dir() {
        Ok(dir)
    } else {
        Err(Failure::new(
            ERR_WORKDIR,
            ERROR_DIRECTORY,
            format!("The start directory does not exist:\n{dir}"),
        ))
    }
}

fn spawn_detached(
    token: HANDLE,
    cmdline: &mut [u16],
    workdir: &[u16],
    env: *const c_void,
    show: u16,
) -> Result<u32, u32> {
    unsafe {
        let mut si: STARTUPINFOW = core::mem::zeroed();
        si.cb = core::mem::size_of::<STARTUPINFOW>() as u32;
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = show;
        let mut desktop = sys::wide("winsta0\\default");
        si.lpDesktop = desktop.as_mut_ptr();
        let mut pi: PROCESS_INFORMATION = core::mem::zeroed();
        let ok = CreateProcessAsUserW(
            token,
            null(),
            cmdline.as_mut_ptr(),
            null(),
            null(),
            0,
            CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT,
            env,
            workdir.as_ptr(),
            &si,
            &mut pi,
        );
        if ok == 0 {
            return Err(sys::last_error());
        }
        let _thread = sys::Handle(pi.hThread);
        let _process = sys::Handle(pi.hProcess);
        Ok(pi.dwProcessId)
    }
}

pub struct Started {
    pub pid: u32,
    pub file: String,
}

pub fn launch(file: &str, params: &str, start_dir: &str, show: Show) -> Result<Started, Failure> {
    let resolved = resolve_file(file)?;
    let dir = resolve_start_dir(start_dir, &resolved)?;
    let expanded_params = expand_env(params);
    let line = command_line(&resolved, &expanded_params, &system_dir());
    let mut cmdbuf = sys::wide(&line);
    let wd = sys::wide(&dir);

    let caller = sys::caller_token_query();
    let env = caller.as_ref().and_then(|c| sys::make_env_block(c.0));
    let envptr = env.as_ref().map(|e| e.0 as *const c_void).unwrap_or(null());
    let session = sys::caller_session_id();

    let identity = |win32: u32| {
        Failure::new(
            ERR_IDENTITY,
            win32,
            "TrustedInstaller could not be started or its token could not be obtained.",
        )
    };
    let ti_pid = sys::ensure_trustedinstaller_running().map_err(|_| identity(sys::last_error()))?;
    sys::enable_privilege("SeDebugPrivilege");
    let winlogon = run::open_richest_system_source("winlogon.exe")
        .ok_or_else(|| identity(sys::last_error()))?;
    let guard = sys::impersonate(winlogon.0);
    sys::enable_thread_privileges_for_launch();
    let src = run::open_pid_source(ti_pid).ok_or_else(|| identity(sys::last_error()))?;
    let primary = sys::duplicate_primary(src.0).ok_or_else(|| identity(sys::last_error()))?;
    sys::set_session(primary.0, session);
    if !sys::enable_all_privileges(primary.0) {
        return Err(identity(sys::last_error()));
    }
    let result = spawn_detached(primary.0, &mut cmdbuf, &wd, envptr, show.sw());
    drop(guard);

    match result {
        Ok(pid) => Ok(Started {
            pid,
            file: resolved,
        }),
        Err(code) if code == ERROR_BAD_EXE_FORMAT => Err(Failure::new(
            ERR_CHILD,
            code,
            format!(
                "This file is not a program:\n{resolved}\n\nXSudo starts .exe and .com programs, .bat, .cmd and .ps1 scripts and .msc consoles. Open other files with the program they belong to."
            ),
        )),
        Err(code) => Err(Failure::new(
            ERR_CHILD,
            code,
            format!("The program could not be started:\n{resolved}"),
        )),
    }
}

pub fn message_box(owner: HWND, text: &str, flags: u32) -> i32 {
    let t = sys::wide(text);
    let c = sys::wide(TITLE);
    unsafe { MessageBoxW(owner, t.as_ptr(), c.as_ptr(), flags) }
}

pub fn show_failure(owner: HWND, f: &Failure) {
    let text = failure_text(f, &windows_error_text(f.win32));
    message_box(owner, &text, MB_ICONERROR | MB_SETFOREGROUND);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Elevation {
    Started,
    Declined,
    Refused,
}

pub fn take_elevation_marker() -> bool {
    let present = std::env::var_os(ELEVATION_MARKER).is_some();
    let name = sys::wide(ELEVATION_MARKER);
    unsafe {
        SetEnvironmentVariableW(name.as_ptr(), null());
    }
    present
}

pub fn relaunch_elevated(params: &[u16], already_tried: bool) -> Elevation {
    if already_tried {
        return Elevation::Refused;
    }
    unsafe {
        let name = sys::wide(ELEVATION_MARKER);
        let one = sys::wide("1");
        SetEnvironmentVariableW(name.as_ptr(), one.as_ptr());
        let mut p = params.to_vec();
        p.push(0);
        let file = sys::wide(&self_path());
        let verb = sys::wide("runas");
        let workdir = sys::current_directory();
        let mut info: SHELLEXECUTEINFOW = core::mem::zeroed();
        info.cbSize = core::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
        info.fMask = SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI;
        info.lpVerb = verb.as_ptr();
        info.lpFile = file.as_ptr();
        info.lpParameters = p.as_ptr();
        info.lpDirectory = workdir.as_ptr();
        info.nShow = SW_HIDE;
        let ok = ShellExecuteExW(&mut info);
        let err = sys::last_error();
        SetEnvironmentVariableW(name.as_ptr(), null());
        if ok != 0 {
            Elevation::Started
        } else if err == ERROR_CANCELLED {
            Elevation::Declined
        } else {
            Elevation::Refused
        }
    }
}

pub const NEEDS_ADMIN: &str = "XSudo needs administrator rights. Sign in with an administrator account and start XSudo again.";

fn exit(code: u32) -> ! {
    std::process::exit(as_process_code(code));
}

pub fn launch_switch(raw: &[u16]) -> ! {
    unsafe {
        FreeConsole();
    }
    let tried = take_elevation_marker();
    let tokens = cli::tokenize(raw);
    let file = tokens
        .get(2)
        .map(|t| t.text.trim().to_string())
        .unwrap_or_default();
    if file.is_empty() {
        message_box(
            null_mut(),
            "Usage: XSudo --Launch <file>\n\nRuns the file as TrustedInstaller in its own window and returns at once.",
            MB_ICONERROR | MB_SETFOREGROUND,
        );
        exit(ERR_USAGE);
    }
    if !sys::is_elevated() {
        let tail = &raw[tokens[1].start..];
        match relaunch_elevated(tail, tried) {
            Elevation::Started => exit(0),
            Elevation::Declined => exit(ERR_ELEVATION),
            Elevation::Refused => {
                message_box(null_mut(), NEEDS_ADMIN, MB_ICONERROR | MB_SETFOREGROUND);
                exit(ERR_ELEVATION);
            }
        }
    }
    let params = match tokens.get(3) {
        Some(t) => String::from_utf16_lossy(&cli::tail_slice(raw, t.start)),
        None => String::new(),
    };
    match launch(&file, &params, "", Show::Normal) {
        Ok(_) => exit(0),
        Err(f) => {
            show_failure(null_mut(), &f);
            exit(f.code);
        }
    }
}

pub fn is_launch_switch(text: &str) -> bool {
    text.eq_ignore_ascii_case("--Launch")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYS: &str = "C:\\Windows\\System32";

    #[test]
    fn exe_and_com_start_directly() {
        assert_eq!(
            command_line("C:\\a b\\x.exe", "", SYS),
            "\"C:\\a b\\x.exe\""
        );
        assert_eq!(
            command_line("C:\\a b\\x.exe", "/c whoami > \"C:\\o.txt\"", SYS),
            "\"C:\\a b\\x.exe\" /c whoami > \"C:\\o.txt\""
        );
        assert_eq!(
            command_line("C:\\t\\x.COM", "-q", SYS),
            "\"C:\\t\\x.COM\" -q"
        );
    }

    #[test]
    fn batch_files_run_through_cmd_c() {
        assert_eq!(
            command_line("C:\\s p\\t.bat", "", SYS),
            "\"C:\\Windows\\System32\\cmd.exe\" /c \"\"C:\\s p\\t.bat\"\""
        );
        assert_eq!(
            command_line("C:\\s p\\t.CMD", "a \"b c\"", SYS),
            "\"C:\\Windows\\System32\\cmd.exe\" /c \"\"C:\\s p\\t.CMD\" a \"b c\"\""
        );
    }

    #[test]
    fn powershell_scripts_bypass_policy() {
        assert_eq!(
            command_line("C:\\s\\t.ps1", "-Name x", "C:\\Windows\\System32\\"),
            "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -NoProfile -ExecutionPolicy Bypass -File \"C:\\s\\t.ps1\" -Name x"
        );
    }

    #[test]
    fn consoles_run_through_mmc() {
        assert_eq!(
            command_line("C:\\Windows\\System32\\services.msc", "", SYS),
            "\"C:\\Windows\\System32\\mmc.exe\" \"C:\\Windows\\System32\\services.msc\""
        );
    }

    #[test]
    fn other_files_start_directly() {
        assert_eq!(kind_of("C:\\x\\readme.txt"), Kind::Direct);
        assert_eq!(kind_of("C:\\x.y\\noext"), Kind::Direct);
        assert_eq!(kind_of("C:\\x\\a.Ps1"), Kind::PowerShell);
        assert_eq!(kind_of("a.msc"), Kind::Console);
        assert_eq!(
            command_line("C:\\x\\readme.txt", "", SYS),
            "\"C:\\x\\readme.txt\""
        );
    }

    fn lookup(name: &str) -> Option<String> {
        match name.to_ascii_uppercase().as_str() {
            "SYSTEMROOT" => Some("C:\\Windows".into()),
            "TEMP" => Some("C:\\Temp".into()),
            "EMPTY" => Some(String::new()),
            _ => None,
        }
    }

    #[test]
    fn env_expansion() {
        assert_eq!(
            expand_env_with("%SystemRoot%\\regedit.exe", lookup),
            "C:\\Windows\\regedit.exe"
        );
        assert_eq!(
            expand_env_with("%systemroot%\\x;%TEMP%", lookup),
            "C:\\Windows\\x;C:\\Temp"
        );
        assert_eq!(expand_env_with("plain", lookup), "plain");
        assert_eq!(expand_env_with("%NOPE%\\x", lookup), "%NOPE%\\x");
        assert_eq!(expand_env_with("100%", lookup), "100%");
        assert_eq!(expand_env_with("%%", lookup), "%%");
        assert_eq!(expand_env_with("a%EMPTY%b", lookup), "ab");
        assert_eq!(expand_env_with("%NOPE%TEMP%", lookup), "%NOPEC:\\Temp");
        assert_eq!(expand_env_with("%TEMP", lookup), "%TEMP");
        assert_eq!(
            expand_env_with("\u{4e2d}%TEMP%\u{6587}", lookup),
            "\u{4e2d}C:\\Temp\u{6587}"
        );
    }

    #[test]
    fn parent_and_name() {
        assert_eq!(parent_dir("C:\\Windows\\regedit.exe"), "C:\\Windows");
        assert_eq!(parent_dir("C:\\x.exe"), "C:\\");
        assert_eq!(parent_dir("x.exe"), "");
        assert_eq!(file_name("C:\\a\\b.cmd"), "b.cmd");
        assert_eq!(file_name("b.cmd"), "b.cmd");
    }

    #[test]
    fn failure_text_names_both_codes() {
        let f = Failure::new(ERR_CHILD, 2, "The file was not found:\nC:\\x.exe");
        let t = failure_text(&f, "The system cannot find the file specified.\r\n");
        assert!(t.contains("XSudo code 0x58530004"));
        assert!(t.ends_with("Windows error 2: The system cannot find the file specified."));
        let g = Failure::new(ERR_IDENTITY, 0, "x");
        assert!(!failure_text(&g, "").contains("Windows error"));
    }

    #[test]
    fn launch_switch_name() {
        assert!(is_launch_switch("--Launch"));
        assert!(is_launch_switch("--LAUNCH"));
        assert!(!is_launch_switch("-Launch"));
        assert!(!is_launch_switch("/Launch"));
        assert!(!is_launch_switch("--Launcher"));
    }

    #[test]
    fn missing_file_is_reported() {
        let f = resolve_file("C:\\definitely\\not\\here\\x.exe")
            .err()
            .unwrap();
        assert_eq!(f.code, ERR_CHILD);
        assert_eq!(f.win32, ERROR_FILE_NOT_FOUND);
        assert!(resolve_file("   ").is_err());
    }

    #[test]
    fn start_dir_defaults_to_file_folder() {
        let sys = system_dir();
        let cmd = format!("{sys}\\cmd.exe");
        assert_eq!(resolve_start_dir("", &cmd).unwrap(), sys);
        assert_eq!(
            resolve_start_dir("C:\\no\\such\\dir", &cmd)
                .err()
                .unwrap()
                .code,
            ERR_WORKDIR
        );
    }
}

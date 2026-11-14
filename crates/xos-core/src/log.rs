use std::fs::OpenOptions;
use std::io::Write;
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
use winreg::RegKey;

const SLOW_THRESHOLD_MS: u128 = 1000;

struct State {
    path: Option<PathBuf>,
    dir: Option<PathBuf>,
}

static STATE: Mutex<State> = Mutex::new(State {
    path: None,
    dir: None,
});

struct OpenAction {
    id: u64,
    page: String,
    name: String,
    started: Instant,
    failures_at_start: usize,
}

static OPEN_ACTIONS: Mutex<Vec<OpenAction>> = Mutex::new(Vec::new());
static NEXT_ACTION_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy)]
pub struct ActionToken(u64);

fn state() -> std::sync::MutexGuard<'static, State> {
    STATE.lock().unwrap_or_else(|e| e.into_inner())
}

fn open_actions() -> std::sync::MutexGuard<'static, Vec<OpenAction>> {
    OPEN_ACTIONS.lock().unwrap_or_else(|e| e.into_inner())
}

fn create_log_directory(path: &Path) -> Option<PathBuf> {
    std::fs::create_dir_all(path)
        .ok()
        .map(|_| path.to_path_buf())
}

fn env_dir(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
}

static RETENTION: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

pub fn disable_retention() {
    RETENTION.store(false, Ordering::SeqCst);
}

pub fn init(version: &str) {
    if state().path.is_some() {
        return;
    }
    let common = env_dir("ProgramData").unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    let preferred = common.join("XOS Toolkit").join("Logs");
    let fallback = env_dir("LOCALAPPDATA")
        .unwrap_or_default()
        .join("XOSToolkit")
        .join("Logs");
    let temp = std::env::temp_dir().join("XOSToolkit").join("Logs");
    let Some(dir) = create_log_directory(&preferred)
        .or_else(|| create_log_directory(&fallback))
        .or_else(|| create_log_directory(&temp))
    else {
        return;
    };

    if RETENTION.load(Ordering::SeqCst) {
        if let Ok(read) = std::fs::read_dir(&dir) {
        let mut files: Vec<(std::time::SystemTime, PathBuf)> = read
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                let lower = name.to_lowercase();
                if lower.starts_with("xos-toolkit-") && lower.ends_with(".log") {
                    let modified = e.metadata().ok()?.modified().ok()?;
                    Some((modified, e.path()))
                } else {
                    None
                }
            })
            .collect();
        files.sort_by(|a, b| b.0.cmp(&a.0));
        for (_, old) in files.into_iter().skip(19) {
            let _ = std::fs::remove_file(old);
        }
        }
    }

    let ts = chrono::Local::now().format("%Y-%m-%d_%H-%M-%S-%3f");
    let path = dir.join(format!("XOS-Toolkit-{ts}-P{}.log", std::process::id()));
    {
        let mut st = state();
        st.path = Some(path.clone());
        st.dir = Some(dir);
    }

    log(&format!("=== XOS Toolkit v{version} started ==="));
    log(&format!("Log: {}", path.display()));
    log(&format!("Windows: {}", windows_description()));
    log(&format!(
        "Runtime: Rust | OS {} | Process {}",
        if os_is_64bit() { "x64" } else { "x86" },
        if cfg!(target_pointer_width = "64") {
            "x64"
        } else {
            "x86"
        }
    ));
    log(&format!(
        "Account: {} | Elevated: {} | Culture: {} | UI: {} | XOS detected: {}",
        account_sid(),
        is_elevated(),
        culture_name(),
        ui_culture_name(),
        if crate::detect::is_xos() { "yes" } else { "no" }
    ));
    log(&format!(
        "Paths: ProgramFiles={} | System={}",
        env_dir("ProgramFiles")
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
        system_directory()
    ));
}

pub fn is_available() -> bool {
    state().path.is_some()
}

pub fn path() -> Option<PathBuf> {
    state().path.clone()
}

pub fn log_path() -> Option<PathBuf> {
    path()
}

pub fn log_directory() -> Option<PathBuf> {
    state().dir.clone()
}

fn write(message: &str) {
    let st = state();
    let Some(p) = &st.path else { return };
    let line = format!(
        "[{}] {}\r\n",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f"),
        crate::redact::redact(message)
    );
    if let Ok(mut f) = OpenOptions::new()
        .create(true)
        .append(true)
        .share_mode(3)
        .open(p)
    {
        let _ = f.write_all(line.as_bytes());
    }
}

pub fn log(message: &str) {
    write(message);
}

pub fn action(what: &str, detail: &str) {
    action_opt(
        what,
        if detail.is_empty() {
            None
        } else {
            Some(detail)
        },
    );
}

pub fn action_opt(what: &str, detail: Option<&str>) {
    match detail {
        None => write(&format!("[ACTION] {what}")),
        Some(d) => write(&format!("[ACTION] {what} | {d}")),
    }
}

pub fn action_clicked(page: &str, card: &str, label: &str) {
    if card == label {
        action_clicked_token(page, label);
    } else {
        action_clicked_token(page, &format!("{card}: {label}"));
    }
}

pub fn action_clicked_token(page: &str, action: &str) -> ActionToken {
    write(&format!("[ACTION] clicked [{action}] | page={page}"));
    let id = NEXT_ACTION_ID.fetch_add(1, Ordering::SeqCst);
    let open = OpenAction {
        id,
        page: page.to_string(),
        name: action.to_string(),
        started: Instant::now(),
        failures_at_start: crate::session_log::failure_count(),
    };
    let mut list = open_actions();
    list.push(open);
    if list.len() > 64 {
        list.remove(0);
    }
    ActionToken(id)
}

pub fn action_done(page: &str, operation_failed: bool, writes_failed: bool, detail: Option<&str>) {
    let open = {
        let mut list = open_actions();
        let latest = list
            .iter()
            .rposition(|o| o.page.eq_ignore_ascii_case(page))
            .map(|i| list.remove(i));
        list.retain(|o| !o.page.eq_ignore_ascii_case(page));
        latest
    };
    write_action_done(page, open, operation_failed, writes_failed, detail);
}

pub fn action_done_token(
    token: ActionToken,
    page: &str,
    operation_failed: bool,
    writes_failed: bool,
    detail: Option<&str>,
) {
    let open = {
        let mut list = open_actions();
        list.iter()
            .position(|o| o.id == token.0 && o.page.eq_ignore_ascii_case(page))
            .map(|i| list.remove(i))
    };
    write_action_done(page, open, operation_failed, writes_failed, detail);
}

fn write_action_done(
    page: &str,
    open: Option<OpenAction>,
    operation_failed: bool,
    writes_failed: bool,
    detail: Option<&str>,
) {
    let logged = open
        .as_ref()
        .map(|o| crate::session_log::failure_count().saturating_sub(o.failures_at_start))
        .unwrap_or(0);
    let outcome = if operation_failed {
        "FAILED"
    } else if writes_failed || logged > 0 {
        "PARTIAL"
    } else {
        "OK"
    };
    let mut line = match &open {
        None => format!("[RESULT] {outcome} {page}/(no click recorded)"),
        Some(o) => format!(
            "[RESULT] {outcome} {page}/{} {} ms",
            o.name,
            o.started.elapsed().as_millis()
        ),
    };
    if let Some(d) = detail {
        if !d.trim().is_empty() {
            line.push_str(" | ");
            line.push_str(&d.replace('\r', " ").replace('\n', " "));
        }
    }
    if logged > 0 {
        line.push_str(&format!(" | {logged} failure(s) logged during the action"));
    }
    write(&line);
}

pub fn op(text: &str) {
    write(&format!("[OP] {text}"));
}

pub fn op_detail(what: &str, detail: Option<&str>) {
    match detail {
        None => write(&format!("[OP] {what}")),
        Some(d) => write(&format!("[OP] {what} | {d}")),
    }
}

pub fn result(ok: bool, what: &str, detail: &str) {
    result_opt(
        ok,
        what,
        if detail.is_empty() {
            None
        } else {
            Some(detail)
        },
    );
}

pub fn result_opt(ok: bool, what: &str, detail: Option<&str>) {
    let head = format!("[RESULT] {} {what}", if ok { "OK" } else { "FAILED" });
    match detail {
        None => write(&head),
        Some(d) => write(&format!("{head} | {d}")),
    }
    if !ok {
        crate::session_log::operation_failed_opt(what, detail);
    }
}

pub fn perf(what: &str, ms: u128) {
    perf_detail(what, ms, None);
}

pub fn perf_detail(what: &str, ms: u128, detail: Option<&str>) {
    let head = format!("[PERF] {what} took {ms} ms");
    match detail {
        None => write(&head),
        Some(d) => write(&format!("{head} | {d}")),
    }
}

fn panic_text(p: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = p.downcast_ref::<&str>() {
        s.to_string()
    } else if let Some(s) = p.downcast_ref::<String>() {
        s.clone()
    } else {
        "panic".to_string()
    }
}

fn finish_timed(what: &str, started: Instant, ok: bool, detail: Option<&str>) {
    let elapsed: Duration = started.elapsed();
    result_opt(ok, what, detail);
    if elapsed.as_millis() >= SLOW_THRESHOLD_MS {
        perf_detail(what, elapsed.as_millis(), detail);
    }
}

pub fn timed<T>(
    what: &str,
    work: impl FnOnce() -> T,
    succeeded: Option<&dyn Fn(&T) -> bool>,
    detail: Option<&str>,
) -> T {
    let started = Instant::now();
    let value = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(work)) {
        Ok(v) => v,
        Err(p) => {
            write(&format!(
                "[RESULT] FAILED {what} | threw after {} ms | panic: {}",
                started.elapsed().as_millis(),
                panic_text(p.as_ref())
            ));
            std::panic::resume_unwind(p);
        }
    };
    let ok = succeeded.map(|f| f(&value)).unwrap_or(true);
    finish_timed(what, started, ok, detail);
    value
}

pub fn timed_result<T, E: std::fmt::Display>(
    what: &str,
    work: impl FnOnce() -> Result<T, E>,
    detail: Option<&str>,
) -> Result<T, E> {
    let started = Instant::now();
    let r = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(work)) {
        Ok(r) => r,
        Err(p) => {
            write(&format!(
                "[RESULT] FAILED {what} | threw after {} ms | panic: {}",
                started.elapsed().as_millis(),
                panic_text(p.as_ref())
            ));
            std::panic::resume_unwind(p);
        }
    };
    if let Err(e) = &r {
        write(&format!(
            "[RESULT] FAILED {what} | threw after {} ms | Error: {e}",
            started.elapsed().as_millis()
        ));
        return r;
    }
    finish_timed(what, started, true, detail);
    r
}

pub fn section(name: &str) {
    write(&format!("--- {name} ---"));
}

pub fn session_end(reason: &str) {
    write(&format!("=== XOS Toolkit session ended ({reason}) ==="));
}

pub fn exception(context: &str, error: &str) {
    log(&format!("[ERROR] {context}\r\n{error}"));
}

pub fn log_exception(context: &str, error: &dyn std::fmt::Debug) {
    exception(context, &format!("{error:?}"));
}

fn reg_text(key: &RegKey, name: &str) -> Option<String> {
    use winreg::enums::RegType;
    let raw = key.get_raw_value(name).ok()?;
    match raw.vtype {
        RegType::REG_DWORD if raw.bytes.len() >= 4 => Some(
            u32::from_le_bytes([raw.bytes[0], raw.bytes[1], raw.bytes[2], raw.bytes[3]])
                .to_string(),
        ),
        RegType::REG_SZ | RegType::REG_EXPAND_SZ => {
            let units: Vec<u16> = raw
                .bytes
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            Some(
                String::from_utf16_lossy(&units)
                    .trim_end_matches('\0')
                    .to_string(),
            )
        }
        _ => None,
    }
}

fn windows_description() -> String {
    let Ok(key) = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", KEY_READ)
    else {
        return "Windows".to_string();
    };
    let mut product = reg_text(&key, "ProductName").unwrap_or_else(|| "Windows".to_string());
    let display = reg_text(&key, "DisplayVersion");
    let build = reg_text(&key, "CurrentBuildNumber").unwrap_or_default();
    match build.trim().parse::<i32>() {
        Ok(n) if n >= 22000 => product = "Windows 11".to_string(),
        Ok(n) if n >= 10240 => product = "Windows 10".to_string(),
        _ => {}
    }
    let ubr = reg_text(&key, "UBR").unwrap_or_default();
    let full = if ubr.is_empty() {
        build
    } else {
        format!("{build}.{ubr}")
    };
    match display {
        Some(d) if !d.is_empty() => format!("{product} {d} build {full}"),
        _ => format!("{product} build {full}"),
    }
}

fn os_is_64bit() -> bool {
    cfg!(target_pointer_width = "64") || std::env::var_os("PROCESSOR_ARCHITEW6432").is_some()
}

fn system_directory() -> String {
    use windows::Win32::System::SystemInformation::GetSystemDirectoryW;
    let mut buf = [0u16; 260];
    let n = unsafe { GetSystemDirectoryW(Some(&mut buf)) } as usize;
    if n == 0 || n > buf.len() {
        return env_dir("SystemRoot")
            .map(|p| p.join("System32").display().to_string())
            .unwrap_or_default();
    }
    String::from_utf16_lossy(&buf[..n])
}

fn culture_name() -> String {
    use windows::Win32::Globalization::GetUserDefaultLocaleName;
    let mut buf = [0u16; 85];
    let n = unsafe { GetUserDefaultLocaleName(&mut buf) };
    if n <= 1 {
        return String::new();
    }
    String::from_utf16_lossy(&buf[..(n as usize - 1)])
}

fn ui_culture_name() -> String {
    use windows::Win32::Globalization::{GetUserDefaultUILanguage, LCIDToLocaleName};
    let lcid = unsafe { GetUserDefaultUILanguage() } as u32;
    let mut buf = [0u16; 85];
    let n = unsafe { LCIDToLocaleName(lcid, Some(&mut buf), 0) };
    if n <= 1 {
        return String::new();
    }
    String::from_utf16_lossy(&buf[..(n as usize - 1)])
}

fn account_sid() -> String {
    use windows::core::PWSTR;
    use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return "unknown".to_string();
        }
        let mut needed = 0u32;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut needed);
        let mut result = "unknown".to_string();
        if needed > 0 {
            let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
            if GetTokenInformation(
                token,
                TokenUser,
                Some(buf.as_mut_ptr() as *mut _),
                needed,
                &mut needed,
            )
            .is_ok()
            {
                let user = &*(buf.as_ptr() as *const TOKEN_USER);
                let mut s = PWSTR::null();
                if ConvertSidToStringSidW(user.User.Sid, &mut s).is_ok() {
                    result = s.to_string().unwrap_or_else(|_| "unknown".to_string());
                    let _ = LocalFree(Some(HLOCAL(s.0 as *mut _)));
                }
            }
        }
        let _ = CloseHandle(token);
        result
    }
}

fn is_elevated() -> &'static str {
    use windows::core::BOOL;
    use windows::Win32::Security::{
        CheckTokenMembership, CreateWellKnownSid, WinBuiltinAdministratorsSid, PSID,
    };
    unsafe {
        let mut size = 0u32;
        let _ = CreateWellKnownSid(WinBuiltinAdministratorsSid, None, None, &mut size);
        if size == 0 {
            return "unknown";
        }
        let mut buf = vec![0u8; size as usize];
        let sid = PSID(buf.as_mut_ptr() as *mut _);
        if CreateWellKnownSid(WinBuiltinAdministratorsSid, None, Some(sid), &mut size).is_err() {
            return "unknown";
        }
        let mut member = BOOL(0);
        if CheckTokenMembership(None, sid, &mut member).is_err() {
            return "unknown";
        }
        if member.as_bool() {
            "yes"
        } else {
            "no"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_helpers() {
        assert!(windows_description().contains("build"));
        assert!(account_sid().starts_with("S-1-"));
        assert!(matches!(is_elevated(), "yes" | "no"));
        assert!(!system_directory().is_empty());
        assert!(!culture_name().is_empty());
    }

    #[test]
    fn action_done_without_click() {
        action_done("LogTestPage", false, false, Some("a\nb"));
        let v = timed("log-test", || 5, Some(&|v: &i32| *v == 5), None);
        assert_eq!(v, 5);
        let r: Result<i32, String> = timed_result("log-test", || Err("x".to_string()), None);
        assert!(r.is_err());
    }
}

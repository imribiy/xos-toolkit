use std::io::Write;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Mutex;

use base64::Engine;
use windows::core::PCWSTR;
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::UI::Shell::{FOLDERID_Desktop, SHGetKnownFolderPath, KNOWN_FOLDER_FLAG};
use xos_core::{redact, session_log};

type PhaseCallback = Box<dyn Fn(&str) + Send + Sync>;

static UNINSTALL_LOG_PATH: Mutex<Option<String>> = Mutex::new(None);
static UNINSTALL_LOG_LOCK: Mutex<()> = Mutex::new(());
static ACTION_COMMAND_FAILURES: AtomicI32 = AtomicI32::new(0);
static PHASE_CALLBACK: Mutex<Option<PhaseCallback>> = Mutex::new(None);

pub fn windows_directory() -> String {
    std::env::var("SystemRoot")
        .or_else(|_| std::env::var("windir"))
        .unwrap_or_else(|_| r"C:\Windows".to_string())
}

pub fn system_directory() -> String {
    format!(r"{}\System32", windows_directory())
}

pub fn local_application_data() -> String {
    std::env::var("LOCALAPPDATA").unwrap_or_default()
}

pub fn common_application_data() -> String {
    std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string())
}

pub fn path_combine(a: &str, b: &str) -> String {
    if a.is_empty() {
        return b.to_string();
    }
    if b.is_empty() {
        return a.to_string();
    }
    if b.starts_with('\\') || b.starts_with('/') || b.as_bytes().get(1) == Some(&b':') {
        return b.to_string();
    }
    let last = a.chars().last().unwrap_or('\\');
    if last == '\\' || last == '/' || last == ':' {
        format!("{a}{b}")
    } else {
        format!(r"{a}\{b}")
    }
}

pub fn path_root(path: &str) -> Option<String> {
    let b = path.as_bytes();
    if b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic() {
        if b.len() >= 3 && (b[2] == b'\\' || b[2] == b'/') {
            return Some(path[..3].to_string());
        }
        return Some(path[..2].to_string());
    }
    if path.starts_with('\\') || path.starts_with('/') {
        return Some(path[..1].to_string());
    }
    None
}

pub fn encode_power_shell_command(script: &str) -> String {
    let bytes: Vec<u8> = script
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub fn new_guid_n() -> String {
    match unsafe { windows::Win32::System::Com::CoCreateGuid() } {
        Ok(g) => format!(
            "{:08x}{:04x}{:04x}{}",
            g.data1,
            g.data2,
            g.data3,
            g.data4
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ),
        Err(_) => {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            format!("{:032x}", nanos ^ ((std::process::id() as u128) << 64))
        }
    }
}

fn desktop_directory() -> Option<String> {
    unsafe {
        let p = SHGetKnownFolderPath(&FOLDERID_Desktop, KNOWN_FOLDER_FLAG(0), None).ok()?;
        let s = PCWSTR(p.0).to_string().ok();
        CoTaskMemFree(Some(p.0 as *const _));
        s
    }
}

pub fn begin_uninstall_log() -> Option<String> {
    let path = desktop_directory().map(|desktop| {
        path_combine(
            &desktop,
            &format!(
                "UninstallXOS-{}.log",
                chrono::Local::now().format("%Y-%m-%d_%H-%M-%S")
            ),
        )
    });
    set_uninstall_log_path(path.clone());
    path
}

pub fn set_uninstall_log_path(path: Option<String>) {
    *UNINSTALL_LOG_PATH.lock().unwrap() = path;
}

pub fn uninstall_log_path() -> Option<String> {
    UNINSTALL_LOG_PATH.lock().unwrap().clone()
}

pub fn end_uninstall_log() {
    set_uninstall_log_path(None);
}

pub fn set_uninstall_phase_callback(callback: Option<PhaseCallback>) {
    *PHASE_CALLBACK.lock().unwrap() = callback;
}

pub fn uninstall_phase_text(msg: &str) -> Option<String> {
    let len = msg.chars().count();
    if len > 8 && msg.starts_with("--- ") && msg.ends_with(" ---") {
        let inner: String = msg.chars().skip(4).take(len - 8).collect();
        let phase = inner.trim().to_lowercase();
        let mut chars = phase.chars();
        if let Some(first) = chars.next() {
            let phase: String = first.to_uppercase().chain(chars).collect();
            return Some(format!("Uninstalling XOS: {phase}..."));
        }
    }
    None
}

pub fn uninstall_log(msg: &str) {
    if let Some(text) = uninstall_phase_text(msg) {
        if let Some(cb) = PHASE_CALLBACK.lock().unwrap().as_ref() {
            cb(&text);
        }
    }

    let path = match uninstall_log_path() {
        Some(p) => p,
        None => return,
    };
    let _guard = UNINSTALL_LOG_LOCK.lock().unwrap();
    let line = format!(
        "[{}] {}\r\n",
        chrono::Local::now().format("%H:%M:%S%.3f"),
        redact::redact(msg)
    );
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = f.write_all(line.as_bytes());
    }
}

pub fn record_action_command(ok: bool) -> bool {
    if !ok {
        ACTION_COMMAND_FAILURES.fetch_add(1, Ordering::SeqCst);
    }
    ok
}

pub fn any_action_command_failed() -> bool {
    ACTION_COMMAND_FAILURES.load(Ordering::SeqCst) > 0
}

pub fn reset_action_command_tracker() {
    ACTION_COMMAND_FAILURES.store(0, Ordering::SeqCst);
}

pub fn fmt_val_int(v: Option<i32>) -> String {
    match v {
        Some(n) => n.to_string(),
        None => "(not set)".to_string(),
    }
}

pub fn fmt_val(v: Option<&str>) -> String {
    v.unwrap_or("(not set)").to_string()
}

pub fn is_hklm(key: &str) -> bool {
    let k = key.to_ascii_uppercase();
    k.starts_with("HKLM")
        || k.starts_with("HKEY_LOCAL_MACHINE")
        || k.starts_with("HKU")
        || k.starts_with("HKEY_USERS")
        || k.starts_with("HKCR")
        || k.starts_with("HKEY_CLASSES_ROOT")
}

pub fn skip_absent_feature(feature_name: &str) -> bool {
    if !xos_sys::is_feature_absent_on_this_build(feature_name) {
        return false;
    }
    session_log::operation_succeeded(
        &format!("command exit {}", xos_sys::FEATURE_NOT_AVAILABLE_TEXT),
        "dism.exe",
    );
    uninstall_log(&format!(
        "  {feature_name} is not available on this Windows build; skipped"
    ));
    true
}

pub fn registry_value_query_exit_code_as_ti(key: &str, value: &str) -> i32 {
    if xos_sys::reg_value_exists(key, value) {
        0
    } else {
        1
    }
}

pub fn registry_key_query_exit_code_as_ti(key: &str) -> i32 {
    if xos_sys::reg_key_exists(key) {
        0
    } else {
        1
    }
}

fn dword_and_string_text(key: &str, value: &str) -> String {
    let mut text = fmt_val_int(xos_sys::reg_get_dword(key, value));
    if let Some(s) = xos_sys::reg_get_string(key, value) {
        text.push('/');
        text.push_str(&s);
    }
    text
}

pub fn uninstall_reg_del(key: &str, value: &str) -> bool {
    uninstall_reg_del_optional(key, value, false)
}

pub fn uninstall_reg_del_optional(key: &str, value: &str, optional: bool) -> bool {
    let existed = xos_sys::reg_value_exists(key, value);
    let before = dword_and_string_text(key, value);
    let hklm = is_hklm(key);
    if !hklm && !existed {
        uninstall_log(&format!(
            "  DEL [{value}]: was={before}  now=(not set)  not found  -- {key}"
        ));
        return true;
    }
    if hklm && !existed {
        let query_exit_code = registry_value_query_exit_code_as_ti(key, value);
        if query_exit_code == 1 {
            uninstall_log(&format!(
                "  DEL [{value}]: was={before}  now=(not set)  not found  -- {key}"
            ));
            return true;
        }
        if query_exit_code != 0 {
            record_action_command(false);
            uninstall_log(&format!(
                "  DEL [{value}]: protected registry query failed ({query_exit_code})  -- {key}"
            ));
            return false;
        }
    }

    if hklm {
        xos_sys::run_as_ti_output("reg.exe", &format!("delete \"{key}\" /v \"{value}\" /f"));
    } else {
        xos_sys::reg_delete_value(key, value);
    }
    let verified = if hklm {
        registry_value_query_exit_code_as_ti(key, value) == 1
    } else {
        !xos_sys::reg_value_exists(key, value)
    };
    if optional && !verified {
        let still_there = dword_and_string_text(key, value);
        uninstall_log(&format!(
            "  DEL [{value}]: was={before}  now={still_there}  held by the running Defender engine, left as it is  -- {key}"
        ));
        return true;
    }
    record_action_command(verified);
    let after = dword_and_string_text(key, value);
    uninstall_log(&format!(
        "  DEL [{value}]: was={before}  now={after}  {}  -- {key}",
        if verified { "OK" } else { "FAILED" }
    ));
    verified
}

pub fn defender_del(key: &str, value: &str, engine_running: bool) -> bool {
    let current = xos_sys::reg_get_dword(key, value);
    let owned_by_running_engine = engine_running
        && !key
            .to_ascii_uppercase()
            .starts_with(r"HKLM\SOFTWARE\POLICIES\")
        && (current == Some(0)
            || (current == Some(2) && value.eq_ignore_ascii_case("SpyNetReporting")));
    uninstall_reg_del_optional(key, value, owned_by_running_engine)
}

pub fn uninstall_reg_del_key(key: &str) -> bool {
    let existed = xos_sys::reg_key_exists(key);
    let hklm = is_hklm(key);
    if !hklm && !existed {
        uninstall_log(&format!("  DELKEY: not found  -- {key}"));
        return true;
    }
    if hklm && !existed {
        let query_exit_code = registry_key_query_exit_code_as_ti(key);
        if query_exit_code == 1 {
            uninstall_log(&format!("  DELKEY: not found  -- {key}"));
            return true;
        }
        if query_exit_code != 0 {
            record_action_command(false);
            uninstall_log(&format!(
                "  DELKEY: protected registry query failed ({query_exit_code})  -- {key}"
            ));
            return false;
        }
    }

    if hklm {
        xos_sys::run_as_ti_output("reg.exe", &format!("delete \"{key}\" /f"));
    } else {
        xos_sys::reg_delete_key(key);
    }
    let verified = if hklm {
        registry_key_query_exit_code_as_ti(key) == 1
    } else {
        !xos_sys::reg_key_exists(key)
    };
    record_action_command(verified);
    uninstall_log(&format!(
        "  DELKEY: {}  -- {key}",
        if verified { "OK" } else { "FAILED" }
    ));
    verified
}

pub fn uninstall_delete_service_stub_key(service: &str) -> bool {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
    use winreg::RegKey;

    let path = format!(r"SYSTEM\CurrentControlSet\Services\{service}");
    let stub;
    let start: Option<i32>;
    match RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(&path, KEY_READ) {
        Ok(key) => {
            stub = xos_sys::is_start_only_service_stub(Some(&key));
            start = if stub {
                key.get_value::<u32, _>("Start").ok().map(|v| v as i32)
            } else {
                None
            };
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return true,
        Err(e) => {
            uninstall_log(&format!(
                "  {service}: service key could not be read ({e}), left as it is"
            ));
            return true;
        }
    }
    if !stub {
        return true;
    }
    uninstall_log(&format!(
        "  {service}: key holds only Start={} with no Type, ImagePath or subkeys (an earlier XOS write on a build without this service); deleting it",
        fmt_val_int(start)
    ));
    uninstall_reg_del_key(&format!(
        r"HKLM\SYSTEM\CurrentControlSet\Services\{service}"
    ))
}

pub fn uninstall_reg_set(key: &str, value: &str, data: i32) -> bool {
    let before = fmt_val_int(xos_sys::reg_get_dword(key, value));
    let ok = if is_hklm(key) {
        xos_sys::run_as_ti(
            "reg.exe",
            &format!("add \"{key}\" /v \"{value}\" /t REG_DWORD /d {data} /f"),
        )
    } else {
        xos_sys::reg_set_dword(key, value, data)
    };
    let actual = xos_sys::reg_get_dword(key, value);
    let verified = actual == Some(data);
    record_action_command(verified);
    let after = fmt_val_int(actual);
    uninstall_log(&format!(
        "  SET [{value}]: {before} -> {data}  actual={after}  {}  -- {key}",
        verdict_text(ok, verified)
    ));
    verified
}

pub fn uninstall_reg_set_str(key: &str, value: &str, data: &str) -> bool {
    let before = fmt_val(xos_sys::reg_get_string(key, value).as_deref());
    let ok = if is_hklm(key) {
        xos_sys::run_as_ti(
            "reg.exe",
            &format!("add \"{key}\" /v \"{value}\" /t REG_SZ /d \"{data}\" /f"),
        )
    } else {
        xos_sys::reg_set_string(key, value, data)
    };
    let actual = xos_sys::reg_get_string(key, value);
    let verified = actual
        .as_deref()
        .map(|a| a.to_lowercase() == data.to_lowercase())
        .unwrap_or(false);
    record_action_command(verified);
    let after = fmt_val(actual.as_deref());
    uninstall_log(&format!(
        "  SETSTR [{value}]: {before} -> {data}  actual={after}  {}  -- {key}",
        verdict_text(ok, verified)
    ));
    verified
}

pub fn verdict_text(wrote: bool, verified: bool) -> &'static str {
    match (verified, wrote) {
        (true, true) => "OK",
        (true, false) => "OK (already as requested; the write was refused)",
        (false, _) => "FAILED",
    }
}

pub fn uninstall_reg_set_exp(key: &str, value: &str, data: &str) -> bool {
    let before = fmt_val(xos_sys::reg_get_string(key, value).as_deref());
    let ok = if is_hklm(key) {
        xos_sys::run_as_ti(
            "reg.exe",
            &format!("add \"{key}\" /v \"{value}\" /t REG_EXPAND_SZ /d \"{data}\" /f"),
        )
    } else {
        xos_sys::reg_set_expand_string(key, value, data)
    };
    let actual = xos_sys::reg_get_string(key, value);
    let expanded = xos_sys::expand_environment_variables(data);
    let verified = ok
        && actual
            .as_deref()
            .map(|a| {
                let a = a.to_lowercase();
                a == data.to_lowercase() || a == expanded.to_lowercase()
            })
            .unwrap_or(false);
    record_action_command(verified);
    let after = fmt_val(actual.as_deref());
    uninstall_log(&format!(
        "  SETEXP [{value}]: {before} -> {data}  actual={after}  {}  -- {key}",
        if verified { "OK" } else { "FAILED" }
    ));
    verified
}

pub fn stock_disabled_tasks(build: i32) -> Vec<String> {
    let mut stock_disabled: Vec<String> = vec![
        r"\Microsoft\Windows\InstallService\WakeUpAndContinueUpdates".to_string(),
        r"\Microsoft\Windows\InstallService\WakeUpAndScanForUpdates".to_string(),
        r"\Microsoft\Windows\UpdateOrchestrator\Schedule Maintenance Work".to_string(),
        r"\Microsoft\Windows\UpdateOrchestrator\Schedule Wake To Work".to_string(),
        r"\Microsoft\Windows\UpdateOrchestrator\Reboot_AC".to_string(),
        r"\Microsoft\Windows\UpdateOrchestrator\Reboot_Battery".to_string(),
    ];
    if build != 26200 {
        stock_disabled.push(r"\Microsoft\Windows\Printing\PrintJobCleanupTask".to_string());
    }
    stock_disabled.push(r"\Microsoft\Windows\MemoryDiagnostic\RunFullMemoryDiagnostic".to_string());
    stock_disabled
}

pub fn without_stock_disabled_tasks<S: AsRef<str>>(tasks: &[S]) -> Vec<String> {
    let stock_disabled: std::collections::HashSet<String> =
        stock_disabled_tasks(xos_sys::get_windows_build_number())
            .into_iter()
            .map(|t| t.to_lowercase())
            .collect();
    tasks
        .iter()
        .filter(|t| !stock_disabled.contains(&t.as_ref().to_lowercase()))
        .map(|t| t.as_ref().to_string())
        .collect()
}

pub fn escape_power_shell_literal(value: &str) -> String {
    value.replace('\'', "''")
}

pub fn run_encoded_power_shell_as_ti(script: &str, timeout_ms: u32) -> bool {
    let encoded = encode_power_shell_command(script);
    xos_sys::run_as_ti_timeout(
        "powershell.exe",
        &format!("-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}"),
        timeout_ms,
    )
}

pub fn run_encoded_power_shell_as_ti_default(script: &str) -> bool {
    run_encoded_power_shell_as_ti(script, 300000)
}

pub fn uninstall_log_run_ti(tag: &str, exe: &str, args: &str, required: bool) -> bool {
    uninstall_log(&format!("  {tag}"));
    let (code, output) = xos_sys::run_as_ti_output(exe, args);
    if required {
        record_action_command(code == 0);
    }
    let out_line = if output.trim().is_empty() {
        "(no output)".to_string()
    } else {
        output.replace("\r\n", " | ").replace('\n', " | ")
    };
    uninstall_log(&format!("    EXIT:{code}  {out_line}"));
    code == 0
}

pub fn uninstall_reg_restore_captured_hkcu(sub_key: &str, value: &str) -> bool {
    let captured = xos_sys::reg_get_string(
        r"HKCU\Software\XOSToolkit\StockValues",
        &format!(r"{sub_key}\{value}"),
    );
    if let Some(text) = captured.as_deref() {
        if let Ok(data) = text.trim().parse::<i32>() {
            uninstall_log(&format!("  [{value}]: install-time capture {data}"));
            return uninstall_reg_set(&format!(r"HKCU\{sub_key}"), value, data);
        }
    }
    uninstall_log(&format!(
        "  [{value}]: install-time capture {}, removing XOS's value",
        captured.as_deref().unwrap_or("none")
    ));
    uninstall_reg_del(&format!(r"HKCU\{sub_key}"), value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fmt_values() {
        assert_eq!(fmt_val_int(None), "(not set)");
        assert_eq!(fmt_val_int(Some(3)), "3");
        assert_eq!(fmt_val(None), "(not set)");
        assert_eq!(fmt_val(Some("x")), "x");
    }

    #[test]
    fn phase_text() {
        assert_eq!(
            uninstall_phase_text("--- EVENT CHANNELS ---"),
            Some("Uninstalling XOS: Event channels...".to_string())
        );
        assert_eq!(uninstall_phase_text("--- ---"), None);
        assert_eq!(uninstall_phase_text("plain"), None);
    }

    #[test]
    fn hklm_detection() {
        assert!(is_hklm(r"HKLM\SOFTWARE"));
        assert!(is_hklm(r"hkcr\x"));
        assert!(!is_hklm(r"HKCU\x"));
    }

    #[test]
    fn stock_tasks_depend_on_build() {
        assert_eq!(stock_disabled_tasks(26200).len(), 7);
        assert_eq!(stock_disabled_tasks(26300).len(), 8);
    }

    #[test]
    fn encoded_command_is_utf16_base64() {
        assert_eq!(encode_power_shell_command("a"), "YQA=");
    }

    #[test]
    fn path_helpers() {
        assert_eq!(path_combine(r"C:\Windows", "Temp"), r"C:\Windows\Temp");
        assert_eq!(path_root(r"C:\Windows"), Some(r"C:\".to_string()));
    }
}

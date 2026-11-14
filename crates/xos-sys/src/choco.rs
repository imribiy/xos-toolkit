use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex, OnceLock};
use std::thread::ThreadId;
use std::time::Instant;

use regex::Regex;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{HANDLE, HWND, LPARAM, WAIT_ABANDONED, WAIT_OBJECT_0, WPARAM};
use windows::Win32::System::Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject};
use windows::Win32::UI::WindowsAndMessaging::{
    SendMessageTimeoutW, HWND_BROADCAST, SMTO_ABORTIFHUNG, WM_SETTINGCHANGE,
};
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE, REG_EXPAND_SZ};
use winreg::{RegKey, RegValue};

use crate::ci_map::CiMap;
use crate::process::{
    run_cmd_capture_opts, run_cmd_opts, run_cmd_visible_timeout, spawn_hidden,
    terminate_process_tree, wait_for_exit, CmdOptions,
};
use crate::reg::key_get_string;
use crate::util::{
    expand_environment_variables, full_path, path_combine, path_root, program_data_dir, wide,
    windows_dir,
};
use xos_core::{log, session_log};

pub fn get_choco_path() -> Option<String> {
    if let Ok(configured_root) = std::env::var("ChocolateyInstall") {
        if !configured_root.trim().is_empty() {
            let configured = path_combine(
                &path_combine(configured_root.trim().trim_matches('"'), "bin"),
                "choco.exe",
            );
            if std::path::Path::new(&configured).is_file() {
                return Some(configured);
            }
        }
    }

    let default_path = r"C:\ProgramData\chocolatey\bin\choco.exe";
    if std::path::Path::new(default_path).is_file() {
        return Some(default_path.to_string());
    }
    let legacy_path = r"C:\Program Files\Chocolatey\bin\choco.exe";
    if std::path::Path::new(legacy_path).is_file() {
        return Some(legacy_path.to_string());
    }

    let path_env = std::env::var("PATH").unwrap_or_default();
    for dir in path_env.split(';') {
        if dir.trim().is_empty() {
            continue;
        }
        let expanded = expand_environment_variables(dir.trim().trim_matches('"'));
        if expanded.trim().is_empty() {
            continue;
        }
        let p = path_combine(&expanded, "choco.exe");
        if std::path::Path::new(&p).is_file() {
            return Some(p);
        }
    }
    None
}

pub fn is_choco_installed() -> bool {
    match get_choco_path() {
        Some(c) => try_get_choco_major_version(&c).is_some(),
        None => false,
    }
}

struct ReentrantOwner {
    owner: Option<ThreadId>,
    count: usize,
}

fn owner() -> &'static (Mutex<ReentrantOwner>, Condvar) {
    static O: OnceLock<(Mutex<ReentrantOwner>, Condvar)> = OnceLock::new();
    O.get_or_init(|| {
        (
            Mutex::new(ReentrantOwner {
                owner: None,
                count: 0,
            }),
            Condvar::new(),
        )
    })
}

fn process_mutex() -> isize {
    static M: OnceLock<isize> = OnceLock::new();
    *M.get_or_init(|| {
        let name = wide(r"Local\XOSToolkit.Chocolatey.Operation");
        unsafe {
            CreateMutexW(None, false, PCWSTR(name.as_ptr()))
                .map(|h| h.0 as isize)
                .unwrap_or(0)
        }
    })
}

pub struct ChocolateyOperation {
    owns_mutex: AtomicBool,
}

pub fn enter_chocolatey_operation() -> ChocolateyOperation {
    let me = std::thread::current().id();
    {
        let (lock, cv) = owner();
        let mut g = lock.lock().unwrap();
        while g.owner.is_some() && g.owner != Some(me) {
            g = cv.wait(g).unwrap();
        }
        g.owner = Some(me);
        g.count += 1;
    }
    let mut owns = false;
    let h = process_mutex();
    if h != 0 {
        let r = unsafe { WaitForSingleObject(HANDLE(h as *mut _), u32::MAX) };
        owns = r == WAIT_OBJECT_0 || r == WAIT_ABANDONED;
    }
    ChocolateyOperation {
        owns_mutex: AtomicBool::new(owns),
    }
}

impl Drop for ChocolateyOperation {
    fn drop(&mut self) {
        if self.owns_mutex.swap(false, Ordering::SeqCst) {
            unsafe {
                let _ = ReleaseMutex(HANDLE(process_mutex() as *mut _));
            }
        }
        let (lock, cv) = owner();
        let mut g = lock.lock().unwrap();
        g.count -= 1;
        if g.count == 0 {
            g.owner = None;
            cv.notify_one();
        }
    }
}

pub fn install_choco() -> bool {
    let _guard = enter_chocolatey_operation();
    install_choco_while_locked()
}

pub fn install_choco_while_locked() -> bool {
    let existing = get_choco_path();
    if let Some(e) = &existing {
        if try_get_choco_major_version(e).is_some() {
            return true;
        }
        log::log("[CHOCO] Existing executable is not healthy. Removing the broken installation.");
        remove_chocolatey_while_locked();
    }
    let ps = "[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))";
    let mut sp = match spawn_hidden(
        "powershell.exe",
        &format!("-NoProfile -ExecutionPolicy Bypass -Command \"{ps}\""),
        false,
    ) {
        Ok(s) => s,
        Err(_) => return false,
    };
    if !wait_for_exit(&sp.child, 300000) {
        terminate_process_tree(&mut sp.child);
        sp.out.collect(5000);
        sp.err.collect(5000);
    } else {
        sp.out.wait_all();
        sp.err.wait_all();
    }
    drop(sp);
    is_choco_installed()
}

fn choco_version_cache() -> &'static Mutex<(i32, Option<String>)> {
    static C: OnceLock<Mutex<(i32, Option<String>)>> = OnceLock::new();
    C.get_or_init(|| Mutex::new((0, None)))
}

pub(crate) fn try_parse_version_major(text: &str) -> Option<i32> {
    let parts: Vec<&str> = text.trim().split('.').collect();
    if parts.len() < 2 || parts.len() > 4 {
        return None;
    }
    let mut nums = Vec::new();
    for p in &parts {
        if p.is_empty() || !p.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        nums.push(p.parse::<i32>().ok()?);
    }
    if nums[0] > 0 {
        Some(nums[0])
    } else {
        None
    }
}

fn try_get_choco_major_version(choco: &str) -> Option<i32> {
    if choco.trim().is_empty() || !std::path::Path::new(choco).is_file() {
        return None;
    }
    {
        let c = choco_version_cache().lock().unwrap();
        if c.0 > 0 {
            if let Some(p) = &c.1 {
                if p.eq_ignore_ascii_case(choco) {
                    return Some(c.0);
                }
            }
        }
    }
    let result = run_cmd_capture_opts(choco, "--version", 30000, false);
    if result.0 != 0 {
        return None;
    }
    for line in result.1.split(['\r', '\n']).filter(|l| !l.is_empty()) {
        if let Some(major) = try_parse_version_major(line) {
            let mut c = choco_version_cache().lock().unwrap();
            c.0 = major;
            c.1 = Some(choco.to_string());
            return Some(major);
        }
    }
    None
}

pub fn get_choco_installed_packages() -> anyhow::Result<CiMap<bool>> {
    let _guard = enter_chocolatey_operation();
    let mut dict = CiMap::new();
    let choco = get_choco_path();
    let major = choco.as_deref().and_then(try_get_choco_major_version);
    let (choco, major) = match (choco, major) {
        (Some(c), Some(m)) => (c, m),
        _ => anyhow::bail!("Chocolatey is missing or not working."),
    };
    let args = if major <= 1 {
        "list --local-only --limit-output"
    } else {
        "list --limit-output"
    };
    let command = run_cmd_capture_opts(&choco, args, 120000, false);
    if command.0 != 0 {
        let detail = if !command.2.trim().is_empty() {
            command.2.trim().to_string()
        } else {
            "Chocolatey package inventory failed.".to_string()
        };
        anyhow::bail!("{detail}");
    }
    for line in command.1.split(['\r', '\n']).filter(|l| !l.is_empty()) {
        if !line.contains('|') {
            continue;
        }
        let pkg = line.split('|').next().unwrap_or("").trim();
        if !pkg.is_empty() {
            dict.insert(pkg, true);
        }
    }
    Ok(dict)
}

fn is_safe_chocolatey_package_id(package_id: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    let r = R.get_or_init(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._-]*$").unwrap());
    !package_id.trim().is_empty() && r.is_match(package_id.trim())
}

fn choco_package_operation(verb: &str, package_id: &str, args_tail: &str, timeout: u32) -> bool {
    let package_id = package_id.trim();
    let what = format!("choco {verb} {package_id}");
    if !is_safe_chocolatey_package_id(package_id) {
        log::result(false, &what, "invalid package id");
        return false;
    }
    let _guard = enter_chocolatey_operation();
    let sw = Instant::now();
    let choco = match get_choco_path() {
        Some(c) => c,
        None => {
            log::result(false, &what, "choco.exe not found");
            return false;
        }
    };
    if try_get_choco_major_version(&choco).is_none() {
        log::result(false, &what, "choco.exe did not report a version");
        return false;
    }
    log::op(&what);
    let ok = run_cmd_visible_timeout(&choco, &format!("{verb} {package_id}{args_tail}"), timeout);
    log::result(ok, &what, &format!("{} ms", sw.elapsed().as_millis()));
    ok
}

pub fn choco_install(package_id: &str) -> bool {
    choco_package_operation("install", package_id, " -y --ignore-checksums", 600000)
}

pub fn choco_uninstall(package_id: &str) -> bool {
    choco_package_operation("uninstall", package_id, " -y", 300000)
}

pub fn remove_chocolatey() {
    let _guard = enter_chocolatey_operation();
    remove_chocolatey_while_locked();
}

fn broadcast_environment_change() {
    let env = wide("Environment");
    unsafe {
        let mut result = 0usize;
        let _ = SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            WPARAM(0),
            LPARAM(env.as_ptr() as isize),
            SMTO_ABORTIFHUNG,
            1000,
            Some(&mut result),
        );
        let _ = HWND::default();
    }
}

fn environment_key(machine: bool, write: bool) -> Option<RegKey> {
    let flags = if write {
        KEY_READ | KEY_WRITE
    } else {
        KEY_READ
    };
    if machine {
        RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey_with_flags(
                r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
                flags,
            )
            .ok()
    } else {
        RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags("Environment", flags)
            .ok()
    }
}

fn remove_chocolatey_while_locked() {
    log::log("[CHOCO] RemoveChocolatey: starting thorough cleanup");
    {
        let mut c = choco_version_cache().lock().unwrap();
        c.0 = 0;
        c.1 = None;
    }

    for proc in ["choco", "cpack", "cup", "cinst", "clist", "ChocolateyGui"] {
        run_cmd_opts(
            "taskkill.exe",
            &format!("/f /im {proc}.exe"),
            &CmdOptions {
                timeout_ms: Some(10000),
                suppress_log: true,
                ..Default::default()
            },
        );
    }

    let app_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_string_lossy().to_string()))
        .unwrap_or_default();
    let msi = path_combine(&path_combine(&app_dir, "Bundled"), "chocolatey-2.7.1.0.msi");
    if std::path::Path::new(&msi).is_file() {
        let result = run_cmd_capture_opts(
            "msiexec.exe",
            &format!("/x \"{msi}\" /qn /norestart"),
            120000,
            false,
        );
        let accepted = matches!(result.0, 0 | 1605 | 1614 | 1641 | 3010);
        log::log(&format!(
            "[CHOCO] MSI unregister exit {}{}",
            result.0,
            if accepted && result.0 != 0 {
                " treated as already absent or reboot-required"
            } else {
                ""
            }
        ));
        if !accepted {
            session_log::operation_failed("Chocolatey MSI unregister", &result.0.to_string());
        }
    }

    let mut dirs: Vec<String> = vec![
        r"C:\ProgramData\chocolatey".to_string(),
        r"C:\Program Files\Chocolatey".to_string(),
    ];
    if let Ok(env_install) = std::env::var("ChocolateyInstall") {
        if !env_install.is_empty() {
            dirs.push(env_install);
        }
    }
    let mut distinct: Vec<String> = Vec::new();
    for d in &dirs {
        if !distinct.iter().any(|e| e.eq_ignore_ascii_case(d)) {
            distinct.push(d.clone());
        }
    }
    for dir in &distinct {
        if !std::path::Path::new(dir).is_dir() {
            continue;
        }
        if !is_safe_chocolatey_directory(dir) {
            log::log(&format!(
                "[CHOCO] Refused unsafe install-directory cleanup target: {dir}"
            ));
            continue;
        }
        run_cmd_opts(
            "cmd.exe",
            &format!("/c rd /s /q \"{dir}\""),
            &CmdOptions {
                timeout_ms: Some(60000),
                ..Default::default()
            },
        );
    }

    for name in [
        "ChocolateyInstall",
        "ChocolateyLastPathUpdate",
        "ChocolateyToolsLocation",
        "ChocolateyBinRoot",
    ] {
        for machine in [true, false] {
            if let Some(k) = environment_key(machine, true) {
                let _ = k.delete_value(name);
            }
        }
    }
    broadcast_environment_change();

    for machine in [true, false] {
        remove_chocolatey_path_entries(machine, &dirs);
    }

    log::log("[CHOCO] RemoveChocolatey: cleanup complete");
}

fn trim_end_sep(s: &str) -> String {
    s.trim_end_matches(['\\', '/']).to_string()
}

fn is_safe_chocolatey_directory(path: &str) -> bool {
    let full = match full_path(path.trim().trim_matches('"')) {
        Some(f) => trim_end_sep(&f),
        None => return false,
    };
    let root = trim_end_sep(&path_root(&full));
    if full.is_empty() || full.eq_ignore_ascii_case(&root) {
        return false;
    }

    let protected_paths = [
        windows_dir(),
        std::env::var("ProgramFiles").unwrap_or_default(),
        std::env::var("ProgramFiles(x86)").unwrap_or_default(),
        program_data_dir().to_string_lossy().to_string(),
        std::env::var("USERPROFILE").unwrap_or_default(),
    ];
    if protected_paths
        .iter()
        .any(|p| !p.trim().is_empty() && full.eq_ignore_ascii_case(&trim_end_sep(p)))
    {
        return false;
    }

    let leaf = full.rsplit(['\\', '/']).next().unwrap_or("").to_string();
    leaf.to_lowercase().contains("choco")
        || std::path::Path::new(&path_combine(&path_combine(&full, "bin"), "choco.exe")).is_file()
}

fn remove_chocolatey_path_entries(machine: bool, chocolatey_directories: &[String]) {
    let scope = if machine { "Machine" } else { "User" };
    let attempt = || -> Result<(), String> {
        let environment = match environment_key(machine, true) {
            Some(e) => e,
            None => return Ok(()),
        };
        let has_path = environment
            .enum_values()
            .filter_map(|r| r.ok())
            .any(|(n, _)| n.eq_ignore_ascii_case("Path"));
        if !has_path {
            return Ok(());
        }
        let path = match key_get_string(&environment, "Path", false) {
            Some(p) if !p.is_empty() => p,
            _ => return Ok(()),
        };
        let mut roots: Vec<String> = Vec::new();
        for dir in chocolatey_directories
            .iter()
            .filter(|d| !d.trim().is_empty())
        {
            let full = full_path(dir.trim().trim_matches('"'))
                .ok_or_else(|| "The path is not of a legal form.".to_string())?;
            let r = trim_end_sep(&full);
            if !roots.iter().any(|e| e.eq_ignore_ascii_case(&r)) {
                roots.push(r);
            }
        }
        let kept: Vec<&str> = path
            .split(';')
            .filter(|segment| {
                if segment.trim().is_empty() {
                    return true;
                }
                let candidate = match full_path(&expand_environment_variables(
                    segment.trim().trim_matches('"'),
                )) {
                    Some(c) => trim_end_sep(&c),
                    None => return true,
                };
                let lower = candidate.to_lowercase();
                !roots.iter().any(|root| {
                    let rl = root.to_lowercase();
                    lower == rl || lower.starts_with(&format!("{rl}\\"))
                })
            })
            .collect();
        let cleaned = kept.join(";");
        if cleaned == path {
            return Ok(());
        }
        let raw = environment
            .get_raw_value("Path")
            .map_err(|e| crate::util::io_message(&e))?;
        let kind = raw.vtype.clone();
        let bytes: Vec<u8> = cleaned
            .encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let kind_name = if kind == REG_EXPAND_SZ {
            "ExpandString"
        } else {
            "String"
        };
        environment
            .set_raw_value(
                "Path",
                &RegValue {
                    bytes: bytes.into(),
                    vtype: kind,
                },
            )
            .map_err(|e| crate::util::io_message(&e))?;
        log::log(&format!(
            "[CHOCO] Removed only PATH entries under known Chocolatey roots ({scope}); registry type preserved as {kind_name}."
        ));
        Ok(())
    };
    if let Err(m) = attempt() {
        log::log(&format!("[CHOCO] PATH clean ({scope}) skipped: {m}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_ids() {
        assert!(is_safe_chocolatey_package_id("7zip.install"));
        assert!(is_safe_chocolatey_package_id(" vcredist-all "));
        assert!(!is_safe_chocolatey_package_id("-bad"));
        assert!(!is_safe_chocolatey_package_id("a b"));
        assert!(!is_safe_chocolatey_package_id("a;b"));
        assert!(!is_safe_chocolatey_package_id(""));
    }

    #[test]
    fn versions() {
        assert_eq!(try_parse_version_major("2.7.1"), Some(2));
        assert_eq!(try_parse_version_major(" 1.4.0.0 "), Some(1));
        assert_eq!(try_parse_version_major("2"), None);
        assert_eq!(try_parse_version_major("0.1"), None);
        assert_eq!(try_parse_version_major("v2.1"), None);
    }
}

use std::path::Path;
use std::time::Instant;

use regex::Regex;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{
    GetTokenInformation, LookupAccountSidW, TokenUser, SID_NAME_USE, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::System::RemoteDesktop::{
    ProcessIdToSessionId, WTSFreeMemory, WTSQuerySessionInformationW, WTS_INFO_CLASS,
};
use windows::Win32::System::Threading::{GetCurrentProcess, GetCurrentProcessId, OpenProcessToken};
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
use xos_core::log;
use xos_sys::{get_windows_build_number, run_cmd_capture_opts, run_cmd_output_timeout};

use crate::util::{encode_powershell, env_path, wide};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Skipped,
    Present,
    Installed,
    Failed,
}

pub const PACKAGE_NAME: &str = "MicrosoftWindows.Client.WebExperience";
pub const STORE_PRODUCT_ID: &str = "9MSSGKG348SP";
pub const STORE_URI: &str = "ms-windows-store://pdp/?productid=9MSSGKG348SP";
const INSTALL_TIMEOUT_MS: u32 = 120000;

pub fn applies() -> bool {
    get_windows_build_number() >= 22000
}

pub fn parse_probe_output(output: &str) -> (Option<bool>, Option<bool>) {
    let re = Regex::new(r"STORE=(\d+) WEB=(\d+)").unwrap();
    match re.captures(output) {
        None => (None, None),
        Some(m) => (Some(&m[1] != "0"), Some(&m[2] != "0")),
    }
}

pub fn probe() -> (Option<bool>, Option<bool>) {
    let script = format!(
        "$ErrorActionPreference='Stop';try{{$s=@(Get-AppxPackage -Name 'Microsoft.WindowsStore').Count;$w=@(Get-AppxPackage -Name '{PACKAGE_NAME}').Count;\"STORE=$s WEB=$w\"}}catch{{'UNKNOWN'}}"
    );
    let encoded = encode_powershell(&script);
    let output = run_cmd_output_timeout(
        "powershell.exe",
        &format!("-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}"),
        60000,
    );
    parse_probe_output(&output)
}

pub fn winget_path() -> Option<String> {
    let path = Path::new(&env_path("LOCALAPPDATA")).join(r"Microsoft\WindowsApps\winget.exe");
    if path.is_file() {
        Some(path.to_string_lossy().to_string())
    } else {
        None
    }
}

pub fn ensure_installed() -> (Outcome, String, bool) {
    let probe_result = probe();
    let can_open_store = probe_result.0 == Some(true);
    if probe_result.0 == Some(false) {
        let detail = "Microsoft Store not installed for this account, app step skipped".to_string();
        log::result(true, "Widgets app check", &detail);
        return (Outcome::Skipped, detail, can_open_store);
    }
    if probe_result.1 == Some(true) {
        let detail = "already installed".to_string();
        log::result(
            true,
            "Widgets app check",
            &format!("{PACKAGE_NAME} {detail}"),
        );
        return (Outcome::Present, detail, can_open_store);
    }

    let winget = winget_path();
    log::op_detail(
        "Widgets app install",
        Some(&format!(
            "{PACKAGE_NAME}, Store product {STORE_PRODUCT_ID}, {}{}, {}",
            if probe_result.1.is_none() {
                "presence could not be read"
            } else {
                "not installed"
            },
            if winget.is_none() {
                ", winget not found"
            } else {
                ", through winget msstore"
            },
            account_detail()
        )),
    );
    let winget = match winget {
        Some(w) => w,
        None => {
            let detail =
                "winget is not available on this Windows, so it could not be installed automatically"
                    .to_string();
            log::result(false, "Widgets app install", &detail);
            return (Outcome::Failed, detail, can_open_store);
        }
    };

    let sw = Instant::now();
    let (exit_code, output, error) = run_cmd_capture_opts(
        &winget,
        &format!(
            "install --id {STORE_PRODUCT_ID} --source msstore --accept-package-agreements --accept-source-agreements --silent"
        ),
        INSTALL_TIMEOUT_MS,
        false,
    );
    log::perf_detail(
        "Widgets app install",
        sw.elapsed().as_millis(),
        Some(&format!("winget exit {}", format_exit(exit_code))),
    );

    if probe().1 == Some(true) {
        let detail = "installed from the Microsoft Store".to_string();
        log::result(
            true,
            "Widgets app install",
            &format!(
                "{PACKAGE_NAME} {detail} (winget exit {})",
                format_exit(exit_code)
            ),
        );
        return (Outcome::Installed, detail, can_open_store);
    }

    let mut reason = if exit_code == -1 {
        if error.trim().is_empty() {
            "winget did not start".to_string()
        } else {
            error.trim().to_string()
        }
    } else if exit_code == 0 {
        "winget reported success but the package is not installed".to_string()
    } else {
        format!("winget exit {}", format_exit(exit_code))
    };
    let last = last_line(&output);
    if !last.is_empty() && exit_code != 0 {
        reason.push_str(&format!(": {last}"));
    }
    let detail = format!("the Microsoft Store install through winget failed ({reason})");
    log::result(false, "Widgets app install", &detail);
    (Outcome::Failed, detail, can_open_store)
}

pub fn remove() -> (bool, String) {
    log::op_detail(
        "Widgets app removal",
        Some(&format!(
            "{PACKAGE_NAME}, all users and deprovisioned, as the playbook removes it, {}",
            account_detail()
        )),
    );
    let sw = Instant::now();
    let (success, error) = xos_helpers::appx_removal::remove(PACKAGE_NAME, None, 120000, None);
    log::perf("Widgets app removal", sw.elapsed().as_millis());
    let installed = probe().1;
    let ok = success && installed == Some(false);
    let detail = if ok {
        "removed for all users and deprovisioned".to_string()
    } else if !success {
        error.unwrap_or_default()
    } else if installed == Some(true) {
        "the package is still installed for this account".to_string()
    } else {
        "whether the package is gone could not be read".to_string()
    };
    log::result(ok, "Widgets app removal", &detail);
    (ok, detail)
}

pub fn open_store_page() -> bool {
    unsafe {
        let verb = wide("open");
        let uri = wide(STORE_URI);
        let result = ShellExecuteW(
            None,
            PCWSTR(verb.as_ptr()),
            PCWSTR(uri.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        );
        if result.0 as isize > 32 {
            log::result(true, "Widgets app Store page", STORE_URI);
            true
        } else {
            log::result(
                false,
                "Widgets app Store page",
                &format!(
                    "{STORE_URI}: The system cannot find the file specified (ShellExecute code {})",
                    result.0 as isize
                ),
            );
            false
        }
    }
}

fn account_detail() -> String {
    let (sid, name) = current_identity();
    let session_user = session_user();
    let same = match (&session_user, &name) {
        (Some(s), Some(n)) => {
            if s.to_uppercase() == n.to_uppercase() {
                "yes"
            } else {
                "no"
            }
        }
        _ => "unknown",
    };
    format!("runs as {sid}, same account as the signed-in user: {same}")
}

fn current_identity() -> (String, Option<String>) {
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return ("unknown".to_string(), None);
        }
        let mut needed = 0u32;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut needed);
        if needed == 0 {
            let _ = CloseHandle(token);
            return ("unknown".to_string(), None);
        }
        let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
        let got = GetTokenInformation(
            token,
            TokenUser,
            Some(buffer.as_mut_ptr() as *mut std::ffi::c_void),
            needed,
            &mut needed,
        );
        let _ = CloseHandle(token);
        if got.is_err() {
            return ("unknown".to_string(), None);
        }
        let user = &*(buffer.as_ptr() as *const TOKEN_USER);
        let sid_ptr = user.User.Sid;
        let mut text = PWSTR::null();
        let sid = if ConvertSidToStringSidW(sid_ptr, &mut text).is_ok() {
            let s = text.to_string().unwrap_or_else(|_| "unknown".to_string());
            let _ = LocalFree(Some(HLOCAL(text.0 as *mut std::ffi::c_void)));
            s
        } else {
            "unknown".to_string()
        };
        let mut name_len = 256u32;
        let mut domain_len = 256u32;
        let mut name_buf = vec![0u16; name_len as usize];
        let mut domain_buf = vec![0u16; domain_len as usize];
        let mut use_type = SID_NAME_USE::default();
        let name = if LookupAccountSidW(
            PCWSTR::null(),
            sid_ptr,
            Some(PWSTR(name_buf.as_mut_ptr())),
            &mut name_len,
            Some(PWSTR(domain_buf.as_mut_ptr())),
            &mut domain_len,
            &mut use_type,
        )
        .is_ok()
        {
            let n = String::from_utf16_lossy(&name_buf[..name_len as usize]);
            let d = String::from_utf16_lossy(&domain_buf[..domain_len as usize]);
            Some(format!("{d}\\{n}"))
        } else {
            None
        };
        (sid, name)
    }
}

fn session_user() -> Option<String> {
    unsafe {
        let mut session = 0u32;
        if ProcessIdToSessionId(GetCurrentProcessId(), &mut session).is_err() {
            return None;
        }
        let user = query_session(session, 5);
        let domain = query_session(session, 7);
        let user = user.filter(|u| !u.is_empty())?;
        match domain {
            Some(d) if !d.is_empty() => Some(format!("{d}\\{user}")),
            _ => Some(user),
        }
    }
}

unsafe fn query_session(session: u32, info_class: i32) -> Option<String> {
    let mut buffer = PWSTR::null();
    let mut bytes = 0u32;
    if WTSQuerySessionInformationW(
        None,
        session,
        WTS_INFO_CLASS(info_class),
        &mut buffer,
        &mut bytes,
    )
    .is_err()
    {
        return None;
    }
    let text = buffer.to_string().ok();
    WTSFreeMemory(buffer.0 as *mut std::ffi::c_void);
    text
}

fn format_exit(code: i32) -> String {
    if code == -1 {
        "none".to_string()
    } else {
        format!("0x{:08X}", code as u32)
    }
}

fn last_line(output: &str) -> String {
    let line = output
        .split(['\r', '\n'])
        .map(|l| {
            l.chars()
                .filter(|c| !c.is_control())
                .collect::<String>()
                .trim()
                .to_string()
        })
        .filter(|l| l.chars().any(|c| c.is_alphabetic()))
        .last()
        .unwrap_or_default();
    if line.chars().count() > 160 {
        format!("{}...", line.chars().take(160).collect::<String>())
    } else {
        line
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_output_parsing() {
        assert_eq!(
            parse_probe_output("STORE=1 WEB=0\r\n"),
            (Some(true), Some(false))
        );
        assert_eq!(
            parse_probe_output("STORE=0 WEB=2"),
            (Some(false), Some(true))
        );
        assert_eq!(parse_probe_output("UNKNOWN"), (None, None));
    }

    #[test]
    fn exit_formatting_and_last_line() {
        assert_eq!(format_exit(-1), "none");
        assert_eq!(format_exit(0x8A150014u32 as i32), "0x8A150014");
        assert_eq!(
            last_line("  \r\n-\r\nInstall failed\r\n   \r\n"),
            "Install failed"
        );
        let long = "a".repeat(200);
        assert_eq!(last_line(&long).chars().count(), 163);
    }
}

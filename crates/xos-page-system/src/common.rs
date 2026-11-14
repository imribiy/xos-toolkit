use base64::Engine;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
use xos_core::host::{Buttons, Host, Icon};
use xos_core::{app_state, log};

pub const TITLE: &str = "XOS Toolkit";

pub fn done(host: &dyn Host, msg: &str, operation_failed: bool, known_cause: Option<&str>) {
    let failed = xos_sys::ops::any_failed() || operation_failed;
    log::action_done("System", operation_failed, failed, known_cause);
    xos_sys::ops::reset();
    app_state::require_reboot_if_message_asks(msg);
    host.set_status(msg);
    let mut text = msg.to_string();
    if failed && known_cause.is_none() {
        text.push_str(
            "\n\nNote: one or more settings could not be written (often a permissions issue). Try again.",
        );
    }
    host.dialog(
        &text,
        TITLE,
        Buttons::Ok,
        if failed {
            Icon::Warning
        } else {
            Icon::Information
        },
    );
}

pub fn encode_command(script: &str) -> String {
    let bytes: Vec<u8> = script
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub fn process_ids_by_name(name: &str) -> Vec<u32> {
    let mut ids = Vec::new();
    unsafe {
        let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
            return ids;
        };
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut more = Process32FirstW(snapshot, &mut entry).is_ok();
        while more {
            let len = entry
                .szExeFile
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(entry.szExeFile.len());
            let exe = String::from_utf16_lossy(&entry.szExeFile[..len]);
            let stem = if exe.to_lowercase().ends_with(".exe") {
                &exe[..exe.len() - 4]
            } else {
                exe.as_str()
            };
            if stem.eq_ignore_ascii_case(name) {
                ids.push(entry.th32ProcessID);
            }
            more = Process32NextW(snapshot, &mut entry).is_ok();
        }
        let _ = CloseHandle(snapshot);
    }
    ids
}

pub fn process_running(name: &str) -> bool {
    !process_ids_by_name(name).is_empty()
}

pub fn kill_processes_named(name: &str) {
    for pid in process_ids_by_name(name) {
        unsafe {
            if let Ok(handle) = OpenProcess(PROCESS_TERMINATE, false, pid) {
                let _ = TerminateProcess(handle, 1);
                let _ = CloseHandle(handle);
            }
        }
    }
}

pub fn system_root() -> String {
    std::env::var("SystemRoot")
        .or_else(|_| std::env::var("windir"))
        .unwrap_or_else(|_| r"C:\Windows".to_string())
}

pub fn system_dir() -> String {
    format!(r"{}\System32", system_root())
}

pub fn distinct_ci(items: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for item in items {
        if !out.iter().any(|e| e.eq_ignore_ascii_case(&item)) {
            out.push(item);
        }
    }
    out
}

pub fn stock_split_disabled() -> Vec<String> {
    let build = xos_sys::get_windows_build_number();
    let mut stock: Vec<String> = ["BFE", "mpssvc", "RasMan", "PlugPlay"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    if build >= 26200 {
        stock.push("DcomLaunch".into());
        stock.push("Power".into());
    }
    stock
}

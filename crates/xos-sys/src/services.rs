use winreg::enums::{KEY_READ, REG_DWORD};
use winreg::RegKey;

use crate::elevation::{run_as_ti, run_as_ti_accepting, run_as_ti_best_effort, run_as_ti_with, TiOptions};
use crate::ops::track;
use crate::reg::{key_get_string, reg_delete_value, reg_get_dword, reg_set_dword};
use crate::util::{
    encode_command, escape_powershell_literal, path_combine, path_is_rooted, windows_dir,
};
use xos_core::log;

fn services_key(service_name: &str) -> Option<RegKey> {
    RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(
            format!(r"SYSTEM\CurrentControlSet\Services\{service_name}"),
            KEY_READ,
        )
        .ok()
}

pub fn set_svc_host_split_threshold(threshold: u32) -> bool {
    run_as_ti(
        "reg.exe",
        &format!(
            "add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\" /v SvcHostSplitThresholdInKB /t REG_DWORD /d 0x{threshold:08X} /f"
        ),
    )
}

pub fn set_service_grouping_values(service_names: &[String], grouped: bool) -> bool {
    if service_names.is_empty() {
        return true;
    }
    let mut names: Vec<String> = Vec::new();
    for n in service_names.iter().filter(|n| !n.trim().is_empty()) {
        let q = format!("'{}'", escape_powershell_literal(n.trim()));
        if !names.iter().any(|e| e.to_lowercase() == q.to_lowercase()) {
            names.push(q);
        }
    }
    if names.is_empty() {
        return true;
    }
    let script = format!(
        "$ErrorActionPreference='Stop';\
$grouped={grouped};\
$failed=$false;\
$services=@({names});\
foreach($name in $services){{\
$path='HKLM:\\SYSTEM\\CurrentControlSet\\Services\\' + $name;\
if(-not (Test-Path -LiteralPath $path) -or $null -eq (Get-ItemProperty -LiteralPath $path -ErrorAction SilentlyContinue).Type){{continue;}}\
try{{\
if($grouped){{\
New-ItemProperty -LiteralPath $path -Name 'SvcHostSplitDisable' -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null;\
$value=Get-ItemPropertyValue -LiteralPath $path -Name 'SvcHostSplitDisable' -ErrorAction Stop;\
if($value -ne 1){{throw 'Value verification failed.'}}\
}}else{{\
Remove-ItemProperty -LiteralPath $path -Name 'SvcHostSplitDisable' -Force -ErrorAction SilentlyContinue;\
$value=(Get-ItemProperty -LiteralPath $path -ErrorAction SilentlyContinue).SvcHostSplitDisable;\
if($null -ne $value){{throw 'Value deletion verification failed.'}}\
}}\
}}catch{{\
$failed=$true;\
[Console]::Error.WriteLine($name + ': ' + $_.Exception.Message);\
}}\
}}\
if($failed){{exit 1}}",
        grouped = if grouped { "$true" } else { "$false" },
        names = names.join(",")
    );
    run_as_ti(
        "powershell.exe",
        &format!(
            "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand {}",
            encode_command(&script)
        ),
    )
}

pub fn config_service_reg(service_name: &str, start_type: i32) -> bool {
    if !service_exists(service_name) {
        log::log(&format!(
            "[Service] {service_name} is not present; Start={start_type} was not written."
        ));
        return false;
    }
    let key = format!(r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\{service_name}");
    run_as_ti(
        "reg.exe",
        &format!("add \"{key}\" /v Start /t REG_DWORD /d {start_type} /f"),
    )
}

const WINDOWS_SEARCH_IFEO_KEYS: [&str; 3] = [
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SearchApp.exe",
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SearchUI.exe",
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SearchHost.exe",
];

fn windows_search_host_path() -> String {
    path_combine(
        &windows_dir(),
        r"SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SearchHost.exe",
    )
}

pub fn enable_windows_search() -> bool {
    let mut operation_ok = true;

    operation_ok &= config_service_reg("WSearch", 2);
    operation_ok &= run_as_ti("sc.exe", "config WSearch start= delayed-auto");
    operation_ok &= reg_set_dword(
        r"HKLM\SYSTEM\CurrentControlSet\Services\WSearch",
        "DelayedAutoStart",
        1,
    );
    operation_ok &= reg_set_dword(
        r"HKLM\SOFTWARE\Microsoft\Windows Search",
        "SetupCompletedSuccessfully",
        1,
    );
    for key in WINDOWS_SEARCH_IFEO_KEYS {
        operation_ok &= reg_delete_value(key, "Debugger");
    }

    operation_ok &= reg_set_dword(
        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search",
        "SearchboxTaskbarMode",
        1,
    );

    let host = windows_search_host_path();
    let backup = format!("{host}.bak");
    if std::path::Path::new(&backup).exists() && !std::path::Path::new(&host).exists() {
        let restored = run_as_ti("cmd.exe", &format!("/c move /Y \"{backup}\" \"{host}\""))
            && std::path::Path::new(&host).exists();
        operation_ok &= restored;
    }

    operation_ok &= run_as_ti_accepting("sc.exe", "start WSearch", &[SC_SERVICE_ALREADY_RUNNING]);
    operation_ok
}

pub fn config_service_reg_if_present(service_name: &str, start_type: i32) -> bool {
    if !service_exists(service_name) {
        log::log(&format!(
            "[Service] {service_name} is not present on this build; nothing to configure."
        ));
        return true;
    }
    let key = format!(r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\{service_name}");
    run_as_ti(
        "reg.exe",
        &format!("add \"{key}\" /v Start /t REG_DWORD /d {start_type} /f"),
    )
}

pub fn config_service_sc(service_name: &str, start_str: &str) -> bool {
    let expected = match start_str {
        "boot" => 0,
        "system" => 1,
        "auto" | "delayed-auto" => 2,
        "demand" => 3,
        "disabled" => 4,
        _ => -1,
    };
    let mut ran;
    for attempt in 1..=2 {
        ran = run_as_ti_with(
            "sc.exe",
            &format!("config \"{service_name}\" start= {start_str}"),
            &TiOptions {
                timeout_ms: Some(300000),
                best_effort: true,
                ..Default::default()
            },
        );
        let actual = get_service_start_type(service_name);
        if expected < 0 || actual < 0 {
            return ran;
        }
        if actual == expected {
            return true;
        }
        if attempt == 1 {
            log::log(&format!(
                "[OP] service {service_name} start= {start_str}: Start is {actual}, retrying"
            ));
        } else {
            log::log(&format!(
                "[RESULT] FAILED service {service_name} start= {start_str}: Start is {actual} after 2 attempts"
            ));
        }
    }
    track(false)
}

pub const SC_SERVICE_ALREADY_RUNNING: i32 = 1056;
pub const SC_SERVICE_NOT_ACTIVE: i32 = 1062;

pub fn stop_service(service_name: &str) -> bool {
    run_as_ti_accepting(
        "sc.exe",
        &format!("stop \"{service_name}\""),
        &[SC_SERVICE_NOT_ACTIVE],
    )
}

pub fn start_service(service_name: &str) -> bool {
    run_as_ti_accepting(
        "sc.exe",
        &format!("start \"{service_name}\""),
        &[SC_SERVICE_ALREADY_RUNNING],
    )
}

pub fn stop_service_best_effort(service_name: &str) -> bool {
    run_as_ti_best_effort("sc.exe", &format!("stop \"{service_name}\""))
}

pub fn start_service_best_effort(service_name: &str) -> bool {
    run_as_ti_best_effort("sc.exe", &format!("start \"{service_name}\""))
}

pub fn get_service_delayed_auto_start(service_name: &str) -> i32 {
    match services_key(service_name) {
        Some(k) => match k.get_raw_value("DelayedAutostart") {
            Ok(v) if v.vtype == REG_DWORD && v.bytes.len() >= 4 => {
                i32::from_le_bytes([v.bytes[0], v.bytes[1], v.bytes[2], v.bytes[3]])
            }
            _ => 0,
        },
        None => 0,
    }
}

pub fn parse_service_image_path(raw: &str) -> Option<String> {
    if raw.trim().is_empty() {
        return None;
    }
    let mut path = raw.trim().to_string();
    if path.starts_with('"') {
        let end = path[1..].find('"')? + 1;
        path = path[1..end].to_string();
    } else {
        let lower = path.to_ascii_lowercase();
        let exe = lower.find(".exe");
        let sys = lower.find(".sys");
        if let Some(e) = exe {
            path = path[..e + 4].to_string();
        } else if let Some(s) = sys {
            path = path[..s + 4].to_string();
        } else {
            return None;
        }
    }
    Some(path)
}

fn resolve_service_binary_path(path: String, windows: &str, expand: bool) -> Option<String> {
    let mut path = if expand {
        crate::util::expand_environment_variables(&path)
    } else {
        path
    };
    if let Some(rest) = path.strip_prefix(r"\??\") {
        path = rest.to_string();
    }
    if path.len() >= 12
        && path.is_char_boundary(12)
        && path[..12].eq_ignore_ascii_case(r"\SystemRoot\")
    {
        path = path_combine(windows, &path[12..]);
    } else if !path_is_rooted(&path) {
        path = path_combine(windows, &path);
    }
    if path.contains('%') {
        return None;
    }
    Some(path)
}

pub fn is_service_binary_missing(service_name: &str) -> bool {
    let raw = match services_key(service_name).and_then(|k| key_get_string(&k, "ImagePath", false))
    {
        Some(r) => r,
        None => return false,
    };
    let path = match parse_service_image_path(&raw) {
        Some(p) => p,
        None => return false,
    };
    match resolve_service_binary_path(path, &windows_dir(), true) {
        Some(p) => !std::path::Path::new(&p).exists(),
        None => false,
    }
}

pub fn service_exists(service_name: &str) -> bool {
    match services_key(service_name) {
        Some(k) => k.get_raw_value("Type").is_ok(),
        None => false,
    }
}

pub fn is_start_only_service_stub(key: Option<&RegKey>) -> bool {
    let key = match key {
        Some(k) => k,
        None => return false,
    };
    match key.query_info() {
        Ok(info) if info.sub_keys == 0 => {}
        _ => return false,
    }
    let names: Vec<String> = key
        .enum_values()
        .filter_map(|r| r.ok())
        .map(|(n, _)| n)
        .collect();
    if names.len() != 1 || !names[0].eq_ignore_ascii_case("Start") {
        return false;
    }
    match key.get_raw_value(&names[0]) {
        Ok(v) => v.vtype == REG_DWORD,
        Err(_) => false,
    }
}

pub fn get_service_start_type(service_name: &str) -> i32 {
    reg_get_dword(
        &format!(r"HKLM\SYSTEM\CurrentControlSet\Services\{service_name}"),
        "Start",
    )
    .unwrap_or(-1)
}

pub fn get_service_start_type_text(service_name: &str) -> &'static str {
    match get_service_start_type(service_name) {
        0 => "Boot",
        1 => "System",
        2 => "Automatic",
        3 => "Manual",
        4 => "Disabled",
        _ => "Not Found",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_path_quoted() {
        assert_eq!(
            parse_service_image_path("\"C:\\Program Files\\x\\svc.exe\" -k group").as_deref(),
            Some("C:\\Program Files\\x\\svc.exe")
        );
        assert_eq!(parse_service_image_path("\"C:\\broken"), None);
    }

    #[test]
    fn image_path_unquoted() {
        assert_eq!(
            parse_service_image_path("C:\\Windows\\system32\\svchost.exe -k netsvcs -p").as_deref(),
            Some("C:\\Windows\\system32\\svchost.exe")
        );
        assert_eq!(
            parse_service_image_path("System32\\drivers\\x.SYS").as_deref(),
            Some("System32\\drivers\\x.SYS")
        );
        assert_eq!(parse_service_image_path("nothing"), None);
        assert_eq!(parse_service_image_path("  "), None);
    }

    #[test]
    fn image_path_resolution() {
        let r = resolve_service_binary_path(
            "\\SystemRoot\\System32\\drivers\\a.sys".to_string(),
            "C:\\Windows",
            false,
        );
        assert_eq!(r.as_deref(), Some("C:\\Windows\\System32\\drivers\\a.sys"));
        let r = resolve_service_binary_path("\\??\\C:\\x\\a.sys".to_string(), "C:\\Windows", false);
        assert_eq!(r.as_deref(), Some("C:\\x\\a.sys"));
        let r = resolve_service_binary_path("%unknown%\\a.exe".to_string(), "C:\\Windows", false);
        assert_eq!(r, None);
    }
}

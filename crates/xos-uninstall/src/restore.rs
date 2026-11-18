use std::collections::HashMap;
use std::path::Path;

use regex::Regex;
use winreg::enums::{
    HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_ALL_ACCESS, KEY_READ, REG_BINARY,
    REG_NONE,
};
use winreg::RegKey;
use xos_core::session_log;
use xos_helpers::{defender_run_entry, service_defaults_table, stock_hardware_marker};
use xos_winupdate::{hard_disable, legacy, service_guard, webview2, widgets_policy};

pub use crate::helpers::run_encoded_power_shell_as_ti;
use crate::helpers::{
    defender_del, encode_power_shell_command, escape_power_shell_literal, fmt_val_int,
    local_application_data, new_guid_n, path_combine, path_root, record_action_command,
    skip_absent_feature, stock_disabled_tasks, system_directory, uninstall_delete_service_stub_key,
    uninstall_log, uninstall_reg_del, uninstall_reg_del_key, uninstall_reg_set,
    uninstall_reg_set_exp, uninstall_reg_set_str, windows_directory,
};
use crate::scripts;

const OPTIONAL_FEATURES_LOG_RELATIVE: &str = r"AME\Logs\OptionalFeatures.log";

const PLAYBOOK_OPTIONAL_FEATURES: [&str; 17] = [
    "SMBDirect",
    "MSRDC-Infrastructure",
    "Workfolders-Client",
    "WCF-Services45",
    "WCF-TCP-PortSharing45",
    "Microsoft-Hyper-V-All",
    "Microsoft-Hyper-V",
    "Microsoft-Hyper-V-Tools-All",
    "Microsoft-Hyper-V-Management-PowerShell",
    "Microsoft-Hyper-V-Hypervisor",
    "Microsoft-Hyper-V-Services",
    "Microsoft-Hyper-V-Management-Clients",
    "DirectPlay",
    "Printing-Foundation-Features",
    "Printing-Foundation-InternetPrinting-Client",
    "Printing-PrintToPDFServices-Features",
    "Printing-XPSServices-Features",
];

const MITIGATION_EXES: [&str; 9] = [
    "fontdrvhost.exe",
    "dwm.exe",
    "lsass.exe",
    "svchost.exe",
    "WmiPrvSE.exe",
    "winlogon.exe",
    "csrss.exe",
    "ntoskrnl.exe",
    "services.exe",
];

pub const DEFAULT_HIVE_PREFIX: &str = r"HKDU\";

pub fn optional_features_log() -> String {
    path_combine(
        &crate::helpers::common_application_data(),
        OPTIONAL_FEATURES_LOG_RELATIVE,
    )
}

fn crlf(lines: &[&str]) -> String {
    let mut s = String::new();
    for l in lines {
        s.push_str(l);
        s.push_str("\r\n");
    }
    s
}

fn nullable_text(v: Option<i32>) -> String {
    match v {
        Some(n) => n.to_string(),
        None => String::new(),
    }
}

fn pass_text(ok: bool) -> &'static str {
    if ok {
        "OK"
    } else {
        "FAILED"
    }
}

fn eq_ci(a: &str, b: &str) -> bool {
    a.to_lowercase() == b.to_lowercase()
}

fn contains_ci(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().contains(&needle.to_lowercase())
}

fn read_text_file(path: &str) -> std::io::Result<String> {
    let bytes = std::fs::read(path)?;
    if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE {
        let units: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        return Ok(String::from_utf16_lossy(&units));
    }
    if bytes.len() >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF {
        let units: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        return Ok(String::from_utf16_lossy(&units));
    }
    let body = if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        &bytes[3..]
    } else {
        &bytes[..]
    };
    Ok(String::from_utf8_lossy(body).into_owned())
}

pub fn split_lines(text: &str) -> Vec<String> {
    let normalized = text.replace("\r\n", "\n").replace('\r', "\n");
    let mut lines: Vec<String> = normalized.split('\n').map(|s| s.to_string()).collect();
    if lines.last().map(|l| l.is_empty()).unwrap_or(false) {
        lines.pop();
    }
    lines
}

fn read_all_lines(path: &str) -> std::io::Result<Vec<String>> {
    Ok(split_lines(&read_text_file(path)?))
}

fn path_exists(path: &str) -> bool {
    Path::new(path).exists()
}

pub fn is_xos_mitigation_mask_bytes(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    bytes.iter().all(|&b| b == 0x22 || b == 0x00)
}

pub fn looks_like_xos_mitigation_mask(key: &str, value: &str) -> bool {
    let sub_key = if key.to_ascii_uppercase().starts_with(r"HKLM\") {
        &key[5..]
    } else {
        key
    };
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let opened = match hklm.open_subkey_with_flags(sub_key, KEY_READ) {
        Ok(k) => k,
        Err(_) => return false,
    };
    match opened.get_raw_value(value) {
        Ok(raw) if raw.vtype == REG_BINARY || raw.vtype == REG_NONE => {
            is_xos_mitigation_mask_bytes(&raw.bytes)
        }
        _ => false,
    }
}

pub fn restore_process_mitigations() -> bool {
    uninstall_log("--- PROCESS MITIGATIONS ---");
    let mut ok = true;
    let kernel = r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel";
    for value in ["MitigationOptions", "MitigationAuditOptions"] {
        if looks_like_xos_mitigation_mask(kernel, value) {
            ok &= uninstall_reg_del(kernel, value);
        } else if xos_sys::reg_value_exists(kernel, value) {
            uninstall_log(&format!(
                "  Kernel {value} does not match the XOS fingerprint, left unchanged"
            ));
        }
    }

    for exe in MITIGATION_EXES {
        let key = format!(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{exe}"
        );
        for value in ["MitigationOptions", "MitigationAuditOptions"] {
            if looks_like_xos_mitigation_mask(&key, value) {
                ok &= uninstall_reg_del(&key, value);
            } else if xos_sys::reg_value_exists(&key, value) {
                uninstall_log(&format!(
                    "  {exe} {value} does not match the XOS fingerprint, left unchanged"
                ));
            }
        }
    }

    let reset_ok = run_encoded_power_shell_as_ti(scripts::PROCESS_MITIGATIONS_RESET, 120000);
    uninstall_log(if reset_ok {
        "  System process mitigations reset to the local Windows defaults"
    } else {
        "  System process mitigation reset FAILED"
    });
    ok &= reset_ok;

    let mut remaining = 0;
    for exe in MITIGATION_EXES {
        let key = format!(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{exe}"
        );
        if looks_like_xos_mitigation_mask(&key, "MitigationOptions") {
            remaining += 1;
        }
        if looks_like_xos_mitigation_mask(&key, "MitigationAuditOptions") {
            remaining += 1;
        }
    }
    if looks_like_xos_mitigation_mask(kernel, "MitigationOptions") {
        remaining += 1;
    }
    if looks_like_xos_mitigation_mask(kernel, "MitigationAuditOptions") {
        remaining += 1;
    }
    uninstall_log(&format!(
        "  Remaining XOS-fingerprint mitigation values: {remaining}"
    ));
    ok && remaining == 0
}

pub fn restore_data_collection_settings() -> bool {
    let target = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection";
    let backup = r"HKLM\SOFTWARE\XOSToolkit\DataCollectionBackup";
    let values = [
        "AllowTelemetry",
        "DoNotShowFeedbackNotifications",
        "MaxTelemetryAllowed",
    ];
    let present = xos_sys::get_windows_build_number() >= 26200;

    uninstall_log("  Restoring DataCollection values to the Windows defaults for this build");
    let mut ok = true;
    for value in values {
        let should_exist = present && value != "DoNotShowFeedbackNotifications";
        if !should_exist {
            ok &= uninstall_reg_del(target, value);
            continue;
        }

        let written = xos_sys::run_as_ti(
            "reg.exe",
            &format!("add \"{target}\" /v \"{value}\" /t REG_DWORD /d 3 /f"),
        );
        let verified = written && xos_sys::reg_get_dword(target, value) == Some(3);
        record_action_command(verified);
        uninstall_log(&format!(
            "  RESTORE [{value}]: value=3  {}",
            pass_text(verified)
        ));
        ok &= verified;
    }

    if ok {
        ok &= uninstall_reg_del_key(backup);
    }
    ok
}

pub fn remove_telemetry_opt_out_variables() -> bool {
    let key = r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment";
    let mut ok = true;
    for name in ["DOTNET_CLI_TELEMETRY_OPTOUT", "POWERSHELL_TELEMETRY_OPTOUT"] {
        let current = xos_sys::reg_get_string(key, name);
        if xos_sys::reg_value_exists(key, name) && current.as_deref().map(|c| c.trim()) != Some("1")
        {
            uninstall_log(&format!(
                "  [{name}] is not the XOS value 1, left unchanged  -- {key}"
            ));
            continue;
        }
        ok &= uninstall_reg_del(key, name);
    }
    uninstall_log(
        "  System environment variable changes apply to programs started after the uninstall's restart",
    );
    ok
}

pub fn restore_event_channels() -> bool {
    uninstall_log("--- EVENT CHANNELS ---");
    let backup_key = r"HKLM\SOFTWARE\XOSToolkit\EventChannelState";
    let backup_reg = path_combine(
        &windows_directory(),
        r"service-backups\xos-event-channel-state.reg",
    );
    let mut capture_status = xos_sys::reg_get_string(backup_key, "CaptureStatus");
    let is_complete =
        |s: &Option<String>| s.as_deref().map(|v| eq_ci(v, "Complete")).unwrap_or(false);
    if !is_complete(&capture_status) && path_exists(&backup_reg) {
        let imported = xos_sys::run_as_ti("reg.exe", &format!("import \"{backup_reg}\""));
        uninstall_log(&format!(
            "  Event-channel registry backup import: {}",
            if imported { "OK" } else { "FAILED" }
        ));
        capture_status = xos_sys::reg_get_string(backup_key, "CaptureStatus");
    }

    let captured_total = xos_sys::reg_get_dword(backup_key, "EnabledTotal");
    if !is_complete(&capture_status) || captured_total.is_none() {
        uninstall_log(
            "  No verified event-channel capture was found; channels were left unchanged",
        );
        return false;
    }

    let result_path = path_combine(
        &path_combine(&windows_directory(), "Temp"),
        &format!("xos-event-channel-restore-{}.txt", new_guid_n()),
    );
    let result_literal = escape_power_shell_literal(&result_path);
    let inner = format!(
        "{}{}{}",
        scripts::EVENT_CHANNEL_0,
        result_literal,
        scripts::EVENT_CHANNEL_2
    );
    let encoded = encode_power_shell_command(&inner);
    let launched = xos_sys::run_as_ti(
        "powershell.exe",
        &format!("-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}"),
    );
    let channel_wait = std::time::Instant::now();
    while launched
        && !path_exists(&result_path)
        && channel_wait.elapsed() < std::time::Duration::from_secs(5 * 60)
    {
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    let mut output = String::new();
    if path_exists(&result_path) {
        match read_text_file(&result_path) {
            Ok(t) => output = t.trim().to_string(),
            Err(e) => output = format!("result read failed: {e}"),
        }
    }
    if path_exists(&result_path) {
        let _ = std::fs::remove_file(&result_path);
    }

    let mut ok = launched && contains_ci(&output, "failed=0");
    uninstall_log(&format!(
        "  Event channel restore: {}",
        if output.trim().is_empty() {
            "(no output)"
        } else {
            &output
        }
    ));
    if !ok {
        uninstall_log("  Event channel restore FAILED");
    } else if path_exists(&backup_reg) {
        if let Err(e) = std::fs::remove_file(&backup_reg) {
            ok = false;
            uninstall_log(&format!(
                "  Event-channel registry backup cleanup: FAILED {e}"
            ));
        }
    }
    ok
}

pub fn restore_dma_remapping_overrides() -> bool {
    uninstall_log("--- DMA REMAPPING ---");
    let mut ok = true;
    ok &= uninstall_reg_del(
        r"HKLM\SOFTWARE\Microsoft\PolicyManager\default\DmaGuard",
        "DeviceEnumerationPolicy",
    );

    let encoded = encode_power_shell_command(scripts::DMA_REMAPPING);
    let (exit_code, output) = xos_sys::run_as_ti_output_timeout(
        "powershell.exe",
        &format!("-NoProfile -NonInteractive -EncodedCommand {encoded}"),
        120000,
    );
    uninstall_log(&format!(
        "  DmaRemappingCompatible cleanup: {}",
        if output.trim().is_empty() {
            "no output"
        } else {
            output.trim()
        }
    ));
    let restored = exit_code == 0 && contains_ci(&output, "unresolved=0");
    ok && restored
}

struct OrderedCi {
    items: Vec<(String, bool)>,
}

impl OrderedCi {
    fn new() -> Self {
        OrderedCi { items: Vec::new() }
    }

    fn set(&mut self, key: &str, value: bool) {
        let lower = key.to_lowercase();
        if let Some(item) = self
            .items
            .iter_mut()
            .find(|(k, _)| k.to_lowercase() == lower)
        {
            item.1 = value;
        } else {
            self.items.push((key.to_string(), value));
        }
    }
}

fn is_playbook_feature(name: &str) -> bool {
    PLAYBOOK_OPTIONAL_FEATURES.iter().any(|f| eq_ci(f, name))
}

pub fn try_parse_feature_log_entry(line: &str, marker: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    let marker_index = lower.find(&marker.to_ascii_lowercase())?;
    let start = marker_index + marker.len();
    let end = line[start..]
        .find(" - ")
        .map(|i| start + i)
        .unwrap_or(line.len());
    let mut feature = line[start..end].trim().to_string();
    if let Some(space) = feature.find(' ') {
        if space > 0 {
            feature.truncate(space);
        }
    }
    if feature.is_empty() {
        None
    } else {
        Some(feature)
    }
}

pub fn is_feature_state_disabled(state: &str) -> bool {
    eq_ci(state, "Disabled")
        || eq_ci(state, "DisabledWithPayloadRemoved")
        || eq_ci(state, "Disabled With Payload Removed")
        || eq_ci(state, "DisablePending")
        || eq_ci(state, "Disable Pending")
}

pub fn restore_optional_features_from_log() -> bool {
    uninstall_log("--- OPTIONAL FEATURES ---");
    let log_path = optional_features_log();
    let mut pending: HashMap<String, &'static str> = HashMap::new();
    let mut restore_enabled = OrderedCi::new();
    let mut saw_run = false;
    let mut history_ok = true;

    if !path_exists(&log_path) {
        uninstall_log(&format!(
            "  Feature history is missing: {log_path}; Hyper-V is left as it is"
        ));
    } else {
        match read_all_lines(&log_path) {
            Ok(lines) => {
                for line in lines {
                    if contains_ci(&line, "--- OptionalFeatures script started ---") {
                        saw_run = true;
                        pending.clear();
                        continue;
                    }

                    if let Some(f) = try_parse_feature_log_entry(&line, "[DISABLE]") {
                        if is_playbook_feature(&f) {
                            pending.insert(f.to_lowercase(), "DISABLE");
                            continue;
                        }
                    }

                    if let Some(f) = try_parse_feature_log_entry(&line, "[ENABLE]") {
                        if is_playbook_feature(&f) {
                            pending.insert(f.to_lowercase(), "ENABLE");
                            continue;
                        }
                    }

                    let completed = match try_parse_feature_log_entry(&line, "[DONE]") {
                        Some(f) if is_playbook_feature(&f) => f,
                        _ => continue,
                    };
                    let action = match pending.get(&completed.to_lowercase()) {
                        Some(a) => *a,
                        None => continue,
                    };
                    restore_enabled.set(&completed, action.eq_ignore_ascii_case("DISABLE"));
                    pending.remove(&completed.to_lowercase());
                }
            }
            Err(e) => {
                uninstall_log(&format!("  Feature history could not be read: {e}"));
                history_ok = false;
            }
        }
    }

    if path_exists(&log_path) && history_ok && !saw_run {
        uninstall_log(
            "  Feature history has no recognizable playbook run; Hyper-V is left as it is",
        );
    }

    restore_enabled
        .items
        .retain(|(name, _)| name.to_lowercase().starts_with("microsoft-hyper-v"));

    let states = xos_sys::get_all_feature_states();
    if states.is_empty() {
        uninstall_log("  Windows optional-feature states could not be queried");
        return false;
    }

    let build = xos_sys::get_windows_build_number();
    let windows_defaults: [(&str, bool); 11] = [
        ("SMBDirect", true),
        ("MSRDC-Infrastructure", true),
        ("WorkFolders-Client", true),
        ("WCF-Services45", true),
        ("WCF-TCP-PortSharing45", true),
        ("Printing-Foundation-Features", true),
        ("Printing-Foundation-InternetPrinting-Client", true),
        ("Printing-PrintToPDFServices-Features", true),
        ("Printing-XPSServices-Features", build < 22631),
        ("DirectPlay", false),
        ("LegacyComponents", false),
    ];
    for (name, value) in windows_defaults {
        if states.contains_key(name) {
            restore_enabled.set(name, value);
        }
    }

    let mut ok = history_ok;
    for (name, want_enabled) in &restore_enabled.items {
        let state = match states.get(name) {
            Some(s) => s.clone(),
            None => {
                ok = false;
                uninstall_log(&format!(
                    "  {name}: expected feature was missing from the state query"
                ));
                continue;
            }
        };

        let already_correct = if *want_enabled {
            xos_sys::is_feature_state_enabled(&state)
        } else {
            is_feature_state_disabled(&state)
        };
        if already_correct {
            uninstall_log(&format!("  {name}: already restored ({state})"));
            continue;
        }

        let changed = if *want_enabled {
            xos_sys::enable_feature(name)
        } else {
            xos_sys::disable_feature(name)
        };
        if !changed && *want_enabled && skip_absent_feature(name) {
            continue;
        }
        uninstall_log(&format!(
            "  {name}: restore to {} {}",
            if *want_enabled { "enabled" } else { "disabled" },
            if changed {
                "requested"
            } else {
                "not accepted on its own (a parent feature may bring it); the final state decides"
            }
        ));
    }

    let final_states = xos_sys::get_all_feature_states();
    for (name, want_enabled) in &restore_enabled.items {
        let state = match final_states.get(name) {
            Some(s) => s.clone(),
            None => {
                ok = false;
                uninstall_log(&format!("  {name}: missing from the final state query"));
                continue;
            }
        };
        let correct = if *want_enabled {
            xos_sys::is_feature_state_enabled(&state)
        } else {
            is_feature_state_disabled(&state)
        };
        ok &= correct;
        uninstall_log(&format!(
            "  {name}: final state {state} {}",
            pass_text(correct)
        ));
    }
    ok
}

pub fn delete_xos_dword_if_matches(key: &str, value: &str, xos_values: &[i32]) -> bool {
    let current = match xos_sys::reg_get_dword(key, value) {
        Some(c) => c,
        None => return true,
    };
    if xos_values.contains(&current) {
        return uninstall_reg_del(key, value);
    }
    uninstall_log(&format!(
        "  [{value}] is not an XOS-written value, left unchanged: {key}"
    ));
    true
}

pub fn restore_update_service_registry_acl() -> bool {
    uninstall_log("--- WINDOWS UPDATE SERVICE UNLOCK ---");
    let mut script = crlf(scripts::UPDATE_ACL_HEAD);
    for svc in ["wuauserv", "UsoSvc", "WaaSMedicSvc", "BITS", "DoSvc"] {
        script.push_str(&format!(
            "$k = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\{svc}'\r\n"
        ));
        script.push_str(&format!(
            "$sddl = (Get-ItemProperty -Path $backup -Name '{svc}' -EA SilentlyContinue).'{svc}'\r\n"
        ));
        script.push_str(&crlf(scripts::UPDATE_ACL_LOOP_TAIL));
    }
    script.push_str(&crlf(scripts::UPDATE_ACL_TAIL));

    let ok = run_encoded_power_shell_as_ti(&script, 120000);
    uninstall_log(if ok {
        "  Update service registry permissions restored"
    } else {
        "  Update service registry permission restore FAILED"
    });
    ok
}

pub fn get_service_runtime_state(service_name: &str) -> String {
    use windows::core::PCWSTR;
    use windows::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_MANAGER_CONNECT,
        SERVICE_QUERY_STATUS, SERVICE_STATUS,
    };

    if !xos_sys::service_exists(service_name) {
        return "NotPresent".to_string();
    }
    let wide: Vec<u16> = service_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        let scm = match OpenSCManagerW(None, None, SC_MANAGER_CONNECT) {
            Ok(h) => h,
            Err(_) => return "Unknown".to_string(),
        };
        let svc = match OpenServiceW(scm, PCWSTR(wide.as_ptr()), SERVICE_QUERY_STATUS) {
            Ok(h) => h,
            Err(_) => {
                let _ = CloseServiceHandle(scm);
                return "Unknown".to_string();
            }
        };
        let mut status = SERVICE_STATUS::default();
        let queried = QueryServiceStatus(svc, &mut status);
        let _ = CloseServiceHandle(svc);
        let _ = CloseServiceHandle(scm);
        if queried.is_err() {
            return "Unknown".to_string();
        }
        match status.dwCurrentState.0 {
            1 => "Stopped",
            2 => "StartPending",
            3 => "StopPending",
            4 => "Running",
            5 => "ContinuePending",
            6 => "PausePending",
            7 => "Paused",
            _ => "Unknown",
        }
        .to_string()
    }
}

pub fn restore_toolkit_service_defaults() -> bool {
    uninstall_log(
        "  Applying documented XOS Toolkit service enable/default values; install-time service captures are not used",
    );
    let mut ok = xos_page_network::restore_windows_default_service_start_types(Some(&|m: &str| {
        uninstall_log(m)
    }));
    ok &= restore_compatibility_service_defaults();
    ok &= uninstall_reg_del_key(r"HKLM\SOFTWARE\XOSToolkit\HyperVServiceBackup");
    uninstall_log(&format!("  Toolkit service defaults: {}", pass_text(ok)));
    ok
}

fn process_running(name: &str) -> bool {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    let wanted = name.to_lowercase();
    unsafe {
        let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(h) => h,
            Err(_) => return false,
        };
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut found = false;
        let mut more = Process32FirstW(snapshot, &mut entry).is_ok();
        while more {
            let len = entry
                .szExeFile
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(entry.szExeFile.len());
            let exe = String::from_utf16_lossy(&entry.szExeFile[..len]).to_lowercase();
            let stem = exe.strip_suffix(".exe").unwrap_or(&exe);
            if stem == wanted {
                found = true;
                break;
            }
            more = Process32NextW(snapshot, &mut entry).is_ok();
        }
        let _ = CloseHandle(snapshot);
        found
    }
}

pub fn restore_defender_compatibility() -> bool {
    let mut ok = true;
    uninstall_log(&format!(
        "  TamperProtection before: {}",
        nullable_text(xos_sys::reg_get_dword(
            r"HKLM\SOFTWARE\Microsoft\Windows Defender\Features",
            "TamperProtection"
        ))
    ));

    ok &= restore_defender_service_defaults();

    let engine_running = process_running("MsMpEng");

    for root in [
        r"HKLM\SOFTWARE\Microsoft\Windows Defender",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender",
    ] {
        for value in [
            "ServiceKeepAlive",
            "PreviousRunningMode",
            "IsServiceRunning",
            "DisableAntiSpyware",
            "DisableAntiVirus",
            "PassiveMode",
        ] {
            ok &= defender_del(root, value, engine_running);
        }
    }

    for root in [
        r"HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
    ] {
        for value in [
            "DisableRealtimeMonitoring",
            "DisableBehaviorMonitoring",
            "DisableIOAVProtection",
            "DisableOnAccessProtection",
            "DisableScanOnRealtimeEnable",
        ] {
            ok &= defender_del(root, value, engine_running);
        }
    }

    for value in ["SpyNetReporting", "DisableBlockAtFirstSeen"] {
        ok &= defender_del(
            r"HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet",
            value,
            engine_running,
        );
    }
    ok &= restore_sample_submission_default(engine_running);
    if engine_running
        && xos_sys::reg_get_dword(
            r"HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet",
            "SpyNetReporting",
        ) == Some(0)
    {
        uninstall_log(
            "  Cloud-delivered protection is off and Defender protects that setting while it runs. Turn it on in Windows Security if you want it.",
        );
    }
    ok &= uninstall_reg_del(
        r"HKLM\Software\Policies\Microsoft\Windows Defender\Reporting",
        "DisableGenericRePorts",
    );
    ok &= uninstall_reg_del(
        r"HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates",
        "DisableScheduledSignatureUpdateOnBattery",
    );

    for root in [
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WTDS\Components",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components",
    ] {
        for value in [
            "ServiceEnabled",
            "CaptureThreatWindow",
            "NotifyMalicious",
            "NotifyPasswordReuse",
            "NotifyUnsafeApp",
        ] {
            ok &= uninstall_reg_del(root, value);
        }
    }

    ok &= uninstall_reg_del(
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WTDS\FeatureFlags",
        "BlockUxDisabled",
    );
    ok &= uninstall_reg_del(
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WTDS\FeatureFlags",
        "TelemetryCallsEnabled",
    );
    ok &= uninstall_reg_del(
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer",
        "SmartScreenEnabled",
    );
    ok &= uninstall_reg_del(
        r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer",
        "SmartScreenEnabled",
    );
    ok &= uninstall_reg_del(
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\System",
        "EnableSmartScreen",
    );
    ok &= uninstall_reg_del(
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\System",
        "ShellSmartScreenLevel",
    );
    ok &= uninstall_reg_del(
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost",
        "Enabled",
    );
    ok &= uninstall_reg_del(
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost",
        "PreventOverride",
    );
    ok &= uninstall_reg_del(
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppHost",
        "EnableWebContentEvaluation",
    );
    ok &= uninstall_reg_del(
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer",
        "AicEnabled",
    );
    ok &= uninstall_reg_del(
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\smartscreen.exe",
        "Debugger",
    );
    ok &= uninstall_reg_del(
        r"HKLM\Software\Policies\Microsoft\Windows Defender\SmartScreen",
        "ConfigureAppInstallControlEnabled",
    );
    ok &= uninstall_reg_del(
        r"HKLM\Software\Policies\Microsoft\Windows Defender\SmartScreen",
        "ConfigureAppInstallControl",
    );
    ok &= uninstall_reg_del(
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray",
        "HideSystray",
    );
    ok &= uninstall_reg_del(
        r"HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy",
        "VerifiedAndReputablePolicyState",
    );
    ok &= uninstall_reg_del(
        r"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity",
        "Enabled",
    );
    ok &= uninstall_reg_del(
        r"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard",
        "Enabled",
    );
    ok &= uninstall_reg_del(
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard",
        "ConfigureSystemGuardLaunch",
    );

    ok &= restore_wer_disabled_value();
    ok &= restore_defender_renamed_files();

    for logger in ["DefenderApiLogger", "DefenderAuditLogger"] {
        let key = format!(r"HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\{logger}");
        if xos_sys::reg_key_exists(&key) {
            ok &= uninstall_reg_set(&key, "Start", 1);
        }
    }

    for task in [
        r"\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance",
        r"\Microsoft\Windows\Windows Defender\Windows Defender Cleanup",
        r"\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan",
        r"\Microsoft\Windows\Windows Defender\Windows Defender Verification",
        r"\Microsoft\Windows\ExploitGuard\ExploitGuard MDM policy Refresh",
    ] {
        ok &= enable_scheduled_task_if_present(task);
    }

    let security_health_exe = path_combine(&system_directory(), "SecurityHealthSystray.exe");
    if path_exists(&security_health_exe) {
        ok &= uninstall_reg_set_exp(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "SecurityHealth",
            r"%windir%\system32\SecurityHealthSystray.exe",
        );
        ok &= set_security_health_startup_approved();
    } else {
        uninstall_log("  SecurityHealthSystray.exe is not present, startup entry skipped");
    }

    let (run_defender_restored, run_defender_restore_detail) =
        defender_run_entry::restore_default();
    uninstall_log(&format!(
        "  Run WindowsDefender: {run_defender_restore_detail}"
    ));
    ok &= run_defender_restored;
    if run_defender_restored {
        ok &= uninstall_reg_del_key(r"HKLM\SOFTWARE\XOSToolkit\DefenderRunBackup");
    }

    ok &= restore_security_health_ui_registration();

    ok &= crate::helpers::uninstall_reg_del_optional(
        r"HKLM\SOFTWARE\Microsoft\Windows Defender\Features",
        "TamperProtection",
        true,
    );

    ok &= uninstall_reg_del_key(r"HKLM\SOFTWARE\XOSToolkit\DefenderServiceBackup");

    uninstall_log(&format!(
        "  TamperProtection after: {}",
        nullable_text(xos_sys::reg_get_dword(
            r"HKLM\SOFTWARE\Microsoft\Windows Defender\Features",
            "TamperProtection"
        ))
    ));
    ok
}

pub fn restore_defender_service_defaults() -> bool {
    uninstall_log("  Applying documented Defender service enable/default values.");
    let mut ok = true;
    let build = xos_sys::get_windows_build_number();
    let items: [(&str, i32); 16] = [
        ("WinDefend", 2),
        ("WdNisSvc", 3),
        ("WdFilter", 0),
        ("WdBoot", 0),
        ("WdNisDrv", 3),
        ("MDCoreSvc", 2),
        ("Sense", 3),
        ("wscsvc", 2),
        ("SecurityHealthService", 3),
        ("MsSecCore", 0),
        ("MsSecWfp", 3),
        ("MsSecFlt", 3),
        ("SgrmBroker", 3),
        ("wtd", 2),
        ("webthreatdefusersvc", 2),
        ("webthreatdefsvc", 3),
    ];
    for (name, default) in items {
        let mut start = service_defaults_table::get_start_type(name, build);
        if !(0..=4).contains(&start) {
            start = default;
        }
        if start != 4 && name == "SgrmBroker" && xos_sys::is_service_binary_missing(name) {
            uninstall_log(
                "  SgrmBroker: its program file is not on this Windows, so it is set to 4 (disabled), as Windows leaves it",
            );
            start = 4;
        }
        ok &= uninstall_delete_service_stub_key(name);
        ok &= set_service_start_exact_if_present(name, start);
    }
    ok
}

pub fn set_service_start_exact_if_present(service: &str, start: i32) -> bool {
    if !xos_sys::service_exists(service) {
        uninstall_log(&format!(
            "  {service}: not present on this Windows build, skipped"
        ));
        return true;
    }
    let delayed = start == 2
        && service_defaults_table::is_delayed_auto_start(
            service,
            xos_sys::get_windows_build_number(),
        );
    let wrote = xos_sys::config_service_reg(service, start);
    let sc_name = if delayed {
        "delayed-auto"
    } else {
        sc_start_type_name(start)
    };
    let scm_wrote = xos_sys::config_service_sc(service, sc_name);
    let actual = xos_sys::get_service_start_type(service);
    let delayed_actual = if delayed {
        xos_sys::get_service_delayed_auto_start(service)
    } else {
        0
    };
    let ok = wrote && scm_wrote && actual == start && (!delayed || delayed_actual == 1);
    uninstall_log(&format!(
        "  {service}: Start={actual}{}, expected {start}{} {}",
        if delayed {
            format!(" DelayedAutostart={delayed_actual}")
        } else {
            String::new()
        },
        if delayed { " delayed" } else { "" },
        pass_text(ok)
    ));
    ok
}

pub fn sc_start_type_name(start_type: i32) -> &'static str {
    match start_type {
        0 => "boot",
        1 => "system",
        2 => "auto",
        3 => "demand",
        4 => "disabled",
        _ => panic!(
            "Specified argument was out of the range of valid values. (Parameter 'startType')"
        ),
    }
}

pub fn enable_scheduled_task_if_present(task: &str) -> bool {
    let ok = xos_sys::enable_task(task);
    uninstall_log(&format!(
        "  Task {task}: {}",
        if ok {
            "verified enabled or explicitly absent"
        } else {
            "FAILED"
        }
    ));
    ok
}

pub fn set_security_health_startup_approved() -> bool {
    let key = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
    let wrote = xos_sys::run_as_ti(
        "reg.exe",
        &format!("add \"{key}\" /v SecurityHealth /t REG_BINARY /d 020000000000000000000000 /f"),
    );
    let mut verified = false;
    if let Ok(k) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
        KEY_READ,
    ) {
        if let Ok(raw) = k.get_raw_value("SecurityHealth") {
            if raw.vtype == REG_BINARY || raw.vtype == REG_NONE {
                verified = !raw.bytes.is_empty() && raw.bytes[0] == 2;
            }
        }
    }
    uninstall_log(&format!(
        "  SecurityHealth StartupApproved: {}",
        pass_text(wrote && verified)
    ));
    wrote && verified
}

pub fn restore_wer_disabled_value() -> bool {
    let ok = run_encoded_power_shell_as_ti(scripts::WER_DISABLED, 60000)
        && !xos_sys::reg_value_exists(
            r"HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting",
            "Disabled_Old",
        );
    uninstall_log(if ok {
        "  Original Windows Error Reporting Disabled value restored"
    } else {
        "  Windows Error Reporting Disabled_Old restore FAILED"
    });
    ok
}

pub fn restore_defender_renamed_files() -> bool {
    let script = crlf(scripts::DEFENDER_RENAMED);
    let ok = run_encoded_power_shell_as_ti(&script, 180000);
    uninstall_log(if ok {
        "  Defender and SmartScreen executables restored"
    } else {
        "  Defender or SmartScreen executable restore FAILED"
    });
    ok
}

pub fn restore_security_health_ui_registration() -> bool {
    let mut ok = true;
    ok &= uninstall_reg_del_key(
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.SecHealthUI_8wekyb3d8bbwe",
    );
    ok &= uninstall_reg_del_key(
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.Windows.SecHealthUI_cw5n1h2txyewy",
    );

    let encoded = encode_power_shell_command(scripts::SEC_HEALTH_UI);
    let (exit_code, out, err) = xos_sys::run_cmd_capture_opts(
        "powershell.exe",
        &format!("-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}"),
        60000,
        false,
    );
    let registration_ok = exit_code == 0;
    let output = xos_sys::strip_clixml_noise(&format!("{out} {err}"));
    uninstall_log(&format!(
        "  SecHealthUI {}",
        if output.trim().is_empty() {
            "(no output)"
        } else {
            &output
        }
    ));
    ok && registration_ok
}

pub fn restore_captured_task_states() -> bool {
    let stock_disabled = stock_disabled_tasks(xos_sys::get_windows_build_number());
    let disabled: std::collections::HashSet<String> =
        stock_disabled.iter().map(|t| t.to_lowercase()).collect();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut enable_targets: Vec<String> = Vec::new();
    for task in scripts::XOS_TASKS {
        let lower = task.to_lowercase();
        if seen.insert(lower.clone()) && !disabled.contains(&lower) {
            enable_targets.push(task.to_string());
        }
    }
    let mut ok = xos_sys::disable_tasks_batch(&stock_disabled);
    ok &= xos_sys::enable_tasks_batch(&enable_targets);
    ok &= xos_sys::enable_scheduled_tasks_in_folder(r"\Microsoft\Office\");
    uninstall_log(&format!(
        "  XOS task defaults restored through TrustedInstaller: {}",
        if ok {
            "OK"
        } else {
            "FAILED; see per-task Toolkit log"
        }
    ));

    let legacy_backup = r"HKLM\SOFTWARE\XOSToolkit\ScheduledTaskState";
    let legacy_reg = path_combine(
        &windows_directory(),
        r"service-backups\xos-scheduled-task-state.reg",
    );
    if xos_sys::reg_key_exists(legacy_backup)
        && !xos_sys::run_as_ti("reg.exe", &format!("delete \"{legacy_backup}\" /f"))
    {
        uninstall_log("  Legacy scheduled-task capture registry cleanup: FAILED");
    }
    if path_exists(&legacy_reg) {
        if let Err(e) = std::fs::remove_file(&legacy_reg) {
            uninstall_log(&format!(
                "  Legacy scheduled-task capture cleanup: FAILED {e}"
            ));
        }
    }
    ok
}

pub fn restore_captured_disabled_devices() -> bool {
    let list_path = path_combine(
        &windows_directory(),
        r"service-backups\disabled-devices.txt",
    );
    if !path_exists(&list_path) {
        uninstall_log(
            "  No captured disabled-device list on this machine, leaving devices as they are",
        );
        return true;
    }

    let mut instance_ids: Vec<String> = Vec::new();
    match read_all_lines(&list_path) {
        Ok(lines) => {
            for raw_line in lines {
                let line = raw_line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                instance_ids.push(line.to_string());
            }
        }
        Err(e) => {
            uninstall_log(&format!(
                "  The disabled-device list could not be read: {e}"
            ));
            return false;
        }
    }

    if instance_ids.is_empty() {
        uninstall_log("  The captured list has no disabled devices, nothing to re-enable");
        return true;
    }

    let mut ok = true;
    let mut restored = 0;
    let mut missing = 0;
    for instance_id in &instance_ids {
        if !xos_sys::reg_key_exists(&format!(
            r"HKLM\SYSTEM\CurrentControlSet\Enum\{instance_id}"
        )) {
            missing += 1;
            continue;
        }
        if xos_sys::enable_device(instance_id, false) {
            restored += 1;
        } else {
            ok = false;
            uninstall_log(&format!("  Device could not be re-enabled: {instance_id}"));
        }
    }
    uninstall_log(&format!(
        "  Re-enabled {restored} of {} captured disabled device(s){}",
        instance_ids.len(),
        if missing > 0 {
            format!(", {missing} no longer present")
        } else {
            String::new()
        }
    ));
    ok
}

pub fn restore_profiles_wallpaper_and_security_overrides() -> bool {
    let script = crlf(scripts::PROFILES_WALLPAPER);
    let ok = run_encoded_power_shell_as_ti(&script, 180000);
    uninstall_log(if ok {
        "  XOS wallpaper, lock-screen policy, and per-user security overrides restored"
    } else {
        "  Profile wallpaper or security override restore FAILED"
    });
    ok
}

pub fn restore_power_setting_visibility_defaults() -> bool {
    let mut ok = true;
    let processor = r"HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\";
    for setting in [
        "0cc5b647-c1df-4637-891a-dec35c318583",
        "ea062031-0e34-4ff1-9b6d-eb1059334028",
        "943c8cb6-6f93-4227-ad87-e9a3feec08d1",
        "f7277c87-9043-4248-9e8d-db20e412c751",
        "df142941-20f1-4cc0-928d-fde8c3378dce",
        "a55612aa-f624-42c6-a443-7397d064c04f",
        "2430ab6f-a520-44a2-9601-f7f23b5134b1",
    ] {
        ok &= uninstall_reg_del(&format!("{processor}{setting}"), "Attributes");
    }
    ok &= uninstall_reg_del(
        r"HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\0012ee47-9041-4b5d-9b77-535fba8b1442\0b2d69d7-a2a1-449c-9680-f91c70521c60",
        "Attributes",
    );
    ok
}

pub fn restore_settings_page_visibility() -> bool {
    let policy = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";
    let backup = r"HKLM\SOFTWARE\XOSToolkit\UpdateVisibilityBackup";
    let mut current = xos_sys::reg_get_string(policy, "SettingsPageVisibility");
    let original = xos_sys::reg_get_string(backup, "Original");
    let applied = xos_sys::reg_get_string(backup, "Applied");
    let mut ok = true;

    if let (Some(original), Some(applied)) = (original.as_deref(), applied.as_deref()) {
        if current
            .as_deref()
            .map(|c| eq_ci(c, applied))
            .unwrap_or(false)
        {
            ok &= if original == "<XOS:NO_VALUE>" {
                uninstall_reg_del(policy, "SettingsPageVisibility")
            } else {
                uninstall_reg_set_str(policy, "SettingsPageVisibility", original)
            };
            current = xos_sys::reg_get_string(policy, "SettingsPageVisibility");
        }
    }

    if let Some(cur) = current.as_deref() {
        if !cur.is_empty() && cur.to_lowercase().starts_with("hide:") {
            let pages: Vec<&str> = cur[5..].split(';').filter(|p| !p.is_empty()).collect();
            let mut kept: Vec<&str> = Vec::new();
            for page in &pages {
                let trimmed = page.trim();
                if !eq_ci(trimmed, "windowsupdate") && !eq_ci(trimmed, "windowsdefender") {
                    kept.push(trimmed);
                }
            }
            if kept.len() != pages.len() {
                ok &= if kept.is_empty() {
                    uninstall_reg_del(policy, "SettingsPageVisibility")
                } else {
                    uninstall_reg_set_str(
                        policy,
                        "SettingsPageVisibility",
                        &format!("hide:{}", kept.join(";")),
                    )
                };
            }
        }
    }

    if ok {
        ok &= uninstall_reg_del_key(backup);
    }
    ok
}

pub fn restore_windows_update_policy_values() -> bool {
    let mut ok = service_guard::remove_owned();
    uninstall_log(&format!(
        "  Windows Update service protection cleanup: {}",
        if ok {
            "OK"
        } else {
            "FAILED; recovery records retained"
        }
    ));
    let mut sources_ok = true;
    match hard_disable::owned_source_values() {
        Ok(values) => {
            for (key, name) in values {
                sources_ok &= uninstall_reg_del(&key, &name);
            }
        }
        Err(e) => {
            sources_ok = false;
            uninstall_log(&format!(
                "  Windows Update source ownership could not be read: {e}"
            ));
        }
    }
    ok &= sources_ok;
    if sources_ok
        && hard_disable::owned_source_values()
            .map(|v| v.is_empty())
            .unwrap_or(false)
    {
        ok &= delete_xos_dword_if_matches(hard_disable::OWNERSHIP_KEY, "Applied", &[1]);
    }
    for (key, value) in legacy::matches(true) {
        ok &= uninstall_reg_del(&key, &value);
    }
    let machine = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate";
    ok &= delete_xos_dword_if_matches(machine, "DisableDualScan", &[1]);
    ok &= delete_xos_dword_if_matches(machine, "ExcludeWUDriversInQualityUpdate", &[1]);
    ok &= delete_xos_dword_if_matches(machine, "DeferFeatureUpdates", &[1]);
    ok &= delete_xos_dword_if_matches(machine, "DeferFeatureUpdatesPeriodInDays", &[365]);
    ok &= delete_xos_dword_if_matches(machine, "SetAllowOptionalContent", &[0]);
    ok &= delete_xos_dword_if_matches(
        machine,
        "DoNotConnectToWindowsUpdateInternetLocations",
        &[1],
    );
    ok &= delete_xos_dword_if_matches(machine, "DisableWindowsUpdateAccess", &[1]);
    ok &= delete_xos_dword_if_matches(machine, "SetDisableUXWUAccess", &[1]);
    ok &= delete_xos_dword_if_matches(machine, "SetUpdateNotificationLevel", &[1]);
    ok &= delete_xos_dword_if_matches(machine, "UpdateNotificationLevel", &[2]);
    ok &= delete_xos_dword_if_matches(
        machine,
        "AllowAutoWindowsUpdateDownloadOverMeteredNetwork",
        &[0, 1],
    );

    let current_version = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    let mut current_release = xos_sys::reg_get_string(current_version, "DisplayVersion");
    if current_release
        .as_deref()
        .map(|s| s.is_empty())
        .unwrap_or(true)
    {
        current_release = xos_sys::reg_get_string(current_version, "ReleaseId");
    }
    let target_release = xos_sys::reg_get_string(machine, "TargetReleaseVersionInfo");
    match target_release.as_deref() {
        Some(target)
            if !target.is_empty()
                && current_release
                    .as_deref()
                    .map(|c| eq_ci(target, c))
                    .unwrap_or(false) =>
        {
            ok &= uninstall_reg_del(machine, "TargetReleaseVersionInfo");
            ok &= delete_xos_dword_if_matches(machine, "TargetReleaseVersion", &[1]);
            if xos_sys::reg_get_string(machine, "ProductVersion").as_deref() == Some("Windows 11") {
                ok &= uninstall_reg_del(machine, "ProductVersion");
            }
        }
        Some(target) if !target.is_empty() => {
            uninstall_log(
                "  TargetReleaseVersionInfo does not match the XOS fingerprint, left unchanged",
            );
        }
        _ => {}
    }

    let machine_au = format!(r"{machine}\AU");
    let machine_no_auto_update = xos_sys::reg_get_dword(&machine_au, "NoAutoUpdate");
    if machine_no_auto_update == Some(0) || machine_no_auto_update == Some(1) {
        ok &= delete_xos_dword_if_matches(&machine_au, "AUOptions", &[1, 2, 4]);
    } else if xos_sys::reg_get_dword(&machine_au, "NoAutoRebootWithLoggedOnUsers") == Some(1) {
        ok &= delete_xos_dword_if_matches(&machine_au, "AUOptions", &[4]);
    } else if xos_sys::reg_get_dword(&machine_au, "AUOptions").is_some() {
        uninstall_log("  AUOptions left unchanged (no XOS fingerprint in this key)");
    }
    ok &= delete_xos_dword_if_matches(&machine_au, "NoAutoUpdate", &[0, 1]);
    ok &= delete_xos_dword_if_matches(&machine_au, "NoAUShutdownOption", &[1]);
    ok &= delete_xos_dword_if_matches(&machine_au, "AlwaysAutoRebootAtScheduledTime", &[0]);
    ok &= delete_xos_dword_if_matches(&machine_au, "AutoInstallMinorUpdates", &[0]);
    ok &= delete_xos_dword_if_matches(&machine_au, "UseWUServer", &[0]);
    ok &= delete_xos_dword_if_matches(&machine_au, "NoAutoRebootWithLoggedOnUsers", &[1]);
    ok &= delete_xos_dword_if_matches(&machine_au, "AllowMUUpdateService", &[1]);

    let user_au = r"HKCU\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU";
    ok &= delete_xos_dword_if_matches(user_au, "NoAUShutdownOption", &[1]);

    let ux = r"HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings";
    ok &= delete_xos_dword_if_matches(ux, "ExcludeWUDriversInQualityUpdate", &[1]);
    ok &= delete_xos_dword_if_matches(ux, "IsContinuousInnovationOptedIn", &[0, 1]);
    ok &= delete_xos_dword_if_matches(ux, "AllowMUUpdateService", &[0, 1]);
    ok &= delete_xos_dword_if_matches(ux, "IsExpedited", &[0, 1]);
    ok &= delete_xos_dword_if_matches(ux, "RestartNotificationsAllowed2", &[0, 1]);
    ok &= delete_xos_dword_if_matches(
        ux,
        "AllowAutoWindowsUpdateDownloadOverMeteredNetwork",
        &[0, 1],
    );
    ok
}

pub fn restore_driver_update_values() -> bool {
    let mut ok = true;
    let system = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching";
    if xos_sys::reg_get_dword(system, "SearchOrderConfig") == Some(0) {
        ok &= uninstall_reg_set(system, "SearchOrderConfig", 1);
    } else {
        uninstall_log("  Driver SearchOrderConfig was not XOS-blocked, left unchanged");
    }
    ok &= delete_xos_dword_if_matches(system, "DontSearchWindowsUpdate", &[1]);
    ok &= delete_xos_dword_if_matches(system, "DontPromptForWindowsUpdate", &[1]);
    ok &= delete_xos_dword_if_matches(system, "DriverUpdateWizardWuSearchEnabled", &[0]);

    let machine_policy = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\DriverSearching";
    ok &= delete_xos_dword_if_matches(machine_policy, "SearchOrderConfig", &[0]);
    ok &= delete_xos_dword_if_matches(machine_policy, "DontSearchWindowsUpdate", &[1]);
    ok &= delete_xos_dword_if_matches(machine_policy, "DontPromptForWindowsUpdate", &[1]);
    ok &= delete_xos_dword_if_matches(machine_policy, "DriverUpdateWizardWuSearchEnabled", &[0]);

    let user_policy = r"HKCU\SOFTWARE\Policies\Microsoft\Windows\DriverSearching";
    ok &= delete_xos_dword_if_matches(user_policy, "DontSearchWindowsUpdate", &[1]);
    ok &= delete_xos_dword_if_matches(user_policy, "DriverUpdateWizardWuSearchEnabled", &[0]);
    ok &= delete_xos_dword_if_matches(user_policy, "DontPromptForWindowsUpdate", &[1]);
    ok &= delete_xos_dword_if_matches(
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata",
        "PreventDeviceMetadataFromNetwork",
        &[1],
    );
    ok &= delete_xos_dword_if_matches(
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Device Metadata",
        "PreventDeviceMetadataFromNetwork",
        &[1],
    );
    ok
}

pub fn restore_store_and_delivery_values() -> bool {
    let mut ok = true;
    let store_policy = r"HKLM\SOFTWARE\Policies\Microsoft\WindowsStore";
    ok &= delete_xos_dword_if_matches(store_policy, "AutoDownload", &[2, 4]);
    ok &= delete_xos_dword_if_matches(store_policy, "DisableOSUpgrade", &[1]);
    ok &= delete_xos_dword_if_matches(
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate",
        "AutoDownload",
        &[2, 4],
    );

    ok &= delete_xos_dword_if_matches(
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization",
        "DODownloadMode",
        &[0, 1],
    );
    ok &= delete_xos_dword_if_matches(
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config",
        "DODownloadMode",
        &[0, 1],
    );
    ok &= delete_xos_dword_if_matches(
        r"HKU\S-1-5-20\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings",
        "DownloadMode",
        &[0],
    );
    ok &= delete_xos_dword_if_matches(
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization",
        "SystemSettingsDownloadMode",
        &[0],
    );
    ok
}

pub fn restore_preview_maps_and_speech_values() -> bool {
    let mut ok = true;
    let preview = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds";
    ok &= delete_xos_dword_if_matches(preview, "EnableExperimentation", &[0]);
    ok &= delete_xos_dword_if_matches(preview, "EnableConfigFlighting", &[0]);
    ok &= delete_xos_dword_if_matches(preview, "AllowBuildPreview", &[0]);
    ok &= delete_xos_dword_if_matches(
        r"HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility",
        "HideInsiderPage",
        &[1],
    );

    let experimentation =
        r"HKLM\SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation";
    if xos_sys::reg_get_dword(experimentation, "value") == Some(0) {
        let default_value = xos_sys::reg_get_dword(experimentation, "defaultValue");
        ok &= match default_value {
            Some(v) => uninstall_reg_set(experimentation, "value", v),
            None => uninstall_reg_del(experimentation, "value"),
        };
    }

    ok &= delete_xos_dword_if_matches(r"HKLM\SYSTEM\Maps", "AutoUpdateEnabled", &[0]);
    ok &= delete_xos_dword_if_matches(
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Maps",
        "AutoDownloadAndUpdateMapData",
        &[0],
    );
    ok &= delete_xos_dword_if_matches(
        r"HKLM\SOFTWARE\Policies\Microsoft\Speech",
        "AllowSpeechModelUpdate",
        &[0],
    );
    ok &= delete_xos_dword_if_matches(
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\OutlookUpdate",
        "workCompleted",
        &[1],
    );
    ok
}

pub fn restore_surgical_policy_leftovers() -> bool {
    let mut ok = true;
    ok &= delete_xos_dword_if_matches(
        r"HKCU\SOFTWARE\Policies\Microsoft\Windows\EdgeUI",
        "DisableCharms",
        &[1],
    );
    ok &= delete_xos_dword_if_matches(
        r"HKCU\SOFTWARE\Policies\Microsoft\Windows\EdgeUI",
        "DisableRecentApps",
        &[1],
    );
    ok &= delete_xos_dword_if_matches(
        r"HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer",
        "DisableThumbsDBOnNetworkFolders",
        &[1],
    );
    ok &= delete_xos_dword_if_matches(
        r"HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer",
        "SkipNetworkShieldCheck",
        &[1],
    );
    ok &= delete_xos_dword_if_matches(
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer",
        "DisableThumbsDBOnNetworkFolders",
        &[1],
    );
    ok &= delete_xos_dword_if_matches(
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer",
        "DisableSearchBoxSuggestions",
        &[1],
    );
    ok &= delete_xos_dword_if_matches(
        r"HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer",
        "DisableSearchBoxSuggestions",
        &[1],
    );
    ok &= delete_xos_dword_if_matches(
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
        "MaxNegativeCacheTtl",
        &[5],
    );

    ok &= delete_xos_dword_if_matches(
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging",
        "EnableModuleLogging",
        &[0],
    );
    ok &= delete_xos_dword_if_matches(
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
        "EnableScriptBlockLogging",
        &[0],
    );

    let cloud = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent";
    for value in [
        "DisableSoftLanding",
        "DisableWindowsSpotlightFeatures",
        "DisableCloudOptimizedContent",
        "DisableWindowsConsumerFeatures",
        "DisableTailoredExperiencesWithDiagnosticData",
    ] {
        ok &= delete_xos_dword_if_matches(cloud, value, &[1]);
    }

    let edge = r"HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate";
    ok &= xos_sys::reg_delete_key(r"HKLM\SOFTWARE\XOS Toolkit\WebView2");
    for value in [
        "InstallDefault",
        "UpdateDefault",
        "CreateDesktopShortcutDefault",
        "Install{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}",
        "Install{2CD8A007-E189-409D-A2C8-9AF4EF3C72AA}",
        "Install{0D50BFEC-CD6A-4F9A-964C-C7416E3ACB10}",
        "Install{65C35B14-6C1D-4122-AC46-7148CC9D6497}",
        "Update{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}",
        "Update{2CD8A007-E189-409D-A2C8-9AF4EF3C72AA}",
        "Update{0D50BFEC-CD6A-4F9A-964C-C7416E3ACB10}",
        "Update{65C35B14-6C1D-4122-AC46-7148CC9D6497}",
    ] {
        ok &= delete_xos_dword_if_matches(edge, value, &[0]);
    }
    for value in [
        "DoNotUpdateToEdgeWithChromium",
        "Install{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}",
        "Update{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}",
        "Uninstall{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}",
    ] {
        ok &= delete_xos_dword_if_matches(edge, value, &[1]);
    }
    ok &= delete_xos_dword_if_matches(edge, &format!("Install{}", webview2::GUID), &[0]);
    ok &= delete_xos_dword_if_matches(edge, &format!("Update{}", webview2::GUID), &[0]);
    ok &= delete_xos_dword_if_matches(edge, &format!("Uninstall{}", webview2::GUID), &[0]);

    ok &= delete_xos_dword_if_matches(
        r"HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform",
        "NoGenTicket",
        &[1],
    );
    ok &= delete_xos_dword_if_matches(
        r"HKLM\SOFTWARE\Policies\Microsoft\WindowsCopilot",
        "DisableAIDataAnalysis",
        &[1],
    );
    ok &= delete_xos_dword_if_matches(
        r"HKCU\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot",
        "TurnOffWindowsCopilot",
        &[1],
    );
    ok &= delete_xos_dword_if_matches(
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot",
        "TurnOffWindowsCopilot",
        &[1],
    );
    ok &= delete_xos_dword_if_matches(
        r"HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization",
        "RestrictImplicitInkCollection",
        &[1],
    );
    ok &= delete_xos_dword_if_matches(
        r"HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization",
        "AllowInputPersonalization",
        &[0],
    );
    ok &= delete_xos_dword_if_matches(
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports",
        "PreventHandwritingErrorReports",
        &[1],
    );
    ok &= delete_xos_dword_if_matches(
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC",
        "PreventHandwritingDataSharing",
        &[1],
    );
    ok &= delete_xos_dword_if_matches(
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Maps",
        "AllowUntriggeredNetworkTrafficOnSettingsPage",
        &[0],
    );
    let (widgets_ok, widgets_detail) = widgets_policy::enable();
    uninstall_log(&format!(
        "  [Widgets and News policy] {}: {widgets_detail}",
        pass_text(widgets_ok)
    ));
    ok &= widgets_ok;
    ok &= delete_xos_dword_if_matches(
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging",
        "EnableProtectedEventLogging",
        &[0],
    );
    ok &= delete_xos_dword_if_matches(
        r"HKCU\Software\Policies\Microsoft\Windows\WindowsAI",
        "DisableAIDataAnalysis",
        &[1],
    );
    ok &= delete_xos_dword_if_matches(
        r"HKCU\Software\Policies\Microsoft\Windows\WindowsAI",
        "AllowRecallEnablement",
        &[0],
    );
    ok &= delete_xos_dword_if_matches(
        r"HKLM\SOFTWARE\Policies\Microsoft\FindMyDevice",
        "AllowFindMyDevice",
        &[0],
    );
    ok &= delete_xos_dword_if_matches(
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched",
        "TimerResolution",
        &[10],
    );
    ok &= delete_xos_dword_if_matches(
        r"HKLM\Software\Policies\Microsoft\SQMClient\Windows",
        "CEIPEnable",
        &[0],
    );

    let search = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search";
    for value in [
        "AllowCortanaAboveLock",
        "AllowCortana",
        "AllowCloudSearch",
        "AllowSearchToUseLocation",
        "EnableDynamicContentInWSB",
        "DisableBackoff",
        "ConnectedSearchUseWeb",
    ] {
        ok &= delete_xos_dword_if_matches(search, value, &[0]);
    }
    ok &= delete_xos_dword_if_matches(search, "PreventIndexingLowDiskSpaceMB", &[2048]);
    ok &= delete_xos_dword_if_matches(search, "DisableRemovableDriveIndexing", &[1]);
    ok &= delete_xos_dword_if_matches(search, "PreventIndexOnBattery", &[1]);
    ok &= delete_xos_dword_if_matches(search, "PreventIndexingOutlook", &[1]);

    let input = r"HKLM\SOFTWARE\Microsoft\Input\Settings\proc_1";
    ok &= delete_xos_dword_if_matches(input, "BluebirdDTWMultiplier", &[0]);
    ok &= delete_xos_dword_if_matches(input, "DynamicAutocorrectionAllowed", &[0]);
    let input_locale = format!(r"{input}\loc_0409");
    for value in [
        "AUTOCORRECTIONTRIGGERS",
        "AUTOCORRECTSUPPRESSPREVCHARS",
        "BluebirdDTWMultiplier",
        "DynamicAutocorrectionAllowed",
        "PERIODSHORTCUTCHARS",
        "PERIODSHORTCUTDELAY",
        "PERIODSHORTCUTDELAYCANDSELECTION",
    ] {
        ok &= delete_xos_dword_if_matches(&input_locale, value, &[0]);
    }
    let input_method = format!(r"{input_locale}\im_1");
    for value in [
        "AUTOCORRECTIONTRIGGERS",
        "AUTOCORRECTSUPPRESSPREVCHARS",
        "BluebirdDTWMultiplier",
        "COMMONEMOJIPRETERMINATORS",
        "COMMONEMOJITERMINATORS",
        "DynamicAutocorrectionAllowed",
        "PERIODSHORTCUTCHARS",
        "PERIODSHORTCUTDELAY",
        "PERIODSHORTCUTDELAYCANDSELECTION",
    ] {
        ok &= delete_xos_dword_if_matches(&input_method, value, &[0]);
    }
    ok &= delete_xos_dword_if_matches(
        r"HKLM\SOFTWARE\Microsoft\MdmCommon\SettingValues",
        "LocationSyncEnabled",
        &[0],
    );
    ok
}

fn device_census_disallow_run() -> std::io::Result<bool> {
    let parent = r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer";
    let child = format!(r"{parent}\DisallowRun");
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let is_census = |key: &RegKey, name: &str| {
        key.get_value::<String, _>(name)
            .map(|v| eq_ci(&v, "DeviceCensus.exe"))
            .unwrap_or(false)
    };

    let mut removed = false;
    let empty;
    {
        let key = match hkcu.open_subkey_with_flags(&child, KEY_ALL_ACCESS) {
            Ok(k) => k,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(true),
            Err(e) => return Err(e),
        };
        let names: Vec<String> = key
            .enum_values()
            .filter_map(|r| r.ok())
            .map(|(n, _)| n)
            .collect();
        for name in names {
            if is_census(&key, &name) {
                let _ = key.delete_value(&name);
                removed = true;
            }
        }
        let info = key.query_info()?;
        empty = info.values == 0 && info.sub_keys == 0;
    }

    if empty {
        match hkcu.delete_subkey_all(&child) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        match hkcu.open_subkey_with_flags(parent, KEY_ALL_ACCESS) {
            Ok(key) => {
                if key.get_value::<u32, _>("DisallowRun").ok() == Some(1) {
                    let _ = key.delete_value("DisallowRun");
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }

    if let Ok(key) = hkcu.open_subkey_with_flags(&child, KEY_READ) {
        let names: Vec<String> = key
            .enum_values()
            .filter_map(|r| r.ok())
            .map(|(n, _)| n)
            .collect();
        for name in names {
            if is_census(&key, &name) {
                return Ok(false);
            }
        }
    }
    uninstall_log(if removed {
        "  DeviceCensus.exe removed from DisallowRun"
    } else {
        "  DeviceCensus.exe was not present in DisallowRun"
    });
    Ok(true)
}

pub fn restore_device_census_disallow_run() -> bool {
    match device_census_disallow_run() {
        Ok(r) => r,
        Err(e) => {
            uninstall_log(&format!(
                "  DeviceCensus.exe DisallowRun restore FAILED: {e}"
            ));
            false
        }
    }
}

pub fn restore_power_timeout_backup() -> bool {
    let balanced = "381b4222-f694-41f0-9685-ff5bb260df2e";
    let build = xos_sys::get_windows_build_number();
    let current = build >= 22621;
    let monitor_ac = if current { 300 } else { 600 };
    let monitor_dc = if current { 180 } else { 300 };
    let standby_ac = if current { 900 } else { 1800 };
    let standby_dc = if current { 600 } else { 900 };

    let map: [(&str, &str, bool, i32); 8] = [
        ("SUB_VIDEO", "VIDEOIDLE", false, monitor_ac),
        ("SUB_VIDEO", "VIDEOIDLE", true, monitor_dc),
        ("SUB_DISK", "DISKIDLE", false, 1200),
        ("SUB_DISK", "DISKIDLE", true, 600),
        ("SUB_SLEEP", "STANDBYIDLE", false, standby_ac),
        ("SUB_SLEEP", "STANDBYIDLE", true, standby_dc),
        ("SUB_SLEEP", "HIBERNATEIDLE", false, 0),
        ("SUB_SLEEP", "HIBERNATEIDLE", true, 0),
    ];

    let mut ok = true;
    let mut written = 0;
    let mut failed = 0;
    for (sub, setting, dc, value) in map {
        let verb = if dc {
            "/setdcvalueindex"
        } else {
            "/setacvalueindex"
        };
        let applied = xos_sys::run_cmd(
            "powercfg.exe",
            &format!("{verb} {balanced} {sub} {setting} {value}"),
        );
        if applied {
            written += 1;
        } else {
            failed += 1;
            uninstall_log(&format!(
                "  Power timeout {sub} {setting} {} could not be written",
                if dc { "DC" } else { "AC" }
            ));
        }
        ok &= applied;
    }

    let activated = xos_sys::run_cmd("powercfg.exe", &format!("/setactive {balanced}"));
    ok &= activated;
    uninstall_log(&format!(
        "  Power timeouts set to the Windows defaults for build {build}: {written} written, {failed} failed, Balanced activated {}",
        pass_text(activated)
    ));
    ok
}

pub fn delete_xos_string_value_if_matches(key: &str, value: &str, xos_values: &[&str]) -> bool {
    let current = match xos_sys::reg_get_string(key, value) {
        Some(c) => c,
        None => return true,
    };
    for candidate in xos_values {
        if current == *candidate {
            uninstall_log(&format!("  Removing XOS value {key}\\{value} = {current}"));
            return uninstall_reg_del(key, value);
        }
    }
    uninstall_log(&format!(
        "  {key}\\{value} was changed by the user, left unchanged"
    ));
    true
}

pub fn remove_override_value(key: &str, value: &str, label: &str) -> bool {
    if !xos_sys::reg_value_exists(key, value) {
        uninstall_log(&format!("  {label} was not present"));
        return true;
    }
    let removed = xos_sys::reg_delete_value(key, value);
    uninstall_log(&if removed {
        format!("  {label} removed")
    } else {
        format!("  {label} could not be removed")
    });
    removed
}

fn run_encoded_ti_output(script: &str, timeout_ms: u32) -> (i32, String) {
    let encoded = encode_power_shell_command(script);
    xos_sys::run_as_ti_output_timeout(
        "powershell.exe",
        &format!("-NoProfile -NonInteractive -EncodedCommand {encoded}"),
        timeout_ms,
    )
}

fn output_or(output: &str, fallback: &'static str) -> String {
    if output.trim().is_empty() {
        fallback.to_string()
    } else {
        output.trim().to_string()
    }
}

pub fn restore_playbook_msi_mode_overrides() -> bool {
    uninstall_log("--- MSI MODE (playbook overrides) ---");
    let (exit_code, output) = run_encoded_ti_output(scripts::MSI_MODE, 120000);
    uninstall_log(&format!(
        "  MSI mode restore: {}",
        output_or(&output, "no output")
    ));
    exit_code == 0 && contains_ci(&output, "unresolved=0")
}

pub fn restore_nic_class_overrides() -> bool {
    uninstall_log("--- NETWORK ADAPTER POWER VALUES ---");
    let (exit_code, output) = run_encoded_ti_output(scripts::NIC_CLASS, 120000);
    uninstall_log(&format!(
        "  Adapter value restore: {}",
        output_or(&output, "no output")
    ));
    exit_code == 0 && contains_ci(&output, "unresolved=0")
}

pub fn restore_ms_power_overrides() -> bool {
    uninstall_log("--- DEVICE POWER MANAGEMENT (MSPower_DeviceEnable) ---");
    let (exit_code, output) = run_encoded_ti_output(scripts::MS_POWER, 120000);
    uninstall_log(&format!(
        "  Device power restore: {}",
        output_or(&output, "no output")
    ));
    exit_code == 0 && contains_ci(&output, "unresolved=0")
}

pub fn write_stock_hardware_restored_marker(groups_restored: bool) {
    uninstall_log("--- STOCK HARDWARE MARKER ---");
    uninstall_log(&format!(
        "  {}",
        stock_hardware_marker::write_default(groups_restored)
    ));
}

pub fn restore_visual_and_graphics_overrides() -> bool {
    uninstall_log("--- VISUAL AND GRAPHICS OVERRIDES ---");
    let mut ok = true;

    let ns = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace";
    let ns32 =
        r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace";
    let folder_clsids = [
        "{24ad3ad4-a569-4530-98e1-ab02f9417aa8}",
        "{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}",
        "{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}",
        "{1CF1260C-4DD0-4ebb-811F-33C572699FDE}",
        "{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}",
        "{A0953C92-50DC-43bf-BE83-3742FED03C9C}",
    ];
    let mut recreated = 0;
    for clsid in folder_clsids {
        let native_created = xos_sys::reg_create_key(&format!("{ns}\\{clsid}"));
        let wow_created = xos_sys::reg_create_key(&format!("{ns32}\\{clsid}"));
        if native_created && wow_created {
            recreated += 1;
        } else {
            ok = false;
            uninstall_log(&format!("  This PC folder {clsid} could not be restored"));
        }
    }
    uninstall_log(&format!(
        "  This PC folders restored: {recreated}/{}",
        folder_clsids.len()
    ));

    ok &= remove_override_value(
        r"HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers",
        "DisableOverlays",
        "Hardware overlay override",
    );
    ok &= remove_override_value(
        r"HKCU\Software\Microsoft\Windows\DWM",
        "CompositionPolicy",
        "Desktop composition override",
    );

    let write_cache_encoded = encode_power_shell_command(scripts::WRITE_CACHE);
    let (_, write_cache_output) = xos_sys::run_as_ti_output(
        "powershell.exe",
        &format!("-NoProfile -NonInteractive -EncodedCommand {write_cache_encoded}"),
    );
    uninstall_log(&format!(
        "  Write-cache buffer flushing restore: {}",
        output_or(&write_cache_output, "no output")
    ));

    ok
}

pub fn restore_compatibility_service_defaults() -> bool {
    uninstall_log("  Applying documented Windows Update and Search service enable/default values");
    let mut ok = true;
    let build = xos_sys::get_windows_build_number();
    let items: [(&str, i32); 13] = [
        ("WSearch", 2),
        ("RasMan", 3),
        ("RasAuto", 3),
        ("IKEEXT", 3),
        ("PolicyAgent", 3),
        ("RASSSTP", 3),
        ("SstpSvc", 3),
        ("wuauserv", 3),
        ("UsoSvc", 2),
        ("WaaSMedicSvc", 3),
        ("BITS", 2),
        ("DoSvc", 2),
        ("uhssvc", if build == 19045 { 4 } else { 3 }),
    ];
    for (name, start) in items {
        ok &= set_service_start_exact_if_present(name, start);
    }
    ok &= uninstall_reg_del_key(r"HKLM\SOFTWARE\XOSToolkit\UpdateServiceBackup");
    ok
}

fn volume_label(root: &str) -> Result<String, String> {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::GetVolumeInformationW;

    let wide: Vec<u16> = root.encode_utf16().chain(std::iter::once(0)).collect();
    let mut name = [0u16; 261];
    unsafe {
        GetVolumeInformationW(
            PCWSTR(wide.as_ptr()),
            Some(&mut name),
            None,
            None,
            None,
            None,
        )
        .map_err(|e| e.message())?;
    }
    let len = name.iter().position(|&c| c == 0).unwrap_or(name.len());
    Ok(String::from_utf16_lossy(&name[..len]))
}

fn boot_menu_policy(output: &str) -> String {
    let re = Regex::new(r"(?im)^\s*bootmenupolicy\s+(\w+)").unwrap();
    match re.captures(output) {
        Some(c) => c[1].to_string(),
        None => "Standard".to_string(),
    }
}

pub fn restore_xos_boot_description_and_volume_label() -> bool {
    let mut ok = true;
    if let Some(root) = path_root(&windows_directory()) {
        if !root.is_empty() {
            match volume_label(&root) {
                Ok(label) => {
                    if eq_ci(&label, "XOS") {
                        let letter = root.chars().next().unwrap().to_uppercase().to_string();
                        let script = format!(
                            "Set-Volume -DriveLetter '{letter}' -NewFileSystemLabel ([string]::Empty) -ErrorAction Stop"
                        );
                        let cleared = run_encoded_power_shell_as_ti(&script, 60000);
                        let actual = if cleared {
                            Some(volume_label(&root))
                        } else {
                            None
                        };
                        let verified = match &actual {
                            Some(Ok(l)) => cleared && l.is_empty(),
                            Some(Err(_)) => false,
                            None => false,
                        };
                        if let Some(Err(e)) = &actual {
                            ok = false;
                            uninstall_log(&format!("  Volume label restore FAILED: {e}"));
                        }
                        ok &= verified;
                        uninstall_log(&format!(
                            "  XOS volume label removal: {}",
                            pass_text(verified)
                        ));
                    } else {
                        uninstall_log("  System volume label is not XOS, left unchanged");
                    }
                }
                Err(e) => {
                    ok = false;
                    uninstall_log(&format!("  Volume label restore FAILED: {e}"));
                }
            }
        }
    }

    let (query_code, query_output) = xos_sys::run_as_ti_output("bcdedit.exe", "/enum {current}");
    if query_code != 0 {
        uninstall_log(&format!(
            "  Current boot description query FAILED ({query_code})"
        ));
        session_log::operation_failed("BCD restore", "boot description query");
        return false;
    }
    if contains_ci(&query_output, "XOS-Playbook-") {
        let product_name = xos_sys::reg_get_string(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "ProductName",
        )
        .unwrap_or_else(|| "Windows".to_string())
        .replace('"', "");
        let (changed_code, _) = xos_sys::run_as_ti_output(
            "bcdedit.exe",
            &format!("/set {{current}} description \"{product_name}\""),
        );
        let (after_code, after_output) =
            xos_sys::run_as_ti_output("bcdedit.exe", "/enum {current}");
        let verified =
            changed_code == 0 && after_code == 0 && !contains_ci(&after_output, "XOS-Playbook-");
        ok &= verified;
        uninstall_log(&format!(
            "  XOS boot description removal: {}",
            pass_text(verified)
        ));
    } else {
        uninstall_log("  Current boot description is not XOS-owned, left unchanged");
    }

    let mut current_policy: Option<String> = None;
    let (pol_code, pol_output) = xos_sys::run_as_ti_output("bcdedit.exe", "/enum {current}");
    if pol_code == 0 {
        current_policy = Some(boot_menu_policy(&pol_output));
    } else {
        ok = false;
        uninstall_log(&format!("  Boot menu policy query FAILED ({pol_code})"));
    }
    if current_policy
        .as_deref()
        .map(|p| eq_ci(p, "Legacy"))
        .unwrap_or(false)
    {
        let (change_code, _) =
            xos_sys::run_as_ti_output("bcdedit.exe", "/set bootmenupolicy Standard");
        let (after_code, after_output) =
            xos_sys::run_as_ti_output("bcdedit.exe", "/enum {current}");
        let restored_policy = boot_menu_policy(&after_output);
        let ok_policy = change_code == 0 && after_code == 0 && eq_ci(&restored_policy, "Standard");
        ok &= ok_policy;
        uninstall_log(&format!(
            "  Boot menu policy restored to Standard: {}",
            pass_text(ok_policy)
        ));
    } else if pol_code == 0 {
        uninstall_log(&format!(
            "  Boot menu policy is not Legacy, left unchanged (current={})",
            current_policy.as_deref().unwrap_or("")
        ));
    }

    let (timeout_code, _) = xos_sys::run_as_ti_output("bcdedit.exe", "/timeout 30");
    let ok_timeout = timeout_code == 0;
    ok &= ok_timeout;
    uninstall_log(&format!(
        "  Boot timeout restored to the Windows default 30: {}",
        pass_text(ok_timeout)
    ));
    if !ok {
        session_log::operation_failed(
            "BCD restore",
            "boot description, menu policy or volume label",
        );
    }
    ok
}

pub fn restore_deterministic_xos_leftovers() -> bool {
    let mut ok = true;
    ok &= uninstall_reg_del(
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Communications",
        "ConfigureChatAutoInstall",
    );
    ok &= uninstall_reg_del(
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings",
        "TaskbarEndTask",
    );
    ok &= uninstall_reg_del(
        r"HKCU\SOFTWARE\Microsoft\TabletTip\1.7",
        "TipbandDesiredVisibility",
    );
    ok &= uninstall_reg_del(
        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People",
        "PeopleBand",
    );
    ok &= uninstall_reg_del(
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
        "HideSCAMeetNow",
    );
    ok &= uninstall_reg_del(
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
        "HideSCAMeetNow",
    );
    ok &= uninstall_reg_del(
        r"HKLM\Software\Policies\Microsoft\Windows\Server\InitialConfigurationTasks",
        "DoNotOpenAtLogon",
    );

    for key in [
        r"HKCR\RunAsTI",
        r"HKCR\batfile\shell\setdesktopwallpaper",
        r"HKCR\cmdfile\shell\setdesktopwallpaper",
        r"HKCR\exefile\shell\setdesktopwallpaper",
        r"HKCR\mscfile\shell\setdesktopwallpaper",
        r"HKCR\Microsoft.PowerShellScript.1\shell\setdesktopwallpaper",
        r"HKCR\regfile\shell\setdesktopwallpaper",
        r"HKCR\Folder\shell\setdesktopwallpaper",
        r"HKCR\*\shell\TakeOwnership",
        r"HKCR\Directory\shell\TakeOwnership",
        r"HKCR\Microsoft.PowerShellScript.1\Shell\RunAs",
    ] {
        ok &= uninstall_reg_del_key(key);
    }

    let (menu_ok, menu_detail) = xos_sys::restore_power_plan_menu_snapshot();
    if menu_ok {
        uninstall_log(&format!("  Power Plan context menu: {menu_detail}"));
    } else {
        uninstall_log(&format!(
            "  Power Plan context menu restore failed ({menu_detail}), removing it"
        ));
        ok &= uninstall_reg_del_key(r"HKCR\DesktopBackground\Shell\PowerPlan");
    }

    {
        let drive_run_as = r"HKCR\Drive\shell\runas";
        let drive_label = xos_sys::reg_get_string(drive_run_as, "");
        let drive_command =
            xos_sys::reg_get_string(&format!(r"{drive_run_as}\command"), "").unwrap_or_default();
        let is_xos_drive_handler = drive_label
            .as_deref()
            .map(|l| eq_ci(l, "Take Ownership"))
            .unwrap_or(false)
            || (contains_ci(&drive_command, "icacls")
                && contains_ci(&drive_command, "*S-1-5-32-544"));
        if is_xos_drive_handler {
            ok &= uninstall_reg_del_key(drive_run_as);
        } else {
            uninstall_log("  Drive runas handler is not XOS-owned, left unchanged");
        }
    }

    ok &= remove_xsudo_install();
    ok &= restore_windows_time_configuration();
    ok
}

pub const XSUDO_SHELL_CLASSES: [&str; 7] = [
    "exefile",
    "batfile",
    "cmdfile",
    "Microsoft.PowerShellScript.1",
    "mscfile",
    "regfile",
    "Folder",
];

pub const XSUDO_CREATED_VALUE: &str = "XSudoCreated";

pub fn xsudo_created_parents(class: &str, marker: Option<&str>) -> Vec<String> {
    let shell = format!(r"HKLM\SOFTWARE\Classes\{class}\shell");
    match marker.map(|m| m.trim().to_ascii_lowercase()) {
        Some(m) if m == "class" => vec![shell, format!(r"HKLM\SOFTWARE\Classes\{class}")],
        Some(m) if m == "shell" => vec![shell],
        _ => Vec::new(),
    }
}

fn hklm_key_is_empty(path: &str) -> bool {
    let sub = match path.split_once('\\') {
        Some((_, sub)) => sub,
        None => return false,
    };
    match RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(sub, KEY_READ) {
        Ok(key) => key
            .query_info()
            .map(|i| i.sub_keys == 0 && i.values == 0)
            .unwrap_or(false),
        Err(_) => false,
    }
}

pub struct XsudoInstallPaths {
    pub dir: std::path::PathBuf,
    pub exe: std::path::PathBuf,
    pub shortcut: std::path::PathBuf,
    pub shell_keys: Vec<String>,
}

pub fn xsudo_install_paths(program_files: &str, program_data: &str) -> XsudoInstallPaths {
    let dir = Path::new(program_files).join("XSudo");
    XsudoInstallPaths {
        exe: dir.join("XSudo.exe"),
        dir,
        shortcut: Path::new(program_data)
            .join(r"Microsoft\Windows\Start Menu\Programs")
            .join("XSudo.lnk"),
        shell_keys: XSUDO_SHELL_CLASSES
            .iter()
            .map(|c| format!(r"HKLM\SOFTWARE\Classes\{c}\shell\XSudoRunAsTI"))
            .collect(),
    }
}

fn delete_now_or_at_restart(path: &Path, is_dir: bool) -> Result<&'static str, String> {
    let removed = if is_dir {
        std::fs::remove_dir(path)
    } else {
        std::fs::remove_file(path)
    };
    match removed {
        Ok(()) => Ok("removed"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok("not present"),
        Err(e) => {
            let wide = windows::core::HSTRING::from(path.as_os_str());
            unsafe {
                windows::Win32::Storage::FileSystem::MoveFileExW(
                    &wide,
                    windows::core::PCWSTR::null(),
                    windows::Win32::Storage::FileSystem::MOVEFILE_DELAY_UNTIL_REBOOT,
                )
            }
            .map(|_| "in use, removed at the next restart")
            .map_err(|e2| format!("{e}; removal at restart could not be scheduled: {e2}"))
        }
    }
}

pub fn remove_xsudo_install() -> bool {
    let program_files = std::env::var("ProgramW6432")
        .or_else(|_| std::env::var("ProgramFiles"))
        .unwrap_or_else(|_| r"C:\Program Files".to_string());
    let program_data =
        std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string());
    let paths = xsudo_install_paths(&program_files, &program_data);
    let mut ok = true;
    let previous = paths.dir.join("XSudo.exe.old");
    for (path, is_dir, label) in [
        (&paths.exe, false, "XSudo program"),
        (&previous, false, "XSudo program replaced while in use"),
        (&paths.shortcut, false, "XSudo Start menu shortcut"),
        (&paths.dir, true, "XSudo folder"),
    ] {
        match delete_now_or_at_restart(path, is_dir) {
            Ok(what) => uninstall_log(&format!("  {label} {}: {what}", path.display())),
            Err(e) => {
                ok = false;
                uninstall_log(&format!("  {label} {}: FAILED ({e})", path.display()));
            }
        }
    }
    for (class, key) in XSUDO_SHELL_CLASSES.iter().zip(paths.shell_keys.iter()) {
        if !xos_sys::reg_key_exists(key) {
            uninstall_log(&format!("  DELKEY: not found  -- {key}"));
            continue;
        }
        let marker = xos_sys::reg_get_string(key, XSUDO_CREATED_VALUE);
        let removed = uninstall_reg_del_key(key);
        ok &= removed;
        if !removed {
            continue;
        }
        for parent in xsudo_created_parents(class, marker.as_deref()) {
            if hklm_key_is_empty(&parent) {
                uninstall_log(&format!(
                    "  {parent} was created by XSudo and is empty, removing it"
                ));
                ok &= uninstall_reg_del_key(&parent);
            } else {
                uninstall_log(&format!(
                    "  {parent} was created by XSudo but is not empty or not present, left unchanged"
                ));
                break;
            }
        }
    }
    uninstall_log(r"  The XSudo window's saved list (%APPDATA%\XSudo) is left to the user");
    ok
}

pub fn parse_registry_defaults(text: &str, build: &str) -> (Vec<Vec<String>>, i32) {
    let mut rows = Vec::new();
    let mut skipped = 0;
    for raw in text.split('\n') {
        let line = raw.trim_end_matches('\r');
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<String> = line.split('\t').map(|s| s.to_string()).collect();
        if parts.len() < 5 {
            continue;
        }
        let builds = parts[4].trim();
        if builds != "*" && !builds.split(',').any(|b| b == build) {
            skipped += 1;
            continue;
        }
        rows.push(parts);
    }
    (rows, skipped)
}

pub fn restore_windows_registry_defaults() -> bool {
    let text = include_str!("../../../resources/XOS-RegistryDefaults.tsv");

    let build = xos_sys::get_windows_build_number().to_string();
    let mut ok = true;
    let (mut written, mut deleted, mut failed) = (0, 0, 0);
    let (rows, skipped) = parse_registry_defaults(text, &build);
    let mut default_hive_rows: Vec<Vec<String>> = Vec::new();
    for parts in rows {
        let (key, name, kind, data) = (
            parts[0].as_str(),
            parts[1].as_str(),
            parts[2].as_str(),
            parts[3].as_str(),
        );
        if key.to_ascii_uppercase().starts_with(DEFAULT_HIVE_PREFIX) {
            default_hive_rows.push(parts.clone());
            continue;
        }
        let done;
        if kind == "delete" {
            done = uninstall_reg_del(key, name);
            if done {
                deleted += 1;
            }
        } else if kind == "dword" && data.trim().parse::<i32>().is_ok() {
            done = uninstall_reg_set(key, name, data.trim().parse::<i32>().unwrap());
            if done {
                written += 1;
            }
        } else if kind == "sz" {
            done = uninstall_reg_set_str(key, name, data);
            if done {
                written += 1;
            }
        } else {
            uninstall_log(&format!(
                "  Registry defaults row not understood: {}",
                parts.join("\t")
            ));
            done = false;
        }
        if !done {
            failed += 1;
        }
        ok &= done;
    }

    uninstall_log(&format!(
        "  Windows registry defaults: written={written} deleted={deleted} not for this build={skipped} failed={failed}"
    ));
    ok &= restore_default_user_hive(&default_hive_rows);
    ok &= restore_power_shell_script_association();
    ok
}

fn default_hive_value_state(key: &str, name: &str) -> (&'static str, Option<String>) {
    match RegKey::predef(HKEY_USERS).open_subkey_with_flags(&key[4..], KEY_READ) {
        Ok(sub_key) => {
            for entry in sub_key.enum_values() {
                match entry {
                    Ok((value_name, _)) => {
                        if eq_ci(&value_name, name) {
                            return ("present", None);
                        }
                    }
                    Err(e) => return ("unreadable", Some(format!("IOException: {e}"))),
                }
            }
            ("absent", None)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => ("absent", None),
        Err(e) => ("unreadable", Some(format!("IOException: {e}"))),
    }
}

pub fn restore_default_user_hive(rows: &[Vec<String>]) -> bool {
    if rows.is_empty() {
        return true;
    }
    let reg = path_combine(&system_directory(), "reg.exe");
    let profile_dir = xos_sys::expand_environment_variables(
        &xos_sys::reg_get_string(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList",
            "Default",
        )
        .unwrap_or_else(|| r"%SystemDrive%\Users\Default".to_string()),
    );
    let hive = path_combine(&profile_dir, "NTUSER.DAT");
    let mount = r"HKU\XOS_Uninstall_DefaultUser";

    xos_sys::run_cmd_capture(&reg, &format!("unload \"{mount}\""));
    let (load_code, load_out, load_err) =
        xos_sys::run_cmd_capture(&reg, &format!("load \"{mount}\" \"{hive}\""));
    if load_code != 0 {
        uninstall_log(&format!(
            "  Default user profile hive: FAILED, {hive} could not be loaded ({}); new accounts may still get XOS values",
            format!("{load_err} {load_out}").trim()
        ));
        return false;
    }

    let mut ok = true;
    let (mut deleted, mut absent, mut failed) = (0, 0, 0);
    for row in rows {
        let key = format!(r"{mount}\{}", &row[0][DEFAULT_HIVE_PREFIX.len()..]);
        let name = row[1].as_str();
        if row[2] != "delete" {
            uninstall_log(&format!(
                "  Default user profile hive: FAILED, row not understood: {}",
                row.join(" ")
            ));
            failed += 1;
            ok = false;
            continue;
        }
        let (before, before_error) = default_hive_value_state(&key, name);
        if before == "absent" {
            absent += 1;
            continue;
        }
        if before == "unreadable" {
            uninstall_log(&format!(
                "  Default user profile hive: FAILED, {}\\{name} could not be read ({})",
                row[0],
                before_error.unwrap_or_default()
            ));
            failed += 1;
            ok = false;
            continue;
        }
        xos_sys::run_cmd_capture(&reg, &format!("delete \"{key}\" /v \"{name}\" /f"));
        let (after, after_error) = default_hive_value_state(&key, name);
        if after != "absent" {
            uninstall_log(&format!(
                "  Default user profile hive: FAILED, {}\\{name} could not be deleted{}",
                row[0],
                if after == "unreadable" {
                    format!(" (read back failed: {})", after_error.unwrap_or_default())
                } else {
                    String::new()
                }
            ));
            failed += 1;
            ok = false;
        } else {
            deleted += 1;
        }
    }

    let mut unloaded = false;
    let mut attempt = 1;
    while attempt <= 5 && !unloaded {
        let (code, out, err) = xos_sys::run_cmd_capture(&reg, &format!("unload \"{mount}\""));
        unloaded = code == 0;
        if !unloaded {
            uninstall_log(&format!(
                "  Default user profile hive: unload attempt {attempt} FAILED ({})",
                format!("{err} {out}").trim()
            ));
            std::thread::sleep(std::time::Duration::from_millis(2000));
        }
        attempt += 1;
    }
    if !unloaded {
        uninstall_log(
            "  Default user profile hive: FAILED, it is still mounted and changes may not be saved until restart",
        );
        ok = false;
    }
    uninstall_log(&format!(
        "  Default user profile hive: deleted={deleted} already absent={absent} failed={failed} {}",
        pass_text(ok)
    ));
    ok
}

pub fn restore_sample_submission_default(engine_running: bool) -> bool {
    let spynet = r"HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet";
    let hint = "  Automatic sample submission could not be set back to the Windows default. Turn it on in Windows Security.";
    if !engine_running {
        let written = uninstall_reg_set(spynet, "SubmitSamplesConsent", 1);
        if !written {
            uninstall_log(hint);
        }
        return written;
    }

    let before = xos_sys::reg_get_dword(spynet, "SubmitSamplesConsent");
    if before != Some(1) {
        xos_sys::run_cmd_timeout(
            "powershell.exe",
            "-NoProfile -NonInteractive -Command \"Set-MpPreference -SubmitSamplesConsent 1\"",
            60000,
        );
        if xos_sys::reg_get_dword(spynet, "SubmitSamplesConsent") != Some(1) {
            xos_sys::run_as_ti(
                "reg.exe",
                &format!("add \"{spynet}\" /v SubmitSamplesConsent /t REG_DWORD /d 1 /f"),
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(3000));
    }
    let settled = xos_sys::reg_get_dword(spynet, "SubmitSamplesConsent");
    uninstall_log(&format!(
        "  SET [SubmitSamplesConsent]: {} -> 1  actual after 3 s={}  {}  -- {spynet}",
        fmt_val_int(before),
        fmt_val_int(settled),
        if settled == Some(1) {
            "OK"
        } else {
            "left as Defender has it"
        }
    ));
    if settled != Some(1) {
        uninstall_log(hint);
    }
    true
}

pub fn restore_power_shell_script_association() -> bool {
    let script_class = r"HKLM\SOFTWARE\Classes\Microsoft.PowerShellScript.1";
    let module_class = r"HKLM\SOFTWARE\Classes\Microsoft.PowerShellModule.1";
    let windows10 = xos_sys::get_windows_build_number() < 22000;
    let mut ok = true;

    let script_shipped = xos_sys::reg_value_exists(script_class, "FriendlyTypeName")
        || xos_sys::reg_get_string(r"HKLM\SOFTWARE\Classes\.ps1", "")
            .map(|v| eq_ci(&v, "Microsoft.PowerShellScript.1"))
            .unwrap_or(false);
    if script_shipped {
        let notepad = format!(
            "\"{}\" \"%1\"",
            path_combine(
                &path_combine(&windows_directory(), "System32"),
                "notepad.exe"
            )
        );
        let command_key = format!(r"{script_class}\Shell\Open\Command");
        let written = xos_sys::reg_set_string(&command_key, "", &notepad)
            && xos_sys::reg_get_string(&command_key, "")
                .map(|v| eq_ci(&v, &notepad))
                .unwrap_or(false)
            && restore_shell_default_verb(script_class, windows10);
        record_action_command(written);
        ok &= written;
        uninstall_log(if written {
            "  .ps1 files open in Notepad again (Windows PowerShell class present)"
        } else {
            "  .ps1 Open command restore FAILED"
        });
    } else if xos_sys::reg_key_exists(script_class) {
        ok &= uninstall_reg_del_key(script_class);
        uninstall_log("  .ps1 class created by the Playbook removed (this Windows ships none)");
    }

    if script_shipped || xos_sys::reg_value_exists(module_class, "FriendlyTypeName") {
        let written = restore_shell_default_verb(module_class, windows10);
        record_action_command(written);
        ok &= written;
        if !written {
            uninstall_log("  .psm1 Shell default verb restore FAILED");
        }
    } else {
        if xos_sys::reg_key_exists(module_class) {
            ok &= uninstall_reg_del_key(module_class);
        }
        if xos_sys::reg_get_string(r"HKLM\SOFTWARE\Classes\.psm1", "")
            .map(|v| eq_ci(&v, "Microsoft.PowerShellModule.1"))
            .unwrap_or(false)
        {
            ok &= uninstall_reg_del_key(r"HKLM\SOFTWARE\Classes\.psm1");
        }
    }
    ok
}

pub fn restore_shell_default_verb(class_key: &str, windows10: bool) -> bool {
    let shell = format!(r"{class_key}\Shell");
    if windows10 {
        return xos_sys::reg_set_string(&shell, "", "Open")
            && xos_sys::reg_get_string(&shell, "")
                .map(|v| eq_ci(&v, "Open"))
                .unwrap_or(false);
    }
    xos_sys::reg_delete_value(&shell, "")
}

pub fn restore_windows_time_configuration() -> bool {
    if !xos_sys::service_exists("W32Time") {
        uninstall_log("  W32Time is not present, time configuration skipped");
        return true;
    }
    let ok = run_encoded_power_shell_as_ti(scripts::WINDOWS_TIME, 60000);
    uninstall_log(&format!("  Windows Time configuration: {}", pass_text(ok)));
    ok
}

pub fn remove_xos_blank_start_layouts() -> bool {
    let system_drive = path_root(&windows_directory()).unwrap_or_else(|| r"C:\".to_string());
    let default_layout = path_combine(
        &system_drive,
        r"Users\Default\AppData\Local\Microsoft\Windows\Shell\LayoutModification.xml",
    );
    let user_layout = path_combine(
        &local_application_data(),
        r"Microsoft\Windows\Shell\LayoutModification.xml",
    );
    let script = format!(
        "{}{}{}{}{}",
        scripts::START_LAYOUT_0,
        escape_power_shell_literal(&default_layout),
        scripts::START_LAYOUT_2,
        escape_power_shell_literal(&user_layout),
        scripts::START_LAYOUT_4
    );
    let ok = run_encoded_power_shell_as_ti(&script, 60000);
    uninstall_log(&format!("  XOS blank Start layouts: {}", pass_text(ok)));
    ok
}

pub fn verify_compatibility_restore(
    service_defaults_restored: bool,
    windows_search_restored: bool,
    optional_features_restored: bool,
    process_mitigations_restored: bool,
) -> bool {
    uninstall_log("--- COMPATIBILITY VERIFICATION ---");
    let mut failures: Vec<&str> = Vec::new();
    let mut ok = true;
    if !windows_search_restored {
        ok = false;
        failures.push("Windows Search");
        uninstall_log("  Windows Search enable sequence was not verified");
    }
    if !optional_features_restored {
        ok = false;
        failures.push("optional features");
    }
    if !process_mitigations_restored {
        ok = false;
        failures.push("process mitigations");
    }
    if !service_defaults_restored {
        ok = false;
        failures.push("Toolkit service defaults");
        uninstall_log("  Documented Toolkit service defaults were not fully verified");
    }

    let mut state_checks_ok = xos_sys::reg_get_dword(
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "EnableLUA",
    ) == Some(1);
    state_checks_ok &= xos_sys::reg_get_dword(
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching",
        "SearchOrderConfig",
    ) != Some(0);
    state_checks_ok &= xos_sys::reg_get_dword(
        r"HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings",
        "ExcludeWUDriversInQualityUpdate",
    ) != Some(1);
    state_checks_ok &= xos_sys::reg_get_dword(
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\DriverSearching",
        "SearchOrderConfig",
    ) != Some(0);
    state_checks_ok &= !xos_sys::reg_value_exists(
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender",
        "DisableAntiSpyware",
    );
    state_checks_ok &= xos_sys::reg_get_dword(
        r"HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection",
        "DisableRealtimeMonitoring",
    ) != Some(1);
    state_checks_ok &= !xos_sys::reg_value_exists(
        r"HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy",
        "VerifiedAndReputablePolicyState",
    );
    state_checks_ok &= xos_sys::reg_get_dword(
        r"HKLM\SYSTEM\CurrentControlSet\Control",
        "SvcHostSplitThresholdInKB",
    )
    .unwrap_or(3670016)
        == 3670016;
    state_checks_ok &= !xos_sys::reg_value_exists(
        r"HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters",
        "DisableCoalescing",
    );
    ok &= state_checks_ok;
    if !state_checks_ok {
        failures.push("post-state registry cleanup");
    }

    uninstall_log(&format!(
        "  Compatibility restore verification: {}",
        if ok { "PASSED" } else { "FAILED" }
    ));
    if !ok {
        let detail = if failures.is_empty() {
            "one or more checks".to_string()
        } else {
            failures.join(", ")
        };
        uninstall_log(&format!("  Compatibility restore failures: {detail}"));
        session_log::operation_failed("compatibility restore", &detail);
    }
    ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xsudo_install_paths_match_the_playbook_and_the_window() {
        let p = xsudo_install_paths(r"C:\Program Files", r"C:\ProgramData");
        assert_eq!(p.dir, Path::new(r"C:\Program Files\XSudo"));
        assert_eq!(p.exe, Path::new(r"C:\Program Files\XSudo\XSudo.exe"));
        assert_eq!(
            p.shortcut,
            Path::new(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\XSudo.lnk")
        );
        assert_eq!(
            p.shell_keys,
            [
                r"HKLM\SOFTWARE\Classes\exefile\shell\XSudoRunAsTI",
                r"HKLM\SOFTWARE\Classes\batfile\shell\XSudoRunAsTI",
                r"HKLM\SOFTWARE\Classes\cmdfile\shell\XSudoRunAsTI",
                r"HKLM\SOFTWARE\Classes\Microsoft.PowerShellScript.1\shell\XSudoRunAsTI",
                r"HKLM\SOFTWARE\Classes\mscfile\shell\XSudoRunAsTI",
                r"HKLM\SOFTWARE\Classes\regfile\shell\XSudoRunAsTI",
                r"HKLM\SOFTWARE\Classes\Folder\shell\XSudoRunAsTI",
            ]
        );
    }

    #[test]
    fn xsudo_removes_only_the_parents_it_recorded() {
        let c = "Microsoft.PowerShellScript.1";
        assert!(xsudo_created_parents(c, None).is_empty());
        assert!(xsudo_created_parents(c, Some("")).is_empty());
        assert_eq!(
            xsudo_created_parents(c, Some("shell")),
            [r"HKLM\SOFTWARE\Classes\Microsoft.PowerShellScript.1\shell"]
        );
        assert_eq!(
            xsudo_created_parents(c, Some("CLASS")),
            [
                r"HKLM\SOFTWARE\Classes\Microsoft.PowerShellScript.1\shell",
                r"HKLM\SOFTWARE\Classes\Microsoft.PowerShellScript.1",
            ]
        );
    }

    #[test]
    fn feature_log_entry_parses_name_before_dash() {
        assert_eq!(
            try_parse_feature_log_entry(
                "12:00 [DISABLE] Microsoft-Hyper-V-All - done",
                "[DISABLE]"
            ),
            Some("Microsoft-Hyper-V-All".to_string())
        );
        assert_eq!(
            try_parse_feature_log_entry("[done] DirectPlay extra words", "[DONE]"),
            Some("DirectPlay".to_string())
        );
        assert_eq!(try_parse_feature_log_entry("nothing here", "[DONE]"), None);
        assert_eq!(
            try_parse_feature_log_entry("[ENABLE]   - x", "[ENABLE]"),
            None
        );
    }

    #[test]
    fn mitigation_mask_detection() {
        assert!(is_xos_mitigation_mask_bytes(&[0x22, 0x22, 0x00, 0x22]));
        assert!(!is_xos_mitigation_mask_bytes(&[]));
        assert!(!is_xos_mitigation_mask_bytes(&[0x22, 0x11]));
    }

    #[test]
    fn registry_defaults_rows_filter_by_build() {
        let text = "# c\r\nHKLM\\A\tv\tdelete\t\t*\r\nHKLM\\B\tw\tdword\t1\t19045,22631\r\nshort\trow\r\nHKDU\\C\tx\tdelete\t\t26200\r\n";
        let (rows, skipped) = parse_registry_defaults(text, "22631");
        assert_eq!(rows.len(), 2);
        assert_eq!(skipped, 1);
        assert_eq!(rows[1][1], "w");
    }

    #[test]
    fn embedded_registry_defaults_parse() {
        let text = include_str!("../../../resources/XOS-RegistryDefaults.tsv");
        let (rows, _) = parse_registry_defaults(text, "26200");
        assert!(!rows.is_empty());
    }

    #[test]
    fn feature_state_disabled_names() {
        assert!(is_feature_state_disabled("Disable Pending"));
        assert!(is_feature_state_disabled("disabled"));
        assert!(!is_feature_state_disabled("Enabled"));
    }

    #[test]
    fn split_lines_matches_read_all_lines() {
        assert_eq!(split_lines("a\r\nb\nc\r"), vec!["a", "b", "c"]);
        assert_eq!(split_lines("a\n\nb\n"), vec!["a", "", "b"]);
    }

    #[test]
    fn ordered_ci_overwrites_in_place() {
        let mut m = OrderedCi::new();
        m.set("A", true);
        m.set("B", false);
        m.set("a", false);
        assert_eq!(
            m.items,
            vec![("A".to_string(), false), ("B".to_string(), false)]
        );
    }

    #[test]
    fn sc_names() {
        assert_eq!(sc_start_type_name(2), "auto");
        assert_eq!(sc_start_type_name(4), "disabled");
    }

    #[test]
    fn boot_policy_regex() {
        assert_eq!(boot_menu_policy("x\n bootmenupolicy   Legacy\n"), "Legacy");
        assert_eq!(boot_menu_policy("none"), "Standard");
    }
}

use crate::util::cmp_ci;
use std::path::Path;
use std::sync::{mpsc, Mutex};
use std::time::{Duration, Instant};
use windows::core::{Interface, BSTR, PCWSTR};
use windows::Win32::Foundation::{MAX_PATH, RPC_E_CHANGED_MODE};
use windows::Win32::Storage::FileSystem::WIN32_FIND_DATAW;
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, IPersistFile, CLSCTX_INPROC_SERVER,
    COINIT_APARTMENTTHREADED, STGM_READ,
};
use windows::Win32::System::TaskScheduler::{
    IComHandlerAction, IExecAction, IRegisteredTask, ITaskFolder, ITaskService, TaskScheduler,
};
use windows::Win32::System::Variant::VARIANT;
use windows::Win32::UI::Shell::{IShellLinkW, ShellLink};
use winreg::enums::*;
use winreg::{RegKey, RegValue};
use xos_core::host::{Host, Icon, Page};
use xos_core::log;
use xos_core::ui::*;

const ACTIVE_SETUP_KEY: &str = r"SOFTWARE\Microsoft\Active Setup\Installed Components";
const STARTUP_FOLDER_APPROVED: &str =
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder";
const SAVED_STUB: &str = "XOSDisabledStubPath";
const ENTRY_NOT_TOGGLEABLE_HINT: &str = "Active Setup configures applications for user accounts. Disabling saves its setup command without marking the application uninstalled.";

#[derive(Clone, Default)]
struct LogonEntry {
    id: usize,
    enabled: bool,
    entry_name: String,
    command: String,
    location: String,
    scope: String,
    modify_hint: Option<String>,
    can_toggle: bool,
    reg_key_path: Option<String>,
    reg_value_name: Option<String>,
    file_path: Option<String>,
    approved_hive: Option<String>,
    approved_sub_key: Option<String>,
    approved_val_name: Option<String>,
    is_active_setup: bool,
}

#[derive(Clone, Default)]
struct TaskEntry {
    id: usize,
    enabled: bool,
    task_name: String,
    folder_path: String,
    full_task_path: String,
    trigger_summary: String,
    action_summary: String,
}

fn blank(s: &str) -> bool {
    s.trim().is_empty()
}

fn blank_opt(s: &Option<String>) -> bool {
    s.as_deref().map(blank).unwrap_or(true)
}

fn hive_key(name: &str) -> RegKey {
    RegKey::predef(if name == "HKLM" {
        HKEY_LOCAL_MACHINE
    } else {
        HKEY_CURRENT_USER
    })
}

fn utf16_text(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

fn utf16_bytes(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(|u| u.to_le_bytes())
        .collect()
}

fn is_string_type(t: &winreg::enums::RegType) -> bool {
    matches!(t, REG_SZ | REG_EXPAND_SZ)
}

fn raw_string(key: &RegKey, name: &str) -> Option<String> {
    let v = key.get_raw_value(name).ok()?;
    if is_string_type(&v.vtype) {
        Some(utf16_text(&v.bytes))
    } else {
        None
    }
}

fn display_value(v: &RegValue) -> String {
    match v.vtype {
        REG_SZ => utf16_text(&v.bytes),
        REG_EXPAND_SZ => xos_sys::expand_environment_variables(&utf16_text(&v.bytes)),
        REG_DWORD if v.bytes.len() >= 4 => {
            i32::from_le_bytes([v.bytes[0], v.bytes[1], v.bytes[2], v.bytes[3]]).to_string()
        }
        REG_QWORD if v.bytes.len() >= 8 => {
            let mut b = [0u8; 8];
            b.copy_from_slice(&v.bytes[..8]);
            i64::from_le_bytes(b).to_string()
        }
        REG_MULTI_SZ => "System.String[]".into(),
        _ => "System.Byte[]".into(),
    }
}

fn open_read(hive: &str, sub: &str) -> Result<Option<RegKey>, String> {
    match hive_key(hive).open_subkey_with_flags(sub, KEY_READ) {
        Ok(k) => Ok(Some(k)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

fn read_startup_approved(hive: &str, sub_key: Option<&str>, value_name: &str) -> bool {
    let Some(sub) = sub_key else { return true };
    let Ok(Some(key)) = open_read(hive, sub) else {
        return true;
    };
    match key.get_raw_value(value_name) {
        Ok(v) if v.vtype == REG_BINARY && !v.bytes.is_empty() => v.bytes[0] != 0x03,
        _ => true,
    }
}

fn read_run_key(
    hive: &str,
    sub_path: &str,
    location: &str,
    approved_bucket: &str,
    out: &mut Vec<LogonEntry>,
) -> Result<(), String> {
    let is_run_once = location == "RunOnce";
    let full_path = format!(r"{hive}\{sub_path}");
    let approved_sub = if is_run_once {
        None
    } else {
        Some(format!(
            r"{}\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\{approved_bucket}",
            if hive == "HKLM" {
                "SOFTWARE"
            } else {
                "Software"
            }
        ))
    };
    let Some(key) = open_read(hive, sub_path)? else {
        return Ok(());
    };
    for item in key.enum_values() {
        let (name, value) = item.map_err(|e| e.to_string())?;
        let data = display_value(&value);
        let enabled = is_run_once || read_startup_approved(hive, approved_sub.as_deref(), &name);
        out.push(LogonEntry {
            entry_name: name.clone(),
            command: data,
            location: location.into(),
            scope: hive.into(),
            reg_key_path: Some(full_path.clone()),
            reg_value_name: Some(name.clone()),
            approved_hive: Some(hive.into()),
            approved_sub_key: approved_sub.clone(),
            approved_val_name: Some(name),
            can_toggle: !is_run_once,
            modify_hint: if is_run_once {
                Some("RunOnce entries execute once and cannot be toggled.".into())
            } else {
                None
            },
            enabled,
            ..Default::default()
        });
    }
    Ok(())
}

fn resolve_shortcut(lnk_path: &str) -> String {
    unsafe {
        let init = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        let owned = init.is_ok();
        let result = (|| -> windows::core::Result<String> {
            if let Err(e) = init.ok() {
                if e.code() != RPC_E_CHANGED_MODE {
                    return Err(e);
                }
            }
            let link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER)?;
            let file: IPersistFile = link.cast()?;
            let wide: Vec<u16> = lnk_path.encode_utf16().chain(std::iter::once(0)).collect();
            file.Load(PCWSTR(wide.as_ptr()), STGM_READ)?;
            let mut buf = [0u16; MAX_PATH as usize];
            let mut find = WIN32_FIND_DATAW::default();
            link.GetPath(&mut buf, &mut find, 4)?;
            let target = String::from_utf16_lossy(
                &buf[..buf.iter().position(|&c| c == 0).unwrap_or(buf.len())],
            );
            let mut abuf = [0u16; 2048];
            link.GetArguments(&mut abuf)?;
            let args = String::from_utf16_lossy(
                &abuf[..abuf.iter().position(|&c| c == 0).unwrap_or(abuf.len())],
            );
            Ok(if blank(&args) {
                target
            } else {
                format!("{target} {args}")
            })
        })();
        if owned {
            CoUninitialize();
        }
        result.unwrap_or_else(|_| lnk_path.to_string())
    }
}

fn read_startup_folder(folder: &str, scope: &str, out: &mut Vec<LogonEntry>) {
    if !Path::new(folder).is_dir() {
        return;
    }
    let Ok(rd) = std::fs::read_dir(folder) else {
        return;
    };
    for entry in rd.flatten() {
        let path = entry.path();
        let listed = entry
            .file_type()
            .map(|t| t.is_file() || (t.is_symlink() && !path.is_dir()))
            .unwrap_or(false);
        if !listed {
            continue;
        }
        let ext = path
            .extension()
            .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()))
            .unwrap_or_default();
        if ext == ".ini" {
            continue;
        }
        let name = path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let file = path.to_string_lossy().into_owned();
        let command = if ext == ".lnk" {
            resolve_shortcut(&file)
        } else {
            file.clone()
        };
        let val_name = path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let approved_hive = if scope == "Common" { "HKLM" } else { "HKCU" };
        let enabled =
            read_startup_approved(approved_hive, Some(STARTUP_FOLDER_APPROVED), &val_name);
        out.push(LogonEntry {
            entry_name: name,
            command,
            location: "Startup Folder".into(),
            scope: scope.into(),
            file_path: Some(file),
            approved_hive: Some(approved_hive.into()),
            approved_sub_key: Some(STARTUP_FOLDER_APPROVED.into()),
            approved_val_name: Some(val_name),
            can_toggle: true,
            enabled,
            ..Default::default()
        });
    }
}

fn read_winlogon(out: &mut Vec<LogonEntry>) -> Result<(), String> {
    const SUB_KEY: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
    let Some(key) = open_read("HKLM", SUB_KEY)? else {
        return Ok(());
    };
    for name in ["Shell", "Userinit", "Taskman", "AppSetup"] {
        let Some(data) = raw_string(&key, name) else {
            continue;
        };
        if blank(&data) {
            continue;
        }
        out.push(LogonEntry {
            entry_name: name.into(),
            command: data.trim().trim_end_matches(',').to_string(),
            location: "Winlogon".into(),
            scope: "HKLM".into(),
            reg_key_path: Some(format!(r"HKLM\{SUB_KEY}")),
            reg_value_name: Some(name.into()),
            can_toggle: false,
            modify_hint: Some("Winlogon entries are protected system logon settings.".into()),
            enabled: true,
            ..Default::default()
        });
    }
    Ok(())
}

fn windows_dir() -> String {
    std::env::var("SystemRoot")
        .or_else(|_| std::env::var("windir"))
        .unwrap_or_else(|_| "C:\\Windows".into())
}

fn starts_with_ci(s: &str, prefix: &str) -> bool {
    s.len() >= prefix.len()
        && s.is_char_boundary(prefix.len())
        && s[..prefix.len()].eq_ignore_ascii_case(prefix)
}

fn is_microsoft_active_setup_entry(component_id: &str, command: &str) -> bool {
    let expanded = xos_sys::expand_environment_variables(command);
    let expanded = expanded.trim_matches(|c| c == '"' || c == ' ');
    if starts_with_ci(expanded, &windows_dir()) {
        return true;
    }
    component_id.eq_ignore_ascii_case("{2C7339CF-2B09-4501-B3F3-F3508C9228ED}")
        || component_id.eq_ignore_ascii_case("{89820200-ECBD-11cf-8B85-00AA005B4340}")
}

fn read_active_setup_installed(component: &RegKey) -> bool {
    match component.get_raw_value("IsInstalled") {
        Err(_) => true,
        Ok(v) => match v.vtype {
            REG_DWORD if v.bytes.len() >= 4 => {
                i32::from_le_bytes([v.bytes[0], v.bytes[1], v.bytes[2], v.bytes[3]]) != 0
            }
            REG_QWORD if v.bytes.len() >= 8 => {
                let mut b = [0u8; 8];
                b.copy_from_slice(&v.bytes[..8]);
                let n = i64::from_le_bytes(b);
                match i32::try_from(n) {
                    Ok(n) => n != 0,
                    Err(_) => true,
                }
            }
            REG_SZ | REG_EXPAND_SZ => match utf16_text(&v.bytes).trim().parse::<i32>() {
                Ok(n) => n != 0,
                Err(_) => true,
            },
            _ => true,
        },
    }
}

fn read_active_setup_state(component: &RegKey) -> bool {
    let stub = raw_string(component, "StubPath");
    !blank_opt(&stub) && read_active_setup_installed(component)
}

fn read_active_setup(out: &mut Vec<LogonEntry>) -> Result<(), String> {
    let Some(root) = open_read("HKLM", ACTIVE_SETUP_KEY)? else {
        return Ok(());
    };
    for component_id in root.enum_keys() {
        let component_id = component_id.map_err(|e| e.to_string())?;
        let comp = match root.open_subkey_with_flags(&component_id, KEY_READ) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.to_string()),
        };
        let mut stub_path = raw_string(&comp, "StubPath");
        let saved_stub = raw_string(&comp, SAVED_STUB);
        if blank_opt(&stub_path) {
            stub_path = saved_stub;
        }
        if blank_opt(&stub_path) {
            continue;
        }
        let stub_path = stub_path.unwrap();
        let display_name = raw_string(&comp, "")
            .or_else(|| raw_string(&comp, "ComponentID"))
            .unwrap_or_else(|| component_id.clone());
        let microsoft_entry = is_microsoft_active_setup_entry(&component_id, &stub_path);
        let hint = if microsoft_entry {
            "Microsoft Active Setup entries are protected system components."
        } else if !read_active_setup_installed(&comp) {
            "Windows marks this component as uninstalled. Enable only if the application is still installed; this repairs its installation flag and can run its per-user setup at next sign-in."
        } else {
            ENTRY_NOT_TOGGLEABLE_HINT
        };
        out.push(LogonEntry {
            entry_name: display_name,
            command: stub_path,
            location: "Active Setup".into(),
            scope: "HKLM".into(),
            reg_key_path: Some(format!(r"HKLM\{ACTIVE_SETUP_KEY}\{component_id}")),
            reg_value_name: Some("StubPath".into()),
            can_toggle: !microsoft_entry,
            modify_hint: Some(hint.into()),
            enabled: read_active_setup_state(&comp),
            is_active_setup: true,
            ..Default::default()
        });
    }
    Ok(())
}

fn enumerate_logon_entries() -> Result<Vec<LogonEntry>, String> {
    let mut out = Vec::new();
    for (path, location, bucket) in [
        (
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "Run",
            "Run",
        ),
        (
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "RunOnce",
            "Run",
        ),
        (
            r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
            "Run (x86)",
            "Run32",
        ),
    ] {
        read_run_key("HKLM", path, location, bucket, &mut out)?;
    }
    for (path, location, bucket) in [
        (
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            "Run",
            "Run",
        ),
        (
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            "RunOnce",
            "Run",
        ),
    ] {
        read_run_key("HKCU", path, location, bucket, &mut out)?;
    }
    let program_data = std::env::var("ProgramData").unwrap_or_default();
    read_startup_folder(
        &format!(r"{program_data}\Microsoft\Windows\Start Menu\Programs\StartUp"),
        "Common",
        &mut out,
    );
    let app_data = std::env::var("APPDATA").unwrap_or_default();
    read_startup_folder(
        &format!(r"{app_data}\Microsoft\Windows\Start Menu\Programs\Startup"),
        "User",
        &mut out,
    );
    read_winlogon(&mut out)?;
    read_active_setup(&mut out)?;
    for (i, e) in out.iter_mut().enumerate() {
        e.id = i;
    }
    Ok(out)
}

fn write_active_setup_state(entry: &LogonEntry, enable: bool) -> Result<bool, String> {
    const PREFIX: &str = r"HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\";
    let Some(path) = entry.reg_key_path.as_deref() else {
        return Ok(false);
    };
    if !starts_with_ci(path, PREFIX) {
        return Ok(false);
    }
    let component = match hive_key("HKLM").open_subkey_with_flags(&path[5..], KEY_READ | KEY_WRITE)
    {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e.to_string()),
    };
    let stub = raw_string(&component, "StubPath");
    let saved = raw_string(&component, SAVED_STUB);
    let io = |e: std::io::Error| e.to_string();
    if enable {
        if blank_opt(&stub) {
            let Some(saved_text) = saved.clone().filter(|s| !blank(s)) else {
                return Ok(false);
            };
            let kind = component.get_raw_value(SAVED_STUB).map_err(io)?.vtype;
            if !is_string_type(&kind) {
                return Ok(false);
            }
            component
                .set_raw_value(
                    "StubPath",
                    &RegValue {
                        bytes: utf16_bytes(&saved_text).into(),
                        vtype: kind.clone(),
                    },
                )
                .map_err(io)?;
            let back = component.get_raw_value("StubPath").ok();
            let same = back
                .as_ref()
                .map(|v| {
                    is_string_type(&v.vtype)
                        && utf16_text(&v.bytes) == saved_text
                        && v.vtype == kind
                })
                .unwrap_or(false);
            if !same {
                return Ok(false);
            }
        }
        if !read_active_setup_installed(&component) {
            component.set_value("IsInstalled", &1u32).map_err(io)?;
            if !read_active_setup_installed(&component) {
                return Ok(false);
            }
            log::log(&format!("[StartupManager] Repaired Active Setup installation flag by explicit Enable: {path}"));
        }
        match component.delete_value(SAVED_STUB) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.to_string()),
        }
        return Ok(
            component.get_raw_value(SAVED_STUB).is_err() && read_active_setup_state(&component)
        );
    }
    if !read_active_setup_installed(&component) {
        return Ok(false);
    }
    if blank_opt(&stub) {
        return Ok(!blank_opt(&saved));
    }
    let stub = stub.unwrap();
    let original_kind = component.get_raw_value("StubPath").map_err(io)?.vtype;
    if !is_string_type(&original_kind) {
        return Ok(false);
    }
    component
        .set_raw_value(
            SAVED_STUB,
            &RegValue {
                bytes: utf16_bytes(&stub).into(),
                vtype: original_kind.clone(),
            },
        )
        .map_err(io)?;
    let back = component.get_raw_value(SAVED_STUB).ok();
    let same = back
        .as_ref()
        .map(|v| {
            is_string_type(&v.vtype) && utf16_text(&v.bytes) == stub && v.vtype == original_kind
        })
        .unwrap_or(false);
    if !same {
        return Ok(false);
    }
    match component.delete_value("StubPath") {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.to_string()),
    }
    Ok(component.get_raw_value("StubPath").is_err() && !read_active_setup_state(&component))
}

fn write_startup_approved(entry: &LogonEntry, enable: bool) -> Result<bool, String> {
    if entry.is_active_setup {
        return write_active_setup_state(entry, enable);
    }
    let Some(sub) = entry.approved_sub_key.as_deref() else {
        return Ok(false);
    };
    let root = hive_key(entry.approved_hive.as_deref().unwrap_or(""));
    let (key, _) = root
        .create_subkey_with_flags(sub, KEY_READ | KEY_WRITE)
        .map_err(|e| e.to_string())?;
    let name = entry.approved_val_name.as_deref().unwrap_or("");
    let mut value = vec![0u8; 12];
    value[0] = if enable { 0x02 } else { 0x03 };
    key.set_raw_value(
        name,
        &RegValue {
            bytes: value.clone().into(),
            vtype: REG_BINARY,
        },
    )
    .map_err(|e| e.to_string())?;
    Ok(match key.get_raw_value(name) {
        Ok(v) => v.vtype == REG_BINARY && !v.bytes.is_empty() && v.bytes[0] == value[0],
        Err(_) => false,
    })
}

fn read_failed_logon_toggle_state(
    entry: &LogonEntry,
    previous_state: bool,
) -> (bool, Option<String>) {
    if !entry.is_active_setup {
        return (previous_state, None);
    }
    let path = entry.reg_key_path.clone().unwrap_or_default();
    let sub = path.get(5..).unwrap_or("");
    match hive_key("HKLM").open_subkey_with_flags(sub, KEY_READ) {
        Ok(component) => {
            let actual = read_active_setup_state(&component);
            log::log(&format!(
                "[StartupManager] Active Setup state after failed toggle: {path} | enabled={}",
                if actual { "True" } else { "False" }
            ));
            (actual, None)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            log::log(&format!(
                "[StartupManager] Active Setup state after failed toggle: {path} | enabled=False"
            ));
            (false, None)
        }
        Err(e) => {
            log::log(&format!(
                "[StartupManager] Active Setup state unavailable after failed toggle: {path} | {e}"
            ));
            (
                previous_state,
                Some("The change failed and Windows' current state could not be read. Refresh Startup Manager before relying on this checkbox.".into()),
            )
        }
    }
}

fn remove_active_setup_command(entry: &LogonEntry) -> bool {
    let path = entry.reg_key_path.clone().unwrap_or_default();
    let live_removed = xos_sys::reg_delete_value(&path, "StubPath");
    let saved_removed = xos_sys::reg_delete_value(&path, SAVED_STUB);
    live_removed && saved_removed
}

fn delete_startup_approved(entry: &LogonEntry) -> Result<(), String> {
    let Some(sub) = entry.approved_sub_key.as_deref() else {
        return Ok(());
    };
    let name = entry.approved_val_name.as_deref().unwrap_or("");
    if blank(name) {
        return Ok(());
    }
    let root = hive_key(entry.approved_hive.as_deref().unwrap_or(""));
    let key = match root.open_subkey_with_flags(sub, KEY_READ | KEY_WRITE) {
        Ok(k) => k,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.to_string()),
    };
    match key.delete_value(name) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

fn is_microsoft_logon_entry(e: &LogonEntry) -> bool {
    if e.location == "Winlogon" {
        return true;
    }
    if e.location == "Active Setup" && !e.can_toggle {
        return true;
    }
    let expanded = xos_sys::expand_environment_variables(&e.command);
    let cmd = expanded.trim_matches(|c| c == '"' || c == ' ');
    if starts_with_ci(cmd, &windows_dir()) {
        return true;
    }
    cmd.to_lowercase().contains(r"\microsoft\")
}

fn trigger_label(kind: i32) -> &'static str {
    match kind {
        0 => "Event",
        1 => "Once",
        2 => "Daily",
        3 => "Weekly",
        4 | 5 => "Monthly",
        6 => "Idle",
        7 => "Registration",
        8 => "Boot",
        9 => "Logon",
        11 => "Session",
        _ => "Custom",
    }
}

fn read_com_triggers(task: &IRegisteredTask) -> windows::core::Result<(String, String)> {
    let definition = unsafe { task.Definition()? };
    let mut parts: Vec<String> = Vec::new();
    if let Ok(triggers) = unsafe { definition.Triggers() } {
        let mut count = 0i32;
        let _ = unsafe { triggers.Count(&mut count) };
        for i in 1..=count {
            if let Ok(trig) = unsafe { triggers.get_Item(i) } {
                let mut t = Default::default();
                if unsafe { trig.Type(&mut t) }.is_ok() {
                    let label = trigger_label(t.0).to_string();
                    if !parts.contains(&label) {
                        parts.push(label);
                    }
                }
            }
        }
    }
    let trig_summary = if parts.is_empty() {
        "-".to_string()
    } else {
        parts.join(", ")
    };

    let mut actions_parts: Vec<String> = Vec::new();
    if let Ok(actions) = unsafe { definition.Actions() } {
        let mut count = 0i32;
        let _ = unsafe { actions.Count(&mut count) };
        for i in 1..=count {
            let Ok(act) = (unsafe { actions.get_Item(i) }) else {
                continue;
            };
            let mut t = Default::default();
            if unsafe { act.Type(&mut t) }.is_err() {
                continue;
            }
            match t.0 {
                0 => {
                    if let Ok(exec) = act.cast::<IExecAction>() {
                        let mut b = BSTR::new();
                        let _ = unsafe { exec.Path(&mut b) };
                        let exe = b.to_string();
                        let mut b2 = BSTR::new();
                        let _ = unsafe { exec.Arguments(&mut b2) };
                        let args = b2.to_string();
                        let line = if blank(&args) {
                            exe
                        } else {
                            format!("{exe} {args}")
                        };
                        if !blank(&line) {
                            actions_parts.push(line);
                        }
                    }
                }
                5 => {
                    if let Ok(com) = act.cast::<IComHandlerAction>() {
                        let mut b = BSTR::new();
                        let _ = unsafe { com.ClassId(&mut b) };
                        let clsid = b.to_string();
                        if !blank(&clsid) {
                            actions_parts.push(format!("COM: {clsid}"));
                        }
                    }
                }
                _ => {}
            }
        }
    }
    let act_summary = if actions_parts.is_empty() {
        "-".to_string()
    } else {
        actions_parts.join(" | ")
    };
    Ok((trig_summary, act_summary))
}

fn walk_task_folder(folder: &ITaskFolder, results: &mut Vec<TaskEntry>) {
    if let Ok(subs) = unsafe { folder.GetFolders(0) } {
        let count = unsafe { subs.Count() }.unwrap_or(0);
        for i in 1..=count {
            if let Ok(sub) = unsafe { subs.get_Item(&VARIANT::from(i)) } {
                walk_task_folder(&sub, results);
            }
        }
    }
    if let Ok(tasks) = unsafe { folder.GetTasks(1) } {
        let count = unsafe { tasks.Count() }.unwrap_or(0);
        for i in 1..=count {
            let Ok(task) = (unsafe { tasks.get_Item(&VARIANT::from(i)) }) else {
                continue;
            };
            let (Ok(name), Ok(full_path), Ok(enabled)) =
                (unsafe { task.Name() }, unsafe { task.Path() }, unsafe {
                    task.Enabled()
                })
            else {
                continue;
            };
            let name = name.to_string();
            let full_path = full_path.to_string();
            let folder2 = match full_path.rfind('\\') {
                Some(slash) if slash > 0 => full_path[..slash].to_string(),
                _ => "\\".to_string(),
            };
            let (trigger_summary, action_summary) =
                read_com_triggers(&task).unwrap_or(("-".into(), "-".into()));
            results.push(TaskEntry {
                id: 0,
                enabled: enabled.as_bool(),
                task_name: name,
                folder_path: folder2,
                full_task_path: full_path,
                trigger_summary,
                action_summary,
            });
        }
    }
}

fn enumerate_tasks_com(results: &mut Vec<TaskEntry>) -> windows::core::Result<()> {
    unsafe {
        let init = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        let owned = init.is_ok();
        let result = (|| -> windows::core::Result<()> {
            init.ok()?;
            let svc: ITaskService =
                match CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER) {
                    Ok(s) => s,
                    Err(e) if e.code().0 as u32 == 0x80040154 => {
                        log::log("[StartupManager] Schedule.Service ProgID not found");
                        return Ok(());
                    }
                    Err(e) => return Err(e),
                };
            let empty = VARIANT::default();
            svc.Connect(&empty, &empty, &empty, &empty)?;
            let root = svc.GetFolder(&BSTR::from("\\"))?;
            walk_task_folder(&root, results);
            log::log(&format!(
                "[StartupManager] COM scan enumerated {} task(s)",
                results.len()
            ));
            Ok(())
        })();
        if owned {
            CoUninitialize();
        }
        result
    }
}

fn enumerate_task_files() -> Result<Vec<TaskEntry>, String> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut results = Vec::new();
        let r = enumerate_tasks_com(&mut results);
        let _ = tx.send(match r {
            Ok(()) => Ok(results),
            Err(e) => {
                log::log(&format!(
                    "[StartupManager] Task COM enumeration failed: COMException: {}",
                    e.message()
                ));
                Err(())
            }
        });
    });
    match rx.recv_timeout(Duration::from_secs(60)) {
        Ok(Ok(mut v)) => {
            for (i, t) in v.iter_mut().enumerate() {
                t.id = i;
            }
            Ok(v)
        }
        Ok(Err(())) => Err("Task Scheduler enumeration failed.".into()),
        Err(_) => Err("Task Scheduler did not respond within 60 seconds.".into()),
    }
}

struct State {
    active_tab: &'static str,
    all_logon: Vec<LogonEntry>,
    logon_loaded: bool,
    logon_loading: bool,
    logon_counted: bool,
    logon_search: String,
    logon_hide_ms: bool,
    logon_sort_col: &'static str,
    logon_sort_desc: bool,
    logon_empty_text: String,
    toggling_logon: Option<usize>,
    all_tasks: Vec<TaskEntry>,
    tasks_loaded: bool,
    tasks_loading: bool,
    tasks_counted: bool,
    tasks_search: String,
    tasks_hide_ms: bool,
    tasks_sort_desc: bool,
    tasks_empty_text: String,
    toggling_task: Option<usize>,
}

impl State {
    fn display_logon(&self) -> Vec<usize> {
        let mut idx: Vec<usize> = (0..self.all_logon.len()).collect();
        let by_location = self.logon_sort_col == "location";
        idx.sort_by(|&a, &b| {
            let (x, y) = (&self.all_logon[a], &self.all_logon[b]);
            let o = if by_location {
                cmp_ci(&x.location, &y.location)
            } else {
                cmp_ci(&x.entry_name, &y.entry_name)
            };
            if self.logon_sort_desc {
                o.reverse()
            } else {
                o
            }
        });
        if self.logon_hide_ms {
            idx.retain(|&i| !is_microsoft_logon_entry(&self.all_logon[i]));
        }
        let search = self.logon_search.trim().to_lowercase();
        if !search.is_empty() {
            idx.retain(|&i| {
                let e = &self.all_logon[i];
                e.entry_name.to_lowercase().contains(&search)
                    || e.command.to_lowercase().contains(&search)
                    || e.location.to_lowercase().contains(&search)
                    || e.scope.to_lowercase().contains(&search)
            });
        }
        idx
    }

    fn display_tasks(&self) -> Vec<usize> {
        let mut idx: Vec<usize> = (0..self.all_tasks.len()).collect();
        idx.sort_by(|&a, &b| {
            let o = cmp_ci(&self.all_tasks[a].task_name, &self.all_tasks[b].task_name);
            if self.tasks_sort_desc {
                o.reverse()
            } else {
                o
            }
        });
        if self.tasks_hide_ms {
            idx.retain(|&i| !starts_with_ci(&self.all_tasks[i].folder_path, r"\Microsoft"));
        }
        let search = self.tasks_search.trim().to_lowercase();
        if !search.is_empty() {
            idx.retain(|&i| {
                let t = &self.all_tasks[i];
                t.task_name.to_lowercase().contains(&search)
                    || t.folder_path.to_lowercase().contains(&search)
                    || t.action_summary.to_lowercase().contains(&search)
            });
        }
        idx
    }
}

pub struct StartupManagerPage {
    st: Mutex<State>,
}

impl StartupManagerPage {
    pub fn new() -> Self {
        Self {
            st: Mutex::new(State {
                active_tab: "logon",
                all_logon: Vec::new(),
                logon_loaded: false,
                logon_loading: false,
                logon_counted: false,
                logon_search: String::new(),
                logon_hide_ms: true,
                logon_sort_col: "name",
                logon_sort_desc: false,
                logon_empty_text: "No startup entries found.".into(),
                toggling_logon: None,
                all_tasks: Vec::new(),
                tasks_loaded: false,
                tasks_loading: false,
                tasks_counted: false,
                tasks_search: String::new(),
                tasks_hide_ms: true,
                tasks_sort_desc: false,
                tasks_empty_text: "No tasks found.".into(),
                toggling_task: None,
            }),
        }
    }

    fn load_logon(&self, host: &dyn Host) {
        {
            let mut st = self.st.lock().unwrap();
            if st.logon_loading {
                return;
            }
            st.logon_loading = true;
            st.logon_loaded = true;
        }
        host.publish(self.model());
        host.set_status("Scanning startup entries...");
        let result = enumerate_logon_entries();
        let status;
        {
            let mut st = self.st.lock().unwrap();
            match result {
                Ok(entries) => {
                    status = format!("Found {} logon entry/entries.", entries.len());
                    st.all_logon = entries;
                    st.logon_counted = true;
                }
                Err(e) => {
                    st.logon_loaded = false;
                    log::log(&format!("[StartupManager] Logon enumeration failed: {e}"));
                    status = "Startup entry scan failed.".into();
                    st.logon_empty_text =
                        "Startup entries could not be read. Select Refresh to try again.".into();
                }
            }
            st.logon_loading = false;
        }
        host.set_status(&status);
    }

    fn load_tasks(&self, host: &dyn Host) {
        {
            let mut st = self.st.lock().unwrap();
            if st.tasks_loading {
                return;
            }
            st.tasks_loading = true;
            st.tasks_loaded = true;
        }
        host.publish(self.model());
        host.set_status("Reading scheduled tasks...");
        let result = enumerate_task_files();
        let status;
        {
            let mut st = self.st.lock().unwrap();
            match result {
                Ok(tasks) => {
                    status = format!("Found {} task(s).", tasks.len());
                    st.all_tasks = tasks;
                    st.tasks_counted = true;
                }
                Err(e) => {
                    st.tasks_loaded = false;
                    log::log(&format!("[StartupManager] Task enumeration failed: {e}"));
                    status = "Scheduled task scan failed.".into();
                    st.tasks_empty_text =
                        "Scheduled tasks could not be read. Select Refresh to try again.".into();
                }
            }
            st.tasks_loading = false;
        }
        host.set_status(&status);
    }

    fn switch_tab(&self, host: &dyn Host, tab: &'static str) {
        let (need_logon, need_tasks) = {
            let mut st = self.st.lock().unwrap();
            st.active_tab = tab;
            (
                tab == "logon" && !st.logon_loaded,
                tab == "tasks" && !st.tasks_loaded,
            )
        };
        host.publish(self.model());
        if need_logon {
            self.load_logon(host);
        }
        if need_tasks {
            self.load_tasks(host);
        }
    }

    fn toggle_logon(&self, host: &dyn Host, row: usize, enable: bool) {
        let entry = {
            let mut st = self.st.lock().unwrap();
            let display = st.display_logon();
            let Some(&i) = display.get(row) else { return };
            if st.all_logon[i].enabled == enable {
                return;
            }
            st.all_logon[i].enabled = enable;
            st.toggling_logon = Some(st.all_logon[i].id);
            st.all_logon[i].clone()
        };
        host.publish(self.model());
        let verb = if enable { "Enable" } else { "Disable" };
        let click = log::action_clicked_token("Startup", &format!("{}: {verb}", entry.entry_name));
        let result = write_startup_approved(&entry, enable).and_then(|ok| {
            if ok {
                Ok(())
            } else {
                Err("Windows did not accept the startup entry state.".to_string())
            }
        });
        match result {
            Ok(()) => {
                {
                    let mut st = self.st.lock().unwrap();
                    if entry.is_active_setup && enable {
                        if let Some(e) = st.all_logon.iter_mut().find(|e| e.id == entry.id) {
                            e.modify_hint = Some(ENTRY_NOT_TOGGLEABLE_HINT.into());
                        }
                    }
                }
                host.set_status(&format!(
                    "{}: {}",
                    if enable { "Enabled" } else { "Disabled" },
                    entry.entry_name
                ));
                log::log(&format!(
                    "[StartupManager] {} logon entry: {} | location={} | key={} | mechanism={}",
                    if enable { "Enabled" } else { "Disabled" },
                    entry.entry_name,
                    entry.location,
                    entry.reg_key_path.clone().unwrap_or_default(),
                    if entry.is_active_setup {
                        "saved setup command"
                    } else {
                        "StartupApproved"
                    }
                ));
                log::action_done_token(click, "Startup", false, false, None);
            }
            Err(msg) => {
                let (state, hint) = read_failed_logon_toggle_state(&entry, !enable);
                {
                    let mut st = self.st.lock().unwrap();
                    if let Some(e) = st.all_logon.iter_mut().find(|e| e.id == entry.id) {
                        e.enabled = state;
                        if hint.is_some() {
                            e.modify_hint = hint;
                        }
                    }
                }
                host.set_status(&format!("Failed to toggle {}", entry.entry_name));
                log::log(&format!(
                    "[StartupManager] Toggle failed for {}: {msg}",
                    entry.entry_name
                ));
                log::action_done_token(click, "Startup", true, false, Some(&msg));
            }
        }
        self.st.lock().unwrap().toggling_logon = None;
    }

    fn delete_logon(&self, host: &dyn Host, row: usize) {
        let entry = {
            let st = self.st.lock().unwrap();
            let display = st.display_logon();
            let Some(&i) = display.get(row) else { return };
            if !st.all_logon[i].can_toggle {
                return;
            }
            st.all_logon[i].clone()
        };
        if !host.confirm(
            &format!(
                "Remove \"{}\" from startup?\n\nThis cannot be undone.",
                entry.entry_name
            ),
            "Startup Manager",
            Icon::Warning,
        ) {
            return;
        }
        xos_sys::ops::reset();
        let result: Result<(), String> = (|| {
            if let Some(file) = &entry.file_path {
                std::fs::remove_file(file).map_err(|e| e.to_string())?;
                if Path::new(file).exists() {
                    return Err("The startup file still exists after deletion.".into());
                }
            } else {
                let removed = if entry.is_active_setup {
                    remove_active_setup_command(&entry)
                } else {
                    xos_sys::reg_delete_value(
                        entry.reg_key_path.as_deref().unwrap_or(""),
                        entry.reg_value_name.as_deref().unwrap_or(""),
                    )
                };
                if !removed {
                    return Err("The startup registry value could not be deleted.".into());
                }
            }
            delete_startup_approved(&entry)
        })();
        match result {
            Ok(()) => {
                self.st
                    .lock()
                    .unwrap()
                    .all_logon
                    .retain(|e| e.id != entry.id);
                host.set_status(&format!("Removed: {}", entry.entry_name));
                log::log(&format!(
                    "[StartupManager] Deleted logon entry: {}",
                    entry.entry_name
                ));
                log::action_done(
                    "Startup",
                    false,
                    false,
                    Some(&format!("{} removed", entry.entry_name)),
                );
            }
            Err(msg) => {
                host.set_status(&format!("Failed to remove {}", entry.entry_name));
                log::log(&format!(
                    "[StartupManager] Delete failed for {}: {msg}",
                    entry.entry_name
                ));
                log::action_done("Startup", true, false, Some(&msg));
            }
        }
        xos_sys::ops::reset();
    }

    fn toggle_task(&self, host: &dyn Host, row: usize, enable: bool) {
        let entry = {
            let mut st = self.st.lock().unwrap();
            let display = st.display_tasks();
            let Some(&i) = display.get(row) else { return };
            if st.all_tasks[i].enabled == enable {
                return;
            }
            st.all_tasks[i].enabled = enable;
            st.toggling_task = Some(st.all_tasks[i].id);
            st.all_tasks[i].clone()
        };
        host.publish(self.model());
        let verb = if enable { "Enable" } else { "Disable" };
        let lower = if enable { "enable" } else { "disable" };
        let click = log::action_clicked_token("Startup", &format!("{}: {verb}", entry.task_name));
        let sw = Instant::now();
        let ok = if enable {
            xos_sys::enable_task(&entry.full_task_path)
        } else {
            xos_sys::disable_task(&entry.full_task_path)
        };
        let ms = sw.elapsed().as_millis();
        if !ok {
            self.set_task_enabled(entry.id, !enable);
            host.set_status(&format!("Failed to {lower} {}", entry.task_name));
            log::result(
                false,
                &format!("task {lower} {}", entry.full_task_path),
                &format!("{ms} ms"),
            );
        } else {
            host.set_status(&format!(
                "{}: {}",
                if enable { "Enabled" } else { "Disabled" },
                entry.task_name
            ));
            log::result(
                true,
                &format!("task {lower} {}", entry.full_task_path),
                &format!("{ms} ms"),
            );
        }
        log::perf(&format!("task {lower}"), ms);
        log::action_done_token(click, "Startup", !ok, false, Some(&entry.full_task_path));
        self.st.lock().unwrap().toggling_task = None;
    }

    fn set_task_enabled(&self, id: usize, enabled: bool) {
        let mut st = self.st.lock().unwrap();
        if let Some(t) = st.all_tasks.iter_mut().find(|t| t.id == id) {
            t.enabled = enabled;
        }
    }

    fn logon_hide_changed(&self, host: &dyn Host, hide: bool) {
        if !hide
            && !host.confirm_once(
                "StartupShowMicrosoftLogon",
                "Microsoft logon entries are part of Windows and installed Microsoft software.\n\nDisabling or removing them may break system functionality or installed applications. This view is intended for Power Users only.\n\nAre you sure you want to show Microsoft items?",
                "Warning",
                Icon::Warning,
            )
        {
            self.st.lock().unwrap().logon_hide_ms = true;
            return;
        }
        self.st.lock().unwrap().logon_hide_ms = hide;
    }

    fn tasks_hide_changed(&self, host: &dyn Host, hide: bool) {
        if !hide
            && !host.confirm_once(
                "StartupShowMicrosoftTasks",
                "Microsoft Scheduled Tasks are required for Windows to function correctly.\n\nDisabling or modifying them may cause system instability, broken Windows features, and application compatibility issues.\n\nThis view is intended for Power Users only. Are you sure you want to continue?",
                "Warning",
                Icon::Warning,
            )
        {
            self.st.lock().unwrap().tasks_hide_ms = true;
            return;
        }
        self.st.lock().unwrap().tasks_hide_ms = hide;
    }

    fn logon_header_click(&self, col: usize) {
        let column = match col {
            0 => "name",
            2 => "location",
            _ => return,
        };
        let mut st = self.st.lock().unwrap();
        st.logon_sort_desc = if column == st.logon_sort_col {
            !st.logon_sort_desc
        } else {
            false
        };
        st.logon_sort_col = column;
    }
}

impl Page for StartupManagerPage {
    fn id(&self) -> &'static str {
        "Startup"
    }

    fn label(&self) -> &'static str {
        "Startup Manager"
    }

    fn model(&self) -> PageModel {
        let st = self.st.lock().unwrap();
        let logon_active = st.active_tab == "logon";
        let arrow = |desc: bool| if desc { "  \u{25BC}" } else { "  \u{25B2}" };

        let logon_display = st.display_logon();
        let logon_rows: Vec<TableRow> = if st.logon_loading {
            Vec::new()
        } else {
            logon_display
                .iter()
                .map(|&i| {
                    let e = &st.all_logon[i];
                    let enabled = e.can_toggle && st.toggling_logon != Some(e.id);
                    TableRow::new(
                        i.to_string(),
                        vec![
                            e.entry_name.clone(),
                            e.command.clone(),
                            e.location.clone(),
                            e.scope.clone(),
                        ],
                    )
                    .checked(e.enabled)
                    .enabled(enabled)
                    .tooltip(e.modify_hint.clone().unwrap_or_else(|| e.command.clone()))
                    .button({
                        let mut b = RowButton::new("delete", "\u{2715}", BtnStyle::Link);
                        b.enabled = e.can_toggle;
                        b
                    })
                })
                .collect()
        };
        let logon_empty = if st.logon_loading {
            "Scanning startup entries...".to_string()
        } else {
            st.logon_empty_text.clone()
        };
        let logon_count = if st.logon_counted {
            format!("{} entry/entries", logon_display.len())
        } else {
            "-".to_string()
        };

        let task_display = st.display_tasks();
        let task_rows: Vec<TableRow> = if st.tasks_loading {
            Vec::new()
        } else {
            task_display
                .iter()
                .map(|&i| {
                    let t = &st.all_tasks[i];
                    TableRow::new(
                        i.to_string(),
                        vec![
                            t.task_name.clone(),
                            t.folder_path.clone(),
                            t.trigger_summary.clone(),
                            t.action_summary.clone(),
                        ],
                    )
                    .checked(t.enabled)
                    .enabled(st.toggling_task != Some(t.id))
                    .tooltip(t.full_task_path.clone())
                })
                .collect()
        };
        let task_empty = if st.tasks_loading {
            "Reading scheduled tasks...".to_string()
        } else {
            st.tasks_empty_text.clone()
        };
        let task_count = if st.tasks_counted {
            format!("{} task(s)", task_display.len())
        } else {
            "-".to_string()
        };

        PageModel::new(
            "Startup",
            "Startup Manager",
            "View and manage programs that run at logon and scheduled tasks",
        )
        .single_column()
        .card(Card::new("tabs", "", "").not_searchable().controls(vec![
            Control::button(
                "tab_logon",
                "Logon Entries",
                if logon_active {
                    BtnStyle::Action
                } else {
                    BtnStyle::Link
                },
            ),
            Control::button(
                "tab_tasks",
                "Scheduled Tasks",
                if logon_active {
                    BtnStyle::Link
                } else {
                    BtnStyle::Action
                },
            ),
        ]))
        .card(
            Card::new("logon_controls", "", "")
                .not_searchable()
                .visible(logon_active)
                .controls(vec![
                    Control::text_input("logon_search", st.logon_search.clone(), "\u{1F50D}"),
                    Control::check("logon_hide_ms", "Hide Microsoft items", st.logon_hide_ms),
                    Control::muted(logon_count).id("count"),
                    Control::button("logon_refresh", "\u{21BB}  Refresh", BtnStyle::Action)
                        .enabled(!st.logon_loading),
                ]),
        )
        .card(
            Card::new("logon_list", "", "")
                .not_searchable()
                .visible(logon_active)
                .controls(vec![Control::table(
                    "logon_list",
                    Table::new(
                        vec![
                            Column::new(
                                format!(
                                    "Name{}",
                                    if st.logon_sort_col == "name" {
                                        arrow(st.logon_sort_desc)
                                    } else {
                                        ""
                                    }
                                ),
                                200.0,
                            ),
                            Column::stretch("Command"),
                            Column::new(
                                format!(
                                    "Location{}",
                                    if st.logon_sort_col == "location" {
                                        arrow(st.logon_sort_desc)
                                    } else {
                                        ""
                                    }
                                ),
                                110.0,
                            ),
                            Column::new("Scope", 65.0),
                        ],
                        logon_rows,
                    )
                    .checkable(true)
                    .sortable(true)
                    .height(460.0)
                    .empty_text(logon_empty),
                )]),
        )
        .card(
            Card::new("tasks_controls", "", "")
                .not_searchable()
                .visible(!logon_active)
                .controls(vec![
                    Control::text_input("tasks_search", st.tasks_search.clone(), "\u{1F50D}"),
                    Control::check("tasks_hide_ms", "Hide Microsoft items", st.tasks_hide_ms),
                    Control::muted(task_count).id("count"),
                    Control::button("tasks_refresh", "\u{21BB}  Refresh", BtnStyle::Action)
                        .enabled(!st.tasks_loading),
                ]),
        )
        .card(
            Card::new("tasks_list", "", "")
                .not_searchable()
                .visible(!logon_active)
                .controls(vec![Control::table(
                    "tasks_list",
                    Table::new(
                        vec![
                            Column::new(format!("Task{}", arrow(st.tasks_sort_desc)), 220.0),
                            Column::new("Folder", 170.0),
                            Column::new("Trigger", 120.0),
                            Column::stretch("Action"),
                        ],
                        task_rows,
                    )
                    .checkable(true)
                    .sortable(true)
                    .height(460.0)
                    .empty_text(task_empty),
                )]),
        )
    }

    fn refresh(&self, host: &dyn Host) {
        let loaded = self.st.lock().unwrap().logon_loaded;
        if !loaded {
            self.load_logon(host);
        }
    }

    fn handle(&self, host: &dyn Host, event: &Event) {
        match (event.control.as_str(), &event.kind) {
            ("tab_logon", EventKind::Click) => self.switch_tab(host, "logon"),
            ("tab_tasks", EventKind::Click) => self.switch_tab(host, "tasks"),
            ("logon_refresh", EventKind::Click) => {
                self.st.lock().unwrap().logon_loaded = false;
                self.load_logon(host);
            }
            ("tasks_refresh", EventKind::Click) => {
                self.st.lock().unwrap().tasks_loaded = false;
                self.load_tasks(host);
            }
            ("logon_search", EventKind::Text(t)) | ("logon_search", EventKind::Submit(t)) => {
                self.st.lock().unwrap().logon_search = t.clone();
            }
            ("tasks_search", EventKind::Text(t)) | ("tasks_search", EventKind::Submit(t)) => {
                self.st.lock().unwrap().tasks_search = t.clone();
            }
            ("logon_hide_ms", EventKind::Check(b)) => self.logon_hide_changed(host, *b),
            ("tasks_hide_ms", EventKind::Check(b)) => self.tasks_hide_changed(host, *b),
            ("logon_list", EventKind::RowCheck { row, checked }) => {
                self.toggle_logon(host, *row, *checked)
            }
            ("logon_list", EventKind::RowButton { row, button }) if button == "delete" => {
                self.delete_logon(host, *row)
            }
            ("logon_list", EventKind::HeaderClick(col)) => self.logon_header_click(*col),
            ("tasks_list", EventKind::RowCheck { row, checked }) => {
                self.toggle_task(host, *row, *checked)
            }
            ("tasks_list", EventKind::HeaderClick(0)) => {
                let mut st = self.st.lock().unwrap();
                st.tasks_sort_desc = !st.tasks_sort_desc;
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(location: &str, command: &str, can_toggle: bool) -> LogonEntry {
        LogonEntry {
            location: location.into(),
            command: command.into(),
            can_toggle,
            ..Default::default()
        }
    }

    #[test]
    fn microsoft_detection() {
        assert!(is_microsoft_logon_entry(&entry("Winlogon", "", false)));
        assert!(is_microsoft_logon_entry(&entry("Active Setup", "x", false)));
        assert!(is_microsoft_logon_entry(&entry(
            "Run",
            r"C:\Program Files\Microsoft\x.exe",
            true
        )));
        assert!(!is_microsoft_logon_entry(&entry(
            "Run",
            r"C:\Apps\x.exe",
            true
        )));
    }

    #[test]
    fn trigger_labels() {
        assert_eq!(trigger_label(9), "Logon");
        assert_eq!(trigger_label(5), "Monthly");
        assert_eq!(trigger_label(10), "Custom");
    }

    #[test]
    fn active_setup_microsoft_ids() {
        assert!(is_microsoft_active_setup_entry(
            "{2c7339cf-2b09-4501-b3f3-f3508c9228ed}",
            "x"
        ));
        assert!(!is_microsoft_active_setup_entry(
            "{abc}",
            r"C:\Apps\setup.exe"
        ));
    }

    #[test]
    fn utf16_roundtrip() {
        assert_eq!(utf16_text(&utf16_bytes("abc")), "abc");
    }
}

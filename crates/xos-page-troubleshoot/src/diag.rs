use std::collections::HashSet;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};

use regex::Regex;
use windows::core::PCWSTR;
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_HANDLE, SERVICE_STATUS,
};
use windows::Win32::UI::Shell::{FOLDERID_Desktop, SHGetKnownFolderPath, KNOWN_FOLDER_FLAG};
use xos_core::{eventlog, redact};

use crate::netinfo::build_network_info;
use crate::regval::{self, RegData};
use crate::wmi::Wmi;
use crate::zipw;

const REPARSE_POINT: u32 = 0x400;
const TEXT_EXTENSIONS: [&str; 14] = [
    ".log", ".txt", ".yml", ".yaml", ".reg", ".bat", ".cmd", ".ps1", ".json", ".xml", ".csv",
    ".tsv", ".ini", ".session",
];

pub fn desktop_directory() -> Option<PathBuf> {
    unsafe {
        let p = SHGetKnownFolderPath(&FOLDERID_Desktop, KNOWN_FOLDER_FLAG(0), None).ok()?;
        let s = PCWSTR(p.0).to_string().ok();
        CoTaskMemFree(Some(p.0 as *const _));
        s.map(PathBuf::from)
    }
}

fn nl(text: &mut String, s: &str) {
    text.push_str(s);
    text.push_str("\r\n");
}

fn write_bom_text(path: &Path, text: &str) -> std::io::Result<()> {
    let mut bytes = vec![0xEF, 0xBB, 0xBF];
    bytes.extend_from_slice(text.as_bytes());
    std::fs::write(path, bytes)
}

fn full_path(path: &str) -> String {
    let s = path.replace('/', "\\");
    s.trim_end_matches('\\').to_string()
}

fn new_temp_name() -> String {
    format!("XOS-Diagnostics-{}", xos_uninstall::new_guid_n())
}

fn now_stamp() -> String {
    chrono::Local::now()
        .format("%Y-%m-%d %H:%M:%S %:z")
        .to_string()
}

pub fn create_diagnostic_bundle(destination: &Path) -> std::io::Result<()> {
    let temp_root = std::env::temp_dir().join(new_temp_name());
    std::fs::create_dir_all(&temp_root)?;

    let mut manifest = String::new();
    nl(
        &mut manifest,
        &format!("XOS diagnostic bundle created {}", now_stamp()),
    );
    nl(&mut manifest, "");

    let result = (|| -> std::io::Result<()> {
        write_bom_text(
            &temp_root.join("SystemInfo.txt"),
            &redact::redact(&build_system_info()),
        )?;
        nl(&mut manifest, "[included] SystemInfo.txt");
        let network = std::panic::catch_unwind(build_network_info)
            .map_err(|_| "network information collection failed".to_string())
            .and_then(|text| {
                write_bom_text(&temp_root.join("NetworkInfo.txt"), &redact::redact(&text))
                    .map_err(|e| e.to_string())
            });
        match network {
            Ok(()) => nl(&mut manifest, "[included] NetworkInfo.txt"),
            Err(e) => nl(&mut manifest, &format!("[failed] NetworkInfo.txt: {e}")),
        }

        let mut seen: HashSet<String> = HashSet::new();
        let t = |name: &str| temp_root.join(name);
        copy_diagnostic_directory(
            r"C:\ProgramData\AME\Logs",
            &t("AME-Logs"),
            &mut manifest,
            &mut seen,
        );
        copy_diagnostic_directory(
            &xos_uninstall::path_combine(
                &xos_uninstall::path_combine(
                    &xos_uninstall::common_application_data(),
                    "XOS Toolkit",
                ),
                "Logs",
            ),
            &t("Toolkit-Logs"),
            &mut manifest,
            &mut seen,
        );
        copy_diagnostic_directory(
            &xos_uninstall::path_combine(
                &xos_uninstall::path_combine(
                    &xos_uninstall::local_application_data(),
                    "XOSToolkit",
                ),
                "Logs",
            ),
            &t("Toolkit-Crash-Logs"),
            &mut manifest,
            &mut seen,
        );
        copy_diagnostic_directory(
            &xos_uninstall::path_combine(
                &xos_uninstall::path_combine(&std::env::temp_dir().to_string_lossy(), "XOSToolkit"),
                "Logs",
            ),
            &t("Toolkit-Temp-Logs"),
            &mut manifest,
            &mut seen,
        );
        let base_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_string_lossy().to_string()))
            .unwrap_or_default();
        copy_diagnostic_directory(
            &xos_uninstall::path_combine(&base_dir, "Logs"),
            &t("Toolkit-Legacy-Logs"),
            &mut manifest,
            &mut seen,
        );
        copy_diagnostic_directory(
            r"C:\Windows\service-backups",
            &t("Service-Backups"),
            &mut manifest,
            &mut seen,
        );
        copy_diagnostic_file(
            r"C:\Windows\Logs\DISM\dism.log",
            &t("Windows-Logs").join("dism.log"),
            &mut manifest,
        );
        copy_diagnostic_file(
            r"C:\Windows\Logs\CBS\CBS.log",
            &t("Windows-Logs").join("CBS.log"),
            &mut manifest,
        );

        copy_uninstall_logs(&t("Uninstall-Logs"), &mut manifest);

        export_event_log_text(
            "System",
            &t("Windows-Logs").join("System-events.txt"),
            &mut manifest,
            false,
        );
        export_event_log_text(
            "Application",
            &t("Windows-Logs").join("Application-events.txt"),
            &mut manifest,
            true,
        );
        export_event_log_text(
            "Microsoft-Windows-WindowsUpdateClient/Operational",
            &t("Windows-Logs").join("WindowsUpdate-events.txt"),
            &mut manifest,
            false,
        );

        write_bom_text(&t("Manifest.txt"), &redact::redact(&manifest))?;

        if let Some(parent) = destination.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        if destination.exists() {
            std::fs::remove_file(destination)?;
        }
        zipw::create_from_directory(&temp_root, destination)
    })();

    let _ = std::fs::remove_dir_all(&temp_root);
    result
}

fn copy_diagnostic_directory(
    source: &str,
    destination: &Path,
    manifest: &mut String,
    seen: &mut HashSet<String>,
) {
    let normalized = full_path(source);
    if normalized.is_empty() {
        nl(manifest, &format!("[skipped] Invalid path: {source}"));
        return;
    }
    if !seen.insert(normalized.to_lowercase()) {
        return;
    }
    if !Path::new(&normalized).is_dir() {
        nl(manifest, &format!("[missing] {normalized}"));
        return;
    }

    let mut copied = 0;
    let mut skipped = 0;
    for file in enumerate_diagnostic_files(&normalized, manifest) {
        let relative = file[normalized.len().min(file.len())..]
            .trim_start_matches(['\\', '/'])
            .to_string();
        let target = destination.join(&relative);
        let attempt = (|| -> std::io::Result<bool> {
            if let Some(dir) = target.parent() {
                std::fs::create_dir_all(dir)?;
            }
            copy_redacted(&file, &target)
        })();
        match attempt {
            Ok(false) => {
                skipped += 1;
                nl(manifest, &format!("[not text, skipped] {file}"));
            }
            Ok(true) => copied += 1,
            Err(e) => {
                skipped += 1;
                nl(manifest, &format!("[file skipped] {file}: {e}"));
            }
        }
    }
    nl(
        manifest,
        &format!("[included] {normalized} ({copied} files, {skipped} skipped)"),
    );
}

fn enumerate_diagnostic_files(root: &str, manifest: &mut String) -> Vec<String> {
    let mut files_out = Vec::new();
    let mut pending: Vec<String> = vec![root.to_string()];
    let mut visited: HashSet<String> = HashSet::new();

    while let Some(directory) = pending.pop() {
        let full = full_path(&directory);
        if !visited.insert(full.to_lowercase()) {
            continue;
        }

        let entries = match std::fs::read_dir(&full) {
            Ok(rd) => rd,
            Err(e) => {
                nl(manifest, &format!("[directory skipped] {full}: {e}"));
                continue;
            }
        };
        let mut dirs: Vec<String> = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path().to_string_lossy().to_string();
            match entry.file_type() {
                Ok(t) if t.is_dir() => dirs.push(path),
                Ok(_) => files_out.push(path),
                Err(_) => files_out.push(path),
            }
        }

        for child in dirs {
            match std::fs::symlink_metadata(&child) {
                Ok(meta) => {
                    if meta.file_attributes() & REPARSE_POINT != 0 {
                        nl(manifest, &format!("[reparse point skipped] {child}"));
                        continue;
                    }
                    pending.push(child);
                }
                Err(e) => nl(manifest, &format!("[subdirectory skipped] {child}: {e}")),
            }
        }
    }
    files_out
}

fn copy_diagnostic_file(source: &str, destination: &Path, manifest: &mut String) {
    if !Path::new(source).is_file() {
        nl(manifest, &format!("[missing] {source}"));
        return;
    }
    let attempt = (|| -> std::io::Result<()> {
        if let Some(dir) = destination.parent() {
            std::fs::create_dir_all(dir)?;
        }
        copy_redacted(source, destination)?;
        Ok(())
    })();
    match attempt {
        Ok(()) => nl(manifest, &format!("[included] {source}")),
        Err(e) => nl(manifest, &format!("[file skipped] {source}: {e}")),
    }
}

fn copy_redacted(source: &str, destination: &Path) -> std::io::Result<bool> {
    let extension = Path::new(source)
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()))
        .unwrap_or_default();
    if !TEXT_EXTENSIONS.contains(&extension.as_str()) {
        return Ok(false);
    }
    redact::redact_file(source, &destination.to_string_lossy())?;
    Ok(true)
}

fn copy_uninstall_logs(destination: &Path, manifest: &mut String) {
    let attempt = (|| -> Result<(), String> {
        let desktop =
            desktop_directory().ok_or_else(|| "Desktop folder not available".to_string())?;
        let mut logs: Vec<(std::time::SystemTime, PathBuf)> = std::fs::read_dir(&desktop)
            .map_err(|e| e.to_string())?
            .flatten()
            .filter(|e| {
                let name = e.file_name().to_string_lossy().to_lowercase();
                name.starts_with("uninstallxos-") && name.ends_with(".log")
            })
            .filter_map(|e| {
                let modified = e.metadata().ok()?.modified().ok()?;
                Some((modified, e.path()))
            })
            .collect();
        logs.sort_by(|a, b| b.0.cmp(&a.0));
        logs.truncate(3);
        if logs.is_empty() {
            nl(manifest, "[missing] Uninstall XOS log on the Desktop");
            return Ok(());
        }
        std::fs::create_dir_all(destination).map_err(|e| e.to_string())?;
        for (_, log) in logs {
            let name = log.file_name().unwrap_or_default().to_os_string();
            let full = log.to_string_lossy().to_string();
            match copy_redacted(&full, &destination.join(name)) {
                Ok(_) => nl(manifest, &format!("[included] {full}")),
                Err(e) => nl(manifest, &format!("[file skipped] {full}: {e}")),
            }
        }
        Ok(())
    })();
    if let Err(e) = attempt {
        nl(manifest, &format!("[failed] Uninstall XOS logs: {e}"));
    }
}

fn level_name(level: u8) -> &'static str {
    match level {
        1 => "Critical",
        2 => "Error",
        3 => "Warning",
        5 => "Verbose",
        _ => "Info",
    }
}

pub fn format_event_line(record: &eventlog::EventRecord) -> String {
    static WS: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let ws = WS.get_or_init(|| Regex::new(r"\s+").unwrap());
    let mut message = match record.description.as_deref() {
        Some(d) if !d.trim().is_empty() => d.to_string(),
        _ => match &record.properties {
            Some(p) => format!("properties: {}", p.join("; ")),
            None => String::new(),
        },
    };
    message = ws.replace_all(&message, " ").trim().to_string();
    if message.chars().count() > 1000 {
        message = message.chars().take(1000).collect::<String>() + "...";
    }
    let time = match record.time_created {
        Some(t) => t.format("%Y-%m-%d %H:%M:%S").to_string(),
        None => "?".to_string(),
    };
    redact::redact(&format!(
        "{time} | {} | {} | {} | {message}",
        level_name(record.level),
        record.provider,
        record.event_id
    ))
}

fn export_event_log_text(
    channel: &str,
    destination: &Path,
    manifest: &mut String,
    warnings_and_above: bool,
) {
    const DAYS: i64 = 14;
    const MAX_EVENTS: usize = 10000;
    let query = format!(
        "*[System[TimeCreated[timediff(@SystemTime) <= {}]{}]]",
        DAYS * 86400000,
        if warnings_and_above {
            " and (Level=1 or Level=2 or Level=3)"
        } else {
            ""
        }
    );
    let attempt = (|| -> Result<usize, String> {
        let mut limit = MAX_EVENTS;
        let (lines, omitted) = loop {
            let records =
                eventlog::query(channel, &query, true, limit, true).map_err(|e| e.message())?;
            let total = records.len();
            let mut lines: Vec<String> = Vec::new();
            let mut omitted = 0usize;
            for record in &records {
                if lines.len() >= MAX_EVENTS {
                    break;
                }
                if record
                    .provider
                    .eq_ignore_ascii_case("Microsoft-Windows-DNS-Client")
                {
                    omitted += 1;
                    continue;
                }
                lines.push(format_event_line(record));
            }
            if lines.len() >= MAX_EVENTS || total < limit {
                break (lines, omitted);
            }
            limit = MAX_EVENTS + omitted;
        };
        let mut lines = lines;
        lines.reverse();

        if let Some(dir) = destination.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        let mut out = String::new();
        nl(
            &mut out,
            &format!(
                "# {channel} event log, last {DAYS} days, {}, oldest first, {} events{}",
                if warnings_and_above {
                    "critical, error and warning"
                } else {
                    "all levels"
                },
                lines.len(),
                if lines.len() >= MAX_EVENTS {
                    ", capped, older events not included"
                } else {
                    ""
                }
            ),
        );
        if omitted > 0 {
            nl(
                &mut out,
                &format!(
                    "# {omitted} DNS Client events omitted because they name the hosts this PC looked up"
                ),
            );
        }
        nl(&mut out, "# time | level | provider | id | message");
        for line in &lines {
            nl(&mut out, line);
        }
        std::fs::write(destination, out).map_err(|e| e.to_string())?;
        Ok(lines.len())
    })();
    match attempt {
        Ok(count) => nl(
            manifest,
            &format!("[included] Windows {channel} event log as text ({count} events)"),
        ),
        Err(e) => nl(
            manifest,
            &format!("[failed] Windows {channel} event log: {e}"),
        ),
    }
}

struct ScHandle(SC_HANDLE);

impl Drop for ScHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseServiceHandle(self.0);
        }
    }
}

fn service_status(service: &str) -> Result<&'static str, String> {
    unsafe {
        let manager = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), 1).map_err(|e| {
            format!(
                "Cannot open Service Control Manager on computer '.'. {}",
                e.message()
            )
        })?;
        let manager = ScHandle(manager);
        let name: Vec<u16> = service.encode_utf16().chain(std::iter::once(0)).collect();
        let handle = OpenServiceW(manager.0, PCWSTR(name.as_ptr()), 4).map_err(|e| {
            format!(
                "Cannot open {service} service on computer '.'. {}",
                e.message()
            )
        })?;
        let handle = ScHandle(handle);
        let mut status = SERVICE_STATUS::default();
        QueryServiceStatus(handle.0, &mut status).map_err(|e| e.message())?;
        Ok(match status.dwCurrentState.0 {
            1 => "Stopped",
            2 => "StartPending",
            3 => "StopPending",
            4 => "Running",
            5 => "ContinuePending",
            6 => "PausePending",
            7 => "Paused",
            _ => "Unknown",
        })
    }
}

fn append_wmi_section(text: &mut String, title: &str, query: &str, properties: &[&str]) {
    nl(text, "");
    nl(text, &format!("{title}:"));
    match Wmi::connect(r"ROOT\CIMV2").and_then(|w| w.query(query, properties)) {
        Ok(rows) => {
            for row in rows {
                for (property, value) in properties.iter().zip(row.iter()) {
                    let shown = match value {
                        crate::wmi::Val::None => "not available".to_string(),
                        crate::wmi::Val::Text(t) => t.clone(),
                        crate::wmi::Val::Ints(v) => v
                            .iter()
                            .map(|n| n.to_string())
                            .collect::<Vec<_>>()
                            .join(" "),
                    };
                    nl(text, &format!("  {property}: {shown}"));
                }
            }
        }
        Err(e) => nl(text, &format!("  unavailable: {e}")),
    }
}

pub fn build_system_info() -> String {
    let mut text = String::new();
    nl(&mut text, &format!("Generated: {}", now_stamp()));
    nl(&mut text, &format!("Toolkit: {}", xos_core::VERSION));
    let process64 = cfg!(target_pointer_width = "64");
    let os64 = process64 || std::env::var_os("PROCESSOR_ARCHITEW6432").is_some();
    nl(
        &mut text,
        &format!(
            "Architecture: OS {}, process {}",
            if os64 { "x64" } else { "x86" },
            if process64 { "x64" } else { "x86" }
        ),
    );
    nl(&mut text, "Runtime: native Rust build, no CLR");

    match regval::open_hklm(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") {
        Some(key) => {
            let get = |n: &str| regval::value_text(&key, n);
            let build = get("CurrentBuildNumber").unwrap_or_else(|| "?".to_string());
            let ubr = get("UBR");
            let mut product = get("ProductName").unwrap_or_else(|| "Windows".to_string());
            if let Ok(number) = build.trim().parse::<i32>() {
                if number >= 22000 && product.to_lowercase().starts_with("windows 10") {
                    product = format!("Windows 11{}", &product["Windows 10".len()..]);
                }
            }
            nl(
                &mut text,
                &format!(
                    "Windows: {product} {}",
                    get("DisplayVersion").unwrap_or_default()
                ),
            );
            nl(
                &mut text,
                &format!(
                    "Edition: {} | Installation type: {}",
                    get("EditionID").unwrap_or_default(),
                    get("InstallationType").unwrap_or_default()
                ),
            );
            nl(
                &mut text,
                &format!(
                    "Build: {build}{}",
                    match ubr {
                        Some(u) if !u.is_empty() => format!(".{u}"),
                        _ => String::new(),
                    }
                ),
            );
        }
        None => {
            nl(&mut text, "Windows: Windows ");
            nl(&mut text, "Edition:  | Installation type: ");
            nl(&mut text, "Build: ?");
        }
    }

    append_wmi_section(
        &mut text,
        "Computer",
        "SELECT Manufacturer,Model,TotalPhysicalMemory FROM Win32_ComputerSystem",
        &["Manufacturer", "Model", "TotalPhysicalMemory"],
    );
    append_wmi_section(
        &mut text,
        "Processor",
        "SELECT Name,NumberOfCores,NumberOfLogicalProcessors FROM Win32_Processor",
        &["Name", "NumberOfCores", "NumberOfLogicalProcessors"],
    );
    append_wmi_section(
        &mut text,
        "Graphics",
        "SELECT Name,DriverVersion FROM Win32_VideoController",
        &["Name", "DriverVersion"],
    );
    append_wmi_section(
        &mut text,
        "BIOS",
        "SELECT Manufacturer,SMBIOSBIOSVersion,ReleaseDate FROM Win32_BIOS",
        &["Manufacturer", "SMBIOSBIOSVersion", "ReleaseDate"],
    );

    nl(&mut text, "");
    nl(&mut text, "Selected service states:");
    for service in [
        "WinDefend",
        "WdFilter",
        "WdNisSvc",
        "SecurityHealthService",
        "wscsvc",
        "EventLog",
        "BITS",
        "wuauserv",
        "DoSvc",
        "UsoSvc",
        "WaaSMedicSvc",
        "uhssvc",
        "WSearch",
        "SysMain",
        "DiagTrack",
    ] {
        let path = format!(r"SYSTEM\CurrentControlSet\Services\{service}");
        match regval::open_hklm(&path) {
            None => nl(&mut text, &format!("  {service}: not present")),
            Some(key) => {
                let start = match key.get_raw_value("Start") {
                    Ok(v) => match regval::decode(&v) {
                        RegData::Dword(n) => n.to_string(),
                        RegData::Qword(n) => n.to_string(),
                        RegData::Text(s) | RegData::Expand(s) => s,
                        _ => "unexpected data type".to_string(),
                    },
                    Err(_) => "not set".to_string(),
                };
                let status = match service_status(service) {
                    Ok(s) => s.to_string(),
                    Err(e) => format!("unavailable ({e})"),
                };
                nl(
                    &mut text,
                    &format!("  {service}: Start={start}; Status={status}"),
                );
            }
        }
    }

    nl(&mut text, "");
    nl(&mut text, "Windows Update service protection:");
    match xos_winupdate::service_guard::has_owned_guards() {
        Ok(owned) => {
            nl(
                &mut text,
                &format!(
                    "  Recovery journal: {}",
                    if owned { "present" } else { "not present" }
                ),
            );
            nl(
                &mut text,
                &format!(
                    "  Disabled service permissions verified: {}",
                    if owned && xos_winupdate::service_guard::matches(false) {
                        "True"
                    } else {
                        "False"
                    }
                ),
            );
        }
        Err(e) => nl(&mut text, &format!("  unavailable ({e})")),
    }
    nl(&mut text, "");
    nl(&mut text, "Windows Update source and access policies:");
    use xos_winupdate::hard_disable as hd;
    let mut update_values: Vec<(String, String)> = Vec::new();
    for name in hd::SERVER_VALUES
        .iter()
        .chain(hd::CLASS_VALUES.iter())
        .chain(
            [
                "DisableWindowsUpdateAccess",
                "DoNotConnectToWindowsUpdateInternetLocations",
                "SetDisableUXWUAccess",
            ]
            .iter(),
        )
    {
        update_values.push((hd::POLICY.to_string(), name.to_string()));
    }
    for name in ["NoAutoUpdate", "UseWUServer", "UseUpdateClassPolicySource"] {
        update_values.push((hd::AU.to_string(), name.to_string()));
    }
    update_values.push((hd::OWNERSHIP_KEY.to_string(), "Applied".to_string()));
    update_values.push((
        r"HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Update".to_string(),
        "IgnoreWindowsUpdateGroupPolicies".to_string(),
    ));
    for (key_path, name) in update_values {
        let sub = key_path.get(5..).unwrap_or("");
        let state = match regval::open_hklm(sub) {
            None => "not set".to_string(),
            Some(key) => match key.get_raw_value(&name) {
                Err(_) => "not set".to_string(),
                Ok(raw) => match regval::decode(&raw) {
                    RegData::Dword(n) => n.to_string(),
                    RegData::Text(s) | RegData::Expand(s) => {
                        if s == " " {
                            "exactly one space".to_string()
                        } else {
                            "configured string (destination omitted)".to_string()
                        }
                    }
                    _ => "unexpected data type".to_string(),
                },
            },
        };
        nl(&mut text, &format!("  {key_path} / {name}: {state}"));
    }

    nl(&mut text, "");
    nl(&mut text, "Key files:");
    for file in [
        r"C:\Program Files\XOS Toolkit\XOS-Toolkit.exe",
        r"C:\Program Files (x86)\Microsoft\Edge\Application",
        r"C:\Program Files (x86)\Microsoft\EdgeWebView\Application",
        r"C:\Windows\System32\smartscreen.exe",
        r"C:\Windows\System32\smartscreen.old",
    ] {
        nl(
            &mut text,
            &format!(
                "  {}: {file}",
                if Path::new(file).exists() {
                    "present"
                } else {
                    "missing"
                }
            ),
        );
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(level: u8, provider: &str, description: Option<&str>) -> eventlog::EventRecord {
        eventlog::EventRecord {
            time_created: None,
            provider: provider.to_string(),
            event_id: 7,
            level,
            description: description.map(|s| s.to_string()),
            properties: Some(vec!["1".to_string(), "C:\\x".to_string()]),
        }
    }

    #[test]
    fn event_line_shape() {
        let line = format_event_line(&record(2, "Prov", Some("a\r\n  b   c")));
        assert_eq!(line, "? | Error | Prov | 7 | a b c");
        let long = "x".repeat(1200);
        let line = format_event_line(&record(3, "P", Some(&long)));
        assert!(line.ends_with("..."));
        assert!(line.contains("Warning"));
        let none = format_event_line(&record(0, "P", None));
        assert_eq!(none, "? | Info | P | 7 | properties: 1; C:\\x");
    }

    #[test]
    fn text_filter() {
        let dest = std::env::temp_dir().join("xos-diag-test-never-written");
        assert!(!copy_redacted(r"C:\x\file.bin", &dest).unwrap());
    }

    #[test]
    fn system_info_has_sections() {
        let text = build_system_info();
        assert!(text.contains("Selected service states:"));
        assert!(text.contains("Key files:"));
        assert!(text.contains("Windows Update source and access policies:"));
    }
}

use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Result};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, WAIT_TIMEOUT};
use windows::Win32::Networking::WinHttp::{
    WinHttpCloseHandle, WinHttpConnect, WinHttpOpen, WinHttpOpenRequest, WinHttpQueryDataAvailable,
    WinHttpQueryHeaders, WinHttpQueryOption, WinHttpReadData, WinHttpReceiveResponse,
    WinHttpSendRequest, WinHttpSetTimeouts, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
    WINHTTP_FLAG_SECURE, WINHTTP_OPEN_REQUEST_FLAGS, WINHTTP_QUERY_FLAG_NUMBER,
    WINHTTP_QUERY_STATUS_CODE,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_STATUS_PROCESS_INFO,
    SERVICE_STATUS_PROCESS,
};
use windows::Win32::System::Threading::{
    OpenProcess, TerminateProcess, WaitForSingleObject, PROCESS_ACCESS_RIGHTS,
};
use winreg::enums::{
    HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_ALL_ACCESS, KEY_READ, KEY_WOW64_32KEY,
    KEY_WOW64_64KEY,
};
use winreg::RegKey;
use xos_core::{app_state, log};
use xos_sys::{
    config_service_reg, config_service_sc, disable_task, enable_task, expand_environment_variables,
    get_scheduled_task_paths_by_name_prefix, get_service_start_type, get_task_state,
    record_task_state_failure, reg_delete_key, reg_delete_value, reg_get_dword, reg_get_string,
    reg_set_dword, reg_set_string, run_as_ti_renamed_timeout, run_as_ti_timeout,
    run_cmd_output_timeout, service_exists, stop_service, stop_service_best_effort, try_disable_task_quiet,
};

use crate::util::{
    dedupe_ignore_case, encode_powershell, env_path, eq_ignore_case, io_msg, random_hex32,
    sorted_ignore_case, wide, win32_code, windows_directory,
};

pub const GUID: &str = "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}";
pub const POLICY_PATH: &str = r"HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate";
pub const EDGE_UPDATE_DEV_PATH: &str = r"HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdateDev";
const RUNTIME_STATE_PATH: &str = r"HKLM\SOFTWARE\XOS Toolkit\WebView2";
const EDGE_REMOVAL_STATE_PATH: &str = r"HKLM\SOFTWARE\XOS Toolkit\EdgeRemoval";
const EDGE_REMOVAL_REQUESTED_VALUE: &str = "UserRequested";
const UPDATER_STATE_SAVED_VALUE: &str = "UpdaterStateSaved";
const UPDATER_BLOCKED_VALUE: &str = "UpdaterBlocked";
const UPDATER_TASK_PATHS_VALUE: &str = "UpdaterTaskPaths";
const UPDATER_SERVICES: [&str; 2] = ["edgeupdate", "edgeupdatem"];
const UPDATER_TASK_PREFIXES: [&str; 2] = [
    "MicrosoftEdgeUpdateTaskMachineCore",
    "MicrosoftEdgeUpdateTaskMachineUA",
];
const LEGACY_UPDATER_TASKS: [&str; 2] = [
    r"\MicrosoftEdgeUpdateTaskMachineCore",
    r"\MicrosoftEdgeUpdateTaskMachineUA",
];
const REMOVAL_PROCESS_NAMES: [&str; 12] = [
    "msedge",
    "msedgewebview2",
    "MicrosoftEdgeUpdate",
    "RuntimeBroker",
    "SearchHost",
    "SearchApp",
    "SearchUI",
    "StartMenuExperienceHost",
    "ShellExperienceHost",
    "TextInputHost",
    "backgroundTaskHost",
    "Widgets",
];

fn program_files_roots() -> Vec<String> {
    vec![
        env_path("ProgramFiles(x86)"),
        env_path("ProgramFiles"),
        env_path("LOCALAPPDATA"),
    ]
}

fn profile_local_roots() -> Vec<String> {
    let mut roots = Vec::new();
    let profiles = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList",
        KEY_READ,
    );
    if let Ok(profiles) = profiles {
        for sid in profiles.enum_keys().filter_map(|k| k.ok()) {
            if let Ok(profile) = profiles.open_subkey_with_flags(&sid, KEY_READ) {
                if let Ok(path) = profile.get_value::<String, _>("ProfileImagePath") {
                    if !path.trim().is_empty() {
                        roots.push(
                            Path::new(&expand_environment_variables(&path))
                                .join(r"AppData\Local")
                                .to_string_lossy()
                                .to_string(),
                        );
                    }
                }
            }
        }
    }
    roots
}

fn distinct_roots(roots: Vec<String>) -> Vec<String> {
    dedupe_ignore_case(roots.into_iter().filter(|p| !p.trim().is_empty()))
}

fn sub_directories(path: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            out.push(entry.path());
        }
    }
    Ok(out)
}

pub fn get_executable_paths(all_users: bool) -> Vec<String> {
    let mut roots = program_files_roots();
    if all_users {
        roots.extend(profile_local_roots());
    }
    find_executables(&roots)
}

pub fn find_executables(roots: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for root in distinct_roots(roots.to_vec()) {
        let application = Path::new(&root).join(r"Microsoft\EdgeWebView\Application");
        if !application.is_dir() {
            continue;
        }
        if let Ok(dirs) = sub_directories(&application) {
            for directory in dirs {
                let executable = directory.join("msedgewebview2.exe");
                if executable.is_file() {
                    out.push(executable.to_string_lossy().to_string());
                }
            }
        }
    }
    out
}

pub fn has_edge_browser() -> bool {
    let mut roots = program_files_roots();
    roots.extend(profile_local_roots());
    for root in distinct_roots(roots) {
        let microsoft = Path::new(&root).join("Microsoft");
        if !microsoft.is_dir() {
            continue;
        }
        let channels: Vec<PathBuf> = match sub_directories(&microsoft) {
            Ok(d) => d
                .into_iter()
                .filter(|p| {
                    p.file_name()
                        .map(|n| n.to_string_lossy().to_uppercase().starts_with("EDGE"))
                        .unwrap_or(false)
                })
                .collect(),
            Err(_) => continue,
        };
        for channel in channels {
            let application = channel.join("Application");
            if application.join("msedge.exe").is_file() {
                return true;
            }
            if let Ok(versions) = sub_directories(&application) {
                for version in versions {
                    if version.join("msedge.exe").is_file() {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn updater_task_state_value(task_path: &str) -> String {
    format!(
        "UpdaterTask_{}",
        task_path.trim_matches('\\').replace('\\', "_")
    )
}

fn get_updater_task_paths() -> Vec<String> {
    let mut paths: Vec<String> = Vec::new();
    let prefixes: Vec<String> = UPDATER_TASK_PREFIXES
        .iter()
        .map(|s| s.to_string())
        .collect();
    for task in get_scheduled_task_paths_by_name_prefix(&prefixes) {
        if !task.trim().is_empty() {
            paths.push(task.trim().to_string());
        }
    }
    let mut paths = dedupe_ignore_case(paths);

    if paths.is_empty() {
        let tasks_root = Path::new(&windows_directory()).join(r"System32\Tasks");
        match std::fs::read_dir(&tasks_root) {
            Ok(entries) => {
                let names: Vec<(String, bool)> = entries
                    .flatten()
                    .map(|e| {
                        (
                            e.file_name().to_string_lossy().to_string(),
                            e.file_type().map(|t| t.is_file()).unwrap_or(false),
                        )
                    })
                    .collect();
                for prefix in UPDATER_TASK_PREFIXES {
                    for (name, is_file) in &names {
                        if *is_file && name.to_uppercase().starts_with(&prefix.to_uppercase()) {
                            paths.push(format!(r"\{name}"));
                        }
                    }
                }
                paths = dedupe_ignore_case(paths);
            }
            Err(e) => {
                log::log(&format!(
                    "[WebView2] Edge Update task file discovery failed: {}",
                    io_msg(&e)
                ));
            }
        }
    }
    sorted_ignore_case(paths)
}

fn get_saved_updater_task_paths() -> Vec<String> {
    let saved = reg_get_string(RUNTIME_STATE_PATH, UPDATER_TASK_PATHS_VALUE);
    if let Some(saved) = saved {
        if !saved.trim().is_empty() {
            let items: Vec<String> = saved
                .split(['\r', '\n'])
                .filter(|s| !s.is_empty())
                .map(|s| s.trim().to_string())
                .filter(|s| s.starts_with('\\'))
                .collect();
            return dedupe_ignore_case(items);
        }
    }
    LEGACY_UPDATER_TASKS
        .iter()
        .filter(|task| reg_get_dword(RUNTIME_STATE_PATH, &updater_task_state_value(task)).is_some())
        .map(|s| s.to_string())
        .collect()
}

fn save_updater_state() -> Result<()> {
    if reg_get_dword(RUNTIME_STATE_PATH, UPDATER_STATE_SAVED_VALUE) == Some(1) {
        return Ok(());
    }
    for service in UPDATER_SERVICES {
        let start = get_service_start_type(service);
        if start < 0 {
            continue;
        }
        if !reg_set_dword(
            RUNTIME_STATE_PATH,
            &format!("UpdaterService_{service}_Start"),
            start,
        ) {
            bail!("The previous Edge Update service state could not be saved.");
        }
    }
    let tasks = get_updater_task_paths();
    for task in &tasks {
        let state = get_task_state(task);
        if state < 0 {
            continue;
        }
        if !reg_set_dword(RUNTIME_STATE_PATH, &updater_task_state_value(task), state) {
            bail!("The previous Edge Update task state could not be saved.");
        }
    }
    if !tasks.is_empty()
        && !reg_set_string(
            RUNTIME_STATE_PATH,
            UPDATER_TASK_PATHS_VALUE,
            &tasks.join("\n"),
        )
    {
        bail!("The previous Edge Update task paths could not be saved.");
    }
    if !reg_set_dword(RUNTIME_STATE_PATH, UPDATER_STATE_SAVED_VALUE, 1) {
        bail!("The previous Edge Update state could not be saved.");
    }
    log::log("[WebView2] Saved the previous Edge Update service and task states.");
    Ok(())
}

fn is_service_running(service_name: &str) -> bool {
    unsafe {
        let manager = match OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), 1) {
            Ok(m) => m,
            Err(_) => return false,
        };
        let name = wide(service_name);
        let service = OpenServiceW(manager, PCWSTR(name.as_ptr()), 4);
        let result = match service {
            Ok(service) => {
                let mut status = SERVICE_STATUS_PROCESS::default();
                let mut needed = 0u32;
                let buffer = std::slice::from_raw_parts_mut(
                    &mut status as *mut SERVICE_STATUS_PROCESS as *mut u8,
                    std::mem::size_of::<SERVICE_STATUS_PROCESS>(),
                );
                let ok = QueryServiceStatusEx(
                    service,
                    SC_STATUS_PROCESS_INFO,
                    Some(buffer),
                    &mut needed,
                )
                .is_ok();
                let _ = CloseServiceHandle(service);
                ok && status.dwCurrentState.0 == 4
            }
            Err(_) => false,
        };
        let _ = CloseServiceHandle(manager);
        result
    }
}

fn process_ids_by_name(name: &str) -> std::result::Result<Vec<u32>, String> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            .map_err(|e| format!("{}", e.message()))?;
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut ids = Vec::new();
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
            if eq_ignore_case(stem, name) {
                ids.push(entry.th32ProcessID);
            }
            more = Process32NextW(snapshot, &mut entry).is_ok();
        }
        let _ = CloseHandle(snapshot);
        Ok(ids)
    }
}

fn kill_processes_named(name: &str, updater_only: bool) {
    let ids = match process_ids_by_name(name) {
        Ok(ids) => ids,
        Err(msg) => {
            if updater_only {
                log::log(&format!(
                    "[WebView2] Updater process enumeration failed: {msg}"
                ));
            } else {
                log::log(&format!(
                    "[WebView2] Process enumeration failed for {name}: {msg}"
                ));
            }
            return;
        }
    };
    let label = if updater_only {
        "updater process"
    } else {
        "process"
    };
    for pid in ids {
        unsafe {
            let handle = match OpenProcess(PROCESS_ACCESS_RIGHTS(0x0001 | 0x0010_0000), false, pid)
            {
                Ok(h) => h,
                Err(e) => {
                    if win32_code(&e) != 87 {
                        log::log(&format!(
                            "[WebView2] Could not stop {label} {name}: {}",
                            e.message()
                        ));
                    }
                    continue;
                }
            };
            match TerminateProcess(handle, 1) {
                Ok(()) => {
                    WaitForSingleObject(handle, 2000);
                    log::log(&format!("[WebView2] Stopped {label} {name} (PID {pid})."));
                }
                Err(e) => {
                    log::log(&format!(
                        "[WebView2] Could not stop {label} {name}: {}",
                        e.message()
                    ));
                }
            }
            let _ = CloseHandle(handle);
        }
    }
}

fn stop_updater_processes() {
    kill_processes_named("MicrosoftEdgeUpdate", true);
}

fn disable_updater_infrastructure(force: bool) -> Result<bool> {
    if !force && has_edge_browser() {
        log::log("[WebView2] Edge browser detected; shared Edge Update infrastructure remains available.");
        return Ok(true);
    }

    save_updater_state()?;
    let mut failures: Vec<String> = Vec::new();

    for service in UPDATER_SERVICES {
        if !service_exists(service) {
            continue;
        }
        if is_service_running(service) {
            stop_service_best_effort(service);
            std::thread::sleep(Duration::from_millis(300));
        }
        if is_service_running(service) {
            failures.push(format!("{service} could not be stopped"));
        }

        let configured = config_service_sc(service, "disabled");
        let start = get_service_start_type(service);
        if (!configured && service_exists(service)) || (start >= 0 && start != 4) {
            failures.push(format!("{service} could not be disabled"));
        } else {
            log::log(&format!(
                "[WebView2] Edge Update service disabled: {service}"
            ));
        }
    }

    for task in get_updater_task_paths() {
        let state = get_task_state(&task);
        if state < 0 {
            continue;
        }
        let mut verify = state;
        let mut attempt = 1;
        while attempt <= 3 && verify > 0 {
            if verify != 0 {
                try_disable_task_quiet(&task);
            }
            verify = get_task_state(&task);
            if verify > 0 && attempt < 3 {
                log::log(&format!(
                    "[WebView2] {task} still enabled after attempt {attempt}, stopping the updater and retrying."
                ));
                stop_updater_processes();
                std::thread::sleep(Duration::from_millis(1000));
            }
            attempt += 1;
        }

        if verify > 0 {
            failures.push(format!("{task} could not be disabled"));
            record_task_state_failure(&task);
        } else {
            log::log(&format!("[WebView2] Edge Update task disabled: {task}"));
        }
    }

    stop_updater_processes();
    if !failures.is_empty() {
        log::log(&format!(
            "[WebView2] Edge Update blocking failed: {}",
            failures.join("; ")
        ));
        bail!(
            "The shared Edge Update infrastructure could not be fully blocked. {}",
            failures.join("; ")
        );
    }

    if !reg_set_dword(RUNTIME_STATE_PATH, UPDATER_BLOCKED_VALUE, 1) {
        bail!("The shared Edge Update blocked state could not be saved.");
    }
    log::log(
        "[WebView2] Edge Update services and scheduled tasks are blocked because Edge is absent.",
    );
    Ok(true)
}

pub fn restore_updater_infrastructure() -> bool {
    let state_saved = reg_get_dword(RUNTIME_STATE_PATH, UPDATER_STATE_SAVED_VALUE) == Some(1);
    let blocked = reg_get_dword(RUNTIME_STATE_PATH, UPDATER_BLOCKED_VALUE) == Some(1);
    if !state_saved && !blocked {
        return true;
    }

    let mut ok = true;
    for service in UPDATER_SERVICES {
        let saved = reg_get_dword(
            RUNTIME_STATE_PATH,
            &format!("UpdaterService_{service}_Start"),
        );
        let saved = match saved {
            Some(s) if service_exists(service) => s,
            _ => continue,
        };
        let configured = (0..=4).contains(&saved) && config_service_reg(service, saved);
        let current = get_service_start_type(service);
        if !configured || (current >= 0 && current != saved) {
            log::log(&format!(
                "[WebView2] Could not restore Edge Update service: {service}"
            ));
            ok = false;
        } else {
            log::log(&format!(
                "[WebView2] Restored Edge Update service Start={saved}: {service}"
            ));
        }
    }

    for task in get_saved_updater_task_paths() {
        let saved = match reg_get_dword(RUNTIME_STATE_PATH, &updater_task_state_value(&task)) {
            Some(s) => s,
            None => continue,
        };
        let current = get_task_state(&task);
        if current < 0 {
            continue;
        }
        let changed = if saved == 1 {
            enable_task(&task)
        } else {
            disable_task(&task)
        };
        let verify = get_task_state(&task);
        if !changed || (verify >= 0 && verify != saved) {
            log::log(&format!(
                "[WebView2] Could not restore Edge Update task: {task}"
            ));
            ok = false;
        } else {
            log::log(&format!(
                "[WebView2] Restored Edge Update task state={saved}: {task}"
            ));
        }
    }

    if !ok {
        return false;
    }
    if !clear_updater_state() {
        log::log("[WebView2] Previous Edge Update state was restored, but its temporary state could not be cleared.");
        return false;
    }
    log::log("[WebView2] Previous Edge Update infrastructure state restored.");
    true
}

pub fn clear_updater_state() -> bool {
    let mut ok = true;
    for service in UPDATER_SERVICES {
        ok &= reg_delete_value(
            RUNTIME_STATE_PATH,
            &format!("UpdaterService_{service}_Start"),
        );
    }
    let mut tasks: Vec<String> = LEGACY_UPDATER_TASKS.iter().map(|s| s.to_string()).collect();
    tasks.extend(get_updater_task_paths());
    tasks.extend(get_saved_updater_task_paths());
    for task in dedupe_ignore_case(tasks) {
        ok &= reg_delete_value(RUNTIME_STATE_PATH, &updater_task_state_value(&task));
    }
    ok &= reg_delete_value(RUNTIME_STATE_PATH, UPDATER_TASK_PATHS_VALUE);
    ok &= reg_delete_value(RUNTIME_STATE_PATH, UPDATER_STATE_SAVED_VALUE);
    ok &= reg_delete_value(RUNTIME_STATE_PATH, UPDATER_BLOCKED_VALUE);
    ok
}

pub fn is_edge_removal_requested() -> bool {
    reg_get_dword(EDGE_REMOVAL_STATE_PATH, EDGE_REMOVAL_REQUESTED_VALUE) == Some(1)
}

pub fn mark_edge_removal_requested() -> bool {
    let written = reg_set_dword(EDGE_REMOVAL_STATE_PATH, EDGE_REMOVAL_REQUESTED_VALUE, 1);
    written && reg_get_dword(EDGE_REMOVAL_STATE_PATH, EDGE_REMOVAL_REQUESTED_VALUE) == Some(1)
}

pub fn clear_edge_removal_requested() -> bool {
    reg_delete_key(EDGE_REMOVAL_STATE_PATH)
}

pub fn preserve_edge_removal_after_uninstall() -> bool {
    if !is_edge_removal_requested() {
        return true;
    }

    let runtime_removed = remove_residual_files(true);

    let mut updater_blocked = false;
    match block_installation_force(true) {
        Ok(()) => updater_blocked = true,
        Err(e) => log::log(&format!(
            "[WebView2] Explicit Edge removal updater block failed during uninstall: {e}"
        )),
    }

    let state_cleared = clear_updater_state();
    log::log(&format!(
        "[WebView2] Explicit Edge removal preserved after XOS uninstall: runtimeRemoved={}; updaterBlocked={}; temporaryStateCleared={}",
        py_bool(runtime_removed),
        py_bool(updater_blocked),
        py_bool(state_cleared)
    ));
    runtime_removed && updater_blocked && state_cleared
}

fn py_bool(b: bool) -> &'static str {
    if b {
        "True"
    } else {
        "False"
    }
}

fn parse_version_nonzero(text: &str) -> bool {
    let parts: Vec<&str> = text.trim().split('.').collect();
    if !(2..=4).contains(&parts.len()) {
        return false;
    }
    let mut any = false;
    for p in parts {
        match p.parse::<i32>() {
            Ok(n) if n >= 0 => any |= n > 0,
            _ => return false,
        }
    }
    any
}

pub fn has_registration() -> bool {
    for hive in [HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER] {
        for view in [KEY_WOW64_32KEY, KEY_WOW64_64KEY] {
            let key = RegKey::predef(hive).open_subkey_with_flags(
                format!(r"SOFTWARE\Microsoft\EdgeUpdate\Clients\{GUID}"),
                KEY_READ | view,
            );
            if let Ok(key) = key {
                if let Ok(pv) = key.get_value::<String, _>("pv") {
                    if parse_version_nonzero(&pv) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

pub fn prepare_for_removal() {
    for service in UPDATER_SERVICES {
        if !service_exists(service) {
            continue;
        }
        if !is_service_running(service) {
            continue;
        }
        log::log(&format!(
            "[WebView2] Stopping updater service before removal: {service}"
        ));
        if !stop_service(service) {
            log::log(&format!(
                "[WebView2] Updater service stop returned a nonzero result: {service}"
            ));
        }
    }

    for _attempt in 0..4 {
        stop_removal_processes();
        if !removal_processes_running() {
            break;
        }
        std::thread::sleep(Duration::from_millis(300));
    }
}

fn stop_removal_processes() {
    for name in REMOVAL_PROCESS_NAMES {
        kill_processes_named(name, false);
    }
}

fn removal_processes_running() -> bool {
    for name in REMOVAL_PROCESS_NAMES {
        if let Ok(ids) = process_ids_by_name(name) {
            for pid in ids {
                unsafe {
                    if let Ok(handle) = OpenProcess(PROCESS_ACCESS_RIGHTS(0x0010_0000), false, pid)
                    {
                        let running = WaitForSingleObject(handle, 0) == WAIT_TIMEOUT;
                        let _ = CloseHandle(handle);
                        if running {
                            return true;
                        }
                    }
                }
            }
        }
    }
    false
}

pub fn remove_residual_files(all_users: bool) -> bool {
    for attempt in 1..=3 {
        prepare_for_removal();
        let files = get_executable_paths(all_users);
        if files.is_empty() {
            cleanup_registration();
            return true;
        }

        for directory in get_application_directories(&files) {
            if !is_safe_application_directory(&directory) {
                log::log(&format!(
                    "[WebView2] Refused unsafe residual cleanup target: {directory}"
                ));
                continue;
            }

            log::log(&format!(
                "[WebView2] Removing residual runtime directory: {directory}"
            ));
            let removed =
                run_as_ti_timeout("cmd.exe", &format!("/c rd /s /q \"{directory}\""), 120000);
            if !removed && Path::new(&directory).exists() {
                if let Err(e) = std::fs::remove_dir_all(&directory) {
                    log::log(&format!(
                        "[WebView2] Direct residual cleanup failed: {}",
                        io_msg(&e)
                    ));
                }
            }
        }

        if get_executable_paths(all_users).is_empty() {
            cleanup_registration();
            log::log("[WebView2] Residual runtime cleanup verified.");
            return true;
        }
        if attempt < 3 {
            std::thread::sleep(Duration::from_millis(1000));
        }
    }

    log::log(&format!(
        "[WebView2] Residual runtime cleanup could not remove: {}",
        get_executable_paths(all_users).join("; ")
    ));
    false
}

fn get_application_directories(executables: &[String]) -> Vec<String> {
    let dirs = executables.iter().filter_map(|p| {
        Path::new(p)
            .parent()
            .and_then(|d| d.parent())
            .map(|d| d.to_string_lossy().to_string())
    });
    dedupe_ignore_case(dirs.filter(|p| !p.trim().is_empty()))
}

fn is_safe_application_directory(directory: &str) -> bool {
    let full = directory.trim_end_matches(['\\', '/']);
    full.to_uppercase()
        .ends_with(r"\MICROSOFT\EDGEWEBVIEW\APPLICATION")
}

fn cleanup_registration() {
    let paths = [
        format!(r"SOFTWARE\Microsoft\EdgeUpdate\Clients\{GUID}"),
        format!(r"SOFTWARE\Microsoft\EdgeUpdate\ClientState\{GUID}"),
        format!(r"SOFTWARE\Microsoft\EdgeUpdate\ClientStateMedium\{GUID}"),
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft EdgeWebView".to_string(),
    ];

    for hklm in [true, false] {
        for view32 in [true, false] {
            for path in &paths {
                delete_registration_key(hklm, view32, path);
            }
        }
    }
}

fn delete_registration_key(hklm: bool, view32: bool, path: &str) {
    let hive_name = if hklm { "LocalMachine" } else { "CurrentUser" };
    let view_name = if view32 { "Registry32" } else { "Registry64" };
    let view = if view32 {
        KEY_WOW64_32KEY
    } else {
        KEY_WOW64_64KEY
    };
    let hive = if hklm {
        HKEY_LOCAL_MACHINE
    } else {
        HKEY_CURRENT_USER
    };
    let result = (|| -> std::io::Result<bool> {
        let present = RegKey::predef(hive)
            .open_subkey_with_flags(path, KEY_READ | view)
            .is_ok();
        if !present {
            return Ok(false);
        }
        let root = RegKey::predef(hive).open_subkey_with_flags("", KEY_ALL_ACCESS | view)?;
        root.delete_subkey_all(path)?;
        Ok(true)
    })();
    match result {
        Ok(true) => log::log(&format!(
            "[WebView2] Removed registration: {hive_name} {view_name} {path}"
        )),
        Ok(false) => {}
        Err(e) => {
            log::log(&format!(
                "[WebView2] Registration cleanup failed for {hive_name} {view_name} {path}: {}",
                io_msg(&e)
            ));
            if hklm {
                let view_switch = if view32 { "/reg:32" } else { "/reg:64" };
                let ok = run_as_ti_renamed_timeout(
                    "reg.exe",
                    &format!("delete \"HKLM\\{path}\" /f {view_switch}"),
                    60000,
                );
                if !ok {
                    log::log(&format!(
                        "[WebView2] TrustedInstaller registration cleanup also failed: {path}"
                    ));
                }
            }
        }
    }
}

pub fn block_installation() -> Result<()> {
    block_installation_force(false)
}

pub fn block_installation_force(force_updater_block: bool) -> Result<()> {
    let attempt = || -> Result<()> {
        disable_updater_infrastructure(force_updater_block)?;

        let mut written = reg_set_dword(POLICY_PATH, &format!("Install{GUID}"), 0);
        written &= reg_set_dword(POLICY_PATH, &format!("Update{GUID}"), 0);
        if !written
            || reg_get_dword(POLICY_PATH, &format!("Install{GUID}")) != Some(0)
            || reg_get_dword(POLICY_PATH, &format!("Update{GUID}")) != Some(0)
        {
            bail!("WebView2 installation and update policies could not be blocked.");
        }
        Ok(())
    };
    match attempt() {
        Ok(()) => Ok(()),
        Err(e) => {
            if !restore_updater_infrastructure() {
                log::log("[WebView2] Edge Update rollback was incomplete after blocking failed.");
            }
            Err(e)
        }
    }
}

pub fn allow_installation() -> Result<()> {
    let mut written = reg_set_dword(POLICY_PATH, &format!("Install{GUID}"), 1);
    written &= reg_set_dword(POLICY_PATH, &format!("Update{GUID}"), 1);
    if !written
        || reg_get_dword(POLICY_PATH, &format!("Install{GUID}")) != Some(1)
        || reg_get_dword(POLICY_PATH, &format!("Update{GUID}")) != Some(1)
    {
        bail!("WebView2 installation and update policies could not be enabled.");
    }

    if reg_get_dword(RUNTIME_STATE_PATH, UPDATER_STATE_SAVED_VALUE) == Some(1)
        || reg_get_dword(RUNTIME_STATE_PATH, UPDATER_BLOCKED_VALUE) == Some(1)
    {
        if !restore_updater_infrastructure() {
            bail!("The shared WebView2 updater could not be restored.");
        }
    } else {
        for service in UPDATER_SERVICES {
            if service_exists(service) && !config_service_sc(service, "demand") {
                bail!("The shared WebView2 updater could not be enabled.");
            }
        }
    }
    Ok(())
}

pub fn prepare_for_reinstall() -> Result<()> {
    allow_installation()?;

    reg_delete_value(POLICY_PATH, &format!("Uninstall{GUID}"));
    let written = reg_set_dword(EDGE_UPDATE_DEV_PATH, "AllowUninstall", 1);
    if !written || reg_get_dword(EDGE_UPDATE_DEV_PATH, "AllowUninstall") != Some(1) {
        bail!("WebView2 reinstall permissions could not be restored.");
    }
    if !clear_edge_removal_requested() {
        bail!("The previous explicit Edge removal preference could not be cleared.");
    }
    Ok(())
}

struct InternetHandle(*mut c_void);

impl Drop for InternetHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let _ = WinHttpCloseHandle(self.0);
            }
        }
    }
}

fn download_file(url: &str, output: &Path, timeout_ms: i32) -> Result<()> {
    let (secure, rest) = match url.strip_prefix("https://") {
        Some(r) => (true, r),
        None => match url.strip_prefix("http://") {
            Some(r) => (false, r),
            None => bail!("Invalid download address."),
        },
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
            (h.to_string(), p.parse::<u16>()?)
        }
        _ => (authority.to_string(), if secure { 443 } else { 80 }),
    };
    unsafe {
        let agent = wide("XOSToolkit");
        let session = InternetHandle(WinHttpOpen(
            PCWSTR(agent.as_ptr()),
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            PCWSTR::null(),
            PCWSTR::null(),
            0,
        ));
        if session.0.is_null() {
            bail!("The WebView2 download could not be started.");
        }
        WinHttpSetTimeouts(session.0, timeout_ms, timeout_ms, timeout_ms, timeout_ms)
            .map_err(|e| anyhow!("{}", e.message()))?;
        let whost = wide(&host);
        let connection = InternetHandle(WinHttpConnect(session.0, PCWSTR(whost.as_ptr()), port, 0));
        if connection.0.is_null() {
            bail!("The WebView2 download server could not be reached.");
        }
        let verb = wide("GET");
        let wpath = wide(path);
        let request = InternetHandle(WinHttpOpenRequest(
            connection.0,
            PCWSTR(verb.as_ptr()),
            PCWSTR(wpath.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            std::ptr::null(),
            if secure {
                WINHTTP_FLAG_SECURE
            } else {
                WINHTTP_OPEN_REQUEST_FLAGS(0)
            },
        ));
        if request.0.is_null() {
            bail!("The WebView2 download request could not be created.");
        }
        WinHttpSendRequest(request.0, None, None, 0, 0, 0)
            .map_err(|e| anyhow!("{}", e.message()))?;
        WinHttpReceiveResponse(request.0, std::ptr::null_mut())
            .map_err(|e| anyhow!("{}", e.message()))?;
        let mut status: u32 = 0;
        let mut size = std::mem::size_of::<u32>() as u32;
        WinHttpQueryHeaders(
            request.0,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            PCWSTR::null(),
            Some(&mut status as *mut u32 as *mut c_void),
            &mut size,
            std::ptr::null_mut(),
        )
        .map_err(|e| anyhow!("{}", e.message()))?;
        if !(200..300).contains(&status) {
            bail!("The remote server returned an error: ({status}).");
        }

        let mut url_buffer = vec![0u16; 4096];
        let mut url_bytes = (url_buffer.len() * 2) as u32;
        let final_url = match WinHttpQueryOption(
            request.0,
            34,
            Some(url_buffer.as_mut_ptr() as *mut c_void),
            &mut url_bytes,
        ) {
            Ok(()) => {
                let len = (url_bytes as usize / 2).min(url_buffer.len());
                let end = url_buffer[..len]
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(len);
                String::from_utf16_lossy(&url_buffer[..end])
            }
            Err(_) => url.to_string(),
        };

        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output)
            .map_err(|e| anyhow!("{}", io_msg(&e)))?;
        if !final_url.to_lowercase().starts_with("https://") {
            bail!("The WebView2 download was redirected to an insecure connection.");
        }
        loop {
            let mut available: u32 = 0;
            WinHttpQueryDataAvailable(request.0, &mut available)
                .map_err(|e| anyhow!("{}", e.message()))?;
            if available == 0 {
                break;
            }
            let mut chunk = vec![0u8; available as usize];
            let mut read: u32 = 0;
            WinHttpReadData(
                request.0,
                chunk.as_mut_ptr() as *mut c_void,
                available,
                &mut read,
            )
            .map_err(|e| anyhow!("{}", e.message()))?;
            if read == 0 {
                break;
            }
            file.write_all(&chunk[..read as usize])
                .map_err(|e| anyhow!("{}", io_msg(&e)))?;
        }
    }
    Ok(())
}

pub fn install() -> Result<()> {
    prepare_for_reinstall()?;
    if !reg_set_dword(RUNTIME_STATE_PATH, "PreserveRuntime", 1) {
        bail!("WebView2 preservation state could not be saved.");
    }
    if has_registration() && !get_executable_paths(false).is_empty() && service_exists("edgeupdate")
    {
        log::log("[WebView2] Runtime already installed. Installation and updates are allowed.");
        return Ok(());
    }
    let installer = std::env::temp_dir().join(format!("XOS-WebView2-{}.exe", random_hex32()));
    let mut installer_running = false;
    let outcome = (|| -> Result<()> {
        log::log("[WebView2] Downloading Microsoft Evergreen bootstrapper.");
        download_file(
            "https://go.microsoft.com/fwlink/p/?LinkId=2124703",
            &installer,
            120000,
        )?;

        let script = format!(
            "$s=Get-AuthenticodeSignature -LiteralPath '{}';if($s.Status -eq 'Valid' -and $s.SignerCertificate.Subject -match '(^|,\\s*)O=Microsoft Corporation(,|$)'){{'TRUSTED'}}",
            installer.to_string_lossy().replace('\'', "''")
        );
        let encoded = encode_powershell(&script);
        let signature = run_cmd_output_timeout(
            "powershell.exe",
            &format!("-NoProfile -NonInteractive -EncodedCommand {encoded}"),
            60000,
        );
        if signature.trim() != "TRUSTED" {
            bail!("The downloaded installer does not have a valid Microsoft signature.");
        }

        use std::os::windows::process::CommandExt;
        let mut child = std::process::Command::new(&installer)
            .args(["/silent", "/install"])
            .creation_flags(0x08000000)
            .spawn()
            .map_err(|_| anyhow!("The WebView2 installer could not be started."))?;
        installer_running = true;
        let started = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(s)) => break s,
                Ok(None) => {
                    if started.elapsed() >= Duration::from_millis(600000) {
                        bail!("The WebView2 installer is still running. Wait for it to finish before retrying.");
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(e) => bail!("{}", io_msg(&e)),
            }
        };
        installer_running = false;
        let code = status.code().unwrap_or(-1);
        log::log(&format!("[WebView2] Installer exit code: {code}"));
        if code != 0 && code != 3010 {
            bail!("WebView2 installation failed with exit code {code}.");
        }
        if code == 3010 {
            app_state::require_reboot();
        }

        let files = get_executable_paths(false);
        if !has_registration() || files.is_empty() {
            bail!("The installer finished, but a registered WebView2 runtime with executable files could not be verified.");
        }
        prepare_for_reinstall()?;
        log::log(&format!(
            "[WebView2] Installation verified: {}",
            files.join("; ")
        ));
        Ok(())
    })();
    if !installer_running {
        if let Err(e) = std::fs::remove_file(&installer) {
            if e.kind() != std::io::ErrorKind::NotFound {
                log::log(&format!("[WebView2] Installer cleanup: {}", io_msg(&e)));
            }
        }
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_state_value_names() {
        assert_eq!(
            updater_task_state_value(r"\MicrosoftEdgeUpdateTaskMachineCore"),
            "UpdaterTask_MicrosoftEdgeUpdateTaskMachineCore"
        );
        assert_eq!(updater_task_state_value(r"\A\B"), "UpdaterTask_A_B");
    }

    #[test]
    fn safe_directory_check() {
        assert!(is_safe_application_directory(
            r"C:\Program Files (x86)\Microsoft\EdgeWebView\Application\"
        ));
        assert!(!is_safe_application_directory(r"C:\Windows\System32"));
        assert!(!is_safe_application_directory(
            r"C:\Program Files (x86)\Microsoft\EdgeWebView\Application\123.0"
        ));
    }

    #[test]
    fn version_parsing() {
        assert!(parse_version_nonzero("123.0.2420.97"));
        assert!(!parse_version_nonzero("0.0.0.0"));
        assert!(!parse_version_nonzero("abc"));
        assert!(!parse_version_nonzero("1"));
    }

    #[test]
    fn application_directories_distinct() {
        let dirs = get_application_directories(&[
            r"C:\P\Microsoft\EdgeWebView\Application\1.0\msedgewebview2.exe".to_string(),
            r"c:\p\microsoft\edgewebview\application\2.0\msedgewebview2.exe".to_string(),
        ]);
        assert_eq!(dirs.len(), 1);
        assert!(dirs[0].ends_with("Application"));
    }
}

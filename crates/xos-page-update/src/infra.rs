use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use base64::Engine;
use windows::core::{BSTR, PCWSTR};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER,
    COINIT_APARTMENTTHREADED,
};
use windows::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_HANDLE, SERVICE_STATUS,
};
use windows::Win32::System::TaskScheduler::{ITaskFolder, ITaskService, TaskScheduler};
use windows::Win32::System::Variant::VARIANT;
use xos_core::log;
use xos_sys::{
    config_service_sc, get_service_delayed_auto_start, get_service_start_type,
    get_windows_build_number, ops, reg_delete_key, reg_delete_value, reg_get_dword, reg_get_string,
    reg_set_dword, reg_set_string, run_as_ti_output_timeout, start_service, stop_service,
};
use xos_winupdate::{hard_disable, legacy, service_guard};

use crate::consts::*;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SvcStatus {
    Stopped,
    StartPending,
    StopPending,
    Running,
    ContinuePending,
    PausePending,
    Paused,
}

impl SvcStatus {
    pub fn name(self) -> &'static str {
        match self {
            SvcStatus::Stopped => "Stopped",
            SvcStatus::StartPending => "StartPending",
            SvcStatus::StopPending => "StopPending",
            SvcStatus::Running => "Running",
            SvcStatus::ContinuePending => "ContinuePending",
            SvcStatus::PausePending => "PausePending",
            SvcStatus::Paused => "Paused",
        }
    }

    fn from_code(code: u32) -> Option<SvcStatus> {
        match code {
            1 => Some(SvcStatus::Stopped),
            2 => Some(SvcStatus::StartPending),
            3 => Some(SvcStatus::StopPending),
            4 => Some(SvcStatus::Running),
            5 => Some(SvcStatus::ContinuePending),
            6 => Some(SvcStatus::PausePending),
            7 => Some(SvcStatus::Paused),
            _ => None,
        }
    }
}

fn win32(e: &windows::core::Error) -> u32 {
    (e.code().0 as u32) & 0xFFFF
}

struct ScHandle(SC_HANDLE);

impl Drop for ScHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseServiceHandle(self.0);
        }
    }
}

pub fn read_update_service_status(service: &str) -> Result<Option<SvcStatus>> {
    unsafe {
        let manager = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), 1).map_err(|e| {
            anyhow!(
                "Cannot open Service Control Manager on computer '.'. Win32 error {}",
                win32(&e)
            )
        })?;
        let manager = ScHandle(manager);
        let wname: Vec<u16> = service.encode_utf16().chain(std::iter::once(0)).collect();
        let handle = match OpenServiceW(manager.0, PCWSTR(wname.as_ptr()), 4) {
            Ok(h) => ScHandle(h),
            Err(e) => {
                let code = win32(&e);
                if code == 1060 {
                    return Ok(None);
                }
                bail!("Cannot open {service} service on computer '.'. Win32 error {code}");
            }
        };
        let mut status = SERVICE_STATUS::default();
        QueryServiceStatus(handle.0, &mut status).map_err(|e| {
            anyhow!(
                "Cannot query {service} service status. Win32 error {}",
                win32(&e)
            )
        })?;
        Ok(SvcStatus::from_code(status.dwCurrentState.0))
    }
}

pub fn update_service_exists(service: &str) -> Result<bool> {
    Ok(read_update_service_status(service)?.is_some())
}

pub fn fallback_update_service_start(service: &str) -> i32 {
    if service.eq_ignore_ascii_case("dosvc") || service.eq_ignore_ascii_case("UsoSvc") {
        return 2;
    }
    3
}

pub fn sc_start_name(start_type: i32) -> &'static str {
    if start_type == 2 {
        "auto"
    } else if start_type == 4 {
        "disabled"
    } else {
        "demand"
    }
}

pub fn is_service_running(service: &str) -> Result<bool> {
    Ok(read_update_service_status(service)? == Some(SvcStatus::Running))
}

pub fn resolve_service_start(current: i32, saved: Option<i32>, fallback: i32) -> i32 {
    if let Some(s) = saved {
        if s == 2 || s == 3 {
            return s;
        }
    }
    if current == 2 || current == 3 {
        current
    } else {
        fallback
    }
}

pub fn is_blocked_mode_task(task: &str) -> bool {
    BLOCKED_MODE_TASKS
        .iter()
        .any(|t| t.eq_ignore_ascii_case(task))
}

pub fn shipped_disabled(task: &str) -> bool {
    if ORCHESTRATOR_MANAGED_TASKS
        .iter()
        .any(|t| t.eq_ignore_ascii_case(task))
    {
        return true;
    }
    task.eq_ignore_ascii_case(r"\Microsoft\Windows\InstallService\WakeUpAndContinueUpdates")
        || task.eq_ignore_ascii_case(r"\Microsoft\Windows\InstallService\WakeUpAndScanForUpdates")
}

#[derive(Clone, Debug, Default)]
pub struct TaskStates {
    items: Vec<(String, i32)>,
}

impl TaskStates {
    pub fn insert(&mut self, key: &str, value: i32) {
        if let Some(item) = self
            .items
            .iter_mut()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
        {
            item.1 = value;
        } else {
            self.items.push((key.to_string(), value));
        }
    }

    pub fn get(&self, key: &str) -> Option<i32> {
        self.items
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| *v)
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, i32)> {
        self.items.iter().map(|(k, v)| (k, *v))
    }

    pub fn keys(&self) -> Vec<String> {
        self.items.iter().map(|(k, _)| k.clone()).collect()
    }
}

pub fn update_tasks_match(states: Option<&TaskStates>, enabled: bool) -> bool {
    match states {
        None => false,
        Some(s) => {
            s.is_empty()
                || s.iter().all(|(k, v)| {
                    (enabled && shipped_disabled(k)) || v == if enabled { 1 } else { 0 }
                })
        }
    }
}

fn read_task_folder(folder: &ITaskFolder, states: &mut TaskStates) -> windows::core::Result<()> {
    unsafe {
        let tasks = folder.GetTasks(1)?;
        let count = tasks.Count()?;
        for i in 1..=count {
            let task = tasks.get_Item(&VARIANT::from(i))?;
            let path = task.Path()?.to_string();
            let enabled = task.Enabled()?.as_bool();
            states.insert(&path, if enabled { 1 } else { 0 });
        }
        let folders = folder.GetFolders(0)?;
        let count = folders.Count()?;
        for i in 1..=count {
            let child = folders.get_Item(&VARIANT::from(i))?;
            read_task_folder(&child, states)?;
        }
        Ok(())
    }
}

fn read_task_states_com() -> windows::core::Result<TaskStates> {
    unsafe {
        let init = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        let owned = init.is_ok();
        let result = (|| -> windows::core::Result<TaskStates> {
            let service: ITaskService =
                CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER)?;
            let empty = VARIANT::default();
            service.Connect(&empty, &empty, &empty, &empty)?;
            let mut states = TaskStates::default();
            for path in UPDATE_TASK_PATHS {
                let folder = match service.GetFolder(&BSTR::from(path)) {
                    Ok(f) => f,
                    Err(e) => {
                        let code = e.code().0 as u32;
                        if code == 0x80070002 || code == 0x80070003 {
                            continue;
                        }
                        return Err(e);
                    }
                };
                read_task_folder(&folder, &mut states)?;
            }
            Ok(states)
        })();
        if owned {
            CoUninitialize();
        }
        result
    }
}

pub fn read_update_task_states() -> Option<TaskStates> {
    match read_task_states_com() {
        Ok(s) => Some(s),
        Err(e) => {
            log::log(&format!(
                "[ERROR] Could not read update tasks: {}",
                e.message().trim_end()
            ));
            None
        }
    }
}

pub fn read_hard_disable_service_mismatches() -> Result<Vec<(String, (i32, SvcStatus))>> {
    let mut mismatches = Vec::new();
    for service in UPDATE_SVCS {
        let status = match read_update_service_status(service)? {
            Some(s) => s,
            None => continue,
        };
        let start = get_service_start_type(service);
        if start < 0 {
            bail!("Could not read update service startup: {service}");
        }
        if start != 4 || status != SvcStatus::Stopped {
            mismatches.push((service.to_string(), (start, status)));
        }
    }
    Ok(mismatches)
}

pub fn hard_disable_infrastructure_matches(task_states: Option<&TaskStates>) -> bool {
    if !update_tasks_match(task_states, false) {
        return false;
    }
    match read_hard_disable_service_mismatches() {
        Ok(m) => m.is_empty(),
        Err(e) => {
            log::log(&format!(
                "[ERROR] Could not verify hard-disabled update services: {e}"
            ));
            false
        }
    }
}

fn wait_for_service_state(service: &str, running: bool) -> Result<bool> {
    let wait = if running {
        SERVICE_START_WAIT_MS
    } else {
        SERVICE_STOP_WAIT_MS
    };
    let attempts = wait / SERVICE_WAIT_POLL_MS;
    let target = if running {
        SvcStatus::Running
    } else {
        SvcStatus::Stopped
    };
    for _ in 0..attempts {
        match read_update_service_status(service)? {
            None => return Ok(!running),
            Some(s) if s == target => return Ok(true),
            Some(_) => {}
        }
        std::thread::sleep(Duration::from_millis(SERVICE_WAIT_POLL_MS));
    }
    let final_status = read_update_service_status(service)?;
    Ok(final_status == Some(target) || (final_status.is_none() && !running))
}

fn backup_update_service_start_types() -> Result<()> {
    for service in UPDATE_SVCS {
        if !update_service_exists(service)?
            || reg_get_dword(UPDATE_SERVICE_BACKUP, service).is_some()
        {
            continue;
        }
        let current = get_service_start_type(service);
        if (2..=4).contains(&current) {
            reg_set_dword(UPDATE_SERVICE_BACKUP, service, current);
        }
    }
    Ok(())
}

pub fn disable_update_infrastructure(protect_services: bool) -> Result<bool> {
    backup_update_service_start_types()?;
    if ops::any_failed() {
        return Ok(false);
    }
    log::log("[OP] Hard disable: disabling update tasks before services change");
    let (pre_service_tasks_ok, pre_service_hard_failure) =
        set_update_tasks(&|_| false, Some(false), true)?;
    log::log("[OP] Hard disable: disabling update service startup");
    backup_update_service_start_types()?;
    if ops::any_failed() {
        return Ok(false);
    }

    let mut ok = !pre_service_hard_failure;
    for service in UPDATE_SVCS {
        if !update_service_exists(service)? {
            continue;
        }
        if !config_service_sc(service, "disabled") {
            ok = false;
        }
    }

    if protect_services {
        log::log("[OP] Hard disable: protecting disabled services before stopping them");
        if !service_guard::apply() {
            return Ok(false);
        }
    }

    log::log("[OP] Hard disable: stopping update services");
    ok &= stop_update_services(true)?;

    log::log("[OP] Hard disable: disabling update tasks after services stop");
    let (mut stopped_tasks_ok, stopped_tasks_hard_failure) =
        set_update_tasks(&|_| false, Some(false), true)?;
    ok &= !stopped_tasks_hard_failure;
    let mut mismatches = read_hard_disable_service_mismatches()?;
    if !mismatches.is_empty() {
        log::log("[OP] Hard disable: service state changed during the operation; retrying once");
        for (name, (start, status)) in &mismatches {
            log::log(&format!(
                "[Update] Retrying hard-disable service {name} Start={start} Status={}",
                status.name()
            ));
        }
        if protect_services && !service_guard::remove_owned() {
            return Ok(false);
        }
        backup_update_service_start_types()?;
        if ops::any_failed() {
            return Ok(false);
        }
        for service in UPDATE_SVCS {
            if !update_service_exists(service)? {
                continue;
            }
            let matched = if protect_services {
                service_guard::startup_matches(service, 4, false)
            } else {
                get_service_start_type(service) == 4
            };
            if matched {
                continue;
            }
            if !config_service_sc(service, "disabled") {
                ok = false;
            }
        }
        if protect_services && !service_guard::apply() {
            return Ok(false);
        }
        ok &= stop_update_services(false)?;
        stopped_tasks_ok = set_known_update_tasks(false)?;
        mismatches = read_hard_disable_service_mismatches()?;
    } else if !stopped_tasks_ok && !stopped_tasks_hard_failure {
        log::log("[OP] Hard disable: update task state changed after services stopped; retrying task disable once");
        stopped_tasks_ok = set_known_update_tasks(false)?;
        mismatches = read_hard_disable_service_mismatches()?;
    }
    ok &= stopped_tasks_ok;
    if !pre_service_tasks_ok && !pre_service_hard_failure && stopped_tasks_ok {
        log::log("[OP] Hard disable: update tasks that changed while the update services were running are disabled again after the stop");
    }
    for (name, (start, status)) in &mismatches {
        log::log(&format!(
            "[ERROR] Update service verification failed: {name} Start={start} Status={}",
            status.name()
        ));
        ok = false;
    }
    Ok(ok)
}

fn stop_update_services(allow_state_retry: bool) -> Result<bool> {
    let mut ok = true;
    for service in UPDATE_SVCS_STOP_ORDER {
        let status = match read_update_service_status(service)? {
            None | Some(SvcStatus::Stopped) => continue,
            Some(s) => s,
        };
        if status != SvcStatus::StopPending {
            ok &= stop_service(service);
        }
        if !wait_for_service_state(service, false)? {
            let prefix = if allow_state_retry {
                "[OP] Hard disable: update service stop is pending before final verification: "
            } else {
                "[ERROR] Update service did not stop within "
            };
            log::log(&format!(
                "{prefix}{} seconds: {service}",
                SERVICE_STOP_WAIT_MS / 1000
            ));
            if !allow_state_retry {
                ok = false;
            }
        }
    }
    Ok(ok)
}

pub fn undo_hard_disable() -> Result<bool> {
    if !is_hard_disabled()? {
        return Ok(true);
    }
    log::log("[Update] Windows Update is hard disabled; removing the hard disable as part of Windows defaults.");
    clean_hard_disable_registry()?;
    if reg_get_dword(POL_WU_AU, "NoAutoRebootWithLoggedOnUsers") == Some(1) {
        reg_set_dword(POL_WU_AU, "AUOptions", 4);
    }
    remove_hidden_settings_page("windowsupdate");
    restore_update_infrastructure()
}

pub fn is_hard_disabled() -> Result<bool> {
    Ok(service_guard::has_owned_guards()?
        || hard_disable::has_owned_sources()?
        || ((reg_get_dword(POL_WU, "SetDisableUXWUAccess") == Some(1)
            || reg_get_dword(POL_WU, "DisableWindowsUpdateAccess") == Some(1))
            && reg_get_dword(POL_WU_AU, "NoAutoUpdate") == Some(1)))
}

pub fn restore_update_infrastructure() -> Result<bool> {
    let mut ok = set_known_update_tasks(true)?;
    ok &= restore_update_services()?;
    Ok(ok)
}

pub fn set_blocked_mode_infrastructure() -> Result<bool> {
    let (mut ok, _) = set_update_tasks(&|task| !is_blocked_mode_task(task), None, false)?;
    ok &= restore_update_services()?;
    Ok(ok)
}

fn restore_update_services() -> Result<bool> {
    let mut ok = true;
    let build = get_windows_build_number();
    for service in UPDATE_SVCS {
        if !update_service_exists(service)? {
            continue;
        }
        let current = get_service_start_type(service);
        let saved = reg_get_dword(UPDATE_SERVICE_BACKUP, service);
        let desired = resolve_service_start(current, saved, fallback_update_service_start(service));
        let delayed = desired == 2
            && xos_helpers::service_defaults_table::is_delayed_auto_start(service, build);
        let needs_write = !service_guard::startup_matches(service, desired, false)
            || (delayed && get_service_delayed_auto_start(service) != 1);
        if needs_write
            && !config_service_sc(
                service,
                if delayed {
                    "delayed-auto"
                } else {
                    sc_start_name(desired)
                },
            )
        {
            ok = false;
        }
        if !service_guard::startup_matches(service, desired, true)
            || (delayed && get_service_delayed_auto_start(service) != 1)
        {
            log::log(&format!(
                "[ERROR] Update service startup verification failed: {service}"
            ));
            ok = false;
        }
    }

    for service in UPDATE_SVCS_START_ORDER {
        if !update_service_exists(service)? || is_service_running(service)? {
            continue;
        }
        start_service(service);
        if !wait_for_service_state(service, true)? {
            log::log(&format!("[ERROR] Update service did not start: {service}"));
            ok = false;
        }
    }

    if ok {
        reg_delete_key(UPDATE_SERVICE_BACKUP);
    }
    Ok(ok)
}

fn set_known_update_tasks(enable: bool) -> Result<bool> {
    let (ok, _) = set_update_tasks(&move |_| enable, Some(enable), false)?;
    Ok(ok)
}

pub fn ps_list(tasks: &[String]) -> String {
    format!(
        "@({})",
        tasks
            .iter()
            .map(|t| format!("'{}'", t.replace('\'', "''")))
            .collect::<Vec<_>>()
            .join(",")
    )
}

pub fn build_task_script(enable: &[String], disable: &[String]) -> String {
    let mut script = String::new();
    let mut line = |s: &str| {
        script.push_str(s);
        script.push_str("\r\n");
    };
    line("$ErrorActionPreference = 'Stop'");
    line("$ProgressPreference = 'SilentlyContinue'");
    line("$script:ok = $true");
    line("function Set-UpdateTask([string]$p, [bool]$on) {");
    line("  $i = $p.LastIndexOf('\\')");
    line("  try {");
    line("    $t = Get-ScheduledTask -TaskPath ([WildcardPattern]::Escape($p.Substring(0, $i + 1))) -TaskName ([WildcardPattern]::Escape($p.Substring($i + 1))) -ErrorAction SilentlyContinue");
    line(
        "    if ($null -eq $t) { Write-Output ('Task not present on this build, skipped: ' + $p) }",
    );
    line("    elseif ($on) { $t | Enable-ScheduledTask -ErrorAction Stop | Out-Null }");
    line("    else { $t | Disable-ScheduledTask -ErrorAction Stop | Out-Null }");
    line("  } catch {");
    line("    if ($_.FullyQualifiedErrorId -match '^HRESULT 0x(80070002|80070003|80070490),') {");
    line("      Write-Output ('Task registered but not usable on this build, skipped: ' + $p + ': ' + $_.Exception.Message)");
    line("    } else { $script:ok = $false; Write-Output ('Task ' + $p + ': ' + $_.Exception.Message) }");
    line("  }");
    line("}");
    line(&format!("$enable = {}", ps_list(enable)));
    line(&format!("$disable = {}", ps_list(disable)));
    line("foreach ($p in $enable) { Set-UpdateTask $p $true }");
    line("foreach ($p in $disable) { Set-UpdateTask $p $false }");
    line("if (-not $script:ok) { exit 1 }");
    script
}

pub fn encode_command(script: &str) -> String {
    let bytes: Vec<u8> = script
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn set_update_tasks(
    enable: &dyn Fn(&str) -> bool,
    uniform: Option<bool>,
    allow_state_retry: bool,
) -> Result<(bool, bool)> {
    let states = match read_update_task_states() {
        Some(s) => s,
        None => return Ok((false, true)),
    };
    let targets: Vec<String> = states
        .keys()
        .into_iter()
        .filter(|t| !enable(t) || !shipped_disabled(t))
        .collect();
    let enable_list: Vec<String> = targets.iter().filter(|t| enable(t)).cloned().collect();
    let disable_list: Vec<String> = targets.iter().filter(|t| !enable(t)).cloned().collect();
    let script = build_task_script(&enable_list, &disable_list);
    let commands_ok = run_ps_as_ti(&script);
    let mut ok = commands_ok;
    let actual = match read_update_task_states() {
        Some(s) => s,
        None => return Ok((false, true)),
    };
    let hard_failure = !commands_ok;
    let mismatch = if allow_state_retry {
        "[OP] Hard disable: update task state changed before final verification: "
    } else {
        "[ERROR] Update task verification failed: "
    };
    for task in &targets {
        let current = match actual.get(task) {
            Some(v) => v,
            None => continue,
        };
        if current != if enable(task) { 1 } else { 0 } {
            log::log(&format!("{mismatch}{task}"));
            ok = false;
        }
    }
    if let Some(uniform_value) = uniform {
        if !update_tasks_match(Some(&actual), uniform_value) {
            for (task, value) in actual.iter() {
                if targets.contains(task)
                    || (uniform_value && shipped_disabled(task))
                    || value == if uniform_value { 1 } else { 0 }
                {
                    continue;
                }
                log::log(&format!(
                    "{mismatch}{task} Enabled={value} Expected={} (task appeared during the operation)",
                    if uniform_value { 1 } else { 0 }
                ));
            }
            ok = false;
        }
    }
    if uniform == Some(true) && ok {
        reg_delete_key(UPDATE_TASK_BACKUP);
    }
    Ok((ok, hard_failure))
}

fn run_ps_as_ti(script: &str) -> bool {
    let encoded = encode_command(script);
    let (exit_code, output) = run_as_ti_output_timeout(
        "powershell.exe",
        &format!("-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}"),
        300000,
    );
    if exit_code != 0 {
        log::log(&format!("[ERROR] Update task operation failed: {output}"));
    }
    exit_code == 0
}

pub fn set_microsoft_update_registration(enable: bool) -> bool {
    let service_id = MU_SERVICE_ID;
    let action = if enable {
        format!(
            "if (-not $existing) {{ $sm.AddService2('{service_id}', 7, '') | Out-Null }} elseif (-not $existing.IsRegisteredWithAU) {{ $sm.RegisterServiceWithAU('{service_id}') }}"
        )
    } else {
        format!("if ($existing) {{ $sm.RemoveService('{service_id}') }}")
    };
    let script = format!(
        "$ErrorActionPreference='Stop';$sm = New-Object -ComObject Microsoft.Update.ServiceManager;$existing = $sm.Services | Where-Object {{ $_.ServiceID -eq '{service_id}' }};{action}"
    );
    let encoded = encode_command(&script);
    let (ok, _) = xos_sys::run_cmd_with_error_timeout(
        "powershell.exe",
        &format!("-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}"),
        60000,
    );
    ok
}

pub fn clean_hard_disable_registry() -> Result<()> {
    if !service_guard::remove_owned() {
        bail!("Windows Update service protection could not be removed; recovery records were retained.");
    }
    let mut sources_ok = true;
    for (key, name) in hard_disable::owned_source_values()? {
        sources_ok &= reg_delete_value(&key, &name);
    }
    if sources_ok
        && hard_disable::owned_source_values()?.is_empty()
        && reg_get_dword(hard_disable::OWNERSHIP_KEY, "Applied") == Some(1)
    {
        reg_delete_value(hard_disable::OWNERSHIP_KEY, "Applied");
    }
    for name in [
        "DisableWindowsUpdateAccess",
        "DoNotConnectToWindowsUpdateInternetLocations",
        "SetDisableUXWUAccess",
    ] {
        reg_delete_value(POL_WU, name);
        reg_delete_value(POL_WU_CU, name);
    }
    for name in ["NoAutoUpdate", "AUOptions", "UseWUServer"] {
        reg_delete_value(POL_WU_AU, name);
        reg_delete_value(POL_WU_AU_CU, name);
    }
    Ok(())
}

pub fn clean_policy_overlay(clear_settings_pause: bool) {
    for (key, name) in legacy::matches(false) {
        reg_delete_value(&key, &name);
    }
    reg_delete_value(POL_WU, "DisableDualScan");
    reg_delete_value(POL_WU, "DeferFeatureUpdates");
    reg_delete_value(POL_WU, "DeferFeatureUpdatesPeriodInDays");
    reg_delete_value(POL_WU, "DeferQualityUpdates");
    reg_delete_value(POL_WU, "DeferQualityUpdatesPeriodInDays");
    reg_delete_value(POL_WU, "PauseFeatureUpdatesStartTime");
    reg_delete_value(POL_WU, "PauseQualityUpdatesStartTime");
    reg_delete_value(POL_WU, "SetAllowOptionalContent");
    reg_delete_value(POL_WU, "AllowOptionalContent");
    reg_delete_value(POL_WU_AU, "NoAUShutdownOption");
    reg_delete_value(POL_WU_AU_CU, "NoAUShutdownOption");
    reg_delete_value(POL_WU_AU, "AlwaysAutoRebootAtScheduledTime");
    reg_delete_value(POL_WU_AU, "AutoInstallMinorUpdates");
    reg_delete_value(POL_WU_AU_CU, "AUOptions");
    reg_delete_value(POL_WU_AU_CU, "NoAutoUpdate");
    if !clear_settings_pause {
        return;
    }
    for name in [
        "BranchReadinessLevel",
        "DeferFeatureUpdates",
        "DeferFeatureUpdatesPeriodInDays",
        "DeferQualityUpdates",
        "DeferQualityUpdatesPeriodInDays",
        "PauseFeatureUpdatesStartTime",
        "PauseFeatureUpdatesEndTime",
        "PauseQualityUpdatesStartTime",
        "PauseQualityUpdatesEndTime",
        "PauseUpdatesStartTime",
        "PauseUpdatesExpiryTime",
        "PausedQualityDate",
        "PausedFeatureDate",
        "FlightSettingsMaxPauseDays",
        "PausedFeatureStatus",
        "PausedQualityStatus",
    ] {
        reg_delete_value(UX_SET, name);
    }
}

pub fn clear_feature_restrictions() {
    for name in [
        "DisableOSUpgrade",
        "TargetReleaseVersion",
        "TargetReleaseVersionInfo",
        "ProductVersion",
        "BranchReadinessLevel",
    ] {
        reg_delete_value(POL_WU, name);
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum HidePlan {
    Refuse,
    AlreadyHidden,
    AlreadyNotVisible,
    Apply { original: String, applied: String },
}

fn starts_with_ci(s: &str, prefix: &str) -> bool {
    s.get(..prefix.len())
        .map_or(false, |p| p.eq_ignore_ascii_case(prefix))
}

pub fn plan_hide_settings_page(current: &str, page: &str) -> HidePlan {
    if !current.is_empty() && !starts_with_ci(current, "hide:") {
        if !starts_with_ci(current, "showonly:") {
            return HidePlan::Refuse;
        }
        let visible = current[9..].split(';').filter(|p| !p.is_empty());
        let mut any = false;
        for p in visible {
            if p.eq_ignore_ascii_case(page) {
                any = true;
            }
        }
        return if any {
            HidePlan::Refuse
        } else {
            HidePlan::AlreadyNotVisible
        };
    }
    let body = if starts_with_ci(current, "hide:") {
        &current[5..]
    } else {
        current
    };
    if body
        .split(';')
        .filter(|p| !p.is_empty())
        .any(|p| p.eq_ignore_ascii_case(page))
    {
        return HidePlan::AlreadyHidden;
    }
    let applied = if current.is_empty() {
        format!("hide:{page}")
    } else {
        format!("{current};{page}")
    };
    HidePlan::Apply {
        original: if current.is_empty() {
            "<XOS:NO_VALUE>".to_string()
        } else {
            current.to_string()
        },
        applied,
    }
}

pub fn add_hidden_settings_page(page: &str) -> bool {
    let current = reg_get_string(POL_EXPL, "SettingsPageVisibility").unwrap_or_default();
    match plan_hide_settings_page(&current, page) {
        HidePlan::Refuse => false,
        HidePlan::AlreadyNotVisible => true,
        HidePlan::AlreadyHidden => true,
        HidePlan::Apply { original, applied } => {
            if !reg_set_string(UPDATE_VISIBILITY_BACKUP, "Original", &original)
                || !reg_set_string(UPDATE_VISIBILITY_BACKUP, "Applied", &applied)
            {
                return false;
            }
            reg_set_string(POL_EXPL, "SettingsPageVisibility", &applied)
        }
    }
}

pub fn remove_hidden_settings_page(_page: &str) {
    let current = reg_get_string(POL_EXPL, "SettingsPageVisibility");
    let original = reg_get_string(UPDATE_VISIBILITY_BACKUP, "Original");
    let applied = reg_get_string(UPDATE_VISIBILITY_BACKUP, "Applied");
    let (original, applied) = match (original, applied) {
        (Some(o), Some(a)) => (o, a),
        _ => return,
    };
    if current
        .as_deref()
        .map_or(false, |c| c.eq_ignore_ascii_case(&applied))
    {
        let restored = if original == "<XOS:NO_VALUE>" {
            reg_delete_value(POL_EXPL, "SettingsPageVisibility")
        } else {
            reg_set_string(POL_EXPL, "SettingsPageVisibility", &original)
        };
        if !restored {
            return;
        }
    }
    reg_delete_key(UPDATE_VISIBILITY_BACKUP);
}

use std::cell::Cell;
use std::collections::HashMap;
use std::io::Write;
use std::sync::{Mutex, OnceLock};
use std::thread::sleep;
use std::time::Duration;

use xos_core::host::{Buttons, Host, Icon};
use xos_core::{app_state, log};
use xos_helpers::{defender_run_entry, service_defaults_table};
use xos_sys::{
    extract_protected_resource, get_service_delayed_auto_start, get_service_start_type,
    get_task_state, get_windows_build_number, is_service_binary_missing, reg_delete_key,
    reg_delete_value, reg_get_dword, reg_get_string, reg_set_dword, reg_set_expand_string,
    reg_set_string, run_as_ti_output, run_cmd_capture_opts, service_exists, strip_clixml_noise,
};

use crate::common::{self, done, encode_command, process_running, TITLE};

const SETTINGS_VISIBILITY_KEY: &str =
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";
const DEFENDER_SERVICE_BACKUP_KEY: &str = r"HKLM\SOFTWARE\XOSToolkit\DefenderServiceBackup";
const POLICY_KEY: &str = r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender";
const RTP_KEY: &str = r"HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection";
const FEATURES_KEY: &str = r"HKLM\SOFTWARE\Microsoft\Windows Defender\Features";
const WD_KEY: &str = r"HKLM\SOFTWARE\Microsoft\Windows Defender";
const RUN_KEY: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";

const DEFENDER_SERVICES: [(&str, i32); 16] = [
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
    ("SgrmBroker", 2),
    ("wtd", 2),
    ("webthreatdefusersvc", 2),
    ("webthreatdefsvc", 3),
];

#[derive(Clone, Debug, Default)]
pub struct DefenderOutcome {
    pub ok: bool,
    pub log_path: Option<String>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DefenderOptions {
    pub show_result: bool,
    pub show_blocking_messages: bool,
    pub defer_reboot_status: bool,
}

pub(crate) struct Hooks<'a> {
    pub overlay: &'a dyn Fn(Option<&str>),
    pub refresh: &'a dyn Fn(),
}

fn start_writes() -> &'static Mutex<HashMap<String, i32>> {
    static M: OnceLock<Mutex<HashMap<String, i32>>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(HashMap::new()))
}

fn record_defender_start_write(name: &str, start: i32) {
    start_writes()
        .lock()
        .unwrap()
        .insert(name.to_lowercase(), start);
}

fn defender_start_write_matches(name: &str) -> bool {
    let expected = start_writes()
        .lock()
        .unwrap()
        .get(&name.to_lowercase())
        .copied()
        .unwrap_or(-1);
    if expected < 0 {
        return true;
    }
    for _ in 0..4 {
        if get_service_start_type(name) == expected {
            return true;
        }
        sleep(Duration::from_millis(500));
    }
    false
}

fn backup_defender_service_starts() -> bool {
    let mut ok = true;
    for (name, _) in DEFENDER_SERVICES {
        if !service_exists(name) || reg_get_dword(DEFENDER_SERVICE_BACKUP_KEY, name).is_some() {
            continue;
        }
        let start = get_service_start_type(name);
        if start >= 0 && start != 4 {
            ok &= reg_set_dword(DEFENDER_SERVICE_BACKUP_KEY, name, start);
        }
    }
    ok
}

fn defender_restore_start(name: &str, default_start: i32) -> i32 {
    let mut start = service_defaults_table::get_start_type(name, get_windows_build_number());
    if !(0..=4).contains(&start) {
        start = default_start;
    }
    if start != 4 && name == "SgrmBroker" && is_service_binary_missing(name) {
        log::log("[Defender] SgrmBroker: its program file is not on this Windows, so it is set to 4 (disabled), as Windows leaves it.");
        start = 4;
    }
    start
}

fn note_defender_start_variance(name: &str, documented: i32) {
    let previous = reg_get_dword(DEFENDER_SERVICE_BACKUP_KEY, name);
    let Some(previous) = previous else {
        return;
    };
    if previous == documented {
        return;
    }
    log::log(&format!(
        "[Defender] {name}: captured start {previous} differs from the documented default {documented}; the documented default was written."
    ));
}

fn split_pages(value: &str) -> Vec<String> {
    value
        .split(';')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

fn starts_with_ci(text: &str, prefix: &str) -> bool {
    text.len() >= prefix.len()
        && text.is_char_boundary(prefix.len())
        && text[..prefix.len()].eq_ignore_ascii_case(prefix)
}

fn add_hidden_settings_page(page: &str) -> bool {
    let current = reg_get_string(SETTINGS_VISIBILITY_KEY, "SettingsPageVisibility");
    let current = match current {
        Some(c) if !c.trim().is_empty() => c,
        _ => {
            return reg_set_string(
                SETTINGS_VISIBILITY_KEY,
                "SettingsPageVisibility",
                &format!("hide:{page}"),
            )
        }
    };

    if starts_with_ci(&current, "showonly:") {
        let visible = split_pages(&current[9..]);
        return !visible.iter().any(|i| i.eq_ignore_ascii_case(page));
    }
    if !starts_with_ci(&current, "hide:") {
        return false;
    }

    let pages = split_pages(&current[5..]);
    if pages.iter().any(|i| i.eq_ignore_ascii_case(page)) {
        return true;
    }
    reg_set_string(
        SETTINGS_VISIBILITY_KEY,
        "SettingsPageVisibility",
        &format!("{};{page}", current.trim_end_matches(';')),
    )
}

fn remove_hidden_settings_page(page: &str) -> bool {
    let current = reg_get_string(SETTINGS_VISIBILITY_KEY, "SettingsPageVisibility");
    let current = match current {
        Some(c) if !c.trim().is_empty() => c,
        _ => return true,
    };

    if starts_with_ci(&current, "showonly:") {
        let visible = split_pages(&current[9..]);
        return visible.iter().any(|i| i.eq_ignore_ascii_case(page));
    }
    if !starts_with_ci(&current, "hide:") {
        return false;
    }

    let pages = split_pages(&current[5..]);
    let remaining: Vec<String> = pages
        .into_iter()
        .filter(|i| !i.eq_ignore_ascii_case(page))
        .collect();
    if remaining.is_empty() {
        reg_delete_value(SETTINGS_VISIBILITY_KEY, "SettingsPageVisibility")
    } else {
        reg_set_string(
            SETTINGS_VISIBILITY_KEY,
            "SettingsPageVisibility",
            &format!("hide:{}", remaining.join(";")),
        )
    }
}

pub fn is_missing_task_result(exit_code: i32, output: &str) -> bool {
    if exit_code == 0 {
        return true;
    }
    if output.is_empty() {
        return false;
    }
    let lower = output.to_lowercase();
    lower.contains("does not exist")
        || lower.contains("cannot find")
        || lower.contains("element not found")
}

struct DefLog {
    path: Option<String>,
}

impl DefLog {
    fn new() -> Self {
        Self { path: None }
    }

    fn init(&mut self, action: &str) {
        let dir = r"C:\ProgramData\XOS Toolkit\Logs";
        let attempt = || -> std::io::Result<String> {
            std::fs::create_dir_all(dir)?;
            Ok(format!(
                r"{dir}\Defender-{action}-{}.log",
                chrono::Local::now().format("%Y-%m-%d_%H-%M-%S")
            ))
        };
        match attempt() {
            Ok(p) => {
                self.path = Some(p);
                self.log(&format!("=== Defender {action} started ==="));
                self.log(&format!("Build: {}", get_windows_build_number()));
            }
            Err(_) => self.path = None,
        }
    }

    fn log(&self, msg: &str) {
        let Some(path) = &self.path else {
            return;
        };
        let line = format!(
            "[{}] {msg}\r\n",
            chrono::Local::now().format("%H:%M:%S%.3f")
        );
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            let _ = f.write_all(line.as_bytes());
        }
    }

    fn run(&self, tag: &str, exe: &str, args: &str) -> bool {
        self.log(&format!("  {tag}"));
        self.log(&format!("    CMD: {exe} {args}"));
        let (code, output) = run_as_ti_output(exe, args);
        let out_line = if output.trim().is_empty() {
            "(no output)".to_string()
        } else {
            output.replace("\r\n", " | ").replace('\n', " | ")
        };
        self.log(&format!("    EXIT: {code}  OUT: {out_line}"));
        code == 0
    }

    fn reg_svc(&self, svc: &str, start: i32) -> bool {
        if !service_exists(svc) {
            self.log(&format!(
                "  Service {svc} is not present on this Windows build; skipped."
            ));
            return true;
        }
        self.run(
            &format!("Service {svc} -> Start={start}"),
            "reg.exe",
            &format!(
                "add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\{svc}\" /v Start /t REG_DWORD /d {start} /f"
            ),
        )
    }

    fn run_task_disable(&self, tag: &str, task_path: &str) -> bool {
        self.log(&format!("  {tag}"));
        let args = format!("/change /tn \"{task_path}\" /disable");
        self.log(&format!("    CMD: schtasks.exe {args}"));
        let (code, output) = run_as_ti_output("schtasks.exe", &args);
        let out_line = if output.trim().is_empty() {
            "(no output)".to_string()
        } else {
            output.replace("\r\n", " | ").replace('\n', " | ")
        };
        self.log(&format!("    EXIT: {code}  OUT: {out_line}"));

        if is_missing_task_result(code, &output) {
            if code != 0 {
                self.log(&format!(
                    "    {tag}: task not present right now (Defender removes and recreates its own tasks), nothing to disable."
                ));
            }
            return true;
        }
        false
    }

    fn verify_disabled_services(&self) -> bool {
        for attempt in 1..=3 {
            let mut verified = true;
            for (name, _) in DEFENDER_SERVICES {
                if service_exists(name) && get_service_start_type(name) != 4 {
                    verified = false;
                    break;
                }
            }

            if verified {
                self.log(&format!(
                    "  Defender service starts verified at Start=4 on attempt {attempt}."
                ));
                return true;
            }

            self.log(&format!(
                "  Defender service start mismatch on attempt {attempt}; reapplying Start=4."
            ));
            let mut reasserted = true;
            for (name, _) in DEFENDER_SERVICES {
                reasserted &= self.reg_svc(name, 4);
            }
            if !reasserted {
                self.log(
                    "  One or more Defender service Start=4 writes failed during reassertion.",
                );
            }
            if attempt < 3 {
                sleep(Duration::from_millis(750));
            }
        }

        self.log("  Defender service starts could not be verified at Start=4.");
        false
    }

    fn snapshot_enable(&self) {
        self.log(&format!(
            "  TamperProtection: {}",
            dword_text(reg_get_dword(FEATURES_KEY, "TamperProtection"))
        ));
        self.log(&format!(
            "  WinDefend Start: {}",
            get_service_start_type("WinDefend")
        ));
        self.log(&format!(
            "  PassiveMode: {}",
            dword_text(reg_get_dword(WD_KEY, "PassiveMode"))
        ));
        self.log(&format!(
            "  DisableRealtimeMonitoring: {}",
            dword_text(reg_get_dword(RTP_KEY, "DisableRealtimeMonitoring"))
        ));
        self.log(&format!(
            "  DisableAntiSpyware (Policy): {}",
            dword_text(reg_get_dword(POLICY_KEY, "DisableAntiSpyware"))
        ));
    }
}

fn dword_text(v: Option<i32>) -> String {
    v.map(|v| v.to_string()).unwrap_or_default()
}

fn reg_add_dword(key: &str, name: &str, value: i32) -> String {
    format!("add \"{key}\" /v {name} /t REG_DWORD /d {value} /f")
}

fn reg_delete_value_args(key: &str, name: &str) -> String {
    format!("delete \"{key}\" /v {name} /f")
}

pub fn check_blocked() -> Option<String> {
    let spy_key = r"HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet";

    let tp = reg_get_dword(FEATURES_KEY, "TamperProtection");
    if tp == Some(5) {
        return Some("Tamper Protection is enabled. Disable it first:\n\nWindows Security - Virus & threat protection - Manage settings - Tamper Protection.".to_string());
    }

    let mut blocked = String::new();

    let rtp_off = reg_get_dword(RTP_KEY, "DisableRealtimeMonitoring");
    if rtp_off != Some(1) {
        blocked.push_str("\n- Real-time Protection");
    }

    let spynet = reg_get_dword(spy_key, "SpynetReporting");
    let maps = reg_get_dword(spy_key, "MAPSReporting");
    if spynet.is_some_and(|v| v > 0) || maps.is_some_and(|v| v > 0) {
        blocked.push_str("\n- Cloud-delivered Protection");
    }

    let samples = reg_get_dword(spy_key, "SubmitSamplesConsent");
    if samples.is_some_and(|v| v != 0) {
        blocked.push_str("\n- Automatic Sample Submission");
    }

    if blocked.is_empty() {
        return None;
    }
    Some(format!(
        "Turn off the following in Windows Security (Virus & threat protection settings) first:{blocked}\n\nOpen Windows Security - Virus & threat protection - Manage settings."
    ))
}

pub fn read_state() -> String {
    let win_defend = get_service_start_type("WinDefend");
    let wd_filter = get_service_start_type("WdFilter");
    let security_health = get_service_start_type("SecurityHealthService");
    let defender_policy = reg_get_dword(POLICY_KEY, "DisableAntiSpyware");
    let defender_realtime = reg_get_dword(RTP_KEY, "DisableRealtimeMonitoring");
    if win_defend < 0 {
        xos_core::status::service("WinDefend")
    } else if win_defend == 4 && (wd_filter < 0 || wd_filter == 4) && defender_policy == Some(1) {
        "Disabled".to_string()
    } else if win_defend != 4
        && (wd_filter < 0 || wd_filter != 4)
        && (security_health < 0 || security_health != 4)
        && defender_policy != Some(1)
        && defender_realtime != Some(1)
    {
        "Enabled".to_string()
    } else {
        "Partial".to_string()
    }
}

struct Busy<'a> {
    on: Cell<bool>,
    hooks: &'a Hooks<'a>,
}

impl Busy<'_> {
    fn set(&self, host: &dyn Host, busy: bool, message: Option<&str>) {
        if busy != self.on.get() {
            self.on.set(busy);
            if busy {
                app_state::begin_operation();
            } else {
                app_state::end_operation();
            }
        }
        (self.hooks.overlay)(if busy {
            Some(message.unwrap_or("Applying..."))
        } else {
            None
        });
        if let Some(m) = message {
            host.set_status(m);
        }
    }
}

fn finish_defender_change(
    host: &dyn Host,
    log: &DefLog,
    enabled: bool,
    additional_success: bool,
    show_result: bool,
    defer_reboot_status: bool,
) -> bool {
    let start = get_service_start_type("WinDefend");
    let policy = reg_get_dword(POLICY_KEY, "DisableAntiSpyware");
    let state_matches = if enabled {
        start >= 0 && start != 4 && policy != Some(1)
    } else {
        start == 4 && policy == Some(1)
    };

    let word = if enabled { "enabled" } else { "disabled" };
    if state_matches && additional_success {
        if show_result {
            done(
                host,
                &format!(
                    "Windows Defender {word}. Please reboot.\n\nLog: {}",
                    log.path.clone().unwrap_or_default()
                ),
                false,
                None,
            );
        } else if !defer_reboot_status {
            host.set_status(&format!("Windows Defender {word}. Please reboot."));
        } else {
            host.set_status(&format!(
                "Windows Defender {word}. Continuing configuration restore..."
            ));
        }
        return true;
    }

    let action = if enabled { "enable" } else { "disable" };
    host.set_status(&format!("Windows Defender {action} incomplete."));
    if show_result {
        xos_sys::ops::reset();
        host.dialog(
            &format!(
                "Windows Defender could not be fully {action}d. Please check the log and try again.\n\nLog: {}",
                log.path.clone().unwrap_or_default()
            ),
            TITLE,
            Buttons::Ok,
            Icon::Warning,
        );
    }
    false
}

pub fn enable(host: &dyn Host) -> DefenderOutcome {
    set_enabled(host, true, DefenderOptions::default())
}

pub fn disable(host: &dyn Host) -> DefenderOutcome {
    set_enabled(host, false, DefenderOptions::default())
}

pub fn set_enabled(host: &dyn Host, enabled: bool, options: DefenderOptions) -> DefenderOutcome {
    let hooks = Hooks {
        overlay: &|_| {},
        refresh: &|| {},
    };
    set_enabled_hooked(host, enabled, options, &hooks)
}

pub(crate) fn set_enabled_hooked(
    host: &dyn Host,
    enabled: bool,
    options: DefenderOptions,
    hooks: &Hooks,
) -> DefenderOutcome {
    let mut def_log = DefLog::new();
    let ok = if enabled {
        enable_defender(host, &mut def_log, options, hooks)
    } else {
        disable_defender(host, &mut def_log, options, hooks)
    };
    DefenderOutcome {
        ok,
        log_path: def_log.path.clone(),
    }
}

const SECURITY_UI_SCRIPT: &str = "$ErrorActionPreference='Continue';$manifests=@();$manifests+=Get-ChildItem \"$env:windir\\SystemApps\\*SecHealthUI*\\AppxManifest.xml\" -File -EA SilentlyContinue;Get-AppxPackage -AllUsers|Where-Object{$_.Name -like '*SecHealthUI*'}|ForEach-Object{$p=Join-Path $_.InstallLocation 'AppxManifest.xml';if(Test-Path $p){$manifests+=Get-Item $p}};if($manifests.Count -eq 0){Write-Error 'No SecHealthUI manifest was found';exit 2};$registered=0;foreach($manifest in ($manifests|Sort-Object FullName -Unique)){try{Add-AppxPackage -Register $manifest.FullName -DisableDevelopmentMode -EA Stop;$registered++}catch{}};$current=@(Get-AppxPackage|Where-Object{$_.Name -like '*SecHealthUI*'});Write-Output ('Registered=' + $registered + ';CurrentUserPackages=' + $current.Count);if($current.Count -eq 0){exit 3}";

const RENAME_SMARTSCREEN_ARGS: &str = r#"-NonInteractive -ExecutionPolicy Bypass -Command "$old = \"$env:SystemRoot\System32\smartscreen.old\"; if (Test-Path $old) { Rename-Item -Path $old -NewName 'smartscreen.exe' -Force -EA 0 }""#;

const PASSIVE_MODE_ARGS: &str = r#"-NonInteractive -ExecutionPolicy Bypass -Command "$p = 'C:\ProgramData\Microsoft\Windows Defender\Platform'; if (Test-Path $p) { Get-ChildItem $p -Directory -EA 0 | Sort-Object Name -Descending | Select-Object -First 1 | ForEach-Object { $off = Join-Path $_.FullName 'OFFmeansOFF.exe'; $on = Join-Path $_.FullName 'MpCmdRun.exe'; Write-Output (\"OFFmeansOFF exists: \" + (Test-Path $off) + \"  MpCmdRun exists: \" + (Test-Path $on)); if ((Test-Path $off) -and !(Test-Path $on)) { Rename-Item -Path $off -NewName 'MpCmdRun.exe' -Force -EA 0; Write-Output 'Renamed OK' } } }; foreach ($k in @('HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender','HKLM:\SOFTWARE\Microsoft\Windows Defender')) { foreach ($v in @('PassiveMode','IsServiceRunning','ServiceKeepAlive','PreviousRunningMode')) { Remove-ItemProperty -Path $k -Name $v -Force -EA 0 } }""#;

const SCM_REASON_ARGS: &str = r#"-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$n=(Get-Service WinDefend -EA 0).DisplayName; $e=Get-WinEvent -FilterHashtable @{LogName='System';Id=7000;StartTime=(Get-Date).AddMinutes(-5)} -EA 0 | Where-Object { $v=[string]$_.Properties[0].Value; $v -eq 'WinDefend' -or ($n -and $v -eq $n) } | Select-Object -First 1; if ($e) { $m=$e.Message; if (-not $m) { $m=($e.Properties | ForEach-Object { $_.Value }) -join ' | ' }; Write-Output ($m -replace '\s+',' ') } else { Write-Output 'no SCM 7000 event for WinDefend in the last 5 minutes' }""#;

const RESTORE_NAME_SCRIPT: &str = r"$ErrorActionPreference='SilentlyContinue';$roots=@($env:ProgramFiles + '\Windows Defender');$plat=Join-Path $env:ProgramData 'Microsoft\Windows Defender\Platform';if(Test-Path $plat){$roots += (Get-ChildItem $plat -Directory | ForEach-Object {$_.FullName})};$fixed=0;foreach($r in $roots){$off=Join-Path $r 'OFFmeansOFF.exe'; $on=Join-Path $r 'MpCmdRun.exe';if((Test-Path $off) -and -not (Test-Path $on)){try{Rename-Item -LiteralPath $off -NewName 'MpCmdRun.exe' -Force -ErrorAction Stop; $fixed++}catch{}}};Write-Output ('restoredMpCmdRun=' + $fixed)";

fn enable_defender(
    host: &dyn Host,
    l: &mut DefLog,
    options: DefenderOptions,
    hooks: &Hooks,
) -> bool {
    xos_sys::ops::reset();
    l.init("Enable");
    l.log("--- Pre-state registry snapshot ---");
    l.snapshot_enable();

    let engine_already_up = process_running("MsMpEng")
        && get_service_start_type("WinDefend") == 2
        && reg_get_dword(RTP_KEY, "DisableRealtimeMonitoring") != Some(1);

    if engine_already_up {
        l.log("--- Already enabled ---");
        l.log("  WinDefend is automatic and the engine is running, so there is nothing to write.");
        l.log("  A running Defender engine protects its own registry keys, so writes here would be refused and none are needed.");
        let (cleared, cleanup_ok) = clear_disable_leftovers(l);
        if options.show_result {
            let msg = match (cleared, cleanup_ok) {
                (_, false) => "Windows Defender is already enabled and its engine is running, but a leftover of an earlier disable could not be removed. See the log.",
                (true, true) => "Windows Defender is already enabled and its engine is running. Leftovers of an earlier disable were removed.",
                (false, true) => "Windows Defender is already enabled and its engine is running. Nothing needed changing.",
            };
            done(host, msg, !cleanup_ok, None);
        }
        return cleanup_ok;
    }

    let busy = Busy {
        on: Cell::new(false),
        hooks,
    };
    busy.set(host, true, Some("Enabling Windows Defender..."));
    let mut required_operations_ok = true;

    l.log("--- Remove boot safety task ---");
    l.run(
        "Delete ONSTART task",
        "schtasks.exe",
        "/delete /tn XOS-DefenderDisable /f",
    );

    l.log("--- Restore service Start values ---");
    let mut services_restored = true;
    for (name, default_start) in DEFENDER_SERVICES {
        let documented = defender_restore_start(name, default_start);
        note_defender_start_variance(name, documented);
        let mut written = l.reg_svc(name, documented);
        if written
            && documented == 2
            && service_exists(name)
            && service_defaults_table::is_delayed_auto_start(name, get_windows_build_number())
        {
            l.run(
                &format!("Service {name} -> DelayedAutostart=1"),
                "reg.exe",
                &format!(
                    "add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\{name}\" /v DelayedAutostart /t REG_DWORD /d 1 /f"
                ),
            );
            let delayed_actual = get_service_delayed_auto_start(name);
            written = delayed_actual == 1;
            l.log(&format!(
                "  {name} DelayedAutostart after write: {delayed_actual} {}",
                if written { "OK" } else { "FAILED" }
            ));
        }
        if written {
            record_defender_start_write(name, documented);
        }
        services_restored &= written;
    }
    required_operations_ok &= services_restored;
    if services_restored {
        reg_delete_key(DEFENDER_SERVICE_BACKUP_KEY);
    }

    l.log("--- Remove policy overrides ---");
    l.run(
        "Delete Policies DisableAntiSpyware",
        "reg.exe",
        &reg_delete_value_args(POLICY_KEY, "DisableAntiSpyware"),
    );
    l.run(
        "Delete Policies DisableAntiVirus",
        "reg.exe",
        &reg_delete_value_args(POLICY_KEY, "DisableAntiVirus"),
    );
    l.run(
        "Delete WD DisableAntiSpyware",
        "reg.exe",
        &reg_delete_value_args(WD_KEY, "DisableAntiSpyware"),
    );
    l.run(
        "Delete WD DisableAntiVirus",
        "reg.exe",
        &reg_delete_value_args(WD_KEY, "DisableAntiVirus"),
    );

    l.log("--- Remove Real-Time Protection disables ---");
    l.run(
        "Delete DisableRealtimeMonitoring",
        "reg.exe",
        &reg_delete_value_args(RTP_KEY, "DisableRealtimeMonitoring"),
    );
    l.run(
        "Delete DisableBehaviorMonitoring",
        "reg.exe",
        &reg_delete_value_args(RTP_KEY, "DisableBehaviorMonitoring"),
    );
    l.run(
        "Delete DisableIOAVProtection",
        "reg.exe",
        &reg_delete_value_args(RTP_KEY, "DisableIOAVProtection"),
    );
    l.run(
        "Delete DisableOnAccessProtection",
        "reg.exe",
        &reg_delete_value_args(RTP_KEY, "DisableOnAccessProtection"),
    );
    l.run(
        "Delete DisableScanOnRealtimeEnable",
        "reg.exe",
        &reg_delete_value_args(RTP_KEY, "DisableScanOnRealtimeEnable"),
    );

    l.log("--- Clear Real-Time Protection policy lock (managed by your organization) ---");
    l.run(
        "Delete policy RTP subkey",
        "reg.exe",
        r#"delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /f"#,
    );
    l.run(
        "Delete policy DisableRealtimeMonitoring",
        "reg.exe",
        &reg_delete_value_args(POLICY_KEY, "DisableRealtimeMonitoring"),
    );
    l.run(
        "Delete PolicyManager AllowRealtimeMonitoring",
        "reg.exe",
        &reg_delete_value_args(
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager",
            "AllowRealtimeMonitoring",
        ),
    );

    l.log("--- Remove IFEO debugger + restore smartscreen.exe ---");
    l.run(
        "Delete smartscreen IFEO",
        "reg.exe",
        &reg_delete_value_args(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\smartscreen.exe",
            "Debugger",
        ),
    );
    l.run(
        "Rename smartscreen.old -> smartscreen.exe",
        "powershell.exe",
        RENAME_SMARTSCREEN_ARGS,
    );

    l.log("--- Restore SecurityHealth startup entry ---");
    let run_set = reg_set_expand_string(
        RUN_KEY,
        "SecurityHealth",
        r"%windir%\system32\SecurityHealthSystray.exe",
    );
    required_operations_ok &= run_set;
    l.log(&format!(
        "  RegSetExpandString SecurityHealth Run: {}",
        bool_text(run_set)
    ));
    let (run_defender_restored, run_defender_restore_detail) =
        defender_run_entry::restore_default();
    required_operations_ok &= run_defender_restored;
    l.log(&format!(
        "  Restore Run WindowsDefender: {} ({run_defender_restore_detail})",
        bool_text(run_defender_restored)
    ));
    required_operations_ok &= l.run(
        "Set StartupApproved SecurityHealth=02",
        "reg.exe",
        r#"add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v SecurityHealth /t REG_BINARY /d 020000000000000000000000 /f"#,
    );

    l.log("--- Restore Windows Security app registration ---");
    l.run(
        "Remove SecHealthUI deprovisioning",
        "reg.exe",
        r#"delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.SecHealthUI_8wekyb3d8bbwe" /f"#,
    );
    l.run(
        "Remove Windows SecHealthUI deprovisioning",
        "reg.exe",
        r#"delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.Windows.SecHealthUI_cw5n1h2txyewy" /f"#,
    );
    let security_ui_encoded = encode_command(SECURITY_UI_SCRIPT);
    let (ui_code, ui_out, ui_err) = run_cmd_capture_opts(
        "powershell.exe",
        &format!(
            "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {security_ui_encoded}"
        ),
        60000,
        false,
    );
    let security_ui_ok = ui_code == 0;
    required_operations_ok &= security_ui_ok;
    let security_ui_output = strip_clixml_noise(&format!("{ui_out} {ui_err}"));
    l.log(&format!(
        "  SecHealthUI {}",
        if security_ui_output.trim().is_empty() {
            "(no output)".to_string()
        } else {
            security_ui_output
        }
    ));

    l.log("--- Re-enable Defender scheduled tasks ---");
    for (tag, name) in [
        (
            "Enable CacheMaintenance",
            "Windows Defender Cache Maintenance",
        ),
        ("Enable Cleanup", "Windows Defender Cleanup"),
        ("Enable ScheduledScan", "Windows Defender Scheduled Scan"),
        ("Enable Verification", "Windows Defender Verification"),
    ] {
        l.run(
            tag,
            "schtasks.exe",
            &format!("/change /tn \"\\Microsoft\\Windows\\Windows Defender\\{name}\" /enable"),
        );
    }

    l.log("--- Restore PassiveMode/IsServiceRunning + rename MpCmdRun ---");
    l.run(
        "PS PassiveMode+MpCmdRun",
        "powershell.exe",
        PASSIVE_MODE_ARGS,
    );

    l.log("--- Re-enable ETW loggers ---");
    l.run(
        "DefenderApiLogger Start=1",
        "reg.exe",
        &reg_add_dword(
            r"HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger",
            "Start",
            1,
        ),
    );
    l.run(
        "DefenderAuditLogger Start=1",
        "reg.exe",
        &reg_add_dword(
            r"HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger",
            "Start",
            1,
        ),
    );

    l.log("--- Remove SettingsPageVisibility ---");
    let sv_del = remove_hidden_settings_page("windowsdefender");
    required_operations_ok &= sv_del;
    l.log(&format!(
        "  Remove windowsdefender from SettingsPageVisibility: {}",
        bool_text(sv_del)
    ));

    l.log("--- Start the engine ---");
    l.run("sc start WinDefend", "sc.exe", "start WinDefend");
    let mut engine_up = false;
    let mut attempt = 0;
    while attempt < 20 && !engine_up {
        engine_up = process_running("MsMpEng");
        if !engine_up {
            sleep(Duration::from_millis(1000));
        }
        attempt += 1;
    }
    l.log(&format!("  MsMpEng running: {}", bool_text(engine_up)));
    if !engine_up {
        l.log("  Defender is set correctly in the registry but the engine is not up yet.");
        l.log("  That is expected until the next restart: the boot-start drivers load at boot,");
        l.log("  and Windows Security reports Getting protection info until the engine answers.");
        l.run("SCM reason", "powershell.exe", SCM_REASON_ARGS);
    }

    l.log("--- Post-state registry snapshot ---");
    l.snapshot_enable();
    l.log("=== Done ===");

    (hooks.refresh)();
    busy.set(host, false, None);
    let defender_start = get_service_start_type("WinDefend");
    required_operations_ok &= defender_start >= 0 && defender_start != 4;
    required_operations_ok &=
        !service_exists("WdFilter") || defender_start_write_matches("WdFilter");
    required_operations_ok &= reg_get_dword(POLICY_KEY, "DisableAntiSpyware") != Some(1);
    required_operations_ok &= reg_get_dword(RTP_KEY, "DisableRealtimeMonitoring") != Some(1);
    finish_defender_change(
        host,
        l,
        true,
        required_operations_ok,
        options.show_result,
        options.defer_reboot_status,
    )
}

fn clear_disable_leftovers(l: &mut DefLog) -> (bool, bool) {
    let mut found = false;
    let mut ok = true;
    if get_task_state(r"\XOS-DefenderDisable") >= 0 {
        found = true;
        l.log("--- Remove boot safety task left by an earlier disable ---");
        l.run(
            "Delete ONSTART task",
            "schtasks.exe",
            "/delete /tn XOS-DefenderDisable /f",
        );
        let gone = get_task_state(r"\XOS-DefenderDisable") < 0;
        l.log(&format!(
            "  XOS-DefenderDisable removed: {}",
            bool_text(gone)
        ));
        ok &= gone;
    }
    for logger in ["DefenderApiLogger", "DefenderAuditLogger"] {
        let key = format!(r"HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\{logger}");
        if reg_get_dword(&key, "Start") == Some(0) {
            found = true;
            l.log(&format!(
                "--- Re-enable {logger} left off by an earlier disable ---"
            ));
            l.run(
                &format!("{logger} Start=1"),
                "reg.exe",
                &reg_add_dword(&key, "Start", 1),
            );
            let on = reg_get_dword(&key, "Start") == Some(1);
            l.log(&format!("  {logger} Start=1: {}", bool_text(on)));
            ok &= on;
        }
    }
    (found, ok)
}

fn bool_text(b: bool) -> &'static str {
    if b {
        "True"
    } else {
        "False"
    }
}

fn disable_defender(
    host: &dyn Host,
    l: &mut DefLog,
    options: DefenderOptions,
    hooks: &Hooks,
) -> bool {
    xos_sys::ops::reset();
    let blocked = check_blocked();
    if let Some(blocked) = blocked {
        if options.show_result || options.show_blocking_messages {
            host.dialog(&blocked, TITLE, Buttons::Ok, Icon::Warning);
        } else {
            log::log(&format!(
                "[Defender] Disable blocked: {}",
                blocked.replace('\n', " ")
            ));
        }
        return false;
    }

    let def_off_script = extract_protected_resource(
        "XOSToolkit.DefenderOFF.ps1",
        &format!("DefenderOFF_{}.ps1", unique_token()),
    );
    let Some(def_off_script) = def_off_script else {
        if options.show_result || options.show_blocking_messages {
            host.dialog(
                "DefenderOFF.ps1 could not be loaded into the protected runtime directory.\n\nPlease reinstall XOS Toolkit.",
                TITLE,
                Buttons::Ok,
                Icon::Error,
            );
        } else {
            log::log("[Defender] DefenderOFF.ps1 could not be loaded into the protected runtime directory.");
        }
        return false;
    };

    l.init("Disable");
    l.log("--- Pre-state registry snapshot ---");
    l.log(&format!(
        "  TamperProtection: {}",
        dword_text(reg_get_dword(FEATURES_KEY, "TamperProtection"))
    ));
    l.log(&format!(
        "  WinDefend Start: {}",
        get_service_start_type("WinDefend")
    ));
    l.log(&format!(
        "  DisableRealtimeMonitoring: {}",
        dword_text(reg_get_dword(RTP_KEY, "DisableRealtimeMonitoring"))
    ));

    let busy = Busy {
        on: Cell::new(false),
        hooks,
    };
    busy.set(host, true, Some("Stopping Defender engine..."));
    let boot_task_ready;
    let mut required_operations_ok = true;

    l.log("--- Restore canonical MpCmdRun.exe name ---");
    let restore_args = format!(
        "-NonInteractive -ExecutionPolicy Bypass -EncodedCommand {}",
        encode_command(RESTORE_NAME_SCRIPT)
    );
    required_operations_ok &= l.run("Restore MpCmdRun.exe", "powershell.exe", &restore_args);

    l.log("--- Clear TamperProtection (before stopping the engine) ---");
    let tamper_cleared = l.run(
        "TamperProtection=0",
        "reg.exe",
        &reg_add_dword(FEATURES_KEY, "TamperProtection", 0),
    );
    l.log(&format!(
        "  TamperProtection after write: {}",
        dword_text(reg_get_dword(FEATURES_KEY, "TamperProtection"))
    ));
    if !tamper_cleared {
        l.log("  The engine refused the TamperProtection write. Continuing: the engine is stopped next, and that is what the disable depends on.");
    }

    l.log("--- Run DefenderOFF.ps1 ---");
    l.log(&format!("  Script: {def_off_script}"));
    required_operations_ok &= l.run(
        "DefenderOFF.ps1",
        "powershell.exe",
        &format!(
            "-NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File \"{def_off_script}\""
        ),
    );
    l.log("  DefenderOFF.ps1 own log: C:\\ProgramData\\AME\\Logs\\DefenderOFF.log");
    let _ = std::fs::remove_file(&def_off_script);

    l.log("--- Wait for MsMpEng ---");
    let mut waited = 0;
    while process_running("MsMpEng") && waited < 30 {
        sleep(Duration::from_millis(1000));
        waited += 1;
    }
    let gone = !process_running("MsMpEng");
    required_operations_ok &= gone;
    l.log(&format!(
        "  MsMpEng gone: {}  (waited {waited}s extra)",
        bool_text(gone)
    ));

    l.log("--- Services Start=4 ---");
    required_operations_ok &= backup_defender_service_starts();
    for (name, _) in DEFENDER_SERVICES {
        required_operations_ok &= l.reg_svc(name, 4);
    }

    l.log("--- Verify WinDefend Start after write ---");
    l.log(&format!(
        "  WinDefend Start: {}",
        get_service_start_type("WinDefend")
    ));

    l.log("--- Policy overrides ---");
    required_operations_ok &= l.run(
        "Policies DisableAntiSpyware=1",
        "reg.exe",
        &reg_add_dword(POLICY_KEY, "DisableAntiSpyware", 1),
    );
    required_operations_ok &= l.run(
        "Policies DisableAntiVirus=1",
        "reg.exe",
        &reg_add_dword(POLICY_KEY, "DisableAntiVirus", 1),
    );
    required_operations_ok &= l.run(
        "WD DisableAntiSpyware=1",
        "reg.exe",
        &reg_add_dword(WD_KEY, "DisableAntiSpyware", 1),
    );
    required_operations_ok &= l.run(
        "WD DisableAntiVirus=1",
        "reg.exe",
        &reg_add_dword(WD_KEY, "DisableAntiVirus", 1),
    );

    l.log("--- Verify policy after write ---");
    l.log(&format!(
        "  Policies DisableAntiSpyware: {}",
        dword_text(reg_get_dword(POLICY_KEY, "DisableAntiSpyware"))
    ));
    l.log(&format!(
        "  WD DisableAntiSpyware: {}",
        dword_text(reg_get_dword(WD_KEY, "DisableAntiSpyware"))
    ));

    l.log("--- Real-Time Protection disables ---");
    for (tag, name) in [
        ("DisableBehaviorMonitoring=1", "DisableBehaviorMonitoring"),
        ("DisableIOAVProtection=1", "DisableIOAVProtection"),
        ("DisableOnAccessProtection=1", "DisableOnAccessProtection"),
        (
            "DisableScanOnRealtimeEnable=1",
            "DisableScanOnRealtimeEnable",
        ),
    ] {
        required_operations_ok &= l.run(tag, "reg.exe", &reg_add_dword(RTP_KEY, name, 1));
    }

    l.log("--- IFEO + SecurityHealth startup ---");
    l.run(
        "Set smartscreen IFEO Debugger",
        "reg.exe",
        r#"add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\smartscreen.exe" /v Debugger /t REG_SZ /d "%SYSTEMROOT%\System32\taskkill.exe" /f"#,
    );
    let run_del = reg_delete_value(RUN_KEY, "SecurityHealth");
    l.log(&format!(
        "  Delete Run SecurityHealth: {}",
        bool_text(run_del)
    ));
    required_operations_ok &= run_del;
    let (run_defender_backed_up, run_defender_backup_detail) = defender_run_entry::backup_default();
    l.log(&format!(
        "  Back up Run WindowsDefender: {} ({run_defender_backup_detail})",
        bool_text(run_defender_backed_up)
    ));
    let run_defender_del = run_defender_backed_up && reg_delete_value(RUN_KEY, "WindowsDefender");
    l.log(&format!(
        "  Delete Run WindowsDefender: {}",
        bool_text(run_defender_del)
    ));
    required_operations_ok &= run_defender_del;
    l.run(
        "Set StartupApproved SecurityHealth=03",
        "reg.exe",
        r#"add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v SecurityHealth /t REG_BINARY /d 030000000000000000000000 /f"#,
    );

    l.log("--- Disable Defender scheduled tasks ---");
    for (tag, name) in [
        (
            "Disable CacheMaintenance",
            "Windows Defender Cache Maintenance",
        ),
        ("Disable Cleanup", "Windows Defender Cleanup"),
        ("Disable ScheduledScan", "Windows Defender Scheduled Scan"),
        ("Disable Verification", "Windows Defender Verification"),
    ] {
        required_operations_ok &= l.run_task_disable(
            tag,
            &format!("\\Microsoft\\Windows\\Windows Defender\\{name}"),
        );
    }

    l.log("--- Write and register boot safety task ---");
    let dd_script_path = format!(r"{}\XOS-DD.ps1", common::system_root());
    let mut boot_script = String::new();
    for service in ["MDCoreSvc", "WinDefend", "WdNisSvc"] {
        if service_exists(service) {
            boot_script.push_str(&format!("sc.exe stop {service};"));
        }
    }
    boot_script.push_str("Start-Sleep -Seconds 5;");
    for service in [
        "WinDefend",
        "WdNisSvc",
        "MDCoreSvc",
        "WdNisDrv",
        "WdBoot",
        "WdFilter",
    ] {
        if service_exists(service) {
            boot_script.push_str(&format!(
                "reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\{service} /v Start /t REG_DWORD /d 4 /f;"
            ));
        }
    }
    match std::fs::write(&dd_script_path, &boot_script) {
        Ok(()) => {
            l.log("  XOS-DD.ps1 written OK");
            boot_task_ready = l.run(
                "Create ONSTART task",
                "schtasks.exe",
                &format!(
                    "/create /ru SYSTEM /rl HIGHEST /sc ONSTART /tn XOS-DefenderDisable /tr \"powershell.exe -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File {dd_script_path}\" /f"
                ),
            );
        }
        Err(ex) => {
            l.log(&format!("  XOS-DD.ps1 write FAILED: {ex}"));
            boot_task_ready = false;
            l.log("  Skipped task creation: XOS-DD.ps1 missing.");
            if options.show_result || options.show_blocking_messages {
                host.dialog(
                    &format!(
                        "Could not write {dd_script_path}. The boot-time fallback that re-disables Defender services on every restart has NOT been registered.\n\nDefender services are still set to Disabled in the registry, but if Windows Update re-enables them, there's nothing scheduled to disable them again."
                    ),
                    TITLE,
                    Buttons::Ok,
                    Icon::Warning,
                );
            }
        }
    }

    l.log("--- ETW loggers ---");
    l.run(
        "DefenderApiLogger Start=0",
        "reg.exe",
        &reg_add_dword(
            r"HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger",
            "Start",
            0,
        ),
    );
    l.run(
        "DefenderAuditLogger Start=0",
        "reg.exe",
        &reg_add_dword(
            r"HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger",
            "Start",
            0,
        ),
    );

    l.log("--- SettingsPageVisibility ---");
    let sv_set = add_hidden_settings_page("windowsdefender");
    required_operations_ok &= sv_set;
    l.log(&format!(
        "  Add windowsdefender to SettingsPageVisibility: {}",
        bool_text(sv_set)
    ));

    l.log("--- Verify Defender service starts after all writes ---");
    required_operations_ok &= l.verify_disabled_services();

    l.log("--- Post-state registry snapshot ---");
    l.log(&format!(
        "  TamperProtection: {}",
        dword_text(reg_get_dword(FEATURES_KEY, "TamperProtection"))
    ));
    l.log(&format!(
        "  WinDefend Start: {}",
        get_service_start_type("WinDefend")
    ));
    l.log(&format!(
        "  Policies DisableAntiSpyware: {}",
        dword_text(reg_get_dword(POLICY_KEY, "DisableAntiSpyware"))
    ));
    l.log(&format!(
        "  WD DisableAntiSpyware: {}",
        dword_text(reg_get_dword(WD_KEY, "DisableAntiSpyware"))
    ));
    l.log("=== Done ===");

    (hooks.refresh)();
    busy.set(host, false, None);
    required_operations_ok &= get_service_start_type("WinDefend") == 4;
    required_operations_ok &=
        !service_exists("WdFilter") || get_service_start_type("WdFilter") == 4;
    required_operations_ok &= reg_get_dword(POLICY_KEY, "DisableAntiSpyware") == Some(1);
    finish_defender_change(
        host,
        l,
        false,
        boot_task_ready && required_operations_ok,
        options.show_result,
        options.defer_reboot_status,
    )
}

fn unique_token() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{:016x}{:016x}", nanos as u64, std::process::id())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_task_results() {
        assert!(is_missing_task_result(0, ""));
        assert!(!is_missing_task_result(1, ""));
        assert!(is_missing_task_result(
            1,
            "ERROR: The system cannot find the file specified."
        ));
        assert!(is_missing_task_result(
            1,
            "The specified task name does not exist in the system"
        ));
        assert!(is_missing_task_result(1, "Element not found."));
        assert!(!is_missing_task_result(5, "Access is denied."));
    }

    #[test]
    fn unique_token_is_32_hex() {
        let t = unique_token();
        assert_eq!(t.len(), 32);
        assert!(t.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn registry_arguments() {
        assert_eq!(
            reg_delete_value_args(POLICY_KEY, "DisableAntiSpyware"),
            r#"delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /f"#
        );
        assert_eq!(
            reg_add_dword(FEATURES_KEY, "TamperProtection", 0),
            r#"add "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v TamperProtection /t REG_DWORD /d 0 /f"#
        );
    }

    #[test]
    fn prefix_helper() {
        assert!(starts_with_ci("HIDE:a;b", "hide:"));
        assert!(!starts_with_ci("hid", "hide:"));
        assert_eq!(split_pages("a;;b;"), vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn readers_do_not_panic() {
        let _ = read_state();
        let _ = check_blocked();
    }
}

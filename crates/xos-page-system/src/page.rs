use std::collections::HashMap;
use std::sync::Mutex;
use std::thread::sleep;
use std::time::Duration;

use windows::Win32::Storage::FileSystem::GetLogicalDrives;
use xos_core::host::{Buttons, DialogResult, Host, Icon, Page};
use xos_core::status;
use xos_core::ui::*;
use xos_core::{app_state, log};
use xos_helpers::card_state_helper::{write_usb_power_registry, USB_POWER_REGISTRY};
use xos_helpers::{network_reset, service_defaults_table};
use xos_sys::*;

use crate::common::{
    distinct_ci, done, kill_processes_named, stock_split_disabled, system_dir, system_root, TITLE,
};
use crate::defender::{self, DefenderOptions, Hooks};
use crate::security::*;

const POL_APP_PRIV: &str = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy";
const CU_BG_APPS: &str =
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications";
const TOAST_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications";
const UAC_POL: &str = r"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System";
const HIBER_KEY: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\Power";
const HIBER_POL: &str = r"HKLM\Software\Policies\Microsoft\Windows\System";
const SLEEP_POWER: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power";
const TERM_SRV_KEY: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server";
const SVC_HOST_CONTROL_READ: &str = r"HKLM\SYSTEM\CurrentControlSet\Control";
const SVC_BASE_PATH: &str = r"HKLM\SYSTEM\CurrentControlSet\Services\";
const MOUSE_KEY: &str = r"HKCU\Control Panel\Mouse";
const MEM_MGMT: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management";
const PS_POLICY_KEY: &str = r"HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell";

const PLAYBOOK_CORE_SPLIT: [&str; 5] = ["BFE", "DcomLaunch", "mpssvc", "PlugPlay", "Power"];

const RECOMMENDED_SPLIT_DISABLED: [&str; 22] = [
    "DisplayEnhancementService",
    "PcaSvc",
    "WdiSystemHost",
    "AudioEndpointBuilder",
    "Appinfo",
    "BITS",
    "gpsvc",
    "SENS",
    "ShellHWDetection",
    "TrkWks",
    "Winmgmt",
    "EventLog",
    "FontCache",
    "Schedule",
    "SessionEnv",
    "Themes",
    "W32Time",
    "SamSs",
    "EventSystem",
    "CryptSvc",
    "Dhcp",
    "Dnscache",
];

const SUB_USB: &str = "2a737441-1930-4402-8d77-b2bebba308a3";
const SET_USBLINK: &str = "48e6b7a6-50f5-4782-a5d4-53bb8f07e226";
const SUB_PCIE: &str = "501a4d13-42af-4429-9fd1-a8218c268e20";
const SET_ASPM: &str = "ee12f906-d277-404b-b6da-e5fa1a576df5";
const SUB_DISK: &str = "0012ee47-9041-4b5d-9b77-535fba8b1442";
const SET_DISKIDLE: &str = "6738e2c4-e8a5-4a42-b16a-e040e769756e";
const SET_AHCILINK: &str = "0b2d69d7-a2a1-449c-9680-f91c70521c60";
const AHCILINK_ATTRS: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\0012ee47-9041-4b5d-9b77-535fba8b1442\0b2d69d7-a2a1-449c-9680-f91c70521c60";

const HYPER_V_SERVICE_BACKUP_KEY: &str = r"HKLM\SOFTWARE\XOSToolkit\HyperVServiceBackup";
const HYPER_V_SERVICES: [(&str, i32); 9] = [
    ("bttflt", 0),
    ("gencounter", 3),
    ("hyperkbd", 3),
    ("hypervideo", 3),
    ("spaceparser", 3),
    ("storflt", 0),
    ("vmgid", 3),
    ("vpci", 0),
    ("vid", 1),
];

const RDP_SERVICES: [&str; 3] = ["TermService", "UmRdpService", "SessionEnv"];
const RDP_FIREWALL_RULES: [&str; 3] = [
    "RemoteDesktop-UserMode-In-TCP",
    "RemoteDesktop-UserMode-In-UDP",
    "RemoteDesktop-Shadow-In-TCP",
];
const RDP_HOME_MESSAGE: &str = "Remote Desktop hosting is not available on Windows Home. This PC can connect to other PCs with Remote Desktop, but Windows Home cannot accept Remote Desktop connections, so there is nothing to turn on or off here.";

const SEARCH_IFEO_KEYS: [&str; 3] = [
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SearchApp.exe",
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SearchUI.exe",
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SearchHost.exe",
];

const BG_MSG_TAGS: [i32; 2] = [20, 8];
const BG_MSG_OPTIONS: [&str; 2] = ["50 Hz (Low)", "125 Hz (Default)"];

const CARD_IDS: [&str; 18] = [
    "uac",
    "defender",
    "bgapps",
    "notif",
    "power",
    "xosplan",
    "hibernate",
    "gpumon",
    "usagerep",
    "vbs",
    "hvci",
    "spectre",
    "hyperv",
    "rdp",
    "wsearch",
    "svcsplit",
    "pspolicy",
    "bgmsgrate",
];

struct State {
    badges: HashMap<&'static str, (String, Option<String>)>,
    bg_msg_visible: bool,
    bg_msg_selected: i32,
    hvci_enable_enabled: bool,
    hvci_note_visible: bool,
    overlay: Option<String>,
}

pub struct SystemPage {
    st: Mutex<State>,
}

impl Default for SystemPage {
    fn default() -> Self {
        Self::new()
    }
}

fn get_power_saving_state() -> String {
    let schemes = r"HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes";
    let active = reg_get_string(schemes, "ActivePowerScheme");
    let Some(active) = active.filter(|a| !a.is_empty()) else {
        return "N/A".to_string();
    };
    let values: Vec<Option<i32>> = USB_POWER_REGISTRY
        .iter()
        .map(|(key, name, _)| reg_get_dword(key, name))
        .collect();
    let settings: [(&str, &str, i32, i32); 4] = [
        (SUB_USB, SET_USBLINK, 1, 1),
        (SUB_PCIE, SET_ASPM, 1, 2),
        (SUB_DISK, SET_DISKIDLE, 1200, 600),
        (SUB_DISK, SET_AHCILINK, 2, 3),
    ];
    let mut disabled = USB_POWER_REGISTRY
        .iter()
        .enumerate()
        .all(|(i, (_, _, d))| values[i] == Some(*d));
    for (sub, setting, _, _) in settings {
        let path = format!(r"{schemes}\{active}\{sub}\{setting}");
        let ac = reg_get_dword(&path, "ACSettingIndex");
        let dc = reg_get_dword(&path, "DCSettingIndex");
        disabled &= ac == Some(0) && dc == Some(0);
    }
    disabled &= reg_get_dword(AHCILINK_ATTRS, "Attributes") == Some(2);
    if disabled {
        return "Disabled".to_string();
    }

    let any_registry_override = values.iter().any(|v| v.is_some());
    let mut enabled = !any_registry_override;
    for (sub, setting, ac_v, dc_v) in settings {
        let path = format!(r"{schemes}\{active}\{sub}\{setting}");
        let ac = reg_get_dword(&path, "ACSettingIndex");
        let dc = reg_get_dword(&path, "DCSettingIndex");
        enabled &= ac == Some(ac_v) && dc == Some(dc_v);
    }
    if enabled {
        return "Enabled".to_string();
    }

    let mut any = any_registry_override;
    for (sub, setting, _, _) in settings {
        let path = format!(r"{schemes}\{active}\{sub}\{setting}");
        any |= reg_get_dword(&path, "ACSettingIndex").is_some();
        any |= reg_get_dword(&path, "DCSettingIndex").is_some();
    }
    if any {
        "Partial".to_string()
    } else {
        "N/A".to_string()
    }
}

fn is_hyper_v_feature_disabled(state: &str) -> bool {
    if state.trim().is_empty() {
        return false;
    }
    let normalized = state.replace([' ', '_'], "");
    [
        "Disabled",
        "DisablePending",
        "DisabledWithPayloadRemoved",
        "NotPresent",
    ]
    .iter()
    .any(|s| normalized.eq_ignore_ascii_case(s))
}

fn get_hyper_v_state(features: &CiMap<String>) -> String {
    let mut total = 0;
    let mut enabled = 0;
    let mut disabled = 0;
    let mut unknown = 0;

    for feature in xos_core::catalog::HYPER_V_FEATURES {
        let Some(state) = features.get(feature) else {
            continue;
        };
        total += 1;
        if is_feature_state_enabled(state) {
            enabled += 1;
        } else if is_hyper_v_feature_disabled(state) {
            disabled += 1;
        } else {
            unknown += 1;
        }
    }

    for (name, _) in HYPER_V_SERVICES {
        if !service_exists(name) {
            continue;
        }
        total += 1;
        let start = get_service_start_type(name);
        if start == 4 {
            disabled += 1;
        } else if (0..=3).contains(&start) {
            enabled += 1;
        } else {
            unknown += 1;
        }
    }

    if total == 0 {
        return "N/A".to_string();
    }
    if unknown > 0 {
        return "Partial".to_string();
    }
    if enabled == total {
        return "Enabled".to_string();
    }
    if disabled == total {
        return "Disabled".to_string();
    }
    "Partial".to_string()
}

fn hyper_v_default_start(name: &str, default_start: i32) -> i32 {
    let start = service_defaults_table::get_start_type(name, get_windows_build_number());
    if (0..=3).contains(&start) {
        start
    } else {
        default_start
    }
}

fn hyper_v_restore_start(name: &str, default_start: i32) -> i32 {
    reg_get_dword(HYPER_V_SERVICE_BACKUP_KEY, name)
        .unwrap_or_else(|| hyper_v_default_start(name, default_start))
}

fn backup_hyper_v_service_starts() -> bool {
    let mut ok = true;
    for (name, _) in HYPER_V_SERVICES {
        if !service_exists(name) || reg_get_dword(HYPER_V_SERVICE_BACKUP_KEY, name).is_some() {
            continue;
        }
        let start = get_service_start_type(name);
        if start < 0 {
            ok = false;
        } else if start != 4 {
            ok &= reg_set_dword(HYPER_V_SERVICE_BACKUP_KEY, name, start);
        }
    }
    ok
}

fn hyper_v_enable_work() -> Result<(), String> {
    let failures: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let device_failures: Mutex<Vec<String>> = Mutex::new(Vec::new());
    std::thread::scope(|scope| {
        let services_task = scope.spawn(|| {
            std::thread::scope(|inner| {
                for (name, default_start) in HYPER_V_SERVICES {
                    let failures = &failures;
                    inner.spawn(move || {
                        if !config_service_reg_if_present(
                            name,
                            hyper_v_restore_start(name, default_start),
                        ) {
                            failures.lock().unwrap().push(format!("service {name}"));
                        }
                    });
                }
                for d in xos_core::catalog::HYPER_V_DEVICES {
                    let device_failures = &device_failures;
                    inner.spawn(move || {
                        let device_key = format!(r"HKLM\SYSTEM\CurrentControlSet\Enum\{d}");
                        if reg_key_exists(&device_key) && !enable_device(d, true) {
                            device_failures.lock().unwrap().push(d.to_string());
                        }
                    });
                }
            });
        });

        let states = get_all_feature_states();
        if states.is_empty() {
            failures
                .lock()
                .unwrap()
                .push("the optional feature list could not be read".to_string());
        }
        for feature in xos_core::catalog::HYPER_V_FEATURES {
            let Some(st) = states.get(feature) else {
                continue;
            };
            if !is_feature_state_enabled(st) && !enable_feature(feature) {
                failures.lock().unwrap().push(format!("feature {feature}"));
            }
        }

        let _ = services_task.join();
    });

    let device_failures = device_failures.into_inner().unwrap();
    let mut failures = failures.into_inner().unwrap();
    if !device_failures.is_empty() {
        log::log(&format!(
            "[HyperV] devices that did not start on command: {}. These are expected to start after the restart.",
            device_failures.join(", ")
        ));
    }
    if failures.is_empty() && !reg_delete_key(HYPER_V_SERVICE_BACKUP_KEY) {
        failures.push("the previous service start values could not be cleared".to_string());
    }

    if !failures.is_empty() {
        let detail = failures.join(", ");
        log::log(&format!("[HyperV] enable reported failures: {detail}"));
        return Err(format!(
            "These Hyper-V components were not applied:\n{detail}\n\nEverything else was enabled. A reboot is required before Windows reports the new state, so check this page again afterwards."
        ));
    }
    Ok(())
}

fn hyper_v_disable_work() -> Result<(), String> {
    if !backup_hyper_v_service_starts() {
        return Err(
            "The current Hyper-V service configuration could not be backed up.".to_string(),
        );
    }

    let operation_failed = std::sync::atomic::AtomicBool::new(false);
    std::thread::scope(|scope| {
        let services_task = scope.spawn(|| {
            std::thread::scope(|inner| {
                for (name, _) in HYPER_V_SERVICES {
                    let operation_failed = &operation_failed;
                    inner.spawn(move || {
                        if service_exists(name) && !config_service_reg(name, 4) {
                            operation_failed.store(true, std::sync::atomic::Ordering::SeqCst);
                        }
                    });
                }
                for d in xos_core::catalog::HYPER_V_DEVICES {
                    let operation_failed = &operation_failed;
                    inner.spawn(move || {
                        let device_key = format!(r"HKLM\SYSTEM\CurrentControlSet\Enum\{d}");
                        if reg_key_exists(&device_key) && !disable_device(d, true) {
                            operation_failed.store(true, std::sync::atomic::Ordering::SeqCst);
                        }
                    });
                }
            });
        });

        let states = get_all_feature_states();
        if states.is_empty() {
            operation_failed.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        for feature in xos_core::catalog::HYPER_V_FEATURES {
            let Some(st) = states.get(feature) else {
                continue;
            };
            if is_feature_state_enabled(st) && !disable_feature(feature) {
                operation_failed.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }

        let _ = services_task.join();
    });

    if operation_failed.load(std::sync::atomic::Ordering::SeqCst) {
        return Err("One or more Hyper-V components could not be disabled.".to_string());
    }
    Ok(())
}

fn set_firewall_rule_enabled(rule_name: &str, enabled: bool) -> bool {
    let command = format!(
        "$ProgressPreference='SilentlyContinue'; try {{ Get-NetFirewallRule -Name '{rule_name}' -ErrorAction Stop | Set-NetFirewallRule -Enabled {} -ErrorAction Stop }} catch {{ Write-Output $_.Exception.Message; exit 1 }}",
        if enabled { "True" } else { "False" }
    );
    let encoded = crate::common::encode_command(&command);
    let (ok, error) = run_cmd_with_error(
        "powershell.exe",
        &format!("-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}"),
    );
    if !ok {
        log::log(&format!(
            "[RDP] Firewall rule {rule_name} could not be {}: {}",
            if enabled { "enabled" } else { "disabled" },
            error.unwrap_or_default()
        ));
    }
    ok
}

fn apply_vbs_disable_registry() -> bool {
    let cg_scenario =
        r"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard";
    let lsa = r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa";

    reg_set_dword(DEV_GUARD_POL, "EnableVirtualizationBasedSecurity", 0);
    reg_set_dword(DEV_GUARD_POL, "RequirePlatformSecurityFeatures", 0);
    reg_set_dword(DEV_GUARD_POL, "HypervisorEnforcedCodeIntegrity", 0);
    reg_set_dword(DEV_GUARD_POL, "LsaCfgFlags", 0);
    reg_set_dword(DEV_GUARD_POL, "ConfigureSystemGuardLaunch", 0);

    reg_set_dword(DEV_GUARD_DIRECT, "EnableVirtualizationBasedSecurity", 0);
    reg_set_dword(DEV_GUARD_DIRECT, "RequirePlatformSecurityFeatures", 0);
    reg_set_dword(DEV_GUARD_DIRECT, "Mandatory", 0);
    reg_set_dword(DEV_GUARD_DIRECT, "Locked", 0);

    reg_set_dword(HVCI_SCENARIO, "Enabled", 0);
    reg_set_dword(HVCI_SCENARIO, "Locked", 0);
    reg_delete_value(HVCI_SCENARIO, "WasEnabledBy");
    reg_delete_value(HVCI_SCENARIO, "ChangedInBootCycle");

    reg_set_dword(cg_scenario, "Enabled", 0);
    reg_set_dword(cg_scenario, "Locked", 0);
    reg_delete_value(cg_scenario, "WasEnabledBy");
    reg_delete_value(cg_scenario, "ChangedInBootCycle");

    reg_set_dword(SG_SCENARIO, "Enabled", 0);
    reg_set_dword(SG_SCENARIO, "Locked", 0);

    reg_set_dword(lsa, "LsaCfgFlags", 0);

    let mut boot_config_ok = bcd_edit("hypervisorlaunchtype", "off");
    boot_config_ok &= bcd_edit("vsmlaunchtype", "off");
    boot_config_ok
}

fn disable_vbs_complete() -> &'static str {
    if !apply_vbs_disable_registry() {
        return "failed";
    }
    let vbs = get_vbs_running_status();
    if vbs == 2 && !any_vbs_service_configured() {
        return "locked";
    }
    if vbs == 0 {
        "off"
    } else {
        "pending"
    }
}

fn stage_uefi_lock_clear() -> (bool, String) {
    let sec_config = format!(r"{}\SecConfig.efi", system_dir());
    if !std::path::Path::new(&sec_config).exists() {
        return (
            false,
            "SecConfig.efi not found. This Windows edition can't self-clear the lock; use Microsoft's DG_Readiness tool.".to_string(),
        );
    }

    let used = unsafe { GetLogicalDrives() };
    let mut letter = '\0';
    for c in ('D'..='Z').rev() {
        let bit = c as u32 - 'A' as u32;
        if used & (1 << bit) == 0 {
            letter = c;
            break;
        }
    }
    if letter == '\0' {
        return (
            false,
            "No free drive letter to mount the EFI partition.".to_string(),
        );
    }

    let drv = format!("{letter}:");
    if !run_cmd("mountvol.exe", &format!("{drv} /s")) {
        return (
            false,
            "Failed to mount the EFI System Partition.".to_string(),
        );
    }

    let result = (|| -> (bool, String) {
        let dest_dir = format!(r"{drv}\EFI\Microsoft\Boot");
        let _ = std::fs::create_dir_all(&dest_dir);
        if let Err(ex) = std::fs::copy(&sec_config, format!(r"{dest_dir}\SecConfig.efi")) {
            return (false, format!("Failed staging the unlock entry: {ex}"));
        }

        let guid = "{0cb3b571-2f2e-4343-a879-d86a476d7215}";
        run_cmd(
            "bcdedit.exe",
            &format!("/create {guid} /d \"DebugTool\" /application osloader"),
        );
        let mut bcd_ok = run_cmd(
            "bcdedit.exe",
            &format!("/set {guid} path \"\\EFI\\Microsoft\\Boot\\SecConfig.efi\""),
        );
        bcd_ok &= run_cmd(
            "bcdedit.exe",
            &format!("/set {{bootmgr}} bootsequence {guid}"),
        );
        bcd_ok &= run_cmd(
            "bcdedit.exe",
            &format!("/set {guid} loadoptions \"DISABLE-LSA-ISO,DISABLE-VBS\""),
        );
        bcd_ok &= run_cmd(
            "bcdedit.exe",
            &format!("/set {guid} device partition={drv}"),
        );
        if !bcd_ok {
            return (
                false,
                "Failed to configure the one-time firmware unlock boot entry.".to_string(),
            );
        }
        (true, String::new())
    })();

    run_cmd("mountvol.exe", &format!("{drv} /d"));

    if !result.0 {
        return result;
    }
    (
        true,
        "Unlock staged. Please reboot and accept the firmware confirmation prompt to finish disabling VBS/HVCI.".to_string(),
    )
}

fn power_cfg_defaults() -> bool {
    let mut ok = true;
    ok &= power_cfg_set(SUB_USB, SET_USBLINK, 1, 1);
    ok &= power_cfg_set(SUB_PCIE, SET_ASPM, 1, 2);
    ok &= power_cfg_set(SUB_DISK, SET_DISKIDLE, 1200, 600);
    ok &= power_cfg_set(SUB_DISK, SET_AHCILINK, 2, 3);
    ok
}

fn ask_yes_no(host: &dyn Host, message: &str, title: &str, icon: Icon) -> bool {
    host.dialog(message, title, Buttons::YesNo, icon) == DialogResult::Yes
}

fn warn_ok(host: &dyn Host, message: &str) {
    host.dialog(message, TITLE, Buttons::Ok, Icon::Warning);
}

impl SystemPage {
    pub fn new() -> Self {
        let mut badges = HashMap::new();
        for id in CARD_IDS {
            badges.insert(id, ("Checking".to_string(), None));
        }
        Self {
            st: Mutex::new(State {
                badges,
                bg_msg_visible: get_windows_build_number() >= 22621,
                bg_msg_selected: -1,
                hvci_enable_enabled: true,
                hvci_note_visible: false,
                overlay: None,
            }),
        }
    }

    fn set_badge(&self, id: &'static str, state: &str, detail: Option<&str>) {
        self.st
            .lock()
            .unwrap()
            .badges
            .insert(id, (state.to_string(), detail.map(|d| d.to_string())));
    }

    fn set_overlay(&self, host: &dyn Host, text: Option<&str>) {
        self.st.lock().unwrap().overlay = text.map(|t| t.to_string());
        host.publish(self.model());
    }

    pub fn refresh_states(&self, host: &dyn Host) {
        self.refresh_core();
        host.publish(self.model());
        self.refresh_hyper_v();
    }

    fn refresh_hyper_v(&self) {
        let features = get_all_feature_states();
        self.set_badge("hyperv", &get_hyper_v_state(&features), None);
    }

    fn refresh_core(&self) {
        let bg_visible = self.st.lock().unwrap().bg_msg_visible;
        if bg_visible {
            let throttle_enabled = reg_get_dword(MOUSE_KEY, "RawMouseThrottleEnabled");
            let throttle_duration = reg_get_dword(MOUSE_KEY, "RawMouseThrottleDuration");
            if throttle_enabled == Some(1) && throttle_duration.is_some_and(|d| d > 0) {
                let d = throttle_duration.unwrap();
                let hz = (1000.0 / d as f64).round_ties_even() as i32;
                self.set_badge(
                    "bgmsgrate",
                    &format!("{hz} Hz"),
                    Some(&format!("Background message rate is limited to {hz} Hz.")),
                );
                if let Some(i) = BG_MSG_TAGS.iter().position(|t| *t == d) {
                    self.st.lock().unwrap().bg_msg_selected = i as i32;
                }
            } else if throttle_enabled == Some(0) {
                self.set_badge(
                    "bgmsgrate",
                    "Disabled",
                    Some("The limit is off, so background message rate is not throttled."),
                );
            } else if throttle_enabled.is_none() && throttle_duration.is_none() {
                self.set_badge(
                    "bgmsgrate",
                    "125 Hz",
                    Some("Windows default rate. Nothing has been limited by XOS."),
                );
                self.st.lock().unwrap().bg_msg_selected = 1;
            } else {
                self.set_badge(
                    "bgmsgrate",
                    "Partial",
                    Some("The limit is only partly configured."),
                );
            }
        }

        self.set_badge("defender", &defender::read_state(), None);

        let uac = reg_get_dword(UAC_POL, "EnableLUA");
        self.set_badge("uac", &status::toggle(uac), None);

        let bg = reg_get_dword(POL_APP_PRIV, "LetAppsRunInBackground");
        let bg_override = reg_get_dword(CU_BG_APPS, "GlobalUserOverride");
        let bam = status::service("bam");
        let bg_state = if bg.is_none() && bg_override.is_none() {
            if bam == "N/A" {
                "N/A".to_string()
            } else if bam == "Unknown" {
                "Unknown".to_string()
            } else if bam == "Disabled" {
                "Partial".to_string()
            } else {
                status::ENABLED_WINDOWS_DEFAULT.to_string()
            }
        } else if bg == Some(2) && bg_override == Some(1) && bam == "Disabled" {
            "Disabled".to_string()
        } else if bg == Some(1)
            && (bg_override.is_none() || bg_override == Some(0))
            && bam == "Enabled"
        {
            "Enabled".to_string()
        } else if bam == "Unknown" {
            "Unknown".to_string()
        } else {
            "Partial".to_string()
        };
        self.set_badge("bgapps", &bg_state, None);

        let toast = reg_get_dword(TOAST_KEY, "ToastEnabled");
        let wpn_service = get_service_start_type("WpnService");
        let wpn_user_service = get_service_start_type("WpnUserService");
        let notification_state = if toast == Some(0) {
            "Disabled".to_string()
        } else if wpn_service == 4 || wpn_user_service == 4 {
            "Partial".to_string()
        } else if toast.is_none() && wpn_service >= 0 && wpn_user_service >= 0 {
            status::ENABLED_WINDOWS_DEFAULT.to_string()
        } else if toast == Some(1) && wpn_service >= 0 && wpn_user_service >= 0 {
            "Enabled".to_string()
        } else if toast.is_none() {
            "N/A".to_string()
        } else {
            "Partial".to_string()
        };
        self.set_badge("notif", &notification_state, None);

        self.set_badge("power", &get_power_saving_state(), None);
        let xos_plan = is_xos_power_plan_imported();
        self.set_badge(
            "xosplan",
            if xos_plan { "Enabled" } else { "Disabled" },
            Some(if xos_plan {
                "The XOS Power Plan is installed."
            } else {
                "The XOS Power Plan is not installed."
            }),
        );

        let hiber_enabled = reg_get_dword(HIBER_KEY, "HibernateEnabled");
        self.set_badge("hibernate", &status::toggle(hiber_enabled), None);

        let gpu_perf = get_service_start_type("GraphicsPerfSvc");
        let ndu = get_service_start_type("Ndu");
        let dusm = get_service_start_type("dusmsvc");
        let monitor_dps = get_service_start_type("DPS");
        let mon_enabled = gpu_perf >= 0
            && gpu_perf != 4
            && ndu == 2
            && dusm == 2
            && monitor_dps >= 0
            && monitor_dps != 4;
        let mon_disabled = gpu_perf == 4 && ndu == 4 && dusm == 4;
        self.set_badge(
            "gpumon",
            if gpu_perf < 0 && ndu < 0 && dusm < 0 {
                "N/A"
            } else if mon_enabled {
                "Enabled"
            } else if mon_disabled {
                "Disabled"
            } else {
                "Partial"
            },
            None,
        );

        let wdi_host = get_service_start_type("WdiServiceHost");
        let wdi_sys = get_service_start_type("WdiSystemHost");
        let diag_svc = get_service_start_type("diagsvc");
        let usage_dps = get_service_start_type("DPS");
        let sleep_study_disabled = reg_get_dword(SLEEP_POWER, "SleepStudyDisabled");
        let usage_enabled = wdi_host >= 0
            && wdi_host != 4
            && wdi_sys >= 0
            && wdi_sys != 4
            && diag_svc >= 0
            && diag_svc != 4
            && usage_dps >= 0
            && usage_dps != 4
            && sleep_study_disabled != Some(1);
        let usage_disabled =
            wdi_host == 4 && wdi_sys == 4 && diag_svc == 4 && sleep_study_disabled == Some(1);
        self.set_badge(
            "usagerep",
            if wdi_host < 0
                && wdi_sys < 0
                && diag_svc < 0
                && usage_dps < 0
                && sleep_study_disabled.is_none()
            {
                "N/A"
            } else if usage_enabled {
                "Enabled"
            } else if usage_disabled {
                "Disabled"
            } else {
                "Partial"
            },
            None,
        );

        let f_deny = reg_get_dword(TERM_SRV_KEY, "fDenyTSConnections");
        let all_rdp_enabled = RDP_SERVICES.iter().all(|s| {
            let start = get_service_start_type(s);
            start >= 0 && start != 4
        });
        let all_rdp_disabled = RDP_SERVICES.iter().all(|s| get_service_start_type(s) == 4);
        let rdp_state = if xos_winupdate::widgets_policy::is_home_edition()
            || (f_deny.is_none() && RDP_SERVICES.iter().all(|s| !service_exists(s)))
        {
            "N/A"
        } else if f_deny == Some(0) && all_rdp_enabled {
            "Enabled"
        } else if f_deny == Some(1) && all_rdp_disabled {
            "Disabled"
        } else {
            "Partial"
        };
        self.set_badge("rdp", rdp_state, None);

        let vbs_running = get_vbs_running_status();
        let vbs_configured_target = get_vbs_configured();
        log_security_state("VBS", vbs_running, vbs_configured_target);
        self.set_badge(
            "vbs",
            security_badge_label(vbs_running, vbs_configured_target),
            None,
        );

        let hvci_status = get_hvci_status();
        let mut hvci_configured = reg_get_dword(HVCI_SCENARIO, "Enabled");
        if hvci_configured.is_none() && hvci_status == 1 {
            hvci_configured = Some(1);
        }
        log_security_state("HVCI", hvci_status, hvci_configured);
        self.set_badge(
            "hvci",
            security_badge_label(hvci_status, hvci_configured),
            None,
        );
        let vbs_configured = is_vbs_configured_enabled();
        {
            let mut st = self.st.lock().unwrap();
            st.hvci_enable_enabled = vbs_configured;
            st.hvci_note_visible = !vbs_configured;
            st.badges.insert("hyperv", ("Checking".to_string(), None));
        }

        let w_search_svc = get_service_start_type("WSearch");
        let mut search_ifeo_count = 0usize;
        for key in SEARCH_IFEO_KEYS {
            if reg_get_string(key, "Debugger").is_some() {
                search_ifeo_count += 1;
            }
        }
        let (w_search_state, w_search_detail): (&str, String) = if w_search_svc < 0 {
            ("N/A", "WSearch is not present on this build.".to_string())
        } else if w_search_svc == 4 && search_ifeo_count == SEARCH_IFEO_KEYS.len() {
            (
                "Disabled",
                "Search is fully disabled: the WSearch service does not start and SearchApp, SearchUI and SearchHost are blocked, so the taskbar search box will not run.".to_string(),
            )
        } else if w_search_svc == 4 && search_ifeo_count == 0 {
            (
                "Disabled Service Only",
                "The WSearch service does not start, so indexing is off. Search executables are not blocked.".to_string(),
            )
        } else if w_search_svc != 4 && search_ifeo_count == 0 {
            (
                "Enabled",
                "Windows Search and indexing are running normally.".to_string(),
            )
        } else {
            (
                "Partial",
                format!(
                    "The service and the search executable block disagree: service {}, {} of {} search executables blocked.",
                    if w_search_svc == 4 { "disabled" } else { "enabled" },
                    search_ifeo_count,
                    SEARCH_IFEO_KEYS.len()
                ),
            )
        };
        self.set_badge("wsearch", w_search_state, Some(&w_search_detail));

        let split_val = reg_get_dword(SVC_HOST_CONTROL_READ, "SvcHostSplitThresholdInKB");
        let mut default_split_services = 0;
        let mut default_split_disabled = 0;
        for service in stock_split_disabled() {
            if !service_exists(&service) {
                continue;
            }
            default_split_services += 1;
            if reg_get_dword(&format!("{SVC_BASE_PATH}{service}"), "SvcHostSplitDisable") == Some(1)
            {
                default_split_disabled += 1;
            }
        }
        let mut recommended_split_services = 0;
        let mut recommended_split_disabled = 0;
        for service in RECOMMENDED_SPLIT_DISABLED {
            if !service_exists(service) {
                continue;
            }
            recommended_split_services += 1;
            if reg_get_dword(&format!("{SVC_BASE_PATH}{service}"), "SvcHostSplitDisable") == Some(1)
            {
                recommended_split_disabled += 1;
            }
        }
        let (svc_split_state, svc_split_detail): (&str, Option<&str>) =
            if split_val == Some(0xFFFFFFFFu32 as i32) {
                (
                    "Forced",
                    Some("Every service is isolated in its own svchost."),
                )
            } else if split_val == Some(0x380000)
                && default_split_services > 0
                && default_split_disabled == default_split_services
                && recommended_split_services > 0
                && recommended_split_disabled == recommended_split_services
            {
                (
                    "Recommended",
                    Some("The recommended XOS service-grouping profile is active."),
                )
            } else if (split_val.is_none() || split_val == Some(0x380000))
                && default_split_services > 0
                && default_split_disabled == default_split_services
                && recommended_split_disabled == 0
            {
                (
                    "Default (Windows)",
                    Some("Windows default service grouping is active."),
                )
            } else {
                ("Partial", None)
            };
        self.set_badge("svcsplit", svc_split_state, svc_split_detail);

        let spectre = reg_get_dword(MEM_MGMT, "FeatureSettingsOverride");
        let spectre_mask = reg_get_dword(MEM_MGMT, "FeatureSettingsOverrideMask");
        let spectre_state = if spectre == Some(3) && spectre_mask == Some(3) {
            "Disabled"
        } else if spectre == Some(0) && spectre_mask == Some(3) {
            "Enabled"
        } else if spectre.is_none() && spectre_mask.is_none() {
            "N/A"
        } else {
            "Partial"
        };
        self.set_badge("spectre", spectre_state, None);

        let ps_pol = reg_get_string(PS_POLICY_KEY, "ExecutionPolicy");
        let (ps_state, ps_detail): (String, String) = match ps_pol {
            None => (
                "Restricted (Windows Default)".to_string(),
                "Windows default. Scripts are blocked.".to_string(),
            ),
            Some(p) if p.trim().is_empty() => (
                "Restricted (Windows Default)".to_string(),
                "Windows default. Scripts are blocked.".to_string(),
            ),
            Some(p) => {
                if [
                    "Restricted",
                    "RemoteSigned",
                    "Unrestricted",
                    "AllSigned",
                    "Bypass",
                    "Undefined",
                ]
                .iter()
                .any(|s| p.eq_ignore_ascii_case(s))
                {
                    let mut chars = p.chars();
                    let first: String = chars.next().unwrap().to_uppercase().collect();
                    (
                        format!("{first}{}", chars.as_str()),
                        format!("Current PowerShell execution policy: {p}."),
                    )
                } else {
                    (
                        "Partial".to_string(),
                        format!("Unrecognised execution policy value: {p}."),
                    )
                }
            }
        };
        self.set_badge("pspolicy", &ps_state, Some(&ps_detail));
    }

    fn done(&self, host: &dyn Host, msg: &str, failed: bool, cause: Option<&str>) {
        done(host, msg, failed, cause);
    }

    fn after_change(&self, host: &dyn Host) {
        self.refresh_states(host);
    }

    fn uac_enable(&self, host: &dyn Host) {
        xos_sys::ops::reset();
        reg_set_dword(UAC_POL, "EnableLUA", 1);
        reg_set_dword(UAC_POL, "PromptOnSecureDesktop", 1);
        reg_set_dword(UAC_POL, "ConsentPromptBehaviorAdmin", 5);
        let mut ok = config_service_reg("luafv", 2);
        ok &= config_service_reg("Appinfo", 3);
        self.after_change(host);
        self.done(host, "UAC Enabled. Please reboot.", !ok, None);
    }

    fn uac_disable(&self, host: &dyn Host) {
        xos_sys::ops::reset();
        reg_set_dword(UAC_POL, "EnableLUA", 0);
        reg_set_dword(UAC_POL, "PromptOnSecureDesktop", 0);
        reg_set_dword(UAC_POL, "ConsentPromptBehaviorAdmin", 0);
        let ok = config_service_reg("luafv", 4);
        self.after_change(host);
        self.done(host, "UAC Disabled. Please reboot.", !ok, None);
    }

    fn defender_click(&self, host: &dyn Host, enabled: bool) {
        let overlay = |t: Option<&str>| self.set_overlay(host, t);
        let refresh = || self.after_change(host);
        let hooks = Hooks {
            overlay: &overlay,
            refresh: &refresh,
        };
        defender::set_enabled_hooked(
            host,
            enabled,
            DefenderOptions {
                show_result: true,
                ..Default::default()
            },
            &hooks,
        );
    }

    fn bg_apps_enable(&self, host: &dyn Host) {
        xos_sys::ops::reset();
        reg_set_dword(POL_APP_PRIV, "LetAppsRunInBackground", 1);
        reg_delete_value(CU_BG_APPS, "GlobalUserOverride");
        let ok = config_service_sc("bam", "system");
        self.after_change(host);
        self.done(host, "Background Apps Enabled. Please reboot.", !ok, None);
    }

    fn bg_apps_disable(&self, host: &dyn Host) {
        xos_sys::ops::reset();
        reg_set_dword(POL_APP_PRIV, "LetAppsRunInBackground", 2);
        reg_set_dword(CU_BG_APPS, "GlobalUserOverride", 1);
        reg_delete_value(
            POL_APP_PRIV,
            "LetAppsRunInBackground_UserInControlOfTheseApps",
        );
        reg_delete_value(POL_APP_PRIV, "LetAppsRunInBackground_ForceAllowTheseApps");
        reg_delete_value(POL_APP_PRIV, "LetAppsRunInBackground_ForceDenyTheseApps");
        let ok = config_service_sc("bam", "disabled");
        self.after_change(host);
        self.done(host, "Background Apps Disabled. Please reboot.", !ok, None);
    }

    fn notif_enable(&self, host: &dyn Host) {
        xos_sys::ops::reset();
        let mut ok = config_service_reg("WpnService", 2);
        ok &= config_service_reg("WpnUserService", 2);
        reg_set_dword(TOAST_KEY, "ToastEnabled", 1);
        self.after_change(host);
        self.done(host, "Notifications Enabled. Please reboot.", !ok, None);
    }

    fn notif_disable(&self, host: &dyn Host) {
        xos_sys::ops::reset();
        let mut ok = true;
        let clipboard_start = get_service_start_type("cbdhsvc");
        let clip_deps = clipboard_start >= 0 && clipboard_start != 4;
        let mut keep_wpn = false;

        if clip_deps {
            keep_wpn = ask_yes_no(
                host,
                "The Windows Push Notification Service (WpnService) is also required by Clipboard & Snipping Tool.\n\nWould you like to keep WpnService enabled?",
                TITLE,
                Icon::Question,
            );
        }

        if !keep_wpn {
            ok &= config_service_reg("WpnService", 4);
            ok &= config_service_reg("WpnUserService", 4);
        }

        reg_set_dword(TOAST_KEY, "ToastEnabled", 0);
        self.after_change(host);
        self.done(host, "Notifications Disabled. Please reboot.", !ok, None);
    }

    fn power_disable(&self, host: &dyn Host) {
        xos_sys::ops::reset();
        let mut ok = true;
        write_usb_power_registry(true);

        ok &= power_cfg_set(SUB_USB, SET_USBLINK, 0, 0);
        ok &= power_cfg_set(SUB_PCIE, SET_ASPM, 0, 0);
        ok &= power_cfg_set(SUB_DISK, SET_DISKIDLE, 0, 0);
        reg_set_dword(AHCILINK_ATTRS, "Attributes", 2);
        ok &= power_cfg_set(SUB_DISK, SET_AHCILINK, 0, 0);

        self.after_change(host);
        self.done(
            host,
            "Power Savings Disabled. Maximum performance applied. Please reboot.",
            !ok,
            None,
        );
    }

    fn power_enable(&self, host: &dyn Host) {
        xos_sys::ops::reset();
        write_usb_power_registry(false);
        let ok = power_cfg_defaults();
        self.after_change(host);
        self.done(
            host,
            "Power Savings Enabled. Defaults restored. Please reboot.",
            !ok,
            None,
        );
    }

    fn xos_plan_import(&self, host: &dyn Host) {
        xos_sys::ops::reset();
        if is_xos_power_plan_imported() {
            self.done(host, "XOS Power Plan is already installed.", false, None);
            return;
        }

        let (success, detail) = import_xos_power_plan_detail();
        if success {
            sync_power_plan_context_menu();
            self.after_change(host);
            self.done(
                host,
                "XOS Power Plan built from a Windows power plan and set active.",
                false,
                None,
            );
        } else {
            self.after_change(host);
            let mut message = "Failed to build the XOS Power Plan.".to_string();
            if !detail.trim().is_empty() {
                message.push_str("\n\nDetails:\n");
                message.push_str(&detail);
            }
            if log::is_available() {
                message.push_str("\n\nSession log:\n");
                message.push_str(
                    &log::log_path()
                        .map(|p| p.display().to_string())
                        .unwrap_or_default(),
                );
            }
            host.dialog(&message, TITLE, Buttons::Ok, Icon::Error);
        }
    }

    fn xos_plan_remove(&self, host: &dyn Host) {
        xos_sys::ops::reset();
        if !is_xos_power_plan_imported() {
            self.done(host, "XOS Power Plan is not installed.", false, None);
            return;
        }

        let (switched, selected_guid) = try_switch_away_from_xos_power_plan();
        if !switched {
            log::result(
                false,
                "Switch away from XOS power plan",
                "no installed non-XOS power scheme could be activated",
            );
            self.after_change(host);
            warn_ok(
                host,
                "Could not activate another installed power plan. The XOS Power Plan was not removed.",
            );
            return;
        }

        log::op_detail(
            "Switched away from the XOS power plan before removing it",
            Some(&format!("scheme={}", selected_guid.unwrap_or_default())),
        );
        let (success, detail) = delete_xos_power_plan_detail();
        if success {
            sync_power_plan_context_menu();
            self.after_change(host);
            self.done(host, "XOS Power Plan removed.", false, None);
        } else {
            self.after_change(host);
            let mut message = "Failed to remove XOS Power Plan.".to_string();
            if !detail.trim().is_empty() {
                message.push_str("\n\nDetails:\n");
                message.push_str(&detail);
            }
            if log::is_available() {
                message.push_str("\n\nSession log:\n");
                message.push_str(
                    &log::log_path()
                        .map(|p| p.display().to_string())
                        .unwrap_or_default(),
                );
            }
            host.dialog(&message, TITLE, Buttons::Ok, Icon::Error);
        }
    }

    fn hibernate_enable(&self, host: &dyn Host) {
        xos_sys::ops::reset();
        let (ok, blocker) = hibernate_set(true);
        if !ok {
            self.after_change(host);
            let blocker = blocker.unwrap_or_default();
            self.done(
                host,
                &format!(
                    "Hibernation could not be enabled on this system.{}\n\nThis is a firmware or platform limitation, not a setting this Toolkit can change. The registry value was left as it was.",
                    if blocker.is_empty() {
                        String::new()
                    } else {
                        format!("\n\nWindows reported:\n{blocker}")
                    }
                ),
                true,
                Some("firmware or platform does not support hibernation"),
            );
            return;
        }
        reg_set_dword(HIBER_KEY, "HibernateEnabled", 1);
        reg_set_dword(HIBER_POL, "ShowHibernateOption", 1);
        self.after_change(host);
        self.done(
            host,
            "Hibernate enabled. The option will appear in the Start menu power options.",
            false,
            None,
        );
    }

    fn hibernate_disable(&self, host: &dyn Host) {
        xos_sys::ops::reset();
        let (ok, blocker) = hibernate_set(false);
        if !ok {
            self.after_change(host);
            let blocker = blocker.unwrap_or_default();
            let cause = if blocker.is_empty() {
                None
            } else {
                Some("powercfg refused the change")
            };
            self.done(
                host,
                &format!(
                    "Hibernation could not be disabled.{}",
                    if blocker.is_empty() {
                        String::new()
                    } else {
                        format!("\n\nWindows reported:\n{blocker}")
                    }
                ),
                true,
                cause,
            );
            return;
        }
        reg_set_dword(HIBER_KEY, "HibernateEnabled", 0);
        reg_set_dword(HIBER_POL, "ShowHibernateOption", 0);
        self.after_change(host);
        self.done(
            host,
            "Hibernate disabled. The hiberfil.sys file will be removed, freeing disk space.",
            false,
            None,
        );
    }

    fn gpu_mon_enable(&self, host: &dyn Host) {
        xos_sys::ops::reset();
        let mut ok = true;
        ok &= config_service_reg("GraphicsPerfSvc", 3);
        ok &= config_service_reg("Ndu", 2);
        ok &= config_service_reg("DPS", 2);
        ok &= config_service_reg("dusmsvc", 2);
        ok &= config_service_sc("dusmsvc", "auto");
        run_as_ti("sc.exe", "start Ndu");
        let dusm_started = run_as_ti("sc.exe", "start dusmsvc");
        self.after_change(host);

        let mut msg = "GPU & Network monitoring enabled (services set to Automatic).\n\nReboot required for the Data Usage page (Settings > Network) and live network graphs to repopulate - the Ndu driver only tracks usage from boot.".to_string();
        if !dusm_started {
            msg.push_str("\n\nNote: the Data Usage service (dusmsvc) did not start immediately; the reboot will bring it up.");
        }
        self.done(host, &msg, !ok, None);
    }

    fn gpu_mon_disable(&self, host: &dyn Host) {
        xos_sys::ops::reset();
        let mut ok = config_service_reg("GraphicsPerfSvc", 4);
        ok &= config_service_reg("Ndu", 4);

        let usage_start = get_service_start_type("WdiServiceHost");
        let fivem_start = get_service_start_type("PcaSvc");
        let usage_deps = usage_start >= 0 && usage_start != 4;
        let fivem_deps = fivem_start >= 0 && fivem_start != 4;
        let mut keep_dps = false;

        if usage_deps || fivem_deps {
            let dep_list = if usage_deps && fivem_deps {
                "System Usage & Diagnostics Reporting and FiveM Services"
            } else if usage_deps {
                "System Usage & Diagnostics Reporting"
            } else {
                "FiveM Services"
            };
            keep_dps = ask_yes_no(
                host,
                &format!(
                    "The Diagnostic Policy Service (DPS) is also required by {dep_list}.\n\nWould you like to keep DPS enabled?"
                ),
                TITLE,
                Icon::Question,
            );
        }

        if !keep_dps {
            ok &= config_service_reg("DPS", 4);
        }

        ok &= config_service_reg("dusmsvc", 4);
        self.after_change(host);
        self.done(
            host,
            "GPU & Network monitoring disabled. Reboot to apply.",
            !ok,
            None,
        );
    }

    fn usage_rep_enable(&self, host: &dyn Host) {
        xos_sys::ops::reset();
        let mut ok = config_service_reg("DPS", 2);
        ok &= config_service_reg("diagsvc", 3);
        ok &= config_service_reg("WdiServiceHost", 3);
        ok &= config_service_reg("WdiSystemHost", 3);
        reg_delete_value(SLEEP_POWER, "SleepStudyDisabled");
        ok &= run_as_ti(
            "wevtutil.exe",
            "sl \"Microsoft-Windows-SleepStudy/Diagnostic\" /q:true",
        );
        ok &= run_as_ti(
            "wevtutil.exe",
            "sl \"Microsoft-Windows-Kernel-Processor-Power/Diagnostic\" /q:true",
        );
        ok &= run_as_ti(
            "wevtutil.exe",
            "sl \"Microsoft-Windows-UserModePowerService/Diagnostic\" /q:true",
        );
        self.after_change(host);
        self.done(
            host,
            "System usage & diagnostics reporting enabled. Please reboot to apply.",
            !ok,
            None,
        );
    }

    fn usage_rep_disable(&self, host: &dyn Host) {
        xos_sys::ops::reset();
        let mut ok = true;
        let graphics_start = get_service_start_type("GraphicsPerfSvc");
        let ndu_start = get_service_start_type("Ndu");
        let fivem_start = get_service_start_type("PcaSvc");
        let gpu_deps =
            (graphics_start >= 0 && graphics_start != 4) || (ndu_start >= 0 && ndu_start != 4);
        let fivem_deps = fivem_start >= 0 && fivem_start != 4;
        let mut keep_dps = false;

        if gpu_deps || fivem_deps {
            let dep_list = if gpu_deps && fivem_deps {
                "GPU & Network Monitoring and FiveM Services"
            } else if gpu_deps {
                "GPU & Network Monitoring"
            } else {
                "FiveM Services"
            };
            keep_dps = ask_yes_no(
                host,
                &format!(
                    "The Diagnostic Policy Service (DPS) is also required by {dep_list}.\n\nWould you like to keep DPS enabled?"
                ),
                TITLE,
                Icon::Question,
            );
        }

        if !keep_dps {
            ok &= config_service_reg("DPS", 4);
        }

        ok &= config_service_reg("diagsvc", 4);
        ok &= config_service_reg("WdiServiceHost", 4);
        ok &= config_service_reg("WdiSystemHost", 4);
        reg_set_dword(SLEEP_POWER, "SleepStudyDisabled", 1);
        ok &= run_as_ti(
            "wevtutil.exe",
            "sl \"Microsoft-Windows-SleepStudy/Diagnostic\" /q:false",
        );
        ok &= run_as_ti(
            "wevtutil.exe",
            "sl \"Microsoft-Windows-Kernel-Processor-Power/Diagnostic\" /q:false",
        );
        ok &= run_as_ti(
            "wevtutil.exe",
            "sl \"Microsoft-Windows-UserModePowerService/Diagnostic\" /q:false",
        );
        self.after_change(host);
        self.done(
            host,
            "System usage & diagnostics reporting disabled. Please reboot to apply.",
            !ok,
            None,
        );
    }

    fn vbs_enable(&self, host: &dyn Host) {
        xos_sys::ops::reset();
        if !confirm_hypervisor_enable(host, "VBS") {
            return;
        }
        clear_hypervisor_override();
        reg_set_dword(DEV_GUARD_POL, "EnableVirtualizationBasedSecurity", 1);
        reg_set_dword(DEV_GUARD_DIRECT, "EnableVirtualizationBasedSecurity", 1);
        let hypervisor_launch = get_bcd_setting("hypervisorlaunchtype");
        let mut boot_config_ok = true;
        if hypervisor_launch
            .as_deref()
            .is_some_and(|h| h.eq_ignore_ascii_case("off"))
        {
            log::log("[BCD] hypervisorlaunchtype is off; setting it to auto so Windows can start the hypervisor for VBS.");
            boot_config_ok = bcd_edit("hypervisorlaunchtype", "auto")
                && verify_bcd_setting("hypervisorlaunchtype", "auto");
        } else {
            log::log(&format!(
                "[BCD] hypervisorlaunchtype is {}; left as it is.",
                hypervisor_launch
                    .unwrap_or_else(|| "not present on the current boot entry".to_string())
            ));
        }
        self.after_change(host);
        self.done(
            host,
            "VBS enabled. Restart your PC.\nAlso ensure SVM/VT-x is enabled in BIOS.\n\nMemory Integrity can now be enabled separately below.",
            !boot_config_ok,
            None,
        );
    }

    fn vbs_disable(&self, host: &dyn Host) {
        xos_sys::ops::reset();
        let boot_config_ok = apply_vbs_disable_registry();
        self.after_change(host);
        self.done(
            host,
            "VBS & HVCI disabled. Restart your PC.",
            !boot_config_ok,
            None,
        );
    }

    fn vbs_force_disable(&self, host: &dyn Host) {
        xos_sys::ops::reset();
        let warn = ask_yes_no(
            host,
            "Use this ONLY if the normal \"Disable VBS & HVCI\" button didn't work after a restart.\n\nWhy it's separate: normal Disable only clears registry and boot flags. If VBS/HVCI was turned on with a firmware (UEFI) lock, Windows re-enables it on every boot and registry changes can't stop it. Force Disable clears that lock the same way Microsoft's own tool does: it edits your boot configuration (BCD) and copies an unlock file to the EFI system partition, then your firmware shows a one-time confirmation screen at the next boot that you must accept.\n\nWhat could go wrong: because it touches boot configuration, there is a small risk on unusual setups. It only stages a one-time boot entry, so if you don't accept the firmware prompt nothing changes.\n\nContinue?",
            "Force Disable - Last Resort",
            Icon::Warning,
        );
        if !warn {
            return;
        }

        let state = disable_vbs_complete();
        self.after_change(host);

        if state == "failed" {
            self.done(
                host,
                "VBS registry settings were disabled, but the boot configuration could not be updated. Restarting may not apply the change.",
                true,
                Some("boot configuration could not be updated"),
            );
            return;
        }

        if state == "off" {
            self.done(
                host,
                "VBS & HVCI disabled. Restart your PC to apply.",
                false,
                None,
            );
            return;
        }
        if state == "pending" {
            self.done(
                host,
                "VBS & HVCI set to disabled. Restart your PC.\nNo firmware lock was detected, so the normal disable is enough here.",
                false,
                None,
            );
            return;
        }

        let (ok, message) = stage_uefi_lock_clear();
        self.done(host, &message, !ok, None);
    }

    fn hvci_enable(&self, host: &dyn Host) {
        xos_sys::ops::reset();
        if !is_vbs_configured_enabled() {
            warn_ok(
                host,
                "Enable VBS first. Memory Integrity runs on top of VBS and cannot be turned on without it.",
            );
            return;
        }
        if !confirm_hypervisor_enable(host, "HVCI") {
            return;
        }
        clear_hypervisor_override();
        reg_set_dword(DEV_GUARD_POL, "HypervisorEnforcedCodeIntegrity", 1);
        reg_set_dword(HVCI_SCENARIO, "Enabled", 1);
        reg_delete_value(HVCI_SCENARIO, "WasEnabledBy");
        self.after_change(host);
        self.done(
            host,
            "Memory Integrity (HVCI) enabled. Restart your PC.",
            false,
            None,
        );
    }

    fn hvci_disable(&self, host: &dyn Host) {
        xos_sys::ops::reset();
        reg_set_dword(DEV_GUARD_POL, "HypervisorEnforcedCodeIntegrity", 0);
        reg_set_dword(HVCI_SCENARIO, "Enabled", 0);
        reg_set_dword(HVCI_SCENARIO, "WasEnabledBy", 0);
        self.after_change(host);
        self.done(
            host,
            "Memory Integrity (HVCI) disabled. Restart your PC.\nVBS is left enabled.",
            false,
            None,
        );
    }

    fn spectre_enable(&self, host: &dyn Host) {
        xos_sys::ops::reset();
        reg_set_dword(MEM_MGMT, "FeatureSettingsOverride", 0);
        reg_set_dword(MEM_MGMT, "FeatureSettingsOverrideMask", 3);
        self.after_change(host);
        self.done(
            host,
            "Spectre/Meltdown mitigations enabled. Please reboot.",
            false,
            None,
        );
    }

    fn spectre_disable(&self, host: &dyn Host) {
        xos_sys::ops::reset();
        reg_set_dword(MEM_MGMT, "FeatureSettingsOverride", 3);
        reg_set_dword(MEM_MGMT, "FeatureSettingsOverrideMask", 3);
        self.after_change(host);
        self.done(
            host,
            "Spectre/Meltdown mitigations disabled. Please reboot.",
            false,
            None,
        );
    }

    fn hyper_v_run(&self, host: &dyn Host, enable: bool) {
        xos_sys::ops::reset();
        app_state::begin_operation();
        self.set_overlay(
            host,
            Some(if enable {
                "Enabling Hyper-V..."
            } else {
                "Disabling Hyper-V..."
            }),
        );
        host.set_status(if enable {
            "Enabling Hyper-V..."
        } else {
            "Disabling Hyper-V..."
        });
        let result = if enable {
            hyper_v_enable_work()
        } else {
            hyper_v_disable_work()
        };
        match result {
            Ok(()) => {
                self.refresh_core();
                host.publish(self.model());
                self.done(
                    host,
                    if enable {
                        "Hyper-V enabled. Please reboot."
                    } else {
                        "Hyper-V disabled. Please reboot."
                    },
                    false,
                    None,
                );
                self.refresh_hyper_v();
            }
            Err(ex) => {
                log::exception(
                    if enable {
                        "Hyper-V enable failed"
                    } else {
                        "Hyper-V disable failed"
                    },
                    &ex,
                );
                host.dialog(
                    &if enable {
                        format!("Some Hyper-V components could not be enabled.\n\n{ex}")
                    } else {
                        format!("Hyper-V could not be disabled.\n\n{ex}")
                    },
                    TITLE,
                    Buttons::Ok,
                    Icon::Error,
                );
            }
        }
        app_state::end_operation();
        self.set_overlay(host, None);
    }

    fn rdp_enable(&self, host: &dyn Host) {
        xos_sys::ops::reset();
        if xos_winupdate::widgets_policy::is_home_edition() {
            self.after_change(host);
            self.done(
                host,
                &format!("{RDP_HOME_MESSAGE} Nothing was changed."),
                true,
                Some("Windows Home has no Remote Desktop host"),
            );
            return;
        }
        reg_set_dword(TERM_SRV_KEY, "fDenyTSConnections", 0);
        let mut ok = true;
        for svc in RDP_SERVICES {
            ok &= config_service_reg(svc, 3);
        }
        for rule in RDP_FIREWALL_RULES {
            ok &= set_firewall_rule_enabled(rule, true);
        }
        self.after_change(host);
        self.done(host, "Remote Desktop enabled.", !ok, None);
    }

    fn rdp_disable(&self, host: &dyn Host) {
        xos_sys::ops::reset();
        if xos_winupdate::widgets_policy::is_home_edition() {
            self.after_change(host);
            self.done(
                host,
                &format!("Remote Desktop is already off: {RDP_HOME_MESSAGE} Nothing was changed."),
                false,
                Some("Windows Home has no Remote Desktop host"),
            );
            return;
        }
        reg_set_dword(TERM_SRV_KEY, "fDenyTSConnections", 1);
        let mut ok = true;
        for svc in RDP_SERVICES {
            ok &= config_service_reg(svc, 4);
        }
        for rule in RDP_FIREWALL_RULES {
            ok &= set_firewall_rule_enabled(rule, false);
        }
        self.after_change(host);
        self.done(host, "Remote Desktop disabled. Please reboot.", !ok, None);
    }

    fn wsearch_enable(&self, host: &dyn Host) {
        xos_sys::ops::reset();
        let ok = enable_windows_search();
        self.after_change(host);
        self.done(
            host,
            "Windows Search enabled and configured to start.",
            !ok,
            None,
        );
    }

    fn wsearch_disable_indexing(&self, host: &dyn Host) {
        xos_sys::ops::reset();
        let ok = config_service_reg("WSearch", 4);
        self.after_change(host);
        self.done(
            host,
            "Windows Search indexing disabled. Please reboot.",
            !ok,
            None,
        );
    }

    fn wsearch_disable_search(&self, host: &dyn Host) {
        xos_sys::ops::reset();
        let mut ok = config_service_reg("WSearch", 4);
        for key in SEARCH_IFEO_KEYS {
            reg_set_string(key, "Debugger", &format!(r"{}\taskkill.exe", system_dir()));
        }
        reg_set_dword(
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search",
            "SearchboxTaskbarMode",
            0,
        );
        for name in ["SearchApp", "SearchUI", "SearchHost"] {
            kill_processes_named(name);
        }
        let search_exe_paths = [format!(
            r"{}\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SearchHost.exe",
            system_root()
        )];
        for path in search_exe_paths {
            if !std::path::Path::new(&path).exists() {
                continue;
            }
            let backup = format!("{path}.bak");
            if std::path::Path::new(&backup).exists() {
                continue;
            }
            let renamed = run_as_ti("cmd.exe", &format!("/c move /Y \"{path}\" \"{backup}\""))
                && std::path::Path::new(&backup).exists();
            ok &= renamed;
        }
        kill_process("explorer.exe");
        sleep(Duration::from_millis(1000));
        if !xos_sys::shell_start("explorer.exe", "") {
            ok = false;
        }
        self.after_change(host);
        self.done(
            host,
            "Windows Search disabled entirely. Please reboot.",
            !ok,
            None,
        );
    }

    fn svc_split_forced(&self, host: &dyn Host) {
        xos_sys::ops::reset();
        let result = ask_yes_no(
            host,
            "Forced mode merges all services into shared svchost processes for the lowest RAM use. This may break some features like Xbox services.\n\nYou can revert by choosing Recommended or Default.\n\nContinue?",
            TITLE,
            Icon::Warning,
        );
        if !result {
            return;
        }

        let ok = set_svc_host_split_threshold(0xFFFFFFFF);
        self.after_change(host);
        self.done(
            host,
            "Service grouping set to Forced. Please reboot.",
            !ok,
            None,
        );
    }

    fn svc_split_recommended(&self, host: &dyn Host) {
        xos_sys::ops::reset();
        let all: Vec<String> = PLAYBOOK_CORE_SPLIT
            .iter()
            .chain(RECOMMENDED_SPLIT_DISABLED.iter())
            .filter(|s| service_exists(s))
            .map(|s| s.to_string())
            .collect();
        let grouped = distinct_ci(all);
        let mut ok = set_svc_host_split_threshold(0x380000);
        ok &= set_service_grouping_values(&grouped, true);

        self.after_change(host);
        self.done(
            host,
            "Service grouping set to Recommended. Please reboot.",
            !ok,
            None,
        );
    }

    fn svc_split_default(&self, host: &dyn Host) {
        xos_sys::ops::reset();
        let stock_split = stock_split_disabled();
        let core_not_stock: Vec<String> =
            distinct_ci(PLAYBOOK_CORE_SPLIT.iter().map(|s| s.to_string()).collect())
                .into_iter()
                .filter(|s| !stock_split.iter().any(|t| t.eq_ignore_ascii_case(s)))
                .collect();
        let to_ungroup = distinct_ci(
            RECOMMENDED_SPLIT_DISABLED
                .iter()
                .map(|s| s.to_string())
                .chain(network_reset::SPLIT_SERVICES.iter().map(|s| s.to_string()))
                .chain(core_not_stock)
                .filter(|s| service_exists(s))
                .collect(),
        );
        let to_group = distinct_ci(
            stock_split
                .into_iter()
                .filter(|s| service_exists(s))
                .collect(),
        );

        let mut ok = set_svc_host_split_threshold(0x380000);
        ok &= set_service_grouping_values(&to_ungroup, false);
        ok &= set_service_grouping_values(&to_group, true);

        self.after_change(host);
        self.done(
            host,
            "Service grouping restored to Windows default. Please reboot.",
            !ok,
            None,
        );
    }

    fn set_ps_policy(&self, host: &dyn Host, policy: &str) {
        xos_sys::ops::reset();
        reg_set_string(PS_POLICY_KEY, "ExecutionPolicy", policy);
        self.after_change(host);
        self.done(
            host,
            &format!("PowerShell Execution Policy set to {policy}."),
            false,
            None,
        );
    }

    fn bg_msg_rate_apply(&self, host: &dyn Host) {
        xos_sys::ops::reset();
        let selected = self.st.lock().unwrap().bg_msg_selected;
        if selected < 0 || selected as usize >= BG_MSG_TAGS.len() {
            return;
        }
        let ms = BG_MSG_TAGS[selected as usize];
        if !(3..=20).contains(&ms) {
            host.dialog("Invalid duration value.", TITLE, Buttons::Ok, Icon::Error);
            return;
        }
        reg_set_dword(MOUSE_KEY, "RawMouseThrottleEnabled", 1);
        reg_set_dword(MOUSE_KEY, "RawMouseThrottleDuration", ms);
        let hz = (1000.0 / ms as f64).round_ties_even() as i32;
        self.after_change(host);
        self.done(
            host,
            &format!("Background message rate set to {hz} Hz ({ms}ms)."),
            false,
            None,
        );
    }
}

fn card_with_desc(st: &State, id: &'static str, title: &str, desc: &str) -> Card {
    let (state, detail) = st
        .badges
        .get(id)
        .cloned()
        .unwrap_or_else(|| ("Checking".to_string(), None));
    Card::new(id, title, desc).badge(status::badge_with(&state, detail.as_deref()))
}

fn toggle_card(st: &State, id: &'static str, title: &str, desc: &str) -> Card {
    card_with_desc(st, id, title, desc).enable_disable(id)
}

fn note(text: &str) -> Row {
    Row::new(vec![Control::label(text).tone(Tone::Orange)])
}

impl Page for SystemPage {
    fn id(&self) -> &'static str {
        "System"
    }

    fn label(&self) -> &'static str {
        "System"
    }

    fn model(&self) -> PageModel {
        let st = self.st.lock().unwrap();
        let mut m = PageModel::new(
            "System",
            "System Control",
            "Security, power, virtualization, and Windows services.",
        )
        .max_width(1080.0);

        m = m.card(toggle_card(
            &st,
            "uac",
            "User Account Control (UAC)",
            "Asks for your permission before an app makes changes that need administrator rights. When disabled, apps get those rights without asking, which also lets malware make changes silently. Requires a restart.",
        ));
        m = m.card(toggle_card(
            &st,
            "defender",
            "Windows Defender",
            "Windows' built-in antivirus: real-time protection, SmartScreen and related services. Disabling it leaves the PC without virus protection unless you install another antivirus. You can turn it back on here at any time.",
        ));
        m = m.card(toggle_card(
            &st,
            "bgapps",
            "Background Apps",
            "Lets Microsoft Store apps keep running in the background to receive messages, calls and updates. If a Store messaging app like WhatsApp only shows new messages after you open it, enable this. Regular desktop programs are not affected.",
        ));
        m = m.card(toggle_card(
            &st,
            "notif",
            "Notifications",
            "Windows pop-up notifications and system alerts. Needed by apps like WhatsApp, Snipping Tool, the Xbox app and most Store apps to show their alerts. Requires a restart.",
        ));
        m = m.card(toggle_card(
            &st,
            "power",
            "Power Savings",
            "Lets USB devices, PCIe devices and drives drop into low power states when idle. Disabling it can remove small delays when a device wakes up, but uses more power. Keep it enabled on laptops.",
        ));
        m = m.card(
            card_with_desc(
                &st,
                "xosplan",
                "XOS Power Plan",
                "Adds or removes the XOS power plan, tuned for performance. Once added, pick it from the Power Plan menu on the desktop right-click menu or in Windows power settings.",
            )
            .actions(vec![
                Control::button("xosplan.add", "Add", BtnStyle::Enable),
                Control::button("xosplan.remove", "Remove", BtnStyle::Disable),
            ]),
        );
        m = m.card(toggle_card(
            &st,
            "hibernate",
            "Hibernate",
            "Saves everything you have open to the drive and fully powers off the PC, so you can continue later. Disabling it frees several GB of disk space and also turns off Fast Startup.",
        ));
        m = m.card(
            card_with_desc(
                &st,
                "gpumon",
                "GPU & Network Monitoring",
                "Services behind the GPU graphs and network usage numbers in Task Manager, and data usage in Settings. Disabling them saves a little background work. Requires a restart.",
            )
            .row(note(
                "Note: Disabling will cause Task Manager to show 0% network usage and Windows data usage stats to stop updating.",
            ))
            .enable_disable("gpumon"),
        );
        m = m.card(toggle_card(
            &st,
            "usagerep",
            "System Usage & Diagnostics Reporting",
            "Windows diagnostic services and sleep reports that collect system health and battery data. Disabling them reduces background activity, but Windows troubleshooters stop working. Requires a restart.",
        ));
        m = m.card(
            card_with_desc(
                &st,
                "vbs",
                "Virtualization-Based Security (VBS)",
                "Uses your CPU's virtualization feature to protect core parts of Windows from malware. Turning it off can raise FPS but lowers security. Some anti-cheats may require it, and Memory Integrity below needs it. To turn it on, virtualization (SVM or VT-x) must also be enabled in your BIOS.",
            )
            .actions(vec![
                Control::enable("vbs.enable"),
                Control::disable("vbs.disable"),
                Control::button("vbs.forcedisable", "Force Disable (UEFI Lock)", BtnStyle::Warning),
            ]),
        );
        let mut hvci = card_with_desc(
            &st,
            "hvci",
            "Memory Integrity (HVCI)",
            "Blocks untrusted or modified drivers from loading. Needs VBS to be on. Disabling it can fix problems with older drivers and slightly lower latency, but lowers security.",
        );
        if st.hvci_note_visible {
            hvci = hvci.row(note("Enable VBS first to turn on Memory Integrity."));
        }
        hvci = hvci.actions(vec![
            Control::enable("hvci.enable").enabled(st.hvci_enable_enabled),
            Control::disable("hvci.disable"),
        ]);
        m = m.card(hvci);
        let spectre = card_with_desc(
            &st,
            "spectre",
            "Spectre / Meltdown Mitigations",
            "Windows protections against a group of CPU security flaws known as Spectre and Meltdown. Disabling them can improve performance, mostly on older CPUs, but lowers security. Requires a restart.",
        )
        .row(note(
            "Note: Newer CPUs lose little speed to these protections, so the gain on them is small. Not recommended on PCs shared with other people.",
        ))
        .enable_disable("spectre");
        m = m.card(spectre);
        m = m.card(toggle_card(
            &st,
            "hyperv",
            "Hyper-V",
            "Windows' built-in virtualization. Needed by WSL2, Docker Desktop, Windows Sandbox and some Android emulators. Disabling it removes virtual machine support. Requires a restart.",
        ));
        m = m.card(toggle_card(
            &st,
            "rdp",
            "Remote Desktop (RDP)",
            "Lets other computers connect to this PC with Windows Remote Desktop. Apps like Parsec, AnyDesk and TeamViewer do not need it. Disabling it closes a common way into the PC from the network.",
        ));
        m = m.card(
            card_with_desc(
                &st,
                "wsearch",
                "Windows Search",
                "Disable Indexing stops Windows from indexing your files, so file searches are slower but there is less disk activity. Disable Search also turns off the search box in the taskbar and Start menu. Requires a restart.",
            )
            .actions(vec![
                Control::enable("wsearch.enable"),
                Control::button("wsearch.indexing", "Disable Indexing", BtnStyle::Disable),
                Control::button("wsearch.search", "Disable Search", BtnStyle::Disable),
            ]),
        );
        m = m.card(
            card_with_desc(
                &st,
                "svcsplit",
                "Service Grouping (Svchost Split)",
                "Controls how Windows groups its services into shared processes. Default is how Windows does it. Recommended groups more services together to save some RAM while keeping important ones separate. Forced groups everything for the lowest RAM use, but can break features like Xbox services.",
            )
            .actions(vec![
                Control::button("svcsplit.forced", "Forced", BtnStyle::Warning),
                Control::button("svcsplit.recommended", "Recommended", BtnStyle::Enable),
                Control::button("svcsplit.default", "Default", BtnStyle::Action),
            ]),
        );
        m = m.card(
            card_with_desc(
                &st,
                "pspolicy",
                "PowerShell Execution Policy",
                "Controls whether PowerShell scripts can run. XOS sets Unrestricted so its scripts run without prompts. Restricted blocks all scripts and is the Windows default. RemoteSigned runs your own scripts but blocks unsigned ones downloaded from the internet, a good balance of safety.",
            )
            .actions(vec![
                Control::button("pspolicy.restricted", "Restricted", BtnStyle::Disable),
                Control::button("pspolicy.remotesigned", "RemoteSigned", BtnStyle::Enable),
                Control::button("pspolicy.unrestricted", "Unrestricted", BtnStyle::Action),
            ]),
        );
        m = m.card(
            card_with_desc(
                &st,
                "bgmsgrate",
                "Background Message Rate Limit",
                "Limits how often apps in the background receive mouse movement. The Windows default is 125 Hz. 50 Hz can save a little CPU with high polling rate mice, but apps that read the mouse from the background, like overlays or macro tools, may feel choppy. Windows 11 23H2 and newer only. Experimental.",
            )
            .visible(st.bg_msg_visible)
            .actions(vec![
                Control::combo(
                    "bgmsgrate.combo",
                    BG_MSG_OPTIONS.iter().map(|s| s.to_string()).collect(),
                    st.bg_msg_selected,
                )
                .width(160.0),
                Control::button("bgmsgrate.apply", "Apply", BtnStyle::Action),
            ]),
        );

        m.overlay(st.overlay.clone())
    }

    fn refresh(&self, host: &dyn Host) {
        self.refresh_states(host);
    }

    fn handle(&self, host: &dyn Host, event: &Event) {
        match (event.control.as_str(), &event.kind) {
            ("bgmsgrate.combo", EventKind::Select(i)) => {
                self.st.lock().unwrap().bg_msg_selected = *i;
                return;
            }
            (_, EventKind::Click) => {}
            _ => return,
        }
        match event.control.as_str() {
            "uac.enable" => self.uac_enable(host),
            "uac.disable" => self.uac_disable(host),
            "defender.enable" => self.defender_click(host, true),
            "defender.disable" => self.defender_click(host, false),
            "bgapps.enable" => self.bg_apps_enable(host),
            "bgapps.disable" => self.bg_apps_disable(host),
            "notif.enable" => self.notif_enable(host),
            "notif.disable" => self.notif_disable(host),
            "power.enable" => self.power_enable(host),
            "power.disable" => self.power_disable(host),
            "xosplan.add" => self.xos_plan_import(host),
            "xosplan.remove" => self.xos_plan_remove(host),
            "hibernate.enable" => self.hibernate_enable(host),
            "hibernate.disable" => self.hibernate_disable(host),
            "gpumon.enable" => self.gpu_mon_enable(host),
            "gpumon.disable" => self.gpu_mon_disable(host),
            "usagerep.enable" => self.usage_rep_enable(host),
            "usagerep.disable" => self.usage_rep_disable(host),
            "vbs.enable" => self.vbs_enable(host),
            "vbs.disable" => self.vbs_disable(host),
            "vbs.forcedisable" => self.vbs_force_disable(host),
            "hvci.enable" => self.hvci_enable(host),
            "hvci.disable" => self.hvci_disable(host),
            "spectre.enable" => self.spectre_enable(host),
            "spectre.disable" => self.spectre_disable(host),
            "hyperv.enable" => self.hyper_v_run(host, true),
            "hyperv.disable" => self.hyper_v_run(host, false),
            "rdp.enable" => self.rdp_enable(host),
            "rdp.disable" => self.rdp_disable(host),
            "wsearch.enable" => self.wsearch_enable(host),
            "wsearch.indexing" => self.wsearch_disable_indexing(host),
            "wsearch.search" => self.wsearch_disable_search(host),
            "svcsplit.forced" => self.svc_split_forced(host),
            "svcsplit.recommended" => self.svc_split_recommended(host),
            "svcsplit.default" => self.svc_split_default(host),
            "pspolicy.restricted" => self.set_ps_policy(host, "Restricted"),
            "pspolicy.remotesigned" => self.set_ps_policy(host, "RemoteSigned"),
            "pspolicy.unrestricted" => self.set_ps_policy(host, "Unrestricted"),
            "bgmsgrate.apply" => self.bg_msg_rate_apply(host),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_has_all_cards() {
        let page = SystemPage::new();
        let m = page.model();
        assert_eq!(m.id, "System");
        assert_eq!(m.cards.len(), 18);
        assert_eq!(page.label(), "System");
        for id in CARD_IDS {
            assert!(m.cards.iter().any(|c| c.id == id), "{id}");
        }
        let hidden = m.cards.iter().find(|c| c.id == "bgmsgrate").unwrap();
        assert_eq!(hidden.visible, get_windows_build_number() >= 22621);
    }

    #[test]
    fn hyper_v_disabled_states() {
        assert!(is_hyper_v_feature_disabled("Disabled"));
        assert!(is_hyper_v_feature_disabled("Disable Pending"));
        assert!(is_hyper_v_feature_disabled("Not_Present"));
        assert!(is_hyper_v_feature_disabled("Disabled with Payload Removed"));
        assert!(!is_hyper_v_feature_disabled("Enabled"));
        assert!(!is_hyper_v_feature_disabled(" "));
    }

    #[test]
    fn security_labels() {
        assert_eq!(security_badge_label(-1, None), "Unknown");
        assert_eq!(security_badge_label(2, Some(1)), "Enabled");
        assert_eq!(security_badge_label(2, None), "Enabled");
        assert_eq!(security_badge_label(2, Some(0)), "Disable Pending Reboot");
        assert_eq!(
            security_badge_label(1, Some(1)),
            "Enabled (Restart Required)"
        );
        assert_eq!(security_badge_label(1, None), "Disabled");
        assert_eq!(
            security_badge_label(0, Some(1)),
            "Enabled (Restart Required)"
        );
        assert_eq!(security_badge_label(0, Some(0)), "Disabled");
        assert_eq!(security_badge_label(5, None), "Partial");
    }

    #[test]
    fn hz_rounding() {
        assert_eq!((1000.0f64 / 8.0).round_ties_even() as i32, 125);
        assert_eq!((1000.0f64 / 20.0).round_ties_even() as i32, 50);
        assert_eq!((1000.0f64 / 16.0).round_ties_even() as i32, 62);
    }

    #[test]
    fn stock_split_has_core_services() {
        let s = stock_split_disabled();
        assert!(s.iter().any(|x| x == "BFE"));
        assert!(s.iter().any(|x| x == "PlugPlay"));
    }

    #[test]
    fn wmi_readers_work() {
        let running = get_vbs_running_status();
        let status = get_hvci_status();
        let pre = hypervisor_preflight("VBS");
        println!(
            "vbs={running} hvci={status} blocked={} risks={}",
            pre.blocked,
            pre.risks.len()
        );
        assert!((-1..=2).contains(&running));
    }
}

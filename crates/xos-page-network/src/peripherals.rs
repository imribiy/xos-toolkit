use std::sync::Mutex;

use anyhow::{anyhow, bail, Result};
use base64_free::encode_utf16_base64;
use regex::Regex;
use windows::core::PCWSTR;
use windows::Win32::Devices::DeviceAndDriverInstallation::{
    CM_Get_Device_IDW, CM_Get_Device_ID_Size, CM_Get_Parent, CM_Locate_DevNodeW,
    CM_LOCATE_DEVNODE_FLAGS,
};
use winreg::enums::{RegType, HKEY_LOCAL_MACHINE, KEY_READ};
use winreg::RegKey;
use xos_core::catalog;
use xos_core::host::{Buttons, DialogResult, Host, Icon, Page};
use xos_core::log;
use xos_core::status;
use xos_core::ui::*;
use xos_helpers::card_state_helper;
use xos_sys::ops;

use crate::common::{done, mark_failure_if_present, require_service, strings};
use crate::write_cache_script::{SCRIPT_HEAD, SCRIPT_REST};

const SERIAL_DEVICE_FILTER: &str = "$_.Class -eq 'Ports'";
const CLIP_POL: &str = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\System";
const CLIPBOARD_KEY: &str = r"HKCU\Software\Microsoft\Clipboard";
const TOAST_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications";
const KBD_KEY: &str = r"HKCU\Control Panel\Keyboard";
const MIRACAST_KEY: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers";
const POWER_SCHEMES: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes";
const SUB_USB: &str = "2a737441-1930-4402-8d77-b2bebba308a3";
const SET_USBLINK: &str = "48e6b7a6-50f5-4782-a5d4-53bb8f07e226";
const DISK_CLASS_GUID: &str = "{4d36e967-e325-11ce-bfc1-08002be10318}";
const CONFIG_RET_SUCCESS: u32 = 0;

const SERIAL_SERVICES: [(&str, i32); 5] = [
    ("Serenum", 3),
    ("Serial", 3),
    ("sermouse", 3),
    ("usbser", 3),
    ("Parport", 3),
];

const PRINT_SERVICES: [(&str, i32); 7] = [
    ("Spooler", 2),
    ("StiSvc", 3),
    ("PrintWorkFlowUserSvc", 3),
    ("PrintNotify", 3),
    ("usbprint", 3),
    ("PrintScanBrokerService", 3),
    ("PrintDeviceConfigurationService", 3),
];

mod base64_free {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    pub fn encode_utf16_base64(text: &str) -> String {
        let mut bytes = Vec::with_capacity(text.len() * 2);
        for u in text.encode_utf16() {
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
        for chunk in bytes.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = *chunk.get(1).unwrap_or(&0) as u32;
            let b2 = *chunk.get(2).unwrap_or(&0) as u32;
            let n = (b0 << 16) | (b1 << 8) | b2;
            out.push(TABLE[((n >> 18) & 63) as usize] as char);
            out.push(TABLE[((n >> 12) & 63) as usize] as char);
            if chunk.len() > 1 {
                out.push(TABLE[((n >> 6) & 63) as usize] as char);
            } else {
                out.push('=');
            }
            if chunk.len() > 2 {
                out.push(TABLE[(n & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
        out
    }
}

struct State {
    usb: String,
    clip: String,
    print: String,
    serial: String,
    miracast: String,
    write_cache: String,
    busy: Option<String>,
}

pub struct PeripheralsPage {
    st: Mutex<State>,
}

impl Default for PeripheralsPage {
    fn default() -> Self {
        Self::new()
    }
}

pub fn usb_power_state(
    values: &[Option<i32>],
    disabled_values: &[i32],
    ac: Option<i32>,
    dc: Option<i32>,
) -> &'static str {
    let disabled = values
        .iter()
        .zip(disabled_values.iter())
        .all(|(v, d)| *v == Some(*d))
        && ac == Some(0)
        && dc == Some(0);
    if disabled {
        return "Disabled";
    }
    if values.iter().all(|v| v.is_none()) && ac == Some(1) && dc == Some(1) {
        return "Enabled";
    }
    if values.iter().all(|v| v.is_none()) && ac.is_none() && dc.is_none() {
        return "N/A";
    }
    "Partial"
}

#[allow(clippy::too_many_arguments)]
pub fn clipboard_state_from(
    clipboard: i32,
    policy: Option<i32>,
    user_enabled: Option<i32>,
    wpn: i32,
    wpn_user: i32,
    toast: Option<i32>,
) -> Option<&'static str> {
    if clipboard < 0 {
        return None;
    }
    let notifications_enabled =
        wpn >= 0 && wpn != 4 && wpn_user >= 0 && wpn_user != 4 && toast != Some(0);
    let no_explicit_override = policy.is_none() && user_enabled.is_none() && toast.is_none();
    if clipboard == 4 && policy != Some(1) && user_enabled != Some(1) {
        return Some("Disabled");
    }
    if no_explicit_override && clipboard != 4 && notifications_enabled {
        return Some("N/A");
    }
    if clipboard != 4 && policy == Some(1) && user_enabled == Some(1) && notifications_enabled {
        return Some("Enabled");
    }
    if clipboard == 4 && policy == Some(0) && user_enabled == Some(0) {
        return Some("Disabled");
    }
    Some("Partial")
}

pub fn managed_service_state(services: &[(i32, i32)]) -> &'static str {
    let mut present = 0;
    let mut disabled = 0;
    let mut enabled_defaults = true;
    for &(start, enabled_start) in services {
        if start < 0 {
            continue;
        }
        present += 1;
        if start == 4 {
            disabled += 1;
        }
        if start != enabled_start {
            enabled_defaults = false;
        }
    }
    if present == 0 {
        "N/A"
    } else if disabled == present {
        "Disabled"
    } else if enabled_defaults {
        "Enabled"
    } else {
        "Partial"
    }
}

pub fn miracast_state(value: Option<i32>) -> String {
    match value {
        None => status::ENABLED_WINDOWS_DEFAULT.to_string(),
        Some(0) => "Enabled".to_string(),
        Some(1) => "Disabled".to_string(),
        Some(_) => "Partial".to_string(),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheValue {
    Absent,
    Dword(i32),
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiskEntry {
    MissingInstance,
    NoParameters,
    Parameters(CacheValue, CacheValue),
}

pub fn write_cache_state_from(disks: &[DiskEntry]) -> &'static str {
    let mut disk_count = 0;
    let mut disabled_count = 0;
    let mut configured_count = 0;
    let mut inconsistent = false;
    for disk in disks {
        match disk {
            DiskEntry::MissingInstance => return "Unknown",
            DiskEntry::NoParameters => {
                disk_count += 1;
            }
            DiskEntry::Parameters(user, power) => {
                disk_count += 1;
                if *user != CacheValue::Absent || *power != CacheValue::Absent {
                    configured_count += 1;
                }
                if *user == CacheValue::Other || *power == CacheValue::Other {
                    return "Unknown";
                }
                let user_disabled = *user == CacheValue::Dword(1);
                let protected_cache = *power == CacheValue::Dword(1);
                if user_disabled && protected_cache {
                    disabled_count += 1;
                } else if user_disabled || protected_cache {
                    inconsistent = true;
                }
            }
        }
    }
    if disk_count == 0 {
        "N/A"
    } else if configured_count == 0 {
        "Automatic"
    } else if configured_count != disk_count {
        "Partial"
    } else if !inconsistent && disabled_count == disk_count {
        "Disabled"
    } else if !inconsistent && disabled_count == 0 {
        "Enabled"
    } else {
        "Partial"
    }
}

fn hklm() -> RegKey {
    RegKey::predef(HKEY_LOCAL_MACHINE)
}

fn open_or_none(root: &RegKey, path: &str) -> std::io::Result<Option<RegKey>> {
    match root.open_subkey_with_flags(path, KEY_READ) {
        Ok(k) => Ok(Some(k)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

fn cache_value(key: &RegKey, name: &str) -> std::io::Result<CacheValue> {
    match key.get_raw_value(name) {
        Ok(raw) => {
            if raw.vtype == RegType::REG_DWORD && raw.bytes.len() >= 4 {
                Ok(CacheValue::Dword(i32::from_le_bytes([
                    raw.bytes[0],
                    raw.bytes[1],
                    raw.bytes[2],
                    raw.bytes[3],
                ])))
            } else {
                Ok(CacheValue::Other)
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(CacheValue::Absent),
        Err(e) => Err(e),
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn get_device_id(device_instance: u32) -> Option<String> {
    let mut length: u32 = 0;
    if unsafe { CM_Get_Device_ID_Size(&mut length, device_instance, 0) }.0 != CONFIG_RET_SUCCESS {
        return None;
    }
    let mut buffer = vec![0u16; length as usize + 1];
    if unsafe { CM_Get_Device_IDW(device_instance, &mut buffer, 0) }.0 != CONFIG_RET_SUCCESS {
        return None;
    }
    let end = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
    Some(String::from_utf16_lossy(&buffer[..end]))
}

fn is_present_non_usb_device(instance_id: &str) -> bool {
    let w = wide(instance_id);
    let mut node: u32 = 0;
    if unsafe { CM_Locate_DevNodeW(&mut node, PCWSTR(w.as_ptr()), CM_LOCATE_DEVNODE_FLAGS(0)) }.0
        != CONFIG_RET_SUCCESS
    {
        return false;
    }
    for _depth in 0..32 {
        let current_id = match get_device_id(node) {
            Some(id) if !id.is_empty() => id,
            _ => return false,
        };
        let upper = current_id.to_uppercase();
        if upper.starts_with(r"USB\") || upper.starts_with(r"USBSTOR\") {
            return false;
        }
        let mut parent: u32 = 0;
        if unsafe { CM_Get_Parent(&mut parent, node, 0) }.0 != CONFIG_RET_SUCCESS {
            break;
        }
        node = parent;
    }
    true
}

pub fn present_internal_disk_instance_ids() -> std::io::Result<Vec<String>> {
    let mut results = Vec::new();
    let root = hklm();
    let enum_key = match open_or_none(&root, r"SYSTEM\CurrentControlSet\Enum")? {
        Some(k) => k,
        None => return Ok(results),
    };
    for bus_name in enum_key.enum_keys().collect::<std::io::Result<Vec<_>>>()? {
        let bus_key = match open_or_none(&enum_key, &bus_name)? {
            Some(k) => k,
            None => continue,
        };
        for dev_name in bus_key.enum_keys().collect::<std::io::Result<Vec<_>>>()? {
            let dev_key = match open_or_none(&bus_key, &dev_name)? {
                Some(k) => k,
                None => continue,
            };
            for inst_name in dev_key.enum_keys().collect::<std::io::Result<Vec<_>>>()? {
                let class_guid: Option<String> = match open_or_none(&dev_key, &inst_name)? {
                    Some(inst_key) => inst_key.get_value("ClassGUID").ok(),
                    None => None,
                };
                if !class_guid
                    .map(|g| g.eq_ignore_ascii_case(DISK_CLASS_GUID))
                    .unwrap_or(false)
                {
                    continue;
                }
                let instance_id = format!(r"{bus_name}\{dev_name}\{inst_name}");
                if is_present_non_usb_device(&instance_id) {
                    results.push(instance_id);
                }
            }
        }
    }
    Ok(results)
}

fn read_write_cache_state() -> std::io::Result<&'static str> {
    let mut disks = Vec::new();
    let root = hklm();
    for instance_id in present_internal_disk_instance_ids()? {
        let inst_key = match open_or_none(
            &root,
            &format!(r"SYSTEM\CurrentControlSet\Enum\{instance_id}"),
        )? {
            Some(k) => k,
            None => {
                disks.push(DiskEntry::MissingInstance);
                return Ok(write_cache_state_from(&disks));
            }
        };
        match open_or_none(&inst_key, r"Device Parameters\Disk")? {
            None => disks.push(DiskEntry::NoParameters),
            Some(dp) => {
                let user = cache_value(&dp, "UserWriteCacheSetting")?;
                let power = cache_value(&dp, "CacheIsPowerProtected")?;
                disks.push(DiskEntry::Parameters(user, power));
            }
        }
    }
    Ok(write_cache_state_from(&disks))
}

pub fn get_write_cache_flushing_state() -> &'static str {
    read_write_cache_state().unwrap_or("Unknown")
}

pub fn build_write_cache_ps_script(disable: bool, instance_ids: &[String]) -> String {
    let mut id_list = String::new();
    for instance_id in instance_ids {
        if !id_list.is_empty() {
            id_list.push(',');
        }
        id_list.push('\'');
        id_list.push_str(&instance_id.replace('\'', "''"));
        id_list.push('\'');
    }
    format!(
        "{SCRIPT_HEAD}$ids=@({id_list}); $disable=${}; {SCRIPT_REST}",
        if disable { "true" } else { "false" }
    )
}

fn apply_write_cache_settings(disable: bool) -> Result<()> {
    let instance_ids = present_internal_disk_instance_ids().map_err(|e| anyhow!("{e}"))?;
    if instance_ids.is_empty() {
        bail!("No present internal disk devices were found.");
    }
    let ps = build_write_cache_ps_script(disable, &instance_ids);
    let b64 = encode_utf16_base64(&ps);
    let launched = xos_sys::run_as_ti(
        "powershell.exe",
        &format!("-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {b64}"),
    );
    if !launched {
        bail!("The TrustedInstaller write-cache operation failed.");
    }
    let actual = get_write_cache_flushing_state();
    let matches = if disable {
        actual == "Disabled"
    } else {
        actual == "Enabled" || actual == "Automatic"
    };
    if !matches {
        bail!("Write-cache settings were only partially applied. Current state: {actual}.");
    }
    Ok(())
}

fn get_usb_power_saving_state() -> &'static str {
    let entries = card_state_helper::USB_POWER_REGISTRY;
    let values: Vec<Option<i32>> = entries
        .iter()
        .map(|(key, name, _)| xos_sys::reg_get_dword(key, name))
        .collect();
    let disabled_values: Vec<i32> = entries.iter().map(|(_, _, d)| *d).collect();
    let active_scheme = xos_sys::reg_get_string(POWER_SCHEMES, "ActivePowerScheme");
    let setting_path = match active_scheme {
        Some(s) if !s.trim().is_empty() => {
            Some(format!(r"{POWER_SCHEMES}\{s}\{SUB_USB}\{SET_USBLINK}"))
        }
        _ => None,
    };
    let ac = setting_path
        .as_ref()
        .and_then(|p| xos_sys::reg_get_dword(p, "ACSettingIndex"));
    let dc = setting_path
        .as_ref()
        .and_then(|p| xos_sys::reg_get_dword(p, "DCSettingIndex"));
    usb_power_state(&values, &disabled_values, ac, dc)
}

fn get_clipboard_state() -> String {
    let clipboard = xos_sys::get_service_start_type("cbdhsvc");
    if clipboard < 0 {
        return status::service("cbdhsvc");
    }
    let policy = xos_sys::reg_get_dword(CLIP_POL, "AllowClipboardHistory");
    let user_enabled = xos_sys::reg_get_dword(CLIPBOARD_KEY, "EnableClipboardHistory");
    let wpn = xos_sys::get_service_start_type("WpnService");
    let wpn_user = xos_sys::get_service_start_type("WpnUserService");
    let toast = xos_sys::reg_get_dword(TOAST_KEY, "ToastEnabled");
    clipboard_state_from(clipboard, policy, user_enabled, wpn, wpn_user, toast)
        .unwrap_or("Partial")
        .to_string()
}

fn get_managed_service_state(services: &[(&str, i32)]) -> &'static str {
    let starts: Vec<(i32, i32)> = services
        .iter()
        .map(|(name, enabled)| (xos_sys::get_service_start_type(name), *enabled))
        .collect();
    managed_service_state(&starts)
}

fn configure_required_service(service: &str, start_type: i32) -> bool {
    xos_sys::service_exists(service) && xos_sys::config_service_reg(service, start_type)
}

fn is_service_running(service: &str) -> bool {
    let output = xos_sys::run_cmd_output("sc.exe", &format!("query \"{service}\""));
    Regex::new(r":\s*4\s+")
        .map(|r| r.is_match(&output))
        .unwrap_or(false)
}

fn print_enable() -> Result<()> {
    require_service("Spooler", "Printing")?;
    let mut failed = false;
    mark_failure_if_present(
        "Spooler",
        || xos_sys::config_service_sc("Spooler", "auto"),
        &mut failed,
    );
    mark_failure_if_present(
        "StiSvc",
        || xos_sys::config_service_sc("StiSvc", "demand"),
        &mut failed,
    );
    for name in [
        "PrintWorkFlowUserSvc",
        "PrintNotify",
        "usbprint",
        "PrintScanBrokerService",
        "PrintDeviceConfigurationService",
    ] {
        mark_failure_if_present(name, || xos_sys::config_service_reg(name, 3), &mut failed);
    }
    if !xos_sys::enable_tasks_batch(&strings(catalog::PRINT_TASKS)) {
        failed = true;
    }

    let states = xos_sys::get_all_feature_states();
    if states.is_empty() {
        failed = true;
    }
    for f in catalog::PRINT_FEATURES {
        let st = match states.get(f) {
            Some(s) => s,
            None => continue,
        };
        if !xos_sys::is_feature_state_enabled(st) && !xos_sys::enable_feature(f) {
            failed = true;
        }
    }
    if failed {
        bail!("One or more printing components could not be enabled.");
    }

    if !is_service_running("Spooler")
        && !xos_sys::start_service("Spooler")
        && !is_service_running("Spooler")
    {
        bail!("The Print Spooler service could not be started.");
    }
    Ok(())
}

fn print_disable() -> Result<()> {
    require_service("Spooler", "Printing")?;
    let mut failed = false;
    xos_sys::stop_service("Spooler");
    mark_failure_if_present(
        "Spooler",
        || xos_sys::config_service_sc("Spooler", "disabled"),
        &mut failed,
    );
    mark_failure_if_present(
        "StiSvc",
        || xos_sys::config_service_sc("StiSvc", "disabled"),
        &mut failed,
    );
    for name in [
        "PrintWorkFlowUserSvc",
        "PrintNotify",
        "usbprint",
        "PrintScanBrokerService",
        "PrintDeviceConfigurationService",
    ] {
        mark_failure_if_present(name, || xos_sys::config_service_reg(name, 4), &mut failed);
    }

    let states = xos_sys::get_all_feature_states();
    if states.is_empty() {
        failed = true;
    }
    for f in catalog::PRINT_FEATURES.iter().rev() {
        let st = match states.get(f) {
            Some(s) => s,
            None => continue,
        };
        if xos_sys::is_feature_state_enabled(st) && !xos_sys::disable_feature(f) {
            failed = true;
        }
    }

    if !xos_sys::disable_tasks_batch(&strings(catalog::PRINT_TASKS)) {
        failed = true;
    }
    if failed {
        bail!("One or more printing components could not be disabled.");
    }
    Ok(())
}

fn serial_enable() -> Result<()> {
    require_service("Serial", "Serial ports")?;
    let mut failed = false;
    for (name, start) in SERIAL_SERVICES {
        mark_failure_if_present(
            name,
            || xos_sys::config_service_reg(name, start),
            &mut failed,
        );
    }
    if !xos_sys::set_pnp_devices(true, SERIAL_DEVICE_FILTER, true) {
        failed = true;
    }
    if failed {
        bail!("Serial ports could not be fully enabled.");
    }
    Ok(())
}

fn serial_disable() -> Result<()> {
    require_service("Serial", "Serial ports")?;
    let mut failed = false;
    for (name, _) in SERIAL_SERVICES {
        mark_failure_if_present(name, || xos_sys::config_service_reg(name, 4), &mut failed);
    }
    if !xos_sys::set_pnp_devices(false, SERIAL_DEVICE_FILTER, false) {
        failed = true;
    }
    if failed {
        bail!("Serial ports could not be fully disabled.");
    }
    Ok(())
}

impl PeripheralsPage {
    pub fn new() -> Self {
        Self {
            st: Mutex::new(State {
                usb: "Checking".into(),
                clip: "Checking".into(),
                print: "Checking".into(),
                serial: "Checking".into(),
                miracast: "Checking".into(),
                write_cache: "Checking".into(),
                busy: None,
            }),
        }
    }

    pub fn refresh_states(&self) {
        let usb = get_usb_power_saving_state().to_string();
        let clip = get_clipboard_state();
        let print = get_managed_service_state(&PRINT_SERVICES).to_string();
        let serial = get_managed_service_state(&SERIAL_SERVICES).to_string();
        let miracast = miracast_state(xos_sys::reg_get_dword(MIRACAST_KEY, "MiracastForceDisable"));
        let write_cache = get_write_cache_flushing_state().to_string();
        let mut st = self.st.lock().unwrap();
        st.usb = usb;
        st.clip = clip;
        st.print = print;
        st.serial = serial;
        st.miracast = miracast;
        st.write_cache = write_cache;
    }

    fn run_busy(
        &self,
        host: &dyn Host,
        busy_message: &str,
        operation: impl FnOnce() -> Result<()>,
        success_message: &str,
    ) {
        let _op = xos_core::app_state::operation();
        self.st.lock().unwrap().busy = Some(busy_message.to_string());
        host.publish(self.model());
        host.set_status(busy_message);
        match operation() {
            Ok(()) => {
                self.refresh_states();
                host.publish(self.model());
                done(host, "Peripherals", success_message, false);
            }
            Err(ex) => {
                log::exception(busy_message, &format!("{ex:?}"));
                ops::reset();
                host.set_status("Peripheral operation failed.");
                host.dialog(
                    &format!("The peripheral operation failed.\n\n{ex}"),
                    "XOS Toolkit",
                    Buttons::Ok,
                    Icon::Error,
                );
            }
        }
        self.st.lock().unwrap().busy = None;
        host.publish(self.model());
    }

    fn finish_sync(&self, host: &dyn Host, message: &str, operation_failed: bool) {
        self.refresh_states();
        host.publish(self.model());
        done(host, "Peripherals", message, operation_failed);
    }

    fn usb_toggle(&self, host: &dyn Host, disable: bool) {
        ops::reset();
        card_state_helper::write_usb_power_registry(disable);
        let value = if disable { 0 } else { 1 };
        let operation_ok = xos_sys::power_cfg_set(SUB_USB, SET_USBLINK, value, value);
        self.finish_sync(
            host,
            if disable {
                "USB power saving disabled. USB devices will stay fully powered at all times. Please reboot."
            } else {
                "USB power saving enabled (Windows default). If you experience random disconnects, disable this option. Please reboot."
            },
            !operation_ok,
        );
    }

    fn clip_enable(&self, host: &dyn Host) {
        ops::reset();
        let mut operation_ok = configure_required_service("cbdhsvc", 3);
        operation_ok &= configure_required_service("WpnService", 2);
        operation_ok &= configure_required_service("WpnUserService", 2);
        xos_sys::reg_set_dword(CLIP_POL, "AllowClipboardHistory", 1);
        xos_sys::reg_set_dword(CLIPBOARD_KEY, "EnableClipboardHistory", 1);
        xos_sys::reg_set_dword(TOAST_KEY, "ToastEnabled", 1);

        let map_prt_scn = host.dialog(
            "Do you want to map the Print Screen key to Snipping Tool?",
            "Print Screen Key",
            Buttons::YesNo,
            Icon::Question,
        );
        xos_sys::reg_set_dword(
            KBD_KEY,
            "PrintScreenKeyForSnippingEnabled",
            if map_prt_scn == DialogResult::Yes {
                1
            } else {
                0
            },
        );

        self.finish_sync(
            host,
            "Clipboard & Snipping Tool enabled. Please reboot.",
            !operation_ok,
        );
    }

    fn clip_disable_keep_notifications(&self, host: &dyn Host) {
        ops::reset();
        let operation_ok = configure_required_service("cbdhsvc", 4);
        xos_sys::reg_set_dword(CLIP_POL, "AllowClipboardHistory", 0);
        xos_sys::reg_set_dword(CLIPBOARD_KEY, "EnableClipboardHistory", 0);
        xos_sys::reg_set_dword(KBD_KEY, "PrintScreenKeyForSnippingEnabled", 0);
        self.finish_sync(
            host,
            "Clipboard disabled (notifications kept). Please reboot.",
            !operation_ok,
        );
    }

    fn clip_disable_all(&self, host: &dyn Host) {
        ops::reset();
        let mut operation_ok = configure_required_service("cbdhsvc", 4);

        let wpn_start = xos_sys::get_service_start_type("WpnService");
        let notif_enabled = wpn_start != 4 && wpn_start >= 0;
        let mut keep_wpn = false;

        if notif_enabled {
            let result = host.dialog(
                "The Windows Push Notification Service (WpnService) is also required by Notifications (System tab).\n\nWould you like to keep WpnService enabled?",
                "XOS Toolkit",
                Buttons::YesNo,
                Icon::Question,
            );
            keep_wpn = result == DialogResult::Yes;
        }

        if !keep_wpn {
            operation_ok &= configure_required_service("WpnService", 4);
            operation_ok &= configure_required_service("WpnUserService", 4);
            xos_sys::reg_set_dword(TOAST_KEY, "ToastEnabled", 0);
        }

        xos_sys::reg_set_dword(CLIP_POL, "AllowClipboardHistory", 0);
        xos_sys::reg_set_dword(CLIPBOARD_KEY, "EnableClipboardHistory", 0);
        xos_sys::reg_set_dword(KBD_KEY, "PrintScreenKeyForSnippingEnabled", 0);
        self.finish_sync(
            host,
            if keep_wpn {
                "Clipboard disabled (notifications kept). Please reboot."
            } else {
                "Clipboard & Notifications disabled. Please reboot."
            },
            !operation_ok,
        );
    }
}

impl Page for PeripheralsPage {
    fn id(&self) -> &'static str {
        "Peripherals"
    }

    fn label(&self) -> &'static str {
        "Peripherals"
    }

    fn model(&self) -> PageModel {
        let st = self.st.lock().unwrap();
        PageModel::new(
            "Peripherals",
            "Peripherals & Features",
            "USB power, printing, serial ports, and clipboard features",
        )
        .max_width(1080.0)
        .overlay(st.busy.clone())
        .card(
            Card::new(
                "usb",
                "USB Power Saving",
                "Lets USB devices go into low power mode when idle. If a mouse, keyboard or headset disconnects or stops responding at random, disable this.",
            )
            .badge(status::badge(&st.usb))
            .controls(vec![Control::muted(
                "This is also controlled by System > Power Savings. The most recent choice takes effect.",
            )
            .tone(Tone::Orange)])
            .enable_disable("usb"),
        )
        .card(
            Card::new(
                "clip",
                "Snipping Tool & Clipboard History",
                "Clipboard history (Win+V) and the Win+Shift+S screenshot tool. Snipping Tool needs notifications turned on to save your screenshots.",
            )
            .badge(status::badge(&st.clip))
            .controls(vec![Control::muted(
                "Snipping Tool should be installed and kept up to date through the Microsoft Store.",
            )])
            .actions(vec![
                Control::button("clip.enable", "Enable", BtnStyle::Enable),
                Control::button("clip.keep", "Disable (Keep Notifications)", BtnStyle::Warning),
                Control::button("clip.all", "Disable All", BtnStyle::Disable),
            ]),
        )
        .card(
            Card::new(
                "print",
                "Printing & Scanners",
                "Print and scan services and Windows printing features. Needed if you use a printer or scanner.",
            )
            .badge(status::badge(&st.print))
            .actions(vec![
                Control::button("print.enable", "Enable Printing", BtnStyle::Enable),
                Control::button("print.disable", "Disable Printing", BtnStyle::Disable),
            ]),
        )
        .card(
            Card::new(
                "serial",
                "Serial Ports",
                "COM and LPT port drivers. Only needed for older hardware that connects this way.",
            )
            .badge(status::badge(&st.serial))
            .controls(vec![Control::muted(
                "Some legacy touchpads and serial input devices depend on these drivers. Disabling can break affected hardware.",
            )
            .tone(Tone::Orange)])
            .actions(vec![
                Control::button("serial.enable", "Enable Serial Ports", BtnStyle::Enable),
                Control::button("serial.disable", "Disable Serial Ports", BtnStyle::Disable),
            ]),
        )
        .card(
            Card::new(
                "miracast",
                "Miracast",
                "Wireless screen casting to TVs, monitors and projectors over Wi-Fi. Needed for Win+K casting.",
            )
            .badge(status::badge(&st.miracast))
            .enable_disable("miracast"),
        )
        .card(
            Card::new(
                "writecache",
                "Write-Cache Buffer Flushing",
                "Controls whether Windows tells your drives to save cached data right away. Disabling it can speed up file writes, but if the PC loses power suddenly, recent files can be lost or damaged.",
            )
            .badge(status::badge(&st.write_cache))
            .controls(vec![Control::muted(
                "Do not disable if you experience power outages or use an unstable power supply. Applies to all internal non-USB storage devices.",
            )
            .tone(Tone::Orange)])
            .actions(vec![
                Control::button("writecache.enable", "Enable (Default)", BtnStyle::Enable),
                Control::button("writecache.disable", "Disable", BtnStyle::Disable),
            ]),
        )
    }

    fn refresh(&self, _host: &dyn Host) {
        self.refresh_states();
    }

    fn handle(&self, host: &dyn Host, event: &Event) {
        if event.kind != EventKind::Click {
            return;
        }
        match event.control.as_str() {
            "usb.enable" => self.usb_toggle(host, false),
            "usb.disable" => self.usb_toggle(host, true),
            "clip.enable" => self.clip_enable(host),
            "clip.keep" => self.clip_disable_keep_notifications(host),
            "clip.all" => self.clip_disable_all(host),
            "print.enable" => {
                ops::reset();
                self.run_busy(
                    host,
                    "Enabling printing features...",
                    print_enable,
                    "Printing enabled. Please reboot for full effect.",
                );
            }
            "print.disable" => {
                ops::reset();
                self.run_busy(
                    host,
                    "Disabling printing features...",
                    print_disable,
                    "Printing disabled. Please reboot for full effect.",
                );
            }
            "serial.enable" => {
                ops::reset();
                self.run_busy(
                    host,
                    "Enabling serial ports...",
                    serial_enable,
                    "Serial ports enabled. Please reboot.",
                );
            }
            "serial.disable" => {
                ops::reset();
                self.run_busy(
                    host,
                    "Disabling serial ports...",
                    serial_disable,
                    "Serial ports disabled. Please reboot.",
                );
            }
            "miracast.enable" => {
                ops::reset();
                xos_sys::reg_delete_value(MIRACAST_KEY, "MiracastForceDisable");
                self.finish_sync(host, "Miracast enabled.", false);
            }
            "miracast.disable" => {
                ops::reset();
                xos_sys::reg_set_dword(MIRACAST_KEY, "MiracastForceDisable", 1);
                self.finish_sync(host, "Miracast disabled.", false);
            }
            "writecache.enable" => {
                ops::reset();
                self.run_busy(
                    host,
                    "Enabling write-cache buffer flushing...",
                    || apply_write_cache_settings(false),
                    "Write-cache buffer flushing enabled (Windows default). Please reboot.",
                );
            }
            "writecache.disable" => {
                ops::reset();
                self.run_busy(
                    host,
                    "Disabling write-cache buffer flushing...",
                    || apply_write_cache_settings(true),
                    "Write-cache buffer flushing disabled. Please reboot.",
                );
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_known_vector() {
        assert_eq!(encode_utf16_base64("A"), "QQA=");
        assert_eq!(encode_utf16_base64("Hi!"), "SABpACEA");
    }

    #[test]
    fn usb_rules() {
        let dis = [0, 1, 0, 1, 0, 0];
        let all_dis: Vec<Option<i32>> = dis.iter().map(|d| Some(*d)).collect();
        assert_eq!(
            usb_power_state(&all_dis, &dis, Some(0), Some(0)),
            "Disabled"
        );
        assert_eq!(
            usb_power_state(&[None; 6], &dis, Some(1), Some(1)),
            "Enabled"
        );
        assert_eq!(usb_power_state(&[None; 6], &dis, None, None), "N/A");
        assert_eq!(usb_power_state(&all_dis, &dis, Some(1), Some(0)), "Partial");
    }

    #[test]
    fn clipboard_rules() {
        assert_eq!(clipboard_state_from(-1, None, None, 2, 2, None), None);
        assert_eq!(
            clipboard_state_from(4, Some(0), Some(0), 2, 2, None),
            Some("Disabled")
        );
        assert_eq!(clipboard_state_from(3, None, None, 2, 2, None), Some("N/A"));
        assert_eq!(
            clipboard_state_from(3, Some(1), Some(1), 2, 2, None),
            Some("Enabled")
        );
        assert_eq!(
            clipboard_state_from(3, Some(1), Some(1), 4, 2, None),
            Some("Partial")
        );
    }

    #[test]
    fn managed_rules() {
        assert_eq!(managed_service_state(&[(-1, 2)]), "N/A");
        assert_eq!(
            managed_service_state(&[(4, 2), (4, 3), (-1, 3)]),
            "Disabled"
        );
        assert_eq!(managed_service_state(&[(2, 2), (3, 3)]), "Enabled");
        assert_eq!(managed_service_state(&[(2, 2), (4, 3)]), "Partial");
        assert_eq!(managed_service_state(&[(3, 2)]), "Partial");
    }

    #[test]
    fn miracast_rules() {
        assert_eq!(miracast_state(None), "Enabled (Windows Default)");
        assert_eq!(miracast_state(Some(0)), "Enabled");
        assert_eq!(miracast_state(Some(1)), "Disabled");
        assert_eq!(miracast_state(Some(2)), "Partial");
    }

    #[test]
    fn write_cache_rules() {
        use CacheValue::*;
        use DiskEntry::*;
        assert_eq!(write_cache_state_from(&[]), "N/A");
        assert_eq!(write_cache_state_from(&[NoParameters]), "Automatic");
        assert_eq!(write_cache_state_from(&[MissingInstance]), "Unknown");
        assert_eq!(
            write_cache_state_from(&[Parameters(Dword(1), Dword(1))]),
            "Disabled"
        );
        assert_eq!(
            write_cache_state_from(&[Parameters(Dword(0), Dword(0))]),
            "Enabled"
        );
        assert_eq!(
            write_cache_state_from(&[Parameters(Dword(1), Absent)]),
            "Partial"
        );
        assert_eq!(
            write_cache_state_from(&[Parameters(Dword(1), Dword(1)), NoParameters]),
            "Partial"
        );
        assert_eq!(
            write_cache_state_from(&[Parameters(Other, Absent)]),
            "Unknown"
        );
    }

    #[test]
    fn script_assembly() {
        let ps = build_write_cache_ps_script(true, &["A\\B'C".to_string(), "D".to_string()]);
        assert!(ps.starts_with(
            "$ErrorActionPreference='Stop'; $ids=@('A\\B''C','D'); $disable=$true; $actor="
        ));
        assert!(ps.ends_with("exit 1 }"));
        assert!(build_write_cache_ps_script(false, &[]).contains("$ids=@(); $disable=$false; "));
    }

    #[test]
    fn model_shape() {
        let page = PeripheralsPage::new();
        let model = page.model();
        assert_eq!(model.id, "Peripherals");
        assert_eq!(model.cards.len(), 6);
        assert_eq!(page.label(), "Peripherals");
    }
}

use std::cmp::Ordering;
use std::io;

use anyhow::{anyhow, Result};
use windows::core::{HRESULT, PCWSTR};
use windows::Win32::Devices::DeviceAndDriverInstallation::{
    CM_Free_Log_Conf_Handle, CM_Free_Res_Des_Handle, CM_Get_First_Log_Conf, CM_Get_Next_Res_Des,
    CM_Get_Res_Des_Data, CM_Get_Res_Des_Data_Size, ResType_IRQ, SetupDiDestroyDeviceInfoList,
    SetupDiEnumDeviceInfo, SetupDiGetClassDevsW, SetupDiGetDeviceInstanceIdW,
    SetupDiGetDevicePropertyW, SetupDiGetDeviceRegistryPropertyW, ALLOC_LOG_CONF, BASIC_LOG_CONF,
    CM_LOG_CONF, CR_SUCCESS, DIGCF_ALLCLASSES, DIGCF_PRESENT, FILTERED_LOG_CONF, HDEVINFO,
    SETUP_DI_REGISTRY_PROPERTY, SPDRP_DEVICEDESC, SPDRP_FRIENDLYNAME, SP_DEVINFO_DATA,
};
use windows::Win32::Devices::Properties::DEVPROPTYPE;
use windows::Win32::Foundation::DEVPROPKEY;
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE, REG_DWORD, REG_SZ};
use winreg::{RegKey, RegValue};
use xos_core::log;
use xos_sys::run_as_ti;

const DEVICE_ROOT: &str = r"SYSTEM\CurrentControlSet\Enum";
const INTERRUPT_PATH: &str = r"Device Parameters\Interrupt Management";
const MSI_SUB_KEY: &str = "MessageSignaledInterruptProperties";
const AFFINITY_SUB_KEY: &str = "Affinity Policy";
const BACKUP_ROOT: &str = r"SOFTWARE\XOS Toolkit\MSI Mode";

const INTERRUPT_SUPPORT_PROPERTY: DEVPROPKEY = DEVPROPKEY {
    fmtid: windows::core::GUID::from_u128(0x3AB22E31_8264_4B4E_9AF5_A8D2D8E33E62),
    pid: 14,
};
const INTERRUPT_MAXIMUM_PROPERTY: DEVPROPKEY = DEVPROPKEY {
    fmtid: windows::core::GUID::from_u128(0x3AB22E31_8264_4B4E_9AF5_A8D2D8E33E62),
    pid: 15,
};

#[derive(Clone, Debug, Default)]
pub struct MsiDevice {
    pub name: String,
    pub instance_id: String,
    pub irq: String,
    pub irq_details: String,
    pub supported_modes: String,
    pub max_message_limit: i32,
    pub msi_capable: bool,
    pub supports_msi_x: bool,
    pub has_backup: bool,
    pub is_selected_for_restore: bool,
    pub is_msi_enabled: bool,
    pub message_limit_text: String,
    priority: String,
    initial_msi_enabled: bool,
    initial_message_limit_text: String,
    initial_priority: String,
}

fn normalize(value: &str) -> &str {
    value.trim()
}

impl MsiDevice {
    pub fn priority(&self) -> &str {
        &self.priority
    }

    pub fn set_priority(&mut self, value: &str) {
        self.priority = if value.trim().is_empty() {
            "Undefined".to_string()
        } else {
            value.to_string()
        };
    }

    pub fn max_message_limit_text(&self) -> String {
        if self.max_message_limit > 0 {
            self.max_message_limit.to_string()
        } else {
            String::new()
        }
    }

    pub fn can_edit_limit(&self) -> bool {
        self.msi_capable && self.is_msi_enabled && self.max_message_limit > 0
    }

    pub fn is_msi_dirty(&self) -> bool {
        self.is_msi_enabled != self.initial_msi_enabled
    }

    pub fn is_message_limit_dirty(&self) -> bool {
        normalize(&self.message_limit_text) != normalize(&self.initial_message_limit_text)
    }

    pub fn is_priority_dirty(&self) -> bool {
        self.priority != self.initial_priority
    }

    pub fn is_dirty(&self) -> bool {
        self.is_msi_dirty() || self.is_message_limit_dirty() || self.is_priority_dirty()
    }

    pub fn mark_clean(&mut self) {
        if !self.is_msi_enabled && !self.message_limit_text.is_empty() {
            self.message_limit_text.clear();
        }
        self.initial_msi_enabled = self.is_msi_enabled;
        self.initial_message_limit_text = normalize(&self.message_limit_text).to_string();
        self.initial_priority = self.priority.clone();
        self.has_backup = true;
    }

    pub fn mark_initial(&mut self) {
        self.initial_msi_enabled = self.is_msi_enabled;
        self.initial_message_limit_text = self.message_limit_text.clone();
        self.initial_priority = self.priority.clone();
    }
}

#[derive(Clone, Debug, Default)]
pub struct MsiApplyResult {
    pub applied: i32,
    pub failed: i32,
    pub errors: Vec<String>,
    pub applied_instance_ids: Vec<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct RegistryState {
    present: bool,
    value: i32,
}

#[derive(Clone, Copy, Debug, Default)]
struct DeviceBackup {
    msi_present: bool,
    msi_value: i32,
    limit_present: bool,
    limit_value: i32,
    priority_present: bool,
    priority_value: i32,
}

pub fn read_devices() -> Result<Vec<MsiDevice>> {
    let mut result: Vec<MsiDevice> = Vec::new();
    let info_set = unsafe {
        SetupDiGetClassDevsW(
            None,
            PCWSTR::null(),
            None,
            windows::Win32::Devices::DeviceAndDriverInstallation::SETUP_DI_GET_CLASS_DEVS_FLAGS(
                DIGCF_PRESENT.0 | DIGCF_ALLCLASSES.0,
            ),
        )
    }
    .map_err(|_| anyhow!("Windows could not enumerate installed devices."))?;

    let outcome = (|| -> Result<()> {
        let mut index: u32 = 0;
        loop {
            let mut info = SP_DEVINFO_DATA {
                cbSize: std::mem::size_of::<SP_DEVINFO_DATA>() as u32,
                ..Default::default()
            };
            if let Err(e) = unsafe { SetupDiEnumDeviceInfo(info_set, index, &mut info) } {
                if e.code() != HRESULT::from_win32(259) {
                    return Err(anyhow!(
                        "Windows stopped while enumerating installed devices."
                    ));
                }
                break;
            }
            index += 1;

            let irq_values = read_irq_values(info.DevInst);
            if irq_values.is_empty() {
                continue;
            }
            let instance_id = match read_instance_id(info_set, &info) {
                Some(v) if !v.trim().is_empty() => v,
                _ => continue,
            };
            if !instance_id.to_uppercase().starts_with("PCI\\") {
                continue;
            }
            let mut name = read_registry_property_string(info_set, &info, SPDRP_FRIENDLYNAME)
                .unwrap_or_default();
            if name.trim().is_empty() {
                name = read_registry_property_string(info_set, &info, SPDRP_DEVICEDESC)
                    .unwrap_or_default();
            }
            if name.trim().is_empty() {
                name = instance_id.clone();
            }
            let interrupt_support =
                read_device_property_u32(info_set, &info, &INTERRUPT_SUPPORT_PROPERTY);
            let maximum = read_device_property_u32(info_set, &info, &INTERRUPT_MAXIMUM_PROPERTY);
            let msi_capable = (interrupt_support & 0x06) != 0;
            if !msi_capable {
                continue;
            }
            let interrupt_base = format!("{DEVICE_ROOT}\\{instance_id}\\{INTERRUPT_PATH}");
            let msi_value = read_dword(&format!("{interrupt_base}\\{MSI_SUB_KEY}"), "MSISupported");
            let limit_value = read_dword(
                &format!("{interrupt_base}\\{MSI_SUB_KEY}"),
                "MessageNumberLimit",
            );
            let priority_value = read_dword(
                &format!("{interrupt_base}\\{AFFINITY_SUB_KEY}"),
                "DevicePriority",
            );
            let mut device = MsiDevice {
                name,
                instance_id: instance_id.clone(),
                irq: format_irq(irq_values[0]),
                irq_details: irq_values
                    .iter()
                    .map(|v| format_irq(*v))
                    .collect::<Vec<_>>()
                    .join(", "),
                supported_modes: format_interrupt_modes(interrupt_support),
                max_message_limit: if maximum > i32::MAX as u32 {
                    i32::MAX
                } else {
                    maximum as i32
                },
                msi_capable,
                supports_msi_x: (interrupt_support & 0x04) != 0,
                has_backup: backup_exists(&instance_id),
                is_msi_enabled: msi_capable && msi_value == Some(1),
                message_limit_text: match limit_value {
                    Some(v) if v > 0 => v.to_string(),
                    _ => String::new(),
                },
                ..Default::default()
            };
            device.set_priority(&priority_name(priority_value));
            device.mark_initial();
            result.push(device);
        }
        Ok(())
    })();

    unsafe {
        let _ = SetupDiDestroyDeviceInfoList(info_set);
    }
    outcome?;

    result.sort_by(|a, b| match b.msi_capable.cmp(&a.msi_capable) {
        Ordering::Equal => a.name.to_uppercase().cmp(&b.name.to_uppercase()),
        other => other,
    });
    Ok(result)
}

pub fn validate(device: &MsiDevice) -> Option<String> {
    if !device.is_dirty() {
        return None;
    }
    if !device.msi_capable && device.is_msi_enabled {
        return Some(format!(
            "{}: Windows does not report MSI or MSI-X support.",
            device.name
        ));
    }
    if !device.is_msi_enabled
        || !device.is_message_limit_dirty()
        || device.message_limit_text.trim().is_empty()
    {
        return None;
    }
    let limit = match device.message_limit_text.trim().parse::<i32>() {
        Ok(v) if v > 0 => v,
        _ => {
            return Some(format!(
                "{}: the MSI limit must be a positive whole number or left blank.",
                device.name
            ))
        }
    };
    if device.max_message_limit <= 0 {
        return Some(format!(
            "{}: Windows did not report a safe maximum, so leave the limit blank.",
            device.name
        ));
    }
    if limit > device.max_message_limit {
        return Some(format!(
            "{}: the MSI limit cannot exceed {}.",
            device.name, device.max_message_limit
        ));
    }
    if !device.supports_msi_x && ![1, 2, 4, 8, 16].contains(&limit) {
        return Some(format!(
            "{}: MSI limits must be 1, 2, 4, 8, or 16.",
            device.name
        ));
    }
    None
}

fn powershell_ti_args(script: &str) -> String {
    format!(
        "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {}",
        encode_command(script)
    )
}

pub fn apply(devices: &[MsiDevice]) -> MsiApplyResult {
    let changed: Vec<&MsiDevice> = devices.iter().filter(|d| d.is_dirty()).collect();
    let mut result = MsiApplyResult::default();
    if !changed.is_empty() {
        if let Err(marker_error) =
            xos_helpers::stock_hardware_marker::try_invalidate("MSI Mode apply")
        {
            result.failed = changed.len() as i32;
            result.errors.push(format!(
                "No MSI change was written: the restored-to-stock record could not be cleared first ({marker_error})."
            ));
            return result;
        }
    }

    for device in changed {
        if let Some(validation) = validate(device) {
            result.failed += 1;
            result.errors.push(validation);
            continue;
        }
        let attempt = || -> Result<Option<String>> {
            save_backup(&device.instance_id)?;
            let mut limit: Option<i32> = None;
            if device.is_msi_enabled && !device.message_limit_text.trim().is_empty() {
                limit = Some(device.message_limit_text.trim().parse::<i32>()?);
            }
            let priority = priority_value(device.priority());
            let update_msi = device.is_msi_dirty() || device.is_message_limit_dirty();
            let update_priority = device.is_priority_dirty();
            let script = build_apply_script(
                &device.instance_id,
                update_msi,
                device.msi_capable,
                device.is_msi_enabled,
                limit,
                update_priority,
                priority,
            );
            let ok = run_as_ti("powershell.exe", &powershell_ti_args(&script));
            if !ok {
                return Ok(Some(format!(
                    "{}: Windows rejected the registry update.",
                    device.name
                )));
            }
            if !verify_applied_state(
                &device.instance_id,
                update_msi,
                device.is_msi_enabled,
                limit,
                update_priority,
                priority,
            ) {
                return Ok(Some(format!(
                    "{}: Windows did not retain the requested interrupt settings.",
                    device.name
                )));
            }
            Ok(None)
        };
        match attempt() {
            Ok(Some(error)) => {
                result.failed += 1;
                result.errors.push(error);
            }
            Ok(None) => {
                result.applied_instance_ids.push(device.instance_id.clone());
                result.applied += 1;
                log::log(&format!(
                    "[MSI Mode] Applied: {} ({})",
                    device.name, device.instance_id
                ));
            }
            Err(ex) => {
                result.failed += 1;
                result.errors.push(format!("{}: {}", device.name, ex));
                log::exception(
                    &format!("MSI Mode apply failed for {}", device.instance_id),
                    &ex.to_string(),
                );
            }
        }
    }
    result
}

pub fn restore(devices: &[MsiDevice]) -> MsiApplyResult {
    let mut result = MsiApplyResult::default();
    if !devices.is_empty() {
        if let Err(marker_error) =
            xos_helpers::stock_hardware_marker::try_invalidate("MSI Mode restore")
        {
            result.failed = devices.len() as i32;
            result.errors.push(format!(
                "Nothing was restored: the restored-to-stock record could not be cleared first ({marker_error})."
            ));
            return result;
        }
    }
    for device in devices {
        let attempt = || -> Result<Option<String>> {
            let backup = match try_read_backup(&device.instance_id) {
                Some(b) => b,
                None => {
                    return Ok(Some(format!(
                        "{}: the saved original settings are missing or invalid.",
                        device.name
                    )))
                }
            };
            let script = build_restore_script(&device.instance_id, &backup);
            let ok = run_as_ti("powershell.exe", &powershell_ti_args(&script));
            if !ok {
                return Ok(Some(format!(
                    "{}: Windows rejected the restore operation.",
                    device.name
                )));
            }
            if !verify_backup_state(&device.instance_id, &backup) {
                return Ok(Some(format!(
                    "{}: Windows did not restore every original interrupt setting.",
                    device.name
                )));
            }
            delete_backup(&device.instance_id)?;
            Ok(None)
        };
        match attempt() {
            Ok(Some(error)) => {
                result.failed += 1;
                result.errors.push(error);
            }
            Ok(None) => {
                result.applied += 1;
                log::log(&format!(
                    "[MSI Mode] Restored original values: {} ({})",
                    device.name, device.instance_id
                ));
            }
            Err(ex) => {
                result.failed += 1;
                result.errors.push(format!("{}: {}", device.name, ex));
                log::exception(
                    &format!("MSI Mode restore failed for {}", device.instance_id),
                    &ex.to_string(),
                );
            }
        }
    }
    result
}

fn base_path(instance_id: &str) -> String {
    format!("Registry::HKEY_LOCAL_MACHINE\\{DEVICE_ROOT}\\{instance_id}\\{INTERRUPT_PATH}")
}

fn build_apply_script(
    instance_id: &str,
    update_msi: bool,
    msi_capable: bool,
    msi_enabled: bool,
    limit: Option<i32>,
    update_priority: bool,
    priority: i32,
) -> String {
    let base = base_path(instance_id);
    let msi_path = ps_literal(&format!("{base}\\{MSI_SUB_KEY}"));
    let affinity_path = ps_literal(&format!("{base}\\{AFFINITY_SUB_KEY}"));
    let mut script = String::from("$ErrorActionPreference='Stop';");
    if update_msi && msi_capable {
        script.push_str(&format!(
            "$m='{msi_path}';New-Item -Path $m -Force|Out-Null;"
        ));
        script.push_str(&format!(
            "New-ItemProperty -Path $m -Name MSISupported -PropertyType DWord -Value {} -Force|Out-Null;",
            if msi_enabled { "1" } else { "0" }
        ));
        match (msi_enabled, limit) {
            (true, Some(l)) => script.push_str(&format!(
                "New-ItemProperty -Path $m -Name MessageNumberLimit -PropertyType DWord -Value {l} -Force|Out-Null;"
            )),
            _ => script.push_str(
                "Remove-ItemProperty -Path $m -Name MessageNumberLimit -Force -ErrorAction SilentlyContinue;",
            ),
        }
    }
    if update_priority {
        script.push_str(&format!("$a='{affinity_path}';"));
        if priority == 0 {
            script.push_str(
                "Remove-ItemProperty -Path $a -Name DevicePriority -Force -ErrorAction SilentlyContinue;",
            );
        } else {
            script.push_str(&format!(
                "New-Item -Path $a -Force|Out-Null;New-ItemProperty -Path $a -Name DevicePriority -PropertyType DWord -Value {priority} -Force|Out-Null;"
            ));
        }
    }
    script
}

fn build_restore_script(instance_id: &str, backup: &DeviceBackup) -> String {
    let base = base_path(instance_id);
    let msi_path = ps_literal(&format!("{base}\\{MSI_SUB_KEY}"));
    let affinity_path = ps_literal(&format!("{base}\\{AFFINITY_SUB_KEY}"));
    let mut script = String::from("$ErrorActionPreference='Stop';");
    append_restore_value(
        &mut script,
        "$m",
        &msi_path,
        "MSISupported",
        backup.msi_present,
        backup.msi_value,
    );
    append_restore_value(
        &mut script,
        "$m",
        &msi_path,
        "MessageNumberLimit",
        backup.limit_present,
        backup.limit_value,
    );
    append_restore_value(
        &mut script,
        "$a",
        &affinity_path,
        "DevicePriority",
        backup.priority_present,
        backup.priority_value,
    );
    script
}

fn append_restore_value(
    script: &mut String,
    variable: &str,
    path: &str,
    name: &str,
    present: bool,
    value: i32,
) {
    script.push_str(&format!("{variable}='{path}';"));
    if present {
        script.push_str(&format!(
            "New-Item -Path {variable} -Force|Out-Null;New-ItemProperty -Path {variable} -Name {name} -PropertyType DWord -Value {value} -Force|Out-Null;"
        ));
    } else {
        script.push_str(&format!(
            "Remove-ItemProperty -Path {variable} -Name {name} -Force -ErrorAction SilentlyContinue;"
        ));
    }
}

fn verify_applied_state(
    instance_id: &str,
    update_msi: bool,
    msi_enabled: bool,
    limit: Option<i32>,
    update_priority: bool,
    priority: i32,
) -> bool {
    let interrupt_base = format!("{DEVICE_ROOT}\\{instance_id}\\{INTERRUPT_PATH}");
    if update_msi {
        if !registry_state_matches(
            &format!("{interrupt_base}\\{MSI_SUB_KEY}"),
            "MSISupported",
            true,
            if msi_enabled { 1 } else { 0 },
        ) {
            return false;
        }
        if !registry_state_matches(
            &format!("{interrupt_base}\\{MSI_SUB_KEY}"),
            "MessageNumberLimit",
            msi_enabled && limit.is_some(),
            limit.unwrap_or(0),
        ) {
            return false;
        }
    }
    !update_priority
        || registry_state_matches(
            &format!("{interrupt_base}\\{AFFINITY_SUB_KEY}"),
            "DevicePriority",
            priority != 0,
            priority,
        )
}

fn verify_backup_state(instance_id: &str, backup: &DeviceBackup) -> bool {
    let interrupt_base = format!("{DEVICE_ROOT}\\{instance_id}\\{INTERRUPT_PATH}");
    registry_state_matches(
        &format!("{interrupt_base}\\{MSI_SUB_KEY}"),
        "MSISupported",
        backup.msi_present,
        backup.msi_value,
    ) && registry_state_matches(
        &format!("{interrupt_base}\\{MSI_SUB_KEY}"),
        "MessageNumberLimit",
        backup.limit_present,
        backup.limit_value,
    ) && registry_state_matches(
        &format!("{interrupt_base}\\{AFFINITY_SUB_KEY}"),
        "DevicePriority",
        backup.priority_present,
        backup.priority_value,
    )
}

fn registry_state_matches(path: &str, name: &str, present: bool, value: i32) -> bool {
    let state = read_registry_state(path, name);
    state.present == present && (!present || state.value == value)
}

fn backup_instance_matches(key: &RegKey, instance_id: &str) -> bool {
    match key.get_raw_value("InstanceId") {
        Ok(v) if v.vtype == REG_SZ => {
            decode_utf16(&v.bytes).to_uppercase() == instance_id.to_uppercase()
        }
        _ => false,
    }
}

fn save_backup(instance_id: &str) -> Result<()> {
    let backup_path = backup_path(instance_id);
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(existing) = hklm.open_subkey_with_flags(&backup_path, KEY_READ) {
        if backup_instance_matches(&existing, instance_id) {
            return Ok(());
        }
    }
    let interrupt_base = format!("{DEVICE_ROOT}\\{instance_id}\\{INTERRUPT_PATH}");
    let msi = read_registry_state(&format!("{interrupt_base}\\{MSI_SUB_KEY}"), "MSISupported");
    let limit = read_registry_state(
        &format!("{interrupt_base}\\{MSI_SUB_KEY}"),
        "MessageNumberLimit",
    );
    let priority = read_registry_state(
        &format!("{interrupt_base}\\{AFFINITY_SUB_KEY}"),
        "DevicePriority",
    );
    let (key, _) = hklm
        .create_subkey_with_flags(&backup_path, KEY_READ | KEY_WRITE)
        .map_err(|_| anyhow!("The original device settings could not be backed up."))?;
    write_backup_value(&key, "Msi", msi)?;
    write_backup_value(&key, "Limit", limit)?;
    write_backup_value(&key, "Priority", priority)?;
    key.set_raw_value(
        "InstanceId",
        &RegValue {
            bytes: utf16_bytes(instance_id).into(),
            vtype: REG_SZ,
        },
    )?;
    Ok(())
}

fn write_backup_value(key: &RegKey, prefix: &str, state: RegistryState) -> Result<()> {
    set_dword(
        key,
        &format!("{prefix}Present"),
        if state.present { 1 } else { 0 },
    )?;
    set_dword(key, &format!("{prefix}Value"), state.value)?;
    Ok(())
}

fn set_dword(key: &RegKey, name: &str, value: i32) -> Result<()> {
    key.set_raw_value(
        name,
        &RegValue {
            bytes: value.to_le_bytes().to_vec().into(),
            vtype: REG_DWORD,
        },
    )?;
    Ok(())
}

fn try_read_backup(instance_id: &str) -> Option<DeviceBackup> {
    let key = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(backup_path(instance_id), KEY_READ)
        .ok()?;
    if !backup_instance_matches(&key, instance_id) {
        return None;
    }
    Some(DeviceBackup {
        msi_present: read_backup_number(&key, "MsiPresent") == 1,
        msi_value: read_backup_number(&key, "MsiValue"),
        limit_present: read_backup_number(&key, "LimitPresent") == 1,
        limit_value: read_backup_number(&key, "LimitValue"),
        priority_present: read_backup_number(&key, "PriorityPresent") == 1,
        priority_value: read_backup_number(&key, "PriorityValue"),
    })
}

fn delete_backup(instance_id: &str) -> Result<()> {
    match RegKey::predef(HKEY_LOCAL_MACHINE).delete_subkey_all(backup_path(instance_id)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

fn backup_exists(instance_id: &str) -> bool {
    match RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(backup_path(instance_id), KEY_READ)
    {
        Ok(key) => backup_instance_matches(&key, instance_id),
        Err(_) => false,
    }
}

fn backup_path(instance_id: &str) -> String {
    format!("{BACKUP_ROOT}\\{}", encode_key_name(instance_id))
}

fn encode_key_name(value: &str) -> String {
    base64(value.as_bytes())
        .trim_end_matches('=')
        .replace('+', "-")
        .replace('/', "_")
}

fn read_backup_number(key: &RegKey, name: &str) -> i32 {
    raw_to_i32(key, name).unwrap_or(0)
}

fn raw_to_i32(key: &RegKey, name: &str) -> Option<i32> {
    let v = key.get_raw_value(name).ok()?;
    if v.vtype == REG_DWORD && v.bytes.len() >= 4 {
        Some(i32::from_le_bytes([
            v.bytes[0], v.bytes[1], v.bytes[2], v.bytes[3],
        ]))
    } else if v.vtype == REG_SZ {
        decode_utf16(&v.bytes).trim().parse::<i32>().ok()
    } else {
        None
    }
}

fn read_registry_state(path: &str, name: &str) -> RegistryState {
    let key = match RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(path, KEY_READ) {
        Ok(k) => k,
        Err(_) => return RegistryState::default(),
    };
    if key.get_raw_value(name).is_err() {
        return RegistryState::default();
    }
    RegistryState {
        present: true,
        value: raw_to_i32(&key, name).unwrap_or(0),
    }
}

fn read_dword(path: &str, name: &str) -> Option<i32> {
    let state = read_registry_state(path, name);
    if state.present {
        Some(state.value)
    } else {
        None
    }
}

pub fn priority_name(value: Option<i32>) -> String {
    match value {
        Some(1) => "Low",
        Some(2) => "Normal",
        Some(3) => "High",
        _ => "Undefined",
    }
    .to_string()
}

pub fn priority_value(value: &str) -> i32 {
    match value {
        "Low" => 1,
        "Normal" => 2,
        "High" => 3,
        _ => 0,
    }
}

pub fn format_interrupt_modes(value: u32) -> String {
    let mut modes: Vec<&str> = Vec::new();
    if value & 0x01 != 0 {
        modes.push("Line-Based");
    }
    if value & 0x02 != 0 {
        modes.push("MSI");
    }
    if value & 0x04 != 0 {
        modes.push("MSI-X");
    }
    if modes.is_empty() {
        "Not reported".to_string()
    } else {
        modes.join(", ")
    }
}

pub fn format_irq(value: u32) -> String {
    if value >= 0x8000_0000 {
        format!("-{}", 0x1_0000_0000u64 - value as u64)
    } else {
        value.to_string()
    }
}

fn ps_literal(value: &str) -> String {
    value.replace('\'', "''")
}

fn decode_utf16(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
    String::from_utf16_lossy(&units[..end])
}

fn utf16_bytes(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(|u| u.to_le_bytes())
        .collect()
}

fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn encode_command(script: &str) -> String {
    let bytes: Vec<u8> = script
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    base64(&bytes)
}

fn read_instance_id(info_set: HDEVINFO, info: &SP_DEVINFO_DATA) -> Option<String> {
    let mut buffer = [0u16; 512];
    unsafe { SetupDiGetDeviceInstanceIdW(info_set, info, Some(&mut buffer), None) }.ok()?;
    let end = buffer.iter().position(|&u| u == 0).unwrap_or(buffer.len());
    Some(String::from_utf16_lossy(&buffer[..end]))
}

fn read_registry_property_string(
    info_set: HDEVINFO,
    info: &SP_DEVINFO_DATA,
    property: SETUP_DI_REGISTRY_PROPERTY,
) -> Option<String> {
    let mut buffer = vec![0u8; 8192];
    let mut required: u32 = 0;
    unsafe {
        SetupDiGetDeviceRegistryPropertyW(
            info_set,
            info,
            property,
            None,
            Some(&mut buffer),
            Some(&mut required),
        )
    }
    .ok()?;
    if required < 2 {
        return None;
    }
    let len = (required as usize).min(buffer.len());
    let units: Vec<u16> = buffer[..len]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let value = String::from_utf16_lossy(&units);
    let cut = match value.find('\0') {
        Some(i) => &value[..i],
        None => &value[..],
    };
    Some(cut.trim().to_string())
}

fn read_device_property_u32(info_set: HDEVINFO, info: &SP_DEVINFO_DATA, key: &DEVPROPKEY) -> u32 {
    let mut buffer = [0u8; 16];
    let mut required: u32 = 0;
    let mut ptype = DEVPROPTYPE::default();
    let ok = unsafe {
        SetupDiGetDevicePropertyW(
            info_set,
            info,
            key,
            &mut ptype,
            Some(&mut buffer),
            Some(&mut required),
            0,
        )
    };
    if ok.is_err() || required == 0 {
        return 0;
    }
    if required >= 4 {
        u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]])
    } else if required >= 2 {
        u16::from_le_bytes([buffer[0], buffer[1]]) as u32
    } else {
        buffer[0] as u32
    }
}

fn read_irq_values(device_instance: u32) -> Vec<u32> {
    for configuration in [ALLOC_LOG_CONF, FILTERED_LOG_CONF, BASIC_LOG_CONF] {
        let mut log_configuration: usize = 0;
        let status = unsafe {
            CM_Get_First_Log_Conf(
                Some(&mut log_configuration),
                device_instance,
                CM_LOG_CONF(configuration.0),
            )
        };
        if status != CR_SUCCESS {
            continue;
        }
        let values = read_irq_values_from_configuration(log_configuration);
        unsafe {
            CM_Free_Log_Conf_Handle(log_configuration);
        }
        if !values.is_empty() {
            return values;
        }
    }
    Vec::new()
}

fn read_irq_values_from_configuration(log_configuration: usize) -> Vec<u32> {
    let mut result: Vec<u32> = Vec::new();
    let mut current: usize = 0;
    let mut status =
        unsafe { CM_Get_Next_Res_Des(&mut current, log_configuration, ResType_IRQ, None, 0) };
    while status == CR_SUCCESS {
        let mut next: usize = 0;
        let mut size: u32 = 0;
        if unsafe { CM_Get_Res_Des_Data_Size(&mut size, current, 0) } == CR_SUCCESS && size >= 16 {
            let mut data = vec![0u8; size as usize];
            if unsafe { CM_Get_Res_Des_Data(current, data.as_mut_ptr() as *mut _, size, 0) }
                == CR_SUCCESS
            {
                result.push(u32::from_le_bytes([data[12], data[13], data[14], data[15]]));
            }
        }
        status = unsafe { CM_Get_Next_Res_Des(&mut next, current, ResType_IRQ, None, 0) };
        unsafe {
            CM_Free_Res_Des_Handle(current);
        }
        current = next;
    }
    if status.0 != 0x0E && status.0 != 0x0F {
        log::log(&format!(
            "[MSI Mode] IRQ enumeration ended with CONFIGRET 0x{:X}.",
            status.0
        ));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device() -> MsiDevice {
        let mut d = MsiDevice {
            name: "GPU".into(),
            instance_id: r"PCI\VEN_10DE&DEV_1".into(),
            max_message_limit: 32,
            msi_capable: true,
            supports_msi_x: false,
            ..Default::default()
        };
        d.set_priority("");
        d.mark_initial();
        d
    }

    #[test]
    fn irq_formatting() {
        assert_eq!(format_irq(16), "16");
        assert_eq!(format_irq(0xFFFF_FFF0), "-16");
        assert_eq!(format_interrupt_modes(0x06), "MSI, MSI-X");
        assert_eq!(format_interrupt_modes(0), "Not reported");
    }

    #[test]
    fn priorities() {
        assert_eq!(priority_name(Some(3)), "High");
        assert_eq!(priority_name(None), "Undefined");
        assert_eq!(priority_value("Normal"), 2);
        assert_eq!(priority_value("x"), 0);
    }

    #[test]
    fn key_name_encoding() {
        assert_eq!(encode_key_name("ab"), "YWI");
        assert_eq!(encode_key_name("a?>"), "YT8-");
    }

    #[test]
    fn encoded_command() {
        assert_eq!(encode_command("a"), "YQA=");
    }

    #[test]
    fn dirty_and_validate() {
        let mut d = device();
        assert!(!d.is_dirty());
        assert_eq!(validate(&d), None);
        d.is_msi_enabled = true;
        assert!(d.is_dirty());
        assert_eq!(validate(&d), None);
        d.message_limit_text = "3".into();
        assert_eq!(
            validate(&d).unwrap(),
            "GPU: MSI limits must be 1, 2, 4, 8, or 16."
        );
        d.message_limit_text = "64".into();
        assert_eq!(
            validate(&d).unwrap(),
            "GPU: the MSI limit cannot exceed 32."
        );
        d.message_limit_text = "x".into();
        assert!(validate(&d).unwrap().contains("positive whole number"));
        d.message_limit_text = "4".into();
        assert_eq!(validate(&d), None);
        d.mark_clean();
        assert!(!d.is_dirty() && d.has_backup);
    }

    #[test]
    fn apply_script() {
        let s = build_apply_script("PCI\\X'Y", true, true, true, Some(4), true, 2);
        assert!(s.starts_with("$ErrorActionPreference='Stop';$m='Registry::HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Enum\\PCI\\X''Y\\"));
        assert!(s.contains("MessageNumberLimit -PropertyType DWord -Value 4"));
        assert!(s.contains("DevicePriority -PropertyType DWord -Value 2"));
        let r = build_restore_script("PCI\\X", &DeviceBackup::default());
        assert!(r.contains("Remove-ItemProperty -Path $a -Name DevicePriority"));
    }
}

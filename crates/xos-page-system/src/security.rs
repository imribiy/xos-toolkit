use xos_core::host::{Buttons, DialogResult, Host, Icon};
use xos_core::log;
use xos_sys::{reg_delete_value, reg_get_dword, reg_set_dword};

use crate::wmi::Wmi;

pub const DEV_GUARD_POL: &str = r"HKLM\Software\Policies\Microsoft\Windows\DeviceGuard";
pub const DEV_GUARD_DIRECT: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard";
pub const HVCI_SCENARIO: &str =
    r"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity";
pub const SG_SCENARIO: &str =
    r"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard";
const DEVICE_GUARD_NS: &str = r"root\Microsoft\Windows\DeviceGuard";
const HYPERVISOR_OVERRIDE_KEY: &str = r"HKLM\SOFTWARE\XOSToolkit";
pub const HYPERVISOR_OVERRIDE_VALUE: &str = "VbsOverrideAcknowledged";

const HYPERVISOR_SECURITY_PROPERTY_NAMES: [&str; 9] = [
    "0 None",
    "1 Hypervisor support",
    "2 Secure Boot",
    "3 DMA Protection",
    "4 Secure Memory Overwrite",
    "5 NX Protections",
    "6 SMM Mitigations",
    "7 MBEC/GMET",
    "8 APIC Virtualization",
];

pub fn get_vbs_running_status() -> i32 {
    if let Ok(wmi) = Wmi::connect(DEVICE_GUARD_NS) {
        if let Ok(rows) = wmi.query(
            "SELECT VirtualizationBasedSecurityStatus FROM Win32_DeviceGuard",
            &["VirtualizationBasedSecurityStatus"],
        ) {
            if let Some(row) = rows.first() {
                if let Ok(v) = row[0].text().trim().parse::<i32>() {
                    return v;
                }
            }
        }
    }

    let hvci = reg_get_dword(HVCI_SCENARIO, "Enabled");
    let dg_direct = reg_get_dword(DEV_GUARD_DIRECT, "EnableVirtualizationBasedSecurity");
    let dg_pol = reg_get_dword(DEV_GUARD_POL, "EnableVirtualizationBasedSecurity");
    if hvci == Some(1) || dg_direct == Some(1) || dg_pol == Some(1) {
        return 1;
    }
    if hvci == Some(0) && dg_direct != Some(1) && dg_pol != Some(1) {
        return 0;
    }
    -1
}

pub fn get_vbs_configured() -> Option<i32> {
    let pol = reg_get_dword(DEV_GUARD_POL, "EnableVirtualizationBasedSecurity");
    let direct = reg_get_dword(DEV_GUARD_DIRECT, "EnableVirtualizationBasedSecurity");
    let hvci = reg_get_dword(HVCI_SCENARIO, "Enabled");
    if pol == Some(1) || direct == Some(1) || hvci == Some(1) {
        return Some(1);
    }
    if pol == Some(0) || direct == Some(0) {
        return Some(0);
    }
    None
}

pub fn security_badge_label(running: i32, configured: Option<i32>) -> &'static str {
    if running < 0 {
        return "Unknown";
    }
    if running == 2 && configured != Some(0) {
        return "Enabled";
    }
    if running == 2 && configured == Some(0) {
        return "Disable Pending Reboot";
    }
    if running == 1 && configured == Some(1) {
        return "Enabled (Restart Required)";
    }
    if running == 1 {
        return "Disabled";
    }
    if running == 0 && configured == Some(1) {
        return "Enabled (Restart Required)";
    }
    if running == 0 {
        return "Disabled";
    }
    "Partial"
}

fn join_ints(v: Option<&Vec<i64>>) -> String {
    v.map(|v| {
        v.iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(",")
    })
    .unwrap_or_default()
}

pub fn log_security_state(label: &str, running: i32, configured: Option<i32>) {
    let attempt = || -> anyhow::Result<()> {
        let wmi = Wmi::connect(DEVICE_GUARD_NS)?;
        let rows = wmi.query(
            "SELECT * FROM Win32_DeviceGuard",
            &[
                "VirtualizationBasedSecurityStatus",
                "SecurityServicesRunning",
                "SecurityServicesConfigured",
            ],
        )?;
        if let Some(row) = rows.first() {
            log::op_detail(
                &format!("{label} detection"),
                Some(&format!(
                    "running={running} configured={} VbsStatus={} servicesRunning=[{}] servicesConfigured=[{}]",
                    configured.map(|c| c.to_string()).unwrap_or_else(|| "null".into()),
                    row[0].text(),
                    join_ints(row[1].ints()),
                    join_ints(row[2].ints()),
                )),
            );
        }
        Ok(())
    };
    if let Err(ex) = attempt() {
        log::log(&format!(
            "[{label}] detection values could not be read: {ex}"
        ));
    }
}

pub fn is_vbs_configured_enabled() -> bool {
    let pol = reg_get_dword(DEV_GUARD_POL, "EnableVirtualizationBasedSecurity");
    let direct = reg_get_dword(DEV_GUARD_DIRECT, "EnableVirtualizationBasedSecurity");
    pol == Some(1) || direct == Some(1)
}

pub fn get_hvci_status() -> i32 {
    let attempt = || -> anyhow::Result<Option<i32>> {
        let wmi = Wmi::connect(DEVICE_GUARD_NS)?;
        let rows = wmi.query(
            "SELECT SecurityServicesRunning, SecurityServicesConfigured FROM Win32_DeviceGuard",
            &["SecurityServicesRunning", "SecurityServicesConfigured"],
        )?;
        if let Some(row) = rows.first() {
            if row[0].ints().is_some_and(|v| v.contains(&2)) {
                return Ok(Some(2));
            }
            if row[1].ints().is_some_and(|v| v.contains(&2)) {
                return Ok(Some(1));
            }
            return Ok(Some(
                if reg_get_dword(HVCI_SCENARIO, "Enabled") == Some(1) {
                    1
                } else {
                    0
                },
            ));
        }
        Ok(None)
    };
    if let Ok(Some(v)) = attempt() {
        return v;
    }
    match reg_get_dword(HVCI_SCENARIO, "Enabled") {
        Some(1) => 1,
        Some(0) => 0,
        _ => -1,
    }
}

pub fn any_vbs_service_configured() -> bool {
    let attempt = || -> anyhow::Result<bool> {
        let wmi = Wmi::connect(DEVICE_GUARD_NS)?;
        let rows = wmi.query(
            "SELECT SecurityServicesConfigured FROM Win32_DeviceGuard",
            &["SecurityServicesConfigured"],
        )?;
        for row in rows {
            if row[0].ints().is_some_and(|v| v.iter().any(|i| *i != 0)) {
                return Ok(true);
            }
        }
        Ok(false)
    };
    attempt().unwrap_or(false)
}

fn describe_security_properties(values: Option<&Vec<i64>>) -> String {
    match values {
        None => "none reported".to_string(),
        Some(v) if v.is_empty() => "none reported".to_string(),
        Some(v) => v
            .iter()
            .map(|i| {
                let index = *i;
                if index >= 0 && (index as usize) < HYPERVISOR_SECURITY_PROPERTY_NAMES.len() {
                    HYPERVISOR_SECURITY_PROPERTY_NAMES[index as usize].to_string()
                } else {
                    index.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join(", "),
    }
}

#[derive(Default)]
pub struct HypervisorPreflightResult {
    pub blocked: bool,
    pub blocked_reason: String,
    pub risks: Vec<String>,
}

impl HypervisorPreflightResult {
    pub fn risk_message(&self) -> Option<String> {
        if self.risks.is_empty() {
            return None;
        }
        let mut m = String::new();
        let mut line = |s: &str| {
            m.push_str(s);
            m.push_str("\r\n");
        };
        line("Enabling this turns on the Windows hypervisor at the next boot. On a machine that cannot launch it, Windows does not reach the desktop and shows this instead:");
        line("");
        line("    Windows failed to start ... Status: 0xC0000189");
        line("");
        line("Detected:");
        for risk in &self.risks {
            line(&format!("  - {risk}"));
        }
        line("");
        line("If that happens: restart, then disable VBS from this page or with the Windows recovery options. Choosing Enable writes the settings now.");
        Some(m)
    }
}

pub fn hypervisor_preflight(feature: &str) -> HypervisorPreflightResult {
    let mut result = HypervisorPreflightResult::default();
    let label = if feature == "HVCI" {
        "Memory Integrity"
    } else {
        "VBS"
    };
    let property_name = &HYPERVISOR_SECURITY_PROPERTY_NAMES[1][2..];
    let mut available_text = "not reported".to_string();
    let mut required_text = "not reported".to_string();
    let mut device_guard_read = false;

    let device_guard = || -> anyhow::Result<Option<(String, String)>> {
        let wmi = Wmi::connect(DEVICE_GUARD_NS)?;
        let rows = wmi.query(
            "SELECT * FROM Win32_DeviceGuard",
            &["AvailableSecurityProperties", "RequiredSecurityProperties"],
        )?;
        Ok(rows.first().map(|row| {
            (
                describe_security_properties(row[0].ints()),
                describe_security_properties(row[1].ints()),
            )
        }))
    };
    match device_guard() {
        Ok(Some((a, r))) => {
            available_text = a;
            required_text = r;
            device_guard_read = true;
            log::log(&format!(
                "[VBS] preflight ({label}): availableSecurityProperties=[{available_text}] requiredSecurityProperties=[{required_text}]"
            ));
        }
        Ok(None) => {}
        Err(ex) => log::log(&format!(
            "[VBS] preflight could not read Win32_DeviceGuard: {ex}"
        )),
    }

    let reported_available = available_text
        .to_lowercase()
        .contains(&property_name.to_lowercase());
    let already_in_place = if feature == "HVCI" {
        reg_get_dword(HVCI_SCENARIO, "Enabled") == Some(1)
    } else {
        is_vbs_configured_enabled() || get_vbs_running_status() == 2
    };

    if device_guard_read && !reported_available && !already_in_place {
        let secure_boot_on = reg_get_dword(
            r"HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State",
            "UEFISecureBootEnabled",
        ) == Some(1);
        let secure_boot_note = if secure_boot_on {
            String::new()
        } else {
            "\n\nSecure Boot is off on this machine. It is the platform requirement VBS asks for by default, and turning it on is the first thing to try: on a virtual machine it is a VM setting, under Options then Advanced, and it needs a full power off rather than a restart.".to_string()
        };
        if !secure_boot_on {
            log::log("[VBS] preflight: Secure Boot is off; it is the platform requirement enabled VBS asks for by default.");
        }

        result.blocked = true;
        result.blocked_reason = format!(
            "Windows does not report {property_name} as available on this machine, so the hypervisor cannot start and the next boot stops at the Windows Boot Manager.\n\n    availableSecurityProperties: {available_text}\n    requiredSecurityProperties: {required_text}\n\nThis is the same answer Windows Security gives on the Core isolation page. Nothing was changed.\n\nTo make it available: enable virtualization in the firmware, on a virtual machine expose nested virtualization to the guest and give it more memory, then reopen this page.{secure_boot_note}"
        );
        log::log(&format!(
            "[VBS] {label} enable refused: Windows does not list {property_name} in availableSecurityProperties=[{available_text}]."
        ));
        return result;
    }

    let required_but_missing = device_guard_read
        && required_text
            .to_lowercase()
            .contains(&property_name.to_lowercase())
        && !reported_available;
    if required_but_missing {
        result.blocked = true;
        result.blocked_reason = format!(
            "Windows already requires {property_name} and does not report the property for it, so this machine is in the state that fails at boot.\n\n    availableSecurityProperties: {available_text}\n    requiredSecurityProperties: {required_text}\n\nDisable it from this page first. If the machine will not start, use the Windows recovery options to disable it, then reopen this page. Nothing was changed."
        );
        log::log(&format!(
            "[VBS] {label} enable refused: requiredSecurityProperties=[{required_text}] asks for {property_name} and availableSecurityProperties=[{available_text}] does not provide it."
        ));
        return result;
    }

    let mut computer_system = || -> anyhow::Result<()> {
        let wmi = Wmi::connect(r"ROOT\CIMV2")?;
        let rows = wmi.query(
            "SELECT * FROM Win32_ComputerSystem",
            &[
                "Manufacturer",
                "Model",
                "TotalPhysicalMemory",
                "HypervisorPresent",
            ],
        )?;
        if let Some(row) = rows.first() {
            let manufacturer = row[0].text();
            let model = row[1].text();
            let memory_mb: i64 = row[2]
                .text()
                .trim()
                .parse::<i64>()
                .map(|b| b / (1024 * 1024))
                .unwrap_or(0);
            log::log(&format!(
                "[VBS] preflight: machine={manufacturer} {model}; memoryMb={memory_mb}; hypervisorPresent={}",
                row[3].text()
            ));

            let virtual_hosts = [
                "vmware",
                "virtualbox",
                "innotek",
                "qemu",
                "xen",
                "microsoft corporation",
                "parallels",
                "bochs",
                "hyper-v",
            ];
            let probe = format!("{manufacturer} {model}").to_lowercase();
            if virtual_hosts.iter().any(|h| probe.contains(h)) {
                result.risks.push(format!(
                    "This looks like a virtual machine ({manufacturer} {model}). VBS needs virtualization exposed to the guest, and a guest without it can stop at the Windows Boot Manager instead of starting."
                ));
            }

            if memory_mb > 0 && memory_mb < 8192 {
                result.risks.push(format!(
                    "This machine has {memory_mb} MB of memory. Hypervisor-based security holds page hashes for every loaded driver, and a small machine is more likely to stop at boot while the hypervisor is starting."
                ));
            }
        }
        Ok(())
    };
    if let Err(ex) = computer_system() {
        log::log(&format!(
            "[VBS] preflight could not read Win32_ComputerSystem: {ex}"
        ));
    }

    if get_vbs_running_status() != 2 && feature == "HVCI" {
        result.risks.push("VBS is configured but not running yet, so the hypervisor starts at the next boot. That boot is the one that fails on a machine that cannot launch it.".to_string());
    }

    if xos_sys::get_pending_reboot_reason().is_some() {
        result.risks.push("Windows is already waiting to restart. Let that restart finish before changing hypervisor settings, so a boot failure can be told apart from a restart that was already owed.".to_string());
    }

    result
}

fn hypervisor_override_acknowledged() -> bool {
    reg_get_dword(HYPERVISOR_OVERRIDE_KEY, HYPERVISOR_OVERRIDE_VALUE) == Some(1)
}

pub fn clear_hypervisor_override() {
    reg_delete_value(HYPERVISOR_OVERRIDE_KEY, HYPERVISOR_OVERRIDE_VALUE);
}

fn ask(host: &dyn Host, message: &str, title: &str) -> bool {
    host.dialog(message, title, Buttons::YesNo, Icon::Warning) == DialogResult::Yes
}

pub fn confirm_hypervisor_enable(host: &dyn Host, feature: &str) -> bool {
    let label = if feature == "HVCI" {
        "Memory Integrity"
    } else {
        "VBS"
    };
    let title = format!("Enable {label}");
    let mut preflight = hypervisor_preflight(feature);
    if !preflight.blocked {
        let Some(risk_only) = preflight.risk_message() else {
            return true;
        };
        if ask(host, &risk_only, &title) {
            return true;
        }
        host.set_status(&format!("{label} enable cancelled."));
        return false;
    }

    log::log(&format!(
        "[VBS] {label} enable is not supported by this machine's reported properties."
    ));
    if !hypervisor_override_acknowledged() {
        let prompt = format!(
            "{}\n\nEnable it anyway? The Toolkit will write the setting.\nIf the boot then stops at the Windows Boot Manager: restart, then disable VBS from this page or from the Windows recovery options.",
            preflight.blocked_reason
        );
        if !ask(host, &prompt, &title) {
            host.set_status(&format!("{label} cannot run on this machine."));
            return false;
        }
        reg_set_dword(HYPERVISOR_OVERRIDE_KEY, HYPERVISOR_OVERRIDE_VALUE, 1);
    }

    if preflight.risks.is_empty() {
        preflight
            .risks
            .push("Windows does not report hypervisor support on this machine.".to_string());
    }
    let risk = preflight.risk_message().unwrap_or_default();
    if ask(host, &risk, &title) {
        return true;
    }
    host.set_status(&format!("{label} enable cancelled."));
    false
}

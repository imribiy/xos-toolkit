use std::sync::Arc;
use xos_core::host::{Host, Page};
use xos_core::ui::*;

pub mod stability;

pub struct Placeholder {
    id: &'static str,
    label: &'static str,
}

impl Page for Placeholder {
    fn id(&self) -> &'static str {
        self.id
    }
    fn label(&self) -> &'static str {
        self.label
    }
    fn model(&self) -> PageModel {
        PageModel::new(self.id, self.label, "This module is being ported.")
    }
    fn handle(&self, _host: &dyn Host, _event: &Event) {}
}

const NAV: &[(&str, &str)] = &[
    ("Apps", "App Installer"),
    ("AppX", "AppX Manager"),
    ("Cleanup", "Disk Cleanup"),
    ("DriverCleaner", "Driver Cleaner"),
    ("Startup", "Startup Manager"),
    ("System", "System"),
    ("Visuals", "Visuals"),
    ("Gaming", "Gaming"),
    ("Network", "Network"),
    ("Update", "Updates"),
    ("Peripherals", "Peripherals"),
    ("MsiMode", "MSI Mode"),
    ("Cpu", "CPU Affinity"),
    ("Services", "Services"),
    ("Troubleshoot", "Troubleshooting"),
    ("Stability", "Stability Monitor"),
    ("Configuration", "Configuration Backup"),
    ("About", "About"),
];

pub fn all() -> Vec<Arc<dyn Page>> {
    let mut ported: Vec<Arc<dyn Page>> = Vec::new();
    ported.extend(xos_page_software::pages());
    ported.extend(xos_page_cpu::pages());
    ported.extend(xos_page_gaming::pages());
    ported.extend(xos_page_visuals::pages());
    ported.extend(xos_page_update::pages());
    ported.extend(xos_page_apps::pages());
    ported.extend(xos_page_network::pages());
    ported.extend(xos_page_system::pages());
    ported.extend(xos_page_config::pages());
    ported.extend(xos_page_troubleshoot::pages());
    ported.push(Arc::new(stability::StabilityPage::new()));
    NAV.iter()
        .map(|(id, label)| {
            ported
                .iter()
                .find(|p| p.id() == *id)
                .cloned()
                .unwrap_or_else(|| Arc::new(Placeholder { id, label }) as Arc<dyn Page>)
        })
        .collect()
}

pub fn pending_reboot_reason() -> Option<String> {
    xos_sys::get_pending_reboot_reason().map(|s| s.to_string())
}

pub fn is_xos() -> bool {
    xos_core::detect::is_xos()
}

pub fn chocolatey_bootstrap_running() -> bool {
    crate::bootstrap::running()
}

pub fn wait_chocolatey_bootstrap(timeout: std::time::Duration) {
    xos_core::log::log("[CHOCO] Restart requested while automatic installation was running; waiting for completion.");
    crate::bootstrap::wait(timeout);
    if crate::bootstrap::running() {
        xos_core::log::log("[CHOCO] Automatic installation did not finish within 90 seconds; restarting anyway.");
    }
}

pub fn restart_windows() -> bool {
    let ready = xos_sys::is_choco_installed();
    xos_core::log::log(&format!("[CHOCO] Automatic installation state before restart: {}", if ready { "ready" } else { "not ready" }));
    let ok = xos_sys::run_cmd("shutdown.exe", "/r /t 0");
    if !ok {
        xos_sys::ops::reset();
    }
    ok
}

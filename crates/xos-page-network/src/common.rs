use xos_core::app_state;
use xos_core::host::{Buttons, Host, Icon};
use xos_core::log;
use xos_sys::ops;

pub fn done(host: &dyn Host, page: &str, msg: &str, operation_failed: bool) {
    let failed = ops::any_failed() || operation_failed;
    log::action_done(page, operation_failed, failed, None);
    ops::reset();
    app_state::require_reboot_if_message_asks(msg);
    host.set_status(msg);
    let mut text = msg.to_string();
    if failed {
        text.push_str(
            "\n\nNote: one or more settings could not be written (often a permissions issue). Try again.",
        );
    }
    host.dialog(
        &text,
        "XOS Toolkit",
        Buttons::Ok,
        if failed {
            Icon::Warning
        } else {
            Icon::Information
        },
    );
}

pub fn mark_failure_if_present(service: &str, operation: impl FnOnce() -> bool, failed: &mut bool) {
    if xos_sys::service_exists(service) && !operation() {
        *failed = true;
    }
}

pub fn require_service(service: &str, feature: &str) -> anyhow::Result<()> {
    if !xos_sys::service_exists(service) {
        anyhow::bail!(
            "{feature} cannot be configured because the {service} service is not installed."
        );
    }
    Ok(())
}

pub fn service_is_enabled(service: &str) -> bool {
    let start = xos_sys::get_service_start_type(service);
    start >= 0 && start != 4
}

pub fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

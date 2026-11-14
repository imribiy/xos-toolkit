use std::sync::Arc;
use xos_core::Page;

mod common;
pub mod network;
pub mod network_reset_action;
pub mod peripherals;
pub mod services;
pub mod services_data;
mod write_cache_script;

pub use network::NetworkPage;
pub use peripherals::PeripheralsPage;
pub use services::{
    apply_xos_service_disables, managed_service_names, managed_task_paths,
    playbook_disabled_services, restore_windows_default_service_start_types, sc_start_type_name,
    ServicesPage,
};

pub fn pages() -> Vec<Arc<dyn Page>> {
    vec![
        Arc::new(NetworkPage::new()),
        Arc::new(PeripheralsPage::new()),
        Arc::new(ServicesPage::new()),
    ]
}

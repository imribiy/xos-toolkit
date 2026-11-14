use std::sync::Arc;
use xos_core::Page;

mod cleanup;
mod driver_cleaner;
mod startup_manager;
mod util;

pub use cleanup::CleanupPage;
pub use driver_cleaner::DriverCleanerPage;
pub use startup_manager::StartupManagerPage;

pub fn pages() -> Vec<Arc<dyn Page>> {
    vec![
        Arc::new(CleanupPage::new()),
        Arc::new(DriverCleanerPage::new()),
        Arc::new(StartupManagerPage::new()),
    ]
}

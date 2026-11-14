mod common;
pub mod defender;
mod page;
mod security;
mod wmi;

use std::sync::Arc;

use xos_core::Page;

pub use defender::{DefenderOptions, DefenderOutcome};
pub use page::SystemPage;

pub fn pages() -> Vec<Arc<dyn Page>> {
    vec![Arc::new(SystemPage::new())]
}

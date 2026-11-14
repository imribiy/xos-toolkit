use std::sync::Arc;
use xos_core::Page;

mod page;
pub mod toolkit_configuration;

pub use page::ConfigurationPage;

pub fn pages() -> Vec<Arc<dyn Page>> {
    vec![Arc::new(ConfigurationPage::new())]
}

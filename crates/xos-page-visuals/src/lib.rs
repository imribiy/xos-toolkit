use std::sync::Arc;
use xos_core::Page;

pub mod visuals_page;

pub use visuals_page::VisualsPage;

pub fn pages() -> Vec<Arc<dyn Page>> {
    vec![Arc::new(VisualsPage::new())]
}

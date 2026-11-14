use std::sync::Arc;
use xos_core::Page;

pub mod about;
pub mod cpu_page;
pub mod msi_manager;
pub mod msi_page;

pub use about::AboutPage;
pub use cpu_page::CpuPage;
pub use msi_page::MsiModePage;

pub fn pages() -> Vec<Arc<dyn Page>> {
    vec![
        Arc::new(MsiModePage::new()),
        Arc::new(CpuPage::new()),
        Arc::new(AboutPage::new()),
    ]
}

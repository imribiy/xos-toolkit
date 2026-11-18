use std::sync::Arc;

use xos_core::Page;

mod diag;
mod netinfo;
mod page;
mod procs;
mod regval;
mod report;
mod uninstall;
mod wmi;
mod zipw;

pub use page::TroubleshootPage;

pub fn pages() -> Vec<Arc<dyn Page>> {
    vec![Arc::new(TroubleshootPage::new())]
}

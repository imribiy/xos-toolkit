use std::sync::Arc;
use xos_core::Page;

mod apps;
mod appx;
mod catalog;
mod choco_bootstrap;
mod edge;
mod onedrive;
mod util;

pub use apps::AppsPage;
pub use appx::{AppXPackageItem, AppXPage};
pub use catalog::{catalog_apps, is_catalog_package_id, CatalogApp, CatalogCategory, CATALOG};
pub use choco_bootstrap::{
    ensure_chocolatey, is_choco_bootstrap_running, mark_choco_bootstrap_running,
};
pub use edge::remove_edge_component;

pub fn pages() -> Vec<Arc<dyn Page>> {
    vec![Arc::new(AppsPage::new()), Arc::new(AppXPage::new())]
}

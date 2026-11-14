pub mod amd_driver_stock;
pub mod appx_removal;
pub mod card_state_helper;
pub mod defender_run_entry;
pub mod network_reset;
pub mod service_defaults_table;
pub mod stock_hardware_marker;

mod regutil;

pub fn init() {
    xos_sys::set_stock_marker_invalidator(stock_hardware_marker::try_invalidate);
}

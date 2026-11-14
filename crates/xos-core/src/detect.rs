use std::sync::OnceLock;
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
use winreg::RegKey;

const OEM_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation";
const EXPECTED_MANUFACTURER: &str = "XOS";
const EXPECTED_SUPPORT_URL: &str = "https://discord.gg/XTYEjZNPgX";

static CACHED: OnceLock<bool> = OnceLock::new();

pub fn is_xos() -> bool {
    *CACHED.get_or_init(detect)
}

fn detect() -> bool {
    let Ok(key) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(OEM_KEY, KEY_READ)
    else {
        return false;
    };
    let manufacturer = key.get_value::<String, _>("Manufacturer").ok();
    let support_url = key.get_value::<String, _>("SupportURL").ok();
    match (manufacturer, support_url) {
        (Some(m), Some(u)) => {
            m.eq_ignore_ascii_case(EXPECTED_MANUFACTURER)
                && u.eq_ignore_ascii_case(EXPECTED_SUPPORT_URL)
        }
        _ => false,
    }
}

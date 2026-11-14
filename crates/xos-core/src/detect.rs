use std::sync::OnceLock;
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
use winreg::RegKey;

const OEM_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation";
const EXPECTED_MANUFACTURER: &str = "XOS";
const EXPECTED_SUPPORT_URLS: [&str; 2] = [
    "https://github.com/imribiy/XOS",
    "https://discord.gg/XTYEjZNPgX",
];

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
        (Some(m), Some(u)) => is_xos_oem(&m, &u),
        _ => false,
    }
}

fn is_xos_oem(manufacturer: &str, support_url: &str) -> bool {
    manufacturer.eq_ignore_ascii_case(EXPECTED_MANUFACTURER)
        && EXPECTED_SUPPORT_URLS
            .iter()
            .any(|e| support_url.trim_end_matches('/').eq_ignore_ascii_case(e))
}

#[cfg(test)]
mod tests {
    use super::is_xos_oem;

    #[test]
    fn oem_marker() {
        assert!(is_xos_oem("XOS", "https://github.com/imribiy/XOS"));
        assert!(is_xos_oem("xos", "https://github.com/imribiy/xos/"));
        assert!(is_xos_oem("XOS", "https://discord.gg/XTYEjZNPgX"));
        assert!(!is_xos_oem("Dell", "https://github.com/imribiy/XOS"));
        assert!(!is_xos_oem("XOS", "https://example.com"));
    }
}

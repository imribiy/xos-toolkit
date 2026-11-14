use crate::ui::{Badge, Tone};
use winreg::enums::{RegType, HKEY_LOCAL_MACHINE, KEY_READ};
use winreg::RegKey;

pub const ENABLED_WINDOWS_DEFAULT: &str = "Enabled (Windows Default)";
pub const DISABLED_WINDOWS_DEFAULT: &str = "Disabled (Windows Default)";
pub const WINDOWS_DEFAULT: &str = "Default (Windows)";
pub const AUTOMATIC: &str = "Automatic";

pub fn toggle(value: Option<i32>) -> String {
    toggle_with(value, 1, 0, "N/A")
}

pub fn toggle_with(value: Option<i32>, enabled: i32, disabled: i32, when_absent: &str) -> String {
    match value {
        None => when_absent.to_string(),
        Some(v) if v == enabled => "Enabled".to_string(),
        Some(v) if v == disabled => "Disabled".to_string(),
        Some(_) => "Partial".to_string(),
    }
}

pub fn toggle_str(value: Option<&str>) -> String {
    toggle_str_with(value, "1", "0", "N/A")
}

pub fn toggle_str_with(
    value: Option<&str>,
    enabled: &str,
    disabled: &str,
    when_absent: &str,
) -> String {
    match value {
        None => when_absent.to_string(),
        Some(v) if v.eq_ignore_ascii_case(enabled) => "Enabled".to_string(),
        Some(v) if v.eq_ignore_ascii_case(disabled) => "Disabled".to_string(),
        Some(_) => "Partial".to_string(),
    }
}

pub fn is_windows_default(state: &str) -> bool {
    state == ENABLED_WINDOWS_DEFAULT
        || state == DISABLED_WINDOWS_DEFAULT
        || state == WINDOWS_DEFAULT
        || state == AUTOMATIC
}

pub fn combine<S: AsRef<str>>(states: &[S]) -> String {
    if states.iter().any(|s| s.as_ref() == "Unknown") {
        return "Unknown".to_string();
    }
    if states.is_empty() || states.iter().all(|s| s.as_ref() == "N/A") {
        return "N/A".to_string();
    }
    let first = states[0].as_ref();
    if states.iter().all(|s| s.as_ref() == first) {
        first.to_string()
    } else {
        "Partial".to_string()
    }
}

pub fn match_state(enabled: bool, disabled: bool, present: &[bool]) -> String {
    if present.iter().all(|p| !*p) {
        return "N/A".to_string();
    }
    if present.iter().any(|p| !*p) {
        return "Partial".to_string();
    }
    if enabled {
        "Enabled".to_string()
    } else if disabled {
        "Disabled".to_string()
    } else {
        "Partial".to_string()
    }
}

pub fn r#match(enabled: bool, disabled: bool, present: &[bool]) -> String {
    match_state(enabled, disabled, present)
}

pub fn service(name: &str) -> String {
    let key = match RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(
        format!(r"SYSTEM\CurrentControlSet\Services\{name}"),
        KEY_READ,
    ) {
        Ok(k) => k,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return "N/A".to_string(),
        Err(_) => return "Unknown".to_string(),
    };
    match key.get_raw_value("Start") {
        Ok(raw) => {
            if raw.vtype != RegType::REG_DWORD || raw.bytes.len() < 4 {
                return "Unknown".to_string();
            }
            let start =
                i32::from_le_bytes([raw.bytes[0], raw.bytes[1], raw.bytes[2], raw.bytes[3]]);
            if start == 4 {
                "Disabled"
            } else if (0..=3).contains(&start) {
                "Enabled"
            } else {
                "Partial"
            }
            .to_string()
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => "N/A".to_string(),
        Err(_) => "Unknown".to_string(),
    }
}

pub fn services<S: AsRef<str>>(names: &[S]) -> String {
    let states: Vec<String> = names
        .iter()
        .map(|n| service(n.as_ref()))
        .filter(|s| s != "N/A")
        .collect();
    combine(&states)
}

pub fn description(state: &str) -> String {
    if state == "N/A" {
        return "No explicit setting entry or applicable component was found. Windows may use its built-in behavior.".to_string();
    }
    if is_windows_default(state) {
        return if state == AUTOMATIC {
            "Windows manages this setting automatically. No XOS override is set.".to_string()
        } else {
            "Windows default. No XOS override is set.".to_string()
        };
    }
    if state == "Partial" {
        return "The entries do not fully match either option, or some required entries are missing.".to_string();
    }
    if state == "Checking" {
        return "Reading the current Windows setting.".to_string();
    }
    if state == "Unknown" {
        return "The current state could not be verified.".to_string();
    }
    "Configured state. Changes that require a restart may not be active yet.".to_string()
}

const RED_STATES: &[&str] = &[
    "Disabled",
    DISABLED_WINDOWS_DEFAULT,
    "Disabled Service Only",
    "Force Disabled",
    "Force Disabled (VBS)",
    "Force Disabled (HVCI)",
    "Force Disabled (Hyper-V)",
    "Force Disabled (Defender)",
    "Hard Disabled",
    "Classic",
];

const GREEN_STATES: &[&str] = &[
    "Enabled",
    ENABLED_WINDOWS_DEFAULT,
    AUTOMATIC,
    "Safe",
    "Immersive",
    "Immersive (Windows Default)",
    "Default (Windows)",
    "Recommended",
    "Forced",
    "Restricted (Windows Default)",
    "RemoteSigned",
    "Unrestricted",
    "AllSigned",
    "Bypass",
    "Undefined",
    "Enabled (Restart Required)",
    "Disable Pending Reboot",
];

pub fn tone_for(state: &str) -> Tone {
    if state.ends_with(" Hz") {
        Tone::Green
    } else if RED_STATES.contains(&state) {
        Tone::Red
    } else if GREEN_STATES.contains(&state) {
        Tone::Green
    } else if state == "Partial" || state == "Experimental" {
        Tone::Orange
    } else {
        Tone::Neutral
    }
}

pub fn tooltip_for(state: &str, detail: Option<&str>) -> String {
    match detail {
        Some(d) => d.to_string(),
        None => description(state),
    }
}

pub fn badge(state: &str) -> Badge {
    badge_with(state, None)
}

pub fn badge_with<'a>(state: &str, tooltip: impl Into<Option<&'a str>>) -> Badge {
    Badge::new(state, tone_for(state)).tooltip(tooltip_for(state, tooltip.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toggles() {
        assert_eq!(toggle(None), "N/A");
        assert_eq!(toggle(Some(1)), "Enabled");
        assert_eq!(toggle(Some(0)), "Disabled");
        assert_eq!(toggle(Some(7)), "Partial");
        assert_eq!(toggle_with(Some(2), 2, 0, "x"), "Enabled");
        assert_eq!(toggle_str(Some("1")), "Enabled");
        assert_eq!(toggle_str_with(Some("ON"), "on", "off", "N/A"), "Enabled");
        assert_eq!(toggle_str(None), "N/A");
    }

    #[test]
    fn combining() {
        assert_eq!(combine::<&str>(&[]), "N/A");
        assert_eq!(combine(&["N/A", "N/A"]), "N/A");
        assert_eq!(combine(&["Enabled", "Enabled"]), "Enabled");
        assert_eq!(combine(&["Enabled", "Disabled"]), "Partial");
        assert_eq!(combine(&["Enabled", "Unknown"]), "Unknown");
        assert_eq!(match_state(true, false, &[true, true]), "Enabled");
        assert_eq!(match_state(true, false, &[false, false]), "N/A");
        assert_eq!(match_state(true, false, &[true, false]), "Partial");
        assert_eq!(match_state(false, false, &[true]), "Partial");
    }

    #[test]
    fn tones_and_badges() {
        assert_eq!(tone_for("Enabled"), Tone::Green);
        assert_eq!(tone_for("144 Hz"), Tone::Green);
        assert_eq!(tone_for("Classic"), Tone::Red);
        assert_eq!(tone_for("Experimental"), Tone::Orange);
        assert_eq!(tone_for("Checking"), Tone::Neutral);
        assert_eq!(badge("Partial").tooltip, description("Partial"));
        assert_eq!(badge_with("Enabled", "custom").tooltip, "custom");
        assert_eq!(badge_with("Enabled", None).tooltip, description("Enabled"));
    }

    #[test]
    fn service_absent() {
        assert_eq!(service("XosNoSuchService_zz"), "N/A");
    }
}

use crate::util::{read_reg_value, RegVal};

pub const UX_SETTINGS: &str = r"HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings";
pub const POLICY: &str = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate";
pub const MACHINE_AU: &str = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU";
pub const USER_AU: &str = r"HKCU\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU";

const END_TIMES: [&str; 1] = ["2038-01-19T03:14:07Z"];
const START_TIMES: [&str; 1] = ["2025-01-01T00:00:00Z"];
const START_NAMES: [&str; 5] = [
    "PauseUpdatesStartTime",
    "PauseFeatureUpdatesStartTime",
    "PauseQualityUpdatesStartTime",
    "PausedFeatureDate",
    "PausedQualityDate",
];

fn add(found: &mut Vec<(String, String)>, key: &str, name: &str) {
    let item = (key.to_string(), name.to_string());
    if !found.contains(&item) {
        found.push(item);
    }
}

pub fn matches(for_uninstall: bool) -> Vec<(String, String)> {
    let mut found: Vec<(String, String)> = Vec::new();

    let expiry = is_string(UX_SETTINGS, "PauseUpdatesExpiryTime", &END_TIMES);
    let feature_end = is_string(UX_SETTINGS, "PauseFeatureUpdatesEndTime", &END_TIMES);
    let quality_end = is_string(UX_SETTINGS, "PauseQualityUpdatesEndTime", &END_TIMES);
    let feature_end_open =
        feature_end || (for_uninstall && read(UX_SETTINGS, "PauseFeatureUpdatesEndTime").is_none());
    let quality_end_open =
        quality_end || (for_uninstall && read(UX_SETTINGS, "PauseQualityUpdatesEndTime").is_none());
    let security_only = is_dword(UX_SETTINGS, "BranchReadinessLevel", &[20]);
    let machine_no_auto_update_absent = read(MACHINE_AU, "NoAutoUpdate").is_none();
    if expiry {
        add(&mut found, UX_SETTINGS, "PauseUpdatesExpiryTime");
    }
    if feature_end {
        add(&mut found, UX_SETTINGS, "PauseFeatureUpdatesEndTime");
    }
    if quality_end {
        add(&mut found, UX_SETTINGS, "PauseQualityUpdatesEndTime");
    }
    for name in START_NAMES {
        if is_string(UX_SETTINGS, name, &START_TIMES) {
            add(&mut found, UX_SETTINGS, name);
        }
    }
    if is_dword(UX_SETTINGS, "FlightSettingsMaxPauseDays", &[5269]) {
        add(&mut found, UX_SETTINGS, "FlightSettingsMaxPauseDays");
    }
    if feature_end_open && is_dword(UX_SETTINGS, "PausedFeatureStatus", &[1]) {
        add(&mut found, UX_SETTINGS, "PausedFeatureStatus");
    }
    if quality_end_open && is_dword(UX_SETTINGS, "PausedQualityStatus", &[1]) {
        add(&mut found, UX_SETTINGS, "PausedQualityStatus");
    }
    if (expiry || for_uninstall) && is_dword(UX_SETTINGS, "DeferFeatureUpdatesPeriodInDays", &[365])
    {
        add(&mut found, UX_SETTINGS, "DeferFeatureUpdatesPeriodInDays");
    }
    if (expiry || for_uninstall) && is_dword(UX_SETTINGS, "DeferQualityUpdatesPeriodInDays", &[30])
    {
        add(&mut found, UX_SETTINGS, "DeferQualityUpdatesPeriodInDays");
    }

    if security_only {
        add(&mut found, UX_SETTINGS, "BranchReadinessLevel");
        if is_dword(UX_SETTINGS, "DeferFeatureUpdates", &[1]) {
            add(&mut found, UX_SETTINGS, "DeferFeatureUpdates");
        }
        if is_dword(UX_SETTINGS, "DeferFeatureUpdatesPeriodInDays", &[365]) {
            add(&mut found, UX_SETTINGS, "DeferFeatureUpdatesPeriodInDays");
        }
        if is_dword(UX_SETTINGS, "DeferQualityUpdates", &[1]) {
            add(&mut found, UX_SETTINGS, "DeferQualityUpdates");
        }
        if is_dword(UX_SETTINGS, "DeferQualityUpdatesPeriodInDays", &[7]) {
            add(&mut found, UX_SETTINGS, "DeferQualityUpdatesPeriodInDays");
        }
        if machine_no_auto_update_absent && is_dword(MACHINE_AU, "AUOptions", &[2]) {
            add(&mut found, MACHINE_AU, "AUOptions");
        }
    }

    if read(POLICY, "DeferFeatureUpdates").is_none()
        && is_dword(POLICY, "DeferFeatureUpdatesPeriodInDays", &[365])
    {
        add(&mut found, POLICY, "DeferFeatureUpdatesPeriodInDays");
    }
    if read(POLICY, "DeferQualityUpdates").is_none()
        && is_dword(POLICY, "DeferQualityUpdatesPeriodInDays", &[30])
    {
        add(&mut found, POLICY, "DeferQualityUpdatesPeriodInDays");
    }

    if is_dword(USER_AU, "NoAutoUpdate", &[1]) {
        add(&mut found, USER_AU, "NoAutoUpdate");
        if is_dword(USER_AU, "AUOptions", &[1]) {
            add(&mut found, USER_AU, "AUOptions");
        }
    }
    if is_dword(MACHINE_AU, "NoAutoUpdate", &[1]) && is_dword(MACHINE_AU, "AUOptions", &[1]) {
        add(&mut found, MACHINE_AU, "AUOptions");
    }
    found
}

fn is_string(key: &str, name: &str, values: &[&str]) -> bool {
    matches!(read(key, name), Some(RegVal::Sz(text)) if values.contains(&text.as_str()))
}

fn is_dword(key: &str, name: &str, values: &[i32]) -> bool {
    matches!(read(key, name), Some(RegVal::Dword(number)) if values.contains(&number))
}

fn read(key: &str, name: &str) -> Option<RegVal> {
    let hkcu = key.len() >= 5 && key[..5].eq_ignore_ascii_case(r"HKCU\");
    read_reg_value(hkcu, &key[5..], name).ok().flatten()
}

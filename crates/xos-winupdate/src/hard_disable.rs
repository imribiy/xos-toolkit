use anyhow::Result;
use xos_core::log;
use xos_sys::{
    get_windows_build_number, reg_get_dword, reg_get_string, reg_set_dword, reg_set_string,
};

use crate::util::{io_msg, read_reg_value, RegVal};

pub const POLICY: &str = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate";
pub const AU: &str = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU";
pub const OWNERSHIP_KEY: &str = r"HKLM\SOFTWARE\XOSToolkit\UpdateSourceBlock";
pub const SERVER_VALUES: [&str; 3] = ["WUServer", "WUStatusServer", "UpdateServiceUrlAlternate"];
pub const CLASS_VALUES: [&str; 4] = [
    "SetPolicyDrivenUpdateSourceForDriverUpdates",
    "SetPolicyDrivenUpdateSourceForFeatureUpdates",
    "SetPolicyDrivenUpdateSourceForQualityUpdates",
    "SetPolicyDrivenUpdateSourceForOtherUpdates",
];

pub fn supports_scan_sources_for(build: i32, revision: i32) -> bool {
    build >= 22000 || (build == 19045 && revision >= 2130)
}

pub fn supports_scan_sources() -> bool {
    supports_scan_sources_for(
        get_windows_build_number(),
        reg_get_dword(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "UBR").unwrap_or(0),
    )
}

pub fn apply() -> bool {
    if !reg_set_dword(OWNERSHIP_KEY, "Applied", 1) {
        return false;
    }
    let mut ok = true;
    for name in SERVER_VALUES {
        ok &= reg_set_string(POLICY, name, " ");
    }
    ok &= reg_set_dword(AU, "UseWUServer", 1);
    ok &= reg_set_dword(POLICY, "DoNotConnectToWindowsUpdateInternetLocations", 1);
    ok &= reg_set_dword(POLICY, "DisableWindowsUpdateAccess", 1);
    ok &= reg_set_dword(POLICY, "SetDisableUXWUAccess", 1);
    ok &= reg_set_dword(AU, "NoAutoUpdate", 1);
    if supports_scan_sources() {
        for name in CLASS_VALUES {
            ok &= reg_set_dword(POLICY, name, 1);
        }
        ok &= reg_set_dword(AU, "UseUpdateClassPolicySource", 1);
    }
    matches(true) && ok
}

pub fn matches(log_failures: bool) -> bool {
    let mut ok = true;
    let mut check = |name: &str, matched: bool| {
        if matched {
            return;
        }
        ok = false;
        if log_failures {
            log::log(&format!(
                "[ERROR] Windows Update hard-disable policy verification failed: {name}"
            ));
        }
    };
    for name in SERVER_VALUES {
        check(name, reg_get_string(POLICY, name).as_deref() == Some(" "));
    }
    for name in [
        "DoNotConnectToWindowsUpdateInternetLocations",
        "DisableWindowsUpdateAccess",
        "SetDisableUXWUAccess",
    ] {
        check(name, reg_get_dword(POLICY, name) == Some(1));
    }
    check("UseWUServer", reg_get_dword(AU, "UseWUServer") == Some(1));
    check("NoAutoUpdate", reg_get_dword(AU, "NoAutoUpdate") == Some(1));
    if supports_scan_sources() {
        for name in CLASS_VALUES {
            check(name, reg_get_dword(POLICY, name) == Some(1));
        }
        check(
            "UseUpdateClassPolicySource",
            reg_get_dword(AU, "UseUpdateClassPolicySource") == Some(1),
        );
    }
    check(
        "MDM allows Windows Update Group Policy",
        group_policy_applies(log_failures),
    );
    ok
}

fn group_policy_applies(log_failures: bool) -> bool {
    match read_reg_value(
        false,
        r"SOFTWARE\Microsoft\PolicyManager\current\device\Update",
        "IgnoreWindowsUpdateGroupPolicies",
    ) {
        Ok(None) => true,
        Ok(Some(RegVal::Dword(n))) => n != 1,
        Ok(Some(_)) => false,
        Err(e) => {
            if log_failures {
                log::log(&format!(
                    "[ERROR] Effective Windows Update MDM policy could not be read: {}",
                    io_msg(&e)
                ));
            }
            false
        }
    }
}

fn is_dword_one(value: Option<RegVal>) -> bool {
    matches!(value, Some(RegVal::Dword(1)))
}

fn is_blank_string(value: Option<RegVal>) -> bool {
    matches!(value, Some(RegVal::Sz(ref s)) | Some(RegVal::ExpandSz(ref s)) if s == " ")
}

pub fn has_owned_sources() -> Result<bool> {
    if is_dword_one(read_source_value(OWNERSHIP_KEY, "Applied")?) {
        return Ok(true);
    }
    for name in SERVER_VALUES {
        if is_blank_string(read_source_value(POLICY, name)?) {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn owned_source_values() -> Result<Vec<(String, String)>> {
    let mut found = Vec::new();
    let mut owned = is_dword_one(read_source_value(OWNERSHIP_KEY, "Applied")?);
    for name in SERVER_VALUES {
        if !is_blank_string(read_source_value(POLICY, name)?) {
            continue;
        }
        owned = true;
        found.push((POLICY.to_string(), name.to_string()));
    }
    if !owned {
        return Ok(found);
    }
    for name in CLASS_VALUES {
        if is_dword_one(read_source_value(POLICY, name)?) {
            found.push((POLICY.to_string(), name.to_string()));
        }
    }
    if is_dword_one(read_source_value(AU, "UseUpdateClassPolicySource")?) {
        found.push((AU.to_string(), "UseUpdateClassPolicySource".to_string()));
    }
    if is_dword_one(read_source_value(AU, "UseWUServer")?) {
        found.push((AU.to_string(), "UseWUServer".to_string()));
    }
    Ok(found)
}

fn read_source_value(path: &str, name: &str) -> Result<Option<RegVal>> {
    match read_reg_value(false, &path[5..], name) {
        Ok(v) => Ok(v),
        Err(e) => {
            log::log(&format!(
                "[ERROR] Windows Update source ownership could not be read: {path} / {name}: {}",
                io_msg(&e)
            ));
            Err(anyhow::anyhow!("{}", io_msg(&e)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_source_support_thresholds() {
        assert!(supports_scan_sources_for(22000, 0));
        assert!(supports_scan_sources_for(26100, 1));
        assert!(supports_scan_sources_for(19045, 2130));
        assert!(!supports_scan_sources_for(19045, 2129));
        assert!(!supports_scan_sources_for(19044, 9999));
    }
}

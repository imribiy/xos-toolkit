use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock};
use xos_core::log;
use xos_helpers::amd_driver_stock::{AmdDriverStock, StockValue};

pub const AMD_SERVICE_BACKUP_KEY: &str = r"HKLM\SOFTWARE\XOSToolkit\AmdServiceBackup";

pub const AMD_SERVICES: [(&str, i32); 4] = [
    ("AMD Crash Defender Service", 2),
    ("amdfendr", 3),
    ("amdfendrmgr", 3),
    ("amdlog", 3),
];

pub const EXPERIMENTAL_ONLY_VALUES: [&str; 52] = [
    "StutterMode",
    "KMD_DeLagEnabled",
    "KMD_FramePacingSupport",
    "DalDisableStutter",
    "DisableBlockWrite",
    "DisableFBCSupport",
    "DisableFBCForFullScreenApp",
    "PP_Force3DPerformanceMode",
    "PP_ForceHighDPMLevel",
    "PP_SclkDeepSleepDisable",
    "PP_GfxOffControl",
    "PP_ThermalAutoThrottlingEnable",
    "PP_EnableRaceToIdle",
    "DisableGfxClockGating",
    "DisableVceClockGating",
    "DisableSamuClockGating",
    "DisableRomMGCGClockGating",
    "DisableGfxCoarseGrainClockGating",
    "DisableGfxMediumGrainClockGating",
    "DisableGfxFineGrainClockGating",
    "DisableHdpMGClockGating",
    "DisableXdmaSclkGating",
    "DisableRomMediumGrainClockGating",
    "DisableNbioMediumGrainClockGating",
    "DisableMcMediumGrainClockGating",
    "IRQMgrDisableIHClockGating",
    "EnableVceSwClockGating",
    "EnableUvdClockGating",
    "EnableGfxClockGatingThruSmu",
    "EnableSysClockGatingThruSmu",
    "DalFineGrainClockGating",
    "DisableGfxMGLS",
    "DisableHdpClockPowerGating",
    "DisableUVDPowerGating",
    "DisableVCEPowerGating",
    "DisableAcpPowerGating",
    "DisableDrmdmaPowerGating",
    "DisableGfxCGPowerGating",
    "DisableStaticGfxMGPowerGating",
    "DisableDynamicGfxMGPowerGating",
    "DisableCpPowerGating",
    "DisableGDSPowerGating",
    "DisableXdmaPowerGating",
    "DisableGFXPipelinePowerGating",
    "DisableQuickGfxMGPowerGating",
    "DisablePowerGating",
    "SMU_DisableMmhubPowerGating",
    "SMU_DisableAthubPowerGating",
    "DalForceMaxDisplayClock",
    "DalDisableClockGating",
    "DalDisableDeepSleep",
    "DalDisableDiv2",
];

pub const AMD_SAFE_VALUES: [(&str, i32); 13] = [
    ("ReportAnalytics", 0),
    ("NotifySubscription", 0),
    ("AllowSubscription", 0),
    ("ShowReleaseNotes", 0),
    ("KMD_ChillEnabled", 0),
    ("KMD_RadeonBoostEnabled", 0),
    ("EnableAspmL0s", 0),
    ("EnableAspmL1", 0),
    ("EnableAspmL1SS", 0),
    ("DisableAspmL0s", 1),
    ("DisableAspmL1", 1),
    ("EnableSpreadSpectrum", 0),
    ("EnableVcePllSpreadSpectrum", 0),
];

pub const AMD_EXPERIMENTAL_ZERO: [&str; 10] = [
    "StutterMode",
    "KMD_FramePacingSupport",
    "PP_GfxOffControl",
    "PP_ThermalAutoThrottlingEnable",
    "PP_EnableRaceToIdle",
    "EnableVceSwClockGating",
    "EnableUvdClockGating",
    "EnableGfxClockGatingThruSmu",
    "EnableSysClockGatingThruSmu",
    "DalFineGrainClockGating",
];

pub const AMD_REMOVED_VALUES: [&str; 5] = [
    "EnableUlps",
    "EnableUlps_NA",
    "PP_DisableULPS",
    "KMD_EnableULPS",
    "KMD_ForceD3ColdSupport",
];

#[derive(Clone, Debug, PartialEq)]
pub enum Val {
    Unset,
    Dword(i32),
    Str(String),
    Unsupported,
}

struct Caches {
    stock: HashMap<String, AmdDriverStock>,
    logged: HashSet<String>,
}

fn caches() -> &'static Mutex<Caches> {
    static C: OnceLock<Mutex<Caches>> = OnceLock::new();
    C.get_or_init(|| {
        Mutex::new(Caches {
            stock: HashMap::new(),
            logged: HashSet::new(),
        })
    })
}

pub fn last_mismatch_log() -> &'static Mutex<Option<String>> {
    static C: OnceLock<Mutex<Option<String>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(None))
}

pub fn amd_key_name(path: &str) -> &str {
    match path.rfind('\\') {
        Some(i) => &path[i + 1..],
        None => path,
    }
}

pub fn stock_for(path: &str) -> Option<AmdDriverStock> {
    let identity = format!(
        "{}|{}|{}",
        path,
        xos_sys::reg_get_string(path, "InfPath").unwrap_or_default(),
        xos_sys::reg_get_string(path, "DriverVersion").unwrap_or_default()
    );
    let lower = identity.to_lowercase();
    if let Some(cached) = caches().lock().unwrap().stock.get(&lower) {
        return Some(cached.clone());
    }
    let loaded = AmdDriverStock::load(path);
    let (stock, error) = match loaded {
        Ok(s) => (Some(s), String::new()),
        Err(e) => (None, e),
    };
    let first_log = {
        let mut c = caches().lock().unwrap();
        if let Some(s) = &stock {
            c.stock.insert(lower.clone(), s.clone());
        }
        c.logged.insert(format!(
            "{lower}|{}",
            if stock.is_some() { "true" } else { "false" }
        ))
    };
    if first_log {
        let detail = match &stock {
            Some(s) => {
                let mut d = format!(
                    "{} values from {} [{}] for {}",
                    s.count(),
                    s.inf_file,
                    s.section,
                    amd_key_name(path)
                );
                if !s.missing_sections.is_empty() {
                    d.push_str(&format!(
                        "; sections not in the INF: {}",
                        s.missing_sections
                    ));
                }
                d
            }
            None => format!(
                "{}: {error}; Safe and Revert delete the values instead of restoring the driver's",
                amd_key_name(path)
            ),
        };
        log::result(stock.is_some(), "AMD driver defaults", &detail);
    }
    stock
}

pub fn read_amd_value(path: &str, name: &str) -> Val {
    if let Some(n) = xos_sys::reg_get_dword(path, name) {
        return Val::Dword(n);
    }
    match xos_sys::reg_get_string(path, name) {
        Some(s) => Val::Str(s),
        None => Val::Unset,
    }
}

pub fn stock_value(stock: &Option<AmdDriverStock>, name: &str) -> Val {
    match stock.as_ref().and_then(|s| s.try_get(name)) {
        Some(StockValue::Unsupported) => Val::Unsupported,
        Some(StockValue::Dword(n)) => Val::Dword(*n),
        Some(StockValue::Str(s)) => Val::Str(s.clone()),
        None => Val::Unset,
    }
}

fn at_stock(path: &str, name: &str, stock: &Option<AmdDriverStock>) -> bool {
    let wanted = stock_value(stock, name);
    wanted == Val::Unsupported || read_amd_value(path, name) == wanted
}

pub fn restore_amd_stock(path: &str, name: &str, stock: &Option<AmdDriverStock>) {
    match stock_value(stock, name) {
        Val::Unsupported => {}
        Val::Dword(n) => {
            xos_sys::reg_set_dword(path, name, n);
        }
        Val::Str(s) => {
            xos_sys::reg_set_string(path, name, &s);
        }
        Val::Unset => {
            xos_sys::reg_delete_value(path, name);
        }
    }
}

pub fn experimental_target(name: &str) -> i32 {
    if AMD_EXPERIMENTAL_ZERO.contains(&name) {
        0
    } else {
        1
    }
}

fn experimental_names() -> impl Iterator<Item = &'static str> {
    EXPERIMENTAL_ONLY_VALUES.iter().copied()
}

pub fn get_amd_profile_state(path: &str) -> &'static str {
    let stock = stock_for(path);
    let safe_matches = AMD_SAFE_VALUES
        .iter()
        .all(|(n, v)| xos_sys::reg_get_dword(path, n) == Some(*v));
    let removed_absent = AMD_REMOVED_VALUES
        .iter()
        .all(|n| read_amd_value(path, n) == Val::Unset);
    let experimental_at_stock = experimental_names().all(|n| at_stock(path, n, &stock));
    if safe_matches && removed_absent && experimental_at_stock {
        return "Safe";
    }
    if safe_matches
        && removed_absent
        && experimental_names()
            .all(|n| xos_sys::reg_get_dword(path, n) == Some(experimental_target(n)))
    {
        return "Experimental";
    }
    if experimental_at_stock
        && AMD_SAFE_VALUES
            .iter()
            .all(|(n, _)| at_stock(path, n, &stock))
        && AMD_REMOVED_VALUES.iter().all(|n| at_stock(path, n, &stock))
    {
        return "Stock";
    }
    "Partial"
}

pub fn format_amd_value(value: &Val) -> String {
    match value {
        Val::Unset => "not set".to_string(),
        Val::Unsupported => "the driver's own value".to_string(),
        Val::Str(t) => format!("\"{t}\""),
        Val::Dword(n) if *n > 255 => format!("0x{:X}", n),
        Val::Dword(n) => n.to_string(),
    }
}

pub fn amd_mismatches(paths: &[String], target: &str) -> Vec<String> {
    let mut found = Vec::new();
    for path in paths {
        let stock = stock_for(path);
        let key = format!("{}\\", amd_key_name(path));
        let mut check = |name: &str, wanted: Val| {
            let value = read_amd_value(path, name);
            if wanted != Val::Unsupported && value != wanted {
                found.push(format!(
                    "{key}{name}={}, expected {}",
                    format_amd_value(&value),
                    format_amd_value(&wanted)
                ));
            }
        };
        for (name, v) in AMD_SAFE_VALUES.iter() {
            check(
                name,
                if target == "Stock" {
                    stock_value(&stock, name)
                } else {
                    Val::Dword(*v)
                },
            );
        }
        for name in AMD_REMOVED_VALUES.iter() {
            check(
                name,
                if target == "Stock" {
                    stock_value(&stock, name)
                } else {
                    Val::Unset
                },
            );
        }
        for name in experimental_names() {
            check(
                name,
                if target == "Experimental" {
                    Val::Dword(experimental_target(name))
                } else {
                    stock_value(&stock, name)
                },
            );
        }
    }
    if target == "Stock" {
        return found;
    }
    for (name, _) in AMD_SERVICES.iter() {
        if !xos_sys::service_exists(name) {
            continue;
        }
        let start = xos_sys::get_service_start_type(name);
        if start != 4 {
            found.push(format!("service {name} Start={start}, expected 4"));
        }
    }
    found
}

pub fn amd_partial_target(paths: &[String]) -> &'static str {
    let mut best = "Safe";
    let mut fewest = amd_mismatches(paths, "Safe").len();
    for target in ["Stock", "Experimental"] {
        let count = amd_mismatches(paths, target).len();
        if count < fewest {
            best = target;
            fewest = count;
        }
    }
    best
}

pub fn amd_read_back_problem(paths: &[String], experimental: bool) -> Option<String> {
    let mismatches = amd_mismatches(paths, if experimental { "Experimental" } else { "Safe" });
    if mismatches.is_empty() {
        None
    } else {
        Some(format!(
            "read back does not match: {}",
            mismatches.join("; ")
        ))
    }
}

pub fn card_state(paths: &[String]) -> (String, String) {
    let mut safe_count = 0;
    let mut experimental_count = 0;
    for p in paths {
        let profile = get_amd_profile_state(p);
        if profile == "Safe" || profile == "Experimental" {
            safe_count += 1;
        }
        if profile == "Experimental" {
            experimental_count += 1;
        }
    }

    let mut any_present = false;
    let mut any_disabled = false;
    let mut all_disabled = true;
    for (name, _) in AMD_SERVICES.iter() {
        if !xos_sys::service_exists(name) {
            continue;
        }
        any_present = true;
        let disabled = xos_sys::get_service_start_type(name) == 4;
        any_disabled |= disabled;
        all_disabled &= disabled;
    }
    if !any_present {
        all_disabled = true;
    }

    let n = paths.len();
    if safe_count == n && experimental_count == n && all_disabled {
        *last_mismatch_log().lock().unwrap() = None;
        return (
            "Experimental".into(),
            "The experimental AMD GPU profile is applied.".into(),
        );
    }
    if safe_count == n && experimental_count == 0 && all_disabled {
        *last_mismatch_log().lock().unwrap() = None;
        return ("Safe".into(), "The safe AMD GPU profile is applied.".into());
    }
    if paths.iter().all(|p| get_amd_profile_state(p) == "Stock") {
        let mut detail = if paths.iter().all(|p| stock_for(p).is_some()) {
            "The AMD GPU values match the installed driver's defaults (its INF).".to_string()
        } else {
            "No AMD GPU profile values are set; the installed driver's defaults could not be read."
                .to_string()
        };
        if any_disabled {
            detail.push_str(
                " XOS may already have disabled the AMD crash services; Safe applies the rest.",
            );
        }
        *last_mismatch_log().lock().unwrap() = None;
        return ("Stock".into(), detail);
    }
    let target = amd_partial_target(paths);
    let mismatches = amd_mismatches(paths, target);
    let profile = if target == "Stock" {
        "the installed driver's defaults".to_string()
    } else {
        format!("the {} AMD GPU profile", target.to_lowercase())
    };
    let detail = if mismatches.is_empty() {
        "The AMD GPU settings changed while they were being read; reopen the page.".to_string()
    } else {
        let mut d = format!(
            "Not matching {profile}: {}",
            mismatches
                .iter()
                .take(6)
                .cloned()
                .collect::<Vec<_>>()
                .join("; ")
        );
        if mismatches.len() > 6 {
            d.push_str(&format!("; and {} more", mismatches.len() - 6));
        }
        d
    };
    let log_line = mismatches.join("; ");
    {
        let mut last = last_mismatch_log().lock().unwrap();
        if last.as_deref() != Some(log_line.as_str()) {
            *last = Some(log_line.clone());
            log::log(&format!(
                "[STATE] AMD Radeon GPU Tweaks reads Partial against {profile}: {log_line}"
            ));
        }
    }
    ("Partial".into(), detail)
}

pub fn apply_amd_safe(t: &str) {
    for n in [
        "ReportAnalytics",
        "NotifySubscription",
        "AllowSubscription",
        "ShowReleaseNotes",
    ] {
        xos_sys::reg_set_dword(t, n, 0);
    }
    for n in [
        "KMD_EnableAmdFendrOptions",
        "KMD_ChillEnabled",
        "KMD_RadeonBoostEnabled",
    ] {
        xos_sys::reg_set_dword(t, n, 0);
    }
    for n in AMD_REMOVED_VALUES {
        xos_sys::reg_delete_value(t, n);
    }
    for (n, v) in [
        ("EnableAspmL0s", 0),
        ("EnableAspmL1", 0),
        ("EnableAspmL1SS", 0),
        ("DisableAspmL0s", 1),
        ("DisableAspmL1", 1),
        ("EnableSpreadSpectrum", 0),
        ("EnableVcePllSpreadSpectrum", 0),
    ] {
        xos_sys::reg_set_dword(t, n, v);
    }
    let stock = stock_for(t);
    for n in experimental_names() {
        restore_amd_stock(t, n, &stock);
    }
}

pub fn apply_amd_experimental_extra(t: &str) {
    for (n, v) in [
        ("PP_Force3DPerformanceMode", 1),
        ("PP_ForceHighDPMLevel", 1),
        ("PP_SclkDeepSleepDisable", 1),
        ("PP_GfxOffControl", 0),
        ("PP_ThermalAutoThrottlingEnable", 0),
        ("PP_EnableRaceToIdle", 0),
        ("StutterMode", 0),
        ("KMD_DeLagEnabled", 1),
        ("KMD_FramePacingSupport", 0),
        ("DalDisableStutter", 1),
        ("DisableBlockWrite", 1),
        ("DisableFBCSupport", 1),
        ("DisableFBCForFullScreenApp", 1),
    ] {
        xos_sys::reg_set_dword(t, n, v);
    }
    for cg in [
        "DisableGfxClockGating",
        "DisableVceClockGating",
        "DisableSamuClockGating",
        "DisableRomMGCGClockGating",
        "DisableGfxCoarseGrainClockGating",
        "DisableGfxMediumGrainClockGating",
        "DisableGfxFineGrainClockGating",
        "DisableHdpMGClockGating",
        "DisableXdmaSclkGating",
        "DisableRomMediumGrainClockGating",
        "DisableNbioMediumGrainClockGating",
        "DisableMcMediumGrainClockGating",
        "IRQMgrDisableIHClockGating",
    ] {
        xos_sys::reg_set_dword(t, cg, 1);
    }
    for n in [
        "EnableVceSwClockGating",
        "EnableUvdClockGating",
        "EnableGfxClockGatingThruSmu",
        "EnableSysClockGatingThruSmu",
        "DalFineGrainClockGating",
    ] {
        xos_sys::reg_set_dword(t, n, 0);
    }
    for pg in [
        "DisableGfxMGLS",
        "DisableHdpClockPowerGating",
        "DisableUVDPowerGating",
        "DisableVCEPowerGating",
        "DisableAcpPowerGating",
        "DisableDrmdmaPowerGating",
        "DisableGfxCGPowerGating",
        "DisableStaticGfxMGPowerGating",
        "DisableDynamicGfxMGPowerGating",
        "DisableCpPowerGating",
        "DisableGDSPowerGating",
        "DisableXdmaPowerGating",
        "DisableGFXPipelinePowerGating",
        "DisableQuickGfxMGPowerGating",
        "DisablePowerGating",
    ] {
        xos_sys::reg_set_dword(t, pg, 1);
    }
    xos_sys::reg_set_dword(t, "SMU_DisableMmhubPowerGating", 1);
    xos_sys::reg_set_dword(t, "SMU_DisableAthubPowerGating", 1);
    for n in [
        "DalForceMaxDisplayClock",
        "DalDisableClockGating",
        "DalDisableDeepSleep",
        "DalDisableDiv2",
    ] {
        xos_sys::reg_set_dword(t, n, 1);
    }
}

pub fn backup_amd_service_starts() -> bool {
    let mut ok = true;
    for (name, _) in AMD_SERVICES.iter() {
        if !xos_sys::service_exists(name)
            || xos_sys::reg_get_dword(AMD_SERVICE_BACKUP_KEY, name).is_some()
        {
            continue;
        }
        let start = xos_sys::get_service_start_type(name);
        if start < 0 {
            ok = false;
        } else if start != 4 {
            ok &= xos_sys::reg_set_dword(AMD_SERVICE_BACKUP_KEY, name, start);
        }
    }
    ok
}

pub fn set_amd_services(start_type: i32) -> bool {
    let mut ok = true;
    for (name, _) in AMD_SERVICES.iter() {
        if xos_sys::service_exists(name) {
            ok &= xos_sys::config_service_reg(name, start_type);
        }
    }
    ok
}

pub fn restore_amd_services() -> bool {
    let mut ok = true;
    for (name, default_start) in AMD_SERVICES.iter() {
        if !xos_sys::service_exists(name) {
            continue;
        }
        let start = xos_sys::reg_get_dword(AMD_SERVICE_BACKUP_KEY, name).unwrap_or(*default_start);
        ok &= xos_sys::config_service_reg(name, start);
    }
    if ok {
        ok &= xos_sys::reg_delete_key(AMD_SERVICE_BACKUP_KEY);
    }
    ok
}

pub const AMD_REVERT_VALUES: [&str; 66] = [
    "ReportAnalytics",
    "NotifySubscription",
    "AllowSubscription",
    "ShowReleaseNotes",
    "StutterMode",
    "KMD_EnableAmdFendrOptions",
    "KMD_ChillEnabled",
    "KMD_DeLagEnabled",
    "KMD_FramePacingSupport",
    "KMD_RadeonBoostEnabled",
    "DalDisableStutter",
    "DisableBlockWrite",
    "DisableFBCSupport",
    "DisableFBCForFullScreenApp",
    "PP_Force3DPerformanceMode",
    "PP_ForceHighDPMLevel",
    "PP_SclkDeepSleepDisable",
    "PP_GfxOffControl",
    "PP_ThermalAutoThrottlingEnable",
    "PP_EnableRaceToIdle",
    "EnableAspmL0s",
    "EnableAspmL1",
    "EnableAspmL1SS",
    "DisableAspmL0s",
    "DisableAspmL1",
    "DisableGfxClockGating",
    "DisableVceClockGating",
    "DisableSamuClockGating",
    "DisableRomMGCGClockGating",
    "DisableGfxCoarseGrainClockGating",
    "DisableGfxMediumGrainClockGating",
    "DisableGfxFineGrainClockGating",
    "DisableHdpMGClockGating",
    "EnableVceSwClockGating",
    "EnableUvdClockGating",
    "EnableGfxClockGatingThruSmu",
    "EnableSysClockGatingThruSmu",
    "DisableXdmaSclkGating",
    "DalFineGrainClockGating",
    "DisableRomMediumGrainClockGating",
    "DisableNbioMediumGrainClockGating",
    "DisableMcMediumGrainClockGating",
    "IRQMgrDisableIHClockGating",
    "DisableGfxMGLS",
    "DisableHdpClockPowerGating",
    "DisableUVDPowerGating",
    "DisableVCEPowerGating",
    "DisableAcpPowerGating",
    "DisableDrmdmaPowerGating",
    "DisableGfxCGPowerGating",
    "DisableStaticGfxMGPowerGating",
    "DisableDynamicGfxMGPowerGating",
    "DisableCpPowerGating",
    "DisableGDSPowerGating",
    "DisableXdmaPowerGating",
    "DisableGFXPipelinePowerGating",
    "DisableQuickGfxMGPowerGating",
    "DisablePowerGating",
    "SMU_DisableMmhubPowerGating",
    "SMU_DisableAthubPowerGating",
    "DalForceMaxDisplayClock",
    "DalDisableClockGating",
    "DalDisableDeepSleep",
    "DalDisableDiv2",
    "EnableSpreadSpectrum",
    "EnableVcePllSpreadSpectrum",
];

pub fn revert_values(stock_known: bool) -> Vec<&'static str> {
    let mut v: Vec<&'static str> = AMD_REVERT_VALUES.to_vec();
    if stock_known {
        v.extend(AMD_REMOVED_VALUES);
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_sizes() {
        assert_eq!(experimental_names().count(), 52);
        assert_eq!(AMD_SAFE_VALUES.len(), 13);
        assert_eq!(revert_values(false).len(), 66);
        assert_eq!(revert_values(true).len(), 71);
    }

    #[test]
    fn formats() {
        assert_eq!(format_amd_value(&Val::Unset), "not set");
        assert_eq!(
            format_amd_value(&Val::Unsupported),
            "the driver's own value"
        );
        assert_eq!(format_amd_value(&Val::Str("1".into())), "\"1\"");
        assert_eq!(format_amd_value(&Val::Dword(0x200A)), "0x200A");
        assert_eq!(format_amd_value(&Val::Dword(16)), "16");
    }

    #[test]
    fn targets() {
        assert_eq!(experimental_target("StutterMode"), 0);
        assert_eq!(experimental_target("DalDisableDiv2"), 1);
        assert_eq!(amd_key_name(r"HKLM\X\Class\0001"), "0001");
    }
}

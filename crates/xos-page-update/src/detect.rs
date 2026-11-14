use chrono::{
    DateTime, Datelike, FixedOffset, Local, NaiveDate, NaiveDateTime, TimeZone, Timelike, Utc,
};
use windows::core::PCWSTR;
use windows::Win32::Foundation::SYSTEMTIME;
use windows::Win32::Globalization::{GetDateFormatEx, DATE_SHORTDATE};
use winreg::enums::{HKEY_CURRENT_USER, KEY_READ};
use winreg::RegKey;
use xos_core::log;
use xos_core::status;
use xos_core::ui::Badge;
use xos_sys::{get_service_start_type, get_windows_build_number, reg_get_dword, reg_get_string};
use xos_winupdate::{hard_disable, service_guard};

use crate::consts::*;
use crate::dispatch::{Arg, Disp};
use crate::infra::*;

#[derive(Clone)]
pub struct Snapshot {
    pub policy: Badge,
    pub policy_warning: Option<String>,
    pub delivery: Badge,
    pub no_reboot: Badge,
    pub expedited: Badge,
    pub update_notif: Badge,
    pub restart_notif: Badge,
    pub latest: Badge,
    pub other_products: Badge,
    pub metered: Badge,
    pub drivers: Badge,
    pub store: Badge,
    pub latest_supported: bool,
    pub security_enabled: bool,
    pub security_tooltip: Option<String>,
    pub disabled_tooltip: Option<String>,
    pub hard_policy_applied: bool,
    pub msa: bool,
}

impl Default for Snapshot {
    fn default() -> Self {
        Snapshot {
            policy: Badge::checking(),
            policy_warning: None,
            delivery: Badge::checking(),
            no_reboot: Badge::checking(),
            expedited: Badge::checking(),
            update_notif: Badge::checking(),
            restart_notif: Badge::checking(),
            latest: Badge::checking(),
            other_products: Badge::checking(),
            metered: Badge::checking(),
            drivers: Badge::checking(),
            store: Badge::checking(),
            latest_supported: true,
            security_enabled: true,
            security_tooltip: None,
            disabled_tooltip: None,
            hard_policy_applied: false,
            msa: false,
        }
    }
}

pub fn build_number() -> i32 {
    get_windows_build_number()
}

pub fn edition_id() -> String {
    reg_get_string(CURRENT_VERSION, "EditionID").unwrap_or_default()
}

fn starts_with_ci(s: &str, prefix: &str) -> bool {
    s.get(..prefix.len())
        .map_or(false, |p| p.eq_ignore_ascii_case(prefix))
}

pub fn is_windows_home() -> bool {
    starts_with_ci(&edition_id(), "Core")
}

pub fn supports_update_policies() -> bool {
    let edition = edition_id();
    starts_with_ci(&edition, "Professional")
        || starts_with_ci(&edition, "Enterprise")
        || starts_with_ci(&edition, "Education")
        || starts_with_ci(&edition, "IoTEnterprise")
}

pub fn supports_latest_updates_for(build: i32, revision: i32) -> bool {
    build >= 22631 || (build == 19045 && revision >= 3758)
}

pub fn supports_latest_updates() -> bool {
    supports_latest_updates_for(
        build_number(),
        reg_get_dword(CURRENT_VERSION, "UBR").unwrap_or(0),
    )
}

pub fn supports_optional_content() -> bool {
    let build = build_number();
    let revision = reg_get_dword(CURRENT_VERSION, "UBR").unwrap_or(0);
    supports_update_policies() && (build >= 22631 || (build == 19045 && revision >= 3757))
}

pub fn security_focused_description() -> String {
    let features = if build_number() >= 22000 {
        "Keeps the installed Windows release until its end of support."
    } else {
        "Defers feature updates for one year after their release."
    };
    format!(
        "{features}{} Monthly cumulative updates can include non-security fixes.",
        if supports_optional_content() {
            " Automatic optional previews are disabled."
        } else {
            ""
        }
    )
}

pub fn is_security_focused() -> bool {
    let features = if build_number() >= 22000 {
        reg_get_dword(POL_WU, "TargetReleaseVersion") == Some(1)
            && reg_get_string(POL_WU, "ProductVersion").as_deref() == Some("Windows 11")
            && !reg_get_string(CURRENT_VERSION, "DisplayVersion")
                .unwrap_or_default()
                .is_empty()
            && reg_get_string(POL_WU, "TargetReleaseVersionInfo")
                == reg_get_string(CURRENT_VERSION, "DisplayVersion")
    } else {
        reg_get_dword(POL_WU, "DeferFeatureUpdates") == Some(1)
            && reg_get_dword(POL_WU, "DeferFeatureUpdatesPeriodInDays") == Some(365)
    };
    let automatic = reg_get_dword(POL_WU_AU, "AUOptions");
    supports_update_policies()
        && features
        && (automatic == Some(2) || automatic == Some(4))
        && reg_get_dword(POL_WU_AU, "NoAutoUpdate") == Some(0)
        && (!supports_optional_content()
            || reg_get_dword(POL_WU, "SetAllowOptionalContent") == Some(0))
        && (!supports_latest_updates()
            || reg_get_dword(UX_SET, "IsContinuousInnovationOptedIn") == Some(0))
}

pub fn has_managed_update_policy() -> bool {
    [
        "AllowAutoUpdate",
        "AllowUpdateService",
        "DeferFeatureUpdatesPeriodInDays",
        "PauseFeatureUpdatesStartTime",
        "PauseQualityUpdatesStartTime",
        "TargetReleaseVersion",
        "AllowOptionalContent",
    ]
    .iter()
    .any(|name| {
        reg_get_dword(POL_MGR_UPDATE, name).is_some()
            || reg_get_string(POL_MGR_UPDATE, name).is_some()
    })
}

pub fn is_microsoft_account() -> bool {
    let attempt = || -> std::io::Result<bool> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        if let Ok(extended) = hkcu.open_subkey_with_flags(
            r"SOFTWARE\Microsoft\IdentityCRL\UserExtendedProperties",
            KEY_READ,
        ) {
            if extended.enum_values().count() > 0 || extended.enum_keys().count() > 0 {
                return Ok(true);
            }
        }
        match hkcu
            .open_subkey_with_flags(r"SOFTWARE\Microsoft\IdentityCRL\StoredIdentities", KEY_READ)
        {
            Ok(stored) => Ok(stored.enum_keys().count() > 0),
            Err(_) => Ok(false),
        }
    };
    attempt().unwrap_or(false)
}

pub fn parse_pause_expiry(text: &str) -> Option<DateTime<Utc>> {
    let t = text.trim();
    if t.is_empty() {
        return None;
    }
    if let Ok(d) = DateTime::parse_from_rfc3339(t) {
        return Some(d.with_timezone(&Utc));
    }
    for fmt in [
        "%Y-%m-%dT%H:%M:%S%.f%z",
        "%Y-%m-%d %H:%M:%S%.f%z",
        "%m/%d/%Y %H:%M:%S %z",
    ] {
        if let Ok(d) = DateTime::<FixedOffset>::parse_from_str(t, fmt) {
            return Some(d.with_timezone(&Utc));
        }
    }
    for fmt in [
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S%.f",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
        "%m/%d/%Y %H:%M",
    ] {
        if let Ok(n) = NaiveDateTime::parse_from_str(t, fmt) {
            return Local
                .from_local_datetime(&n)
                .earliest()
                .map(|d| d.with_timezone(&Utc));
        }
    }
    for fmt in ["%Y-%m-%d", "%m/%d/%Y"] {
        if let Ok(d) = NaiveDate::parse_from_str(t, fmt) {
            if let Some(n) = d.and_hms_opt(0, 0, 0) {
                return Local
                    .from_local_datetime(&n)
                    .earliest()
                    .map(|d| d.with_timezone(&Utc));
            }
        }
    }
    None
}

pub fn short_date(dt: &DateTime<Local>) -> String {
    let st = SYSTEMTIME {
        wYear: dt.year() as u16,
        wMonth: dt.month() as u16,
        wDayOfWeek: dt.weekday().num_days_from_sunday() as u16,
        wDay: dt.day() as u16,
        wHour: dt.hour() as u16,
        wMinute: dt.minute() as u16,
        wSecond: dt.second() as u16,
        wMilliseconds: 0,
    };
    let mut buf = [0u16; 80];
    let written = unsafe {
        GetDateFormatEx(
            PCWSTR::null(),
            DATE_SHORTDATE,
            Some(&st),
            PCWSTR::null(),
            Some(&mut buf),
            PCWSTR::null(),
        )
    };
    if written > 1 {
        String::from_utf16_lossy(&buf[..(written as usize - 1)])
    } else {
        dt.format("%x").to_string()
    }
}

pub fn get_other_microsoft_products_state() -> String {
    let policy = reg_get_dword(POL_WU_AU, "AllowMUUpdateService");
    let ux_setting = reg_get_dword(UX_SET, "AllowMUUpdateService");
    let mdm_policy = reg_get_dword(POL_MGR_UPDATE, "AllowMUUpdateService");
    let read = || -> Result<bool, String> {
        let manager = Disp::create("Microsoft.Update.ServiceManager").map_err(|e| e.message())?;
        let services = manager
            .call_obj("Services", &[])
            .map_err(|e| e.message())?
            .ok_or_else(|| "Services unavailable".to_string())?;
        let count = services
            .call("Count", &[])
            .map_err(|e| e.message())?
            .as_i32()
            .map_err(|e| e.message())?;
        let mut registered = false;
        for i in 0..count {
            let item = services
                .call_obj("Item", &[Arg::Int(i)])
                .map_err(|e| e.message())?;
            if let Some(service) = item {
                let id = service
                    .call("ServiceID", &[])
                    .map_err(|e| e.message())?
                    .as_string();
                if id == MU_SERVICE_ID {
                    registered = service
                        .call("IsRegisteredWithAU", &[])
                        .map_err(|e| e.message())?
                        .as_bool();
                }
            }
        }
        Ok(registered)
    };
    let registered = match read() {
        Ok(r) => r,
        Err(message) => {
            if get_service_start_type("wuauserv") == 4 {
                log::log("[Update] Microsoft Update registration not read because the Windows Update service is disabled.");
            } else {
                log::log(&format!(
                    "[ERROR] Microsoft Update registration check failed: {}",
                    message.trim_end()
                ));
            }
            return "Unknown".to_string();
        }
    };
    if mdm_policy == Some(0) {
        "Disabled"
    } else if mdm_policy == Some(1) && !registered {
        "Partial"
    } else if policy == Some(0) {
        "Disabled"
    } else if ux_setting == Some(0) && registered {
        "Partial"
    } else if registered {
        "Enabled"
    } else if policy == Some(1) || ux_setting == Some(1) {
        "Partial"
    } else {
        "Disabled"
    }
    .to_string()
}

pub fn get_driver_update_state() -> String {
    let gpo_exclude = reg_get_dword(POL_WU, "ExcludeWUDriversInQualityUpdate");
    let user_exclude = reg_get_dword(POL_WU_CU, "ExcludeWUDriversInQualityUpdate");
    let ux_exclude = reg_get_dword(UX_SET, "ExcludeWUDriversInQualityUpdate");
    let mdm_exclude = reg_get_dword(POL_MGR_UPDATE, "ExcludeWUDriversInQualityUpdate");
    let quality_updates_blocked = gpo_exclude == Some(1)
        || user_exclude == Some(1)
        || ux_exclude == Some(1)
        || mdm_exclude == Some(1);

    let policy_search_order = reg_get_dword(POL_DR, "SearchOrderConfig");
    let legacy_no_search = reg_get_dword(POL_DR, "DontSearchWindowsUpdate");
    let legacy_no_prompt = reg_get_dword(POL_DR, "DontPromptForWindowsUpdate");
    let legacy_wizard_search = reg_get_dword(POL_DR, "DriverUpdateWizardWuSearchEnabled");
    let user_no_search = reg_get_dword(POL_DR_CU, "DontSearchWindowsUpdate");
    let user_wizard_search = reg_get_dword(POL_DR_CU, "DriverUpdateWizardWuSearchEnabled");
    let user_no_prompt = reg_get_dword(POL_DR_CU, "DontPromptForWindowsUpdate");
    let user_search_order = reg_get_dword(SYS_DR, "SearchOrderConfig");
    let system_no_search = reg_get_dword(SYS_DR, "DontSearchWindowsUpdate");
    let system_no_prompt = reg_get_dword(SYS_DR, "DontPromptForWindowsUpdate");
    let system_wizard_search = reg_get_dword(SYS_DR, "DriverUpdateWizardWuSearchEnabled");
    let device_search_blocked = policy_search_order == Some(0)
        || legacy_no_search == Some(1)
        || legacy_no_prompt == Some(1)
        || legacy_wizard_search == Some(0)
        || user_no_search == Some(1)
        || user_wizard_search == Some(0)
        || user_no_prompt == Some(1)
        || system_no_search == Some(1)
        || system_no_prompt == Some(1)
        || system_wizard_search == Some(0)
        || (policy_search_order.is_none() && user_search_order == Some(0));

    let metadata_blocked = reg_get_dword(META, "PreventDeviceMetadataFromNetwork") == Some(1)
        || reg_get_dword(META_POL, "PreventDeviceMetadataFromNetwork") == Some(1);

    if quality_updates_blocked && device_search_blocked && metadata_blocked {
        return "Disabled".to_string();
    }
    if quality_updates_blocked || device_search_blocked || metadata_blocked {
        return "Partial".to_string();
    }

    let driver_source = reg_get_dword(POL_WU, "SetPolicyDrivenUpdateSourceForDriverUpdates");
    let use_wu_server = reg_get_dword(POL_WU_AU, "UseWUServer");
    if driver_source == Some(1) && use_wu_server == Some(1) {
        return "Partial".to_string();
    }

    let any_setting = [
        gpo_exclude,
        user_exclude,
        ux_exclude,
        mdm_exclude,
        policy_search_order,
        legacy_no_search,
        legacy_no_prompt,
        legacy_wizard_search,
        user_no_search,
        user_wizard_search,
        user_no_prompt,
        user_search_order,
        system_no_search,
        system_no_prompt,
        system_wizard_search,
        driver_source,
        use_wu_server,
        reg_get_dword(META, "PreventDeviceMetadataFromNetwork"),
        reg_get_dword(META_POL, "PreventDeviceMetadataFromNetwork"),
    ]
    .iter()
    .any(|v| v.is_some());
    if any_setting { "Enabled" } else { "N/A" }.to_string()
}

pub fn read_states() -> Snapshot {
    let mut snap = Snapshot::default();
    let wu_disabled = reg_get_dword(POL_WU, "DisableWindowsUpdateAccess");
    let ux_access_off = reg_get_dword(POL_WU, "SetDisableUXWUAccess");
    let wu_disabled_cu = reg_get_dword(POL_WU_CU, "DisableWindowsUpdateAccess");
    let do_not_connect = reg_get_dword(POL_WU, "DoNotConnectToWindowsUpdateInternetLocations");
    let do_not_connect_cu =
        reg_get_dword(POL_WU_CU, "DoNotConnectToWindowsUpdateInternetLocations");
    let no_auto_update = reg_get_dword(POL_WU_AU, "NoAutoUpdate");
    let no_auto_update_cu = reg_get_dword(POL_WU_AU_CU, "NoAutoUpdate");
    let pause_expiry = reg_get_string(UX_SET, "PauseUpdatesExpiryTime");
    let defer_feature = reg_get_dword(POL_WU, "DeferFeatureUpdates");
    let use_wu_server = reg_get_dword(POL_WU_AU, "UseWUServer");
    let mut service_state_unknown = false;
    let mut any_service_disabled = false;
    for service in UPDATE_SVCS {
        match update_service_exists(service) {
            Ok(exists) => {
                if exists && get_service_start_type(service) == 4 {
                    any_service_disabled = true;
                }
            }
            Err(e) => {
                service_state_unknown = true;
                log::log(&format!(
                    "[ERROR] Could not read update service {service}: {e}"
                ));
            }
        }
    }
    let task_states = read_update_task_states();
    let mut policy_state_unknown = false;
    let mut hard_policy_applied = false;
    match is_hard_disabled() {
        Ok(v) => hard_policy_applied = v,
        Err(e) => {
            policy_state_unknown = true;
            log::log(&format!(
                "[ERROR] Could not read update source ownership: {e}"
            ));
        }
    }
    let security_focused = is_security_focused();
    let home = is_windows_home();

    let policy_state: &str;
    let policy_detail: Option<String>;
    let mut warning: Option<String> = None;
    if policy_state_unknown {
        policy_state = "Partial";
        policy_detail = Some("Windows Update source ownership could not be read.".into());
        warning = Some(
            "Windows Update policy state could not be verified. Check the Toolkit log for details."
                .into(),
        );
    } else if hard_policy_applied {
        let infrastructure_matches = !service_state_unknown
            && hard_disable::matches(false)
            && service_guard::matches(false)
            && hard_disable_infrastructure_matches(task_states.as_ref());
        policy_state = if infrastructure_matches {
            "Hard Disabled"
        } else {
            "Partial"
        };
        policy_detail = Some(
            if infrastructure_matches {
                "Update source restrictions are configured, update services are stopped, disabled and protected, and installed update tasks are disabled."
            } else {
                "Hard disable is incomplete: update policies, service protection, services or tasks do not match or could not be verified."
            }
            .into(),
        );
        warning = Some(if infrastructure_matches {
            format!(
                "Update services are disabled and protected, and installed update tasks are disabled. Windows servicing can replace this protection.{}",
                if home { format!(" {HOME_HARD_DISABLE_NOTE}") } else { String::new() }
            )
        } else {
            "Windows Update hard disable is incomplete. Choose Hard Disabled to retry, Disabled for manual updates, or Normal to restore updates.".into()
        });
    } else if service_state_unknown {
        policy_state = "Partial";
        policy_detail = Some("The state of one or more update services could not be read.".into());
        warning = Some("Windows Update service state could not be verified. Check the Toolkit log for details.".into());
    } else if no_auto_update == Some(1)
        && ux_access_off != Some(1)
        && wu_disabled != Some(1)
        && wu_disabled_cu != Some(1)
        && do_not_connect != Some(1)
        && do_not_connect_cu != Some(1)
    {
        policy_state = "Disabled";
        policy_detail = Some(if home {
            "Automatic updates policy applied, but it may not take effect on Windows Home.".into()
        } else {
            "Automatic updates are turned off by policy (Configure Automatic Updates: Disabled)."
                .into()
        });
        warning = Some(if home {
            format!("Automatic updates are set to off. {HOME_POLICY_NOTE} Install updates manually from Settings > Windows Update.")
        } else {
            "Automatic updates are off. Install updates manually from Settings > Windows Update."
                .into()
        });
    } else if security_focused && !any_service_disabled {
        policy_state = "Enabled";
        policy_detail = Some("Security-focused update policy is active.".into());
        warning = Some(security_focused_description());
    } else if any_service_disabled
        || (!security_focused && !update_tasks_match(task_states.as_ref(), true))
        || no_auto_update == Some(1)
        || no_auto_update_cu == Some(1)
        || wu_disabled == Some(1)
        || wu_disabled_cu == Some(1)
        || ux_access_off == Some(1)
        || do_not_connect == Some(1)
        || do_not_connect_cu == Some(1)
    {
        policy_state = "Partial";
        policy_detail = None;
        warning = Some("Windows Update has a partial or conflicting configuration. Choose Normal to repair XOS-managed settings.".into());
    } else if use_wu_server == Some(1) || has_managed_update_policy() {
        policy_state = "Partial";
        policy_detail = Some("An organization policy controls Windows Update.".into());
        warning = Some(
            "An organization policy controls Windows Update. Local preferences may be overridden."
                .into(),
        );
    } else if defer_feature == Some(1) || reg_get_dword(POL_WU, "TargetReleaseVersion") == Some(1) {
        policy_state = "Partial";
        policy_detail = Some("A feature-update restriction is configured.".into());
        warning = Some("A feature-update restriction is configured. Choose Normal to remove local feature restrictions.".into());
    } else if let Some(until) = pause_expiry
        .as_deref()
        .and_then(parse_pause_expiry)
        .filter(|u| *u > Utc::now())
    {
        let date = short_date(&until.with_timezone(&Local));
        policy_state = "Disabled";
        policy_detail = Some(format!("Windows Update is paused until {date}."));
        warning = Some(format!("Windows updates are paused until {date}."));
    } else {
        policy_state = "Enabled";
        policy_detail = Some("Windows Update is using its normal Windows configuration.".into());
    }
    snap.policy = status::badge_with(policy_state, policy_detail.as_deref());
    snap.policy_warning = warning;

    let do_mode = reg_get_dword(POL_DO, "DODownloadMode");
    let do_config_mode = reg_get_dword(DO_CONFIG, "DODownloadMode");
    let do_state: String =
        if do_mode.is_some() && do_config_mode.is_some() && do_mode != do_config_mode {
            "Partial".into()
        } else {
            let effective = do_mode
                .or(do_config_mode)
                .or_else(|| reg_get_dword(DO_USER, "SystemSettingsDownloadMode"))
                .or_else(|| reg_get_dword(DO_NETWORK_SERVICE, "DownloadMode"));
            match effective {
                None => status::AUTOMATIC.into(),
                Some(0) | Some(99) | Some(100) => "Disabled".into(),
                Some(v) if (1..=3).contains(&v) => "Enabled".into(),
                Some(_) => "Partial".into(),
            }
        };
    snap.delivery = status::badge(&do_state);

    let no_reboot = reg_get_dword(POL_WU_AU, "NoAutoRebootWithLoggedOnUsers");
    let scheduled_installs = reg_get_dword(POL_WU_AU, "AUOptions") == Some(4)
        && no_auto_update != Some(1)
        && reg_get_dword(UX_SET, "IsExpedited") != Some(1);
    let restart_deadline = reg_get_dword(POL_WU, "SetComplianceDeadline") == Some(1)
        || reg_get_dword(POL_MGR_UPDATE, "ConfigureDeadlineForQualityUpdates").is_some();
    let no_reboot_state: &str = match no_reboot {
        None => status::DISABLED_WINDOWS_DEFAULT,
        Some(0) => "Disabled",
        Some(1) => "Enabled",
        Some(_) => "Partial",
    };
    let no_reboot_detail = if !scheduled_installs && no_reboot_state == "Enabled" {
        Some("The preference is enabled, but no scheduled update installation is currently active.")
    } else if restart_deadline && no_reboot_state == "Enabled" {
        Some("The preference is enabled, but Windows Update deadlines can still require a restart.")
    } else {
        None
    };
    snap.no_reboot = status::badge_with(no_reboot_state, no_reboot_detail);

    let expedited = reg_get_dword(UX_SET, "IsExpedited");
    snap.expedited = status::badge(&status::toggle_with(
        expedited,
        1,
        0,
        status::DISABLED_WINDOWS_DEFAULT,
    ));

    let notif_policy = reg_get_dword(POL_WU, "SetUpdateNotificationLevel");
    let notif_level = reg_get_dword(POL_WU, "UpdateNotificationLevel");
    let notif_policy_cu = reg_get_dword(POL_WU_CU, "SetUpdateNotificationLevel");
    let notif_level_cu = reg_get_dword(POL_WU_CU, "UpdateNotificationLevel");
    let notifications_disabled =
        notif_policy == Some(1) && (notif_level == Some(1) || notif_level == Some(2));
    let notification_conflict = notif_policy_cu.is_some()
        || notif_level_cu.is_some()
        || (notif_policy == Some(1) && notif_level != Some(1) && notif_level != Some(2))
        || (notif_policy != Some(1) && (notif_level == Some(1) || notif_level == Some(2)));
    let notif_state: &str = if notification_conflict {
        "Partial"
    } else if notifications_disabled {
        "Disabled"
    } else if notif_policy.is_none() && notif_level.is_none() {
        status::ENABLED_WINDOWS_DEFAULT
    } else if notif_policy == Some(0) {
        "Enabled"
    } else {
        "Partial"
    };
    snap.update_notif = status::badge(notif_state);

    let restart_notif = reg_get_dword(UX_SET, "RestartNotificationsAllowed2");
    let restart_state = if notif_policy == Some(1) && notif_level == Some(2) {
        "Disabled".to_string()
    } else {
        status::toggle_with(restart_notif, 1, 0, status::DISABLED_WINDOWS_DEFAULT)
    };
    snap.restart_notif = status::badge(&restart_state);

    let latest = reg_get_dword(UX_SET, "IsContinuousInnovationOptedIn");
    let latest_supported = supports_latest_updates();
    let optional_policy = if supports_optional_content() {
        reg_get_dword(POL_MGR_UPDATE, "AllowOptionalContent")
            .or_else(|| reg_get_dword(POL_WU, "SetAllowOptionalContent"))
            .or_else(|| reg_get_dword(POL_WU, "AllowOptionalContent"))
    } else {
        None
    };
    let latest_state = if !latest_supported {
        "N/A".to_string()
    } else if optional_policy == Some(0) || optional_policy == Some(2) {
        "Disabled".to_string()
    } else if optional_policy == Some(1) {
        "Enabled".to_string()
    } else {
        status::toggle_with(latest, 1, 0, status::DISABLED_WINDOWS_DEFAULT)
    };
    snap.latest = status::badge(&latest_state);
    snap.latest_supported = latest_supported;
    snap.security_enabled = supports_update_policies();
    snap.disabled_tooltip = Some(format!(
        "Turns off automatic updates with the documented Configure Automatic Updates policy (Disabled). You install updates yourself from Settings > Windows Update.{}",
        if home { format!(" {HOME_POLICY_NOTE}") } else { String::new() }
    ));
    if !snap.security_enabled {
        let edition = edition_id();
        snap.security_tooltip = Some(format!(
            "{} Microsoft supports these update policies only on Pro, Enterprise and Education.",
            if starts_with_ci(&edition, "Core") {
                "Not available on Windows Home."
            } else {
                "Not available on this Windows edition."
            }
        ));
    }

    let wu_service_disabled = get_service_start_type("wuauserv") == 4;
    let other_state = if wu_service_disabled {
        "Disabled".to_string()
    } else {
        get_other_microsoft_products_state()
    };
    snap.other_products = status::badge_with(
        &other_state,
        if wu_service_disabled {
            Some("The Windows Update service is disabled, so no updates for other Microsoft products are installed.")
        } else {
            None
        },
    );

    let metered_policy = reg_get_dword(POL_WU, "AllowAutoWindowsUpdateDownloadOverMeteredNetwork");
    let metered_ux = reg_get_dword(UX_SET, "AllowAutoWindowsUpdateDownloadOverMeteredNetwork");
    let metered_state =
        if metered_policy.is_some() && metered_ux.is_some() && metered_policy != metered_ux {
            "Partial".to_string()
        } else {
            status::toggle_with(
                metered_policy.or(metered_ux),
                1,
                0,
                status::DISABLED_WINDOWS_DEFAULT,
            )
        };
    snap.metered = status::badge(&metered_state);

    snap.drivers = status::badge(&get_driver_update_state());

    let store_auto = reg_get_dword(POL_STORE, "AutoDownload");
    let store_setting = reg_get_dword(STORE_SET, "AutoDownload");
    let store_state: String =
        if store_auto.is_some() && store_setting.is_some() && store_auto != store_setting {
            "Partial".into()
        } else {
            match store_auto.or(store_setting) {
                Some(2) => "Disabled".into(),
                None => status::AUTOMATIC.into(),
                Some(4) => "Enabled".into(),
                Some(_) => "Partial".into(),
            }
        };
    snap.store = status::badge(&store_state);

    snap.hard_policy_applied = hard_policy_applied;
    snap.msa = is_microsoft_account();
    snap
}

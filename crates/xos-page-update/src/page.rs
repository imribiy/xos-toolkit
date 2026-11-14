use std::sync::Mutex;

use anyhow::Result;
use regex::Regex;
use xos_core::app_state;
use xos_core::host::{Buttons, DialogResult, Host, Icon, Page};
use xos_core::log;
use xos_core::ui::*;
use xos_sys::{
    http_get_string, ops, reg_delete_value, reg_get_dword, reg_get_string, reg_set_dword,
    reg_set_string, run_cmd_with_error_timeout,
};
use xos_winupdate::{hard_disable, service_guard};

use crate::consts::*;
use crate::detect::*;
use crate::infra::*;

struct State {
    snap: Snapshot,
    sub_disabled: bool,
    sub_note: bool,
    busy: Option<String>,
}

pub struct UpdatePage {
    st: Mutex<State>,
}

impl Default for UpdatePage {
    fn default() -> Self {
        Self::new()
    }
}

pub fn json_value(json: &str, key: &str) -> Option<String> {
    let pattern = format!("(?i)\"{}\"\\s*:\\s*\"([^\"]*)\"", regex::escape(key));
    let re = Regex::new(&pattern).ok()?;
    re.captures(json)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
}

fn is_https_absolute(uri: &str) -> bool {
    let lower = uri.to_ascii_lowercase();
    match lower.strip_prefix("https://") {
        Some(rest) => {
            let host = rest.split(['/', '?', '#']).next().unwrap_or("");
            !host.is_empty() && !uri.chars().any(|c| c.is_whitespace())
        }
        None => false,
    }
}

pub fn update_kgl() -> Option<String> {
    let body = match http_get_string(KGL_API) {
        Some(b) if !b.is_empty() => b,
        _ => {
            return Some(
                "No response from Microsoft. Check your internet connection and try again.".into(),
            )
        }
    };
    let uri = json_value(&body, "URI");
    let hash = json_value(&body, "HASH");
    let version_str = json_value(&body, "VERSION");
    let activate_str = json_value(&body, "ACTIVATEONUPDATE");
    let timeout_str = json_value(&body, "VERSIONCHECKTIMEOUT");

    let version = version_str
        .as_deref()
        .and_then(|s| s.trim().parse::<i32>().ok());
    let version = match version {
        Some(v) if v >= 0 => v,
        _ => return Some("The response from Microsoft was not in the expected format.".into()),
    };
    let uri = match uri {
        Some(u) if is_https_absolute(&u) => u,
        _ => return Some("The response from Microsoft was not in the expected format.".into()),
    };
    let hash = match hash {
        Some(h) if !h.trim().is_empty() => h,
        _ => return Some("The response from Microsoft was not in the expected format.".into()),
    };
    let activate = activate_str
        .as_deref()
        .and_then(|s| s.trim().parse::<u32>().ok());
    let timeout = timeout_str
        .as_deref()
        .and_then(|s| s.trim().parse::<i32>().ok());
    let (activate, timeout) = match (activate, timeout) {
        (Some(a), Some(t)) if t >= 0 => (a, t),
        _ => return Some("The response from Microsoft contained an invalid numeric value.".into()),
    };

    reg_set_dword(KGL_ONE, "ActivateOnUpdate", activate as i32);
    reg_set_string(KGL_ONE, "Hash", &hash);
    reg_set_string(KGL_ONE, "URI", &uri);
    reg_set_dword(KGL_ONE, "Version", version);
    reg_set_dword(KGL_ONE, "VersionCheckTimeout", timeout);
    None
}

pub const ROOT_CERT_SCRIPT: &str = "$ErrorActionPreference='Stop';$sst = Join-Path $env:TEMP ([System.IO.Path]::GetRandomFileName() + '.sst');try {  & certutil.exe -generateSSTFromWU -f $sst | Out-Null;  if ($LASTEXITCODE -ne 0) { throw ('certutil failed with exit code ' + $LASTEXITCODE) };  if (-not (Test-Path $sst) -or (Get-Item $sst).Length -le 0) { throw 'Microsoft returned an empty certificate store' };  Import-Certificate -FilePath $sst -CertStoreLocation 'Cert:\\LocalMachine\\Root' -ErrorAction Stop | Out-Null;  Import-Certificate -FilePath $sst -CertStoreLocation 'Cert:\\LocalMachine\\AuthRoot' -ErrorAction Stop | Out-Null;} finally {  Remove-Item -LiteralPath $sst -Force -ErrorAction SilentlyContinue;}";

pub fn update_root_certificates() -> Option<String> {
    let encoded = encode_command(ROOT_CERT_SCRIPT);
    let (ok, error) = run_cmd_with_error_timeout(
        "powershell.exe",
        &format!("-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}"),
        120000,
    );
    if ok {
        None
    } else {
        Some(error.unwrap_or_else(|| "The certificate update command failed.".to_string()))
    }
}

impl UpdatePage {
    pub fn new() -> Self {
        Self {
            st: Mutex::new(State {
                snap: Snapshot::default(),
                sub_disabled: false,
                sub_note: false,
                busy: None,
            }),
        }
    }

    fn refresh_states(&self) {
        let snap = read_states();
        let mut st = self.st.lock().unwrap();
        st.sub_disabled = snap.hard_policy_applied;
        st.sub_note = snap.hard_policy_applied;
        st.snap = snap;
    }

    fn set_sub_settings_enabled(&self, enabled: bool) {
        self.st.lock().unwrap().sub_disabled = !enabled;
    }

    fn set_busy(&self, host: &dyn Host, busy: bool, message: Option<&str>) {
        {
            let mut st = self.st.lock().unwrap();
            if busy {
                let text = match message {
                    Some(m) => m.to_string(),
                    None => st.busy.clone().unwrap_or_else(|| "Applying...".to_string()),
                };
                st.busy = Some(text);
            } else {
                st.busy = None;
            }
        }
        if let Some(m) = message {
            host.set_status(m);
        }
        host.publish(self.model());
    }

    fn done(&self, host: &dyn Host, msg: &str, operation_failed: bool, detail: Option<&str>) {
        let failed = operation_failed || ops::any_failed();
        log::action_done("Update", operation_failed, failed, detail);
        ops::reset();
        app_state::require_reboot_if_message_asks(msg);
        let mut msg = msg.to_string();
        if failed {
            log::log(&format!("[ERROR] Windows Update action incomplete: {msg}"));
            msg = "The operation did not complete. Some settings may have changed. Check the Toolkit log for details.".to_string();
        }
        host.set_status(&msg);
        host.dialog(
            &msg,
            "XOS Toolkit",
            Buttons::Ok,
            if failed {
                Icon::Warning
            } else {
                Icon::Information
            },
        );
    }

    fn guarded(&self, host: &dyn Host, refresh_on_error: bool, body: impl FnOnce() -> Result<()>) {
        if let Err(e) = body() {
            log::log(&format!("[ERROR] Windows Update action failed: {e:#}"));
            if refresh_on_error {
                self.refresh_states();
            }
            self.done(host, "Windows Update action failed.", true, None);
        }
        self.set_busy(host, false, None);
    }

    fn policy_normal(&self, host: &dyn Host) {
        self.guarded(host, true, || {
            ops::reset();
            self.set_busy(host, true, Some("Restoring update services..."));
            clean_policy_overlay(true);
            clean_hard_disable_registry()?;
            clear_feature_restrictions();
            if reg_get_dword(POL_WU_AU, "NoAutoRebootWithLoggedOnUsers") == Some(1) {
                reg_set_dword(POL_WU_AU, "AUOptions", 4);
            }
            remove_hidden_settings_page("windowsupdate");
            let infrastructure_ok = restore_update_infrastructure()?;
            app_state::require_reboot();
            self.refresh_states();
            self.set_busy(host, false, None);
            self.done(
                host,
                "Windows Update services and tasks restored. Local pause and feature restrictions removed.",
                !infrastructure_ok,
                None,
            );
            Ok(())
        });
    }

    fn policy_security_only(&self, host: &dyn Host) {
        self.guarded(host, true, || {
            if !supports_update_policies() {
                return Ok(());
            }
            let release = reg_get_string(CURRENT_VERSION, "DisplayVersion");
            let build = build_number();
            if build >= 22000 && release.as_deref().map_or(true, |r| r.trim().is_empty()) {
                self.done(
                    host,
                    "Could not determine the installed Windows release.",
                    true,
                    None,
                );
                return Ok(());
            }
            ops::reset();
            self.set_busy(host, true, Some("Configuring update services..."));
            clean_policy_overlay(false);
            clean_hard_disable_registry()?;
            clear_feature_restrictions();
            reg_set_dword(
                POL_WU_AU,
                "AUOptions",
                if reg_get_dword(POL_WU_AU, "NoAutoRebootWithLoggedOnUsers") == Some(1) {
                    4
                } else {
                    2
                },
            );
            reg_set_dword(POL_WU_AU, "NoAutoUpdate", 0);
            if build >= 22000 {
                reg_set_string(POL_WU, "ProductVersion", "Windows 11");
                reg_set_string(
                    POL_WU,
                    "TargetReleaseVersionInfo",
                    release.as_deref().unwrap_or(""),
                );
                reg_set_dword(POL_WU, "TargetReleaseVersion", 1);
            } else {
                reg_set_dword(POL_WU, "DeferFeatureUpdates", 1);
                reg_set_dword(POL_WU, "DeferFeatureUpdatesPeriodInDays", 365);
            }
            if supports_optional_content() {
                reg_set_dword(POL_WU, "SetAllowOptionalContent", 0);
            }
            if supports_latest_updates() {
                reg_set_dword(UX_SET, "IsContinuousInnovationOptedIn", 0);
            }
            let infrastructure_ok = restore_update_infrastructure()?;
            app_state::require_reboot();
            remove_hidden_settings_page("windowsupdate");
            self.refresh_states();
            self.set_busy(host, false, None);
            self.done(
                host,
                &security_focused_description(),
                !infrastructure_ok || !is_security_focused(),
                None,
            );
            Ok(())
        });
    }

    fn policy_blocked(&self, host: &dyn Host) {
        self.guarded(host, true, || {
            ops::reset();
            let home = is_windows_home();
            let message = format!(
                "This turns off automatic Windows updates (the documented Configure Automatic Updates policy, Disabled).\n\nWindows will not install updates on its own, security fixes included. Install them yourself from Settings > Windows Update.\n\n{}Continue?",
                if home { format!("{HOME_POLICY_NOTE}\n\n") } else { String::new() }
            );
            let result = host.dialog(&message, "Warning", Buttons::YesNo, Icon::Warning);
            if result != DialogResult::Yes {
                return Ok(());
            }

            self.set_busy(host, true, Some("Configuring update services..."));

            clean_policy_overlay(false);
            clean_hard_disable_registry()?;
            clear_feature_restrictions();

            reg_set_dword(POL_WU_AU, "NoAutoUpdate", 1);
            reg_set_dword(POL_WU_AU, "NoAUShutdownOption", 1);
            reg_set_dword(POL_WU_AU_CU, "NoAUShutdownOption", 1);
            reg_set_dword(POL_WU_AU, "AlwaysAutoRebootAtScheduledTime", 0);
            reg_set_dword(POL_WU_AU, "AutoInstallMinorUpdates", 0);
            reg_set_dword(POL_WU_AU, "UseWUServer", 0);
            let applied = reg_get_dword(POL_WU_AU, "NoAutoUpdate") == Some(1);
            if !applied {
                log::log("[ERROR] Windows Update: NoAutoUpdate did not read back as 1.");
            }

            let infrastructure_ok = set_blocked_mode_infrastructure()?;
            app_state::require_reboot();

            remove_hidden_settings_page("windowsupdate");

            self.refresh_states();
            self.set_busy(host, false, None);
            let (msg, detail) = if home {
                (
                    format!("Automatic updates policy applied (NoAutoUpdate=1). {HOME_POLICY_NOTE} Install updates manually from Settings > Windows Update."),
                    "NoAutoUpdate=1 applied; Windows Home: may not take effect, Windows may still install updates automatically",
                )
            } else {
                (
                    "Automatic updates turned off. Install updates manually from Settings > Windows Update.".to_string(),
                    "NoAutoUpdate=1 applied",
                )
            };
            self.done(host, &msg, !infrastructure_ok || !applied, Some(detail));
            Ok(())
        });
    }

    fn policy_disabled(&self, host: &dyn Host) {
        self.guarded(host, true, || {
            ops::reset();
            let home = is_windows_home();
            let message = format!(
                "Hard Disabled blocks Windows Update sources and public update access, and disables update services and scheduled tasks. The PC will miss Windows security fixes.\n\nThis can disrupt Microsoft Store installs and updates, Defender updates, optional Windows features and other functions that depend on the disabled components. Microsoft account and Windows Hello behavior varies by configuration.\n\nThis is NOT recommended for daily use. Choose Disabled for manual Windows updates, or Security Focused instead.\n\nThis protects disabled update services against ordinary repair. Restart after applying. Windows servicing can replace this protection. Choose Normal, Disabled or Security Focused in the Toolkit to restore service permissions and update components.\n\n{}Continue?",
                if home { format!("{HOME_HARD_DISABLE_NOTE}\n\n") } else { String::new() }
            );
            let result = host.dialog(&message, "Warning", Buttons::YesNo, Icon::Warning);
            if result != DialogResult::Yes {
                return Ok(());
            }

            self.set_busy(host, true, Some("Disabling update services..."));

            clean_policy_overlay(false);
            clear_feature_restrictions();

            clean_hard_disable_registry()?;
            let policies_ok = hard_disable::apply();

            let settings_page_hidden = add_hidden_settings_page("windowsupdate");

            app_state::require_reboot();
            let infrastructure_ok = disable_update_infrastructure(true)?;
            let guards_ok = service_guard::matches(true);

            self.set_sub_settings_enabled(false);
            self.refresh_states();
            if is_hard_disabled()? {
                self.set_sub_settings_enabled(false);
            }
            self.st.lock().unwrap().sub_note = true;
            self.set_busy(host, false, None);
            let verified = policies_ok
                && infrastructure_ok
                && guards_ok
                && settings_page_hidden
                && service_guard::matches(true)
                && hard_disable::matches(true)
                && hard_disable_infrastructure_matches(read_update_task_states().as_ref());
            let msg = format!(
                "{}{}",
                if verified {
                    "Windows Update sources blocked, update services stopped, disabled and protected, and known update tasks disabled."
                } else {
                    "Windows Update hard disable is incomplete; check the Toolkit log and retry."
                },
                if home { format!(" {HOME_HARD_DISABLE_NOTE}") } else { String::new() }
            );
            let detail = if !verified {
                "Hard-disable configuration could not be fully verified; see the preceding errors"
            } else if home {
                "Update policies applied best effort on Windows Home; service protection verified, services and tasks disabled"
            } else {
                "Update source policies and service protection verified, services and tasks disabled"
            };
            self.done(host, &msg, !verified, Some(detail));
            Ok(())
        });
    }

    fn do_default(&self, host: &dyn Host) {
        ops::reset();
        reg_delete_value(POL_DO, "DODownloadMode");
        reg_delete_value(POL_DO_CU, "DODownloadMode");
        reg_delete_value(DO_CONFIG, "DODownloadMode");
        reg_delete_value(DO_USER, "SystemSettingsDownloadMode");
        reg_delete_value(DO_NETWORK_SERVICE, "DownloadMode");
        self.refresh_states();
        self.done(
            host,
            "Delivery Optimization overrides removed.",
            false,
            None,
        );
    }

    fn do_lan_only(&self, host: &dyn Host) {
        ops::reset();
        reg_set_dword(POL_DO, "DODownloadMode", 1);
        reg_delete_value(POL_DO_CU, "DODownloadMode");
        reg_set_dword(DO_CONFIG, "DODownloadMode", 1);
        self.refresh_states();
        self.done(
            host,
            "Delivery Optimization set to LAN only (no internet sharing).",
            false,
            None,
        );
    }

    fn do_disable(&self, host: &dyn Host) {
        ops::reset();
        reg_set_dword(POL_DO, "DODownloadMode", 0);
        reg_delete_value(POL_DO_CU, "DODownloadMode");
        reg_set_dword(DO_CONFIG, "DODownloadMode", 0);
        self.refresh_states();
        self.done(
            host,
            "Delivery Optimization peer sharing disabled.",
            false,
            None,
        );
    }

    fn no_reboot_enable(&self, host: &dyn Host) {
        ops::reset();
        reg_set_dword(POL_WU_AU, "AUOptions", 4);
        reg_set_dword(UX_SET, "IsExpedited", 0);
        reg_set_dword(POL_WU_AU, "NoAutoRebootWithLoggedOnUsers", 1);
        reg_delete_value(POL_WU_AU_CU, "NoAutoRebootWithLoggedOnUsers");
        self.refresh_states();
        self.done(
            host,
            "Scheduled restart preference saved. Enforced deadlines can override it.",
            false,
            None,
        );
    }

    fn no_reboot_disable(&self, host: &dyn Host) {
        ops::reset();
        reg_delete_value(POL_WU_AU, "NoAutoRebootWithLoggedOnUsers");
        reg_delete_value(POL_WU_AU_CU, "NoAutoRebootWithLoggedOnUsers");
        self.refresh_states();
        self.done(
            host,
            "Automatic restart behavior restored to default.",
            false,
            None,
        );
    }

    fn expedited_enable(&self, host: &dyn Host) {
        ops::reset();
        reg_delete_value(POL_WU_AU, "NoAutoRebootWithLoggedOnUsers");
        reg_delete_value(POL_WU_AU_CU, "NoAutoRebootWithLoggedOnUsers");
        reg_set_dword(UX_SET, "IsExpedited", 1);
        self.refresh_states();
        self.done(
            host,
            "Get Me Up To Date enabled. Windows will restart ASAP to apply updates.",
            false,
            None,
        );
    }

    fn expedited_disable(&self, host: &dyn Host) {
        ops::reset();
        reg_set_dword(UX_SET, "IsExpedited", 0);
        self.refresh_states();
        self.done(host, "Get Me Up To Date disabled.", false, None);
    }

    fn update_notif_enable(&self, host: &dyn Host) {
        ops::reset();
        reg_delete_value(POL_WU, "SetUpdateNotificationLevel");
        reg_delete_value(POL_WU, "UpdateNotificationLevel");
        reg_delete_value(POL_WU_CU, "SetUpdateNotificationLevel");
        reg_delete_value(POL_WU_CU, "UpdateNotificationLevel");
        self.refresh_states();
        self.done(host, "Update notifications enabled.", false, None);
    }

    fn update_notif_disable(&self, host: &dyn Host) {
        ops::reset();
        reg_set_dword(POL_WU, "SetUpdateNotificationLevel", 1);
        reg_set_dword(POL_WU, "UpdateNotificationLevel", 1);
        reg_delete_value(POL_WU_CU, "SetUpdateNotificationLevel");
        reg_delete_value(POL_WU_CU, "UpdateNotificationLevel");
        self.refresh_states();
        self.done(host, "Update notifications disabled.", false, None);
    }

    fn restart_notif_enable(&self, host: &dyn Host) {
        ops::reset();
        if reg_get_dword(POL_WU, "SetUpdateNotificationLevel") == Some(1)
            && reg_get_dword(POL_WU, "UpdateNotificationLevel") == Some(2)
        {
            reg_set_dword(POL_WU, "UpdateNotificationLevel", 1);
        }
        reg_set_dword(UX_SET, "RestartNotificationsAllowed2", 1);
        self.refresh_states();
        self.done(host, "Restart required notifications enabled.", false, None);
    }

    fn restart_notif_disable(&self, host: &dyn Host) {
        ops::reset();
        reg_delete_value(UX_SET, "RestartNotificationsAllowed2");
        self.refresh_states();
        self.done(
            host,
            "Restart required notifications disabled.",
            false,
            None,
        );
    }

    fn latest_enable(&self, host: &dyn Host) {
        ops::reset();
        if !supports_latest_updates() {
            return;
        }
        if supports_optional_content() {
            reg_delete_value(POL_WU, "AllowOptionalContent");
            reg_set_dword(POL_WU, "SetAllowOptionalContent", 3);
        }
        reg_set_dword(UX_SET, "IsContinuousInnovationOptedIn", 1);
        self.refresh_states();
        let text = self.st.lock().unwrap().snap.latest.text.clone();
        self.done(
            host,
            "Latest updates as soon as available: enabled.",
            text != "Enabled",
            None,
        );
    }

    fn latest_disable(&self, host: &dyn Host) {
        if !supports_latest_updates() {
            return;
        }
        ops::reset();
        if supports_optional_content()
            && reg_get_dword(POL_WU, "SetAllowOptionalContent") == Some(1)
        {
            reg_set_dword(POL_WU, "SetAllowOptionalContent", 2);
        }
        reg_set_dword(UX_SET, "IsContinuousInnovationOptedIn", 0);
        self.refresh_states();
        let text = self.st.lock().unwrap().snap.latest.text.clone();
        self.done(
            host,
            "Latest updates as soon as available: disabled.",
            text == "Enabled",
            None,
        );
    }

    fn other_products_enable(&self, host: &dyn Host) {
        self.guarded(host, false, || {
            ops::reset();
            self.set_busy(host, true, Some("Registering Microsoft Update..."));
            reg_set_dword(POL_WU_AU, "AllowMUUpdateService", 1);
            reg_set_dword(UX_SET, "AllowMUUpdateService", 1);
            let registered = set_microsoft_update_registration(true);
            let resulting_state = get_other_microsoft_products_state();
            self.refresh_states();
            self.set_busy(host, false, None);
            self.done(
                host,
                "Updates for other Microsoft products enabled.",
                !registered || resulting_state != "Enabled",
                None,
            );
            Ok(())
        });
    }

    fn other_products_disable(&self, host: &dyn Host) {
        self.guarded(host, false, || {
            ops::reset();
            self.set_busy(host, true, Some("Unregistering Microsoft Update..."));
            reg_delete_value(POL_WU_AU, "AllowMUUpdateService");
            reg_set_dword(UX_SET, "AllowMUUpdateService", 0);
            let unregistered = set_microsoft_update_registration(false);
            let resulting_state = get_other_microsoft_products_state();
            self.refresh_states();
            self.set_busy(host, false, None);
            self.done(
                host,
                "Updates for other Microsoft products disabled.",
                !unregistered || !resulting_state.starts_with("Disabled"),
                None,
            );
            Ok(())
        });
    }

    fn metered_enable(&self, host: &dyn Host) {
        ops::reset();
        reg_set_dword(
            POL_WU,
            "AllowAutoWindowsUpdateDownloadOverMeteredNetwork",
            1,
        );
        reg_set_dword(
            UX_SET,
            "AllowAutoWindowsUpdateDownloadOverMeteredNetwork",
            1,
        );
        self.refresh_states();
        self.done(
            host,
            "Updates over metered connections: allowed.",
            false,
            None,
        );
    }

    fn metered_disable(&self, host: &dyn Host) {
        ops::reset();
        reg_delete_value(POL_WU, "AllowAutoWindowsUpdateDownloadOverMeteredNetwork");
        reg_delete_value(UX_SET, "AllowAutoWindowsUpdateDownloadOverMeteredNetwork");
        self.refresh_states();
        self.done(
            host,
            "Updates over metered connections: blocked.",
            false,
            None,
        );
    }

    fn drivers_allow(&self, host: &dyn Host) {
        ops::reset();
        reg_delete_value(POL_WU, "ExcludeWUDriversInQualityUpdate");
        reg_delete_value(POL_WU_CU, "ExcludeWUDriversInQualityUpdate");
        reg_delete_value(UX_SET, "ExcludeWUDriversInQualityUpdate");
        reg_delete_value(POL_DR, "SearchOrderConfig");
        reg_delete_value(POL_DR, "DontSearchWindowsUpdate");
        reg_delete_value(POL_DR, "DontPromptForWindowsUpdate");
        reg_delete_value(POL_DR, "DriverUpdateWizardWuSearchEnabled");
        reg_delete_value(POL_DR_CU, "DontSearchWindowsUpdate");
        reg_delete_value(POL_DR_CU, "DriverUpdateWizardWuSearchEnabled");
        reg_delete_value(POL_DR_CU, "DontPromptForWindowsUpdate");
        reg_set_dword(SYS_DR, "SearchOrderConfig", 1);
        reg_delete_value(SYS_DR, "DontSearchWindowsUpdate");
        reg_delete_value(SYS_DR, "DontPromptForWindowsUpdate");
        reg_delete_value(SYS_DR, "DriverUpdateWizardWuSearchEnabled");
        reg_delete_value(META, "PreventDeviceMetadataFromNetwork");
        reg_delete_value(META_POL, "PreventDeviceMetadataFromNetwork");
        let resulting_state = get_driver_update_state();
        self.refresh_states();
        if resulting_state == "Enabled" {
            self.done(
                host,
                "Driver updates via Windows Update: allowed.",
                false,
                None,
            );
        } else {
            self.done(
                host,
                "XOS-managed driver restrictions were removed, but another Windows policy is still controlling driver updates.",
                true,
                None,
            );
        }
    }

    fn drivers_block(&self, host: &dyn Host) {
        ops::reset();
        reg_set_dword(POL_WU, "ExcludeWUDriversInQualityUpdate", 1);
        reg_set_dword(POL_DR, "SearchOrderConfig", 0);
        reg_set_dword(POL_DR, "DontSearchWindowsUpdate", 1);
        reg_set_dword(POL_DR, "DontPromptForWindowsUpdate", 1);
        reg_set_dword(SYS_DR, "SearchOrderConfig", 0);
        reg_set_dword(SYS_DR, "DontSearchWindowsUpdate", 1);
        reg_set_dword(META, "PreventDeviceMetadataFromNetwork", 1);
        reg_set_dword(META_POL, "PreventDeviceMetadataFromNetwork", 1);
        reg_delete_value(POL_WU_CU, "ExcludeWUDriversInQualityUpdate");
        reg_delete_value(UX_SET, "ExcludeWUDriversInQualityUpdate");
        reg_delete_value(POL_DR_CU, "DontSearchWindowsUpdate");
        reg_delete_value(POL_DR_CU, "DriverUpdateWizardWuSearchEnabled");
        reg_delete_value(POL_DR_CU, "DontPromptForWindowsUpdate");
        let resulting_state = get_driver_update_state();
        self.refresh_states();
        if resulting_state == "Disabled" {
            self.done(
                host,
                "Driver updates via Windows Update: blocked.",
                false,
                None,
            );
        } else {
            self.done(
                host,
                "The driver-update block was only partially applied. Check the reported state and Toolkit log.",
                true,
                None,
            );
        }
    }

    fn store_enable(&self, host: &dyn Host) {
        ops::reset();
        reg_set_dword(POL_STORE, "AutoDownload", 4);
        reg_delete_value(POL_STORE_CU, "AutoDownload");
        reg_set_dword(STORE_SET, "AutoDownload", 4);
        self.refresh_states();
        self.done(host, "Microsoft Store auto-updates: enabled.", false, None);
    }

    fn store_disable(&self, host: &dyn Host) {
        ops::reset();
        reg_set_dword(POL_STORE, "AutoDownload", 2);
        reg_delete_value(POL_STORE_CU, "AutoDownload");
        reg_set_dword(STORE_SET, "AutoDownload", 2);
        self.refresh_states();
        self.done(host, "Microsoft Store auto-updates: disabled.", false, None);
    }

    fn kgl(&self, host: &dyn Host) {
        self.guarded(host, false, || {
            ops::reset();
            self.set_busy(host, true, Some("Updating Known Game List..."));
            let error = update_kgl();
            self.set_busy(host, false, None);
            match error {
                None => self.done(
                    host,
                    "Known Game List download metadata refreshed from Microsoft.",
                    false,
                    None,
                ),
                Some(error) => {
                    host.set_status("Known Game List update failed.");
                    log::log(&format!("[ERROR] Known Game List update failed: {error}"));
                    host.dialog(
                        &format!("Could not update the Known Game List.\n\n{error}"),
                        "XOS Toolkit",
                        Buttons::Ok,
                        Icon::Warning,
                    );
                }
            }
            Ok(())
        });
    }

    fn certs(&self, host: &dyn Host) {
        self.guarded(host, false, || {
            ops::reset();
            self.set_busy(host, true, Some("Updating root certificates..."));
            let error = update_root_certificates();
            self.set_busy(host, false, None);
            match error {
                None => self.done(host, "Root certificates updated from Microsoft.", false, None),
                Some(error) => {
                    host.set_status("Root certificate update failed.");
                    log::log(&format!("[ERROR] Root certificate update failed: {error}"));
                    let shown = if error.chars().count() > 1200 {
                        format!("{}...", error.chars().take(1200).collect::<String>())
                    } else {
                        error
                    };
                    host.dialog(
                        &format!("Could not update root certificates. Make sure you are connected to the internet and try again.\n\n{shown}"),
                        "XOS Toolkit",
                        Buttons::Ok,
                        Icon::Warning,
                    );
                }
            }
            Ok(())
        });
    }
}

fn badge_chip(b: &Badge) -> Control {
    Control::chip(b.text.clone(), b.tone).tooltip(b.tooltip.clone())
}

fn toggle_header(title: &str, b: &Badge) -> Row {
    Row::new(vec![
        Control::heading(title),
        Control::spacer(),
        badge_chip(b),
    ])
}

fn desc(text: &str) -> Row {
    Row::new(vec![Control::muted(text)])
}

fn pair(prefix: &str, enable: &str, disable: &str, enabled: bool, en: bool) -> Row {
    Row::actions(vec![
        Control::button(format!("{prefix}.enable"), enable, BtnStyle::Enable)
            .enabled(en && enabled),
        Control::button(format!("{prefix}.disable"), disable, BtnStyle::Disable)
            .enabled(en && enabled),
    ])
}

impl Page for UpdatePage {
    fn id(&self) -> &'static str {
        "Update"
    }

    fn label(&self) -> &'static str {
        "Updates"
    }

    fn model(&self) -> PageModel {
        let st = self.st.lock().unwrap();
        let s = &st.snap;
        let en = !st.sub_disabled;
        let msa_blocked = s.msa;

        let mut policy = Card::new(
            "policy",
            "Update Policy",
            "Normal turns Windows Update fully back on and clears pauses. Disabled turns off automatic updates; you install updates yourself from Settings. The other settings on this page keep their values. Disabling updates leaves the PC without security fixes and is not recommended for daily use. Hard Disabled also blocks update sources and disables update services and tasks. It can disrupt Microsoft Store installs and updates, Defender updates and other dependent features; account and Windows Hello behavior varies by configuration.",
        )
        .badge(s.policy.clone());
        if let Some(w) = &s.policy_warning {
            policy = policy.row(Row::new(vec![Control::label(w.clone()).tone(Tone::Orange)]));
        }
        policy = policy
            .row(Row::new(vec![Control::heading("Select mode")]))
            .actions(vec![
                Control::button("policy.normal", "Normal", BtnStyle::Enable),
                Control::button("policy.security", "Security Focused", BtnStyle::Action)
                    .enabled(s.security_enabled)
                    .tooltip(if s.security_enabled {
                        "Delay feature upgrades and optional previews. Availability depends on Windows version and edition.".to_string()
                    } else {
                        s.security_tooltip.clone().unwrap_or_default()
                    }),
                Control::button("policy.blocked", "Disabled", BtnStyle::Warning)
                    .tooltip(s.disabled_tooltip.clone().unwrap_or_default()),
                Control::button("policy.hard", "Hard Disabled", BtnStyle::Disable)
                    .enabled(!msa_blocked),
            ]);
        if msa_blocked {
            policy = policy.row(Row::new(vec![Control::label(
                "Hard Disable is unavailable while this profile has a stored Microsoft account. Disabling Windows Update on an online account can break authentication and account sync.",
            )
            .tone(Tone::Orange)]));
        }
        if st.sub_note {
            policy = policy.row(Row::new(vec![Control::label(
                "Windows Update is hard disabled, so the settings below have no effect until you choose Normal. Their badges still show the last value Windows recorded, which is why a greyed card can read Enabled.",
            )
            .tone(Tone::Orange)]));
        }

        let kgl_help = "The Known Game List helps Windows recognize games. XOS blocks its automatic refresh. This checks Microsoft for the latest list details. It does not confirm that Windows has installed the list.";
        let cert_help = "Windows keeps its trusted root certificates current through Windows Update. With updates paused or disabled, that can stop, and over time some HTTPS sites, installers, or signed apps may fail with certificate errors. This fetches the current root certificates straight from Microsoft and installs them. Use it if you run into certificate or secure-connection errors.";
        let maintenance = Card::new(
            "maintenance",
            "Update Maintenance",
            "One-click updates that normally come through Windows Update. They download straight from Microsoft, so they work even while updates are paused or disabled.",
        )
        .row(Row::new(vec![
            Control::heading("Known Game List (KGL) Metadata").tooltip(kgl_help),
            Control::label("(?)").tone(Tone::Blue).tooltip(kgl_help),
        ]))
        .actions(vec![Control::button("kgl", "Refresh KGL Metadata", BtnStyle::Action)])
        .row(Row::new(vec![
            Control::heading("Update Root Certificates").tooltip(cert_help),
            Control::label("(?)").tone(Tone::Blue).tooltip(cert_help),
        ]))
        .actions(vec![Control::button("certs", "Update Certificates", BtnStyle::Action)]);

        let delivery = Card::new(
            "delivery",
            "Delivery Optimization",
            "Lets your PC share downloaded updates with other PCs so they download less from the internet. Sharing uses your upload bandwidth.",
        )
        .badge(s.delivery.clone())
        .actions(vec![
            Control::button("do.default", "Windows Default", BtnStyle::Enable).enabled(en),
            Control::button("do.lan", "LAN Only", BtnStyle::Action).enabled(en),
            Control::button("do.disable", "Disable Sharing", BtnStyle::Disable).enabled(en),
        ]);

        let restart = Card::new(
            "restart",
            "Automatic Restart Behavior",
            "Control how Windows handles restarts required to finish installing updates.",
        )
        .row(toggle_header("Prevent Auto Restarts", &s.no_reboot))
        .row(desc("Updates still install automatically, but Windows will not restart on its own while you are signed in. Deadlines set by an organization can still force a restart."))
        .row(pair("noreboot", "Enable", "Disable", true, en))
        .row(toggle_header("Get Me Up To Date (Restart ASAP)", &s.expedited))
        .row(desc("Restart as soon as possible to finish updating, even during active hours. Enabling this turns off Prevent Auto Restarts."))
        .row(pair("expedited", "Enable", "Disable", true, en));

        let notif = Card::new(
            "notifications",
            "Update Notifications",
            "Control what notifications Windows shows for available updates and required restarts.",
        )
        .row(toggle_header(
            "Update Availability Notifications",
            &s.update_notif,
        ))
        .row(desc(
            "Show notifications when updates are available or being installed.",
        ))
        .row(pair("updatenotif", "Enable", "Disable", true, en))
        .row(toggle_header(
            "Restart Required Notification",
            &s.restart_notif,
        ))
        .row(desc(
            "Show a notification when a restart is required to finish updating.",
        ))
        .row(pair("restartnotif", "Enable", "Disable", true, en));

        let behavior = Card::new(
            "behavior",
            "Update Behavior",
            "Additional settings that affect what gets downloaded and when.",
        )
        .row(toggle_header("Get Latest Updates as Soon as Available", &s.latest))
        .row(desc("Be among the first to receive non-security improvements as they roll out."))
        .row(pair("latest", "Enable", "Disable", s.latest_supported, en))
        .row(toggle_header("Updates for Other Microsoft Products", &s.other_products))
        .row(desc("Receive Microsoft Update updates for supported products, including MSI-based Office. Microsoft 365 Click-to-Run uses its own updater."))
        .row(pair("otherproducts", "Enable", "Disable", true, en))
        .row(toggle_header("Download Updates over Metered Connections", &s.metered))
        .row(desc("Allow Windows to download updates when using mobile hotspots or data-limited connections."))
        .row(pair("metered", "Enable", "Disable", true, en));

        let driver_store = Card::new(
            "driverstore",
            "Driver & Store Updates",
            "Control automatic driver updates through Windows Update and app updates from the Microsoft Store.",
        )
        .row(toggle_header("Driver Updates via Windows Update", &s.drivers))
        .row(desc("Allow or block driver updates from Windows Update. Blocking stops Windows from replacing drivers you installed yourself, like graphics drivers. Windows feature updates may still include some drivers."))
        .row(pair("drivers", "Allow Drivers", "Block Drivers", true, en))
        .row(toggle_header("Auto-Update Microsoft Store Apps", &s.store))
        .row(desc("Automatically download and install updates for apps from the Microsoft Store."))
        .row(pair("store", "Enable", "Disable", true, en));

        PageModel::new(
            "Update",
            "Windows Update",
            "Control update behavior, delivery, and automatic restart settings",
        )
        .card(policy)
        .card(maintenance)
        .card(delivery)
        .card(restart)
        .card(notif)
        .card(behavior)
        .card(driver_store)
        .overlay(st.busy.clone())
    }

    fn refresh(&self, _host: &dyn Host) {
        self.refresh_states();
    }

    fn handle(&self, host: &dyn Host, event: &Event) {
        if event.kind != EventKind::Click {
            return;
        }
        match event.control.as_str() {
            "policy.normal" => self.policy_normal(host),
            "policy.security" => self.policy_security_only(host),
            "policy.blocked" => self.policy_blocked(host),
            "policy.hard" => self.policy_disabled(host),
            "kgl" => self.kgl(host),
            "certs" => self.certs(host),
            "do.default" => self.do_default(host),
            "do.lan" => self.do_lan_only(host),
            "do.disable" => self.do_disable(host),
            "noreboot.enable" => self.no_reboot_enable(host),
            "noreboot.disable" => self.no_reboot_disable(host),
            "expedited.enable" => self.expedited_enable(host),
            "expedited.disable" => self.expedited_disable(host),
            "updatenotif.enable" => self.update_notif_enable(host),
            "updatenotif.disable" => self.update_notif_disable(host),
            "restartnotif.enable" => self.restart_notif_enable(host),
            "restartnotif.disable" => self.restart_notif_disable(host),
            "latest.enable" => self.latest_enable(host),
            "latest.disable" => self.latest_disable(host),
            "otherproducts.enable" => self.other_products_enable(host),
            "otherproducts.disable" => self.other_products_disable(host),
            "metered.enable" => self.metered_enable(host),
            "metered.disable" => self.metered_disable(host),
            "drivers.enable" => self.drivers_allow(host),
            "drivers.disable" => self.drivers_block(host),
            "store.enable" => self.store_enable(host),
            "store.disable" => self.store_disable(host),
            _ => {}
        }
    }
}

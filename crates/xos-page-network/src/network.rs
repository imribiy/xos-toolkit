use std::sync::Mutex;

use anyhow::{bail, Result};
use xos_core::app_state;
use xos_core::catalog;
use xos_core::host::{Buttons, DialogResult, Host, Icon, Page};
use xos_core::log;
use xos_core::status;
use xos_core::ui::*;
use xos_helpers::{card_state_helper, stock_hardware_marker};
use xos_sys::ops;
use xos_winupdate::webview2;

use crate::common::{done, mark_failure_if_present, require_service, service_is_enabled, strings};
use crate::network_reset_action;

const KEY_THROTTLE: &str =
    r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile";
const VPN_CORE_SVCS: [&str; 6] = ["BFE", "mpssvc", "Dhcp", "Dnscache", "NlaSvc", "netprofm"];
const VPN_RAS_SVCS: [&str; 6] = [
    "RasMan",
    "RasAuto",
    "IKEEXT",
    "PolicyAgent",
    "RASSSTP",
    "SstpSvc",
];
const EDGE_UPDATE_POL: &str = r"HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate";
const EDGE_CHANNEL_GUIDS: [&str; 4] = [
    "{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}",
    "{2CD8A007-E189-409D-A2C8-9AF4EF3C72AA}",
    "{0D50BFEC-CD6A-4F9A-964C-C7416E3ACB10}",
    "{65C35B14-6C1D-4122-AC46-7148CC9D6497}",
];
const BT_SERVICES_DEMAND: [&str; 17] = [
    "RFCOMM",
    "BthEnum",
    "bthleenum",
    "BTHMODEM",
    "BthA2dp",
    "microsoft_bluetooth_avrcptransport",
    "BthHFEnum",
    "BTAGService",
    "bthserv",
    "BluetoothUserService",
    "BthAvctpSvc",
    "BthMini",
    "BthPan",
    "BTHPORT",
    "BTHUSB",
    "HidBth",
    "ibtusb",
];
const BT_DEVICE_FILTER: &str = "$_.Class -eq 'Bluetooth' -or $_.InstanceId -like 'BTH*' -or $_.FriendlyName -like '*Bluetooth*' -or $_.FriendlyName -like '*RFCOMM*'";
const WIFI_DEVICE_FILTER: &str = "$_.Class -eq 'Net' -and ($_.FriendlyName -like '*Wi-Fi*' -or $_.FriendlyName -like '*Wireless*' -or $_.FriendlyName -like '*WLAN*' -or $_.FriendlyName -like '*802.11*')";
const ADAPTER_DISABLE_VALUES: [&str; 41] = [
    "EnablePME",
    "*DeviceSleepOnDisconnect",
    "*EEE",
    "AdvancedEEE",
    "*SipsEnabled",
    "EnableAspm",
    "ASPM",
    "*ModernStandbyWoLMagicPacket",
    "*SelectiveSuspend",
    "EnableGigaLite",
    "GigaLite",
    "*WakeOnMagicPacket",
    "*WakeOnPattern",
    "AutoPowerSaveModeEnabled",
    "EEELinkAdvertisement",
    "EeePhyEnable",
    "EnableGreenEthernet",
    "EnableModernStandby",
    "PowerDownPll",
    "PowerSavingMode",
    "ReduceSpeedOnPowerDown",
    "S5WakeOnLan",
    "SavePowerNowEnabled",
    "ULPMode",
    "WakeOnLink",
    "WakeOnSlot",
    "WakeOnLinkChg",
    "WakeOnLinkUp",
    "WakeUpModeCap",
    "*NicAutoPowerSaver",
    "PowerSaveEnable",
    "EnablePowerManagement",
    "ForceWakeFromMagicPacketOnModernStandby",
    "WakeFromS5",
    "WakeOn",
    "EnableSavePowerNow",
    "*EnableDynamicPowerGating",
    "DynamicPowerGating",
    "EnableD3ColdInS0",
    "WakeFromPowerOff",
    "LogLinkStateEvent",
];

struct State {
    wifi: String,
    vpn: String,
    bt: String,
    throttle: String,
    nagle: String,
    edge: String,
    webview: String,
    runtime_text: String,
    wifi_locked: bool,
    busy: Option<String>,
    last_nagle_log: Option<String>,
}

pub struct NetworkPage {
    st: Mutex<State>,
}

impl Default for NetworkPage {
    fn default() -> Self {
        Self::new()
    }
}

pub fn wifi_state(wlan: i32, wifi_filter: i32, wifi_core_enabled: bool) -> &'static str {
    let disabled = wlan == 4 && (wifi_filter < 0 || wifi_filter == 4);
    let enabled =
        wlan >= 0 && wlan != 4 && (wifi_filter < 0 || wifi_filter != 4) && wifi_core_enabled;
    if disabled {
        "Disabled"
    } else if enabled {
        "Enabled"
    } else if wlan < 0 {
        "N/A"
    } else {
        "Partial"
    }
}

pub fn vpn_state(ras_starts: &[i32], vpn_core_enabled: bool) -> &'static str {
    let mut all_enabled = true;
    let mut all_disabled = true;
    let mut all_present = true;
    for &st in ras_starts {
        if st < 0 {
            all_present = false;
            all_enabled = false;
            all_disabled = false;
        } else if st == 4 {
            all_enabled = false;
        } else {
            all_disabled = false;
        }
    }
    if ras_starts.iter().all(|&s| s < 0) {
        "N/A"
    } else if all_present && all_enabled && vpn_core_enabled {
        "Enabled"
    } else if all_present && all_disabled {
        "Disabled"
    } else {
        "Partial"
    }
}

pub fn throttle_state(value: Option<i32>) -> &'static str {
    match value {
        None => "N/A",
        Some(10) => "Enabled",
        Some(-1) => "Disabled",
        Some(_) => "Partial",
    }
}

pub fn bluetooth_state(bthserv: i32, starts: &[i32]) -> &'static str {
    let mut present = 0;
    let mut disabled = 0;
    for &start in starts {
        if start < 0 {
            continue;
        }
        present += 1;
        if start == 4 {
            disabled += 1;
        }
    }
    if bthserv < 0 {
        "N/A"
    } else if present > 0 && disabled == present {
        "Disabled"
    } else if disabled == 0 {
        "Enabled"
    } else {
        "Partial"
    }
}

pub fn install_policy_state(
    per_app: Option<i32>,
    default_policy: Option<i32>,
    inherit_default: bool,
) -> i32 {
    if let Some(p) = per_app {
        return match p {
            0 => 0,
            1 | 4 | 5 | 6 => 1,
            _ => -1,
        };
    }
    let default_policy = match default_policy {
        Some(d) if inherit_default => d,
        _ => return 1,
    };
    match default_policy {
        0 | 2 => 0,
        1 => 1,
        _ => -1,
    }
}

pub fn update_policy_state(
    per_app: Option<i32>,
    default_policy: Option<i32>,
    inherit_default: bool,
) -> i32 {
    let effective = per_app.or(if inherit_default {
        default_policy
    } else {
        None
    });
    match effective {
        None => 1,
        Some(0) => 0,
        Some(v) if (1..=3).contains(&v) => 1,
        Some(_) => -1,
    }
}

pub fn combined_edge_policy_state(
    install: Option<i32>,
    update: Option<i32>,
    install_default: Option<i32>,
    update_default: Option<i32>,
    inherit_defaults: bool,
) -> i32 {
    let install_state = install_policy_state(install, install_default, inherit_defaults);
    let update_state = update_policy_state(update, update_default, inherit_defaults);
    if install_state >= 0 && install_state == update_state {
        install_state
    } else {
        -1
    }
}

pub fn edge_install_state_from(
    removal_requested: bool,
    install_default: Option<i32>,
    update_default: Option<i32>,
    channels: &[(Option<i32>, Option<i32>)],
) -> String {
    if removal_requested {
        return "Disabled".to_string();
    }
    let mut first_state: Option<i32> = None;
    let mut any_explicit = false;
    for &(install, update) in channels {
        let effective_install = install.or(install_default);
        let effective_update = update.or(update_default);
        if (effective_install.is_none() && effective_update.is_some())
            || (effective_install.is_some() && effective_update.is_none())
        {
            return "Partial".to_string();
        }
        let state =
            combined_edge_policy_state(install, update, install_default, update_default, true);
        if state < 0 || (first_state.is_some() && first_state != Some(state)) {
            return "Partial".to_string();
        }
        first_state = Some(state);
        any_explicit |= install.is_some() || update.is_some();
    }
    if !any_explicit && install_default.is_none() && update_default.is_none() {
        return status::AUTOMATIC.to_string();
    }
    if first_state == Some(1) {
        "Enabled"
    } else {
        "Disabled"
    }
    .to_string()
}

pub fn webview_install_state_from(
    install: Option<i32>,
    update: Option<i32>,
    install_default: Option<i32>,
    update_default: Option<i32>,
) -> String {
    if install_policy_state(install, install_default, true) == 0
        || update_policy_state(update, update_default, true) == 0
    {
        "Disabled"
    } else {
        "Enabled"
    }
    .to_string()
}

pub fn runtime_text(files: bool, registered: bool) -> &'static str {
    if files && registered {
        "Runtime: Installed"
    } else if files || registered {
        "Runtime: Incomplete installation"
    } else {
        "Runtime: Not installed"
    }
}

pub fn is_ethernet_adapter(adapter_path: &str) -> bool {
    let lower_range =
        xos_sys::reg_get_string(&format!(r"{adapter_path}\Ndi\Interfaces"), "LowerRange");
    if let Some(lr) = lower_range {
        if !lr.trim().is_empty() {
            return lr.to_lowercase().contains("ethernet");
        }
    }
    if let Some(medium) = xos_sys::reg_get_dword(adapter_path, "*PhysicalMediaType") {
        return medium == 14;
    }
    !xos_sys::reg_value_exists(adapter_path, "*PhyType")
}

fn get_edge_install_state() -> String {
    let removal = webview2::is_edge_removal_requested();
    if removal {
        return edge_install_state_from(true, None, None, &[]);
    }
    let install_default = xos_sys::reg_get_dword(EDGE_UPDATE_POL, "InstallDefault");
    let update_default = xos_sys::reg_get_dword(EDGE_UPDATE_POL, "UpdateDefault");
    let mut channels = Vec::new();
    for guid in EDGE_CHANNEL_GUIDS {
        channels.push((
            xos_sys::reg_get_dword(EDGE_UPDATE_POL, &format!("Install{guid}")),
            xos_sys::reg_get_dword(EDGE_UPDATE_POL, &format!("Update{guid}")),
        ));
    }
    edge_install_state_from(false, install_default, update_default, &channels)
}

fn get_webview_install_state() -> String {
    let install = xos_sys::reg_get_dword(EDGE_UPDATE_POL, &format!("Install{}", webview2::GUID));
    let update = xos_sys::reg_get_dword(EDGE_UPDATE_POL, &format!("Update{}", webview2::GUID));
    let install_default = xos_sys::reg_get_dword(EDGE_UPDATE_POL, "InstallDefault");
    let update_default = xos_sys::reg_get_dword(EDGE_UPDATE_POL, "UpdateDefault");
    webview_install_state_from(install, update, install_default, update_default)
}

fn nagle_log_text(lacking: &[String], names: &std::collections::HashMap<String, String>) -> String {
    lacking
        .iter()
        .map(|item| {
            let guid = match item.find(' ') {
                Some(i) => &item[..i],
                None => item.as_str(),
            };
            match names.get(&card_state_helper::normalize_guid(guid)) {
                Some(name) => format!("{item} ({name})"),
                None => item.clone(),
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn enable_wifi() -> Result<()> {
    require_service("WlanSvc", "Wi-Fi")?;
    require_service("NlaSvc", "Wi-Fi")?;
    require_service("netprofm", "Wi-Fi")?;
    require_service("eventlog", "Wi-Fi")?;
    let mut failed = false;
    mark_failure_if_present(
        "netprofm",
        || xos_sys::config_service_sc("netprofm", "demand"),
        &mut failed,
    );
    mark_failure_if_present(
        "NlaSvc",
        || xos_sys::config_service_sc("NlaSvc", "auto"),
        &mut failed,
    );
    mark_failure_if_present(
        "vwififlt",
        || xos_sys::config_service_sc("vwififlt", "system"),
        &mut failed,
    );
    mark_failure_if_present(
        "WlanSvc",
        || xos_sys::config_service_sc("WlanSvc", "auto"),
        &mut failed,
    );
    mark_failure_if_present(
        "eventlog",
        || xos_sys::config_service_sc("eventlog", "auto"),
        &mut failed,
    );
    if !xos_sys::enable_tasks_batch(&strings(catalog::WIFI_TASKS)) {
        failed = true;
    }
    if !xos_sys::set_pnp_devices(true, WIFI_DEVICE_FILTER, true) {
        failed = true;
    }
    if failed {
        bail!("Wi-Fi could not be fully enabled.");
    }
    Ok(())
}

fn disable_wifi() -> Result<()> {
    require_service("WlanSvc", "Wi-Fi")?;
    let mut failed = false;
    mark_failure_if_present(
        "WlanSvc",
        || xos_sys::config_service_sc("WlanSvc", "disabled"),
        &mut failed,
    );
    mark_failure_if_present(
        "vwififlt",
        || xos_sys::config_service_sc("vwififlt", "disabled"),
        &mut failed,
    );
    if !xos_sys::disable_tasks_batch(&strings(catalog::WIFI_TASKS)) {
        failed = true;
    }
    if failed {
        bail!("Wi-Fi could not be fully disabled.");
    }
    Ok(())
}

fn enable_vpn() -> Result<()> {
    for s in VPN_CORE_SVCS {
        require_service(s, "VPN")?;
    }
    for s in VPN_RAS_SVCS {
        require_service(s, "VPN")?;
    }
    let mut failed = false;
    for s in VPN_CORE_SVCS {
        mark_failure_if_present(s, || xos_sys::config_service_reg(s, 2), &mut failed);
    }
    for s in VPN_RAS_SVCS {
        mark_failure_if_present(s, || xos_sys::config_service_reg(s, 3), &mut failed);
    }
    if failed {
        bail!("VPN services could not be fully enabled.");
    }
    enable_wifi()
}

fn disable_vpn() -> Result<()> {
    for s in VPN_RAS_SVCS {
        require_service(s, "VPN")?;
    }
    let mut failed = false;
    for s in VPN_RAS_SVCS {
        mark_failure_if_present(s, || xos_sys::config_service_reg(s, 4), &mut failed);
    }
    if failed {
        bail!("VPN services could not be fully disabled.");
    }
    Ok(())
}

fn enable_bluetooth() -> Result<()> {
    require_service("bthserv", "Bluetooth")?;
    let mut failed = false;
    for s in BT_SERVICES_DEMAND {
        mark_failure_if_present(s, || xos_sys::config_service_sc(s, "demand"), &mut failed);
    }
    if !xos_sys::enable_tasks_batch(&[catalog::BLUETOOTH_UNINSTALL_TASK.to_string()]) {
        failed = true;
    }
    if !xos_sys::set_pnp_devices(true, BT_DEVICE_FILTER, true) {
        failed = true;
    }
    if failed {
        bail!("Bluetooth could not be fully enabled.");
    }
    Ok(())
}

fn disable_bluetooth() -> Result<()> {
    require_service("bthserv", "Bluetooth")?;
    let mut failed = false;
    for s in BT_SERVICES_DEMAND {
        mark_failure_if_present(s, || xos_sys::config_service_sc(s, "disabled"), &mut failed);
    }
    if !xos_sys::disable_tasks_batch(&[catalog::BLUETOOTH_UNINSTALL_TASK.to_string()]) {
        failed = true;
    }
    if !xos_sys::set_pnp_devices(false, BT_DEVICE_FILTER, false) {
        failed = true;
    }
    if failed {
        bail!("Bluetooth could not be fully disabled.");
    }
    Ok(())
}

fn apply_xos_tweaks() -> Result<()> {
    if let Err(marker_error) = stock_hardware_marker::try_invalidate("Network XOS tweaks") {
        bail!(
            "No network setting was changed: the restored-to-stock record could not be cleared first ({marker_error})."
        );
    }
    xos_sys::reg_set_dword(
        r"HKLM\System\CurrentControlSet\Services\Dnscache\Parameters",
        "DisableCoalescing",
        1,
    );
    xos_sys::reg_set_dword(
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\Local",
        "fDisablePowerManagement",
        1,
    );
    xos_sys::reg_set_dword(
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy",
        "fDisablePowerManagement",
        1,
    );

    for adapter in xos_sys::find_network_adapter_paths() {
        if !is_ethernet_adapter(&adapter) {
            continue;
        }
        for v in ADAPTER_DISABLE_VALUES {
            if xos_sys::reg_value_exists(&adapter, v) {
                xos_sys::reg_set_string(&adapter, v, "0");
            }
        }
        if xos_sys::reg_value_exists(&adapter, "PnPCapabilities") {
            xos_sys::reg_set_dword(&adapter, "PnPCapabilities", 24);
        }
        if xos_sys::reg_value_exists(&adapter, "WakeOnMagicPacketFromS5") {
            xos_sys::reg_set_string(&adapter, "WakeOnMagicPacketFromS5", "2");
        }
        if xos_sys::reg_value_exists(&adapter, "WolShutdownLinkSpeed") {
            xos_sys::reg_set_string(&adapter, "WolShutdownLinkSpeed", "2");
        }
    }
    Ok(())
}

fn remove_webview2() -> Result<()> {
    webview2::prepare_for_removal();
    xos_page_apps::remove_edge_component(
        webview2::GUID,
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft EdgeWebView",
        true,
    )?;
    let remaining = webview2::get_executable_paths(true);
    log::log(&format!(
        "[WebView2] Explicit removal verification: {}",
        if remaining.is_empty() {
            "No runtime executable found.".to_string()
        } else {
            remaining.join("; ")
        }
    ));
    if !remaining.is_empty() {
        bail!("WebView2 runtime files remain. Windows may have refused removal, or a per-user installation remains. See the Toolkit log.");
    }
    app_state::require_reboot();
    Ok(())
}

impl NetworkPage {
    pub fn new() -> Self {
        Self {
            st: Mutex::new(State {
                wifi: "Checking".into(),
                vpn: "Checking".into(),
                bt: "Checking".into(),
                throttle: "Checking".into(),
                nagle: "Checking".into(),
                edge: "Checking".into(),
                webview: "Checking".into(),
                runtime_text: "Runtime: Checking...".into(),
                wifi_locked: false,
                busy: None,
                last_nagle_log: None,
            }),
        }
    }

    pub fn set_wifi_locked(&self, locked: bool) {
        self.st.lock().unwrap().wifi_locked = locked;
    }

    pub fn refresh_states(&self) {
        let wlan = xos_sys::get_service_start_type("WlanSvc");
        let wifi_filter = xos_sys::get_service_start_type("vwififlt");
        let wifi_core_enabled = service_is_enabled("NlaSvc")
            && service_is_enabled("netprofm")
            && service_is_enabled("eventlog");
        let wifi = wifi_state(wlan, wifi_filter, wifi_core_enabled).to_string();

        let ras_starts: Vec<i32> = VPN_RAS_SVCS
            .iter()
            .map(|s| xos_sys::get_service_start_type(s))
            .collect();
        let mut vpn_core_enabled = true;
        for s in VPN_CORE_SVCS {
            if !service_is_enabled(s) {
                vpn_core_enabled = false;
            }
        }
        let vpn = if VPN_RAS_SVCS.iter().all(|s| !xos_sys::service_exists(s)) {
            "N/A"
        } else {
            vpn_state(&ras_starts, vpn_core_enabled)
        }
        .to_string();

        let locked = xos_sys::has_active_ras_connection();

        let throttle = throttle_state(xos_sys::reg_get_dword(
            KEY_THROTTLE,
            "NetworkThrottlingIndex",
        ))
        .to_string();

        let (nagle_result, nagle_names) = card_state_helper::read_nagle_state();
        let nagle = nagle_result.state.clone();
        {
            let mut st = self.st.lock().unwrap();
            if nagle == "Partial" {
                let text = nagle_log_text(&nagle_result.lacking, &nagle_names);
                if st.last_nagle_log.as_deref() != Some(text.as_str()) {
                    st.last_nagle_log = Some(text.clone());
                    log::log(&format!(
                        "[STATE] Nagle's Algorithm reads Partial; interfaces without both values set to 1: {text}"
                    ));
                }
            } else {
                st.last_nagle_log = None;
            }
        }

        let bt_start = xos_sys::get_service_start_type("bthserv");
        let bt_starts: Vec<i32> = BT_SERVICES_DEMAND
            .iter()
            .map(|s| xos_sys::get_service_start_type(s))
            .collect();
        let bt = bluetooth_state(bt_start, &bt_starts).to_string();

        let edge = get_edge_install_state();
        let webview = get_webview_install_state();
        let runtime = match std::panic::catch_unwind(|| {
            (
                !webview2::get_executable_paths(false).is_empty(),
                webview2::has_registration(),
            )
        }) {
            Ok((files, registered)) => runtime_text(files, registered).to_string(),
            Err(_) => "Runtime: Could not verify installation".to_string(),
        };

        let mut st = self.st.lock().unwrap();
        st.wifi = wifi;
        st.vpn = vpn;
        st.wifi_locked = locked;
        st.throttle = throttle;
        st.nagle = nagle;
        st.bt = bt;
        st.edge = edge;
        st.webview = webview;
        st.runtime_text = runtime;
    }

    fn set_busy(&self, host: &dyn Host, message: Option<&str>) {
        self.st.lock().unwrap().busy = message.map(|m| m.to_string());
        host.publish(self.model());
        if let Some(m) = message {
            host.set_status(m);
        }
    }

    fn run_busy(
        &self,
        host: &dyn Host,
        busy_message: &str,
        operation: impl FnOnce() -> Result<()>,
        success_message: &str,
    ) {
        let _op = app_state::operation();
        self.set_busy(host, Some(busy_message));
        match operation() {
            Ok(()) => {
                self.refresh_states();
                host.publish(self.model());
                done(host, "Network", success_message, false);
            }
            Err(ex) => {
                log::exception(busy_message, &format!("{ex:?}"));
                ops::reset();
                let failed_operation = busy_message.trim_end_matches(['.', ' ']);
                host.set_status(&format!("{failed_operation} failed."));
                let message = ex.to_string();
                let edge_blocking = message.to_lowercase().contains("edge update");
                let mut text = format!("{failed_operation} failed.\n\n{message}");
                if edge_blocking {
                    text.push_str("\n\nNothing was left half done: the previous Edge Update service and task states were put back. A reboot clears the pending restart that blocks the change, and removing Edge again after the reboot normally succeeds.");
                }
                host.dialog(&text, "XOS Toolkit", Buttons::Ok, Icon::Error);
            }
        }
        self.st.lock().unwrap().busy = None;
        host.publish(self.model());
    }

    fn finish_sync(&self, host: &dyn Host, message: &str) {
        self.refresh_states();
        host.publish(self.model());
        done(host, "Network", message, false);
    }

    fn set_edge_policy(
        host_page: &NetworkPage,
        host: &dyn Host,
        value: i32,
        message: &str,
        clear_removal: bool,
    ) {
        ops::reset();
        for g in EDGE_CHANNEL_GUIDS {
            xos_sys::reg_set_dword(EDGE_UPDATE_POL, &format!("Install{g}"), value);
            xos_sys::reg_set_dword(EDGE_UPDATE_POL, &format!("Update{g}"), value);
        }
        host_page.refresh_states();
        if clear_removal && !ops::any_failed() {
            webview2::clear_edge_removal_requested();
        }
        host.publish(host_page.model());
        done(host, "Network", message, false);
    }

    fn confirm(&self, host: &dyn Host, message: &str, title: &str, icon: Icon) -> bool {
        host.dialog(message, title, Buttons::YesNo, icon) == DialogResult::Yes
    }
}

impl Page for NetworkPage {
    fn id(&self) -> &'static str {
        "Network"
    }

    fn label(&self) -> &'static str {
        "Network"
    }

    fn model(&self) -> PageModel {
        let st = self.st.lock().unwrap();
        let mut wifi_card = Card::new(
            "wifi",
            "Wi-Fi Services",
            "Turns the Wi-Fi services on or off. You need them to connect over Wi-Fi, including VPNs that use a wireless connection. Wi-Fi drivers must be installed separately.",
        )
        .badge(status::badge(&st.wifi));
        if st.wifi_locked {
            wifi_card = wifi_card.controls(vec![Control::muted(
                "Wi-Fi cannot be changed while a Windows VPN connection is active.",
            )
            .tone(Tone::Red)]);
        }
        wifi_card = wifi_card.actions(vec![
            Control::button("wifi.enable", "Enable Wi-Fi", BtnStyle::Enable)
                .enabled(!st.wifi_locked),
            Control::button("wifi.disable", "Disable Wi-Fi", BtnStyle::Disable)
                .enabled(!st.wifi_locked),
        ]);

        PageModel::new(
            "Network",
            "Network & Connectivity",
            "Manage WiFi, Bluetooth services and drivers",
        )
        .max_width(1080.0)
        .overlay(st.busy.clone())
        .card(wifi_card)
        .card(
            Card::new(
                "vpn",
                "VPN Services",
                "Turns on the built-in Windows VPN and the network services that VPN apps commonly need. Enabling VPN also turns Wi-Fi services back on.",
            )
            .badge(status::badge(&st.vpn))
            .actions(vec![
                Control::button("vpn.enable", "Enable VPN Services", BtnStyle::Enable),
                Control::button("vpn.disable", "Disable VPN Services", BtnStyle::Disable),
            ]),
        )
        .card(
            Card::new(
                "bt",
                "Bluetooth",
                "Turns Bluetooth services, drivers and tasks on or off. Needed for Bluetooth headphones, controllers, mice and keyboards. Requires a restart.",
            )
            .badge(status::badge(&st.bt))
            .actions(vec![
                Control::button("bt.enable", "Enable Bluetooth", BtnStyle::Enable),
                Control::button("bt.disable", "Disable Bluetooth", BtnStyle::Disable),
            ]),
        )
        .card(
            Card::new(
                "throttle",
                "Network Throttling",
                "While music or video is playing, Windows limits how fast other network traffic is handled. Windows keeps this limit on by default. Turning it off can help in some online games, but may cause latency spikes on some PCs, so test both.",
            )
            .badge(status::badge(&st.throttle))
            .enable_disable("throttle"),
        )
        .card(
            Card::new(
                "nagle",
                "Nagle's Algorithm",
                "Windows groups small network packets together before sending them. Disabling this can lower delay in online games that rely on it, at the cost of slightly more network traffic. Many games already turn it off themselves.",
            )
            .badge(status::badge(&st.nagle))
            .enable_disable("nagle"),
        )
        .card(
            Card::new(
                "tweaks",
                "Network Adapter Tweaks",
                "Turns off power saving features on your Ethernet adapter, such as Energy Efficient Ethernet and Wake-on-LAN. Reset puts these back to default, also resets Windows network settings and firewall rules, then restarts the PC.",
            )
            .actions(vec![
                Control::button("tweaks.apply", "Apply XOS Tweaks", BtnStyle::Enable),
                Control::button("tweaks.reset", "Reset to Default & Reboot", BtnStyle::Warning),
            ]),
        )
        .card(
            Card::new(
                "edge",
                "Microsoft Edge Auto-Install",
                "Controls whether Edge Update can install or update Microsoft Edge. Blocking does not stop Edge from being installed in other ways. Does not affect WebView2 below.",
            )
            .badge(status::badge(&st.edge))
            .actions(vec![
                Control::button("edge.allow", "Allow", BtnStyle::Enable),
                Control::button("edge.block", "Block", BtnStyle::Disable),
            ]),
        )
        .card(
            Card::new(
                "webview",
                "WebView2 Runtime",
                "Many apps need WebView2 to work, such as Microsoft Teams and the new Outlook. Block stops it from installing and updating through Edge Update. Remove uninstalls it. Some app installers may put it back anyway.",
            )
            .badge(status::badge(&st.webview))
            .controls(vec![Control::muted(st.runtime_text.clone())])
            .actions(vec![
                Control::button("wv.allow", "Allow", BtnStyle::Enable),
                Control::button("wv.block", "Block", BtnStyle::Disable),
                Control::button("wv.install", "Install WebView2", BtnStyle::Enable),
                Control::button("wv.remove", "Remove", BtnStyle::Disable),
            ]),
        )
    }

    fn refresh(&self, _host: &dyn Host) {
        self.refresh_states();
    }

    fn handle(&self, host: &dyn Host, event: &Event) {
        if event.kind != EventKind::Click {
            return;
        }
        match event.control.as_str() {
            "wifi.enable" => {
                ops::reset();
                self.run_busy(host, "Enabling Wi-Fi services...", enable_wifi, "Wi-Fi enabled. Please reboot.");
            }
            "wifi.disable" => {
                ops::reset();
                self.run_busy(host, "Disabling Wi-Fi services...", disable_wifi, "Wi-Fi disabled. Please reboot.");
            }
            "vpn.enable" => {
                ops::reset();
                self.run_busy(
                    host,
                    "Enabling VPN services...",
                    enable_vpn,
                    "VPN services enabled. Wi-Fi has been enabled automatically. Please reboot.",
                );
            }
            "vpn.disable" => {
                ops::reset();
                self.run_busy(
                    host,
                    "Disabling VPN services...",
                    disable_vpn,
                    "VPN services disabled. Reboot to fully apply.",
                );
            }
            "edge.allow" => Self::set_edge_policy(
                self,
                host,
                1,
                "Microsoft Edge Update installation and updates allowed for all Edge channels.",
                true,
            ),
            "edge.block" => Self::set_edge_policy(
                self,
                host,
                0,
                "Microsoft Edge Update installation and updates blocked for all Edge channels. Other installation methods are unaffected.",
                false,
            ),
            "wv.allow" => {
                ops::reset();
                self.run_busy(
                    host,
                    "Allowing WebView2 installation and updates...",
                    webview2::prepare_for_reinstall,
                    "WebView2 installation and updates allowed. Use Install WebView2 if the runtime is missing.",
                );
            }
            "wv.block" => {
                if !self.confirm(
                    host,
                    "Block WebView2 installation and updates through Edge Update?\n\nApps that require it may fail. An installed runtime will stop receiving security updates. Other installation methods may bypass this policy.",
                    "Block WebView2",
                    Icon::Warning,
                ) {
                    return;
                }
                ops::reset();
                self.run_busy(
                    host,
                    "Blocking WebView2 installation and updates...",
                    webview2::block_installation,
                    "WebView2 installation and updates blocked through Edge Update. If Edge is absent, its updater is also stopped and blocked. Use Allow or Install to restore it.",
                );
            }
            "wv.remove" => {
                if !self.confirm(
                    host,
                    "Remove the shared WebView2 runtime?\n\nApps using it will be closed and may stop working until it is reinstalled. Your Allow/Block choice will stay unchanged.",
                    "Remove WebView2",
                    Icon::Warning,
                ) {
                    return;
                }
                ops::reset();
                self.run_busy(
                    host,
                    "Removing WebView2...",
                    remove_webview2,
                    "WebView2 removal verified. Your Allow/Block choice is unchanged. Please reboot.",
                );
            }
            "wv.install" => {
                if !self.confirm(
                    host,
                    "Download and install Microsoft WebView2? Installation and updates will be allowed.",
                    "Install WebView2",
                    Icon::Question,
                ) {
                    return;
                }
                ops::reset();
                self.run_busy(
                    host,
                    "Installing WebView2. This may take several minutes...",
                    webview2::install,
                    "WebView2 installation verified. Restart affected apps. Reboot if they still cannot detect it.",
                );
            }
            "throttle.enable" => {
                ops::reset();
                xos_sys::reg_set_dword(KEY_THROTTLE, "NetworkThrottlingIndex", 10);
                self.finish_sync(host, "Network Throttling enabled (default: 10 packets/ms).");
            }
            "throttle.disable" => {
                ops::reset();
                xos_sys::reg_set_dword(KEY_THROTTLE, "NetworkThrottlingIndex", -1);
                self.finish_sync(host, "Network Throttling disabled.");
            }
            "nagle.enable" => {
                ops::reset();
                for path in xos_sys::find_tcpip_interface_paths(false) {
                    xos_sys::reg_delete_value(&path, "TcpAckFrequency");
                    xos_sys::reg_delete_value(&path, "TCPNoDelay");
                }
                self.finish_sync(
                    host,
                    "Nagle's Algorithm restored to default on all network interfaces. Please reboot.",
                );
            }
            "nagle.disable" => {
                ops::reset();
                for path in xos_sys::find_tcpip_interface_paths(false) {
                    xos_sys::reg_set_dword(&path, "TcpAckFrequency", 1);
                    xos_sys::reg_set_dword(&path, "TCPNoDelay", 1);
                }
                self.finish_sync(
                    host,
                    "Nagle's Algorithm disabled on all network interfaces (lower latency). Please reboot.",
                );
            }
            "tweaks.apply" => {
                ops::reset();
                self.run_busy(
                    host,
                    "Applying XOS network tweaks...",
                    apply_xos_tweaks,
                    "XOS network tweaks applied. Please reboot.",
                );
            }
            "tweaks.reset" => {
                network_reset_action::run(host, "Network");
            }
            "bt.enable" => {
                ops::reset();
                self.run_busy(
                    host,
                    "Enabling Bluetooth services...",
                    enable_bluetooth,
                    "Bluetooth enabled. Please reboot.",
                );
            }
            "bt.disable" => {
                ops::reset();
                self.run_busy(
                    host,
                    "Disabling Bluetooth services...",
                    disable_bluetooth,
                    "Bluetooth disabled. Please reboot.",
                );
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wifi_rules() {
        assert_eq!(wifi_state(4, -1, true), "Disabled");
        assert_eq!(wifi_state(4, 4, false), "Disabled");
        assert_eq!(wifi_state(2, 1, true), "Enabled");
        assert_eq!(wifi_state(2, 1, false), "Partial");
        assert_eq!(wifi_state(-1, -1, true), "N/A");
        assert_eq!(wifi_state(4, 1, true), "Partial");
    }

    #[test]
    fn vpn_rules() {
        assert_eq!(vpn_state(&[-1; 6], true), "N/A");
        assert_eq!(vpn_state(&[3, 3, 3, 3, 3, 3], true), "Enabled");
        assert_eq!(vpn_state(&[3, 3, 3, 3, 3, 3], false), "Partial");
        assert_eq!(vpn_state(&[4; 6], false), "Disabled");
        assert_eq!(vpn_state(&[4, 3, 4, 4, 4, 4], true), "Partial");
        assert_eq!(vpn_state(&[3, -1, 3, 3, 3, 3], true), "Partial");
    }

    #[test]
    fn throttle_and_bluetooth() {
        assert_eq!(throttle_state(None), "N/A");
        assert_eq!(throttle_state(Some(10)), "Enabled");
        assert_eq!(throttle_state(Some(-1)), "Disabled");
        assert_eq!(throttle_state(Some(5)), "Partial");
        assert_eq!(bluetooth_state(-1, &[3]), "N/A");
        assert_eq!(bluetooth_state(3, &[4, 4, -1]), "Disabled");
        assert_eq!(bluetooth_state(3, &[3, 3]), "Enabled");
        assert_eq!(bluetooth_state(3, &[3, 4]), "Partial");
    }

    #[test]
    fn edge_policy() {
        let none = (None, None);
        assert_eq!(
            edge_install_state_from(true, None, None, &[none; 4]),
            "Disabled"
        );
        assert_eq!(
            edge_install_state_from(false, None, None, &[none; 4]),
            "Automatic"
        );
        assert_eq!(
            edge_install_state_from(false, None, None, &[(Some(1), Some(1)); 4]),
            "Enabled"
        );
        assert_eq!(
            edge_install_state_from(false, None, None, &[(Some(0), Some(0)); 4]),
            "Disabled"
        );
        assert_eq!(
            edge_install_state_from(false, Some(0), Some(0), &[none; 4]),
            "Disabled"
        );
        assert_eq!(
            edge_install_state_from(false, None, None, &[(Some(1), None); 4]),
            "Partial"
        );
        let mixed = [(Some(1), Some(1)), (Some(0), Some(0)), none, none];
        assert_eq!(
            edge_install_state_from(false, None, None, &mixed),
            "Partial"
        );
        assert_eq!(install_policy_state(Some(4), None, true), 1);
        assert_eq!(install_policy_state(Some(2), None, true), -1);
        assert_eq!(install_policy_state(None, Some(2), true), 0);
        assert_eq!(install_policy_state(None, Some(2), false), 1);
        assert_eq!(update_policy_state(Some(3), None, true), 1);
        assert_eq!(update_policy_state(Some(4), None, true), -1);
    }

    #[test]
    fn webview_policy() {
        assert_eq!(
            webview_install_state_from(None, None, None, None),
            "Enabled"
        );
        assert_eq!(
            webview_install_state_from(Some(1), Some(1), None, None),
            "Enabled"
        );
        assert_eq!(
            webview_install_state_from(Some(0), Some(0), None, None),
            "Disabled"
        );
        assert_eq!(
            webview_install_state_from(Some(1), None, None, None),
            "Enabled"
        );
        assert_eq!(
            webview_install_state_from(None, Some(1), None, None),
            "Enabled"
        );
        assert_eq!(
            webview_install_state_from(Some(1), Some(0), None, None),
            "Disabled"
        );
        assert_eq!(
            webview_install_state_from(Some(0), None, None, None),
            "Disabled"
        );
        assert_eq!(
            webview_install_state_from(None, Some(0), None, None),
            "Disabled"
        );
        assert_eq!(
            webview_install_state_from(Some(5), Some(2), None, None),
            "Enabled"
        );
        assert_eq!(
            webview_install_state_from(None, None, Some(0), None),
            "Disabled"
        );
        assert_eq!(
            webview_install_state_from(None, None, Some(2), None),
            "Disabled"
        );
        assert_eq!(
            webview_install_state_from(None, None, None, Some(0)),
            "Disabled"
        );
        assert_eq!(
            webview_install_state_from(Some(1), None, Some(0), None),
            "Enabled"
        );
        assert_eq!(
            webview_install_state_from(Some(1), Some(1), Some(0), Some(0)),
            "Enabled"
        );
        assert_eq!(
            webview_install_state_from(None, None, Some(1), Some(1)),
            "Enabled"
        );
        assert_eq!(
            webview_install_state_from(None, None, Some(7), Some(9)),
            "Enabled"
        );
    }

    #[test]
    fn runtime_line() {
        assert_eq!(runtime_text(true, true), "Runtime: Installed");
        assert_eq!(
            runtime_text(true, false),
            "Runtime: Incomplete installation"
        );
        assert_eq!(runtime_text(false, false), "Runtime: Not installed");
    }

    #[test]
    fn nagle_log_names() {
        let mut names = std::collections::HashMap::new();
        names.insert(
            card_state_helper::normalize_guid("{ABC}"),
            "Ethernet".to_string(),
        );
        let text = nagle_log_text(&["{abc} 0/1".to_string(), "{zzz} 1/1".to_string()], &names);
        assert!(text.starts_with("{abc} 0/1 (Ethernet); {zzz} 1/1"));
    }

    #[test]
    fn model_shape() {
        let page = NetworkPage::new();
        let model = page.model();
        assert_eq!(model.id, "Network");
        assert_eq!(model.cards.len(), 8);
        assert!(model.overlay.is_none());
        assert_eq!(page.label(), "Network");
    }
}

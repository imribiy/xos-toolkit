use std::collections::BTreeMap;
use std::sync::OnceLock;
use std::time::Instant;

use regex::Regex;
use winreg::RegKey;
use xos_core::{log, session_log};

use crate::regutil::{self, hklm, io_message, open_opt, read_value, Data, Kind, Value};

#[derive(Clone, Debug, Default)]
pub struct Outcome {
    pub failures: Vec<String>,
    pub restored: i32,
    pub removed: i32,
    pub left_as_is: i32,
}

const ADAPTER_CLASS: &str =
    r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}";
const TCPIP_INTERFACES: &str = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";

const GLOBAL_VALUES: [(&str, &str); 6] = [
    (
        r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters",
        "DisableCoalescing",
    ),
    (
        r"SOFTWARE\Policies\Microsoft\Windows\WcmSvc\Local",
        "fDisablePowerManagement",
    ),
    (
        r"SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy",
        "fDisablePowerManagement",
    ),
    (
        r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters",
        "EnableNetbios",
    ),
    (
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp",
        "DisableWpad",
    ),
    (
        r"SYSTEM\CurrentControlSet\Services\Dhcp",
        "PdcActivationDisabled",
    ),
];

const SERVICE_STARTS: [(&str, i32); 2] = [("NetBT", 1), ("tcpipreg", 2)];

pub const SPLIT_SERVICES: [&str; 11] = [
    "IKEEXT",
    "iphlpsvc",
    "LanmanServer",
    "lmhosts",
    "NcbService",
    "RasAuto",
    "SstpSvc",
    "LanmanWorkstation",
    "NlaSvc",
    "nsi",
    "Wcmsvc",
];

const ADAPTER_ZERO_VALUES: [&str; 41] = [
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum StockCaptureState {
    None,
    Complete,
    Incomplete,
}

const STOCK_ROOT: &str = r"SOFTWARE\XOSToolkit\StockHardware\";

pub fn run() -> Outcome {
    let mut outcome = Outcome::default();

    for (path, name) in GLOBAL_VALUES {
        delete_value(path, name, &mut outcome);
    }

    for (service, start) in SERVICE_STARTS {
        restore_service_start(service, start, &mut outcome);
    }

    remove_service_grouping(&mut outcome);
    restore_nic_dma_remapping(&mut outcome);

    for sub in sub_keys(ADAPTER_CLASS, &mut outcome) {
        if !sub.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let path = format!(r"{ADAPTER_CLASS}\{sub}");
        if let Some(adapter) = wired_adapter_key(&sub, &path, &mut outcome) {
            restore_adapter(&adapter, &mut outcome);
        }
    }

    for iface in sub_keys(TCPIP_INTERFACES, &mut outcome) {
        delete_value(
            &format!(r"{TCPIP_INTERFACES}\{iface}"),
            "TcpAckFrequency",
            &mut outcome,
        );
        delete_value(
            &format!(r"{TCPIP_INTERFACES}\{iface}"),
            "TCPNoDelay",
            &mut outcome,
        );
    }

    log::log(&format!(
        "[NET] Registry cleanup: {} adapter value(s) set back to the driver default, {} XOS value(s) removed, {} value(s) left as they are",
        outcome.restored, outcome.removed, outcome.left_as_is
    ));

    run_step("netsh.exe", "winsock reset", &mut outcome);
    run_step("netsh.exe", "int ip reset", &mut outcome);
    run_step("netsh.exe", "int ipv6 reset", &mut outcome);
    run_step("netsh.exe", "advfirewall reset", &mut outcome);
    run_step("ipconfig.exe", "/flushdns", &mut outcome);
    outcome
}

fn restore_service_start(service: &str, windows_start: i32, outcome: &mut Outcome) {
    let path = format!(r"SYSTEM\CurrentControlSet\Services\{service}");
    if !exists(&path, "Start", outcome) {
        log::log(&format!(
            "[NET] {service}: no Start value, nothing to restore"
        ));
        return;
    }
    let text = read_text(&path, "Start", outcome);
    if text.as_deref() != Some("4") {
        outcome.left_as_is += 1;
        log::log(&format!(
            "[NET] {service}: Start {}, not the XOS value 4, left as it is",
            text.unwrap_or_default()
        ));
        return;
    }

    xos_sys::config_service_reg_if_present(service, windows_start);
    let ok =
        read_text(&path, "Start", outcome).as_deref() == Some(windows_start.to_string().as_str());
    log::log(&format!(
        "[NET] {service}: Start 4 -> {windows_start} {}",
        if ok { "OK" } else { "FAILED" }
    ));
    if ok {
        outcome.restored += 1;
        return;
    }
    session_log::operation_failed("network reset registry", &format!(r"HKLM\{path} / Start"));
    outcome.failures.push(format!(
        "{service} could not be set back to Start {windows_start}"
    ));
}

fn remove_service_grouping(outcome: &mut Outcome) {
    let mut present: Vec<String> = Vec::new();
    for service in SPLIT_SERVICES {
        if exists(
            &format!(r"SYSTEM\CurrentControlSet\Services\{service}"),
            "SvcHostSplitDisable",
            outcome,
        ) {
            present.push(service.to_string());
        }
    }
    if present.is_empty() {
        log::log("[NET] SvcHostSplitDisable: not set on any network service");
        return;
    }

    xos_sys::set_service_grouping_values(&present, false);
    for service in &present {
        let path = format!(r"SYSTEM\CurrentControlSet\Services\{service}");
        let removed = !exists(&path, "SvcHostSplitDisable", outcome);
        log::log(&format!(
            "[NET] DEL HKLM\\{path} / SvcHostSplitDisable {}",
            if removed { "OK" } else { "FAILED" }
        ));
        if removed {
            outcome.removed += 1;
            continue;
        }
        session_log::operation_failed(
            "network reset registry",
            &format!(r"HKLM\{path} / SvcHostSplitDisable"),
        );
        outcome.failures.push(format!(
            "SvcHostSplitDisable could not be removed from the {service} service"
        ));
    }
}

fn restore_nic_dma_remapping(outcome: &mut Outcome) {
    let capture_state = get_stock_capture_state();
    for service in find_nic_services() {
        let path = format!(r"SYSTEM\CurrentControlSet\Services\{service}\Parameters");
        if !exists(&path, "DmaRemappingCompatible", outcome) {
            continue;
        }
        let text = read_text(&path, "DmaRemappingCompatible", outcome);
        let text_is_zero = text.as_deref() == Some("0");
        if !text_is_zero || !value_has_kind(&path, "DmaRemappingCompatible", Kind::DWord, outcome) {
            outcome.left_as_is += 1;
            log::log(&format!(
                "[NET] NIC driver {service}: DmaRemappingCompatible {}, not the XOS value 0, left as it is",
                text.unwrap_or_default()
            ));
            continue;
        }
        let text = text.unwrap_or_default();
        let stock_record = match try_stock_record("Dma", &service, outcome) {
            Some(r) => r,
            None => continue,
        };
        if let Some(record) = stock_record {
            let (record_kind, record_data) = match try_parse_record(&record) {
                Some(p) => p,
                None => {
                    outcome.left_as_is += 1;
                    fail(
                        outcome,
                        &format!(
                            "DmaRemappingCompatible: recorded stock type is unsupported; existing value {text} was left unchanged"
                        ),
                    );
                    continue;
                }
            };
            let restored = write_value(
                &path,
                "DmaRemappingCompatible",
                record_kind,
                &record_data,
                outcome,
            );
            log::log(&format!(
                "[NET] NIC driver {service}: DmaRemappingCompatible 0 -> recorded stock value {record_data} {}",
                if restored { "OK" } else { "FAILED" }
            ));
            if restored {
                outcome.restored += 1;
                continue;
            }
            session_log::operation_failed(
                "network reset registry",
                &format!(r"HKLM\{path} / DmaRemappingCompatible"),
            );
            outcome.failures.push(format!(
                "DmaRemappingCompatible on the {service} driver could not be set back to {record_data}"
            ));
            continue;
        }
        if capture_state == StockCaptureState::Incomplete {
            outcome.left_as_is += 1;
            fail(
                outcome,
                &format!(
                    "DmaRemappingCompatible on {service}: stock capture is incomplete and no authoritative record exists; existing value {text} was left unchanged"
                ),
            );
            continue;
        }
        log::log(&format!(
            "[NET] NIC driver {service}: DmaRemappingCompatible 0 is the XOS value (no stock value was recorded), removing it as the uninstall does"
        ));
        delete_value(&path, "DmaRemappingCompatible", outcome);
    }
}

fn try_stock_record(sub_key: &str, name: &str, outcome: &mut Outcome) -> Option<Option<String>> {
    let attempt = || -> std::io::Result<Result<Option<String>, String>> {
        let key = match open_opt(&hklm(), &format!("{STOCK_ROOT}{sub_key}"), false)? {
            Some(k) => k,
            None => return Ok(Ok(None)),
        };
        match read_value(&key, name, true)? {
            None => Ok(Ok(None)),
            Some(v) => match v.data {
                Data::Str(s) => Ok(Ok(Some(s))),
                _ => Ok(Err(format!(
                    "recorded stock value for {name} is not a string"
                ))),
            },
        }
    };
    match attempt() {
        Ok(Ok(record)) => Some(record),
        Ok(Err(detail)) => {
            fail(outcome, &detail);
            None
        }
        Err(e) => {
            fail(
                outcome,
                &format!(
                    "could not read the recorded stock value for {name}: {}",
                    io_message(&e)
                ),
            );
            None
        }
    }
}

fn try_parse_record(record: &str) -> Option<(Kind, String)> {
    let colon = record.find(':')?;
    let kind_text = &record[..colon];
    let data = record[colon + 1..].to_string();
    if kind_text == "DWord" {
        return if data.trim().parse::<i32>().is_ok() {
            Some((Kind::DWord, data))
        } else {
            None
        };
    }
    if kind_text == "String" {
        return Some((Kind::String, data));
    }
    None
}

fn write_value(path: &str, name: &str, kind: Kind, data: &str, outcome: &mut Outcome) -> bool {
    let value = if kind == Kind::DWord {
        Data::Dword(data.trim().parse::<i32>().unwrap_or(0))
    } else {
        Data::Str(data.to_string())
    };
    if let Ok(Some(key)) = open_opt(&hklm(), path, true) {
        let _ = regutil::set_value(&key, name, kind, &value);
    }
    let mut ok = value_matches(path, name, kind, data, outcome);
    if !ok {
        xos_sys::run_as_ti(
            "reg.exe",
            &format!(
                "add \"HKLM\\{path}\" /v \"{name}\" /t {} /d \"{data}\" /f",
                if kind == Kind::DWord {
                    "REG_DWORD"
                } else {
                    "REG_SZ"
                }
            ),
        );
        ok = value_matches(path, name, kind, data, outcome);
    }
    ok
}

fn value_matches(path: &str, name: &str, kind: Kind, data: &str, outcome: &mut Outcome) -> bool {
    let key = match open(path, outcome) {
        Some(k) => k,
        None => return false,
    };
    match read_value(&key, name, true) {
        Ok(Some(v)) => v.kind == kind && v.text() == data,
        Ok(None) => false,
        Err(e) => {
            fail(
                outcome,
                &format!(r"Cannot verify HKLM\{path} / {name}: {}", io_message(&e)),
            );
            false
        }
    }
}

fn value_has_kind(path: &str, name: &str, kind: Kind, outcome: &mut Outcome) -> bool {
    let key = match open(path, outcome) {
        Some(k) => k,
        None => return false,
    };
    match read_value(&key, name, true) {
        Ok(Some(v)) => v.kind == kind,
        Ok(None) => false,
        Err(e) => {
            fail(
                outcome,
                &format!(
                    r"Cannot read the type of HKLM\{path} / {name}: {}",
                    io_message(&e)
                ),
            );
            false
        }
    }
}

fn get_stock_capture_state() -> StockCaptureState {
    let attempt = || -> std::io::Result<StockCaptureState> {
        let key = match open_opt(&hklm(), r"SOFTWARE\XOSToolkit\StockHardware", false)? {
            Some(k) => k,
            None => return Ok(StockCaptureState::None),
        };
        match read_value(&key, "CaptureStatus", true)? {
            None => Ok(StockCaptureState::Incomplete),
            Some(v) => Ok(if v.as_str() == Some("Complete") {
                StockCaptureState::Complete
            } else {
                StockCaptureState::Incomplete
            }),
        }
    };
    attempt().unwrap_or(StockCaptureState::Incomplete)
}

fn find_nic_services() -> Vec<String> {
    let mut services: BTreeMap<String, String> = BTreeMap::new();
    let enum_path = r"SYSTEM\CurrentControlSet\Enum";
    for bus in tolerant_sub_keys(enum_path) {
        let bus_path = format!(r"{enum_path}\{bus}");
        for device in tolerant_sub_keys(&bus_path) {
            let device_path = format!(r"{bus_path}\{device}");
            for instance in tolerant_sub_keys(&device_path) {
                let mut attempt = || -> std::io::Result<()> {
                    let key = match open_opt(&hklm(), &format!(r"{device_path}\{instance}"), false)?
                    {
                        Some(k) => k,
                        None => return Ok(()),
                    };
                    let class_guid = read_value(&key, "ClassGUID", true)?
                        .and_then(|v| v.as_str().map(str::to_string));
                    let service = read_value(&key, "Service", true)?
                        .and_then(|v| v.as_str().map(str::to_string));
                    if let Some(service) = service {
                        if !service.is_empty()
                            && class_guid.is_some_and(|g| {
                                g.eq_ignore_ascii_case("{4d36e972-e325-11ce-bfc1-08002be10318}")
                            })
                        {
                            services.entry(service.to_uppercase()).or_insert(service);
                        }
                    }
                    Ok(())
                };
                let _ = attempt();
            }
        }
    }
    services.into_values().collect()
}

fn tolerant_sub_keys(path: &str) -> Vec<String> {
    let attempt = || -> std::io::Result<Vec<String>> {
        match open_opt(&hklm(), path, false)? {
            Some(k) => k.enum_keys().collect(),
            None => Ok(Vec::new()),
        }
    };
    attempt().unwrap_or_default()
}

fn wired_adapter_key(sub: &str, path: &str, outcome: &mut Outcome) -> Option<String> {
    let key = open(path, outcome);
    if let Some(key) = &key {
        let speed = read_value(key, "*SpeedDuplex", true).ok().flatten();
        speed.as_ref()?;
        let medium = read_value(key, "*PhysicalMediaType", true)
            .ok()
            .flatten()
            .map(|v| v.text());
        let desc = read_value(key, "DriverDesc", true)
            .ok()
            .flatten()
            .map(|v| v.text())
            .unwrap_or_default();
        if medium.as_deref() == Some("9") || medium.as_deref() == Some("16") {
            log::log(&format!("[NET] Adapter {sub} ({desc}): wireless, skipped"));
            return None;
        }
        log::log(&format!("[NET] Adapter {sub} ({desc})"));
        return Some(path.to_string());
    }
    None
}

fn restore_adapter(path: &str, outcome: &mut Outcome) {
    let capture_state = get_stock_capture_state();
    for name in ADAPTER_ZERO_VALUES {
        restore_adapter_value(path, name, "0", outcome, capture_state);
    }
    restore_adapter_value(path, "PnPCapabilities", "24", outcome, capture_state);
    restore_adapter_value(path, "WakeOnMagicPacketFromS5", "2", outcome, capture_state);
    restore_adapter_value(path, "WolShutdownLinkSpeed", "2", outcome, capture_state);
}

fn read_current(path: &str, name: &str, outcome: &mut Outcome) -> Option<Value> {
    let key = open(path, outcome)?;
    read_value(&key, name, true).ok().flatten()
}

fn restore_adapter_value(
    path: &str,
    name: &str,
    xos_value: &str,
    outcome: &mut Outcome,
    capture_state: StockCaptureState,
) {
    let current = match read_current(path, name, outcome) {
        Some(c) => c,
        None => return,
    };
    let kind = current.kind;
    let text = current.text();
    let xos_kind = if name == "PnPCapabilities" {
        Kind::DWord
    } else {
        Kind::String
    };
    let xos_match =
        kind == xos_kind && (text == xos_value || (name == "PnPCapabilities" && text == "280"));
    if !xos_match {
        outcome.left_as_is += 1;
        log::log(&format!(
            "[NET]   {name}: {text} ({}), not the XOS value {xos_value} ({}), left as it is",
            kind.name(),
            xos_kind.name()
        ));
        return;
    }

    let mut adapter_id = open(path, outcome)
        .and_then(|k| read_value(&k, "NetCfgInstanceId", true).ok().flatten())
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default();
    if adapter_id.is_empty() {
        let last = path.rfind('\\').map(|i| &path[i + 1..]).unwrap_or(path);
        adapter_id = format!("class-{last}");
    }
    let stock_record = match try_stock_record(&format!(r"Nic\{adapter_id}"), name, outcome) {
        Some(r) => r,
        None => return,
    };
    if let Some(record) = stock_record {
        if record == "Absent" {
            log::log(&format!(
                "[NET]   {name}: {text} is the XOS value and stock was absent, removing it"
            ));
            delete_value(path, name, outcome);
            return;
        }
        let (stock_kind, stock_data) = match try_parse_record(&record) {
            Some(p) => p,
            None => {
                outcome.left_as_is += 1;
                fail(
                    outcome,
                    &format!(
                        "{name}: recorded stock type is unsupported; existing value {text} was left unchanged"
                    ),
                );
                return;
            }
        };
        if text == stock_data && stock_kind == kind {
            log::log(&format!(
                "[NET]   {name}: {text}, already the recorded stock value"
            ));
            return;
        }
        let stock_ok = write_value(path, name, stock_kind, &stock_data, outcome);
        log::log(&format!(
            "[NET]   {name}: {text} -> recorded stock value {stock_data} {}",
            if stock_ok { "OK" } else { "FAILED" }
        ));
        if stock_ok {
            outcome.restored += 1;
            return;
        }
        session_log::operation_failed("network reset registry", &format!(r"HKLM\{path} / {name}"));
        outcome.failures.push(format!(
            "{name} on the network adapter could not be set back to {stock_data}"
        ));
        return;
    }

    if capture_state == StockCaptureState::Incomplete {
        outcome.left_as_is += 1;
        fail(
            outcome,
            &format!(
                "{name}: stock capture is incomplete and no authoritative record exists; existing value {text} was left unchanged"
            ),
        );
        return;
    }

    let driver_default = open(&format!(r"{path}\Ndi\Params\{name}"), outcome)
        .and_then(|k| read_value(&k, "default", true).ok().flatten())
        .and_then(|v| v.as_str().map(str::to_string));
    let driver_default = match driver_default {
        Some(d) => d,
        None => {
            outcome.left_as_is += 1;
            fail(
                outcome,
                &format!(
                    "{name}: driver default unavailable; existing value {text} was left unchanged"
                ),
            );
            return;
        }
    };
    if text == driver_default {
        log::log(&format!(
            "[NET]   {name}: {text}, already the driver default"
        ));
        return;
    }

    let restored_value = if kind == Kind::DWord {
        match driver_default.trim().parse::<i32>() {
            Ok(n) => Data::Dword(n),
            Err(_) => {
                fail(
                    outcome,
                    &format!(
                        "{name}: driver default {driver_default} is not a DWORD; left unchanged"
                    ),
                );
                return;
            }
        }
    } else if kind == Kind::String {
        Data::Str(driver_default.clone())
    } else {
        fail(
            outcome,
            &format!(
                "{name}: unsupported registry type {}; left unchanged",
                kind.name()
            ),
        );
        return;
    };

    if let Ok(Some(key)) = open_opt(&hklm(), path, true) {
        let _ = regutil::set_value(&key, name, kind, &restored_value);
    }
    let mut ok = read_text(path, name, outcome).as_deref() == Some(driver_default.as_str());
    if !ok {
        xos_sys::run_as_ti(
            "reg.exe",
            &format!(
                "add \"HKLM\\{path}\" /v \"{name}\" /t {} /d \"{driver_default}\" /f",
                if kind == Kind::DWord {
                    "REG_DWORD"
                } else {
                    "REG_SZ"
                }
            ),
        );
        ok = read_text(path, name, outcome).as_deref() == Some(driver_default.as_str());
    }

    log::log(&format!(
        "[NET]   {name}: {text} -> driver default {driver_default} {}",
        if ok { "OK" } else { "FAILED" }
    ));
    if ok {
        outcome.restored += 1;
        return;
    }
    session_log::operation_failed("network reset registry", &format!(r"HKLM\{path} / {name}"));
    outcome.failures.push(format!(
        "{name} on the network adapter could not be set back to {driver_default}"
    ));
}

fn delete_value(path: &str, name: &str, outcome: &mut Outcome) {
    let before = match read_current(path, name, outcome) {
        Some(b) => b,
        None => return,
    };

    if let Ok(Some(key)) = open_opt(&hklm(), path, true) {
        let _ = regutil::delete_value_quiet(&key, name);
    }
    let mut removed = !exists(path, name, outcome);
    if !removed {
        xos_sys::run_as_ti(
            "reg.exe",
            &format!("delete \"HKLM\\{path}\" /v \"{name}\" /f"),
        );
        removed = !exists(path, name, outcome);
    }

    log::log(&format!(
        "[NET] DEL HKLM\\{path} / {name} (was {}) {}",
        before.text(),
        if removed { "OK" } else { "FAILED" }
    ));
    if removed {
        outcome.removed += 1;
        return;
    }
    session_log::operation_failed("network reset registry", &format!(r"HKLM\{path} / {name}"));
    outcome
        .failures
        .push(format!("{name} could not be removed from HKLM\\{path}"));
}

fn run_step(file_name: &str, arguments: &str, outcome: &mut Outcome) {
    let command = format!("{file_name} {arguments}");
    log::log(&format!("[CMD] {command}"));
    let watch = Instant::now();
    let (exit_code, output, error) = xos_sys::run_cmd_capture_opts(
        file_name,
        arguments,
        30000,
        file_name.eq_ignore_ascii_case("netsh.exe"),
    );
    let ms = watch.elapsed().as_millis();
    log::log(&format!("[CMD] -> exit {exit_code} in {ms} ms"));
    log::perf_detail(&command, ms, Some(&format!("exit {exit_code}")));
    let combined = format!("{output}\n{error}");
    let lines: Vec<String> = combined
        .split(['\r', '\n'])
        .filter(|l| !l.is_empty())
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    for line in lines.iter().take(60) {
        log::log(&format!("[CMD]    | {line}"));
    }
    if lines.len() > 60 {
        log::log(&format!(
            "[CMD]    | {} more line(s) omitted",
            lines.len() - 60
        ));
    }
    if exit_code == 0 {
        return;
    }

    if is_ip_reset_command(file_name, arguments)
        && is_known_anonymous_access_denied_reset(exit_code, &combined)
    {
        log::log(&format!(
            "[NET] netsh {arguments}: exit 1 is the known Windows access-denied entry; not counted as a failure"
        ));
        return;
    }

    session_log::operation_failed(&format!("command exit {exit_code}"), &command);
    outcome.failures.push(format!(
        "{command} (exit {exit_code}); see the command output in the Toolkit log"
    ));
}

struct ResetLanguage {
    status: Regex,
    ok: &'static str,
    fail: &'static str,
    access_denied: &'static str,
    footer: &'static str,
}

fn reset_languages() -> &'static [ResetLanguage] {
    static LANGUAGES: OnceLock<Vec<ResetLanguage>> = OnceLock::new();
    LANGUAGES.get_or_init(|| {
        vec![
            ResetLanguage {
                status: Regex::new(r"^Resetting (?<name>[^,]*),\s*(?<result>.+)$").expect("pattern"),
                ok: "OK!",
                fail: "failed.",
                access_denied: "Access is denied.",
                footer: "Restart the computer to complete this action.",
            },
            ResetLanguage {
                status: Regex::new(r"^(?<name>.*?)\s*wird zur\u{00fc}ckgesetzt\.\.\.\s*(?<result>.+)$")
                    .expect("pattern"),
                ok: "OK",
                fail: "Fehler",
                access_denied: "Zugriff verweigert",
                footer: "Starten Sie den Computer neu, um die Aktion abzuschlie\u{00df}en.",
            },
            ResetLanguage {
                status: Regex::new(
                    "^\u{6b63}\u{5728}\u{91cd}\u{7f6e} (?<name>[^\u{ff0c}]*)\u{ff0c}\\s*(?<result>.+)$",
                )
                .expect("pattern"),
                ok: "\u{5b8c}\u{6210}!",
                fail: "\u{5931}\u{8d25}\u{3002}",
                access_denied: "\u{62d2}\u{7edd}\u{8bbf}\u{95ee}\u{3002}",
                footer: "\u{91cd}\u{65b0}\u{542f}\u{52a8}\u{8ba1}\u{7b97}\u{673a}\u{6765}\u{5b8c}\u{6210}\u{6b64}\u{64cd}\u{4f5c}\u{3002}",
            },
        ]
    })
}

fn is_ip_reset_command(file_name: &str, arguments: &str) -> bool {
    file_name.eq_ignore_ascii_case("netsh.exe")
        && (arguments.eq_ignore_ascii_case("int ip reset")
            || arguments.eq_ignore_ascii_case("int ipv6 reset"))
}

pub fn is_known_anonymous_access_denied_reset(exit_code: i32, output: &str) -> bool {
    if exit_code != 1 || output.trim().is_empty() {
        return false;
    }
    let whitespace = Regex::new(r"\s+").expect("pattern");
    let lines: Vec<String> = output
        .split('\n')
        .map(|l| whitespace.replace_all(l.trim(), " ").into_owned())
        .filter(|l| !l.is_empty())
        .collect();
    reset_languages()
        .iter()
        .any(|language| matches_known_entry(language, &lines))
}

fn matches_known_entry(language: &ResetLanguage, lines: &[String]) -> bool {
    let (mut failed, mut ok, mut other) = (0, 0, 0);
    let mut i = 0;
    while i < lines.len() {
        if let Some(status) = language.status.captures(&lines[i]) {
            let result = status["result"].trim();
            if result == language.ok {
                ok += 1;
                i += 1;
                continue;
            }
            if result != language.fail || !status["name"].trim().is_empty() {
                return false;
            }
            failed += 1;
            if failed > 1 || i + 1 >= lines.len() {
                return false;
            }
            if !lines[i + 1].eq_ignore_ascii_case(language.access_denied) {
                return false;
            }
            i += 2;
            continue;
        }
        other += 1;
        if other > 1 || i != lines.len() - 1 || !lines[i].eq_ignore_ascii_case(language.footer) {
            return false;
        }
        i += 1;
    }
    failed == 1 && ok > 0
}

fn fail(outcome: &mut Outcome, detail: &str) {
    log::log(&format!("[NET] FAILED {detail}"));
    session_log::operation_failed("network reset registry", detail);
    outcome.failures.push(detail.to_string());
}

fn open(path: &str, outcome: &mut Outcome) -> Option<RegKey> {
    match open_opt(&hklm(), path, false) {
        Ok(k) => k,
        Err(e) => {
            fail(
                outcome,
                &format!(r"Cannot read HKLM\{path}: {}", io_message(&e)),
            );
            None
        }
    }
}

fn sub_keys(path: &str, outcome: &mut Outcome) -> Vec<String> {
    let key = match open(path, outcome) {
        Some(k) => k,
        None => return Vec::new(),
    };
    match key.enum_keys().collect::<Result<Vec<_>, _>>() {
        Ok(v) => v,
        Err(e) => {
            fail(
                outcome,
                &format!(r"Cannot enumerate HKLM\{path}: {}", io_message(&e)),
            );
            Vec::new()
        }
    }
}

fn exists(path: &str, name: &str, outcome: &mut Outcome) -> bool {
    let failures = outcome.failures.len();
    let key = open(path, outcome);
    if outcome.failures.len() != failures {
        return true;
    }
    let key = match key {
        Some(k) => k,
        None => return false,
    };
    match read_value(&key, name, true) {
        Ok(v) => v.is_some(),
        Err(e) => {
            fail(
                outcome,
                &format!(r"Cannot verify HKLM\{path} / {name}: {}", io_message(&e)),
            );
            true
        }
    }
}

fn read_text(path: &str, name: &str, outcome: &mut Outcome) -> Option<String> {
    let key = open(path, outcome)?;
    match read_value(&key, name, true) {
        Ok(v) => v.map(|v| v.text()),
        Err(e) => {
            fail(
                outcome,
                &format!(r"Cannot verify HKLM\{path} / {name}: {}", io_message(&e)),
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENGLISH: &str = "Resetting Global, OK!\r\nResetting Interface, OK!\r\nResetting , failed.\r\nAccess is denied.\r\n\r\nRestart the computer to complete this action.\r\n";

    #[test]
    fn english_anonymous_access_denied_entry_is_known() {
        assert!(is_known_anonymous_access_denied_reset(1, ENGLISH));
    }

    #[test]
    fn other_exit_codes_or_named_failures_are_not_known() {
        assert!(!is_known_anonymous_access_denied_reset(2, ENGLISH));
        assert!(!is_known_anonymous_access_denied_reset(1, ""));
        let named = "Resetting Global, OK!\nResetting Interface, failed.\nAccess is denied.\n";
        assert!(!is_known_anonymous_access_denied_reset(1, named));
        let two = "Resetting A, OK!\nResetting , failed.\nAccess is denied.\nResetting , failed.\nAccess is denied.\n";
        assert!(!is_known_anonymous_access_denied_reset(1, two));
        let no_ok = "Resetting , failed.\nAccess is denied.\n";
        assert!(!is_known_anonymous_access_denied_reset(1, no_ok));
        let extra = "Resetting A, OK!\nResetting , failed.\nAccess is denied.\nSomething else.\n";
        assert!(!is_known_anonymous_access_denied_reset(1, extra));
    }

    #[test]
    fn german_entry_is_known() {
        let text = "Global wird zur\u{00fc}ckgesetzt... OK\nSchnittstelle wird zur\u{00fc}ckgesetzt... OK\n wird zur\u{00fc}ckgesetzt... Fehler\nZugriff verweigert\nStarten Sie den Computer neu, um die Aktion abzuschlie\u{00df}en.\n";
        assert!(is_known_anonymous_access_denied_reset(1, text));
    }

    #[test]
    fn stock_records_parse() {
        assert_eq!(
            try_parse_record("DWord:5"),
            Some((Kind::DWord, "5".to_string()))
        );
        assert_eq!(try_parse_record("DWord:x"), None);
        assert_eq!(
            try_parse_record("String:a:b"),
            Some((Kind::String, "a:b".to_string()))
        );
        assert_eq!(try_parse_record("Binary:00"), None);
        assert_eq!(try_parse_record("nocolon"), None);
    }
}

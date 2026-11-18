use std::collections::{HashMap, HashSet};

use crate::regutil::{hklm, open_opt, read_value, Data, Kind};

pub const USB_HUB_KEY: &str = r"HKLM\SYSTEM\CurrentControlSet\Services\USBHUB3\Parameters";
pub const USB_CCGP_KEY: &str = r"HKLM\SYSTEM\CurrentControlSet\Services\usbccgp\Parameters";
pub const PCI_PARAMS_KEY: &str = r"HKLM\SYSTEM\CurrentControlSet\Services\pci\Parameters";

pub const USB_POWER_REGISTRY: [(&str, &str, i32); 6] = [
    (USB_HUB_KEY, "D3ColdSupported", 0),
    (USB_HUB_KEY, "DisableLPM", 1),
    (USB_HUB_KEY, "Ceip", 0),
    (USB_HUB_KEY, "DisableSelectiveSuspendUI", 1),
    (USB_CCGP_KEY, "D3ColdSupported", 0),
    (PCI_PARAMS_KEY, "D3ColdSupported", 0),
];

pub fn write_usb_power_registry(disable: bool) {
    for (key, name, disabled) in USB_POWER_REGISTRY {
        if disable {
            xos_sys::reg_set_dword(key, name, disabled);
        } else {
            xos_sys::reg_delete_value(key, name);
        }
    }
}

pub const NCF_VIRTUAL: i32 = 0x1;
pub const NCF_SOFTWARE_ENUMERATED: i32 = 0x2;
pub const NCF_PHYSICAL: i32 = 0x4;

pub fn is_real_adapter(characteristics: i32, pnp_instance_id: &str) -> bool {
    if characteristics & NCF_PHYSICAL == 0 {
        return false;
    }
    if characteristics & (NCF_VIRTUAL | NCF_SOFTWARE_ENUMERATED) != 0 {
        return false;
    }
    let id = pnp_instance_id.to_uppercase();
    !(id.starts_with("ROOT\\")
        || id.starts_with("SWD\\")
        || id.starts_with("BTH\\")
        || id.starts_with("BTHENUM\\")
        || id.starts_with("BTHPAN\\"))
}

#[derive(Clone, Debug, Default)]
pub struct NetAdapterInfo {
    pub guid: String,
    pub name: String,
    pub pnp_instance_id: String,
    pub characteristics: i32,
    pub real: bool,
}

pub fn read_net_adapters() -> Vec<NetAdapterInfo> {
    let mut list = Vec::new();
    let class_path =
        r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}";
    let cls = match open_opt(&hklm(), class_path, false) {
        Ok(Some(k)) => k,
        _ => return list,
    };
    let subs: Vec<String> = match cls.enum_keys().collect::<Result<Vec<_>, _>>() {
        Ok(v) => v,
        Err(_) => return list,
    };
    for sub in subs {
        if !sub.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let k = match open_opt(&cls, &sub, false) {
            Ok(Some(k)) => k,
            _ => continue,
        };
        let guid = match read_value(&k, "NetCfgInstanceId", true) {
            Ok(Some(v)) => v.as_str().map(str::to_string).unwrap_or_default(),
            Ok(None) => continue,
            Err(_) => continue,
        };
        if guid.is_empty() {
            continue;
        }
        let chars = match read_value(&k, "Characteristics", true) {
            Ok(Some(v)) => match v.data {
                Data::Dword(c) => c,
                _ => 0,
            },
            _ => 0,
        };
        let name = match read_value(&k, "DriverDesc", true) {
            Ok(Some(v)) => v.as_str().map(str::to_string).unwrap_or_default(),
            _ => String::new(),
        };
        let conn_path = format!(
            r"SYSTEM\CurrentControlSet\Control\Network\{{4D36E972-E325-11CE-BFC1-08002BE10318}}\{guid}\Connection"
        );
        let pnp = match open_opt(&hklm(), &conn_path, false) {
            Ok(Some(conn)) => match read_value(&conn, "PnpInstanceID", true) {
                Ok(Some(v)) => v.as_str().map(str::to_string).unwrap_or_default(),
                _ => String::new(),
            },
            _ => String::new(),
        };
        let real = is_real_adapter(chars, &pnp);
        list.push(NetAdapterInfo {
            guid,
            name,
            pnp_instance_id: pnp,
            characteristics: chars,
            real,
        });
    }
    list
}

#[derive(Clone, Debug, Default)]
pub struct NagleResult {
    pub state: String,
    pub lacking: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct NagleInterface {
    pub guid: String,
    pub ack: Option<i32>,
    pub no_delay: Option<i32>,
    pub has_gateway: bool,
}

pub fn is_gateway_value(items: &[String]) -> bool {
    items.iter().any(|item| {
        let text = item.trim();
        !text.is_empty() && text != "0.0.0.0" && text != "::"
    })
}

pub fn evaluate_nagle(
    interfaces: &[NagleInterface],
    adapters: Option<&[NetAdapterInfo]>,
) -> NagleResult {
    let mut result = NagleResult::default();
    let mut counted: Vec<&NagleInterface> = interfaces.iter().collect();
    if let Some(adapters) = adapters {
        if !adapters.is_empty() {
            let real: HashSet<String> = adapters
                .iter()
                .filter(|a| is_real_adapter(a.characteristics, &a.pnp_instance_id))
                .map(|a| normalize_guid(&a.guid))
                .collect();
            let filtered: Vec<&NagleInterface> = counted
                .iter()
                .copied()
                .filter(|i| i.has_gateway || real.contains(&normalize_guid(&i.guid)))
                .collect();
            if !filtered.is_empty() {
                counted = filtered;
            }
        }
    }

    if counted.is_empty() {
        result.state = "N/A".to_string();
        return result;
    }
    let disabled = counted
        .iter()
        .filter(|i| i.ack == Some(1) && i.no_delay == Some(1))
        .count();
    let dflt = counted
        .iter()
        .filter(|i| i.ack.is_none() && i.no_delay.is_none())
        .count();
    if disabled == counted.len() {
        result.state = "Disabled".to_string();
    } else if dflt == counted.len() {
        result.state = "Enabled".to_string();
    } else {
        result.state = "Partial".to_string();
        result.lacking = counted
            .iter()
            .filter(|i| !(i.ack == Some(1) && i.no_delay == Some(1)))
            .map(|i| {
                format!(
                    "{} TcpAckFrequency={} TCPNoDelay={} Gateway={}",
                    i.guid,
                    fmt(i.ack),
                    fmt(i.no_delay),
                    if i.has_gateway { "yes" } else { "no" }
                )
            })
            .collect();
    }
    result
}

fn fmt(v: Option<i32>) -> String {
    match v {
        Some(v) => v.to_string(),
        None => "absent".to_string(),
    }
}

pub fn normalize_guid(guid: &str) -> String {
    guid.trim().to_lowercase()
}

fn gateway_items(name: &str, key: &winreg::RegKey) -> Vec<String> {
    match read_value(key, name, true) {
        Ok(Some(v)) => match (v.kind, v.data) {
            (Kind::MultiString, Data::Multi(items)) => items,
            (Kind::String, Data::Str(s)) | (Kind::ExpandString, Data::Str(s)) => vec![s],
            _ => Vec::new(),
        },
        _ => Vec::new(),
    }
}

pub fn interface_has_gateway(path: &str) -> bool {
    let attempt = || -> std::io::Result<bool> {
        let parts = match path.find('\\') {
            Some(i) => &path[i + 1..],
            None => path,
        };
        let key = match open_opt(&hklm(), parts, false)? {
            Some(k) => k,
            None => return Ok(false),
        };
        Ok(is_gateway_value(&gateway_items("DefaultGateway", &key))
            || is_gateway_value(&gateway_items("DhcpDefaultGateway", &key)))
    };
    attempt().unwrap_or(false)
}

pub fn read_nagle_interfaces() -> Vec<NagleInterface> {
    let mut list = Vec::new();
    for path in xos_sys::find_tcpip_interface_paths(false) {
        let guid = match path.rfind('\\') {
            Some(i) => path[i + 1..].to_string(),
            None => path.clone(),
        };
        list.push(NagleInterface {
            guid,
            ack: xos_sys::reg_get_dword(&path, "TcpAckFrequency"),
            no_delay: xos_sys::reg_get_dword(&path, "TCPNoDelay"),
            has_gateway: interface_has_gateway(&path),
        });
    }
    list
}

pub fn read_nagle_state() -> (NagleResult, HashMap<String, String>) {
    let mut names = HashMap::new();
    let adapters = read_net_adapters();
    for a in &adapters {
        names.insert(normalize_guid(&a.guid), a.name.clone());
    }
    let result = evaluate_nagle(&read_nagle_interfaces(), Some(&adapters));
    (result, names)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(guid: &str, ack: Option<i32>, nd: Option<i32>, gw: bool) -> NagleInterface {
        NagleInterface {
            guid: guid.to_string(),
            ack,
            no_delay: nd,
            has_gateway: gw,
        }
    }

    #[test]
    fn real_adapter_rules() {
        assert!(is_real_adapter(NCF_PHYSICAL, r"PCI\VEN_8086"));
        assert!(!is_real_adapter(NCF_PHYSICAL | NCF_VIRTUAL, r"PCI\X"));
        assert!(!is_real_adapter(0, r"PCI\X"));
        assert!(!is_real_adapter(NCF_PHYSICAL, r"root\vmbus"));
        assert!(!is_real_adapter(NCF_PHYSICAL, r"BTHENUM\dev"));
    }

    #[test]
    fn gateway_values() {
        assert!(!is_gateway_value(&[]));
        assert!(!is_gateway_value(&[
            "0.0.0.0".into(),
            " :: ".into(),
            "".into()
        ]));
        assert!(is_gateway_value(&["0.0.0.0".into(), "192.168.1.1".into()]));
    }

    #[test]
    fn nagle_states() {
        let all_off = [
            iface("{A}", Some(1), Some(1), true),
            iface("{B}", Some(1), Some(1), false),
        ];
        assert_eq!(evaluate_nagle(&all_off, None).state, "Disabled");
        let dflt = [iface("{A}", None, None, true)];
        assert_eq!(evaluate_nagle(&dflt, None).state, "Enabled");
        assert_eq!(evaluate_nagle(&[], None).state, "N/A");
        let mixed = [
            iface("{A}", Some(1), None, true),
            iface("{B}", Some(1), Some(1), true),
        ];
        let r = evaluate_nagle(&mixed, None);
        assert_eq!(r.state, "Partial");
        assert_eq!(
            r.lacking,
            vec!["{A} TcpAckFrequency=1 TCPNoDelay=absent Gateway=yes".to_string()]
        );
    }

    #[test]
    fn nagle_filters_to_real_adapters_or_gateway() {
        let adapters = [NetAdapterInfo {
            guid: "{REAL}".into(),
            characteristics: NCF_PHYSICAL,
            pnp_instance_id: r"PCI\X".into(),
            ..Default::default()
        }];
        let ifaces = [
            iface("{real}", Some(1), Some(1), false),
            iface("{virt}", None, None, false),
        ];
        assert_eq!(evaluate_nagle(&ifaces, Some(&adapters)).state, "Disabled");
        assert_eq!(evaluate_nagle(&ifaces, None).state, "Partial");
    }

    #[test]
    fn nagle_with_hyperv_external_switch() {
        let adapters = [
            NetAdapterInfo {
                guid: "{NIC}".into(),
                characteristics: NCF_PHYSICAL,
                pnp_instance_id: r"PCI\VEN_10EC".into(),
                ..Default::default()
            },
            NetAdapterInfo {
                guid: "{VETH}".into(),
                characteristics: NCF_VIRTUAL,
                pnp_instance_id: r"ROOT\VMS_MP\0000".into(),
                ..Default::default()
            },
        ];
        let disabled = [
            iface("{nic}", Some(1), Some(1), false),
            iface("{veth}", Some(1), Some(1), true),
            iface("{loop}", None, None, false),
        ];
        assert_eq!(evaluate_nagle(&disabled, Some(&adapters)).state, "Disabled");
        let switch_made_after_disable = [
            iface("{nic}", Some(1), Some(1), false),
            iface("{veth}", None, None, true),
        ];
        let r = evaluate_nagle(&switch_made_after_disable, Some(&adapters));
        assert_eq!(r.state, "Partial");
        assert_eq!(
            r.lacking,
            vec!["{veth} TcpAckFrequency=absent TCPNoDelay=absent Gateway=yes".to_string()]
        );
        let restored = [
            iface("{nic}", None, None, false),
            iface("{veth}", None, None, true),
        ];
        assert_eq!(evaluate_nagle(&restored, Some(&adapters)).state, "Enabled");
    }
}

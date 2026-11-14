use base64::Engine;
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
use winreg::RegKey;
use xos_core::redact::{self, AddressValue};

use crate::regval::{self, RegData};

const NETWORK_ADAPTER_SCRIPT: &str = concat!(
    "$ErrorActionPreference='Continue';",
    "function S($t,[scriptblock]$b){'--- '+$t+' ---';try{(& $b | Out-String -Width 250).TrimEnd()}catch{'ERROR: '+$_.Exception.Message};''};",
    "S 'Get-NetAdapter' {Get-NetAdapter | Format-List Name,InterfaceDescription,Status,MediaConnectionState,LinkSpeed,MacAddress,DriverVersion,DriverProvider,DriverDate,PnPDeviceID,Virtual};",
    "S 'Get-NetAdapterAdvancedProperty' {Get-NetAdapterAdvancedProperty | Format-Table Name,DisplayName,DisplayValue,RegistryKeyword,RegistryValue -AutoSize};",
    "S 'Get-NetAdapterBinding' {Get-NetAdapterBinding | Format-Table Name,ComponentID,DisplayName,Enabled -AutoSize};",
    "S 'Get-NetAdapterPowerManagement' {Get-NetAdapterPowerManagement | Format-List Name,AllowComputerToTurnOffDevice,WakeOnMagicPacket,WakeOnPattern,DeviceSleepOnDisconnect,SelectiveSuspend};",
    "S 'Adapter driver registry' {foreach($a in @(Get-NetAdapter)){",
    "$id=$a.PnPDeviceID;if(-not $id){continue};",
    "$e='HKLM:\\SYSTEM\\CurrentControlSet\\Enum\\'+$id;",
    "$svc=(Get-ItemProperty -LiteralPath $e -ErrorAction SilentlyContinue).Service;",
    "$dma=$null;if($svc){$dma=(Get-ItemProperty -LiteralPath ('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\'+$svc+'\\Parameters') -ErrorAction SilentlyContinue).DmaRemappingCompatible};",
    "$msi=(Get-ItemProperty -LiteralPath ($e+'\\Device Parameters\\Interrupt Management\\MessageSignaledInterruptProperties') -ErrorAction SilentlyContinue).MSISupported;",
    "$a.Name+' | '+$id+' | service='+$svc+' | DmaRemappingCompatible='+$dma+' | MSISupported='+$msi}}"
);

const NETWORK_CONNECTIVITY_SCRIPT: &str = concat!(
    "$ErrorActionPreference='Continue';",
    "function S($t,[scriptblock]$b){'--- '+$t+' ---';try{(& $b | Out-String -Width 250).TrimEnd()}catch{'ERROR: '+$_.Exception.Message};''};",
    "S 'Get-NetConnectionProfile' {Get-NetConnectionProfile | Format-List Name,InterfaceAlias,NetworkCategory,IPv4Connectivity,IPv6Connectivity};",
    "S 'Default routes' {Get-NetRoute -DestinationPrefix '0.0.0.0/0','::/0' | Format-Table ifIndex,DestinationPrefix,NextHop,RouteMetric,InterfaceAlias -AutoSize};",
    "S 'DNS client servers' {Get-DnsClientServerAddress | Format-Table InterfaceAlias,AddressFamily,ServerAddresses -AutoSize};",
    "S 'Network services' {Get-Service Dhcp,Dnscache,NlaSvc,netprofm,nsi,Wcmsvc,iphlpsvc,BFE,mpssvc,DusmSvc,WinHttpAutoProxySvc -ErrorAction SilentlyContinue | Format-Table Name,Status,StartType -AutoSize}"
);

const NETWORK_INFO_SERVICES: [&str; 18] = [
    "NetBT",
    "tcpipreg",
    "Tcpip",
    "Ndu",
    "Dhcp",
    "Dnscache",
    "NlaSvc",
    "DusmSvc",
    "netprofm",
    "nsi",
    "Wcmsvc",
    "iphlpsvc",
    "BFE",
    "mpssvc",
    "WinHttpAutoProxySvc",
    "NcbService",
    "LanmanWorkstation",
    "LanmanServer",
];

const NETWORK_INFO_KEYS: [&str; 14] = [
    r"SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet",
    r"SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator",
    r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters",
    r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
    r"SYSTEM\CurrentControlSet\Services\Dhcp",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp",
    r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
    r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters",
    r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters",
    r"SOFTWARE\Microsoft\PolicyManager\default\DmaGuard\DeviceEnumerationPolicy",
    r"SOFTWARE\XOSToolkit\DmaRemappingBackup",
    r"SOFTWARE\XOSToolkit\MsiModeBackup",
    r"SOFTWARE\XOSToolkit\DefenderRunBackup",
    r"SOFTWARE\XOSToolkit\StockHardware",
];

fn line(text: &mut String, s: &str) {
    text.push_str(s);
    text.push_str("\r\n");
}

pub fn build_network_info() -> String {
    let mut text = String::new();
    line(
        &mut text,
        &format!(
            "Generated: {}",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S %:z")
        ),
    );
    line(&mut text, "");

    append_command_section(&mut text, "ipconfig /all", "ipconfig.exe", "/all", false);
    append_command_section(
        &mut text,
        "netsh winhttp show proxy",
        "netsh.exe",
        "winhttp show proxy",
        true,
    );
    append_powershell_section(&mut text, NETWORK_ADAPTER_SCRIPT, 60000);
    append_powershell_section(&mut text, NETWORK_CONNECTIVITY_SCRIPT, 45000);

    line(
        &mut text,
        "--- Service registry (Start, Type, SvcHostSplitDisable) ---",
    );
    for service in NETWORK_INFO_SERVICES {
        let path = format!(r"SYSTEM\CurrentControlSet\Services\{service}");
        match RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(&path, KEY_READ) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                line(&mut text, &format!("{service}: no service key"));
            }
            Err(e) => line(&mut text, &format!("{service}: ERROR {e}")),
            Ok(key) => {
                let get =
                    |n: &str| format_value(key.get_raw_value(n).ok().map(|v| regval::decode(&v)));
                line(
                    &mut text,
                    &format!(
                        "{service}: Start={} Type={} SvcHostSplitDisable={}",
                        get("Start"),
                        get("Type"),
                        get("SvcHostSplitDisable")
                    ),
                );
            }
        }
    }
    line(&mut text, "");

    line(&mut text, "--- Registry values ---");
    for path in NETWORK_INFO_KEYS {
        line(&mut text, &format!(r"HKLM\{path}"));
        match RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(path, KEY_READ) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                line(&mut text, "  (key absent)");
            }
            Err(e) => line(&mut text, &format!("  ERROR {e}")),
            Ok(key) => {
                let values: Vec<(String, winreg::RegValue)> =
                    key.enum_values().filter_map(|r| r.ok()).collect();
                if values.is_empty() {
                    line(&mut text, "  (no values)");
                }
                for (name, raw) in values {
                    let shown = format_named_value(&name, &raw);
                    line(
                        &mut text,
                        &format!(
                            "  {} = {} ({})",
                            if name.is_empty() { "(Default)" } else { &name },
                            shown,
                            regval::kind_name(&raw.vtype)
                        ),
                    );
                }
            }
        }
    }
    append_nagle_interfaces(&mut text);
    text
}

fn append_nagle_interfaces(text: &mut String) {
    line(text, "");
    line(
        text,
        "--- Network adapters (Class registry: InterfaceGuid, name, kind, Characteristics, PnP prefix) ---",
    );
    let adapters = xos_helpers::card_state_helper::read_net_adapters();
    if adapters.is_empty() {
        line(text, "(none read)");
    }
    for adapter in adapters {
        let pnp = adapter.pnp_instance_id.as_str();
        let prefix = match pnp.find('\\') {
            Some(i) if i > 0 => pnp[..i].to_string(),
            _ => "(none)".to_string(),
        };
        line(
            text,
            &format!(
                "{} | {} | {} | Characteristics=0x{:X} | PnP={}",
                adapter.guid,
                adapter.name,
                if adapter.real {
                    "real"
                } else {
                    "virtual-or-software"
                },
                adapter.characteristics,
                prefix
            ),
        );
    }
    line(text, "");
    line(
        text,
        "--- Tcpip\\Parameters\\Interfaces (TcpAckFrequency, TCPNoDelay, TcpDelAckTicks) ---",
    );
    for path in xos_sys::find_tcpip_interface_paths(false) {
        let guid = path.rsplit('\\').next().unwrap_or("").to_string();
        let dword = |n: &str| match xos_sys::reg_get_dword(&path, n) {
            Some(v) => v.to_string(),
            None => "(absent)".to_string(),
        };
        let gateway = if xos_helpers::card_state_helper::interface_has_gateway(&path) {
            "True"
        } else {
            "False"
        };
        line(
            text,
            &format!(
                "{guid}: TcpAckFrequency={} TCPNoDelay={} TcpDelAckTicks={} hasGateway={gateway}",
                dword("TcpAckFrequency"),
                dword("TCPNoDelay"),
                dword("TcpDelAckTicks"),
            ),
        );
    }
}

fn format_named_value(name: &str, raw: &winreg::RegValue) -> String {
    let data = regval::decode(raw);
    if redact::is_address_bearing_value(name) {
        let value = match data {
            RegData::Dword(n) => AddressValue::Number(n.to_string()),
            RegData::Qword(n) => AddressValue::Number(n.to_string()),
            RegData::Text(s) | RegData::Expand(s) => AddressValue::Text(s),
            RegData::Multi(l) => AddressValue::Lines(l),
            RegData::Binary(b) | RegData::Other(b) => AddressValue::Bytes(b.len()),
        };
        redact::mask_address_value(&value)
    } else {
        format_value(Some(data))
    }
}

fn format_value(value: Option<RegData>) -> String {
    match value {
        None => "(absent)".to_string(),
        Some(RegData::Dword(n)) => n.to_string(),
        Some(RegData::Qword(n)) => n.to_string(),
        Some(RegData::Text(s)) | Some(RegData::Expand(s)) => s,
        Some(RegData::Multi(l)) => l.join(" | "),
        Some(RegData::Binary(b)) | Some(RegData::Other(b)) => b
            .iter()
            .take(64)
            .map(|x| format!("{x:02X}"))
            .collect::<Vec<_>>()
            .join("-"),
    }
}

fn append_command_section(
    text: &mut String,
    title: &str,
    file: &str,
    args: &str,
    detect_utf8: bool,
) {
    line(text, &format!("--- {title} ---"));
    let (code, output, error) = xos_sys::run_cmd_capture_opts(file, args, 25000, detect_utf8);
    line(text, output.trim_end());
    if !error.trim().is_empty() {
        line(text, error.trim_end());
    }
    if code != 0 {
        line(text, &format!("(exit {code})"));
    }
    line(text, "");
}

fn append_powershell_section(text: &mut String, script: &str, timeout_ms: u32) {
    let bytes: Vec<u8> = script
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
    let (code, output, error) = xos_sys::run_cmd_capture_opts(
        "powershell.exe",
        &format!("-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}"),
        timeout_ms,
        false,
    );
    line(text, output.trim_end());
    if !error.trim().is_empty() {
        line(text, error.trim_end());
    }
    if code != 0 {
        line(text, &format!("(PowerShell exit {code})"));
    }
    line(text, "");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_formatting() {
        assert_eq!(format_value(None), "(absent)");
        assert_eq!(format_value(Some(RegData::Dword(-1))), "-1");
        assert_eq!(
            format_value(Some(RegData::Multi(vec!["a".into(), "b".into()]))),
            "a | b"
        );
        assert_eq!(
            format_value(Some(RegData::Binary(vec![1, 0xAB, 0x0F]))),
            "01-AB-0F"
        );
    }

    #[test]
    fn scripts_have_expected_shape() {
        assert!(NETWORK_ADAPTER_SCRIPT.contains(r"HKLM:\SYSTEM\CurrentControlSet\Enum\"));
        assert!(NETWORK_ADAPTER_SCRIPT.ends_with("+$msi}}"));
        assert!(NETWORK_CONNECTIVITY_SCRIPT.ends_with("-AutoSize}"));
    }
}

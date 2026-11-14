use windows::Win32::NetworkManagement::Rras::{RasEnumConnectionsW, RASCONNW};
use winreg::enums::{REG_EXPAND_SZ, REG_MULTI_SZ, REG_SZ};
use winreg::RegValue;

use crate::reg::{decode_utf16_value, key_get_string, open_read};
use xos_core::log;

const GPU_CLASS: &str =
    r"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}";
const NET_CLASS: &str =
    r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}";

fn class_instances(base_path: &str) -> Vec<(String, winreg::RegKey)> {
    let base = match open_read(&format!(r"HKLM\{base_path}")) {
        Some(b) => b,
        None => return Vec::new(),
    };
    let mut out = Vec::new();
    for name in base.enum_keys().filter_map(|r| r.ok()) {
        if !name.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        if let Ok(sub) = base.open_subkey(&name) {
            out.push((name, sub));
        }
    }
    out
}

pub fn find_amd_gpu_reg_path() -> Option<String> {
    find_amd_gpu_reg_paths().into_iter().next()
}

pub fn find_amd_gpu_reg_paths() -> Vec<String> {
    let mut paths = Vec::new();
    for (name, sub) in class_instances(GPU_CLASS) {
        if let Some(provider) = key_get_string(&sub, "ProviderName", true) {
            if provider.to_lowercase().contains("advanced micro devices") {
                paths.push(format!(r"HKLM\{GPU_CLASS}\{name}"));
            }
        }
    }
    paths
}

pub fn has_nvidia_gpu() -> bool {
    for (_, sub) in class_instances(GPU_CLASS) {
        if let Some(provider) = key_get_string(&sub, "ProviderName", true) {
            if provider.to_lowercase().contains("nvidia") {
                return true;
            }
        }
    }
    false
}

pub fn find_network_adapter_paths() -> Vec<String> {
    let mut results = Vec::new();
    for (name, sub) in class_instances(NET_CLASS) {
        if sub.get_raw_value("*SpeedDuplex").is_ok() {
            results.push(format!(r"HKLM\{NET_CLASS}\{name}"));
        }
    }
    results
}

pub fn find_tcpip_interface_paths(active_only: bool) -> Vec<String> {
    let base_path = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";
    let mut results = Vec::new();
    let key = match open_read(&format!(r"HKLM\{base_path}")) {
        Some(k) => k,
        None => return results,
    };
    for name in key.enum_keys().filter_map(|r| r.ok()) {
        if active_only {
            let sub = match key.open_subkey(&name) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let dhcp = sub.get_raw_value("DhcpIPAddress").ok();
            let stat = sub.get_raw_value("IPAddress").ok();
            if !has_usable_ip_address(dhcp.as_ref()) && !has_usable_ip_address(stat.as_ref()) {
                continue;
            }
        }
        results.push(format!(r"HKLM\{base_path}\{name}"));
    }
    results
}

fn has_usable_ip_address(value: Option<&RegValue>) -> bool {
    let addresses: Vec<String> = match value {
        Some(v) if v.vtype == REG_MULTI_SZ => {
            let units: Vec<u16> = v
                .bytes
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            units
                .split(|&u| u == 0)
                .map(String::from_utf16_lossy)
                .filter(|s| !s.is_empty())
                .collect()
        }
        Some(v) if v.vtype == REG_SZ || v.vtype == REG_EXPAND_SZ => {
            vec![decode_utf16_value(&v.bytes)]
        }
        _ => Vec::new(),
    };
    addresses
        .iter()
        .any(|a| !a.trim().is_empty() && !a.trim().eq_ignore_ascii_case("0.0.0.0"))
}

const ERROR_SUCCESS: u32 = 0;
const ERROR_BUFFER_TOO_SMALL: u32 = 603;

pub fn has_active_ras_connection() -> bool {
    let struct_size = std::mem::size_of::<RASCONNW>();
    let mut first: Vec<RASCONNW> = vec![RASCONNW::default()];
    first[0].dwSize = struct_size as u32;
    let mut buffer_size = first[0].dwSize;
    let mut connection_count: u32 = 0;
    let result = unsafe {
        RasEnumConnectionsW(
            Some(first.as_mut_ptr()),
            &mut buffer_size,
            &mut connection_count,
        )
    };
    if result == ERROR_SUCCESS {
        return connection_count > 0;
    }
    if result == ERROR_BUFFER_TOO_SMALL {
        let needed = std::cmp::max(buffer_size as usize, struct_size);
        let slots = needed / struct_size;
        let mut retry: Vec<RASCONNW> = vec![RASCONNW::default(); slots];
        for r in retry.iter_mut() {
            r.dwSize = struct_size as u32;
        }
        let mut retry_size = (slots * struct_size) as u32;
        let mut retry_count: u32 = 0;
        let retry_result = unsafe {
            RasEnumConnectionsW(Some(retry.as_mut_ptr()), &mut retry_size, &mut retry_count)
        };
        return retry_result == ERROR_SUCCESS && retry_count > 0;
    }
    log::log(&format!("[RAS] RasEnumConnections failed: {result}"));
    false
}

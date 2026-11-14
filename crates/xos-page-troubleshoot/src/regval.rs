use winreg::enums::{
    RegType, HKEY_LOCAL_MACHINE, KEY_READ, REG_BINARY, REG_DWORD, REG_EXPAND_SZ, REG_MULTI_SZ,
    REG_NONE, REG_QWORD, REG_SZ,
};
use winreg::{RegKey, RegValue};

pub enum RegData {
    Dword(i32),
    Qword(i64),
    Text(String),
    Expand(String),
    Multi(Vec<String>),
    Binary(Vec<u8>),
    Other(Vec<u8>),
}

fn utf16_units(bytes: &[u8]) -> Vec<u16> {
    bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect()
}

fn decode_text(bytes: &[u8]) -> String {
    let units = utf16_units(bytes);
    let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
    String::from_utf16_lossy(&units[..end])
}

pub fn decode(value: &RegValue) -> RegData {
    let bytes: Vec<u8> = value.bytes.to_vec();
    match value.vtype {
        REG_DWORD if bytes.len() >= 4 => {
            RegData::Dword(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        }
        REG_QWORD if bytes.len() >= 8 => {
            let mut b = [0u8; 8];
            b.copy_from_slice(&bytes[..8]);
            RegData::Qword(i64::from_le_bytes(b))
        }
        REG_SZ => RegData::Text(decode_text(&bytes)),
        REG_EXPAND_SZ => {
            RegData::Expand(xos_sys::expand_environment_variables(&decode_text(&bytes)))
        }
        REG_MULTI_SZ => {
            let units = utf16_units(&bytes);
            let mut lines: Vec<String> = units
                .split(|&u| u == 0)
                .map(String::from_utf16_lossy)
                .collect();
            while lines.last().is_some_and(|l| l.is_empty()) {
                lines.pop();
            }
            RegData::Multi(lines)
        }
        REG_BINARY => RegData::Binary(bytes),
        _ => RegData::Other(bytes),
    }
}

pub fn kind_name(vtype: &RegType) -> &'static str {
    match *vtype {
        REG_NONE => "None",
        REG_SZ => "String",
        REG_EXPAND_SZ => "ExpandString",
        REG_BINARY => "Binary",
        REG_DWORD => "DWord",
        REG_MULTI_SZ => "MultiString",
        REG_QWORD => "QWord",
        _ => "Unknown",
    }
}

pub fn open_hklm(path: &str) -> Option<RegKey> {
    RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(path, KEY_READ)
        .ok()
}

pub fn value_text(key: &RegKey, name: &str) -> Option<String> {
    let raw = key.get_raw_value(name).ok()?;
    Some(match decode(&raw) {
        RegData::Dword(n) => n.to_string(),
        RegData::Qword(n) => n.to_string(),
        RegData::Text(s) | RegData::Expand(s) => s,
        RegData::Multi(l) => l.join(" "),
        RegData::Binary(b) | RegData::Other(b) => b
            .iter()
            .map(|x| format!("{x:02X}"))
            .collect::<Vec<_>>()
            .join("-"),
    })
}

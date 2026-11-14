use winreg::enums::{
    RegType, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_WOW64_64KEY,
};
use winreg::RegKey;

pub(crate) fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub(crate) fn io_msg(e: &std::io::Error) -> String {
    let text = e.to_string();
    match text.rfind(" (os error ") {
        Some(i) if text.ends_with(')') => text[..i].to_string(),
        _ => text,
    }
}

pub(crate) fn ordinal_ignore_case_key(s: &str) -> Vec<u16> {
    s.to_uppercase().encode_utf16().collect()
}

pub(crate) fn eq_ignore_case(a: &str, b: &str) -> bool {
    a.to_uppercase() == b.to_uppercase()
}

pub(crate) fn dedupe_ignore_case(items: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for item in items {
        if !out.iter().any(|x| eq_ignore_case(x, &item)) {
            out.push(item);
        }
    }
    out
}

pub(crate) fn sorted_ignore_case(mut items: Vec<String>) -> Vec<String> {
    items.sort_by_key(|s| ordinal_ignore_case_key(s));
    items
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum RegVal {
    Dword(i32),
    Sz(String),
    ExpandSz(String),
    Multi(Vec<String>),
    Other,
}

fn utf16_units(bytes: &[u8]) -> Vec<u16> {
    bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect()
}

fn utf16_until_nul(bytes: &[u8]) -> String {
    let units = utf16_units(bytes);
    let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
    String::from_utf16_lossy(&units[..end])
}

pub(crate) fn decode_multi_sz(bytes: &[u8]) -> Vec<String> {
    let mut units = utf16_units(bytes);
    while units.last() == Some(&0) {
        units.pop();
    }
    if units.is_empty() {
        return Vec::new();
    }
    units
        .split(|&u| u == 0)
        .map(String::from_utf16_lossy)
        .collect()
}

pub(crate) fn decode_reg_value(vtype: RegType, bytes: &[u8]) -> RegVal {
    match vtype {
        RegType::REG_DWORD if bytes.len() >= 4 => {
            RegVal::Dword(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        }
        RegType::REG_SZ => RegVal::Sz(utf16_until_nul(bytes)),
        RegType::REG_EXPAND_SZ => RegVal::ExpandSz(utf16_until_nul(bytes)),
        RegType::REG_MULTI_SZ => RegVal::Multi(decode_multi_sz(bytes)),
        _ => RegVal::Other,
    }
}

pub(crate) fn read_reg_value(
    hkcu: bool,
    path: &str,
    name: &str,
) -> std::io::Result<Option<RegVal>> {
    let root = RegKey::predef(if hkcu {
        HKEY_CURRENT_USER
    } else {
        HKEY_LOCAL_MACHINE
    });
    let key = match root.open_subkey_with_flags(path, KEY_QUERY_VALUE) {
        Ok(k) => k,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    match key.get_raw_value(name) {
        Ok(v) => Ok(Some(decode_reg_value(v.vtype, &v.bytes))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

pub(crate) fn open_hklm64(path: &str, rights: u32) -> std::io::Result<RegKey> {
    RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(path, rights | KEY_WOW64_64KEY)
}

pub(crate) fn encode_powershell(script: &str) -> String {
    use base64::Engine;
    let bytes: Vec<u8> = script
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub(crate) fn win32_code(e: &windows::core::Error) -> u32 {
    (e.code().0 as u32) & 0xFFFF
}

pub(crate) fn random_hex32() -> String {
    use std::hash::{BuildHasher, Hasher};
    let state = std::collections::hash_map::RandomState::new();
    let mut a = state.build_hasher();
    a.write_u64(std::process::id() as u64);
    let hi = a.finish();
    let mut b = state.build_hasher();
    b.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    );
    format!("{hi:016x}{:016x}", b.finish())
}

pub(crate) fn env_path(name: &str) -> String {
    std::env::var(name).unwrap_or_default()
}

pub(crate) fn windows_directory() -> String {
    let v = env_path("SystemRoot");
    if v.is_empty() {
        let w = env_path("windir");
        if w.is_empty() {
            r"C:\Windows".to_string()
        } else {
            w
        }
    } else {
        v
    }
}

pub(crate) fn system_directory() -> String {
    use windows::Win32::System::SystemInformation::GetSystemDirectoryW;
    let mut buf = [0u16; 520];
    let n = unsafe { GetSystemDirectoryW(Some(&mut buf)) } as usize;
    if n == 0 || n > buf.len() {
        format!(r"{}\System32", windows_directory())
    } else {
        String::from_utf16_lossy(&buf[..n])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multi_sz_decoding() {
        let bytes: Vec<u8> = "A\0B\0\0"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        assert_eq!(decode_multi_sz(&bytes), vec!["A", "B"]);
        let bytes: Vec<u8> = "A\0\0B\0\0"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        assert_eq!(decode_multi_sz(&bytes), vec!["A", "", "B"]);
        assert!(decode_multi_sz(&[0, 0]).is_empty());
    }

    #[test]
    fn case_insensitive_helpers() {
        assert_eq!(
            dedupe_ignore_case(vec![
                "\\A".to_string(),
                "\\a".to_string(),
                "\\B".to_string()
            ]),
            vec!["\\A", "\\B"]
        );
        assert_eq!(
            sorted_ignore_case(vec!["b".to_string(), "A".to_string()]),
            vec!["A", "b"]
        );
    }
}

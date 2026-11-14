use std::io;

use winreg::enums::{
    HKEY_CLASSES_ROOT, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_READ, KEY_WRITE,
    REG_DWORD, REG_EXPAND_SZ, REG_SZ,
};
use winreg::{RegKey, RegValue};

use crate::ops::track;
use crate::util::{expand_environment_variables, io_message};
use xos_core::log;

pub struct RegPathParts {
    pub root: RegKey,
    pub sub_key: String,
}

pub fn split_reg_path(full_path: &str) -> Result<RegPathParts, String> {
    if full_path.trim().is_empty() {
        return Err("A registry path is required. (Parameter 'fullPath')".to_string());
    }
    let first_slash = full_path.find('\\');
    let first_slash = match first_slash {
        Some(i) if i > 0 && i != full_path.len() - 1 => i,
        _ => return Err(
            "The registry path must include a supported root and subkey. (Parameter 'fullPath')"
                .to_string(),
        ),
    };
    let root_str = full_path[..first_slash].to_uppercase();
    let sub_key = full_path[first_slash + 1..].to_string();
    let predef = match root_str.as_str() {
        "HKLM" | "HKEY_LOCAL_MACHINE" => HKEY_LOCAL_MACHINE,
        "HKCU" | "HKEY_CURRENT_USER" => HKEY_CURRENT_USER,
        "HKCR" | "HKEY_CLASSES_ROOT" => HKEY_CLASSES_ROOT,
        "HKU" | "HKEY_USERS" => HKEY_USERS,
        _ => {
            return Err(format!(
                "Unsupported registry root: {root_str} (Parameter 'fullPath')"
            ))
        }
    };
    Ok(RegPathParts {
        root: RegKey::predef(predef),
        sub_key,
    })
}

fn set_value(
    what: &str,
    key_path: &str,
    value_name: &str,
    vtype: winreg::enums::RegType,
    bytes: Vec<u8>,
) -> bool {
    let attempt = || -> Result<bool, String> {
        let parts = split_reg_path(key_path)?;
        let (key, _) = parts
            .root
            .create_subkey_with_flags(&parts.sub_key, KEY_READ | KEY_WRITE)
            .map_err(|e| io_message(&e))?;
        key.set_raw_value(
            value_name,
            &RegValue {
                bytes: bytes.into(),
                vtype,
            },
        )
        .map_err(|e| io_message(&e))?;
        Ok(true)
    };
    match attempt() {
        Ok(_) => track(true),
        Err(m) => {
            log::log(&format!(
                "[ERROR] Registry {what}: {key_path} / {value_name}: {m}"
            ));
            track(false)
        }
    }
}

fn utf16_bytes(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(|u| u.to_le_bytes())
        .collect()
}

pub fn reg_set_dword(key_path: &str, value_name: &str, data: i32) -> bool {
    set_value(
        "RegSetDword",
        key_path,
        value_name,
        REG_DWORD,
        data.to_le_bytes().to_vec(),
    )
}

pub fn reg_set_string(key_path: &str, value_name: &str, data: &str) -> bool {
    set_value(
        "RegSetString",
        key_path,
        value_name,
        REG_SZ,
        utf16_bytes(data),
    )
}

pub fn reg_set_expand_string(key_path: &str, value_name: &str, data: &str) -> bool {
    set_value(
        "RegSetExpandString",
        key_path,
        value_name,
        REG_EXPAND_SZ,
        utf16_bytes(data),
    )
}

pub(crate) fn open_read(key_path: &str) -> Option<RegKey> {
    let parts = split_reg_path(key_path).ok()?;
    parts
        .root
        .open_subkey_with_flags(&parts.sub_key, KEY_READ)
        .ok()
}

pub(crate) fn decode_utf16_value(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
    String::from_utf16_lossy(&units[..end])
}

pub fn reg_get_dword(key_path: &str, value_name: &str) -> Option<i32> {
    let key = open_read(key_path)?;
    let v = key.get_raw_value(value_name).ok()?;
    if v.vtype == REG_DWORD && v.bytes.len() >= 4 {
        Some(i32::from_le_bytes([
            v.bytes[0], v.bytes[1], v.bytes[2], v.bytes[3],
        ]))
    } else {
        None
    }
}

pub fn reg_get_string(key_path: &str, value_name: &str) -> Option<String> {
    let key = open_read(key_path)?;
    key_get_string(&key, value_name, true)
}

pub(crate) fn key_get_string(key: &RegKey, value_name: &str, expand: bool) -> Option<String> {
    let v = key.get_raw_value(value_name).ok()?;
    if v.vtype == REG_SZ {
        Some(decode_utf16_value(&v.bytes))
    } else if v.vtype == REG_EXPAND_SZ {
        let s = decode_utf16_value(&v.bytes);
        Some(if expand {
            expand_environment_variables(&s)
        } else {
            s
        })
    } else {
        None
    }
}

pub fn reg_delete_value(key_path: &str, value_name: &str) -> bool {
    let attempt = || -> Result<(), String> {
        let parts = split_reg_path(key_path)?;
        if let Ok(key) = parts
            .root
            .open_subkey_with_flags(&parts.sub_key, KEY_READ | KEY_WRITE)
        {
            match key.delete_value(value_name) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(io_message(&e)),
            }
        }
        Ok(())
    };
    match attempt() {
        Ok(()) => {
            if !reg_value_exists(key_path, value_name) {
                return true;
            }
            log::log(&format!(
                "[RESULT] FAILED Registry RegDeleteValue: {key_path} / {value_name}: still present after the delete"
            ));
            track(false)
        }
        Err(m) => {
            log::log(&format!(
                "[ERROR] Registry RegDeleteValue: {key_path} / {value_name}: {m}"
            ));
            track(false)
        }
    }
}

pub fn reg_enum_sub_keys(key_path: &str) -> Vec<String> {
    match open_read(key_path) {
        Some(k) => k.enum_keys().filter_map(|r| r.ok()).collect(),
        None => Vec::new(),
    }
}

pub fn reg_delete_key(key_path: &str) -> bool {
    let attempt = || -> Result<(), String> {
        let parts = split_reg_path(key_path)?;
        match parts.root.delete_subkey_all(&parts.sub_key) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io_message(&e)),
        }
    };
    match attempt() {
        Ok(()) => track(!reg_key_exists(key_path)),
        Err(m) => {
            log::log(&format!("[ERROR] Registry RegDeleteKey: {key_path}: {m}"));
            track(false)
        }
    }
}

pub fn reg_create_key(key_path: &str) -> bool {
    let attempt = || -> Result<(), String> {
        let parts = split_reg_path(key_path)?;
        parts
            .root
            .create_subkey_with_flags(&parts.sub_key, KEY_READ | KEY_WRITE)
            .map_err(|e| io_message(&e))?;
        Ok(())
    };
    match attempt() {
        Ok(()) => track(true),
        Err(_) => track(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_roots() {
        let p = split_reg_path(r"hklm\SOFTWARE\Microsoft\Windows")
            .ok()
            .unwrap();
        assert_eq!(p.sub_key, r"SOFTWARE\Microsoft\Windows");
        assert!(split_reg_path(r"HKEY_CURRENT_USER\Software").is_ok());
        assert!(split_reg_path(r"HKU\.DEFAULT").is_ok());
        assert!(split_reg_path(r"HKCR\.txt").is_ok());
        assert!(split_reg_path("").is_err());
        assert!(split_reg_path("HKLM").is_err());
        assert!(split_reg_path(r"HKLM\").is_err());
        assert!(split_reg_path(r"\Software").is_err());
        assert_eq!(
            split_reg_path(r"HKXX\a").err().unwrap(),
            "Unsupported registry root: HKXX (Parameter 'fullPath')"
        );
    }
}

pub fn reg_key_exists(key_path: &str) -> bool {
    open_read(key_path).is_some()
}

pub fn reg_value_exists(key_path: &str, value_name: &str) -> bool {
    match open_read(key_path) {
        Some(k) => k.get_raw_value(value_name).is_ok(),
        None => false,
    }
}

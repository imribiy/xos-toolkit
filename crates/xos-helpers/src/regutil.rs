use std::io;

use winreg::enums::{
    RegType, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE, REG_BINARY, REG_DWORD, REG_EXPAND_SZ,
    REG_MULTI_SZ, REG_NONE, REG_QWORD, REG_SZ,
};
use winreg::{RegKey, RegValue};

pub(crate) fn hklm() -> RegKey {
    RegKey::predef(HKEY_LOCAL_MACHINE)
}

pub(crate) fn io_message(e: &io::Error) -> String {
    let s = e.to_string();
    match s.rfind(" (os error ") {
        Some(i) if s.ends_with(')') => s[..i].to_string(),
        _ => s,
    }
}

pub(crate) fn open_opt(root: &RegKey, path: &str, write: bool) -> io::Result<Option<RegKey>> {
    let flags = if write {
        KEY_READ | KEY_WRITE
    } else {
        KEY_READ
    };
    match root.open_subkey_with_flags(path, flags) {
        Ok(k) => Ok(Some(k)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Kind {
    String,
    ExpandString,
    Binary,
    DWord,
    MultiString,
    QWord,
    None,
    Unknown,
}

impl Kind {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Kind::String => "String",
            Kind::ExpandString => "ExpandString",
            Kind::Binary => "Binary",
            Kind::DWord => "DWord",
            Kind::MultiString => "MultiString",
            Kind::QWord => "QWord",
            Kind::None => "None",
            Kind::Unknown => "Unknown",
        }
    }

    pub(crate) fn is_string(self) -> bool {
        matches!(self, Kind::String | Kind::ExpandString)
    }

    pub(crate) fn reg_type(self) -> RegType {
        match self {
            Kind::String => REG_SZ,
            Kind::ExpandString => REG_EXPAND_SZ,
            Kind::DWord => REG_DWORD,
            Kind::QWord => REG_QWORD,
            Kind::MultiString => REG_MULTI_SZ,
            Kind::None => REG_NONE,
            _ => REG_BINARY,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) enum Data {
    Dword(i32),
    Qword(i64),
    Str(String),
    Multi(Vec<String>),
    Bin(Vec<u8>),
}

#[derive(Clone, Debug)]
pub(crate) struct Value {
    pub kind: Kind,
    pub data: Data,
}

impl Value {
    pub(crate) fn text(&self) -> String {
        match &self.data {
            Data::Dword(v) => v.to_string(),
            Data::Qword(v) => v.to_string(),
            Data::Str(s) => s.clone(),
            Data::Multi(_) => "System.String[]".to_string(),
            Data::Bin(_) => "System.Byte[]".to_string(),
        }
    }

    pub(crate) fn as_str(&self) -> Option<&str> {
        match &self.data {
            Data::Str(s) => Some(s),
            _ => None,
        }
    }
}

fn utf16_units(bytes: &[u8]) -> Vec<u16> {
    bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect()
}

pub(crate) fn decode_sz(bytes: &[u8]) -> String {
    let units = utf16_units(bytes);
    let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
    String::from_utf16_lossy(&units[..end])
}

pub(crate) fn encode_sz(text: &str) -> Vec<u8> {
    text.encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(|u| u.to_le_bytes())
        .collect()
}

pub(crate) fn from_raw(v: &RegValue, expand: bool) -> Value {
    let bytes: &[u8] = &v.bytes;
    match v.vtype {
        REG_SZ => Value {
            kind: Kind::String,
            data: Data::Str(decode_sz(bytes)),
        },
        REG_EXPAND_SZ => {
            let raw = decode_sz(bytes);
            Value {
                kind: Kind::ExpandString,
                data: Data::Str(if expand {
                    xos_sys::expand_environment_variables(&raw)
                } else {
                    raw
                }),
            }
        }
        REG_DWORD if bytes.len() >= 4 => Value {
            kind: Kind::DWord,
            data: Data::Dword(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])),
        },
        REG_QWORD if bytes.len() >= 8 => Value {
            kind: Kind::QWord,
            data: Data::Qword(i64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ])),
        },
        REG_MULTI_SZ => {
            let units = utf16_units(bytes);
            let mut items: Vec<String> = units
                .split(|&u| u == 0)
                .map(String::from_utf16_lossy)
                .collect();
            while items.last().is_some_and(|s| s.is_empty()) {
                items.pop();
            }
            Value {
                kind: Kind::MultiString,
                data: Data::Multi(items),
            }
        }
        REG_BINARY => Value {
            kind: Kind::Binary,
            data: Data::Bin(bytes.to_vec()),
        },
        REG_NONE => Value {
            kind: Kind::None,
            data: Data::Bin(bytes.to_vec()),
        },
        _ => Value {
            kind: Kind::Unknown,
            data: Data::Bin(bytes.to_vec()),
        },
    }
}

pub(crate) fn read_value(key: &RegKey, name: &str, expand: bool) -> io::Result<Option<Value>> {
    match key.get_raw_value(name) {
        Ok(v) => Ok(Some(from_raw(&v, expand))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

pub(crate) fn delete_value_quiet(key: &RegKey, name: &str) -> io::Result<()> {
    match key.delete_value(name) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

pub(crate) fn set_value(key: &RegKey, name: &str, kind: Kind, data: &Data) -> io::Result<()> {
    let bytes = match data {
        Data::Dword(v) => v.to_le_bytes().to_vec(),
        Data::Qword(v) => v.to_le_bytes().to_vec(),
        Data::Str(s) => encode_sz(s),
        Data::Multi(_) => Vec::new(),
        Data::Bin(b) => b.clone(),
    };
    key.set_raw_value(
        name,
        &RegValue {
            bytes: bytes.into(),
            vtype: kind.reg_type(),
        },
    )
}

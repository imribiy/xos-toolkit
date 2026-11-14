use std::path::{Path, PathBuf};

use windows::core::PCWSTR;
use windows::Win32::System::Environment::ExpandEnvironmentStringsW;
use windows::Win32::System::SystemInformation::{GetSystemDirectoryW, GetWindowsDirectoryW};

pub(crate) fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub(crate) fn pcwstr(w: &[u16]) -> PCWSTR {
    PCWSTR(w.as_ptr())
}

pub(crate) fn encode_command(script: &str) -> String {
    use base64::Engine;
    let bytes: Vec<u8> = script
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub(crate) fn read_all_text(path: &str) -> std::io::Result<String> {
    let data = std::fs::read(path)?;
    Ok(crate::process::decode_text_with_bom(&data))
}

pub(crate) fn path_combine(a: &str, b: &str) -> String {
    if b.is_empty() {
        return a.to_string();
    }
    if path_is_rooted(b) || a.is_empty() {
        return b.to_string();
    }
    if a.ends_with('\\') || a.ends_with('/') {
        format!("{a}{b}")
    } else {
        format!("{a}\\{b}")
    }
}

pub(crate) fn ulen(s: &str) -> usize {
    s.encode_utf16().count()
}

pub(crate) fn substring_to(s: &str, units: usize) -> String {
    let w: Vec<u16> = s.encode_utf16().take(units).collect();
    String::from_utf16_lossy(&w)
}

pub(crate) fn escape_powershell_literal(value: &str) -> String {
    value.replace('\'', "''")
}

pub(crate) fn quote_command_argument(value: &str) -> String {
    if !value.is_empty() && !value.contains([' ', '\t', '"']) {
        return value.to_string();
    }
    format!("\"{}\"", value.replace('"', "\\\""))
}

pub(crate) fn truncate_for_log(value: &str) -> String {
    const MAXIMUM: usize = 2048;
    if ulen(value) > MAXIMUM {
        format!("{}...", substring_to(value, MAXIMUM))
    } else {
        value.to_string()
    }
}

pub(crate) fn perf_detail(what: &str, elapsed_ms: u128, detail: &str) {
    xos_core::log::log(&format!("[PERF] {what} took {elapsed_ms} ms | {detail}"));
}

pub(crate) fn io_message(e: &std::io::Error) -> String {
    let s = e.to_string();
    match s.rfind(" (os error ") {
        Some(i) if s.ends_with(')') => s[..i].to_string(),
        _ => s,
    }
}

fn dir_from(f: unsafe fn(Option<&mut [u16]>) -> u32) -> String {
    let mut buf = vec![0u16; 520];
    let n = unsafe { f(Some(&mut buf)) } as usize;
    String::from_utf16_lossy(&buf[..n.min(buf.len())])
}

pub(crate) fn windows_dir() -> String {
    let d = dir_from(GetWindowsDirectoryW);
    if d.is_empty() {
        "C:\\Windows".to_string()
    } else {
        d
    }
}

pub(crate) fn system_dir() -> String {
    let d = dir_from(GetSystemDirectoryW);
    if d.is_empty() {
        "C:\\Windows\\System32".to_string()
    } else {
        d
    }
}

pub(crate) fn program_data_dir() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("C:\\ProgramData"))
}

pub fn expand_environment_variables(name: &str) -> String {
    let src = wide(name);
    unsafe {
        let n = ExpandEnvironmentStringsW(pcwstr(&src), None) as usize;
        if n == 0 {
            return name.to_string();
        }
        let mut buf = vec![0u16; n];
        let m = ExpandEnvironmentStringsW(pcwstr(&src), Some(&mut buf)) as usize;
        if m == 0 {
            return name.to_string();
        }
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..end])
    }
}

pub(crate) fn full_path(p: &str) -> Option<String> {
    if p.is_empty() || p.contains('\0') {
        return None;
    }
    let src = wide(p);
    unsafe {
        let n = windows::Win32::Storage::FileSystem::GetFullPathNameW(pcwstr(&src), None, None)
            as usize;
        if n == 0 {
            return None;
        }
        let mut buf = vec![0u16; n + 1];
        let m = windows::Win32::Storage::FileSystem::GetFullPathNameW(
            pcwstr(&src),
            Some(&mut buf),
            None,
        ) as usize;
        if m == 0 || m > buf.len() {
            return None;
        }
        Some(String::from_utf16_lossy(&buf[..m]))
    }
}

pub(crate) fn path_root(full: &str) -> String {
    let b = full.as_bytes();
    if b.len() >= 3 && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/') {
        return full[..3].to_string();
    }
    if b.len() >= 2 && b[1] == b':' {
        return full[..2].to_string();
    }
    if full.starts_with("\\\\") {
        let parts: Vec<&str> = full[2..].splitn(3, '\\').collect();
        if parts.len() >= 2 {
            return format!("\\\\{}\\{}", parts[0], parts[1]);
        }
    }
    if full.starts_with('\\') {
        return "\\".to_string();
    }
    String::new()
}

pub(crate) fn path_is_rooted(p: &str) -> bool {
    let b = p.as_bytes();
    if b.is_empty() {
        return false;
    }
    if b[0] == b'\\' || b[0] == b'/' {
        return true;
    }
    b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic()
}

pub(crate) fn file_name_of(p: &str) -> String {
    Path::new(p)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default()
}

pub(crate) fn guid_n() -> String {
    match unsafe { windows::Win32::System::Com::CoCreateGuid() } {
        Ok(g) => format!(
            "{:08x}{:04x}{:04x}{}",
            g.data1,
            g.data2,
            g.data3,
            g.data4
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ),
        Err(_) => {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            format!("{:032x}", nanos)
        }
    }
}

use core::ptr::null;
use core::ptr::null_mut;

use windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND;
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::Registry::RegCloseKey;
use windows_sys::Win32::System::Registry::RegCreateKeyExW;
use windows_sys::Win32::System::Registry::RegDeleteKeyExW;
use windows_sys::Win32::System::Registry::RegDeleteTreeW;
use windows_sys::Win32::System::Registry::RegOpenKeyExW;
use windows_sys::Win32::System::Registry::RegQueryInfoKeyW;
use windows_sys::Win32::System::Registry::RegQueryValueExW;
use windows_sys::Win32::System::Registry::RegSetValueExW;
use windows_sys::Win32::System::Registry::HKEY;
use windows_sys::Win32::System::Registry::KEY_QUERY_VALUE;
use windows_sys::Win32::System::Registry::KEY_READ;
use windows_sys::Win32::System::Registry::KEY_SET_VALUE;
use windows_sys::Win32::System::Registry::KEY_WOW64_64KEY;
use windows_sys::Win32::System::Registry::KEY_WRITE;
use windows_sys::Win32::System::Registry::REG_EXPAND_SZ;
use windows_sys::Win32::System::Registry::REG_LINK;
use windows_sys::Win32::System::Registry::REG_OPTION_NON_VOLATILE;
use windows_sys::Win32::System::Registry::REG_OPTION_OPEN_LINK;
use windows_sys::Win32::System::Registry::REG_SZ;

use crate::sys;

pub struct Key(pub HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        unsafe {
            RegCloseKey(self.0);
        }
    }
}

fn open_with(root: HKEY, path: &str, access: u32, options: u32) -> Result<Key, u32> {
    unsafe {
        let p = sys::wide(path);
        let mut h: HKEY = null_mut();
        let rc = RegOpenKeyExW(root, p.as_ptr(), options, access | KEY_WOW64_64KEY, &mut h);
        if rc == ERROR_SUCCESS {
            Ok(Key(h))
        } else {
            Err(rc)
        }
    }
}

pub fn open_read(root: HKEY, path: &str) -> Result<Key, u32> {
    open_with(root, path, KEY_READ, 0)
}

pub fn open_values(root: HKEY, path: &str) -> Result<Key, u32> {
    open_with(root, path, KEY_QUERY_VALUE | KEY_SET_VALUE, 0)
}

pub fn open_link(root: HKEY, path: &str) -> Result<Key, u32> {
    open_with(
        root,
        path,
        KEY_QUERY_VALUE | KEY_SET_VALUE,
        REG_OPTION_OPEN_LINK,
    )
}

pub fn exists(root: HKEY, path: &str) -> bool {
    open_read(root, path).is_ok()
}

pub fn create(root: HKEY, path: &str) -> Result<Key, u32> {
    unsafe {
        let p = sys::wide(path);
        let mut h: HKEY = null_mut();
        let rc = RegCreateKeyExW(
            root,
            p.as_ptr(),
            0,
            null(),
            REG_OPTION_NON_VOLATILE,
            KEY_READ | KEY_WRITE | KEY_WOW64_64KEY,
            null(),
            &mut h,
            null_mut(),
        );
        if rc == ERROR_SUCCESS {
            Ok(Key(h))
        } else {
            Err(rc)
        }
    }
}

fn set_raw(key: &Key, name: &str, kind: u32, data: &[u16]) -> Result<(), u32> {
    unsafe {
        let n = sys::wide(name);
        let rc = RegSetValueExW(
            key.0,
            if name.is_empty() { null() } else { n.as_ptr() },
            0,
            kind,
            data.as_ptr() as *const u8,
            (data.len() * 2) as u32,
        );
        if rc == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(rc)
        }
    }
}

pub fn set_string(key: &Key, name: &str, value: &str) -> Result<(), u32> {
    set_raw(key, name, REG_SZ, &sys::wide(value))
}

pub fn set_link(key: &Key, target: &str) -> Result<(), u32> {
    let data: Vec<u16> = target.encode_utf16().collect();
    set_raw(key, "SymbolicLinkValue", REG_LINK, &data)
}

fn read_raw(key: &Key, name: &str) -> Option<(u32, String)> {
    unsafe {
        let n = sys::wide(name);
        let np = if name.is_empty() { null() } else { n.as_ptr() };
        let mut kind = 0u32;
        let mut size = 0u32;
        if RegQueryValueExW(key.0, np, null(), &mut kind, null_mut(), &mut size) != ERROR_SUCCESS {
            return None;
        }
        let mut buf = vec![0u16; size as usize / 2 + 1];
        let mut bytes = (buf.len() * 2) as u32;
        if RegQueryValueExW(
            key.0,
            np,
            null(),
            &mut kind,
            buf.as_mut_ptr() as *mut u8,
            &mut bytes,
        ) != ERROR_SUCCESS
        {
            return None;
        }
        let mut len = bytes as usize / 2;
        while len > 0 && buf[len - 1] == 0 {
            len -= 1;
        }
        Some((kind, String::from_utf16_lossy(&buf[..len])))
    }
}

pub fn read_string(key: &Key, name: &str) -> Option<String> {
    match read_raw(key, name) {
        Some((kind, text)) if kind == REG_SZ || kind == REG_EXPAND_SZ => Some(text),
        _ => None,
    }
}

pub fn read_link(key: &Key) -> Option<String> {
    match read_raw(key, "SymbolicLinkValue") {
        Some((kind, text)) if kind == REG_LINK => Some(text),
        _ => None,
    }
}

pub fn read_string_at(root: HKEY, path: &str, name: &str) -> Option<String> {
    open_read(root, path).ok().and_then(|k| read_string(&k, name))
}

pub fn is_empty(root: HKEY, path: &str) -> bool {
    let key = match open_read(root, path) {
        Ok(k) => k,
        Err(_) => return false,
    };
    unsafe {
        let mut subkeys = 0u32;
        let mut values = 0u32;
        let rc = RegQueryInfoKeyW(
            key.0,
            null_mut(),
            null_mut(),
            null(),
            &mut subkeys,
            null_mut(),
            null_mut(),
            &mut values,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
        );
        rc == ERROR_SUCCESS && subkeys == 0 && values == 0
    }
}

pub fn delete_tree(root: HKEY, path: &str) -> Result<(), u32> {
    let p = sys::wide(path);
    let rc = unsafe { RegDeleteTreeW(root, p.as_ptr()) };
    if rc == ERROR_SUCCESS || rc == ERROR_FILE_NOT_FOUND {
        Ok(())
    } else {
        Err(rc)
    }
}

pub fn delete_empty(root: HKEY, path: &str) -> Result<(), u32> {
    if !is_empty(root, path) {
        return Ok(());
    }
    let p = sys::wide(path);
    let rc = unsafe { RegDeleteKeyExW(root, p.as_ptr(), KEY_WOW64_64KEY, 0) };
    if rc == ERROR_SUCCESS || rc == ERROR_FILE_NOT_FOUND {
        Ok(())
    } else {
        Err(rc)
    }
}

use core::ptr::null;
use core::ptr::null_mut;

use windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND;
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::Registry::RegCloseKey;
use windows_sys::Win32::System::Registry::RegCreateKeyExW;
use windows_sys::Win32::System::Registry::RegDeleteTreeW;
use windows_sys::Win32::System::Registry::RegOpenKeyExW;
use windows_sys::Win32::System::Registry::RegQueryValueExW;
use windows_sys::Win32::System::Registry::RegSetValueExW;
use windows_sys::Win32::System::Registry::HKEY;
use windows_sys::Win32::System::Registry::HKEY_LOCAL_MACHINE;
use windows_sys::Win32::System::Registry::KEY_READ;
use windows_sys::Win32::System::Registry::KEY_WOW64_64KEY;
use windows_sys::Win32::System::Registry::KEY_WRITE;
use windows_sys::Win32::System::Registry::REG_OPTION_NON_VOLATILE;
use windows_sys::Win32::System::Registry::REG_SZ;

use crate::sys;

pub const CLASSES: [&str; 4] = [
    "exefile",
    "batfile",
    "cmdfile",
    "Microsoft.PowerShellScript.1",
];
pub const VERB: &str = "XSudoRunAsTI";
pub const LABEL: &str = "Run as TrustedInstaller";

pub fn key_path(class: &str) -> String {
    format!("SOFTWARE\\Classes\\{class}\\shell\\{VERB}")
}

pub fn command_string(exe: &str) -> String {
    format!("\"{exe}\" --Launch \"%1\"")
}

struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        unsafe {
            RegCloseKey(self.0);
        }
    }
}

fn create(path: &str) -> Result<Key, u32> {
    unsafe {
        let p = sys::wide(path);
        let mut h: HKEY = null_mut();
        let rc = RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            p.as_ptr(),
            0,
            null(),
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE | KEY_WOW64_64KEY,
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

fn set_string(key: &Key, name: &str, value: &str) -> Result<(), u32> {
    unsafe {
        let n = sys::wide(name);
        let v = sys::wide(value);
        let rc = RegSetValueExW(
            key.0,
            if name.is_empty() { null() } else { n.as_ptr() },
            0,
            REG_SZ,
            v.as_ptr() as *const u8,
            (v.len() * 2) as u32,
        );
        if rc == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(rc)
        }
    }
}

fn read_default(path: &str) -> Option<String> {
    unsafe {
        let p = sys::wide(path);
        let mut h: HKEY = null_mut();
        if RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            p.as_ptr(),
            0,
            KEY_READ | KEY_WOW64_64KEY,
            &mut h,
        ) != ERROR_SUCCESS
        {
            return None;
        }
        let key = Key(h);
        let mut kind = 0u32;
        let mut size = 0u32;
        if RegQueryValueExW(key.0, null(), null(), &mut kind, null_mut(), &mut size)
            != ERROR_SUCCESS
            || kind != REG_SZ
        {
            return None;
        }
        let mut buf = vec![0u16; size as usize / 2 + 1];
        let mut bytes = (buf.len() * 2) as u32;
        if RegQueryValueExW(
            key.0,
            null(),
            null(),
            &mut kind,
            buf.as_mut_ptr() as *mut u8,
            &mut bytes,
        ) != ERROR_SUCCESS
        {
            return None;
        }
        let mut n = bytes as usize / 2;
        while n > 0 && buf[n - 1] == 0 {
            n -= 1;
        }
        Some(String::from_utf16_lossy(&buf[..n]))
    }
}

pub fn is_enabled(exe: &str) -> bool {
    let want = command_string(exe);
    CLASSES.iter().all(|c| {
        read_default(&format!("{}\\command", key_path(c)))
            .map(|v| v.eq_ignore_ascii_case(&want))
            .unwrap_or(false)
    })
}

pub fn enable(exe: &str) -> Result<(), u32> {
    let command = command_string(exe);
    for class in CLASSES {
        let path = key_path(class);
        let verb = create(&path)?;
        set_string(&verb, "MUIVerb", LABEL)?;
        set_string(&verb, "Icon", exe)?;
        set_string(&verb, "HasLUAShield", "")?;
        let cmd = create(&format!("{path}\\command"))?;
        set_string(&cmd, "", &command)?;
    }
    Ok(())
}

pub fn disable() -> Result<(), u32> {
    let mut first_error = None;
    for class in CLASSES {
        let p = sys::wide(&key_path(class));
        let rc = unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, p.as_ptr()) };
        if rc != ERROR_SUCCESS && rc != ERROR_FILE_NOT_FOUND && first_error.is_none() {
            first_error = Some(rc);
        }
    }
    match first_error {
        None => Ok(()),
        Some(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_quotes_exe_and_argument() {
        assert_eq!(
            command_string("C:\\Program Files\\XSudo\\XSudo.exe"),
            "\"C:\\Program Files\\XSudo\\XSudo.exe\" --Launch \"%1\""
        );
    }

    #[test]
    fn keys_cover_the_four_classes() {
        let keys: Vec<String> = CLASSES.iter().map(|c| key_path(c)).collect();
        assert_eq!(
            keys,
            [
                "SOFTWARE\\Classes\\exefile\\shell\\XSudoRunAsTI",
                "SOFTWARE\\Classes\\batfile\\shell\\XSudoRunAsTI",
                "SOFTWARE\\Classes\\cmdfile\\shell\\XSudoRunAsTI",
                "SOFTWARE\\Classes\\Microsoft.PowerShellScript.1\\shell\\XSudoRunAsTI",
            ]
        );
    }

    #[test]
    fn launch_command_round_trips_through_the_parser() {
        let cmd =
            command_string("C:\\Program Files\\XSudo\\XSudo.exe").replace("%1", "C:\\a b\\t.bat");
        let wide: Vec<u16> = cmd.encode_utf16().collect();
        let t = crate::cli::tokenize(&wide);
        assert_eq!(t.len(), 3);
        assert_eq!(t[0].text, "C:\\Program Files\\XSudo\\XSudo.exe");
        assert!(crate::launch::is_launch_switch(&t[1].text));
        assert_eq!(t[2].text, "C:\\a b\\t.bat");
    }
}

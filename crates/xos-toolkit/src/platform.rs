use std::path::PathBuf;
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
use winreg::RegKey;

pub fn windows_build() -> u32 {
    RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        .and_then(|k| k.get_value::<String, _>("CurrentBuildNumber"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

pub fn windows_text() -> String {
    let b = windows_build();
    if b >= 22000 {
        format!("Win 11 / {b}")
    } else {
        format!("Win 10 / {b}")
    }
}

pub fn system_prefers_dark() -> bool {
    RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey(r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")
        .and_then(|k| k.get_value::<u32, _>("AppsUseLightTheme"))
        .map(|v| v == 0)
        .unwrap_or(true)
}

const DIALOGS_KEY: &str = r"Software\XOSToolkit\Dialogs";

pub fn dialog_muted(key: &str) -> bool {
    RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey(DIALOGS_KEY)
        .and_then(|k| k.get_value::<u32, _>(key))
        .map(|v| v == 1)
        .unwrap_or(false)
}

pub fn mute_dialog(key: &str) -> std::io::Result<()> {
    let (k, _) = RegKey::predef(HKEY_CURRENT_USER).create_subkey(DIALOGS_KEY)?;
    k.set_value(key, &1u32)
}

pub fn user_name() -> String {
    std::env::var("USERNAME").unwrap_or_default()
}

fn current_user_sid() -> Option<String> {
    use windows::core::PWSTR;
    use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).ok()?;
        let mut len = 0u32;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut len);
        let mut buf = vec![0u8; len as usize];
        let ok = GetTokenInformation(token, TokenUser, Some(buf.as_mut_ptr() as *mut _), len, &mut len).is_ok();
        let _ = CloseHandle(token);
        if !ok {
            return None;
        }
        let tu = &*(buf.as_ptr() as *const TOKEN_USER);
        let mut s = PWSTR::null();
        ConvertSidToStringSidW(tu.User.Sid, &mut s).ok()?;
        let out = s.to_string().ok();
        let _ = LocalFree(Some(HLOCAL(s.0 as *mut _)));
        out
    }
}

pub fn avatar_path() -> Option<PathBuf> {
    let exists = |p: String| {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            Some(pb)
        } else {
            None
        }
    };
    if let Ok(k) = RegKey::predef(HKEY_CURRENT_USER).open_subkey(r"Software\Microsoft\Windows\CurrentVersion\AccountPicture") {
        if let Ok(p) = k.get_value::<String, _>("Image96") {
            if let Some(pb) = exists(p) {
                return Some(pb);
            }
        }
    }
    let sid = current_user_sid()?;
    let k = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey(format!(r"SOFTWARE\Microsoft\Windows\CurrentVersion\AccountPicture\Users\{sid}"))
        .ok()?;
    for name in ["Image96", "Image40"] {
        if let Ok(p) = k.get_value::<String, _>(name) {
            if let Some(pb) = exists(p) {
                return Some(pb);
            }
        }
    }
    None
}

pub fn set_title_bar_dark(hwnd: isize, dark: bool) {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::Graphics::Dwm::{DwmSetWindowAttribute, DWMWINDOWATTRIBUTE};
    let attr = if windows_build() < 18985 { 19 } else { 20 };
    let value: i32 = if dark { 1 } else { 0 };
    unsafe {
        let _ = DwmSetWindowAttribute(
            HWND(hwnd as *mut _),
            DWMWINDOWATTRIBUTE(attr),
            &value as *const i32 as *const _,
            std::mem::size_of::<i32>() as u32,
        );
    }
}

pub fn message_box_error(text: &str, title: &str) {
    use windows::core::HSTRING;
    use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK};
    unsafe {
        MessageBoxW(None, &HSTRING::from(text), &HSTRING::from(title), MB_OK | MB_ICONERROR);
    }
}

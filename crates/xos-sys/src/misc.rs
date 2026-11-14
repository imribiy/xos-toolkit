use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use windows::core::{s, w};
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::SystemInformation::OSVERSIONINFOW;
use windows::Win32::UI::Shell::{SHChangeNotify, SHCNE_ASSOCCHANGED, SHCNF_IDLIST};

use crate::elevation::{get_protected_runtime_dir, protect_directory, resource_bytes};
use crate::reg::{reg_get_string, reg_key_exists};
use crate::util::path_combine;

pub fn get_pending_reboot_reason() -> Option<&'static str> {
    if reg_key_exists(
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
    ) {
        return Some("a component servicing operation");
    }
    if reg_key_exists(
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\PackagesPending",
    ) {
        return Some("a package installation");
    }
    if reg_key_exists(
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
    ) {
        return Some("a Windows Update");
    }
    None
}

fn os_version_build() -> i32 {
    type RtlGetVersionFn = unsafe extern "system" fn(*mut OSVERSIONINFOW) -> i32;
    unsafe {
        let ntdll = match GetModuleHandleW(w!("ntdll.dll")) {
            Ok(h) => h,
            Err(_) => return 0,
        };
        match GetProcAddress(ntdll, s!("RtlGetVersion")) {
            Some(p) => {
                let f: RtlGetVersionFn = std::mem::transmute(p);
                let mut info = OSVERSIONINFOW {
                    dwOSVersionInfoSize: std::mem::size_of::<OSVERSIONINFOW>() as u32,
                    ..Default::default()
                };
                if f(&mut info) == 0 {
                    info.dwBuildNumber as i32
                } else {
                    0
                }
            }
            None => 0,
        }
    }
}

pub fn get_windows_build_number() -> i32 {
    match reg_get_string(
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        "CurrentBuildNumber",
    ) {
        Some(v) => v
            .trim()
            .parse::<i32>()
            .unwrap_or_else(|_| os_version_build()),
        None => os_version_build(),
    }
}

pub fn notify_shell_assoc_changed() {
    unsafe { SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, None, None) };
}

fn npi_dir_cache() -> &'static Mutex<Option<PathBuf>> {
    static C: OnceLock<Mutex<Option<PathBuf>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(None))
}

pub fn ensure_nvidia_profile_inspector() -> anyhow::Result<String> {
    let mut cache = npi_dir_cache().lock().unwrap();
    if let Some(d) = cache.as_ref() {
        if d.is_dir() && d.join("nvidiaProfileInspector.exe").exists() {
            return Ok(d.to_string_lossy().to_string());
        }
    }
    let runtime = get_protected_runtime_dir()?;
    let dir = runtime.join("NPI");
    std::fs::create_dir_all(&dir)?;
    protect_directory(&runtime.to_string_lossy())?;
    protect_directory(&dir.to_string_lossy())?;

    for (resource, file) in [
        (
            "XOSToolkit.NPI.nvidiaProfileInspector.exe",
            "nvidiaProfileInspector.exe",
        ),
        (
            "XOSToolkit.NPI.nvidiaProfileInspector.exe.config",
            "nvidiaProfileInspector.exe.config",
        ),
        ("XOSToolkit.NPI.XOS.nip", "XOS.nip"),
        ("XOSToolkit.NPI.Reference.xml", "Reference.xml"),
        ("XOSToolkit.NPI.Default.nip", "Default.nip"),
    ] {
        extract_embedded_resource(resource, &path_combine(&dir.to_string_lossy(), file))?;
    }

    *cache = Some(dir.clone());
    Ok(dir.to_string_lossy().to_string())
}

fn extract_embedded_resource(resource_name: &str, target_path: &str) -> anyhow::Result<()> {
    if Path::new(target_path).exists() {
        std::fs::remove_file(target_path)?;
    }
    if let Some(bytes) = resource_bytes(resource_name) {
        std::fs::write(target_path, bytes)?;
    }
    Ok(())
}

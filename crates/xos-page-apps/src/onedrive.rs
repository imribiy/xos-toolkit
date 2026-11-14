use crate::util::*;
use std::collections::HashSet;
use std::path::Path;
use std::time::Duration;
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ};
use winreg::RegKey;
use xos_core::log;
use xos_sys::CmdOptions;

const ONE_DRIVE_PROCESS_NAMES: [&str; 8] = [
    "OneDrive.exe",
    "OneDrive.App.exe",
    "OneDrive.Sync.Service.exe",
    "OneDriveStandaloneUpdater.exe",
    "OneDriveSetup.exe",
    "OneDriveLauncher.exe",
    "Microsoft.SharePoint.exe",
    "FileCoAuth.exe",
];

pub fn local_onedrive_dir() -> String {
    combine(&local_app_data(), r"Microsoft\OneDrive")
}

pub fn check_onedrive() -> bool {
    if file_exists(&combine(
        &local_app_data(),
        r"Microsoft\OneDrive\OneDrive.exe",
    )) {
        return true;
    }
    if file_exists(&combine(
        &program_files(),
        r"Microsoft OneDrive\OneDrive.exe",
    )) {
        return true;
    }
    if file_exists(&combine(
        &program_files_x86(),
        r"Microsoft OneDrive\OneDrive.exe",
    )) {
        return true;
    }

    let script = "$ErrorActionPreference='Stop';\
$p=Get-AppxPackage -AllUsers -Name *OneDriveSync*;\
$q=Get-AppxProvisionedPackage -Online|Where-Object{$_.PackageName -like '*OneDriveSync*'};\
$r=Get-Process -ErrorAction SilentlyContinue|Where-Object{$_.ProcessName -like 'OneDrive*' -or $_.ProcessName -in @('Microsoft.SharePoint','FileCoAuth')};\
if($p -or $q -or $r){'OD_YES'}else{'OD_NO'}";
    let output = run_powershell_output(script, 60000);
    !contains_ci(&output, "OD_NO")
}

pub fn stop_onedrive_processes() {
    for name in ONE_DRIVE_PROCESS_NAMES {
        xos_sys::run_cmd_opts(
            "taskkill.exe",
            &format!("/F /IM \"{name}\""),
            &CmdOptions {
                timeout_ms: Some(10000),
                suppress_log: true,
                ..Default::default()
            },
        );
    }
}

pub fn remove_onedrive_scheduled_tasks() {
    let script = "$ErrorActionPreference='SilentlyContinue';\
Get-ScheduledTask -ErrorAction SilentlyContinue|\
Where-Object{$_.TaskName -like '*OneDrive*'}|\
Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue";
    let encoded = encode_command(script);
    xos_sys::run_cmd_opts(
        "powershell.exe",
        &format!("-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}"),
        &CmdOptions {
            timeout_ms: Some(30000),
            suppress_log: true,
            ..Default::default()
        },
    );
}

pub fn split_uninstall_command(command: &str) -> Option<(String, String)> {
    let command = command.trim();
    let split = if command.starts_with('"') {
        match command[1..].find('"') {
            Some(i) => i + 1 + 1,
            None => 0,
        }
    } else {
        match command.to_ascii_lowercase().find(".exe") {
            Some(i) => i + 4,
            None => 3,
        }
    };
    if split == 0 || split > command.len() || !command.is_char_boundary(split) {
        return None;
    }
    let exe = command[..split]
        .trim_matches(|c| c == '"' || c == ' ')
        .to_string();
    let args = command[split..].trim().to_string();
    Some((exe, args))
}

fn walk_files(dir: &Path, file_name: &str, found: &mut Vec<String>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            walk_files(&path, file_name, found)?;
        } else if entry
            .file_name()
            .to_string_lossy()
            .eq_ignore_ascii_case(file_name)
        {
            found.push(path.to_string_lossy().to_string());
        }
    }
    Ok(())
}

pub fn find_onedrive_uninstallers(local_od_dir: &str) -> Vec<(String, String)> {
    let mut result: Vec<(String, String)> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut add = |exe: &str, args: &str| {
        if !exe.trim().is_empty()
            && file_exists(exe)
            && seen.insert(format!("{exe}|{args}").to_lowercase())
        {
            result.push((exe.to_string(), args.to_string()));
        }
    };

    for root in [
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ] {
        let hive = if root.to_uppercase().starts_with("HKCU") {
            HKEY_CURRENT_USER
        } else {
            HKEY_LOCAL_MACHINE
        };
        match RegKey::predef(hive).open_subkey_with_flags(&root[5..], KEY_READ) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                log::log(&format!(
                    "[Apps] OneDrive uninstall entries under {root} could not be read: {e}"
                ));
                continue;
            }
            Ok(key) => {
                for name in key.enum_keys().filter_map(|k| k.ok()) {
                    let command =
                        xos_sys::reg_get_string(&format!("{root}\\{name}"), "UninstallString")
                            .unwrap_or_default();
                    if command.trim().is_empty() || !contains_ci(&command, "OneDriveSetup.exe") {
                        continue;
                    }
                    if let Some((exe, args)) = split_uninstall_command(&command) {
                        let args = if args.is_empty() {
                            "/uninstall".to_string()
                        } else {
                            args
                        };
                        add(&exe, &args);
                    }
                }
            }
        }
    }

    if dir_exists(local_od_dir) {
        let mut found = Vec::new();
        match walk_files(Path::new(local_od_dir), "OneDriveSetup.exe", &mut found) {
            Ok(()) => {
                for exe in found {
                    add(&exe, "/uninstall");
                }
            }
            Err(e) => log::log(&format!(
                "[Apps] OneDrive folder could not be searched: {e}"
            )),
        }
    }

    add(
        &combine(&windows_dir(), r"SysWOW64\OneDriveSetup.exe"),
        "/uninstall",
    );
    add(&combine(&system_dir(), "OneDriveSetup.exe"), "/uninstall");
    result
}

pub fn run_onedrive_removal() {
    stop_onedrive_processes();
    std::thread::sleep(Duration::from_millis(2000));

    let local_od_dir = local_onedrive_dir();
    for (exe, args) in find_onedrive_uninstallers(&local_od_dir) {
        let uninstalled = xos_sys::run_cmd_timeout(&exe, &args, 120000);
        log::log(&format!(
            "[Apps] OneDrive uninstaller {exe} {args}: {}",
            if uninstalled { "ok" } else { "did not finish" }
        ));
        if uninstalled && !file_exists(&combine(&local_od_dir, "OneDrive.exe")) {
            break;
        }
    }

    std::thread::sleep(Duration::from_millis(5000));
    stop_onedrive_processes();
    remove_onedrive_scheduled_tasks();

    if dir_exists(&local_od_dir) {
        if let Err(e) = std::fs::remove_dir_all(&local_od_dir) {
            log::log(&format!(
                "[Apps] OneDrive folder could not be removed: {local_od_dir}: {e}"
            ));
        }
        log::log(&format!(
            "[Apps] OneDrive folder {local_od_dir} present after cleanup: {}",
            if dir_exists(&local_od_dir) {
                "True"
            } else {
                "False"
            }
        ));
    }

    xos_sys::run_cmd(
        "powershell.exe",
        "-NoProfile -Command \"Get-AppxPackage -Name *OneDriveSync* -AllUsers | Remove-AppxPackage -AllUsers\"",
    );
    xos_sys::run_cmd(
        "powershell.exe",
        "-NoProfile -Command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -like '*OneDriveSync*'} | Remove-AppxProvisionedPackage -Online\"",
    );

    let sf = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders";
    xos_sys::reg_set_expand_string(sf, "Desktop", "%USERPROFILE%\\Desktop");
    xos_sys::reg_set_expand_string(sf, "Personal", "%USERPROFILE%\\Documents");
    xos_sys::reg_set_expand_string(sf, "My Pictures", "%USERPROFILE%\\Pictures");
    xos_sys::reg_set_expand_string(
        sf,
        "{374DE290-123F-4565-9164-39C4925E467B}",
        "%USERPROFILE%\\Downloads",
    );

    let clsid1 = "{018D5C66-4533-4307-9B53-224DE2ED1FE6}";
    let clsid2 = "{04271989-C4D1-480D-BEE1-053A5CA6222E}";
    xos_sys::reg_delete_key(&format!(r"HKCU\Software\Classes\CLSID\{clsid1}"));
    xos_sys::reg_delete_key(&format!(r"HKCU\Software\Classes\CLSID\{clsid2}"));
    xos_sys::reg_delete_key(&format!(
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{clsid1}"
    ));
    xos_sys::reg_delete_key(&format!(
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{clsid2}"
    ));

    xos_sys::reg_delete_value(
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        "OneDrive",
    );
    xos_sys::reg_delete_value(
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        "OneDriveSetup",
    );
    xos_sys::reg_delete_value(
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "OneDrive",
    );
    xos_sys::reg_delete_value(
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "OneDriveSetup",
    );

    stop_onedrive_processes();
    xos_sys::kill_process("explorer.exe");
    std::thread::sleep(Duration::from_millis(1000));
    let _ = xos_sys::shell_start("explorer.exe", "");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uninstall_command_splits_quoted_and_bare() {
        assert_eq!(
            split_uninstall_command("\"C:\\X\\OneDriveSetup.exe\" /uninstall /allusers"),
            Some((
                "C:\\X\\OneDriveSetup.exe".to_string(),
                "/uninstall /allusers".to_string()
            ))
        );
        assert_eq!(
            split_uninstall_command("C:\\X\\OneDriveSetup.EXE /uninstall"),
            Some((
                "C:\\X\\OneDriveSetup.EXE".to_string(),
                "/uninstall".to_string()
            ))
        );
        assert_eq!(
            split_uninstall_command("C:\\X\\OneDriveSetup.exe"),
            Some(("C:\\X\\OneDriveSetup.exe".to_string(), String::new()))
        );
        assert_eq!(split_uninstall_command("\"C:\\X\\OneDriveSetup.exe"), None);
    }
}

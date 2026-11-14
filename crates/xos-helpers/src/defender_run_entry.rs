use std::io;
use std::path::Path;

use crate::regutil::{self, hklm, io_message, open_opt, read_value, Data, Kind};

pub const RUN_PATH: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
pub const BACKUP_PATH: &str = r"SOFTWARE\XOSToolkit\DefenderRunBackup";
pub const VALUE_NAME: &str = "WindowsDefender";

pub fn tray_executable() -> Option<String> {
    let mut root = std::env::var("ProgramW6432").unwrap_or_default();
    if root.is_empty() {
        root = std::env::var("ProgramFiles").unwrap_or_default();
    }
    if root.is_empty() {
        None
    } else {
        Some(
            Path::new(&root)
                .join("Windows Defender")
                .join("MSASCuiL.exe")
                .to_string_lossy()
                .into_owned(),
        )
    }
}

fn matches_stored(key: &winreg::RegKey, kind: Kind, data: &str) -> io::Result<bool> {
    Ok(matches!(
        read_value(key, VALUE_NAME, false)?,
        Some(v) if v.kind == kind && v.as_str() == Some(data)
    ))
}

pub fn backup(run_path: &str, backup_path: &str) -> (bool, String) {
    let attempt = || -> io::Result<(bool, String)> {
        let run = match open_opt(&hklm(), run_path, false)? {
            Some(k) => k,
            None => {
                return Ok((
                    true,
                    format!("Run\\{VALUE_NAME} is not present, nothing to record"),
                ))
            }
        };
        let current = match read_value(&run, VALUE_NAME, false)? {
            Some(v) => v,
            None => {
                return Ok((
                    true,
                    format!("Run\\{VALUE_NAME} is not present, nothing to record"),
                ))
            }
        };
        if let Some(existing) = open_opt(&hklm(), backup_path, false)? {
            if read_value(&existing, VALUE_NAME, false)?.is_some() {
                return Ok((
                    true,
                    format!("Run\\{VALUE_NAME} backup already exists, kept"),
                ));
            }
        }
        let kind = current.kind;
        if !kind.is_string() {
            return Ok((
                false,
                format!("Run\\{VALUE_NAME} has kind {}, not recorded", kind.name()),
            ));
        }
        let data = current.as_str().unwrap_or_default().to_string();
        let (backup_key, _) = hklm().create_subkey(backup_path)?;
        regutil::set_value(&backup_key, VALUE_NAME, kind, &Data::Str(data.clone()))?;
        let ok = matches_stored(&backup_key, kind, &data)?;
        if !ok {
            regutil::delete_value_quiet(&backup_key, VALUE_NAME)?;
            return Ok((false, format!("Run\\{VALUE_NAME} backup did not verify")));
        }
        Ok((
            true,
            format!("Run\\{VALUE_NAME} recorded ({})", kind.name()),
        ))
    };
    match attempt() {
        Ok(r) => r,
        Err(e) => (
            false,
            format!("Run\\{VALUE_NAME} backup failed: {}", io_message(&e)),
        ),
    }
}

pub fn backup_default() -> (bool, String) {
    backup(RUN_PATH, BACKUP_PATH)
}

pub fn restore(run_path: &str, backup_path: &str, tray_exe: Option<&str>) -> (bool, String) {
    let attempt = || -> io::Result<(bool, String)> {
        let stored = match open_opt(&hklm(), backup_path, false)? {
            Some(b) => read_value(&b, VALUE_NAME, false)?,
            None => None,
        };
        let stored = match stored {
            Some(v) => v,
            None => return Ok((true, format!("no Run\\{VALUE_NAME} backup, left as it is"))),
        };
        let kind = stored.kind;
        let data = stored.as_str().map(str::to_string);
        let data = match data {
            Some(d) if kind.is_string() => d,
            _ => {
                return Ok((
                    false,
                    format!("Run\\{VALUE_NAME} backup is not a string value, left as it is"),
                ))
            }
        };
        let exe = match tray_exe {
            Some(e) => Some(e.to_string()),
            None => tray_executable(),
        };
        match exe {
            Some(e) if Path::new(&e).is_file() => {}
            _ => {
                return Ok((
                    true,
                    format!("MSASCuiL.exe is not present, Run\\{VALUE_NAME} not restored"),
                ))
            }
        }
        let detail;
        {
            let (run, _) = hklm().create_subkey(run_path)?;
            if read_value(&run, VALUE_NAME, false)?.is_some() {
                detail = format!("Run\\{VALUE_NAME} already present, kept");
            } else {
                regutil::set_value(&run, VALUE_NAME, kind, &Data::Str(data.clone()))?;
                if !matches_stored(&run, kind, &data)? {
                    return Ok((
                        false,
                        format!("Run\\{VALUE_NAME} did not verify after the restore"),
                    ));
                }
                detail = format!("Run\\{VALUE_NAME} restored ({})", kind.name());
            }
        }
        if let Some(backup_key) = open_opt(&hklm(), backup_path, true)? {
            regutil::delete_value_quiet(&backup_key, VALUE_NAME)?;
            let info = backup_key.query_info()?;
            if info.values == 0 && info.sub_keys == 0 {
                drop(backup_key);
                match hklm().delete_subkey(backup_path) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e),
                }
            }
        }
        Ok((true, detail))
    };
    match attempt() {
        Ok(r) => r,
        Err(e) => (
            false,
            format!("Run\\{VALUE_NAME} restore failed: {}", io_message(&e)),
        ),
    }
}

pub fn restore_default() -> (bool, String) {
    restore(RUN_PATH, BACKUP_PATH, None)
}

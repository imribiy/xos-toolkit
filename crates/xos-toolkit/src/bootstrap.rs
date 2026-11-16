use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::Duration;
use xos_core::log;

static RUNNING: AtomicBool = AtomicBool::new(false);
static DONE: (Mutex<bool>, Condvar) = (Mutex::new(true), Condvar::new());

fn common_app_data() -> PathBuf {
    std::env::var_os("ProgramData").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
}

fn marker() -> PathBuf {
    common_app_data().join("XOS Toolkit").join("State").join("chocolatey-bootstrap-complete")
}

fn utc_o() -> String {
    format_utc_o(chrono::Utc::now())
}

fn format_utc_o(t: chrono::DateTime<chrono::Utc>) -> String {
    format!("{}.{:07}Z", t.format("%Y-%m-%dT%H:%M:%S"), (t.timestamp_subsec_nanos() / 100).min(9_999_999))
}

fn has_previous_toolkit_logs() -> bool {
    let dirs = [
        common_app_data().join("XOS Toolkit").join("Logs"),
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from).unwrap_or_default().join("XOSToolkit").join("Logs"),
    ];
    dirs.iter().any(|d| {
        std::fs::read_dir(d)
            .map(|rd| {
                rd.flatten().any(|e| {
                    let n = e.file_name().to_string_lossy().to_lowercase();
                    n.starts_with("xos-toolkit-") && n.ends_with(".log")
                })
            })
            .unwrap_or(false)
    })
}

fn write_marker(reason: &str) {
    let m = marker();
    if let Some(d) = m.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let _ = std::fs::write(&m, format!("{reason} {}", utc_o()));
}

pub fn claim() -> bool {
    let m = marker();
    let crashed_first_launch = std::fs::metadata(&m).map(|x| x.len() == 0).unwrap_or(false);
    if m.exists() && !crashed_first_launch {
        return false;
    }
    if crashed_first_launch {
        if std::fs::remove_file(&m).is_err() {
            return false;
        }
    } else if has_previous_toolkit_logs() {
        write_marker("migrated");
        return false;
    }
    if let Some(d) = m.parent() {
        if std::fs::create_dir_all(d).is_err() {
            return false;
        }
    }
    match std::fs::OpenOptions::new().write(true).create_new(true).open(&m) {
        Ok(mut f) => f.write_all(format!("first-launch {}\r\n", utc_o()).as_bytes()).is_ok(),
        Err(_) => false,
    }
}

pub fn start(claimed: bool) {
    if claimed {
        log::log("Application startup complete. Running the first-launch Chocolatey check in the background.");
        *DONE.0.lock().unwrap() = false;
        RUNNING.store(true, Ordering::SeqCst);
        xos_page_apps::mark_choco_bootstrap_running();
        std::thread::spawn(|| {
            let _ = std::panic::catch_unwind(xos_page_apps::ensure_chocolatey);
            RUNNING.store(false, Ordering::SeqCst);
            *DONE.0.lock().unwrap() = true;
            DONE.1.notify_all();
        });
    } else {
        log::log("Application startup complete. Chocolatey automatic installation was already handled.");
    }
}

pub fn running() -> bool {
    RUNNING.load(Ordering::SeqCst)
}

pub fn wait(timeout: Duration) {
    let guard = DONE.0.lock().unwrap();
    let _ = DONE.1.wait_timeout_while(guard, timeout, |done| !*done);
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn utc_o_has_seven_fraction_digits() {
        let t = chrono::Utc.with_ymd_and_hms(2026, 11, 15, 16, 1, 10).unwrap() + chrono::Duration::nanoseconds(123_456_789);
        assert_eq!(format_utc_o(t), "2026-11-15T16:01:10.1234567Z");
        assert_eq!(utc_o().len(), 28);
    }
}

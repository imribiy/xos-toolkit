use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use xos_core::log;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

static BOOTSTRAP_RUNNING: AtomicBool = AtomicBool::new(false);

pub fn is_choco_bootstrap_running() -> bool {
    BOOTSTRAP_RUNNING.load(Ordering::SeqCst)
}

pub fn mark_choco_bootstrap_running() {
    BOOTSTRAP_RUNNING.store(true, Ordering::SeqCst);
}

struct RunningFlag;

impl RunningFlag {
    fn set() -> Self {
        BOOTSTRAP_RUNNING.store(true, Ordering::SeqCst);
        RunningFlag
    }
}

impl Drop for RunningFlag {
    fn drop(&mut self) {
        BOOTSTRAP_RUNNING.store(false, Ordering::SeqCst);
    }
}

fn bundled_msi() -> String {
    let dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_default();
    dir.join("Bundled")
        .join("chocolatey-2.7.1.0.msi")
        .to_string_lossy()
        .to_string()
}

fn run_msi_install(msi: &str) {
    let mut cmd = Command::new("msiexec.exe");
    cmd.raw_arg(format!("/i \"{msi}\" /qn /norestart"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW);
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            log::exception("Bundled Chocolatey MSI failed", &e.to_string());
            return;
        }
    };
    let deadline = Instant::now() + Duration::from_millis(300000);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                log::log(&format!(
                    "[CHOCO] Bundled MSI exit code: {}",
                    status.code().unwrap_or(-1)
                ));
                return;
            }
            Ok(None) => {}
            Err(e) => {
                log::exception("Bundled Chocolatey MSI failed", &e.to_string());
                return;
            }
        }
        if Instant::now() >= deadline {
            log::log("[CHOCO] Bundled MSI timed out after 300 seconds.");
            xos_sys::terminate_process_tree(&mut child);
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

pub fn ensure_chocolatey() -> bool {
    let _flag = RunningFlag::set();
    if xos_sys::is_choco_installed() {
        log::log("[CHOCO] Existing installation detected.");
        return true;
    }

    let msi = bundled_msi();
    let msi_exists = std::path::Path::new(&msi).is_file();
    let mut installed;
    {
        let _guard = xos_sys::enter_chocolatey_operation();
        installed = xos_sys::is_choco_installed();
        if !installed {
            let started = Instant::now();
            log::log("[CHOCO] Automatic installation started.");

            if msi_exists {
                log::log(&format!("[CHOCO] Installing bundled MSI: {msi}"));
                run_msi_install(&msi);
                installed = xos_sys::is_choco_installed();
                log::log(&format!(
                    "[CHOCO] Bundled MSI result after {} ms: {}",
                    started.elapsed().as_millis(),
                    if installed {
                        "installed"
                    } else {
                        "not detected"
                    }
                ));
            } else {
                log::log(&format!("[CHOCO] Bundled MSI not found: {msi}"));
            }

            if !installed {
                log::log(
                    "[CHOCO] Bundled MSI did not install; clearing leftover state first. A first launch can spend minutes here.",
                );
                xos_sys::remove_chocolatey();
                log::log(&format!(
                    "[CHOCO] Cleanup finished after {} ms.",
                    started.elapsed().as_millis()
                ));

                if msi_exists {
                    log::log(&format!("[CHOCO] Installing bundled MSI again: {msi}"));
                    run_msi_install(&msi);
                    installed = xos_sys::is_choco_installed();
                    log::log(&format!(
                        "[CHOCO] Second bundled MSI result: {}",
                        if installed {
                            "installed"
                        } else {
                            "not detected"
                        }
                    ));
                }

                if !installed {
                    log::log("[CHOCO] Trying the web bootstrap fallback.");
                    installed = xos_sys::install_choco_while_locked();
                }
            }

            log::log(&format!(
                "[CHOCO] Automatic installation finished after {} ms: {}",
                started.elapsed().as_millis(),
                if installed { "success" } else { "failed" }
            ));
        }
    }

    log::log(&format!(
        "[CHOCO] Automatic installation finished: {}",
        if installed { "success" } else { "failed" }
    ));
    installed
}

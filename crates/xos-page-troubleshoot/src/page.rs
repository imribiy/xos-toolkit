use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use xos_core::host::{Buttons, FileFilter, Host, Icon, Page};
use xos_core::ui::*;
use xos_core::{app_state, catalog, detect, log};
use xos_uninstall as u;

use crate::diag;
use crate::uninstall;

const TITLE: &str = "XOS Toolkit";
const SHELL_FOLDERS: &str =
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders";

const BUSY_SUB_DEFAULT: &str = "Please do not close the toolkit or turn off your PC.";
const BUSY_SUB_DIAG: &str = "This can take a minute while Windows event logs are exported.";
const BUSY_SUB_CHOCO: &str =
    "The diagnostic bundle will be created after the background installation finishes.";
const BUSY_SUB_RESTART: &str = "You can close this message; the restart will continue on its own.";

static BUSY: Mutex<(Option<String>, &'static str)> = Mutex::new((None, BUSY_SUB_DEFAULT));

fn busy_text() -> Option<String> {
    let busy = BUSY.lock().unwrap();
    busy.0.as_ref().map(|t| {
        format!(
            "{t}

{}",
            busy.1
        )
    })
}

fn put_busy(text: Option<String>, sub_text: &'static str) {
    *BUSY.lock().unwrap() = (text, sub_text);
}

fn put_busy_text(text: String) {
    BUSY.lock().unwrap().0 = Some(text);
}

pub struct TroubleshootPage {
    is_xos: bool,
}

impl Default for TroubleshootPage {
    fn default() -> Self {
        Self::new()
    }
}

fn tracker_failed() -> bool {
    xos_sys::ops::any_failed() || u::any_action_command_failed()
}

fn reset_trackers() {
    xos_sys::ops::reset();
    u::reset_action_command_tracker();
}

pub fn shell_folder_entries() -> [(&'static str, &'static str); 10] {
    [
        ("Desktop", "%USERPROFILE%\\Desktop"),
        ("Favorites", "%USERPROFILE%\\Favorites"),
        ("My Music", "%USERPROFILE%\\Music"),
        ("My Video", "%USERPROFILE%\\Videos"),
        ("Personal", "%USERPROFILE%\\Documents"),
        (
            "{F42EE2D3-909F-4907-8871-4C22FC0BF756}",
            "%USERPROFILE%\\Documents",
        ),
        ("My Pictures", "%USERPROFILE%\\Pictures"),
        (
            "{0DDD015D-B06C-45D5-8C4C-F59713854639}",
            "%USERPROFILE%\\Pictures",
        ),
        (
            "{374DE290-123F-4565-9164-39C4925E467B}",
            "%USERPROFILE%\\Downloads",
        ),
        (
            "{B7BEDE81-DF94-4682-A7D8-57A52620B86F}",
            "%USERPROFILE%\\Pictures\\Screenshots",
        ),
    ]
}

fn profile_folder() -> String {
    use windows::Win32::UI::Shell::{FOLDERID_Profile, SHGetKnownFolderPath, KF_FLAG_DEFAULT};
    unsafe {
        if let Ok(p) = SHGetKnownFolderPath(&FOLDERID_Profile, KF_FLAG_DEFAULT, None) {
            let s = p.to_string().unwrap_or_default();
            windows::Win32::System::Com::CoTaskMemFree(Some(p.0 as *const _));
            if !s.is_empty() {
                return s;
            }
        }
    }
    std::env::var("USERPROFILE").unwrap_or_default()
}

fn card(id: &str, title: &str, description: &str, button: Control) -> Card {
    Card::new(id, title, description)
        .not_searchable()
        .actions(vec![button])
}

impl TroubleshootPage {
    pub fn new() -> Self {
        Self {
            is_xos: detect::is_xos(),
        }
    }

    fn set_busy(&self, host: &dyn Host, text: Option<&str>) {
        self.set_busy_sub(host, text, BUSY_SUB_DEFAULT);
    }

    fn set_busy_sub(&self, host: &dyn Host, text: Option<&str>, sub_text: &'static str) {
        put_busy(text.map(|t| t.to_string()), sub_text);
        host.publish(self.model());
    }

    fn done(&self, host: &dyn Host, msg: &str) {
        let failed = tracker_failed();
        log::action_done("Troubleshoot", false, failed, None);
        xos_sys::ops::reset();
        app_state::require_reboot_if_message_asks(msg);
        u::reset_action_command_tracker();
        host.set_status(msg);
        let mut text = msg.to_string();
        if failed {
            text.push_str(
                "\n\nNote: one or more settings could not be written (often a permissions issue). Try again.",
            );
        }
        host.dialog(
            &text,
            TITLE,
            Buttons::Ok,
            if failed {
                Icon::Warning
            } else {
                Icon::Information
            },
        );
    }

    fn export_logs(&self, host: &dyn Host) {
        let default_name = format!(
            "XOS-Diagnostics-{}.zip",
            chrono::Local::now().format("%Y-%m-%d_%H-%M-%S")
        );
        let Some(path) = host.save_file(
            "Export XOS Diagnostic Bundle",
            &[FileFilter::new("ZIP archive", &["zip"])],
            &default_name,
            diag::desktop_directory(),
        ) else {
            return;
        };
        let path_text = path.to_string_lossy().to_string();

        self.set_busy_sub(host, Some("Collecting diagnostic logs..."), BUSY_SUB_DIAG);
        host.set_status("Collecting diagnostic logs...");
        log::log(&format!("[DIAGNOSTICS] Export started: {path_text}"));

        if xos_page_apps::is_choco_bootstrap_running() {
            self.set_busy_sub(
                host,
                Some("Finishing Chocolatey installation..."),
                BUSY_SUB_CHOCO,
            );
            log::log("[DIAGNOSTICS] Waiting for the background Chocolatey installation before collecting logs.");
            let started = Instant::now();
            while xos_page_apps::is_choco_bootstrap_running()
                && started.elapsed() < Duration::from_secs(120)
            {
                std::thread::sleep(Duration::from_millis(250));
            }
            if !xos_page_apps::is_choco_bootstrap_running() {
                log::log(&format!(
                    "[DIAGNOSTICS] Background Chocolatey installation completed: {}",
                    if xos_sys::is_choco_installed() {
                        "success"
                    } else {
                        "failed"
                    }
                ));
            } else {
                log::log("[DIAGNOSTICS] Background Chocolatey installation did not finish within two minutes; collecting the current logs.");
            }
        }
        self.set_busy_sub(host, Some("Collecting diagnostic logs..."), BUSY_SUB_DIAG);
        let result = std::panic::catch_unwind(|| diag::create_diagnostic_bundle(&path))
            .unwrap_or_else(|payload| {
                Err(std::io::Error::other(uninstall::panic_text(
                    payload.as_ref(),
                )))
            });
        match result {
            Ok(()) => {
                log::log(&format!("[DIAGNOSTICS] Export completed: {path_text}"));
                host.set_status("Diagnostic bundle exported.");
                host.info(
                    &format!("Diagnostic bundle saved to:\n\n{path_text}"),
                    TITLE,
                );
            }
            Err(e) => {
                log::exception("Diagnostic bundle export failed", &e.to_string());
                host.set_status("Diagnostic export failed.");
                host.error(
                    &format!("Could not create the diagnostic bundle.\n\n{e}"),
                    TITLE,
                );
            }
        }
        self.set_busy(host, None);
    }

    fn restore_shell(&self, host: &dyn Host) {
        let user_profile = profile_folder();
        reset_trackers();
        xos_sys::kill_process("explorer.exe");
        let mut restored = false;
        let attempt = (|| -> std::io::Result<()> {
            for sub in [
                "Desktop",
                "Documents",
                "Pictures",
                "Music",
                "Videos",
                "Favorites",
                "Downloads",
                r"Pictures\Screenshots",
            ] {
                let path = u::path_combine(&user_profile, sub);
                if !Path::new(&path).is_dir() {
                    std::fs::create_dir_all(&path)?;
                }
            }
            for (name, data) in shell_folder_entries() {
                u::uninstall_reg_set_exp(SHELL_FOLDERS, name, data);
            }
            Ok(())
        })();
        match attempt {
            Ok(()) => restored = true,
            Err(e) => {
                reset_trackers();
                host.set_status("Shell folder restore failed.");
                host.error(
                    &format!("Shell folders could not be restored.\n\n{e}"),
                    TITLE,
                );
            }
        }
        let explorer_started = xos_sys::shell_start("explorer.exe", "");
        u::record_action_command(explorer_started);
        if restored {
            self.done(host, "Shell folders restored to defaults.");
        } else {
            reset_trackers();
        }
    }

    fn restore_win_services(&self, host: &dyn Host) {
        if !host.confirm(
            "This will apply the documented XOS Toolkit enable/default values for managed services, features, scheduled tasks, and devices. It does not use an install-time service backup.\n\nWindows Defender is brought back first, through its own workflow, so the service values it writes afterwards match a working Defender rather than leaving it half enabled.\n\nThis may take a few minutes. A reboot is required afterwards. Continue?",
            "Restore Windows Defaults",
            Icon::Warning,
        ) {
            return;
        }

        self.set_busy(host, Some("Restoring Windows defaults..."));
        reset_trackers();
        let outcome = (|| -> Result<(), String> {
            host.set_status("Restoring Windows Defender first...");
            let defender_ok = xos_page_system::defender::set_enabled(
                host,
                true,
                xos_page_system::DefenderOptions::default(),
            )
            .ok;
            u::record_action_command(defender_ok);

            let update_ok = xos_page_update::undo_hard_disable().map_err(|e| e.to_string())?;
            u::record_action_command(update_ok);
            let mut ok = xos_page_network::restore_windows_default_service_start_types(None);
            u::record_action_command(ok);
            ok &= update_ok;
            let components_ok = restore_all_features_tasks_and_devices(host);
            u::record_action_command(components_ok);
            app_state::require_reboot();

            let everything_ok = defender_ok && ok && components_ok;
            self.done(
                host,
                if everything_ok {
                    "Windows defaults restored (Defender, services, features, tasks, devices). Please reboot."
                } else {
                    "Windows defaults were only partially restored. Check the operation log."
                },
            );

            if !defender_ok {
                host.warn(
                    "Windows Defender was not restored before the service values were written.\n\nOpen the System page, turn Defender on from there, and run this again so the two match. Until then Defender may be enabled without working properly.",
                    TITLE,
                );
            }
            Ok(())
        })();
        if let Err(message) = outcome {
            host.set_status("Windows default restore failed.");
            host.error(
                &format!("Windows defaults could not be fully restored.\n\n{message}"),
                TITLE,
            );
        }
        reset_trackers();
        self.set_busy(host, None);
    }

    fn restore_xos_services(&self, host: &dyn Host) {
        if !host.confirm(
            "This applies stock Windows service values, then disables every service XOS turns off. It does not change Windows Defender either way: if Defender is on, it stays on.\n\nA reboot is required afterwards. Continue?",
            "Apply XOS Defaults",
            Icon::Warning,
        ) {
            return;
        }

        self.set_busy(host, Some("Applying XOS default services..."));
        reset_trackers();
        let sink = |msg: &str| log::log(msg);
        let windows_ok = xos_page_network::restore_windows_default_service_start_types(Some(&sink));
        let xos_ok = xos_page_network::apply_xos_service_disables(Some(&sink));
        u::record_action_command(windows_ok && xos_ok);

        let defender_already_off = is_defender_disabled();
        log::log(if defender_already_off {
            "[XOSDefaults] Defender is already disabled; the XOS state is applied as is."
        } else {
            "[XOSDefaults] Defender is enabled and was left untouched, as XOS Defaults does not change it."
        });

        app_state::require_reboot();
        self.done(host, "XOS default services applied. Please reboot.");
        reset_trackers();
        self.set_busy(host, None);
    }

    fn reboot_bios(&self, host: &dyn Host) {
        if !host.confirm(
            "This will immediately restart your PC into BIOS/UEFI settings.\n\nProceed?",
            "Reboot to BIOS",
            Icon::Warning,
        ) {
            return;
        }
        for args in ["/r /fw /t 0", "-r -fw -t 0", "/r /fw /t 5"] {
            if xos_sys::run_cmd("shutdown.exe", args) {
                log::log(&format!(
                    "[RebootBios] Firmware restart scheduled with: shutdown.exe {args}"
                ));
                return;
            }
            log::log(&format!("[RebootBios] Refused: shutdown.exe {args}"));
        }
        host.dialog(
            if is_uefi_boot() {
                "Windows refused the firmware restart. Run shutdown /r /fw /t 0 from an elevated Command Prompt and check the message it prints."
            } else {
                "This PC appears to boot from legacy BIOS rather than UEFI, so there is no UEFI settings screen to restart into.\n\nRestart the PC and press the BIOS setup key during power on instead."
            },
            "Reboot to BIOS",
            Buttons::Ok,
            Icon::Warning,
        );
    }

    fn fix_time_sync(&self, host: &dyn Host) {
        host.set_status("Fixing Windows Time sync...");
        reset_trackers();
        let mut required = xos_sys::run_cmd("sc.exe", "config w32time start= demand");
        xos_sys::run_cmd("net.exe", "stop w32time");
        xos_sys::run_cmd("w32tm.exe", "/unregister");
        required &= xos_sys::run_cmd("w32tm.exe", "/register");
        required &= xos_sys::run_cmd("net.exe", "start w32time");
        let configured = xos_sys::run_cmd(
            "w32tm.exe",
            "/config /manualpeerlist:\"time.windows.com,0x9 pool.ntp.org,0x9 time.nist.gov,0x9\" /syncfromflags:manual /reliable:no /update",
        );
        xos_sys::run_cmd("net.exe", "stop w32time");
        required &= xos_sys::run_cmd("net.exe", "start w32time");
        let synced = xos_sys::run_cmd("w32tm.exe", "/resync /rediscover");
        let ok = required && configured && synced;

        u::record_action_command(ok);
        if ok {
            self.done(host, "Windows Time service re-registered and resynced.");
        } else {
            reset_trackers();
            host.set_status("Windows Time repair was incomplete.");
            host.warn(
                "Windows Time was repaired, but the first synchronization attempt failed. Check your internet connection and try Sync now in Windows Settings.",
                TITLE,
            );
        }
    }

    fn remove_choco(&self, host: &dyn Host) {
        if !host.confirm(
            "This removes Chocolatey and all of its leftovers: the install folder, environment variables, PATH entries, and the bundled installer registration.\n\nApplications already installed through Chocolatey are not automatically uninstalled, but their package records and command shims are removed. The Toolkit will not reinstall Chocolatey automatically.\n\nContinue?",
            "Remove Chocolatey",
            Icon::Warning,
        ) {
            return;
        }
        self.set_busy(host, Some("Removing Chocolatey and clearing leftovers..."));
        reset_trackers();
        xos_sys::remove_chocolatey();
        if xos_sys::is_choco_installed() {
            reset_trackers();
            host.set_status("Chocolatey removal failed.");
            host.error(
                "Chocolatey could not be removed.\n\nChocolatey is still present after cleanup.",
                TITLE,
            );
        } else {
            self.done(
                host,
                "Chocolatey and its leftovers have been removed. You can install it again from the Apps page if needed.",
            );
        }
        self.set_busy(host, None);
    }

    fn uninstall_xos(&self, host: &dyn Host) {
        if !host.confirm(
            "This will revert all XOS Playbook changes to stock Windows defaults.\n\nBefore you continue, save any work you have open and close all running applications. Once started, the process should not be interrupted, and your PC will restart automatically when it finishes.\n\nRegistry tweaks, services, scheduled tasks, UAC, kernel settings, telemetry, and more will all be restored.\n\nContinue?",
            "Uninstall XOS",
            Icon::Warning,
        ) {
            return;
        }

        let log_path = u::begin_uninstall_log();
        self.set_busy(host, Some("Uninstalling XOS, please wait..."));
        reset_trackers();
        u::set_uninstall_phase_callback(Some(Box::new(|text: &str| {
            put_busy_text(text.to_string())
        })));

        let stop = AtomicBool::new(false);
        let outcome = std::thread::scope(|s| {
            s.spawn(|| {
                let mut last = busy_text();
                while !stop.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(200));
                    let now = busy_text();
                    if now != last {
                        host.publish(self.model());
                        last = now;
                    }
                }
            });
            let result = std::panic::catch_unwind(uninstall::run_body);
            stop.store(true, Ordering::SeqCst);
            result
        });
        u::set_uninstall_phase_callback(None);

        let compatibility_restored = match outcome {
            Ok(v) => v,
            Err(payload) => {
                let message = uninstall::panic_text(payload.as_ref());
                u::uninstall_log(&format!("!!! UNHANDLED EXCEPTION: panic: {message}"));
                self.set_busy(host, None);
                reset_trackers();
                let mut msg = format!(
                    "The uninstall did not complete and your PC was NOT restarted.\n\n{message}"
                );
                if let Some(p) = &log_path {
                    msg.push_str(&format!("\n\nLog saved to:\n{p}"));
                }
                host.dialog(&msg, "Uninstall XOS", Buttons::Ok, Icon::Error);
                return;
            }
        };

        let restart_scheduled = xos_sys::run_cmd("shutdown.exe", "/r /t 10");

        let failed = !compatibility_restored || tracker_failed();
        reset_trackers();
        if !restart_scheduled {
            app_state::require_reboot();
            self.set_busy(host, None);
            let mut restart_message = "XOS was uninstalled, but Windows rejected the automatic restart request. Please restart the PC manually before using it.".to_string();
            if failed {
                restart_message.push_str("\n\nCompatibility verification reported a restore warning. Check the uninstall log before continuing.");
            }
            if let Some(p) = &log_path {
                restart_message.push_str(&format!("\n\nLog saved to:\n{p}"));
            }
            host.set_status(if failed {
                "XOS uninstalled with restore warnings. Please reboot manually."
            } else {
                "XOS uninstalled. Please reboot manually."
            });
            host.dialog(
                &restart_message,
                "Uninstall XOS",
                Buttons::Ok,
                Icon::Warning,
            );
            return;
        }

        let mut done_msg =
            "XOS has been uninstalled. Your PC will restart automatically in 10 seconds."
                .to_string();
        if failed {
            done_msg = "XOS uninstall finished, but compatibility verification reported a restore warning. Check the uninstall log. Your PC will restart automatically in 10 seconds.".to_string();
        }
        if let Some(p) = &log_path {
            done_msg.push_str(&format!("\n\nLog saved to:\n{p}"));
        }
        self.set_busy_sub(host, Some(&done_msg), BUSY_SUB_RESTART);
        host.set_status(if failed {
            "XOS uninstalled with restore warnings. Restarting..."
        } else {
            "XOS uninstalled. Restarting..."
        });
    }
}

fn is_defender_disabled() -> bool {
    let start = xos_sys::get_service_start_type("WinDefend");
    let policy = xos_sys::reg_get_dword(
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender",
        "DisableAntiSpyware",
    );
    start == 4 && policy == Some(1)
}

fn is_uefi_boot() -> bool {
    if xos_sys::reg_key_exists(r"HKLM\SYSTEM\CurrentControlSet\Control\SystemPartition") {
        return true;
    }
    xos_sys::reg_get_dword(r"HKLM\SYSTEM\CurrentControlSet\Control", "PEFirmwareType") == Some(2)
}

fn job<T>(work: impl FnOnce() -> T) -> (T, bool) {
    xos_sys::ops::reset();
    let result = work();
    (result, xos_sys::ops::any_failed())
}

fn restore_all_features_tasks_and_devices(host: &dyn Host) -> bool {
    host.set_status("Restoring features, tasks, and devices...");
    std::thread::scope(|s| {
        let mut all_tasks: Vec<String> =
            catalog::PRINT_TASKS.iter().map(|t| t.to_string()).collect();
        all_tasks.extend(catalog::WIFI_TASKS.iter().map(|t| t.to_string()));
        all_tasks.push(catalog::BLUETOOTH_UNINSTALL_TASK.to_string());
        let tasks_job = s.spawn(move || job(|| xos_sys::enable_tasks_batch(&all_tasks)));

        let devices_job = s.spawn(|| {
            job(|| {
                let mut ok = true;
                for device in catalog::HYPER_V_DEVICES {
                    let device_key = format!(r"HKLM\SYSTEM\CurrentControlSet\Enum\{device}");
                    if xos_sys::reg_key_exists(&device_key) {
                        ok &= xos_sys::enable_device(device, true);
                    }
                }
                ok
            })
        });

        let states = xos_sys::get_all_feature_states();
        let mut features_ok = !states.is_empty();

        for f in catalog::PRINT_FEATURES
            .iter()
            .chain(catalog::HYPER_V_FEATURES.iter())
        {
            if let Some(st) = states.get(f) {
                if !xos_sys::is_feature_state_enabled(st) {
                    features_ok &= xos_sys::enable_feature(f) || u::skip_absent_feature(f);
                }
            }
        }

        let collect = |h: std::thread::ScopedJoinHandle<'_, (bool, bool)>| match h.join() {
            Ok((result, failed)) => {
                if failed {
                    xos_sys::ops::track(false);
                }
                result
            }
            Err(payload) => std::panic::resume_unwind(payload),
        };
        let tasks_ok = collect(tasks_job);
        let devices_ok = collect(devices_job);
        features_ok && tasks_ok && devices_ok
    })
}

impl Page for TroubleshootPage {
    fn id(&self) -> &'static str {
        "Troubleshoot"
    }

    fn label(&self) -> &'static str {
        "Troubleshooting"
    }

    fn model(&self) -> PageModel {
        PageModel::new(
            "Troubleshoot",
            "Troubleshooting",
            "Fixes, resets, and advanced configuration",
        )
        .max_width(1080.0)
        .overlay(busy_text())
        .card(card(
            "network",
            "Network Reset (Low Internet Speed Fix)",
            "Sets the network adapter settings XOS changed back to their driver defaults, then resets Windows networking: DNS cache, TCP/IP, Winsock and firewall rules. Custom firewall rules are removed. Try this if your internet is slow or not working. The PC restarts automatically.",
            Control::button("network_reset", "Reset Network & Reboot", BtnStyle::Warning),
        ))
        .card(card(
            "shell",
            "Restore Shell Folders",
            "Fixes 'Location is not available' errors by pointing Desktop, Documents, Downloads, Pictures, Music, Videos and Screenshots back to their default folders.",
            Control::button("restore_shell", "Restore Shell Folders", BtnStyle::Action),
        ))
        .card(card(
            "time",
            "Fix Windows Time Sync",
            "Repairs the Windows Time service and syncs your clock with internet time servers. Use this if your clock is wrong or will not update.",
            Control::button("fix_time", "Fix Time Sync", BtnStyle::Action),
        ))
        .card(card(
            "choco",
            "Remove Chocolatey",
            "Removes Chocolatey and everything it left behind, even if it looks uninstalled already. Apps you installed with it stay installed. The Toolkit will not reinstall Chocolatey on its own.",
            Control::button("remove_choco", "Remove Chocolatey", BtnStyle::Warning),
        ))
        .card(card(
            "diag",
            "Export Diagnostic Bundle",
            "Creates one ZIP with XOS and AME Wizard logs, crash reports and Windows event logs. Send it when you report a problem.",
            Control::button("export", "Export Diagnostic Bundle", BtnStyle::Action),
        ))
        .card(
            Card::new(
                "services",
                "Restore Service Defaults",
                "Windows Defaults turns Windows Defender back on and returns the services, features, tasks and devices XOS changed to their Windows settings. XOS Defaults puts services back the way XOS sets them and does not touch Windows Defender. Both require a restart.",
            )
            .not_searchable()
            .actions(vec![
                Control::button("win_defaults", "Windows Defaults", BtnStyle::Action),
                Control::button("xos_defaults", "XOS Defaults", BtnStyle::Enable),
            ]),
        )
        .card(card(
            "bios",
            "Reboot to BIOS / UEFI",
            "Restarts the PC right away into your BIOS/UEFI settings. Save your work first.",
            Control::button("reboot_bios", "Reboot to BIOS Now", BtnStyle::Warning),
        ))
        .card(
            card(
                "uninstall",
                "Uninstall XOS",
                "Turns the settings XOS changed back to Windows defaults: registry tweaks, services, scheduled tasks, UAC, telemetry and more. Apps XOS removed are not reinstalled. Requires a restart.",
                Control::button("uninstall", "Uninstall XOS", BtnStyle::Warning),
            )
            .visible(self.is_xos),
        )
    }

    fn handle(&self, host: &dyn Host, event: &Event) {
        if event.kind != EventKind::Click {
            return;
        }
        match event.control.as_str() {
            "network_reset" => xos_page_network::network_reset_action::run(host, "Troubleshoot"),
            "restore_shell" => self.restore_shell(host),
            "fix_time" => self.fix_time_sync(host),
            "remove_choco" => self.remove_choco(host),
            "export" => self.export_logs(host),
            "win_defaults" => self.restore_win_services(host),
            "xos_defaults" => self.restore_xos_services(host),
            "reboot_bios" => self.reboot_bios(host),
            "uninstall" => self.uninstall_xos(host),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_has_all_cards() {
        let page = TroubleshootPage::new();
        let model = page.model();
        assert_eq!(model.id, "Troubleshoot");
        assert_eq!(model.cards.len(), 8);
        assert_eq!(page.label(), "Troubleshooting");
        let ids: Vec<&str> = model.cards.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "network",
                "shell",
                "time",
                "choco",
                "diag",
                "services",
                "bios",
                "uninstall"
            ]
        );
    }

    #[test]
    fn shell_folder_table() {
        let entries = shell_folder_entries();
        assert_eq!(entries.len(), 10);
        assert_eq!(entries[0], ("Desktop", "%USERPROFILE%\\Desktop"));
        assert_eq!(entries[9].1, "%USERPROFILE%\\Pictures\\Screenshots");
    }
}

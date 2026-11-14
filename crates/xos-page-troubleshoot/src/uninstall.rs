use std::path::Path;

use windows::core::PCWSTR;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Threading::{OpenEventW, SetEvent, EVENT_MODIFY_STATE};
use winreg::enums::{HKEY_CURRENT_USER, KEY_READ};
use winreg::RegKey;
use xos_uninstall as u;

use crate::procs;
use crate::regval::{self, RegData};

const NT_CURRENT_VERSION: &str = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion";

const REREGISTER_SCRIPT: &str = concat!("$ErrorActionPreference='Continue';", "$manifests=@();", "$manifests+=Get-ChildItem \"$env:windir\\SystemApps\\*StartMenuExperienceHost*\\AppxManifest.xml\" -File -EA SilentlyContinue;", "Get-AppxPackage -AllUsers | Where-Object { $_.Name -like '*StartMenuExperienceHost*' } | ForEach-Object { ", "$p=Join-Path $_.InstallLocation 'AppxManifest.xml'; if (Test-Path $p) { $manifests += Get-Item $p } };", "$ok=0;", "foreach ($manifest in ($manifests | Sort-Object FullName -Unique)) { ", "try { Add-AppxPackage -Register $manifest.FullName -DisableDevelopmentMode -EA Stop; $ok++ } catch { } };", "if ($ok -eq 0) { exit 1 }");

fn log(message: &str) {
    u::uninstall_log(message);
}

fn del(key: &str, value: &str) {
    u::uninstall_reg_del(key, value);
}

fn set(key: &str, value: &str, data: i32) {
    u::uninstall_reg_set(key, value, data);
}

fn delkey(key: &str) {
    u::uninstall_reg_del_key(key);
}

fn rec(ok: bool) -> bool {
    u::record_action_command(ok)
}

fn tf(value: bool) -> &'static str {
    if value {
        "True"
    } else {
        "False"
    }
}

fn opt(value: Option<i32>) -> String {
    value.map(|v| v.to_string()).unwrap_or_default()
}

fn tasks_best_effort(list: &[&str]) -> bool {
    xos_sys::enable_tasks_batch_best_effort(&u::without_stock_disabled_tasks(list))
}

pub fn panic_text(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unexpected failure".to_string()
    }
}

fn job<T>(work: impl FnOnce() -> T) -> (T, bool) {
    xos_sys::ops::reset();
    let result = work();
    (result, xos_sys::ops::any_failed())
}

fn join(handle: std::thread::ScopedJoinHandle<'_, (bool, bool)>) -> bool {
    match handle.join() {
        Ok((result, failed)) => {
            if failed {
                xos_sys::ops::track(false);
            }
            result
        }
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

fn directory_contains_file(root: &str, name: &str) -> bool {
    let mut pending = vec![std::path::PathBuf::from(root)];
    while let Some(dir) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            match entry.file_type() {
                Ok(t) if t.is_dir() => pending.push(path),
                Ok(_) => {
                    if entry
                        .file_name()
                        .to_string_lossy()
                        .eq_ignore_ascii_case(name)
                    {
                        return true;
                    }
                }
                Err(_) => {}
            }
        }
    }
    false
}

fn account_info() -> (String, bool) {
    use windows::core::{BOOL, PWSTR};
    use windows::Win32::Foundation::{LocalFree, HANDLE, HLOCAL};
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows::Win32::Security::{
        CheckTokenMembership, CreateWellKnownSid, GetTokenInformation, TokenUser,
        WinBuiltinAdministratorsSid, PSID, TOKEN_QUERY, TOKEN_USER,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    let mut sid_text = String::new();
    let mut admin = false;
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_ok() {
            let mut needed = 0u32;
            let _ = GetTokenInformation(token, TokenUser, None, 0, &mut needed);
            if needed > 0 {
                let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
                if GetTokenInformation(
                    token,
                    TokenUser,
                    Some(buf.as_mut_ptr() as *mut _),
                    needed,
                    &mut needed,
                )
                .is_ok()
                {
                    let user = &*(buf.as_ptr() as *const TOKEN_USER);
                    let mut s = PWSTR::null();
                    if ConvertSidToStringSidW(user.User.Sid, &mut s).is_ok() {
                        sid_text = s.to_string().unwrap_or_default();
                        let _ = LocalFree(Some(HLOCAL(s.0 as *mut _)));
                    }
                }
            }
            let _ = CloseHandle(token);
        }
        let mut size = 0u32;
        let _ = CreateWellKnownSid(WinBuiltinAdministratorsSid, None, None, &mut size);
        if size > 0 {
            let mut buf = vec![0u8; size as usize];
            let sid = PSID(buf.as_mut_ptr() as *mut _);
            if CreateWellKnownSid(WinBuiltinAdministratorsSid, None, Some(sid), &mut size).is_ok() {
                let mut member = BOOL(0);
                if CheckTokenMembership(None, sid, &mut member).is_ok() {
                    admin = member.as_bool();
                }
            }
        }
    }
    (sid_text, admin)
}

fn signal_cpu_service_stop() -> bool {
    let name: Vec<u16> = "Global\\XOS_CpuService_Stop"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        match OpenEventW(EVENT_MODIFY_STATE, false, PCWSTR(name.as_ptr())) {
            Ok(handle) => {
                let _ = SetEvent(handle);
                let _ = CloseHandle(handle);
                true
            }
            Err(_) => false,
        }
    }
}

fn query(key: &str) {
    log(&format!("  [QUERY] {key}"));
    if u::is_hklm(key) {
        let (code, output) = xos_sys::run_as_ti_output("reg.exe", &format!("query \"{key}\""));
        if output.trim().is_empty() {
            log(&format!("    (key not found or empty, exit={code})"));
            return;
        }
        for line in output.split(['\r', '\n']).filter(|l| !l.is_empty()) {
            let t = line.trim();
            if !t.is_empty() {
                log(&format!("    {t}"));
            }
        }
    } else {
        let sub = match key.find('\\') {
            Some(i) => &key[i + 1..],
            None => key,
        };
        match RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(sub, KEY_READ) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => log("    (key not found)"),
            Err(e) => log(&format!("    ERROR: {e}")),
            Ok(rk) => {
                let values: Vec<(String, winreg::RegValue)> =
                    rk.enum_values().filter_map(|r| r.ok()).collect();
                if values.is_empty() {
                    log("    (key exists, no values)");
                    return;
                }
                for (name, raw) in values {
                    let text = match regval::decode(&raw) {
                        RegData::Dword(n) => n.to_string(),
                        RegData::Qword(n) => n.to_string(),
                        RegData::Text(s) | RegData::Expand(s) => s,
                        RegData::Multi(_) => "System.String[]".to_string(),
                        RegData::Binary(_) | RegData::Other(_) => "System.Byte[]".to_string(),
                    };
                    log(&format!(
                        "    {}  REG_{}  {}",
                        if name.is_empty() { "(Default)" } else { &name },
                        regval::kind_name(&raw.vtype).to_uppercase(),
                        text
                    ));
                }
            }
        }
    }
}

pub fn run_body() -> bool {
    std::thread::scope(|s| {
        log("=== Uninstall XOS started ===");
        let stale_marker = xos_helpers::stock_hardware_marker::invalidate_default();
        if let Some(marker) = stale_marker {
            log(&format!("  {marker}"));
        }
        log(&format!("Build: {}", xos_sys::get_windows_build_number()));
        let disp_ver = xos_sys::reg_get_string(NT_CURRENT_VERSION, "DisplayVersion")
            .unwrap_or_else(|| "?".to_string());
        let build_lab = xos_sys::reg_get_string(NT_CURRENT_VERSION, "BuildLabEx")
            .unwrap_or_else(|| "?".to_string());
        log(&format!(
            "DisplayVersion: {disp_ver}  BuildLabEx: {build_lab}"
        ));
        let (account_sid, is_admin) = account_info();
        log(&format!(
            "Account: {account_sid}  IsAdmin: {}",
            tf(is_admin)
        ));
        log("--- PRE-STATE: SEARCH ---");
        query(r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search");
        query(r"HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings");
        query(r"HKLM\SOFTWARE\Microsoft\Windows Search");
        query(r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search");
        query(r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer");
        log(&format!(
            "  WSearch Start:         {}",
            xos_sys::get_service_start_type("WSearch")
        ));
        log(&format!(
            "  WSearch Status:        {}",
            u::get_service_runtime_state("WSearch")
        ));
        log(&format!(
            "  WSearch DelayedAuto:   {}",
            opt(xos_sys::reg_get_dword(
                r"HKLM\SYSTEM\CurrentControlSet\Services\WSearch",
                "DelayedAutoStart"
            ))
        ));
        for exe in ["SearchApp.exe", "SearchUI.exe", "SearchHost.exe"] {
            let debugger = xos_sys::reg_get_string(
                &format!(
                    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{exe}"
                ),
                "Debugger",
            );
            log(&format!(
                "  IFEO {exe} Debugger: {}",
                debugger.unwrap_or_else(|| "(not set)".to_string())
            ));
        }
        let search_host_exe = u::path_combine(
            &u::windows_directory(),
            r"SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SearchHost.exe",
        );
        log(&format!(
            "  SearchHost.exe exists: {}",
            tf(Path::new(&search_host_exe).is_file())
        ));
        log(&format!(
            "  SearchHost.exe.bak exists: {}",
            tf(Path::new(&format!("{search_host_exe}.bak")).is_file())
        ));
        log("--- PRE-STATE ---");
        log(&format!(
            "  WinDefend Start: {}",
            xos_sys::get_service_start_type("WinDefend")
        ));
        log(&format!(
            "  TamperProtection: {}",
            opt(xos_sys::reg_get_dword(
                r"HKLM\SOFTWARE\Microsoft\Windows Defender\Features",
                "TamperProtection"
            ))
        ));
        log(&format!(
            "  DisableAntiSpyware (Policy): {}",
            opt(xos_sys::reg_get_dword(
                r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender",
                "DisableAntiSpyware"
            ))
        ));
        log(&format!(
            "  DisableRealtimeMonitoring: {}",
            opt(xos_sys::reg_get_dword(
                r"HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection",
                "DisableRealtimeMonitoring"
            ))
        ));
        log(&format!(
            "  UAC EnableLUA: {}",
            opt(xos_sys::reg_get_dword(
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                "EnableLUA"
            ))
        ));
        log(&format!(
            "  OFFmeansOFF.exe exists: {}",
            tf(directory_contains_file(
                r"C:\ProgramData\Microsoft\Windows Defender\Platform",
                "OFFmeansOFF.exe"
            ))
        ));
        log("--- PARALLEL RESTORE JOBS ---");
        let process_mitigations_job = s.spawn(|| job(u::restore_process_mitigations));
        let dma_remapping_job = s.spawn(|| job(u::restore_dma_remapping_overrides));
        let event_channels_job = s.spawn(|| job(u::restore_event_channels));
        let msi_mode_job = s.spawn(|| job(u::restore_playbook_msi_mode_overrides));
        let nic_class_job = s.spawn(|| {
            job(|| {
                let device_power = match std::panic::catch_unwind(u::restore_ms_power_overrides) {
                    Ok(v) => v,
                    Err(payload) => {
                        log(&format!(
                            "  Device power management restore: FAILED {}",
                            panic_text(payload.as_ref())
                        ));
                        false
                    }
                };
                let adapters = u::restore_nic_class_overrides();
                device_power && adapters
            })
        });
        let disabled_devices_job = s.spawn(|| job(u::restore_captured_disabled_devices));
        let optional_features_job = s.spawn(|| job(u::restore_optional_features_from_log));
        log("--- VISUAL SETTINGS ---");
        del(
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
            "ShowTaskViewButton",
        );
        del(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
            "TaskbarMn",
        );
        set(
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
            "Hidden",
            2,
        );
        set(
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
            "HideFileExt",
            1,
        );
        set(
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search",
            "SearchboxTaskbarMode",
            1,
        );
        set(
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize",
            "SystemUsesLightTheme",
            1,
        );
        set(
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize",
            "AppsUseLightTheme",
            1,
        );
        set(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
            "EnableTransparency",
            1,
        );
        del(
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer",
            "ShowRecommendations",
        );
        del(
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked",
            "{e2bf9676-5f8f-435c-97eb-11607a5bedf7}",
        );
        del(
            r"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked",
            "{e2bf9676-5f8f-435c-97eb-11607a5bedf7}",
        );
        del(
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked",
            "{596AB062-B4D2-4215-9F74-E9109B0A8153}",
        );
        del(
            r"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked",
            "{596AB062-B4D2-4215-9F74-E9109B0A8153}",
        );
        del(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
            "ListviewAlphaSelect",
        );
        del(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
            "ListviewShadow",
        );
        del(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
            "TaskbarAnimations",
        );
        del(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects",
            "VisualFXSetting",
        );
        del(r"HKCU\Software\Microsoft\Windows\DWM", "EnableAeroPeek");
        del(
            r"HKCU\Software\Microsoft\Windows\DWM",
            "AlwaysHibernateThumbnails",
        );
        del(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\PenWorkspace",
            "PenWorkspaceButtonDesiredVisibility",
        );
        del(r"HKCU\Control Panel\Desktop", "DragFullWindows");
        del(r"HKCU\Control Panel\Desktop", "UserPreferencesMask");
        del(r"HKCU\Control Panel\Desktop\WindowMetrics", "MinAnimate");
        del(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
            "TaskbarAl",
        );
        delkey(r"HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}");
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer",
            "HubMode",
        );
        del(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3",
            "1806",
        );
        del(
            r"HKCU\Software\Classes\CLSID\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}",
            "System.IsPinnedToNameSpaceTree",
        );
        del(
            r"HKCU\Software\Classes\CLSID\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}",
            "System.IsPinnedToNameSpaceTree",
        );
        del(
            r"HKCU\Software\Classes\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}",
            "System.IsPinnedToNameSpaceTree",
        );
        del(
            r"HKCU\Software\Microsoft\DirectX\UserGpuPreferences",
            "DirectXUserGlobalSettings",
        );
        del(
            r"HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers",
            "HwSchMode",
        );
        set(
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer",
            "AltTabSettings",
            0,
        );
        set(
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer",
            "HoverSelectDesktops",
            1,
        );
        if xos_sys::get_windows_build_number() >= 22621 {
            del(r"HKCU\Control Panel\Mouse", "RawMouseThrottleEnabled");
            del(r"HKCU\Control Panel\Mouse", "RawMouseThrottleDuration");
        }
        delkey(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CrossDeviceResume.exe",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\PolicyManager\default\Connectivity\DisableCrossDeviceResume",
            "value",
        );
        del(
            r"HKLM\SYSTEM\CurrentControlSet\Policies\Microsoft\FeatureManagement\Overrides",
            "1387020943",
        );
        delkey(r"HKLM\SYSTEM\CurrentControlSet\Control\FeatureManagement\Overrides\8\1387020943");
        del(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\CrossDeviceResume",
            "IsResumeAllowed",
        );
        {
            let cdr_dir = u::path_combine(
                &u::windows_directory(),
                r"SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy",
            );
            let cdr_old = u::path_combine(&cdr_dir, "CrossDeviceResume.exe.old");
            let cdr_exe = u::path_combine(&cdr_dir, "CrossDeviceResume.exe");
            if Path::new(&cdr_old).is_file() && !Path::new(&cdr_exe).is_file() {
                rec(xos_sys::run_as_ti(
                    "takeown.exe",
                    &format!("/f \"{cdr_old}\""),
                ));
                rec(xos_sys::run_as_ti(
                    "icacls.exe",
                    &format!("\"{cdr_old}\" /grant *S-1-5-32-544:F"),
                ));
                rec(xos_sys::run_as_ti(
                    "cmd.exe",
                    &format!("/c ren \"{cdr_old}\" \"CrossDeviceResume.exe\""),
                ));
                log("  CrossDeviceResume.exe restored from .old");
            } else if Path::new(&cdr_exe).is_file() {
                log("  CrossDeviceResume.exe already present");
            } else {
                log("  CrossDeviceResume.exe.old not found at expected CBS path");
            }
        }
        log("--- WALLPAPER ---");
        rec(u::restore_profiles_wallpaper_and_security_overrides());
        log("--- OEM INFO ---");
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation",
            "Manufacturer",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation",
            "SupportURL",
        );
        log("--- UAC ---");
        set(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "EnableLUA",
            1,
        );
        set(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "PromptOnSecureDesktop",
            1,
        );
        set(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "ConsentPromptBehaviorAdmin",
            5,
        );
        set(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "ValidateAdminCodeSignatures",
            0,
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "DelayedDesktopSwitchTimeout",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "RunLogonScriptSync",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "RunStartupScriptSync",
        );
        log("--- KERNEL, SCHEDULER AND MEMORY ---");
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile",
            "NoLazyMode",
        );
        set(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile",
            "SystemResponsiveness",
            20,
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile",
            "NetworkThrottlingIndex",
        );
        del(
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched",
            "TimerResolution",
        );
        set(
            r"HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl",
            "Win32PrioritySeparation",
            2,
        );
        del(
            r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
            "FeatureSettingsOverride",
        );
        del(
            r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
            "FeatureSettingsOverrideMask",
        );
        del(
            r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
            "DisablePageCombining",
        );
        del(
            r"HKLM\SYSTEM\CurrentControlSet\Control",
            "SvcHostSplitThresholdInKB",
        );
        del(
            r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power",
            "CoalescingTimerInterval",
        );
        del(
            r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power",
            "SleepStudyDisabled",
        );
        del(
            r"HKLM\SYSTEM\CurrentControlSet\Control\SCMConfig",
            "EnableSvchostMitigationPolicy",
        );
        del(
            r"HKLM\SYSTEM\CurrentControlSet\Control\SCMConfig",
            "EnableSvchostMitigationsPolicy",
        );
        del(
            r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager",
            "Segment Heap",
        );
        del(
            r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager",
            "BackgroundLoadKnownDlls",
        );
        del(
            r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager",
            "BootExecuteNoPnpSync",
        );
        del(
            r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager",
            "TaskhostTimeout",
        );
        del(
            r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Quota System",
            "EnableCpuQuota",
        );
        del(
            r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
            "TokenLeakDetectDelaySecs",
        );
        set(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
            "DesktopHeapLogging",
            1,
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
            "TimerCoalescing",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\EventSystem",
            "ParallelFiringTimeoutEnabled",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Audio",
            "AudioHealthMonitorLimit",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager",
            "ComServerShutdownDelayMs",
        );
        del(
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\System",
            "CopyFileBufferedSynchronousIo",
        );
        del(
            r"HKLM\SYSTEM\CurrentControlSet\Services\BrokerInfrastructure\Parameters",
            "DefaultTriggerCoalescingTime",
        );
        del(
            r"HKLM\SYSTEM\CurrentControlSet\Services\BrokerInfrastructure\Parameters",
            "DisableTriggerCoalescing",
        );
        for svc in [
            "SamSs",
            "EventSystem",
            "CryptSvc",
            "Dhcp",
            "Dnscache",
            "DisplayEnhancementService",
            "PcaSvc",
            "WdiSystemHost",
            "AudioEndpointBuilder",
            "Appinfo",
            "BITS",
            "gpsvc",
            "IKEEXT",
            "iphlpsvc",
            "LanmanServer",
            "lmhosts",
            "NcbService",
            "RasAuto",
            "SENS",
            "ShellHWDetection",
            "SstpSvc",
            "TrkWks",
            "Winmgmt",
            "EventLog",
            "FontCache",
            "LanmanWorkstation",
            "NlaSvc",
            "nsi",
            "Schedule",
            "SessionEnv",
            "Themes",
            "W32Time",
            "Wcmsvc",
        ] {
            del(
                &format!(r"HKLM\SYSTEM\CurrentControlSet\Services\{svc}"),
                "SvcHostSplitDisable",
            );
        }
        let split_build = xos_sys::get_windows_build_number();
        if split_build < 26200 {
            del(
                r"HKLM\SYSTEM\CurrentControlSet\Services\DcomLaunch",
                "SvcHostSplitDisable",
            );
            del(
                r"HKLM\SYSTEM\CurrentControlSet\Services\Power",
                "SvcHostSplitDisable",
            );
        }
        let process_mitigations_restored = join(process_mitigations_job);
        rec(process_mitigations_restored);
        let dma_restored = join(dma_remapping_job);
        rec(dma_restored);
        rec(join(event_channels_job));
        let msi_restored = join(msi_mode_job);
        rec(msi_restored);
        let nic_restored = join(nic_class_job);
        rec(nic_restored);
        u::write_stock_hardware_restored_marker(dma_restored && msi_restored && nic_restored);
        rec(join(disabled_devices_job));
        log("--- INPUT OPTIMIZATIONS ---");
        del(r"HKLM\SOFTWARE\Microsoft\Input", "IsInputAppPreloadEnabled");
        del(r"HKLM\SOFTWARE\Microsoft\Input", "InputServiceEnabled");
        del(
            r"HKLM\SOFTWARE\Microsoft\Input",
            "InputServiceEnabledForCCI",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Input\Settings",
            "BluebirdDTWMultiplier",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Input\Settings",
            "DisableExpressiveInputShellHotkey",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Input\Settings",
            "DisablePersonalizationGTKM",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Input\Settings",
            "DynamicAutocorrectionAllowed",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Input\Settings",
            "INLINEPREDICTIONMINPREDICTIONLENGTH",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Input\Settings",
            "INLINEPREDICTIONMINPREFIXLENGTH",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism",
            "ClosestInteractiveBoundsUpdateIntervalInMilliseconds",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism",
            "SearchHeightInDIPS",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism",
            "SearchWidthInDIPS",
        );
        del(r"HKLM\SOFTWARE\Microsoft\Input\TIPC", "Enabled");
        u::uninstall_reg_restore_captured_hkcu(
            r"SOFTWARE\Microsoft\Input",
            "IsInputAppPreloadEnabled",
        );
        del(r"HKCU\SOFTWARE\Microsoft\Input\Settings", "Insights");
        del(
            r"HKCU\SOFTWARE\Microsoft\Input\Settings",
            "UserStatsEnabled",
        );
        del(r"HKCU\SOFTWARE\Microsoft\Input\TIPC", "Enabled");
        log("--- LOGGING AND DIAGNOSTICS ---");
        del(
            r"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KeyGuard",
            "DisableTelemetry",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Cryptography\CatalogDB",
            "EnablePerformanceCounters",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows Media Foundation\Platform",
            "CallStackTracingEnabled",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows Media Foundation\Platform",
            "CallStackTracingNoisy",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Configuration",
            "AdapterLoggingEnabled",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Configuration",
            "EnableAt",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit",
            "PolicyDebugLevel",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
            "GDIEnableReferenceStackTraces",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
            "USERExtraInstrumentations",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
            "USERPostMortemLogging",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\Win32kWPP\Parameters",
            "VerboseOn",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "NoDebugThread",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "RsopLogging",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "RunLogonScriptSync",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "RunStartupScriptSync",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\UIPI",
            "EnableMessageSQM",
        );
        del(
            r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Audit",
            "EtwDirect",
        );
        del(
            r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Tracing",
            "TracingDisabled",
        );
        del(
            r"HKLM\SYSTEM\CurrentControlSet\Control\Wdf",
            "WdfGlobalLogsDisabled",
        );
        del(
            r"HKLM\SYSTEM\CurrentControlSet\Control\Wdf",
            "WdfGlobalSleepStudyDisabled",
        );
        set(
            r"HKLM\SYSTEM\CurrentControlSet\Control\Diagnostics\Performance",
            "DisableDiagnosticTracing",
            0,
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
            "DesktopLivePreviewHoverTime",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
            "Start_NotifyNewApps",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
            "Start_TrackCachedFileUpdaterContract",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
            "Start_TrackConnectedSearchHistory",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
            "Start_TrackEnabled",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
            "Start_TrackOpenPickerContract",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
            "Start_TrackSavePickerContract",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
            "Start_TrackSearchContract",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
            "Start_TrackShareContractMFU",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
            "ThumbnailLivePreviewHoverTime",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            "NoLowDiskSpaceChecks",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            "NoNetCrawling",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            "NoRemoteChangeNotify",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            "NoRemoteRecursiveEvents",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            "TurnOffSPIAnimations",
        );
        log("--- VISUAL DESKTOP ELEMENTS ---");
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows\Dwm",
            "DisableProjectedShadows",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows\Dwm",
            "MousewheelAnimationDurationMs",
        );
        del(r"HKLM\SOFTWARE\Microsoft\Windows\Dwm", "OverlayTestMode");
        del(r"HKLM\SOFTWARE\Microsoft\XAML", "DisableGlobalAnimations");
        del(
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\System",
            "DisableLogonBackgroundImage",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications",
            "InitializePlatformOnStartup",
        );
        del(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications",
            "ToastEnabled",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\SchedulingAgent",
            "ViewHiddenTasks",
        );
        u::uninstall_reg_restore_captured_hkcu(r"Control Panel\Cursors", "PenVisualization");
        del(r"HKCU\Control Panel\Desktop", "AutoColorization");
        del(r"HKCU\Control Panel\Desktop", "SmoothScroll");
        del(
            r"HKCU\Control Panel\Keyboard",
            "PrintScreenKeyForSnippingEnabled",
        );
        del(
            r"HKCU\Control Panel\Personalization\Desktop Slideshow",
            "AnimationDuration",
        );
        del(
            r"HKCU\SOFTWARE\Microsoft\Clipboard",
            "CloudClipboardAutomaticUpload",
        );
        del(r"HKCU\SOFTWARE\Microsoft\Clipboard", "CloudClipRDPOverride");
        del(
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
            "DisablePreviewDesktop",
        );
        del(
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
            "DisablePreviewWindow",
        );
        del(
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
            "NoNetCrawling",
        );
        del(
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
            "Start_TrackCachedFileUpdaterContract",
        );
        del(
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
            "Start_TrackConnectedSearchHistory",
        );
        del(
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
            "Start_TrackEnabled",
        );
        del(
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
            "Start_TrackOpenPickerContract",
        );
        del(
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
            "Start_TrackSavePickerContract",
        );
        del(
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
            "Start_TrackSearchContract",
        );
        del(
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
            "Start_TrackShareContractMFU",
        );
        del(
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
            "TaskbarFlashOverrideBreatheCount",
        );
        del(
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\BamThrottling",
            "DisableWindowHinting",
        );
        del(
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
            "ShowCopilotButton",
        );
        del(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
            "ShowCortanaButton",
        );
        del(
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds",
            "ShellFeedsTaskbarViewMode",
        );
        del(
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            "NoNetCrawling",
        );
        del(
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            "NoRecentDocsMenu",
        );
        del(
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            "NoRemoteChangeNotify",
        );
        del(
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            "NoRemoteRecursiveEvents",
        );
        del(
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            "NoSMHelp",
        );
        del(
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            "TurnOffSPIAnimations",
        );
        del(
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications",
            "HourlyTelemetyThreshold",
        );
        rec(u::restore_surgical_policy_leftovers());
        log("--- NETWORK ---");
        del(
            r"HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters",
            "EnableNetbios",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp",
            "DisableWpad",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp",
            "EnableDefaultHttp2",
        );
        del(
            r"HKLM\SYSTEM\CurrentControlSet\Services\BFE\Parameters\Policy\Options",
            "CollectConnections",
        );
        del(
            r"HKLM\SYSTEM\CurrentControlSet\Services\BFE\Parameters\Policy\Options",
            "CollectNetEvents",
        );
        del(
            r"HKLM\SYSTEM\CurrentControlSet\Services\Dhcp",
            "PdcActivationDisabled",
        );
        del(
            r"HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters",
            "DisableCoalescing",
        );
        del(
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\Local",
            "fDisablePowerManagement",
        );
        del(
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy",
            "fDisablePowerManagement",
        );
        for iface in xos_sys::find_tcpip_interface_paths(false) {
            del(&iface, "TcpAckFrequency");
            del(&iface, "TCPNoDelay");
        }
        log("--- GRAPHICS DRIVERS ---");
        del(
            r"HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers",
            "MiracastForceDisable",
        );
        del(
            r"HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers",
            "TdrDelay",
        );
        del(
            r"HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers",
            "WarpSupportsResourceResidency",
        );
        log("--- POWERSHELL ---");
        del(
            r"HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell",
            "ExecutionPolicy",
        );
        log("--- TELEMETRY ---");
        del(
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo",
            "DisabledByGroupPolicy",
        );
        del(
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
            "AllowDesktopAnalyticsProcessing",
        );
        del(
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
            "AllowDeviceNameInTelemetry",
        );
        del(
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
            "MicrosoftEdgeDataOptIn",
        );
        del(
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
            "AllowWUfBCloudProcessing",
        );
        del(
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
            "AllowUpdateComplianceProcessing",
        );
        del(
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
            "AllowCommercialDataPipeline",
        );
        del(
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
            "AllowTelemetry",
        );
        del(
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
            "DisableOneSettingsDownloads",
        );
        del(
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
            "DoNotShowFeedbackNotifications",
        );
        u::restore_data_collection_settings();
        u::remove_telemetry_opt_out_variables();
        del(
            r"HKCU\Software\Microsoft\Windows\Windows Error Reporting",
            "Disabled",
        );
        del(
            r"HKCU\Software\Policies\Microsoft\Windows\Windows Error Reporting",
            "Disabled",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting",
            "Disabled",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting",
            "DontSendAdditionalData",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting",
            "LoggingDisabled",
        );
        del(
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting",
            "Disabled",
        );
        del(
            r"HKCU\Software\Microsoft\Windows\Shell\Copilot\BingChat",
            "IsUserEligible",
        );
        del(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings",
            "AutoOpenCopilotLargeScreens",
        );
        del(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\ShowJumpView",
            "Microsoft.Copilot_8wekyb3d8bbwe!App",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput",
            "AllowLinguisticDataCollection",
        );
        del(
            r"HKCU\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy",
            "HasAccepted",
        );
        set(
            r"HKCU\SOFTWARE\Microsoft\Personalization\Settings",
            "AcceptedPrivacyPolicy",
            1,
        );
        del(
            r"HKCU\SOFTWARE\Microsoft\Siuf\Rules",
            "NumberOfSIUFInPeriod",
        );
        set(
            r"HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore",
            "HarvestContacts",
            1,
        );
        set(
            r"HKCU\SOFTWARE\Microsoft\InputPersonalization",
            "RestrictImplicitInkCollection",
            0,
        );
        set(
            r"HKCU\SOFTWARE\Microsoft\InputPersonalization",
            "RestrictImplicitTextCollection",
            0,
        );
        set(
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy",
            "TailoredExperiencesWithDiagnosticDataEnabled",
            2,
        );
        del(
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\System",
            "EnableActivityFeed",
        );
        del(
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\System",
            "PublishUserActivities",
        );
        del(
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\System",
            "UploadUserActivities",
        );
        del(r"HKLM\SOFTWARE\Microsoft\Input\TIPC", "Enabled");
        log("--- CEIP ---");
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications",
            "NoCloudApplicationNotification",
        );
        del(r"HKLM\Software\Microsoft\SQMClient", "UploadDisableFlag");
        del(r"HKCU\SOFTWARE\Microsoft\Edge", "SmartScreenEnabled");
        del(
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost",
            "EnableWebContentEvaluation",
        );
        del(
            r"HKLM\Software\Policies\Microsoft\Windows Defender\SmartScreen",
            "ConfigureAppInstallControlEnabled",
        );
        del(
            r"HKLM\Software\Policies\Microsoft\Windows Defender\SmartScreen",
            "ConfigureAppInstallControl",
        );
        del(
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray",
            "HideSystray",
        );
        log("--- CLOUD SYNC ---");
        for v in [
            "DisableSettingSync",
            "DisableSettingSyncUserOverride",
            "DisableSyncOnPaidNetwork",
            "SyncPolicy",
            "DisableApplicationSettingSync",
            "DisableApplicationSettingSyncUserOverride",
            "DisableAppSyncSettingSync",
            "DisableAppSyncSettingSyncUserOverride",
            "DisableDesktopThemeSettingSync",
            "DisableDesktopThemeSettingSyncUserOverride",
            "DisableStartLayoutSettingSync",
            "DisableStartLayoutSettingSyncUserOverride",
            "DisableWebBrowserSettingSync",
            "DisableWebBrowserSettingSyncUserOverride",
            "DisableWindowsSettingSync",
            "DisableWindowsSettingSyncUserOverride",
            "DisableCredentialsSettingSync",
            "DisableCredentialsSettingSyncUserOverride",
            "DisablePersonalizationSettingSync",
            "DisablePersonalizationSettingSyncUserOverride",
        ] {
            del(r"HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync", v);
        }
        del(
            r"HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Experience",
            "AllowSyncMySettings",
        );
        del(
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\System",
            "AllowCrossDeviceClipboard",
        );
        log("--- WINDOWS SEARCH POLICIES ---");
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search",
            "CortanaEnabled",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search",
            "CortanaInAmbientMode",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana",
            "value",
        );
        log("--- WINDOWS UPDATE ---");
        rec(u::restore_windows_update_policy_values());
        rec(u::restore_driver_update_values());
        rec(u::restore_store_and_delivery_values());
        rec(u::restore_preview_maps_and_speech_values());
        del(
            r"HKLM\Software\Policies\Microsoft\Windows\Appx",
            "AllowAutomaticAppArchiving",
        );
        del(
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\MobilityCenter",
            "NoMobilityCenter",
        );
        log("--- APPHOST / SMARTSCREEN / DEVICE GUARD ---");
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost",
            "Enabled",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost",
            "PreventOverride",
        );
        del(
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppHost",
            "EnableWebContentEvaluation",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer",
            "AicEnabled",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer",
            "SmartScreenEnabled",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WTDS\Components",
            "ServiceEnabled",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WTDS\Components",
            "CaptureThreatWindow",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WTDS\Components",
            "NotifyMalicious",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WTDS\Components",
            "NotifyPasswordReuse",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WTDS\Components",
            "NotifyUnsafeApp",
        );
        for v in [
            "ServiceEnabled",
            "CaptureThreatWindow",
            "NotifyMalicious",
            "NotifyPasswordReuse",
            "NotifyUnsafeApp",
        ] {
            del(
                r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components",
                v,
            );
        }
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WTDS\FeatureFlags",
            "BlockUxDisabled",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WTDS\FeatureFlags",
            "TelemetryCallsEnabled",
        );
        del(
            r"HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy",
            "VerifiedAndReputablePolicyState",
        );
        del(
            r"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity",
            "Enabled",
        );
        del(
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard",
            "ConfigureSystemGuardLaunch",
        );
        del(
            r"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard",
            "Enabled",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\smartscreen.exe",
            "Debugger",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DeviceCensus.exe",
            "Debugger",
        );
        rec(u::restore_device_census_disallow_run());
        log("--- FAULT TOLERANT HEAP ---");
        set(r"HKLM\SOFTWARE\Microsoft\FTH", "Enabled", 1);
        log("--- MOUSE ---");
        rec(u::delete_xos_string_value_if_matches(
            r"HKCU\Control Panel\Mouse",
            "MouseSpeed",
            &["0"],
        ));
        rec(u::delete_xos_string_value_if_matches(
            r"HKCU\Control Panel\Mouse",
            "MouseThreshold1",
            &["0"],
        ));
        rec(u::delete_xos_string_value_if_matches(
            r"HKCU\Control Panel\Mouse",
            "MouseThreshold2",
            &["0"],
        ));
        log("--- ACCESSIBILITY ---");
        rec(u::delete_xos_string_value_if_matches(
            r"HKCU\Control Panel\Accessibility\StickyKeys",
            "Flags",
            &["506"],
        ));
        rec(u::delete_xos_string_value_if_matches(
            r"HKCU\Control Panel\Accessibility\Keyboard Response",
            "Flags",
            &["2"],
        ));
        rec(u::delete_xos_string_value_if_matches(
            r"HKCU\Control Panel\Accessibility\ToggleKeys",
            "Flags",
            &["34"],
        ));
        rec(u::delete_xos_string_value_if_matches(
            r"HKCU\Control Panel\Accessibility\MouseKeys",
            "Flags",
            &["130"],
        ));
        rec(u::delete_xos_string_value_if_matches(
            r"HKCU\Control Panel\Accessibility\HighContrast",
            "Flags",
            &["4194"],
        ));
        del(
            r"HKCU\SOFTWARE\Microsoft\Narrator\NoRoam",
            "WinEnterLaunchEnabled",
        );
        log("--- SHUTDOWN TIMEOUTS ---");
        del(
            r"HKU\.DEFAULT\Control Panel\Desktop",
            "CriticalAppShutdownCleanupTimeout",
        );
        del(
            r"HKU\.DEFAULT\Control Panel\Desktop",
            "CriticalAppShutdownTimeout",
        );
        del(r"HKU\.DEFAULT\Control Panel\Desktop", "WaitToKillTimeout");
        log("--- DELIVERY OPTIMIZATION / MISC HKCU ---");
        del(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization",
            "SystemSettingsDownloadMode",
        );
        del(
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language",
            "Enabled",
        );
        set(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager",
            "SilentInstalledAppsEnabled",
            1,
        );
        set(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager",
            "OemPreInstalledAppsEnabled",
            1,
        );
        set(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager",
            "PreInstalledAppsEnabled",
            1,
        );
        set(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager",
            "ContentDeliveryAllowed",
            1,
        );
        del(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager",
            "PreInstalledAppsEverEnabled",
        );
        del(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager",
            "FeatureManagementEnabled",
        );
        del(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager",
            "RotatingLockScreenEnabled",
        );
        del(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager",
            "RotatingLockScreenOverlayEnabled",
        );
        del(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager",
            "SoftLandingEnabled",
        );
        del(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager",
            "SystemPaneSuggestionsEnabled",
        );
        for id in [
            "SubscribedContent-310093Enabled",
            "SubscribedContent-338387Enabled",
            "SubscribedContent-338388Enabled",
            "SubscribedContent-338389Enabled",
            "SubscribedContent-338393Enabled",
            "SubscribedContent-353694Enabled",
            "SubscribedContent-353696Enabled",
            "SubscribedContent-353698Enabled",
        ] {
            del(
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager",
                id,
            );
        }
        del(
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy",
            "LetAppsRunInBackground",
        );
        del(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications",
            "GlobalUserOverride",
        );
        del(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\MicrosoftWindows.Client.CBS_cw5n1h2txyewy",
            "Disabled",
        );
        del(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\MicrosoftWindows.Client.CBS_cw5n1h2txyewy",
            "DisabledByUser",
        );
        del(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            "AllowOnlineTips",
        );
        del(r"HKCU\Software\Microsoft\input\Settings", "InsightsEnabled");
        log("--- POWER PLAN ---");
        log("  Restoring power timeouts");
        rec(u::restore_power_timeout_backup());
        let had_xos_plan = xos_sys::is_xos_power_plan_imported();
        let mut selected_power_scheme: Option<String> = None;
        let switched_power_scheme = if had_xos_plan {
            let (switched, selected) = xos_sys::try_switch_away_from_xos_power_plan();
            selected_power_scheme = selected;
            switched
        } else {
            true
        };
        if had_xos_plan {
            rec(switched_power_scheme);
            log(&if switched_power_scheme {
                format!(
                    "  Switched away from XOS power plan: {}",
                    selected_power_scheme.clone().unwrap_or_default()
                )
            } else {
                "  Could not activate an installed non-XOS power scheme; XOS power plan kept"
                    .to_string()
            });
        }
        let mut xos_plan_delete_detail = String::new();
        let mut xos_plan_deleted = !had_xos_plan;
        if had_xos_plan && switched_power_scheme {
            let (deleted, detail) = xos_sys::delete_xos_power_plan_detail();
            xos_plan_deleted = deleted;
            xos_plan_delete_detail = detail;
        }
        if had_xos_plan {
            rec(xos_plan_deleted);
        }
        log(&format!(
            "  DeleteXosPowerPlan: {}{}",
            tf(xos_plan_deleted),
            if xos_plan_delete_detail.trim().is_empty() {
                String::new()
            } else {
                format!(
                    " | {}",
                    xos_plan_delete_detail
                        .replace('\r', " ")
                        .replace('\n', " | ")
                )
            }
        ));
        {
            let imribiy_pow = xos_sys::expand_environment_variables(r"%windir%\imribiy.pow");
            if Path::new(&imribiy_pow).is_file() {
                let _ = std::fs::remove_file(&imribiy_pow);
            }
        }
        log("--- HIBERNATE ---");
        let (hibernate_available, hibernate_blocker) = xos_sys::hibernate_set(true);
        if hibernate_available {
            rec(u::uninstall_reg_set(
                r"HKLM\SYSTEM\CurrentControlSet\Control\Power",
                "HibernateEnabled",
                1,
            ));
            rec(u::uninstall_reg_set(
                r"HKLM\Software\Policies\Microsoft\Windows\System",
                "ShowHibernateOption",
                1,
            ));
            log("  Hibernation enabled and verified");
        } else {
            log("  Hibernation is not supported by this firmware; removing XOS overrides");
            if let Some(blocker) = hibernate_blocker.as_deref() {
                if !blocker.trim().is_empty() {
                    log(&format!("  {blocker}"));
                }
            }
            rec(u::uninstall_reg_del(
                r"HKLM\SYSTEM\CurrentControlSet\Control\Power",
                "HibernateEnabled",
            ));
            rec(u::uninstall_reg_del(
                r"HKLM\Software\Policies\Microsoft\Windows\System",
                "ShowHibernateOption",
            ));
        }
        log("--- USB / PCIE / DISK POWER SAVINGS ---");
        del(
            r"HKLM\SYSTEM\CurrentControlSet\Services\USBHUB3\Parameters",
            "DisableLPM",
        );
        del(
            r"HKLM\SYSTEM\CurrentControlSet\Services\USBHUB3\Parameters",
            "D3ColdSupported",
        );
        del(
            r"HKLM\SYSTEM\CurrentControlSet\Services\USBHUB3\Parameters",
            "Ceip",
        );
        del(
            r"HKLM\SYSTEM\CurrentControlSet\Services\USBHUB3\Parameters",
            "DisableSelectiveSuspendUI",
        );
        del(
            r"HKLM\SYSTEM\CurrentControlSet\Services\usbccgp\Parameters",
            "D3ColdSupported",
        );
        del(
            r"HKLM\SYSTEM\CurrentControlSet\Services\pci\Parameters",
            "D3ColdSupported",
        );
        del(
            r"HKLM\SYSTEM\CurrentControlSet\Services\pci\Parameters",
            "D3ColdSupport",
        );
        del(
            r"HKLM\SYSTEM\CurrentControlSet\Control\Power",
            "EnergyEstimationEnabled",
        );
        del(
            r"HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling",
            "PowerThrottlingOff",
        );
        del(
            r"HKLM\SYSTEM\CurrentControlSet\Services\iphlpsvc\Teredo",
            "AllowLowPowerMode",
        );
        rec(u::restore_power_setting_visibility_defaults());
        log("--- MEMORY MANAGEMENT ---");
        rec(xos_sys::run_cmd(
            "powershell.exe",
            r#"-NoProfile -Command "Enable-MMAgent -MemoryCompression -ErrorAction SilentlyContinue""#,
        ));
        log("--- NTFS ---");
        u::uninstall_log_run_ti(
            "fsutil disable8dot3 2",
            "fsutil.exe",
            "behavior set disable8dot3 2",
            true,
        );
        u::uninstall_log_run_ti(
            "fsutil disablelastaccess 2",
            "fsutil.exe",
            "behavior set disablelastaccess 2",
            true,
        );
        let optional_features_restored = join(optional_features_job);
        rec(optional_features_restored);
        log("--- SERVICES ---");
        rec(u::restore_update_service_registry_acl());
        let toolkit_service_defaults_restored = u::restore_toolkit_service_defaults();
        rec(toolkit_service_defaults_restored);
        set(
            r"HKLM\SOFTWARE\Microsoft\Windows Search",
            "SetupCompletedSuccessfully",
            1,
        );
        log("  Managed services use the documented Toolkit enable/default configuration");
        log("--- EDGE UPDATE ---");
        for value in [
            "InstallDefault",
            "UpdateDefault",
            "CreateDesktopShortcutDefault",
            "DoNotUpdateToEdgeWithChromium",
            "Install{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}",
            "Install{2CD8A007-E189-409D-A2C8-9AF4EF3C72AA}",
            "Install{0D50BFEC-CD6A-4F9A-964C-C7416E3ACB10}",
            "Install{65C35B14-6C1D-4122-AC46-7148CC9D6497}",
            "Install{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}",
            "Update{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}",
            "Update{2CD8A007-E189-409D-A2C8-9AF4EF3C72AA}",
            "Update{0D50BFEC-CD6A-4F9A-964C-C7416E3ACB10}",
            "Update{65C35B14-6C1D-4122-AC46-7148CC9D6497}",
            "Update{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}",
        ] {
            del(r"HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate", value);
        }
        rec(xos_winupdate::webview2::clear_updater_state());
        log("  Edge Update policies and temporary updater state cleared");
        rec(u::restore_visual_and_graphics_overrides());
        log("--- XOS CPU SERVICE ---");
        if signal_cpu_service_stop() {
            std::thread::sleep(std::time::Duration::from_millis(1000));
        }
        procs::kill_processes_named("XOS-CpuService");
        if xos_sys::get_task_state("XOS CPU Service") >= 0 {
            rec(xos_sys::run_cmd(
                "schtasks.exe",
                "/delete /tn \"XOS CPU Service\" /f",
            ));
            log("  XOS CPU Service stopped and task deleted");
        } else {
            log("  XOS CPU Service task was not present; nothing to delete");
        }
        log("--- DEPROVISIONING ---");
        const DEPROV_BASE: &str =
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\";
        for pkg in [
            "Microsoft.549981C3F5F10_8wekyb3d8bbwe",
            "Microsoft.BingNews_8wekyb3d8bbwe",
            "Microsoft.BingWeather_8wekyb3d8bbwe",
            "Microsoft.ECApp_8wekyb3d8bbwe",
            "Microsoft.GetHelp_8wekyb3d8bbwe",
            "Microsoft.Getstarted_8wekyb3d8bbwe",
            "Microsoft.MicrosoftSolitaireCollection_8wekyb3d8bbwe",
            "Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe",
            "Microsoft.People_8wekyb3d8bbwe",
            "Microsoft.PowerAutomateDesktop_8wekyb3d8bbwe",
            "Microsoft.Todos_8wekyb3d8bbwe",
            "Microsoft.Windows.Apprep.ChxApp_cw5n1h2txyewy",
            "Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy",
            "Microsoft.Windows.PeopleExperienceHost_cw5n1h2txyewy",
            "Microsoft.Windows.Photos_8wekyb3d8bbwe",
            "Microsoft.Windows.SecureAssessmentBrowser_cw5n1h2txyewy",
            "Microsoft.WindowsAlarms_8wekyb3d8bbwe",
            "Microsoft.WindowsCamera_8wekyb3d8bbwe",
            "Microsoft.WindowsFeedbackHub_8wekyb3d8bbwe",
            "Microsoft.WindowsMaps_8wekyb3d8bbwe",
            "Microsoft.WindowsSoundRecorder_8wekyb3d8bbwe",
            "Microsoft.ZuneMusic_8wekyb3d8bbwe",
            "Microsoft.ZuneVideo_8wekyb3d8bbwe",
            "MicrosoftWindows.Client.WebExperience_cw5n1h2txyewy",
            "microsoft.windowscommunicationsapps_8wekyb3d8bbwe",
            "Microsoft.Advertising.Xaml_8wekyb3d8bbwe",
            "Microsoft.Microsoft3DViewer_8wekyb3d8bbwe",
            "Microsoft.MixedReality.Portal_8wekyb3d8bbwe",
            "Microsoft.MSPaint_8wekyb3d8bbwe",
            "Microsoft.Paint_8wekyb3d8bbwe",
            "Microsoft.WindowsNotepad_8wekyb3d8bbwe",
            "clipchamp.clipchamp_yxz26nhyzhsrt",
            "Microsoft.SecHealthUI_8wekyb3d8bbwe",
            "Microsoft.WindowsCalculator_8wekyb3d8bbwe",
            "MicrosoftCorporationII.QuickAssist_8wekyb3d8bbwe",
            "MicrosoftCorporationII.MicrosoftFamily_8wekyb3d8bbwe",
            "Microsoft.Whiteboard_8wekyb3d8bbwe",
            "microsoft.microsoftskydrive_8wekyb3d8bbwe",
            "Microsoft.MicrosoftTeamsforSurfaceHub_8wekyb3d8bbwe",
            "MicrosoftCorporationII.MailforSurfaceHub_8wekyb3d8bbwe",
            "Microsoft.MicrosoftPowerBIForWindows_8wekyb3d8bbwe",
            "Microsoft.SkypeApp_kzf8qxf38zg5c",
            "Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe",
            "Microsoft.Office.OneNote_8wekyb3d8bbwe",
            "Microsoft.Office.Excel_8wekyb3d8bbwe",
            "Microsoft.Office.PowerPoint_8wekyb3d8bbwe",
            "Microsoft.Office.Word_8wekyb3d8bbwe",
            "Microsoft.Windows.DevHome_8wekyb3d8bbwe",
            "Microsoft.OutlookForWindows_8wekyb3d8bbwe",
            "MSTeams_8wekyb3d8bbwe",
            "MicrosoftTeams_8wekyb3d8bbwe",
            "MicrosoftWindows.Client.AIX_cw5n1h2txyewy",
            "Microsoft.Copilot_8wekyb3d8bbwe",
            "Microsoft.Windows.AIX_cw5n1h2txyewy",
            "microsoftwindows.crossdevice_cw5n1h2txyewy",
            "Microsoft.MicrosoftEdge.Stable_8wekyb3d8bbwe",
            "Microsoft.MicrosoftEdge_8wekyb3d8bbwe",
            "Microsoft.MicrosoftEdgeDevToolsClient_8wekyb3d8bbwe",
            "Microsoft.Edge.GameAssist_8wekyb3d8bbwe",
        ] {
            delkey(&format!("{DEPROV_BASE}{pkg}"));
        }
        log("--- AIX PACKAGE RESTORE ---");
        let aix_restore = xos_sys::run_cmd_with_error("powershell.exe", concat!("powershell.exe", "-NoProfile -NonInteractive -Command \"$ProgressPreference='SilentlyContinue'; ", "$a = Get-ChildItem 'C:\\Program Files\\WindowsApps' -Directory -EA SilentlyContinue | ", "Where-Object { $_.Name -match '^MicrosoftWindows\\.Client\\.AIX_' } | ", "Select-Object -First 1; ", "if ($a) { $m=Join-Path $a.FullName 'AppxManifest.xml'; if (Test-Path -LiteralPath $m) { ", "try { Add-AppxPackage -Register $m -DisableDevelopmentMode -EA Stop; ", "Write-Host ('AIX registered: ' + $a.Name) } catch { Write-Output $_.Exception.Message; exit 1 } } ", "else { Write-Host 'AIX staged directory has no manifest - Windows Update will restore it' } } ", "else { Write-Host 'AIX not staged - Windows Update will restore it' }\""));
        log(&if aix_restore.0 {
            "  AIX restore attempted".to_string()
        } else {
            format!("  AIX could not be re-registered, left to the Store and Windows Update like the other removed AppX packages: {}", aix_restore.1.clone().unwrap_or_default())
        });
        log("--- CROSSDEVICE PACKAGE RESTORE ---");
        let crossdevice_restore = xos_sys::run_cmd_with_error("powershell.exe", concat!("powershell.exe", "-NoProfile -NonInteractive -Command \"$ProgressPreference='SilentlyContinue'; ", "$a = Get-ChildItem 'C:\\Program Files\\WindowsApps' -Directory -EA SilentlyContinue | ", "Where-Object { $_.Name -match '^MicrosoftWindows\\.CrossDevice_' } | ", "Select-Object -First 1; ", "if ($a) { $m=Join-Path $a.FullName 'AppxManifest.xml'; if (Test-Path -LiteralPath $m) { ", "try { Add-AppxPackage -Register $m -DisableDevelopmentMode -EA Stop; ", "Write-Host ('CrossDevice registered: ' + $a.Name) } catch { Write-Output $_.Exception.Message; exit 1 } } ", "else { Write-Host 'CrossDevice staged directory has no manifest - Windows Update will restore it' } } ", "else { Write-Host 'CrossDevice not staged - Windows Update will restore it' }\""));
        log(&if crossdevice_restore.0 {
            "  CrossDevice restore attempted".to_string()
        } else {
            format!("  CrossDevice could not be re-registered, left to the Store and Windows Update like the other removed AppX packages: {}", crossdevice_restore.1.clone().unwrap_or_default())
        });
        log("--- SCHEDULED TASKS re-enable ---");
        rec(tasks_best_effort(&[
            r"\Microsoft\Windows\UpdateOrchestrator\StartOobeAppsScan_LicenseAccepted",
            r"\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem",
            r"\Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner",
            r"\Microsoft\Windows\Diagnosis\Scheduled",
            r"\Microsoft\Windows\Diagnosis\UnexpectedCodepath",
            r"\Microsoft\Windows\FileHistory\File History (maintenance mode)",
            r"\Microsoft\Windows\Registry\RegIdleBackup",
            r"\Microsoft\Windows\Feedback\Siuf\DmClient",
            r"\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload",
            r"\Microsoft\Windows\Data Integrity Scan\Data Integrity Check And Scan",
            r"\Microsoft\Windows\Data Integrity Scan\Data Integrity Scan",
            r"\Microsoft\Windows\Data Integrity Scan\Data Integrity Scan for Crash Recovery",
            r"\Microsoft\Windows\DiskFootprint\Diagnostics",
            r"\Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents",
            r"\Microsoft\Windows\MemoryDiagnostic\RunFullMemoryDiagnostic",
            r"\Microsoft\Windows\MemoryDiagnostic\AutomaticOfflineMemoryDiagnostic",
            r"\Microsoft\Windows\WDI\ResolutionHost",
            r"\Microsoft\Windows\RetailDemo\CleanupOfflineContent",
            r"\Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask",
            r"\Microsoft\Windows\SettingSync\NetworkStateChangeTask",
            r"\Microsoft\Windows\SettingSync\BackgroundUploadTask",
            r"\Microsoft\Windows\Maps\MapsToastTask",
            r"\Microsoft\Windows\Application Experience\ProgramDataUpdater",
            r"\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
            r"\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser Exp",
            r"\Microsoft\Windows\AccountHealth\RecoverabilityToastTask",
            r"\Microsoft\Windows\Hotpatch\Monitoring",
            r"\Microsoft\Windows\Maintenance\WinSAT",
            r"\Microsoft\Windows\PerformanceTrace\RequestTrace",
            r"\Microsoft\Windows\PerformanceTrace\WhesvcToast",
            r"\Microsoft\Windows\Shell\FamilySafetyMonitor",
            r"\Microsoft\Windows\Shell\FamilySafetyRefreshTask",
            r"\Microsoft\Windows\UsageAndQualityInsights\UsageAndQualityInsights-MaintenanceTask",
            r"\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration",
            r"\Microsoft\Windows\WindowsAI\Settings\InitialConfiguration",
            r"\Microsoft\Windows\Sustainability\PowerGridForecastTask",
            r"\Microsoft\Windows\Sustainability\SustainabilityTelemetry",
            r"\Microsoft\Windows\CloudRestore\Backup",
            r"\Microsoft\Windows\CloudRestore\Restore",
            r"\Microsoft\Windows\InstallService\RestoreDevice",
            r"\Microsoft\Windows\InstallService\ScanForUpdates",
            r"\Microsoft\Windows\InstallService\ScanForUpdatesAsUser",
            r"\Microsoft\Windows\InstallService\SmartRetry",
            r"\Microsoft\Windows\InstallService\WakeUpAndContinueUpdates",
            r"\Microsoft\Windows\InstallService\WakeUpAndScanForUpdates",
            r"\Microsoft\Windows\WindowsUpdate\Scheduled Start",
            r"\Microsoft\Windows\UpdateOrchestrator\Report policies",
            r"\Microsoft\Windows\UpdateOrchestrator\Schedule Maintenance Work",
            r"\Microsoft\Windows\UpdateOrchestrator\Schedule Wake To Work",
            r"\Microsoft\Windows\UpdateOrchestrator\Schedule Work",
            r"\Microsoft\Windows\UpdateOrchestrator\UIEOrchestrator",
        ]));
        rec(tasks_best_effort(&[
            r"\Microsoft\Windows\UpdateOrchestrator\UpdateModelTask",
            r"\Microsoft\Windows\UpdateOrchestrator\Start Oobe Expedite Work",
            r"\Microsoft\Windows\UpdateOrchestrator\StartOobeAppsScan_OobeAppReady",
            r"\Microsoft\Windows\UpdateOrchestrator\StartOobeAppsScanAfterUpdate",
            r"\Microsoft\Windows\UpdateOrchestrator\UUS Failover Task",
            r"\Microsoft\Windows\WaaSMedic\PerformRemediation",
            r"\Microsoft\Windows\UpdateOrchestrator\AC Power Download",
            r"\Microsoft\Windows\UpdateOrchestrator\AC Power Install",
            r"\Microsoft\Windows\UpdateOrchestrator\Backup Scan",
            r"\Microsoft\Windows\UpdateOrchestrator\Battery Saver Deferred Install",
            r"\Microsoft\Windows\UpdateOrchestrator\Driver Install",
            r"\Microsoft\Windows\UpdateOrchestrator\Maintenance Install",
            r"\Microsoft\Windows\UpdateOrchestrator\MusUx_LogonUpdateResults",
            r"\Microsoft\Windows\UpdateOrchestrator\MusUx_UpdateInterval",
            r"\Microsoft\Windows\UpdateOrchestrator\Policy Install",
            r"\Microsoft\Windows\UpdateOrchestrator\Reboot",
            r"\Microsoft\Windows\UpdateOrchestrator\Reboot_AC",
            r"\Microsoft\Windows\UpdateOrchestrator\Reboot_Battery",
            r"\Microsoft\Windows\UpdateOrchestrator\Refresh Settings",
            r"\Microsoft\Windows\UpdateOrchestrator\Resume On Boot",
            r"\Microsoft\Windows\UpdateOrchestrator\Schedule Retry Scan",
            r"\Microsoft\Windows\UpdateOrchestrator\StartOobeAppsScan",
            r"\Microsoft\Windows\UpdateOrchestrator\USO_Broker_Display",
            r"\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker_Display",
            r"\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker_ReadyToReboot",
            r"\Microsoft\Windows\UpdateOrchestrator\Universal Orchestrator Start",
            r"\Microsoft\Windows\UpdateOrchestrator\Universal Orchestrator Idle Start",
            r"\Microsoft\Windows\UpdateOrchestrator\UpdateAssistant",
            r"\Microsoft\Windows\UpdateOrchestrator\UpdateAssistantAllUsersRun",
            r"\Microsoft\Windows\UpdateOrchestrator\UpdateAssistantCalendarRun",
            r"\Microsoft\Windows\UpdateOrchestrator\UpdateAssistantWakeupRun",
            r"\Microsoft\Windows\Windows Error Reporting\QueueReporting",
            r"\Microsoft\Windows\WindowsUpdate\AUScheduledInstall",
            r"\Microsoft\Windows\WindowsUpdate\AUSessionConnect",
            r"\Microsoft\Windows\WindowsUpdate\Automatic App Update",
            r"\Microsoft\Windows\WindowsUpdate\RUXIM\PLUGScheduler",
            r"\Microsoft\Windows\WindowsUpdate\Scheduled Start With Network",
            r"\Microsoft\Windows\WindowsUpdate\sih",
            r"\Microsoft\Windows\WindowsUpdate\sihboot",
            r"\Microsoft\Windows\WindowsUpdate\sihpostreboot",
            r"\Microsoft\Windows\Customer Experience Improvement Program\Server\ServerCeipAssistant",
            r"\Microsoft\Windows\Customer Experience Improvement Program\Server\ServerRoleCollector",
            r"\Microsoft\Windows\Customer Experience Improvement Program\Server\ServerRoleUsageCollector",
            r"\Microsoft\Windows\Autochk\Proxy",
            r"\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask",
            r"\Microsoft\Windows\Customer Experience Improvement Program\BthSQM",
            r"\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
            r"\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver",
            r"\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
            r"\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
            r"\Microsoft\Windows\Customer Experience Improvement Program\Uploader",
        ]));
        rec(tasks_best_effort(&[
            r"\Microsoft\Windows\Application Experience\MareBackup",
            r"\Microsoft\Windows\ExploitGuard\ExploitGuard MDM policy Refresh",
            r"\Microsoft\Windows\Printing\EduPrintProv",
            r"\Microsoft\Windows\Printing\PrintJobCleanupTask",
            r"\Microsoft\Windows\Printing\PrinterCleanupTask",
            r"\Microsoft\Windows\AppxDeploymentClient\UCPD velocity",
            r"\Microsoft\Windows\Server Manager\ServerManager",
            r"\Microsoft\Windows\UpdateOrchestrator\Schedule Scan",
            r"\Microsoft\Windows\UpdateOrchestrator\Schedule Scan Static Task",
            r"\Microsoft\Windows\WindowsAI\ClickToDo\ModelCachingIdle",
            r"\Microsoft\Windows\WindowsAI\ClickToDo\ModelCachingLimit",
            r"\Microsoft\Windows\WindowsAI\ClickToDo\ModelCachingUpdate",
        ]));
        log("  Enabling Edge Update tasks (wildcard)");
        rec(xos_sys::enable_scheduled_tasks_by_name_prefix(&[
            "MicrosoftEdgeUpdateTaskMachineCore".to_string(),
            "MicrosoftEdgeUpdateTaskMachineUA".to_string(),
        ]));
        log("  Restoring captured task states");
        let captured_task_states_job = s.spawn(|| job(u::restore_captured_task_states));
        rec(u::uninstall_reg_del_key(
            r"HKLM\SOFTWARE\XOSToolkit\UpdateTaskBackup",
        ));
        log("--- BCD AND VOLUME LABEL ---");
        u::uninstall_log_run_ti(
            "bcdedit deletevalue disabledynamictick",
            "bcdedit.exe",
            "/deletevalue disabledynamictick",
            false,
        );
        rec(u::restore_xos_boot_description_and_volume_label());
        log("--- CLEANUP XOS ARTIFACTS ---");
        for xos_task in ["XOS-DefenderDisable", "XOSLogonFix"] {
            if xos_sys::get_task_state(&format!(r"\{xos_task}")) < 0 {
                log(&format!("  {xos_task} task not present; nothing to delete"));
            } else {
                u::uninstall_log_run_ti(
                    &format!("schtasks delete {xos_task}"),
                    "schtasks.exe",
                    &format!(r#"/delete /tn "\{xos_task}" /f"#),
                    false,
                );
            }
        }
        {
            let xos_dd = xos_sys::expand_environment_variables(r"%windir%\XOS-DD.ps1");
            if Path::new(&xos_dd).is_file() {
                let _ = std::fs::remove_file(&xos_dd);
            }
        }
        {
            let taskbar_bat = xos_sys::expand_environment_variables(
                r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\taskbar.bat",
            );
            if Path::new(&taskbar_bat).is_file() {
                let _ = std::fs::remove_file(&taskbar_bat);
            }
        }
        {
            let feeds_step = xos_sys::expand_environment_variables(
                r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\feeds-home.bat",
            );
            let feeds_step_present = Path::new(&feeds_step).is_file();
            let removed = if feeds_step_present {
                std::fs::remove_file(&feeds_step)
            } else {
                Ok(())
            };
            match removed {
                Ok(()) => log(&format!(
                    "  DEL [feeds-home.bat]: {}  OK",
                    if feeds_step_present {
                        "removed from the Startup folder"
                    } else {
                        "not present"
                    }
                )),
                Err(e) => log(&format!("  DEL [feeds-home.bat] FAILED: {e}")),
            }
        }
        {
            let default_profile = xos_sys::reg_get_string(
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList",
                "Default",
            );
            match default_profile.filter(|p| !p.is_empty()) {
                Some(profile) => {
                    let default_step = u::path_combine(&xos_sys::expand_environment_variables(&profile), r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\feeds-home.bat");
                    let present = Path::new(&default_step).is_file();
                    let removed = if present { std::fs::remove_file(&default_step) } else { Ok(()) };
                    match removed {
                        Ok(()) => log(&format!("  DEL [feeds-home.bat]: {}  OK", if present { "removed from the Default user profile" } else { "not present in the Default user profile" })),
                        Err(e) => log(&format!("  DEL [feeds-home.bat] in the Default user profile FAILED: {e}")),
                    }
                }
                None => log("  DEL [feeds-home.bat] in the Default user profile SKIPPED: the Default profile path could not be read"),
            }
        }
        let captured_task_states_restored = join(captured_task_states_job);
        rec(captured_task_states_restored);
        log("  Scheduled tasks re-enable done");
        log("--- WINDOWS DEFENDER ---");
        rec(u::restore_defender_compatibility());
        log("--- GAME BAR / GAME MODE / FSE / FSO ---");
        for v in ["ShowStartupPanel", "UseNexusForGameBarEnabled"] {
            del(r"HKCU\Software\Microsoft\GameBar", v);
        }
        set(r"HKCU\Software\Microsoft\GameBar", "AutoGameModeEnabled", 1);
        set(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR",
            "AppCaptureEnabled",
            1,
        );
        set(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR",
            "GameDVR_Enabled",
            1,
        );
        del(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR",
            "AudioCaptureEnabled",
        );
        del(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR",
            "CursorCaptureEnabled",
        );
        for v in [
            "GameDVR_DSEBehavior",
            "GameDVR_FSEBehavior",
            "GameDVR_FSEBehaviorMode",
            "GameDVR_DXGIHonorFSEWindowsCompatible",
            "GameDVR_EFSEFeatureFlags",
            "GameDVR_HonorUserFSEBehaviorMode",
            "GameDVR_Enabled",
        ] {
            del(r"HKCU\System\GameConfigStore", v);
        }
        del(
            r"HKLM\Software\Policies\Microsoft\Windows\GameDVR",
            "AllowGameDVR",
        );
        del(
            r"HKLM\Software\Policies\Microsoft\Windows\GameDVR",
            "AllowAutoGameMode",
        );
        for exe in [
            "GameBarPresenceWriter.exe",
            "bcastdvr.exe",
            "GamePanel.exe",
            "GameBar.exe",
            "GameBarFTServer.exe",
            "GameBarFT.exe",
            "XboxGameBarWidgets.exe",
        ] {
            delkey(&format!(
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{exe}"
            ));
        }
        log("--- WINDOWS SEARCH ---");
        let windows_search_restored = xos_sys::enable_windows_search();
        log(&format!(
            "  Toolkit Windows Search enable sequence: {}",
            if windows_search_restored {
                "OK"
            } else {
                "FAILED"
            }
        ));
        rec(windows_search_restored);
        log("--- SEARCH INIT TASK ---");
        let search_init_needed = !windows_search_restored;
        if search_init_needed {
            let batch_content: &str = concat!("@echo off\r\n", "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\WSearch\" /v Start /t REG_DWORD /d 2 /f 2>nul\r\n", "sc config WSearch start= delayed-auto\r\n", "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\WSearch\" /v DelayedAutoStart /t REG_DWORD /d 1 /f\r\n", "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows Search\" /v SetupCompletedSuccessfully /t REG_DWORD /d 1 /f\r\n", "reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\SearchApp.exe\" /v Debugger /f 2>nul\r\n", "reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\SearchUI.exe\" /v Debugger /f 2>nul\r\n", "reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\SearchHost.exe\" /v Debugger /f 2>nul\r\n", "reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Search\" /v SearchboxTaskbarMode /t REG_DWORD /d 1 /f\r\n", "if exist \"%windir%\\SystemApps\\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\\SearchHost.exe.bak\" if not exist \"%windir%\\SystemApps\\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\\SearchHost.exe\" move /Y \"%windir%\\SystemApps\\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\\SearchHost.exe.bak\" \"%windir%\\SystemApps\\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\\SearchHost.exe\"\r\n", "sc start WSearch\r\n", "schtasks /delete /tn \"XOS Search Init\" /f\r\n", "del \"%~f0\"\r\n");
            let batch_path = r"C:\Windows\Temp\xos_search_init.bat";
            match std::fs::write(batch_path, batch_content.as_bytes()) {
                Ok(()) => {
                    rec(xos_sys::run_cmd(
                        "schtasks.exe",
                        concat!(
                            "/create /tn \"XOS Search Init\" /sc ONLOGON /rl HIGHEST /f ",
                            "/tr \"cmd.exe /c C:\\Windows\\Temp\\xos_search_init.bat\""
                        ),
                    ));
                    log("  Search init task registered, will run at next logon and self-delete");
                }
                Err(e) => log(&format!(
                    "  WARNING: Could not register search init task: {e}"
                )),
            }
        } else {
            log("  Windows Search enable sequence completed. No fallback task was created.");
        }
        rec(u::restore_settings_page_visibility());
        log("--- DETERMINISTIC XOS LEFTOVERS ---");
        rec(u::restore_deterministic_xos_leftovers());
        log("--- WINDOWS REGISTRY DEFAULTS ---");
        rec(u::restore_windows_registry_defaults());
        log("--- POST-STATE ---");
        log(&format!(
            "  WinDefend Start: {}",
            xos_sys::get_service_start_type("WinDefend")
        ));
        log(&format!(
            "  TamperProtection: {}",
            opt(xos_sys::reg_get_dword(
                r"HKLM\SOFTWARE\Microsoft\Windows Defender\Features",
                "TamperProtection"
            ))
        ));
        log(&format!(
            "  DisableAntiSpyware (Policy): {}",
            opt(xos_sys::reg_get_dword(
                r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender",
                "DisableAntiSpyware"
            ))
        ));
        log(&format!(
            "  DisableRealtimeMonitoring: {}",
            opt(xos_sys::reg_get_dword(
                r"HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection",
                "DisableRealtimeMonitoring"
            ))
        ));
        log(&format!(
            "  UAC EnableLUA: {}",
            opt(xos_sys::reg_get_dword(
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                "EnableLUA"
            ))
        ));
        log(&format!(
            "  PassiveMode: {}",
            opt(xos_sys::reg_get_dword(
                r"HKLM\SOFTWARE\Microsoft\Windows Defender",
                "PassiveMode"
            ))
        ));
        log("--- POST-STATE: SEARCH ---");
        query(r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search");
        query(r"HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings");
        query(r"HKLM\SOFTWARE\Microsoft\Windows Search");
        query(r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search");
        log(&format!(
            "  WSearch Start:         {}",
            xos_sys::get_service_start_type("WSearch")
        ));
        log(&format!(
            "  WSearch Status:        {}",
            u::get_service_runtime_state("WSearch")
        ));
        log(&format!(
            "  WSearch DelayedAuto:   {}",
            opt(xos_sys::reg_get_dword(
                r"HKLM\SYSTEM\CurrentControlSet\Services\WSearch",
                "DelayedAutoStart"
            ))
        ));
        for exe in ["SearchApp.exe", "SearchUI.exe", "SearchHost.exe"] {
            let debugger = xos_sys::reg_get_string(
                &format!(
                    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{exe}"
                ),
                "Debugger",
            );
            log(&format!(
                "  IFEO {exe} Debugger: {}",
                debugger.unwrap_or_else(|| "(not set)".to_string())
            ));
        }
        log(&format!(
            "  SearchHost.exe exists: {}",
            tf(Path::new(&search_host_exe).is_file())
        ));
        log(&format!(
            "  SearchHost.exe.bak exists: {}",
            tf(Path::new(&format!("{search_host_exe}.bak")).is_file())
        ));
        let compatibility_restored = u::verify_compatibility_restore(
            toolkit_service_defaults_restored,
            windows_search_restored,
            optional_features_restored,
            process_mitigations_restored,
        );
        rec(compatibility_restored);
        xos_core::log::log(&format!(
            "[Uninstall] Compatibility verification: {}",
            if compatibility_restored {
                "PASSED"
            } else {
                "FAILED"
            }
        ));
        if xos_winupdate::webview2::is_edge_removal_requested() {
            log("--- PRESERVE EXPLICIT EDGE REMOVAL ---");
            let preserved = xos_winupdate::webview2::preserve_edge_removal_after_uninstall();
            rec(preserved);
            if preserved {
                xos_winupdate::webview2::clear_edge_removal_requested();
            }
            log(if preserved {
                "  Edge and WebView2 removal preference preserved after uninstall"
            } else {
                "  WARNING: explicit Edge removal preference could not be fully preserved"
            });
        }
        log("--- OPEN-SHELL ---");
        uninstall_open_shell();
        log(if compatibility_restored {
            "=== Uninstall XOS complete ==="
        } else {
            "=== Uninstall XOS complete with restore warnings ==="
        });

        compatibility_restored
    })
}

fn program_files_dirs() -> Vec<String> {
    [
        std::env::var("ProgramFiles").unwrap_or_default(),
        std::env::var("ProgramFiles(x86)").unwrap_or_default(),
    ]
    .to_vec()
}

fn is_open_shell_installed() -> bool {
    let program_files = std::env::var("ProgramFiles").unwrap_or_default();
    let program_files_x86 = std::env::var("ProgramFiles(x86)").unwrap_or_default();
    xos_sys::reg_key_exists(r"HKLM\SOFTWARE\OpenShell\OpenShell")
        || xos_sys::reg_key_exists(r"HKLM\SOFTWARE\WOW6432Node\OpenShell\OpenShell")
        || Path::new(&u::path_combine(
            &program_files,
            r"Open-Shell\StartMenu.exe",
        ))
        .is_file()
        || Path::new(&u::path_combine(
            &program_files_x86,
            r"Open-Shell\StartMenu.exe",
        ))
        .is_file()
}

fn find_open_shell_product_code() -> Option<String> {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    for root in [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ] {
        let Ok(rk) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(root, KEY_READ)
        else {
            continue;
        };
        for sub in rk.enum_keys().filter_map(|r| r.ok()) {
            let Ok(k) = rk.open_subkey_with_flags(&sub, KEY_READ) else {
                continue;
            };
            let Ok(name) = k.get_value::<String, _>("DisplayName") else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            let lower = name.to_lowercase();
            if (lower.contains("open-shell") || lower.contains("classic shell"))
                && sub.starts_with('{')
                && sub.ends_with('}')
            {
                return Some(sub);
            }
        }
    }
    None
}

fn uninstall_open_shell() {
    if xos_sys::reg_get_dword(r"HKLM\SOFTWARE\XOSToolkit", "OpenShellInstalledByXos") != Some(1) {
        log("  Open Shell was not installed by XOS, left untouched");
        return;
    }
    if let Some(choco) = xos_sys::get_choco_path().filter(|c| !c.is_empty()) {
        let _operation = xos_sys::enter_chocolatey_operation();
        let (code, _, _) =
            xos_sys::run_cmd_capture_opts(&choco, "uninstall open-shell -y", 300000, false);
        log(&format!(
            "  Chocolatey Open-Shell uninstall exit code: {code}"
        ));
    }

    if is_open_shell_installed() {
        match find_open_shell_product_code() {
            Some(product_code) => {
                log(&format!("  Open-Shell ProductCode: {product_code}"));
                let (code, _, _) = xos_sys::run_cmd_capture_opts(
                    "msiexec.exe",
                    &format!("/x {product_code} /qn /norestart"),
                    120000,
                    false,
                );
                log(&format!("  msiexec /x exit code: {code}"));
            }
            None => log("  Open-Shell not found in Uninstall registry (skipping MSI removal)"),
        }
    }

    for name in [
        "StartMenu",
        "ClassicStartMenu",
        "Open-Shell-Menu",
        "StartMenuHelper",
    ] {
        procs::kill_and_wait(name, 3000);
    }

    delkey(r"HKCU\Software\OpenShell");
    delkey(r"HKCU\Software\IvoSoft\ClassicStartMenu");
    delkey(r"HKCU\Software\IvoSoft\ClassicExplorer");
    delkey(r"HKLM\Software\OpenShell");
    delkey(r"HKLM\Software\Policies\OpenShell");
    delkey(r"HKLM\Software\IvoSoft\ClassicStartMenu");

    for base_dir in program_files_dirs() {
        if base_dir.is_empty() {
            continue;
        }
        let skin_dir = u::path_combine(&u::path_combine(&base_dir, "Open-Shell"), "Skins");
        for f in ["Fluent-Metro.skin", "Fluent-Metro.skin7"] {
            let path = u::path_combine(&skin_dir, f);
            if Path::new(&path).is_file() {
                match std::fs::remove_file(&path) {
                    Ok(()) => log(&format!("  Deleted skin: {path}")),
                    Err(e) => {
                        rec(false);
                        log(&format!("  Skin delete FAILED ({f}): {e}"));
                    }
                }
            }
        }
    }

    let package_removed = !is_open_shell_installed();
    rec(package_removed);
    log(if package_removed {
        "  Open-Shell package is absent after uninstall"
    } else {
        "  Open-Shell package is still present after uninstall"
    });

    let smeh_dir = u::path_combine(
        &u::windows_directory(),
        r"SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy",
    );
    let smeh_exe = u::path_combine(&smeh_dir, "StartMenuExperienceHost.exe");
    let smeh_old = u::path_combine(&smeh_dir, "StartMenuExperienceHost.exe.old");
    if Path::new(&smeh_old).is_file() && !Path::new(&smeh_exe).is_file() {
        let restored = xos_sys::run_as_ti(
            "cmd.exe",
            &format!("/c ren \"{smeh_old}\" \"StartMenuExperienceHost.exe\""),
        ) && Path::new(&smeh_exe).is_file();
        rec(restored);
        log(if restored {
            "  StartMenuExperienceHost.exe restored from .old"
        } else {
            "  StartMenuExperienceHost.exe restore FAILED"
        });
    }

    let reregister_script: &str = REREGISTER_SCRIPT;
    let reregister_encoded = u::encode_power_shell_command(reregister_script);
    let reregistered = xos_sys::run_as_ti(
        "powershell.exe",
        &format!("-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {reregister_encoded}"),
    );
    rec(reregistered);
    log(&format!(
        "  Start menu package re-registered: {}",
        if reregistered { "OK" } else { "FAILED" }
    ));

    procs::kill_and_wait("explorer", 5000);
    let mut running = false;
    let mut attempt = 0;
    while attempt < 10 && !running {
        std::thread::sleep(std::time::Duration::from_millis(500));
        running = procs::process_running("explorer");
        attempt += 1;
    }
    if !running {
        log("  Explorer did not restart on its own, starting it");
        match xos_sys::shell_start("explorer.exe", "") {
            true => {
                let mut attempt = 0;
                while attempt < 10 && !running {
                    std::thread::sleep(std::time::Duration::from_millis(500));
                    running = procs::process_running("explorer");
                    attempt += 1;
                }
            }
            false => log(&format!("  Explorer start FAILED: {}", std::io::Error::last_os_error())),
        }
    }
    log(if running {
        "  Explorer is running; sign out and back in if the Start menu does not open"
    } else {
        "  Explorer still not running; sign out and back in to restore the shell"
    });
    rec(running);

    if package_removed {
        del(r"HKLM\SOFTWARE\XOSToolkit", "OpenShellInstalledByXos");
    }
}

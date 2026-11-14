mod amd;
mod logic;

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use xos_core::host::{Buttons, DialogResult, Host, Icon, Page};
use xos_core::ui::*;
use xos_core::{app_state, log, status};

use logic::*;

const KEY_GAME_BAR: &str = r"HKCU\Software\Microsoft\GameBar";
const KEY_GAME_DVR: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR";
const KEY_GAME_CFG: &str = r"HKCU\System\GameConfigStore";
const KEY_POLICY: &str = r"HKLM\Software\Policies\Microsoft\Windows\GameDVR";
const KEY_HAGS: &str = r"HKLM\System\CurrentControlSet\Control\GraphicsDrivers";
const KEY_DWM: &str = r"HKLM\Software\Microsoft\Windows\Dwm";
const KEY_IFEO: &str =
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
const KEY_MM_PROFILE: &str =
    r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile";
const KEY_GAMES: &str =
    r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games";
const KEY_DIRECTX: &str = r"HKCU\Software\Microsoft\DirectX\UserGpuPreferences";
const KEY_MON_STORE: &str =
    r"HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\MonitorDataStore";

const DX_VALUE: &str = "DirectXUserGlobalSettings";

const GAME_BAR_EXES: [&str; 7] = [
    "GameBarPresenceWriter.exe",
    "bcastdvr.exe",
    "GamePanel.exe",
    "GameBar.exe",
    "GameBarFTServer.exe",
    "GameBarFT.exe",
    "XboxGameBarWidgets.exe",
];

const FSE_VALUES: [&str; 7] = [
    "GameDVR_DSEBehavior",
    "GameDVR_FSEBehavior",
    "GameDVR_FSEBehaviorMode",
    "GameDVR_DXGIHonorFSEWindowsCompatible",
    "GameDVR_EFSEFeatureFlags",
    "GameDVR_HonorUserFSEBehaviorMode",
    "GameDVR_Enabled",
];

fn get_dx_token(token: &str) -> Option<String> {
    dx_get_token(
        xos_sys::reg_get_string(KEY_DIRECTX, DX_VALUE).as_deref(),
        token,
    )
}

fn set_dx_token(token: &str, value: &str) {
    let current = xos_sys::reg_get_string(KEY_DIRECTX, DX_VALUE).unwrap_or_default();
    xos_sys::reg_set_string(KEY_DIRECTX, DX_VALUE, &dx_set_token(&current, token, value));
}

struct Snapshot {
    badges: HashMap<&'static str, Badge>,
    flip: bool,
    hags: bool,
    vrr: bool,
    hdr: bool,
    color: bool,
    amd: bool,
    nvidia: bool,
}

struct State {
    snap: Snapshot,
    busy: Option<String>,
}

pub struct GamingPage {
    st: Mutex<State>,
}

impl Default for GamingPage {
    fn default() -> Self {
        Self::new()
    }
}

pub fn pages() -> Vec<Arc<dyn Page>> {
    vec![Arc::new(GamingPage::new())]
}

fn initial_badges() -> HashMap<&'static str, Badge> {
    let mut m = HashMap::new();
    m.insert("gb", Badge::new("Game Bar: Checking", Tone::Neutral));
    m.insert(
        "fso",
        Badge::new("Full Screen Optimizations: Checking", Tone::Neutral),
    );
    m
}

fn set_badge(
    m: &mut HashMap<&'static str, Badge>,
    key: &'static str,
    state: &str,
    detail: Option<&str>,
) {
    m.insert(key, status::badge_with(state, detail));
}

impl GamingPage {
    pub fn new() -> Self {
        Self {
            st: Mutex::new(State {
                snap: Snapshot {
                    badges: initial_badges(),
                    flip: false,
                    hags: false,
                    vrr: false,
                    hdr: false,
                    color: false,
                    amd: false,
                    nvidia: false,
                },
                busy: None,
            }),
        }
    }

    fn read_snapshot() -> Snapshot {
        let mut b: HashMap<&'static str, Badge> = HashMap::new();
        let rd = xos_sys::reg_get_dword;

        let app_capture = rd(KEY_GAME_DVR, "AppCaptureEnabled");
        let game_dvr_enabled = rd(KEY_GAME_DVR, "GameDVR_Enabled");
        let audio_capture = rd(KEY_GAME_DVR, "AudioCaptureEnabled");
        let cursor_capture = rd(KEY_GAME_DVR, "CursorCaptureEnabled");
        let game_dvr_policy = rd(KEY_POLICY, "AllowGameDVR");
        let mut ifeo_count = 0usize;
        for exe in GAME_BAR_EXES {
            if xos_sys::reg_get_string(&format!(r"{KEY_IFEO}\{exe}"), "Debugger").is_some() {
                ifeo_count += 1;
            }
        }
        let gb = game_bar_state(&GameBarInputs {
            app_capture,
            game_dvr_enabled,
            audio_capture,
            cursor_capture,
            game_dvr_policy,
            game_mode: rd(KEY_GAME_BAR, "AllowAutoGameMode"),
            auto_mode: rd(KEY_GAME_BAR, "AutoGameModeEnabled"),
            startup_panel: rd(KEY_GAME_BAR, "ShowStartupPanel"),
            nexus: rd(KEY_GAME_BAR, "UseNexusForGameBarEnabled"),
            ifeo_count,
            exe_count: GAME_BAR_EXES.len(),
        });
        let text = format!("Game Bar: {}", gb.state);
        let tone = if gb.disabled {
            Tone::Red
        } else if gb.enabled {
            Tone::Green
        } else {
            Tone::Neutral
        };
        b.insert(
            "gb",
            Badge::new(text.clone(), tone).tooltip(status::description(&text)),
        );

        let cfg = |n: &str| rd(KEY_GAME_CFG, n);
        let (fso_state, fso_detail) = fso_state(&FsoInputs {
            dse_behavior: cfg("GameDVR_DSEBehavior"),
            fse_behavior: cfg("GameDVR_FSEBehavior"),
            fse_mode: cfg("GameDVR_FSEBehaviorMode"),
            dxgi_honor: cfg("GameDVR_DXGIHonorFSEWindowsCompatible"),
            efse_flags: cfg("GameDVR_EFSEFeatureFlags"),
            honor_user: cfg("GameDVR_HonorUserFSEBehaviorMode"),
            config_dvr: cfg("GameDVR_Enabled"),
        });
        b.insert(
            "fso",
            Badge::new(
                format!("Full Screen Optimizations: {fso_state}"),
                status::tone_for(&fso_state),
            )
            .tooltip(format!("Full Screen Optimizations: {fso_detail}")),
        );

        let build = xos_sys::get_windows_build_number();
        let hags = build >= 19041;
        if hags {
            let v = rd(KEY_HAGS, "HwSchMode");
            set_badge(&mut b, "hags", &status::toggle_with(v, 2, 1, "N/A"), None);
        }

        let svc = xos_sys::get_service_start_type;
        let pca = svc("PcaSvc");
        let diag = svc("DiagTrack");
        let sysmain = svc("SysMain");
        let dps = svc("DPS");
        let evt = svc("EventLog");
        set_badge(
            &mut b,
            "fivem",
            &fivem_state(pca, diag, sysmain, dps, evt),
            None,
        );

        let amd_paths = xos_sys::find_amd_gpu_reg_paths();
        let amd = !amd_paths.is_empty();
        if amd {
            let (state, detail) = amd::card_state(&amd_paths);
            set_badge(&mut b, "amd", &state, Some(&detail));
        }
        let nvidia = xos_sys::has_nvidia_gpu();

        let overlay_test_mode = rd(KEY_DWM, "OverlayTestMode");
        set_badge(
            &mut b,
            "mpo",
            match overlay_test_mode {
                None => status::ENABLED_WINDOWS_DEFAULT,
                Some(5) => "Disabled",
                Some(_) => "Partial",
            },
            None,
        );

        set_badge(
            &mut b,
            "sysresp",
            &status::toggle_with(rd(KEY_MM_PROFILE, "SystemResponsiveness"), 10, 20, "N/A"),
            None,
        );
        set_badge(
            &mut b,
            "cpuprio",
            &status::toggle_with(rd(KEY_GAMES, "Priority"), 6, 2, "N/A"),
            None,
        );
        let sched = xos_sys::reg_get_string(KEY_GAMES, "Scheduling Category");
        set_badge(
            &mut b,
            "schedcat",
            &status::toggle_str_with(sched.as_deref(), "High", "Medium", "N/A"),
            None,
        );
        set_badge(
            &mut b,
            "gpuprio",
            &status::toggle_with(rd(KEY_GAMES, "GPU Priority"), 8, 2, "N/A"),
            None,
        );

        let flip = build >= 22000;
        if flip {
            set_badge(
                &mut b,
                "flip",
                &status::toggle_str(get_dx_token("SwapEffectUpgradeEnable").as_deref()),
                None,
            );
        }
        let vrr = build >= 19041;
        if vrr {
            set_badge(
                &mut b,
                "vrr",
                &status::toggle_str(get_dx_token("VRROptimizeEnable").as_deref()),
                None,
            );
        }
        let hdr = build >= 22000;
        if hdr {
            set_badge(
                &mut b,
                "hdr",
                &status::toggle_str_with(
                    get_dx_token("AutoHDREnable").as_deref(),
                    "1",
                    "0",
                    status::WINDOWS_DEFAULT,
                ),
                None,
            );
        }
        let color = build >= 26200;
        if color {
            let monitors = xos_sys::reg_enum_sub_keys(KEY_MON_STORE);
            if monitors.is_empty() {
                set_badge(&mut b, "color", status::ENABLED_WINDOWS_DEFAULT, None);
            } else {
                let values: Vec<String> = monitors
                    .iter()
                    .map(|mon| {
                        status::toggle_with(
                            rd(
                                &format!(r"{KEY_MON_STORE}\{mon}"),
                                "AutoColorManagementEnabled",
                            ),
                            1,
                            0,
                            status::ENABLED_WINDOWS_DEFAULT,
                        )
                    })
                    .collect();
                set_badge(&mut b, "color", &status::combine(&values), None);
            }
        }

        let disable_overlays = rd(KEY_HAGS, "DisableOverlays");
        set_badge(
            &mut b,
            "hwoverlay",
            match disable_overlays {
                None => status::ENABLED_WINDOWS_DEFAULT,
                Some(0) => "Enabled",
                Some(1) => "Disabled",
                Some(_) => "Partial",
            },
            None,
        );

        let min_fps = rd(KEY_DWM, "OverlayMinFPS");
        set_badge(
            &mut b,
            "mpominfps",
            match min_fps {
                None => status::ENABLED_WINDOWS_DEFAULT,
                Some(0) => "Disabled",
                Some(n) if n > 0 => "Enabled",
                Some(_) => "Partial",
            },
            None,
        );

        Snapshot {
            badges: b,
            flip,
            hags,
            vrr,
            hdr,
            color,
            amd,
            nvidia,
        }
    }

    fn refresh_states(&self) {
        let snap = Self::read_snapshot();
        let mut st = self.st.lock().unwrap();
        let mut merged = initial_badges();
        merged.extend(snap.badges.iter().map(|(k, v)| (*k, v.clone())));
        st.snap = Snapshot {
            badges: merged,
            ..snap
        };
    }

    fn done(
        &self,
        host: &dyn Host,
        msg: &str,
        operation_failed: bool,
        read_back_problem: Option<String>,
    ) {
        let failed = xos_sys::ops::any_failed() || operation_failed || read_back_problem.is_some();
        log::action_done(
            "Gaming",
            operation_failed,
            failed,
            read_back_problem.as_deref(),
        );
        xos_sys::ops::reset();
        app_state::require_reboot_if_message_asks(msg);
        host.set_status(msg);
        let mut text = msg.to_string();
        if read_back_problem.is_some() {
            text.push_str("\n\nNote: some values did not read back as written, so the driver or another program may be changing them. The card's tooltip lists them.");
        } else if failed {
            text.push_str("\n\nNote: one or more settings could not be written (often a permissions issue). Try again.");
        }
        host.dialog(
            &text,
            "XOS Toolkit",
            Buttons::Ok,
            if failed {
                Icon::Warning
            } else {
                Icon::Information
            },
        );
    }

    fn simple(&self, host: &dyn Host, action: impl FnOnce(), msg: &str) {
        xos_sys::ops::reset();
        action();
        self.refresh_states();
        self.done(host, msg, false, None);
    }

    fn set_busy(&self, host: &dyn Host, busy: bool, message: Option<&str>) {
        {
            let mut st = self.st.lock().unwrap();
            if busy {
                st.busy = Some(message.unwrap_or("Applying...").to_string());
            } else {
                st.busy = None;
            }
        }
        if let (true, Some(m)) = (busy, message) {
            host.set_status(m);
        }
        host.publish(self.model());
    }

    fn apply_auto_color(&self, host: &dyn Host, value: i32) {
        xos_sys::ops::reset();
        let monitors = xos_sys::reg_enum_sub_keys(KEY_MON_STORE);
        if monitors.is_empty() {
            host.warn(
                "No display profiles were found to update. Connect your monitor and try again.",
                "XOS Toolkit",
            );
            return;
        }
        for mon in &monitors {
            xos_sys::reg_set_dword(
                &format!(r"{KEY_MON_STORE}\{mon}"),
                "AutoColorManagementEnabled",
                value,
            );
        }
        self.refresh_states();
        self.done(
            host,
            if value == 1 {
                "Automatic color management enabled for all displays. Please restart your PC."
            } else {
                "Automatic color management disabled for all displays. Please restart your PC."
            },
            false,
            None,
        );
    }

    fn hw_overlay_disable(&self, host: &dyn Host) {
        xos_sys::ops::reset();
        let result = host.dialog(
            "Disabling hardware overlays forces software composition and is known to break the Steam, Discord, and RTSS in-game overlays.\n\nDisable anyway?",
            "XOS Toolkit",
            Buttons::YesNo,
            Icon::Warning,
        );
        if result != DialogResult::Yes {
            return;
        }
        xos_sys::reg_set_dword(KEY_HAGS, "DisableOverlays", 1);
        self.refresh_states();
        self.done(
            host,
            "Hardware overlays disabled. Please restart your PC.",
            false,
            None,
        );
    }

    fn fivem_enable(&self, host: &dyn Host) {
        xos_sys::ops::reset();
        self.set_busy(host, true, Some("Enabling FiveM services..."));
        let result: anyhow::Result<()> = (|| {
            let failed = std::sync::atomic::AtomicBool::new(false);
            let pca_delayed = xos_helpers::service_defaults_table::is_delayed_auto_start(
                "PcaSvc",
                xos_sys::get_windows_build_number(),
            );
            let mark = |name: &str, op: &dyn Fn() -> bool| {
                if xos_sys::service_exists(name) && !op() {
                    failed.store(true, std::sync::atomic::Ordering::SeqCst);
                }
            };
            std::thread::scope(|s| {
                s.spawn(|| {
                    mark("PcaSvc", &|| {
                        xos_sys::config_service_sc(
                            "PcaSvc",
                            if pca_delayed { "delayed-auto" } else { "auto" },
                        ) && (!pca_delayed
                            || xos_sys::get_service_delayed_auto_start("PcaSvc") == 1)
                    })
                });
                for name in ["DPS", "DiagTrack", "SysMain", "EventLog"] {
                    let mark = &mark;
                    s.spawn(move || mark(name, &|| xos_sys::config_service_sc(name, "auto")));
                }
            });
            if failed.load(std::sync::atomic::Ordering::SeqCst) {
                anyhow::bail!("One or more required FiveM services could not be enabled.");
            }
            Ok(())
        })();
        match result {
            Ok(()) => {
                self.refresh_states();
                self.done(host, "FiveM services enabled. Please reboot.", false, None);
            }
            Err(ex) => {
                log::log_exception("FiveM service enable failed", &ex);
                host.error(
                    &format!("FiveM services could not be enabled.\n\n{ex}"),
                    "XOS Toolkit",
                );
            }
        }
        self.set_busy(host, false, None);
    }

    fn fivem_disable(&self, host: &dyn Host) {
        xos_sys::ops::reset();
        let mut ok = true;
        for name in ["PcaSvc", "DiagTrack", "SysMain"] {
            if xos_sys::service_exists(name) {
                ok &= xos_sys::config_service_sc(name, "disabled");
            }
        }
        let graphics = xos_sys::get_service_start_type("GraphicsPerfSvc");
        let ndu = xos_sys::get_service_start_type("Ndu");
        let usage = xos_sys::get_service_start_type("WdiServiceHost");
        let gpu_deps = (graphics >= 0 && graphics != 4) || (ndu >= 0 && ndu != 4);
        let usage_deps = usage >= 0 && usage != 4;
        let mut keep_dps = false;
        if gpu_deps || usage_deps {
            let dep_list = if gpu_deps && usage_deps {
                "GPU & Network Monitoring and System Usage & Diagnostics Reporting"
            } else if gpu_deps {
                "GPU & Network Monitoring"
            } else {
                "System Usage & Diagnostics Reporting"
            };
            let result = host.dialog(
                &format!(
                    "The Diagnostic Policy Service (DPS) is also required by {dep_list}.\n\nWould you like to keep DPS enabled?"
                ),
                "XOS Toolkit",
                Buttons::YesNo,
                Icon::Question,
            );
            keep_dps = result == DialogResult::Yes;
        }
        if !keep_dps {
            ok &= !xos_sys::service_exists("DPS") || xos_sys::config_service_sc("DPS", "disabled");
        }
        self.refresh_states();
        self.done(host, "FiveM services disabled. Please reboot.", !ok, None);
    }

    fn launch_nvidia(&self, host: &dyn Host, nip_name: &str, status_text: &str, log_context: &str) {
        xos_sys::ops::reset();
        let dir = match xos_sys::ensure_nvidia_profile_inspector() {
            Ok(d) => d,
            Err(_) => {
                host.info("Failed to extract NVIDIA Profile Inspector.", "Error");
                return;
            }
        };
        let exe = Path::new(&dir).join("nvidiaProfileInspector.exe");
        let nip = Path::new(&dir).join(nip_name);
        match shell_launch(
            &exe.to_string_lossy(),
            &format!("\"{}\"", nip.to_string_lossy()),
            &dir,
        ) {
            Ok(()) => host.set_status(status_text),
            Err(ex) => {
                log::log_exception(log_context, &ex);
                host.error(
                    &format!("NVIDIA Profile Inspector could not be launched.\n\n{ex}"),
                    "XOS Toolkit",
                );
            }
        }
    }

    fn amd_apply(&self, host: &dyn Host, experimental: bool) {
        xos_sys::ops::reset();
        let paths = xos_sys::find_amd_gpu_reg_paths();
        if paths.is_empty() {
            host.info("No AMD GPU detected. Aborting.", "Error");
            return;
        }
        if !amd::backup_amd_service_starts() {
            host.error(
                "The current AMD service configuration could not be backed up. No changes were made.",
                "XOS Toolkit",
            );
            return;
        }
        for p in &paths {
            amd::apply_amd_safe(p);
            if experimental {
                amd::apply_amd_experimental_extra(p);
            }
        }
        let services_ok = amd::set_amd_services(4);
        xos_sys::reg_set_dword(r"HKLM\SOFTWARE\Microsoft\Windows\Dwm", "OverlayTestMode", 5);
        self.refresh_states();
        self.done(
            host,
            if experimental {
                "AMD experimental tweaks applied. Please restart your PC."
            } else {
                "AMD safe tweaks applied. Please restart your PC."
            },
            !services_ok,
            amd::amd_read_back_problem(&paths, experimental),
        );
    }

    fn amd_revert(&self, host: &dyn Host) {
        xos_sys::ops::reset();
        let paths = xos_sys::find_amd_gpu_reg_paths();
        if paths.is_empty() {
            host.info("No AMD GPU detected.", "Error");
            return;
        }
        for t in &paths {
            let stock = amd::stock_for(t);
            for v in amd::revert_values(stock.is_some()) {
                amd::restore_amd_stock(t, v, &stock);
            }
        }
        let services_ok = amd::restore_amd_services();
        xos_sys::reg_delete_value(r"HKLM\SOFTWARE\Microsoft\Windows\Dwm", "OverlayTestMode");
        self.refresh_states();
        self.done(
            host,
            "AMD GPU tweaks reverted. Please restart your PC.",
            !services_ok,
            None,
        );
    }
}

fn apply_game_bar_disable() {
    for n in [
        "AllowAutoGameMode",
        "AutoGameModeEnabled",
        "ShowStartupPanel",
        "UseNexusForGameBarEnabled",
    ] {
        xos_sys::reg_set_dword(KEY_GAME_BAR, n, 0);
    }
    for n in [
        "AppCaptureEnabled",
        "AudioCaptureEnabled",
        "CursorCaptureEnabled",
        "GameDVR_Enabled",
    ] {
        xos_sys::reg_set_dword(KEY_GAME_DVR, n, 0);
    }
}

fn apply_game_bar_enable() {
    for n in [
        "AllowAutoGameMode",
        "AutoGameModeEnabled",
        "ShowStartupPanel",
        "UseNexusForGameBarEnabled",
    ] {
        xos_sys::reg_delete_value(KEY_GAME_BAR, n);
    }
    xos_sys::reg_set_dword(KEY_GAME_DVR, "AppCaptureEnabled", 1);
    xos_sys::reg_delete_value(KEY_GAME_DVR, "AudioCaptureEnabled");
    xos_sys::reg_delete_value(KEY_GAME_DVR, "CursorCaptureEnabled");
    xos_sys::reg_set_dword(KEY_GAME_DVR, "GameDVR_Enabled", 1);
}

fn apply_fse_force() {
    for (n, v) in [
        ("GameDVR_DSEBehavior", 2),
        ("GameDVR_FSEBehavior", 2),
        ("GameDVR_FSEBehaviorMode", 2),
        ("GameDVR_DXGIHonorFSEWindowsCompatible", 1),
        ("GameDVR_EFSEFeatureFlags", 0),
        ("GameDVR_HonorUserFSEBehaviorMode", 1),
        ("GameDVR_Enabled", 0),
    ] {
        xos_sys::reg_set_dword(KEY_GAME_CFG, n, v);
    }
}

fn apply_fso_restore() {
    for v in FSE_VALUES {
        xos_sys::reg_delete_value(KEY_GAME_CFG, v);
    }
}

fn apply_policy_disable() {
    xos_sys::reg_set_dword(KEY_POLICY, "AllowGameDVR", 0);
}

fn apply_policy_enable() {
    xos_sys::reg_delete_value(KEY_POLICY, "AllowGameDVR");
}

fn apply_game_bar_ifeo() {
    for exe in GAME_BAR_EXES {
        xos_sys::reg_set_string(
            &format!(r"{KEY_IFEO}\{exe}"),
            "Debugger",
            r"%SystemRoot%\System32\systray.exe",
        );
    }
}

fn remove_game_bar_ifeo() {
    for exe in GAME_BAR_EXES {
        xos_sys::reg_delete_value(&format!(r"{KEY_IFEO}\{exe}"), "Debugger");
    }
}

fn shell_launch(exe: &str, args: &str, dir: &str) -> Result<(), std::io::Error> {
    use windows::core::PCWSTR;
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    let wide = |s: &str| -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() };
    let (f, a, d) = (wide(exe), wide(args), wide(dir));
    let h = unsafe {
        ShellExecuteW(
            None,
            PCWSTR::null(),
            PCWSTR(f.as_ptr()),
            PCWSTR(a.as_ptr()),
            PCWSTR(d.as_ptr()),
            SW_SHOWNORMAL,
        )
    };
    let code = h.0 as isize;
    if code > 32 {
        Ok(())
    } else {
        Err(std::io::Error::from_raw_os_error(code as i32))
    }
}

fn section(id: &str, title: &str) -> Card {
    Card::new(id, "", "")
        .full_width()
        .not_searchable()
        .controls(vec![Control::heading(title)])
}

impl Page for GamingPage {
    fn id(&self) -> &'static str {
        "Gaming"
    }

    fn label(&self) -> &'static str {
        "Gaming"
    }

    fn model(&self) -> PageModel {
        let st = self.st.lock().unwrap();
        let snap = &st.snap;
        let badge = |k: &str| snap.badges.get(k).cloned().unwrap_or_else(Badge::checking);
        let toggle = |id: &str, title: &str, desc: &str, key: &str, visible: bool| {
            Card::new(id, title, desc)
                .badge(badge(key))
                .visible(visible)
                .actions(vec![
                    Control::button(format!("{id}.enable"), "Enable", BtnStyle::Enable),
                    Control::button(format!("{id}.disable"), "Disable", BtnStyle::Disable),
                ])
        };
        let restore_disable =
            |id: &str, title: &str, desc: &str, key: &str, disable_label: &str| {
                Card::new(id, title, desc).badge(badge(key)).actions(vec![
                    Control::button(
                        format!("{id}.enable"),
                        "Restore Windows Default",
                        BtnStyle::Enable,
                    ),
                    Control::button(format!("{id}.disable"), disable_label, BtnStyle::Disable),
                ])
            };
        let gb = badge("gb");
        let fso = badge("fso");

        PageModel::new(
            "Gaming",
            "Gaming & Performance",
            "Optimize fullscreen behavior, Game Bar, and GPU settings",
        )
        .overlay(st.busy.clone())
        .card(
            Card::new(
                "fse",
                "Game Bar & Full Screen Mode",
                "Full Screen Exclusive (FSE) gives a game direct control of the screen. Full Screen Optimizations (FSO) is the Windows default and makes Alt-Tab faster. Neither is best for every game, so try both. Disabling Game Bar also turns off Game Mode and background game recording.",
            )
            .controls(vec![
                Control::chip(gb.text, gb.tone).tooltip(gb.tooltip),
                Control::chip(fso.text, fso.tone).tooltip(fso.tooltip),
            ])
            .controls(vec![Control::heading("Combined")])
            .actions(vec![
                Control::button("optimize", "Optimize FSE", BtnStyle::Enable),
                Control::button("restore_defaults", "Restore Defaults", BtnStyle::Action),
            ])
            .controls(vec![Control::heading("Individual")])
            .actions(vec![
                Control::button("disable_gamebar", "Disable Game Bar Only", BtnStyle::Disable),
                Control::button("enable_gamebar", "Enable Game Bar Only", BtnStyle::Enable),
                Control::button("force_fse", "Force FSE", BtnStyle::Warning),
                Control::button("enable_fso", "Enable Fullscreen Optimizations", BtnStyle::Action),
            ]),
        )
        .card(toggle(
            "flip",
            "Optimizations for Windowed Games",
            "Lets windowed and borderless games use a faster way to show frames, which lowers input delay. Also needed for Variable Refresh Rate and Auto HDR in those modes. Does not affect exclusive fullscreen games.",
            "flip",
            snap.flip,
        ))
        .card(section("sec.processor", "Processor"))
        .card(toggle(
            "sysresp",
            "System Responsiveness for Games",
            "Windows keeps 20 percent of CPU time for background tasks while games and media apps run. Lowering it to 10 gives more of it to the game. Only affects apps that use the Windows multimedia scheduler, so results vary.",
            "sysresp",
            true,
        ))
        .card(toggle(
            "cpuprio",
            "CPU Priority for Gaming",
            "Raises the CPU priority Windows gives to games from 2 to 6. Only games that use the Windows multimedia scheduler are affected, and most do not. Has no effect while High Scheduling Category below is on. Test it on your own PC.",
            "cpuprio",
            true,
        ))
        .card(toggle(
            "schedcat",
            "High Scheduling Category for Gaming",
            "Puts games that use the Windows multimedia scheduler into the highest priority group, the one made for pro audio. Most games do not use it, and it can help or hurt depending on the game. Test it and turn it off if it does not help.",
            "schedcat",
            true,
        ))
        .card(section("sec.graphics", "Graphics"))
        .card(
            Card::new(
                "hags",
                "Hardware-Accelerated GPU Scheduling (HAGS)",
                "Lets the graphics card manage its own memory and scheduling, which can lower CPU use and input delay. Required for NVIDIA DLSS Frame Generation. Needs Windows 10 22H2 or newer and a supported graphics driver. Requires a restart.",
            )
            .badge(badge("hags"))
            .visible(snap.hags)
            .actions(vec![
                Control::button("hags.enable", "Enable HAGS", BtnStyle::Enable),
                Control::button("hags.disable", "Disable HAGS", BtnStyle::Disable),
            ]),
        )
        .card(toggle(
            "gpuprio",
            "GPU Priority for Gaming",
            "Sets the GPU priority for games in the Windows multimedia scheduler. Microsoft says Windows does not use this value yet, so expect no change.",
            "gpuprio",
            true,
        ))
        .card(toggle(
            "vrr",
            "Variable Refresh Rate",
            "Helps G-Sync or FreeSync work in windowed and borderless games. Does nothing without a monitor that supports G-Sync or FreeSync.",
            "vrr",
            snap.vrr,
        ))
        .card(toggle(
            "hdr",
            "Auto HDR",
            "Makes older games that were not made for HDR look brighter and more colorful. Only works on an HDR display with HDR turned on. Windows 11 only.",
            "hdr",
            snap.hdr,
        ))
        .card(toggle(
            "color",
            "Automatically Manage Color for Apps",
            "Lets Windows manage colors so apps show accurate colors on wide color and HDR displays. Windows 11 only, and only on supported displays. Requires a restart.",
            "color",
            snap.color,
        ))
        .card(restore_disable(
            "hwoverlay",
            "Hardware Overlays",
            "Lets the graphics card show videos and some windows on separate display layers, so Windows has less to draw itself. Keep it on. Turning it off makes Windows draw everything itself, which adds GPU work.",
            "hwoverlay",
            "Disable",
        ))
        .card(restore_disable(
            "mpo",
            "Multiplane Overlay (MPO)",
            "Multiplane Overlay lets the graphics card combine screen layers itself, which saves work for Windows. On some PCs it causes flickering or stutter. Disable it only if you see those problems.",
            "mpo",
            "Disable MPO",
        ))
        .card(restore_disable(
            "mpominfps",
            "MPO Minimum Frame Rate Requirement",
            "Windows moves apps off the overlay layer when their frame rate is low. Turning this rule off can fix stutter in browsers and Discord without disabling MPO. Requires a restart.",
            "mpominfps",
            "Disable",
        ))
        .card(
            Card::new(
                "fivem",
                "FiveM Services",
                "FiveM needs PcaSvc, DPS, DiagTrack, SysMain and EventLog to be running. Enable them here if you play FiveM.",
            )
            .badge(badge("fivem"))
            .actions(vec![
                Control::button("fivem.enable", "Enable FiveM Services", BtnStyle::Enable),
                Control::button("fivem.disable", "Disable FiveM Services", BtnStyle::Disable),
            ]),
        )
        .card(
            Card::new(
                "amd",
                "AMD Radeon GPU Tweaks",
                "For AMD Radeon graphics cards. Safe turns off AMD data collection, Radeon Chill, Radeon Boost, the AMD crash and log services, PCIe power saving and MPO, and clears power saving values that cause stutter. Experimental also forces higher clocks and turns off more power saving. Experimental is not recommended for RX 7000 or RX 9000 cards. Requires a restart.",
            )
            .badge(badge("amd"))
            .visible(snap.amd)
            .actions(vec![
                Control::button("amd.safe", "Safe", BtnStyle::Enable),
                Control::button("amd.experimental", "Experimental", BtnStyle::Warning),
                Control::button("amd.revert", "Revert to Default", BtnStyle::Disable),
            ]),
        )
        .card(
            Card::new(
                "nvidia",
                "NVIDIA Profile Inspector",
                "Opens NVIDIA Profile Inspector with the XOS profile loaded. Click \"Apply changes\" in the tool to apply it to your NVIDIA driver.",
            )
            .visible(snap.nvidia)
            .actions(vec![
                Control::button("nvidia.apply", "Apply XOS.nip", BtnStyle::Enable),
                Control::button("nvidia.revert", "Revert to Default", BtnStyle::Disable),
            ]),
        )
    }

    fn refresh(&self, _host: &dyn Host) {
        self.refresh_states();
    }

    fn handle(&self, host: &dyn Host, event: &Event) {
        if event.kind != EventKind::Click {
            return;
        }
        match event.control.as_str() {
            "optimize" => self.simple(
                host,
                || {
                    apply_game_bar_disable();
                    apply_game_bar_ifeo();
                    apply_fse_force();
                    apply_policy_disable();
                },
                "Gaming optimized: FSE forced, Game Bar disabled.",
            ),
            "restore_defaults" => self.simple(
                host,
                || {
                    apply_game_bar_enable();
                    remove_game_bar_ifeo();
                    apply_fso_restore();
                    apply_policy_enable();
                },
                "Windows defaults restored: FSO + Game Bar enabled.",
            ),
            "disable_gamebar" => self.simple(
                host,
                || {
                    apply_game_bar_disable();
                    apply_game_bar_ifeo();
                    apply_policy_disable();
                },
                "Game Bar disabled.",
            ),
            "enable_gamebar" => self.simple(
                host,
                || {
                    apply_game_bar_enable();
                    remove_game_bar_ifeo();
                    apply_policy_enable();
                },
                "Game Bar enabled.",
            ),
            "force_fse" => self.simple(host, apply_fse_force, "FSE forced globally."),
            "enable_fso" => self.simple(host, apply_fso_restore, "FSO restored (Windows default)."),
            "hags.enable" => self.simple(
                host,
                || {
                    xos_sys::reg_set_dword(KEY_HAGS, "HwSchMode", 2);
                },
                "Hardware-Accelerated GPU Scheduling enabled. Please restart your PC.",
            ),
            "hags.disable" => self.simple(
                host,
                || {
                    xos_sys::reg_set_dword(KEY_HAGS, "HwSchMode", 1);
                },
                "Hardware-Accelerated GPU Scheduling disabled. Please restart your PC.",
            ),
            "mpo.enable" => self.simple(
                host,
                || {
                    xos_sys::reg_delete_value(KEY_DWM, "OverlayTestMode");
                },
                "MPO enabled (Windows default). Please restart your PC.",
            ),
            "mpo.disable" => self.simple(
                host,
                || {
                    xos_sys::reg_set_dword(KEY_DWM, "OverlayTestMode", 5);
                },
                "MPO disabled. Please restart your PC.",
            ),
            "sysresp.enable" => self.simple(
                host,
                || {
                    xos_sys::reg_set_dword(KEY_MM_PROFILE, "SystemResponsiveness", 10);
                },
                "System responsiveness optimized for games.",
            ),
            "sysresp.disable" => self.simple(
                host,
                || {
                    xos_sys::reg_set_dword(KEY_MM_PROFILE, "SystemResponsiveness", 20);
                },
                "System responsiveness restored to the Windows default.",
            ),
            "cpuprio.enable" => self.simple(
                host,
                || {
                    xos_sys::reg_set_dword(KEY_GAMES, "Priority", 6);
                },
                "CPU priority for games raised.",
            ),
            "cpuprio.disable" => self.simple(
                host,
                || {
                    xos_sys::reg_set_dword(KEY_GAMES, "Priority", 2);
                },
                "CPU priority for games restored to default.",
            ),
            "schedcat.enable" => self.simple(
                host,
                || {
                    xos_sys::reg_set_string(KEY_GAMES, "Scheduling Category", "High");
                },
                "Scheduling category for games set to High.",
            ),
            "schedcat.disable" => self.simple(
                host,
                || {
                    xos_sys::reg_set_string(KEY_GAMES, "Scheduling Category", "Medium");
                },
                "Scheduling category for games restored to Medium.",
            ),
            "gpuprio.enable" => self.simple(
                host,
                || {
                    xos_sys::reg_set_dword(KEY_GAMES, "GPU Priority", 8);
                },
                "GPU priority for games raised.",
            ),
            "gpuprio.disable" => self.simple(
                host,
                || {
                    xos_sys::reg_set_dword(KEY_GAMES, "GPU Priority", 2);
                },
                "GPU priority for games restored to default.",
            ),
            "flip.enable" => self.simple(
                host,
                || set_dx_token("SwapEffectUpgradeEnable", "1"),
                "Windowed-game optimizations (DirectX flip model) enabled.",
            ),
            "flip.disable" => self.simple(
                host,
                || set_dx_token("SwapEffectUpgradeEnable", "0"),
                "Windowed-game optimizations (DirectX flip model) disabled.",
            ),
            "vrr.enable" => self.simple(
                host,
                || set_dx_token("VRROptimizeEnable", "1"),
                "Variable Refresh Rate optimization enabled.",
            ),
            "vrr.disable" => self.simple(
                host,
                || set_dx_token("VRROptimizeEnable", "0"),
                "Variable Refresh Rate optimization disabled.",
            ),
            "hdr.enable" => self.simple(host, || set_dx_token("AutoHDREnable", "1"), "Auto HDR enabled."),
            "hdr.disable" => self.simple(host, || set_dx_token("AutoHDREnable", "0"), "Auto HDR disabled."),
            "color.enable" => self.apply_auto_color(host, 1),
            "color.disable" => self.apply_auto_color(host, 0),
            "hwoverlay.enable" => self.simple(
                host,
                || {
                    xos_sys::reg_delete_value(KEY_HAGS, "DisableOverlays");
                },
                "Hardware overlays enabled (Windows default). Please restart your PC.",
            ),
            "hwoverlay.disable" => self.hw_overlay_disable(host),
            "mpominfps.enable" => self.simple(
                host,
                || {
                    xos_sys::reg_delete_value(KEY_DWM, "OverlayMinFPS");
                },
                "MPO minimum frame rate requirement enabled (Windows default). Please restart your PC.",
            ),
            "mpominfps.disable" => self.simple(
                host,
                || {
                    xos_sys::reg_set_dword(KEY_DWM, "OverlayMinFPS", 0);
                },
                "MPO minimum frame rate requirement disabled. Please restart your PC.",
            ),
            "fivem.enable" => self.fivem_enable(host),
            "fivem.disable" => self.fivem_disable(host),
            "nvidia.apply" => self.launch_nvidia(
                host,
                "XOS.nip",
                "NVIDIA Profile Inspector launched. Click 'Apply changes' in the tool.",
                "NVIDIA Profile Inspector launch failed",
            ),
            "nvidia.revert" => self.launch_nvidia(
                host,
                "Default.nip",
                "NVIDIA Profile Inspector launched with default profile. Click 'Apply changes' to revert.",
                "NVIDIA profile restore launch failed",
            ),
            "amd.safe" => self.amd_apply(host, false),
            "amd.experimental" => self.amd_apply(host, true),
            "amd.revert" => self.amd_revert(host),
            _ => {}
        }
    }
}

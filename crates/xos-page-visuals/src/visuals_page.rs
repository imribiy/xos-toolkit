use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use winreg::enums::{HKEY_CURRENT_USER, KEY_READ};
use winreg::RegKey;
use xos_core::app_state;
use xos_core::host::{Buttons, Host, Icon, Page};
use xos_core::log;
use xos_core::status;
use xos_core::ui::*;
use xos_sys::CmdOptions;
use xos_winupdate::widgets_app::{self, Outcome};
use xos_winupdate::widgets_policy;

const TITLE: &str = "XOS Toolkit";
const EXPLORER_KEY: &str = r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer";
const EXPLORER_KEY_LM: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer";
const GALLERY_CLSID: &str = r"HKCU\Software\Classes\CLSID\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}";
const HOME_CLSID: &str = r"HKCU\Software\Classes\CLSID\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}";
const NETWORK_CLSID: &str = r"HKCU\Software\Classes\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}";
const INTERNET_ZONE_KEY: &str =
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3";
const LAUNCH_UNSAFE_FILES: &str = "1806";
const PINNED: &str = "System.IsPinnedToNameSpaceTree";
const MY_COMPUTER_NS: &str =
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace";
const MY_COMPUTER_NS32: &str =
    r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace";
const PICTURES_CLSIDS: [&str; 2] = [
    "{24ad3ad4-a569-4530-98e1-ab02f9417aa8}",
    "{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}",
];
const MUSIC_CLSIDS: [&str; 2] = [
    "{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}",
    "{1CF1260C-4DD0-4ebb-811F-33C572699FDE}",
];
const VIDEOS_CLSIDS: [&str; 2] = [
    "{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}",
    "{A0953C92-50DC-43bf-BE83-3742FED03C9C}",
];
const START_MENU_HOST_EXE: &str = "StartMenuExperienceHost.exe";
const START_MENU_HOST_OLD: &str = "StartMenuExperienceHost.exe.old";
const FLUENT_METRO_API: &str =
    "https://api.github.com/repos/bonzibudd/Fluent-Metro/releases/latest";

const WIDGETS_DESCRIPTION: &str = "Widgets on Windows 11 and News and interests on Windows 10, set through local Group Policy. Disable is the XOS default; while it is set, Windows shows these settings as managed by your organization. Enable removes the policy and returns them to the Windows default.";
const WIDGETS_W10_HOME: &str = " Windows Home: News and interests is turned off through the per-user taskbar value, because Microsoft does not document local Group Policy for this edition.";
const WIDGETS_HOME: &str = " Windows Home: Microsoft does not document local Group Policy for this edition, so the policy may not apply here.";
const WIDGETS_APP_NOTE: &str = " On Windows 11, Enable also reinstalls the Widgets app (Windows Web Experience Pack) from the Microsoft Store when it is missing.";

const FLUENT_SCRIPT: &str = "param($Url,$Zip,$Dir)\r\n$ErrorActionPreference = 'Stop'\r\n[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12\r\nAdd-Type -AssemblyName System.IO.Compression.FileSystem\r\n$wc = New-Object System.Net.WebClient\r\n$wc.Headers.Add('User-Agent', 'XOS-Toolkit')\r\n$wc.DownloadFile($Url, $Zip)\r\n$a = [System.IO.Compression.ZipFile]::OpenRead($Zip)\r\ntry {\r\n    foreach ($e in $a.Entries) {\r\n        $d = $null\r\n        if ($e.Name -ieq 'Fluent-Metro.skin') { $d = Join-Path $Dir 'Fluent-Metro.skin' }\r\n        elseif ($e.Name -ieq 'Fluent-Metro.skin7') { $d = Join-Path $Dir 'Fluent-Metro.skin7' }\r\n        if ($d -and -not (Test-Path -LiteralPath $d)) {\r\n            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($e, $d, $false)\r\n        }\r\n    }\r\n} finally { $a.Dispose() }\r\n";

struct State {
    badges: HashMap<&'static str, Badge>,
    widgets_app_text: Option<String>,
    widgets_app_note_added: bool,
    overlay: Option<String>,
}

pub struct VisualsPage {
    st: Mutex<State>,
    build: i32,
    widgets_suffix: &'static str,
    pictures_path: String,
    music_path: String,
    videos_path: String,
}

impl Default for VisualsPage {
    fn default() -> Self {
        Self::new()
    }
}

fn known_folder(id: &windows::core::GUID, fallback: &str) -> String {
    use windows::Win32::System::Com::CoTaskMemFree;
    use windows::Win32::UI::Shell::{SHGetKnownFolderPath, KF_FLAG_DEFAULT};
    unsafe {
        if let Ok(p) = SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, None) {
            let s = p.to_string().unwrap_or_default();
            CoTaskMemFree(Some(p.0 as *const _));
            if !s.is_empty() {
                return s;
            }
        }
    }
    let profile = std::env::var("USERPROFILE").unwrap_or_default();
    if profile.is_empty() {
        String::new()
    } else {
        format!(r"{profile}\{fallback}")
    }
}

fn program_files() -> String {
    std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".to_string())
}

fn program_files_x86() -> String {
    std::env::var("ProgramFiles(x86)").unwrap_or_default()
}

fn start_menu_host_dir() -> PathBuf {
    let windir = std::env::var("windir").unwrap_or_else(|_| r"C:\Windows".to_string());
    Path::new(&windir).join(r"SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy")
}

fn open_shell_menu_exe() -> PathBuf {
    Path::new(&program_files()).join(r"Open-Shell\StartMenu.exe")
}

pub fn is_open_shell_installed() -> bool {
    let pf = program_files();
    let pf86 = program_files_x86();
    xos_sys::reg_key_exists(r"HKLM\SOFTWARE\OpenShell\OpenShell")
        || xos_sys::reg_key_exists(r"HKLM\SOFTWARE\WOW6432Node\OpenShell\OpenShell")
        || Path::new(&pf).join(r"Open-Shell\StartMenu.exe").exists()
        || Path::new(&pf86).join(r"Open-Shell\StartMenu.exe").exists()
}

pub fn alt_tab_state(value: Option<i32>) -> (&'static str, Option<&'static str>) {
    match value {
        Some(1) => ("Classic", Some("Classic Alt-Tab is active.")),
        Some(0) => ("Immersive", Some("Immersive Alt-Tab is active.")),
        None => (
            "Immersive (Windows Default)",
            Some("Windows default. Immersive Alt-Tab is active."),
        ),
        Some(_) => ("Partial", None),
    }
}

pub fn widgets_app_line(installed: Option<bool>) -> &'static str {
    match installed {
        Some(true) => "Widgets app (Windows Web Experience Pack): installed.",
        Some(false) => "Widgets app (Windows Web Experience Pack): not installed. Enable (Default) installs it from the Microsoft Store.",
        None => "Widgets app (Windows Web Experience Pack): could not be read.",
    }
}

pub fn zip_url_from_json(json: &str) -> Option<String> {
    let re = regex::Regex::new(r#"(?i)"browser_download_url"\s*:\s*"([^"]+)""#).ok()?;
    for c in re.captures_iter(json) {
        let url = c.get(1)?.as_str();
        if url.to_lowercase().ends_with(".zip") {
            return Some(url.to_string());
        }
    }
    None
}

fn folder_state(clsids: &[&str], path: &str) -> String {
    if !xos_sys::is_pinned_to_quick_access(path) {
        return "Disabled".to_string();
    }
    for c in clsids {
        if xos_sys::reg_key_exists(&format!(r"{MY_COMPUTER_NS}\{c}"))
            || xos_sys::reg_key_exists(&format!(r"{MY_COMPUTER_NS32}\{c}"))
        {
            return "Enabled".to_string();
        }
    }
    "Disabled".to_string()
}

fn restore_nav_pane_default(clsid_key: &str) {
    xos_sys::reg_delete_value(clsid_key, PINNED);
    let sub = &clsid_key[r"HKCU\".len()..];
    match RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(sub, KEY_READ) {
        Ok(k) => {
            let values = k.enum_values().count();
            let subkeys = k.enum_keys().count();
            if values > 0 || subkeys > 0 {
                return;
            }
        }
        Err(_) => return,
    }
    xos_sys::reg_delete_key(clsid_key);
}

fn enable_folder(clsids: &[&str], path: &str) {
    for c in clsids {
        xos_sys::reg_create_key(&format!(r"{MY_COMPUTER_NS}\{c}"));
        xos_sys::reg_create_key(&format!(r"{MY_COMPUTER_NS32}\{c}"));
    }
    if !xos_sys::is_pinned_to_quick_access(path) {
        xos_sys::quick_access_pin(path);
    }
}

fn disable_folder(clsids: &[&str], path: &str) {
    for c in clsids {
        xos_sys::reg_delete_key(&format!(r"{MY_COMPUTER_NS}\{c}"));
        xos_sys::reg_delete_key(&format!(r"{MY_COMPUTER_NS32}\{c}"));
    }
    if xos_sys::is_pinned_to_quick_access(path) {
        xos_sys::quick_access_unpin(path);
    }
}

fn explorer_pids() -> Vec<u32> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    let mut out = Vec::new();
    unsafe {
        let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
            return out;
        };
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let len = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                if String::from_utf16_lossy(&entry.szExeFile[..len])
                    .eq_ignore_ascii_case("explorer.exe")
                {
                    out.push(entry.th32ProcessID);
                }
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
    }
    out
}

fn restart_explorer() {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        OpenProcess, TerminateProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
    };
    for pid in explorer_pids() {
        unsafe {
            let Ok(handle) = OpenProcess(PROCESS_TERMINATE | PROCESS_SYNCHRONIZE, false, pid)
            else {
                return;
            };
            let killed = TerminateProcess(handle, 1).is_ok();
            if killed {
                WaitForSingleObject(handle, 3000);
            }
            let _ = CloseHandle(handle);
            if !killed {
                return;
            }
        }
    }
    let _ = xos_sys::shell_start("explorer.exe", "");
}

fn taskkill_accepting_128(image: &str) {
    xos_sys::run_cmd_opts(
        "taskkill.exe",
        &format!("/F /IM {image}"),
        &CmdOptions {
            accepted_exit_codes: &[128],
            ..Default::default()
        },
    );
}

fn disable_start_menu_host() -> bool {
    let dir = start_menu_host_dir();
    let exe = dir.join(START_MENU_HOST_EXE);
    let old = dir.join(START_MENU_HOST_OLD);
    if !exe.exists() && !old.exists() {
        return true;
    }
    if !exe.exists() && old.exists() {
        return true;
    }
    if exe.exists() && old.exists() {
        let _ = std::fs::remove_file(&old);
        if old.exists() {
            return false;
        }
    }
    if !exe.exists() {
        return false;
    }
    taskkill_accepting_128(START_MENU_HOST_EXE);
    xos_sys::run_as_ti(
        "cmd.exe",
        &format!("/c ren \"{}\" \"{}\"", exe.display(), START_MENU_HOST_OLD),
    );
    !exe.exists() && old.exists()
}

fn enable_start_menu_host() -> bool {
    let dir = start_menu_host_dir();
    let exe = dir.join(START_MENU_HOST_EXE);
    let old = dir.join(START_MENU_HOST_OLD);
    if !exe.exists() && !old.exists() {
        return true;
    }
    if !old.exists() {
        return exe.exists();
    }
    if exe.exists() {
        let _ = std::fs::remove_file(&old);
        return true;
    }
    xos_sys::run_as_ti(
        "cmd.exe",
        &format!("/c ren \"{}\" \"{}\"", old.display(), START_MENU_HOST_EXE),
    );
    if exe.exists() {
        let _ = xos_sys::shell_start(&exe.to_string_lossy(), "");
    }
    exe.exists()
}

fn unique_token() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{:x}{:x}", nanos, std::process::id())
}

fn fluent_metro_zip_url() -> Option<String> {
    let json = xos_sys::http_get_string(FLUENT_METRO_API)?;
    zip_url_from_json(&json)
}

fn ensure_fluent_metro_skin() -> bool {
    let skins_dir = Path::new(&program_files()).join(r"Open-Shell\Skins");
    let token = unique_token();
    let temp = std::env::temp_dir();
    let zip = temp.join(format!("FluentMetro-{token}.zip"));
    let script = temp.join(format!("FluentMetro-{token}.ps1"));
    let result = (|| -> Option<bool> {
        if !skins_dir.is_dir() {
            std::fs::create_dir_all(&skins_dir).ok()?;
        }
        let skin = skins_dir.join("Fluent-Metro.skin");
        let skin7 = skins_dir.join("Fluent-Metro.skin7");
        if skin.exists() && skin7.exists() {
            return Some(true);
        }
        let url = fluent_metro_zip_url()?;
        std::fs::write(&script, FLUENT_SCRIPT).ok()?;
        let args = format!(
            "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{}\" -Url \"{}\" -Zip \"{}\" -Dir \"{}\"",
            script.display(),
            url,
            zip.display(),
            skins_dir.display()
        );
        xos_sys::run_cmd_opts(
            "powershell.exe",
            &args,
            &CmdOptions {
                timeout_ms: Some(180000),
                suppress_log: true,
                ..Default::default()
            },
        );
        Some(skin.exists() && skin7.exists())
    })();
    let _ = std::fs::remove_file(&zip);
    let _ = std::fs::remove_file(&script);
    result.unwrap_or(false)
}

fn apply_fluent_metro_settings() {
    taskkill_accepting_128("StartMenu.exe");
    std::thread::sleep(std::time::Duration::from_millis(500));
    let settings_key = r"HKCU\Software\OpenShell\StartMenu\Settings";
    xos_sys::reg_set_string(settings_key, "MenuStyle", "Win7");
    xos_sys::reg_set_string(settings_key, "SkinW7", "Fluent-Metro");
    xos_sys::reg_set_dword(settings_key, "SkipMetro", 1);
    xos_sys::reg_set_dword(r"HKCU\Software\OpenShell\StartMenu", "ShowedStyle2", 1);
    let exe = open_shell_menu_exe();
    if exe.exists() {
        let _ = xos_sys::shell_start(&exe.to_string_lossy(), "");
    }
}

impl VisualsPage {
    pub fn new() -> Self {
        use windows::Win32::UI::Shell::{FOLDERID_Music, FOLDERID_Pictures, FOLDERID_Videos};
        let widgets_suffix = if widgets_policy::is_windows10_home() {
            WIDGETS_W10_HOME
        } else if widgets_policy::is_home_edition() {
            WIDGETS_HOME
        } else {
            ""
        };
        Self {
            st: Mutex::new(State {
                badges: HashMap::new(),
                widgets_app_text: None,
                widgets_app_note_added: false,
                overlay: None,
            }),
            build: xos_sys::get_windows_build_number(),
            widgets_suffix,
            pictures_path: known_folder(&FOLDERID_Pictures, "Pictures"),
            music_path: known_folder(&FOLDERID_Music, "Music"),
            videos_path: known_folder(&FOLDERID_Videos, "Videos"),
        }
    }

    fn set_badge(&self, card: &'static str, state: &str, detail: Option<&str>) {
        let badge = status::badge_with(state, detail);
        self.st.lock().unwrap().badges.insert(card, badge);
    }

    fn refresh_states(&self) {
        self.set_badge("themes", &status::service("Themes"), None);

        let alt = xos_sys::reg_get_dword(EXPLORER_KEY, "AltTabSettings");
        let (state, detail) = alt_tab_state(alt);
        self.set_badge("alttab", state, detail);

        let (widgets_state, widgets_detail) = widgets_policy::read_state();
        self.set_badge("widgets", &widgets_state, widgets_detail.as_deref());
        self.refresh_widgets_app_text();

        let power_menu = xos_sys::reg_key_exists(r"HKCR\DesktopBackground\Shell\PowerPlan");
        self.set_badge(
            "powermenu",
            if power_menu { "Enabled" } else { "Disabled" },
            None,
        );

        let hub = xos_sys::reg_get_dword(EXPLORER_KEY_LM, "HubMode");
        self.set_badge(
            "quickaccess",
            &status::toggle_with(hub, 0, 1, status::ENABLED_WINDOWS_DEFAULT),
            None,
        );

        let pinned = |key: &str| {
            status::toggle_with(
                xos_sys::reg_get_dword(key, PINNED),
                1,
                0,
                status::ENABLED_WINDOWS_DEFAULT,
            )
        };
        self.set_badge("home", &pinned(HOME_CLSID), None);
        self.set_badge("gallery", &pinned(GALLERY_CLSID), None);
        self.set_badge("network", &pinned(NETWORK_CLSID), None);

        self.set_badge(
            "pictures",
            &folder_state(&PICTURES_CLSIDS, &self.pictures_path),
            None,
        );
        self.set_badge(
            "music",
            &folder_state(&MUSIC_CLSIDS, &self.music_path),
            None,
        );
        self.set_badge(
            "videos",
            &folder_state(&VIDEOS_CLSIDS, &self.videos_path),
            None,
        );

        let prompt = xos_sys::reg_get_dword(INTERNET_ZONE_KEY, LAUNCH_UNSAFE_FILES);
        self.set_badge(
            "fileprompt",
            &status::toggle_with(prompt, 1, 0, status::ENABLED_WINDOWS_DEFAULT),
            None,
        );

        let installed = is_open_shell_installed();
        let state = if installed {
            "Installed"
        } else {
            "Not Installed"
        };
        let mut badge = status::badge_with(state, None);
        badge.tone = if installed { Tone::Green } else { Tone::Red };
        self.st.lock().unwrap().badges.insert("openshell", badge);
    }

    fn refresh_widgets_app_text(&self) {
        if !widgets_app::applies() {
            return;
        }
        let (store, installed) = widgets_app::probe();
        let mut st = self.st.lock().unwrap();
        if store == Some(false) {
            st.widgets_app_text = None;
            return;
        }
        if store == Some(true) {
            st.widgets_app_note_added = true;
        }
        st.widgets_app_text = Some(widgets_app_line(installed).to_string());
    }

    fn set_overlay(&self, host: &dyn Host, text: Option<&str>) {
        self.st.lock().unwrap().overlay = text.map(|t| t.to_string());
        host.publish(self.model());
    }

    fn done(&self, host: &dyn Host, msg: &str, operation_failed: bool, warn: bool) {
        let failed = xos_sys::ops::any_failed() || operation_failed;
        log::action_done("Visuals", operation_failed, failed || warn, None);
        xos_sys::ops::reset();
        app_state::require_reboot_if_message_asks(msg);
        host.set_status(msg);
        let mut text = msg.to_string();
        if failed {
            text.push_str("\n\nNote: one or more settings could not be written (often a permissions issue). Try again.");
        }
        let icon = if failed || warn {
            Icon::Warning
        } else {
            Icon::Information
        };
        host.dialog(&text, TITLE, Buttons::Ok, icon);
    }

    fn simple(&self, host: &dyn Host, msg: &str) {
        self.refresh_states();
        self.done(host, msg, false, false);
    }

    fn badge_of(st: &State, id: &'static str) -> Badge {
        st.badges.get(id).cloned().unwrap_or_else(Badge::checking)
    }

    fn card(
        st: &State,
        id: &'static str,
        title: &str,
        description: &str,
        enable_text: &str,
        disable_text: &str,
    ) -> Card {
        Card::new(id, title, description)
            .badge(Self::badge_of(st, id))
            .actions(vec![
                Control::button(format!("{id}.enable"), enable_text, BtnStyle::Enable),
                Control::button(format!("{id}.disable"), disable_text, BtnStyle::Disable),
            ])
    }

    fn themes_toggle(&self, host: &dyn Host, enable: bool) {
        xos_sys::ops::reset();
        if enable {
            let ok = xos_sys::config_service_sc("Themes", "auto");
            xos_sys::start_service("Themes");
            self.refresh_states();
            self.done(host, "Windows Themes enabled. Please reboot.", !ok, false);
        } else {
            xos_sys::stop_service("Themes");
            let ok = xos_sys::config_service_sc("Themes", "disabled");
            self.refresh_states();
            self.done(host, "Windows Themes disabled. Please reboot.", !ok, false);
        }
    }

    fn alt_tab(&self, host: &dyn Host, classic: bool) {
        xos_sys::ops::reset();
        if classic {
            xos_sys::reg_set_dword(EXPLORER_KEY, "AltTabSettings", 1);
            xos_sys::reg_set_dword(EXPLORER_KEY, "HoverSelectDesktops", 0);
        } else {
            xos_sys::reg_delete_value(EXPLORER_KEY, "AltTabSettings");
            xos_sys::reg_delete_value(EXPLORER_KEY, "HoverSelectDesktops");
        }
        restart_explorer();
        self.refresh_states();
        self.done(
            host,
            if classic {
                "Alt-Tab set to Classic."
            } else {
                "Alt-Tab set to Immersive (Default)."
            },
            false,
            false,
        );
    }

    fn run_widgets_policy(&self, host: &dyn Host, enable: bool) {
        xos_sys::ops::reset();
        let status_text = if enable {
            "Removing the Widgets and News policy..."
        } else {
            "Applying the Widgets and News policy..."
        };
        self.set_overlay(host, Some(status_text));
        host.set_status(status_text);
        let (ok, detail) = if enable {
            widgets_policy::enable()
        } else {
            widgets_policy::disable()
        };
        let mut app = Outcome::Skipped;
        let mut app_detail = String::new();
        let mut can_open_store = false;
        if ok && enable && widgets_app::applies() {
            host.set_status(
                "Checking the Widgets app, installing it from the Microsoft Store if it is missing...",
            );
            let (o, d, c) = widgets_app::ensure_installed();
            app = o;
            app_detail = d;
            can_open_store = c;
        }
        let app_ok = app != Outcome::Failed;
        let mut removed: Option<bool> = None;
        let mut remove_detail = String::new();
        if ok && !enable && widgets_app::applies() {
            let (store, installed) = widgets_app::probe();
            if store == Some(true) && installed == Some(true) {
                self.set_overlay(host, None);
                let yes = host.confirm(
                    "Also uninstall the Widgets app (Windows Web Experience Pack)? You can get it back with Enable.",
                    TITLE,
                    Icon::Question,
                );
                if yes {
                    self.set_overlay(host, Some(status_text));
                    host.set_status("Removing the Widgets app...");
                    let (r, d) = widgets_app::remove();
                    removed = Some(r);
                    remove_detail = d;
                } else {
                    log::op("Widgets app removal | declined by the user, app kept");
                }
            }
        }
        let store_opened = !app_ok && can_open_store && widgets_app::open_store_page();
        self.set_overlay(host, None);
        if ok {
            restart_explorer();
        }
        self.refresh_states();
        if !ok {
            let prefix = if enable {
                "The Widgets and News policy could not be fully removed: "
            } else {
                "The Widgets and News policy did not apply: "
            };
            self.done(host, &format!("{prefix}{detail}"), true, false);
            return;
        }
        if !app_ok {
            let store_line = if store_opened {
                "The Microsoft Store page for Windows Web Experience Pack is open: press Get there to install it.".to_string()
            } else {
                format!(
                    "Install Windows Web Experience Pack from the Microsoft Store (product {}) if the Store is available on this Windows.",
                    widgets_app::STORE_PRODUCT_ID
                )
            };
            self.done(
                host,
                &format!(
                    "The Widgets and News policy was removed, but the Widgets app is not installed: {app_detail}.\n\n{store_line}"
                ),
                false,
                true,
            );
            return;
        }
        if removed == Some(false) {
            self.done(
                host,
                &format!(
                    "Widgets and News disabled through local Group Policy, but the Widgets app could not be removed: {remove_detail}\n\nThe policy keeps Widgets off either way. You can try again, or remove Windows Web Experience Pack from the AppX page."
                ),
                false,
                true,
            );
            return;
        }
        let msg = if enable {
            "Widgets and News returned to the Windows default."
        } else if removed == Some(true) {
            "Widgets and News disabled through local Group Policy, and the Widgets app was uninstalled."
        } else {
            "Widgets and News disabled through local Group Policy."
        };
        self.done(host, msg, false, false);
    }

    fn power_menu_add(&self, host: &dyn Host) {
        xos_sys::ops::reset();
        xos_sys::reg_delete_key(r"HKCR\DesktopBackground\Shell\XOS_DisableIdle");
        xos_sys::reg_delete_key(r"HKCR\DesktopBackground\Shell\XOS_EnableIdle");

        if !xos_sys::is_xos_power_plan_imported() {
            let yes = host.confirm(
                "The XOS Power Plan is not installed.\n\nWould you like to add it now? If you skip this, the XOS Power Plan option will not appear in the context menu.",
                TITLE,
                Icon::Question,
            );
            if yes {
                let (ok, detail) = xos_sys::import_xos_power_plan_detail();
                if !ok {
                    let mut message = "Failed to build the XOS Power Plan.".to_string();
                    if !detail.trim().is_empty() {
                        message.push_str("\n\nDetails:\n");
                        message.push_str(&detail);
                    }
                    if log::is_available() {
                        if let Some(p) = log::log_path() {
                            message.push_str("\n\nSession log:\n");
                            message.push_str(&p.display().to_string());
                        }
                    }
                    host.warn(&message, TITLE);
                }
            }
        }

        let base = r"HKCR\DesktopBackground\Shell\PowerPlan";
        xos_sys::reg_set_string(base, "Icon", "powercpl.dll");
        xos_sys::reg_set_string(base, "MUIVerb", "Choose Power Plan");
        xos_sys::reg_set_string(base, "Position", "Middle");
        xos_sys::reg_set_string(base, "SubCommands", "");

        xos_sys::sync_power_plan_context_menu();
        self.simple(host, "Power Plan context menu added.");
    }

    fn power_menu_remove(&self, host: &dyn Host) {
        xos_sys::ops::reset();
        xos_sys::reg_delete_key(r"HKCR\DesktopBackground\Shell\PowerPlan");
        xos_sys::reg_delete_key(r"HKCR\DesktopBackground\Shell\XOS_DisableIdle");
        xos_sys::reg_delete_key(r"HKCR\DesktopBackground\Shell\XOS_EnableIdle");
        xos_sys::notify_shell_assoc_changed();
        self.simple(host, "Power Plan context menu removed.");
    }

    fn nav_pane(&self, host: &dyn Host, clsid: &str, name: &str, enable: bool) {
        xos_sys::ops::reset();
        if enable {
            restore_nav_pane_default(clsid);
        } else {
            xos_sys::reg_set_dword(clsid, PINNED, 0);
        }
        self.simple(
            host,
            &format!("{name} {}.", if enable { "enabled" } else { "disabled" }),
        );
    }

    fn folder(&self, host: &dyn Host, clsids: &[&str], path: &str, name: &str, enable: bool) {
        xos_sys::ops::reset();
        if enable {
            enable_folder(clsids, path);
            self.simple(
                host,
                &format!("{name} shown in This PC and pinned to Quick Access. Restart File Explorer if the This PC entry doesn't update."),
            );
        } else {
            disable_folder(clsids, path);
            self.simple(
                host,
                &format!("{name} hidden from This PC and unpinned from Quick Access. Restart File Explorer if the This PC entry doesn't update."),
            );
        }
    }

    fn open_shell_install(&self, host: &dyn Host) {
        xos_sys::ops::reset();
        if is_open_shell_installed() {
            host.info("Open Shell is already installed.", TITLE);
            return;
        }
        if !xos_sys::is_choco_installed() {
            host.warn(
                "Chocolatey is required. Install it from the Apps tab first.",
                TITLE,
            );
            return;
        }

        self.set_overlay(host, Some("Installing Open Shell..."));
        host.set_status("Installing Open Shell...");

        let healthy = match xos_sys::get_choco_path() {
            Some(p) if !p.is_empty() => {
                let ver = xos_sys::run_cmd_output(&p, "--version");
                !ver.trim().is_empty()
                    && regex::Regex::new(r"^\d+(\.\d+)+")
                        .map(|r| r.is_match(ver.trim()))
                        .unwrap_or(false)
            }
            _ => false,
        };
        if !healthy {
            host.set_status("Repairing Chocolatey...");
            if !xos_sys::install_choco() {
                self.set_overlay(host, None);
                host.set_status("Ready");
                host.error(
                    "Chocolatey appears broken and could not be repaired automatically.\n\nWorkaround: open an admin Command Prompt, run \"rmdir /s /q C:\\ProgramData\\chocolatey\", then reinstall Chocolatey from the Apps tab.",
                    TITLE,
                );
                return;
            }
            host.set_status("Installing Open Shell...");
        }

        let ok = {
            let _guard = xos_sys::enter_chocolatey_operation();
            match xos_sys::get_choco_path() {
                Some(choco) => xos_sys::run_cmd_timeout(
                    &choco,
                    "install open-shell -y --ignore-checksums --params \"/StartMenu\"",
                    300000,
                ),
                None => false,
            }
        };

        if !ok || !is_open_shell_installed() {
            self.set_overlay(host, None);
            host.set_status("Ready");
            host.error("Open Shell installation failed.", TITLE);
            return;
        }

        let start_menu_disabled = disable_start_menu_host();

        xos_sys::reg_set_dword(r"HKLM\SOFTWARE\XOSToolkit", "OpenShellInstalledByXos", 1);

        host.set_status("Preparing Fluent-Metro skin...");
        let skin_ok = ensure_fluent_metro_skin();
        if skin_ok {
            apply_fluent_metro_settings();
        }

        self.refresh_states();
        self.set_overlay(host, None);
        app_state::require_reboot();
        let skin_msg = if skin_ok {
            " Fluent-Metro skin applied."
        } else {
            ""
        };
        let host_msg = if start_menu_disabled {
            " The Windows Start Menu has been disabled."
        } else {
            " The Windows Start Menu host could not be disabled."
        };
        self.done(
            host,
            &format!(
                "Open Shell installed.{skin_msg}{host_msg}\nPlease restart your PC for changes to take full effect."
            ),
            false,
            !start_menu_disabled,
        );
    }

    fn open_shell_uninstall(&self, host: &dyn Host) {
        xos_sys::ops::reset();
        if !host.confirm("Restore the Windows Start Menu?", TITLE, Icon::Question) {
            return;
        }

        self.set_overlay(host, Some("Restoring Windows Start Menu..."));
        host.set_status("Restoring Windows Start Menu...");

        let installed = is_open_shell_installed();
        let mut uninstalled = true;
        if installed {
            let _guard = xos_sys::enter_chocolatey_operation();
            if let Some(choco) = xos_sys::get_choco_path() {
                xos_sys::run_cmd_timeout(&choco, "uninstall open-shell -y", 300000);
            }
            uninstalled = !is_open_shell_installed();
        }

        if !uninstalled {
            self.set_overlay(host, None);
            host.set_status("Open Shell could not be uninstalled.");
            host.error(
                "Open Shell could not be uninstalled, so the Windows Start Menu host was left unchanged to avoid running both Start Menu implementations together.",
                TITLE,
            );
            return;
        }

        let restored = enable_start_menu_host();

        self.refresh_states();
        self.set_overlay(host, None);
        host.set_status("Windows Start Menu restored.");
        app_state::require_reboot();
        let msg = if !restored {
            "The Windows Start Menu host could not be restored."
        } else if installed {
            "Open Shell uninstalled. The Windows Start Menu has been restored."
        } else {
            "Windows Start Menu has been restored."
        };
        host.dialog(
            &format!("{msg}\nPlease restart your PC for changes to take full effect."),
            TITLE,
            Buttons::Ok,
            if restored && uninstalled {
                Icon::Information
            } else {
                Icon::Warning
            },
        );
    }
}

impl Page for VisualsPage {
    fn id(&self) -> &'static str {
        "Visuals"
    }

    fn label(&self) -> &'static str {
        "Visuals"
    }

    fn model(&self) -> PageModel {
        let st = self.st.lock().unwrap();
        let win11 = self.build >= 22000;

        let mut widgets_desc = WIDGETS_DESCRIPTION.to_string();
        widgets_desc.push_str(self.widgets_suffix);
        if st.widgets_app_note_added {
            widgets_desc.push_str(WIDGETS_APP_NOTE);
        }
        let mut widgets = Card::new("widgets", "Widgets and News", widgets_desc)
            .badge(Self::badge_of(&st, "widgets"));
        if let Some(t) = &st.widgets_app_text {
            widgets = widgets.controls(vec![Control::muted(t.clone())]);
        }
        widgets = widgets.actions(vec![
            Control::button("widgets.enable", "Enable (Default)", BtnStyle::Enable),
            Control::button("widgets.disable", "Disable", BtnStyle::Disable),
        ]);

        let open_shell = Card::new(
            "openshell",
            "Open Shell",
            "Replaces the Windows Start menu with Open Shell, a lightweight classic-style menu. The built-in Start menu is turned off while it is installed.",
        )
        .badge(Self::badge_of(&st, "openshell"))
        .actions(vec![
            Control::button("openshell.install", "Install", BtnStyle::Enable),
            Control::button("openshell.uninstall", "Uninstall", BtnStyle::Disable),
        ]);

        let folder_desc = |name: &str| {
            format!("Show or hide the {name} folder in both places it appears: the Quick Access (Home) pins in the sidebar and the folder list inside This PC.")
        };

        PageModel::new("Visuals", "Visuals", "Context menu and visual customization")
            .max_width(1080.0)
            .overlay(st.overlay.clone())
            .card(Self::card(
                &st,
                "themes",
                "Windows Themes",
                "Lets you switch between Windows themes in Personalization settings. Disabling it saves a small amount of resources, but you cannot change themes until you enable it again.",
                "Enable (Default)",
                "Disable",
            ))
            .card(Self::card(
                &st,
                "alttab",
                "Alt-Tab Style",
                "Switch between the classic Windows Alt-Tab switcher and the modern immersive Alt-Tab. Requires an Explorer restart to take effect.",
                "Immersive (Default)",
                "Classic",
            ))
            .card(widgets)
            .card(Self::card(
                &st,
                "powermenu",
                "Power Plan Context Menu",
                "Adds a 'Choose Power Plan' menu to the desktop right-click menu for quick switching between power plans and power options.",
                "Add to Context Menu",
                "Remove from Context Menu",
            ))
            .card(Self::card(
                &st,
                "quickaccess",
                "Quick Access",
                "Show or hide Quick Access in the File Explorer navigation pane.",
                "Enable (Default)",
                "Disable",
            ))
            .card(
                Self::card(
                    &st,
                    "home",
                    "Home",
                    "Show or hide Home in the File Explorer navigation pane.",
                    "Enable (Default)",
                    "Disable",
                )
                .visible(win11),
            )
            .card(
                Self::card(
                    &st,
                    "gallery",
                    "Gallery",
                    "Show or hide Gallery in the File Explorer navigation pane.",
                    "Enable (Default)",
                    "Disable",
                )
                .visible(win11),
            )
            .card(Self::card(
                &st,
                "network",
                "Network",
                "Show or hide Network in the File Explorer navigation pane.",
                "Enable (Default)",
                "Disable",
            ))
            .card(Self::card(
                &st,
                "pictures",
                "Pictures",
                &folder_desc("Pictures"),
                "Enable (Default)",
                "Disable",
            ))
            .card(Self::card(
                &st,
                "music",
                "Music",
                &folder_desc("Music"),
                "Enable (Default)",
                "Disable",
            ))
            .card(Self::card(
                &st,
                "videos",
                "Videos",
                &folder_desc("Videos"),
                "Enable (Default)",
                "Disable",
            ))
            .card(open_shell)
            .card(Self::card(
                &st,
                "fileprompt",
                "Open File Security Warning",
                "The \"Do you want to run this file?\" prompt Windows shows before opening a file downloaded from the internet. Disabling it removes a layer of security protection: downloaded files open without asking.",
                "Enable (Default)",
                "Disable",
            ))
    }

    fn refresh(&self, host: &dyn Host) {
        self.refresh_states();
        host.publish(self.model());
    }

    fn handle(&self, host: &dyn Host, event: &Event) {
        if event.kind != EventKind::Click {
            return;
        }
        match event.control.as_str() {
            "themes.enable" => self.themes_toggle(host, true),
            "themes.disable" => self.themes_toggle(host, false),
            "alttab.enable" => self.alt_tab(host, false),
            "alttab.disable" => self.alt_tab(host, true),
            "widgets.enable" => self.run_widgets_policy(host, true),
            "widgets.disable" => self.run_widgets_policy(host, false),
            "powermenu.enable" => self.power_menu_add(host),
            "powermenu.disable" => self.power_menu_remove(host),
            "quickaccess.enable" => {
                xos_sys::ops::reset();
                xos_sys::reg_delete_value(EXPLORER_KEY_LM, "HubMode");
                self.simple(host, "Quick Access enabled.");
            }
            "quickaccess.disable" => {
                xos_sys::ops::reset();
                xos_sys::reg_set_dword(EXPLORER_KEY_LM, "HubMode", 1);
                self.simple(host, "Quick Access disabled.");
            }
            "home.enable" => self.nav_pane(host, HOME_CLSID, "Home", true),
            "home.disable" => self.nav_pane(host, HOME_CLSID, "Home", false),
            "gallery.enable" => self.nav_pane(host, GALLERY_CLSID, "Gallery", true),
            "gallery.disable" => self.nav_pane(host, GALLERY_CLSID, "Gallery", false),
            "network.enable" => self.nav_pane(host, NETWORK_CLSID, "Network", true),
            "network.disable" => self.nav_pane(host, NETWORK_CLSID, "Network", false),
            "pictures.enable" => self.folder(
                host,
                &PICTURES_CLSIDS,
                &self.pictures_path,
                "Pictures",
                true,
            ),
            "pictures.disable" => self.folder(
                host,
                &PICTURES_CLSIDS,
                &self.pictures_path,
                "Pictures",
                false,
            ),
            "music.enable" => self.folder(host, &MUSIC_CLSIDS, &self.music_path, "Music", true),
            "music.disable" => self.folder(host, &MUSIC_CLSIDS, &self.music_path, "Music", false),
            "videos.enable" => self.folder(host, &VIDEOS_CLSIDS, &self.videos_path, "Videos", true),
            "videos.disable" => {
                self.folder(host, &VIDEOS_CLSIDS, &self.videos_path, "Videos", false)
            }
            "openshell.install" => self.open_shell_install(host),
            "openshell.uninstall" => self.open_shell_uninstall(host),
            "fileprompt.enable" => {
                xos_sys::ops::reset();
                xos_sys::reg_delete_value(INTERNET_ZONE_KEY, LAUNCH_UNSAFE_FILES);
                self.simple(host, "Open file security warning enabled.");
            }
            "fileprompt.disable" => {
                xos_sys::ops::reset();
                xos_sys::reg_set_dword(INTERNET_ZONE_KEY, LAUNCH_UNSAFE_FILES, 0);
                self.simple(host, "Open file security warning disabled.");
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alt_tab_states() {
        assert_eq!(alt_tab_state(Some(1)).0, "Classic");
        assert_eq!(alt_tab_state(Some(0)).0, "Immersive");
        assert_eq!(alt_tab_state(None).0, "Immersive (Windows Default)");
        assert_eq!(alt_tab_state(Some(5)), ("Partial", None));
    }

    #[test]
    fn widgets_lines() {
        assert!(widgets_app_line(Some(true)).ends_with("installed."));
        assert!(widgets_app_line(Some(false)).contains("not installed."));
        assert!(widgets_app_line(None).contains("could not be read"));
    }

    #[test]
    fn zip_url_parse() {
        let json = r#"{"assets":[{"browser_download_url": "https://x/a.txt"},{"browser_download_url":"https://x/Fluent-Metro.ZIP"}]}"#;
        assert_eq!(
            zip_url_from_json(json).as_deref(),
            Some("https://x/Fluent-Metro.ZIP")
        );
        assert_eq!(zip_url_from_json("{}"), None);
    }

    #[test]
    fn model_shape() {
        let page = VisualsPage::new();
        let m = page.model();
        assert_eq!(m.cards.len(), 13);
        assert_eq!(page.id(), "Visuals");
        for c in &m.cards {
            assert!(c.badge.is_some());
        }
    }
}

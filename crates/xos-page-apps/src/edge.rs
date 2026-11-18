use crate::util::*;
use anyhow::{anyhow, bail, Result};
use regex::Regex;
use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use winreg::enums::{HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_READ, KEY_SET_VALUE, KEY_WRITE};
use winreg::{RegKey, RegValue};
use xos_core::{log, session_log};
use xos_winupdate::webview2;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const EDGE_UNINSTALL_GEO_ID: i32 = 94;
const EDGE_UNINSTALL_GEO_NAME: &str = "DE";
const GEO_PATH: &str = r".DEFAULT\Control Panel\International\Geo";
pub const EDGE_BROWSER_GUID: &str = "{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}";
const EDGE_APPX_SCRIPT: &str = include_str!("edge_appx.ps1");

fn hklm() -> RegKey {
    RegKey::predef(HKEY_LOCAL_MACHINE)
}

pub fn get_edge_game_assist_presence() -> Option<bool> {
    let script = "$p=Get-AppxPackage -AllUsers -Name Microsoft.Edge.GameAssist -ErrorAction SilentlyContinue;\
$q=Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue|Where-Object{$_.DisplayName -eq 'Microsoft.Edge.GameAssist' -or $_.PackageName -like '*Microsoft.Edge.GameAssist*'};\
if($p -or $q){'PRESENT'}else{'ABSENT'}";
    present_state(&run_powershell_output(script, 60000))
}

pub fn get_edge_appx_presence() -> Option<bool> {
    let script = "$ErrorActionPreference='Stop';try{\
$names=@('Microsoft.MicrosoftEdge.Stable','Microsoft.MicrosoftEdge');\
$p=Get-AppxPackage -AllUsers -ErrorAction Stop|Where-Object{$names -contains $_.Name};\
$q=Get-AppxProvisionedPackage -Online -ErrorAction Stop|Where-Object{\
$base=([string]$_.PackageName -split '_')[0];$names -contains $base -or $names -contains $_.DisplayName};\
if($p -or $q){'PRESENT'}else{'ABSENT'}}catch{'UNKNOWN'}";
    present_state(&run_powershell_output(script, 60000))
}

fn bool_text(v: bool) -> &'static str {
    if v {
        "True"
    } else {
        "False"
    }
}

pub fn check_edge() -> bool {
    let prog_x86 = program_files_x86();
    let mut native_found = file_exists(&combine(
        &prog_x86,
        r"Microsoft\Edge\Application\msedge.exe",
    )) || file_exists(&combine(
        &program_files(),
        r"Microsoft\Edge\Application\msedge.exe",
    ));
    for path in
        registry_views(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge")
    {
        if hklm().open_subkey_with_flags(&path, KEY_READ).is_ok() {
            native_found = true;
        }
    }

    let appx_found = get_edge_appx_presence();
    log::log(&format!(
        "[Apps] Edge presence: native={}; EdgeStable AppX={}",
        bool_text(native_found),
        status_text(appx_found, "present", "absent")
    ));
    native_found || appx_found != Some(false)
}

pub fn is_edge_webview_installed() -> bool {
    let files = webview2::get_executable_paths(true);
    log::log(&format!(
        "[WebView2] Removal verification: {}",
        if files.is_empty() {
            "No runtime executable found.".to_string()
        } else {
            files.join("; ")
        }
    ));
    !files.is_empty()
}

fn remove_edge_appx_packages() -> bool {
    let encoded = encode_command(EDGE_APPX_SCRIPT);
    let (exit_code, raw) = xos_sys::run_as_ti_output_timeout(
        "powershell.exe",
        &format!("-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}"),
        120000,
    );
    let output = xos_sys::strip_clixml_noise(&raw);
    log::log(&format!(
        "[Apps] Edge AppX cleanup exit={exit_code}: {output}"
    ));
    let presence = get_edge_appx_presence();
    log::log(&format!(
        "[Apps] Edge AppX presence after cleanup: {}",
        status_text(presence, "present", "absent")
    ));
    let game_assist = get_edge_game_assist_presence();
    log::log(&format!(
        "[Apps] Edge Game Assist presence after cleanup: {}",
        status_text(game_assist, "present", "absent")
    ));
    if presence == Some(false) && game_assist == Some(false) {
        if exit_code != 0 {
            log::log(&format!(
                "[Apps] Edge AppX helper returned exit {exit_code}, but direct state verification confirms the packages are absent."
            ));
        }
        return true;
    }
    if exit_code != 0 {
        session_log::operation_failed("Edge AppX cleanup", &output);
    } else {
        session_log::operation_failed(
            "Edge AppX cleanup",
            "The Edge AppX helper completed, but one or more package states could not be verified as absent.",
        );
    }
    false
}

fn remove_directory_as_trusted_installer(directory: &str) -> bool {
    let path = directory.replace('\'', "''");
    let script = format!(
        "$ErrorActionPreference='Stop';\
$path='{path}';\
if (Test-Path -LiteralPath $path) {{\
Get-ChildItem -LiteralPath $path -Force -Recurse -ErrorAction SilentlyContinue | \
ForEach-Object {{ try {{ $_.Attributes = 'Normal' }} catch {{}} }};\
Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop;\
}};\
if (Test-Path -LiteralPath $path) {{ throw 'Directory still exists after removal.' }}"
    );
    let encoded = encode_command(&script);
    let (exit_code, raw) = xos_sys::run_as_ti_output_timeout(
        "powershell.exe",
        &format!("-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand {encoded}"),
        120000,
    );
    let output = if raw.trim().is_empty() {
        "(no output)".to_string()
    } else {
        raw.replace("\r\n", " | ").replace('\n', " | ")
    };
    log::log(&format!(
        "[Apps] Edge directory force cleanup: {directory}; tiExit={exit_code}; output={output}"
    ));
    !dir_exists(directory)
}

fn remove_edge_install_directories() -> bool {
    let mut all_absent = true;
    let prog_x86 = program_files_x86();
    let prog_files = program_files();
    let candidates = [
        combine(&prog_x86, r"Microsoft\Edge\Application"),
        combine(&prog_files, r"Microsoft\Edge\Application"),
        combine(&prog_x86, r"Microsoft\Edge"),
        combine(&prog_files, r"Microsoft\Edge"),
        combine(&prog_x86, r"Microsoft\EdgeCore"),
        combine(&prog_files, r"Microsoft\EdgeCore"),
    ];
    let mut directories: Vec<String> = Vec::new();
    for c in candidates {
        if !directories.iter().any(|d| d.eq_ignore_ascii_case(&c)) {
            directories.push(c);
        }
    }
    for directory in directories {
        if !dir_exists(&directory) {
            continue;
        }
        let mut absent = false;
        let mut attempt = 1;
        while attempt <= 3 && !absent {
            webview2::prepare_for_removal();
            let (ti_exit, _) = xos_sys::run_as_ti_output_timeout(
                "cmd.exe",
                &format!("/c rd /s /q \"{directory}\""),
                120000,
            );
            absent = !dir_exists(&directory);
            log::log(&format!(
                "[Apps] Edge directory cleanup: {directory}; attempt={attempt}; tiExit={ti_exit}; absent={}",
                bool_text(absent)
            ));

            if !absent {
                let force_verified = remove_directory_as_trusted_installer(&directory);
                absent = force_verified || !dir_exists(&directory);
            }

            if !absent {
                match std::fs::remove_dir_all(&directory) {
                    Ok(()) => log::log(&format!(
                        "[Apps] Edge directory cleanup direct fallback completed: {directory}"
                    )),
                    Err(e) => log::log(&format!(
                        "[Apps] Edge directory cleanup direct fallback failed: {directory}; {e}"
                    )),
                }
                absent = !dir_exists(&directory);
            }

            if !absent && attempt < 3 {
                std::thread::sleep(Duration::from_millis(1000));
            }
            attempt += 1;
        }

        log::log(&format!(
            "[Apps] Edge directory cleanup final state: {directory}; absent={}",
            bool_text(absent)
        ));
        all_absent &= absent;
        if !absent {
            session_log::operation_failed("Edge directory cleanup", &directory);
        }
    }
    all_absent
}

fn remove_edge_registry_entries() -> bool {
    let guid = EDGE_BROWSER_GUID;
    let keys = [
        r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge"
            .to_string(),
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge".to_string(),
        format!(r"HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{guid}"),
        format!(r"HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\ClientState\{guid}"),
        format!(r"HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\ClientStateMedium\{guid}"),
        format!(r"HKLM\SOFTWARE\Microsoft\EdgeUpdate\Clients\{guid}"),
        format!(r"HKLM\SOFTWARE\Microsoft\EdgeUpdate\ClientState\{guid}"),
        format!(r"HKLM\SOFTWARE\Microsoft\EdgeUpdate\ClientStateMedium\{guid}"),
    ];
    let mut all_removed = true;
    for key in keys {
        if !xos_sys::reg_key_exists(&key) {
            continue;
        }
        let command_ok = xos_sys::run_as_ti("reg.exe", &format!("delete \"{key}\" /f"));
        let removed = !xos_sys::reg_key_exists(&key);
        log::log(&format!(
            "[Apps] Edge registry cleanup: {key}; commandOk={}; removed={}",
            bool_text(command_ok),
            bool_text(removed)
        ));
        all_removed &= removed;
    }
    all_removed
}

pub struct EdgeRemovalOutcome {
    pub game_assist_command_ok: bool,
    pub region_restore_ok: bool,
    pub edge_appx_removed: bool,
    pub edge_files_removed: bool,
    pub edge_registry_removed: bool,
    pub updater_block_started: bool,
}

impl EdgeRemovalOutcome {
    pub fn new() -> Self {
        Self {
            game_assist_command_ok: false,
            region_restore_ok: true,
            edge_appx_removed: true,
            edge_files_removed: true,
            edge_registry_removed: true,
            updater_block_started: false,
        }
    }
}

fn ignore_missing(r: std::io::Result<()>) -> std::io::Result<()> {
    match r {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

struct SavedRegion {
    nation: Option<RegValue<'static>>,
    geo_name: Option<RegValue<'static>>,
}

fn restore_region(saved: &SavedRegion, out: &mut EdgeRemovalOutcome) {
    let restore = || -> std::io::Result<()> {
        let geo =
            RegKey::predef(HKEY_USERS).open_subkey_with_flags(GEO_PATH, KEY_READ | KEY_WRITE)?;
        match &saved.nation {
            Some(v) => geo.set_raw_value("Nation", v)?,
            None => ignore_missing(geo.delete_value("Nation"))?,
        }
        match &saved.geo_name {
            Some(v) => geo.set_raw_value("Name", v)?,
            None => ignore_missing(geo.delete_value("Name"))?,
        }
        Ok(())
    };
    if restore().is_err() {
        out.region_restore_ok = false;
    }
    if !out.region_restore_ok {
        log::log("[Apps] Edge removal could not restore one or more temporary region values.");
    }
}

fn verify_region_spoof() -> Result<()> {
    let verify_geo = RegKey::predef(HKEY_USERS)
        .open_subkey_with_flags(GEO_PATH, KEY_READ)
        .ok();
    let nation_ok = verify_geo
        .as_ref()
        .and_then(|k| k.get_value::<String, _>("Nation").ok())
        .map(|v| v == EDGE_UNINSTALL_GEO_ID.to_string())
        .unwrap_or(false);
    let name_ok = verify_geo
        .as_ref()
        .and_then(|k| k.get_value::<String, _>("Name").ok())
        .map(|v| v.eq_ignore_ascii_case(EDGE_UNINSTALL_GEO_NAME))
        .unwrap_or(false);
    if !nation_ok || !name_ok {
        bail!("The temporary EEA region could not be verified.");
    }
    Ok(())
}

pub fn run_edge_removal(out: &mut EdgeRemovalOutcome) -> Result<()> {
    webview2::prepare_for_removal();

    let geo_key = RegKey::predef(HKEY_USERS)
        .open_subkey_with_flags(GEO_PATH, KEY_READ | KEY_WRITE)
        .map_err(|_| anyhow!("The default-user region could not be backed up."))?;
    let saved = SavedRegion {
        nation: geo_key.get_raw_value("Nation").ok(),
        geo_name: geo_key.get_raw_value("Name").ok(),
    };
    geo_key.set_value("Nation", &EDGE_UNINSTALL_GEO_ID.to_string())?;
    geo_key.set_value("Name", &EDGE_UNINSTALL_GEO_NAME)?;
    drop(geo_key);

    let inner = (|| -> Result<()> {
        verify_region_spoof()?;

        remove_edge_component(
            EDGE_BROWSER_GUID,
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge",
            true,
        )?;
        remove_edge_component(
            "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft EdgeWebView",
            true,
        )?;

        out.edge_appx_removed = remove_edge_appx_packages();
        out.edge_registry_removed = remove_edge_registry_entries();
        Ok(())
    })();

    restore_region(&saved, out);
    inner?;

    out.updater_block_started = true;
    webview2::block_installation_force(true)?;
    xos_sys::run_cmd("sc.exe", "delete MicrosoftEdgeElevationService");

    out.edge_files_removed = remove_edge_install_directories();

    let game_assist_after = get_edge_game_assist_presence();
    log::log(&format!(
        "[Apps] Edge Game Assist present after AppX cleanup: {}",
        status_text(game_assist_after, "yes", "no")
    ));
    out.game_assist_command_ok = game_assist_after == Some(false);

    xos_sys::reg_delete_key(r"HKLM\SOFTWARE\Clients\StartMenuInternet\Microsoft Edge");
    Ok(())
}

pub fn append_switch_if_missing(arguments: &str, switch_name: &str) -> String {
    let pattern = format!(r"(?i)(^|\s){}(\s|$)", regex::escape(switch_name));
    let re = Regex::new(&pattern).expect("pattern");
    if re.is_match(arguments) {
        return arguments.to_string();
    }
    if arguments.trim().is_empty() {
        switch_name.to_string()
    } else {
        format!("{} {}", arguments.trim_end(), switch_name)
    }
}

pub fn remove_edge_component(
    client_guid: &str,
    uninstall_reg_key: &str,
    enable_dev_policy: bool,
) -> Result<()> {
    let edge_update_roots = registry_views(r"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate");
    let client_state_paths: Vec<String> = edge_update_roots
        .iter()
        .map(|root| format!(r"{root}\ClientState\{client_guid}"))
        .collect();
    let client_state = client_state_paths
        .iter()
        .find(|p| hklm().open_subkey_with_flags(p.as_str(), KEY_READ).is_ok())
        .cloned()
        .unwrap_or_else(|| client_state_paths[0].clone());
    let is_web_view = client_guid.eq_ignore_ascii_case(webview2::GUID);

    if is_web_view {
        xos_sys::reg_delete_value(
            webview2::POLICY_PATH,
            &format!("Uninstall{}", webview2::GUID),
        );
        webview2::prepare_for_removal();
    }

    for uninstall_path in registry_views(uninstall_reg_key) {
        if let Ok(k) = hklm().open_subkey_with_flags(&uninstall_path, KEY_SET_VALUE) {
            let _ = k.delete_value("NoRemove");
        }
    }

    if enable_dev_policy {
        for root in registry_views(r"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdateDev") {
            if let Ok((k, _)) = hklm().create_subkey_with_flags(&root, KEY_WRITE) {
                let _ = k.set_value("AllowUninstall", &1u32);
            }
        }
    }

    for state_path in &client_state_paths {
        if let Ok(k) = hklm().open_subkey_with_flags(state_path, KEY_SET_VALUE) {
            let _ = k.delete_value("experiment_control_labels");
        }
    }

    let stub_dir = combine(
        &windows_dir(),
        r"SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe",
    );
    let _ = (|| -> std::io::Result<()> {
        if !dir_exists(&stub_dir) {
            std::fs::create_dir_all(&stub_dir)?;
        }
        let stub_exe = combine(&stub_dir, "MicrosoftEdge.exe");
        if !file_exists(&stub_exe) {
            std::fs::write(&stub_exe, [])?;
        }
        Ok(())
    })();

    let result = run_component_uninstaller(client_guid, &client_state, is_web_view);
    if let Err(e) = &result {
        log::log(&format!("[Apps] Edge component {client_guid}: {e}"));
    }
    result
}

fn run_component_uninstaller(
    client_guid: &str,
    client_state: &str,
    is_web_view: bool,
) -> Result<()> {
    let state_key = match hklm().open_subkey_with_flags(client_state, KEY_READ) {
        Ok(k) => k,
        Err(_) => {
            if is_web_view && !webview2::remove_residual_files(true) {
                bail!("WebView2 runtime files remain and no registered uninstaller is available.");
            }
            return Ok(());
        }
    };
    let uninstall_string = state_key
        .get_value::<String, _>("UninstallString")
        .unwrap_or_default()
        .trim()
        .trim_matches('"')
        .to_string();
    let uninstall_args: Option<String> =
        state_key.get_value::<String, _>("UninstallArguments").ok();
    drop(state_key);

    if uninstall_string.is_empty() || !file_exists(&uninstall_string) {
        if is_web_view && !webview2::remove_residual_files(true) {
            bail!("WebView2 runtime files remain and its registered uninstaller could not be started.");
        }
        return Ok(());
    }

    let mut arguments = if is_web_view {
        uninstall_args.unwrap_or_default()
    } else {
        String::new()
    };
    if is_web_view {
        arguments = append_switch_if_missing(&arguments, "--msedgewebview");
        arguments = append_switch_if_missing(&arguments, "--system-level");
        arguments = append_switch_if_missing(&arguments, "--verbose-logging");
    }
    arguments = append_switch_if_missing(&arguments, "--uninstall");
    arguments = append_switch_if_missing(&arguments, "--force-uninstall");

    log::log(&format!(
        "[Apps] Running Edge component {client_guid} uninstaller: {uninstall_string} {arguments}"
    ));
    let mut cmd = Command::new(&uninstall_string);
    cmd.raw_arg(&arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW);
    if let Some(dir) = std::path::Path::new(&uninstall_string).parent() {
        cmd.current_dir(dir);
    }
    if xos_sys::get_windows_build_number() < 22000 {
        cmd.env("windir", "");
    }
    let mut child = cmd.spawn()?;
    let deadline = Instant::now() + Duration::from_millis(120000);
    let exit_code = loop {
        if let Some(status) = child.try_wait()? {
            break status.code().unwrap_or(-1);
        }
        if Instant::now() >= deadline {
            bail!("The Edge component uninstaller did not finish. Wait before retrying.");
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    log::log(&format!(
        "[Apps] Edge component {client_guid} uninstaller exit code: {exit_code}"
    ));

    if is_web_view {
        let remaining = !webview2::get_executable_paths(true).is_empty();
        if exit_code != 0 || remaining {
            log::log("[WebView2] Native uninstaller did not fully remove the runtime; starting the protected cleanup fallback.");
        }
        if !webview2::remove_residual_files(true) {
            bail!("WebView2 runtime files remain after the native uninstaller and protected cleanup fallback.");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn switches_are_appended_once() {
        assert_eq!(append_switch_if_missing("", "--uninstall"), "--uninstall");
        assert_eq!(
            append_switch_if_missing("--a  ", "--uninstall"),
            "--a --uninstall"
        );
        assert_eq!(
            append_switch_if_missing("--x --UNINSTALL", "--uninstall"),
            "--x --UNINSTALL"
        );
        assert_eq!(
            append_switch_if_missing("--uninstall-all", "--uninstall"),
            "--uninstall-all --uninstall"
        );
    }

    #[test]
    fn appx_script_is_embedded() {
        assert!(EDGE_APPX_SCRIPT.contains("Microsoft.Edge.GameAssist"));
        assert!(EDGE_APPX_SCRIPT.contains("Edge and Game Assist AppX removal verified."));
    }
}

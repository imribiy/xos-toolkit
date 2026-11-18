use std::path::Path;
use std::sync::OnceLock;

use regex::Regex;

use crate::elevation::{resource_bytes, run_as_ti};
use crate::misc::notify_shell_assoc_changed;
use crate::process::{
    describe_command, run_cmd, run_cmd_capture, run_cmd_capture_into, run_cmd_opts, run_cmd_output,
    CmdOptions,
};
use crate::reg::{reg_delete_key, reg_key_exists, reg_set_dword, reg_set_string};
use crate::util::{program_data_dir, truncate_for_log};
use xos_core::log;

pub const XOS_POWER_PLAN_GUID: &str = "31693169-3169-3169-3169-316931693169";

const POWER_PLAN_TEMPLATES: [&str; 3] = [
    "e9a42b02-d5df-448d-aa00-03f14749eb61",
    "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c",
    "381b4222-f694-41f0-9685-ff5bb260df2e",
];

pub const BUILT_IN_POWER_PLANS: [&str; 4] = [
    "e9a42b02-d5df-448d-aa00-03f14749eb61",
    "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c",
    "381b4222-f694-41f0-9685-ff5bb260df2e",
    "a1841308-3541-4fab-bc81-f71556f20b4a",
];

pub type StockMarkerInvalidator = fn(&str) -> Result<(), String>;

static STOCK_MARKER_INVALIDATOR: OnceLock<StockMarkerInvalidator> = OnceLock::new();

pub fn set_stock_marker_invalidator(f: StockMarkerInvalidator) {
    let _ = STOCK_MARKER_INVALIDATOR.set(f);
}

fn power_scheme_guid_pattern() -> &'static fancy_regex::Regex {
    static R: OnceLock<fancy_regex::Regex> = OnceLock::new();
    R.get_or_init(|| {
        fancy_regex::Regex::new(
            r"(?i)(?<![0-9a-fA-F])[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?![0-9a-fA-F])",
        )
        .unwrap()
    })
}

pub(crate) fn extract_power_scheme_guid(output: &str) -> Option<String> {
    if output.trim().is_empty() {
        return None;
    }
    power_scheme_guid_pattern()
        .find(output)
        .ok()
        .flatten()
        .map(|m| m.as_str().to_string())
}

fn get_power_scheme_guids() -> Vec<String> {
    let output = run_cmd_output("powercfg.exe", "/list");
    let mut out: Vec<String> = Vec::new();
    for m in power_scheme_guid_pattern().find_iter(&output).flatten() {
        let g = m.as_str().to_string();
        if !out.iter().any(|e| e.eq_ignore_ascii_case(&g)) {
            out.push(g);
        }
    }
    out
}

pub fn try_switch_away_from_xos_power_plan() -> (bool, Option<String>) {
    let active_guid =
        extract_power_scheme_guid(&run_cmd_output("powercfg.exe", "/getactivescheme"));
    if let Some(a) = &active_guid {
        if !a.eq_ignore_ascii_case(XOS_POWER_PLAN_GUID) {
            return (true, Some(a.clone()));
        }
    }
    for candidate in get_power_scheme_guids() {
        if candidate.eq_ignore_ascii_case(XOS_POWER_PLAN_GUID) {
            continue;
        }
        run_cmd_opts(
            "powercfg.exe",
            &format!("/setactive {candidate}"),
            &CmdOptions {
                suppress_log: true,
                ..Default::default()
            },
        );
        let resulting =
            extract_power_scheme_guid(&run_cmd_output("powercfg.exe", "/getactivescheme"));
        if let Some(r) = resulting {
            if r.eq_ignore_ascii_case(&candidate) {
                return (true, Some(candidate));
            }
        }
    }
    (false, None)
}

pub fn power_plan_menu_snapshot_path() -> String {
    program_data_dir()
        .join(r"XOS Toolkit\Backup\PowerPlanShellMenu.reg")
        .to_string_lossy()
        .to_string()
}

fn snapshot_power_plan_shell_menu(shell_key_path: &str) {
    let attempt = || -> Result<(), String> {
        if !reg_key_exists(shell_key_path) {
            return Ok(());
        }
        let target = power_plan_menu_snapshot_path();
        if Path::new(&target).exists() {
            return Ok(());
        }
        if let Some(dir) = Path::new(&target).parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir).map_err(|e| crate::util::io_message(&e))?;
            }
        }
        run_cmd(
            "reg.exe",
            &format!("export \"{shell_key_path}\" \"{target}\" /y"),
        );
        if Path::new(&target).exists() {
            log::log(&format!(
                "[PowerPlan] snapshotted the original context menu to {target}"
            ));
        }
        Ok(())
    };
    if let Err(m) = attempt() {
        log::log(&format!(
            "[PowerPlan] could not snapshot the context menu: {m}"
        ));
    }
}

pub fn restore_power_plan_menu_snapshot() -> (bool, String) {
    let source = power_plan_menu_snapshot_path();
    if !Path::new(&source).exists() {
        return (
            true,
            "no snapshot was taken, menu left as rebuilt".to_string(),
        );
    }
    let base_path = r"HKCR\DesktopBackground\Shell\PowerPlan";
    let cleared = reg_delete_key(&format!(r"{base_path}\shell"));
    run_cmd("reg.exe", &format!("import \"{source}\""));
    let restored = reg_key_exists(&format!(r"{base_path}\shell"));
    let detail = if !cleared {
        "the rebuilt entries could not be removed before the snapshot import"
    } else if restored {
        "original context menu entries restored"
    } else {
        "snapshot import did not recreate the shell subtree"
    };
    (cleared && restored, detail.to_string())
}

pub fn is_xos_power_plan_imported() -> bool {
    let output = run_cmd_output("powercfg.exe", "/list");
    output.to_lowercase().contains(XOS_POWER_PLAN_GUID)
}

fn run_power_plan_command(operation: &str, arguments: &str) -> (bool, String) {
    log::log(&format!(
        "[PowerPlan] {operation}: {}",
        describe_command("powercfg.exe", arguments)
    ));
    let result = run_cmd_capture("powercfg.exe", arguments);
    let response = if !result.2.trim().is_empty() {
        result.2.trim().to_string()
    } else {
        result.1.trim().to_string()
    };
    let detail = if response.trim().is_empty() {
        format!("powercfg.exe exited with code {}.", result.0)
    } else {
        format!(
            "powercfg.exe exited with code {}:\n{}",
            result.0,
            truncate_for_log(&response)
        )
    };
    log::log(&format!(
        "[PowerPlan] {operation} -> {}",
        truncate_for_log(&detail.replace('\r', " ").replace('\n', " | "))
    ));
    (result.0 == 0, detail)
}

pub fn import_xos_power_plan() -> bool {
    import_xos_power_plan_detail().0
}

pub fn import_xos_power_plan_detail() -> (bool, String) {
    let fail = |detail: String| {
        log::result(false, "Build XOS power plan", &detail);
        (false, detail)
    };

    if let Some(invalidate) = STOCK_MARKER_INVALIDATOR.get() {
        if let Err(marker_error) = invalidate("XOS power plan") {
            return fail(format!(
                "The XOS Power Plan was not created: the restored-to-stock record could not be cleared first ({marker_error})."
            ));
        }
    }

    let active = get_active_power_plan_guid();
    let was_active = active
        .as_deref()
        .map(|a| a.eq_ignore_ascii_case(XOS_POWER_PLAN_GUID))
        .unwrap_or(false);
    if was_active {
        for candidate in [POWER_PLAN_TEMPLATES[1], POWER_PLAN_TEMPLATES[2]] {
            if run_power_plan_command("setactive", &format!("/setactive {candidate}")).0 {
                break;
            }
        }
        if get_active_power_plan_guid()
            .map(|a| a.eq_ignore_ascii_case(XOS_POWER_PLAN_GUID))
            .unwrap_or(false)
        {
            return fail(
                "The XOS Power Plan is active and no built-in plan could be activated to replace it."
                    .to_string(),
            );
        }
    }

    if is_xos_power_plan_imported() {
        run_power_plan_command("delete", &format!("/delete {XOS_POWER_PLAN_GUID}"));
    }

    let mut template: Option<String> = None;
    let mut template_detail: Option<String> = None;
    for candidate in POWER_PLAN_TEMPLATES {
        let (ok, d) = run_power_plan_command(
            "duplicatescheme",
            &format!("/duplicatescheme {candidate} {XOS_POWER_PLAN_GUID}"),
        );
        template_detail = Some(d);
        if ok && is_xos_power_plan_imported() {
            template = Some(candidate.to_string());
            break;
        }
    }

    let template = match template {
        Some(t) => t,
        None => {
            let current = get_active_power_plan_guid();
            let copied = match &current {
                Some(c) if !c.is_empty() => {
                    let (ok, d) = run_power_plan_command(
                        "duplicatescheme",
                        &format!("/duplicatescheme {c} {XOS_POWER_PLAN_GUID}"),
                    );
                    template_detail = Some(d);
                    ok && is_xos_power_plan_imported()
                }
                _ => false,
            };
            if !copied {
                return fail(format!(
                    "No power plan could be copied to create the XOS Power Plan: {}",
                    template_detail.unwrap_or_else(|| "no template available".to_string())
                ));
            }
            current.unwrap()
        }
    };

    let mut applied = 0;
    let mut skipped = 0;
    for setting in read_embedded_power_plan_settings() {
        let ac_args = format!(
            "/setacvalueindex {XOS_POWER_PLAN_GUID} {} {} {}",
            setting.subgroup, setting.setting, setting.ac_value
        );
        if run_power_plan_command("setac", &ac_args).0 {
            applied += 1;
        } else {
            skipped += 1;
        }
        let dc_args = format!(
            "/setdcvalueindex {XOS_POWER_PLAN_GUID} {} {} {}",
            setting.subgroup, setting.setting, setting.dc_value
        );
        if run_power_plan_command("setdc", &dc_args).0 {
            applied += 1;
        } else {
            skipped += 1;
        }
    }

    if applied == 0 {
        return fail(
            "The XOS Power Plan was created but no setting could be written to it.".to_string(),
        );
    }

    run_power_plan_command("setactive", &format!("/setactive {XOS_POWER_PLAN_GUID}"));
    let named = set_power_plan_friendly_name();

    if !is_xos_power_plan_imported() {
        return fail(
            "powercfg.exe reported success, but the XOS Power Plan GUID was not found in powercfg /list."
                .to_string(),
        );
    }

    let detail = format!(
        "Built the XOS Power Plan from the {} template: {applied} values applied, {skipped} skipped because this Windows build does not have them. {}",
        describe_power_plan(&template),
        if named {
            "The plan is named and active."
        } else {
            "The plan is active but its registry name could not be written, so Power Options shows the template name."
        }
    );
    log::result(true, "Build XOS power plan", &detail);
    (true, detail)
}

fn get_active_power_plan_guid() -> Option<String> {
    let output = run_cmd_output("powercfg.exe", "/getactivescheme");
    static R: OnceLock<Regex> = OnceLock::new();
    let r = R.get_or_init(|| {
        Regex::new("([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})")
            .unwrap()
    });
    r.captures(&output).map(|c| c[1].to_string())
}

fn describe_power_plan(guid: &str) -> String {
    for candidate in POWER_PLAN_TEMPLATES {
        if candidate.eq_ignore_ascii_case(guid) {
            return if candidate == POWER_PLAN_TEMPLATES[0] {
                "Ultimate Performance"
            } else if candidate == POWER_PLAN_TEMPLATES[1] {
                "High performance"
            } else {
                "Balanced"
            }
            .to_string();
        }
    }
    guid.to_string()
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PowerPlanSetting {
    pub subgroup: String,
    pub setting: String,
    pub ac_value: i32,
    pub dc_value: i32,
}

pub fn parse_power_plan_settings(csv: &str) -> Vec<PowerPlanSetting> {
    let mut settings = Vec::new();
    let mut first = true;
    for line in csv.trim_start_matches('\u{feff}').lines() {
        if first {
            first = false;
            if line.to_lowercase().starts_with("sub") {
                continue;
            }
        }
        if line.trim().is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split(',').collect();
        if parts.len() < 4 {
            continue;
        }
        let ac: i32 = match parts[2].trim().parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let dc: i32 = parts[3].trim().parse().unwrap_or(ac);
        settings.push(PowerPlanSetting {
            subgroup: parts[0].trim().to_string(),
            setting: parts[1].trim().to_string(),
            ac_value: ac,
            dc_value: dc,
        });
    }
    settings
}

fn read_embedded_power_plan_settings() -> Vec<PowerPlanSetting> {
    match resource_bytes("XOSToolkit.XOS-PowerSettings.csv") {
        Some(bytes) => parse_power_plan_settings(&String::from_utf8_lossy(bytes)),
        None => {
            log::log("[PowerPlan] The embedded XOS-PowerSettings.csv resource is missing from this build.");
            Vec::new()
        }
    }
}

fn set_power_plan_friendly_name() -> bool {
    let key = format!(
        r"HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\{XOS_POWER_PLAN_GUID}"
    );
    let name_ok = run_as_ti(
        "reg.exe",
        &format!("add \"{key}\" /v FriendlyName /t REG_SZ /d \"imribiy Power Plan\" /f"),
    );
    run_as_ti(
        "reg.exe",
        &format!("add \"{key}\" /v Description /t REG_SZ /d \"dsc.gg/xos\" /f"),
    );

    if !name_ok {
        log::log("[PowerPlan] The plan name could not be written; Power Options will show the template name.");
    }
    name_ok
}

pub fn delete_xos_power_plan() -> bool {
    delete_xos_power_plan_detail().0
}

pub fn delete_xos_power_plan_detail() -> (bool, String) {
    let (mut success, mut detail) =
        run_power_plan_command("delete", &format!("/delete {XOS_POWER_PLAN_GUID}"));
    if success && is_xos_power_plan_imported() {
        detail = "powercfg.exe reported success, but the XOS Power Plan GUID is still present in powercfg /list."
            .to_string();
        success = false;
    } else if success {
        detail = "powercfg.exe removed the plan and the XOS Power Plan GUID was verified absent."
            .to_string();
    }
    log::result(success, "Delete XOS power plan", &detail);
    (success, detail)
}

pub fn is_power_plan_context_menu_installed() -> bool {
    reg_key_exists(r"HKCR\DesktopBackground\Shell\PowerPlan")
}

pub fn sync_power_plan_context_menu() {
    if !is_power_plan_context_menu_installed() {
        return;
    }

    let xos_imported = is_xos_power_plan_imported();

    let base_path = r"HKCR\DesktopBackground\Shell\PowerPlan";
    snapshot_power_plan_shell_menu(&format!(r"{base_path}\shell"));
    reg_delete_key(&format!(r"{base_path}\shell"));

    let entry = |n: &str, verb: &str, command: &str| {
        reg_set_string(&format!(r"{base_path}\shell\{n}"), "MUIVerb", verb);
        reg_set_string(&format!(r"{base_path}\shell\{n}"), "Icon", "powercpl.dll");
        reg_set_string(&format!(r"{base_path}\shell\{n}\command"), "", command);
    };
    entry(
        "01menu",
        "Power Saver",
        "powercfg.exe /setactive a1841308-3541-4fab-bc81-f71556f20b4a",
    );
    entry(
        "02menu",
        "Balanced",
        "powercfg.exe /setactive 381b4222-f694-41f0-9685-ff5bb260df2e",
    );
    entry(
        "03menu",
        "High Performance",
        "powercfg.exe /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c",
    );

    let mut next = 4;
    if xos_imported {
        entry(
            "04menu",
            "XOS Power Plan",
            &format!("powercfg.exe /setactive {XOS_POWER_PLAN_GUID}"),
        );
        next = 5;
    }

    let idle_key = format!(r"{base_path}\shell\{next:02}menu");
    reg_set_string(&idle_key, "MUIVerb", "Disable Idle");
    reg_set_string(&idle_key, "Icon", "powercpl.dll");
    reg_set_dword(&idle_key, "CommandFlags", 0x20);
    reg_set_string(
        &format!(r"{idle_key}\command"),
        "",
        "cmd.exe /c powercfg -setacvalueindex scheme_current sub_processor 5d76a2ca-e8c0-402f-a133-2158492d58ad 1 && powercfg -setactive scheme_current",
    );
    next += 1;

    let enable_key = format!(r"{base_path}\shell\{next:02}menu");
    reg_set_string(&enable_key, "MUIVerb", "Enable Idle");
    reg_set_string(&enable_key, "Icon", "powercpl.dll");
    reg_set_string(
        &format!(r"{enable_key}\command"),
        "",
        "cmd.exe /c powercfg -setacvalueindex scheme_current sub_processor 5d76a2ca-e8c0-402f-a133-2158492d58ad 0 && powercfg -setactive scheme_current",
    );
    next += 1;

    let options_key = format!(r"{base_path}\shell\{next:02}menu");
    reg_set_string(&options_key, "MUIVerb", "Power Options");
    reg_set_string(&options_key, "Icon", "powercpl.dll");
    reg_set_dword(&options_key, "CommandFlags", 0x20);
    reg_set_string(
        &format!(r"{options_key}\command"),
        "",
        "control.exe powercfg.cpl",
    );

    notify_shell_assoc_changed();
}

pub fn hibernate_set(enable: bool) -> (bool, Option<String>) {
    let mut output = String::new();
    let mut ok = run_cmd_capture_into(
        "powercfg.exe",
        if enable { "-h on" } else { "-h off" },
        &mut output,
    );
    if ok && enable {
        ok = run_cmd_capture_into("powercfg.exe", "/h /type full", &mut output);
    }
    let mut blocker = None;
    if !ok {
        blocker = extract_hibernate_blocker(&output);
        log::log(&format!(
            "[Hibernate] {} refused: {}",
            if enable { "enable" } else { "disable" },
            blocker.as_deref().unwrap_or("(no reason reported)")
        ));
    }
    (ok, blocker)
}

pub(crate) fn extract_hibernate_blocker(text: &str) -> Option<String> {
    if text.trim().is_empty() {
        return None;
    }
    let lines: Vec<String> = text
        .replace('\r', "")
        .split('\n')
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    if lines.is_empty() {
        return None;
    }
    let detail: Vec<&String> = lines.iter().skip(1).collect();
    if detail.is_empty() {
        return Some(lines[0].clone());
    }
    Some(
        detail
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(" "),
    )
}

pub fn power_cfg_set(subgroup: &str, setting: &str, ac_value: i32, dc_value: i32) -> bool {
    let a = run_cmd(
        "powercfg.exe",
        &format!("/SETACVALUEINDEX SCHEME_CURRENT {subgroup} {setting} {ac_value}"),
    );
    let b = run_cmd(
        "powercfg.exe",
        &format!("/SETDCVALUEINDEX SCHEME_CURRENT {subgroup} {setting} {dc_value}"),
    );
    let c = run_cmd("powercfg.exe", "/SETACTIVE SCHEME_CURRENT");
    a && b && c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guid_extraction() {
        let out = "Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2e  (Balanced)";
        assert_eq!(
            extract_power_scheme_guid(out).as_deref(),
            Some("381b4222-f694-41f0-9685-ff5bb260df2e")
        );
        assert_eq!(extract_power_scheme_guid("   "), None);
        assert_eq!(
            extract_power_scheme_guid("aa381b4222-f694-41f0-9685-ff5bb260df2e0"),
            None
        );
    }

    #[test]
    fn csv_parse() {
        let csv = "Subgroup,Setting,AC,DC\r\nsub_a,set_a,1,2\r\n\r\nsub_b,set_b,5,x\r\nbad,line\r\nsub_c,set_c,zz,1\r\n";
        let s = parse_power_plan_settings(csv);
        assert_eq!(s.len(), 2);
        assert_eq!((s[0].ac_value, s[0].dc_value), (1, 2));
        assert_eq!((s[1].ac_value, s[1].dc_value), (5, 5));
    }

    #[test]
    fn embedded_csv_has_rows() {
        assert!(!read_embedded_power_plan_settings().is_empty());
    }

    #[test]
    fn blocker() {
        assert_eq!(
            extract_hibernate_blocker("first\r\nsecond\r\nthird").as_deref(),
            Some("second third")
        );
        assert_eq!(extract_hibernate_blocker("only").as_deref(), Some("only"));
        assert_eq!(extract_hibernate_blocker(" \r\n"), None);
    }
}

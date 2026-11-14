use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use regex::Regex;
use windows::Win32::Storage::FileSystem::{ReplaceFileW, REPLACE_FILE_FLAGS};
use xos_core::log;
use xos_core::status;
use xos_sys::{
    expand_environment_variables, get_windows_build_number, reg_delete_value, reg_get_dword,
    reg_get_string, reg_set_dword, reg_value_exists, run_cmd_opts, CmdOptions,
};

use crate::util::{
    env_path, eq_ignore_case, io_msg, ordinal_ignore_case_key, system_directory, wide,
};

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct PolEntry {
    pub key: String,
    pub name: String,
    pub kind: u32,
    pub data: Vec<u8>,
    pub raw: Vec<u8>,
}

const POLICIES: [[&str; 2]; 2] = [
    [r"SOFTWARE\Policies\Microsoft\Dsh", "AllowNewsAndInterests"],
    [
        r"SOFTWARE\Policies\Microsoft\Windows\Windows Feeds",
        "EnableFeeds",
    ],
];

const PREG_SIGNATURE: u32 = 0x67655250;
const REG_DWORD: u32 = 4;
const REGISTRY_CSE: &str = "{35378EAC-683F-11D2-A89A-00C04FBBCFA2}";
const ADMIN_TEMPLATES_TOOL: &str = "{D02B1F72-3407-48AE-BA88-E8213C6761F1}";
const USER_VALUE_PATH: &str = r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds";
const USER_VALUE_NAME: &str = "ShellFeedsTaskbarViewMode";
const USER_VALUE_DISABLED: i32 = 2;

fn policy_root() -> PathBuf {
    Path::new(&system_directory()).join("GroupPolicy")
}

fn machine_pol_path() -> PathBuf {
    policy_root().join(r"Machine\Registry.pol")
}

fn gpt_ini_path() -> PathBuf {
    policy_root().join("gpt.ini")
}

pub fn is_home_edition() -> bool {
    let edition = reg_get_string(
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        "EditionID",
    )
    .unwrap_or_default();
    edition.to_uppercase().starts_with("CORE")
}

pub fn is_windows10_home() -> bool {
    get_windows_build_number() < 22000 && is_home_edition()
}

fn set_user_value_disabled() -> Option<String> {
    if !reg_set_dword(USER_VALUE_PATH, USER_VALUE_NAME, USER_VALUE_DISABLED) {
        return Some(
            "ShellFeedsTaskbarViewMode could not be set to 2 through the registry API".to_string(),
        );
    }
    let after = reg_get_dword(USER_VALUE_PATH, USER_VALUE_NAME);
    if after != Some(USER_VALUE_DISABLED) {
        return Some(format!(
            "ShellFeedsTaskbarViewMode reads {} after the write instead of 2",
            after
                .map(|v| v.to_string())
                .unwrap_or_else(|| "absent".to_string())
        ));
    }
    None
}

fn staged_step_path() -> PathBuf {
    Path::new(&env_path("APPDATA"))
        .join(r"Microsoft\Windows\Start Menu\Programs\Startup\feeds-home.bat")
}

fn default_staged_step_path() -> Option<PathBuf> {
    let dir = reg_get_string(
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList",
        "Default",
    )?;
    if dir.is_empty() {
        return None;
    }
    Some(
        Path::new(&expand_environment_variables(&dir))
            .join(r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\feeds-home.bat"),
    )
}

fn remove_staged_step() -> (Option<String>, bool) {
    let mut paths = vec![staged_step_path()];
    if let Some(d) = default_staged_step_path() {
        if !paths.contains(&d) {
            paths.push(d);
        }
    }
    let mut existed = false;
    let mut problems: Vec<String> = Vec::new();
    for path in paths {
        if !path.is_file() {
            continue;
        }
        existed = true;
        if let Err(e) = std::fs::remove_file(&path) {
            problems.push(format!(
                "{} could not be removed: {}",
                path.display(),
                io_msg(&e)
            ));
            continue;
        }
        if path.is_file() {
            problems.push(format!(
                "{} is still there after the delete",
                path.display()
            ));
        }
    }
    (
        if problems.is_empty() {
            None
        } else {
            Some(problems.join("; "))
        },
        existed,
    )
}

pub fn read_state() -> (String, Option<String>) {
    if is_windows10_home()
        && reg_get_dword(USER_VALUE_PATH, USER_VALUE_NAME) == Some(USER_VALUE_DISABLED)
    {
        return (
            "Disabled".to_string(),
            Some("News and interests is off through the per-user taskbar value; Windows Home has no local Group Policy route for it".to_string()),
        );
    }
    let entries = match read_entries() {
        Ok(e) => e,
        Err(e) => {
            return (
                "Unknown".to_string(),
                Some(format!("Registry.pol could not be read: {e}")),
            )
        }
    };
    let mut states: Vec<&str> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    for p in &POLICIES {
        let path = format!(r"HKLM\{}", p[0]);
        let value = reg_get_dword(&path, p[1]);
        let in_pol = entries.iter().any(|e| is_slot(e, p) && is_xos_value(e));
        if in_pol && value == Some(0) {
            states.push("policy");
        } else if in_pol {
            states.push("pending");
            notes.push(format!(
                "{} is in Registry.pol but Windows has not applied it",
                p[1]
            ));
        } else if value == Some(0) {
            states.push("direct");
            notes.push(format!("{} is 0 without a local Group Policy entry, written directly by an older XOS or another tool", p[1]));
        } else if !reg_value_exists(&path, p[1]) {
            states.push("absent");
        } else {
            states.push("enabled");
        }
    }
    let detail = if notes.is_empty() {
        None
    } else {
        Some(format!(
            "{}. Disable or Enable (Default) sets both consistently.",
            notes.join("; ")
        ))
    };
    let state = if states.iter().all(|x| *x == "policy") {
        "Disabled".to_string()
    } else if states.iter().all(|x| *x == "absent") {
        status::ENABLED_WINDOWS_DEFAULT.to_string()
    } else if states.iter().all(|x| *x == "absent" || *x == "enabled") {
        "Enabled".to_string()
    } else {
        "Partial".to_string()
    };
    (state, detail)
}

pub fn disable() -> (bool, String) {
    if is_windows10_home() {
        let failure = set_user_value_disabled();
        let home_ok = failure.is_none();
        let detail = match failure {
            None => "News and interests is off through the per-user taskbar value, the route Windows Home has; the local Group Policy entry cannot apply there".to_string(),
            Some(f) => f,
        };
        log::result(home_ok, "Widgets and News policy disable", &detail);
        return (home_ok, detail);
    }
    let mut entries = match read_entries() {
        Ok(e) => e,
        Err(e) => {
            let detail = format!("Registry.pol could not be read and was left unchanged: {e}");
            log::result(false, "Widgets and News policy disable", &detail);
            return (false, detail);
        }
    };
    entries.retain(|e| !is_owned_slot(e));
    for p in &POLICIES {
        entries.push(new_dword_entry(p[0], p[1], 0));
    }
    if let Some(write_error) = write_policy_files(&entries) {
        log::result(false, "Widgets and News policy disable", &write_error);
        return (false, write_error);
    }

    let (refreshed, refresh) = refresh_policy();
    let after = read_entries().unwrap_or_default();
    let mut problems: Vec<String> = Vec::new();
    for p in &POLICIES {
        if !after.iter().any(|e| is_slot(e, p) && is_xos_value(e)) {
            problems.push(format!("{} has no Registry.pol entry", p[1]));
        }
        if reg_get_dword(&format!(r"HKLM\{}", p[0]), p[1]) != Some(0) {
            problems.push(format!("{} is not 0", p[1]));
        }
    }
    if !refreshed {
        problems.insert(0, refresh);
    }
    let ok = problems.is_empty();
    let detail = if ok {
        "AllowNewsAndInterests and EnableFeeds are 0 through local Group Policy".to_string()
    } else {
        format!("{}{}", problems.join(", "), home_note())
    };
    log::result(ok, "Widgets and News policy disable", &detail);
    (ok, detail)
}

pub fn enable() -> (bool, String) {
    let mut entries = match read_entries() {
        Ok(e) => e,
        Err(e) => {
            let detail = format!("Registry.pol could not be read and was left unchanged: {e}");
            log::result(false, "Widgets and News policy removal", &detail);
            return (false, detail);
        }
    };
    let before = entries.len();
    entries.retain(|e| !(is_owned_slot(e) && is_xos_value(e)));
    let removed = before - entries.len();
    let mut refresh = "no Registry.pol entry to remove".to_string();
    if removed > 0 {
        if let Some(write_error) = write_policy_files(&entries) {
            log::result(false, "Widgets and News policy removal", &write_error);
            return (false, write_error);
        }
        refresh = refresh_policy().1;
    }

    for p in &POLICIES {
        let path = format!(r"HKLM\{}", p[0]);
        if reg_get_dword(&path, p[1]) == Some(0) {
            reg_delete_value(&path, p[1]);
        }
    }
    let mut user_value_left = false;
    if is_windows10_home()
        && reg_get_dword(USER_VALUE_PATH, USER_VALUE_NAME) == Some(USER_VALUE_DISABLED)
    {
        reg_delete_value(USER_VALUE_PATH, USER_VALUE_NAME);
        user_value_left =
            reg_get_dword(USER_VALUE_PATH, USER_VALUE_NAME) == Some(USER_VALUE_DISABLED);
    }
    let (staged_failure, staged_existed) = remove_staged_step();
    if staged_existed && staged_failure.is_none() {
        log::log(
            "[OP] Widgets and News: the staged feeds-home.bat was removed from the Startup folders",
        );
    }
    let after = read_entries().unwrap_or_default();
    let mut problems: Vec<String> = Vec::new();
    let left: Vec<&str> = POLICIES
        .iter()
        .filter(|p| {
            reg_get_dword(&format!(r"HKLM\{}", p[0]), p[1]) == Some(0)
                || after.iter().any(|e| is_slot(e, p) && is_xos_value(e))
        })
        .map(|p| p[1])
        .collect();
    if !left.is_empty() {
        problems.push(format!(
            "{} still 0 or still in Registry.pol after policy removal ({refresh})",
            left.join(", ")
        ));
    }
    if user_value_left {
        problems.push(format!("{USER_VALUE_NAME} is still 2 after the removal"));
    }
    if let Some(f) = staged_failure {
        problems.push(f);
    }
    let ok = problems.is_empty();
    let detail = if ok {
        format!(
            "{removed} Registry.pol entr{} removed, AllowNewsAndInterests and EnableFeeds are not 0 ({refresh})",
            if removed == 1 { "y" } else { "ies" }
        )
    } else {
        problems.join("; ")
    };
    log::result(ok, "Widgets and News policy removal", &detail);
    (ok, detail)
}

fn home_note() -> &'static str {
    if is_home_edition() {
        "; Windows Home, where Microsoft does not document local Group Policy processing"
    } else {
        ""
    }
}

fn is_owned_slot(e: &PolEntry) -> bool {
    POLICIES.iter().any(|p| {
        eq_ignore_case(&e.key, p[0])
            && (eq_ignore_case(&e.name, p[1])
                || eq_ignore_case(&e.name, &format!("**del.{}", p[1])))
    })
}

fn is_slot(e: &PolEntry, p: &[&str; 2]) -> bool {
    eq_ignore_case(&e.key, p[0]) && eq_ignore_case(&e.name, p[1])
}

fn is_xos_value(e: &PolEntry) -> bool {
    e.kind == REG_DWORD
        && e.data.len() == 4
        && u32::from_le_bytes([e.data[0], e.data[1], e.data[2], e.data[3]]) == 0
        && !e.name.starts_with("**")
}

fn refresh_policy() -> (bool, String) {
    let gpupdate = format!(r"{}\gpupdate.exe", system_directory());
    let ok = run_cmd_opts(
        &gpupdate,
        "/target:computer /force",
        &CmdOptions {
            timeout_ms: Some(180000),
            standard_input: Some("N\r\n"),
            ..Default::default()
        },
    );
    (
        ok,
        if ok {
            "gpupdate exit 0".to_string()
        } else {
            "gpupdate did not finish cleanly".to_string()
        },
    )
}

fn write_policy_files(entries: &[PolEntry]) -> Option<String> {
    let built = (|| -> Result<(Vec<u8>, Vec<u8>)> {
        let pol = build_pol(entries);
        let existing = match std::fs::read(gpt_ini_path()) {
            Ok(bytes) => Some(decode_text(&bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(anyhow!("{}", io_msg(&e))),
        };
        let gpt = build_gpt_ini(existing.as_deref());
        Ok((pol, gpt))
    })();
    let (pol, gpt) = match built {
        Ok(v) => v,
        Err(e) => return Some(format!("Registry.pol and gpt.ini left unchanged, {e}")),
    };
    if let Err(e) = replace_file(&gpt_ini_path(), &gpt) {
        return Some(format!(
            "gpt.ini could not be written ({}), Registry.pol left unchanged",
            io_msg(&e)
        ));
    }
    if let Err(e) = replace_file(&machine_pol_path(), &pol) {
        return Some(format!("Registry.pol could not be written ({}), left unchanged; gpt.ini already has the raised version, which changes no setting", io_msg(&e)));
    }
    None
}

fn replace_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut temp = path.as_os_str().to_os_string();
    temp.push(".xos-tmp");
    let temp = PathBuf::from(temp);
    let attempt = || -> std::io::Result<()> {
        std::fs::write(&temp, bytes)?;
        if path.is_file() {
            let target = wide(&path.to_string_lossy());
            let source = wide(&temp.to_string_lossy());
            unsafe {
                ReplaceFileW(
                    windows::core::PCWSTR(target.as_ptr()),
                    windows::core::PCWSTR(source.as_ptr()),
                    windows::core::PCWSTR::null(),
                    REPLACE_FILE_FLAGS(0),
                    None,
                    None,
                )
                .map_err(|e| std::io::Error::from_raw_os_error((e.code().0 as u32 & 0xFFFF) as i32))
            }
        } else {
            std::fs::rename(&temp, path)
        }
    };
    match attempt() {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&temp);
            Err(e)
        }
    }
}

fn decode_text(bytes: &[u8]) -> String {
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return String::from_utf8_lossy(&bytes[3..]).into_owned();
    }
    if bytes.starts_with(&[0xFF, 0xFE]) {
        let units: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        return String::from_utf16_lossy(&units);
    }
    if bytes.starts_with(&[0xFE, 0xFF]) {
        let units: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        return String::from_utf16_lossy(&units);
    }
    String::from_utf8_lossy(bytes).into_owned()
}

fn read_all_lines(text: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    let mut chars = text.chars().peekable();
    let mut pending = false;
    while let Some(c) = chars.next() {
        match c {
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                lines.push(std::mem::take(&mut current));
                pending = false;
            }
            '\n' => {
                lines.push(std::mem::take(&mut current));
                pending = false;
            }
            _ => {
                current.push(c);
                pending = true;
            }
        }
    }
    if pending {
        lines.push(current);
    }
    lines
}

fn read_entries() -> Result<Vec<PolEntry>> {
    let path = machine_pol_path();
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let bytes = std::fs::read(&path).map_err(|e| anyhow!("{}", io_msg(&e)))?;
    parse_pol(&bytes)
}

pub(crate) fn parse_pol(b: &[u8]) -> Result<Vec<PolEntry>> {
    let mut entries = Vec::new();
    let u32_at = |pos: usize| u32::from_le_bytes([b[pos], b[pos + 1], b[pos + 2], b[pos + 3]]);
    if b.len() < 8 || u32_at(0) != PREG_SIGNATURE || u32_at(4) != 1 {
        return Err(anyhow!("Registry.pol has no PReg version 1 header"));
    }
    let mut pos = 8usize;
    while pos < b.len() {
        let start = pos;
        expect(b, &mut pos, '[')?;
        let key = read_string(b, &mut pos)?;
        expect(b, &mut pos, ';')?;
        let name = read_string(b, &mut pos)?;
        expect(b, &mut pos, ';')?;
        let kind = read_uint(b, &mut pos)?;
        expect(b, &mut pos, ';')?;
        let size = read_uint(b, &mut pos)? as usize;
        expect(b, &mut pos, ';')?;
        if size > b.len() - pos {
            return Err(anyhow!("Registry.pol entry truncated at offset {start}"));
        }
        let data = b[pos..pos + size].to_vec();
        pos += size;
        expect(b, &mut pos, ']')?;
        let raw = b[start..pos].to_vec();
        entries.push(PolEntry {
            key,
            name,
            kind,
            data,
            raw,
        });
    }
    Ok(entries)
}

fn expect(b: &[u8], pos: &mut usize, c: char) -> Result<()> {
    if *pos + 1 >= b.len() || u16::from_le_bytes([b[*pos], b[*pos + 1]]) != c as u16 {
        return Err(anyhow!("Registry.pol: expected '{c}' at offset {}", *pos));
    }
    *pos += 2;
    Ok(())
}

fn read_string(b: &[u8], pos: &mut usize) -> Result<String> {
    let start = *pos;
    while *pos + 1 < b.len() && u16::from_le_bytes([b[*pos], b[*pos + 1]]) != 0 {
        *pos += 2;
    }
    if *pos + 1 >= b.len() {
        return Err(anyhow!(
            "Registry.pol: unterminated string at offset {start}"
        ));
    }
    let units: Vec<u16> = b[start..*pos]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    *pos += 2;
    Ok(String::from_utf16_lossy(&units))
}

fn read_uint(b: &[u8], pos: &mut usize) -> Result<u32> {
    if *pos + 4 > b.len() {
        return Err(anyhow!("Registry.pol truncated at offset {}", *pos));
    }
    let v = u32::from_le_bytes([b[*pos], b[*pos + 1], b[*pos + 2], b[*pos + 3]]);
    *pos += 4;
    Ok(v)
}

fn utf16_bytes(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

pub(crate) fn new_dword_entry(key: &str, name: &str, value: u32) -> PolEntry {
    let mut raw: Vec<u8> = Vec::new();
    raw.extend(utf16_bytes(&format!("[{key}\0;{name}\0;")));
    raw.extend(REG_DWORD.to_le_bytes());
    raw.extend(utf16_bytes(";"));
    raw.extend(4u32.to_le_bytes());
    raw.extend(utf16_bytes(";"));
    raw.extend(value.to_le_bytes());
    raw.extend(utf16_bytes("]"));
    PolEntry {
        key: key.to_string(),
        name: name.to_string(),
        kind: REG_DWORD,
        data: value.to_le_bytes().to_vec(),
        raw,
    }
}

pub(crate) fn build_pol(entries: &[PolEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(PREG_SIGNATURE.to_le_bytes());
    out.extend(1u32.to_le_bytes());
    for e in entries {
        out.extend(&e.raw);
    }
    out
}

fn extension_guid_regex() -> Regex {
    Regex::new(r"\{[^}]*\}").unwrap()
}

pub(crate) fn build_gpt_ini(existing: Option<&str>) -> Vec<u8> {
    let general_re = Regex::new(r"(?i)^\s*\[General\]\s*$").unwrap();
    let version_re = Regex::new(r"(?i)^\s*Version\s*=").unwrap();
    let version_prefix_re = Regex::new(r"(?i)^\s*Version\s*=\s*").unwrap();
    let ext_re = Regex::new(r"(?i)^\s*gPCMachineExtensionNames\s*=").unwrap();
    let group_re = Regex::new(r"\[[^\]]*\]").unwrap();
    let guid_re = extension_guid_regex();

    let mut lines: Vec<String> = existing.map(read_all_lines).unwrap_or_default();
    let mut general = lines.iter().position(|l| general_re.is_match(l));
    if general.is_none() {
        lines.insert(0, "[General]".to_string());
        general = Some(0);
    }
    let general = general.unwrap();

    let version_at = lines.iter().position(|l| version_re.is_match(l));
    let mut version: i64 = 0;
    if let Some(i) = version_at {
        version = version_prefix_re
            .replace(&lines[i], "")
            .trim()
            .parse::<i64>()
            .unwrap_or(0);
    }
    let mut machine = ((version & 0xFFFF) + 1) & 0xFFFF;
    if machine == 0 {
        machine = 1;
    }
    let version_line = format!("Version={}", (version & 0xFFFF0000) | machine);
    match version_at {
        Some(i) => lines[i] = version_line,
        None => lines.insert(general + 1, version_line),
    }

    let ext_at = lines.iter().position(|l| ext_re.is_match(l));
    let mut groups: Vec<String> = Vec::new();
    if let Some(i) = ext_at {
        let rest = &lines[i][lines[i].find('=').unwrap() + 1..];
        groups.extend(group_re.find_iter(rest).map(|m| m.as_str().to_string()));
    }
    let mut found = false;
    for group in groups.iter_mut() {
        let guids: Vec<String> = guid_re
            .find_iter(group)
            .map(|m| m.as_str().to_string())
            .collect();
        if guids.is_empty() || !eq_ignore_case(&guids[0], REGISTRY_CSE) {
            continue;
        }
        found = true;
        if guids[1..]
            .iter()
            .any(|g| eq_ignore_case(g, ADMIN_TEMPLATES_TOOL))
        {
            continue;
        }
        let mut tools: Vec<String> = guids[1..].to_vec();
        tools.push(ADMIN_TEMPLATES_TOOL.to_string());
        tools.sort_by_key(|g| ordinal_ignore_case_key(g));
        *group = format!("[{REGISTRY_CSE}{}]", tools.concat());
    }
    if !found {
        groups.push(format!("[{REGISTRY_CSE}{ADMIN_TEMPLATES_TOOL}]"));
    }
    groups.sort_by_key(|g| ordinal_ignore_case_key(g));
    let ext_line = format!("gPCMachineExtensionNames={}", groups.concat());
    match ext_at {
        Some(i) => lines[i] = ext_line,
        None => lines.insert(general + 1, ext_line),
    }

    let text = format!("{}\r\n", lines.join("\r\n"));
    text.encode_utf16()
        .map(|u| if u < 128 { u as u8 } else { b'?' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gpt(existing: Option<&str>) -> String {
        String::from_utf8(build_gpt_ini(existing)).unwrap()
    }

    #[test]
    fn pol_round_trip_in_memory() {
        let entries = vec![
            new_dword_entry(
                r"SOFTWARE\Policies\Microsoft\Dsh",
                "AllowNewsAndInterests",
                0,
            ),
            new_dword_entry(
                r"SOFTWARE\Policies\Microsoft\Windows\Windows Feeds",
                "EnableFeeds",
                7,
            ),
        ];
        let bytes = build_pol(&entries);
        assert_eq!(&bytes[..8], &[0x50, 0x52, 0x65, 0x67, 1, 0, 0, 0]);
        let parsed = parse_pol(&bytes).unwrap();
        assert_eq!(parsed, entries);
        assert!(is_xos_value(&parsed[0]));
        assert!(!is_xos_value(&parsed[1]));
        assert_eq!(build_pol(&parsed), bytes);
    }

    #[test]
    fn pol_header_only_and_errors() {
        let header = build_pol(&[]);
        assert!(parse_pol(&header).unwrap().is_empty());
        assert!(parse_pol(&[1, 2, 3]).is_err());
        let mut bad = build_pol(&[new_dword_entry("K", "N", 0)]);
        bad.truncate(bad.len() - 2);
        assert!(parse_pol(&bad).is_err());
        let mut sig = header.clone();
        sig[4] = 2;
        assert!(parse_pol(&sig).is_err());
    }

    #[test]
    fn owned_slot_matches_del_prefix() {
        let del = new_dword_entry(
            r"software\policies\microsoft\dsh",
            "**del.AllowNewsAndInterests",
            0,
        );
        assert!(is_owned_slot(&del));
        assert!(!is_xos_value(&del));
        let other = new_dword_entry(r"SOFTWARE\Policies\Microsoft\Dsh", "Other", 0);
        assert!(!is_owned_slot(&other));
    }

    #[test]
    fn gpt_ini_fresh_file() {
        assert_eq!(
            gpt(None),
            format!(
                "[General]\r\ngPCMachineExtensionNames=[{REGISTRY_CSE}{ADMIN_TEMPLATES_TOOL}]\r\nVersion=1\r\n"
            )
        );
    }

    #[test]
    fn gpt_ini_version_bump_keeps_user_half() {
        let out = gpt(Some("[General]\r\nVersion=65537\r\n"));
        assert!(out.contains("Version=65538\r\n"));
        let wrap = gpt(Some("[General]\r\nVersion=65535\r\n"));
        assert!(wrap.contains("Version=1\r\n"));
        let junk = gpt(Some("[General]\nversion = abc\n"));
        assert!(junk.contains("Version=1\r\n"));
    }

    #[test]
    fn gpt_ini_extension_names_merge() {
        let other = "{00000000-0000-0000-0000-000000000001}";
        let existing = format!(
            "[General]\r\ngPCMachineExtensionNames=[{REGISTRY_CSE}{{AAAAAAAA-0000-0000-0000-000000000000}}][{other}{other}]\r\nVersion=2\r\n"
        );
        let out = gpt(Some(&existing));
        let line = out
            .lines()
            .find(|l| l.starts_with("gPCMachineExtensionNames="))
            .unwrap();
        assert!(line.contains(&format!(
            "[{REGISTRY_CSE}{{AAAAAAAA-0000-0000-0000-000000000000}}{ADMIN_TEMPLATES_TOOL}]"
        )));
        assert!(line.contains(&format!("[{other}{other}]")));
        let again = gpt(Some(&out));
        assert_eq!(
            again
                .lines()
                .find(|l| l.starts_with("gPCMachineExtensionNames="))
                .unwrap(),
            line
        );
        assert!(again.contains("Version=4\r\n"));
    }

    #[test]
    fn read_all_lines_matches_dotnet() {
        assert_eq!(read_all_lines("a\r\nb\n"), vec!["a", "b"]);
        assert_eq!(read_all_lines("a\r\n\r\nb"), vec!["a", "", "b"]);
        assert!(read_all_lines("").is_empty());
    }
}

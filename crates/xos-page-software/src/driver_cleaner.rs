use crate::util::{cmp_ci, encode_command, split_lines};
use regex::Regex;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock};
use windows::core::BOOL;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Devices::DeviceAndDriverInstallation::{
    CM_Get_DevNode_PropertyW, CM_Get_Device_ID_ListW, CM_Get_Device_ID_List_SizeW,
    CM_Locate_DevNodeW, CM_Query_And_Remove_SubTreeW, DiUninstallDriverW, SetupUninstallOEMInfW,
    CM_LOCATE_DEVNODE_FLAGS, DIURFLAG_NO_REMOVE_INF, PNP_VETO_TYPE, SUOI_FORCEDELETE,
};
use windows::Win32::Devices::Properties::DEVPROPTYPE;
use windows::Win32::Foundation::{GetLastError, DEVPROPKEY};
use windows::Win32::System::Diagnostics::Debug::{
    FormatMessageW, FORMAT_MESSAGE_FROM_HMODULE, FORMAT_MESSAGE_FROM_SYSTEM,
    FORMAT_MESSAGE_IGNORE_INSERTS,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use xos_core::app_state;
use xos_core::host::{Buttons, DialogResult, Host, Icon, Page};
use xos_core::log;
use xos_core::ui::*;

const CR_SUCCESS: u32 = 0x00;
const CR_NO_SUCH_DEVNODE: u32 = 0x0D;
const CR_BUFFER_SMALL: u32 = 0x1A;
const CR_NO_SUCH_VALUE: u32 = 0x25;
const CM_LOCATE_DEVNODE_PHANTOM: u32 = 0x00000001;
const CM_REMOVE_UI_NOT_OK: u32 = 0x00000002;
const CM_REMOVE_NO_RESTART: u32 = 0x00000004;

const DEVPKEY_DRIVER_INF_PATH: DEVPROPKEY = DEVPROPKEY {
    fmtid: windows::core::GUID::from_u128(0xa8b865dd_2e3d_4094_ad97_e593a70c75d6),
    pid: 5,
};
const DEVPKEY_EXTENDED_CONFIGURATION_IDS: DEVPROPKEY = DEVPROPKEY {
    fmtid: windows::core::GUID::from_u128(0x540b947e_8b40_45bc_a8a2_6a0b894cbda2),
    pid: 15,
};

type Ver = [i32; 4];
type Date = (i32, i32, i32);

const MIN_DATE: Date = (1, 1, 1);
const ZERO_VER: Ver = [0, 0, -1, -1];

#[derive(Clone, Default)]
struct DriverItem {
    published_name: String,
    original_name: String,
    provider: String,
    class_name: String,
    version: String,
    driver_date: String,
    device_name: String,
    date_key: Date,
    version_key: Option<Ver>,
    is_old_duplicate: bool,
    is_in_use_older: bool,
    selected: bool,
}

fn blank(s: &str) -> bool {
    s.trim().is_empty()
}

impl DriverItem {
    fn display_title(&self) -> &str {
        if !blank(&self.device_name) {
            &self.device_name
        } else if !blank(&self.original_name) {
            &self.original_name
        } else {
            &self.published_name
        }
    }

    fn provider_with_inf(&self) -> String {
        if !blank(&self.device_name) && !blank(&self.original_name) {
            format!("{}  \u{2022}  {}", self.provider, self.original_name)
        } else {
            self.provider.clone()
        }
    }

    fn duplicate_badge(&self) -> &'static str {
        if self.is_old_duplicate {
            "OLD"
        } else if self.is_in_use_older {
            "IN USE"
        } else {
            ""
        }
    }

    fn ver(&self) -> Ver {
        self.version_key.unwrap_or(ZERO_VER)
    }
}

fn date_ver_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(\d{1,2}[/\-\.]\d{1,2}[/\-\.]\d{2,4})\s+([\d\.]+)").unwrap())
}

fn days_in_month(y: i32, m: i32) -> i32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ => {
            if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 {
                29
            } else {
                28
            }
        }
    }
}

fn parse_date(text: &str) -> Date {
    let parts: Vec<&str> = text.split(['/', '-', '.']).collect();
    if parts.len() != 3 {
        return MIN_DATE;
    }
    let (Ok(m), Ok(d), Ok(mut y)) = (
        parts[0].parse::<i32>(),
        parts[1].parse::<i32>(),
        parts[2].parse::<i32>(),
    ) else {
        return MIN_DATE;
    };
    if parts[2].len() <= 2 {
        y += if y < 50 { 2000 } else { 1900 };
    }
    if !(1..=12).contains(&m) || y < 1 || d < 1 || d > days_in_month(y, m) {
        return MIN_DATE;
    }
    (y, m, d)
}

fn parse_version(text: &str) -> Option<Ver> {
    let parts: Vec<&str> = text.split('.').collect();
    if parts.len() < 2 || parts.len() > 4 {
        return None;
    }
    let mut v = [-1i32; 4];
    for (i, p) in parts.iter().enumerate() {
        if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        v[i] = p.parse::<i32>().ok()?;
    }
    Some(v)
}

fn apply_date_ver(item: &mut DriverItem, date: &str, version: &str) {
    item.driver_date = date.to_string();
    item.version = version.to_string();
    item.date_key = parse_date(date);
    item.version_key = Some(parse_version(version).unwrap_or(ZERO_VER));
}

fn parse(output: &str) -> Vec<DriverItem> {
    let mut items = Vec::new();
    if blank(output) {
        return items;
    }
    static SPLIT: OnceLock<Regex> = OnceLock::new();
    let split = SPLIT.get_or_init(|| Regex::new(r"\n\s*\n").unwrap());
    let normalized = output.replace("\r\n", "\n");
    for block in split.split(&normalized) {
        if !block.contains(".inf") {
            continue;
        }
        let mut item = DriverItem::default();
        let mut positional: Vec<String> = Vec::new();

        for raw in block.split('\n') {
            let line = raw.trim();
            if line.is_empty() {
                continue;
            }
            let colon = line.find(':');
            let value = match colon {
                Some(c) if c > 0 && c < line.len() - 1 => line[c + 1..].trim().to_string(),
                _ => line.to_string(),
            };
            if matches!(colon, Some(c) if c > 0) {
                positional.push(value.clone());
            }
            let key_lower = match colon {
                Some(c) if c > 0 => line[..c].trim().to_lowercase(),
                _ => String::new(),
            };

            if key_lower.contains("published") {
                item.published_name = value;
            } else if key_lower.contains("original") {
                item.original_name = value;
            } else if key_lower.contains("provider") {
                item.provider = value;
            } else if key_lower.contains("class") && !key_lower.contains("guid") {
                item.class_name = value;
            } else if key_lower.contains("version") || key_lower.contains("date") {
                if let Some(m) = date_ver_regex().captures(&value) {
                    apply_date_ver(&mut item, &m[1], &m[2]);
                }
            }
        }

        if item.published_name.is_empty() && !positional.is_empty() {
            item.published_name = positional.first().cloned().unwrap_or_default();
            item.original_name = positional.get(1).cloned().unwrap_or_default();
            item.provider = positional.get(2).cloned().unwrap_or_default();
            item.class_name = positional.get(3).cloned().unwrap_or_default();
            if let Some(ver) = positional.iter().find(|p| date_ver_regex().is_match(p)) {
                let m = date_ver_regex().captures(ver).unwrap();
                apply_date_ver(&mut item, &m[1], &m[2]);
            }
        }

        if !blank(&item.published_name) {
            items.push(item);
        }
    }
    items
}

fn read_string_property(node: u32, key: &DEVPROPKEY) -> (u32, Vec<String>) {
    let mut size: u32 = 0;
    let mut ptype = DEVPROPTYPE::default();
    let read = unsafe { CM_Get_DevNode_PropertyW(node, key, &mut ptype, None, &mut size, 0) }.0;
    if read == CR_NO_SUCH_VALUE {
        return (CR_SUCCESS, Vec::new());
    }
    if read != CR_BUFFER_SMALL {
        return (read, Vec::new());
    }
    let mut data = vec![0u8; size as usize];
    let read = unsafe {
        CM_Get_DevNode_PropertyW(node, key, &mut ptype, Some(data.as_mut_ptr()), &mut size, 0)
    }
    .0;
    if read != CR_SUCCESS {
        return (read, Vec::new());
    }
    let units: Vec<u16> = data[..size as usize]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let values = String::from_utf16_lossy(&units)
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();
    (CR_SUCCESS, values)
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn locate_devnode(id: &str, flags: u32) -> (u32, u32) {
    let w = wide(id);
    let mut node = 0u32;
    let cr = unsafe {
        CM_Locate_DevNodeW(
            &mut node,
            PCWSTR(w.as_ptr()),
            CM_LOCATE_DEVNODE_FLAGS(flags),
        )
    }
    .0;
    (cr, node)
}

fn is_device_present(id: &str) -> bool {
    locate_devnode(id, 0).0 != CR_NO_SUCH_DEVNODE
}

fn load_bound_infs() -> Option<HashSet<String>> {
    let mut buffer: Vec<u16> = Vec::new();
    let mut cr = CR_BUFFER_SMALL;
    let mut attempt = 0;
    while attempt < 5 && cr == CR_BUFFER_SMALL {
        let mut length = 0u32;
        cr = unsafe { CM_Get_Device_ID_List_SizeW(&mut length, PCWSTR::null(), 0) }.0;
        if cr != CR_SUCCESS {
            break;
        }
        buffer = vec![0u16; length as usize];
        cr = unsafe { CM_Get_Device_ID_ListW(PCWSTR::null(), &mut buffer, 0) }.0;
        attempt += 1;
    }
    if cr != CR_SUCCESS || buffer.is_empty() {
        log::log(&format!(
            "[DriverCleaner] Device list read FAILED: CR=0x{cr:X}"
        ));
        return None;
    }

    let ids: Vec<String> = String::from_utf16_lossy(&buffer)
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();
    if ids.is_empty() {
        log::log("[DriverCleaner] Device list read FAILED: no devices returned.");
        return None;
    }

    let mut bound: HashSet<String> = HashSet::new();
    let mut skipped = 0;
    for id in &ids {
        let (locate, node) = locate_devnode(id, CM_LOCATE_DEVNODE_PHANTOM);
        if locate == CR_NO_SUCH_DEVNODE {
            continue;
        }
        if locate != CR_SUCCESS {
            if is_device_present(id) {
                log::log(&format!(
                    "[DriverCleaner] Device binding read FAILED for connected device {id}: locate CR=0x{locate:X}"
                ));
                return None;
            }
            skipped += 1;
            if skipped <= 5 {
                log::log(&format!(
                    "[DriverCleaner] Skipped disconnected device {id}: binding unreadable, locate CR=0x{locate:X}"
                ));
            }
            continue;
        }

        let mut extensions: Vec<String> = Vec::new();
        let (mut read, infs) = read_string_property(node, &DEVPKEY_DRIVER_INF_PATH);
        if read == CR_SUCCESS {
            let (r, e) = read_string_property(node, &DEVPKEY_EXTENDED_CONFIGURATION_IDS);
            read = r;
            extensions = e;
        }
        if read == CR_NO_SUCH_DEVNODE {
            continue;
        }
        if read == CR_SUCCESS {
            for value in infs.iter().chain(extensions.iter()) {
                let mut inf: &str = value;
                if let Some(c) = inf.find(':') {
                    inf = &inf[..c];
                }
                let inf = inf.rsplit('\\').next().unwrap_or("").trim();
                if !inf.is_empty() {
                    bound.insert(inf.to_lowercase());
                }
            }
            continue;
        }
        if is_device_present(id) {
            log::log(&format!("[DriverCleaner] Device binding read FAILED for connected device {id}: CR=0x{read:X}"));
            return None;
        }
        skipped += 1;
        if skipped <= 5 {
            log::log(&format!("[DriverCleaner] Skipped disconnected device {id}: binding unreadable, CR=0x{read:X}"));
        }
    }

    let oem = bound.iter().filter(|b| b.starts_with("oem")).count();
    log::log(&format!(
        "[DriverCleaner] Device binding check: {} device(s), {} OEM package(s) in use, {} disconnected device(s) unreadable and skipped.",
        ids.len(),
        oem,
        skipped
    ));
    Some(bound)
}

fn load_device_name_map() -> HashMap<String, String> {
    let mut map: HashMap<String, String> = HashMap::new();
    let ps = "Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue | Where-Object { $_.InfName -and $_.DeviceName } | ForEach-Object { \"$($_.InfName)|$($_.DeviceName)\" }";
    let output = xos_sys::run_cmd_output(
        "powershell.exe",
        &format!(
            "-NoProfile -NonInteractive -EncodedCommand {}",
            encode_command(ps)
        ),
    );
    for line in split_lines(&output) {
        let Some(pipe) = line.find('|') else { continue };
        if pipe == 0 || pipe >= line.len() - 1 {
            continue;
        }
        let inf = line[..pipe].trim();
        let dev = line[pipe + 1..].trim();
        if inf.is_empty() || dev.is_empty() {
            continue;
        }
        let key = inf.to_lowercase();
        match map.get_mut(&key) {
            Some(existing) => {
                if !existing.split(" + ").any(|n| n.eq_ignore_ascii_case(dev)) {
                    existing.push_str(" + ");
                    existing.push_str(dev);
                }
            }
            None => {
                map.insert(key, dev.to_string());
            }
        }
    }
    map
}

fn mark_old_duplicates(items: &mut [DriverItem], bound: &Option<HashSet<String>>) {
    let Some(bound) = bound else { return };
    let mut order: Vec<String> = Vec::new();
    let mut groups: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, it) in items.iter().enumerate() {
        if blank(&it.provider) || blank(&it.class_name) || blank(&it.original_name) {
            continue;
        }
        let key = format!(
            "{}|{}|{}",
            it.provider.to_lowercase(),
            it.class_name.to_lowercase(),
            it.original_name.to_lowercase()
        );
        if !groups.contains_key(&key) {
            order.push(key.clone());
        }
        groups.entry(key).or_default().push(i);
    }
    for key in order {
        let g = &groups[&key];
        if g.len() < 2 {
            continue;
        }
        let mut newest = g[0];
        for &i in &g[1..] {
            let ord = items[i]
                .ver()
                .cmp(&items[newest].ver())
                .then(items[i].date_key.cmp(&items[newest].date_key));
            if ord == Ordering::Greater {
                newest = i;
            }
        }
        for &i in g {
            if i == newest {
                continue;
            }
            if bound.contains(&items[i].published_name.to_lowercase()) {
                log::log(&format!(
                    "[DriverCleaner] {} is older than {} but a device uses it, not marked as an old duplicate.",
                    items[i].published_name, items[newest].published_name
                ));
                items[i].is_in_use_older = true;
                continue;
            }
            items[i].is_old_duplicate = true;
        }
    }
}

fn sort_indices(items: &[DriverItem], idx: &mut [usize], column: &str, desc: bool) {
    let dir = |o: Ordering| if desc { o.reverse() } else { o };
    match column {
        "name" => idx.sort_by(|&a, &b| {
            dir(cmp_ci(items[a].display_title(), items[b].display_title()))
                .then_with(|| cmp_ci(&items[a].provider, &items[b].provider))
        }),
        "version" => idx.sort_by(|&a, &b| {
            dir(items[a].ver().cmp(&items[b].ver()))
                .then_with(|| items[b].date_key.cmp(&items[a].date_key))
        }),
        "date" => idx.sort_by(|&a, &b| {
            dir(items[a].date_key.cmp(&items[b].date_key))
                .then_with(|| items[b].ver().cmp(&items[a].ver()))
        }),
        _ => idx.sort_by(|&a, &b| {
            dir(cmp_ci(&items[a].class_name, &items[b].class_name))
                .then_with(|| cmp_ci(&items[a].provider, &items[b].provider))
                .then_with(|| items[b].date_key.cmp(&items[a].date_key))
        }),
    }
}

fn win32_code(e: &windows::core::Error) -> u32 {
    let c = e.code().0 as u32;
    if c & 0xFFFF0000 == 0x80070000 {
        c & 0xFFFF
    } else {
        c
    }
}

fn driver_error_message(code: u32) -> String {
    let module = unsafe { GetModuleHandleW(PCWSTR(wide("setupapi.dll").as_ptr())) };
    if let Ok(h) = module {
        if !h.is_invalid() {
            let mut buf = vec![0u16; 1024];
            let len = unsafe {
                FormatMessageW(
                    FORMAT_MESSAGE_FROM_HMODULE
                        | FORMAT_MESSAGE_FROM_SYSTEM
                        | FORMAT_MESSAGE_IGNORE_INSERTS,
                    Some(h.0 as *const _),
                    code,
                    0,
                    PWSTR(buf.as_mut_ptr()),
                    buf.len() as u32,
                    None,
                )
            };
            if len > 0 {
                return String::from_utf16_lossy(&buf[..len as usize])
                    .trim()
                    .to_string();
            }
        }
    }
    known_message(code)
        .map(String::from)
        .unwrap_or_else(|| format!("Error 0x{code:08X}"))
}

fn known_message(code: u32) -> Option<&'static str> {
    match code {
        0xE000023D | 0xE000023C => Some("The driver is currently installed on an active device. Enable Force delete to remove it."),
        0xE0000235 => Some("The driver is in use by an active device. Enable Force delete to remove it."),
        0xE0000237 => Some("Failed to add the driver package to the driver store."),
        _ => None,
    }
}

fn windows_dir() -> String {
    std::env::var("SystemRoot")
        .or_else(|_| std::env::var("windir"))
        .unwrap_or_else(|_| "C:\\Windows".into())
}

fn delete_driver_direct(
    published: &str,
    original: &str,
    force: bool,
) -> (bool, Option<String>, bool) {
    log::log(&format!(
        "[DriverCleaner] Deleting {published} (original: {original}, force: {})",
        if force { "True" } else { "False" }
    ));
    let mut need_reboot_after = false;
    if force {
        let full = std::path::Path::new(&windows_dir())
            .join("INF")
            .join(published);
        let full_text = full.to_string_lossy().into_owned();
        log::log(&format!("[DriverCleaner]   INF path: {full_text}"));
        if full.is_file() {
            let mut need_reboot = BOOL(0);
            let w = wide(&full_text);
            let r = unsafe {
                DiUninstallDriverW(
                    None,
                    PCWSTR(w.as_ptr()),
                    DIURFLAG_NO_REMOVE_INF,
                    Some(&mut need_reboot),
                )
            };
            let ok = r.is_ok();
            let reboot = need_reboot.as_bool();
            need_reboot_after |= ok && reboot;
            let err = match &r {
                Err(e) => win32_code(e),
                Ok(()) => 0,
            };
            log::log(&format!(
                "[DriverCleaner]   DiUninstallDriver: {} reboot={}",
                if ok {
                    "OK".to_string()
                } else {
                    format!("FAILED 0x{err:08X}")
                },
                if reboot { "True" } else { "False" }
            ));
        }
    }

    let w = wide(published);
    let flags = if force { SUOI_FORCEDELETE } else { 0 };
    let uninstall = unsafe { SetupUninstallOEMInfW(PCWSTR(w.as_ptr()), flags, None) };
    let ok = uninstall.as_bool();
    let err = if ok { 0 } else { unsafe { GetLastError() }.0 };
    log::log(&format!(
        "[DriverCleaner]   SetupUninstallOEMInf: {}",
        if ok {
            "OK".to_string()
        } else {
            format!("FAILED 0x{err:08X}")
        }
    ));
    if !ok {
        return (false, Some(driver_error_message(err)), need_reboot_after);
    }
    (true, None, need_reboot_after)
}

struct Ghost {
    id: String,
    name: String,
}

const GHOST_SCRIPT: &str = r#"
$ErrorActionPreference='Stop'
try {
function Test-Aff([string]$id){
  $p="HKLM:\SYSTEM\CurrentControlSet\Enum\$id\Device Parameters\Interrupt Management\Affinity Policy"
  if(Test-Path $p){
    $a=Get-ItemProperty $p -ErrorAction SilentlyContinue
    if($null -ne $a.DevicePolicy -and $a.DevicePolicy -ge 3){return $true}
    if($a.AssignmentSetOverride){ foreach($b in [byte[]]$a.AssignmentSetOverride){ if($b -ne 0){return $true} } }
  }
  return $false
}
$all=@(Get-PnpDevice -ErrorAction Stop)
$presentDevices=@(Get-PnpDevice -PresentOnly -ErrorAction Stop)
if($all.Count -gt 0 -and $presentDevices.Count -eq 0){ throw 'Present-device enumeration returned no devices.' }
$present=@{}
foreach($p in $presentDevices){ if($p.InstanceId){$present[$p.InstanceId]=$true} }
foreach($d in $all){
  $id=($d.InstanceId -replace '[\r\n\t]','').Trim()
  if($id -and -not $present.ContainsKey($id) -and -not (Test-Aff $id)){
    "$id|$($d.FriendlyName)"
  }
}
} catch { Write-Output ('XOS_ERROR|' + $_.Exception.Message) }
"#;

fn scan_ghost_devices() -> Result<Vec<Ghost>, String> {
    let output = xos_sys::run_cmd_output_timeout(
        "powershell.exe",
        &format!(
            "-NoProfile -NonInteractive -EncodedCommand {}",
            encode_command(GHOST_SCRIPT)
        ),
        120000,
    );
    if let Some(e) = split_lines(&output).find(|l| l.starts_with("XOS_ERROR|")) {
        return Err(e["XOS_ERROR|".len()..].to_string());
    }
    let mut list = Vec::new();
    for line in split_lines(&output) {
        let Some(pipe) = line.find('|') else { continue };
        if pipe == 0 {
            continue;
        }
        let id = line[..pipe].trim();
        let name = line[pipe + 1..].trim();
        if id.is_empty() {
            continue;
        }
        list.push(Ghost {
            id: id.to_string(),
            name: if name.is_empty() {
                "(unnamed device)".into()
            } else {
                name.to_string()
            },
        });
    }
    Ok(list)
}

fn remove_ghost_device_native(instance_id: &str) -> bool {
    let (locate, node) = locate_devnode(instance_id, CM_LOCATE_DEVNODE_PHANTOM);
    if locate != 0 {
        return false;
    }
    let mut veto_type = PNP_VETO_TYPE(0);
    let mut veto_name = vec![0u16; 260];
    let remove = unsafe {
        CM_Query_And_Remove_SubTreeW(
            node,
            Some(&mut veto_type),
            Some(&mut veto_name),
            CM_REMOVE_UI_NOT_OK | CM_REMOVE_NO_RESTART,
        )
    }
    .0;
    if remove != 0 {
        let end = veto_name
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(veto_name.len());
        log::log(&format!(
            "[GhostDevices] Native removal failed for {instance_id}: CR=0x{remove:X}, veto={} {}",
            veto_type.0,
            String::from_utf16_lossy(&veto_name[..end])
        ));
    }
    remove == 0
}

fn remove_ghost_devices(ids: &[String]) -> (i32, i32) {
    if ids.is_empty() {
        return (0, 0);
    }
    let mut ok = 0;
    let mut fail = 0;
    let pnputil_supports_removal = xos_sys::get_windows_build_number() >= 19041;
    let mut seen: HashSet<String> = HashSet::new();
    for id in ids.iter().filter(|v| !blank(v)) {
        if !seen.insert(id.to_uppercase()) {
            continue;
        }
        let mut removed = false;
        if pnputil_supports_removal && !id.contains('"') {
            let (success, _) = xos_sys::run_cmd_with_error_timeout(
                "pnputil.exe",
                &format!("/remove-device \"{id}\""),
                30000,
            );
            removed = success;
        }
        if !removed {
            removed = remove_ghost_device_native(id);
        }
        if removed {
            ok += 1;
        } else {
            fail += 1;
            log::log(&format!("[GhostDevices] Could not remove: {id}"));
        }
    }
    (ok, fail)
}

struct State {
    all: Vec<DriverItem>,
    loaded: bool,
    loading: bool,
    counted: bool,
    search: String,
    force: bool,
    sort_column: &'static str,
    sort_desc: bool,
    bound: Option<HashSet<String>>,
    empty_text: String,
}

impl State {
    fn display(&self) -> Vec<usize> {
        let mut idx: Vec<usize> = (0..self.all.len()).collect();
        sort_indices(&self.all, &mut idx, self.sort_column, self.sort_desc);
        let search = self.search.trim().to_lowercase();
        if !search.is_empty() {
            idx.retain(|&i| {
                let d = &self.all[i];
                d.published_name.to_lowercase().contains(&search)
                    || d.original_name.to_lowercase().contains(&search)
                    || d.provider.to_lowercase().contains(&search)
                    || d.class_name.to_lowercase().contains(&search)
                    || d.device_name.to_lowercase().contains(&search)
            });
        }
        idx
    }
}

pub struct DriverCleanerPage {
    st: Mutex<State>,
}

impl DriverCleanerPage {
    pub fn new() -> Self {
        Self {
            st: Mutex::new(State {
                all: Vec::new(),
                loaded: false,
                loading: false,
                counted: false,
                search: String::new(),
                force: false,
                sort_column: "class",
                sort_desc: false,
                bound: None,
                empty_text: "No OEM drivers found.".into(),
            }),
        }
    }

    fn enumerate(&self) -> Result<(Vec<DriverItem>, Option<HashSet<String>>), String> {
        let output = xos_sys::run_cmd_output("pnputil.exe", "/enum-drivers");
        if blank(&output) {
            return Err("PnPUtil returned no Driver Store data.".into());
        }
        let mut parsed = parse(&output);
        if parsed.is_empty() && !blank(&output) && output.to_lowercase().contains("oem") {
            return Err("Driver Store output could not be parsed on this Windows language.".into());
        }
        let device_map = load_device_name_map();
        for item in parsed.iter_mut() {
            if let Some(name) = device_map.get(&item.published_name.to_lowercase()) {
                item.device_name = name.clone();
            }
        }
        let bound = load_bound_infs();
        if bound.is_none() {
            log::log("[DriverCleaner] No package is marked as an old duplicate because the device binding check did not complete.");
        }
        mark_old_duplicates(&mut parsed, &bound);
        Ok((parsed, bound))
    }

    fn load(&self, host: &dyn Host) {
        {
            let mut st = self.st.lock().unwrap();
            if st.loading {
                return;
            }
            st.loading = true;
            st.loaded = true;
        }
        host.publish(self.model());
        host.set_status("Enumerating driver packages...");
        log::log("[DriverCleaner] Enumerating driver packages...");
        let result = self.enumerate();
        let status;
        {
            let mut st = self.st.lock().unwrap();
            match result {
                Ok((items, bound)) => {
                    let count = items.len();
                    let unchecked = bound.is_none();
                    st.all = items;
                    st.bound = bound;
                    st.counted = true;
                    log::log(&format!(
                        "[DriverCleaner] Found {count} OEM driver package(s)."
                    ));
                    status = Some(if unchecked {
                        format!("Found {count} OEM driver package(s). Could not check which drivers are in use, so no old duplicates are marked.")
                    } else {
                        format!("Found {count} OEM driver package(s).")
                    });
                }
                Err(e) => {
                    st.loaded = false;
                    log::log(&format!("[DriverCleaner] Enumeration failed: {e}"));
                    status = Some("Driver Store scan failed.".into());
                    st.empty_text =
                        "Driver packages could not be read. Select Refresh to try again.".into();
                }
            }
            st.loading = false;
        }
        if let Some(s) = status {
            host.set_status(&s);
        }
    }

    fn set_selection(&self, f: impl Fn(&DriverItem) -> bool) {
        let mut st = self.st.lock().unwrap();
        for i in st.display() {
            let v = f(&st.all[i]);
            st.all[i].selected = v;
        }
    }

    fn remove_selected(&self, host: &dyn Host) {
        let (to_remove, force, bound) = {
            let st = self.st.lock().unwrap();
            let items: Vec<DriverItem> = st
                .display()
                .into_iter()
                .filter(|&i| st.all[i].selected)
                .map(|i| st.all[i].clone())
                .collect();
            (items, st.force, st.bound.clone())
        };
        if to_remove.is_empty() {
            return;
        }

        let mut warn = format!(
            "Remove {} driver package(s) from the Driver Store?",
            to_remove.len()
        );
        if force {
            warn.push_str("\n\nForce delete is ON. This will attempt removal even if Windows reports the driver is in use.");
        }
        let in_use: Vec<&DriverItem> = match &bound {
            None => Vec::new(),
            Some(b) => to_remove
                .iter()
                .filter(|d| b.contains(&d.published_name.to_lowercase()))
                .collect(),
        };
        if bound.is_none() {
            warn.push_str("\n\nThe Toolkit could not check which of these a device is using. Make sure none of these are the active driver for a device you still use.");
        } else if !in_use.is_empty() {
            warn.push_str(&format!(
                "\n\n{} of these are still assigned to a device, which can stop working until its driver is reinstalled:\n",
                in_use.len()
            ));
            warn.push_str(
                &in_use
                    .iter()
                    .take(10)
                    .map(|d| format!("\u{2022} {} ({})", d.display_title(), d.published_name))
                    .collect::<Vec<_>>()
                    .join("\n"),
            );
            if in_use.len() > 10 {
                warn.push_str(&format!("\n...and {} more", in_use.len() - 10));
            }
        } else {
            warn.push_str("\n\nNo device is using these packages.");
        }

        if host.dialog(&warn, "XOS Toolkit", Buttons::YesNo, Icon::Warning) != DialogResult::Yes {
            return;
        }

        self.st.lock().unwrap().loading = true;
        host.publish(self.model());
        let mut success = 0;
        let mut failed: Vec<(String, String)> = Vec::new();
        for d in &to_remove {
            host.set_status(&format!("Removing {}...", d.published_name));
            let (ok, error, need_reboot) =
                delete_driver_direct(&d.published_name, &d.original_name, force);
            if need_reboot {
                app_state::require_reboot();
            }
            if ok {
                success += 1;
            } else {
                failed.push((
                    d.published_name.clone(),
                    error.unwrap_or_else(|| "Driver removal failed".into()),
                ));
            }
        }
        self.st.lock().unwrap().loading = false;

        let mut msg = format!("Removed {success} driver package(s).");
        log::log(&format!(
            "[DriverCleaner] Done. removed: {success}, failed: {}",
            failed.len()
        ));
        let mut detail = format!("removed {success}, failed {}", failed.len());
        if !failed.is_empty() {
            detail.push_str(": ");
            detail.push_str(
                &failed
                    .iter()
                    .map(|f| f.0.clone())
                    .collect::<Vec<_>>()
                    .join(", "),
            );
        }
        log::action_done(
            "DriverCleaner",
            success == 0 && !failed.is_empty(),
            !failed.is_empty(),
            Some(&detail),
        );
        if !failed.is_empty() {
            msg.push_str(&format!("\n\nFailed ({}):\n", failed.len()));
            for f in &failed {
                msg.push_str(&format!("\n\u{2022} {}\n   {}\n", f.0, f.1));
                log::log(&format!("[DriverCleaner]   FAILED {}: {}", f.0, f.1));
            }
            if !force {
                msg.push_str("\nTip: enable 'Force delete' and try again.");
            }
        }

        host.dialog(
            &msg,
            "XOS Toolkit",
            Buttons::Ok,
            if failed.is_empty() {
                Icon::Information
            } else {
                Icon::Warning
            },
        );
        host.set_status(msg.split('\n').next().unwrap_or(""));
        self.load(host);
    }

    fn ghost_devices(&self, host: &dyn Host) {
        host.set_status("Scanning for inactive devices...");
        log::log("[GhostDevices] Scanning for inactive devices...");

        let ghosts = match scan_ghost_devices() {
            Ok(g) => g,
            Err(e) => {
                self.ghost_failed(host, &e);
                return;
            }
        };

        if ghosts.is_empty() {
            log::action_done(
                "DriverCleaner",
                false,
                false,
                Some("no inactive devices found"),
            );
            host.dialog(
                "No inactive devices were found. Nothing to remove.",
                "XOS Toolkit",
                Buttons::Ok,
                Icon::Information,
            );
            host.set_status("No inactive devices found.");
            return;
        }

        let mut preview = ghosts
            .iter()
            .take(15)
            .map(|g| format!("\u{2022} {}", g.name))
            .collect::<Vec<_>>()
            .join("\n");
        if ghosts.len() > 15 {
            preview.push_str(&format!("\n...and {} more", ghosts.len() - 15));
        }
        let warn = format!(
            "Found {} inactive device(s) left behind by hardware that is no longer connected:\n\n{}\n\nRemove them? Devices with CPU affinity configured are preserved. This cannot be undone.",
            ghosts.len(),
            preview
        );

        if host.dialog(&warn, "XOS Toolkit", Buttons::YesNo, Icon::Warning) != DialogResult::Yes {
            log::action_done(
                "DriverCleaner",
                false,
                false,
                Some(&format!(
                    "{} inactive device(s) found, removal declined",
                    ghosts.len()
                )),
            );
            host.set_status("Inactive device removal cancelled.");
            return;
        }

        host.set_status(&format!("Removing {} inactive device(s)...", ghosts.len()));
        let ids: Vec<String> = ghosts.iter().map(|g| g.id.clone()).collect();
        let (ok, fail) = remove_ghost_devices(&ids);

        let msg = if fail > 0 {
            format!("Removed {ok} inactive device(s). {fail} could not be removed.")
        } else {
            format!("Removed {ok} inactive device(s).")
        };
        log::log(&format!(
            "[GhostDevices] Done. removed: {ok}, failed: {fail}"
        ));
        log::action_done(
            "DriverCleaner",
            ok == 0 && fail > 0,
            fail > 0,
            Some(&format!("removed {ok}, failed {fail}")),
        );
        host.dialog(
            &msg,
            "XOS Toolkit",
            Buttons::Ok,
            if fail > 0 {
                Icon::Warning
            } else {
                Icon::Information
            },
        );
        host.set_status(&msg);
    }

    fn ghost_failed(&self, host: &dyn Host, message: &str) {
        log::log(&format!("[GhostDevices] Error: {message}"));
        log::action_done("DriverCleaner", true, false, Some(message));
        host.set_status("Inactive device removal failed.");
        host.dialog(
            &format!("Could not complete inactive device removal.\n\n{message}"),
            "XOS Toolkit",
            Buttons::Ok,
            Icon::Error,
        );
    }

    fn header_click(&self, col: usize) {
        let column = match col {
            0 => "name",
            4 => "class",
            5 => "version",
            6 => "date",
            _ => return,
        };
        let mut st = self.st.lock().unwrap();
        if column == st.sort_column {
            st.sort_desc = !st.sort_desc;
        } else {
            st.sort_column = column;
            st.sort_desc = column == "date" || column == "version";
        }
    }
}

impl Page for DriverCleanerPage {
    fn id(&self) -> &'static str {
        "DriverCleaner"
    }

    fn label(&self) -> &'static str {
        "Driver Cleaner"
    }

    fn model(&self) -> PageModel {
        let st = self.st.lock().unwrap();
        let display = st.display();
        let arrow = if st.sort_desc {
            "  \u{25BC}"
        } else {
            "  \u{25B2}"
        };
        let title = |text: &str, col: &str| {
            format!("{text}{}", if st.sort_column == col { arrow } else { "" })
        };

        let selected = display.iter().filter(|&&i| st.all[i].selected).count();
        let old = display
            .iter()
            .filter(|&&i| st.all[i].is_old_duplicate)
            .count();
        let count_text = if st.counted {
            format!(
                "{} driver(s) shown  \u{2022}  {} old duplicate(s)  \u{2022}  {} selected",
                display.len(),
                old,
                selected
            )
        } else {
            "-".to_string()
        };

        let rows: Vec<TableRow> = if st.loading {
            Vec::new()
        } else {
            display
                .iter()
                .map(|&i| {
                    let d = &st.all[i];
                    let badge = d.duplicate_badge();
                    TableRow::new(
                        i.to_string(),
                        vec![
                            d.display_title().to_string(),
                            d.provider_with_inf(),
                            d.published_name.clone(),
                            badge.to_string(),
                            d.class_name.clone(),
                            d.version.clone(),
                            d.driver_date.clone(),
                        ],
                    )
                    .checked(d.selected)
                    .tone(if badge.is_empty() {
                        Tone::Neutral
                    } else {
                        Tone::Orange
                    })
                    .tooltip(d.provider_with_inf())
                })
                .collect()
        };
        let empty = if st.loading {
            "Enumerating driver packages...".to_string()
        } else {
            st.empty_text.clone()
        };
        let any_selected = selected > 0;
        let idle = !st.loading;

        PageModel::new("DriverCleaner", "Driver Cleaner", "Remove old, duplicate, or orphan OEM drivers from the Windows Driver Store")
            .single_column()
            .card(
                Card::new(
                    "warning",
                    " Read before removing",
                    "Only old duplicates of your GPU/audio/chipset drivers are safe to remove. Deleting the active driver for a device may break it until you reinstall. \"Pick old duplicates\" keeps the newest package per provider, class and INF name, selects the rest. An older package a device is still using is marked IN USE and never picked.",
                )
                .not_searchable(),
            )
            .card(
                Card::new("controls", "", "")
                    .not_searchable()
                    .controls(vec![
                        Control::text_input("search", st.search.clone(), "\u{1F50D}"),
                        Control::spacer(),
                        Control::button("refresh", "\u{21BB}  Refresh", BtnStyle::Action).enabled(idle),
                    ])
                    .controls(vec![
                        Control::muted(count_text),
                        Control::spacer(),
                        Control::check("force", "Force delete (use if normal delete fails)", st.force),
                    ]),
            )
            .card(
                Card::new("list", "", "")
                    .not_searchable()
                    .controls(vec![Control::table(
                        "list",
                        Table::new(
                            vec![
                                Column::stretch(title("Device / INF", "name")),
                                Column::new("Provider / INF", 220.0),
                                Column::new("Package", 80.0),
                                Column::new("Flag", 60.0),
                                Column::new(title("Class", "class"), 130.0),
                                Column::new(title("Version", "version"), 110.0),
                                Column::new(title("Date", "date"), 80.0),
                            ],
                            rows,
                        )
                        .checkable(true)
                        .sortable(true)
                        .height(420.0)
                        .empty_text(empty),
                    )])
                    .actions(vec![
                        Control::button("remove", "Remove Selected", BtnStyle::Disable).enabled(idle && any_selected),
                        Control::button("pick_old", "Pick Old Duplicates", BtnStyle::Action).enabled(idle),
                        Control::button("select_all", "Select All", BtnStyle::Action).enabled(idle),
                        Control::button("clear", "Clear Selection", BtnStyle::Warning).enabled(idle),
                        Control::button("ghost", "Remove Inactive Devices", BtnStyle::Disable).tooltip(
                            "Remove inactive devices left behind by hardware that is no longer connected. Devices with CPU affinity configured are preserved.",
                        ),
                    ]),
            )
    }

    fn refresh(&self, host: &dyn Host) {
        let loaded = self.st.lock().unwrap().loaded;
        if !loaded {
            self.load(host);
        }
    }

    fn handle(&self, host: &dyn Host, event: &Event) {
        match (event.control.as_str(), &event.kind) {
            ("refresh", EventKind::Click) => self.load(host),
            ("search", EventKind::Text(t)) | ("search", EventKind::Submit(t)) => {
                self.st.lock().unwrap().search = t.clone();
            }
            ("force", EventKind::Check(b)) => self.st.lock().unwrap().force = *b,
            ("list", EventKind::RowCheck { row, checked }) => {
                let mut st = self.st.lock().unwrap();
                let display = st.display();
                if let Some(&i) = display.get(*row) {
                    st.all[i].selected = *checked;
                }
            }
            ("list", EventKind::HeaderClick(col)) => self.header_click(*col),
            ("pick_old", EventKind::Click) => self.set_selection(|d| d.is_old_duplicate),
            ("select_all", EventKind::Click) => self.set_selection(|_| true),
            ("clear", EventKind::Click) => self.set_selection(|_| false),
            ("remove", EventKind::Click) => self.remove_selected(host),
            ("ghost", EventKind::Click) => self.ghost_devices(host),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "Microsoft PnP Utility\r\n\r\nPublished Name:     oem1.inf\r\nOriginal Name:      nv_disp.inf\r\nProvider Name:      NVIDIA\r\nClass Name:         Display adapters\r\nClass GUID:         {4d36e968-e325-11ce-bfc1-08002be10318}\r\nDriver Version:     10/15/2024 32.0.15.6094\r\nSigner Name:        Microsoft Windows Hardware Compatibility Publisher\r\n\r\nPublished Name:     oem2.inf\r\nOriginal Name:      nv_disp.inf\r\nProvider Name:      NVIDIA\r\nClass Name:         Display adapters\r\nDriver Version:     01/05/2023 31.0.15.2802\r\n";

    #[test]
    fn parses_blocks() {
        let items = parse(SAMPLE);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].published_name, "oem1.inf");
        assert_eq!(items[0].provider, "NVIDIA");
        assert_eq!(items[0].class_name, "Display adapters");
        assert_eq!(items[0].version, "32.0.15.6094");
        assert_eq!(items[0].date_key, (2024, 10, 15));
        assert_eq!(items[1].driver_date, "01/05/2023");
    }

    #[test]
    fn marks_old_and_in_use() {
        let mut items = parse(SAMPLE);
        mark_old_duplicates(&mut items, &Some(HashSet::new()));
        assert!(!items[0].is_old_duplicate && items[1].is_old_duplicate);
        let mut items = parse(SAMPLE);
        let mut bound = HashSet::new();
        bound.insert("oem2.inf".to_string());
        mark_old_duplicates(&mut items, &Some(bound));
        assert!(items[1].is_in_use_older && !items[1].is_old_duplicate);
        let mut items = parse(SAMPLE);
        mark_old_duplicates(&mut items, &None);
        assert!(!items[1].is_old_duplicate);
    }

    #[test]
    fn dates_and_versions() {
        assert_eq!(parse_date("30/12/2020"), MIN_DATE);
        assert_eq!(parse_date("1.2.20"), (2020, 1, 2));
        assert_eq!(parse_version("1.2"), Some([1, 2, -1, -1]));
        assert_eq!(parse_version("1"), None);
        assert!(parse_version("1.2.3").unwrap() > parse_version("1.2").unwrap());
    }

    #[test]
    fn messages() {
        assert_eq!(
            known_message(0xE0000237),
            Some("Failed to add the driver package to the driver store.")
        );
    }
}

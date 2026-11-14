#![windows_subsystem = "windows"]

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::{ErrorKind, Write};
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use serde::{Deserialize, Deserializer};
use windows::core::w;
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, HANDLE, WAIT_OBJECT_0,
};
use windows::Win32::System::SystemInformation::{
    GetSystemCpuSetInformation, SYSTEM_CPU_SET_INFORMATION,
};
use windows::Win32::System::Threading::{
    CreateEventW, CreateMutexW, GetCurrentProcess, GetCurrentProcessId, GetCurrentThread,
    OpenProcess, SetPriorityClass, SetProcessAffinityMask, SetProcessDefaultCpuSets,
    SetThreadPriority, WaitForSingleObject, BELOW_NORMAL_PRIORITY_CLASS, PROCESS_ACCESS_RIGHTS,
    THREAD_PRIORITY_BELOW_NORMAL,
};

const PROCESS_SET_LIMITED_INFORMATION: u32 = 0x2000;
const PROCESS_SET_INFORMATION: u32 = 0x0200;
const SYSTEM_PROCESS_INFORMATION: i32 = 5;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC0000004u32 as i32;
const LOG_LIMIT_BYTES: u64 = 256 * 1024;
const ENTRY_MIN_SIZE: usize = 88;

#[link(name = "ntdll")]
extern "system" {
    fn NtQuerySystemInformation(
        info_class: i32,
        buffer: *mut core::ffi::c_void,
        buffer_size: u32,
        return_length: *mut u32,
    ) -> i32;
}

fn null_default<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(d)
}

#[derive(Debug, Clone, Default, Deserialize)]
struct CpuRule {
    #[serde(default, rename = "processName", deserialize_with = "null_default")]
    process_name: Option<String>,
    #[serde(default, rename = "maskType", deserialize_with = "null_default")]
    mask_type: Option<String>,
    #[serde(default, rename = "cores", deserialize_with = "null_default")]
    cores: Option<Vec<bool>>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct CpuRulesConfig {
    #[serde(default, rename = "rules", deserialize_with = "null_default")]
    rules: Option<Vec<Option<CpuRule>>>,
}

fn fold_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            let mut up = c.to_uppercase();
            match (up.next(), up.next()) {
                (Some(u), None) => u,
                _ => c,
            }
        })
        .collect()
}

fn utf16_len(s: &str) -> usize {
    s.encode_utf16().count()
}

fn win32(e: &windows::core::Error) -> u32 {
    (e.code().0 & 0xFFFF) as u32
}

fn log_path_slot() -> &'static std::sync::Mutex<Option<PathBuf>> {
    static SLOT: std::sync::OnceLock<std::sync::Mutex<Option<PathBuf>>> =
        std::sync::OnceLock::new();
    SLOT.get_or_init(|| std::sync::Mutex::new(None))
}

fn open_log() {
    let result = (|| -> std::io::Result<PathBuf> {
        let base = std::env::var_os("PROGRAMDATA")
            .map(PathBuf::from)
            .unwrap_or_default();
        let dir = base.join("XOS Toolkit").join("Logs");
        fs::create_dir_all(&dir)?;
        let path = dir.join("XOS-CpuService.log");
        if let Ok(meta) = fs::metadata(&path) {
            if meta.len() > LOG_LIMIT_BYTES {
                let old = dir.join("XOS-CpuService.old.log");
                let _ = fs::remove_file(&old);
                fs::rename(&path, &old)?;
            }
        }
        Ok(path)
    })();
    if let Ok(path) = result {
        *log_path_slot().lock().unwrap_or_else(|e| e.into_inner()) = Some(path);
    }
}

fn log(message: &str) {
    let path = match log_path_slot()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
    {
        Some(p) => p,
        None => return,
    };
    let line = format!(
        "[{}] {}\r\n",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f"),
        message
    );
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = f.write_all(line.as_bytes());
    }
}

struct Handle(HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

struct Service {
    config_path: PathBuf,
    cpu_set_ids: HashMap<usize, u32>,
    applied: HashMap<i32, String>,
    cached_config: Option<CpuRulesConfig>,
    rules_by_name: HashMap<String, CpuRule>,
    rule_name_byte_lengths: HashSet<usize>,
    running_pids: BTreeMap<i32, String>,
    failed: HashMap<i32, String>,
    logged_once: HashSet<String>,
    apply_error: u32,
    process_buffer: Vec<u64>,
    process_buffer_size: usize,
    last_config_write: i128,
    last_config_size: u64,
    self_pid: i32,
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut config_dir: Option<PathBuf> = None;
    for i in 0..args.len().saturating_sub(1) {
        if args[i] == "--config-dir" {
            config_dir = Some(PathBuf::from(&args[i + 1]));
            break;
        }
    }
    let config_dir = config_dir.unwrap_or_else(|| {
        std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_default()
            .join("XOS Toolkit")
    });
    let config_path = config_dir.join("CpuRules.json");

    let mutex = match unsafe { CreateMutexW(None, true, w!("Global\\XOS_CpuService_Mutex")) } {
        Ok(h) => Handle(h),
        Err(_) => return,
    };
    if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        return;
    }
    let _mutex = mutex;

    let stop_event =
        match unsafe { CreateEventW(None, true, false, w!("Global\\XOS_CpuService_Stop")) } {
            Ok(h) => Handle(h),
            Err(_) => return,
        };

    let self_pid = unsafe { GetCurrentProcessId() } as i32;
    unsafe {
        let _ = SetPriorityClass(GetCurrentProcess(), BELOW_NORMAL_PRIORITY_CLASS);
        let _ = SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
    }

    open_log();
    std::panic::set_hook(Box::new(|info| {
        log(&format!("[ERROR] Crashed: {info}"));
    }));

    let mut svc = Service::new(config_path, self_pid);
    svc.cpu_set_ids = get_cpu_set_ids();
    let procs = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    log(&format!(
        "[OP] Started | PID {} | Logical processors {} | CPU sets {}",
        self_pid,
        procs,
        svc.cpu_set_ids.len()
    ));

    svc.reload_config_if_changed(true);

    while unsafe { WaitForSingleObject(stop_event.0, 1500) } != WAIT_OBJECT_0 {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            svc.reload_config_if_changed(false);
            svc.apply_rules();
        }));
        if let Err(payload) = outcome {
            let msg = payload
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_default();
            svc.log_once(&format!("[ERROR] Cycle failed: Panic: {msg}"));
        }
    }

    log("[OP] Stopped");
}

impl Service {
    fn new(config_path: PathBuf, self_pid: i32) -> Self {
        Service {
            config_path,
            cpu_set_ids: HashMap::new(),
            applied: HashMap::new(),
            cached_config: None,
            rules_by_name: HashMap::new(),
            rule_name_byte_lengths: HashSet::new(),
            running_pids: BTreeMap::new(),
            failed: HashMap::new(),
            logged_once: HashSet::new(),
            apply_error: 0,
            process_buffer: Vec::new(),
            process_buffer_size: 1024 * 1024,
            last_config_write: 0,
            last_config_size: 0,
            self_pid,
        }
    }

    fn log_once(&mut self, message: &str) {
        if self.logged_once.len() >= 50 || !self.logged_once.insert(message.to_string()) {
            return;
        }
        log(message);
    }

    fn reload_config_if_changed(&mut self, force: bool) {
        if !self.config_path.exists() {
            if self.cached_config.is_some() || force {
                log("[OP] Rules file not found, no rules active");
                self.cached_config = None;
                self.last_config_write = 0;
                self.last_config_size = 0;
                self.rebuild_rule_cache();
            }
            return;
        }

        let meta = match fs::metadata(&self.config_path) {
            Ok(m) => m,
            Err(_) => return,
        };
        let write_time = meta
            .modified()
            .ok()
            .map(|t| match t.duration_since(UNIX_EPOCH) {
                Ok(d) => d.as_nanos() as i128,
                Err(e) => -(e.duration().as_nanos() as i128),
            })
            .unwrap_or(0);
        let size = meta.len();

        if !force && write_time == self.last_config_write && size == self.last_config_size {
            return;
        }

        let cfg = match load_config_with_retry(&self.config_path) {
            Some(c) => c,
            None => {
                self.log_once("[ERROR] Rules file unreadable, keeping the previous rules");
                return;
            }
        };

        let total = cfg.rules.as_ref().map(|r| r.len()).unwrap_or(0);
        self.cached_config = Some(cfg);
        self.last_config_write = write_time;
        self.last_config_size = size;
        if !self.rebuild_rule_cache() {
            self.log_once(
                "[ERROR] Rules check failed: NullReferenceException: Object reference not set to an instance of an object.",
            );
            return;
        }
        self.logged_once.clear();
        log(&format!(
            "[OP] Rules loaded: {} active of {}",
            self.rules_by_name.len(),
            total
        ));

        self.applied.clear();
    }

    fn rebuild_rule_cache(&mut self) -> bool {
        self.rules_by_name.clear();
        self.rule_name_byte_lengths.clear();

        let Some(rules) = self.cached_config.as_ref().and_then(|c| c.rules.as_ref()) else {
            return true;
        };
        for r in rules {
            let Some(r) = r else { return false };
            let name = r.process_name.clone().unwrap_or_default();
            let has_cores = r.cores.as_ref().map(|c| !c.is_empty()).unwrap_or(false);
            if name.is_empty() || !has_cores {
                continue;
            }
            self.rule_name_byte_lengths.insert(utf16_len(&name) * 2);
            self.rules_by_name.insert(fold_name(&name), r.clone());
        }
        true
    }

    fn apply_rules(&mut self) {
        if self.rules_by_name.is_empty() {
            return;
        }

        self.get_running_processes();

        let running = &self.running_pids;
        self.applied.retain(|pid, _| running.contains_key(pid));
        self.failed.retain(|pid, _| running.contains_key(pid));

        let entries: Vec<(i32, String)> = self
            .running_pids
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        for (pid, name) in entries {
            if let Some(prev) = self.applied.get(&pid) {
                if fold_name(prev) == fold_name(&name) {
                    continue;
                }
            }

            let Some(rule) = self.rules_by_name.get(&fold_name(&name)).cloned() else {
                continue;
            };

            std::thread::sleep(std::time::Duration::from_millis(1));

            self.apply_error = 0;
            let mask_type = rule.mask_type.clone().unwrap_or_default();
            if self.apply_mask(&rule, pid as u32) {
                self.applied.insert(pid, name.clone());
                self.failed.remove(&pid);
                log(&format!("[RESULT] OK {mask_type} on {name} (PID {pid})"));
            } else {
                let already = self
                    .failed
                    .get(&pid)
                    .map(|f| fold_name(f) == fold_name(&name))
                    .unwrap_or(false);
                if !already {
                    self.failed.insert(pid, name.clone());
                    let reason = if self.apply_error == 0 {
                        "the rule selects cores this PC does not have".to_string()
                    } else {
                        format!("Windows error {}", self.apply_error)
                    };
                    log(&format!(
                        "[RESULT] FAILED {mask_type} on {name} (PID {pid}): {reason}, retrying every cycle"
                    ));
                }
            }
        }
    }

    fn get_running_processes(&mut self) {
        self.running_pids.clear();

        if self.process_buffer.is_empty() {
            self.process_buffer = vec![0u64; self.process_buffer_size.div_ceil(8)];
        }

        let mut return_length: u32 = 0;
        let mut status = unsafe {
            NtQuerySystemInformation(
                SYSTEM_PROCESS_INFORMATION,
                self.process_buffer.as_mut_ptr() as *mut _,
                self.process_buffer_size as u32,
                &mut return_length,
            )
        };

        if status == STATUS_INFO_LENGTH_MISMATCH {
            self.process_buffer = Vec::new();
            self.process_buffer_size = return_length as usize + 65536;
            self.process_buffer = vec![0u64; self.process_buffer_size.div_ceil(8)];
            status = unsafe {
                NtQuerySystemInformation(
                    SYSTEM_PROCESS_INFORMATION,
                    self.process_buffer.as_mut_ptr() as *mut _,
                    self.process_buffer_size as u32,
                    &mut return_length,
                )
            };
        }

        if status != 0 {
            self.log_once(&format!(
                "[ERROR] Process scan failed, status 0x{:08X}",
                status as u32
            ));
            return;
        }

        let valid = if return_length > 0 && return_length as usize <= self.process_buffer_size {
            return_length as usize
        } else {
            self.process_buffer_size
        };
        let bytes =
            unsafe { std::slice::from_raw_parts(self.process_buffer.as_ptr() as *const u8, valid) };
        let base = self.process_buffer.as_ptr() as usize;
        let scan = scan_processes(
            bytes,
            base,
            self.self_pid,
            &self.rule_name_byte_lengths,
            &self.rules_by_name,
        );
        self.running_pids = scan.found;
        if scan.truncated {
            self.log_once("[ERROR] Process scan stopped at an entry past the end of the list");
        }
    }

    fn apply_mask(&mut self, rule: &CpuRule, pid: u32) -> bool {
        let cores: &[bool] = rule.cores.as_deref().unwrap_or(&[]);
        match rule.mask_type.as_deref() {
            Some("CPUSet") => {
                let handle = match unsafe {
                    OpenProcess(
                        PROCESS_ACCESS_RIGHTS(PROCESS_SET_LIMITED_INFORMATION),
                        false,
                        pid,
                    )
                } {
                    Ok(h) if !h.is_invalid() => Handle(h),
                    Ok(_) => return false,
                    Err(e) => {
                        self.apply_error = win32(&e);
                        return false;
                    }
                };
                let Some(ids) = cpu_set_ids_for(&self.cpu_set_ids, cores) else {
                    return false;
                };
                if unsafe { SetProcessDefaultCpuSets(handle.0, Some(&ids)) }.as_bool() {
                    return true;
                }
                self.apply_error = unsafe { GetLastError() }.0;
                false
            }
            Some("Affinity") => {
                let width = usize::BITS as usize;
                if self.cpu_set_ids.keys().any(|&i| i >= width) {
                    return false;
                }
                let handle = match unsafe {
                    OpenProcess(PROCESS_ACCESS_RIGHTS(PROCESS_SET_INFORMATION), false, pid)
                } {
                    Ok(h) if !h.is_invalid() => Handle(h),
                    Ok(_) => return false,
                    Err(e) => {
                        self.apply_error = win32(&e);
                        return false;
                    }
                };
                let Some(mask) = affinity_mask_for(cores, width) else {
                    return false;
                };
                match unsafe { SetProcessAffinityMask(handle.0, mask as usize) } {
                    Ok(()) => true,
                    Err(e) => {
                        self.apply_error = win32(&e);
                        false
                    }
                }
            }
            _ => false,
        }
    }
}

fn load_config_with_retry(path: &Path) -> Option<CpuRulesConfig> {
    for _ in 0..3 {
        let read = fs::OpenOptions::new()
            .read(true)
            .share_mode(7)
            .open(path)
            .and_then(|mut f| {
                let mut buf = Vec::new();
                std::io::Read::read_to_end(&mut f, &mut buf)?;
                Ok(buf)
            });
        match read {
            Ok(bytes) => {
                let slice = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(&bytes);
                match serde_json::from_slice::<Option<CpuRulesConfig>>(slice) {
                    Ok(Some(cfg)) if cfg.rules.is_some() => return Some(cfg),
                    Ok(_) => {}
                    Err(_) => return None,
                }
            }
            Err(e) if is_sharing_io_error(&e) => {
                std::thread::sleep(std::time::Duration::from_millis(200))
            }
            Err(_) => return None,
        }
    }
    None
}

fn is_sharing_io_error(e: &std::io::Error) -> bool {
    !matches!(
        e.kind(),
        ErrorKind::NotFound | ErrorKind::PermissionDenied | ErrorKind::InvalidInput
    )
}

fn cpu_set_ids_for(map: &HashMap<usize, u32>, cores: &[bool]) -> Option<Vec<u32>> {
    let mut ids = Vec::new();
    for (i, &on) in cores.iter().enumerate() {
        if !on {
            continue;
        }
        ids.push(*map.get(&i)?);
    }
    if ids.is_empty() {
        None
    } else {
        Some(ids)
    }
}

fn affinity_mask_for(cores: &[bool], width: usize) -> Option<u64> {
    let usable = cores.len().min(width);
    if cores.iter().skip(usable).any(|&c| c) {
        return None;
    }
    let mut mask = 0u64;
    for (i, &on) in cores.iter().enumerate().take(usable) {
        if on {
            mask |= 1u64 << i;
        }
    }
    if mask == 0 {
        None
    } else {
        Some(mask)
    }
}

struct Scan {
    found: BTreeMap<i32, String>,
    truncated: bool,
}

fn rd_u16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

fn rd_u32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn rd_u64(b: &[u8], o: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(a)
}

fn scan_processes(
    bytes: &[u8],
    base: usize,
    self_pid: i32,
    name_byte_lengths: &HashSet<usize>,
    rules: &HashMap<String, CpuRule>,
) -> Scan {
    let mut found = BTreeMap::new();
    let end = bytes.len();
    let mut current = 0usize;
    let mut processed = 0u32;
    loop {
        if current + ENTRY_MIN_SIZE > end {
            return Scan {
                found,
                truncated: true,
            };
        }

        let next_offset = rd_u32(bytes, current) as usize;
        let pid = rd_u64(bytes, current + 80) as i64 as i32;

        if pid != self_pid {
            let name_length = rd_u16(bytes, current + 56) as usize;
            let name_ptr = rd_u64(bytes, current + 64) as usize;
            if name_length > 0
                && name_ptr >= base
                && name_ptr - base + name_length <= end
                && name_byte_lengths.contains(&name_length)
            {
                let off = name_ptr - base;
                let units: Vec<u16> = (0..name_length / 2)
                    .map(|i| rd_u16(bytes, off + i * 2))
                    .collect();
                let image = String::from_utf16_lossy(&units);
                if rules.contains_key(&fold_name(&image)) {
                    found.insert(pid, image);
                }
            }
        }

        if next_offset == 0 {
            break;
        }
        current += next_offset;

        processed += 1;
        if processed % 20 == 0 {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
    Scan {
        found,
        truncated: false,
    }
}

fn get_cpu_set_ids() -> HashMap<usize, u32> {
    let mut result = HashMap::new();
    let mut len: u32 = 0;
    unsafe {
        let _ = GetSystemCpuSetInformation(None, 0, &mut len, None, Some(0));
    }
    if len == 0 {
        return result;
    }
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    let ok = unsafe {
        GetSystemCpuSetInformation(
            Some(buf.as_mut_ptr() as *mut SYSTEM_CPU_SET_INFORMATION),
            len,
            &mut len,
            None,
            Some(0),
        )
    };
    if !ok.as_bool() {
        return result;
    }
    let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, len as usize) };
    parse_cpu_sets(bytes, &mut result);
    result
}

fn parse_cpu_sets(bytes: &[u8], result: &mut HashMap<usize, u32>) {
    let mut pos = 0usize;
    while pos < bytes.len() {
        if pos + 16 > bytes.len() {
            break;
        }
        let size = rd_u32(bytes, pos) as usize;
        if size < 8 || pos + size > bytes.len() {
            break;
        }
        if rd_u32(bytes, pos + 4) == 0 {
            let id = rd_u32(bytes, pos + 8);
            let group = rd_u16(bytes, pos + 12) as usize;
            let lp = bytes[pos + 14] as usize;
            result.insert(group * 64 + lp, id);
        }
        pos += size;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn affinity_mask_rules() {
        assert_eq!(affinity_mask_for(&[true, false, true], 64), Some(0b101));
        assert_eq!(affinity_mask_for(&[false, false], 64), None);
        let mut high = vec![false; 70];
        high[1] = true;
        high[66] = true;
        assert_eq!(affinity_mask_for(&high, 64), None);
        high[66] = false;
        assert_eq!(affinity_mask_for(&high, 64), Some(0b10));
        assert_eq!(affinity_mask_for(&[true, true, true], 2), None);
    }

    #[test]
    fn cpu_set_selection() {
        let map: HashMap<usize, u32> = [(0, 256), (1, 257)].into_iter().collect();
        assert_eq!(cpu_set_ids_for(&map, &[true, true]), Some(vec![256, 257]));
        assert_eq!(cpu_set_ids_for(&map, &[true, false, true]), None);
    }

    #[test]
    fn config_parse_matches_data_contract() {
        let cfg: CpuRulesConfig = serde_json::from_str(
            r#"{"rules":[{"cores":[true],"maskType":"CPUSet","processName":"a.exe"}],"userPresets":[{"name":"x"}]}"#,
        )
        .unwrap();
        assert_eq!(cfg.rules.unwrap().len(), 1);
        let none: CpuRulesConfig = serde_json::from_str("{}").unwrap();
        assert!(none.rules.is_none());
    }

    #[test]
    fn rule_cache_skips_empty_rules_and_ignores_case() {
        let mut s = Service::new(PathBuf::new(), 1);
        s.cached_config = serde_json::from_str(
            r#"{"rules":[{"cores":[true],"maskType":"CPUSet","processName":"Game.exe"},{"cores":[],"maskType":"CPUSet","processName":"b.exe"},{"cores":[true],"maskType":"Affinity","processName":""}]}"#,
        )
        .ok();
        assert!(s.rebuild_rule_cache());
        assert_eq!(s.rules_by_name.len(), 1);
        assert!(s.rules_by_name.contains_key(&fold_name("GAME.EXE")));
        assert!(s.rule_name_byte_lengths.contains(&16));
    }

    fn entry(buf: &mut Vec<u8>, next: u32, pid: u64, name: &str, name_off_from_base: usize) {
        let start = buf.len();
        buf.resize(start + ENTRY_MIN_SIZE, 0);
        buf[start..start + 4].copy_from_slice(&next.to_le_bytes());
        buf[start + 56..start + 58]
            .copy_from_slice(&((name.encode_utf16().count() * 2) as u16).to_le_bytes());
        buf[start + 64..start + 72].copy_from_slice(&(name_off_from_base as u64).to_le_bytes());
        buf[start + 80..start + 88].copy_from_slice(&pid.to_le_bytes());
    }

    #[test]
    fn process_scan_bounds_and_matching() {
        let base = 0x1000usize;
        let mut buf = Vec::new();
        entry(
            &mut buf,
            ENTRY_MIN_SIZE as u32,
            10,
            "game.exe",
            base + ENTRY_MIN_SIZE * 2,
        );
        entry(&mut buf, 0, 11, "other.exe", base + 100000);
        let name = "Game.EXE";
        for u in name.encode_utf16() {
            buf.extend_from_slice(&u.to_le_bytes());
        }
        let mut rules = HashMap::new();
        rules.insert(fold_name("game.exe"), CpuRule::default());
        let lens: HashSet<usize> = [16].into_iter().collect();
        let scan = scan_processes(&buf, base, 999, &lens, &rules);
        assert!(!scan.truncated);
        assert_eq!(scan.found.get(&10).map(String::as_str), Some("Game.EXE"));
        assert!(!scan.found.contains_key(&11));

        let scan = scan_processes(&buf, base, 10, &lens, &rules);
        assert!(scan.found.is_empty());

        let scan = scan_processes(&buf[..100], base, 999, &lens, &rules);
        assert!(scan.truncated);
    }

    #[test]
    fn cpu_set_buffer_parse() {
        let mut buf = vec![0u8; 64];
        buf[0..4].copy_from_slice(&32u32.to_le_bytes());
        buf[8..12].copy_from_slice(&258u32.to_le_bytes());
        buf[14] = 2;
        buf[32..36].copy_from_slice(&8u32.to_le_bytes());
        let mut m = HashMap::new();
        parse_cpu_sets(&buf, &mut m);
        assert_eq!(m.get(&2), Some(&258));
    }
}

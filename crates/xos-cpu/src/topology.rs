use std::collections::{BTreeSet, HashMap};
use std::sync::RwLock;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::SystemInformation::{
    GetLogicalProcessorInformationEx, GetSystemCpuSetInformation, LOGICAL_PROCESSOR_RELATIONSHIP,
    SYSTEM_CPU_SET_INFORMATION,
};
use windows::Win32::System::Threading::{
    OpenProcess, SetProcessAffinityMask, SetProcessDefaultCpuSets, PROCESS_ACCESS_RIGHTS,
};

const RELATION_CORE: i32 = 0;
const RELATION_CACHE_LEVEL: i32 = 2;
const RELATION_DIE: i32 = 5;

const ACCESS_SET_LIMITED: u32 = 0x2000;
const ACCESS_SET_INFO: u32 = 0x0200;

const HEADER_SIZE: usize = 8;
const CORE_RELATION_SIZE: usize = 24;
const CACHE_RELATION_SIZE: usize = 32;
const AFFINITY_GROUP_SIZE: usize = 16;
const CPU_SET_ENTRY_MIN: usize = 32;

#[derive(Debug, Clone, Default)]
pub struct PhysicalCore {
    pub has_threads: bool,
    pub tier: u32,
    pub logical_processors: BTreeSet<usize>,
}

#[derive(Debug, Clone, Default)]
pub struct DieEntry {
    pub logical_processors: BTreeSet<usize>,
}

#[derive(Debug, Clone, Default)]
pub struct CacheEntry {
    pub level: u32,
    pub cache_size: u32,
    pub logical_processors: BTreeSet<usize>,
}

pub type Preset = (String, Vec<bool>);
pub type CoreGroup = (String, Vec<usize>);

#[derive(Debug, Clone)]
pub struct State {
    pub cpu_name: String,
    pub manufacturer: String,
    pub logical_processor_count: usize,
    pub physical_core_count: usize,
    pub has_smt: bool,
    pub error_message: Option<String>,
    pub thread_labels: Vec<String>,
    pub presets: Vec<Preset>,
    pub core_groups: Vec<CoreGroup>,
    pub cpu_set_id_map: HashMap<usize, u32>,
    pub cores: Vec<PhysicalCore>,
    pub available: BTreeSet<usize>,
    pub is_hybrid: bool,
    pub is_three_tier_hybrid: bool,
    initialized: bool,
}

impl Default for State {
    fn default() -> Self {
        State {
            cpu_name: "Unknown".into(),
            manufacturer: "Unknown".into(),
            logical_processor_count: 0,
            physical_core_count: 0,
            has_smt: false,
            error_message: None,
            thread_labels: Vec::new(),
            presets: Vec::new(),
            core_groups: Vec::new(),
            cpu_set_id_map: HashMap::new(),
            cores: Vec::new(),
            available: BTreeSet::new(),
            is_hybrid: false,
            is_three_tier_hybrid: false,
            initialized: false,
        }
    }
}

static STATE: RwLock<Option<State>> = RwLock::new(None);

fn with_state<T>(f: impl FnOnce(&State) -> T) -> T {
    let guard = STATE.read().unwrap_or_else(|e| e.into_inner());
    match guard.as_ref() {
        Some(s) => f(s),
        None => f(&State::default()),
    }
}

fn env_processor_count() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

pub fn initialize() {
    let mut guard = STATE.write().unwrap_or_else(|e| e.into_inner());
    if guard.as_ref().map(|s| s.initialized).unwrap_or(false) {
        return;
    }
    let mut s = State::default();
    s.initialized = true;
    if let Err(message) = run_initialize(&mut s) {
        s.error_message = Some(message);
        if s.thread_labels.is_empty() {
            s.logical_processor_count = env_processor_count();
            for i in 0..s.logical_processor_count {
                s.thread_labels.push(format!("Core {i}"));
            }
        }
        finalize_available_processors(&mut s);
        if s.core_groups.is_empty() {
            s.core_groups
                .push(("Cores".into(), s.available.iter().copied().collect()));
        }
    }
    *guard = Some(s);
}

fn run_initialize(s: &mut State) -> Result<(), String> {
    s.logical_processor_count = env_processor_count();
    read_cpu_name(s);
    analyze_core_layout(s)?;
    map_cpu_set_ids(s);
    finalize_available_processors(s);
    let dies = enumerate_dies()?;
    let caches = if dies.len() >= 2 {
        enumerate_caches()?
    } else {
        Vec::new()
    };
    generate_presets(s, &dies, &caches);
    build_core_groups(s, &dies);
    Ok(())
}

pub fn cpu_name() -> String {
    with_state(|s| s.cpu_name.clone())
}

pub fn manufacturer() -> String {
    with_state(|s| s.manufacturer.clone())
}

pub fn logical_processor_count() -> usize {
    with_state(|s| s.logical_processor_count)
}

pub fn physical_core_count() -> usize {
    with_state(|s| s.physical_core_count)
}

pub fn has_smt() -> bool {
    with_state(|s| s.has_smt)
}

pub fn error_message() -> Option<String> {
    with_state(|s| s.error_message.clone())
}

pub fn thread_labels() -> Vec<String> {
    with_state(|s| s.thread_labels.clone())
}

pub fn presets() -> Vec<Preset> {
    with_state(|s| s.presets.clone())
}

pub fn core_groups() -> Vec<CoreGroup> {
    with_state(|s| s.core_groups.clone())
}

pub fn is_logical_processor_available(index: i64) -> bool {
    with_state(|s| is_available(s, index))
}

pub fn supports_affinity_masks() -> bool {
    with_state(supports_masks)
}

fn is_available(s: &State, index: i64) -> bool {
    index >= 0 && s.available.contains(&(index as usize))
}

fn supports_masks(s: &State) -> bool {
    !s.available.is_empty() && s.available.iter().all(|&i| i < usize::BITS as usize)
}

fn read_cpu_name(s: &mut State) {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;
    let read = || -> Option<String> {
        let key = RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey(r"HARDWARE\DESCRIPTION\System\CentralProcessor\0")
            .ok()?;
        let value: Result<String, _> = key.get_value("ProcessorNameString");
        value.ok().map(|v| v.trim().to_string())
    };
    s.cpu_name = read().unwrap_or_else(|| "Unknown".into());
    set_manufacturer(s);
}

fn set_manufacturer(s: &mut State) {
    let lower = s.cpu_name.to_lowercase();
    s.manufacturer = if lower.contains("amd") {
        "AMD".into()
    } else if lower.contains("intel") {
        "Intel".into()
    } else {
        "Other".into()
    };
}

fn analyze_core_layout(s: &mut State) -> Result<(), String> {
    s.cores = read_relationships(RELATION_CORE).map_err(|e| format!("{e}"))?;
    analyze_cores(s, env_processor_count());
    Ok(())
}

fn analyze_cores(s: &mut State, env_count: usize) {
    s.physical_core_count = s.cores.len();
    let topology_count = s
        .cores
        .iter()
        .flat_map(|c| c.logical_processors.iter().copied())
        .max()
        .map(|m| m + 1)
        .unwrap_or(0);
    s.logical_processor_count = env_count.max(topology_count);

    let highest_tier = s.cores.iter().map(|c| c.tier).max().unwrap_or(0);
    s.is_hybrid = highest_tier >= 1;
    s.is_three_tier_hybrid = highest_tier >= 2;

    s.thread_labels = Vec::with_capacity(s.logical_processor_count);
    s.has_smt = false;
    for thread_idx in 0..s.logical_processor_count {
        let owner = s
            .cores
            .iter()
            .position(|c| c.logical_processors.contains(&thread_idx));
        let Some(owner) = owner else {
            s.thread_labels.push(format!("Core {thread_idx}"));
            continue;
        };

        let mut tag = "";
        if s.manufacturer == "Intel" && s.is_hybrid {
            let perf_tier = if s.is_three_tier_hybrid { 2 } else { 1 };
            tag = if s.cores[owner].tier >= perf_tier {
                "P-"
            } else {
                "E-"
            };
        }

        let mut suffix = String::new();
        if s.cores[owner].has_threads {
            s.has_smt = true;
            let siblings = s.cores[owner]
                .logical_processors
                .iter()
                .filter(|&&i| i < thread_idx)
                .count();
            suffix = format!(" T{siblings}");
        }

        s.thread_labels.push(format!("{tag}Core {owner}{suffix}"));
    }
}

fn map_cpu_set_ids(s: &mut State) {
    s.cpu_set_id_map = HashMap::new();
    let mut needed: u32 = 0;
    unsafe {
        let _ = GetSystemCpuSetInformation(None, 0, &mut needed, None, Some(0));
    }
    if needed == 0 {
        return;
    }
    let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
    let ok = unsafe {
        GetSystemCpuSetInformation(
            Some(buf.as_mut_ptr() as *mut SYSTEM_CPU_SET_INFORMATION),
            needed,
            &mut needed,
            None,
            Some(0),
        )
    };
    if !ok.as_bool() {
        return;
    }
    let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, needed as usize) };
    s.cpu_set_id_map = parse_cpu_set_entries(bytes);
}

pub fn parse_cpu_set_entries(bytes: &[u8]) -> HashMap<usize, u32> {
    let mut map = HashMap::new();
    let mut pos = 0usize;
    while pos + CPU_SET_ENTRY_MIN <= bytes.len() {
        let size = u32_at(bytes, pos) as usize;
        let remaining = bytes.len() - pos;
        if size < CPU_SET_ENTRY_MIN || size > remaining {
            break;
        }
        let kind = u32_at(bytes, pos + 4);
        if kind == 0 {
            let id = u32_at(bytes, pos + 8);
            let group = u16_at(bytes, pos + 12);
            let lp = bytes[pos + 14];
            map.insert(global_index(group, lp), id);
        }
        pos += size;
    }
    map
}

fn u16_at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn u64_at(b: &[u8], o: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(a)
}

fn global_index(group: u16, lp: u8) -> usize {
    group as usize * 64 + lp as usize
}

fn add_group_processors(dest: &mut BTreeSet<usize>, mask: u64, group: u16) {
    for index in 0..64u8 {
        if mask & (1u64 << index) != 0 {
            dest.insert(global_index(group, index));
        }
    }
}

fn indices_to_mask<'a>(indices: impl IntoIterator<Item = &'a usize>, length: usize) -> Vec<bool> {
    let mut result = vec![false; length];
    for &index in indices {
        if index < length {
            result[index] = true;
        }
    }
    result
}

fn filter_primary_threads(s: &State, mask: &[bool]) -> (Vec<bool>, bool) {
    let mut result = vec![false; mask.len()];
    let mut did_filter = false;
    for i in 0..mask.len() {
        let mut secondary = false;
        if let Some(label) = s.thread_labels.get(i) {
            let chars: Vec<char> = label.chars().collect();
            secondary =
                chars.len() >= 3 && chars[chars.len() - 2] == 'T' && chars[chars.len() - 1] != '0';
        }
        if mask[i] && secondary {
            did_filter = true;
        }
        result[i] = mask[i] && !secondary;
    }
    (result, did_filter)
}

pub fn generate_presets(s: &mut State, dies: &[DieEntry], caches: &[CacheEntry]) {
    s.presets = Vec::new();
    let total = s.logical_processor_count;

    if s.manufacturer == "Intel" && s.is_hybrid {
        let perf_tier = if s.is_three_tier_hybrid { 2 } else { 1 };
        let eff_tier = if s.is_three_tier_hybrid { 1 } else { 0 };
        let mut perf = BTreeSet::new();
        let mut eff = BTreeSet::new();
        let mut lp = BTreeSet::new();
        for core in &s.cores {
            if core.tier == perf_tier {
                perf.extend(core.logical_processors.iter().copied());
            } else if core.tier == eff_tier {
                eff.extend(core.logical_processors.iter().copied());
            } else if s.is_three_tier_hybrid && core.tier == 0 {
                lp.extend(core.logical_processors.iter().copied());
            }
        }
        s.presets
            .push(("P-Cores".into(), indices_to_mask(&perf, total)));
        s.presets
            .push(("E-Cores".into(), indices_to_mask(&eff, total)));
        if s.is_three_tier_hybrid && !lp.is_empty() {
            s.presets
                .push(("LP E-Cores".into(), indices_to_mask(&lp, total)));
        }
    }

    if dies.len() >= 2 {
        let l3: Vec<&CacheEntry> = caches.iter().filter(|c| c.level == 3).collect();
        let l3_per_die: Vec<i64> = dies
            .iter()
            .map(|d| {
                l3.iter()
                    .filter(|c| c.logical_processors == d.logical_processors)
                    .map(|c| c.cache_size as i64)
                    .sum()
            })
            .collect();
        let smallest = *l3_per_die.iter().min().unwrap_or(&0);
        let mut large = Vec::new();
        let mut standard = Vec::new();
        for (d, &size) in l3_per_die.iter().enumerate() {
            if size > smallest * 2 {
                large.push(d);
            } else {
                standard.push(d);
            }
        }
        if large.is_empty() {
            standard = (0..dies.len()).collect();
        }

        for &d in &large {
            let label = if large.len() >= 2 {
                format!("3D Cores {d}")
            } else {
                "3D Cores".to_string()
            };
            s.presets
                .push((label, indices_to_mask(&dies[d].logical_processors, total)));
        }
        for (i, &d) in standard.iter().enumerate() {
            let label = if !large.is_empty() {
                if standard.len() >= 2 {
                    format!("Non 3D Cores {i}")
                } else {
                    "Non 3D Cores".to_string()
                }
            } else if standard.len() >= 2 {
                format!("CCD {i}")
            } else {
                "CCD".to_string()
            };
            s.presets
                .push((label, indices_to_mask(&dies[d].logical_processors, total)));
        }
    }

    let (all_physical, any_filtered) =
        filter_primary_threads(s, &indices_to_mask(&s.available, total));
    if any_filtered {
        s.presets
            .push(("Physical Cores".into(), all_physical.clone()));
        let logical_only: Vec<bool> = (0..total)
            .map(|i| is_available(s, i as i64) && !all_physical[i])
            .collect();
        s.presets.push(("Logical Cores".into(), logical_only));
    }
}

pub fn build_core_groups(s: &mut State, dies: &[DieEntry]) {
    s.core_groups = Vec::new();

    if s.is_hybrid {
        let perf_tier = if s.is_three_tier_hybrid { 2 } else { 1 };
        let mut perf = Vec::new();
        let mut eff = Vec::new();
        let mut lp = Vec::new();
        for i in 0..s.logical_processor_count {
            let Some(owner) = s.cores.iter().find(|c| c.logical_processors.contains(&i)) else {
                continue;
            };
            if owner.tier >= perf_tier {
                perf.push(i);
            } else if s.is_three_tier_hybrid && owner.tier >= 1 {
                eff.push(i);
            } else if !s.is_three_tier_hybrid && owner.tier == 0 {
                eff.push(i);
            } else {
                lp.push(i);
            }
        }
        if !perf.is_empty() {
            s.core_groups.push(("P-Cores".into(), perf));
        }
        if !eff.is_empty() {
            s.core_groups.push(("E-Cores".into(), eff));
        }
        if !lp.is_empty() {
            s.core_groups.push(("LP E-Cores".into(), lp));
        }
    } else if dies.len() >= 2 {
        for (d, die) in dies.iter().enumerate() {
            let indices: Vec<usize> = (0..s.logical_processor_count)
                .filter(|i| die.logical_processors.contains(i))
                .collect();
            if !indices.is_empty() {
                s.core_groups.push((format!("CCD {d}"), indices));
            }
        }
    }

    if s.core_groups.is_empty() {
        s.core_groups
            .push(("Cores".into(), s.available.iter().copied().collect()));
    }
}

pub fn finalize_available_processors(s: &mut State) {
    s.available = s.cpu_set_id_map.keys().copied().collect();
    for core in &s.cores {
        s.available.extend(core.logical_processors.iter().copied());
    }
    if s.available.is_empty() {
        s.available.extend(0..s.logical_processor_count);
    }
    let required = s.available.iter().max().map(|m| m + 1).unwrap_or(0);
    while s.thread_labels.len() < required {
        let n = s.thread_labels.len();
        s.thread_labels.push(format!("Core {n}"));
    }
    s.logical_processor_count = s.logical_processor_count.max(required);
}

struct ProcessHandle(HANDLE);

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

fn open_process(access: u32, pid: u32) -> Option<ProcessHandle> {
    unsafe { OpenProcess(PROCESS_ACCESS_RIGHTS(access), false, pid) }
        .ok()
        .filter(|h| !h.is_invalid())
        .map(ProcessHandle)
}

pub fn cpu_set_ids_for(map: &HashMap<usize, u32>, cores: &[bool]) -> Option<Vec<u32>> {
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

pub fn affinity_mask_for(cores: &[bool]) -> u64 {
    let mut bits = 0u64;
    for (i, &on) in cores.iter().enumerate().take(64) {
        if on {
            bits |= 1u64 << i;
        }
    }
    bits
}

pub fn apply_cpu_set(pid: u32, cores: Option<&[bool]>) -> bool {
    let Some(cores) = cores else { return false };
    let Some(handle) = open_process(ACCESS_SET_LIMITED, pid) else {
        return false;
    };
    let ids = with_state(|s| cpu_set_ids_for(&s.cpu_set_id_map, cores));
    let Some(ids) = ids else { return false };
    unsafe { SetProcessDefaultCpuSets(handle.0, Some(&ids)) }.as_bool()
}

pub fn apply_affinity(pid: u32, cores: Option<&[bool]>) -> bool {
    let Some(cores) = cores else { return false };
    if !supports_affinity_masks() {
        return false;
    }
    let width = usize::BITS as usize;
    if cores.iter().skip(width).any(|&c| c) {
        return false;
    }
    for (i, &on) in cores.iter().enumerate().take(width) {
        if on && !is_logical_processor_available(i as i64) {
            return false;
        }
    }
    let Some(handle) = open_process(ACCESS_SET_INFO, pid) else {
        return false;
    };
    let bits = affinity_mask_for(cores);
    if bits == 0 {
        return false;
    }
    unsafe { SetProcessAffinityMask(handle.0, bits as usize) }.is_ok()
}

fn enumerate_dies() -> Result<Vec<DieEntry>, String> {
    match read_relationships(RELATION_DIE) {
        Ok(rels) => Ok(rels
            .into_iter()
            .map(|r| DieEntry {
                logical_processors: r.logical_processors,
            })
            .collect()),
        Err(31) => Ok(Vec::new()),
        Err(code) => Err(win32_message(code)),
    }
}

fn win32_message(code: i32) -> String {
    windows::core::Error::from(windows::core::HRESULT::from_win32(code as u32)).message()
}

fn fetch_relationship(relationship: i32) -> Result<Vec<u8>, i32> {
    let rel = LOGICAL_PROCESSOR_RELATIONSHIP(relationship);
    let mut needed: u32 = 0;
    unsafe {
        let _ = GetLogicalProcessorInformationEx(rel, None, &mut needed);
    }
    if needed == 0 {
        return Ok(Vec::new());
    }
    let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
    let r = unsafe {
        GetLogicalProcessorInformationEx(rel, Some(buf.as_mut_ptr() as *mut _), &mut needed)
    };
    if let Err(e) = r {
        return Err((e.code().0 & 0xFFFF) as i32);
    }
    let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, needed as usize) };
    Ok(bytes.to_vec())
}

fn read_relationships(relationship: i32) -> Result<Vec<PhysicalCore>, i32> {
    Ok(parse_cores(&fetch_relationship(relationship)?))
}

fn enumerate_caches() -> Result<Vec<CacheEntry>, String> {
    let bytes = fetch_relationship(RELATION_CACHE_LEVEL).map_err(win32_message)?;
    Ok(parse_caches(&bytes))
}

fn read_groups(bytes: &[u8], first: usize, count: usize) -> BTreeSet<usize> {
    let mut set = BTreeSet::new();
    for g in 0..count {
        let at = first + g * AFFINITY_GROUP_SIZE;
        if at + AFFINITY_GROUP_SIZE > bytes.len() {
            break;
        }
        add_group_processors(&mut set, u64_at(bytes, at), u16_at(bytes, at + 8));
    }
    set
}

pub fn parse_cores(bytes: &[u8]) -> Vec<PhysicalCore> {
    let mut result = Vec::new();
    let mut pos = 0usize;
    while bytes.len() - pos >= HEADER_SIZE {
        let size = u32_at(bytes, pos + 4) as usize;
        if size < HEADER_SIZE || size > bytes.len() - pos {
            break;
        }
        let data = pos + HEADER_SIZE;
        if data + CORE_RELATION_SIZE > bytes.len() {
            break;
        }
        let flags = bytes[data];
        let tier = bytes[data + 1] as u32;
        let group_count = u16_at(bytes, data + 22) as usize;
        result.push(PhysicalCore {
            has_threads: flags & 1 != 0,
            tier,
            logical_processors: read_groups(bytes, data + CORE_RELATION_SIZE, group_count),
        });
        pos += size;
    }
    result
}

pub fn parse_caches(bytes: &[u8]) -> Vec<CacheEntry> {
    let mut result = Vec::new();
    let mut pos = 0usize;
    while bytes.len() - pos >= HEADER_SIZE {
        let size = u32_at(bytes, pos + 4) as usize;
        if size < HEADER_SIZE || size > bytes.len() - pos {
            break;
        }
        let data = pos + HEADER_SIZE;
        if data + CACHE_RELATION_SIZE > bytes.len() {
            break;
        }
        let group_count = u16_at(bytes, data + 30) as usize;
        result.push(CacheEntry {
            level: bytes[data] as u32,
            cache_size: u32_at(bytes, data + 4),
            logical_processors: read_groups(bytes, data + CACHE_RELATION_SIZE, group_count),
        });
        pos += size;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn core(tier: u32, threads: bool, lps: &[usize]) -> PhysicalCore {
        PhysicalCore {
            has_threads: threads,
            tier,
            logical_processors: lps.iter().copied().collect(),
        }
    }

    fn state(manufacturer: &str, cores: Vec<PhysicalCore>, total: usize) -> State {
        let mut s = State::default();
        s.manufacturer = manufacturer.into();
        s.logical_processor_count = total;
        s.cores = cores;
        analyze_cores(&mut s, total);
        finalize_available_processors(&mut s);
        s
    }

    #[test]
    fn affinity_mask_ignores_index_64_and_above() {
        let mut cores = vec![false; 70];
        cores[1] = true;
        cores[65] = true;
        assert_eq!(affinity_mask_for(&cores), 0b10);
        assert_eq!(affinity_mask_for(&[true, false, true]), 0b101);
    }

    #[test]
    fn cpu_set_ids_require_every_selected_core() {
        let map: HashMap<usize, u32> = [(0, 256), (1, 257)].into_iter().collect();
        assert_eq!(cpu_set_ids_for(&map, &[true, true]), Some(vec![256, 257]));
        assert_eq!(cpu_set_ids_for(&map, &[true, false, true]), None);
        assert_eq!(cpu_set_ids_for(&map, &[false, false]), None);
    }

    #[test]
    fn hybrid_intel_labels_and_presets() {
        let s = {
            let mut s = state(
                "Intel",
                vec![
                    core(1, true, &[0, 1]),
                    core(0, false, &[2]),
                    core(0, false, &[3]),
                ],
                4,
            );
            let (dies, caches) = (Vec::new(), Vec::new());
            generate_presets(&mut s, &dies, &caches);
            build_core_groups(&mut s, &dies);
            s
        };
        assert_eq!(
            s.thread_labels,
            vec!["P-Core 0 T0", "P-Core 0 T1", "E-Core 1", "E-Core 2"]
        );
        assert!(s.has_smt);
        let names: Vec<&str> = s.presets.iter().map(|p| p.0.as_str()).collect();
        assert_eq!(
            names,
            vec!["P-Cores", "E-Cores", "Physical Cores", "Logical Cores"]
        );
        assert_eq!(s.presets[0].1, vec![true, true, false, false]);
        assert_eq!(s.presets[2].1, vec![true, false, true, true]);
        assert_eq!(s.presets[3].1, vec![false, true, false, false]);
        let groups: Vec<&str> = s.core_groups.iter().map(|g| g.0.as_str()).collect();
        assert_eq!(groups, vec!["P-Cores", "E-Cores"]);
    }

    #[test]
    fn amd_dual_ccd_with_3d_cache() {
        let mut s = state("AMD", vec![core(0, false, &[0]), core(0, false, &[1])], 2);
        let dies = vec![
            DieEntry {
                logical_processors: [0].into_iter().collect(),
            },
            DieEntry {
                logical_processors: [1].into_iter().collect(),
            },
        ];
        let caches = vec![
            CacheEntry {
                level: 3,
                cache_size: 96,
                logical_processors: [0].into_iter().collect(),
            },
            CacheEntry {
                level: 3,
                cache_size: 32,
                logical_processors: [1].into_iter().collect(),
            },
        ];
        generate_presets(&mut s, &dies, &caches);
        build_core_groups(&mut s, &dies);
        let names: Vec<&str> = s.presets.iter().map(|p| p.0.as_str()).collect();
        assert_eq!(names, vec!["3D Cores", "Non 3D Cores"]);
        assert_eq!(s.core_groups[1].0, "CCD 1");
    }

    #[test]
    fn parse_relationship_buffers() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&(8u32 + 24 + 16).to_le_bytes());
        let mut rel = [0u8; 24];
        rel[0] = 1;
        rel[1] = 2;
        rel[22] = 1;
        buf.extend_from_slice(&rel);
        buf.extend_from_slice(&0b11u64.to_le_bytes());
        buf.extend_from_slice(&1u16.to_le_bytes());
        buf.extend_from_slice(&[0u8; 6]);
        let cores = parse_cores(&buf);
        assert_eq!(cores.len(), 1);
        assert!(cores[0].has_threads);
        assert_eq!(cores[0].tier, 2);
        assert_eq!(
            cores[0]
                .logical_processors
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            vec![64, 65]
        );
    }

    #[test]
    fn parse_cpu_set_buffer_stops_on_bad_size() {
        let mut buf = vec![0u8; 64];
        buf[0..4].copy_from_slice(&32u32.to_le_bytes());
        buf[8..12].copy_from_slice(&256u32.to_le_bytes());
        buf[12..14].copy_from_slice(&1u16.to_le_bytes());
        buf[14] = 3;
        buf[32..36].copy_from_slice(&4u32.to_le_bytes());
        let map = parse_cpu_set_entries(&buf);
        assert_eq!(map.len(), 1);
        assert_eq!(map[&67], 256);
    }

    #[test]
    fn live_initialize_is_readable() {
        initialize();
        assert!(logical_processor_count() >= 1);
        assert_eq!(thread_labels().len(), logical_processor_count());
        assert!(!core_groups().is_empty());
    }
}

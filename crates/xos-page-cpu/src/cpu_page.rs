use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use windows::core::w;
use windows::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    OpenEventW, OpenProcess, SetEvent, TerminateProcess, WaitForSingleObject, EVENT_MODIFY_STATE,
    PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
};
use xos_core::host::{Buttons, DialogResult, FileFilter, Host, Icon, Page, PickItem};
use xos_core::ui::*;
use xos_core::{app_state, log, status};
use xos_cpu::rules::{self, CpuConfigExport, CpuRule, CpuRulesConfig, UserPreset};
use xos_cpu::topology;

const TASK_NAME: &str = "XOS CPU Service";
const TITLE: &str = "XOS Toolkit";
const ROW_CHUNK: usize = 6;

#[derive(Clone, Debug, Default)]
pub struct Topo {
    pub logical_count: usize,
    pub available: Vec<bool>,
    pub supports_affinity: bool,
    pub presets: Vec<(String, Vec<bool>)>,
    pub groups: Vec<(String, Vec<usize>)>,
    pub labels: Vec<String>,
    pub shown: Vec<bool>,
}

impl Topo {
    pub fn snapshot() -> Self {
        let logical_count = topology::logical_processor_count();
        let available: Vec<bool> = (0..logical_count)
            .map(|i| topology::is_logical_processor_available(i as i64))
            .collect();
        let groups = topology::core_groups();
        let mut t = Topo {
            logical_count,
            available,
            supports_affinity: topology::supports_affinity_masks(),
            presets: topology::presets(),
            groups,
            labels: topology::thread_labels(),
            shown: Vec::new(),
        };
        t.compute_shown();
        t
    }

    pub fn compute_shown(&mut self) {
        let mut shown = vec![false; self.logical_count];
        for (_, indices) in &self.groups {
            for &idx in indices {
                if idx < self.logical_count && self.is_available(idx) && !shown[idx] {
                    shown[idx] = true;
                }
            }
        }
        self.shown = shown;
    }

    pub fn is_available(&self, idx: usize) -> bool {
        self.available.get(idx).copied().unwrap_or(false)
    }

    pub fn label(&self, idx: usize) -> String {
        self.labels
            .get(idx)
            .cloned()
            .unwrap_or_else(|| format!("Core {idx}"))
    }
}

pub fn normalize_process_name(value: &str) -> Option<String> {
    if value.trim().is_empty() {
        return None;
    }
    let trimmed = value.trim().trim_matches('"');
    let name = match trimmed.rfind(['\\', '/', ':']) {
        Some(i) => &trimmed[i + 1..],
        None => trimmed,
    };
    if name.trim().is_empty()
        || name.chars().any(|c| {
            (c as u32) < 32 || matches!(c, '"' | '<' | '>' | '|' | ':' | '*' | '?' | '\\' | '/')
        })
    {
        return None;
    }
    let mut name = name.to_string();
    if !name.to_lowercase().ends_with(".exe") {
        name.push_str(".exe");
    }
    Some(name)
}

pub fn normalize_core_mask(source: &[bool], affinity: bool, topo: &Topo) -> Vec<bool> {
    let count = topo.logical_count;
    let mut normalized = vec![false; count];
    let limit = if affinity { count.min(64) } else { count };
    let usable = source.len().min(limit);
    for i in 0..usable {
        normalized[i] = source[i] && topo.is_available(i);
    }
    normalized
}

fn canonical_mask_type(value: &str) -> Option<&'static str> {
    if value.eq_ignore_ascii_case("CPUSet") {
        Some("CPUSet")
    } else if value.eq_ignore_ascii_case("Affinity") {
        Some("Affinity")
    } else {
        None
    }
}

pub fn normalize_rule(rule: &CpuRule, topo: &Topo) -> Option<CpuRule> {
    let name = normalize_process_name(&rule.process_name)?;
    let mut kind = canonical_mask_type(&rule.mask_type)?;
    if kind == "Affinity" && !topo.supports_affinity {
        kind = "CPUSet";
    }
    let cores = normalize_core_mask(&rule.cores, kind == "Affinity", topo);
    if !cores.iter().any(|c| *c) {
        return None;
    }
    Some(CpuRule {
        cores,
        mask_type: kind.to_string(),
        process_name: name,
    })
}

pub fn normalize_loaded(config: &mut CpuRulesConfig, topo: &Topo) -> bool {
    if topo.logical_count == 0 {
        return false;
    }
    let mut changed = false;
    let mut rules: Vec<CpuRule> = Vec::new();
    for rule in &config.rules {
        let Some(normalized) = normalize_rule(rule, topo) else {
            changed = true;
            continue;
        };
        if normalized != *rule {
            changed = true;
        }
        match rules.iter().position(|r| {
            r.process_name
                .eq_ignore_ascii_case(&normalized.process_name)
        }) {
            Some(d) => {
                rules[d] = normalized;
                changed = true;
            }
            None => rules.push(normalized),
        }
    }
    let mut presets: Vec<UserPreset> = Vec::new();
    for preset in &config.user_presets {
        let name = preset.name.trim().to_string();
        let cores = normalize_core_mask(&preset.cores, false, topo);
        if name.is_empty() || !cores.iter().any(|c| *c) {
            changed = true;
            continue;
        }
        if cores != preset.cores || name != preset.name {
            changed = true;
        }
        let normalized = UserPreset {
            name: name.clone(),
            cores,
        };
        match presets
            .iter()
            .position(|p| p.name.eq_ignore_ascii_case(&name))
        {
            Some(d) => {
                presets[d] = normalized;
                changed = true;
            }
            None => presets.push(normalized),
        }
    }
    config.rules = rules;
    config.user_presets = presets;
    changed
}

pub fn summarize_mask(cores: &[bool], topo: &Topo) -> String {
    for (name, mask) in &topo.presets {
        if mask.len() == cores.len() && mask.as_slice() == cores {
            return name.clone();
        }
    }
    let mut selected = 0;
    let mut available = 0;
    for (i, c) in cores.iter().enumerate() {
        if !topo.is_available(i) {
            continue;
        }
        available += 1;
        if *c {
            selected += 1;
        }
    }
    if selected == 0 {
        return "None".to_string();
    }
    if selected == available {
        return "All Cores".to_string();
    }
    let indices: Vec<String> = cores
        .iter()
        .enumerate()
        .filter(|(_, c)| **c)
        .map(|(i, _)| i.to_string())
        .collect();
    format!("{selected}/{available} cores [{}]", indices.join(","))
}

pub fn service_label(state: i32, running: bool, installed: bool) -> &'static str {
    if state == 1 && running {
        "Enabled"
    } else if state == 0 && !running {
        "Disabled"
    } else if state < 0 && !running {
        if installed {
            "Disabled"
        } else {
            "N/A"
        }
    } else {
        "Partial"
    }
}

pub fn process_display_name(exe_file: &str) -> String {
    let base = if exe_file.to_lowercase().ends_with(".exe") {
        &exe_file[..exe_file.len() - 4]
    } else {
        exe_file
    };
    format!("{base}.exe")
}

fn list_processes() -> Vec<(u32, String)> {
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
                out.push((
                    entry.th32ProcessID,
                    String::from_utf16_lossy(&entry.szExeFile[..len]),
                ));
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
    }
    out
}

fn service_pids() -> Vec<u32> {
    list_processes()
        .into_iter()
        .filter(|(_, n)| process_display_name(n).eq_ignore_ascii_case("XOS-CpuService.exe"))
        .map(|(pid, _)| pid)
        .collect()
}

fn is_cpu_service_running() -> bool {
    !service_pids().is_empty()
}

fn wait_for_cpu_service_state(running: bool, timeout_ms: u64) -> bool {
    let timer = Instant::now();
    loop {
        if is_cpu_service_running() == running {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
        if timer.elapsed().as_millis() as u64 >= timeout_ms {
            break;
        }
    }
    is_cpu_service_running() == running
}

fn service_exe_path() -> Option<std::path::PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("XOS-CpuService.exe")))
}

struct State {
    config: CpuRulesConfig,
    editing_index: i32,
    process_name: String,
    affinity: bool,
    core_checked: Vec<bool>,
    service_label: Option<String>,
}

pub struct CpuPage {
    topo: Topo,
    cpu_name: String,
    cpu_details: String,
    cpu_topology_text: String,
    cpu_warning: bool,
    st: Mutex<State>,
}

impl Default for CpuPage {
    fn default() -> Self {
        Self::new()
    }
}

impl CpuPage {
    pub fn new() -> Self {
        topology::initialize();
        let topo = Topo::snapshot();
        let mut config = rules::load();
        if normalize_loaded(&mut config, &topo) {
            if let Err(ex) = rules::save(&config) {
                log::exception(
                    "CPU configuration normalization could not be saved",
                    &ex.to_string(),
                );
            }
        }
        let available = topo.available.iter().filter(|a| **a).count();
        let manufacturer = topology::manufacturer();
        let mut details = format!(
            "{} Physical Cores / {} Logical Processors",
            topology::physical_core_count(),
            available
        );
        if topology::has_smt() {
            details.push_str(if manufacturer == "Intel" {
                " (Hyper-Threading)"
            } else {
                " (SMT)"
            });
        }
        let mut features: Vec<String> = Vec::new();
        if manufacturer != "Unknown" {
            features.push(manufacturer.clone());
        }
        for (name, indices) in &topo.groups {
            if name != "Cores" {
                features.push(format!("{name}: {} threads", indices.len()));
            }
        }
        let mut topology_text = features.join("  |  ");
        let mut warning = false;
        if let Some(err) = topology::error_message() {
            if !topology_text.is_empty() {
                topology_text.push('\n');
            }
            topology_text.push_str(&format!("Warning: {err}"));
            warning = true;
        }
        let affinity = false;
        let core_checked = vec![false; topo.logical_count];
        CpuPage {
            cpu_name: topology::cpu_name(),
            cpu_details: details,
            cpu_topology_text: topology_text,
            cpu_warning: warning,
            topo,
            st: Mutex::new(State {
                config,
                editing_index: -1,
                process_name: String::new(),
                affinity,
                core_checked,
                service_label: None,
            }),
        }
    }

    fn selected_cores(&self, st: &State) -> Vec<bool> {
        (0..self.topo.logical_count)
            .map(|i| self.topo.shown[i] && st.core_checked.get(i).copied().unwrap_or(false))
            .collect()
    }

    fn clear_editor(&self, st: &mut State) {
        st.process_name.clear();
        for c in st.core_checked.iter_mut() {
            *c = false;
        }
    }

    fn cancel_edit(&self, st: &mut State) {
        st.editing_index = -1;
        self.clear_editor(st);
    }

    fn save_config(&self, host: &dyn Host) -> bool {
        let result = {
            let st = self.st.lock().unwrap();
            rules::save(&st.config)
        };
        match result {
            Ok(()) => true,
            Err(ex) => {
                log::exception("CPU configuration save failed", &ex.to_string());
                log::action_done(
                    "Cpu",
                    true,
                    false,
                    Some(&format!(
                        "the CPU configuration file could not be saved: {ex}"
                    )),
                );
                {
                    let mut st = self.st.lock().unwrap();
                    let mut config = rules::load();
                    normalize_loaded(&mut config, &self.topo);
                    st.config = config;
                }
                host.error(
                    &format!("CPU configuration could not be saved.\n\n{ex}"),
                    TITLE,
                );
                false
            }
        }
    }

    fn warn(&self, host: &dyn Host, msg: &str) {
        host.warn(msg, TITLE);
    }

    fn apply_preset(&self, name: &str, mask: Option<&[bool]>) {
        let mut st = self.st.lock().unwrap();
        if name == "Select All" {
            for i in 0..self.topo.logical_count {
                if self.topo.shown[i] {
                    st.core_checked[i] = true;
                }
            }
        } else if name == "Clear" {
            for i in 0..self.topo.logical_count {
                if self.topo.shown[i] {
                    st.core_checked[i] = false;
                }
            }
        } else if let Some(mask) = mask {
            for i in 0..self.topo.logical_count {
                if self.topo.shown[i] {
                    st.core_checked[i] = i < mask.len() && mask[i] && self.topo.is_available(i);
                }
            }
        }
    }

    fn save_preset(&self, host: &dyn Host) {
        let cores = {
            let st = self.st.lock().unwrap();
            self.selected_cores(&st)
        };
        if cores.iter().all(|c| !c) {
            self.warn(host, "Select at least one core before saving a preset.");
            return;
        }
        let Some(name) = host.input_text("Preset name:", "Save Core Preset", 40, "Save") else {
            return;
        };
        if name.trim().is_empty() {
            return;
        }
        let name = name.trim().to_string();
        let existing = {
            let st = self.st.lock().unwrap();
            st.config
                .user_presets
                .iter()
                .position(|p| p.name.eq_ignore_ascii_case(&name))
        };
        if let Some(e) = existing {
            if host.dialog(
                &format!("A preset named '{name}' already exists. Replace it?"),
                TITLE,
                Buttons::YesNo,
                Icon::Question,
            ) != DialogResult::Yes
            {
                return;
            }
            self.st.lock().unwrap().config.user_presets[e].cores = cores;
        } else {
            self.st
                .lock()
                .unwrap()
                .config
                .user_presets
                .push(UserPreset {
                    name: name.clone(),
                    cores,
                });
        }
        if !self.save_config(host) {
            return;
        }
        log::action_done("Cpu", false, false, Some(&format!("preset '{name}' saved")));
        host.set_status(&format!("Preset '{name}' saved."));
    }

    fn delete_user_preset(&self, host: &dyn Host, index: usize) {
        let name = {
            let mut st = self.st.lock().unwrap();
            let Some(name) = st.config.user_presets.get(index).map(|p| p.name.clone()) else {
                return;
            };
            st.config
                .user_presets
                .retain(|p| !p.name.eq_ignore_ascii_case(&name));
            name
        };
        if !self.save_config(host) {
            return;
        }
        log::action_done(
            "Cpu",
            false,
            false,
            Some(&format!("preset '{name}' deleted")),
        );
        host.set_status(&format!("Preset '{name}' deleted."));
    }

    fn browse(&self, host: &dyn Host) {
        let mut processes: HashMap<String, (String, usize)> = HashMap::new();
        for (_, exe) in list_processes() {
            let name = process_display_name(&exe);
            processes
                .entry(name.to_lowercase())
                .and_modify(|e| e.1 += 1)
                .or_insert((name, 1));
        }
        let mut sorted: Vec<(String, usize)> = processes.into_values().collect();
        sorted.sort_by(|a, b| a.0.to_uppercase().cmp(&b.0.to_uppercase()));
        let has_rule: Vec<String> = {
            let st = self.st.lock().unwrap();
            st.config
                .rules
                .iter()
                .map(|r| r.process_name.to_lowercase())
                .collect()
        };
        let items: Vec<PickItem> = sorted
            .iter()
            .map(|(name, count)| {
                let exists = has_rule.contains(&name.to_lowercase());
                PickItem {
                    id: name.clone(),
                    label: format!(
                        "{name}  ({count} instance{}){}",
                        if *count > 1 { "s" } else { "" },
                        if exists { "  [rule set]" } else { "" }
                    ),
                    tone: if exists { Tone::Orange } else { Tone::Neutral },
                }
            })
            .collect();
        let selected = host.pick_many(
            "Select Running Processes",
            "Orange = rule already exists",
            "Filter processes...",
            items,
            "Select",
        );
        if selected.is_empty() {
            return;
        }
        if selected.len() == 1 {
            self.st.lock().unwrap().process_name = selected[0].clone();
            return;
        }
        let (cores, affinity) = {
            let st = self.st.lock().unwrap();
            (self.selected_cores(&st), st.affinity)
        };
        if !cores.iter().any(|c| *c) {
            self.warn(
                host,
                "Please select cores first, then use Browse to bulk-add processes.",
            );
            return;
        }
        let mask_type = if affinity { "Affinity" } else { "CPUSet" };
        if mask_type == "Affinity" && !self.topo.supports_affinity {
            self.warn(
                host,
                "Affinity cannot safely address this processor layout. Use CPU Set instead.",
            );
            return;
        }
        let mut added = 0;
        let mut replaced = 0;
        {
            let mut st = self.st.lock().unwrap();
            for proc_name in &selected {
                let rule = CpuRule {
                    process_name: proc_name.clone(),
                    mask_type: mask_type.to_string(),
                    cores: cores.clone(),
                };
                match st
                    .config
                    .rules
                    .iter()
                    .position(|r| r.process_name.eq_ignore_ascii_case(proc_name))
                {
                    Some(e) => {
                        st.config.rules[e] = rule;
                        replaced += 1;
                    }
                    None => {
                        st.config.rules.push(rule);
                        added += 1;
                    }
                }
            }
        }
        if !self.save_config(host) {
            return;
        }
        let mut msg = format!("Added {added} rule(s)");
        if replaced > 0 {
            msg.push_str(&format!(", replaced {replaced}"));
        }
        log::action_done("Cpu", false, false, Some(&msg));
        host.set_status(&msg);
    }

    fn add_rule(&self, host: &dyn Host) {
        let (raw_name, cores, affinity, editing) = {
            let st = self.st.lock().unwrap();
            (
                st.process_name.clone(),
                self.selected_cores(&st),
                st.affinity,
                st.editing_index,
            )
        };
        let Some(process_name) = normalize_process_name(&raw_name) else {
            self.warn(
                host,
                "Enter a valid executable name, for example discord.exe.",
            );
            return;
        };
        if cores.iter().all(|c| !c) {
            self.warn(host, "Please select at least one core.");
            return;
        }
        let mask_type = if affinity { "Affinity" } else { "CPUSet" };
        if mask_type == "Affinity" && !self.topo.supports_affinity {
            self.warn(
                host,
                "Affinity cannot safely address this processor layout. Use CPU Set instead.",
            );
            return;
        }
        if mask_type == "Affinity" && cores.iter().skip(64).any(|c| *c) {
            self.warn(
                host,
                "The Windows affinity mask cannot address every selected logical processor. Use CPU Set instead.",
            );
            return;
        }
        let rule = CpuRule {
            process_name: process_name.clone(),
            mask_type: mask_type.to_string(),
            cores,
        };
        let rule_count = self.st.lock().unwrap().config.rules.len();
        if editing >= 0 && (editing as usize) < rule_count {
            let editing = editing as usize;
            let duplicate = {
                let st = self.st.lock().unwrap();
                st.config.rules.iter().enumerate().position(|(i, r)| {
                    i != editing && r.process_name.eq_ignore_ascii_case(&process_name)
                })
            };
            if let Some(d) = duplicate {
                if host.dialog(
                    &format!(
                        "A rule for '{process_name}' already exists. Replace it and remove the rule being edited?"
                    ),
                    TITLE,
                    Buttons::YesNo,
                    Icon::Question,
                ) != DialogResult::Yes
                {
                    return;
                }
                let mut st = self.st.lock().unwrap();
                st.config.rules[d] = rule;
                st.config.rules.remove(editing);
            } else {
                self.st.lock().unwrap().config.rules[editing] = rule;
            }
            self.st.lock().unwrap().editing_index = -1;
        } else {
            let existing = {
                let st = self.st.lock().unwrap();
                st.config
                    .rules
                    .iter()
                    .position(|r| r.process_name.eq_ignore_ascii_case(&process_name))
            };
            match existing {
                Some(e) => {
                    if host.dialog(
                        &format!("A rule for '{process_name}' already exists. Replace it?"),
                        TITLE,
                        Buttons::YesNo,
                        Icon::Question,
                    ) != DialogResult::Yes
                    {
                        return;
                    }
                    self.st.lock().unwrap().config.rules[e] = rule;
                }
                None => self.st.lock().unwrap().config.rules.push(rule),
            }
        }
        if !self.save_config(host) {
            return;
        }
        {
            let mut st = self.st.lock().unwrap();
            self.clear_editor(&mut st);
        }
        log::action_done(
            "Cpu",
            false,
            false,
            Some(&format!("rule saved for {process_name}")),
        );
        host.set_status(&format!("Rule saved for {process_name}"));
    }

    fn edit_rule(&self, index: usize) {
        let mut st = self.st.lock().unwrap();
        let Some(rule) = st.config.rules.get(index).cloned() else {
            return;
        };
        st.editing_index = index as i32;
        st.process_name = rule.process_name.clone();
        st.affinity = rule.mask_type == "Affinity";
        for i in 0..self.topo.logical_count {
            if self.topo.shown[i] {
                st.core_checked[i] = i < rule.cores.len() && rule.cores[i];
            }
        }
    }

    fn remove_rule(&self, host: &dyn Host, index: usize) {
        let name = {
            let mut st = self.st.lock().unwrap();
            if index >= st.config.rules.len() {
                return;
            }
            st.config.rules.remove(index).process_name
        };
        if !self.save_config(host) {
            return;
        }
        {
            let mut st = self.st.lock().unwrap();
            if st.editing_index == index as i32 {
                xos_sys::ops::reset();
                self.cancel_edit(&mut st);
            } else if st.editing_index > index as i32 {
                st.editing_index -= 1;
            }
        }
        log::action_done(
            "Cpu",
            false,
            false,
            Some(&format!("rule removed for {name}")),
        );
        host.set_status(&format!("Rule removed for {name}"));
    }

    fn export_config(&self, host: &dyn Host) {
        let (rules_n, presets_n, export) = {
            let st = self.st.lock().unwrap();
            if st.config.rules.is_empty() && st.config.user_presets.is_empty() {
                drop(st);
                host.info("There are no rules or presets to export yet.", TITLE);
                return;
            }
            (
                st.config.rules.len(),
                st.config.user_presets.len(),
                CpuConfigExport {
                    format: CpuConfigExport::FORMAT_ID.to_string(),
                    cpu_name: self.cpu_name.clone(),
                    logical_processors: self.topo.logical_count as i32,
                    exported_utc: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                    rules: st.config.rules.clone(),
                    user_presets: st.config.user_presets.clone(),
                },
            )
        };
        let filters = [
            FileFilter::new("JSON configuration (*.json)", &["json"]),
            FileFilter::new("All files (*.*)", &["*"]),
        ];
        let Some(path) = host.save_file(
            "Export CPU Affinity Configuration",
            &filters,
            "XOS-CPU-Rules.json",
            None,
        ) else {
            return;
        };
        let path_text = path.to_string_lossy().to_string();
        match rules::export(&path_text, &export) {
            Ok(()) => {
                let msg = format!("Exported {rules_n} rule(s) and {presets_n} preset(s)");
                log::action_done("Cpu", false, false, Some(&msg));
                host.set_status(&format!("{msg}."));
                host.info(
                    &format!(
                        "Exported {rules_n} rule(s) and {presets_n} preset(s) to:\n\n{path_text}"
                    ),
                    TITLE,
                );
            }
            Err(ex) => {
                log::action_done("Cpu", true, false, Some(&ex.to_string()));
                host.error(&format!("Could not write the file:\n\n{ex}"), TITLE);
            }
        }
    }

    fn import_config(&self, host: &dyn Host) {
        let filters = [
            FileFilter::new("JSON configuration (*.json)", &["json"]),
            FileFilter::new("All files (*.*)", &["*"]),
        ];
        let Some(path) = host.open_file("Import CPU Affinity Configuration", &filters, None) else {
            return;
        };
        let import = match rules::import(&path.to_string_lossy()) {
            Ok(i) => i,
            Err(ex) => {
                log::action_done(
                    "Cpu",
                    true,
                    false,
                    Some(&format!("the file is not an XOS CPU configuration: {ex}")),
                );
                host.error(
                    &format!("Could not read that file as an XOS configuration:\n\n{ex}"),
                    TITLE,
                );
                return;
            }
        };
        if import.rules.is_empty() && import.user_presets.is_empty() {
            host.info("That file contains no rules or presets.", TITLE);
            return;
        }
        let logical = self.topo.logical_count as i32;
        if import.logical_processors > 0 && import.logical_processors != logical {
            if host.dialog(
                &format!(
                    "This configuration was created on a CPU with {} logical processors, but this machine has {}.\n\nRules will still import, but core selections may not line up. Continue?",
                    import.logical_processors, logical
                ),
                TITLE,
                Buttons::YesNo,
                Icon::Warning,
            ) != DialogResult::Yes
            {
                return;
            }
        }
        let existing_rules = self.st.lock().unwrap().config.rules.len();
        let mut replace = false;
        if existing_rules > 0 {
            let choice = host.dialog(
                &format!(
                    "You have {existing_rules} existing rule(s). The file has {}.\n\nYes = replace your rules with the imported set.\nNo = merge (imported rules win on conflicts).",
                    import.rules.len()
                ),
                "Import Configuration",
                Buttons::YesNo,
                Icon::Question,
            );
            if choice == DialogResult::Cancel {
                return;
            }
            replace = choice == DialogResult::Yes;
        }

        let (added, replaced, presets_added) = {
            let mut st = self.st.lock().unwrap();
            if replace {
                st.config.rules.clear();
            }
            let mut added = 0;
            let mut replaced = 0;
            for rule in &import.rules {
                let Some(normalized) = normalize_rule(rule, &self.topo) else {
                    continue;
                };
                match st.config.rules.iter().position(|r| {
                    r.process_name
                        .eq_ignore_ascii_case(&normalized.process_name)
                }) {
                    Some(e) => {
                        st.config.rules[e] = normalized;
                        replaced += 1;
                    }
                    None => {
                        st.config.rules.push(normalized);
                        added += 1;
                    }
                }
            }
            let mut presets_added = 0;
            for preset in &import.user_presets {
                let name = preset.name.trim().to_string();
                let cores = normalize_core_mask(&preset.cores, false, &self.topo);
                if name.is_empty() || !cores.iter().any(|c| *c) {
                    continue;
                }
                let normalized = UserPreset {
                    name: name.clone(),
                    cores,
                };
                match st
                    .config
                    .user_presets
                    .iter()
                    .position(|p| p.name.eq_ignore_ascii_case(&name))
                {
                    Some(e) => st.config.user_presets[e] = normalized,
                    None => {
                        st.config.user_presets.push(normalized);
                        presets_added += 1;
                    }
                }
            }
            (added, replaced, presets_added)
        };

        if !self.save_config(host) {
            return;
        }
        {
            let mut st = self.st.lock().unwrap();
            xos_sys::ops::reset();
            self.cancel_edit(&mut st);
        }
        let mut msg = if replace {
            format!("Replaced with {added} imported rule(s).")
        } else {
            format!("Imported {added} new rule(s), updated {replaced}.")
        };
        if presets_added > 0 {
            msg.push_str(&format!(" Added {presets_added} preset(s)."));
        }
        log::action_done("Cpu", false, false, Some(&msg));
        host.set_status(&msg);
        host.info(&msg, TITLE);
    }

    fn apply_now(&self, host: &dyn Host) {
        let rules_list = self.st.lock().unwrap().config.rules.clone();
        if rules_list.is_empty() {
            host.set_status("No rules to apply.");
            return;
        }
        let mut by_name: HashMap<String, &CpuRule> = HashMap::new();
        for r in &rules_list {
            by_name.insert(r.process_name.to_lowercase(), r);
        }
        let mut applied = 0;
        let mut failed = 0;
        for (pid, exe) in list_processes() {
            let name = process_display_name(&exe).to_lowercase();
            let Some(rule) = by_name.get(&name) else {
                continue;
            };
            let ok = if rule.mask_type == "CPUSet" {
                topology::apply_cpu_set(pid, Some(&rule.cores))
            } else {
                topology::apply_affinity(pid, Some(&rule.cores))
            };
            if ok {
                applied += 1;
            } else {
                failed += 1;
            }
        }
        let mut msg = format!("Applied rules to {applied} process(es).");
        if failed > 0 {
            msg.push_str(&format!(
                " {failed} failed (may need admin rights or anti-cheat blocks access)."
            ));
        }
        log::action_done(
            "Cpu",
            applied == 0 && failed > 0,
            failed > 0,
            Some(&format!("applied {applied}, failed {failed}")),
        );
        host.set_status(&msg);
        host.info(&msg, TITLE);
    }

    fn refresh_service_badge(&self) -> i32 {
        let states = xos_sys::get_task_states_batch(&[TASK_NAME.to_string()]);
        let state = states.get(TASK_NAME).copied().unwrap_or(-1);
        let running = is_cpu_service_running();
        let installed = service_exe_path().map(|p| p.is_file()).unwrap_or(false);
        let label = service_label(state, running, installed);
        self.st.lock().unwrap().service_label = Some(label.to_string());
        state
    }

    fn service_enable(&self, host: &dyn Host) {
        let service_path = service_exe_path();
        let service_path = match service_path {
            Some(p) if p.is_file() => p,
            _ => {
                log::action_done(
                    "Cpu",
                    true,
                    false,
                    Some("XOS-CpuService.exe not found next to the Toolkit"),
                );
                host.error("XOS-CpuService.exe not found.", TITLE);
                return;
            }
        };
        let config_dir = rules::config_dir();
        let created = xos_sys::run_cmd(
            "schtasks.exe",
            &format!(
                "/create /tn \"{TASK_NAME}\" /tr \"\\\"{}\\\" --config-dir \\\"{}\\\"\" /sc onlogon /rl highest /f",
                service_path.display(),
                config_dir.display()
            ),
        );
        let started =
            created && xos_sys::run_cmd("schtasks.exe", &format!("/run /tn \"{TASK_NAME}\""));
        let process_running = started && wait_for_cpu_service_state(true, 3000);
        let task_state = self.refresh_service_badge();
        let enabled = created && started && task_state == 1 && process_running;
        log::action_done(
            "Cpu",
            !created,
            !enabled,
            Some(&format!(
                "task created {}, started {}, task state {task_state}, process running {}",
                bool_text(created),
                bool_text(started),
                bool_text(process_running)
            )),
        );
        if enabled {
            host.set_status("XOS CPU Service enabled and started.");
            host.info("XOS CPU Service has been enabled and started.", TITLE);
        } else {
            host.set_status("XOS CPU Service could not be fully enabled.");
            host.warn(
                "XOS CPU Service could not be fully enabled or started. Please check the Toolkit log and try again.",
                TITLE,
            );
        }
    }

    fn service_disable(&self, host: &dyn Host) {
        unsafe {
            if let Ok(event) =
                OpenEventW(EVENT_MODIFY_STATE, false, w!("Global\\XOS_CpuService_Stop"))
            {
                let _ = SetEvent(event);
                let _ = CloseHandle(event);
                std::thread::sleep(Duration::from_millis(1000));
            }
        }
        let mut process_stopped = true;
        for pid in service_pids() {
            unsafe {
                match OpenProcess(PROCESS_TERMINATE | PROCESS_SYNCHRONIZE, false, pid) {
                    Ok(handle) => {
                        if TerminateProcess(handle, 1).is_err() {
                            process_stopped = false;
                        } else if WaitForSingleObject(handle, 5000) != WAIT_OBJECT_0 {
                            process_stopped = false;
                        }
                        let _ = CloseHandle(handle);
                    }
                    Err(_) => {
                        if service_pids().contains(&pid) {
                            process_stopped = false;
                        }
                    }
                }
            }
        }
        process_stopped &= wait_for_cpu_service_state(false, 2000);

        let previous_task_state = self.refresh_service_badge();
        let task_removed = previous_task_state == -1
            || xos_sys::run_cmd("schtasks.exe", &format!("/delete /tn \"{TASK_NAME}\" /f"));
        let task_state = self.refresh_service_badge();
        let disabled = task_removed && task_state == -1 && process_stopped;
        log::action_done(
            "Cpu",
            !task_removed && !process_stopped,
            !disabled,
            Some(&format!(
                "task removed {}, task state {task_state}, process stopped {}",
                bool_text(task_removed),
                bool_text(process_stopped)
            )),
        );
        if disabled {
            host.set_status("XOS CPU Service disabled.");
            host.info("XOS CPU Service has been disabled.", TITLE);
        } else {
            host.set_status("XOS CPU Service could not be disabled.");
            host.warn(
                "The XOS CPU Service task or running process could not be removed. Please check the Toolkit log and try again.",
                TITLE,
            );
        }
    }
}

fn bool_text(v: bool) -> &'static str {
    if v {
        "True"
    } else {
        "False"
    }
}

fn push_chunked(card: Card, controls: Vec<Control>, chunk: usize) -> Card {
    let mut card = card;
    let mut iter = controls.into_iter().peekable();
    while iter.peek().is_some() {
        let row: Vec<Control> = iter.by_ref().take(chunk).collect();
        card = card.controls(row);
    }
    card
}

impl Page for CpuPage {
    fn id(&self) -> &'static str {
        "Cpu"
    }

    fn label(&self) -> &'static str {
        "CPU Affinity"
    }

    fn model(&self) -> PageModel {
        let st = self.st.lock().unwrap();
        let topo = &self.topo;

        let badge = match &st.service_label {
            None => Badge::checking(),
            Some(label) => {
                let tone = match label.as_str() {
                    "Enabled" => Tone::Green,
                    "Disabled" => Tone::Red,
                    _ => Tone::Neutral,
                };
                let tip = if label == "Partial" {
                    "The startup task and running process do not match.".to_string()
                } else {
                    status::description(label)
                };
                Badge::new(label.clone(), tone).tooltip(tip)
            }
        };

        let mut cpu_text = Control::muted(self.cpu_topology_text.clone());
        if self.cpu_warning {
            cpu_text = cpu_text.tone(Tone::Orange);
        }
        let cpu_card = Card::new("cpu", "Your CPU", "")
            .not_searchable()
            .controls(vec![Control::label(self.cpu_name.clone())])
            .controls(vec![Control::muted(self.cpu_details.clone())])
            .controls(vec![cpu_text]);

        let editing = st.editing_index >= 0 && (st.editing_index as usize) < st.config.rules.len();
        let editor_title = if editing {
            format!(
                "Editing: {}",
                st.config.rules[st.editing_index as usize].process_name
            )
        } else {
            "Add New Rule".to_string()
        };

        let mut cpuset_check = Control::check("type.cpuset", "CPU Set", !st.affinity);
        let mut affinity_check = Control::check("type.affinity", "Affinity", st.affinity);
        if !topo.supports_affinity {
            affinity_check = affinity_check
                .enabled(false)
                .tooltip("Affinity is unavailable on multi-group systems. Use CPU Set.");
            cpuset_check = Control::check("type.cpuset", "CPU Set", true);
        }

        let mut editor = Card::new("editor", editor_title, "")
            .not_searchable()
            .full_width()
            .controls(vec![
                Control::heading("Process Name:"),
                Control::text_input("process", st.process_name.clone(), "").width(200.0),
                Control::button("browse", "Browse", BtnStyle::Action),
                Control::heading("Type:"),
                cpuset_check,
                affinity_check,
            ])
            .controls(vec![
                Control::heading("Presets:"),
                Control::spacer(),
                Control::button("preset.save", "Save as Preset", BtnStyle::Enable),
            ]);

        let mut presets: Vec<Control> = vec![
            Control::button("preset.all", "Select All", BtnStyle::Action),
            Control::button("preset.clear", "Clear", BtnStyle::Action),
        ];
        for (i, (name, _)) in topo.presets.iter().enumerate() {
            presets.push(Control::button(
                format!("tpreset.{i}"),
                name.clone(),
                BtnStyle::Action,
            ));
        }
        let mut preset_rows: Vec<Vec<Control>> = Vec::new();
        let mut current: Vec<Control> = Vec::new();
        for c in presets {
            if current.len() >= ROW_CHUNK {
                preset_rows.push(std::mem::take(&mut current));
            }
            current.push(c);
        }
        for (i, p) in st.config.user_presets.iter().enumerate() {
            if current.len() + 2 > ROW_CHUNK {
                preset_rows.push(std::mem::take(&mut current));
            }
            current.push(Control::button(
                format!("upreset.{i}"),
                p.name.clone(),
                BtnStyle::Enable,
            ));
            current.push(Control::button(
                format!("udel.{i}"),
                "\u{00D7}",
                BtnStyle::Disable,
            ));
        }
        if !current.is_empty() {
            preset_rows.push(current);
        }
        for row in preset_rows {
            editor = editor.controls(row);
        }

        let selected = (0..topo.logical_count)
            .filter(|&i| topo.shown[i] && st.core_checked.get(i).copied().unwrap_or(false))
            .count();
        let available = topo.shown.iter().filter(|s| **s).count();
        editor = editor.controls(vec![
            Control::heading("Cores:"),
            Control::spacer(),
            Control::muted(format!("{selected} of {available} selected")),
        ]);
        for (name, indices) in &topo.groups {
            if topo.groups.len() > 1 {
                editor = editor.controls(vec![Control::heading(name.clone())]);
            }
            let mut seen: Vec<usize> = Vec::new();
            let mut checks: Vec<Control> = Vec::new();
            for &idx in indices {
                if idx >= topo.logical_count
                    || !topo.is_available(idx)
                    || seen.contains(&idx)
                    || group_owner(topo, idx) != Some(name.as_str())
                {
                    continue;
                }
                seen.push(idx);
                checks.push(
                    Control::check(
                        format!("core.{idx}"),
                        topo.label(idx),
                        st.core_checked.get(idx).copied().unwrap_or(false),
                    )
                    .width(140.0),
                );
            }
            editor = push_chunked(editor, checks, ROW_CHUNK);
        }

        let mut buttons = vec![Control::button(
            "rule.add",
            if editing { "Save Rule" } else { "Add Rule" },
            BtnStyle::Enable,
        )];
        if editing {
            buttons.push(Control::button("rule.cancel", "Cancel", BtnStyle::Disable));
        }
        buttons.push(Control::button(
            "rule.apply",
            "Apply All Rules Now",
            BtnStyle::Warning,
        ));
        editor = editor.actions(buttons);

        let mut model = PageModel::new(
            "Cpu",
            "CPU Affinity Rules",
            "Set per-process CPU Set or Affinity rules. A lightweight service applies rules automatically at logon.",
        )
        .single_column()
        .max_width(1080.0)
        .card(
            Card::new(
                "about",
                "",
                "Useful on Intel CPUs with P-cores and E-cores, and on Ryzen CPUs with more than one CCD or with 3D V-Cache. Move background apps to efficiency or non-3D cores and keep your best cores free for your game. CPU Set is recommended: it works with most games and anti-cheats. Affinity locks a program to specific cores more strictly, but most anti-cheats block or override it.",
            )
            .not_searchable(),
        )
        .card(
            Card::new(
                "service",
                "Background Service",
                "XOS CPU Service starts when you sign in and applies your CPU rules to matching programs automatically.",
            )
            .badge(badge)
            .enable_disable("service"),
        )
        .card(cpu_card)
        .card(editor)
        .card(
            Card::new(
                "backup",
                "Backup & Restore",
                "Export all your process rules and saved presets to a file, then import them after a Windows reinstall. Import onto the same CPU restores everything exactly. A different CPU still works but core layouts may not line up.",
            )
            .actions(vec![
                Control::button("export", "Export to File", BtnStyle::Action),
                Control::button("import", "Import from File", BtnStyle::Enable),
            ]),
        );

        let mut rules_card = Card::new("rules", "", "")
            .not_searchable()
            .controls(vec![Control::heading("Active rules")]);
        if st.config.rules.is_empty() {
            rules_card = rules_card.controls(vec![Control::label("No rules configured yet.")]);
        }
        model = model.card(rules_card);
        for (i, rule) in st.config.rules.iter().enumerate() {
            model = model.card(
                Card::new(
                    format!("rule.{i}"),
                    rule.process_name.clone(),
                    format!(
                        "{}  |  {}",
                        rule.mask_type,
                        summarize_mask(&rule.cores, topo)
                    ),
                )
                .not_searchable()
                .actions(vec![
                    Control::button(format!("edit.{i}"), "Edit", BtnStyle::Action),
                    Control::button(format!("remove.{i}"), "Remove", BtnStyle::Disable),
                ]),
            );
        }
        model
    }

    fn refresh(&self, _host: &dyn Host) {
        self.refresh_service_badge();
    }

    fn handle(&self, host: &dyn Host, event: &Event) {
        let control = event.control.as_str();
        match &event.kind {
            EventKind::Text(s) | EventKind::Submit(s) if control == "process" => {
                self.st.lock().unwrap().process_name = s.clone();
            }
            EventKind::Check(b) => {
                let mut st = self.st.lock().unwrap();
                if control == "type.cpuset" {
                    if *b {
                        st.affinity = false;
                    }
                } else if control == "type.affinity" {
                    if *b && self.topo.supports_affinity {
                        st.affinity = true;
                    }
                } else if let Some(idx) = control
                    .strip_prefix("core.")
                    .and_then(|s| s.parse::<usize>().ok())
                {
                    if idx < st.core_checked.len() && self.topo.shown[idx] {
                        st.core_checked[idx] = *b;
                    }
                }
            }
            EventKind::Click => {
                xos_sys::ops::reset();
                let _op = app_state::operation();
                match control {
                    "service.enable" => self.service_enable(host),
                    "service.disable" => self.service_disable(host),
                    "browse" => self.browse(host),
                    "preset.save" => self.save_preset(host),
                    "preset.all" => self.apply_preset("Select All", None),
                    "preset.clear" => self.apply_preset("Clear", None),
                    "rule.add" => self.add_rule(host),
                    "rule.cancel" => {
                        let mut st = self.st.lock().unwrap();
                        self.cancel_edit(&mut st);
                    }
                    "rule.apply" => self.apply_now(host),
                    "export" => self.export_config(host),
                    "import" => self.import_config(host),
                    other => {
                        if let Some(i) = other
                            .strip_prefix("tpreset.")
                            .and_then(|s| s.parse::<usize>().ok())
                        {
                            if let Some((name, mask)) = self.topo.presets.get(i) {
                                self.apply_preset(name, Some(mask));
                            }
                        } else if let Some(i) = other
                            .strip_prefix("upreset.")
                            .and_then(|s| s.parse::<usize>().ok())
                        {
                            let preset =
                                self.st.lock().unwrap().config.user_presets.get(i).cloned();
                            if let Some(p) = preset {
                                self.apply_preset(&p.name, Some(&p.cores));
                            }
                        } else if let Some(i) = other
                            .strip_prefix("udel.")
                            .and_then(|s| s.parse::<usize>().ok())
                        {
                            self.delete_user_preset(host, i);
                        } else if let Some(i) = other
                            .strip_prefix("edit.")
                            .and_then(|s| s.parse::<usize>().ok())
                        {
                            self.edit_rule(i);
                        } else if let Some(i) = other
                            .strip_prefix("remove.")
                            .and_then(|s| s.parse::<usize>().ok())
                        {
                            self.remove_rule(host, i);
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

fn group_owner(topo: &Topo, idx: usize) -> Option<&str> {
    topo.groups
        .iter()
        .find(|(_, indices)| indices.contains(&idx))
        .map(|(n, _)| n.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn topo(n: usize) -> Topo {
        let mut t = Topo {
            logical_count: n,
            available: vec![true; n],
            supports_affinity: true,
            presets: vec![("P-Cores".into(), (0..n).map(|i| i < n / 2).collect())],
            groups: vec![("Cores".into(), (0..n).collect())],
            labels: Vec::new(),
            shown: Vec::new(),
        };
        t.compute_shown();
        t
    }

    #[test]
    fn process_names() {
        assert_eq!(
            normalize_process_name("  \"C:\\Games\\Foo.EXE\" ").as_deref(),
            Some("Foo.EXE")
        );
        assert_eq!(
            normalize_process_name("discord").as_deref(),
            Some("discord.exe")
        );
        assert_eq!(
            normalize_process_name("a/b/c.exe").as_deref(),
            Some("c.exe")
        );
        assert_eq!(normalize_process_name("   "), None);
        assert_eq!(normalize_process_name("bad|name"), None);
        assert_eq!(normalize_process_name("dir\\"), None);
    }

    #[test]
    fn core_masks() {
        let mut t = topo(4);
        t.available[3] = false;
        assert_eq!(
            normalize_core_mask(&[true, true, true, true, true], false, &t),
            vec![true, true, true, false]
        );
        let big = topo(70);
        let src = vec![true; 70];
        let m = normalize_core_mask(&src, true, &big);
        assert_eq!(m.iter().filter(|c| **c).count(), 64);
        assert_eq!(
            normalize_core_mask(&src, false, &big)
                .iter()
                .filter(|c| **c)
                .count(),
            70
        );
    }

    #[test]
    fn summaries() {
        let t = topo(4);
        assert_eq!(summarize_mask(&[true, true, false, false], &t), "P-Cores");
        assert_eq!(summarize_mask(&[true, true, true, true], &t), "All Cores");
        assert_eq!(summarize_mask(&[false; 4], &t), "None");
        assert_eq!(
            summarize_mask(&[true, false, true, false], &t),
            "2/4 cores [0,2]"
        );
    }

    #[test]
    fn service_labels() {
        assert_eq!(service_label(1, true, true), "Enabled");
        assert_eq!(service_label(0, false, true), "Disabled");
        assert_eq!(service_label(-1, false, true), "Disabled");
        assert_eq!(service_label(-1, false, false), "N/A");
        assert_eq!(service_label(1, false, true), "Partial");
        assert_eq!(service_label(-1, true, true), "Partial");
    }

    #[test]
    fn exe_names() {
        assert_eq!(process_display_name("chrome.exe"), "chrome.exe");
        assert_eq!(process_display_name("Idle"), "Idle.exe");
    }

    #[test]
    fn loaded_normalization() {
        let t = topo(4);
        let mut cfg = CpuRulesConfig {
            rules: vec![
                CpuRule {
                    cores: vec![true, false],
                    mask_type: "cpuset".into(),
                    process_name: "a".into(),
                },
                CpuRule {
                    cores: vec![false; 4],
                    mask_type: "CPUSet".into(),
                    process_name: "b.exe".into(),
                },
                CpuRule {
                    cores: vec![false, true],
                    mask_type: "CPUSet".into(),
                    process_name: "A.exe".into(),
                },
                CpuRule {
                    cores: vec![true],
                    mask_type: "bogus".into(),
                    process_name: "c.exe".into(),
                },
            ],
            user_presets: vec![UserPreset {
                cores: vec![true],
                name: " x ".into(),
            }],
        };
        assert!(normalize_loaded(&mut cfg, &t));
        assert_eq!(cfg.rules.len(), 1);
        assert_eq!(cfg.rules[0].process_name, "A.exe");
        assert_eq!(cfg.rules[0].cores, vec![false, true, false, false]);
        assert_eq!(cfg.user_presets[0].name, "x");
        assert!(!normalize_loaded(&mut cfg, &t));
    }

    #[test]
    fn affinity_converted_when_unsupported() {
        let mut t = topo(4);
        t.supports_affinity = false;
        let r = CpuRule {
            cores: vec![true; 4],
            mask_type: "Affinity".into(),
            process_name: "z.exe".into(),
        };
        assert_eq!(normalize_rule(&r, &t).unwrap().mask_type, "CPUSet");
    }

    #[test]
    fn chunking() {
        let controls: Vec<Control> = (0..13).map(|i| Control::label(i.to_string())).collect();
        let card = push_chunked(Card::new("c", "", ""), controls, 6);
        assert_eq!(card.rows.len(), 3);
        assert_eq!(card.rows[2].controls.len(), 1);
    }
}

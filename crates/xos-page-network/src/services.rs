use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::Instant;

use xos_core::app_state;
use xos_core::host::{Buttons, Host, Icon, Page};
use xos_core::log;
use xos_core::ui::*;
use xos_helpers::service_defaults_table;
use xos_sys::ops;
use xos_winupdate::service_guard;

use crate::services_data::{ServiceEntry, TaskEntry, GROUPS, TASK_GROUPS};

const COMBO_VALUES: [i32; 3] = [2, 3, 4];
const COMBO_LABELS: [&str; 3] = ["Automatic", "Manual", "Disabled"];

pub const PLAYBOOK_DISABLED_SERVICES: [&str; 49] = [
    "dmwappushservice",
    "diagnosticshub.standardcollector.service",
    "RetailDemo",
    "MapsBroker",
    "CSC",
    "CscService",
    "Telemetry",
    "WdiSystemHost",
    "WdiServiceHost",
    "troubleshootingsvc",
    "diagsvc",
    "svsvc",
    "DiagTrack",
    "wercplsupport",
    "DPS",
    "GraphicsPerfSvc",
    "Ndu",
    "PcaSvc",
    "DusmSvc",
    "DsSvc",
    "wisvc",
    "InventorySvc",
    "WSAIFabricSvc",
    "amdfendr",
    "amdfendrmgr",
    "McpManagementService",
    "Spooler",
    "PrintWorkflowUserSvc",
    "stisvc",
    "PrintNotify",
    "usbprint",
    "PrintScanBrokerService",
    "PrintDeviceConfigurationService",
    "TermService",
    "UmRdpService",
    "SessionEnv",
    "bttflt",
    "gencounter",
    "hyperkbd",
    "hypervideo",
    "vmgid",
    "vpci",
    "vid",
    "dam",
    "GpuEnergyDrv",
    "UCPD",
    "midisrv",
    "MicrosoftCopilotElevationService",
    "WslService",
];

pub fn playbook_disabled_services() -> Vec<String> {
    PLAYBOOK_DISABLED_SERVICES
        .iter()
        .map(|s| s.to_string())
        .collect()
}

pub fn managed_service_names() -> Vec<String> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for (_, services) in GROUPS {
        for service in *services {
            for name in service.names {
                if seen.insert(name.to_lowercase()) {
                    result.push(name.to_string());
                }
            }
        }
    }
    result
}

pub fn managed_task_paths() -> Vec<String> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for (_, tasks) in TASK_GROUPS {
        for task in *tasks {
            if seen.insert(task.path.to_lowercase()) {
                result.push(task.path.to_string());
            }
        }
    }
    result
}

pub fn sc_start_type_name(start_type: i32) -> &'static str {
    match start_type {
        0 => "boot",
        1 => "system",
        2 => "auto",
        3 => "demand",
        4 => "disabled",
        _ => panic!("start type out of range: {start_type}"),
    }
}

pub fn slot_value(svc: &ServiceEntry, idx: usize) -> i32 {
    if idx != 0 {
        return COMBO_VALUES[idx];
    }
    if svc.win_default >= 0 && svc.win_default <= 2 {
        svc.win_default
    } else {
        2
    }
}

pub fn slot_name(svc: &ServiceEntry, idx: usize) -> String {
    let val = slot_value(svc, idx);
    match val {
        0 => "Boot".to_string(),
        1 => "System".to_string(),
        _ => COMBO_LABELS[idx].to_string(),
    }
}

pub fn build_combo_label(base_label: &str, val: i32, svc: &ServiceEntry) -> String {
    let rec = if svc.recommended < 0 {
        svc.win_default
    } else {
        svc.recommended
    };
    let is_default = val == svc.win_default;
    let is_rec = val == rec;
    if is_default && is_rec {
        format!("{base_label} (Default & Recommended)")
    } else if is_default {
        format!("{base_label} (Default)")
    } else if is_rec {
        format!("{base_label} (Recommended)")
    } else {
        base_label.to_string()
    }
}

pub fn service_selection(svc: &ServiceEntry, starts: &[i32]) -> (usize, Option<String>) {
    let mut distinct: Vec<i32> = Vec::new();
    for &s in starts {
        if s >= 0 && !distinct.contains(&s) {
            distinct.push(s);
        }
    }
    let st = if distinct.len() == 1 { distinct[0] } else { -1 };
    let mut idx: Option<usize> = None;
    if st >= 0 {
        for i in 0..COMBO_VALUES.len() {
            if slot_value(svc, i) == st {
                idx = Some(i);
                break;
            }
        }
    }
    match idx {
        Some(i) => (i, None),
        None => {
            let label = if distinct.is_empty() {
                "N/A"
            } else if distinct.len() > 1 {
                "Partial"
            } else {
                match st {
                    0 => "Boot",
                    1 => "System",
                    2 => "Automatic",
                    _ => "Partial",
                }
            };
            (COMBO_VALUES.len(), Some(label.to_string()))
        }
    }
}

pub fn task_selection(state: i32) -> (usize, bool) {
    let idx = if state == 1 {
        0
    } else if state == 0 {
        1
    } else {
        2
    };
    (idx, state < 0)
}

struct SvcRow {
    entry: &'static ServiceEntry,
    header: Option<&'static str>,
    selected: usize,
    extra: Option<String>,
}

struct TaskRow {
    entry: &'static TaskEntry,
    header: Option<&'static str>,
    selected: usize,
    extra: bool,
}

struct State {
    built: bool,
    svc_rows: Vec<SvcRow>,
    task_rows: Vec<TaskRow>,
    task_states: HashMap<String, i32>,
    task_states_at: Option<Instant>,
}

pub struct ServicesPage {
    st: Mutex<State>,
}

impl Default for ServicesPage {
    fn default() -> Self {
        Self::new()
    }
}

fn service_card_id(entry: &ServiceEntry) -> String {
    format!("svc:{}", entry.names[0])
}

fn task_card_id(entry: &TaskEntry) -> String {
    format!("task:{}", entry.path)
}

impl ServicesPage {
    pub fn new() -> Self {
        Self {
            st: Mutex::new(State {
                built: false,
                svc_rows: Vec::new(),
                task_rows: Vec::new(),
                task_states: HashMap::new(),
                task_states_at: None,
            }),
        }
    }

    fn refresh_task_state_cache(&self) {
        {
            let st = self.st.lock().unwrap();
            if let Some(at) = st.task_states_at {
                if at.elapsed().as_millis() < 250 && !st.task_states.is_empty() {
                    return;
                }
            }
        }
        let paths = managed_task_paths();
        let states = xos_sys::get_task_states_batch(&paths);
        let mut map = HashMap::new();
        for (k, v) in states.iter() {
            map.insert(k.to_lowercase(), *v);
        }
        let mut st = self.st.lock().unwrap();
        st.task_states = map;
        st.task_states_at = Some(Instant::now());
    }

    fn build_page(&self) {
        let mut svc_rows = Vec::new();
        for (header, services) in GROUPS {
            let mut added_header = false;
            for svc in *services {
                if xos_sys::get_service_start_type(svc.names[0]) < 0 {
                    continue;
                }
                svc_rows.push(SvcRow {
                    entry: svc,
                    header: if added_header { None } else { Some(*header) },
                    selected: 0,
                    extra: None,
                });
                added_header = true;
            }
        }

        self.refresh_task_state_cache();
        let mut task_rows = Vec::new();
        {
            let st = self.st.lock().unwrap();
            for (header, tasks) in TASK_GROUPS {
                let mut added_header = false;
                for task in *tasks {
                    match st.task_states.get(&task.path.to_lowercase()) {
                        Some(&s) if s >= 0 => {}
                        _ => continue,
                    }
                    task_rows.push(TaskRow {
                        entry: task,
                        header: if added_header { None } else { Some(*header) },
                        selected: 0,
                        extra: false,
                    });
                    added_header = true;
                }
            }
        }
        let mut st = self.st.lock().unwrap();
        st.svc_rows = svc_rows;
        st.task_rows = task_rows;
        st.built = true;
    }

    pub fn refresh_states(&self) {
        if !self.st.lock().unwrap().built {
            return;
        }
        let entries: Vec<&'static ServiceEntry> = self
            .st
            .lock()
            .unwrap()
            .svc_rows
            .iter()
            .map(|r| r.entry)
            .collect();
        let selections: Vec<(usize, Option<String>)> = entries
            .iter()
            .map(|svc| {
                let starts: Vec<i32> = svc
                    .names
                    .iter()
                    .map(|n| xos_sys::get_service_start_type(n))
                    .collect();
                service_selection(svc, &starts)
            })
            .collect();
        {
            let mut st = self.st.lock().unwrap();
            for (row, (idx, extra)) in st.svc_rows.iter_mut().zip(selections) {
                row.selected = idx;
                row.extra = extra;
            }
        }

        self.refresh_task_state_cache();
        let mut st = self.st.lock().unwrap();
        let states = st.task_states.clone();
        for row in st.task_rows.iter_mut() {
            let state = states
                .get(&row.entry.path.to_lowercase())
                .copied()
                .unwrap_or(-1);
            let (idx, extra) = task_selection(state);
            row.selected = idx;
            row.extra = extra;
        }
    }

    fn change_service(&self, host: &dyn Host, control: &str, idx: i32) {
        let (svc, current) = {
            let st = self.st.lock().unwrap();
            match st
                .svc_rows
                .iter()
                .find(|r| service_card_id(r.entry) == control)
            {
                Some(r) => (r.entry, r.selected),
                None => return,
            }
        };
        ops::reset();
        if idx < 0 || idx as usize >= COMBO_VALUES.len() || idx as usize == current {
            return;
        }
        let idx = idx as usize;
        let slot = slot_name(svc, idx);
        log::action_clicked("Services", svc.display_name, &slot);

        let new_value = slot_value(svc, idx);
        let _op = app_state::operation();
        let ok = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut all = true;
            for name in svc.names {
                if !xos_sys::config_service_reg(name, new_value)
                    || xos_sys::get_service_start_type(name) != new_value
                {
                    all = false;
                }
            }
            all
        }))
        .unwrap_or_else(|e| {
            let text = e
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_default();
            log::exception(
                &format!(
                    "Services start type change failed: {}",
                    svc.names.join(", ")
                ),
                &text,
            );
            false
        });
        log::action_done(
            "Services",
            !ok,
            false,
            Some(&format!("{} start {}", svc.names.join(", "), new_value)),
        );
        ops::reset();
        self.refresh_states();
        if ok {
            app_state::require_reboot();
            host.set_status(&format!(
                "{} set to {}. Reboot required.",
                svc.display_name, slot
            ));
        } else {
            host.set_status(&format!("{} could not be changed.", svc.display_name));
            host.dialog(
                &format!(
                    "{} could not be changed. The actual startup type has been restored in the list.",
                    svc.display_name
                ),
                "XOS Toolkit",
                Buttons::Ok,
                Icon::Warning,
            );
        }
    }

    fn change_task(&self, host: &dyn Host, control: &str, idx: i32) {
        let (task, current) = {
            let st = self.st.lock().unwrap();
            match st
                .task_rows
                .iter()
                .find(|r| task_card_id(r.entry) == control)
            {
                Some(r) => (r.entry, r.selected),
                None => return,
            }
        };
        ops::reset();
        if idx < 0 || idx as usize == current {
            return;
        }
        let enable = idx == 0;
        log::action_clicked(
            "Services",
            task.display_name,
            if enable { "Enable" } else { "Disable" },
        );
        let _op = app_state::operation();
        let ok = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if enable {
                xos_sys::enable_task(task.path)
            } else {
                xos_sys::disable_task(task.path)
            }
        }))
        .unwrap_or_else(|e| {
            let text = e
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_default();
            log::exception(
                &format!("Services task state change failed: {}", task.path),
                &text,
            );
            false
        });
        log::action_done("Services", !ok, false, Some(task.path));
        ops::reset();
        self.st.lock().unwrap().task_states_at = None;
        self.refresh_states();
        if ok {
            host.set_status(&format!(
                "{} {}.",
                task.display_name,
                if enable { "enabled" } else { "disabled" }
            ));
        } else {
            host.set_status(&format!("{} could not be changed.", task.display_name));
            host.dialog(
                &format!(
                    "{} could not be changed. The actual state has been restored in the list.",
                    task.display_name
                ),
                "XOS Toolkit",
                Buttons::Ok,
                Icon::Warning,
            );
        }
    }
}

fn header_card(index: usize, header: &str) -> Card {
    Card::new(format!("hdr{index}"), "", "")
        .not_searchable()
        .controls(vec![Control::heading(header.to_uppercase())])
}

impl Page for ServicesPage {
    fn id(&self) -> &'static str {
        "Services"
    }

    fn label(&self) -> &'static str {
        "Services"
    }

    fn model(&self) -> PageModel {
        let st = self.st.lock().unwrap();
        let mut model = PageModel::new(
            "Services",
            "Service Configurator",
            "Manage startup types for services disabled by XOS. Disable applies XOS defaults. Restore reverts to the Windows default. Changes take effect on next reboot.",
        )
        .single_column()
        .max_width(1080.0);
        let mut header_index = 0;
        for row in &st.svc_rows {
            if let Some(h) = row.header {
                model = model.card(header_card(header_index, h));
                header_index += 1;
            }
            let svc = row.entry;
            let mut options: Vec<String> = (0..COMBO_LABELS.len())
                .map(|i| build_combo_label(&slot_name(svc, i), slot_value(svc, i), svc))
                .collect();
            if let Some(extra) = &row.extra {
                options.push(extra.clone());
            }
            let name_hint = if svc.names.len() == 1 {
                format!("({})", svc.names[0])
            } else {
                format!("({})", svc.names.join(", "))
            };
            model = model.card(
                Card::new(
                    service_card_id(svc),
                    format!("{} {}", svc.display_name, name_hint),
                    svc.description,
                )
                .controls(vec![Control::combo(
                    service_card_id(svc),
                    options,
                    row.selected as i32,
                )
                .width(225.0)]),
            );
        }
        for row in &st.task_rows {
            if let Some(h) = row.header {
                model = model.card(header_card(header_index, h));
                header_index += 1;
            }
            let task = row.entry;
            let mut options = vec![
                "Enabled (Default)".to_string(),
                "Disabled (Recommended)".to_string(),
            ];
            if row.extra {
                options.push("N/A".to_string());
            }
            model = model.card(
                Card::new(task_card_id(task), task.display_name, task.description).controls(vec![
                    Control::combo(task_card_id(task), options, row.selected as i32).width(225.0),
                ]),
            );
        }
        model
    }

    fn refresh(&self, _host: &dyn Host) {
        if !self.st.lock().unwrap().built {
            self.build_page();
        }
        self.refresh_states();
    }

    fn handle(&self, host: &dyn Host, event: &Event) {
        if let EventKind::Select(idx) = event.kind {
            if event.control.starts_with("svc:") {
                self.change_service(host, &event.control, idx);
            } else if event.control.starts_with("task:") {
                self.change_task(host, &event.control, idx);
            }
        }
    }
}

fn emit(log: Option<&dyn Fn(&str)>, message: &str) {
    if let Some(f) = log {
        f(message);
    }
}

pub fn restore_windows_default_service_start_types(log: Option<&dyn Fn(&str)>) -> bool {
    if !service_guard::remove_owned() {
        emit(
            log,
            "  Windows Update service protection could not be removed; service defaults were not applied.",
        );
        return false;
    }
    let mut ok = true;
    let mut seen: HashSet<String> = HashSet::new();
    let build = xos_sys::get_windows_build_number();

    let mut from_table = 0;
    let mut defender_held = 0;
    for (key, value) in service_defaults_table::get_managed_defaults(build) {
        if !seen.insert(key.to_lowercase()) {
            continue;
        }
        if !xos_sys::service_exists(&key) {
            continue;
        }

        if service_defaults_table::is_defender_managed(&key) {
            defender_held += 1;
            continue;
        }

        let expected = value;
        let delayed = service_defaults_table::is_delayed_auto_start(&key, build);
        let registry_ok = xos_sys::config_service_reg(&key, expected);
        let scm_ok = xos_sys::config_service_sc(
            &key,
            if delayed {
                "delayed-auto"
            } else {
                sc_start_type_name(expected)
            },
        );
        let actual = xos_sys::get_service_start_type(&key);
        let delayed_actual = if delayed {
            xos_sys::get_service_delayed_auto_start(&key)
        } else {
            0
        };
        let item_ok =
            registry_ok && scm_ok && actual == expected && (!delayed || delayed_actual == 1);
        ok &= item_ok;
        from_table += 1;
        emit(
            log,
            &format!(
                "  {key}: Start={actual}{}, expected {expected}{} {}",
                if delayed {
                    format!(" DelayedAutostart={delayed_actual}")
                } else {
                    String::new()
                },
                if delayed { " delayed" } else { "" },
                if item_ok { "OK" } else { "FAILED" }
            ),
        );
    }

    if defender_held > 0 {
        emit(
            log,
            &format!(
                "  {defender_held} Defender service(s) skipped here. They are restored by the Defender workflow, which is the only path that keeps the engine, the security centre and the policies consistent."
            ),
        );
    }

    let mut from_catalog = 0;
    for (_, services) in GROUPS {
        for service in *services {
            if service.win_default < 0 || service.win_default > 4 {
                continue;
            }
            for name in service.names {
                if !seen.insert(name.to_lowercase()) || !xos_sys::service_exists(name) {
                    continue;
                }
                let registry_ok = xos_sys::config_service_reg(name, service.win_default);
                let scm_ok =
                    xos_sys::config_service_sc(name, sc_start_type_name(service.win_default));
                let actual = xos_sys::get_service_start_type(name);
                let item_ok = registry_ok && scm_ok && actual == service.win_default;
                ok &= item_ok;
                from_catalog += 1;
                emit(
                    log,
                    &format!(
                        "  {name}: Start={actual}, expected {} {}",
                        service.win_default,
                        if item_ok { "OK" } else { "FAILED" }
                    ),
                );
            }
        }
    }

    emit(
        log,
        &format!(
            "  Service defaults applied: {from_table} from the captured baseline, {from_catalog} from the built-in catalog, build {build}"
        ),
    );

    ok
}

pub fn apply_xos_service_disables(log: Option<&dyn Fn(&str)>) -> bool {
    let build = xos_sys::get_windows_build_number();
    let mut ok = true;
    let mut disabled = 0;
    let mut held = 0;

    for name in playbook_disabled_services() {
        if !xos_sys::service_exists(&name) {
            continue;
        }

        if service_defaults_table::is_defender_managed(&name) {
            held += 1;
            continue;
        }

        let registry_ok = xos_sys::config_service_reg(&name, 4);
        let scm_ok = xos_sys::config_service_sc(&name, sc_start_type_name(4));
        let actual = xos_sys::get_service_start_type(&name);
        let item_ok = registry_ok && scm_ok && actual == 4;
        ok &= item_ok;
        disabled += 1;
        if !item_ok {
            emit(log, &format!("  {name}: Start={actual}, expected 4 FAILED"));
        }
    }

    emit(
        log,
        &format!(
            "  XOS service state applied: {disabled} service(s) set to disabled, {held} Defender service(s) left to the Defender workflow, build {build}"
        ),
    );

    ok
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find(name: &str) -> &'static ServiceEntry {
        for (_, services) in GROUPS {
            for s in *services {
                if s.names[0] == name {
                    return s;
                }
            }
        }
        panic!("missing {name}");
    }

    #[test]
    fn catalog_shape() {
        let total: usize = GROUPS.iter().map(|(_, s)| s.len()).sum();
        assert_eq!(total, 42);
        assert_eq!(GROUPS.len(), 3);
        assert_eq!(GROUPS[0].1.len(), 19);
        assert_eq!(GROUPS[1].1.len(), 19);
        assert_eq!(GROUPS[2].1.len(), 4);
        assert_eq!(managed_service_names().len(), 42);
        assert_eq!(managed_task_paths().len(), 3);
        assert_eq!(playbook_disabled_services().len(), 49);
    }

    #[test]
    fn slots_and_labels() {
        let diag = find("DiagTrack");
        assert_eq!(slot_name(diag, 0), "Automatic");
        assert_eq!(
            build_combo_label(&slot_name(diag, 0), slot_value(diag, 0), diag),
            "Automatic (Default)"
        );
        assert_eq!(
            build_combo_label("Disabled", 4, diag),
            "Disabled (Recommended)"
        );
        assert_eq!(build_combo_label("Manual", 3, diag), "Manual");
        let cdrom = find("cdrom");
        assert_eq!(slot_name(cdrom, 0), "System");
        assert_eq!(
            build_combo_label("System", 1, cdrom),
            "System (Default & Recommended)"
        );
        let vdrv = find("vdrvroot");
        assert_eq!(slot_name(vdrv, 0), "Boot");
        let tel = find("Telemetry");
        assert_eq!(slot_value(tel, 0), 2);
        assert_eq!(build_combo_label("Automatic", 2, tel), "Automatic");
    }

    #[test]
    fn selections() {
        let cdrom = find("cdrom");
        assert_eq!(service_selection(cdrom, &[1]), (0, None));
        assert_eq!(
            service_selection(cdrom, &[2]),
            (3, Some("Automatic".to_string()))
        );
        assert_eq!(
            service_selection(cdrom, &[-1]),
            (3, Some("N/A".to_string()))
        );
        assert_eq!(
            service_selection(cdrom, &[1, 3]),
            (3, Some("Partial".to_string()))
        );
        let diag = find("DiagTrack");
        assert_eq!(service_selection(diag, &[4, 4]), (2, None));
        assert_eq!(service_selection(diag, &[3]), (1, None));
        assert_eq!(task_selection(1), (0, false));
        assert_eq!(task_selection(0), (1, false));
        assert_eq!(task_selection(-1), (2, true));
    }

    #[test]
    fn sc_names() {
        assert_eq!(sc_start_type_name(0), "boot");
        assert_eq!(sc_start_type_name(4), "disabled");
    }

    #[test]
    fn model_before_build_is_empty() {
        let page = ServicesPage::new();
        let model = page.model();
        assert_eq!(model.id, "Services");
        assert!(model.cards.is_empty());
        assert!(!model.two_column);
    }
}

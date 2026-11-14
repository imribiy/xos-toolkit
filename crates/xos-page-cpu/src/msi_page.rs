use std::sync::Mutex;

use xos_core::app_state;
use xos_core::host::{Buttons, DialogResult, Host, Icon, Page};
use xos_core::log;
use xos_core::ui::*;

use crate::msi_manager::{self, MsiApplyResult, MsiDevice};

const PRIORITIES: [&str; 4] = ["Undefined", "Low", "Normal", "High"];

struct State {
    devices: Vec<MsiDevice>,
    loading: bool,
    loaded_once: bool,
    query: String,
    empty_text: String,
    empty_visible: bool,
}

pub struct MsiModePage {
    st: Mutex<State>,
}

impl Default for MsiModePage {
    fn default() -> Self {
        Self::new()
    }
}

pub fn filtered_indices(devices: &[MsiDevice], query: &str) -> Vec<usize> {
    let query = query.trim().to_lowercase();
    devices
        .iter()
        .enumerate()
        .filter(|(_, d)| {
            query.is_empty()
                || d.name.to_lowercase().contains(&query)
                || d.instance_id.to_lowercase().contains(&query)
                || d.supported_modes.to_lowercase().contains(&query)
        })
        .map(|(i, _)| i)
        .collect()
}

pub fn count_text(visible: usize, changed: usize) -> String {
    let label = if visible == 1 { "device" } else { "devices" };
    if changed > 0 {
        format!("{visible} {label} / {changed} changed")
    } else {
        format!("{visible} {label}")
    }
}

pub fn build_result_message(verb: &str, result: &MsiApplyResult) -> String {
    let mut message = format!("{verb}: {}\nFailed: {}", result.applied, result.failed);
    if !result.errors.is_empty() {
        message.push_str("\n\n");
        message.push_str(
            &result
                .errors
                .iter()
                .take(5)
                .cloned()
                .collect::<Vec<_>>()
                .join("\n"),
        );
    }
    if result.errors.len() > 5 {
        message.push_str(&format!("\n...and {} more.", result.errors.len() - 5));
    }
    if result.applied > 0 {
        message.push_str("\n\nReboot Windows to apply the changes.");
    }
    message
}

fn log_result(result: &MsiApplyResult) {
    let mut detail = format!("done {}, failed {}", result.applied, result.failed);
    if !result.errors.is_empty() {
        detail.push_str(": ");
        detail.push_str(
            &result
                .errors
                .iter()
                .take(5)
                .cloned()
                .collect::<Vec<_>>()
                .join("; "),
        );
    }
    log::action_done(
        "MsiMode",
        result.applied == 0 && result.failed > 0,
        result.failed > 0,
        Some(&detail),
    );
}

fn plural(n: usize) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

fn next_priority(current: &str) -> &'static str {
    let index = PRIORITIES.iter().position(|p| *p == current).unwrap_or(0);
    PRIORITIES[(index + 1) % PRIORITIES.len()]
}

impl MsiModePage {
    pub fn new() -> Self {
        Self {
            st: Mutex::new(State {
                devices: Vec::new(),
                loading: false,
                loaded_once: false,
                query: String::new(),
                empty_text: "No MSI-capable devices with allocated interrupts were found.".into(),
                empty_visible: false,
            }),
        }
    }

    fn load(&self, host: &dyn Host) {
        {
            let st = self.st.lock().unwrap();
            if st.loading {
                return;
            }
            if st.loaded_once && st.devices.iter().any(|d| d.is_dirty()) {
                drop(st);
                let discard = host.dialog(
                    "Discard unapplied MSI Mode changes and refresh the device list?",
                    "MSI Mode",
                    Buttons::YesNo,
                    Icon::Question,
                );
                if discard != DialogResult::Yes {
                    return;
                }
            }
        }
        {
            let mut st = self.st.lock().unwrap();
            if st.loading {
                return;
            }
            st.loading = true;
        }
        host.publish(self.model());
        host.set_status("Reading device interrupt information...");
        match msi_manager::read_devices() {
            Ok(devices) => {
                let count = devices.len();
                {
                    let mut st = self.st.lock().unwrap();
                    st.devices = devices;
                    st.loaded_once = true;
                    st.empty_text =
                        "No MSI-capable devices with allocated interrupts were found.".into();
                    st.empty_visible = count == 0;
                }
                host.set_status(&format!("Loaded {count} MSI-capable device entries."));
            }
            Err(ex) => {
                log::exception("MSI Mode device scan failed", &ex.to_string());
                {
                    let mut st = self.st.lock().unwrap();
                    st.empty_text = "Device interrupt information could not be read.".into();
                    st.empty_visible = true;
                    st.loading = false;
                }
                host.error(
                    &format!("MSI Mode could not enumerate device interrupts.\n\n{ex}"),
                    "MSI Mode",
                );
                host.set_status("MSI Mode device scan failed.");
            }
        }
        self.st.lock().unwrap().loading = false;
    }

    fn apply(&self, host: &dyn Host) {
        xos_sys::ops::reset();
        let changed: Vec<MsiDevice> = {
            let st = self.st.lock().unwrap();
            st.devices
                .iter()
                .filter(|d| d.is_dirty())
                .cloned()
                .collect()
        };
        if changed.is_empty() {
            return;
        }
        if let Some(validation) = changed.iter().find_map(msi_manager::validate) {
            host.warn(&validation, "MSI Mode");
            return;
        }
        let n = changed.len();
        if host.dialog(
            &format!(
                "Apply interrupt settings to {n} device{}?\n\nThe original values will be saved for Restore Selected. A reboot is required.",
                plural(n)
            ),
            "MSI Mode",
            Buttons::YesNo,
            Icon::Warning,
        ) != DialogResult::Yes
        {
            return;
        }

        let _op = app_state::operation();
        self.set_loading(host, true, Some("Applying MSI Mode changes..."));
        let result = msi_manager::apply(&changed);
        {
            let mut st = self.st.lock().unwrap();
            for device in st.devices.iter_mut() {
                if device.is_dirty()
                    && result
                        .applied_instance_ids
                        .iter()
                        .any(|id| id.eq_ignore_ascii_case(&device.instance_id))
                {
                    device.mark_clean();
                }
            }
        }
        self.set_loading(host, false, None);

        if result.applied > 0 {
            app_state::require_reboot();
        }
        log_result(&result);
        let message = build_result_message("Applied", &result);
        host.dialog(
            &message,
            "MSI Mode",
            Buttons::Ok,
            if result.failed == 0 {
                Icon::Information
            } else {
                Icon::Warning
            },
        );
        host.set_status(if result.failed == 0 {
            "MSI Mode changes applied. Reboot required."
        } else {
            "Some MSI Mode changes failed."
        });
        if result.failed == 0 {
            self.load(host);
        }
    }

    fn restore(&self, host: &dyn Host) {
        xos_sys::ops::reset();
        let (any_dirty, selected): (bool, Vec<MsiDevice>) = {
            let st = self.st.lock().unwrap();
            (
                st.devices.iter().any(|d| d.is_dirty()),
                st.devices
                    .iter()
                    .filter(|d| d.is_selected_for_restore)
                    .filter(|d| d.has_backup)
                    .cloned()
                    .collect(),
            )
        };
        if any_dirty {
            host.info(
                "Apply or discard the pending changes before restoring original settings.",
                "MSI Mode",
            );
            return;
        }
        if selected.is_empty() {
            host.info(
                "None of the selected devices have saved original settings to restore.",
                "MSI Mode",
            );
            return;
        }
        let n = selected.len();
        if host.dialog(
            &format!(
                "Restore the original interrupt settings for {n} selected device{}?\n\nA reboot is required.",
                plural(n)
            ),
            "MSI Mode",
            Buttons::YesNo,
            Icon::Warning,
        ) != DialogResult::Yes
        {
            return;
        }

        let _op = app_state::operation();
        self.set_loading(host, true, Some("Restoring original interrupt settings..."));
        let result = msi_manager::restore(&selected);
        self.set_loading(host, false, None);

        if result.applied > 0 {
            app_state::require_reboot();
        }
        log_result(&result);
        let message = build_result_message("Restored", &result);
        host.dialog(
            &message,
            "MSI Mode",
            Buttons::Ok,
            if result.failed == 0 {
                Icon::Information
            } else {
                Icon::Warning
            },
        );
        host.set_status(if result.failed == 0 {
            "Original interrupt settings restored. Reboot required."
        } else {
            "Some interrupt settings could not be restored."
        });
        self.load(host);
    }

    fn set_loading(&self, host: &dyn Host, loading: bool, status: Option<&str>) {
        self.st.lock().unwrap().loading = loading;
        host.publish(self.model());
        if let Some(s) = status {
            if !s.is_empty() {
                host.set_status(s);
            }
        }
    }
}

impl Page for MsiModePage {
    fn id(&self) -> &'static str {
        "MsiMode"
    }

    fn label(&self) -> &'static str {
        "MSI Mode"
    }

    fn model(&self) -> PageModel {
        let st = self.st.lock().unwrap();
        let visible = filtered_indices(&st.devices, &st.query);
        let changed = st.devices.iter().filter(|d| d.is_dirty()).count();
        let can_restore = st
            .devices
            .iter()
            .any(|d| d.is_selected_for_restore && d.has_backup);

        let rows: Vec<TableRow> = visible
            .iter()
            .map(|&i| {
                let d = &st.devices[i];
                let mut row = TableRow::new(
                    i.to_string(),
                    vec![
                        d.name.clone(),
                        d.irq.clone(),
                        if d.is_msi_enabled {
                            "On".into()
                        } else {
                            "Off".into()
                        },
                        d.message_limit_text.clone(),
                        d.max_message_limit_text(),
                        d.supported_modes.clone(),
                    ],
                )
                .checked(d.is_selected_for_restore)
                .tooltip(format!("{}\nIRQ: {}", d.instance_id, d.irq_details))
                .button(RowButton {
                    id: "msi".into(),
                    text: if d.is_msi_enabled {
                        "MSI: On".into()
                    } else {
                        "MSI: Off".into()
                    },
                    style: if d.is_msi_enabled {
                        BtnStyle::Enable
                    } else {
                        BtnStyle::Action
                    },
                    enabled: d.msi_capable,
                })
                .button(RowButton {
                    id: "limit".into(),
                    text: "Limit".into(),
                    style: BtnStyle::Action,
                    enabled: d.can_edit_limit(),
                })
                .button(RowButton::new(
                    "priority",
                    format!("Priority: {}", d.priority()),
                    BtnStyle::Action,
                ));
                if d.is_dirty() {
                    row = row.tone(Tone::Orange);
                }
                row
            })
            .collect();

        let mut devices_card = Card::new("devices", "", "").not_searchable();
        if st.empty_visible {
            devices_card = devices_card.controls(vec![Control::muted(st.empty_text.clone())]);
        }
        if !st.devices.is_empty() {
            devices_card = devices_card.controls(vec![Control::table(
                "list",
                Table::new(
                    vec![
                        Column::stretch("DEVICE"),
                        Column::new("IRQ", 60.0),
                        Column::new("MSI", 55.0),
                        Column::new("LIMIT", 60.0),
                        Column::new("MAX", 55.0),
                        Column::new("SUPPORTED MODES", 145.0),
                    ],
                    rows,
                )
                .checkable(true)
                .height(420.0),
            )]);
        }

        PageModel::new(
            "MsiMode",
            "MSI Mode",
            "Manage message-signaled interrupts and interrupt priority for installed devices",
        )
        .single_column()
        .max_width(1080.0)
        .overlay(if st.loading {
            Some("Reading interrupt resources...".to_string())
        } else {
            None
        })
        .card(
            Card::new(
                "audio",
                "Audio controller warning",
                "Enabling MSI mode on audio devices is likely to cause audio dropouts or crackling. Do not enable it for audio controllers unless you are specifically testing a known-compatible device.",
            )
            .not_searchable()
            .badge(Badge::new("Warning", Tone::Red)),
        )
        .card(
            Card::new(
                "info",
                "Device-level interrupt control",
                "Only devices that report MSI or MSI-X hardware support can be toggled. Leave the limit blank to use the driver default. Incorrect settings can prevent a device from starting, so change only hardware you recognize.",
            )
            .not_searchable()
            .badge(Badge::new("Caution", Tone::Orange)),
        )
        .card(Card::new("controls", "", "").not_searchable().controls(vec![
            Control::heading("Search"),
            Control::text_input("search", st.query.clone(), ""),
            Control::muted(if st.loaded_once {
                count_text(visible.len(), changed)
            } else {
                "Scanning...".to_string()
            }),
            Control::button("refresh", "Refresh", BtnStyle::Action).enabled(!st.loading),
        ]))
        .card(devices_card)
        .card(Card::new("footer", "", "").not_searchable().controls(vec![
            Control::muted("A reboot is required after applying or restoring interrupt settings."),
            Control::spacer(),
            Control::button("restore", "Restore Selected", BtnStyle::Action)
                .enabled(!st.loading && can_restore),
            Control::button("apply", "Apply Changes", BtnStyle::Enable)
                .enabled(!st.loading && changed > 0),
        ]))
    }

    fn refresh(&self, host: &dyn Host) {
        self.load(host);
    }

    fn handle(&self, host: &dyn Host, event: &Event) {
        match (event.control.as_str(), &event.kind) {
            ("search", EventKind::Text(s)) | ("search", EventKind::Submit(s)) => {
                self.st.lock().unwrap().query = s.clone();
            }
            ("refresh", EventKind::Click) => {
                xos_sys::ops::reset();
                self.load(host);
            }
            ("apply", EventKind::Click) => self.apply(host),
            ("restore", EventKind::Click) => self.restore(host),
            ("list", EventKind::RowCheck { row, checked }) => {
                let mut st = self.st.lock().unwrap();
                let visible = filtered_indices(&st.devices, &st.query);
                if let Some(&i) = visible.get(*row) {
                    if st.devices[i].has_backup {
                        st.devices[i].is_selected_for_restore = *checked;
                    }
                }
            }
            ("list", EventKind::RowButton { row, button }) => {
                let (index, name, current_limit) = {
                    let st = self.st.lock().unwrap();
                    let visible = filtered_indices(&st.devices, &st.query);
                    match visible.get(*row) {
                        Some(&i) => (
                            i,
                            st.devices[i].name.clone(),
                            st.devices[i].message_limit_text.clone(),
                        ),
                        None => return,
                    }
                };
                match button.as_str() {
                    "msi" => {
                        let mut st = self.st.lock().unwrap();
                        let d = &mut st.devices[index];
                        if d.msi_capable {
                            d.is_msi_enabled = !d.is_msi_enabled;
                        }
                    }
                    "priority" => {
                        let mut st = self.st.lock().unwrap();
                        let d = &mut st.devices[index];
                        let next = next_priority(d.priority());
                        d.set_priority(next);
                    }
                    "limit" => {
                        let prompt = format!(
                            "MSI message limit for {name} (blank uses the driver default; current: {}):",
                            if current_limit.trim().is_empty() { "default" } else { current_limit.trim() }
                        );
                        if let Some(text) = host.input_text(&prompt, "MSI Mode", 10, "Set") {
                            let mut st = self.st.lock().unwrap();
                            let d = &mut st.devices[index];
                            if d.can_edit_limit() {
                                d.message_limit_text = text;
                            }
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(name: &str, id: &str, modes: &str) -> MsiDevice {
        let mut d = MsiDevice::default();
        d.name = name.into();
        d.instance_id = id.into();
        d.supported_modes = modes.into();
        d.msi_capable = true;
        d
    }

    #[test]
    fn filtering() {
        let devices = vec![
            dev("NVIDIA GPU", r"PCI\VEN_10DE", "MSI, MSI-X"),
            dev("Realtek NIC", r"PCI\VEN_10EC", "Line-Based, MSI"),
        ];
        assert_eq!(filtered_indices(&devices, ""), vec![0, 1]);
        assert_eq!(filtered_indices(&devices, " nvidia "), vec![0]);
        assert_eq!(filtered_indices(&devices, "ven_10ec"), vec![1]);
        assert_eq!(filtered_indices(&devices, "msi-x"), vec![0]);
        assert!(filtered_indices(&devices, "zzz").is_empty());
    }

    #[test]
    fn counts_and_messages() {
        assert_eq!(count_text(1, 0), "1 device");
        assert_eq!(count_text(3, 2), "3 devices / 2 changed");
        let mut r = MsiApplyResult {
            applied: 1,
            failed: 6,
            ..Default::default()
        };
        for i in 0..6 {
            r.errors.push(format!("e{i}"));
        }
        assert_eq!(
            build_result_message("Applied", &r),
            "Applied: 1\nFailed: 6\n\ne0\ne1\ne2\ne3\ne4\n...and 1 more.\n\nReboot Windows to apply the changes."
        );
    }

    #[test]
    fn priority_cycle() {
        assert_eq!(next_priority("Undefined"), "Low");
        assert_eq!(next_priority("High"), "Undefined");
    }

    #[test]
    fn model_shape() {
        let page = MsiModePage::new();
        let model = page.model();
        assert_eq!(model.id, "MsiMode");
        assert!(model.overlay.is_none());
        assert_eq!(page.label(), "MSI Mode");
    }
}

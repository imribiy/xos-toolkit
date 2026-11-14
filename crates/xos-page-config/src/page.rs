use crate::toolkit_configuration::{
    self as tc, ConfigurationApplyResult, ConfigurationDifference, ConfigurationSelection,
    ToolkitConfigurationSnapshot,
};
use anyhow::Result;
use std::path::PathBuf;
use std::sync::Mutex;
use xos_core::host::{Buttons, DialogResult, FileFilter, Host, Icon, Page};
use xos_core::ui::*;
use xos_core::{app_state, log, session_log};
use xos_cpu::topology;
use xos_page_system::defender::{self, DefenderOptions};

const TITLE: &str = "Configuration Backup";

const CATEGORIES: [(&str, &str); 6] = [
    ("registry", "Toolkit settings"),
    ("services", "Service start states"),
    ("tasks", "Scheduled tasks"),
    ("features", "Windows features"),
    ("cpu", "CPU rules and presets"),
    ("apps", "Application inventory"),
];

struct State {
    backup: Option<ToolkitConfigurationSnapshot>,
    differences: Vec<ConfigurationDifference>,
    checks: [bool; 6],
    busy: bool,
    busy_text: String,
    backup_info: String,
    preview_count: String,
    preview_note: String,
}

pub struct ConfigurationPage {
    st: Mutex<State>,
}

impl Default for ConfigurationPage {
    fn default() -> Self {
        Self::new()
    }
}

fn selection_of(checks: &[bool; 6]) -> ConfigurationSelection {
    ConfigurationSelection {
        registry: checks[0],
        services: checks[1],
        tasks: checks[2],
        features: checks[3],
        cpu_rules: checks[4],
        applications: checks[5],
    }
}

fn has_selection(checks: &[bool; 6]) -> bool {
    checks.iter().any(|c| *c)
}

fn plural(count: usize, one: &str, many: &str) -> String {
    if count == 1 { one } else { many }.to_string()
}

fn desktop_dir() -> Option<PathBuf> {
    use windows::Win32::System::Com::CoTaskMemFree;
    use windows::Win32::UI::Shell::{FOLDERID_Desktop, SHGetKnownFolderPath, KF_FLAG_DEFAULT};
    unsafe {
        let pwstr = SHGetKnownFolderPath(&FOLDERID_Desktop, KF_FLAG_DEFAULT, None).ok()?;
        let text = pwstr.to_string().ok();
        CoTaskMemFree(Some(pwstr.as_ptr() as *const _));
        text.map(PathBuf::from)
    }
    .or_else(|| std::env::var_os("USERPROFILE").map(|p| PathBuf::from(p).join("Desktop")))
}

impl ConfigurationPage {
    pub fn new() -> Self {
        Self {
            st: Mutex::new(State {
                backup: None,
                differences: Vec::new(),
                checks: [true; 6],
                busy: false,
                busy_text: "Working...".to_string(),
                backup_info: String::new(),
                preview_count: String::new(),
                preview_note: String::new(),
            }),
        }
    }

    fn selection(&self) -> ConfigurationSelection {
        selection_of(&self.st.lock().unwrap().checks)
    }

    fn set_busy(&self, host: &dyn Host, busy: bool, status: Option<&str>) {
        {
            let mut st = self.st.lock().unwrap();
            st.busy = busy;
            if let Some(text) = status.filter(|s| !s.is_empty()) {
                st.busy_text = text.to_string();
            }
        }
        host.publish(self.model());
        if let Some(text) = status.filter(|s| !s.is_empty()) {
            host.set_status(text);
        }
    }

    fn applicable_count(&self) -> usize {
        self.st
            .lock()
            .unwrap()
            .differences
            .iter()
            .filter(|d| d.applicable)
            .count()
    }

    fn export(&self, host: &dyn Host) {
        let default_name = format!(
            "XOS-Toolkit-Configuration-{}.json",
            chrono::Local::now().format("%Y-%m-%d_%H-%M-%S")
        );
        let Some(path) = host.save_file(
            "Save As",
            &[FileFilter::new("XOS configuration", &["json"])],
            &default_name,
            desktop_dir(),
        ) else {
            return;
        };
        self.set_busy(host, true, Some("Capturing Toolkit configuration..."));
        let outcome = (|| -> Result<ToolkitConfigurationSnapshot> {
            let selection = self.selection();
            let snapshot = tc::capture(&selection)?;
            tc::save(&path, &snapshot)?;
            Ok(snapshot)
        })();
        match outcome {
            Ok(snapshot) => {
                let warnings = snapshot.warnings.len();
                log::action_done(
                    "Configuration",
                    false,
                    warnings > 0,
                    Some(&if warnings > 0 {
                        format!("saved, {warnings} unreadable setting(s) omitted")
                    } else {
                        "saved".to_string()
                    }),
                );
                if warnings > 0 {
                    host.warn(
                        &format!(
                            "The backup was saved, but {warnings} protected setting{} not readable and could not be included.\n\n{}{}",
                            plural(warnings, " was", "s were"),
                            snapshot
                                .warnings
                                .iter()
                                .take(8)
                                .cloned()
                                .collect::<Vec<_>>()
                                .join("\n"),
                            if warnings > 8 { "\n..." } else { "" }
                        ),
                        TITLE,
                    );
                    host.set_status(
                        "Configuration backup exported with unreadable settings omitted.",
                    );
                } else {
                    host.set_status("Configuration backup exported.");
                }
            }
            Err(ex) => {
                log::action_done("Configuration", true, false, Some(&ex.to_string()));
                host.error(
                    &format!("The configuration could not be exported.\n\n{ex}"),
                    TITLE,
                );
                host.set_status("Configuration export failed.");
            }
        }
        self.set_busy(host, false, None);
    }

    fn import(&self, host: &dyn Host) {
        let Some(path) = host.open_file(
            "Open",
            &[
                FileFilter::new("XOS configuration", &["json"]),
                FileFilter::new("JSON files", &["json"]),
            ],
            None,
        ) else {
            return;
        };
        self.set_busy(host, true, Some("Opening configuration backup..."));
        let outcome = (|| -> Result<()> {
            let backup = tc::load(&path)?;
            {
                let mut st = self.st.lock().unwrap();
                let cpu_info = if backup.logical_processors > 0 {
                    format!("  |  {} logical processors", backup.logical_processors)
                } else {
                    String::new()
                };
                let warning_info = if !backup.warnings.is_empty() {
                    format!(
                        "  |  {} capture warning{}",
                        backup.warnings.len(),
                        plural(backup.warnings.len(), "", "s")
                    )
                } else {
                    String::new()
                };
                st.backup_info = format!(
                    "Toolkit {}  |  Windows build {}{}{}  |  {}",
                    backup.toolkit_version.as_deref().unwrap_or(""),
                    backup.windows_build,
                    cpu_info,
                    warning_info,
                    backup.exported_utc.as_deref().unwrap_or("")
                );
                st.backup = Some(backup);
            }
            host.publish(self.model());
            self.build_preview(host)?;
            log::action_done(
                "Configuration",
                false,
                false,
                Some(&format!(
                    "backup loaded, {} applicable difference(s)",
                    self.applicable_count()
                )),
            );
            host.set_status("Configuration backup loaded. Review the preview before applying.");
            Ok(())
        })();
        if let Err(ex) = outcome {
            {
                let mut st = self.st.lock().unwrap();
                st.backup = None;
            }
            log::action_done("Configuration", true, false, Some(&ex.to_string()));
            host.error(&format!("The backup could not be opened.\n\n{ex}"), TITLE);
            host.set_status("Configuration import failed.");
        }
        self.set_busy(host, false, None);
    }

    fn refresh_preview(&self, host: &dyn Host) {
        if let Err(ex) = self.build_preview(host) {
            host.error(
                &format!("The import preview could not be refreshed.\n\n{ex}"),
                TITLE,
            );
            host.set_status("Configuration preview failed.");
        }
    }

    fn build_preview(&self, host: &dyn Host) -> Result<()> {
        let backup = match self.st.lock().unwrap().backup.clone() {
            Some(b) => b,
            None => return Ok(()),
        };
        self.set_busy(host, true, Some("Comparing current configuration..."));
        let outcome = (|| -> Result<()> {
            let selection = self.selection();
            let current = tc::capture(&selection)?;
            let differences = tc::compare(&backup, &current, &selection);
            let applicable = differences.iter().filter(|d| d.applicable).count();
            let skipped = differences.len() - applicable;
            let mut st = self.st.lock().unwrap();
            st.preview_count = if differences.is_empty() {
                "No differences".to_string()
            } else {
                format!("{applicable} changes, {skipped} skipped")
            };
            let capture_warning = if !backup.warnings.is_empty() {
                format!(
                    " {} unreadable source setting{} omitted from this backup.",
                    backup.warnings.len(),
                    plural(backup.warnings.len(), " was", "s were")
                )
            } else {
                String::new()
            };
            st.preview_note = format!(
                "{}{}",
                if skipped > 0 {
                    "Unsupported, review-only, and inventory-only entries will be skipped."
                } else {
                    "Only the selected categories will be restored."
                },
                capture_warning
            );
            st.differences = differences;
            Ok(())
        })();
        self.set_busy(host, false, None);
        outcome
    }

    fn apply(&self, host: &dyn Host) {
        let (backup, differences, pending_selection) = {
            let st = self.st.lock().unwrap();
            match &st.backup {
                Some(b) => (b.clone(), st.differences.clone(), selection_of(&st.checks)),
                None => return,
            }
        };
        let count = differences.iter().filter(|d| d.applicable).count();
        if count == 0 {
            return;
        }
        let defender_target = tc::get_defender_target(&backup, &pending_selection);
        let defender_difference = differences.iter().any(tc::is_defender_difference);
        let defender_operation_needed = defender_target.is_some()
            && defender_difference
            && tc::defender_needs_full_operation(defender_target.unwrap());
        let mut cpu_warning = String::new();
        if pending_selection.cpu_rules
            && backup.cpu_rules.is_some()
            && backup.logical_processors > 0
        {
            topology::initialize();
            if backup.logical_processors as usize != topology::logical_processor_count() {
                cpu_warning = format!(
                    "\n\nCPU rules were created for {} logical processors, but this machine has {}. Core selections may not line up.",
                    backup.logical_processors,
                    topology::logical_processor_count()
                );
            }
        }
        let defender_warning = if defender_operation_needed {
            format!(
                "\n\nWindows Defender will be fully {} before its captured service, policy, and task state is restored.",
                if defender_target.unwrap() { "enabled" } else { "disabled" }
            )
        } else {
            String::new()
        };
        if host.dialog(
            &format!(
                "Apply {count} configuration change{}?\n\nServices and Windows features may require a reboot.{cpu_warning}{defender_warning}",
                plural(count, "", "s")
            ),
            TITLE,
            Buttons::YesNo,
            Icon::Warning,
        ) != DialogResult::Yes
        {
            return;
        }

        xos_sys::ops::reset();
        self.set_busy(host, true, Some("Applying configuration..."));
        self.run_apply(host, &backup, defender_target, defender_operation_needed);
        xos_sys::ops::reset();
        self.set_busy(host, false, None);
    }

    fn run_apply(
        &self,
        host: &dyn Host,
        backup: &ToolkitConfigurationSnapshot,
        defender_target: Option<bool>,
        defender_operation_needed: bool,
    ) {
        let outcome = (|| -> Result<()> {
            let selection = self.selection();
            if defender_operation_needed {
                let target = defender_target.unwrap();
                self.set_busy(
                    host,
                    true,
                    Some(if target {
                        "Enabling Windows Defender before restoring configuration..."
                    } else {
                        "Disabling Windows Defender before restoring configuration..."
                    }),
                );
                let outcome = defender::set_enabled(
                    host,
                    target,
                    DefenderOptions {
                        show_result: false,
                        show_blocking_messages: true,
                        defer_reboot_status: true,
                    },
                );
                if !outcome.ok {
                    let block_reason = defender::check_blocked();
                    log::log(&format!(
                        "[Config] Defender prerequisite or workflow failed; configuration restore paused before other categories.{}",
                        match &block_reason {
                            None => String::new(),
                            Some(r) => format!(" Reason: {}", r.replace('\n', " ")),
                        }
                    ));
                    log::action_done(
                        "Configuration",
                        true,
                        false,
                        Some("paused before any category was applied: the Defender step did not complete"),
                    );
                    host.set_status(
                        "Configuration restore paused. Fix Defender protection, then click Apply again.",
                    );
                    host.warn(
                        "Configuration restore paused.\n\nNo other configuration categories were applied. Turn off the requested Defender protection in Windows Security, then click Apply again.",
                        TITLE,
                    );
                    return Ok(());
                }
            }

            let mut result: ConfigurationApplyResult = tc::apply(backup, &selection, false)?;
            if defender_operation_needed {
                result.applied += 1;
                result.reboot_required = true;
            }
            if result.reboot_required {
                app_state::require_reboot();
            }
            self.build_preview(host)?;
            let remaining = self.applicable_count();
            let pending_reboot_differences = result.reboot_required && remaining > 0;
            let remaining_label = if pending_reboot_differences {
                format!("Pending after reboot: {remaining}")
            } else {
                format!("Remaining: {remaining}")
            };
            let summary = format!(
                "Applied: {}\nSkipped: {}\nFailed: {}\n{}",
                result.applied, result.skipped, result.failed, remaining_label
            );
            let complete = result.failed == 0 && (remaining == 0 || pending_reboot_differences);

            log::log(&format!(
                "[Config] Applied={} Skipped={} Failed={} remaining={} pendingAfterReboot={} rebootRequired={} complete={}",
                result.applied,
                result.skipped,
                result.failed,
                remaining,
                pending_reboot_differences,
                result.reboot_required,
                complete
            ));
            if result.failed > 0 || !complete {
                let still: Vec<ConfigurationDifference> = self
                    .st
                    .lock()
                    .unwrap()
                    .differences
                    .iter()
                    .filter(|d| d.applicable)
                    .cloned()
                    .collect();
                for difference in still {
                    log::log(&format!(
                        "[Config] still different: {} / {} (current {}, backup {})",
                        difference.category, difference.item, difference.current, difference.backup
                    ));
                }
                session_log::write_digest();
            }
            log::action_done(
                "Configuration",
                !complete && result.applied == 0,
                !complete,
                Some(&format!(
                    "applied {}, skipped {}, failed {}, {}",
                    result.applied,
                    result.skipped,
                    result.failed,
                    if pending_reboot_differences {
                        format!("pending after reboot {remaining}")
                    } else {
                        format!("remaining {remaining}")
                    }
                )),
            );

            let reboot_note = if result.reboot_required {
                "\n\nA reboot is required to finalize these changes."
            } else {
                ""
            };
            host.dialog(
                &format!("{summary}{reboot_note}"),
                TITLE,
                Buttons::Ok,
                if complete {
                    Icon::Information
                } else {
                    Icon::Warning
                },
            );
            host.set_status(if complete {
                if result.reboot_required {
                    "Configuration restore completed. Please reboot to finalize."
                } else {
                    "Configuration restore completed."
                }
            } else {
                "Configuration restore incomplete."
            });
            Ok(())
        })();
        if let Err(ex) = outcome {
            log::action_done("Configuration", true, false, Some(&ex.to_string()));
            host.error(
                &format!("The configuration could not be restored.\n\n{ex}"),
                TITLE,
            );
            host.set_status("Configuration restore failed.");
        }
    }

    fn cancel(&self, host: &dyn Host) {
        {
            let mut st = self.st.lock().unwrap();
            st.backup = None;
            st.differences.clear();
        }
        host.set_status("Configuration import cancelled.");
    }
}

impl Page for ConfigurationPage {
    fn id(&self) -> &'static str {
        "Configuration"
    }

    fn label(&self) -> &'static str {
        "Configuration Backup"
    }

    fn model(&self) -> PageModel {
        let st = self.st.lock().unwrap();
        let busy = st.busy;
        let mut model = PageModel::new(
            "Configuration",
            "Configuration Backup",
            "Export Toolkit-managed settings to one versioned JSON file, or preview and restore a previous configuration.",
        )
        .single_column()
        .max_width(980.0)
        .overlay(if busy {
            Some(st.busy_text.clone())
        } else {
            None
        });

        let checks = |range: std::ops::Range<usize>| -> Vec<Control> {
            range
                .map(|i| {
                    Control::check(CATEGORIES[i].0, CATEGORIES[i].1, st.checks[i]).enabled(!busy)
                })
                .collect()
        };
        let categories = Card::new("categories", "Included categories", "")
            .controls(checks(0..3))
            .controls(checks(3..6))
            .controls(vec![Control::muted(
                "Application inventory is report-only. Hardware-instance settings such as MSI mode, GPU, network adapter, monitor, and PnP device paths are not included.",
            )])
            .actions(vec![
                Control::button("export", "Export Configuration", BtnStyle::Action)
                    .enabled(!busy && has_selection(&st.checks)),
                Control::button("import", "Open Backup", BtnStyle::Enable).enabled(!busy),
            ]);
        model = model.card(categories);

        let rows: Vec<TableRow> = st
            .differences
            .iter()
            .enumerate()
            .map(|(i, d)| {
                TableRow::new(
                    i.to_string(),
                    vec![
                        d.category.clone(),
                        d.item.clone(),
                        d.current.clone(),
                        d.backup.clone(),
                        d.action.clone(),
                    ],
                )
            })
            .collect();
        let table = Table::new(
            vec![
                Column::new("CATEGORY", 120.0),
                Column::new("ITEM", 300.0),
                Column::new("CURRENT", 140.0),
                Column::new("BACKUP", 140.0),
                Column::new("ACTION", 150.0),
            ],
            rows,
        )
        .height(240.0);
        let any_applicable = st.differences.iter().any(|d| d.applicable);
        let preview = Card::new("preview", "Import preview", st.backup_info.clone())
            .badge_opt(if st.preview_count.is_empty() {
                None
            } else {
                Some(Badge::new(st.preview_count.clone(), Tone::Neutral))
            })
            .visible(st.backup.is_some())
            .controls(vec![Control::table("differences", table)])
            .controls(vec![Control::muted(st.preview_note.clone())])
            .actions(vec![
                Control::button("cancel", "Cancel", BtnStyle::Action).enabled(!busy),
                Control::button("apply", "Apply Selected Categories", BtnStyle::Enable)
                    .enabled(!busy && any_applicable),
            ]);
        model.card(preview)
    }

    fn refresh(&self, host: &dyn Host) {
        let ready = {
            let st = self.st.lock().unwrap();
            st.backup.is_some() && !st.busy
        };
        if ready {
            self.refresh_preview(host);
        }
    }

    fn handle(&self, host: &dyn Host, event: &Event) {
        match &event.kind {
            EventKind::Click => match event.control.as_str() {
                "export" => self.export(host),
                "import" => self.import(host),
                "apply" => self.apply(host),
                "cancel" => self.cancel(host),
                _ => {}
            },
            EventKind::Check(checked) => {
                let Some(index) = CATEGORIES.iter().position(|c| c.0 == event.control) else {
                    return;
                };
                let reload = {
                    let mut st = self.st.lock().unwrap();
                    st.checks[index] = *checked;
                    st.backup.is_some() && !st.busy
                };
                if reload {
                    self.refresh_preview(host);
                }
            }
            _ => {}
        }
    }
}

use crate::catalog::{contains_ignore_case, find_app_by_name, is_catalog_package_id, CATALOG};
use crate::choco_bootstrap::is_choco_bootstrap_running;
use crate::edge::{
    check_edge, get_edge_game_assist_presence, is_edge_webview_installed, run_edge_removal,
    EdgeRemovalOutcome,
};
use crate::onedrive::{check_onedrive, run_onedrive_removal};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use xos_core::app_state;
use xos_core::host::{Buttons, Host, Icon, Page};
use xos_core::log;
use xos_core::ui::*;
use xos_sys::CiMap;
use xos_winupdate::webview2;

struct State {
    installed: CiMap<bool>,
    selected: Vec<String>,
    search: String,
    loading: bool,
    choco_status: String,
    show_install: bool,
    show_uninstall: bool,
    list_visible: bool,
    onedrive_found: bool,
    edge_found: bool,
}

pub struct AppsPage {
    st: Mutex<State>,
}

impl Default for AppsPage {
    fn default() -> Self {
        Self::new()
    }
}

fn matching_apps(search: &str, category: usize) -> Vec<crate::catalog::CatalogApp> {
    CATALOG[category]
        .apps
        .iter()
        .filter(|a| contains_ignore_case(a.name, search))
        .copied()
        .collect()
}

impl AppsPage {
    pub fn new() -> Self {
        Self {
            st: Mutex::new(State {
                installed: CiMap::new(),
                selected: Vec::new(),
                search: String::new(),
                loading: false,
                choco_status: "Checking...".into(),
                show_install: false,
                show_uninstall: false,
                list_visible: false,
                onedrive_found: false,
                edge_found: false,
            }),
        }
    }

    fn set_choco_status(&self, text: &str) {
        self.st.lock().unwrap().choco_status = text.to_string();
    }

    fn check_onedrive_state(&self, host: &dyn Host) {
        let found = check_onedrive();
        self.st.lock().unwrap().onedrive_found = found;
        host.publish(self.model());
    }

    fn check_edge_state(&self, host: &dyn Host) {
        let found = check_edge();
        self.st.lock().unwrap().edge_found = found;
        host.publish(self.model());
    }

    fn init(&self, host: &dyn Host) {
        {
            let mut st = self.st.lock().unwrap();
            if st.loading {
                return;
            }
            st.loading = true;
        }
        host.publish(self.model());
        let mut waited_for_choco = false;
        let mut choco_still_installing = false;
        self.init_body(host, &mut waited_for_choco, &mut choco_still_installing);
        self.st.lock().unwrap().loading = false;
        if choco_still_installing {
            host.set_status("Chocolatey is still installing. Return to this page to check again.");
        } else if waited_for_choco {
            host.set_status("Ready");
        }
    }

    fn init_body(&self, host: &dyn Host, waited: &mut bool, still_installing: &mut bool) {
        if !xos_sys::is_choco_installed() && is_choco_bootstrap_running() {
            {
                let mut st = self.st.lock().unwrap();
                st.choco_status = "Waiting for Chocolatey to finish installing...".into();
                st.show_install = false;
            }
            host.set_status("Setting up Chocolatey, the app list appears when it is ready...");
            *waited = true;
            host.publish(self.model());
            let started = Instant::now();
            while is_choco_bootstrap_running() && started.elapsed() < Duration::from_millis(120000)
            {
                std::thread::sleep(Duration::from_millis(250));
            }
            if is_choco_bootstrap_running() {
                {
                    let mut st = self.st.lock().unwrap();
                    st.choco_status =
                        "Chocolatey installation is still running. Return to this page to check again."
                            .into();
                    st.show_uninstall = false;
                    st.list_visible = false;
                }
                *still_installing = true;
                host.publish(self.model());
                self.check_onedrive_state(host);
                self.check_edge_state(host);
                return;
            }
        }

        if !xos_sys::is_choco_installed() {
            {
                let mut st = self.st.lock().unwrap();
                st.choco_status = "Chocolatey is not installed.".into();
                st.show_install = true;
                st.show_uninstall = false;
                st.list_visible = false;
            }
            host.publish(self.model());
            self.check_onedrive_state(host);
            self.check_edge_state(host);
            return;
        }

        {
            let mut st = self.st.lock().unwrap();
            st.choco_status = "Chocolatey is installed. Loading packages...".into();
            st.show_install = false;
            st.show_uninstall = true;
            st.list_visible = true;
        }
        host.publish(self.model());

        match xos_sys::get_choco_installed_packages() {
            Ok(map) => {
                let mut st = self.st.lock().unwrap();
                st.choco_status = format!("Chocolatey ready: {} packages installed.", map.len());
                st.installed = map;
            }
            Err(_) => {
                self.set_choco_status("Chocolatey installed but failed to list packages.");
            }
        }
        host.publish(self.model());
        self.check_onedrive_state(host);
        self.check_edge_state(host);
    }

    fn reject_while_loading(&self, host: &dyn Host) -> bool {
        if !self.st.lock().unwrap().loading {
            return false;
        }
        host.set_status("Still setting up Chocolatey, try again in a moment.");
        true
    }

    fn reject_empty_selection(&self, host: &dyn Host) -> bool {
        if self.reject_while_loading(host) {
            return true;
        }
        if !self.st.lock().unwrap().selected.is_empty() {
            return false;
        }
        host.set_status("Select at least one app in the list first.");
        true
    }

    fn install_choco_click(&self, host: &dyn Host) {
        if !host.confirm(
            "Install Chocolatey package manager?",
            "XOS Toolkit",
            Icon::Question,
        ) {
            return;
        }
        host.set_status("Installing Chocolatey...");
        self.set_choco_status("Installing Chocolatey... Please wait.");
        host.publish(self.model());

        let ok = xos_sys::install_choco();
        log::action_done(
            "Apps",
            !ok,
            false,
            Some(if ok {
                "Chocolatey installed"
            } else {
                "Chocolatey installation failed"
            }),
        );
        if ok {
            {
                let mut st = self.st.lock().unwrap();
                st.choco_status = "Chocolatey installed. Refreshing...".into();
                st.show_install = false;
                st.loading = false;
            }
            host.publish(self.model());
            self.init(host);
        } else {
            self.set_choco_status("Failed to install Chocolatey.");
        }
        host.set_status("Ready");
    }

    fn uninstall_choco_click(&self, host: &dyn Host) {
        if !host.confirm(
            "Delete C:\\ProgramData\\chocolatey? This removes Chocolatey, its package records, and its command shims. Applications already installed may remain, but Chocolatey will no longer manage them.",
            "XOS Toolkit",
            Icon::Warning,
        ) {
            return;
        }
        self.set_choco_status("Removing Chocolatey...");
        host.set_status("Removing Chocolatey...");
        host.publish(self.model());

        xos_sys::remove_chocolatey();
        if xos_sys::is_choco_installed() {
            let message = "Chocolatey is still present after cleanup.";
            self.set_choco_status("Failed to remove Chocolatey.");
            log::log(&format!("[Apps] Chocolatey removal failed: {message}"));
            log::action_done("Apps", true, false, Some(message));
        } else {
            log::action_done("Apps", false, false, Some("Chocolatey removed"));
            self.st.lock().unwrap().loading = false;
            self.init(host);
        }
        host.set_status("Ready");
    }

    fn refresh_installed(&self, host: &dyn Host) {
        host.set_status("Refreshing package list...");
        match xos_sys::get_choco_installed_packages() {
            Ok(map) => self.st.lock().unwrap().installed = map,
            Err(e) => log::log(&format!("[Apps] Package refresh failed: {e}")),
        }
    }

    fn install_selected(&self, host: &dyn Host) {
        if self.reject_empty_selection(host) {
            return;
        }
        let to_install: Vec<crate::catalog::CatalogApp> = {
            let st = self.st.lock().unwrap();
            st.selected
                .iter()
                .filter_map(|n| find_app_by_name(n))
                .filter(|a| !st.installed.contains_key(a.id))
                .collect()
        };
        if to_install.is_empty() {
            host.info("All selected apps are already installed.", "Info");
            return;
        }

        let total = to_install.len();
        let mut done = 0usize;
        let mut processed = 0usize;
        let mut failed: Vec<String> = Vec::new();
        let sw = Instant::now();
        log::action("install batch", &format!("{total} app(s) requested"));
        log::op_detail(
            "App install batch started",
            Some(
                &to_install
                    .iter()
                    .map(|a| a.id)
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
        );

        for app in &to_install {
            processed += 1;
            host.set_status(&format!("Installing {}... ({processed}/{total})", app.name));
            log::op(&format!("install {} ({processed}/{total})", app.id));
            if !is_catalog_package_id(app.id) {
                failed.push(app.name.to_string());
                log::result(
                    false,
                    &format!("install {}", app.id),
                    "package id is not in the internal catalog",
                );
                continue;
            }
            let ok = xos_sys::choco_install(app.id);
            if ok {
                done += 1;
            } else {
                failed.push(app.name.to_string());
            }
            log::result(ok, &format!("install {}", app.id), "");
        }

        self.refresh_installed(host);
        host.publish(self.model());
        host.set_status("Ready");
        let elapsed = sw.elapsed().as_millis();

        log::result(
            failed.is_empty(),
            "App install batch",
            &format!(
                "installed={done} failed={} of {total} in {elapsed} ms",
                failed.len()
            ),
        );
        if !failed.is_empty() {
            log::log(&format!("[Apps] Failed packages: {}", failed.join(", ")));
        }
        if elapsed >= 1000 {
            log::perf_detail(
                "App install batch",
                elapsed,
                Some(&format!("{total} app(s)")),
            );
        }

        let detail = format!("installed {done}, failed {}", failed.len())
            + &if failed.is_empty() {
                String::new()
            } else {
                format!(": {}", failed.join(", "))
            };
        log::action_done(
            "Apps",
            done == 0 && !failed.is_empty(),
            !failed.is_empty(),
            Some(&detail),
        );
        let mut message = format!("Installed {done} app(s).");
        if !failed.is_empty() {
            message += &format!("\n\nFailed ({}):\n{}", failed.len(), failed.join("\n"));
        }
        host.dialog(
            &message,
            "XOS Toolkit",
            Buttons::Ok,
            if failed.is_empty() {
                Icon::Information
            } else {
                Icon::Warning
            },
        );
    }

    fn uninstall_selected(&self, host: &dyn Host) {
        if self.reject_empty_selection(host) {
            return;
        }
        let to_uninstall: Vec<crate::catalog::CatalogApp> = {
            let st = self.st.lock().unwrap();
            st.selected
                .iter()
                .filter_map(|n| find_app_by_name(n))
                .filter(|a| {
                    a.id != "directx" && a.id != "vcredist-all" && st.installed.contains_key(a.id)
                })
                .collect()
        };
        if to_uninstall.is_empty() {
            host.info("No installed apps selected for removal.", "Info");
            return;
        }
        if !host.confirm(
            &format!("Uninstall {} app(s)?", to_uninstall.len()),
            "Confirm",
            Icon::Warning,
        ) {
            return;
        }

        let total = to_uninstall.len();
        let mut done = 0usize;
        let mut processed = 0usize;
        let mut failed: Vec<String> = Vec::new();

        for app in &to_uninstall {
            processed += 1;
            host.set_status(&format!(
                "Uninstalling {}... ({processed}/{total})",
                app.name
            ));
            if !is_catalog_package_id(app.id) {
                failed.push(app.name.to_string());
                log::result(
                    false,
                    &format!("uninstall {}", app.id),
                    "package id is not in the internal catalog",
                );
                continue;
            }
            if xos_sys::choco_uninstall(app.id) {
                done += 1;
            } else {
                failed.push(app.name.to_string());
            }
        }

        self.refresh_installed(host);
        host.publish(self.model());
        host.set_status("Ready");

        let detail = format!("uninstalled {done}, failed {}", failed.len())
            + &if failed.is_empty() {
                String::new()
            } else {
                format!(": {}", failed.join(", "))
            };
        log::action_done(
            "Apps",
            done == 0 && !failed.is_empty(),
            !failed.is_empty(),
            Some(&detail),
        );
        let mut message = format!("Uninstalled {done} app(s).");
        if !failed.is_empty() {
            message += &format!("\n\nFailed ({}):\n{}", failed.len(), failed.join("\n"));
        }
        host.dialog(
            &message,
            "XOS Toolkit",
            Buttons::Ok,
            if failed.is_empty() {
                Icon::Information
            } else {
                Icon::Warning
            },
        );
    }

    fn refresh_list_click(&self, host: &dyn Host) {
        if self.reject_while_loading(host) {
            return;
        }
        host.set_status("Refreshing...");
        match xos_sys::get_choco_installed_packages() {
            Ok(map) => {
                let mut st = self.st.lock().unwrap();
                st.choco_status = format!("Chocolatey ready: {} packages installed.", map.len());
                st.installed = map;
                drop(st);
                host.set_status("Ready");
            }
            Err(e) => {
                log::log(&format!("[Apps] Package refresh failed: {e}"));
                self.set_choco_status(
                    "Chocolatey is installed, but the package list could not be refreshed.",
                );
                host.set_status("Chocolatey package refresh failed.");
            }
        }
    }

    fn remove_onedrive_click(&self, host: &dyn Host) {
        if !host.confirm(
            "This will uninstall OneDrive and restore local shell folders.\nCloud files will NOT be deleted.\n\nProceed?",
            "Remove OneDrive",
            Icon::Warning,
        ) {
            return;
        }

        xos_sys::ops::reset();
        host.set_status("Removing OneDrive...");

        run_onedrive_removal();
        let registry_writes_failed = xos_sys::ops::any_failed();

        self.check_onedrive_state(host);
        let removed = !self.st.lock().unwrap().onedrive_found;
        if removed {
            app_state::require_reboot();
        }
        let complete = removed && !registry_writes_failed;
        log::action_done(
            "Apps",
            !removed,
            !complete,
            Some(if removed {
                if complete {
                    "OneDrive verified absent"
                } else {
                    "OneDrive verified absent; one or more shell settings could not be restored"
                }
            } else {
                "OneDrive is still installed"
            }),
        );
        host.set_status(if complete {
            "OneDrive removed. Please reboot to finalize."
        } else {
            "OneDrive removal incomplete."
        });
        host.dialog(
            if complete {
                "OneDrive has been removed. Please reboot to finalize."
            } else if removed {
                "OneDrive was removed, but one or more shell settings could not be restored. Please check the Toolkit log."
            } else {
                "OneDrive could not be fully removed. Please check the Toolkit log and try again."
            },
            "XOS Toolkit",
            Buttons::Ok,
            if complete {
                Icon::Information
            } else {
                Icon::Warning
            },
        );
        xos_sys::ops::reset();
    }

    fn remove_edge_click(&self, host: &dyn Host) {
        if !host.confirm(
            "This will uninstall Microsoft Edge and WebView2. Apps that use WebView2 may stop working until it is reinstalled.\n\nIts shared updater services and scheduled tasks will also be stopped and blocked. You can restore them from Network when needed.\n\nProceed?",
            "Remove Microsoft Edge",
            Icon::Warning,
        ) {
            return;
        }

        xos_sys::ops::reset();
        host.set_status("Removing Microsoft Edge...");
        let mut outcome = EdgeRemovalOutcome::new();

        if let Err(e) = run_edge_removal(&mut outcome) {
            log::log(&format!("[Apps] Edge removal failed: {e}"));
            if outcome.updater_block_started {
                match webview2::allow_installation() {
                    Ok(()) => log::log(
                        "[Apps] Restored Edge Update infrastructure after the failed removal.",
                    ),
                    Err(rollback) => {
                        log::log(&format!("[Apps] Edge removal rollback failed: {rollback}"))
                    }
                }
            }
            log::action_done("Apps", true, false, Some(&e.to_string()));
            host.set_status("Microsoft Edge removal failed.");
            host.error(
                &format!("Microsoft Edge removal failed.\n\n{e}"),
                "XOS Toolkit",
            );
            return;
        }
        let registry_writes_failed = xos_sys::ops::any_failed();

        self.check_edge_state(host);
        let edge_removed = !self.st.lock().unwrap().edge_found;
        let web_view_removed = !is_edge_webview_installed();
        let game_assist_present = get_edge_game_assist_presence();
        let game_assist_removed =
            outcome.game_assist_command_ok && game_assist_present == Some(false);
        let mut complete = edge_removed
            && outcome.edge_appx_removed
            && outcome.edge_files_removed
            && outcome.edge_registry_removed
            && web_view_removed
            && game_assist_removed
            && outcome.region_restore_ok
            && !registry_writes_failed;
        xos_sys::ops::reset();
        if edge_removed
            || outcome.edge_appx_removed
            || web_view_removed
            || outcome.game_assist_command_ok
        {
            app_state::require_reboot();
        }
        if complete && !webview2::mark_edge_removal_requested() {
            complete = false;
            log::log("[Apps] Edge removal completed, but the persistent removal preference could not be saved.");
        }
        if complete {
            log::action_done(
                "Apps",
                false,
                false,
                Some("Edge, WebView2 and Edge Game Assist verified absent"),
            );
            host.set_status("Microsoft Edge removed. Please reboot to finalize.");
            host.info(
                "Microsoft Edge has been removed. Please reboot to finalize.",
                "XOS Toolkit",
            );
        } else {
            let mut failures: Vec<&str> = Vec::new();
            if !edge_removed || !outcome.edge_appx_removed {
                failures.push("Edge browser or an Edge AppX package is still installed");
            }
            if !outcome.edge_files_removed {
                failures.push("Edge installation files could not be removed");
            }
            if !outcome.edge_registry_removed {
                failures.push("Edge installation registration could not be removed");
            }
            if !web_view_removed {
                failures.push("WebView2 is still installed");
            }
            if !game_assist_removed {
                failures.push(if game_assist_present.is_none() {
                    "Edge Game Assist could not be verified"
                } else {
                    "Edge Game Assist is still installed"
                });
            }
            if !outcome.region_restore_ok {
                failures.push("temporary region values could not be restored");
            }
            if registry_writes_failed {
                failures.push("one or more cleanup registry writes failed");
            }
            if failures.is_empty() {
                failures.push("the Edge removal preference could not be saved");
            }
            log::action_done("Apps", !edge_removed, true, Some(&failures.join("; ")));
            let message = format!(
                "Microsoft Edge removal was incomplete:\n\n- {}\n\nPlease check the Toolkit log and try again.",
                failures.join("\n- ")
            );
            host.set_status("Microsoft Edge removal incomplete.");
            host.warn(&message, "XOS Toolkit");
        }
    }

    fn toggle_selected(&self, card: &str, row: usize, checked: bool) {
        let Some(idx) = card
            .strip_prefix("cat")
            .and_then(|s| s.parse::<usize>().ok())
        else {
            return;
        };
        if idx >= CATALOG.len() {
            return;
        }
        let mut st = self.st.lock().unwrap();
        let apps = matching_apps(&st.search, idx);
        let Some(app) = apps.get(row) else { return };
        let name = app.name.to_string();
        if checked {
            if !st.selected.contains(&name) {
                st.selected.push(name);
            }
        } else {
            st.selected.retain(|n| n != &name);
        }
    }
}

impl Page for AppsPage {
    fn id(&self) -> &'static str {
        "Apps"
    }

    fn label(&self) -> &'static str {
        "App Installer"
    }

    fn model(&self) -> PageModel {
        let st = self.st.lock().unwrap();
        let mut model = PageModel::new(
            "Apps",
            "App Installer",
            "Install and manage applications via Chocolatey",
        )
        .single_column()
        .max_width(980.0);

        let mut choco_buttons = Vec::new();
        if st.show_uninstall {
            choco_buttons.push(Control::button(
                "choco.uninstall",
                "Uninstall Chocolatey",
                BtnStyle::Disable,
            ));
        }
        if st.show_install {
            choco_buttons.push(Control::button(
                "choco.install",
                "Install Chocolatey",
                BtnStyle::Action,
            ));
        }
        let mut choco = Card::new(
            "choco",
            "Chocolatey Package Manager",
            st.choco_status.clone(),
        );
        if !choco_buttons.is_empty() {
            choco = choco.actions(choco_buttons);
        }
        model = model.card(choco);

        model = model.card(
            Card::new("search", "", "")
                .not_searchable()
                .visible(st.list_visible)
                .controls(vec![Control::text_input(
                    "search",
                    st.search.clone(),
                    "Search apps by name",
                )]),
        );

        for (i, category) in CATALOG.iter().enumerate() {
            let apps = matching_apps(&st.search, i);
            if apps.is_empty() {
                continue;
            }
            let rows: Vec<TableRow> = apps
                .iter()
                .map(|app| {
                    let installed = st.installed.contains_key(app.id);
                    let mut row = TableRow::new(
                        app.id,
                        vec![
                            app.name.to_string(),
                            app.id.to_string(),
                            if installed {
                                "Installed".to_string()
                            } else {
                                String::new()
                            },
                        ],
                    )
                    .checked(st.selected.iter().any(|n| n == app.name));
                    if installed {
                        row = row.tone(Tone::Green);
                    }
                    row
                })
                .collect();
            let height = 40.0 + 30.0 * rows.len() as f32;
            model = model.card(
                Card::new(format!("cat{i}"), category.name, "")
                    .visible(st.list_visible)
                    .controls(vec![Control::table(
                        "list",
                        Table::new(
                            vec![
                                Column::stretch("APP"),
                                Column::new("CHOCOLATEY ID", 260.0),
                                Column::new("STATE", 90.0),
                            ],
                            rows,
                        )
                        .checkable(true)
                        .height(height),
                    )]),
            );
        }

        model = model.card(
            Card::new("actions", "", "")
                .not_searchable()
                .visible(st.list_visible)
                .actions(vec![
                    Control::button("install_selected", "Install Selected", BtnStyle::Enable)
                        .enabled(!st.loading),
                    Control::button(
                        "uninstall_selected",
                        "Uninstall Selected",
                        BtnStyle::Disable,
                    )
                    .enabled(!st.loading),
                    Control::button("refresh_list", "Refresh List", BtnStyle::Action)
                        .enabled(!st.loading),
                ]),
        );

        model = model.card(
            Card::new("onedrive", "Remove OneDrive", "")
                .badge(Badge::new("Installed", Tone::Red))
                .visible(st.onedrive_found)
                .actions(vec![Control::button(
                    "onedrive.remove",
                    "Remove",
                    BtnStyle::Disable,
                )]),
        );
        model = model.card(
            Card::new("edge", "Remove Microsoft Edge", "")
                .badge(Badge::new("Installed", Tone::Red))
                .visible(st.edge_found)
                .actions(vec![Control::button(
                    "edge.remove",
                    "Remove",
                    BtnStyle::Disable,
                )]),
        );
        model
    }

    fn refresh(&self, host: &dyn Host) {
        self.init(host);
    }

    fn handle(&self, host: &dyn Host, event: &Event) {
        match (event.control.as_str(), &event.kind) {
            ("choco.install", EventKind::Click) => self.install_choco_click(host),
            ("choco.uninstall", EventKind::Click) => self.uninstall_choco_click(host),
            ("search", EventKind::Text(s)) => self.st.lock().unwrap().search = s.clone(),
            ("list", EventKind::RowCheck { row, checked }) => {
                self.toggle_selected(&event.card, *row, *checked)
            }
            ("install_selected", EventKind::Click) => self.install_selected(host),
            ("uninstall_selected", EventKind::Click) => self.uninstall_selected(host),
            ("refresh_list", EventKind::Click) => self.refresh_list_click(host),
            ("onedrive.remove", EventKind::Click) => self.remove_onedrive_click(host),
            ("edge.remove", EventKind::Click) => self.remove_edge_click(host),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_lists_every_category_and_app() {
        let page = AppsPage::new();
        {
            let mut st = page.st.lock().unwrap();
            st.list_visible = true;
        }
        let m = page.model();
        let cats: Vec<&Card> = m.cards.iter().filter(|c| c.id.starts_with("cat")).collect();
        assert_eq!(cats.len(), 9);
        let total: usize = cats
            .iter()
            .map(|c| c.rows[0].controls[0].table.as_ref().unwrap().rows.len())
            .sum();
        assert_eq!(total, crate::catalog::catalog_apps().len());
        assert!(m.cards.iter().any(|c| c.id == "edge" && !c.visible));
    }

    #[test]
    fn search_filters_and_selection_toggles_by_name() {
        let page = AppsPage::new();
        page.st.lock().unwrap().search = "chrome".into();
        let m = page.model();
        let cats: Vec<&Card> = m.cards.iter().filter(|c| c.id.starts_with("cat")).collect();
        assert_eq!(cats.len(), 1);
        assert_eq!(cats[0].id, "cat2");
        page.toggle_selected("cat2", 0, true);
        assert_eq!(
            page.st.lock().unwrap().selected,
            vec!["Google Chrome".to_string()]
        );
        page.toggle_selected("cat2", 0, false);
        assert!(page.st.lock().unwrap().selected.is_empty());
    }

    #[test]
    fn installed_apps_show_state() {
        let page = AppsPage::new();
        {
            let mut st = page.st.lock().unwrap();
            st.installed.insert("Steam", true);
        }
        let m = page.model();
        let card = m.cards.iter().find(|c| c.id == "cat1").unwrap();
        let rows = &card.rows[0].controls[0].table.as_ref().unwrap().rows;
        assert_eq!(rows[0].cells[2], "Installed");
        assert_eq!(rows[1].cells[2], "");
    }
}

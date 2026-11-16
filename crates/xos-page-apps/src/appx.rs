use crate::util::{contains_ci, encode_command};
use serde::Deserialize;
use std::sync::Mutex;
use xos_core::host::{Buttons, Host, Icon, Page};
use xos_core::log;
use xos_core::ui::*;

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct AppXPackageItem {
    pub full_name: Option<String>,
    pub name: Option<String>,
    pub friendly_name: Option<String>,
    pub version: Option<String>,
    pub is_framework: bool,
    pub is_non_removable: bool,
    #[serde(skip)]
    pub is_selected: bool,
}

impl AppXPackageItem {
    pub fn display_name(&self) -> String {
        match &self.friendly_name {
            Some(f) if !f.trim().is_empty() => f.clone(),
            _ => self.name.clone().unwrap_or_default(),
        }
    }
}

struct State {
    all: Vec<AppXPackageItem>,
    shown: Vec<usize>,
    search: String,
    loaded: bool,
    loading: bool,
    view_loading: bool,
    scan_failed: bool,
    empty_text: String,
}

pub struct AppXPage {
    st: Mutex<State>,
}

impl Default for AppXPage {
    fn default() -> Self {
        Self::new()
    }
}

const LOAD_SCRIPT: &str = "$ErrorActionPreference='Stop'; try { \
Get-AppxPackage -AllUsers | Sort-Object Name | ForEach-Object { \
$nr = if ($null -ne $_.NonRemovable) { [bool]$_.NonRemovable } else { $_.SignatureKind -eq 'System' }; \
[PSCustomObject]@{ \
FullName = $_.PackageFullName; \
Name = $_.Name; \
Version = [string]$_.Version; \
IsFramework = [bool]$_.IsFramework; \
IsNonRemovable = [bool]$nr; \
FriendlyName = $_.DisplayName \
} } | ConvertTo-Json -Compress -Depth 3 \
} catch { Write-Output ('XOS_ERROR|' + $_.Exception.Message) }";

pub fn parse_packages(output: &str) -> Result<Vec<AppXPackageItem>, String> {
    let mut trimmed = output.trim().to_string();
    if let Some(rest) = trimmed.strip_prefix("XOS_ERROR|") {
        return Err(rest.to_string());
    }
    let mut parsed = Vec::new();
    if !trimmed.is_empty() {
        if !trimmed.starts_with('{') && !trimmed.starts_with('[') {
            return Err("PowerShell did not return valid package data.".to_string());
        }
        if trimmed.starts_with('{') {
            trimmed = format!("[{trimmed}]");
        }
        let items: Vec<Option<AppXPackageItem>> =
            serde_json::from_str(&trimmed).map_err(|e| e.to_string())?;
        parsed.extend(items.into_iter().flatten().filter(|i| {
            i.name
                .as_deref()
                .map(|n| !n.trim().is_empty())
                .unwrap_or(false)
        }));
    }
    Ok(parsed)
}

fn matches_search(p: &AppXPackageItem, search: &str) -> bool {
    contains_ci(p.name.as_deref().unwrap_or(""), search)
        || contains_ci(p.full_name.as_deref().unwrap_or(""), search)
        || contains_ci(p.friendly_name.as_deref().unwrap_or(""), search)
}

impl State {
    fn apply_filter(&mut self) {
        let search = self.search.trim().to_string();
        self.shown = self
            .all
            .iter()
            .enumerate()
            .filter(|(_, p)| !p.is_framework && !p.is_non_removable)
            .filter(|(_, p)| search.is_empty() || matches_search(p, &search))
            .map(|(i, _)| i)
            .collect();
    }

    fn selected_count(&self) -> usize {
        self.shown
            .iter()
            .filter(|&&i| self.all[i].is_selected)
            .count()
    }
}

impl AppXPage {
    pub fn new() -> Self {
        Self {
            st: Mutex::new(State {
                all: Vec::new(),
                shown: Vec::new(),
                search: String::new(),
                loaded: false,
                loading: false,
                view_loading: true,
                scan_failed: false,
                empty_text: "No packages found.".into(),
            }),
        }
    }

    pub fn ensure_loaded(&self, host: &dyn Host) {
        let loaded = self.st.lock().unwrap().loaded;
        if !loaded {
            self.load_packages(host);
        }
    }

    pub fn load_packages(&self, host: &dyn Host) {
        {
            let mut st = self.st.lock().unwrap();
            if st.loading {
                return;
            }
            st.loading = true;
            st.loaded = true;
            st.scan_failed = false;
            st.view_loading = true;
        }
        host.publish(self.model());
        host.set_status("Loading AppX packages...");

        let encoded = encode_command(LOAD_SCRIPT);
        let output = xos_sys::run_cmd_output(
            "powershell.exe",
            &format!("-NoProfile -NonInteractive -EncodedCommand {encoded}"),
        );

        let mut st = self.st.lock().unwrap();
        match parse_packages(&output) {
            Ok(items) => {
                st.all = items;
                st.apply_filter();
                let n = st.all.len();
                drop(st);
                host.set_status(&format!("Loaded {n} AppX packages."));
                st = self.st.lock().unwrap();
            }
            Err(e) => {
                st.loaded = false;
                st.scan_failed = true;
                log::log(&format!("[AppX] Enumeration failed: {e}"));
                st.empty_text =
                    "AppX packages could not be read. Select Refresh to try again.".into();
                drop(st);
                host.set_status("AppX package scan failed.");
                st = self.st.lock().unwrap();
            }
        }
        st.loading = false;
        st.view_loading = false;
        if st.loaded {
            st.empty_text = "No packages found.".into();
        }
    }

    fn select_all(&self, value: bool) {
        let mut st = self.st.lock().unwrap();
        let shown = st.shown.clone();
        for i in shown {
            st.all[i].is_selected = value;
        }
    }

    fn remove_selected(&self, host: &dyn Host) {
        let to_remove: Vec<AppXPackageItem> = {
            let st = self.st.lock().unwrap();
            st.shown
                .iter()
                .map(|&i| st.all[i].clone())
                .filter(|p| p.is_selected)
                .collect()
        };
        if to_remove.is_empty() {
            return;
        }
        if !host.confirm(
            &format!(
                "Remove {} package(s)?\n\nThis action cannot be undone.",
                to_remove.len()
            ),
            "XOS Toolkit",
            Icon::Warning,
        ) {
            return;
        }

        self.st.lock().unwrap().view_loading = true;
        host.publish(self.model());
        let mut success = 0usize;
        let mut failed: Vec<(String, String)> = Vec::new();

        for pkg in &to_remove {
            let name = pkg.name.clone().unwrap_or_default();
            host.set_status(&format!("Removing {name}..."));
            let mut notify = || host.set_status(&format!("Removing {name} (policy workaround)..."));
            let (ok, error) = xos_helpers::appx_removal::remove(
                &name,
                pkg.full_name.as_deref(),
                60000,
                Some(&mut notify as &mut dyn FnMut()),
            );
            if ok {
                success += 1;
            } else {
                failed.push((name.clone(), error.unwrap_or_default()));
            }
        }
        self.st.lock().unwrap().view_loading = false;

        let detail = format!("removed {success}, failed {}", failed.len())
            + &if failed.is_empty() {
                String::new()
            } else {
                format!(
                    ": {}",
                    failed
                        .iter()
                        .map(|f| f.0.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
        log::action_done(
            "AppX",
            success == 0 && !failed.is_empty(),
            !failed.is_empty(),
            Some(&detail),
        );
        let mut msg = format!("Removed {success} package(s).");
        if !failed.is_empty() {
            msg += &format!("\n\nFailed to remove ({}):\n", failed.len());
            for f in &failed {
                msg += &format!("\n\u{2022} {}\n   {}\n", f.0, f.1);
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
        self.load_packages(host);
    }
}

impl Page for AppXPage {
    fn id(&self) -> &'static str {
        "AppX"
    }

    fn label(&self) -> &'static str {
        "AppX Manager"
    }

    fn model(&self) -> PageModel {
        let st = self.st.lock().unwrap();
        let selected = st.selected_count();
        let rows: Vec<TableRow> = if st.view_loading {
            Vec::new()
        } else {
            st.shown
                .iter()
                .map(|&i| {
                    let p = &st.all[i];
                    TableRow::new(
                        p.full_name.clone().unwrap_or_default(),
                        vec![
                            p.display_name(),
                            p.name.clone().unwrap_or_default(),
                            p.full_name.clone().unwrap_or_default(),
                            p.version.clone().unwrap_or_default(),
                        ],
                    )
                    .checked(p.is_selected)
                    .tooltip(p.full_name.clone().unwrap_or_default())
                })
                .collect()
        };
        let count_text = format!(
            "{} package(s) shown  \u{2022}  {} selected",
            st.shown.len(),
            selected
        );
        let list_note = if st.view_loading {
            "Loading packages...".to_string()
        } else if st.scan_failed || st.shown.is_empty() {
            st.empty_text.clone()
        } else {
            String::new()
        };
        let mut list_controls = Vec::new();
        if !list_note.is_empty() {
            list_controls.push(Control::muted(list_note));
        }
        if !st.scan_failed {
            list_controls.push(Control::table(
                "list",
                Table::new(
                    vec![
                        Column::stretch("PACKAGE"),
                        Column::new("NAME", 230.0),
                        Column::new("FULL NAME", 260.0),
                        Column::new("VERSION", 110.0),
                    ],
                    rows,
                )
                .checkable(true)
                .height(420.0),
            ));
        }
        PageModel::new(
            "AppX",
            "AppX Package Manager",
            "Browse and remove Windows built-in AppX packages",
        )
        .single_column()
        .max_width(1080.0)
        .card(
            Card::new("controls", "", "")
                .not_searchable()
                .controls(vec![
                    Control::text_input("search", st.search.clone(), "Search packages"),
                    Control::button("refresh", "\u{21bb}  Refresh", BtnStyle::Action)
                        .enabled(!st.view_loading),
                ])
                .controls(vec![Control::muted(count_text).id("count")]),
        )
        .card(
            Card::new("packages", "", "")
                .not_searchable()
                .controls(list_controls),
        )
        .card(Card::new("actions", "", "").not_searchable().actions(vec![
                Control::button("remove", "Remove Selected", BtnStyle::Disable)
                    .enabled(!st.view_loading && selected > 0),
                Control::button("select_all", "Select All", BtnStyle::Action)
                    .enabled(!st.view_loading),
                Control::button("clear", "Clear Selection", BtnStyle::Warning)
                    .enabled(!st.view_loading),
            ]))
    }

    fn refresh(&self, host: &dyn Host) {
        self.ensure_loaded(host);
    }

    fn handle(&self, host: &dyn Host, event: &Event) {
        match (event.control.as_str(), &event.kind) {
            ("refresh", EventKind::Click) => self.load_packages(host),
            ("search", EventKind::Text(s)) => {
                let mut st = self.st.lock().unwrap();
                st.search = s.clone();
                if st.loaded {
                    st.apply_filter();
                }
            }
            ("list", EventKind::RowCheck { row, checked }) => {
                let mut st = self.st.lock().unwrap();
                if let Some(&i) = st.shown.get(*row) {
                    st.all[i].is_selected = *checked;
                }
            }
            ("select_all", EventKind::Click) => self.select_all(true),
            ("clear", EventKind::Click) => self.select_all(false),
            ("remove", EventKind::Click) => self.remove_selected(host),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"[{"FullName":"A_1.0_x64__x","Name":"Microsoft.A","Version":"1.0","IsFramework":false,"IsNonRemovable":false,"FriendlyName":"App A"},{"FullName":"F_1.0_x64__x","Name":"Microsoft.VCLibs","Version":"1.0","IsFramework":true,"IsNonRemovable":false,"FriendlyName":null},{"FullName":"N_1_x","Name":"Sys.N","Version":"2","IsFramework":false,"IsNonRemovable":true,"FriendlyName":null},{"FullName":"B_1_x","Name":"Contoso.B","Version":"3","IsFramework":false,"IsNonRemovable":false,"FriendlyName":null}]"#;

    #[test]
    fn parses_array_and_single_object() {
        let items = parse_packages(SAMPLE).unwrap();
        assert_eq!(items.len(), 4);
        assert_eq!(items[0].display_name(), "App A");
        assert_eq!(items[3].display_name(), "Contoso.B");
        let one = parse_packages(r#"{"FullName":"X","Name":"Only","Version":"1"}"#).unwrap();
        assert_eq!(one.len(), 1);
        assert!(parse_packages("").unwrap().is_empty());
        assert!(parse_packages("garbage").is_err());
        assert_eq!(parse_packages("XOS_ERROR|boom").unwrap_err(), "boom");
    }

    #[test]
    fn filter_hides_frameworks_and_non_removable() {
        let page = AppXPage::new();
        {
            let mut st = page.st.lock().unwrap();
            st.all = parse_packages(SAMPLE).unwrap();
            st.loaded = true;
            st.view_loading = false;
            st.apply_filter();
        }
        let m = page.model();
        let table = m.cards[1].rows.last().unwrap().controls[0]
            .table
            .as_ref()
            .unwrap();
        assert_eq!(table.rows.len(), 2);
        page.st.lock().unwrap().search = "contoso".into();
        page.st.lock().unwrap().apply_filter();
        assert_eq!(page.st.lock().unwrap().shown.len(), 1);
    }

    #[test]
    fn select_all_only_touches_shown_items() {
        let page = AppXPage::new();
        {
            let mut st = page.st.lock().unwrap();
            st.all = parse_packages(SAMPLE).unwrap();
            st.apply_filter();
        }
        page.select_all(true);
        let st = page.st.lock().unwrap();
        assert_eq!(st.selected_count(), 2);
        assert!(!st.all[1].is_selected);
        assert!(!st.all[2].is_selected);
    }
}

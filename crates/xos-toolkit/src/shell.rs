use crate::view::{apply_busy, pair_cards, PageView};
use crate::{platform, AppWindow, Bridge, NavItemD, PickItemD, Theme};
use slint::{ComponentHandle, Model, ModelRc, SharedString, VecModel};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use xos_core::host::{Buttons, DialogResult, FileFilter, Host, Icon, Page, PickItem};
use xos_core::ui::{Card, Control, Event, EventKind, Kind, PageModel};
use xos_core::{app_state, log};

const SEARCH_PAGE: &str = "__search";

struct NavEntry {
    id: &'static str,
    label: &'static str,
    group: &'static str,
}

struct State {
    current: String,
    models: HashMap<String, PageModel>,
    busy: HashMap<String, u32>,
    search: String,
    highlight: Option<(String, String)>,
    dismissed_reason: Option<String>,
    dark: bool,
}

struct PickState {
    items: Vec<PickItem>,
    selected: HashSet<String>,
    filter: String,
    tx: Option<mpsc::Sender<Option<Vec<String>>>>,
}

pub struct Shell {
    pages: Vec<Arc<dyn Page>>,
    nav: Vec<NavEntry>,
    weak: slint::Weak<AppWindow>,
    state: Mutex<State>,
    dialog_lock: Mutex<()>,
    dialog_tx: Mutex<Option<(mpsc::Sender<(i32, bool)>, Buttons)>>,
    input_tx: Mutex<Option<mpsc::Sender<Option<String>>>>,
    pick: Mutex<PickState>,
    page_locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    ui_thread: std::thread::ThreadId,
}

thread_local! {
    static VIEW: RefCell<Option<PageView>> = const { RefCell::new(None) };
    static NAV_MODEL: RefCell<Option<Rc<VecModel<NavItemD>>>> = const { RefCell::new(None) };
    static PICK_MODEL: RefCell<Option<Rc<VecModel<PickItemD>>>> = const { RefCell::new(None) };
}

fn option_index_in(model: &PageModel, card: &str, control: &str, value: &str) -> Option<i32> {
    model
        .cards
        .iter()
        .filter(|c| c.id == card)
        .flat_map(|c| c.rows.iter())
        .flat_map(|r| r.controls.iter())
        .find(|c| c.id == control && c.kind == Kind::Combo)
        .and_then(|c| c.options.iter().position(|o| o == value))
        .map(|i| i as i32)
}

fn ss(s: &str) -> SharedString {
    SharedString::from(s)
}

const REBOOT_PHRASES: &[&str] = &[
    "please reboot",
    "reboot required",
    "reboot is required",
    "requires a reboot",
    "require a reboot",
    "reboot to apply",
    "reboot to fully apply",
    "reboot for full effect",
    "restart required",
    "restart is required",
    "requires a restart",
    "restart to apply",
    "restart your pc",
    "restart the pc",
    "restart your computer",
];

impl Shell {
    fn page(&self, id: &str) -> Option<Arc<dyn Page>> {
        self.pages.iter().find(|p| p.id() == id).cloned()
    }

    fn on_ui_thread(&self) -> bool {
        std::thread::current().id() == self.ui_thread
    }

    fn page_label(&self, id: &str) -> String {
        self.nav.iter().find(|n| n.id == id).map(|n| n.label.to_string()).unwrap_or_else(|| id.to_string())
    }

    fn ui<F: FnOnce(&Arc<Shell>, AppWindow) + Send + 'static>(self: &Arc<Self>, f: F) {
        let me = self.clone();
        let weak = self.weak.clone();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(ui) = weak.upgrade() {
                f(&me, ui);
            }
        });
    }

    fn latest_model(&self, id: &str) -> PageModel {
        if let Some(m) = self.state.lock().unwrap().models.get(id) {
            return m.clone();
        }
        self.page(id).map(|p| p.model()).unwrap_or_else(|| PageModel::new(id, id, ""))
    }

    fn option_index(&self, card: &str, control: &str, value: &str) -> Option<i32> {
        let current = self.state.lock().unwrap().current.clone();
        option_index_in(&self.latest_model(&current), card, control, value)
    }

    fn search_model(&self, query: &str) -> PageModel {
        let tokens: Vec<String> = query.split_whitespace().map(|t| t.to_lowercase()).collect();
        let matches = |text: &str| {
            let lower = text.to_lowercase();
            tokens.iter().all(|t| lower.contains(t.as_str()))
        };
        let mut model = PageModel::new(SEARCH_PAGE, "Search Results", format!("Showing settings matching \"{query}\""))
            .single_column()
            .max_width(700.0);
        let mut any = false;
        for entry in &self.nav {
            let pm = self.latest_model(entry.id);
            let mut hits: Vec<Card> = Vec::new();
            if matches(entry.label) {
                hits.push(
                    Card::new(format!("hit|{}|", entry.id), entry.label, "Open this module.")
                        .full_width()
                        .actions(vec![Control::button("go", format!("Go to {} →", entry.label), xos_core::BtnStyle::Link)]),
                );
            }
            for card in pm.cards.iter().filter(|c| c.visible && c.searchable && !c.title.is_empty()) {
                let mut text = format!("{} {}", card.title, card.description);
                if let Some(b) = &card.badge {
                    text.push(' ');
                    text.push_str(&b.text);
                }
                for r in &card.rows {
                    for c in &r.controls {
                        if matches!(c.kind, Kind::Label | Kind::Muted | Kind::Heading | Kind::Mono | Kind::Chip | Kind::Stat) {
                            text.push(' ');
                            text.push_str(&c.text);
                            if c.kind == Kind::Stat {
                                text.push(' ');
                                text.push_str(&c.value);
                            }
                        }
                    }
                }
                if matches(&text) {
                    hits.push(
                        Card::new(format!("hit|{}|{}", entry.id, card.id), card.title.clone(), card.description.clone())
                            .full_width()
                            .actions(vec![Control::button("go", format!("Go to {} →", entry.label), xos_core::BtnStyle::Link)]),
                    );
                }
            }
            if !hits.is_empty() {
                any = true;
                model.cards.push(
                    Card::new(format!("hdr|{}", entry.id), "", "")
                        .full_width()
                        .not_searchable()
                        .controls(vec![Control::heading(entry.label.to_uppercase())]),
                );
                model.cards.extend(hits);
            }
        }
        if !any {
            model.cards.push(Card::new("none", "No settings found.", "").full_width());
        }
        model
    }

    fn render(self: &Arc<Self>, ui: &AppWindow) {
        let (current, search, highlight, busy) = {
            let st = self.state.lock().unwrap();
            (
                st.current.clone(),
                st.search.clone(),
                st.highlight.clone(),
                st.busy.get(&st.current).copied().unwrap_or(0) > 0,
            )
        };
        let mut model = if search.trim().is_empty() { self.latest_model(&current) } else { self.search_model(search.trim()) };
        if busy && search.trim().is_empty() {
            apply_busy(&mut model);
        }
        let hl = match &highlight {
            Some((p, c)) if *p == current && search.trim().is_empty() => c.clone(),
            _ => String::new(),
        };
        ui.set_page_title(ss(&model.title));
        ui.set_page_subtitle(ss(&model.subtitle));
        ui.set_page_max_width(model.max_width);
        ui.set_overlay_visible(model.overlay.is_some());
        ui.set_overlay_text(ss(model.overlay.as_deref().unwrap_or("")));
        let pairs = pair_cards(&model.cards, model.two_column);
        VIEW.with(|v| {
            let mut v = v.borrow_mut();
            let view = v.get_or_insert_with(|| {
                let pv = PageView::new();
                ui.set_pairs(pv.model());
                pv
            });
            view.update(pairs, &hl);
        });
    }

    fn reset_view(&self, ui: &AppWindow) {
        VIEW.with(|v| {
            let pv = PageView::new();
            ui.set_pairs(pv.model());
            *v.borrow_mut() = Some(pv);
        });
        ui.set_scroll_y(0.0);
    }

    fn render_nav(&self, ui: &AppWindow) {
        let current = self.state.lock().unwrap().current.clone();
        let mut last_group = "";
        let items: Vec<NavItemD> = self
            .nav
            .iter()
            .map(|n| {
                let group = if n.group != last_group { n.group } else { "" };
                last_group = n.group;
                NavItemD { id: ss(n.id), label: ss(n.label), group: ss(group), active: n.id == current }
            })
            .collect();
        ui.set_settings_active(current == "Settings");
        NAV_MODEL.with(|m| {
            let mut m = m.borrow_mut();
            let model = m.get_or_insert_with(|| {
                let vm = Rc::new(VecModel::default());
                ui.set_nav(ModelRc::from(vm.clone()));
                vm
            });
            model.set_vec(items);
        });
    }

    pub fn navigate_to(self: &Arc<Self>, id: &str, highlight: Option<String>) {
        let id = if self.page(id).is_some() { id.to_string() } else { "System".to_string() };
        {
            let mut st = self.state.lock().unwrap();
            st.current = id.clone();
            st.search.clear();
            st.highlight = highlight.map(|c| (id.clone(), c));
        }
        let label = self.page_label(&id);
        let has_highlight = self.state.lock().unwrap().highlight.is_some();
        self.ui(move |me, ui| {
            ui.set_search_text(SharedString::new());
            me.reset_view(&ui);
            me.render_nav(&ui);
            me.render(&ui);
        });
        self.host().set_status(&format!("Viewing: {label}"));
        if has_highlight {
            let me = self.clone();
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(150));
                me.state.lock().unwrap().highlight = None;
                me.ui(|me, ui| me.render(&ui));
            });
        }
        let me = self.clone();
        std::thread::spawn(move || {
            let Some(page) = me.page(&id) else { return };
            let lock = me.page_lock(&id);
            let _serial = lock.lock().unwrap_or_else(|e| e.into_inner());
            log::log(&format!("[ACTION] viewed page {id}"));
            let started = Instant::now();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| page.refresh(&me.host())));
            log::log(&format!("[PERF] refresh {id} took {} ms", started.elapsed().as_millis()));
            if let Err(e) = result {
                me.report_panic(&format!("refresh {id}"), e);
            }
            me.host().publish(page.model());
        });
    }

    fn report_panic(self: &Arc<Self>, context: &str, e: Box<dyn std::any::Any + Send>) {
        let msg = e
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_else(|| "unknown panic".into());
        log::exception(context, &msg);
        let text = match crate::write_crash_file(&format!("{context}: {msg}")) {
            Some(p) => format!("XOS Toolkit hit an unexpected error.\n\nDetails written to:\n{}", p.display()),
            None => "XOS Toolkit hit an unexpected error.".to_string(),
        };
        self.host().dialog(&text, "XOS Toolkit", Buttons::Ok, Icon::Error);
    }

    fn page_lock(&self, id: &str) -> Arc<Mutex<()>> {
        self.page_locks.lock().unwrap().entry(id.to_string()).or_insert_with(|| Arc::new(Mutex::new(()))).clone()
    }

    fn is_always_enabled(&self, page: &str, ev: &Event) -> bool {
        self.latest_model(page)
            .cards
            .iter()
            .filter(|c| c.id == ev.card)
            .flat_map(|c| c.rows.iter())
            .flat_map(|r| r.controls.iter())
            .any(|c| c.id == ev.control && c.always_enabled)
    }

    fn describe_click(&self, page: &str, ev: &Event) -> Option<(String, String)> {
        let model = if page == SEARCH_PAGE { return None } else { self.latest_model(page) };
        let card = model.cards.iter().find(|c| c.id == ev.card)?;
        let label = match &ev.kind {
            EventKind::Click => card
                .rows
                .iter()
                .flat_map(|r| r.controls.iter())
                .find(|c| c.id == ev.control)
                .map(|c| if c.text.trim().is_empty() { c.id.clone() } else { c.text.trim().to_string() })
                .unwrap_or_else(|| "(unlabelled button)".into()),
            EventKind::RowButton { button, row } => {
                let row_name = card
                    .rows
                    .iter()
                    .flat_map(|r| r.controls.iter())
                    .find(|c| c.id == ev.control)
                    .and_then(|c| c.table.as_ref())
                    .and_then(|t| t.rows.get(*row))
                    .map(|r| r.cells.first().cloned().unwrap_or_else(|| r.id.clone()))
                    .unwrap_or_default();
                format!("{button} {row_name}").trim().to_string()
            }
            EventKind::HeaderClick(col) => card
                .rows
                .iter()
                .flat_map(|r| r.controls.iter())
                .find(|c| c.id == ev.control)
                .and_then(|c| c.table.as_ref())
                .and_then(|t| t.columns.get(*col))
                .map(|c| format!("sort {}", c.title.trim_end_matches(['\u{25B2}', '\u{25BC}', ' '])))?,
            _ => return None,
        };
        let title = if card.title.is_empty() { "(no card)".to_string() } else { card.title.clone() };
        Some((title, label))
    }

    pub fn dispatch(self: &Arc<Self>, ev: Event) {
        let (page_id, searching) = {
            let st = self.state.lock().unwrap();
            (st.current.clone(), !st.search.trim().is_empty())
        };
        if searching {
            if ev.kind == EventKind::Click {
                let parts: Vec<&str> = ev.card.splitn(3, '|').collect();
                if parts.len() == 3 && parts[0] == "hit" {
                    let target = parts[1].to_string();
                    let card = if parts[2].is_empty() { None } else { Some(parts[2].to_string()) };
                    self.navigate_to(&target, card);
                }
            }
            return;
        }
        let Some(page) = self.page(&page_id) else { return };
        let marks_busy = matches!(
            ev.kind,
            EventKind::Click | EventKind::RowButton { .. } | EventKind::Submit(_) | EventKind::RowActivate(_) | EventKind::Select(_) | EventKind::Check(_)
        );
        if let Some((card, label)) = self.describe_click(&page_id, &ev) {
            log::action_clicked(&page_id, &card, &label);
        }
        if marks_busy {
            *self.state.lock().unwrap().busy.entry(page_id.clone()).or_insert(0) += 1;
            self.ui(|me, ui| me.render(&ui));
        }
        let bypass = self.is_always_enabled(&page_id, &ev);
        let lock = self.page_lock(&page_id);
        let me = self.clone();
        std::thread::spawn(move || {
            let _serial = if bypass { None } else { Some(lock.lock().unwrap_or_else(|e| e.into_inner())) };
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| page.handle(&me.host(), &ev)));
            if let Err(e) = result {
                me.report_panic(&format!("{} action", page.id()), e);
            }
            if marks_busy {
                let mut st = me.state.lock().unwrap();
                if let Some(b) = st.busy.get_mut(page.id()) {
                    *b = b.saturating_sub(1);
                }
            }
            me.host().publish(page.model());
        });
    }

    fn update_banner(self: &Arc<Self>) {
        let reason = crate::pages::pending_reboot_reason();
        let dismissed = self.state.lock().unwrap().dismissed_reason.clone();
        let (visible, text) = match reason {
            Some(r) if dismissed.as_deref() != Some(r.as_str()) => (
                true,
                format!("Windows is already waiting to restart for {r}. Feature, service and device changes will not take full effect until you restart."),
            ),
            Some(_) => (false, String::new()),
            None => {
                self.state.lock().unwrap().dismissed_reason = None;
                (app_state::reboot_required(), "System state changed. A reboot is required.".to_string())
            }
        };
        self.ui(move |_, ui| {
            ui.set_banner_visible(visible);
            ui.set_banner_text(ss(&text));
        });
    }

    fn reboot_now(self: &Arc<Self>) {
        let me = self.clone();
        std::thread::spawn(move || {
            static RUNNING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
            if RUNNING.swap(true, std::sync::atomic::Ordering::SeqCst) {
                return;
            }
            if me.host().dialog("Restart now to apply pending changes?", "Restart", Buttons::YesNo, Icon::Question) == DialogResult::Yes {
                if crate::pages::chocolatey_bootstrap_running() {
                    me.ui(|_, ui| ui.set_banner_text(ss("Finishing Chocolatey installation before restart...")));
                    crate::pages::wait_chocolatey_bootstrap(std::time::Duration::from_secs(90));
                }
                if !crate::pages::restart_windows() {
                    me.host().dialog("Windows did not accept the restart command.", "Restart", Buttons::Ok, Icon::Error);
                }
            }
            RUNNING.store(false, std::sync::atomic::Ordering::SeqCst);
        });
    }

    fn set_dark(self: &Arc<Self>, dark: bool, ui: &AppWindow) {
        self.state.lock().unwrap().dark = dark;
        ui.global::<Theme>().set_dark(dark);
        apply_title_bar(ui, dark);
    }
}

fn apply_title_bar(ui: &AppWindow, dark: bool) {
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
    if let Ok(h) = ui.window().window_handle().window_handle() {
        if let RawWindowHandle::Win32(w) = h.as_raw() {
            platform::set_title_bar_dark(w.hwnd.get(), dark);
        }
    }
}

#[derive(Clone)]
pub struct H(pub Arc<Shell>);

impl std::ops::Deref for H {
    type Target = Arc<Shell>;
    fn deref(&self) -> &Arc<Shell> {
        &self.0
    }
}

impl Shell {
    fn host(self: &Arc<Self>) -> H {
        H(self.clone())
    }
}

impl H {
    fn show_dialog(&self, message: &str, title: &str, buttons: Buttons, icon: Icon, can_mute: bool) -> (DialogResult, bool) {
        if self.on_ui_thread() {
            log::log(&format!("[ERROR] dialog requested on UI thread: {title}"));
            let fallback = match buttons {
                Buttons::Ok => DialogResult::Ok,
                Buttons::OkCancel | Buttons::YesNoCancel => DialogResult::Cancel,
                Buttons::YesNo => DialogResult::No,
            };
            return (fallback, false);
        }
        let _guard = self.dialog_lock.lock().unwrap();
        let (tx, rx) = mpsc::channel();
        *self.dialog_tx.lock().unwrap() = Some((tx, buttons));
        let labels: Vec<SharedString> = match buttons {
            Buttons::Ok => vec!["OK".into()],
            Buttons::OkCancel => vec!["Cancel".into(), "OK".into()],
            Buttons::YesNo => vec!["No".into(), "Yes".into()],
            Buttons::YesNoCancel => vec!["Cancel".into(), "No".into(), "Yes".into()],
        };
        let icon_code = match icon {
            Icon::Information => 0,
            Icon::Warning => 1,
            Icon::Error => 2,
            Icon::Question => 3,
        };
        let (m, t) = (message.to_string(), title.to_string());
        self.ui(move |_, ui| {
            ui.set_dialog_title(ss(&t));
            ui.set_dialog_message(ss(&m));
            ui.set_dialog_icon(icon_code);
            ui.set_dialog_buttons(ModelRc::new(VecModel::from(labels)));
            ui.set_dialog_can_mute(can_mute);
            ui.set_dialog_muted(false);
            ui.window().set_minimized(false);
            ui.set_dialog_visible(true);
            let _ = ui.window().show();
        });
        let (idx, muted) = rx.recv().unwrap_or((-1, false));
        let result = match (buttons, idx) {
            (Buttons::Ok, _) => DialogResult::Ok,
            (Buttons::OkCancel, 1) => DialogResult::Ok,
            (Buttons::OkCancel, _) => DialogResult::Cancel,
            (Buttons::YesNo, 1) => DialogResult::Yes,
            (Buttons::YesNo, -1) => DialogResult::Cancel,
            (Buttons::YesNo, _) => DialogResult::No,
            (Buttons::YesNoCancel, 2) => DialogResult::Yes,
            (Buttons::YesNoCancel, 1) => DialogResult::No,
            (Buttons::YesNoCancel, _) => DialogResult::Cancel,
        };
        (result, muted && can_mute)
    }
}

impl Host for H {
    fn dialog(&self, message: &str, title: &str, buttons: Buttons, icon: Icon) -> DialogResult {
        self.show_dialog(message, title, buttons, icon, false).0
    }

    fn dialog_mutable(&self, key: &str, message: &str, title: &str, buttons: Buttons, icon: Icon) -> DialogResult {
        if platform::dialog_muted(key) {
            log::log(&format!("Dialog \"{title}\" ({key}) not shown: the user chose not to see it again."));
            return match buttons {
                Buttons::Ok | Buttons::OkCancel => DialogResult::Ok,
                Buttons::YesNo | Buttons::YesNoCancel => DialogResult::Yes,
            };
        }
        let (result, muted) = self.show_dialog(message, title, buttons, icon, true);
        if muted && result.accepted() {
            match platform::mute_dialog(key) {
                Ok(()) => log::log(&format!("Dialog \"{title}\" ({key}): the user chose not to see it again.")),
                Err(e) => log::log(&format!("[WARN] Dialog \"{title}\" ({key}): could not save \"do not show again\": {e}")),
            }
        }
        result
    }

    fn input_text(&self, prompt: &str, title: &str, max_len: usize, ok_label: &str) -> Option<String> {
        if self.on_ui_thread() {
            return None;
        }
        let _guard = self.dialog_lock.lock().unwrap();
        let (tx, rx) = mpsc::channel();
        *self.input_tx.lock().unwrap() = Some(tx);
        let (p, t, o) = (prompt.to_string(), title.to_string(), ok_label.to_string());
        self.ui(move |_, ui| {
            ui.set_input_title(ss(&t));
            ui.set_input_prompt(ss(&p));
            ui.set_input_ok(ss(&o));
            ui.set_input_max(max_len as i32);
            ui.set_input_text(SharedString::new());
            ui.set_input_visible(true);
        });
        let result = rx.recv().ok().flatten();
        result.map(|s| if max_len > 0 { s.chars().take(max_len).collect() } else { s })
    }

    fn pick_many(&self, title: &str, legend: &str, filter_hint: &str, items: Vec<PickItem>, ok_label: &str) -> Vec<String> {
        if self.on_ui_thread() {
            return Vec::new();
        }
        let _guard = self.dialog_lock.lock().unwrap();
        let (tx, rx) = mpsc::channel();
        {
            let mut p = self.pick.lock().unwrap();
            p.items = items;
            p.selected.clear();
            p.filter.clear();
            p.tx = Some(tx);
        }
        let (t, l, h, o) = (title.to_string(), legend.to_string(), filter_hint.to_string(), ok_label.to_string());
        self.ui(move |me, ui| {
            ui.set_pick_title(ss(&t));
            ui.set_pick_legend(ss(&l));
            ui.set_pick_hint(ss(&h));
            ui.set_pick_ok(ss(&o));
            me.render_pick(&ui);
            ui.set_pick_visible(true);
        });
        rx.recv().ok().flatten().unwrap_or_default()
    }

    fn save_file(&self, title: &str, filters: &[FileFilter], default_name: &str, initial_dir: Option<PathBuf>) -> Option<PathBuf> {
        let mut d = rfd::FileDialog::new().set_title(title).set_file_name(default_name);
        for f in filters {
            d = d.add_filter(&f.name, &f.extensions);
        }
        if let Some(dir) = initial_dir {
            d = d.set_directory(dir);
        }
        d.save_file()
    }

    fn open_file(&self, title: &str, filters: &[FileFilter], initial_dir: Option<PathBuf>) -> Option<PathBuf> {
        let mut d = rfd::FileDialog::new().set_title(title);
        for f in filters {
            d = d.add_filter(&f.name, &f.extensions);
        }
        if let Some(dir) = initial_dir {
            d = d.set_directory(dir);
        }
        d.pick_file()
    }

    fn set_status(&self, text: &str) {
        log::log(&format!("[STATUS] {text}"));
        let lower = text.to_lowercase();
        if REBOOT_PHRASES.iter().any(|p| lower.contains(p)) {
            app_state::require_reboot();
        }
        let t = if text.is_empty() { "Ready".to_string() } else { text.to_string() };
        self.ui(move |_, ui| ui.set_status_text(ss(&t)));
    }

    fn publish(&self, model: PageModel) {
        let id = model.id.clone();
        self.state.lock().unwrap().models.insert(id.clone(), model);
        self.ui(move |me, ui| {
            let st = me.state.lock().unwrap();
            let visible = st.search.trim().is_empty() && st.current == id;
            let searching = !st.search.trim().is_empty();
            drop(st);
            if visible || searching {
                me.render(&ui);
            }
        });
    }

    fn navigate(&self, page_id: &str) {
        self.navigate_to(page_id, None);
    }

    fn current_page(&self) -> String {
        self.state.lock().unwrap().current.clone()
    }
}

impl Shell {
    fn render_pick(&self, ui: &AppWindow) {
        let p = self.pick.lock().unwrap();
        let filter = p.filter.to_lowercase();
        let items: Vec<PickItemD> = p
            .items
            .iter()
            .filter(|i| filter.is_empty() || i.label.to_lowercase().contains(&filter))
            .map(|i| PickItemD { id: ss(&i.id), label: ss(&i.label), tone: i.tone.code(), selected: p.selected.contains(&i.id) })
            .collect();
        drop(p);
        PICK_MODEL.with(|m| {
            let mut m = m.borrow_mut();
            let model = m.get_or_insert_with(|| {
                let vm = Rc::new(VecModel::default());
                ui.set_pick_items(ModelRc::from(vm.clone()));
                vm
            });
            model.set_vec(items);
        });
    }
}

pub fn run(pages: Vec<Arc<dyn Page>>) -> Result<(), slint::PlatformError> {
    let ui = AppWindow::new()?;
    let dark = crate::settings::theme().is_dark();
    ui.global::<Theme>().set_dark(dark);
    if platform::windows_build() < 22000 {
        ui.global::<Theme>().set_font(ss("Segoe UI"));
    }
    ui.set_build_text(ss(&format!("Build {}", xos_core::VERSION)));
    ui.set_win_text(ss(&platform::windows_text()));
    ui.set_xos_detected(crate::pages::is_xos());
    let name = platform::user_name();
    ui.set_user_name(ss(&name));
    ui.set_user_initial(ss(&name.chars().next().map(|c| c.to_uppercase().to_string()).unwrap_or_else(|| "?".into())));
    if let Some(p) = platform::avatar_path() {
        if let Ok(img) = slint::Image::load_from_path(&p) {
            ui.set_avatar(img);
            ui.set_has_avatar(true);
        }
    }

    let nav = vec![
        NavEntry { id: "Apps", label: "App Installer", group: "SOFTWARE" },
        NavEntry { id: "AppX", label: "AppX Manager", group: "SOFTWARE" },
        NavEntry { id: "Cleanup", label: "Disk Cleanup", group: "SOFTWARE" },
        NavEntry { id: "DriverCleaner", label: "Driver Cleaner", group: "SOFTWARE" },
        NavEntry { id: "Startup", label: "Startup Manager", group: "SOFTWARE" },
        NavEntry { id: "System", label: "System", group: "CONTROL" },
        NavEntry { id: "Visuals", label: "Visuals", group: "CONTROL" },
        NavEntry { id: "Gaming", label: "Gaming", group: "CONTROL" },
        NavEntry { id: "Network", label: "Network", group: "CONTROL" },
        NavEntry { id: "Update", label: "Updates", group: "CONTROL" },
        NavEntry { id: "Peripherals", label: "Peripherals", group: "CONTROL" },
        NavEntry { id: "MsiMode", label: "MSI Mode", group: "CONTROL" },
        NavEntry { id: "Cpu", label: "CPU Affinity", group: "CONTROL" },
        NavEntry { id: "Services", label: "Services", group: "CONTROL" },
        NavEntry { id: "Troubleshoot", label: "Troubleshooting", group: "RECOVERY" },
        NavEntry { id: "Stability", label: "Stability Monitor", group: "RECOVERY" },
        NavEntry { id: "Configuration", label: "Configuration Backup", group: "RECOVERY" },
        NavEntry { id: "About", label: "About", group: " " },
    ];

    let shell = Arc::new(Shell {
        pages,
        nav,
        weak: ui.as_weak(),
        state: Mutex::new(State {
            current: "About".into(),
            models: HashMap::new(),
            busy: HashMap::new(),
            search: String::new(),
            highlight: None,
            dismissed_reason: None,
            dark,
        }),
        dialog_lock: Mutex::new(()),
        dialog_tx: Mutex::new(None),
        input_tx: Mutex::new(None),
        pick: Mutex::new(PickState { items: Vec::new(), selected: HashSet::new(), filter: String::new(), tx: None }),
        page_locks: Mutex::new(HashMap::new()),
        ui_thread: std::thread::current().id(),
    });

    {
        let s = shell.clone();
        ui.on_navigate(move |id| s.navigate_to(id.as_str(), None));
    }
    {
        let s = shell.clone();
        ui.on_search_changed(move |text| {
            let q = text.to_string();
            let cleared = q.trim().is_empty();
            let was_searching = {
                let mut st = s.state.lock().unwrap();
                let was = !st.search.trim().is_empty();
                st.search = q;
                was
            };
            if cleared && !was_searching {
                return;
            }
            if cleared {
                let current = s.state.lock().unwrap().current.clone();
                s.navigate_to(&current, None);
            } else {
                s.ui(|me, ui| {
                    me.reset_view(&ui);
                    me.render(&ui);
                });
            }
        });
    }
    {
        let s = shell.clone();
        ui.on_open_settings(move || s.navigate_to("Settings", None));
    }
    {
        let s = shell.clone();
        crate::settings::on_theme_changed(move |dark| {
            s.ui(move |me, ui| me.set_dark(dark, &ui));
        });
    }
    {
        let s = shell.clone();
        ui.on_banner_dismiss(move || {
            let reason = crate::pages::pending_reboot_reason();
            s.state.lock().unwrap().dismissed_reason = reason;
            app_state::clear();
            s.update_banner();
        });
    }
    {
        let s = shell.clone();
        ui.on_banner_reboot(move || s.reboot_now());
    }
    {
        let s = shell.clone();
        ui.on_dialog_choose(move |i| {
            let mut muted = false;
            if let Some(ui) = s.weak.upgrade() {
                muted = ui.get_dialog_muted();
                ui.set_dialog_visible(false);
            }
            if let Some((tx, _)) = s.dialog_tx.lock().unwrap().take() {
                let _ = tx.send((i, muted));
            }
        });
    }
    {
        let s = shell.clone();
        ui.on_input_done(move |ok, text| {
            if let Some(ui) = s.weak.upgrade() {
                ui.set_input_visible(false);
            }
            if let Some(tx) = s.input_tx.lock().unwrap().take() {
                let _ = tx.send(if ok { Some(text.to_string()) } else { None });
            }
        });
    }
    {
        let s = shell.clone();
        ui.on_pick_filter(move |f| {
            s.pick.lock().unwrap().filter = f.to_string();
            if let Some(ui) = s.weak.upgrade() {
                s.render_pick(&ui);
            }
        });
    }
    {
        let s = shell.clone();
        ui.on_pick_toggle(move |i| {
            let id = PICK_MODEL.with(|m| m.borrow().as_ref().and_then(|vm| vm.row_data(i as usize)).map(|r| r.id.to_string()));
            if let Some(id) = id {
                let mut p = s.pick.lock().unwrap();
                if !p.selected.remove(&id) {
                    p.selected.insert(id);
                }
            }
            if let Some(ui) = s.weak.upgrade() {
                s.render_pick(&ui);
            }
        });
    }
    {
        let s = shell.clone();
        ui.on_pick_done(move |ok| {
            if let Some(ui) = s.weak.upgrade() {
                ui.set_pick_visible(false);
            }
            let mut p = s.pick.lock().unwrap();
            let selected: Vec<String> = p.items.iter().filter(|i| p.selected.contains(&i.id)).map(|i| i.id.clone()).collect();
            if let Some(tx) = p.tx.take() {
                let _ = tx.send(if ok && !selected.is_empty() { Some(selected) } else { None });
            }
        });
    }

    let bridge = ui.global::<Bridge>();
    macro_rules! wire {
        ($method:ident, |$($arg:ident),*| $kind:expr) => {{
            let s = shell.clone();
            bridge.$method(move |card, control, $($arg),*| {
                s.dispatch(Event { card: card.to_string(), control: control.to_string(), kind: $kind });
            });
        }};
    }
    {
        let s = shell.clone();
        bridge.on_ctl_click(move |card, control| s.dispatch(Event { card: card.to_string(), control: control.to_string(), kind: EventKind::Click }));
    }
    wire!(on_ctl_select, |i| EventKind::Select(i));
    {
        let s = shell.clone();
        bridge.on_ctl_select_value(move |card, control, value| {
            if let Some(i) = s.option_index(card.as_str(), control.as_str(), value.as_str()) {
                s.dispatch(Event { card: card.to_string(), control: control.to_string(), kind: EventKind::Select(i) });
            }
        });
    }
    wire!(on_ctl_check, |b| EventKind::Check(b));
    wire!(on_ctl_text, |t| EventKind::Text(t.to_string()));
    wire!(on_ctl_submit, |t| EventKind::Submit(t.to_string()));
    wire!(on_row_check, |r, b| EventKind::RowCheck { row: r.max(0) as usize, checked: b });
    wire!(on_row_button, |r, b| EventKind::RowButton { row: r.max(0) as usize, button: b.to_string() });
    wire!(on_row_select, |r| EventKind::RowSelect(r.max(0) as usize));
    wire!(on_row_activate, |r| EventKind::RowActivate(r.max(0) as usize));
    wire!(on_header_click, |c| EventKind::HeaderClick(c.max(0) as usize));

    {
        let s = shell.clone();
        app_state::on_reboot_required_changed(move || s.update_banner());
    }

    {
        let s = shell.clone();
        ui.window().on_close_requested(move || {
            if app_state::is_busy() {
                let s2 = s.clone();
                std::thread::spawn(move || {
                    if s2.host().dialog(
                        "An operation is still running.\n\nClosing now can leave a change half applied. Close anyway?",
                        "XOS Toolkit",
                        Buttons::YesNo,
                        Icon::Warning,
                    ) == DialogResult::Yes
                    {
                        crate::on_exit("window closed");
                        let _ = slint::invoke_from_event_loop(|| {
                            let _ = slint::quit_event_loop();
                        });
                    }
                });
                return slint::CloseRequestResponse::KeepWindowShown;
            }
            crate::on_exit("window closed");
            slint::CloseRequestResponse::HideWindow
        });
    }

    let dev_screenshot = cfg!(debug_assertions) && std::env::var("XOS_DEV_START_PAGE").is_ok();
    let start = if dev_screenshot { std::env::var("XOS_DEV_START_PAGE").unwrap_or_default() } else { "About".to_string() };
    shell.render_nav(&ui);
    shell.navigate_to(&start, None);

    {
        let s = shell.clone();
        slint::Timer::single_shot(std::time::Duration::from_millis(50), move || {
            if let Some(ui) = s.weak.upgrade() {
                let dark = s.state.lock().unwrap().dark;
                apply_title_bar(&ui, dark);
            }
            if !cfg!(debug_assertions) && !dev_screenshot {
                let s3 = s.clone();
                std::thread::spawn(move || {
                    crate::updater::clean_staging();
                    std::thread::sleep(std::time::Duration::from_secs(2));
                    crate::updater::startup_check(&s3.host());
                });
            }
            if !crate::pages::is_xos() && !dev_screenshot {
                let s2 = s.clone();
                std::thread::spawn(move || {
                    s2.host().warn_once(
                        "NonXosWelcome",
                        "This tool is designed for XOS users.\n\nYou can still use it on a standard Windows install, but expect bugs, stability problems, and limited functionality. Some options rely on registry keys, services, and tweaks that the XOS Playbook sets up.\n\nFor the full experience, apply the XOS Playbook first.",
                        "XOS Toolkit",
                    );
                });
            }
        });
    }

    ui.run()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn option_index_finds_the_combo_option() {
        let model = PageModel::new("P", "P", "").card(Card::new("svc:a", "A (a)", "").controls(vec![Control::combo(
            "svc:a",
            vec!["Automatic".to_string(), "Manual".to_string(), "Disabled (Recommended)".to_string()],
            0,
        )]));
        assert_eq!(option_index_in(&model, "svc:a", "svc:a", "Disabled (Recommended)"), Some(2));
        assert_eq!(option_index_in(&model, "svc:a", "svc:a", "Boot"), None);
        assert_eq!(option_index_in(&model, "svc:b", "svc:a", "Manual"), None);
    }
}

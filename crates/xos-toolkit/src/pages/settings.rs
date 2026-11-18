use crate::settings::{self, Channel, ThemeMode};
use crate::updater::{self, Check, Release};
use std::sync::Mutex;
use xos_core::host::{Host, Icon, Page};
use xos_core::log;
use xos_core::ui::*;

#[derive(Default)]
struct State {
    checking: bool,
    status: String,
    status_tone: Tone,
    available: Option<Release>,
}

pub struct SettingsPage {
    st: Mutex<State>,
}

impl SettingsPage {
    pub fn new() -> Self {
        Self { st: Mutex::new(State::default()) }
    }

    fn run_check(&self, host: &dyn Host) {
        {
            let mut st = self.st.lock().unwrap();
            st.checking = true;
            st.available = None;
            st.status = "Checking GitHub for updates...".into();
            st.status_tone = Tone::Muted;
        }
        host.publish(self.model());
        let channel = settings::channel();
        let result = updater::check(channel);
        {
            let mut st = self.st.lock().unwrap();
            st.checking = false;
            match &result {
                Check::UpToDate => {
                    st.status = format!("XOS Toolkit {} is the newest version on the {} channel.", xos_core::VERSION, channel.title());
                    st.status_tone = Tone::Green;
                }
                Check::Available(r) => {
                    st.status = format!(
                        "XOS Toolkit {} is available on the {} channel{}.",
                        r.version_text,
                        channel.title(),
                        if r.prerelease { " (developer beta)" } else { "" }
                    );
                    st.status_tone = Tone::Blue;
                    st.available = Some(r.clone());
                }
                Check::Failed(e) => {
                    st.status = e.clone();
                    st.status_tone = Tone::Red;
                }
            }
        }
        host.publish(self.model());
    }
}

impl Default for SettingsPage {
    fn default() -> Self {
        Self::new()
    }
}

impl Page for SettingsPage {
    fn id(&self) -> &'static str {
        "Settings"
    }

    fn label(&self) -> &'static str {
        "Settings"
    }

    fn model(&self) -> PageModel {
        let st = self.st.lock().unwrap();
        let options = |labels: &[&str]| labels.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let mut updates = Card::new(
            "updates",
            "Updates",
            "XOS Toolkit looks for new versions on GitHub (imribiy/xos-toolkit). An update is downloaded, checked against the checksum GitHub publishes, installed, and XOS Toolkit opens again.",
        )
        .full_width()
        .controls(vec![Control::check("startup", "Check for updates when XOS Toolkit starts", settings::check_updates_on_startup())])
        .controls(vec![
            Control::label("Update channel"),
            Control::combo("channel", options(&Channel::LABELS), settings::channel().index()).width(220.0).enabled(!st.checking),
        ])
        .controls(vec![Control::muted(format!(
            "Installed: XOS Toolkit {} ({} build). Stable offers only stable releases; Beta also offers developer betas, which are tested only in virtual machines.",
            xos_core::VERSION,
            settings::build_channel().title()
        ))]);
        let mut actions = vec![Control::button("check", "Check for updates", BtnStyle::Action).enabled(!st.checking)];
        if let Some(r) = &st.available {
            actions.push(Control::button("install", format!("Install {}", r.version_text), BtnStyle::Enable).enabled(!st.checking));
        }
        actions.push(Control::button("releases", "Release notes", BtnStyle::Link).always_enabled());
        updates = updates.actions(actions);
        if !st.status.is_empty() {
            updates = updates.controls(vec![Control::label(st.status.clone()).tone(st.status_tone).id("status")]);
        }
        PageModel::new("Settings", "Settings", "Appearance and updates for XOS Toolkit. Settings are saved for your Windows account.")
            .single_column()
            .max_width(820.0)
            .card(
                Card::new("appearance", "Appearance", "Colour theme of the XOS Toolkit window.")
                    .full_width()
                    .controls(vec![Control::label("Theme"), Control::combo("theme", options(&ThemeMode::LABELS), settings::theme().index()).width(220.0)]),
            )
            .card(updates)
    }

    fn handle(&self, host: &dyn Host, event: &Event) {
        match (event.card.as_str(), event.control.as_str(), &event.kind) {
            ("appearance", "theme", EventKind::Select(i)) => {
                let mode = ThemeMode::from_index(*i);
                settings::set_theme(mode);
                settings::apply_theme(mode);
            }
            ("updates", "startup", EventKind::Check(on)) => settings::set_check_updates_on_startup(*on),
            ("updates", "channel", EventKind::Select(i)) => {
                let wanted = Channel::from_index(*i);
                if wanted == settings::channel() {
                    return;
                }
                let ok = wanted == Channel::Stable
                    || host.confirm(
                        "Developer betas are for advanced users only.\n\nThey are tested only in virtual machines, not on real hardware. Expect bugs, back up important files and keep a Windows setup USB at hand.\n\nSwitch to the Beta channel?",
                        "Update channel",
                        Icon::Warning,
                    );
                if ok {
                    settings::set_channel(wanted);
                    let mut st = self.st.lock().unwrap();
                    st.available = None;
                    st.status.clear();
                }
            }
            ("updates", "check", EventKind::Click) => self.run_check(host),
            ("updates", "install", EventKind::Click) => {
                let release = self.st.lock().unwrap().available.clone();
                if let Some(r) = release {
                    log::log(&format!("[UPDATE] install {} from Settings", r.version_text));
                    updater::install(host, &r);
                }
            }
            ("updates", "releases", EventKind::Click) => {
                if !xos_sys::shell_start(updater::RELEASES_PAGE, "") {
                    host.error(&format!("The browser could not be opened.\n\n{}", updater::RELEASES_PAGE), "Settings");
                }
            }
            _ => {}
        }
        host.publish(self.model());
    }
}

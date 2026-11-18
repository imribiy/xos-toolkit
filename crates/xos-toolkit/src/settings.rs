use std::sync::OnceLock;
use winreg::enums::HKEY_CURRENT_USER;
use winreg::RegKey;

const SETTINGS_KEY: &str = r"Software\XOSToolkit\Settings";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ThemeMode {
    System,
    Light,
    Dark,
}

impl ThemeMode {
    pub const LABELS: [&'static str; 3] = ["Use Windows setting", "Light", "Dark"];

    pub fn index(self) -> i32 {
        match self {
            ThemeMode::System => 0,
            ThemeMode::Light => 1,
            ThemeMode::Dark => 2,
        }
    }

    pub fn from_index(i: i32) -> ThemeMode {
        match i {
            1 => ThemeMode::Light,
            2 => ThemeMode::Dark,
            _ => ThemeMode::System,
        }
    }

    pub fn is_dark(self) -> bool {
        match self {
            ThemeMode::System => crate::platform::system_prefers_dark(),
            ThemeMode::Light => false,
            ThemeMode::Dark => true,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Channel {
    Stable,
    Beta,
}

impl Channel {
    pub const LABELS: [&'static str; 2] = ["Stable", "Beta (developer builds)"];

    pub fn index(self) -> i32 {
        match self {
            Channel::Stable => 0,
            Channel::Beta => 1,
        }
    }

    pub fn from_index(i: i32) -> Channel {
        if i == 1 {
            Channel::Beta
        } else {
            Channel::Stable
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Channel::Stable => "stable",
            Channel::Beta => "beta",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Channel::Stable => "Stable",
            Channel::Beta => "Beta",
        }
    }

    fn parse(s: &str) -> Option<Channel> {
        match s.trim().to_ascii_lowercase().as_str() {
            "stable" => Some(Channel::Stable),
            "beta" => Some(Channel::Beta),
            _ => None,
        }
    }
}

pub fn build_channel() -> Channel {
    let unset = if cfg!(debug_assertions) { Channel::Beta } else { Channel::Stable };
    match option_env!("XOS_CHANNEL") {
        Some(c) => Channel::parse(c).unwrap_or(unset),
        None => unset,
    }
}

fn read_u32(name: &str) -> Option<u32> {
    RegKey::predef(HKEY_CURRENT_USER).open_subkey(SETTINGS_KEY).and_then(|k| k.get_value::<u32, _>(name)).ok()
}

fn read_string(name: &str) -> Option<String> {
    RegKey::predef(HKEY_CURRENT_USER).open_subkey(SETTINGS_KEY).and_then(|k| k.get_value::<String, _>(name)).ok()
}

fn write_u32(name: &str, value: u32) -> std::io::Result<()> {
    let (k, _) = RegKey::predef(HKEY_CURRENT_USER).create_subkey(SETTINGS_KEY)?;
    k.set_value(name, &value)
}

fn write_string(name: &str, value: &str) -> std::io::Result<()> {
    let (k, _) = RegKey::predef(HKEY_CURRENT_USER).create_subkey(SETTINGS_KEY)?;
    k.set_value(name, &value.to_string())
}

fn logged(what: &str, r: std::io::Result<()>) {
    match r {
        Ok(()) => xos_core::log::log(&format!("[SETTINGS] {what}")),
        Err(e) => xos_core::log::log(&format!("[WARN] [SETTINGS] could not save {what}: {e}")),
    }
}

pub fn theme() -> ThemeMode {
    ThemeMode::from_index(read_u32("Theme").unwrap_or(0) as i32)
}

pub fn set_theme(mode: ThemeMode) {
    logged(&format!("Theme = {mode:?}"), write_u32("Theme", mode.index() as u32));
}

pub fn check_updates_on_startup() -> bool {
    read_u32("CheckUpdatesOnStartup").map(|v| v != 0).unwrap_or(true)
}

pub fn set_check_updates_on_startup(on: bool) {
    logged(&format!("CheckUpdatesOnStartup = {}", on as u32), write_u32("CheckUpdatesOnStartup", on as u32));
}

pub fn channel() -> Channel {
    read_string("UpdateChannel").and_then(|s| Channel::parse(&s)).unwrap_or_else(build_channel)
}

pub fn set_channel(c: Channel) {
    logged(&format!("UpdateChannel = {}", c.name()), write_string("UpdateChannel", c.name()));
}

type ThemeHook = Box<dyn Fn(bool) + Send + Sync>;

static THEME_HOOK: OnceLock<ThemeHook> = OnceLock::new();

pub fn on_theme_changed(f: impl Fn(bool) + Send + Sync + 'static) {
    let _ = THEME_HOOK.set(Box::new(f));
}

pub fn apply_theme(mode: ThemeMode) {
    if let Some(h) = THEME_HOOK.get() {
        h(mode.is_dark());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indexes_round_trip() {
        for m in [ThemeMode::System, ThemeMode::Light, ThemeMode::Dark] {
            assert_eq!(ThemeMode::from_index(m.index()), m);
        }
        for c in [Channel::Stable, Channel::Beta] {
            assert_eq!(Channel::from_index(c.index()), c);
            assert_eq!(Channel::parse(c.name()), Some(c));
        }
        assert_eq!(Channel::parse(" Stable "), Some(Channel::Stable));
        assert_eq!(Channel::parse("nightly"), None);
    }
}

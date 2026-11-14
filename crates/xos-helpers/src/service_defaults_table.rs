use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use xos_core::log;

const RESOURCE_NAME: &str = "XOSToolkit.XOS-ServiceDefaults.tsv";

#[derive(Default)]
pub(crate) struct Table {
    edition: String,
    defaults: HashMap<String, i32>,
    overrides: HashMap<String, HashMap<i32, i32>>,
    edition_overrides: HashMap<String, HashMap<String, i32>>,
    managed: Vec<String>,
    managed_keys: HashSet<String>,
    defender_managed: HashSet<String>,
    delayed: HashMap<String, HashSet<i32>>,
    delayed_every_build: HashSet<String>,
}

fn key(name: &str) -> String {
    name.to_uppercase()
}

fn edition_key(build: i32, edition: &str) -> String {
    format!("{build}/{edition}").to_uppercase()
}

fn parse_int(text: &str) -> Option<i32> {
    let t = text.trim();
    let digits = t.strip_prefix(['+', '-']).unwrap_or(t);
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    t.parse::<i32>().ok()
}

fn try_parse_start_type(text: &str) -> Option<i32> {
    if text.trim().is_empty() {
        return None;
    }
    let trimmed = text.trim();
    if trimmed.len() >= 2 && trimmed[..2].eq_ignore_ascii_case("0x") {
        let rest = trimmed[2..].trim();
        if rest.is_empty() || !rest.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        let hex = i32::from_str_radix(rest, 16).ok()?;
        if !(0..=4).contains(&hex) {
            return None;
        }
        return Some(hex);
    }
    let parsed = parse_int(trimmed)?;
    if !(0..=4).contains(&parsed) {
        return None;
    }
    Some(parsed)
}

impl Table {
    pub(crate) fn parse(text: &str, edition: &str) -> Table {
        let mut t = Table {
            edition: edition.trim().to_string(),
            ..Default::default()
        };
        for raw in text.split('\n') {
            let line = raw.trim_end_matches('\r');
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() < 2 {
                continue;
            }
            let name = parts[0].trim();
            let start_type = match try_parse_start_type(parts[1]) {
                Some(v) if !name.is_empty() => v,
                _ => continue,
            };
            let k = key(name);
            t.defaults.insert(k.clone(), start_type);

            if parts.len() >= 3 && !parts[2].trim().is_empty() {
                let mut per_build: HashMap<i32, i32> = HashMap::new();
                let mut per_edition: HashMap<String, i32> = HashMap::new();
                for pair in parts[2].split(',') {
                    let trimmed = pair.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    let halves: Vec<&str> = trimmed.split(':').collect();
                    if halves.len() != 2 {
                        continue;
                    }
                    let scope: Vec<&str> = halves[0].split('/').collect();
                    if scope.len() > 2 {
                        continue;
                    }
                    if let (Some(build), Some(value)) =
                        (parse_int(scope[0]), try_parse_start_type(halves[1]))
                    {
                        if scope.len() == 1 {
                            per_build.insert(build, value);
                        } else if !scope[1].trim().is_empty() {
                            per_edition.insert(edition_key(build, scope[1].trim()), value);
                        }
                    }
                }
                if !per_build.is_empty() {
                    t.overrides.insert(k.clone(), per_build);
                }
                if !per_edition.is_empty() {
                    t.edition_overrides.insert(k.clone(), per_edition);
                }
            }

            if parts.len() >= 4 && parts[3].trim() == "1" && t.managed_keys.insert(k.clone()) {
                t.managed.push(name.to_string());
            }

            if parts.len() >= 5 && parts[4].trim().eq_ignore_ascii_case("defender") {
                t.defender_managed.insert(k.clone());
            }

            if parts.len() >= 6 && !parts[5].trim().is_empty() {
                let delayed = parts[5].trim();
                if delayed == "*" {
                    t.delayed_every_build.insert(k.clone());
                } else {
                    let builds: HashSet<i32> = delayed.split(',').filter_map(parse_int).collect();
                    if !builds.is_empty() {
                        t.delayed.insert(k.clone(), builds);
                    }
                }
            }
        }
        t
    }

    pub(crate) fn count(&self) -> usize {
        self.defaults.len()
    }

    pub(crate) fn get_start_type(&self, service_name: &str, build: i32) -> i32 {
        if service_name.trim().is_empty() {
            return -1;
        }
        let k = key(service_name);
        let value = match self.defaults.get(&k) {
            Some(v) => *v,
            None => return -1,
        };
        if !self.edition.is_empty() {
            if let Some(per_edition) = self.edition_overrides.get(&k) {
                if let Some(v) = per_edition.get(&edition_key(build, &self.edition)) {
                    return *v;
                }
            }
        }
        if let Some(per_build) = self.overrides.get(&k) {
            if let Some(v) = per_build.get(&build) {
                return *v;
            }
        }
        value
    }

    pub(crate) fn is_delayed_auto_start(&self, service_name: &str, build: i32) -> bool {
        if service_name.trim().is_empty() {
            return false;
        }
        if self.get_start_type(service_name, build) != 2 {
            return false;
        }
        let k = key(service_name);
        if self.delayed_every_build.contains(&k) {
            return true;
        }
        self.delayed.get(&k).is_some_and(|b| b.contains(&build))
    }

    pub(crate) fn managed_defaults(&self, build: i32) -> Vec<(String, i32)> {
        let mut result = Vec::new();
        for name in &self.managed {
            let start_type = self.get_start_type(name, build);
            if start_type >= 0 {
                result.push((name.clone(), start_type));
            }
        }
        result
    }
}

static STATE: Mutex<Option<Table>> = Mutex::new(None);

fn read_table_text() -> Option<String> {
    if let Some(bytes) = xos_sys::resource_bytes(RESOURCE_NAME) {
        return Some(decode(bytes));
    }
    let base = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()));
    if let Some(base) = base {
        let beside = base.join("XOS-ServiceDefaults.tsv");
        if beside.is_file() {
            return std::fs::read(&beside).ok().map(|b| decode(&b));
        }
        let source = base.join(r"..\..\XOS-ServiceDefaults.tsv");
        if source.is_file() {
            return std::fs::read(&source).ok().map(|b| decode(&b));
        }
    }
    None
}

fn decode(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    text.strip_prefix('\u{feff}').unwrap_or(&text).to_string()
}

fn load() -> Table {
    let edition = xos_sys::reg_get_string(
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        "EditionID",
    )
    .unwrap_or_default();
    let edition = edition.trim().to_string();
    match read_table_text() {
        None => {
            log::log(
                "[ServiceDefaults] The service default table could not be read. Uninstall falls back to the built-in catalog values.",
            );
            Table {
                edition,
                ..Default::default()
            }
        }
        Some(text) => {
            let table = Table::parse(&text, &edition);
            log::log(&format!(
                "[ServiceDefaults] Loaded {} service defaults, {} of them managed by XOS, {} of those reserved for the Defender workflow, {} with a delayed automatic start.",
                table.defaults.len(),
                table.managed.len(),
                table.defender_managed.len(),
                table.delayed_every_build.len() + table.delayed.len()
            ));
            table
        }
    }
}

fn with<T>(f: impl FnOnce(&Table) -> T) -> T {
    let mut guard = STATE.lock().unwrap_or_else(|e| e.into_inner());
    if guard.is_none() {
        *guard = Some(load());
    }
    f(guard.as_ref().expect("loaded"))
}

pub fn is_loaded() -> bool {
    with(|t| t.count() > 0)
}

pub fn count() -> usize {
    with(|t| t.count())
}

pub fn managed_count() -> usize {
    with(|t| t.managed.len())
}

pub fn defender_managed_count() -> usize {
    with(|t| t.defender_managed.len())
}

pub fn is_defender_managed(service_name: &str) -> bool {
    if service_name.trim().is_empty() {
        return false;
    }
    with(|t| t.defender_managed.contains(&key(service_name)))
}

pub fn get_start_type(service_name: &str, build_number: i32) -> i32 {
    if service_name.trim().is_empty() {
        return -1;
    }
    with(|t| t.get_start_type(service_name, build_number))
}

pub fn is_delayed_auto_start(service_name: &str, build_number: i32) -> bool {
    if service_name.trim().is_empty() {
        return false;
    }
    with(|t| t.is_delayed_auto_start(service_name, build_number))
}

pub fn get_managed_defaults(build_number: i32) -> Vec<(String, i32)> {
    with(|t| t.managed_defaults(build_number))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "# comment\r\n\
Foo\t3\t19041:4,22000/Core:2\t1\tdefender\t*\r\n\
Bar\t0x2\t\t1\t\t19041,22000\r\n\
Bad\t9\r\n\
Baz\tx\r\n\
\tshort\r\n\
Quux\t4\r\n\
foo\t1\r\n";

    #[test]
    fn parses_defaults_and_overrides() {
        let t = Table::parse(SAMPLE, "Core");
        assert_eq!(t.count(), 3);
        assert_eq!(t.get_start_type("FOO", 19041), 4);
        assert_eq!(t.get_start_type("Foo", 22000), 2);
        assert_eq!(t.get_start_type("Foo", 1), 1);
        assert_eq!(t.get_start_type("Bar", 1), 2);
        assert_eq!(t.get_start_type("Bad", 1), -1);
        assert_eq!(t.get_start_type("", 1), -1);
        let pro = Table::parse(SAMPLE, "Professional");
        assert_eq!(pro.get_start_type("Foo", 22000), 1);
        assert_eq!(pro.get_start_type("Foo", 19041), 4);
    }

    #[test]
    fn edition_override_applies_only_for_matching_edition() {
        let text = "Svc\t3\t22000/Core:2,22000:4\t1\n";
        assert_eq!(Table::parse(text, "core").get_start_type("Svc", 22000), 2);
        assert_eq!(Table::parse(text, "Pro").get_start_type("Svc", 22000), 4);
        assert_eq!(Table::parse(text, "").get_start_type("Svc", 22000), 4);
    }

    #[test]
    fn managed_defender_and_delayed_flags() {
        let t = Table::parse(
            "A\t2\t\t1\tdefender\t*\nB\t2\t\t1\t\t19041\nC\t3\t\t0\n",
            "",
        );
        assert_eq!(t.managed.len(), 2);
        assert_eq!(t.defender_managed.len(), 1);
        assert!(t.is_delayed_auto_start("a", 1));
        assert!(t.is_delayed_auto_start("B", 19041));
        assert!(!t.is_delayed_auto_start("B", 22000));
        assert!(!t.is_delayed_auto_start("C", 19041));
        assert_eq!(
            t.managed_defaults(1),
            vec![("A".to_string(), 2), ("B".to_string(), 2)]
        );
    }

    #[test]
    fn start_type_parsing_rules() {
        assert_eq!(try_parse_start_type(" 0X4 "), Some(4));
        assert_eq!(try_parse_start_type("5"), None);
        assert_eq!(try_parse_start_type("-1"), None);
        assert_eq!(try_parse_start_type("0x"), None);
        assert_eq!(try_parse_start_type(""), None);
    }
}

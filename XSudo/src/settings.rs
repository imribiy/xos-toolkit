use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Show {
    Normal,
    Hidden,
    Minimized,
    Maximized,
}

impl Show {
    pub const ALL: [Show; 4] = [Show::Normal, Show::Hidden, Show::Minimized, Show::Maximized];

    pub fn name(self) -> &'static str {
        match self {
            Show::Normal => "Normal",
            Show::Hidden => "Hidden",
            Show::Minimized => "Minimized",
            Show::Maximized => "Maximized",
        }
    }

    pub fn parse(text: &str) -> Option<Show> {
        let t = text.trim();
        Show::ALL
            .into_iter()
            .find(|s| s.name().eq_ignore_ascii_case(t))
    }

    pub fn sw(self) -> u16 {
        match self {
            Show::Normal => 1,
            Show::Hidden => 0,
            Show::Minimized => 2,
            Show::Maximized => 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub file: String,
    pub params: String,
    pub start_dir: String,
    pub show: Show,
}

impl Entry {
    pub fn new(file: &str) -> Entry {
        Entry {
            file: file.to_string(),
            params: String::new(),
            start_dir: String::new(),
            show: Show::Normal,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Placement {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
    pub maximized: bool,
    pub dpi: u32,
}

impl Placement {
    pub fn scaled_to(self, dpi: u32) -> Placement {
        if self.dpi == 0 || dpi == 0 || self.dpi == dpi {
            return Placement { dpi, ..self };
        }
        let w = (self.right - self.left) as i64 * dpi as i64 / self.dpi as i64;
        let h = (self.bottom - self.top) as i64 * dpi as i64 / self.dpi as i64;
        Placement {
            right: self.left + w as i32,
            bottom: self.top + h as i32,
            dpi,
            ..self
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Settings {
    pub entries: Vec<Entry>,
    pub placement: Option<Placement>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Loaded {
    Missing,
    Damaged,
    Ok(Settings),
}

pub fn examples() -> Vec<Entry> {
    vec![
        Entry::new("%SystemRoot%\\System32\\cmd.exe"),
        Entry::new("%SystemRoot%\\regedit.exe"),
    ]
}

pub fn decode(bytes: &[u8]) -> Option<String> {
    let text = if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE {
        let body = &bytes[2..];
        if !body.len().is_multiple_of(2) {
            return None;
        }
        let units: Vec<u16> = body
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        String::from_utf16(&units).ok()?
    } else if bytes.len() >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF {
        return None;
    } else {
        let body = if bytes.len() >= 3 && bytes[..3] == [0xEF, 0xBB, 0xBF] {
            &bytes[3..]
        } else {
            bytes
        };
        String::from_utf8(body.to_vec()).ok()?
    };
    if text.contains('\0') {
        return None;
    }
    Some(text)
}

fn parse_bool(v: &str) -> bool {
    matches!(v.trim(), "1" | "true" | "True" | "TRUE" | "yes")
}

fn is_program_section(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    match lower.strip_prefix("program") {
        Some(rest) => !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()),
        None => false,
    }
}

enum Section {
    None,
    Window,
    Program(usize),
    Other,
}

pub fn parse(text: &str) -> Option<Settings> {
    let mut settings = Settings::default();
    let mut rows: Vec<(String, String, String, Option<Show>)> = Vec::new();
    let mut window: [Option<i32>; 4] = [None; 4];
    let mut maximized = false;
    let mut dpi = 0u32;
    let mut section = Section::None;
    for raw in text.split('\n') {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with(';') || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with('[') {
            if !trimmed.ends_with(']') || trimmed.len() < 3 {
                return None;
            }
            let name = trimmed[1..trimmed.len() - 1].trim();
            section = if name.eq_ignore_ascii_case("window") {
                Section::Window
            } else if is_program_section(name) {
                rows.push((String::new(), String::new(), String::new(), None));
                Section::Program(rows.len() - 1)
            } else {
                Section::Other
            };
            continue;
        }
        let eq = line.find('=')?;
        let key = line[..eq].trim().to_ascii_lowercase();
        let value = &line[eq + 1..];
        if key.is_empty() {
            return None;
        }
        match section {
            Section::None => return None,
            Section::Other => {}
            Section::Window => {
                let slot = match key.as_str() {
                    "left" => Some(0),
                    "top" => Some(1),
                    "right" => Some(2),
                    "bottom" => Some(3),
                    _ => None,
                };
                if let Some(i) = slot {
                    window[i] = Some(value.trim().parse().ok()?);
                } else if key == "maximized" {
                    maximized = parse_bool(value);
                } else if key == "dpi" {
                    dpi = value.trim().parse().ok()?;
                }
            }
            Section::Program(i) => {
                let row = &mut rows[i];
                match key.as_str() {
                    "file" => row.0 = value.to_string(),
                    "parameters" => row.1 = value.to_string(),
                    "startdirectory" => row.2 = value.to_string(),
                    "window" => row.3 = Show::parse(value),
                    _ => {}
                }
            }
        }
    }
    for (file, params, start_dir, show) in rows {
        if file.trim().is_empty() {
            continue;
        }
        settings.entries.push(Entry {
            file,
            params,
            start_dir,
            show: show.unwrap_or(Show::Normal),
        });
    }
    if let [Some(left), Some(top), Some(right), Some(bottom)] = window {
        if right > left && bottom > top {
            settings.placement = Some(Placement {
                left,
                top,
                right,
                bottom,
                maximized,
                dpi,
            });
        }
    }
    Some(settings)
}

fn one_line(s: &str) -> String {
    s.replace(['\r', '\n'], " ")
}

pub fn render(settings: &Settings) -> String {
    let mut out = String::new();
    if let Some(p) = settings.placement {
        out.push_str("[Window]\r\n");
        out.push_str(&format!("Left={}\r\n", p.left));
        out.push_str(&format!("Top={}\r\n", p.top));
        out.push_str(&format!("Right={}\r\n", p.right));
        out.push_str(&format!("Bottom={}\r\n", p.bottom));
        out.push_str(&format!(
            "Maximized={}\r\n",
            if p.maximized { 1 } else { 0 }
        ));
        if p.dpi != 0 {
            out.push_str(&format!(
                "Dpi={}
",
                p.dpi
            ));
        }
        out.push_str("\r\n");
    }
    for (i, e) in settings.entries.iter().enumerate() {
        out.push_str(&format!("[Program{}]\r\n", i + 1));
        out.push_str(&format!("File={}\r\n", one_line(&e.file)));
        out.push_str(&format!("Parameters={}\r\n", one_line(&e.params)));
        out.push_str(&format!("StartDirectory={}\r\n", one_line(&e.start_dir)));
        out.push_str(&format!("Window={}\r\n", e.show.name()));
        out.push_str("\r\n");
    }
    out
}

pub fn encode(text: &str) -> Vec<u8> {
    let mut bytes = vec![0xEF, 0xBB, 0xBF];
    bytes.extend_from_slice(text.as_bytes());
    bytes
}

pub fn load_from(path: &std::path::Path) -> Loaded {
    match std::fs::read(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Loaded::Missing,
        Err(_) => Loaded::Damaged,
        Ok(bytes) => match decode(&bytes).and_then(|t| parse(&t)) {
            Some(s) => Loaded::Ok(s),
            None => Loaded::Damaged,
        },
    }
}

pub fn save_to(path: &std::path::Path, settings: &Settings) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    std::fs::write(&tmp, encode(&render(settings)))?;
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

pub fn default_path() -> Option<PathBuf> {
    let appdata = std::env::var_os("APPDATA")?;
    if appdata.is_empty() {
        return None;
    }
    let mut p = PathBuf::from(appdata);
    p.push("XSudo");
    p.push("XSudo.ini");
    Some(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Settings {
        Settings {
            entries: vec![
                Entry {
                    file: "%SystemRoot%\\System32\\cmd.exe".into(),
                    params: "/c whoami /groups > \"C:\\x y\\out.txt\"".into(),
                    start_dir: "%TEMP%".into(),
                    show: Show::Hidden,
                },
                Entry {
                    file: "C:\\Tools\\a=b.bat".into(),
                    params: "  two  spaces ".into(),
                    start_dir: String::new(),
                    show: Show::Maximized,
                },
                Entry::new("C:\\Program Files\\\u{4e2d}\u{6587}\\app.exe"),
            ],
            placement: Some(Placement {
                left: -1200,
                top: 40,
                right: -200,
                bottom: 700,
                maximized: true,
                dpi: 144,
            }),
        }
    }

    #[test]
    fn round_trip_utf8_bom() {
        let s = sample();
        let bytes = encode(&render(&s));
        assert_eq!(&bytes[..3], &[0xEF, 0xBB, 0xBF]);
        let back = parse(&decode(&bytes).unwrap()).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn round_trip_utf16_input() {
        let s = sample();
        let text = render(&s);
        let mut bytes = vec![0xFF, 0xFE];
        for u in text.encode_utf16() {
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        assert_eq!(parse(&decode(&bytes).unwrap()).unwrap(), s);
    }

    #[test]
    fn utf8_without_bom_and_lf_lines() {
        let t = "[Program1]\nFile=cmd.exe\nWindow=minimized\n";
        let s = parse(&decode(t.as_bytes()).unwrap()).unwrap();
        assert_eq!(s.entries.len(), 1);
        assert_eq!(s.entries[0].show, Show::Minimized);
        assert!(s.placement.is_none());
    }

    #[test]
    fn order_follows_the_file_not_the_number() {
        let t = "[Program9]\r\nFile=b.exe\r\n[Program2]\r\nFile=a.exe\r\n";
        let s = parse(t).unwrap();
        assert_eq!(s.entries[0].file, "b.exe");
        assert_eq!(s.entries[1].file, "a.exe");
    }

    #[test]
    fn rows_without_file_are_dropped_and_unknown_window_is_normal() {
        let t = "[Program1]\r\nParameters=x\r\n[Program2]\r\nFile=c.exe\r\nWindow=Sideways\r\n[Other]\r\nFile=z.exe\r\n";
        let s = parse(t).unwrap();
        assert_eq!(s.entries.len(), 1);
        assert_eq!(s.entries[0].show, Show::Normal);
    }

    #[test]
    fn damaged_text_is_rejected() {
        for t in [
            "garbage line\r\n",
            "File=x.exe\r\n",
            "[Program1\r\nFile=x\r\n",
            "[]\r\n",
            "[Window]\r\nLeft=abc\r\n",
            "[Program1]\r\n=value\r\n",
        ] {
            assert!(parse(t).is_none(), "{t:?}");
        }
    }

    #[test]
    fn damaged_bytes_are_rejected() {
        assert!(decode(&[0xFF, 0xFE, 0x41]).is_none());
        assert!(decode(&[0xFE, 0xFF, 0x00, 0x41]).is_none());
        assert!(decode(&[0xC3, 0x28, 0x41]).is_none());
        assert!(decode(b"[Program1]\0File=x").is_none());
        let lone_surrogate = [0xFF, 0xFE, 0x00, 0xD8, 0x41, 0x00];
        assert!(decode(&lone_surrogate).is_none());
    }

    #[test]
    fn empty_file_is_an_empty_list() {
        assert_eq!(parse(&decode(&[]).unwrap()).unwrap(), Settings::default());
        assert_eq!(
            parse(&decode(&[0xEF, 0xBB, 0xBF]).unwrap()).unwrap(),
            Settings::default()
        );
    }

    #[test]
    fn newline_in_value_is_flattened() {
        let mut s = Settings::default();
        s.entries.push(Entry {
            file: "a.exe".into(),
            params: "x\r\ny".into(),
            start_dir: String::new(),
            show: Show::Normal,
        });
        let back = parse(&render(&s)).unwrap();
        assert_eq!(back.entries[0].params, "x  y");
    }

    #[test]
    fn invalid_placement_is_ignored() {
        let t = "[Window]\r\nLeft=10\r\nTop=10\r\nRight=5\r\nBottom=50\r\n";
        assert!(parse(t).unwrap().placement.is_none());
        let t = "[Window]\r\nLeft=10\r\nTop=10\r\n";
        assert!(parse(t).unwrap().placement.is_none());
    }

    fn scratch(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("xsudo-test-{}-{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    #[test]
    fn missing_file_loads_as_missing() {
        let dir = scratch("missing");
        assert_eq!(load_from(&dir.join("XSudo.ini")), Loaded::Missing);
    }

    #[test]
    fn save_and_load_through_disk_atomically() {
        let dir = scratch("disk");
        let path = dir.join("XSudo").join("XSudo.ini");
        let s = sample();
        save_to(&path, &s).unwrap();
        assert!(!path.with_extension("ini.tmp").exists());
        assert_eq!(load_from(&path), Loaded::Ok(s.clone()));
        let mut s2 = s.clone();
        s2.entries.remove(0);
        save_to(&path, &s2).unwrap();
        assert_eq!(load_from(&path), Loaded::Ok(s2));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn damaged_file_on_disk_loads_as_damaged() {
        let dir = scratch("damaged");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("XSudo.ini");
        std::fs::write(&path, [0x4D, 0x5A, 0x90, 0x00, 0x03, 0xFF, 0xFE]).unwrap();
        assert_eq!(load_from(&path), Loaded::Damaged);
        std::fs::write(&path, b"not an ini file at all\r\n").unwrap();
        assert_eq!(load_from(&path), Loaded::Damaged);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn placement_scales_to_the_new_dpi() {
        let p = Placement {
            left: 100,
            top: 50,
            right: 880,
            bottom: 510,
            maximized: false,
            dpi: 96,
        };
        let q = p.scaled_to(144);
        assert_eq!(
            (q.left, q.top, q.right, q.bottom, q.dpi),
            (100, 50, 1270, 740, 144)
        );
        assert_eq!(p.scaled_to(96), p);
        let unknown = Placement { dpi: 0, ..p };
        assert_eq!(unknown.scaled_to(144).right, 880);
        let t = "[Window]
Left=1
Top=2
Right=30
Bottom=40
";
        assert_eq!(parse(t).unwrap().placement.unwrap().dpi, 0);
    }

    #[test]
    fn show_values() {
        for s in Show::ALL {
            assert_eq!(Show::parse(s.name()), Some(s));
            assert_eq!(Show::parse(&s.name().to_ascii_uppercase()), Some(s));
        }
        assert_eq!(Show::Hidden.sw(), 0);
        assert_eq!(Show::Normal.sw(), 1);
    }
}

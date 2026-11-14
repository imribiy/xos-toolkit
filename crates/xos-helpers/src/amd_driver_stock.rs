use std::collections::HashMap;
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StockValue {
    Unsupported,
    Dword(i32),
    Str(String),
}

#[derive(Clone, Debug)]
pub struct AmdDriverStock {
    values: HashMap<String, StockValue>,
    pub inf_file: String,
    pub section: String,
    pub missing_sections: String,
}

type Sections = HashMap<String, Vec<String>>;

impl AmdDriverStock {
    pub fn count(&self) -> usize {
        self.values.len()
    }

    pub fn try_get(&self, name: &str) -> Option<&StockValue> {
        self.values.get(&name.to_uppercase())
    }

    pub fn load(class_key_path: &str) -> Result<AmdDriverStock, String> {
        let inf_name = xos_sys::reg_get_string(class_key_path, "InfPath");
        let section_name = xos_sys::reg_get_string(class_key_path, "InfSection");
        let section_ext =
            xos_sys::reg_get_string(class_key_path, "InfSectionExt").unwrap_or_default();
        let (inf_name, section_name) = match (inf_name, section_name) {
            (Some(i), Some(s)) if !i.trim().is_empty() && !s.trim().is_empty() => (i, s),
            _ => return Err("the GPU key has no InfPath or InfSection".to_string()),
        };
        let windows = std::env::var("SystemRoot")
            .or_else(|_| std::env::var("windir"))
            .unwrap_or_else(|_| r"C:\Windows".to_string());
        let inf_file = Path::new(&windows)
            .join("INF")
            .join(inf_name.trim())
            .to_string_lossy()
            .into_owned();
        if !Path::new(&inf_file).is_file() {
            return Err(format!("{inf_file} is not present"));
        }
        let bytes = std::fs::read(&inf_file).map_err(|e| format!("IOException: {e}"))?;
        Self::from_inf_text(&decode_text(&bytes), &inf_name, &section_name, &section_ext)
    }

    pub fn from_inf_text(
        text: &str,
        inf_name: &str,
        section_name: &str,
        section_ext: &str,
    ) -> Result<AmdDriverStock, String> {
        let sections = read_sections(text);
        let strings = read_strings(&sections);
        let install_name = format!("{}{}", section_name.trim(), section_ext.trim());
        let install = match sections
            .get(&install_name.to_uppercase())
            .or_else(|| sections.get(&section_name.trim().to_uppercase()))
        {
            Some(i) => i,
            None => return Err(format!("section [{install_name}] is not in {}", inf_name)),
        };

        let mut add_sections: Vec<String> = Vec::new();
        for line in install {
            let equals = match line.find('=') {
                Some(e) if e > 0 => e,
                _ => continue,
            };
            if !line[..equals].trim().eq_ignore_ascii_case("AddReg") {
                continue;
            }
            for name in line[equals + 1..].split(',') {
                if !name.trim().is_empty() {
                    add_sections.push(name.trim().to_string());
                }
            }
        }

        let mut values: HashMap<String, StockValue> = HashMap::new();
        let mut missing: Vec<String> = Vec::new();
        for name in &add_sections {
            let lines = match sections.get(&name.to_uppercase()) {
                Some(l) => l,
                None => {
                    missing.push(name.clone());
                    continue;
                }
            };
            for line in lines {
                let fields = split_fields(line, &strings);
                if fields.len() < 3 || !is_software_key_root(&fields) || fields[2].is_empty() {
                    continue;
                }
                let k = fields[2].to_uppercase();
                let flag_text = if fields.len() > 3 {
                    fields[3].as_str()
                } else {
                    ""
                };
                let flags = if flag_text.is_empty() {
                    Some(0)
                } else {
                    parse_number(flag_text)
                };
                let flags = match flags {
                    Some(f) => f,
                    None => {
                        values.insert(k, StockValue::Unsupported);
                        continue;
                    }
                };
                if flags & 0x4 != 0 {
                    values.remove(&k);
                    continue;
                }
                let kind = flags & 0xFFFF_0001;
                let data = if fields.len() > 4 {
                    fields[4].as_str()
                } else {
                    ""
                };
                if kind == 0x0001_0001 {
                    values.insert(
                        k,
                        match parse_number(data) {
                            Some(n) => StockValue::Dword(n as i32),
                            None => StockValue::Unsupported,
                        },
                    );
                } else if kind == 0 {
                    values.insert(k, StockValue::Str(data.to_string()));
                } else {
                    values.insert(k, StockValue::Unsupported);
                }
            }
        }
        if values.is_empty() {
            return Err(format!(
                "section [{install_name}] in {inf_name} gives no software-key values"
            ));
        }
        Ok(AmdDriverStock {
            values,
            inf_file: inf_name.trim().to_string(),
            section: install_name,
            missing_sections: missing.join(", "),
        })
    }
}

fn decode_text(bytes: &[u8]) -> String {
    if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE {
        let units: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        return String::from_utf16_lossy(&units);
    }
    if bytes.len() >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF {
        let units: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        return String::from_utf16_lossy(&units);
    }
    let body = if bytes.len() >= 3 && bytes[..3] == [0xEF, 0xBB, 0xBF] {
        &bytes[3..]
    } else {
        bytes
    };
    String::from_utf8_lossy(body).into_owned()
}

fn is_software_key_root(fields: &[String]) -> bool {
    fields[0].eq_ignore_ascii_case("HKR") && fields[1].is_empty()
}

fn read_sections(text: &str) -> Sections {
    let mut sections: Sections = HashMap::new();
    let mut current: Option<String> = None;
    let mut pending = String::new();
    let normalized = text.replace("\r\n", "\n").replace('\r', "\n");
    for raw in normalized.split('\n') {
        let line = format!("{pending}{}", strip_comment(raw).trim());
        pending.clear();
        if line.ends_with('\\') {
            pending = line[..line.len() - 1].to_string();
            continue;
        }
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            let name = line[1..line.len() - 1].trim().to_uppercase();
            sections.entry(name.clone()).or_default();
            current = Some(name);
            continue;
        }
        if let Some(c) = &current {
            sections.get_mut(c).expect("section").push(line);
        }
    }
    sections
}

fn strip_comment(line: &str) -> &str {
    let mut quoted = false;
    for (i, c) in line.char_indices() {
        if c == '"' {
            quoted = !quoted;
        } else if c == ';' && !quoted {
            return &line[..i];
        }
    }
    line
}

fn read_strings(sections: &Sections) -> HashMap<String, String> {
    let mut strings = HashMap::new();
    if let Some(lines) = sections.get("STRINGS") {
        for line in lines {
            let equals = match line.find('=') {
                Some(e) if e > 0 => e,
                _ => continue,
            };
            strings.insert(
                line[..equals].trim().to_uppercase(),
                unquote(line[equals + 1..].trim()),
            );
        }
    }
    strings
}

fn split_fields(line: &str, strings: &HashMap<String, String>) -> Vec<String> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    for c in line.chars() {
        if c == '"' {
            quoted = !quoted;
            field.push(c);
        } else if c == ',' && !quoted {
            fields.push(resolve(field.trim(), strings));
            field.clear();
        } else {
            field.push(c);
        }
    }
    fields.push(resolve(field.trim(), strings));
    fields
}

fn resolve(field: &str, strings: &HashMap<String, String>) -> String {
    if field.chars().count() > 2 && field.starts_with('%') && field.ends_with('%') {
        if let Some(v) = strings.get(&field[1..field.len() - 1].to_uppercase()) {
            return v.clone();
        }
    }
    unquote(field)
}

fn unquote(text: &str) -> String {
    if text.len() >= 2 && text.starts_with('"') && text.ends_with('"') {
        text[1..text.len() - 1].to_string()
    } else {
        text.to_string()
    }
}

fn parse_number(text: &str) -> Option<u32> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    if text.len() >= 2 && text[..2].eq_ignore_ascii_case("0x") {
        let rest = text[2..].trim();
        if rest.is_empty() || !rest.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        return u32::from_str_radix(rest, 16).ok();
    }
    let digits = text.strip_prefix('+').unwrap_or(text);
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    digits.parse::<u32>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const INF: &str = "[Version]\r\nSignature=\"$Windows NT$\"\r\n\
[Install_Section.ext]\r\nAddReg=a, b ; comment\r\n\
[a]\r\nHKR,,DalFoo,%REG_DWORD%,0x10\r\nHKR,,Name,,\"Some, Name\"\r\nHKR,,Gone,%REG_DWORD%,1\r\nHKR,Sub,Skip,0x10001,1\r\nHKR,,Bin,0x1,00\r\n\
[b]\r\nHKR,,Gone,0x4\r\nHKR,,Long,%REG_DWORD%,\\\r\n 7\r\n\
[Strings]\r\nREG_DWORD=0x00010001\r\n";

    #[test]
    fn parses_software_key_values() {
        let stock =
            AmdDriverStock::from_inf_text(INF, " x.inf ", "Install_Section", ".ext").unwrap();
        assert_eq!(stock.inf_file, "x.inf");
        assert_eq!(stock.section, "Install_Section.ext");
        assert_eq!(stock.missing_sections, "");
        assert_eq!(stock.try_get("dalfoo"), Some(&StockValue::Dword(16)));
        assert_eq!(
            stock.try_get("NAME"),
            Some(&StockValue::Str("Some, Name".into()))
        );
        assert_eq!(stock.try_get("Gone"), None);
        assert_eq!(stock.try_get("Skip"), None);
        assert_eq!(stock.try_get("Bin"), Some(&StockValue::Unsupported));
        assert_eq!(stock.try_get("Long"), Some(&StockValue::Dword(7)));
        assert_eq!(stock.count(), 4);
    }

    #[test]
    fn reports_missing_sections_and_errors() {
        let text = "[Inst]\nAddReg=a,nope\n[a]\nHKR,,V,0x10001,1\n";
        let stock = AmdDriverStock::from_inf_text(text, "y.inf", "Inst", "").unwrap();
        assert_eq!(stock.missing_sections, "nope");
        assert_eq!(
            AmdDriverStock::from_inf_text(text, "y.inf", "Other", "").unwrap_err(),
            "section [Other] is not in y.inf"
        );
        let empty = "[Inst]\nAddReg=a\n[a]\nHKLM,,V,0x10001,1\n";
        assert_eq!(
            AmdDriverStock::from_inf_text(empty, "z.inf", "Inst", "").unwrap_err(),
            "section [Inst] in z.inf gives no software-key values"
        );
    }

    #[test]
    fn falls_back_to_section_without_extension() {
        let text = "[Inst]\nAddReg=a\n[a]\nHKR,,V,0x10001,5\n";
        let stock = AmdDriverStock::from_inf_text(text, "y.inf", "Inst", ".NTamd64").unwrap();
        assert_eq!(stock.section, "Inst.NTamd64");
        assert_eq!(stock.try_get("v"), Some(&StockValue::Dword(5)));
    }
}

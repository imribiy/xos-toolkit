use std::sync::OnceLock;

use regex::Regex;

fn clixml_block() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?is)#<\s*CLIXML\s*(?:<Objs\b.*?(?:</Objs>|\z))?").unwrap())
}

fn clixml_text() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r#"(?is)<S S="(?:Error|Warning)">(.*?)</S>"#).unwrap())
}

fn clixml_escape() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"_x([0-9A-Fa-f]{4})_").unwrap())
}

pub(crate) fn empty_stderr_suffix() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"\s*\|\s*STDERR:\s*\z").unwrap())
}

fn clixml_position() -> &'static fancy_regex::Regex {
    static R: OnceLock<fancy_regex::Regex> = OnceLock::new();
    R.get_or_init(|| {
        fancy_regex::Regex::new(r"(?s)\s*At (?:line:\d+|\S+:\d+) char:\d+.*?(?=\+ CategoryInfo|\z)")
            .unwrap()
    })
}

fn whitespace() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"\s+").unwrap())
}

fn unescape_x(s: &str) -> String {
    let mut units: Vec<u16> = Vec::new();
    let mut last = 0;
    let mut out = String::new();
    for m in clixml_escape().captures_iter(s) {
        let whole = m.get(0).unwrap();
        if last < whole.start() {
            if !units.is_empty() {
                out.push_str(&String::from_utf16_lossy(&units));
                units.clear();
            }
            out.push_str(&s[last..whole.start()]);
        }
        let code = u16::from_str_radix(&m[1], 16).unwrap_or(0);
        units.push(code);
        last = whole.end();
    }
    if !units.is_empty() {
        out.push_str(&String::from_utf16_lossy(&units));
    }
    out.push_str(&s[last..]);
    out
}

pub(crate) fn html_decode(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let tail = &rest[i..];
        if let Some(semi) = tail.find(';') {
            let ent = &tail[1..semi];
            let decoded: Option<String> = match ent {
                "amp" => Some("&".into()),
                "lt" => Some("<".into()),
                "gt" => Some(">".into()),
                "quot" => Some("\"".into()),
                "apos" => Some("'".into()),
                "nbsp" => Some("\u{a0}".into()),
                _ if ent.starts_with("#x") || ent.starts_with("#X") => {
                    u32::from_str_radix(&ent[2..], 16)
                        .ok()
                        .and_then(char::from_u32)
                        .map(|c| c.to_string())
                }
                _ if ent.starts_with('#') => ent[1..]
                    .parse::<u32>()
                    .ok()
                    .and_then(char::from_u32)
                    .map(|c| c.to_string()),
                _ => None,
            };
            if let Some(d) = decoded {
                out.push_str(&d);
                rest = &tail[semi + 1..];
                continue;
            }
        }
        out.push('&');
        rest = &tail[1..];
    }
    out.push_str(rest);
    out
}

pub fn decode_clixml(text: &str) -> String {
    if text.is_empty() || !text.to_lowercase().contains("clixml") {
        return text.to_string();
    }
    clixml_block()
        .replace_all(text, |caps: &regex::Captures| {
            let block = &caps[0];
            let joined = clixml_text()
                .captures_iter(block)
                .map(|m| html_decode(&unescape_x(&m[1])).trim().to_string())
                .filter(|l| !l.is_empty())
                .collect::<Vec<_>>()
                .join(" ");
            clixml_position().replace_all(&joined, " ").to_string()
        })
        .to_string()
}

pub fn strip_clixml_noise(text: &str) -> String {
    if text.trim().is_empty() {
        return String::new();
    }
    let decoded = decode_clixml(text);
    let detail = empty_stderr_suffix().replace(&decoded, "").to_string();
    whitespace().replace_all(&detail, " ").trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_error_stream() {
        let raw = "#< CLIXML\r\n<Objs Version=\"1.1.0.1\" xmlns=\"http://schemas.microsoft.com/powershell/2004/04\"><S S=\"Error\">Boom_x000D__x000A_</S><S S=\"Error\">second &amp; third</S></Objs>";
        assert_eq!(decode_clixml(raw), "Boom second & third");
    }

    #[test]
    fn plain_text_is_untouched() {
        assert_eq!(decode_clixml("hello"), "hello");
        assert_eq!(strip_clixml_noise("a  b | STDERR: "), "a b");
    }

    #[test]
    fn html_entities() {
        assert_eq!(
            html_decode("a &lt;b&gt; &#65; &#x42; &bogus;"),
            "a <b> A B &bogus;"
        );
    }
}

use fancy_regex::{Captures, Regex as FRegex};
use regex::Regex;
use std::net::Ipv6Addr;
use std::path::Path;
use std::sync::OnceLock;
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
use winreg::RegKey;

fn fre(p: &str) -> FRegex {
    FRegex::new(p).expect("redaction pattern")
}

fn email() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}").unwrap()
    })
}

fn profile_path() -> &'static FRegex {
    static R: OnceLock<FRegex> = OnceLock::new();
    R.get_or_init(|| {
        fre(r#"(?i)([A-Za-z]:(?:\\{1,2}|/)Users(?:\\{1,2}|/))(?!(?:Public|Default|Default User|All Users)(?:[\\/"']|\n?\z))[^\\/:*?"<>|\s]+"#)
    })
}

fn domain_sid() -> &'static FRegex {
    static R: OnceLock<FRegex> = OnceLock::new();
    R.get_or_init(|| fre(r"(?<![\w-])S-1-5-21-\d+-\d+-\d+(?!\d)"))
}

fn cloud_sid() -> &'static FRegex {
    static R: OnceLock<FRegex> = OnceLock::new();
    R.get_or_init(|| fre(r"(?<![\w-])S-1-12-1-\d+-\d+-\d+-\d+(?!\d)"))
}

fn mac() -> &'static FRegex {
    static R: OnceLock<FRegex> = OnceLock::new();
    R.get_or_init(|| {
        fre(r"(?<![0-9A-Fa-f:-])[0-9A-Fa-f]{2}([:-])(?:[0-9A-Fa-f]{2}\1){4}(?:(?:[0-9A-Fa-f]{2}\1){2})?[0-9A-Fa-f]{2}(?![0-9A-Fa-f:-])")
    })
}

fn cbs_node() -> &'static FRegex {
    static R: OnceLock<FRegex> = OnceLock::new();
    R.get_or_init(|| {
        fre(r"(\b(?i:Transaction[ \t]+UoW:)[ \t]*\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-1[0-9A-Fa-f]{3}-[89ABab][0-9A-Fa-f]{3}-)[0-9A-Fa-f]{12}(?![0-9A-Za-z])")
    })
}

fn cisco_mac() -> &'static FRegex {
    static R: OnceLock<FRegex> = OnceLock::new();
    R.get_or_init(|| {
        fre(r"(?<![0-9A-Za-z.])(?=[0-9A-Fa-f.]{14}(?![0-9A-Za-z]|\.\d))(?=[0-9.]*[A-Fa-f])[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}(?![0-9A-Za-z]|\.\d)")
    })
}

fn duid() -> &'static FRegex {
    static R: OnceLock<FRegex> = OnceLock::new();
    R.get_or_init(|| fre(r"(?i)(DUID[^\r\n:=]*[:=][ \t]*)[0-9A-Fa-f]{2}(?:[ :-]?[0-9A-Fa-f]{2})+"))
}

fn hex_mac() -> &'static FRegex {
    static R: OnceLock<FRegex> = OnceLock::new();
    R.get_or_init(|| fre(r"(?<![0-9A-Za-z])0x[0-9A-Fa-f]{12}(?![0-9A-Za-z])"))
}

fn mac_label_line() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"(?im)^[^\r\n]*(?:Network ?Address|Mac ?Address|Physical ?Address|Permanent ?Address|Link ?Layer ?Address|Locally Administered|Physische Adresse|Adresse physique|Dirección física|物理地址)[^\r\n]*").unwrap()
    })
}

fn bare_mac() -> &'static FRegex {
    static R: OnceLock<FRegex> = OnceLock::new();
    R.get_or_init(|| {
        fre(r"(?<![0-9A-Za-z])[0-9A-Fa-f]{12}(?:[0-9A-Fa-f]{4})?(?![0-9A-Za-z])|(?<![0-9A-Za-z.])[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}(?![0-9A-Za-z.])")
    })
}

fn ipv6() -> &'static FRegex {
    static R: OnceLock<FRegex> = OnceLock::new();
    R.get_or_init(|| {
        fre(r"(?<![0-9A-Za-z:.])[0-9A-Fa-f:]{2,39}(?:%[0-9A-Za-z]+)?(?![0-9A-Za-z:]|\.\d)")
    })
}

fn ipv4() -> &'static FRegex {
    static R: OnceLock<FRegex> = OnceLock::new();
    R.get_or_init(|| fre(r"(?<![\w.~])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\d)"))
}

fn ipv4_exact() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^(?:\d{1,3}\.){3}\d{1,3}$").unwrap())
}

fn bare_hex_exact() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^[0-9A-Fa-f]{12}(?:[0-9A-Fa-f]{4})?$").unwrap())
}

const ADDRESS_VALUE_NAMES: &[&str] = &[
    "DhcpNameServer",
    "NameServer",
    "NameServerList",
    "DhcpServer",
    "DhcpIPAddress",
    "IPAddress",
    "DefaultGateway",
    "DhcpDefaultGateway",
    "DhcpSubnetMask",
    "SubnetMask",
    "DhcpSubnetMaskOpt",
    "DhcpGatewayHardware",
    "DhcpInterfaceOptions",
    "Dhcpv6DUID",
    "Dhcpv6DNSServers",
    "Dhcpv6DomainList",
    "NetworkAddress",
    "Hostname",
    "NV Hostname",
    "Domain",
    "NV Domain",
    "DhcpDomain",
    "SearchList",
    "DnsSuffixSearchList",
    "PrimaryDnsSuffix",
    "ICSDomain",
    "ScopeId",
    "DhcpDomainSearchList",
];

const GENERIC_NAMES: &[&str] = &[
    "Administrator",
    "Admin",
    "User",
    "Users",
    "Owner",
    "Guest",
    "Public",
    "Default",
    "Default User",
    "All Users",
    "System",
    "SYSTEM",
    "LOCAL SERVICE",
    "NETWORK SERVICE",
    "NT AUTHORITY",
    "TrustedInstaller",
    "WORKGROUP",
    "XOS",
    "Windows",
    "defaultuser0",
    "WDAGUtilityAccount",
];

struct Known {
    regex: Option<FRegex>,
    labels: Vec<(String, &'static str)>,
}

fn collect_known(
    machine: Option<String>,
    domain: Option<String>,
    user: Option<String>,
    profiles: Vec<String>,
) -> Known {
    let mut labels: Vec<(String, &'static str)> = Vec::new();
    let mut add = |name: Option<String>, label: &'static str| {
        let Some(name) = name else { return };
        let name = name.trim().to_string();
        if name.trim().is_empty() || name.chars().count() < 3 {
            return;
        }
        let lower = name.to_lowercase();
        if GENERIC_NAMES.iter().any(|g| g.to_lowercase() == lower) {
            return;
        }
        if labels.iter().any(|(n, _)| n.to_lowercase() == lower) {
            return;
        }
        labels.push((name, label));
    };
    add(machine, "<computer>");
    add(domain, "<domain>");
    add(user, "<user>");
    for p in profiles {
        add(Some(p), "<user>");
    }
    let regex = if labels.is_empty() {
        None
    } else {
        let mut names: Vec<&String> = labels.iter().map(|(n, _)| n).collect();
        names.sort_by(|a, b| b.chars().count().cmp(&a.chars().count()));
        let alt = names
            .iter()
            .map(|n| regex::escape(n))
            .collect::<Vec<_>>()
            .join("|");
        FRegex::new(&format!("(?i)(?<![A-Za-z0-9])(?:{alt})(?![A-Za-z0-9])")).ok()
    };
    Known { regex, labels }
}

fn profile_folder_names() -> Vec<String> {
    let mut names = Vec::new();
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let Ok(list) = hklm.open_subkey_with_flags(
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList",
        KEY_READ,
    ) else {
        return names;
    };
    for sid in list.enum_keys().flatten() {
        let up = sid.to_uppercase();
        if !up.starts_with("S-1-5-21-") && !up.starts_with("S-1-12-1-") {
            continue;
        }
        let Ok(profile) = list.open_subkey_with_flags(&sid, KEY_READ) else {
            continue;
        };
        let Ok(path) = profile.get_value::<String, _>("ProfileImagePath") else {
            continue;
        };
        if path.is_empty() {
            continue;
        }
        let trimmed = path.trim_end_matches(['\\', '/']);
        if let Some(leaf) = Path::new(trimmed).file_name().and_then(|s| s.to_str()) {
            if !leaf.is_empty() {
                names.push(leaf.to_string());
            }
        }
    }
    names
}

fn known() -> &'static Known {
    static K: OnceLock<Known> = OnceLock::new();
    K.get_or_init(|| {
        collect_known(
            std::env::var("COMPUTERNAME").ok(),
            std::env::var("USERDOMAIN").ok(),
            std::env::var("USERNAME").ok(),
            profile_folder_names(),
        )
    })
}

fn replace_caps(
    re: &FRegex,
    text: &str,
    f: &dyn Fn(&Captures<'_, str>) -> String,
) -> Option<String> {
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for caps in re.captures_iter(text) {
        let caps = caps.ok()?;
        let m = caps.get(0)?;
        out.push_str(&text[last..m.start()]);
        out.push_str(&f(&caps));
        last = m.end();
    }
    out.push_str(&text[last..]);
    Some(out)
}

fn replace_lit(re: &FRegex, text: &str, rep: &str) -> Option<String> {
    replace_caps(re, text, &|_| rep.to_string())
}

fn replace_group1(re: &FRegex, text: &str, suffix: &str) -> Option<String> {
    replace_caps(re, text, &|c| {
        format!("{}{}", c.get(1).map(|m| m.as_str()).unwrap_or(""), suffix)
    })
}

fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn is_gap(c: char) -> bool {
    !is_word(c) && c != '\r' && c != '\n'
}

fn ends_with_ci(chars: &[char], word: &str) -> bool {
    let w: Vec<char> = word.chars().collect();
    if chars.len() < w.len() {
        return false;
    }
    chars[chars.len() - w.len()..]
        .iter()
        .zip(w.iter())
        .all(|(a, b)| a.to_ascii_lowercase() == *b)
}

fn ver_token_before(head: &[char]) -> bool {
    ends_with_ci(head, "ver") && !(head.len() > 3 && head[head.len() - 4].is_ascii_alphabetic())
}

fn version_token_before(head: &[char]) -> bool {
    if ends_with_ci(head, "version")
        && !(head.len() > 7 && head[head.len() - 8].is_ascii_alphabetic())
    {
        return true;
    }
    if head.len() >= 8 && head[head.len() - 7..].iter().collect::<String>() == "Version" {
        return head[head.len() - 8].is_ascii_lowercase();
    }
    false
}

fn version_reg_before(prefix: &[char]) -> bool {
    let mut i = prefix.len();
    let mut spaces = 0;
    while i > 0 && prefix[i - 1].is_whitespace() && prefix[i - 1] != '\r' && prefix[i - 1] != '\n' {
        i -= 1;
        spaces += 1;
    }
    if spaces == 0 {
        return false;
    }
    let end = i;
    while i > 0 && is_word(prefix[i - 1]) {
        i -= 1;
    }
    let run = &prefix[i..end];
    if run.len() <= 4 || !ends_with_ci(&run[..4], "reg_") {
        return false;
    }
    let mut j = i;
    let mut spaces2 = 0;
    while j > 0 && prefix[j - 1].is_whitespace() && prefix[j - 1] != '\r' && prefix[j - 1] != '\n' {
        j -= 1;
        spaces2 += 1;
    }
    if spaces2 == 0 {
        return false;
    }
    version_token_before_ci(&prefix[..j])
}

fn version_token_before_ci(head: &[char]) -> bool {
    ends_with_ci(head, "version") && !(head.len() > 7 && head[head.len() - 8].is_ascii_alphabetic())
}

fn ipv4_exempt(prefix: &str) -> bool {
    let chars: Vec<char> = prefix.chars().collect();
    let tail_start = chars.len().saturating_sub(80);
    let tail = &chars[tail_start..];
    for gap in 0..=3usize {
        if gap > tail.len() {
            break;
        }
        let cut = tail.len() - gap;
        if tail[cut..].iter().all(|c| is_gap(*c)) && ver_token_before(&tail[..cut]) {
            return true;
        }
    }
    for gap in 0..=40usize {
        if gap > tail.len() {
            break;
        }
        let cut = tail.len() - gap;
        if tail[cut..].iter().all(|c| is_gap(*c)) && version_token_before(&tail[..cut]) {
            return true;
        }
    }
    let whole: Vec<char> = chars;
    version_reg_before(&whole)
}

fn redact_ipv4_all(text: &str) -> Option<String> {
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for m in ipv4().find_iter(text) {
        let m = m.ok()?;
        out.push_str(&text[last..m.start()]);
        if ipv4_exempt(&text[..m.start()]) {
            out.push_str(m.as_str());
        } else {
            out.push_str(&redact_ipv4_text(m.as_str(), false));
        }
        last = m.end();
    }
    out.push_str(&text[last..]);
    Some(out)
}

fn parse_ipv6(value: &str) -> Option<Ipv6Addr> {
    let (bare, zone) = match value.find('%') {
        Some(i) => (&value[..i], Some(&value[i + 1..])),
        None => (value, None),
    };
    if let Some(z) = zone {
        if z.is_empty() || !z.bytes().all(|b| b.is_ascii_digit()) || z.parse::<u32>().is_err() {
            return None;
        }
    }
    bare.parse::<Ipv6Addr>().ok()
}

fn is_link_local(a: &Ipv6Addr) -> bool {
    (a.segments()[0] & 0xffc0) == 0xfe80
}

fn redact_ipv6(value: &str) -> String {
    let colons = value.chars().filter(|c| *c == ':').count();
    if colons < 2 || (colons < 7 && !value.contains("::")) {
        return value.to_string();
    }
    let Some(addr) = parse_ipv6(value) else {
        return value.to_string();
    };
    if addr == Ipv6Addr::LOCALHOST || addr == Ipv6Addr::UNSPECIFIED {
        return value.to_string();
    }
    if is_link_local(&addr) {
        "<ipv6-linklocal>"
    } else {
        "<ipv6>"
    }
    .to_string()
}

fn redact_ipv4_text(value: &str, named: bool) -> String {
    let parts: Vec<&str> = value.split('.').collect();
    let mut octets = [0i32; 4];
    for i in 0..4 {
        match parts.get(i).and_then(|p| p.parse::<i32>().ok()) {
            Some(v) if v <= 255 => octets[i] = v,
            _ => {
                return if named {
                    "<set>".to_string()
                } else {
                    value.to_string()
                }
            }
        }
    }
    if octets[0] == 0 || octets[0] == 127 || octets[0] == 255 || (!named && octets[3] == 0) {
        return value.to_string();
    }
    if octets[0] == 169 && octets[1] == 254 {
        return "<ipv4-linklocal>".to_string();
    }
    if octets[0] == 10
        || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 168)
    {
        return "<ipv4-private>".to_string();
    }
    "<ipv4>".to_string()
}

fn redact_inner(text: &mut String) {
    *text = email().replace_all(text, "<email>").into_owned();
    let k = known();
    if let Some(re) = &k.regex {
        match replace_caps(re, text, &|c| {
            let v = c.get(0).map(|m| m.as_str()).unwrap_or("");
            let lower = v.to_lowercase();
            k.labels
                .iter()
                .find(|(n, _)| n.to_lowercase() == lower)
                .map(|(_, l)| *l)
                .unwrap_or("<user>")
                .to_string()
        }) {
            Some(s) => *text = s,
            None => return,
        }
    }
    let steps: [&dyn Fn(&str) -> Option<String>; 7] = [
        &|t| replace_group1(profile_path(), t, "<user>"),
        &|t| replace_lit(domain_sid(), t, "S-1-5-21-<machine>"),
        &|t| replace_lit(cloud_sid(), t, "S-1-12-1-<account>"),
        &|t| replace_group1(duid(), t, "<duid>"),
        &|t| replace_group1(cbs_node(), t, "<node>"),
        &|t| replace_lit(mac(), t, "<mac>"),
        &|t| replace_lit(hex_mac(), t, "<mac>"),
    ];
    for step in steps {
        match step(text) {
            Some(s) => *text = s,
            None => return,
        }
    }
    match replace_lit(cisco_mac(), text, "<mac>") {
        Some(s) => *text = s,
        None => return,
    }
    let mut failed = false;
    let labelled = mac_label_line()
        .replace_all(text, |c: &regex::Captures| {
            match replace_lit(bare_mac(), &c[0], "<mac>") {
                Some(s) => s,
                None => {
                    failed = true;
                    c[0].to_string()
                }
            }
        })
        .into_owned();
    if failed {
        return;
    }
    *text = labelled;
    match replace_caps(ipv6(), text, &|c| {
        redact_ipv6(c.get(0).map(|m| m.as_str()).unwrap_or(""))
    }) {
        Some(s) => *text = s,
        None => return,
    }
    if let Some(s) = redact_ipv4_all(text) {
        *text = s;
    }
}

pub fn redact(text: &str) -> String {
    if text.is_empty() {
        return text.to_string();
    }
    let mut work = text.to_string();
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| redact_inner(&mut work)));
    work
}

pub fn is_address_bearing_value(name: &str) -> bool {
    let n = name.trim();
    ADDRESS_VALUE_NAMES
        .iter()
        .any(|a| a.eq_ignore_ascii_case(n))
}

pub enum AddressValue {
    Absent,
    Number(String),
    Bytes(usize),
    Lines(Vec<String>),
    Text(String),
}

pub fn mask_address_value(value: &AddressValue) -> String {
    let joined = match value {
        AddressValue::Absent => return "(absent)".to_string(),
        AddressValue::Number(n) => return n.clone(),
        AddressValue::Bytes(0) => return "(empty)".to_string(),
        AddressValue::Bytes(n) => return format!("<set: {n} bytes>"),
        AddressValue::Lines(l) => l.join(" "),
        AddressValue::Text(t) => t.clone(),
    };
    let tokens: Vec<&str> = joined
        .split([' ', ',', ';', '|', '\t', '\r', '\n'])
        .filter(|t| !t.is_empty())
        .collect();
    if tokens.is_empty() {
        return "(empty)".to_string();
    }
    tokens
        .iter()
        .map(|t| mask_address_token(t))
        .collect::<Vec<_>>()
        .join(" | ")
}

fn fancy_is_match(re: &FRegex, t: &str) -> bool {
    re.is_match(t).unwrap_or(false)
}

fn mask_address_token(token: &str) -> String {
    let t = token.trim().trim_matches(['{', '}']);
    if ipv4_exact().is_match(t) {
        return redact_ipv4_text(t, true);
    }
    if fancy_is_match(mac(), t)
        || fancy_is_match(hex_mac(), t)
        || fancy_is_match(cisco_mac(), t)
        || bare_hex_exact().is_match(t)
    {
        return "<mac>".to_string();
    }
    let bare = match t.find('%') {
        Some(z) if z > 0 => &t[..z],
        _ => t,
    };
    if bare.contains(':') {
        if let Some(addr) = parse_ipv6(bare) {
            return if addr == Ipv6Addr::LOCALHOST || addr == Ipv6Addr::UNSPECIFIED {
                t.to_string()
            } else if is_link_local(&addr) {
                "<ipv6-linklocal>".to_string()
            } else {
                "<ipv6>".to_string()
            };
        }
    }
    "<set>".to_string()
}

#[derive(Clone, Copy, PartialEq)]
enum Enc {
    Utf8,
    Utf8Bom,
    Utf16Le,
    Utf16Be,
    Utf32Le,
    Utf32Be,
}

fn detect_encoding(bytes: &[u8]) -> (Enc, usize) {
    if bytes.starts_with(&[0xFF, 0xFE, 0x00, 0x00]) {
        (Enc::Utf32Le, 4)
    } else if bytes.starts_with(&[0x00, 0x00, 0xFE, 0xFF]) {
        (Enc::Utf32Be, 4)
    } else if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        (Enc::Utf8Bom, 3)
    } else if bytes.starts_with(&[0xFF, 0xFE]) {
        (Enc::Utf16Le, 2)
    } else if bytes.starts_with(&[0xFE, 0xFF]) {
        (Enc::Utf16Be, 2)
    } else {
        (Enc::Utf8, 0)
    }
}

fn decode(bytes: &[u8], enc: Enc) -> String {
    match enc {
        Enc::Utf8 | Enc::Utf8Bom => String::from_utf8_lossy(bytes).into_owned(),
        Enc::Utf16Le | Enc::Utf16Be => {
            let units: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|c| {
                    if enc == Enc::Utf16Le {
                        u16::from_le_bytes([c[0], c[1]])
                    } else {
                        u16::from_be_bytes([c[0], c[1]])
                    }
                })
                .collect();
            String::from_utf16_lossy(&units)
        }
        Enc::Utf32Le | Enc::Utf32Be => bytes
            .chunks_exact(4)
            .map(|c| {
                let v = if enc == Enc::Utf32Le {
                    u32::from_le_bytes([c[0], c[1], c[2], c[3]])
                } else {
                    u32::from_be_bytes([c[0], c[1], c[2], c[3]])
                };
                char::from_u32(v).unwrap_or('\u{FFFD}')
            })
            .collect(),
    }
}

fn encode(text: &str, enc: Enc) -> Vec<u8> {
    let mut out = Vec::new();
    match enc {
        Enc::Utf8 => out.extend_from_slice(text.as_bytes()),
        Enc::Utf8Bom => {
            out.extend_from_slice(&[0xEF, 0xBB, 0xBF]);
            out.extend_from_slice(text.as_bytes());
        }
        Enc::Utf16Le => {
            out.extend_from_slice(&[0xFF, 0xFE]);
            for u in text.encode_utf16() {
                out.extend_from_slice(&u.to_le_bytes());
            }
        }
        Enc::Utf16Be => {
            out.extend_from_slice(&[0xFE, 0xFF]);
            for u in text.encode_utf16() {
                out.extend_from_slice(&u.to_be_bytes());
            }
        }
        Enc::Utf32Le => {
            out.extend_from_slice(&[0xFF, 0xFE, 0, 0]);
            for c in text.chars() {
                out.extend_from_slice(&(c as u32).to_le_bytes());
            }
        }
        Enc::Utf32Be => {
            out.extend_from_slice(&[0, 0, 0xFE, 0xFF]);
            for c in text.chars() {
                out.extend_from_slice(&(c as u32).to_be_bytes());
            }
        }
    }
    out
}

fn read_lines(text: &str) -> Vec<&str> {
    let b = text.as_bytes();
    let mut lines = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\r' || b[i] == b'\n' {
            lines.push(&text[start..i]);
            if b[i] == b'\r' && i + 1 < b.len() && b[i + 1] == b'\n' {
                i += 1;
            }
            start = i + 1;
        }
        i += 1;
    }
    if start < b.len() {
        lines.push(&text[start..]);
    }
    lines
}

pub fn redact_file(source: &str, destination: &str) -> std::io::Result<()> {
    redact_file_filtered(source, destination, |_| true).map(|_| ())
}

pub fn redact_file_filtered(
    source: &str,
    destination: &str,
    mut keep: impl FnMut(&str) -> bool,
) -> std::io::Result<usize> {
    use std::io::Read;
    use std::os::windows::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(7)
        .open(source)?;
    let mut bytes = Vec::new();
    f.read_to_end(&mut bytes)?;
    drop(f);
    let (enc, skip) = detect_encoding(&bytes);
    let text = decode(&bytes[skip..], enc);
    let mut out = String::new();
    let mut dropped = 0;
    for line in read_lines(&text) {
        if !keep(line) {
            dropped += 1;
            continue;
        }
        out.push_str(&redact(line));
        out.push_str("\r\n");
    }
    std::fs::write(destination, encode(&out, enc))?;
    Ok(dropped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_rule() {
        assert_eq!(
            redact("mail bob.smith+x@example.co.uk now"),
            "mail <email> now"
        );
    }

    #[test]
    fn known_names_longest_first_and_labels() {
        let k = collect_known(
            Some("DESKTOP-ABC".into()),
            Some("CORP".into()),
            Some("alice".into()),
            vec!["alice2".into(), "Admin".into(), "ab".into(), "Guest".into()],
        );
        let labels: Vec<&str> = k.labels.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(labels, vec!["DESKTOP-ABC", "CORP", "alice", "alice2"]);
        let re = k.regex.unwrap();
        let out = replace_caps(&re, "alice2 and alice and ALICE and xalice", &|c| {
            let v = c.get(0).unwrap().as_str().to_lowercase();
            k.labels
                .iter()
                .find(|(n, _)| n.to_lowercase() == v)
                .unwrap()
                .1
                .to_string()
        })
        .unwrap();
        assert_eq!(out, "<user> and <user> and <user> and xalice");
    }

    #[test]
    fn profile_path_rule() {
        assert_eq!(
            redact(r"C:\Users\zzqtest9\AppData\x"),
            r"C:\Users\<user>\AppData\x"
        );
        assert_eq!(
            redact(r"C:\Users\Public\Documents"),
            r"C:\Users\Public\Documents"
        );
        assert_eq!(redact("c:/users/zzqtest9/x"), "c:/users/<user>/x");
        assert_eq!(redact(r"C:\\Users\\zzqtest9"), r"C:\\Users\\<user>");
    }

    #[test]
    fn sid_rules() {
        assert_eq!(
            redact("S-1-5-21-111-222-333-1001"),
            "S-1-5-21-<machine>-1001"
        );
        assert_eq!(redact("S-1-12-1-1-2-3-4"), "S-1-12-1-<account>");
        assert_eq!(redact("S-1-5-18"), "S-1-5-18");
    }

    #[test]
    fn mac_rules() {
        assert_eq!(redact("a 00-1A-2B-3C-4D-5E b"), "a <mac> b");
        assert_eq!(redact("a 00:1a:2b:3c:4d:5e:6f:70 b"), "a <mac> b");
        assert_eq!(redact("0x001A2B3C4D5E"), "<mac>");
        assert_eq!(redact("001a.2b3c.4d5e"), "<mac>");
        assert_eq!(
            redact("Physical Address. . . : 001A2B3C4D5E"),
            "Physical Address. . . : <mac>"
        );
        assert_eq!(
            redact("Physische Adresse: 001a2b3c4d5e"),
            "Physische Adresse: <mac>"
        );
        assert_eq!(redact("id 001A2B3C4D5E"), "id 001A2B3C4D5E");
    }

    #[test]
    fn duid_rule() {
        assert_eq!(
            redact("Client DUID: 00-01-00-01-2A-3B-4C-5D"),
            "Client DUID: <duid>"
        );
    }

    #[test]
    fn cbs_node_rule() {
        assert_eq!(
            redact("Transaction UoW: {01234567-89ab-1cde-8f01-aabbccddeeff}"),
            "Transaction UoW: {01234567-89ab-1cde-8f01-<node>}"
        );
    }

    #[test]
    fn ipv6_rules() {
        assert_eq!(redact("addr 2001:db8::1 end"), "addr <ipv6> end");
        assert_eq!(redact("addr fe80::1%12 end"), "addr <ipv6-linklocal> end");
        assert_eq!(redact("addr ::1 end"), "addr ::1 end");
        assert_eq!(redact("time 12:34:56 end"), "time 12:34:56 end");
    }

    #[test]
    fn ipv4_rules() {
        assert_eq!(redact("ip 192.168.1.20 x"), "ip <ipv4-private> x");
        assert_eq!(redact("ip 10.0.0.5"), "ip <ipv4-private>");
        assert_eq!(redact("ip 172.20.0.5"), "ip <ipv4-private>");
        assert_eq!(redact("ip 169.254.3.4"), "ip <ipv4-linklocal>");
        assert_eq!(redact("ip 8.8.8.8"), "ip <ipv4>");
        assert_eq!(redact("ip 127.0.0.1"), "ip 127.0.0.1");
        assert_eq!(redact("ip 8.8.8.0"), "ip 8.8.8.0");
        assert_eq!(redact("ip 999.1.1.1"), "ip 999.1.1.1");
        assert_eq!(redact("1.2.3.4.5"), "1.2.3.4.5");
    }

    #[test]
    fn version_exemptions() {
        assert_eq!(redact("version 8.8.8.8"), "version 8.8.8.8");
        assert_eq!(redact("Version: 8.8.8.8"), "Version: 8.8.8.8");
        assert_eq!(redact("ver=8.8.8.8"), "ver=8.8.8.8");
        assert_eq!(redact("DriverVersion 8.8.8.8"), "DriverVersion 8.8.8.8");
        assert_eq!(
            redact("driver 8.8.8.8"),
            "driver 8.8.8.8".replace("8.8.8.8", "<ipv4>")
        );
        assert_eq!(
            redact("version    REG_SZ    8.8.8.8"),
            "version    REG_SZ    8.8.8.8"
        );
        assert_eq!(
            redact("versions 8.8.8.8"),
            "versions 8.8.8.8".replace("8.8.8.8", "<ipv4>")
        );
    }

    #[test]
    fn address_bearing() {
        assert!(is_address_bearing_value(" nameserver "));
        assert!(is_address_bearing_value("Dhcpv6DUID"));
        assert!(!is_address_bearing_value("Start"));
    }

    #[test]
    fn mask_values() {
        assert_eq!(mask_address_value(&AddressValue::Absent), "(absent)");
        assert_eq!(mask_address_value(&AddressValue::Number("5".into())), "5");
        assert_eq!(mask_address_value(&AddressValue::Bytes(0)), "(empty)");
        assert_eq!(
            mask_address_value(&AddressValue::Bytes(6)),
            "<set: 6 bytes>"
        );
        assert_eq!(
            mask_address_value(&AddressValue::Text("  ".into())),
            "(empty)"
        );
        assert_eq!(
            mask_address_value(&AddressValue::Text(
                "192.168.1.1,8.8.8.8 0.0.0.0 fe80::1 2001:db8::2 {001A2B3C4D5E} host".into()
            )),
            "<ipv4-private> | <ipv4> | 0.0.0.0 | <ipv6-linklocal> | <ipv6> | <mac> | <set>"
        );
        assert_eq!(
            mask_address_value(&AddressValue::Lines(vec!["1.1.1.1".into(), "::1".into()])),
            "<ipv4> | ::1"
        );
    }

    #[test]
    fn redact_file_roundtrip_utf16() {
        let dir = std::env::temp_dir().join(format!("xos-redact-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("src.txt");
        let dst = dir.join("dst.txt");
        let src_s = src.to_str().unwrap();
        let dst_s = dst.to_str().unwrap();
        let mut bytes = vec![0xFF, 0xFE];
        for u in "ip 8.8.8.8\r\nsecond\n".encode_utf16() {
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        std::fs::write(&src, bytes).unwrap();
        redact_file(src_s, dst_s).unwrap();
        let out = std::fs::read(&dst).unwrap();
        assert_eq!(&out[..2], &[0xFF, 0xFE]);
        let units: Vec<u16> = out[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        assert_eq!(
            String::from_utf16(&units).unwrap(),
            "ip <ipv4>\r\nsecond\r\n"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

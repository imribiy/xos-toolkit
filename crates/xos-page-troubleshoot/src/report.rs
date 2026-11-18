use crate::regval;

pub const NEW_ISSUE_URL: &str = "https://github.com/imribiy/xos-playbook/issues/new";
pub const TEMPLATE: &str = "bug-report.yml";

pub fn encode_query_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len() * 3);
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

pub fn issue_url(toolkit_version: &str, windows: &str) -> String {
    format!(
        "{NEW_ISSUE_URL}?template={}&toolkit-version={}&windows={}",
        encode_query_value(TEMPLATE),
        encode_query_value(toolkit_version),
        encode_query_value(windows)
    )
}

pub fn windows_summary() -> String {
    let Some(key) = regval::open_hklm(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") else {
        return "Windows (version not readable)".to_string();
    };
    let get = |n: &str| regval::value_text(&key, n).unwrap_or_default();
    let build = get("CurrentBuildNumber");
    let mut product = get("ProductName");
    if product.is_empty() {
        product = "Windows".to_string();
    }
    if build.trim().parse::<i32>().is_ok_and(|n| n >= 22000)
        && product.to_lowercase().starts_with("windows 10")
    {
        product = format!("Windows 11{}", &product["Windows 10".len()..]);
    }
    let display = get("DisplayVersion");
    let ubr = get("UBR");
    let mut text = product;
    if !display.is_empty() {
        text.push(' ');
        text.push_str(&display);
    }
    if !build.is_empty() {
        text.push_str(", build ");
        text.push_str(build.trim());
        if !ubr.is_empty() {
            text.push('.');
            text.push_str(ubr.trim());
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_reserved_and_unicode() {
        assert_eq!(encode_query_value("0.4.3"), "0.4.3");
        assert_eq!(
            encode_query_value("Windows 11 Pro 25H2, build 26200.1&x=y"),
            "Windows%2011%20Pro%2025H2%2C%20build%2026200.1%26x%3Dy"
        );
        assert_eq!(encode_query_value("é"), "%C3%A9");
    }

    #[test]
    fn url_shape() {
        let url = issue_url("0.4.3", "Windows 11 Pro 25H2, build 26200.7171");
        assert_eq!(
            url,
            "https://github.com/imribiy/xos-playbook/issues/new?template=bug-report.yml\
             &toolkit-version=0.4.3&windows=Windows%2011%20Pro%2025H2%2C%20build%2026200.7171"
        );
    }

    #[test]
    fn summary_reads_registry() {
        let s = windows_summary();
        assert!(s.starts_with("Windows"), "{s}");
    }
}

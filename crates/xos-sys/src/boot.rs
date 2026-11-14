use crate::process::{run_cmd, run_cmd_capture};
use xos_core::{log, session_log};

pub fn bcd_edit(setting: &str, value: &str) -> bool {
    run_cmd("bcdedit.exe", &format!("/set {setting} {value}"))
}

pub(crate) fn find_bcd_value(output: &str, setting: &str) -> Option<String> {
    for line in output.split('\n') {
        let trimmed = line.trim();
        let n = setting.len();
        if trimmed.len() < n
            || !trimmed.is_char_boundary(n)
            || !trimmed[..n].to_lowercase().eq(&setting.to_lowercase())
        {
            continue;
        }
        return Some(trimmed[n..].trim().to_string());
    }
    None
}

pub fn get_bcd_setting(setting: &str) -> Option<String> {
    let result = run_cmd_capture("bcdedit.exe", "/enum {current}");
    find_bcd_value(&result.1, setting)
}

pub fn verify_bcd_setting(setting: &str, expected_value: &str) -> bool {
    let result = run_cmd_capture("bcdedit.exe", "/enum {current}");
    let expected = expected_value.trim();
    if let Some(actual) = find_bcd_value(&result.1, setting) {
        let matches = actual.to_lowercase() == expected.to_lowercase();
        log::log(&format!(
            "[BCD] {setting} reads '{actual}' after setting '{expected_value}': {}",
            if matches { "confirmed" } else { "NOT applied" }
        ));
        if !matches {
            session_log::operation_failed("bcd setting", &format!("{setting} reads '{actual}'"));
        }
        return matches;
    }
    log::log(&format!(
        "[BCD] {setting} does not appear in the current boot entry after setting '{expected_value}' (exit={}). Not treated as a failure.",
        result.0
    ));
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "Windows Boot Loader\r\n-------------------\r\nidentifier              {current}\r\ndevice                  partition=C:\r\nnx                      OptIn\r\nuseplatformtick         Yes\r\n";

    #[test]
    fn reads_values() {
        assert_eq!(
            find_bcd_value(SAMPLE, "useplatformtick").as_deref(),
            Some("Yes")
        );
        assert_eq!(find_bcd_value(SAMPLE, "NX").as_deref(), Some("OptIn"));
        assert_eq!(find_bcd_value(SAMPLE, "disabledynamictick"), None);
    }
}

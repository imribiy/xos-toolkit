use base64::Engine;
use std::path::{Path, PathBuf};

pub fn encode_command(script: &str) -> String {
    let bytes: Vec<u8> = script
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub fn env_path(name: &str) -> String {
    std::env::var(name).unwrap_or_default()
}

pub fn local_app_data() -> String {
    env_path("LOCALAPPDATA")
}

pub fn program_files() -> String {
    env_path("ProgramFiles")
}

pub fn program_files_x86() -> String {
    env_path("ProgramFiles(x86)")
}

pub fn windows_dir() -> String {
    xos_sys::expand_environment_variables("%SystemRoot%")
}

pub fn system_dir() -> String {
    Path::new(&windows_dir())
        .join("System32")
        .to_string_lossy()
        .to_string()
}

pub fn combine(a: &str, b: &str) -> String {
    PathBuf::from(a).join(b).to_string_lossy().to_string()
}

pub fn file_exists(path: &str) -> bool {
    Path::new(path).is_file()
}

pub fn dir_exists(path: &str) -> bool {
    Path::new(path).is_dir()
}

pub fn registry_views(path: &str) -> Vec<String> {
    const WOW: &str = r"SOFTWARE\WOW6432Node\";
    const SOFTWARE: &str = r"SOFTWARE\";
    let mut paths = vec![path.to_string()];
    let lower = path.to_lowercase();
    let contains = |paths: &Vec<String>, p: &str| paths.iter().any(|x| x.eq_ignore_ascii_case(p));
    if lower.starts_with(&WOW.to_lowercase()) {
        let native = format!("{SOFTWARE}{}", &path[WOW.len()..]);
        if !contains(&paths, &native) {
            paths.push(native);
        }
    } else if lower.starts_with(&SOFTWARE.to_lowercase()) {
        let wow = format!("{WOW}{}", &path[SOFTWARE.len()..]);
        if !contains(&paths, &wow) {
            paths.push(wow);
        }
    }
    paths
}

pub fn status_text(value: Option<bool>, yes: &str, no: &str) -> String {
    match value {
        None => "unverified".to_string(),
        Some(true) => yes.to_string(),
        Some(false) => no.to_string(),
    }
}

pub fn run_powershell_output(script: &str, timeout_ms: u32) -> String {
    let encoded = encode_command(script);
    xos_sys::run_cmd_output_timeout(
        "powershell.exe",
        &format!("-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}"),
        timeout_ms,
    )
}

pub fn contains_ci(text: &str, needle: &str) -> bool {
    text.to_lowercase().contains(&needle.to_lowercase())
}

pub fn present_state(output: &str) -> Option<bool> {
    let output = output.trim();
    if contains_ci(output, "PRESENT") {
        Some(true)
    } else if contains_ci(output, "ABSENT") {
        Some(false)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn views_add_the_other_registry_view() {
        assert_eq!(
            registry_views(r"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate"),
            vec![
                r"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate".to_string(),
                r"SOFTWARE\Microsoft\EdgeUpdate".to_string()
            ]
        );
        assert_eq!(
            registry_views(r"SOFTWARE\Microsoft\Windows"),
            vec![
                r"SOFTWARE\Microsoft\Windows".to_string(),
                r"SOFTWARE\WOW6432Node\Microsoft\Windows".to_string()
            ]
        );
        assert_eq!(registry_views(r"SYSTEM\X"), vec![r"SYSTEM\X".to_string()]);
    }

    #[test]
    fn presence_parses_absent_and_present() {
        assert_eq!(present_state("PRESENT"), Some(true));
        assert_eq!(present_state(" absent \r\n"), Some(false));
        assert_eq!(present_state("UNKNOWN"), None);
        assert_eq!(present_state("ABSENT PRESENT"), Some(true));
    }

    #[test]
    fn powershell_encoding_is_utf16_base64() {
        assert_eq!(encode_command("a"), "YQA=");
    }
}

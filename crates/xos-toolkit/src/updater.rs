use crate::settings::Channel;
use xos_core::host::{Host, Icon};
use xos_core::log;

pub const RELEASES_API: &str = "https://api.github.com/repos/imribiy/xos-toolkit/releases?per_page=40";
pub const RELEASES_PAGE: &str = "https://github.com/imribiy/xos-toolkit/releases";

#[derive(Clone, Debug, PartialEq)]
pub struct Release {
    pub version: (u32, u32, u32),
    pub version_text: String,
    pub prerelease: bool,
    pub asset_name: String,
    pub asset_url: String,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Check {
    UpToDate,
    Available(Release),
    Failed(String),
}

pub fn parse_version(text: &str) -> Option<(u32, u32, u32)> {
    let t = text.trim();
    let t = t.strip_prefix("xos-toolkit-").unwrap_or(t);
    let t = t.strip_prefix('v').or_else(|| t.strip_prefix('V')).unwrap_or(t);
    let parts: Vec<&str> = t.split('.').collect();
    if parts.len() != 3 || parts.iter().any(|p| p.is_empty() || !p.chars().all(|c| c.is_ascii_digit())) {
        return None;
    }
    Some((parts[0].parse().ok()?, parts[1].parse().ok()?, parts[2].parse().ok()?))
}

pub fn leading_version(text: &str) -> Option<(u32, u32, u32)> {
    let core = text.trim().split(['-', '+']).next().unwrap_or("");
    let parts: Vec<&str> = core.split('.').take(3).collect();
    parse_version(&parts.join("."))
}

pub fn current_version() -> (u32, u32, u32) {
    leading_version(xos_core::VERSION).unwrap_or((u32::MAX, 0, 0))
}

pub fn staging_dir() -> Option<std::path::PathBuf> {
    std::env::current_exe().ok()?.parent().map(|d| d.join("Update"))
}

pub fn clean_staging() {
    if let Some(dir) = staging_dir() {
        if dir.exists() {
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}

fn safe_file_name(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

pub fn pick(json: &str, channel: Channel) -> Option<Release> {
    let list: serde_json::Value = serde_json::from_str(json).ok()?;
    let mut best: Option<Release> = None;
    for r in list.as_array()? {
        if r["draft"].as_bool().unwrap_or(true) {
            continue;
        }
        let prerelease = r["prerelease"].as_bool().unwrap_or(true);
        if prerelease && channel == Channel::Stable {
            continue;
        }
        let Some(version) = r["tag_name"].as_str().and_then(parse_version) else { continue };
        let Some(assets) = r["assets"].as_array() else { continue };
        let asset = assets.iter().find(|a| {
            let n = a["name"].as_str().unwrap_or("").to_ascii_lowercase();
            n.starts_with("xos-toolkit-setup") && n.ends_with(".exe")
        });
        let Some(asset) = asset else { continue };
        let name = asset["name"].as_str().unwrap_or("").to_string();
        let url = asset["browser_download_url"].as_str().unwrap_or("").to_string();
        let digest = asset["digest"].as_str().unwrap_or("").to_ascii_lowercase();
        let Some(sha) = digest.strip_prefix("sha256:") else { continue };
        if sha.len() != 64 || !sha.chars().all(|c| c.is_ascii_hexdigit()) || !safe_file_name(&name) {
            continue;
        }
        if !url.starts_with("https://github.com/imribiy/xos-toolkit/releases/download/") {
            continue;
        }
        if best.as_ref().is_some_and(|b| b.version >= version) {
            continue;
        }
        best = Some(Release {
            version,
            version_text: format!("{}.{}.{}", version.0, version.1, version.2),
            prerelease,
            asset_name: name,
            asset_url: url,
            sha256: sha.to_string(),
        });
    }
    best
}

pub fn evaluate(json: Option<&str>, channel: Channel, current: (u32, u32, u32)) -> Check {
    let Some(json) = json else {
        return Check::Failed("GitHub could not be reached. Check the internet connection and try again.".into());
    };
    if serde_json::from_str::<serde_json::Value>(json).map(|v| !v.is_array()).unwrap_or(true) {
        return Check::Failed("GitHub sent an unexpected answer. Try again later.".into());
    }
    match pick(json, channel) {
        Some(r) if r.version > current => Check::Available(r),
        _ => Check::UpToDate,
    }
}

pub fn check(channel: Channel) -> Check {
    let json = xos_sys::http_get_string_timeout(RELEASES_API, 15000);
    let result = evaluate(json.as_deref(), channel, current_version());
    match &result {
        Check::UpToDate => log::log(&format!("[UPDATE] {} channel: {} is the newest version", channel.name(), xos_core::VERSION)),
        Check::Available(r) => log::log(&format!(
            "[UPDATE] {} channel: {} available ({}), installed {}",
            channel.name(),
            r.version_text,
            if r.prerelease { "pre-release" } else { "release" },
            xos_core::VERSION
        )),
        Check::Failed(e) => log::log(&format!("[UPDATE] {} channel: check failed: {e}", channel.name())),
    }
    result
}

fn download_and_start(r: &Release) -> Result<(), String> {
    let bytes = xos_sys::http_get_bytes_timeout(&r.asset_url, 120000)
        .ok_or_else(|| "The download failed. Check the internet connection and try again.".to_string())?;
    let actual = xos_sys::sha256_hex(&bytes);
    if !actual.eq_ignore_ascii_case(&r.sha256) {
        log::log(&format!("[UPDATE] FAILED: {} SHA256 {actual}, GitHub says {}", r.asset_name, r.sha256));
        return Err("The downloaded installer does not match the checksum GitHub published for it, so it was not run.".into());
    }
    let dir = staging_dir().ok_or_else(|| "The XOS Toolkit folder could not be found.".to_string())?;
    clean_staging();
    std::fs::create_dir_all(&dir).map_err(|e| format!("Could not create {}: {e}", dir.display()))?;
    let path = dir.join(&r.asset_name);
    std::fs::write(&path, &bytes).map_err(|e| format!("Could not save {}: {e}", path.display()))?;
    let written = std::fs::read(&path).map_err(|e| format!("Could not read back {}: {e}", path.display()))?;
    if !xos_sys::sha256_hex(&written).eq_ignore_ascii_case(&r.sha256) {
        let _ = std::fs::remove_file(&path);
        return Err("The saved installer changed after the download, so it was not run.".into());
    }
    log::log(&format!("[UPDATE] downloaded {} ({} bytes, SHA256 verified) to {}", r.asset_name, bytes.len(), path.display()));
    if xos_core::app_state::is_busy() {
        return Err("An operation started during the download. Let it finish, then install the update again.".into());
    }
    std::process::Command::new(&path)
        .args(["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/CLOSEAPPLICATIONS", "/RELAUNCH=1"])
        .spawn()
        .map_err(|e| format!("Could not start the installer: {e}"))?;
    log::log(&format!("[UPDATE] started {} silently; XOS Toolkit closes and the installer reopens it", r.asset_name));
    Ok(())
}

pub fn install(host: &dyn Host, r: &Release) -> bool {
    if xos_core::app_state::is_busy() {
        host.warn("An operation is still running. Wait for it to finish, then install the update.", "XOS Toolkit update");
        return false;
    }
    host.set_status(&format!("Downloading XOS Toolkit {}...", r.version_text));
    match download_and_start(r) {
        Ok(()) => {
            host.set_status(&format!("Installing XOS Toolkit {}...", r.version_text));
            crate::on_exit("update");
            let _ = slint::invoke_from_event_loop(|| {
                let _ = slint::quit_event_loop();
            });
            true
        }
        Err(e) => {
            host.set_status("Ready");
            host.error(&format!("XOS Toolkit {} could not be installed.\n\n{e}", r.version_text), "XOS Toolkit update");
            false
        }
    }
}

pub fn offer_text(r: &Release, channel: Channel) -> String {
    let beta = if r.prerelease {
        "\n\nThis is a developer beta: tested only in virtual machines, so expect bugs."
    } else {
        ""
    };
    format!(
        "XOS Toolkit {} is available ({} channel). You have {}.{beta}\n\nDownload and install it now? XOS Toolkit closes, installs the update and opens again.",
        r.version_text,
        channel.title(),
        xos_core::VERSION
    )
}

pub fn startup_check(host: &dyn Host) {
    if !crate::settings::check_updates_on_startup() || std::env::var_os("XOS_TOOLKIT_NO_UPDATE_CHECK").is_some() {
        return;
    }
    let channel = crate::settings::channel();
    if let Check::Available(r) = check(channel) {
        if host.confirm(&offer_text(&r, channel), "XOS Toolkit update", Icon::Question) {
            log::log(&format!("[UPDATE] user accepted {}", r.version_text));
            install(host, &r);
        } else {
            log::log(&format!("[UPDATE] user declined {}", r.version_text));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "3db775cce4a2c4aa68fbe80714c41c1f0e369f517bc6acefd6fd6d8c7cc6bfcb";

    fn rel(tag: &str, pre: bool, draft: bool, asset: &str) -> String {
        format!(
            r#"{{"tag_name":"{tag}","prerelease":{pre},"draft":{draft},"assets":[{{"name":"{asset}","browser_download_url":"https://github.com/imribiy/xos-toolkit/releases/download/{tag}/{asset}","digest":"sha256:{SHA}"}}]}}"#
        )
    }

    fn list(items: &[String]) -> String {
        format!("[{}]", items.join(","))
    }

    #[test]
    #[ignore]
    fn live_github_releases() {
        let json = xos_sys::http_get_string_timeout(RELEASES_API, 15000).expect("GitHub reachable");
        let beta = pick(&json, Channel::Beta).expect("a beta release with an installer");
        let stable = pick(&json, Channel::Stable).expect("a stable release with an installer");
        println!("beta {} {} | stable {} {}", beta.version_text, beta.asset_name, stable.version_text, stable.asset_name);
        assert!(beta.version >= stable.version);
        assert!(!stable.prerelease);
        let bytes = xos_sys::http_get_bytes_timeout(&beta.asset_url, 120000).expect("installer downloaded");
        assert_eq!(xos_sys::sha256_hex(&bytes), beta.sha256);
        println!("downloaded {} bytes, SHA256 matches", bytes.len());
    }

    #[test]
    fn versions_parse() {
        assert_eq!(parse_version("xos-toolkit-v0.5.1"), Some((0, 5, 1)));
        assert_eq!(parse_version("v1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_version("0.2.178"), Some((0, 2, 178)));
        assert_eq!(parse_version("0.5"), None);
        assert_eq!(parse_version("0.5.1-beta"), None);
        assert_eq!(leading_version("0.5.1-rc1"), Some((0, 5, 1)));
        assert_eq!(leading_version("0.5.1.0"), Some((0, 5, 1)));
        assert_eq!(leading_version("0.5.1+build"), Some((0, 5, 1)));
        assert_eq!(leading_version("junk"), None);
    }

    #[test]
    fn stable_skips_prereleases_and_beta_takes_them() {
        let json = list(&[
            rel("xos-toolkit-v0.6.0", true, false, "XOS-Toolkit-Setup-0.6.0.exe"),
            rel("xos-toolkit-v0.5.2", false, false, "XOS-Toolkit-Setup-0.5.2.exe"),
            rel("xos-toolkit-v0.2.178", false, false, "XOS-Toolkit-Setup-0.2.178.exe"),
        ]);
        assert_eq!(pick(&json, Channel::Stable).unwrap().version_text, "0.5.2");
        assert_eq!(pick(&json, Channel::Beta).unwrap().version_text, "0.6.0");
    }

    #[test]
    fn drafts_bad_assets_and_foreign_urls_are_ignored() {
        let foreign = r#"{"tag_name":"xos-toolkit-v0.9.0","prerelease":false,"draft":false,"assets":[{"name":"XOS-Toolkit-Setup-0.9.0.exe","browser_download_url":"https://example.com/x.exe","digest":"sha256:3db775cce4a2c4aa68fbe80714c41c1f0e369f517bc6acefd6fd6d8c7cc6bfcb"}]}"#;
        let json = list(&[
            rel("xos-toolkit-v0.8.0", false, true, "XOS-Toolkit-Setup-0.8.0.exe"),
            rel("xos-toolkit-v0.7.0", false, false, "notes.txt"),
            rel("xos-toolkit-v0.6.5", false, false, "XOS Toolkit Setup.exe"),
            foreign.to_string(),
            rel("xos-toolkit-v0.5.1", false, false, "XOS-Toolkit-Setup-0.5.1.exe"),
        ]);
        assert_eq!(pick(&json, Channel::Beta).unwrap().version_text, "0.5.1");
    }

    #[test]
    fn evaluate_compares_with_installed() {
        let json = list(&[rel("xos-toolkit-v0.5.1", false, false, "XOS-Toolkit-Setup-0.5.1.exe")]);
        assert!(matches!(evaluate(Some(&json), Channel::Stable, (0, 5, 0)), Check::Available(_)));
        assert_eq!(evaluate(Some(&json), Channel::Stable, (0, 5, 1)), Check::UpToDate);
        assert_eq!(evaluate(Some(&json), Channel::Stable, (0, 6, 0)), Check::UpToDate);
        assert!(matches!(evaluate(Some("not json"), Channel::Stable, (0, 5, 0)), Check::Failed(_)));
        assert!(matches!(evaluate(Some(r#"{"message":"API rate limit exceeded"}"#), Channel::Stable, (0, 5, 0)), Check::Failed(_)));
        assert_eq!(evaluate(Some("[]"), Channel::Stable, (0, 5, 0)), Check::UpToDate);
        assert!(matches!(evaluate(None, Channel::Stable, (0, 5, 0)), Check::Failed(_)));
    }
}

use base64::Engine;
use regex::Regex;

fn encode_command(script: &str) -> String {
    let bytes: Vec<u8> = script
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub const DEFAULT_TIMEOUT_MS: u32 = 60000;

pub fn remove(
    name: &str,
    full_name: Option<&str>,
    timeout_ms: u32,
    before_workaround: Option<&mut dyn FnMut()>,
) -> (bool, Option<String>) {
    let safe_pkg_name = name.replace('\'', "''");
    let safe_full_name = full_name.unwrap_or("").replace('\'', "''");
    let by_name = safe_full_name.trim().is_empty();

    let target_selector = if by_name {
        format!("Where-Object {{ $_.Name -eq '{safe_pkg_name}' }}")
    } else {
        format!("Where-Object {{ $_.PackageFullName -eq '{safe_full_name}' }}")
    };
    let verify_installed = if by_name {
        format!("Get-AppxPackage -AllUsers | Where-Object {{ $_.Name -eq '{safe_pkg_name}' }}")
    } else {
        format!(
            "Get-AppxPackage -AllUsers | Where-Object {{ $_.PackageFullName -eq '{safe_full_name}' }}"
        )
    };
    let verify_provisioned = if by_name {
        format!(
            "Get-AppxProvisionedPackage -Online | Where-Object {{ $_.DisplayName -eq '{safe_pkg_name}' }}"
        )
    } else {
        format!(
            "Get-AppxProvisionedPackage -Online | Where-Object {{ $_.PackageName -eq '{safe_full_name}' }}"
        )
    };

    let ps_step1 = format!(
        "$ErrorActionPreference='Stop'; try {{ $full='{safe_full_name}'; $prov = Get-AppxProvisionedPackage -Online | Where-Object {{ $_.DisplayName -eq '{safe_pkg_name}' }}; if ($prov) {{ $prov | Remove-AppxProvisionedPackage -Online | Out-Null }}; $pkgs = @(Get-AppxPackage -AllUsers | {target_selector}); foreach ($p in $pkgs) {{ Remove-AppxPackage -Package $p.PackageFullName -AllUsers }}; if ({verify_installed}) {{ throw 'The package is still installed.' }}; if ({verify_provisioned}) {{ throw 'The package is still provisioned.' }} }} catch {{ Write-Error $_.Exception.Message; exit 1 }}"
    );
    let encoded1 = encode_command(&ps_step1);

    let (ok1, error1) = xos_sys::run_cmd_with_error_timeout(
        "powershell.exe",
        &format!("-NoProfile -NonInteractive -EncodedCommand {encoded1}"),
        timeout_ms,
    );
    if ok1 {
        return (true, None);
    }
    if let Some(callback) = before_workaround {
        callback();
    }

    let ps_step2 = format!(
        r#"
$ErrorActionPreference = 'Stop'
try {{
    $prov = Get-AppxProvisionedPackage -Online | Where-Object {{ $_.DisplayName -eq '{safe_pkg_name}' }}
    if ($prov) {{ $prov | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Out-Null }}
    $packages = @(Get-AppxPackage -AllUsers | {target_selector})
    foreach ($p in $packages) {{
        $store = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore'
        $fam = $p.PackageFamilyName
        if ($fam) {{ Set-NonRemovableAppsPolicy -Online -PackageFamilyName $fam -NonRemovable 0 -ErrorAction SilentlyContinue }}
        if ($fam) {{ New-Item -Force -Path ($store + '\Deprovisioned\' + $fam) | Out-Null }}
        foreach ($u in $p.PackageUserInformation) {{
            $sid = $u.UserSecurityId.Sid
            New-Item -Force -Path ($store + '\EndOfLife\' + $sid + '\' + $p.PackageFullName) | Out-Null
        }}
        Remove-AppxPackage -Package $p.PackageFullName -AllUsers
        foreach ($u in $p.PackageUserInformation) {{
            $sid = $u.UserSecurityId.Sid
            Remove-Item -Force -Recurse -Path ($store + '\EndOfLife\' + $sid + '\' + $p.PackageFullName) -ErrorAction SilentlyContinue
        }}
        if ($fam) {{ Remove-Item -Force -Recurse -Path ($store + '\Deprovisioned\' + $fam) -ErrorAction SilentlyContinue }}
    }}
    if ({verify_installed}) {{ throw 'The package is still installed.' }}
    if ({verify_provisioned}) {{ throw 'The package is still provisioned.' }}
}} catch {{ Write-Error $_.Exception.Message; exit 1 }}"#
    );

    let encoded2 = encode_command(&ps_step2);
    let (ok2, error2) = xos_sys::run_cmd_with_error_timeout(
        "powershell.exe",
        &format!("-NoProfile -NonInteractive -EncodedCommand {encoded2}"),
        timeout_ms,
    );
    if ok2 {
        return (true, None);
    }
    let chosen = match &error2 {
        Some(e) if !e.trim().is_empty() => Some(e.as_str()),
        _ => error1.as_deref(),
    };
    (false, Some(clean_error(chosen)))
}

fn utf16_len(s: &str) -> usize {
    s.encode_utf16().count()
}

pub fn clean_error(raw: Option<&str>) -> String {
    let raw = match raw {
        Some(r) if !r.trim().is_empty() => r,
        _ => return "Unknown error.".to_string(),
    };

    if !raw.contains("<S S=\"Error\">") {
        return raw.trim().to_string();
    }

    let fragments = Regex::new(r#"(?s)<S S="Error">(.*?)</S>"#).expect("pattern");
    let escapes = Regex::new(r"_x([0-9A-Fa-f]{4})_").expect("pattern");
    let mut sb = String::new();
    for m in fragments.captures_iter(raw) {
        let mut fragment = m[1].to_string();
        fragment = fragment.replace("_x000D__x000A_", "");
        fragment = fragment
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&amp;", "&")
            .replace("&quot;", "\"")
            .replace("&apos;", "'");
        let fragment = escapes.replace_all(&fragment, |c: &regex::Captures| {
            let code = u32::from_str_radix(&c[1], 16).unwrap_or(0xFFFD);
            char::from_u32(code).unwrap_or('\u{FFFD}').to_string()
        });
        sb.push_str(&fragment);
    }

    let mut cleaned = sb.trim().to_string();
    if cleaned.is_empty() {
        return raw.trim().to_string();
    }

    if let Some(at_line) = cleaned.find("At line:") {
        if at_line > 0 {
            cleaned = cleaned[..at_line].trim().to_string();
        }
    }

    if let Some(removal_idx) = cleaned.to_ascii_lowercase().find("removal failed") {
        if removal_idx > 0 {
            cleaned = cleaned[removal_idx..].trim().to_string();
        }
    }

    let hex = Regex::new(r"error (0x[0-9A-Fa-f]+)").expect("pattern");
    if let Some(m) = hex.captures(&cleaned) {
        return format!("Removal failed with error {}.", &m[1]);
    }

    if let Some(dot) = cleaned.find('.') {
        let dot_units = utf16_len(&cleaned[..dot]);
        if dot > 0 && dot_units < 80 {
            return cleaned[..=dot].to_string();
        }
    }

    cleaned
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_unknown() {
        assert_eq!(clean_error(None), "Unknown error.");
        assert_eq!(clean_error(Some("  ")), "Unknown error.");
    }

    #[test]
    fn plain_text_is_trimmed() {
        assert_eq!(clean_error(Some("  boom  ")), "boom");
    }

    #[test]
    fn clixml_error_fragments_are_joined_and_cleaned() {
        let raw = "#< CLIXML\r\n<Objs><S S=\"Error\">The package is still installed._x000D__x000A_</S><S S=\"Error\">At line:1 char:5</S></Objs>";
        assert_eq!(clean_error(Some(raw)), "The package is still installed.");
    }

    #[test]
    fn hex_error_is_summarised() {
        let raw = "<S S=\"Error\">Deployment Remove operation failed. Removal failed. error 0x80073CFA: details &lt;x&gt;</S>";
        assert_eq!(
            clean_error(Some(raw)),
            "Removal failed with error 0x80073CFA."
        );
    }

    #[test]
    fn unicode_escape_and_entities_decode() {
        let raw = "<S S=\"Error\">A_x0042_ &amp; C. Rest of the text</S>";
        assert_eq!(clean_error(Some(raw)), "AB & C.");
    }
}

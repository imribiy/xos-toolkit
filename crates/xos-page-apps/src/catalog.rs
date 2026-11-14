#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CatalogApp {
    pub name: &'static str,
    pub id: &'static str,
}

pub struct CatalogCategory {
    pub name: &'static str,
    pub apps: &'static [CatalogApp],
}

macro_rules! app {
    ($n:expr, $i:expr) => {
        CatalogApp { name: $n, id: $i }
    };
}

pub static CATALOG: [CatalogCategory; 9] = [
    CatalogCategory {
        name: "Essential Runtimes",
        apps: &[
            app!("DirectX", "directx"),
            app!("Visual C++ Runtimes", "vcredist-all"),
            app!("Edge WebView2 Runtime", "webview2-runtime"),
            app!(".NET Desktop Runtime 8", "dotnet-8.0-desktopruntime"),
            app!(".NET Desktop Runtime 9", "dotnet-9.0-desktopruntime"),
            app!(".NET Desktop Runtime 10", "dotnet-10.0-desktopruntime"),
        ],
    },
    CatalogCategory {
        name: "Game Launchers",
        apps: &[
            app!("Steam", "steam"),
            app!("Epic Games", "epicgameslauncher"),
            app!("EA App", "ea-app"),
            app!("Ubisoft Connect", "ubisoft-connect"),
        ],
    },
    CatalogCategory {
        name: "Web Browsers",
        apps: &[
            app!("Google Chrome", "googlechrome"),
            app!("Mozilla Firefox", "firefox"),
            app!("Brave", "brave"),
            app!("Opera", "opera"),
            app!("Opera GX", "opera-gx"),
            app!("Chromium", "chromium"),
            app!("LibreWolf", "librewolf"),
            app!("Helium", "helium"),
            app!("Microsoft Edge", "microsoft-edge"),
        ],
    },
    CatalogCategory {
        name: "Communication & Remote Access",
        apps: &[
            app!("TeamSpeak", "teamspeak"),
            app!("RustDesk", "rustdesk"),
            app!("AnyDesk", "anydesk.portable"),
            app!("TeamViewer", "teamviewer"),
        ],
    },
    CatalogCategory {
        name: "Media & Streaming",
        apps: &[
            app!("VLC", "vlc"),
            app!("Spotify", "spotify"),
            app!("OBS Studio", "obs-studio.install"),
        ],
    },
    CatalogCategory {
        name: "Utilities",
        apps: &[
            app!("7-Zip", "7zip.install"),
            app!("qBittorrent", "qbittorrent"),
            app!("Notepad++", "notepadplusplus.install"),
            app!("ShareX", "sharex"),
            app!("Lightshot", "lightshot.install"),
            app!("PowerToys", "powertoys"),
            app!("Google Drive", "googledrive"),
            app!("Bulk Crap Uninstaller", "bulk-crap-uninstaller"),
            app!("Malwarebytes", "malwarebytes"),
            app!("Cloudflare WARP", "warp"),
        ],
    },
    CatalogCategory {
        name: "Hardware & Diagnostics",
        apps: &[
            app!("HWiNFO", "hwinfo.portable"),
            app!("CPU-Z", "cpu-z.portable"),
            app!("GPU-Z", "gpu-z"),
            app!("OCCT", "occt"),
            app!("AMD Chipset", "amd-ryzen-chipset"),
            app!("AMD Ryzen Master", "amd-ryzen-master"),
        ],
    },
    CatalogCategory {
        name: "System Tools",
        apps: &[
            app!("DevManView", "devmanview"),
            app!("Autoruns", "autoruns"),
            app!("ServiWin", "serviwin"),
        ],
    },
    CatalogCategory {
        name: "Development",
        apps: &[app!("Python", "python")],
    },
];

pub fn catalog_apps() -> Vec<CatalogApp> {
    CATALOG
        .iter()
        .flat_map(|c| c.apps.iter().copied())
        .collect()
}

pub fn is_catalog_package_id(package_id: &str) -> bool {
    CATALOG
        .iter()
        .flat_map(|c| c.apps.iter())
        .any(|a| a.id.eq_ignore_ascii_case(package_id))
}

pub fn find_app_by_name(name: &str) -> Option<CatalogApp> {
    CATALOG
        .iter()
        .flat_map(|c| c.apps.iter())
        .find(|a| a.name == name)
        .copied()
}

pub fn contains_ignore_case(haystack: &str, needle: &str) -> bool {
    needle.is_empty() || haystack.to_lowercase().contains(&needle.to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_has_every_app() {
        assert_eq!(CATALOG.len(), 9);
        assert_eq!(catalog_apps().len(), 6 + 4 + 9 + 4 + 3 + 10 + 6 + 3 + 1);
        assert!(is_catalog_package_id("DIRECTX"));
        assert!(!is_catalog_package_id("nonexistent"));
        assert_eq!(find_app_by_name("Steam").unwrap().id, "steam");
    }

    #[test]
    fn filter_matches_name_case_insensitively() {
        assert!(contains_ignore_case("Google Chrome", "chrome"));
        assert!(contains_ignore_case("Google Chrome", ""));
        assert!(!contains_ignore_case("Steam", "epic"));
    }
}

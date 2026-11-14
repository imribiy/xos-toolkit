use xos_core::status::ENABLED_WINDOWS_DEFAULT;

pub fn dx_get_token(settings: Option<&str>, token: &str) -> Option<String> {
    let s = settings?;
    if s.is_empty() {
        return None;
    }
    for part in s.split(';').filter(|p| !p.is_empty()) {
        if let Some(sep) = part.find('=') {
            if sep > 0 && part[..sep].trim().eq_ignore_ascii_case(token) {
                return Some(part[sep + 1..].trim().to_string());
            }
        }
    }
    None
}

pub fn dx_set_token(settings: &str, token: &str, value: &str) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut found = false;
    for part in settings.split(';').filter(|p| !p.is_empty()) {
        match part.find('=') {
            Some(sep) if sep > 0 && part[..sep].trim().eq_ignore_ascii_case(token) => {
                parts.push(format!("{token}={value}"));
                found = true;
            }
            _ => parts.push(part.trim().to_string()),
        }
    }
    if !found {
        parts.push(format!("{token}={value}"));
    }
    format!("{};", parts.join(";"))
}

pub struct GameBarInputs {
    pub app_capture: Option<i32>,
    pub game_dvr_enabled: Option<i32>,
    pub audio_capture: Option<i32>,
    pub cursor_capture: Option<i32>,
    pub game_dvr_policy: Option<i32>,
    pub game_mode: Option<i32>,
    pub auto_mode: Option<i32>,
    pub startup_panel: Option<i32>,
    pub nexus: Option<i32>,
    pub ifeo_count: usize,
    pub exe_count: usize,
}

pub struct GameBarResult {
    pub state: &'static str,
    pub disabled: bool,
    pub enabled: bool,
}

pub fn game_bar_state(i: &GameBarInputs) -> GameBarResult {
    let is0 = |v: Option<i32>| v == Some(0);
    let null_or_not0 = |v: Option<i32>| v.is_none() || v != Some(0);
    let null_or_1 = |v: Option<i32>| v.is_none() || v == Some(1);
    let disabled = is0(i.app_capture)
        && is0(i.game_dvr_enabled)
        && is0(i.audio_capture)
        && is0(i.cursor_capture)
        && is0(i.game_dvr_policy)
        && i.ifeo_count == i.exe_count
        && is0(i.game_mode)
        && is0(i.auto_mode)
        && is0(i.startup_panel)
        && is0(i.nexus);
    let enabled = null_or_not0(i.app_capture)
        && null_or_not0(i.game_dvr_enabled)
        && null_or_not0(i.audio_capture)
        && null_or_not0(i.cursor_capture)
        && null_or_not0(i.game_dvr_policy)
        && i.ifeo_count == 0
        && null_or_1(i.app_capture)
        && null_or_1(i.game_dvr_enabled)
        && null_or_not0(i.game_mode)
        && null_or_not0(i.auto_mode)
        && null_or_not0(i.startup_panel)
        && null_or_not0(i.nexus);
    let unset = [
        i.app_capture,
        i.game_dvr_enabled,
        i.audio_capture,
        i.cursor_capture,
        i.game_dvr_policy,
        i.game_mode,
        i.auto_mode,
        i.startup_panel,
        i.nexus,
    ]
    .iter()
    .all(|v| v.is_none())
        && i.ifeo_count == 0;
    let state = if unset {
        "N/A"
    } else if enabled {
        "Enabled"
    } else if disabled {
        "Disabled"
    } else {
        "Partial"
    };
    GameBarResult {
        state,
        disabled,
        enabled,
    }
}

pub struct FsoInputs {
    pub dse_behavior: Option<i32>,
    pub fse_behavior: Option<i32>,
    pub fse_mode: Option<i32>,
    pub dxgi_honor: Option<i32>,
    pub efse_flags: Option<i32>,
    pub honor_user: Option<i32>,
    pub config_dvr: Option<i32>,
}

pub fn fso_state(i: &FsoInputs) -> (String, String) {
    let values = [
        i.dse_behavior,
        i.fse_behavior,
        i.fse_mode,
        i.dxgi_honor,
        i.efse_flags,
        i.honor_user,
    ];
    let force_set = values.iter().filter(|v| v.is_some()).count();
    let forced = i.dse_behavior == Some(2)
        && i.fse_behavior == Some(2)
        && i.fse_mode == Some(2)
        && i.dxgi_honor == Some(1)
        && i.efse_flags == Some(0)
        && i.honor_user == Some(1)
        && i.config_dvr == Some(0);
    let stock = i.dse_behavior.is_none()
        && i.fse_behavior.is_none()
        && i.dxgi_honor == Some(0)
        && i.efse_flags == Some(0)
        && i.honor_user == Some(0)
        && (i.fse_mode == Some(2) || i.fse_mode == Some(0));
    let untouched = force_set == 0 || stock;
    if forced {
        (
            "Disabled".to_string(),
            "Full Screen Optimizations are forced off by the six GameDVR force values.".to_string(),
        )
    } else if untouched {
        (
            ENABLED_WINDOWS_DEFAULT.to_string(),
            format!(
                "Windows is managing Full Screen Optimizations. Nothing here has been changed. {}",
                match i.config_dvr {
                    None => "GameDVR is not configured.".to_string(),
                    Some(n) => format!("GameDVR_Enabled={n} is Windows' own value."),
                }
            ),
        )
    } else {
        let names = [
            (i.dse_behavior, "GameDVR_DSEBehavior"),
            (i.fse_behavior, "GameDVR_FSEBehavior"),
            (i.fse_mode, "GameDVR_FSEBehaviorMode"),
            (i.dxgi_honor, "GameDVR_DXGIHonorFSEWindowsCompatible"),
            (i.efse_flags, "GameDVR_EFSEFeatureFlags"),
            (i.honor_user, "GameDVR_HonorUserFSEBehaviorMode"),
        ];
        let missing: Vec<&str> = names
            .iter()
            .filter(|(v, _)| v.is_none())
            .map(|(_, n)| *n)
            .collect();
        (
            "Partial".to_string(),
            format!(
                "The Full Screen Optimizations force is incomplete: {force_set} of 6 values are set. Missing: {}.",
                missing.join(", ")
            ),
        )
    }
}

pub fn fivem_state(pca: i32, diag: i32, sysmain: i32, dps: i32, evt: i32) -> String {
    let enabled = pca >= 0
        && pca != 4
        && diag >= 0
        && diag != 4
        && sysmain >= 0
        && sysmain != 4
        && dps >= 0
        && dps != 4
        && evt >= 0
        && evt != 4;
    let disabled = pca == 4 && diag == 4 && sysmain == 4;
    if pca < 0 && diag < 0 && sysmain < 0 && dps < 0 && evt < 0 {
        "N/A"
    } else if enabled {
        "Enabled"
    } else if disabled {
        "Disabled"
    } else {
        "Partial"
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dx_tokens() {
        assert_eq!(dx_get_token(None, "A"), None);
        assert_eq!(dx_get_token(Some(""), "A"), None);
        let s = "SwapEffectUpgradeEnable=1; VRROptimizeEnable = 0;";
        assert_eq!(
            dx_get_token(Some(s), "swapeffectupgradeenable").as_deref(),
            Some("1")
        );
        assert_eq!(
            dx_get_token(Some(s), "VRROptimizeEnable").as_deref(),
            Some("0")
        );
        assert_eq!(dx_get_token(Some(s), "AutoHDREnable"), None);
        assert_eq!(dx_set_token("", "AutoHDREnable", "1"), "AutoHDREnable=1;");
        assert_eq!(
            dx_set_token(s, "vrroptimizeenable", "1"),
            "SwapEffectUpgradeEnable=1;vrroptimizeenable=1;"
        );
        assert_eq!(dx_set_token("X=1;", "Y", "2"), "X=1;Y=2;");
    }

    fn base() -> GameBarInputs {
        GameBarInputs {
            app_capture: None,
            game_dvr_enabled: None,
            audio_capture: None,
            cursor_capture: None,
            game_dvr_policy: None,
            game_mode: None,
            auto_mode: None,
            startup_panel: None,
            nexus: None,
            ifeo_count: 0,
            exe_count: 7,
        }
    }

    #[test]
    fn game_bar() {
        assert_eq!(game_bar_state(&base()).state, "N/A");
        let mut i = base();
        i.app_capture = Some(1);
        i.game_dvr_enabled = Some(1);
        assert_eq!(game_bar_state(&i).state, "Enabled");
        let d = GameBarInputs {
            app_capture: Some(0),
            game_dvr_enabled: Some(0),
            audio_capture: Some(0),
            cursor_capture: Some(0),
            game_dvr_policy: Some(0),
            game_mode: Some(0),
            auto_mode: Some(0),
            startup_panel: Some(0),
            nexus: Some(0),
            ifeo_count: 7,
            exe_count: 7,
        };
        assert_eq!(game_bar_state(&d).state, "Disabled");
        let mut p = base();
        p.app_capture = Some(0);
        assert_eq!(game_bar_state(&p).state, "Partial");
    }

    #[test]
    fn fso() {
        let none = FsoInputs {
            dse_behavior: None,
            fse_behavior: None,
            fse_mode: None,
            dxgi_honor: None,
            efse_flags: None,
            honor_user: None,
            config_dvr: None,
        };
        let (s, d) = fso_state(&none);
        assert_eq!(s, ENABLED_WINDOWS_DEFAULT);
        assert!(d.ends_with("GameDVR is not configured."));
        let forced = FsoInputs {
            dse_behavior: Some(2),
            fse_behavior: Some(2),
            fse_mode: Some(2),
            dxgi_honor: Some(1),
            efse_flags: Some(0),
            honor_user: Some(1),
            config_dvr: Some(0),
        };
        assert_eq!(fso_state(&forced).0, "Disabled");
        let partial = FsoInputs {
            fse_mode: None,
            ..forced
        };
        let (s, d) = fso_state(&partial);
        assert_eq!(s, "Partial");
        assert!(d.contains("5 of 6 values are set. Missing: GameDVR_FSEBehaviorMode."));
    }

    #[test]
    fn fivem() {
        assert_eq!(fivem_state(-1, -1, -1, -1, -1), "N/A");
        assert_eq!(fivem_state(2, 2, 2, 2, 2), "Enabled");
        assert_eq!(fivem_state(4, 4, 4, 2, 2), "Disabled");
        assert_eq!(fivem_state(4, 2, 2, 2, 2), "Partial");
    }
}

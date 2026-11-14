use std::sync::Arc;
use xos_core::Page;

pub mod consts;
pub mod detect;
mod dispatch;
pub mod infra;
pub mod page;

pub use infra::undo_hard_disable;
pub use page::UpdatePage;

pub fn pages() -> Vec<Arc<dyn Page>> {
    vec![Arc::new(UpdatePage::new())]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::{parse_pause_expiry, supports_latest_updates_for};
    use crate::infra::*;
    use crate::page::json_value;

    #[test]
    fn page_shape() {
        let p = UpdatePage::new();
        let m = xos_core::Page::model(&p);
        assert_eq!(xos_core::Page::id(&p), "Update");
        assert_eq!(xos_core::Page::label(&p), "Updates");
        assert_eq!(m.cards.len(), 7);
        assert!(m.overlay.is_none());
        assert_eq!(pages().len(), 1);
    }

    #[test]
    fn service_start_resolution() {
        assert_eq!(resolve_service_start(4, Some(2), 3), 2);
        assert_eq!(resolve_service_start(4, Some(4), 3), 3);
        assert_eq!(resolve_service_start(2, None, 3), 2);
        assert_eq!(resolve_service_start(4, None, 2), 2);
        assert_eq!(fallback_update_service_start("DoSvc"), 2);
        assert_eq!(fallback_update_service_start("bits"), 3);
        assert_eq!(sc_start_name(2), "auto");
        assert_eq!(sc_start_name(4), "disabled");
        assert_eq!(sc_start_name(3), "demand");
    }

    #[test]
    fn latest_gate() {
        assert!(supports_latest_updates_for(22631, 0));
        assert!(supports_latest_updates_for(19045, 3758));
        assert!(!supports_latest_updates_for(19045, 3757));
        assert!(!supports_latest_updates_for(19044, 9999));
    }

    #[test]
    fn json_values() {
        let body = r#"{"URI" : "https://x/y","version":"12"}"#;
        assert_eq!(json_value(body, "uri").as_deref(), Some("https://x/y"));
        assert_eq!(json_value(body, "VERSION").as_deref(), Some("12"));
        assert_eq!(json_value(body, "HASH"), None);
    }

    #[test]
    fn pause_dates() {
        assert!(parse_pause_expiry("2038-01-19T03:14:07Z").is_some());
        assert!(parse_pause_expiry("").is_none());
        assert!(parse_pause_expiry("garbage").is_none());
    }

    #[test]
    fn task_rules() {
        assert!(is_blocked_mode_task(
            r"\microsoft\windows\windowsupdate\sih"
        ));
        assert!(!is_blocked_mode_task(
            r"\Microsoft\Windows\WindowsUpdate\Other"
        ));
        assert!(shipped_disabled(
            r"\Microsoft\Windows\UpdateOrchestrator\Schedule Work"
        ));
        assert!(!shipped_disabled(
            r"\Microsoft\Windows\UpdateOrchestrator\Reboot"
        ));
        let mut s = TaskStates::default();
        assert!(update_tasks_match(Some(&s), true));
        assert!(!update_tasks_match(None, true));
        s.insert(r"\A\Schedule Work", 0);
        s.insert(r"\A\x", 1);
        assert!(update_tasks_match(Some(&s), true) == false);
        s.insert(r"\Microsoft\Windows\UpdateOrchestrator\Schedule Work", 0);
        s.insert(r"\A\x", 1);
        assert!(!update_tasks_match(Some(&s), false));
    }

    #[test]
    fn task_script() {
        let script = build_task_script(&["\\A\\it's".to_string()], &[]);
        assert!(script.contains("$enable = @('\\A\\it''s')"));
        assert!(script.contains("$disable = @()"));
        assert!(script.ends_with("if (-not $script:ok) { exit 1 }\r\n"));
    }

    #[test]
    fn hide_plan() {
        assert_eq!(
            plan_hide_settings_page("", "windowsupdate"),
            HidePlan::Apply {
                original: "<XOS:NO_VALUE>".into(),
                applied: "hide:windowsupdate".into()
            }
        );
        assert_eq!(
            plan_hide_settings_page("hide:about", "windowsupdate"),
            HidePlan::Apply {
                original: "hide:about".into(),
                applied: "hide:about;windowsupdate".into()
            }
        );
        assert_eq!(
            plan_hide_settings_page("HIDE:WindowsUpdate", "windowsupdate"),
            HidePlan::AlreadyHidden
        );
        assert_eq!(
            plan_hide_settings_page("junk", "windowsupdate"),
            HidePlan::Refuse
        );
        assert_eq!(
            plan_hide_settings_page("showonly:windowsupdate", "windowsupdate"),
            HidePlan::Refuse
        );
        assert_eq!(
            plan_hide_settings_page("showonly:about", "windowsupdate"),
            HidePlan::AlreadyNotVisible
        );
    }

    #[test]
    fn encode_matches_utf16_base64() {
        assert_eq!(encode_command("a"), "YQA=");
    }
}

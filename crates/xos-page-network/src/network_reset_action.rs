use std::panic::AssertUnwindSafe;
use std::time::Instant;

use xos_core::app_state;
use xos_core::host::{Buttons, DialogResult, Host, Icon};
use xos_core::log;
use xos_helpers::network_reset;

fn panic_text(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown error".to_string()
    }
}

pub fn failure_list(failures: &[String]) -> String {
    failures
        .iter()
        .take(8)
        .map(|f| format!("- {f}"))
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn detail_text(outcome: &network_reset::Outcome) -> String {
    let mut detail = format!(
        "{} adapter value(s) restored, {} removed, {} left as they are",
        outcome.restored, outcome.removed, outcome.left_as_is
    );
    if !outcome.failures.is_empty() {
        detail.push_str(&format!(", {} step(s) failed", outcome.failures.len()));
    }
    detail
}

pub fn run(host: &dyn Host, page_name: &str) {
    let answer = host.dialog(
        "This sets the network adapter settings XOS changed back to their driver defaults, removes the XOS network values, and resets the DNS cache, TCP/IP, Winsock and Windows Firewall (custom firewall rules are removed). Then your PC restarts.\n\nProceed?",
        "Network Reset",
        Buttons::YesNo,
        Icon::Warning,
    );
    if answer != DialogResult::Yes {
        log::action_done(
            page_name,
            false,
            false,
            Some("declined by the user, nothing changed"),
        );
        return;
    }

    let _op = app_state::operation();
    let watch = Instant::now();
    log::op_detail("Network reset", Some(page_name));
    host.set_status("Resetting network...");

    let outcome = match std::panic::catch_unwind(AssertUnwindSafe(network_reset::run)) {
        Ok(o) => o,
        Err(payload) => {
            let message = panic_text(payload);
            log::exception("Network reset", &message);
            log::action_done(page_name, true, false, Some(&message));
            log::perf_detail("Network reset", watch.elapsed().as_millis(), Some("failed"));
            app_state::require_reboot();
            host.set_status("Network reset could not be completed.");
            host.dialog(
                &format!(
                    "The network reset could not be completed.\n\n{message}\n\nSome steps may already have run, so restart the PC before trying again."
                ),
                "Network Reset",
                Buttons::Ok,
                Icon::Error,
            );
            return;
        }
    };

    let detail = detail_text(&outcome);
    let failed = !outcome.failures.is_empty();
    app_state::require_reboot();

    if failed {
        host.set_status("Network reset finished with failures. Restart Windows to apply the rest.");
        let restart = host.dialog(
            &format!(
                "The network reset finished, but these steps failed:\n\n{}\n\nThe Toolkit log has the details. Successful changes take effect after a restart.\n\nRestart now?",
                failure_list(&outcome.failures)
            ),
            "Network Reset",
            Buttons::YesNo,
            Icon::Warning,
        );
        if restart != DialogResult::Yes {
            log::action_done(
                page_name,
                false,
                true,
                Some(&format!("{detail}; restart deferred by the user")),
            );
            log::perf_detail(
                "Network reset",
                watch.elapsed().as_millis(),
                Some("partial, restart deferred"),
            );
            return;
        }
    }

    host.set_status(if failed {
        "Network reset finished with failures. Restarting in 5 seconds..."
    } else {
        "Network reset complete. Restarting in 5 seconds..."
    });
    if !xos_sys::run_cmd("shutdown.exe", "/r /t 5") {
        log::action_done(
            page_name,
            false,
            true,
            Some(&format!("{detail}; automatic restart failed")),
        );
        log::perf_detail(
            "Network reset",
            watch.elapsed().as_millis(),
            Some("partial, restart failed"),
        );
        host.set_status("Network reset finished. Restart Windows manually.");
        host.dialog(
            "Windows rejected the automatic restart request. Please restart the PC manually.",
            "Network Reset",
            Buttons::Ok,
            Icon::Warning,
        );
    } else {
        log::action_done(
            page_name,
            false,
            failed,
            Some(&format!("{detail}; restart scheduled")),
        );
        log::perf_detail(
            "Network reset",
            watch.elapsed().as_millis(),
            Some(if failed { "partial" } else { "complete" }),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detail_and_failures() {
        let mut o = network_reset::Outcome {
            restored: 2,
            removed: 3,
            left_as_is: 1,
            ..Default::default()
        };
        assert_eq!(
            detail_text(&o),
            "2 adapter value(s) restored, 3 removed, 1 left as they are"
        );
        for i in 0..10 {
            o.failures.push(format!("f{i}"));
        }
        assert!(detail_text(&o).ends_with(", 10 step(s) failed"));
        let list = failure_list(&o.failures);
        assert_eq!(list.lines().count(), 8);
        assert!(list.starts_with("- f0\n- f1"));
    }
}

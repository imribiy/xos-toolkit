#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

slint::include_modules!();

mod bootstrap;
mod pages;
mod platform;
mod settings;
mod shell;
mod updater;
mod view;

use xos_core::log;

pub fn crash_dir() -> std::path::PathBuf {
    log::path()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| std::path::PathBuf::from(std::env::var("LOCALAPPDATA").unwrap_or_default()).join("XOSToolkit").join("Logs"))
}

pub fn write_crash_file(details: &str) -> Option<std::path::PathBuf> {
    let dir = crash_dir();
    let _ = std::fs::create_dir_all(&dir);
    let stamp = chrono::Local::now();
    let nonce = format!("{:x}{:x}", std::process::id(), stamp.timestamp_nanos_opt().unwrap_or(0));
    let path = dir.join(format!("crash-{}-{}.log", stamp.format("%Y-%m-%d_%H-%M-%S-%3f"), nonce));
    let text = format!(
        "[{}] XOS Toolkit crash\r\nOS: build {}\r\nRuntime: Rust\r\n---\r\n{}\r\n",
        stamp.to_rfc3339(),
        platform::windows_build(),
        xos_core::redact::redact(details)
    );
    std::fs::write(&path, text).ok().map(|_| path)
}

pub fn on_exit(reason: &str) {
    log::session_end(reason);
    xos_core::session_log::write_digest();
}

pub fn restart_toolkit(reason: &str) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    std::process::Command::new(&exe).spawn().map_err(|e| e.to_string())?;
    log::log(&format!("[SETTINGS] restarting XOS Toolkit ({reason})"));
    on_exit(reason);
    let _ = slint::invoke_from_event_loop(|| {
        let _ = slint::quit_event_loop();
    });
    Ok(())
}

fn main() {
    let release = !cfg!(debug_assertions);
    let claimed = release && bootstrap::claim();
    log::init(xos_core::VERSION);
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let bt = std::backtrace::Backtrace::force_capture();
        let text = format!("{info}\n{bt}");
        log::exception("panic", &text);
        write_crash_file(&text);
        default_hook(info);
    }));
    if release {
        bootstrap::start(claimed);
    }
    xos_helpers::init();
    xos_sys::warm_feature_state_cache();
    if std::env::var_os("SLINT_BACKEND").is_none() {
        std::env::set_var("SLINT_BACKEND", "winit-software");
    }
    if std::env::var_os("XOS_TOOLKIT_SCALE_SET").is_some() {
        std::env::remove_var("SLINT_SCALE_FACTOR");
        std::env::remove_var("XOS_TOOLKIT_SCALE_SET");
    }
    let text_size = settings::text_size();
    if text_size != 100 && std::env::var_os("SLINT_SCALE_FACTOR").is_none() {
        let base = platform::system_dpi() as f32 / 96.0;
        let wanted = base * text_size as f32 / 100.0;
        let fit = platform::max_scale_for_min_window(920.0, 640.0).max(base);
        let factor = wanted.min(fit);
        if factor < wanted {
            log::log(&format!("[SETTINGS] text size {text_size}% limited to scale {factor:.2} so the window fits the screen"));
        }
        std::env::set_var("SLINT_SCALE_FACTOR", format!("{factor}"));
        std::env::set_var("XOS_TOOLKIT_SCALE_SET", "1");
    }
    if let Err(e) = shell::run(pages::all()) {
        let path = write_crash_file(&format!("UI failed to start: {e}"));
        platform::message_box_error(
            &format!(
                "XOS Toolkit hit an unexpected error and needs to close.\n\nDetails written to:\n{}",
                path.map(|p| p.display().to_string()).unwrap_or_default()
            ),
            "XOS Toolkit",
        );
    }
}

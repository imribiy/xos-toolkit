use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Mutex, OnceLock};

static REBOOT_REQUIRED: AtomicBool = AtomicBool::new(false);
static BUSY: AtomicI32 = AtomicI32::new(0);

type Listener = Box<dyn Fn() + Send + Sync>;

fn listeners() -> &'static Mutex<Vec<Listener>> {
    static L: OnceLock<Mutex<Vec<Listener>>> = OnceLock::new();
    L.get_or_init(|| Mutex::new(Vec::new()))
}

pub fn on_reboot_required_changed(f: impl Fn() + Send + Sync + 'static) {
    listeners().lock().unwrap().push(Box::new(f));
}

fn raise() {
    for l in listeners().lock().unwrap().iter() {
        l();
    }
}

pub fn reboot_required() -> bool {
    REBOOT_REQUIRED.load(Ordering::SeqCst)
}

pub fn require_reboot() {
    if !REBOOT_REQUIRED.swap(true, Ordering::SeqCst) {
        raise();
    }
}

pub fn clear() {
    if REBOOT_REQUIRED.swap(false, Ordering::SeqCst) {
        raise();
    }
}

pub fn require_reboot_if_message_asks(message: &str) {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::Regex::new(r"(?i)\b(please reboot|please restart|reboot to|reboot required|restart your pc|restart windows)\b").unwrap()
    });
    if re.is_match(message) {
        require_reboot();
    }
}

pub fn begin_operation() {
    BUSY.fetch_add(1, Ordering::SeqCst);
}

pub fn end_operation() {
    let _ = BUSY.try_update(Ordering::SeqCst, Ordering::SeqCst, |v| Some(if v > 0 { v - 1 } else { 0 }));
}

pub fn is_busy() -> bool {
    BUSY.load(Ordering::SeqCst) > 0
}

pub struct OperationGuard(());

impl Drop for OperationGuard {
    fn drop(&mut self) {
        end_operation();
    }
}

pub fn operation() -> OperationGuard {
    begin_operation();
    OperationGuard(())
}

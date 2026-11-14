use std::cell::RefCell;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

thread_local! {
    static CURRENT: RefCell<Option<Arc<AtomicUsize>>> = const { RefCell::new(None) };
}

static UNSCOPED: AtomicUsize = AtomicUsize::new(0);

pub fn reset() {
    CURRENT.with(|c| {
        let mut c = c.borrow_mut();
        if c.is_none() {
            UNSCOPED.store(0, Ordering::SeqCst);
        }
        *c = Some(Arc::new(AtomicUsize::new(0)));
    });
}

pub fn any_failed() -> bool {
    CURRENT.with(|c| match c.borrow().as_ref() {
        Some(t) => t.load(Ordering::SeqCst) > 0,
        None => UNSCOPED.load(Ordering::SeqCst) > 0,
    })
}

pub fn track(ok: bool) -> bool {
    if !ok {
        CURRENT.with(|c| match c.borrow().as_ref() {
            Some(t) => {
                t.fetch_add(1, Ordering::SeqCst);
            }
            None => {
                UNSCOPED.fetch_add(1, Ordering::SeqCst);
            }
        });
    }
    ok
}

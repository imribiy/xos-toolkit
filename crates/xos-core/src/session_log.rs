use std::sync::Mutex;

const MAX_SAMPLES_PER_KIND: usize = 8;
const MAX_SAMPLES: usize = 200;

struct State {
    failures: Vec<(String, usize)>,
    samples: Vec<String>,
}

static STATE: Mutex<State> = Mutex::new(State {
    failures: Vec::new(),
    samples: Vec::new(),
});

fn state() -> std::sync::MutexGuard<'static, State> {
    STATE.lock().unwrap_or_else(|e| e.into_inner())
}

fn same(a: &str, b: &str) -> bool {
    a.to_lowercase() == b.to_lowercase()
}

fn starts_with_ci(s: &str, prefix: &str) -> bool {
    s.to_lowercase().starts_with(&prefix.to_lowercase())
}

pub fn operation_failed(kind: &str, detail: &str) {
    operation_failed_opt(
        kind,
        if detail.is_empty() {
            None
        } else {
            Some(detail)
        },
    );
}

pub fn operation_failed_opt(kind: &str, detail: Option<&str>) {
    if kind.trim().is_empty() {
        return;
    }
    let mut st = state();
    match st.failures.iter_mut().find(|(k, _)| same(k, kind)) {
        Some((_, c)) => *c += 1,
        None => st.failures.push((kind.to_string(), 1)),
    }
    if let Some(detail) = detail {
        if st.samples.len() < MAX_SAMPLES {
            let line = format!("{kind}: {detail}");
            let prefix = format!("{kind}:");
            let n = st
                .samples
                .iter()
                .filter(|s| starts_with_ci(s, &prefix))
                .count();
            if n < MAX_SAMPLES_PER_KIND {
                st.samples.push(line);
            }
        }
    }
}

pub fn failure_count() -> usize {
    state().failures.iter().map(|(_, c)| *c).sum()
}

pub fn operation_succeeded(kind: &str, detail: &str) {
    operation_succeeded_opt(
        kind,
        if detail.is_empty() {
            None
        } else {
            Some(detail)
        },
    );
}

pub fn operation_succeeded_opt(kind: &str, detail: Option<&str>) {
    if kind.trim().is_empty() {
        return;
    }
    let mut st = state();
    let Some(i) = st.failures.iter().position(|(k, _)| same(k, kind)) else {
        return;
    };
    if st.failures[i].1 > 1 {
        st.failures[i].1 -= 1;
    } else {
        st.failures.remove(i);
    }
    let Some(detail) = detail else { return };
    let line = format!("{kind}: {detail}");
    if let Some(idx) = st.samples.iter().position(|s| same(s, &line)) {
        st.samples.remove(idx);
    }
}

pub fn write_digest() {
    let (kinds, samples) = {
        let mut st = state();
        if st.failures.is_empty() {
            drop(st);
            crate::log::section("Failure digest: none");
            return;
        }
        let mut order: Vec<(String, usize)> = st.failures.clone();
        order.sort_by(|a, b| b.1.cmp(&a.1));
        let kinds: Vec<String> = order
            .iter()
            .map(|(k, c)| format!("  {c:>4}x {k}"))
            .collect();
        let samples = std::mem::take(&mut st.samples);
        st.failures.clear();
        (kinds, samples)
    };
    crate::log::section(&format!("Failure digest: {} kind(s)", kinds.len()));
    for line in &kinds {
        crate::log::log(line);
    }
    if !samples.is_empty() {
        crate::log::log("  examples:");
        for s in samples.iter().take(40) {
            crate::log::log(&format!("    {s}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_and_samples() {
        for i in 0..10 {
            operation_failed_opt("sessiontest-kind", Some(&format!("d{i}")));
        }
        operation_failed_opt("SessionTest-Kind", None);
        assert!(failure_count() >= 11);
        let n = state()
            .samples
            .iter()
            .filter(|s| s.starts_with("sessiontest-kind:"))
            .count();
        assert_eq!(n, 8);
        operation_succeeded_opt("sessiontest-kind", Some("d0"));
        let n = state()
            .samples
            .iter()
            .filter(|s| s.starts_with("sessiontest-kind:"))
            .count();
        assert_eq!(n, 7);
        for _ in 0..10 {
            operation_succeeded_opt("sessiontest-kind", None);
        }
        assert!(!state()
            .failures
            .iter()
            .any(|(k, _)| k == "sessiontest-kind"));
        state().samples.clear();
    }
}

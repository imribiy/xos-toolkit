use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::Instant;

use crate::ci_map::CiMap;
use crate::process::{run_cmd_opts, run_cmd_output_timeout, CmdOptions};
use crate::util::perf_detail;

const FEATURE_NOT_AVAILABLE_EXIT_CODE: i32 = -2146498270;

pub const FEATURE_NOT_AVAILABLE_TEXT: &str = "-2146498270";

const FEATURE_STATE_CACHE_TIMEOUT_MS: u128 = 10 * 60 * 1000;

struct Query {
    result: Mutex<Option<CiMap<String>>>,
    done: Condvar,
}

struct State {
    cache: Option<CiMap<String>>,
    cache_time: Option<Instant>,
    query: Option<Arc<Query>>,
    generation: u64,
}

fn state() -> &'static Mutex<State> {
    static S: OnceLock<Mutex<State>> = OnceLock::new();
    S.get_or_init(|| {
        Mutex::new(State {
            cache: None,
            cache_time: None,
            query: None,
            generation: 0,
        })
    })
}

pub fn enable_feature(feature_name: &str) -> bool {
    invalidate_feature_state_cache();
    run_cmd_opts(
        "dism.exe",
        &format!("/online /Enable-Feature /FeatureName:\"{feature_name}\" /Quiet /NoRestart"),
        &CmdOptions {
            timeout_ms: Some(600000),
            allow_restart_required: true,
            ..Default::default()
        },
    )
}

pub fn disable_feature(feature_name: &str) -> bool {
    invalidate_feature_state_cache();
    run_cmd_opts(
        "dism.exe",
        &format!("/online /Disable-Feature /FeatureName:\"{feature_name}\" /Quiet /NoRestart"),
        &CmdOptions {
            timeout_ms: Some(600000),
            allow_restart_required: true,
            ..Default::default()
        },
    )
}

pub fn is_feature_absent_on_this_build(feature_name: &str) -> bool {
    invalidate_feature_state_cache();
    run_cmd_opts(
        "dism.exe",
        &format!("/online /Enable-Feature /FeatureName:\"{feature_name}\" /Quiet /NoRestart"),
        &CmdOptions {
            timeout_ms: Some(600000),
            allow_restart_required: true,
            accepted_exit_codes: &[FEATURE_NOT_AVAILABLE_EXIT_CODE],
            ..Default::default()
        },
    )
}

pub fn invalidate_feature_state_cache() {
    let mut s = state().lock().unwrap();
    s.cache = None;
    s.query = None;
    s.generation += 1;
}

enum Pending {
    Ready(CiMap<String>),
    Waiting(Arc<Query>),
}

fn start_or_get() -> Pending {
    let mut s = state().lock().unwrap();
    if let (Some(c), Some(t)) = (&s.cache, s.cache_time) {
        if t.elapsed().as_millis() < FEATURE_STATE_CACHE_TIMEOUT_MS {
            return Pending::Ready(c.clone());
        }
    }
    if s.query.is_none() {
        let generation = s.generation;
        let q = Arc::new(Query {
            result: Mutex::new(None),
            done: Condvar::new(),
        });
        s.query = Some(q.clone());
        let worker = q.clone();
        std::thread::spawn(move || {
            let result = query_and_store_feature_states(generation);
            {
                let mut s = state().lock().unwrap();
                if let Some(cur) = &s.query {
                    if Arc::ptr_eq(cur, &worker) {
                        s.query = None;
                    }
                }
            }
            *worker.result.lock().unwrap() = Some(result);
            worker.done.notify_all();
        });
    }
    if let Some(c) = &s.cache {
        return Pending::Ready(c.clone());
    }
    Pending::Waiting(s.query.clone().unwrap())
}

pub fn get_all_feature_states() -> CiMap<String> {
    match start_or_get() {
        Pending::Ready(c) => c,
        Pending::Waiting(q) => {
            let mut guard = q.result.lock().unwrap();
            while guard.is_none() {
                guard = q.done.wait(guard).unwrap();
            }
            guard.clone().unwrap()
        }
    }
}

fn query_and_store_feature_states(generation: u64) -> CiMap<String> {
    let result = query_all_feature_states();
    if !result.is_empty() {
        let mut s = state().lock().unwrap();
        if generation == s.generation {
            s.cache = Some(result.clone());
            s.cache_time = Some(Instant::now());
        }
    }
    result
}

pub(crate) fn parse_feature_states(output: &str) -> CiMap<String> {
    let mut dict = CiMap::new();
    for line in output.split(['\r', '\n']).filter(|l| !l.is_empty()) {
        if let Some(sep) = line.find('|') {
            if sep == 0 {
                continue;
            }
            dict.insert(line[..sep].trim(), line[sep + 1..].trim().to_string());
        }
    }
    dict
}

fn query_all_feature_states() -> CiMap<String> {
    let sw = Instant::now();
    let output = run_cmd_output_timeout(
        "powershell.exe",
        "-NoProfile -NonInteractive -Command \"Get-WindowsOptionalFeature -Online | ForEach-Object { $_.FeatureName + '|' + $_.State }\"",
        120000,
    );
    let dict = parse_feature_states(&output);
    perf_detail(
        "feature states",
        sw.elapsed().as_millis(),
        &format!("{} features", dict.len()),
    );
    dict
}

pub fn warm_feature_state_cache() {
    let _ = start_or_get();
}

pub fn is_feature_state_enabled(state: &str) -> bool {
    state.eq_ignore_ascii_case("Enabled")
        || state.eq_ignore_ascii_case("EnablePending")
        || state.eq_ignore_ascii_case("Enable Pending")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_feature_lines() {
        let m = parse_feature_states(
            "NetFx3|Disabled\r\nMicrosoft-Hyper-V|Enabled\r\n|bad\r\nnoseparator\r\n",
        );
        assert_eq!(m.len(), 2);
        assert_eq!(m.get("netfx3").map(|s| s.as_str()), Some("Disabled"));
        assert!(is_feature_state_enabled("enable pending"));
        assert!(!is_feature_state_enabled("Disabled"));
    }
}

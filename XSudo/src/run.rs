use core::ffi::c_void;
use core::ptr::null;

use crate::cli::tail_slice;
use crate::cli::Command;
use crate::cli::Mode;
use crate::cli::Plan;
use crate::exitcode::ERR_CHILD;
use crate::exitcode::ERR_IDENTITY;
use crate::exitcode::ERR_WORKDIR;
use crate::sys;

fn build_cmdline(plan: &Plan, cmd: &[u16]) -> Vec<u16> {
    match plan.command {
        Command::DefaultShell => sys::system_shell_cmdline(),
        Command::Tail(start) => {
            let mut t = tail_slice(cmd, start);
            t.push(0);
            t
        }
    }
}

fn workdir_wide(plan: &Plan) -> Result<Option<Vec<u16>>, u32> {
    match &plan.workdir {
        None => Ok(None),
        Some(dir) => {
            if std::path::Path::new(dir).is_dir() {
                Ok(Some(sys::wide(dir)))
            } else {
                Err(ERR_WORKDIR)
            }
        }
    }
}

pub fn run(plan: &Plan, cmd: &[u16]) -> Result<u32, u32> {
    let mut cmdbuf = build_cmdline(plan, cmd);
    let wd = workdir_wide(plan)?;
    let wd_ref = wd.as_deref();

    let caller = sys::caller_token_query();
    let env = caller.as_ref().and_then(|c| sys::make_env_block(c.0));
    let envptr = env
        .as_ref()
        .map(|e| e.0 as *const c_void)
        .unwrap_or(null());
    let session = sys::caller_session_id();

    match plan.mode {
        Mode::Admin => run_admin(plan, &mut cmdbuf, wd_ref, envptr, caller.as_ref(), session),
        Mode::System => run_identity(None, plan, &mut cmdbuf, wd_ref, envptr, session),
        Mode::TrustedInstaller => {
            let ti_pid = sys::ensure_trustedinstaller_running()?;
            run_identity(Some(ti_pid), plan, &mut cmdbuf, wd_ref, envptr, session)
        }
    }
}

fn run_admin(
    plan: &Plan,
    cmdbuf: &mut [u16],
    wd: Option<&[u16]>,
    envptr: *const c_void,
    caller: Option<&sys::Handle>,
    session: u32,
) -> Result<u32, u32> {
    if plan.privileged {
        let c = caller.ok_or(ERR_IDENTITY)?;
        let dup = sys::duplicate_primary(c.0).ok_or(ERR_IDENTITY)?;
        if !sys::enable_all_privileges(dup.0) {
            return Err(ERR_IDENTITY);
        }
        sys::set_session(dup.0, session);
        let launched = sys::spawn_as_user(dup.0, cmdbuf, wd, envptr).map_err(|_| ERR_CHILD)?;
        return sys::wait_for_exit(launched.process.0).ok_or(ERR_CHILD);
    }
    let launched = sys::spawn_plain(cmdbuf, wd, envptr).map_err(|_| ERR_CHILD)?;
    sys::wait_for_exit(launched.process.0).ok_or(ERR_CHILD)
}

pub(crate) fn open_richest_system_source(exe_lower: &str) -> Option<sys::Handle> {
    let mut tries = 0;
    loop {
        let mut best: Option<sys::Handle> = None;
        let mut best_count = 0u32;
        for pid in sys::find_all_process_ids(exe_lower) {
            if let Some(tok) = sys::open_source_token(pid) {
                let count = sys::token_privilege_count(tok.0);
                if best.is_none() || count > best_count {
                    best = Some(tok);
                    best_count = count;
                }
            }
        }
        if best.is_some() {
            return best;
        }
        tries += 1;
        if tries > 5 {
            return None;
        }
        sys::sleep_ms(100);
    }
}

pub(crate) fn open_pid_source(pid: u32) -> Option<sys::Handle> {
    let mut tries = 0;
    loop {
        if let Some(tok) = sys::open_source_token(pid) {
            return Some(tok);
        }
        tries += 1;
        if tries > 5 {
            return None;
        }
        sys::sleep_ms(100);
    }
}

fn run_identity(
    ti_pid: Option<u32>,
    plan: &Plan,
    cmdbuf: &mut [u16],
    wd: Option<&[u16]>,
    envptr: *const c_void,
    session: u32,
) -> Result<u32, u32> {
    sys::enable_privilege("SeDebugPrivilege");

    let winlogon = open_richest_system_source("winlogon.exe").ok_or(ERR_IDENTITY)?;

    let guard = sys::impersonate(winlogon.0);
    sys::enable_thread_privileges_for_launch();

    let src = match ti_pid {
        None => winlogon,
        Some(pid) => open_pid_source(pid).ok_or(ERR_IDENTITY)?,
    };

    let primary = sys::duplicate_primary(src.0).ok_or(ERR_IDENTITY)?;
    sys::set_session(primary.0, session);
    if plan.privileged && !sys::enable_all_privileges(primary.0) {
        return Err(ERR_IDENTITY);
    }

    let result = sys::spawn_as_user(primary.0, cmdbuf, wd, envptr);
    drop(guard);

    let launched = result.map_err(|_| ERR_CHILD)?;
    sys::wait_for_exit(launched.process.0).ok_or(ERR_CHILD)
}

use core::ptr::null_mut;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::LibraryLoader::GetModuleFileNameW;
use windows_sys::Win32::UI::Shell::ShellExecuteExW;
use windows_sys::Win32::UI::Shell::SHELLEXECUTEINFOW;
use windows_sys::Win32::UI::Shell::SEE_MASK_NOCLOSEPROCESS;
use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

use crate::cli::tokenize;
use crate::exitcode::ERR_ELEVATION;
use crate::sys;

pub const ELEVATE_PREFIX: &str = "--XSudoElevate=";

enum Desc {
    Console,
    Handle(usize),
}

fn encode_desc(h: HANDLE) -> String {
    if sys::is_console_handle(h) {
        "C".to_string()
    } else {
        (h as usize).to_string()
    }
}

fn decode_desc(field: &str) -> Desc {
    if field.eq_ignore_ascii_case("C") {
        Desc::Console
    } else {
        match field.parse::<usize>() {
            Ok(v) => Desc::Handle(v),
            Err(_) => Desc::Console,
        }
    }
}

pub fn build_parameters(
    pid: u32,
    din: &str,
    dout: &str,
    derr: &str,
    envname: &str,
    original_tail: &[u16],
) -> Vec<u16> {
    let head = format!("{ELEVATE_PREFIX}{pid};{din};{dout};{derr};{envname} ");
    let mut v: Vec<u16> = head.encode_utf16().collect();
    v.extend_from_slice(original_tail);
    while v.last() == Some(&0x20) {
        v.pop();
    }
    v.push(0);
    v
}

struct Parsed {
    pid: u32,
    din: Desc,
    dout: Desc,
    derr: Desc,
    envname: Option<String>,
    cleaned: Vec<u16>,
}

fn parse_elevate(cmd: &[u16]) -> Option<Parsed> {
    let tokens = tokenize(cmd);
    if tokens.len() < 2 {
        return None;
    }
    let first = &tokens[1].text;
    let prefix = ELEVATE_PREFIX.to_ascii_lowercase();
    let rest = first.to_ascii_lowercase();
    if !rest.starts_with(&prefix) {
        return None;
    }
    let payload = &first[ELEVATE_PREFIX.len()..];
    let parts: Vec<&str> = payload.split(';').collect();
    if parts.len() != 5 {
        return None;
    }
    let pid: u32 = parts[0].parse().ok()?;
    let envname = if parts[4] == "-" {
        None
    } else {
        Some(parts[4].to_string())
    };

    let mut cleaned: Vec<u16> = "XSudo.exe".encode_utf16().collect();
    if tokens.len() >= 3 {
        cleaned.push(0x20);
        cleaned.extend_from_slice(&cmd[tokens[2].start..]);
    }
    Some(Parsed {
        pid,
        din: decode_desc(parts[1]),
        dout: decode_desc(parts[2]),
        derr: decode_desc(parts[3]),
        envname,
        cleaned,
    })
}

pub fn handle_elevated_stage(raw: &[u16]) -> (Vec<u16>, bool) {
    match parse_elevate(raw) {
        None => (raw.to_vec(), false),
        Some(info) => {
            if Some(info.pid) == sys::parent_process_id() {
                apply_reattach(&info);
            }
            (info.cleaned, true)
        }
    }
}

fn apply_reattach(info: &Parsed) {
    let needs_console = matches!(info.din, Desc::Console)
        || matches!(info.dout, Desc::Console)
        || matches!(info.derr, Desc::Console);
    if needs_console {
        sys::reattach_to_console(info.pid);
    }
    let parent = sys::open_for_dup(info.pid);

    apply_one(&info.din, true, parent.as_ref(), sys::set_std_input);
    apply_one(&info.dout, false, parent.as_ref(), sys::set_std_output);
    apply_one(&info.derr, false, parent.as_ref(), sys::set_std_error);

    if let Some(name) = &info.envname {
        sys::apply_env_from_mapping(name);
    }
}

fn apply_one(desc: &Desc, is_input: bool, parent: Option<&sys::Handle>, set: fn(HANDLE)) {
    match desc {
        Desc::Console => {
            let h = if is_input {
                sys::console_input_handle()
            } else {
                sys::console_output_handle()
            };
            set(h);
        }
        Desc::Handle(v) => {
            if let Some(p) = parent {
                if let Some(h) = sys::dup_from(p.0, *v) {
                    set(h);
                }
            }
        }
    }
}

fn self_exe_path() -> Vec<u16> {
    unsafe {
        let mut buf = vec![0u16; 32768];
        let n = GetModuleFileNameW(null_mut(), buf.as_mut_ptr(), buf.len() as u32);
        buf.truncate(n as usize);
        buf.push(0);
        buf
    }
}

fn original_tail(cmd: &[u16]) -> Vec<u16> {
    let tokens = tokenize(cmd);
    if tokens.len() < 2 {
        Vec::new()
    } else {
        cmd[tokens[1].start..].to_vec()
    }
}

pub fn self_elevate(cmd: &[u16]) -> Result<u32, u32> {
    unsafe {
        let pid = sys::current_process_id();
        let (hin, hout, herr) = sys::get_std_triple();
        let din = encode_desc(hin);
        let dout = encode_desc(hout);
        let derr = encode_desc(herr);

        let envname = format!("Local\\XSudoEnv-{pid}");
        let mapping = sys::create_env_mapping(&envname);
        let envfield = if mapping.is_some() { envname.as_str() } else { "-" };

        let tail = original_tail(cmd);
        let params = build_parameters(pid, &din, &dout, &derr, envfield, &tail);
        let file = self_exe_path();
        let verb = sys::wide("runas");
        let workdir = sys::current_directory();

        let mut info: SHELLEXECUTEINFOW = core::mem::zeroed();
        info.cbSize = core::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
        info.fMask = SEE_MASK_NOCLOSEPROCESS;
        info.lpVerb = verb.as_ptr();
        info.lpFile = file.as_ptr();
        info.lpParameters = params.as_ptr();
        info.lpDirectory = workdir.as_ptr();
        info.nShow = SW_HIDE;

        if ShellExecuteExW(&mut info) == 0 {
            return Err(ERR_ELEVATION);
        }
        let process: HANDLE = info.hProcess;
        if process.is_null() {
            return Err(ERR_ELEVATION);
        }
        let guard = sys::Handle(process);
        let code = sys::wait_for_exit(guard.0).ok_or(ERR_ELEVATION);
        drop(mapping);
        code
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    #[test]
    fn build_then_parse_round_trips() {
        let tail = w("--NoLogo -TI cmd /c echo hi");
        let params = build_parameters(4321, "C", "88", "92", "Local\\XSudoEnv-4321", &tail);
        let mut fake = w("XSudo.exe ");
        fake.extend_from_slice(&params[..params.len() - 1]);
        let p = parse_elevate(&fake).expect("detect");
        assert_eq!(p.pid, 4321);
        assert!(matches!(p.din, Desc::Console));
        assert!(matches!(p.dout, Desc::Handle(88)));
        assert!(matches!(p.derr, Desc::Handle(92)));
        assert_eq!(p.envname.as_deref(), Some("Local\\XSudoEnv-4321"));
        let cleaned = String::from_utf16_lossy(&p.cleaned);
        assert!(cleaned.starts_with("XSudo.exe "));
        assert!(cleaned.ends_with("--NoLogo -TI cmd /c echo hi"));
    }

    #[test]
    fn parse_requires_five_fields() {
        let fake = w("XSudo.exe --XSudoElevate=1;C;C cmd");
        assert!(parse_elevate(&fake).is_none());
    }

    #[test]
    fn parse_none_without_prefix() {
        assert!(parse_elevate(&w("XSudo.exe --NoLogo whoami")).is_none());
        assert!(parse_elevate(&w("XSudo.exe")).is_none());
    }

    #[test]
    fn env_dash_means_none() {
        let params = build_parameters(7, "C", "C", "C", "-", &[]);
        let mut fake = w("XSudo.exe ");
        fake.extend_from_slice(&params[..params.len() - 1]);
        let p = parse_elevate(&fake).unwrap();
        assert!(p.envname.is_none());
        assert_eq!(String::from_utf16_lossy(&p.cleaned), "XSudo.exe");
    }
}

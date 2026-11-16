use std::io::{Read, Write};
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use regex::Regex;
use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
use windows::Win32::Globalization::{GetOEMCP, MultiByteToWideChar, MULTI_BYTE_TO_WIDE_CHAR_FLAGS};
use windows::Win32::System::Threading::{
    GetExitCodeProcess, GetProcessId, TerminateProcess, WaitForSingleObject,
};
use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};

use crate::clixml::decode_clixml;
use crate::util::{file_name_of, io_message, pcwstr, perf_detail, truncate_for_log, ulen, wide};
use xos_core::{log, session_log};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub fn ensure_hidden_powershell_arguments(file_name: &str, arguments: &str) -> String {
    let executable = file_name_of(file_name);
    if !executable.eq_ignore_ascii_case("powershell.exe")
        && !executable.eq_ignore_ascii_case("powershell")
    {
        return arguments.to_string();
    }
    static R: OnceLock<Regex> = OnceLock::new();
    let r = R.get_or_init(|| {
        Regex::new(r"(?i)(^|\s)-(?:windowstyle|w)\s+(?:hidden|h)(?:\s|$)").unwrap()
    });
    if r.is_match(arguments) {
        return arguments.to_string();
    }
    format!("-WindowStyle Hidden {arguments}")
}

pub fn oem_code_page() -> i32 {
    let cp = unsafe { GetOEMCP() };
    if cp == 0 {
        437
    } else {
        cp as i32
    }
}

pub(crate) fn decode_code_page(cp: u32, data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }
    unsafe {
        let flags = MULTI_BYTE_TO_WIDE_CHAR_FLAGS(0);
        let n = MultiByteToWideChar(cp, flags, data, None);
        if n <= 0 {
            return String::from_utf8_lossy(data).to_string();
        }
        let mut buf = vec![0u16; n as usize];
        let m = MultiByteToWideChar(cp, flags, data, Some(&mut buf));
        buf.truncate(m.max(0) as usize);
        String::from_utf16_lossy(&buf)
    }
}

pub(crate) fn decode_oem(data: &[u8]) -> String {
    decode_code_page(oem_code_page() as u32, data)
}

fn utf16_from(data: &[u8], big_endian: bool) -> String {
    let units: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| {
            if big_endian {
                u16::from_be_bytes([c[0], c[1]])
            } else {
                u16::from_le_bytes([c[0], c[1]])
            }
        })
        .collect();
    String::from_utf16_lossy(&units)
}

pub fn decode_console_bytes(data: &[u8]) -> String {
    if data.len() >= 2 && data[0] == 0xff && data[1] == 0xfe {
        return utf16_from(&data[2..], false);
    }
    if data.len() >= 2 && data[0] == 0xfe && data[1] == 0xff {
        return utf16_from(&data[2..], true);
    }
    match std::str::from_utf8(data) {
        Ok(s) => s.trim_start_matches('\u{feff}').to_string(),
        Err(_) => decode_oem(data),
    }
}

pub(crate) fn decode_text_with_bom(data: &[u8]) -> String {
    if data.len() >= 3 && data[0] == 0xef && data[1] == 0xbb && data[2] == 0xbf {
        return String::from_utf8_lossy(&data[3..]).to_string();
    }
    if data.len() >= 2 && data[0] == 0xff && data[1] == 0xfe {
        return utf16_from(&data[2..], false);
    }
    if data.len() >= 2 && data[0] == 0xfe && data[1] == 0xff {
        return utf16_from(&data[2..], true);
    }
    String::from_utf8_lossy(data).to_string()
}

pub(crate) fn decode_stream_bytes(data: &[u8]) -> String {
    if data.len() >= 3 && data[0] == 0xef && data[1] == 0xbb && data[2] == 0xbf {
        return String::from_utf8_lossy(&data[3..]).to_string();
    }
    if data.len() >= 2 && data[0] == 0xff && data[1] == 0xfe {
        return utf16_from(&data[2..], false);
    }
    if data.len() >= 2 && data[0] == 0xfe && data[1] == 0xff {
        return utf16_from(&data[2..], true);
    }
    decode_oem(data)
}

pub(crate) struct PipeCapture {
    buf: Arc<Mutex<Vec<u8>>>,
    done: Arc<AtomicBool>,
}

impl PipeCapture {
    fn new<R: Read + Send + 'static>(mut reader: R) -> PipeCapture {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let done = Arc::new(AtomicBool::new(false));
        let b = buf.clone();
        let d = done.clone();
        std::thread::spawn(move || {
            let mut chunk = [0u8; 4096];
            loop {
                match reader.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => b.lock().unwrap().extend_from_slice(&chunk[..n]),
                }
            }
            d.store(true, Ordering::SeqCst);
        });
        PipeCapture { buf, done }
    }

    pub(crate) fn collect(&self, wait_ms: u64) -> (Vec<u8>, bool) {
        let start = Instant::now();
        while !self.done.load(Ordering::SeqCst) && start.elapsed() < Duration::from_millis(wait_ms)
        {
            std::thread::sleep(Duration::from_millis(5));
        }
        let complete = self.done.load(Ordering::SeqCst);
        (self.buf.lock().unwrap().clone(), complete)
    }

    pub(crate) fn wait_all(&self) -> Vec<u8> {
        while !self.done.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(5));
        }
        self.buf.lock().unwrap().clone()
    }
}

pub(crate) struct Spawned {
    pub child: Child,
    pub out: PipeCapture,
    pub err: PipeCapture,
}

pub(crate) fn spawn_hidden(
    file_name: &str,
    arguments: &str,
    with_stdin: bool,
) -> std::io::Result<Spawned> {
    let args = ensure_hidden_powershell_arguments(file_name, arguments);
    let mut cmd = Command::new(file_name);
    if !args.is_empty() {
        cmd.raw_arg(&args);
    }
    cmd.creation_flags(CREATE_NO_WINDOW)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(if with_stdin {
            Stdio::piped()
        } else {
            Stdio::null()
        });
    let mut child = cmd.spawn()?;
    let out = PipeCapture::new(child.stdout.take().unwrap());
    let err = PipeCapture::new(child.stderr.take().unwrap());
    Ok(Spawned { child, out, err })
}

pub(crate) fn wait_for_exit(child: &Child, timeout_ms: u32) -> bool {
    let h = HANDLE(child.as_raw_handle());
    unsafe { WaitForSingleObject(h, timeout_ms) == WAIT_OBJECT_0 }
}

fn taskkill_tree(pid: u32) {
    if let Ok(mut s) = spawn_hidden("taskkill.exe", &format!("/PID {pid} /T /F"), false) {
        wait_for_exit(&s.child, 5000);
        let _ = s.child.try_wait();
    }
}

pub fn terminate_process_tree(child: &mut Child) {
    let pid = child.id();
    taskkill_tree(pid);
    if let Ok(None) = child.try_wait() {
        let _ = child.kill();
    }
    wait_for_exit(child, 2000);
}

fn exit_code_of(child: &mut Child) -> i32 {
    child.wait().ok().and_then(|s| s.code()).unwrap_or(-1)
}

#[derive(Clone, Default)]
pub struct CmdOptions<'a> {
    pub timeout_ms: Option<u32>,
    pub suppress_log: bool,
    pub allow_restart_required: bool,
    pub accepted_exit_codes: &'a [i32],
    pub standard_input: Option<&'a str>,
}

pub fn describe_command(file_name: &str, arguments: &str) -> String {
    const MAX_TOTAL: usize = 600;
    const MAX_TOKEN: usize = 80;
    if arguments.is_empty() {
        return file_name.to_string();
    }
    let mut sb = String::new();
    let mut sb_len = 0usize;
    for token in arguments.split(' ') {
        if sb_len > 0 {
            sb.push(' ');
            sb_len += 1;
        }
        let tl = ulen(token);
        if tl > MAX_TOKEN && is_encoded_blob(token) {
            let t = format!("<encoded {tl} chars>");
            sb_len += ulen(&t);
            sb.push_str(&t);
        } else {
            sb.push_str(token);
            sb_len += tl;
        }
        if sb_len > MAX_TOTAL {
            let rest = ulen(arguments) as i64 - sb_len as i64;
            sb.push_str(&format!(" ... (+{rest} chars)"));
            break;
        }
    }
    format!("{file_name} {sb}")
}

fn is_encoded_blob(token: &str) -> bool {
    if ulen(token) < 120 {
        return false;
    }
    token.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || c == '+'
            || c == '/'
            || c == '='
            || c == '-'
            || c == '_'
            || c == '"'
    })
}

pub fn run_cmd(file_name: &str, arguments: &str) -> bool {
    run_cmd_opts(file_name, arguments, &CmdOptions::default())
}

pub fn run_cmd_timeout(file_name: &str, arguments: &str, timeout_ms: u32) -> bool {
    run_cmd_opts(
        file_name,
        arguments,
        &CmdOptions {
            timeout_ms: Some(timeout_ms),
            ..Default::default()
        },
    )
}

pub fn exit_code_accepted(code: i32, allow_restart_required: bool, accepted: &[i32]) -> bool {
    code == 0 || (allow_restart_required && code == 3010) || accepted.contains(&code)
}

pub fn run_cmd_opts(file_name: &str, arguments: &str, o: &CmdOptions) -> bool {
    run_cmd_opts_code(file_name, arguments, o).0
}

pub fn run_cmd_opts_code(file_name: &str, arguments: &str, o: &CmdOptions) -> (bool, Option<i32>) {
    let timeout_ms = o.timeout_ms.unwrap_or(30000);
    let suppress_log = o.suppress_log;
    if !suppress_log {
        log::log(&format!("[CMD] {}", describe_command(file_name, arguments)));
    }
    let sw = Instant::now();
    let mut sp = match spawn_hidden(file_name, arguments, o.standard_input.is_some()) {
        Ok(s) => s,
        Err(e) => {
            if !suppress_log {
                log::log(&format!("[CMD] -> exception: {}", io_message(&e)));
            }
            return (false, None);
        }
    };
    if let Some(input) = o.standard_input {
        if let Some(mut stdin) = sp.child.stdin.take() {
            let _ = stdin.write_all(input.as_bytes());
            drop(stdin);
        }
    }
    if !wait_for_exit(&sp.child, timeout_ms) {
        terminate_process_tree(&mut sp.child);
        sp.out.collect(5000);
        sp.err.collect(5000);
        if !suppress_log {
            log::log("[CMD] -> TIMEOUT");
        }
        return (false, None);
    }
    sp.out.wait_all();
    let stderr = decode_clixml(&decode_stream_bytes(&sp.err.wait_all()));
    let code = exit_code_of(&mut sp.child);
    let ms = sw.elapsed().as_millis();
    if !suppress_log {
        log::log(&format!("[CMD] -> exit {code} in {ms} ms"));
    } else if ms >= 1000 {
        perf_detail(&file_name_of(file_name), ms, "silent call");
    }
    let ok_code = exit_code_accepted(code, o.allow_restart_required, o.accepted_exit_codes);
    if (!suppress_log || !ok_code) && code != 0 && !stderr.trim().is_empty() {
        log::log(&format!(
            "[CMD] -> stderr: {}",
            truncate_for_log(stderr.trim())
        ));
    }
    if !ok_code && !suppress_log {
        session_log::operation_failed(
            &format!("command exit {code}"),
            &describe_command(file_name, arguments),
        );
    }
    (ok_code, Some(code))
}

pub fn run_cmd_with_error(file_name: &str, arguments: &str) -> (bool, Option<String>) {
    run_cmd_with_error_timeout(file_name, arguments, 30000)
}

pub fn run_cmd_with_error_timeout(
    file_name: &str,
    arguments: &str,
    timeout_ms: u32,
) -> (bool, Option<String>) {
    let mut sp = match spawn_hidden(file_name, arguments, false) {
        Ok(s) => s,
        Err(e) => return (false, Some(io_message(&e))),
    };
    if !wait_for_exit(&sp.child, timeout_ms) {
        terminate_process_tree(&mut sp.child);
        sp.out.collect(5000);
        sp.err.collect(5000);
        return (false, Some("Operation timed out.".to_string()));
    }
    let stderr = decode_clixml(&decode_stream_bytes(&sp.err.wait_all()));
    let stdout = decode_stream_bytes(&sp.out.wait_all());
    let code = exit_code_of(&mut sp.child);
    if code != 0 {
        let detail = if !stderr.trim().is_empty() {
            stderr.trim().to_string()
        } else if !stdout.trim().is_empty() {
            stdout.trim().to_string()
        } else {
            format!("Exited with code {code}.")
        };
        return (false, Some(detail));
    }
    (true, None)
}

pub fn run_cmd_capture(file_name: &str, arguments: &str) -> (i32, String, String) {
    run_cmd_capture_opts(file_name, arguments, 30000, false)
}

pub fn run_cmd_capture_opts(
    file_name: &str,
    arguments: &str,
    timeout_ms: u32,
    detect_utf8: bool,
) -> (i32, String, String) {
    let mut sp = match spawn_hidden(file_name, arguments, false) {
        Ok(s) => s,
        Err(e) => return (-1, String::new(), io_message(&e)),
    };
    if !wait_for_exit(&sp.child, timeout_ms) {
        terminate_process_tree(&mut sp.child);
        sp.out.collect(5000);
        sp.err.collect(5000);
        return (-1, String::new(), "Operation timed out.".to_string());
    }
    let decode = |b: &[u8]| {
        if detect_utf8 {
            decode_console_bytes(b)
        } else {
            decode_stream_bytes(b)
        }
    };
    let (ob, output_complete) = sp.out.collect(5000);
    let (eb, error_complete) = sp.err.collect(5000);
    let output = decode(&ob);
    let error = decode(&eb);
    let code = exit_code_of(&mut sp.child);
    if !output_complete || !error_complete {
        let which = if !output_complete && !error_complete {
            "output and error pipes stay"
        } else if !output_complete {
            "output pipe stays"
        } else {
            "error pipe stays"
        };
        log::log(&format!(
            "[CMD] {}: exited {code}, but its {which} open 5 s later, held by a child process; keeping the {} characters read so far",
            describe_command(file_name, arguments),
            ulen(&output) + ulen(&error)
        ));
    }
    (code, output, decode_clixml(&error))
}

pub fn run_cmd_output(file_name: &str, arguments: &str) -> String {
    run_cmd_output_timeout(file_name, arguments, 30000)
}

pub fn run_cmd_output_timeout(file_name: &str, arguments: &str, timeout_ms: u32) -> String {
    let mut sp = match spawn_hidden(file_name, arguments, false) {
        Ok(s) => s,
        Err(_) => return String::new(),
    };
    if !wait_for_exit(&sp.child, timeout_ms) {
        terminate_process_tree(&mut sp.child);
        let (ob, complete) = sp.out.collect(5000);
        if !complete {
            return String::new();
        }
        sp.err.collect(5000);
        return decode_stream_bytes(&ob);
    }
    let stdout = decode_stream_bytes(&sp.out.wait_all());
    sp.err.wait_all();
    let _ = sp.child.wait();
    stdout
}

pub fn run_cmd_visible(file_name: &str, arguments: &str) -> bool {
    run_cmd_visible_timeout(file_name, arguments, 600000)
}

pub fn shell_start(file_name: &str, arguments: &str) -> bool {
    let file_w = wide(file_name);
    let args_w = wide(arguments);
    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: 0x0000_0400 | 0x0000_0100,
        lpFile: pcwstr(&file_w),
        lpParameters: if arguments.is_empty() {
            windows::core::PCWSTR::null()
        } else {
            pcwstr(&args_w)
        },
        nShow: 1,
        ..Default::default()
    };
    unsafe { ShellExecuteExW(&mut info).is_ok() }
}

pub fn run_cmd_visible_timeout(file_name: &str, arguments: &str, timeout_ms: u32) -> bool {
    let sw = Instant::now();
    let file_w = wide(file_name);
    let args_w = wide(arguments);
    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS | 0x0000_0400 | 0x0000_0100,
        lpFile: pcwstr(&file_w),
        lpParameters: pcwstr(&args_w),
        nShow: 1,
        ..Default::default()
    };
    let started = unsafe { ShellExecuteExW(&mut info) };
    if let Err(e) = started {
        log::log(&format!(
            "[RUN-VISIBLE] {file_name} -> exception after {} ms: Win32Exception: {}",
            sw.elapsed().as_millis(),
            e.message()
        ));
        return false;
    }
    let h = info.hProcess;
    if h.is_invalid() {
        log::log(&format!("[RUN-VISIBLE] {file_name} -> could not start"));
        return false;
    }
    let exited = unsafe { WaitForSingleObject(h, timeout_ms) == WAIT_OBJECT_0 };
    let elapsed = sw.elapsed().as_millis();
    if !exited {
        let pid = unsafe { GetProcessId(h) };
        taskkill_tree(pid);
        unsafe {
            let _ = TerminateProcess(h, 1);
            WaitForSingleObject(h, 2000);
            let _ = CloseHandle(h);
        }
        log::log(&format!(
            "[RUN-VISIBLE] {file_name} -> TIMEOUT after {elapsed} ms (limit {timeout_ms} ms)"
        ));
        return false;
    }
    let mut raw = 0u32;
    unsafe {
        let _ = GetExitCodeProcess(h, &mut raw);
        let _ = CloseHandle(h);
    }
    let code = raw as i32;
    log::log(&format!(
        "[RUN-VISIBLE] {file_name} -> exit {code} in {elapsed} ms"
    ));
    if elapsed >= 1000 {
        perf_detail(
            &format!("visible {}", file_name_of(file_name)),
            elapsed,
            &format!("exit {code}"),
        );
    }
    if code == 0 {
        return true;
    }
    if code == 1605 || code == 1614 || code == 1641 || code == 3010 {
        log::log(&format!(
            "[RUN-VISIBLE] exit {code} treated as success (already installed or reboot required)"
        ));
        return true;
    }
    false
}

pub fn kill_process(process_name: &str) -> bool {
    run_cmd("taskkill.exe", &format!("/F /IM \"{process_name}\""))
}

pub(crate) fn run_cmd_capture_into(file_name: &str, arguments: &str, sink: &mut String) -> bool {
    let mut sp = match spawn_hidden(file_name, arguments, false) {
        Ok(s) => s,
        Err(e) => {
            sink.push_str(&format!(
                "{file_name} could not be started: {}\r\n",
                io_message(&e)
            ));
            return false;
        }
    };
    if !wait_for_exit(&sp.child, 60000) {
        terminate_process_tree(&mut sp.child);
        sp.out.collect(5000);
        sp.err.collect(5000);
        sink.push_str(&format!("{file_name} timed out\r\n"));
        return false;
    }
    let stdout = decode_stream_bytes(&sp.out.wait_all());
    let stderr = decode_clixml(&decode_stream_bytes(&sp.err.wait_all()));
    if !stdout.trim().is_empty() {
        sink.push_str(stdout.trim());
        sink.push_str("\r\n");
    }
    if !stderr.trim().is_empty() {
        sink.push_str(stderr.trim());
        sink.push_str("\r\n");
    }
    exit_code_of(&mut sp.child) == 0
}

#[cfg(test)]
mod exit_code_tests {
    use super::exit_code_accepted;

    #[test]
    fn zero_is_always_accepted() {
        assert!(exit_code_accepted(0, false, &[]));
    }

    #[test]
    fn nonzero_needs_listing() {
        assert!(!exit_code_accepted(1056, false, &[]));
        assert!(exit_code_accepted(1056, false, &[1056]));
        assert!(!exit_code_accepted(1062, false, &[1056]));
    }

    #[test]
    fn restart_required_only_when_allowed() {
        assert!(!exit_code_accepted(3010, false, &[]));
        assert!(exit_code_accepted(3010, true, &[]));
    }
}

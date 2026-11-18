use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR,
};

use crate::clixml::{decode_clixml, empty_stderr_suffix};
use crate::process::{
    describe_command, ensure_hidden_powershell_arguments, run_cmd_opts_code, spawn_hidden,
    terminate_process_tree, wait_for_exit, CmdOptions,
};
use crate::util::{
    escape_powershell_literal, file_name_of, guid_n, io_message, path_combine, pcwstr,
    program_data_dir, quote_command_argument, read_all_text, wide, windows_dir,
};
use xos_core::{log, session_log};

pub const TRUSTED_INSTALLER_NO_CHILD_RESULT: &str =
    "TrustedInstaller did not return the child result.";

static XSUDO: &[u8] = include_bytes!("../../../resources/XSudo.exe");

fn resources() -> &'static Mutex<HashMap<String, &'static [u8]>> {
    static R: OnceLock<Mutex<HashMap<String, &'static [u8]>>> = OnceLock::new();
    R.get_or_init(|| {
        let mut m: HashMap<String, &'static [u8]> = HashMap::new();
        m.insert("XOSToolkit.XSudo.exe".to_string(), XSUDO);
        m.insert(
            "XOSToolkit.WindowsUpdateServiceGuard.ps1".to_string(),
            include_bytes!("../../../resources/WindowsUpdateServiceGuard.ps1"),
        );
        m.insert(
            "XOSToolkit.DefenderOFF.ps1".to_string(),
            include_bytes!("../../../resources/DefenderOFF.ps1"),
        );
        m.insert(
            "XOSToolkit.XOS.pow".to_string(),
            include_bytes!("../../../resources/XOS.pow"),
        );
        m.insert(
            "XOSToolkit.XOS-PowerSettings.csv".to_string(),
            include_bytes!("../../../resources/XOS-PowerSettings.csv"),
        );
        m.insert(
            "XOSToolkit.XOS-ServiceDefaults.tsv".to_string(),
            include_bytes!("../../../resources/XOS-ServiceDefaults.tsv"),
        );
        m.insert(
            "XOSToolkit.XOS-RegistryDefaults.tsv".to_string(),
            include_bytes!("../../../resources/XOS-RegistryDefaults.tsv"),
        );
        m.insert(
            "XOSToolkit.NPI.nvidiaProfileInspector.exe".to_string(),
            include_bytes!(
                "../../../resources/Nvidia Profile Inspector/nvidiaProfileInspector.exe"
            ),
        );
        m.insert(
            "XOSToolkit.NPI.nvidiaProfileInspector.exe.config".to_string(),
            include_bytes!(
                "../../../resources/Nvidia Profile Inspector/nvidiaProfileInspector.exe.config"
            ),
        );
        m.insert(
            "XOSToolkit.NPI.XOS.nip".to_string(),
            include_bytes!("../../../resources/Nvidia Profile Inspector/XOS.nip"),
        );
        m.insert(
            "XOSToolkit.NPI.Reference.xml".to_string(),
            include_bytes!("../../../resources/Nvidia Profile Inspector/Reference.xml"),
        );
        m.insert(
            "XOSToolkit.NPI.Default.nip".to_string(),
            include_bytes!("../../../resources/Nvidia Profile Inspector/Default.nip"),
        );
        Mutex::new(m)
    })
}

pub fn resource_bytes(resource_name: &str) -> Option<&'static [u8]> {
    resources().lock().unwrap().get(resource_name).copied()
}

pub fn register_embedded_resource(resource_name: &str, data: &'static [u8]) {
    resources()
        .lock()
        .unwrap()
        .insert(resource_name.to_string(), data);
}

fn protected_runtime_cache() -> &'static Mutex<Option<PathBuf>> {
    static C: OnceLock<Mutex<Option<PathBuf>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(None))
}

pub(crate) fn protect_directory(dir: &str) -> anyhow::Result<()> {
    let sddl = wide("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
    let path = wide(dir);
    unsafe {
        let mut sd = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            pcwstr(&sddl),
            SDDL_REVISION_1,
            &mut sd,
            None,
        )?;
        let mut present = windows::core::BOOL(0);
        let mut defaulted = windows::core::BOOL(0);
        let mut acl: *mut ACL = std::ptr::null_mut();
        let got = GetSecurityDescriptorDacl(sd, &mut present, &mut acl, &mut defaulted);
        let result = match got {
            Ok(()) => {
                let err = SetNamedSecurityInfoW(
                    pcwstr(&path),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    None,
                    None,
                    Some(acl as *const ACL),
                    None,
                );
                if err.0 != 0 {
                    Err(anyhow::anyhow!(
                        "{}",
                        io_message(&std::io::Error::from_raw_os_error(err.0 as i32))
                    ))
                } else {
                    Ok(())
                }
            }
            Err(e) => Err(anyhow::anyhow!("{}", e.message())),
        };
        let _ = LocalFree(Some(HLOCAL(sd.0)));
        result
    }
}

pub fn get_protected_runtime_dir() -> anyhow::Result<PathBuf> {
    let mut cache = protected_runtime_cache().lock().unwrap();
    if let Some(p) = cache.as_ref() {
        if p.is_dir() {
            return Ok(p.clone());
        }
    }
    let dir = program_data_dir().join("XOS Toolkit").join("Runtime");
    std::fs::create_dir_all(&dir)?;
    protect_directory(&dir.to_string_lossy())?;
    *cache = Some(dir.clone());
    Ok(dir)
}

pub fn extract_protected_resource(resource_name: &str, file_name: &str) -> Option<String> {
    let attempt = || -> anyhow::Result<Option<String>> {
        if file_name.trim().is_empty() || file_name_of(file_name) != file_name {
            return Ok(None);
        }
        let path = get_protected_runtime_dir()?.join(file_name);
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        let data = resources().lock().unwrap().get(resource_name).copied();
        match data {
            None => Ok(None),
            Some(bytes) => {
                std::fs::write(&path, bytes)?;
                Ok(Some(path.to_string_lossy().to_string()))
            }
        }
    };
    match attempt() {
        Ok(v) => v,
        Err(e) => {
            log::log(&format!("[Runtime] Could not extract {file_name}: {e}"));
            None
        }
    }
}

pub fn extract_protected_bytes(file_name: &str, data: &[u8]) -> Option<String> {
    let attempt = || -> anyhow::Result<Option<String>> {
        if file_name.trim().is_empty() || file_name_of(file_name) != file_name {
            return Ok(None);
        }
        let path = get_protected_runtime_dir()?.join(file_name);
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        std::fs::write(&path, data)?;
        Ok(Some(path.to_string_lossy().to_string()))
    };
    match attempt() {
        Ok(v) => v,
        Err(e) => {
            log::log(&format!("[Runtime] Could not extract {file_name}: {e}"));
            None
        }
    }
}

fn xsudo_cache() -> &'static Mutex<Option<String>> {
    static C: OnceLock<Mutex<Option<String>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(None))
}

pub(crate) fn ensure_xsudo() -> Option<String> {
    let mut cache = xsudo_cache().lock().unwrap();
    if let Some(p) = cache.as_ref() {
        if std::path::Path::new(p).exists() {
            return Some(p.clone());
        }
    }
    let mut path = extract_protected_resource("XOSToolkit.XSudo.exe", "XSudo.exe");
    if path.is_none() {
        let name = resources()
            .lock()
            .unwrap()
            .keys()
            .find(|n| n.to_lowercase().ends_with("xsudo.exe"))
            .cloned();
        if let Some(n) = name {
            path = extract_protected_resource(&n, "XSudo.exe");
        }
    }
    let path = path?;
    *cache = Some(path.clone());
    Some(path)
}

pub fn run_as_ti(file_name: &str, arguments: &str) -> bool {
    run_as_ti_timeout(file_name, arguments, 300000)
}

pub const XSUDO_OWN_EXIT_CODE_FIRST: i32 = 0x5853_0001;
pub const XSUDO_OWN_EXIT_CODE_LAST: i32 = 0x5853_0005;

pub fn is_xsudo_own_exit_code(code: i32) -> bool {
    (XSUDO_OWN_EXIT_CODE_FIRST..=XSUDO_OWN_EXIT_CODE_LAST).contains(&code)
}

fn ti_failure_suffix(code: Option<i32>) -> String {
    match code {
        Some(c) if is_xsudo_own_exit_code(c) => format!(" (launcher exit 0x{c:X})"),
        Some(c) if c != 0 => format!(" (exit {c})"),
        _ => String::new(),
    }
}

#[derive(Clone, Copy, Default)]
pub struct TiOptions<'a> {
    pub timeout_ms: Option<u32>,
    pub accepted_exit_codes: &'a [i32],
    pub best_effort: bool,
}

pub fn run_as_ti_timeout(file_name: &str, arguments: &str, timeout_ms: u32) -> bool {
    run_as_ti_with(
        file_name,
        arguments,
        &TiOptions {
            timeout_ms: Some(timeout_ms),
            ..Default::default()
        },
    )
}

pub fn run_as_ti_accepting(file_name: &str, arguments: &str, accepted_exit_codes: &[i32]) -> bool {
    run_as_ti_with(
        file_name,
        arguments,
        &TiOptions {
            accepted_exit_codes,
            ..Default::default()
        },
    )
}

pub fn run_as_ti_best_effort(file_name: &str, arguments: &str) -> bool {
    run_as_ti_with(
        file_name,
        arguments,
        &TiOptions {
            best_effort: true,
            ..Default::default()
        },
    )
}

pub fn run_as_ti_with(file_name: &str, arguments: &str, o: &TiOptions) -> bool {
    let timeout_ms = o.timeout_ms.unwrap_or(300000);
    let child_arguments = ensure_hidden_powershell_arguments(file_name, arguments);
    log::log(&format!(
        "[TI]  {}",
        describe_command(file_name, &child_arguments)
    ));
    let xsudo = ensure_xsudo();
    let sw = Instant::now();
    let (ok, code) = match &xsudo {
        Some(m) => run_cmd_opts_code(
            m,
            &format!(
                "-TI -P {} {}",
                quote_command_argument(file_name),
                child_arguments
            ),
            &CmdOptions {
                timeout_ms: Some(timeout_ms),
                suppress_log: true,
                accepted_exit_codes: o.accepted_exit_codes,
                ..Default::default()
            },
        ),
        None => (false, None),
    };
    let ms = sw.elapsed().as_millis();
    let ignored = !ok && o.best_effort && code.is_some_and(|c| !is_xsudo_own_exit_code(c));
    if ignored {
        log::log(&format!(
            "[TI]  -> exit {} in {} ms (best effort, not counted as a failure)",
            code.unwrap_or(0),
            ms
        ));
    } else {
        log::log(&format!(
            "[TI]  -> {} in {} ms{}",
            if ok { "ok" } else { "FAILED" },
            ms,
            if ok {
                String::new()
            } else {
                ti_failure_suffix(code)
            }
        ));
        if !ok {
            session_log::operation_failed(
                "elevated command",
                &describe_command(file_name, &child_arguments),
            );
        }
    }
    if ms >= 1000 {
        log::perf(&format!("TI {}", file_name_of(file_name)), ms);
    }
    ok || ignored
}

pub fn run_as_ti_output(file_name: &str, arguments: &str) -> (i32, String) {
    run_as_ti_output_timeout(file_name, arguments, 30000)
}

pub fn run_as_ti_output_timeout(
    file_name: &str,
    arguments: &str,
    timeout_ms: u32,
) -> (i32, String) {
    let arguments = ensure_hidden_powershell_arguments(file_name, arguments);
    let xsudo = match ensure_xsudo() {
        Some(m) => m,
        None => {
            return (
                -1,
                "XSudo could not be loaded from the protected runtime directory".to_string(),
            )
        }
    };
    let temp_directory = path_combine(&windows_dir(), "Temp");
    let token = format!("xos-ti-output-{}", guid_n());
    let script_path = path_combine(&temp_directory, &format!("{token}.ps1"));
    let output_path = path_combine(&temp_directory, &format!("{token}.out"));
    let exit_code_path = path_combine(&temp_directory, &format!("{token}.exit"));
    let result = (|| -> (i32, String) {
        if let Err(e) = std::fs::create_dir_all(&temp_directory) {
            return (-1, io_message(&e));
        }
        if let Err(e) = std::fs::write(
            &script_path,
            build_trusted_installer_output_script(
                file_name,
                &arguments,
                &output_path,
                &exit_code_path,
            ),
        ) {
            return (-1, io_message(&e));
        }
        let args = format!(
            "-TI -P {} -NoProfile -NonInteractive -ExecutionPolicy Bypass -File {}",
            quote_command_argument("powershell.exe"),
            quote_command_argument(&script_path)
        );
        let mut sp = match spawn_hidden(&xsudo, &args, false) {
            Ok(s) => s,
            Err(e) => return (-1, io_message(&e)),
        };
        if !wait_for_exit(&sp.child, timeout_ms) {
            terminate_process_tree(&mut sp.child);
            sp.out.collect(5000);
            sp.err.collect(5000);
            return (-999, "TrustedInstaller command timed out".to_string());
        }
        let stdout = crate::process::decode_stream_bytes(&sp.out.wait_all())
            .trim()
            .to_string();
        let stderr = decode_clixml(&crate::process::decode_stream_bytes(&sp.err.wait_all()))
            .trim()
            .to_string();
        let launcher_output = if !stdout.is_empty() && !stderr.is_empty() {
            format!("{stdout} | STDERR: {stderr}")
        } else if !stderr.is_empty() {
            stderr
        } else {
            stdout
        };
        if !std::path::Path::new(&exit_code_path).exists() {
            let suffix = if launcher_output.trim().is_empty() {
                String::new()
            } else {
                format!(" {launcher_output}")
            };
            return (-1, format!("{TRUSTED_INSTALLER_NO_CHILD_RESULT}{suffix}"));
        }
        let exit_text = match read_all_text(&exit_code_path) {
            Ok(t) => t.trim().to_string(),
            Err(e) => return (-1, io_message(&e)),
        };
        let child_exit: i32 = match exit_text.parse() {
            Ok(c) => c,
            Err(_) => {
                return (
                    -1,
                    format!("TrustedInstaller returned an invalid child exit code: {exit_text}"),
                )
            }
        };
        let child_output = if std::path::Path::new(&output_path).exists() {
            read_all_text(&output_path).unwrap_or_default()
        } else {
            String::new()
        };
        let child_output = empty_stderr_suffix()
            .replace(&decode_clixml(&child_output), "")
            .to_string();
        (child_exit, child_output)
    })();
    for p in [&script_path, &output_path, &exit_code_path] {
        if std::path::Path::new(p).exists() {
            let _ = std::fs::remove_file(p);
        }
    }
    result
}

fn build_trusted_installer_output_script(
    file_name: &str,
    arguments: &str,
    output_path: &str,
    exit_code_path: &str,
) -> String {
    format!(
        "$ErrorActionPreference='Stop';\
$code=-1;$combined='';\
$utf8=New-Object System.Text.UTF8Encoding($false);\
try{{\
$psi=New-Object System.Diagnostics.ProcessStartInfo;\
$psi.FileName='{file}';\
$psi.Arguments='{args}';\
$psi.UseShellExecute=$false;\
$psi.CreateNoWindow=$true;\
$psi.WindowStyle=[System.Diagnostics.ProcessWindowStyle]::Hidden;\
$psi.RedirectStandardOutput=$true;\
$psi.RedirectStandardError=$true;\
$oem=[System.Text.Encoding]::GetEncoding({oem});\
$psi.StandardOutputEncoding=$oem;\
$psi.StandardErrorEncoding=$oem;\
$child=New-Object System.Diagnostics.Process;\
$child.StartInfo=$psi;\
if(-not $child.Start()){{throw 'The child process could not be started.'}};\
$outTask=$child.StandardOutput.ReadToEndAsync();\
$errTask=$child.StandardError.ReadToEndAsync();\
$child.WaitForExit();\
$stdout=$outTask.GetAwaiter().GetResult();\
$stderr=$errTask.GetAwaiter().GetResult();\
$combined=if($stdout -and $stderr){{$stdout + ' | STDERR: ' + $stderr}}elseif($stderr){{$stderr}}else{{$stdout}};\
$code=$child.ExitCode;\
}}catch{{$combined=$_.Exception.Message;}}\
[System.IO.File]::WriteAllText('{out}',$combined,$utf8);\
[System.IO.File]::WriteAllText('{exit}',[string]$code,$utf8);\
exit $code",
        file = escape_powershell_literal(file_name),
        args = escape_powershell_literal(arguments),
        oem = crate::process::oem_code_page(),
        out = escape_powershell_literal(output_path),
        exit = escape_powershell_literal(exit_code_path),
    )
}

#[cfg(test)]
mod ti_exit_code_tests {
    use super::{is_xsudo_own_exit_code, ti_failure_suffix};

    #[test]
    fn own_codes_are_the_reserved_range() {
        assert!(!is_xsudo_own_exit_code(0x5853_0000));
        assert!(is_xsudo_own_exit_code(0x5853_0001));
        assert!(is_xsudo_own_exit_code(0x5853_0005));
        assert!(!is_xsudo_own_exit_code(0x5853_0006));
        assert!(!is_xsudo_own_exit_code(1056));
    }

    #[test]
    fn failure_suffix_names_the_code() {
        assert_eq!(ti_failure_suffix(None), "");
        assert_eq!(ti_failure_suffix(Some(0)), "");
        assert_eq!(ti_failure_suffix(Some(1056)), " (exit 1056)");
        assert_eq!(
            ti_failure_suffix(Some(0x5853_0002)),
            " (launcher exit 0x58530002)"
        );
    }
}

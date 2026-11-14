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
    describe_command, ensure_hidden_powershell_arguments, run_cmd_opts, spawn_hidden,
    terminate_process_tree, wait_for_exit, CmdOptions,
};
use crate::util::{
    escape_powershell_literal, file_name_of, guid_n, io_message, path_combine, path_is_rooted,
    pcwstr, program_data_dir, quote_command_argument, read_all_text, system_dir, wide, windows_dir,
};
use xos_core::{log, session_log};

pub const TRUSTED_INSTALLER_NO_CHILD_RESULT: &str =
    "TrustedInstaller did not return the child result.";

static MIN_SUDO: &[u8] = include_bytes!("../../../resources/MinSudo.exe");

fn resources() -> &'static Mutex<HashMap<String, &'static [u8]>> {
    static R: OnceLock<Mutex<HashMap<String, &'static [u8]>>> = OnceLock::new();
    R.get_or_init(|| {
        let mut m: HashMap<String, &'static [u8]> = HashMap::new();
        m.insert("XOSToolkit.MinSudo.exe".to_string(), MIN_SUDO);
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

fn min_sudo_cache() -> &'static Mutex<Option<String>> {
    static C: OnceLock<Mutex<Option<String>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(None))
}

pub(crate) fn ensure_min_sudo() -> Option<String> {
    let mut cache = min_sudo_cache().lock().unwrap();
    if let Some(p) = cache.as_ref() {
        if std::path::Path::new(p).exists() {
            return Some(p.clone());
        }
    }
    let mut path = extract_protected_resource("XOSToolkit.MinSudo.exe", "MinSudo.exe");
    if path.is_none() {
        let name = resources()
            .lock()
            .unwrap()
            .keys()
            .find(|n| n.to_lowercase().ends_with("minsudo.exe"))
            .cloned();
        if let Some(n) = name {
            path = extract_protected_resource(&n, "MinSudo.exe");
        }
    }
    let path = path?;
    *cache = Some(path.clone());
    Some(path)
}

pub fn run_as_ti(file_name: &str, arguments: &str) -> bool {
    run_as_ti_timeout(file_name, arguments, 300000)
}

pub fn run_as_ti_timeout(file_name: &str, arguments: &str, timeout_ms: u32) -> bool {
    let child_arguments = ensure_hidden_powershell_arguments(file_name, arguments);
    log::log(&format!(
        "[TI]  {}",
        describe_command(file_name, &child_arguments)
    ));
    let min_sudo = ensure_min_sudo();
    let sw = Instant::now();
    let ok = match &min_sudo {
        Some(m) => run_cmd_opts(
            m,
            &format!(
                "-TI -P {} {}",
                quote_command_argument(file_name),
                child_arguments
            ),
            &CmdOptions {
                timeout_ms: Some(timeout_ms),
                suppress_log: true,
                ..Default::default()
            },
        ),
        None => false,
    };
    let ms = sw.elapsed().as_millis();
    log::log(&format!(
        "[TI]  -> {} in {} ms",
        if ok { "ok" } else { "FAILED" },
        ms
    ));
    if !ok {
        session_log::operation_failed(
            "elevated command",
            &describe_command(file_name, &child_arguments),
        );
    }
    if ms >= 1000 {
        log::perf(&format!("TI {}", file_name_of(file_name)), ms);
    }
    ok
}

pub fn run_as_ti_renamed(file_name: &str, arguments: &str) -> bool {
    run_as_ti_renamed_timeout(file_name, arguments, 300000)
}

pub fn run_as_ti_renamed_timeout(file_name: &str, arguments: &str, timeout_ms: u32) -> bool {
    let mut source = file_name.to_string();
    if !path_is_rooted(&source) {
        source = path_combine(&system_dir(), &source);
    }
    let mut temporary_helper: Option<String> = None;
    let result = (|| -> Result<bool, String> {
        if !std::path::Path::new(&source).exists() {
            log::log(&format!(
                "[TI] Neutral helper source was not found: {source}"
            ));
            return Ok(false);
        }
        let temp_directory = path_combine(&windows_dir(), "Temp");
        std::fs::create_dir_all(&temp_directory).map_err(|e| io_message(&e))?;
        let helper = path_combine(&temp_directory, &format!("XOS-Region-{}.exe", guid_n()));
        temporary_helper = Some(helper.clone());
        std::fs::copy(&source, &helper).map_err(|e| io_message(&e))?;
        log::log(&format!("[TI] Using neutral-named helper {helper}"));
        Ok(run_as_ti_timeout(&helper, arguments, timeout_ms))
    })();
    let ok = match result {
        Ok(v) => v,
        Err(m) => {
            log::log(&format!("[TI] Neutral helper failed: {m}"));
            false
        }
    };
    if let Some(h) = temporary_helper {
        if std::path::Path::new(&h).exists() {
            let _ = std::fs::remove_file(&h);
        }
    }
    ok
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
    let min_sudo = match ensure_min_sudo() {
        Some(m) => m,
        None => {
            return (
                -1,
                "MinSudo could not be loaded from the protected runtime directory".to_string(),
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
        let mut sp = match spawn_hidden(&min_sudo, &args, false) {
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

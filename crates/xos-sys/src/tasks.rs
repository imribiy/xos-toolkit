use std::sync::OnceLock;

use regex::Regex;

use crate::ci_map::CiMap;
use crate::elevation::{
    get_protected_runtime_dir, run_as_ti_output_timeout, TRUSTED_INSTALLER_NO_CHILD_RESULT,
};
use crate::process::run_cmd_output;
use crate::util::{
    encode_command, escape_powershell_literal, guid_n, path_combine, path_is_rooted,
    quote_command_argument, read_all_text, system_dir,
};
use crate::xmlmini;
use xos_core::{log, session_log};

const TASK_NAMESPACE: &str = "http://schemas.microsoft.com/windows/2004/02/mit/task";

const TOLERANT_TASK_PATHS: [&str; 1] = [r"\Microsoft\Windows\WlanSvc\CDSSync"];

pub fn is_tolerant_task_path(task_name: &str) -> bool {
    if task_name.trim().is_empty() {
        return false;
    }
    TOLERANT_TASK_PATHS
        .iter()
        .any(|p| task_name.trim().eq_ignore_ascii_case(p))
}

pub fn enable_task(task_name: &str) -> bool {
    set_task_state(task_name, true, true)
}

pub fn disable_task(task_name: &str) -> bool {
    set_task_state(task_name, false, true)
}

pub fn try_disable_task_quiet(task_name: &str) -> bool {
    set_task_state(task_name, false, false)
}

pub fn record_task_state_failure(task_name: &str) {
    session_log::operation_failed("scheduled task state", task_name);
}

fn set_task_state(task_name: &str, enable: bool, record_failure: bool) -> bool {
    if set_tasks_batch(
        Some(&[task_name.to_string()]),
        enable,
        None,
        false,
        is_tolerant_task_path(task_name),
        None,
    ) {
        return true;
    }
    if record_failure {
        session_log::operation_failed("scheduled task state", task_name);
    }
    false
}

pub fn enable_tasks_batch(task_names: &[String]) -> bool {
    set_tasks_batch(Some(task_names), true, None, false, false, None)
}

pub fn enable_tasks_batch_best_effort(task_names: &[String]) -> bool {
    set_tasks_batch(Some(task_names), true, None, true, false, None)
}

pub fn disable_tasks_batch(task_names: &[String]) -> bool {
    set_tasks_batch(Some(task_names), false, None, false, false, None)
}

fn ps_list(items: &[String]) -> String {
    items
        .iter()
        .map(|n| format!("'{}'", escape_powershell_literal(n)))
        .collect::<Vec<_>>()
        .join(",")
}

fn set_tasks_batch(
    names: Option<&[String]>,
    enable: bool,
    match_prefixes: Option<&[String]>,
    best_effort: bool,
    tolerate_state_refusal: bool,
    walk_folder: Option<&str>,
) -> bool {
    let have_names = names.map(|n| !n.is_empty()).unwrap_or(false);
    let have_prefixes = match_prefixes.map(|n| !n.is_empty()).unwrap_or(false);
    let have_folder = walk_folder.map(|f| !f.trim().is_empty()).unwrap_or(false);
    if !have_names && !have_prefixes && !have_folder {
        return true;
    }

    let kind = format!(
        "[Tasks] {}{} through TrustedInstaller",
        if enable { "enable" } else { "disable" },
        if best_effort { " (best effort)" } else { "" }
    );
    let script = build_tasks_batch_script(
        names,
        enable,
        match_prefixes,
        best_effort,
        tolerate_state_refusal,
        walk_folder,
    );
    let mut result = run_task_script_as_ti(&script);
    if is_trusted_installer_child_missing(&result) {
        log::log(&format!(
            "{kind}: no child result on the first launch, retrying once in 1 s: {}",
            split_task_batch_output(&result.1).join(" ")
        ));
        std::thread::sleep(std::time::Duration::from_millis(1000));
        result = run_task_script_as_ti(&script);
    }
    let lines = split_task_batch_output(&result.1);
    let summary = lines
        .iter()
        .rev()
        .find(|l| l.starts_with("changed="))
        .cloned();
    for line in lines.iter().filter(|l| !l.starts_with("changed=")) {
        log::log(&format!("{kind}: {line}"));
    }
    let summary = match summary {
        Some(s) => s,
        None => {
            log::log(&format!(
                "{kind}: FAILED no task summary (exit {}): {}",
                result.0, result.1
            ));
            return false;
        }
    };
    log::log(&format!("{kind}: {summary}"));
    static R: OnceLock<Regex> = OnceLock::new();
    let r = R.get_or_init(|| {
        Regex::new(r"^changed=(\d+) already=(\d+) missing=(\d+) failed=(\d+)$").unwrap()
    });
    match r.captures(&summary) {
        Some(c) => result.0 == 0 && (best_effort || &c[4] == "0"),
        None => false,
    }
}

fn is_trusted_installer_child_missing(result: &(i32, String)) -> bool {
    result.0 == -1 && result.1.starts_with(TRUSTED_INSTALLER_NO_CHILD_RESULT)
}

fn split_task_batch_output(output: &str) -> Vec<String> {
    output
        .split('\n')
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

fn run_task_script_as_ti(script: &str) -> (i32, String) {
    let mut path: Option<String> = None;
    let result = (|| -> Result<(i32, String), String> {
        let dir = get_protected_runtime_dir().map_err(|e| e.to_string())?;
        let p = path_combine(
            &dir.to_string_lossy(),
            &format!("task-state-{}.ps1", guid_n()),
        );
        path = Some(p.clone());
        let mut data = vec![0xEF, 0xBB, 0xBF];
        data.extend_from_slice(script.as_bytes());
        std::fs::write(&p, data).map_err(|e| crate::util::io_message(&e))?;
        Ok(run_as_ti_output_timeout(
            "powershell.exe",
            &format!(
                "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File {}",
                quote_command_argument(&p)
            ),
            300000,
        ))
    })();
    if let Some(p) = path {
        let _ = std::fs::remove_file(p);
    }
    match result {
        Ok(r) => r,
        Err(m) => (-1, m),
    }
}

const TASKS_BATCH_SCRIPT: &str = r##"
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
function Read-XosTask($scheduler, [string]$path) {
    if ([string]::IsNullOrWhiteSpace($path)) { throw 'Task path is empty' }
    if (!$path.StartsWith('\')) { $path='\'+$path }
    $index=$path.LastIndexOf('\')
    $folder=$path.Substring(0,$index)
    if (!$folder) { $folder='\' }
    $name=$path.Substring($index+1)
    if (!$name) { throw 'Task name is empty' }
    try { return $scheduler.GetFolder($folder).GetTask($name) }
    catch {
        if (Test-XosTaskNotFound $_) { return $null }
        throw
    }
}
function Test-XosTaskNotFound($errorRecord) {
    $errorObject=$errorRecord.Exception
    while ($errorObject.InnerException) { $errorObject=$errorObject.InnerException }
    return ($errorObject.HResult -eq -2147024894 -or $errorObject.HResult -eq -2147024893)
}
function Task-ErrorText($errorRecord) {
    $errorObject=$errorRecord.Exception
    while ($errorObject.InnerException) { $errorObject=$errorObject.InnerException }
    return ($errorObject.Message -replace '[\r\n]+',' ') + ' HRESULT=' + $errorObject.HResult
}
function Get-XosTaskPaths($scheduler) {
    $found=@()
    $pending=New-Object System.Collections.ArrayList
    [void]$pending.Add($walkRoot)
    for ($index=0;$index -lt $pending.Count;$index++) {
        $folderPath=[string]$pending[$index]
        $folder=$null;$openError=$null;$onlyNotFound=$true
        for ($attempt=0;$attempt -lt 3;$attempt++) {
            if ($attempt -gt 0) { Start-Sleep -Milliseconds 500 }
            try { $folder=$scheduler.GetFolder($folderPath); break }
            catch { $openError=$_; if (!(Test-XosTaskNotFound $_)) { $onlyNotFound=$false } }
        }
        if ($null -eq $folder) {
            if ($folderPath -ne '\' -and $folderPath -eq $walkRoot -and $onlyNotFound) {
                $script:missing++
                $script:walkLines+=('GONE '+$folderPath+' :: folder not present on this machine')
            } elseif ($folderPath -ne '\' -and $onlyNotFound) {
                $script:missing++
                $script:walkLines+=('GONE '+$folderPath+' :: explicit task/path not found while opening the folder')
            } else { Add-XosWalkFailure $folderPath 'opening folder' $openError }
            continue
        }
        $listError=$null
        for ($attempt=0;$attempt -lt 3;$attempt++) {
            if ($attempt -gt 0) { Start-Sleep -Milliseconds 500 }
            try { $folderTasks=@($folder.GetTasks(1) | ForEach-Object { [string]$_.Path }); $listError=$null; break }
            catch { $listError=$_ }
        }
        if ($listError) { Add-XosWalkFailure $folderPath 'listing tasks' $listError } else { $found+=$folderTasks }
        $listError=$null
        for ($attempt=0;$attempt -lt 3;$attempt++) {
            if ($attempt -gt 0) { Start-Sleep -Milliseconds 500 }
            try { $subfolders=@($folder.GetFolders(0) | ForEach-Object { [string]$_.Path }); $listError=$null; break }
            catch { $listError=$_ }
        }
        if ($listError) { Add-XosWalkFailure $folderPath 'listing subfolders' $listError }
        else { foreach ($subfolder in $subfolders) { [void]$pending.Add($subfolder) } }
    }
    return $found
}
function Add-XosWalkFailure([string]$folderPath, [string]$step, $errorRecord) {
    $script:failed++
    $script:fatal=$true
    $script:walkLines+=('FAILED '+$folderPath+' :: '+$step+': '+(Task-ErrorText $errorRecord))
}
$changed=0;$missing=0;$already=0;$failed=0;$fatal=$false;$walkLines=@()
try {
    $scheduler=New-Object -ComObject Schedule.Service
    $scheduler.Connect()
    if ($prefixes.Count -gt 0 -or $walkAll) {
        foreach ($taskPath in @(Get-XosTaskPaths $scheduler)) {
            if ($walkAll) { $targets+=$taskPath; continue }
            $taskName=$taskPath.Substring($taskPath.LastIndexOf('\')+1)
            foreach ($prefix in $prefixes) {
                if ($taskName.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) {
                    $targets+=$taskPath
                    break
                }
            }
        }
        foreach ($walkLine in $walkLines) { Write-Output $walkLine }
    }
    foreach ($path in @($targets | Select-Object -Unique)) {
        try {
            $task=Read-XosTask $scheduler $path
            if ($null -eq $task) { $missing++; Write-Output ('GONE '+$path+' :: explicit task/path not found'); continue }
            if ([bool]$task.Enabled -eq $want) { $already++; continue }
            $writeError=''
            try { $task.Enabled=$want } catch { $writeError=Task-ErrorText $_ }
            $verified=$false;$absent=$false;$readError=''
            for ($attempt=0;$attempt -lt 3;$attempt++) {
                if ($attempt -gt 0) {
                    Start-Sleep -Milliseconds 500
                    if (!$absent -and !$readError) {
                        try { $after.Enabled=$want; $writeError='' } catch { $writeError=Task-ErrorText $_ }
                    }
                }
                try {
                    $after=Read-XosTask $scheduler $path
                    $absent=($null -eq $after)
                    $readError=''
                    if (!$absent -and [bool]$after.Enabled -eq $want) { $verified=$true; break }
                } catch { $absent=$false; $readError=Task-ErrorText $_ }
            }
            if ($verified) { $changed++; Write-Output ('VERIFIED '+$path+' :: state verified'+$(if ($writeError) { '; command reported '+$writeError })) }
            elseif ($absent) { $missing++; Write-Output ('GONE '+$path+' :: explicit task/path not found after change') }
            elseif ($tolerateStateRefusal -and !$readError) { $already++; Write-Output ('NOTE '+$path+' :: refuses the state change on this build; left as Windows has it') }
            else {
                $failed++
                Write-Output ('FAILED '+$path+' :: requested state not verified; write='+$writeError+'; read='+$readError)
            }
        } catch { $failed++; Write-Output ('FAILED '+$path+' :: '+(Task-ErrorText $_)) }
    }
} catch { $failed++; $fatal=$true; Write-Output ('FAILED task batch :: '+(Task-ErrorText $_)) }
Write-Output ('changed='+$changed+' already='+$already+' missing='+$missing+' failed='+$failed)
if($fatal -or ($failed -gt 0 -and !$bestEffort)){ exit 1 }
"##;

fn ps_bool(b: bool) -> &'static str {
    if b {
        "$true"
    } else {
        "$false"
    }
}

fn build_tasks_batch_script(
    names: Option<&[String]>,
    enable: bool,
    match_prefixes: Option<&[String]>,
    best_effort: bool,
    tolerate_state_refusal: bool,
    walk_folder: Option<&str>,
) -> String {
    let targets = ps_list(names.unwrap_or(&[]));
    let prefixes = ps_list(match_prefixes.unwrap_or(&[]));
    let walk_blank = walk_folder.map(|f| f.trim().is_empty()).unwrap_or(true);
    let root = if walk_blank {
        "\\".to_string()
    } else {
        format!("\\{}", walk_folder.unwrap().trim().trim_matches('\\'))
    };
    format!(
        "$targets=@({targets});$prefixes=@({prefixes});$walkRoot='{root}';$walkAll={walk_all};$want={want};$bestEffort={best};$tolerateStateRefusal={tol};{script}",
        root = escape_powershell_literal(&root),
        walk_all = ps_bool(!walk_blank),
        want = ps_bool(enable),
        best = ps_bool(best_effort),
        tol = ps_bool(tolerate_state_refusal),
        script = TASKS_BATCH_SCRIPT,
    )
}

fn distinct_prefixes(prefixes: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for p in prefixes.iter().filter(|p| !p.trim().is_empty()) {
        let t = p.trim().to_string();
        if !out.iter().any(|e| e.to_lowercase() == t.to_lowercase()) {
            out.push(t);
        }
    }
    out
}

pub fn get_scheduled_task_paths_by_name_prefix(prefixes: &[String]) -> Vec<String> {
    if prefixes.is_empty() {
        return Vec::new();
    }
    let valid = distinct_prefixes(prefixes);
    if valid.is_empty() {
        return Vec::new();
    }
    let prefix_list = ps_list(&valid);
    let script = format!(
        "$prefixes=@({prefix_list}); $s=New-Object -ComObject Schedule.Service; $s.Connect(); \
$pending=New-Object System.Collections.Queue; $pending.Enqueue('\\'); \
while ($pending.Count -gt 0) {{ $p=[string]$pending.Dequeue(); \
try {{ $f=$s.GetFolder($p) }} catch {{ continue }}; \
try {{ foreach ($t in @($f.GetTasks(1))) {{ foreach ($x in $prefixes) {{ \
if ([string]$t.Name -and ([string]$t.Name).StartsWith($x,[StringComparison]::OrdinalIgnoreCase)) {{ [string]$t.Path; break }} }} }} }} catch {{ }}; \
try {{ foreach ($c in @($f.GetFolders(0))) {{ $pending.Enqueue([string]$c.Path) }} }} catch {{ }} }}"
    );
    let output = run_cmd_output(
        "powershell.exe",
        &format!(
            "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {}",
            encode_command(&script)
        ),
    );
    let mut out: Vec<String> = Vec::new();
    for line in output.split(['\r', '\n']).filter(|l| !l.is_empty()) {
        let t = line.trim().to_string();
        if t.starts_with('\\') && !out.iter().any(|e| e.to_lowercase() == t.to_lowercase()) {
            out.push(t);
        }
    }
    out
}

pub fn enable_scheduled_tasks_by_name_prefix(prefixes: &[String]) -> bool {
    if prefixes.is_empty() {
        return true;
    }
    let valid = distinct_prefixes(prefixes);
    if valid.is_empty() {
        return true;
    }
    set_tasks_batch(None, true, Some(&valid), false, false, None)
}

pub fn enable_scheduled_tasks_in_folder(folder_path: &str) -> bool {
    if folder_path.trim().is_empty() || folder_path.trim().trim_matches('\\').is_empty() {
        return false;
    }
    set_tasks_batch(None, true, None, false, false, Some(folder_path))
}

pub fn get_task_state(task_name: &str) -> i32 {
    if task_name.is_empty() {
        return -1;
    }
    let states = get_task_states_batch(&[task_name.to_string()]);
    if let Some(&known) = states.get(task_name) {
        if known >= 0 {
            return known;
        }
    }
    let (folder, name) = split_task_name(task_name);
    if name.is_empty() {
        return -1;
    }
    let output = run_cmd_output(
        "powershell.exe",
        &format!(
            "-NoProfile -Command \"$ErrorActionPreference='Stop'; try {{ $s = New-Object -ComObject Schedule.Service; $s.Connect();\
 $t = $s.GetFolder('{}').GetTask('{}');\
 if ($t.Enabled) {{ Write-Output 1 }} else {{ Write-Output 0 }} }} catch {{ Write-Output -1 }}\"",
            escape_powershell_literal(&folder),
            escape_powershell_literal(&name)
        ),
    );
    output.trim().parse::<i32>().unwrap_or(-1)
}

fn read_task_state_settled(task_name: &str, desired: i32, attempts: i32, delay_ms: u64) -> i32 {
    let mut state = get_task_state(task_name);
    let mut attempt = 1;
    while attempt < attempts && state >= 0 && state != desired {
        std::thread::sleep(std::time::Duration::from_millis(delay_ms));
        state = get_task_state(task_name);
        attempt += 1;
    }
    state
}

pub fn get_task_state_verified(task_name: &str, enabled: bool, wait_ms: i32) -> i32 {
    let attempts = std::cmp::max(1, wait_ms / 500);
    read_task_state_settled(task_name, if enabled { 1 } else { 0 }, attempts, 500)
}

pub fn split_task_name(task_name: &str) -> (String, String) {
    let mut t = task_name.to_string();
    if !t.starts_with('\\') {
        t = format!("\\{t}");
    }
    match t.rfind('\\') {
        Some(last) => {
            let folder = if last > 0 {
                t[..last].to_string()
            } else {
                "\\".to_string()
            };
            (folder, t[last + 1..].to_string())
        }
        None => ("\\".to_string(), t),
    }
}

pub fn get_task_states_batch(task_paths: &[String]) -> CiMap<i32> {
    let mut result = CiMap::new();
    let tasks_root = path_combine(&system_dir(), "Tasks");
    for task_path in task_paths {
        if task_path.is_empty() || result.contains_key(task_path) {
            continue;
        }
        let mut state = -1;
        let rel = task_path.trim_start_matches('\\').replace('/', "\\");
        let file_path = if path_is_rooted(&rel) {
            rel
        } else {
            path_combine(&tasks_root, &rel)
        };
        if std::path::Path::new(&file_path).is_file() {
            if let Ok(xml) = read_all_text(&file_path) {
                state = read_task_enabled(&xml);
            }
        }
        result.insert(task_path, state);
    }
    result
}

pub fn read_task_enabled(xml: &str) -> i32 {
    let task = match xmlmini::parse(xml) {
        Ok(t) => t,
        Err(_) => return -1,
    };
    if task.local != "Task" || task.ns != TASK_NAMESPACE {
        return -1;
    }
    let settings: Vec<_> = task
        .children
        .iter()
        .filter(|e| e.local == "Settings")
        .collect();
    if settings.is_empty() {
        return 1;
    }
    if settings.len() != 1 || settings[0].ns != TASK_NAMESPACE {
        return -1;
    }
    let enabled: Vec<_> = settings[0]
        .children
        .iter()
        .filter(|e| e.local == "Enabled")
        .collect();
    if enabled.is_empty() {
        return 1;
    }
    if enabled.len() != 1 || enabled[0].ns != TASK_NAMESPACE || !enabled[0].children.is_empty() {
        return -1;
    }
    let value = enabled[0].inner_text().trim().to_string();
    if value.is_empty() {
        return 1;
    }
    match value.as_str() {
        "true" | "1" => 1,
        "false" | "0" => 0,
        _ => -1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NS: &str = "http://schemas.microsoft.com/windows/2004/02/mit/task";

    #[test]
    fn enabled_false() {
        let xml = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n<Task version=\"1.2\" xmlns=\"{NS}\"><RegistrationInfo/><Settings><Enabled>false</Enabled></Settings></Task>"
        );
        assert_eq!(read_task_enabled(&xml), 0);
    }

    #[test]
    fn enabled_default_and_true() {
        let xml = format!("<Task xmlns=\"{NS}\"><Settings><Hidden>true</Hidden></Settings></Task>");
        assert_eq!(read_task_enabled(&xml), 1);
        let xml =
            format!("<Task xmlns=\"{NS}\"><Settings><Enabled> true </Enabled></Settings></Task>");
        assert_eq!(read_task_enabled(&xml), 1);
        let xml = format!("<Task xmlns=\"{NS}\"><Actions/></Task>");
        assert_eq!(read_task_enabled(&xml), 1);
    }

    #[test]
    fn enabled_invalid() {
        assert_eq!(read_task_enabled("<Task><Settings/></Task>"), -1);
        assert_eq!(read_task_enabled("garbage"), -1);
        let xml =
            format!("<Task xmlns=\"{NS}\"><Settings><Enabled>maybe</Enabled></Settings></Task>");
        assert_eq!(read_task_enabled(&xml), -1);
        let xml = format!("<Task xmlns=\"{NS}\"><Settings><Enabled>true</Enabled><Enabled>true</Enabled></Settings></Task>");
        assert_eq!(read_task_enabled(&xml), -1);
    }

    #[test]
    fn split_names() {
        assert_eq!(
            split_task_name("\\A\\B\\C"),
            ("\\A\\B".to_string(), "C".to_string())
        );
        assert_eq!(split_task_name("C"), ("\\".to_string(), "C".to_string()));
    }

    #[test]
    fn tolerant() {
        assert!(is_tolerant_task_path(
            " \\microsoft\\windows\\wlansvc\\cdssync "
        ));
        assert!(!is_tolerant_task_path("\\x"));
    }
}

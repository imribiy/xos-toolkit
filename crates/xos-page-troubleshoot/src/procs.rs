use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    OpenProcess, TerminateProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
};

pub fn process_ids_by_name(name: &str) -> Vec<u32> {
    let mut ids = Vec::new();
    unsafe {
        let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
            return ids;
        };
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut more = Process32FirstW(snapshot, &mut entry).is_ok();
        while more {
            let len = entry
                .szExeFile
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(entry.szExeFile.len());
            let exe = String::from_utf16_lossy(&entry.szExeFile[..len]);
            let stem = if exe.to_lowercase().ends_with(".exe") {
                &exe[..exe.len() - 4]
            } else {
                exe.as_str()
            };
            if stem.eq_ignore_ascii_case(name) {
                ids.push(entry.th32ProcessID);
            }
            more = Process32NextW(snapshot, &mut entry).is_ok();
        }
        let _ = CloseHandle(snapshot);
    }
    ids
}

pub fn process_running(name: &str) -> bool {
    !process_ids_by_name(name).is_empty()
}

pub fn kill_processes_named(name: &str) {
    kill_and_wait(name, 0);
}

pub fn kill_and_wait(name: &str, wait_ms: u32) {
    for pid in process_ids_by_name(name) {
        unsafe {
            if let Ok(handle) = OpenProcess(PROCESS_TERMINATE | PROCESS_SYNCHRONIZE, false, pid) {
                if TerminateProcess(handle, 1).is_ok() && wait_ms > 0 {
                    WaitForSingleObject(handle, wait_ms);
                }
                let _ = CloseHandle(handle);
            }
        }
    }
}

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::{Mutex, MutexGuard};
use std::time::Instant;

use anyhow::{anyhow, bail, Result};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW,
};
use windows::Win32::Security::{
    GetSecurityDescriptorControl, GetSecurityDescriptorDacl, GetSecurityDescriptorGroup,
    GetSecurityDescriptorOwner, GetSecurityDescriptorSacl, InitializeSecurityDescriptor,
    SetSecurityDescriptorControl, SetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SECURITY_DESCRIPTOR_CONTROL,
};
use windows::Win32::System::Registry::{
    RegCloseKey, RegGetKeySecurity, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY,
};
use windows::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceConfigW,
    QueryServiceObjectSecurity, QUERY_SERVICE_CONFIGW, SC_HANDLE,
};
use winreg::enums::{RegType, KEY_QUERY_VALUE};
use xos_core::log;
use xos_sys::{extract_protected_resource, run_as_ti_output_timeout};

use crate::util::{open_hklm64, win32_code, windows_directory};

pub const OWNERSHIP_KEY: &str = r"SOFTWARE\XOSToolkit\UpdateServiceGuard";
const RESOURCE: &str = "XOSToolkit.WindowsUpdateServiceGuard.ps1";
const SERVICES: [&str; 6] = [
    "wuauserv",
    "BITS",
    "DoSvc",
    "UsoSvc",
    "WaaSMedicSvc",
    "uhssvc",
];
const SERVICE_MASK: u32 = 0x12;
const REGISTRY_MASK: u32 = 0x10006;
const READ_CONTROL: u32 = 0x20000;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_SERVICE_DOES_NOT_EXIST: u32 = 1060;
const SYSTEM_SID: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];

static SYNC: Mutex<()> = Mutex::new(());

fn lock() -> MutexGuard<'static, ()> {
    SYNC.lock().unwrap_or_else(|e| e.into_inner())
}

pub fn is_target_service(name: &str) -> bool {
    SERVICES.iter().any(|s| s.eq_ignore_ascii_case(name))
}

pub fn is_present(name: &str) -> Result<bool> {
    if !is_target_service(name) {
        bail!("Invalid update service existence target.");
    }
    Ok(open_service_handle(name, 1, true)?.is_some())
}

pub fn read_delayed_auto_start(name: &str) -> Result<i32> {
    if !is_target_service(name) {
        bail!("Invalid update service delayed startup target.");
    }
    let key = open_service_key(name, KEY_QUERY_VALUE)?;
    let exists = key
        .enum_values()
        .filter_map(|v| v.ok())
        .any(|(n, _)| n.eq_ignore_ascii_case("DelayedAutostart"));
    if !exists {
        return Ok(0);
    }
    let raw = key.get_raw_value("DelayedAutostart")?;
    if raw.vtype != RegType::REG_DWORD || raw.bytes.len() < 4 {
        bail!("Malformed update service delayed startup: {name}");
    }
    let value = i32::from_le_bytes([raw.bytes[0], raw.bytes[1], raw.bytes[2], raw.bytes[3]]);
    if !(0..=1).contains(&value) {
        bail!("Malformed update service delayed startup: {name}");
    }
    Ok(value)
}

fn registry_start(name: &str) -> Result<Option<i32>> {
    let key = open_service_key(name, KEY_QUERY_VALUE)?;
    let raw = key.get_raw_value("Start")?;
    if raw.vtype != RegType::REG_DWORD || raw.bytes.len() < 4 {
        return Ok(None);
    }
    Ok(Some(i32::from_le_bytes([
        raw.bytes[0],
        raw.bytes[1],
        raw.bytes[2],
        raw.bytes[3],
    ])))
}

pub fn startup_matches(name: &str, desired: i32, log_failures: bool) -> bool {
    let attempt = || -> Result<bool> {
        if !is_target_service(name) || !(0..=4).contains(&desired) {
            bail!("Invalid update service startup verification target.");
        }
        let service =
            open_service_handle(name, 1, false)?.ok_or_else(|| anyhow!("OpenService {name}"))?;
        let start = read_start_type(&service)?;
        if i64::from(start) != i64::from(desired) || registry_start(name)? != Some(desired) {
            bail!("SCM and registry startup readback do not match {desired}: {name}");
        }
        Ok(true)
    };
    match attempt() {
        Ok(v) => v,
        Err(e) => {
            if log_failures {
                log_error("startup verification failed", &e);
            }
            false
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
struct Record {
    service_original: String,
    service_expected: String,
    registry_original: String,
    registry_expected: String,
}

#[derive(Debug, Default)]
struct Journal {
    targets: Vec<String>,
    records: HashMap<String, Record>,
}

pub fn apply() -> bool {
    let _guard = lock();
    let attempt = || -> Result<bool> {
        present_disabled_services()?;
        read_journal()?;
        Ok(run_worker("Apply", None)? && matches_inner(true))
    };
    match attempt() {
        Ok(v) => v,
        Err(e) => {
            log_error("apply failed", &e);
            false
        }
    }
}

pub fn matches(log_failures: bool) -> bool {
    let _guard = lock();
    matches_inner(log_failures)
}

fn matches_inner(log_failures: bool) -> bool {
    let attempt = || -> Result<bool> {
        let journal = match read_journal()? {
            None => return Ok(false),
            Some(j) => j,
        };
        if journal.targets != present_disabled_services()?
            || journal.records.len() != journal.targets.len()
        {
            bail!("Guard journal does not match the complete current disabled service inventory.");
        }
        for name in &journal.targets {
            let record = journal
                .records
                .get(name)
                .ok_or_else(|| anyhow!("The given key was not present in the dictionary."))?;
            if read_service_dacl(name)?.as_deref() != Some(record.service_expected.as_str())
                || read_registry_dacl(name)? != record.registry_expected
            {
                bail!("Guard DACL readback mismatch: {name}");
            }
        }
        Ok(true)
    };
    match attempt() {
        Ok(v) => v,
        Err(e) => {
            if log_failures {
                log_error("verification failed", &e);
            }
            false
        }
    }
}

pub fn has_owned_guards() -> Result<bool> {
    let _guard = lock();
    match read_journal() {
        Ok(j) => Ok(j.is_some()),
        Err(e) => {
            log_error("ownership could not be read", &e);
            Err(e)
        }
    }
}

pub fn remove_owned() -> bool {
    let _guard = lock();
    let attempt = || -> Result<bool> {
        let journal = match read_journal()? {
            None => return Ok(true),
            Some(j) => j,
        };
        let hash = journal_hash(&journal);
        if !run_worker("Remove", Some(&hash))? {
            return Ok(false);
        }
        match read_journal()? {
            Some(current) if journal_hash(&current) == hash => {}
            _ => bail!("Service guard journal changed before parent cleanup verification."),
        }
        for name in SERVICES {
            let service_dacl = read_service_dacl_optional(name)?;
            let registry_dacl = read_registry_dacl_for_cleanup(name)?;
            if let Some(d) = service_dacl {
                protect(&d, SERVICE_MASK)?;
            }
            if let Some(d) = registry_dacl {
                protect(&d, REGISTRY_MASK)?;
            }
        }
        Ok(run_worker("CompleteRemove", Some(&hash))? && read_journal()?.is_none())
    };
    match attempt() {
        Ok(v) => v,
        Err(e) => {
            log_error("cleanup failed; journal retained for retry", &e);
            false
        }
    }
}

fn new_nonce() -> String {
    use std::hash::{BuildHasher, Hasher};
    let state = std::collections::hash_map::RandomState::new();
    let mut a = state.build_hasher();
    a.write_u64(std::process::id() as u64);
    let hi = a.finish();
    let mut b = state.build_hasher();
    b.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    );
    let lo = b.finish();
    format!("{hi:016x}{lo:016x}")
}

fn deadline_ticks(seconds_ahead: u64) -> i64 {
    const UNIX_EPOCH_TICKS: i64 = 621_355_968_000_000_000;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() / 100)
        .unwrap_or(0) as i64;
    UNIX_EPOCH_TICKS + now + (seconds_ahead as i64) * 10_000_000
}

fn run_worker(action: &str, expected_journal_hash: Option<&str>) -> Result<bool> {
    let watch = Instant::now();
    let deadline = deadline_ticks(280);
    let nonce = new_nonce();
    let mut worker: Option<String> = None;
    let mut result: Option<std::path::PathBuf> = None;
    let mut completed = false;
    log::log(&format!(
        "[TI] Windows Update service guard worker | action={action} | starting"
    ));
    let outcome = (|| -> Result<bool> {
        let w =
            extract_protected_resource(RESOURCE, &format!("WindowsUpdateServiceGuard-{nonce}.ps1"));
        worker = w.clone();
        let w =
            w.ok_or_else(|| anyhow!("Protected service guard worker could not be extracted."))?;
        let result_path = std::path::Path::new(&w)
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_default()
            .join(format!("WindowsUpdateServiceGuard-{nonce}.result"));
        result = Some(result_path.clone());
        if result_path.exists() {
            bail!("Worker result collision.");
        }
        let powershell = format!(
            r"{}\System32\WindowsPowerShell\v1.0\powershell.exe",
            windows_directory()
        );
        let args = format!(
            "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{w}\" -Action {action} -Nonce {nonce} -ResultPath \"{}\" -DeadlineUtcTicks {deadline}{}",
            result_path.display(),
            match expected_journal_hash {
                None => String::new(),
                Some(h) => format!(" -ExpectedJournalHash {h}"),
            }
        );
        let (exit_code, output) = run_as_ti_output_timeout(&powershell, &args, 300000);
        let expected = format!("V1|{nonce}|{action}|OK");
        let content = std::fs::read(&result_path).ok().map(|b| {
            String::from_utf8_lossy(&b)
                .trim_start_matches('\u{feff}')
                .to_string()
        });
        if exit_code != 0 || content.as_deref() != Some(expected.as_str()) {
            bail!("Service guard worker did not complete: {output}");
        }
        completed = true;
        Ok(true)
    })();
    if outcome.is_err() {
        log::log(&format!(
            "[ERROR] Windows Update service guard worker | action={action} | error=InvalidOperationException"
        ));
    }
    log::log(&format!(
        "[TI] Windows Update service guard worker | action={action} | {} | durationMs={}",
        if completed { "completed" } else { "failed" },
        watch.elapsed().as_millis()
    ));
    if let Some(w) = worker {
        let _ = std::fs::remove_file(w);
    }
    if let Some(r) = result {
        let _ = std::fs::remove_file(r);
    }
    outcome
}

fn open_service_key(name: &str, rights: u32) -> Result<winreg::RegKey> {
    let path = format!(r"SYSTEM\CurrentControlSet\Services\{name}");
    match open_hklm64(&path, rights) {
        Ok(k) => Ok(k),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(anyhow!(
            "Open service registry key failed: target={name} | rights=QueryValues: Service registry key missing: {name}"
        )),
        Err(e) => Err(anyhow!(
            "Open service registry key failed: target={name} | rights=QueryValues: {}",
            crate::util::io_msg(&e)
        )),
    }
}

fn present_disabled_services() -> Result<Vec<String>> {
    let mut present = Vec::new();
    for name in SERVICES {
        let service = match open_service_handle(name, 1, true)? {
            None => continue,
            Some(s) => s,
        };
        let start = read_start_type(&service)?;
        let key_start = registry_start(name)?;
        if start != 4 || key_start != Some(4) {
            bail!("Service must already be disabled in SCM and registry: {name}");
        }
        present.push(name.to_string());
    }
    if present.is_empty() {
        bail!("No update services are present.");
    }
    Ok(present)
}

fn read_journal() -> Result<Option<Journal>> {
    let attempt = || -> Result<Option<Journal>> {
        let key = match open_hklm64(OWNERSHIP_KEY, winreg::enums::KEY_READ) {
            Ok(k) => k,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(anyhow!("{}", crate::util::io_msg(&e))),
        };
        if key.enum_keys().count() != 0 {
            bail!("Foreign service guard journal subkeys.");
        }
        let values: Vec<(String, winreg::RegValue)> =
            key.enum_values().collect::<std::io::Result<_>>()?;
        if values.is_empty() {
            return Ok(Some(Journal::default()));
        }
        if values.len() != 1 || values[0].0 != "State" || values[0].1.vtype != RegType::REG_MULTI_SZ
        {
            bail!("Malformed service guard state value.");
        }
        let fields = crate::util::decode_multi_sz(&values[0].1.bytes);
        Ok(Some(parse_state(Some(&fields))?))
    };
    attempt().map_err(|e| anyhow!("Service guard journal read failed: key={OWNERSHIP_KEY}: {e:#}"))
}

fn parse_state(fields: Option<&[String]>) -> Result<Journal> {
    parse_state_with(fields, &protect)
}

fn parse_state_with(
    fields: Option<&[String]>,
    protect: &dyn Fn(&str, u32) -> Result<String>,
) -> Result<Journal> {
    let fields = match fields {
        Some(f)
            if f.len() >= 3
                && f[0] == "V2"
                && !f.iter().any(|v| v.is_empty() || v.contains('\0')) =>
        {
            f
        }
        _ => bail!("Malformed serialized service guard state."),
    };
    let mut names: Vec<String> = Vec::new();
    let mut journal = Journal::default();
    let mut index = 1usize;
    while index < fields.len() {
        let name = fields[index].clone();
        index += 1;
        if !SERVICES.contains(&name.as_str()) || names.contains(&name) || index >= fields.len() {
            bail!("Invalid serialized service guard target.");
        }
        names.push(name.clone());
        let status = fields[index].clone();
        index += 1;
        if status == "N" {
            continue;
        }
        if status != "R" || index + 4 > fields.len() {
            bail!("Incomplete serialized service guard record.");
        }
        let item = Record {
            service_original: fields[index].clone(),
            service_expected: fields[index + 1].clone(),
            registry_original: fields[index + 2].clone(),
            registry_expected: fields[index + 3].clone(),
        };
        index += 4;
        if protect(&item.service_original, SERVICE_MASK)? != item.service_expected
            || protect(&item.registry_original, REGISTRY_MASK)? != item.registry_expected
        {
            bail!("Invalid serialized service guard fingerprint: {name}");
        }
        journal.records.insert(name, item);
    }
    let canonical: Vec<String> = SERVICES
        .iter()
        .filter(|s| names.iter().any(|n| n == *s))
        .map(|s| s.to_string())
        .collect();
    if canonical != names {
        bail!("Serialized service guard inventory is not canonical.");
    }
    journal.targets = names;
    Ok(journal)
}

fn serialize_state(journal: &Journal) -> Vec<String> {
    let mut fields = vec!["V2".to_string()];
    for name in &journal.targets {
        fields.push(name.clone());
        match journal.records.get(name) {
            None => {
                fields.push("N".to_string());
            }
            Some(record) => {
                fields.push("R".to_string());
                fields.push(record.service_original.clone());
                fields.push(record.service_expected.clone());
                fields.push(record.registry_original.clone());
                fields.push(record.registry_expected.clone());
            }
        }
    }
    fields
}

fn journal_hash(journal: &Journal) -> String {
    let joined = serialize_state(journal).join("\0");
    sha256_hex(joined.as_bytes())
}

pub(crate) fn sha256_hex(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&((data.len() as u64) * 8).to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut v = h;
        for i in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
            let t1 = v[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(maj);
            v[7] = v[6];
            v[6] = v[5];
            v[5] = v[4];
            v[4] = v[3].wrapping_add(t1);
            v[3] = v[2];
            v[2] = v[1];
            v[1] = v[0];
            v[0] = t1.wrapping_add(t2);
        }
        for i in 0..8 {
            h[i] = h[i].wrapping_add(v[i]);
        }
    }
    h.iter().map(|x| format!("{x:08x}")).collect()
}

struct LocalMemory(*mut c_void);

impl Drop for LocalMemory {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0)));
            }
        }
    }
}

fn dacl_sddl(psd: PSECURITY_DESCRIPTOR) -> Result<String> {
    unsafe {
        let mut text = PWSTR::null();
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            psd,
            1,
            DACL_SECURITY_INFORMATION,
            &mut text,
            None,
        )
        .map_err(|e| anyhow!("Security descriptor could not be converted to SDDL: {e}"))?;
        let _free = LocalMemory(text.0 as *mut c_void);
        text.to_string()
            .map_err(|e| anyhow!("Security descriptor SDDL is not valid text: {e}"))
    }
}

fn read_u16(b: &[u8], at: usize) -> usize {
    u16::from_le_bytes([b[at], b[at + 1]]) as usize
}

fn is_deny_type(ace_type: u8) -> bool {
    matches!(ace_type, 1 | 6 | 10 | 12)
}

fn is_allow_type(ace_type: u8) -> bool {
    matches!(ace_type, 0 | 5 | 9 | 11)
}

fn ace_sid_offset(ace: &[u8]) -> Option<usize> {
    match ace[0] {
        0..=3 | 9 | 10 => Some(8),
        5..=8 | 11 | 12 => {
            if ace.len() < 12 {
                return None;
            }
            let flags = u32::from_le_bytes([ace[8], ace[9], ace[10], ace[11]]);
            let mut offset = 12;
            if flags & 1 != 0 {
                offset += 16;
            }
            if flags & 2 != 0 {
                offset += 16;
            }
            Some(offset)
        }
        _ => None,
    }
}

fn parse_aces(acl: &[u8]) -> Option<Vec<&[u8]>> {
    if acl.len() < 8 {
        return None;
    }
    let count = read_u16(acl, 4);
    let size = read_u16(acl, 2).min(acl.len());
    let mut aces = Vec::new();
    let mut pos = 8usize;
    for _ in 0..count {
        if pos + 4 > size {
            return None;
        }
        let ace_size = read_u16(acl, pos + 2);
        if ace_size < 4 || pos + ace_size > size {
            return None;
        }
        aces.push(&acl[pos..pos + ace_size]);
        pos += ace_size;
    }
    Some(aces)
}

fn dacl_is_canonical(aces: &[&[u8]]) -> bool {
    let mut seen_allow = false;
    let mut seen_inherited = false;
    for ace in aces {
        let inherited = ace[1] & 0x10 != 0;
        if inherited {
            seen_inherited = true;
            continue;
        }
        if seen_inherited {
            return false;
        }
        if is_deny_type(ace[0]) {
            if seen_allow {
                return false;
            }
        } else if is_allow_type(ace[0]) {
            seen_allow = true;
        }
    }
    true
}

fn protect(sddl: &str, mask: u32) -> Result<String> {
    let invalid = || anyhow!("Journal contains a noncanonical or non-DACL descriptor.");
    unsafe {
        let w: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut psd = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(w.as_ptr()), 1, &mut psd, None)
            .map_err(|e| anyhow!("Value was invalid: {e}"))?;
        let _free = LocalMemory(psd.0);

        let mut owner = PSID::default();
        let mut group = PSID::default();
        let mut defaulted = windows::core::BOOL(0);
        GetSecurityDescriptorOwner(psd, &mut owner, &mut defaulted).map_err(|_| invalid())?;
        GetSecurityDescriptorGroup(psd, &mut group, &mut defaulted).map_err(|_| invalid())?;
        let mut sacl_present = windows::core::BOOL(0);
        let mut sacl: *mut ACL = std::ptr::null_mut();
        GetSecurityDescriptorSacl(psd, &mut sacl_present, &mut sacl, &mut defaulted)
            .map_err(|_| invalid())?;
        let mut dacl_present = windows::core::BOOL(0);
        let mut dacl: *mut ACL = std::ptr::null_mut();
        GetSecurityDescriptorDacl(psd, &mut dacl_present, &mut dacl, &mut defaulted)
            .map_err(|_| invalid())?;
        if !owner.0.is_null()
            || !group.0.is_null()
            || sacl_present.as_bool()
            || !dacl_present.as_bool()
            || dacl.is_null()
        {
            return Err(invalid());
        }
        if dacl_sddl(psd)? != sddl {
            return Err(invalid());
        }
        let header = std::slice::from_raw_parts(dacl as *const u8, 8);
        let acl_size = read_u16(header, 2);
        let acl_bytes = std::slice::from_raw_parts(dacl as *const u8, acl_size);
        let revision = acl_bytes[0].max(2);
        let aces = parse_aces(acl_bytes).ok_or_else(invalid)?;
        if !dacl_is_canonical(&aces) {
            return Err(invalid());
        }
        let overlap = mask | 0x5000_0000 | if mask == SERVICE_MASK { 0x2000_0000 } else { 0 };
        for ace in &aces {
            if !is_deny_type(ace[0]) || ace.len() < 8 {
                continue;
            }
            let access = u32::from_le_bytes([ace[4], ace[5], ace[6], ace[7]]);
            let sid_at = match ace_sid_offset(ace) {
                Some(o) => o,
                None => continue,
            };
            if ace.len() >= sid_at + 12
                && ace[sid_at..sid_at + 12] == SYSTEM_SID
                && access & overlap != 0
            {
                bail!("Existing overlapping SYSTEM deny is not owned.");
            }
        }

        let mut new_ace = vec![1u8, 0, 20, 0];
        new_ace.extend_from_slice(&mask.to_le_bytes());
        new_ace.extend_from_slice(&SYSTEM_SID);
        let body: usize = aces.iter().map(|a| a.len()).sum();
        let total = 8 + new_ace.len() + body;
        let words = total.div_ceil(4);
        let mut buffer = vec![0u32; words];
        let out = std::slice::from_raw_parts_mut(buffer.as_mut_ptr() as *mut u8, words * 4);
        out[0] = revision;
        out[1] = 0;
        out[2..4].copy_from_slice(&(total as u16).to_le_bytes());
        out[4..6].copy_from_slice(&((aces.len() + 1) as u16).to_le_bytes());
        let mut pos = 8;
        out[pos..pos + new_ace.len()].copy_from_slice(&new_ace);
        pos += new_ace.len();
        for ace in &aces {
            out[pos..pos + ace.len()].copy_from_slice(ace);
            pos += ace.len();
        }

        let mut control = 0u16;
        let mut control_revision = 0u32;
        GetSecurityDescriptorControl(psd, &mut control, &mut control_revision)
            .map_err(|_| invalid())?;
        let mut sd_buffer = [0u64; 16];
        let new_sd = PSECURITY_DESCRIPTOR(sd_buffer.as_mut_ptr() as *mut c_void);
        InitializeSecurityDescriptor(new_sd, 1)
            .map_err(|e| anyhow!("Security descriptor could not be initialized: {e}"))?;
        SetSecurityDescriptorDacl(new_sd, true, Some(buffer.as_ptr() as *const ACL), false)
            .map_err(|e| anyhow!("Security descriptor DACL could not be set: {e}"))?;
        let interesting = 0x0100u16 | 0x0400 | 0x1000;
        SetSecurityDescriptorControl(
            new_sd,
            SECURITY_DESCRIPTOR_CONTROL(interesting),
            SECURITY_DESCRIPTOR_CONTROL(control & interesting),
        )
        .map_err(|e| anyhow!("Security descriptor control could not be set: {e}"))?;
        dacl_sddl(new_sd)
    }
}

struct RegHandle(HKEY);

impl Drop for RegHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = RegCloseKey(self.0);
        }
    }
}

fn registry_key_sddl(name: &str) -> Result<Option<String>> {
    unsafe {
        let path: Vec<u16> = format!(r"SYSTEM\CurrentControlSet\Services\{name}")
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut key = HKEY::default();
        let error = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(path.as_ptr()),
            None,
            windows::Win32::System::Registry::REG_SAM_FLAGS(READ_CONTROL | KEY_WOW64_64KEY.0),
            &mut key,
        );
        if error.0 == 2 || error.0 == 3 {
            return Ok(None);
        }
        if error.0 != 0 {
            bail!("Open service registry DACL {name}: Win32 error {}", error.0);
        }
        let handle = RegHandle(key);
        let mut buffer = vec![0u8; 4096];
        loop {
            let mut size = buffer.len() as u32;
            let status = RegGetKeySecurity(
                handle.0,
                DACL_SECURITY_INFORMATION,
                Some(PSECURITY_DESCRIPTOR(buffer.as_mut_ptr() as *mut c_void)),
                &mut size,
            );
            if status.0 == ERROR_INSUFFICIENT_BUFFER && (size as usize) > buffer.len() {
                buffer = vec![0u8; size as usize];
                continue;
            }
            if status.0 != 0 {
                bail!("Service registry DACL {name}: Win32 error {}", status.0);
            }
            break;
        }
        Ok(Some(dacl_sddl(PSECURITY_DESCRIPTOR(
            buffer.as_mut_ptr() as *mut c_void
        ))?))
    }
}

fn read_registry_dacl(name: &str) -> Result<String> {
    registry_key_sddl(name)
        .and_then(|v| v.ok_or_else(|| anyhow!("Service registry key missing: {name}")))
        .map_err(|e| {
            anyhow!("Read service registry DACL failed: target={name} | rights=READ_CONTROL: {e:#}")
        })
}

fn read_registry_dacl_for_cleanup(name: &str) -> Result<Option<String>> {
    registry_key_sddl(name)
}

struct ServiceHandle(SC_HANDLE);

impl Drop for ServiceHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseServiceHandle(self.0);
        }
    }
}

fn open_service_handle(name: &str, rights: u32, optional: bool) -> Result<Option<ServiceHandle>> {
    unsafe {
        let manager = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), 1)
            .map_err(|e| anyhow!("OpenSCManager: Win32 error {}", win32_code(&e)))?;
        let manager = ServiceHandle(manager);
        let wname: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        match OpenServiceW(manager.0, PCWSTR(wname.as_ptr()), rights) {
            Ok(service) => Ok(Some(ServiceHandle(service))),
            Err(e) => {
                let code = win32_code(&e);
                if optional && code == ERROR_SERVICE_DOES_NOT_EXIST {
                    Ok(None)
                } else {
                    Err(anyhow!("OpenService {name}: Win32 error {code}"))
                }
            }
        }
    }
}

fn read_start_type(service: &ServiceHandle) -> Result<u32> {
    unsafe {
        let mut needed = 0u32;
        let sizing = QueryServiceConfigW(service.0, None, 0, &mut needed);
        let code = match &sizing {
            Ok(()) => 0,
            Err(e) => win32_code(e),
        };
        if sizing.is_ok() || code != ERROR_INSUFFICIENT_BUFFER || needed == 0 || needed > 8192 {
            bail!("Service configuration size: Win32 error {code}");
        }
        let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
        let mut actual = 0u32;
        QueryServiceConfigW(
            service.0,
            Some(buffer.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW),
            needed,
            &mut actual,
        )
        .map_err(|e| anyhow!("Service configuration: Win32 error {}", win32_code(&e)))?;
        let bytes = std::slice::from_raw_parts(buffer.as_ptr() as *const u8, 8);
        Ok(u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]))
    }
}

fn read_service_dacl(name: &str) -> Result<Option<String>> {
    read_service_dacl_with(name, false)
}

fn read_service_dacl_optional(name: &str) -> Result<Option<String>> {
    read_service_dacl_with(name, true)
}

fn read_service_dacl_with(name: &str, optional: bool) -> Result<Option<String>> {
    let service = match open_service_handle(name, READ_CONTROL, optional)? {
        None => return Ok(None),
        Some(s) => s,
    };
    unsafe {
        let mut needed = 0u32;
        let sizing = QueryServiceObjectSecurity(
            service.0,
            DACL_SECURITY_INFORMATION.0,
            None,
            0,
            &mut needed,
        );
        let code = match &sizing {
            Ok(()) => 0,
            Err(e) => win32_code(e),
        };
        if sizing.is_ok() || code != ERROR_INSUFFICIENT_BUFFER || needed == 0 || needed > 65536 {
            bail!("Service DACL size {name}: Win32 error {code}");
        }
        let mut buffer = vec![0u8; needed as usize];
        let mut actual = 0u32;
        QueryServiceObjectSecurity(
            service.0,
            DACL_SECURITY_INFORMATION.0,
            Some(PSECURITY_DESCRIPTOR(buffer.as_mut_ptr() as *mut c_void)),
            needed,
            &mut actual,
        )
        .map_err(|e| anyhow!("Service DACL {name}: Win32 error {}", win32_code(&e)))?;
        Ok(Some(dacl_sddl(PSECURITY_DESCRIPTOR(
            buffer.as_mut_ptr() as *mut c_void
        ))?))
    }
}

fn log_error(detail: &str, error: &anyhow::Error) {
    log::exception(
        &format!("Windows Update service guard {detail}"),
        &format!("{error:#}"),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_protect(_: &str, _: u32) -> Result<String> {
        bail!("protect must not be called")
    }

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn sha256_known_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn target_service_names_are_case_insensitive() {
        assert!(is_target_service("WUAUSERV"));
        assert!(is_target_service("uhssvc"));
        assert!(!is_target_service("Spooler"));
    }

    #[test]
    fn journal_with_only_missing_records_parses() {
        let fields = strings(&["V2", "wuauserv", "N", "BITS", "N"]);
        let journal = parse_state_with(Some(&fields), &no_protect).unwrap();
        assert_eq!(journal.targets, vec!["wuauserv", "BITS"]);
        assert!(journal.records.is_empty());
        let hash = journal_hash(&journal);
        assert_eq!(hash, sha256_hex("V2\0wuauserv\0N\0BITS\0N".as_bytes()));
    }

    #[test]
    fn journal_validation_failures() {
        let bad = |fields: &[&str]| {
            parse_state_with(Some(&strings(fields)), &no_protect)
                .unwrap_err()
                .to_string()
        };
        assert!(parse_state_with(None, &no_protect).is_err());
        assert!(bad(&["V1", "wuauserv", "N"]).contains("Malformed serialized"));
        assert!(bad(&["V2", "wuauserv"]).contains("Malformed serialized"));
        assert!(bad(&["V2", "wuauserv", "N", "wuauserv", "N"])
            .contains("Invalid serialized service guard target"));
        assert!(bad(&["V2", "Spooler", "N", "BITS", "N"])
            .contains("Invalid serialized service guard target"));
        assert!(bad(&["V2", "BITS", "N", "wuauserv", "N"]).contains("not canonical"));
        assert!(bad(&["V2", "wuauserv", "X", "BITS", "N"]).contains("Incomplete"));
        assert!(bad(&["V2", "wuauserv", "R", "a", "b", "c"]).contains("Incomplete"));
    }

    #[test]
    fn canonical_check_orders_denies_before_allows() {
        let allow = [0u8, 0, 20, 0, 0, 0, 0, 0];
        let deny = [1u8, 0, 20, 0, 0, 0, 0, 0];
        let inherited_deny = [1u8, 0x10, 20, 0, 0, 0, 0, 0];
        assert!(dacl_is_canonical(&[&deny, &allow, &inherited_deny]));
        assert!(!dacl_is_canonical(&[&allow, &deny]));
        assert!(!dacl_is_canonical(&[&inherited_deny, &allow]));
    }

    #[test]
    fn protect_inserts_system_deny_first() {
        let sddl = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)";
        let guarded = protect(sddl, SERVICE_MASK).unwrap();
        assert!(guarded.starts_with("D:(D;;"));
        assert!(guarded.contains(";;;SY)"));
        assert!(guarded.ends_with(&sddl[2..]));
        assert!(protect(&guarded, SERVICE_MASK).is_err());
        assert!(protect("O:BAD:(A;;GA;;;WD)", SERVICE_MASK).is_err());
    }
}

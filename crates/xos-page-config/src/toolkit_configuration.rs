use anyhow::{anyhow, bail, Result};
use base64::Engine;
use serde::{Deserialize, Deserializer, Serialize};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use winreg::enums::{
    RegType, HKEY_CLASSES_ROOT, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_CREATE_SUB_KEY,
    KEY_READ, KEY_SET_VALUE,
};
use winreg::{RegKey, RegValue};
use xos_core::catalog as feature_catalog;
use xos_core::{log, session_log};
use xos_cpu::rules::{self, CpuRulesConfig};
use xos_cpu::topology;
use xos_sys::{
    config_service_reg, config_service_sc, disable_feature, disable_task, enable_feature,
    enable_task, get_all_feature_states, get_choco_installed_packages, get_service_start_type,
    get_task_state, get_task_state_verified, get_task_states_batch, get_windows_build_number,
    is_choco_installed, is_feature_absent_on_this_build, is_feature_state_enabled,
    is_tolerant_task_path, reg_get_dword, run_as_ti, service_exists, set_service_grouping_values,
    CiMap, FEATURE_NOT_AVAILABLE_TEXT,
};
use xos_winupdate::{hard_disable, service_guard};

#[path = "registry_specs.rs"]
mod registry_specs;

pub const FORMAT_ID: &str = "xos-toolkit-configuration";

fn null_default<'de, D, T>(d: D) -> std::result::Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct RegistrySettingState {
    #[serde(default, deserialize_with = "null_default")]
    pub exists: bool,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default, deserialize_with = "null_default", rename = "minimumBuild")]
    pub minimum_build: i32,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(skip)]
    pub read_succeeded: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ServiceSettingState {
    #[serde(default, deserialize_with = "null_default")]
    pub exists: bool,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default, deserialize_with = "null_default", rename = "startType")]
    pub start_type: i32,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct TaskSettingState {
    #[serde(default, deserialize_with = "null_default")]
    pub enabled: bool,
    #[serde(default, deserialize_with = "null_default")]
    pub exists: bool,
    #[serde(default)]
    pub path: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct FeatureSettingState {
    #[serde(default, deserialize_with = "null_default")]
    pub enabled: bool,
    #[serde(default, deserialize_with = "null_default")]
    pub exists: bool,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ApplicationSettingState {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default, deserialize_with = "null_default")]
    pub installed: bool,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ToolkitConfigurationSnapshot {
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default, deserialize_with = "null_default", rename = "schemaVersion")]
    pub schema_version: i32,
    #[serde(default, rename = "toolkitVersion")]
    pub toolkit_version: Option<String>,
    #[serde(default, deserialize_with = "null_default", rename = "windowsBuild")]
    pub windows_build: i32,
    #[serde(default, rename = "exportedUtc")]
    pub exported_utc: Option<String>,
    #[serde(default, rename = "cpuName")]
    pub cpu_name: Option<String>,
    #[serde(
        default,
        deserialize_with = "null_default",
        rename = "logicalProcessors"
    )]
    pub logical_processors: i32,
    #[serde(default, deserialize_with = "null_default")]
    pub registry: Vec<Option<RegistrySettingState>>,
    #[serde(default, deserialize_with = "null_default")]
    pub services: Vec<Option<ServiceSettingState>>,
    #[serde(default, deserialize_with = "null_default", rename = "scheduledTasks")]
    pub scheduled_tasks: Vec<Option<TaskSettingState>>,
    #[serde(default, deserialize_with = "null_default", rename = "windowsFeatures")]
    pub windows_features: Vec<Option<FeatureSettingState>>,
    #[serde(default, rename = "cpuRules")]
    pub cpu_rules: Option<CpuRulesConfig>,
    #[serde(default, deserialize_with = "null_default")]
    pub applications: Vec<Option<ApplicationSettingState>>,
    #[serde(default, deserialize_with = "warnings_default")]
    pub warnings: Vec<String>,
    #[serde(
        default,
        rename = "windowsUpdateServiceGuard",
        skip_serializing_if = "Option::is_none"
    )]
    pub windows_update_service_guard: Option<bool>,
}

fn warnings_default<'de, D>(d: D) -> std::result::Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let list: Option<Vec<Option<String>>> = Option::deserialize(d)?;
    Ok(list
        .unwrap_or_default()
        .into_iter()
        .map(|w| w.unwrap_or_default())
        .collect())
}

impl ToolkitConfigurationSnapshot {
    pub fn new() -> Self {
        Self {
            format: Some(FORMAT_ID.to_string()),
            schema_version: 1,
            ..Default::default()
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConfigurationSelection {
    pub registry: bool,
    pub services: bool,
    pub tasks: bool,
    pub features: bool,
    pub cpu_rules: bool,
    pub applications: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConfigurationDifference {
    pub category: String,
    pub item: String,
    pub current: String,
    pub backup: String,
    pub action: String,
    pub applicable: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConfigurationApplyResult {
    pub applied: i32,
    pub skipped: i32,
    pub failed: i32,
    pub reboot_required: bool,
}

#[derive(Clone, Debug)]
struct RegistrySpec {
    path: String,
    name: String,
    minimum_build: i32,
    required_service: String,
}

struct Specs {
    list: Vec<RegistrySpec>,
    by_id: HashMap<String, usize>,
}

fn specs() -> &'static Specs {
    static S: OnceLock<Specs> = OnceLock::new();
    S.get_or_init(|| {
        let list = registry_specs::build_registry_specs();
        let mut by_id = HashMap::new();
        for (i, spec) in list.iter().enumerate() {
            by_id.insert(ci(&registry_id(&spec.path, &spec.name)), i);
        }
        Specs { list, by_id }
    })
}

const ADDITIONAL_MANAGED_SERVICES: &[&str] = &[
    "wuauserv",
    "bits",
    "dosvc",
    "UsoSvc",
    "WaaSMedicSvc",
    "uhssvc",
    "Themes",
    "WinDefend",
    "WdNisSvc",
    "WdFilter",
    "WdBoot",
    "WdNisDrv",
    "MDCoreSvc",
    "Sense",
    "wscsvc",
    "SecurityHealthService",
    "MsSecCore",
    "MsSecWfp",
    "MsSecFlt",
    "SgrmBroker",
    "wtd",
    "webthreatdefusersvc",
    "webthreatdefsvc",
    "luafv",
    "Appinfo",
    "bam",
    "WpnService",
    "WpnUserService",
    "GraphicsPerfSvc",
    "Ndu",
    "DPS",
    "dusmsvc",
    "diagsvc",
    "WdiServiceHost",
    "WdiSystemHost",
    "bttflt",
    "gencounter",
    "hyperkbd",
    "hypervideo",
    "spaceparser",
    "storflt",
    "vmgid",
    "vpci",
    "vid",
    "TermService",
    "UmRdpService",
    "SessionEnv",
    "WSearch",
    "netprofm",
    "NlaSvc",
    "vwififlt",
    "WlanSvc",
    "eventlog",
    "BFE",
    "mpssvc",
    "Dhcp",
    "Dnscache",
    "RasMan",
    "RasAuto",
    "IKEEXT",
    "PolicyAgent",
    "RASSSTP",
    "SstpSvc",
    "RFCOMM",
    "BthEnum",
    "bthleenum",
    "BTHMODEM",
    "BthA2dp",
    "microsoft_bluetooth_avrcptransport",
    "BthHFEnum",
    "BTAGService",
    "bthserv",
    "BluetoothUserService",
    "BthAvctpSvc",
    "BthMini",
    "BthPan",
    "BTHPORT",
    "BTHUSB",
    "HidBth",
    "ibtusb",
    "cbdhsvc",
    "Spooler",
    "StiSvc",
    "PrintWorkFlowUserSvc",
    "PrintNotify",
    "usbprint",
    "PrintScanBrokerService",
    "PrintDeviceConfigurationService",
    "Serenum",
    "Serial",
    "sermouse",
    "usbser",
    "Parport",
    "AMD Crash Defender Service",
    "amdfendr",
    "amdfendrmgr",
    "amdlog",
];

const DEFENDER_SERVICE_NAMES: &[&str] = &[
    "WinDefend",
    "WdNisSvc",
    "WdFilter",
    "WdBoot",
    "WdNisDrv",
    "MDCoreSvc",
    "Sense",
    "wscsvc",
    "SecurityHealthService",
    "MsSecCore",
    "MsSecWfp",
    "MsSecFlt",
    "SgrmBroker",
    "wtd",
    "webthreatdefusersvc",
    "webthreatdefsvc",
];

const ADDITIONAL_MANAGED_TASKS: &[&str] = &[
    r"\Microsoft\Windows\WindowsUpdate\Scheduled Start",
    r"\Microsoft\Windows\UpdateOrchestrator\Schedule Scan",
    r"\Microsoft\Windows\UpdateOrchestrator\Schedule Scan Static Task",
    r"\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker",
    r"\Microsoft\Windows\WaaSMedic\PerformRemediation",
    r"\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance",
    r"\Microsoft\Windows\Windows Defender\Windows Defender Cleanup",
    r"\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan",
    r"\Microsoft\Windows\Windows Defender\Windows Defender Verification",
];

fn ci(s: &str) -> String {
    s.to_uppercase()
}

fn ci_eq(a: &str, b: &str) -> bool {
    ci(a) == ci(b)
}

fn icontains(haystack: &str, needle: &str) -> bool {
    ci(haystack).contains(&ci(needle))
}

fn istarts(haystack: &str, prefix: &str) -> bool {
    ci(haystack).starts_with(&ci(prefix))
}

fn iends(haystack: &str, suffix: &str) -> bool {
    ci(haystack).ends_with(&ci(suffix))
}

fn blank(s: Option<&str>) -> bool {
    s.map(|v| v.trim().is_empty()).unwrap_or(true)
}

fn distinct_ci<I: IntoIterator<Item = String>>(items: I) -> Vec<String> {
    let mut seen = HashSet::new();
    items
        .into_iter()
        .filter(|item| seen.insert(ci(item)))
        .collect()
}

fn managed_service_names() -> Vec<String> {
    distinct_ci(
        xos_page_network::managed_service_names()
            .into_iter()
            .chain(ADDITIONAL_MANAGED_SERVICES.iter().map(|s| s.to_string())),
    )
}

fn managed_task_paths() -> Vec<String> {
    distinct_ci(
        xos_page_network::managed_task_paths()
            .into_iter()
            .chain(feature_catalog::PRINT_TASKS.iter().map(|s| s.to_string()))
            .chain(feature_catalog::WIFI_TASKS.iter().map(|s| s.to_string()))
            .chain(std::iter::once(
                feature_catalog::BLUETOOTH_UNINSTALL_TASK.to_string(),
            ))
            .chain(ADDITIONAL_MANAGED_TASKS.iter().map(|s| s.to_string())),
    )
}

fn managed_feature_names() -> Vec<String> {
    distinct_ci(
        feature_catalog::PRINT_FEATURES
            .iter()
            .chain(feature_catalog::HYPER_V_FEATURES.iter())
            .map(|s| s.to_string()),
    )
}

fn registry_id(path: &str, name: &str) -> String {
    format!("{path}\0{name}")
}

fn registry_id_of(state: &RegistrySettingState) -> String {
    registry_id(
        state.path.as_deref().unwrap_or(""),
        state.name.as_deref().unwrap_or(""),
    )
}

fn display_registry_name(name: Option<&str>) -> String {
    match name {
        Some(n) if !n.is_empty() => n.to_string(),
        _ => "(Default)".to_string(),
    }
}

fn registry_text(state: Option<&RegistrySettingState>) -> String {
    match state {
        Some(s) if s.exists => format!(
            "{} ({})",
            s.value.as_deref().unwrap_or(""),
            s.kind.as_deref().unwrap_or("Unknown")
        ),
        _ => "Default / absent".to_string(),
    }
}

fn start_type_text(kind: i32) -> &'static str {
    match kind {
        0 => "Boot",
        1 => "System",
        2 => "Automatic",
        3 => "Manual",
        4 => "Disabled",
        _ => "Not present",
    }
}

fn service_text(state: Option<&ServiceSettingState>) -> String {
    match state {
        Some(s) if s.exists => start_type_text(s.start_type).to_string(),
        _ => "Not present".to_string(),
    }
}

fn task_text(state: Option<&TaskSettingState>) -> String {
    match state {
        Some(s) if s.exists => if s.enabled { "Enabled" } else { "Disabled" }.to_string(),
        _ => "Not present".to_string(),
    }
}

fn feature_text(state: Option<&FeatureSettingState>) -> String {
    match state {
        Some(s) if s.exists => if s.enabled { "Enabled" } else { "Disabled" }.to_string(),
        _ => "Not present".to_string(),
    }
}

fn cpu_text(config: Option<&CpuRulesConfig>) -> String {
    match config {
        None => "Not included".to_string(),
        Some(c) => format!("{} rules, {} presets", c.rules.len(), c.user_presets.len()),
    }
}

fn registry_states_equal(
    left: Option<&RegistrySettingState>,
    right: Option<&RegistrySettingState>,
) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(l), Some(r)) => {
            if l.exists != r.exists {
                return false;
            }
            if !l.exists {
                return true;
            }
            let kind_equal = match (&l.kind, &r.kind) {
                (None, None) => true,
                (Some(a), Some(b)) => ci_eq(a, b),
                _ => false,
            };
            kind_equal && l.value == r.value
        }
        _ => false,
    }
}

fn difference(
    category: &str,
    item: &str,
    current: String,
    backup: String,
    action: &str,
    applicable: bool,
) -> ConfigurationDifference {
    ConfigurationDifference {
        category: category.to_string(),
        item: item.to_string(),
        current,
        backup,
        action: action.to_string(),
        applicable,
    }
}

fn to_json_text<T: Serialize>(value: &T) -> Result<String> {
    Ok(serde_json::to_string(value)?.replace('/', "\\/"))
}

pub fn to_json(snapshot: &ToolkitConfigurationSnapshot) -> Result<String> {
    to_json_text(snapshot)
}

pub fn from_json(text: &str) -> Result<ToolkitConfigurationSnapshot> {
    let bytes = text.as_bytes();
    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    parse_snapshot(bytes)
}

fn parse_snapshot(bytes: &[u8]) -> Result<ToolkitConfigurationSnapshot> {
    let parsed: Option<ToolkitConfigurationSnapshot> = serde_json::from_slice(bytes)?;
    let mut result = match parsed {
        Some(r) if r.format.as_deref() == Some(FORMAT_ID) => r,
        _ => bail!("This is not an XOS Toolkit configuration file."),
    };
    if result.schema_version > 1 {
        bail!("This backup was created by a newer Toolkit version.");
    }
    if result.schema_version < 1 {
        bail!("This backup uses an unsupported schema version.");
    }
    validate_snapshot(&mut result)?;
    Ok(result)
}

fn utc_now_round_trip() -> String {
    let now = chrono::Utc::now();
    format!(
        "{}.{:07}Z",
        now.format("%Y-%m-%dT%H:%M:%S"),
        now.timestamp_subsec_nanos() / 100
    )
}

fn toolkit_version() -> String {
    let parts = xos_core::VERSION.split('.').count();
    if parts >= 4 {
        xos_core::VERSION.to_string()
    } else {
        format!("{}{}", xos_core::VERSION, ".0".repeat(4 - parts))
    }
}

pub fn capture(selection: &ConfigurationSelection) -> Result<ToolkitConfigurationSnapshot> {
    let mut snapshot = ToolkitConfigurationSnapshot::new();
    snapshot.toolkit_version = Some(toolkit_version());
    snapshot.windows_build = get_windows_build_number();
    snapshot.exported_utc = Some(utc_now_round_trip());

    if selection.registry {
        let registry: Vec<RegistrySettingState> =
            specs().list.iter().map(read_registry_state).collect();
        for unreadable in registry.iter().filter(|s| !s.read_succeeded) {
            snapshot.warnings.push(format!(
                "Registry value not captured: {} / {}",
                unreadable.path.as_deref().unwrap_or(""),
                display_registry_name(unreadable.name.as_deref())
            ));
        }
        snapshot.registry = registry
            .into_iter()
            .filter(|s| s.read_succeeded)
            .map(Some)
            .collect();
    }

    if selection.services {
        match service_guard::has_owned_guards() {
            Ok(v) => snapshot.windows_update_service_guard = Some(v),
            Err(ex) => snapshot.warnings.push(format!(
                "Windows Update service protection was not captured: {ex}"
            )),
        }
        snapshot.services = managed_service_names()
            .into_iter()
            .map(|name| {
                let exists = service_exists(&name);
                let start_type = if exists {
                    get_service_start_type(&name)
                } else {
                    -1
                };
                Some(ServiceSettingState {
                    exists,
                    name: Some(name),
                    start_type,
                })
            })
            .collect();
    }

    if selection.tasks {
        let paths = managed_task_paths();
        let states = get_task_states_batch(&paths);
        snapshot.scheduled_tasks = paths
            .into_iter()
            .map(|path| {
                let state = states.get(&path).copied().unwrap_or(-1);
                Some(TaskSettingState {
                    enabled: state == 1,
                    exists: state >= 0,
                    path: Some(path),
                })
            })
            .collect();
    }

    if selection.features {
        let names = managed_feature_names();
        let states = get_all_feature_states();
        if states.is_empty() {
            bail!("Windows optional features could not be enumerated.");
        }
        snapshot.windows_features = names
            .into_iter()
            .map(|name| {
                let state = states.get(&name);
                Some(FeatureSettingState {
                    enabled: state.map(|s| is_feature_state_enabled(s)).unwrap_or(false),
                    exists: state.is_some(),
                    name: Some(name),
                })
            })
            .collect();
    }

    if selection.cpu_rules {
        topology::initialize();
        snapshot.cpu_name = Some(topology::cpu_name());
        snapshot.logical_processors = topology::logical_processor_count() as i32;
        snapshot.cpu_rules = Some(rules::load());
    }

    if selection.applications {
        let installed = installed_packages()?;
        snapshot.applications = xos_page_apps::catalog_apps()
            .into_iter()
            .map(|app| {
                Some(ApplicationSettingState {
                    id: Some(app.id.to_string()),
                    installed: installed.contains_key(app.id),
                    name: Some(app.name.to_string()),
                })
            })
            .collect();
    }

    Ok(snapshot)
}

fn installed_packages() -> Result<CiMap<bool>> {
    if is_choco_installed() {
        get_choco_installed_packages()
    } else {
        Ok(CiMap::new())
    }
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_name(path: &Path) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed) as u128;
    let guid = nanos ^ (u128::from(std::process::id()) << 96) ^ (n << 64);
    let mut name = path.as_os_str().to_os_string();
    name.push(format!(".{guid:032x}.tmp"));
    PathBuf::from(name)
}

fn commit_temp_file(temp: &Path, destination: &Path) -> Result<()> {
    if !destination.exists() {
        fs::rename(temp, destination)?;
        return Ok(());
    }
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{ReplaceFileW, REPLACE_FILE_FLAGS};
    let wide = |p: &Path| -> Vec<u16> { p.as_os_str().encode_wide().chain(Some(0)).collect() };
    let dest = wide(destination);
    let src = wide(temp);
    unsafe {
        ReplaceFileW(
            PCWSTR(dest.as_ptr()),
            PCWSTR(src.as_ptr()),
            PCWSTR::null(),
            REPLACE_FILE_FLAGS(0),
            None,
            None,
        )
    }?;
    Ok(())
}

pub fn save(path: impl AsRef<Path>, snapshot: &ToolkitConfigurationSnapshot) -> Result<()> {
    let path = path.as_ref();
    if path.as_os_str().to_string_lossy().trim().is_empty() {
        bail!("A file path is required.");
    }
    let json = to_json(snapshot)?;
    let full = std::path::absolute(path)?;
    let directory = full
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .ok_or_else(|| anyhow!("The backup folder could not be resolved."))?
        .to_path_buf();
    fs::create_dir_all(&directory)?;
    let temp = temp_name(&full);
    let result = (|| -> Result<()> {
        {
            use std::os::windows::fs::OpenOptionsExt;
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .share_mode(0)
                .open(&temp)?;
            f.write_all(json.as_bytes())?;
            f.sync_all()?;
        }
        commit_temp_file(&temp, &full)
    })();
    if temp.exists() {
        let _ = fs::remove_file(&temp);
    }
    result
}

pub fn load(path: impl AsRef<Path>) -> Result<ToolkitConfigurationSnapshot> {
    let path = path.as_ref();
    if path.as_os_str().to_string_lossy().trim().is_empty() {
        bail!("A file path is required.");
    }
    if fs::metadata(path)?.len() > 16 * 1024 * 1024 {
        bail!("The configuration file is too large.");
    }
    let bytes = fs::read(path)?;
    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(&bytes);
    parse_snapshot(bytes)
}

fn validate_snapshot(snapshot: &mut ToolkitConfigurationSnapshot) -> Result<()> {
    if snapshot.registry.len() > 8192
        || snapshot.services.len() > 4096
        || snapshot.scheduled_tasks.len() > 4096
        || snapshot.windows_features.len() > 4096
        || snapshot.applications.len() > 8192
        || snapshot.warnings.len() > 8192
    {
        bail!("The configuration contains too many entries.");
    }
    if snapshot.logical_processors < 0 || snapshot.logical_processors > 4096 {
        bail!("The configuration contains an invalid logical processor count.");
    }
    if let Some(cpu) = &snapshot.cpu_rules {
        rules::normalize(cpu)?;
        if snapshot.logical_processors == 0 {
            snapshot.logical_processors = infer_cpu_rule_width(cpu);
        }
    }
    Ok(())
}

fn infer_cpu_rule_width(config: &CpuRulesConfig) -> i32 {
    let rules = config
        .rules
        .iter()
        .map(|r| r.cores.len())
        .max()
        .unwrap_or(0);
    let presets = config
        .user_presets
        .iter()
        .map(|p| p.cores.len())
        .max()
        .unwrap_or(0);
    rules.max(presets) as i32
}

fn cpu_fingerprint(config: Option<&CpuRulesConfig>) -> String {
    match config {
        None => String::new(),
        Some(c) => {
            let json = to_json_text(c).unwrap_or_default();
            base64::engine::general_purpose::STANDARD.encode(json.as_bytes())
        }
    }
}

fn cpu_topology_matches(backup: &ToolkitConfigurationSnapshot) -> bool {
    topology::initialize();
    let count_matches = backup.logical_processors <= 0
        || backup.logical_processors as usize == topology::logical_processor_count();
    let name_matches = blank(backup.cpu_name.as_deref())
        || ci_eq(
            backup.cpu_name.as_deref().unwrap_or("").trim(),
            topology::cpu_name().trim(),
        );
    count_matches && name_matches
}

fn first_by<'a, T, F>(items: impl Iterator<Item = &'a T>, key: F) -> HashMap<String, &'a T>
where
    T: 'a,
    F: Fn(&T) -> String,
{
    let mut map = HashMap::new();
    for item in items {
        map.entry(ci(&key(item))).or_insert(item);
    }
    map
}

fn get_managed_registry_spec(
    state: Option<&RegistrySettingState>,
) -> Option<&'static RegistrySpec> {
    let state = state?;
    if blank(state.path.as_deref()) {
        return None;
    }
    let name = state.name.as_deref()?;
    let index = specs()
        .by_id
        .get(&ci(&registry_id(state.path.as_deref()?, name)))?;
    specs().list.get(*index)
}

fn is_registry_spec_supported(spec: &RegistrySpec, build: i32) -> bool {
    let scan_source = (spec.path == hard_disable::POLICY
        && hard_disable::CLASS_VALUES.contains(&spec.name.as_str()))
        || (spec.path == hard_disable::AU && spec.name == "UseUpdateClassPolicySource");
    spec.minimum_build <= build
        && (!scan_source || hard_disable::supports_scan_sources())
        && (spec.required_service.is_empty() || service_exists(&spec.required_service))
}

pub fn compare(
    backup: &ToolkitConfigurationSnapshot,
    current: &ToolkitConfigurationSnapshot,
    selection: &ConfigurationSelection,
) -> Vec<ConfigurationDifference> {
    let mut differences = Vec::new();
    let build = get_windows_build_number();

    if selection.registry {
        let now = first_by(current.registry.iter().flatten(), registry_id_of);
        for saved in backup.registry.iter() {
            let Some(spec) = get_managed_registry_spec(saved.as_ref()) else {
                continue;
            };
            let saved = saved.as_ref().unwrap();
            let value = now.get(&ci(&registry_id(&spec.path, &spec.name))).copied();
            let supported = is_registry_spec_supported(spec, build);
            let current_text = registry_text(value);
            let backup_text = registry_text(Some(saved));
            if !registry_states_equal(value, Some(saved)) || !supported {
                differences.push(difference(
                    "Registry",
                    &format!(
                        "{} / {}",
                        spec.path,
                        display_registry_name(Some(&spec.name))
                    ),
                    current_text,
                    backup_text,
                    if supported {
                        "Restore"
                    } else {
                        "Skip: unsupported build"
                    },
                    supported,
                ));
            }
        }
    }

    if selection.services {
        if let Some(saved_guard) = backup.windows_update_service_guard {
            if Some(saved_guard) != current.windows_update_service_guard {
                differences.push(difference(
                    "Services",
                    "Windows Update service protection",
                    match current.windows_update_service_guard {
                        Some(true) => "Protected",
                        Some(false) => "Unprotected",
                        None => "Unknown",
                    }
                    .to_string(),
                    if saved_guard {
                        "Protected"
                    } else {
                        "Unprotected"
                    }
                    .to_string(),
                    "Restore",
                    true,
                ));
            }
        }
        let managed: HashSet<String> = managed_service_names().iter().map(|n| ci(n)).collect();
        let now = first_by(
            current.services.iter().flatten().filter(|s| {
                !blank(s.name.as_deref()) && managed.contains(&ci(s.name.as_deref().unwrap()))
            }),
            |s| s.name.clone().unwrap_or_default(),
        );
        for saved in backup.services.iter().flatten() {
            let Some(name) = saved.name.as_deref() else {
                continue;
            };
            if blank(Some(name)) || !managed.contains(&ci(name)) {
                continue;
            }
            if !saved.exists {
                continue;
            }
            let value = now.get(&ci(name)).copied();
            let supported = value.map(|v| v.exists).unwrap_or(false);
            if !supported || value.unwrap().start_type != saved.start_type {
                differences.push(difference(
                    "Services",
                    name,
                    service_text(value),
                    service_text(Some(saved)),
                    if supported {
                        "Restore"
                    } else {
                        "Skip: not present"
                    },
                    supported,
                ));
            }
        }
    }

    if selection.tasks {
        let managed: HashSet<String> = managed_task_paths().iter().map(|n| ci(n)).collect();
        let now = first_by(
            current.scheduled_tasks.iter().flatten().filter(|s| {
                !blank(s.path.as_deref()) && managed.contains(&ci(s.path.as_deref().unwrap()))
            }),
            |s| s.path.clone().unwrap_or_default(),
        );
        for saved in backup.scheduled_tasks.iter().flatten() {
            let Some(path) = saved.path.as_deref() else {
                continue;
            };
            if blank(Some(path)) || !managed.contains(&ci(path)) {
                continue;
            }
            if !saved.exists {
                continue;
            }
            let value = now.get(&ci(path)).copied();
            let supported = value.map(|v| v.exists).unwrap_or(false);
            if !supported || value.unwrap().enabled != saved.enabled {
                differences.push(difference(
                    "Scheduled Tasks",
                    path,
                    task_text(value),
                    task_text(Some(saved)),
                    if supported {
                        "Restore"
                    } else {
                        "Skip: not present"
                    },
                    supported,
                ));
            }
        }
    }

    if selection.features {
        let managed: HashSet<String> = managed_feature_names().iter().map(|n| ci(n)).collect();
        let now = first_by(
            current.windows_features.iter().flatten().filter(|s| {
                !blank(s.name.as_deref()) && managed.contains(&ci(s.name.as_deref().unwrap()))
            }),
            |s| s.name.clone().unwrap_or_default(),
        );
        for saved in backup.windows_features.iter().flatten() {
            let Some(name) = saved.name.as_deref() else {
                continue;
            };
            if blank(Some(name)) || !managed.contains(&ci(name)) {
                continue;
            }
            if !saved.exists {
                continue;
            }
            let value = now.get(&ci(name)).copied();
            let supported = value.map(|v| v.exists).unwrap_or(false);
            if !supported || value.unwrap().enabled != saved.enabled {
                differences.push(difference(
                    "Windows Features",
                    name,
                    feature_text(value),
                    feature_text(Some(saved)),
                    if supported {
                        "Restore"
                    } else {
                        "Skip: not present"
                    },
                    supported,
                ));
            }
        }
    }

    if selection.cpu_rules {
        if let Some(backup_rules) = backup.cpu_rules.as_ref() {
            let before = cpu_text(current.cpu_rules.as_ref());
            let after = cpu_text(Some(backup_rules));
            let topology_matches = cpu_topology_matches(backup);
            if !topology_matches {
                differences.push(difference(
                    "CPU Rules",
                    "Processor layout",
                    format!(
                        "{} / {} logical processors",
                        topology::cpu_name(),
                        topology::logical_processor_count()
                    ),
                    format!(
                        "{} / {} logical processors",
                        backup.cpu_name.as_deref().unwrap_or(""),
                        backup.logical_processors
                    ),
                    "Skip: processor layout differs",
                    false,
                ));
            }
            if cpu_fingerprint(current.cpu_rules.as_ref()) != cpu_fingerprint(Some(backup_rules)) {
                differences.push(difference(
                    "CPU Rules",
                    "Affinity rules and presets",
                    before,
                    after,
                    if topology_matches {
                        "Restore"
                    } else {
                        "Skip: processor layout differs"
                    },
                    topology_matches,
                ));
            }
        }
    }

    if selection.applications {
        let catalog_apps = xos_page_apps::catalog_apps();
        let catalog = first_by(catalog_apps.iter(), |app| app.id.to_string());
        let now = first_by(
            current
                .applications
                .iter()
                .flatten()
                .filter(|s| !blank(s.id.as_deref())),
            |s| s.id.clone().unwrap_or_default(),
        );
        for saved in backup.applications.iter().flatten() {
            let Some(id) = saved.id.as_deref() else {
                continue;
            };
            if blank(Some(id)) {
                continue;
            }
            let Some(app) = catalog.get(&ci(id)) else {
                continue;
            };
            let installed = now.get(&ci(id)).map(|v| v.installed).unwrap_or(false);
            if installed != saved.installed {
                differences.push(difference(
                    "Applications",
                    app.name,
                    if installed {
                        "Installed"
                    } else {
                        "Not installed"
                    }
                    .to_string(),
                    if saved.installed {
                        "Installed"
                    } else {
                        "Not installed"
                    }
                    .to_string(),
                    "Inventory only",
                    false,
                ));
            }
        }
    }

    differences
}

fn parse_int(text: Option<&str>) -> Option<i32> {
    text?.trim().parse::<i32>().ok()
}

fn disabled_registry_state_target(
    state: Option<&RegistrySettingState>,
    disabled_when_one: bool,
) -> Option<bool> {
    let state = state?;
    if !state.exists {
        return Some(true);
    }
    let value = parse_int(state.value.as_deref())?;
    let disabled = if disabled_when_one {
        value == 1
    } else {
        value == 0
    };
    Some(!disabled)
}

fn is_defender_target_registry_state(state: &RegistrySettingState) -> bool {
    let name = state.name.as_deref().unwrap_or("");
    let target_name = [
        "DisableAntiSpyware",
        "DisableAntiVirus",
        "PassiveMode",
        "DisableRealtimeMonitoring",
        "DisableBehaviorMonitoring",
        "DisableIOAVProtection",
        "DisableOnAccessProtection",
        "DisableScanOnRealtimeEnable",
        "AllowRealtimeMonitoring",
    ]
    .iter()
    .any(|n| ci_eq(name, n));
    if !target_name {
        return false;
    }
    let path = state.path.as_deref().unwrap_or("");
    ci_eq(path, r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender")
        || ci_eq(path, r"HKLM\SOFTWARE\Microsoft\Windows Defender")
        || icontains(path, r"\Windows Defender\Real-Time Protection")
        || ci_eq(
            path,
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager",
        )
}

pub fn get_defender_target(
    backup: &ToolkitConfigurationSnapshot,
    selection: &ConfigurationSelection,
) -> Option<bool> {
    let mut service_target: Option<bool> = None;
    if selection.services {
        let service = backup.services.iter().flatten().find(|s| {
            s.exists
                && s.name
                    .as_deref()
                    .map(|n| ci_eq(n, "WinDefend"))
                    .unwrap_or(false)
        });
        if let Some(service) = service {
            if service.start_type >= 0 && service.start_type <= 4 {
                service_target = Some(service.start_type != 4);
            }
        }
    }

    let mut registry_target: Option<bool> = None;
    if selection.registry {
        let policy = backup.registry.iter().flatten().find(|s| {
            s.path
                .as_deref()
                .map(|p| ci_eq(p, r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender"))
                .unwrap_or(false)
                && s.name
                    .as_deref()
                    .map(|n| ci_eq(n, "DisableAntiSpyware"))
                    .unwrap_or(false)
        });
        if let Some(policy) = policy {
            registry_target = disabled_registry_state_target(Some(policy), true);
        }

        for state in backup.registry.iter().flatten() {
            if !is_defender_target_registry_state(state) {
                continue;
            }
            let disabled_when_one = !state
                .name
                .as_deref()
                .map(|n| ci_eq(n, "AllowRealtimeMonitoring"))
                .unwrap_or(false);
            let Some(target) = disabled_registry_state_target(Some(state), disabled_when_one)
            else {
                continue;
            };
            if !target {
                registry_target = Some(false);
            } else if registry_target.is_none() {
                registry_target = Some(true);
            }
        }
    }

    if registry_target == Some(false) {
        return Some(false);
    }
    if service_target.is_some() {
        return service_target;
    }
    registry_target
}

pub fn defender_needs_full_operation(enabled: bool) -> bool {
    let win_defend = get_service_start_type("WinDefend");
    let wd_filter = get_service_start_type("WdFilter");
    let policy = reg_get_dword(
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender",
        "DisableAntiSpyware",
    );
    let realtime = reg_get_dword(
        r"HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection",
        "DisableRealtimeMonitoring",
    );
    let boot_task = get_task_state(r"\XOS-DefenderDisable");

    if enabled {
        win_defend == 4
            || wd_filter == 4
            || policy == Some(1)
            || realtime == Some(1)
            || boot_task >= 0
    } else {
        win_defend != 4
            || (wd_filter >= 0 && wd_filter != 4)
            || policy != Some(1)
            || realtime.is_none()
            || boot_task < 0
    }
}

pub fn is_defender_difference(difference: &ConfigurationDifference) -> bool {
    if !difference.applicable {
        return false;
    }
    if ci_eq(&difference.category, "Services") {
        return DEFENDER_SERVICE_NAMES
            .iter()
            .any(|n| ci_eq(n, &difference.item));
    }
    if ci_eq(&difference.category, "Scheduled Tasks") {
        return icontains(&difference.item, r"\Microsoft\Windows\Windows Defender\");
    }
    if ci_eq(&difference.category, "Registry") {
        return icontains(&difference.item, r"\Windows Defender")
            || icontains(&difference.item, "smartscreen.exe");
    }
    false
}

fn is_defender_core_registry(spec: &RegistrySpec) -> bool {
    if spec.path.trim().is_empty() {
        return false;
    }
    if icontains(&spec.path, "\\Windows Defender") {
        return true;
    }
    if icontains(&spec.path, "\\Windows Defender Security Center") {
        return true;
    }
    if iends(&spec.path, r"\Image File Execution Options\smartscreen.exe") {
        return true;
    }
    (iends(&spec.path, r"\CurrentVersion\Run") || iends(&spec.path, r"\StartupApproved\Run"))
        && ci_eq(&spec.name, "SecurityHealth")
}

fn is_defender_service(name: &str) -> bool {
    DEFENDER_SERVICE_NAMES.iter().any(|n| ci_eq(n, name))
}

fn set_task_enabled(path: &str, enabled: bool) -> bool {
    if enabled {
        enable_task(path)
    } else {
        disable_task(path)
    }
}

pub fn apply(
    backup: &ToolkitConfigurationSnapshot,
    selection: &ConfigurationSelection,
    skip_defender_core: bool,
) -> Result<ConfigurationApplyResult> {
    let mut result = ConfigurationApplyResult::default();
    let build = get_windows_build_number();
    let mut update_services_allowed = true;
    let restore_update_protection = selection.services
        && (backup.windows_update_service_guard.is_some()
            || backup.services.iter().flatten().any(|s| {
                s.exists && service_guard::is_target_service(s.name.as_deref().unwrap_or(""))
            }));
    if restore_update_protection && !service_guard::remove_owned() {
        update_services_allowed = false;
        result.failed += 1;
        session_log::operation_failed(
            "configuration restore",
            "Windows Update service protection cleanup",
        );
    }

    if selection.registry {
        let mut seen: HashSet<String> = HashSet::new();
        for state in backup.registry.iter() {
            let spec = get_managed_registry_spec(state.as_ref());
            let Some(spec) = spec else {
                result.skipped += 1;
                continue;
            };
            if !seen.insert(ci(&registry_id(&spec.path, &spec.name))) {
                result.skipped += 1;
                continue;
            }
            let state = state.as_ref().unwrap();
            if skip_defender_core && is_defender_core_registry(spec) {
                result.skipped += 1;
                continue;
            }
            if !is_registry_spec_supported(spec, build) {
                result.skipped += 1;
                continue;
            }

            let safe_state = RegistrySettingState {
                path: Some(spec.path.clone()),
                name: Some(spec.name.clone()),
                minimum_build: spec.minimum_build,
                exists: state.exists,
                kind: state.kind.clone(),
                value: state.value.clone(),
                read_succeeded: false,
            };
            let current = read_registry_state(spec);
            if !current.read_succeeded {
                result.failed += 1;
                session_log::operation_failed(
                    "configuration restore",
                    &format!(
                        "{} / {}",
                        spec.path,
                        display_registry_name(Some(&spec.name))
                    ),
                );
                continue;
            }
            if registry_states_equal(Some(&current), Some(&safe_state)) {
                continue;
            }
            if write_registry_state(spec, &safe_state) {
                result.applied += 1;
                result.reboot_required = true;
            } else {
                result.failed += 1;
                session_log::operation_failed(
                    "configuration restore",
                    &format!(
                        "{} / {}",
                        spec.path,
                        display_registry_name(Some(&spec.name))
                    ),
                );
            }
        }
    }

    if selection.services {
        let managed: HashSet<String> = managed_service_names().iter().map(|n| ci(n)).collect();
        let mut seen: HashSet<String> = HashSet::new();
        for state in backup.services.iter() {
            let Some(state) = state else {
                result.skipped += 1;
                continue;
            };
            let name = state.name.as_deref().unwrap_or("");
            if blank(state.name.as_deref())
                || !managed.contains(&ci(name))
                || !seen.insert(ci(name))
                || state.start_type < 0
                || state.start_type > 4
            {
                result.skipped += 1;
                continue;
            }
            if skip_defender_core && is_defender_service(name) {
                result.skipped += 1;
                continue;
            }
            if !state.exists {
                continue;
            }
            let update_service = service_guard::is_target_service(name);
            if update_service && !update_services_allowed {
                result.skipped += 1;
                continue;
            }
            if update_service {
                match service_guard::is_present(name) {
                    Ok(true) => {}
                    Ok(false) => {
                        result.skipped += 1;
                        continue;
                    }
                    Err(ex) => {
                        result.failed += 1;
                        session_log::operation_failed(
                            "service restore",
                            &format!("{name} native existence unreadable: {ex}"),
                        );
                        continue;
                    }
                }
            } else if !service_exists(name) {
                result.skipped += 1;
                continue;
            }
            let matches = if update_service {
                service_guard::startup_matches(name, state.start_type, false)
            } else {
                get_service_start_type(name) == state.start_type
            };
            if matches {
                continue;
            }
            let mut delayed_start = 0;
            if update_service && state.start_type == 2 {
                match service_guard::read_delayed_auto_start(name) {
                    Ok(v) => delayed_start = v,
                    Err(ex) => {
                        result.failed += 1;
                        session_log::operation_failed(
                            "service restore",
                            &format!("{name} delayed startup unreadable: {ex}"),
                        );
                        continue;
                    }
                }
            }
            let configured = if update_service {
                config_service_sc(
                    name,
                    match state.start_type {
                        4 => "disabled",
                        3 => "demand",
                        2 => {
                            if delayed_start == 1 {
                                "delayed-auto"
                            } else {
                                "auto"
                            }
                        }
                        1 => "system",
                        _ => "boot",
                    },
                )
            } else {
                config_service_reg(name, state.start_type)
            };
            if configured
                && get_service_start_type(name) == state.start_type
                && (!update_service || service_guard::startup_matches(name, state.start_type, true))
            {
                result.applied += 1;
                result.reboot_required = true;
            } else {
                result.failed += 1;
                session_log::operation_failed("service restore", name);
            }
        }
    }

    if restore_update_protection
        && update_services_allowed
        && backup.windows_update_service_guard == Some(true)
    {
        if service_guard::apply() {
            result.applied += 1;
            result.reboot_required = true;
        } else {
            result.failed += 1;
            session_log::operation_failed(
                "configuration restore",
                "Windows Update service protection",
            );
        }
    }

    if selection.tasks {
        let managed: HashSet<String> = managed_task_paths().iter().map(|n| ci(n)).collect();
        let safe_tasks: Vec<&TaskSettingState> = first_by(
            backup.scheduled_tasks.iter().flatten().filter(|s| {
                !blank(s.path.as_deref()) && managed.contains(&ci(s.path.as_deref().unwrap()))
            }),
            |s| s.path.clone().unwrap_or_default(),
        )
        .into_values()
        .collect();
        let safe_tasks = order_like(&backup.scheduled_tasks, safe_tasks);
        result.skipped += (backup.scheduled_tasks.len() - safe_tasks.len()) as i32;
        let paths: Vec<String> = safe_tasks
            .iter()
            .map(|t| t.path.clone().unwrap_or_default())
            .collect();
        let current = get_task_states_batch(&paths);
        for state in safe_tasks {
            let path = state.path.as_deref().unwrap_or("");
            if skip_defender_core && istarts(path, r"\Microsoft\Windows\Windows Defender\") {
                result.skipped += 1;
                continue;
            }
            if !state.exists {
                continue;
            }
            let task_state = match current.get(path) {
                Some(v) if *v >= 0 => *v,
                _ => {
                    result.skipped += 1;
                    continue;
                }
            };
            if (task_state == 1) == state.enabled {
                continue;
            }
            let ok = set_task_enabled(path, state.enabled);
            let verified = if ok {
                get_task_state_verified(path, state.enabled, 3000)
            } else {
                -1
            };
            if ok && verified >= 0 && ((verified == 1) == state.enabled) {
                result.applied += 1;
                session_log::operation_succeeded("scheduled task state", path);
            } else {
                if is_tolerant_task_path(path) {
                    result.skipped += 1;
                    log::log(&format!("[Config] {path} refuses the state change on this build; left as Windows has it. Not counted as a failure."));
                    continue;
                }
                result.failed += 1;
                session_log::operation_failed("task restore", path);
            }
        }
    }

    if selection.features {
        let managed: HashSet<String> = managed_feature_names().iter().map(|n| ci(n)).collect();
        let safe: Vec<&FeatureSettingState> = first_by(
            backup.windows_features.iter().flatten().filter(|s| {
                !blank(s.name.as_deref()) && managed.contains(&ci(s.name.as_deref().unwrap()))
            }),
            |s| s.name.clone().unwrap_or_default(),
        )
        .into_values()
        .collect();
        let mut safe_features = order_like(&backup.windows_features, safe);
        result.skipped += (backup.windows_features.len() - safe_features.len()) as i32;
        let current = get_all_feature_states();
        if safe_features.iter().any(|s| s.exists) && current.is_empty() {
            result.failed += safe_features.iter().filter(|s| s.exists).count() as i32;
            safe_features.clear();
        }
        let mut changed_features: Vec<&FeatureSettingState> = Vec::new();
        for state in safe_features {
            if !state.exists {
                continue;
            }
            let name = state.name.as_deref().unwrap_or("");
            let Some(current_state) = current.get(name) else {
                result.skipped += 1;
                continue;
            };
            let enabled = is_feature_state_enabled(current_state);
            if enabled == state.enabled {
                continue;
            }
            let ok = if state.enabled {
                enable_feature(name)
            } else {
                disable_feature(name)
            };
            if ok {
                changed_features.push(state);
                result.reboot_required = true;
            } else if state.enabled && is_feature_absent_on_this_build(name) {
                result.skipped += 1;
                session_log::operation_succeeded(
                    &format!("command exit {FEATURE_NOT_AVAILABLE_TEXT}"),
                    "dism.exe",
                );
                log::log(&format!(
                    "[Config] {name} is not available on this Windows build; skipped."
                ));
            } else {
                result.failed += 1;
            }
        }
        if !changed_features.is_empty() {
            let verified = get_all_feature_states();
            for state in changed_features {
                let matches = verified
                    .get(state.name.as_deref().unwrap_or(""))
                    .map(|s| is_feature_state_enabled(s) == state.enabled)
                    .unwrap_or(false);
                if matches {
                    result.applied += 1;
                } else {
                    result.failed += 1;
                }
            }
        }
    }

    if selection.cpu_rules {
        if let Some(backup_rules) = backup.cpu_rules.as_ref() {
            if !cpu_topology_matches(backup) {
                result.skipped += 1;
            } else if cpu_fingerprint(Some(&rules::load())) != cpu_fingerprint(Some(backup_rules)) {
                let attempt =
                    (|| -> Result<bool> {
                        rules::normalize(backup_rules)?;
                        rules::save(backup_rules)?;
                        Ok(cpu_fingerprint(Some(&rules::load()))
                            == cpu_fingerprint(Some(backup_rules)))
                    })();
                match attempt {
                    Ok(true) => result.applied += 1,
                    _ => result.failed += 1,
                }
            }
        }
    }

    if selection.applications {
        let catalog_ids: HashSet<String> = xos_page_apps::catalog_apps()
            .iter()
            .map(|a| ci(a.id))
            .collect();
        let installed = installed_packages()?;
        let mut seen: HashSet<String> = HashSet::new();
        for app in backup.applications.iter() {
            let id = app.as_ref().and_then(|a| a.id.as_deref());
            let valid = match (app, id) {
                (Some(_), Some(id)) => {
                    !blank(Some(id)) && catalog_ids.contains(&ci(id)) && seen.insert(ci(id))
                }
                _ => false,
            };
            if !valid {
                result.skipped += 1;
                continue;
            }
            if installed.contains_key(id.unwrap()) != app.as_ref().unwrap().installed {
                result.skipped += 1;
            }
        }
    }

    Ok(result)
}

fn order_like<'a, T>(original: &'a [Option<T>], picked: Vec<&'a T>) -> Vec<&'a T> {
    let keep: HashSet<*const T> = picked.iter().map(|p| *p as *const T).collect();
    let mut out = Vec::with_capacity(picked.len());
    for item in original.iter().flatten() {
        if keep.contains(&(item as *const T)) {
            out.push(item);
        }
    }
    out
}

fn open_registry_key(
    path: &str,
    writable: bool,
    create_if_missing: bool,
) -> Result<Option<RegKey>> {
    if path.trim().is_empty() || path.len() <= 5 {
        return Ok(None);
    }
    let Some(prefix) = path.get(..5) else {
        return Ok(None);
    };
    let root = if ci_eq(prefix, "HKLM\\") {
        HKEY_LOCAL_MACHINE
    } else if ci_eq(prefix, "HKCU\\") {
        HKEY_CURRENT_USER
    } else if ci_eq(prefix, "HKCR\\") {
        HKEY_CLASSES_ROOT
    } else {
        return Ok(None);
    };
    let sub_key = &path[5..];
    let root = RegKey::predef(root);
    if !writable {
        return open_existing(&root, sub_key, KEY_READ);
    }
    if create_if_missing {
        let (key, _) =
            root.create_subkey_with_flags(sub_key, KEY_READ | KEY_SET_VALUE | KEY_CREATE_SUB_KEY)?;
        return Ok(Some(key));
    }
    open_existing(&root, sub_key, KEY_READ | KEY_SET_VALUE)
}

fn open_existing(root: &RegKey, sub_key: &str, flags: u32) -> Result<Option<RegKey>> {
    match root.open_subkey_with_flags(sub_key, flags) {
        Ok(key) => Ok(Some(key)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn utf16_text(bytes: &[u8]) -> Vec<u16> {
    bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect()
}

fn encode_registry_value(raw: &RegValue) -> (String, Option<String>) {
    let bytes: &[u8] = &raw.bytes;
    match raw.vtype {
        RegType::REG_SZ | RegType::REG_EXPAND_SZ => {
            let units = utf16_text(bytes);
            let end = units.iter().position(|u| *u == 0).unwrap_or(units.len());
            let kind = if raw.vtype == RegType::REG_SZ {
                "String"
            } else {
                "ExpandString"
            };
            (
                kind.to_string(),
                Some(String::from_utf16_lossy(&units[..end])),
            )
        }
        RegType::REG_BINARY => (
            "Binary".to_string(),
            Some(base64::engine::general_purpose::STANDARD.encode(bytes)),
        ),
        RegType::REG_DWORD => {
            let mut b = [0u8; 4];
            for (i, v) in bytes.iter().take(4).enumerate() {
                b[i] = *v;
            }
            ("DWord".to_string(), Some(i32::from_le_bytes(b).to_string()))
        }
        RegType::REG_QWORD => {
            let mut b = [0u8; 8];
            for (i, v) in bytes.iter().take(8).enumerate() {
                b[i] = *v;
            }
            ("QWord".to_string(), Some(i64::from_le_bytes(b).to_string()))
        }
        RegType::REG_MULTI_SZ => {
            let units = utf16_text(bytes);
            let mut parts: Vec<String> = units
                .split(|u| *u == 0)
                .map(String::from_utf16_lossy)
                .collect();
            while parts.last().map(|p| p.is_empty()).unwrap_or(false) {
                parts.pop();
            }
            ("MultiString".to_string(), Some(parts.join("\u{1f}")))
        }
        RegType::REG_NONE => ("None".to_string(), Some("System.Byte[]".to_string())),
        _ => ("Unknown".to_string(), Some("System.Byte[]".to_string())),
    }
}

fn read_registry_value(spec: &RegistrySpec) -> Result<Option<(String, Option<String>)>> {
    let Some(key) = open_registry_key(&spec.path, false, false)? else {
        return Ok(None);
    };
    let mut found = false;
    for entry in key.enum_values() {
        let (name, _) = entry?;
        if ci_eq(&name, &spec.name) {
            found = true;
            break;
        }
    }
    if !found {
        return Ok(None);
    }
    let raw = key.get_raw_value(&spec.name)?;
    Ok(Some(encode_registry_value(&raw)))
}

fn read_registry_state(spec: &RegistrySpec) -> RegistrySettingState {
    let mut state = RegistrySettingState {
        path: Some(spec.path.clone()),
        name: Some(spec.name.clone()),
        minimum_build: spec.minimum_build,
        ..Default::default()
    };
    match read_registry_value(spec) {
        Ok(None) => state.read_succeeded = true,
        Ok(Some((kind, value))) => {
            state.exists = true;
            state.kind = Some(kind);
            state.value = value;
            state.read_succeeded = true;
        }
        Err(ex) => log::exception(
            &format!(
                "Managed registry value could not be read: {} / {}",
                spec.path,
                display_registry_name(Some(&spec.name))
            ),
            &format!("{ex}"),
        ),
    }
    state
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ValueKind {
    Unknown,
    String,
    ExpandString,
    Binary,
    DWord,
    MultiString,
    QWord,
    None,
}

fn parse_value_kind(text: Option<&str>) -> Result<ValueKind> {
    let text = text.ok_or_else(|| anyhow!("Value cannot be null."))?.trim();
    Ok(match text {
        "Unknown" | "0" => ValueKind::Unknown,
        "String" | "1" => ValueKind::String,
        "ExpandString" | "2" => ValueKind::ExpandString,
        "Binary" | "3" => ValueKind::Binary,
        "DWord" | "4" => ValueKind::DWord,
        "MultiString" | "7" => ValueKind::MultiString,
        "QWord" | "11" => ValueKind::QWord,
        "None" | "-1" => ValueKind::None,
        _ => bail!("Requested value '{text}' was not found."),
    })
}

fn wide_bytes(text: &str) -> Vec<u8> {
    text.encode_utf16()
        .chain(Some(0))
        .flat_map(|u| u.to_le_bytes())
        .collect()
}

fn decode_registry_value(value: Option<&str>, kind: ValueKind) -> Result<RegValue<'static>> {
    let owned = |bytes: Vec<u8>, vtype: RegType| RegValue {
        bytes: Cow::Owned(bytes),
        vtype,
    };
    Ok(match kind {
        ValueKind::DWord => {
            let v: i32 = value
                .ok_or_else(|| anyhow!("Value cannot be null."))?
                .trim()
                .parse()?;
            owned(v.to_le_bytes().to_vec(), RegType::REG_DWORD)
        }
        ValueKind::QWord => {
            let v: i64 = value
                .ok_or_else(|| anyhow!("Value cannot be null."))?
                .trim()
                .parse()?;
            owned(v.to_le_bytes().to_vec(), RegType::REG_QWORD)
        }
        ValueKind::Binary => owned(
            base64::engine::general_purpose::STANDARD.decode(value.unwrap_or(""))?,
            RegType::REG_BINARY,
        ),
        ValueKind::MultiString => {
            let mut bytes = Vec::new();
            for part in value.unwrap_or("").split('\u{1f}') {
                bytes.extend(wide_bytes(part));
            }
            bytes.extend([0, 0]);
            owned(bytes, RegType::REG_MULTI_SZ)
        }
        ValueKind::ExpandString => owned(wide_bytes(value.unwrap_or("")), RegType::REG_EXPAND_SZ),
        ValueKind::String => owned(wide_bytes(value.unwrap_or("")), RegType::REG_SZ),
        ValueKind::Unknown | ValueKind::None => {
            bail!("The specified RegistryValueKind is an invalid value.")
        }
    })
}

fn is_trusted_machine_registry_path(state: &RegistrySettingState) -> bool {
    match state.path.as_deref() {
        Some(p) if !p.trim().is_empty() => {
            istarts(p, r"HKLM\SOFTWARE\Microsoft\Windows Defender")
                || istarts(p, r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender")
        }
        _ => false,
    }
}

fn service_name_from_svc_host_split_key(state: &RegistrySettingState) -> Option<String> {
    let prefix = r"HKLM\SYSTEM\CurrentControlSet\Services\";
    let path = state.path.as_deref()?;
    if path.is_empty() || state.name.as_deref() != Some("SvcHostSplitDisable") {
        return None;
    }
    if !istarts(path, prefix) {
        return None;
    }
    let remainder = path.get(prefix.len()..)?;
    if remainder.is_empty() || remainder.contains('\\') {
        return None;
    }
    Some(remainder.to_string())
}

fn decode_dword_value(state: &RegistrySettingState) -> i32 {
    match decode_registry_value(state.value.as_deref(), ValueKind::DWord) {
        Ok(v) if v.bytes.len() == 4 => {
            i32::from_le_bytes([v.bytes[0], v.bytes[1], v.bytes[2], v.bytes[3]])
        }
        _ => 0,
    }
}

fn b64_utf16(text: &str) -> String {
    let bytes: Vec<u8> = text.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn write_registry_state(spec: &RegistrySpec, state: &RegistrySettingState) -> bool {
    let attempt = (|| -> Result<bool> {
        let path = state.path.as_deref().unwrap_or("");
        let key = open_registry_key(path, true, state.exists)?;
        if !state.exists {
            if let Some(key) = key {
                match key.delete_value(state.name.as_deref().unwrap_or("")) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.into()),
                }
            } else {
                return Ok(true);
            }
        } else {
            let key =
                key.ok_or_else(|| anyhow!("The registry key could not be opened for writing."))?;
            let kind = parse_value_kind(state.kind.as_deref())?;
            if kind == ValueKind::Unknown {
                return Ok(false);
            }
            let value = decode_registry_value(state.value.as_deref(), kind)?;
            key.set_raw_value(state.name.as_deref().unwrap_or(""), &value)?;
        }
        let verified = read_registry_state(spec);
        Ok(verified.read_succeeded && registry_states_equal(Some(&verified), Some(state)))
    })();
    match attempt {
        Ok(v) => v,
        Err(ex) => {
            if is_trusted_machine_registry_path(state)
                && write_registry_state_as_trusted_installer(state)
            {
                log::log(&format!(
                    "Managed registry value restored with TrustedInstaller: {} / {}",
                    state.path.as_deref().unwrap_or(""),
                    display_registry_name(state.name.as_deref())
                ));
                return true;
            }

            if let Some(service_name) = service_name_from_svc_host_split_key(state) {
                let grouped = state.exists && decode_dword_value(state) == 1;
                let elevated = set_service_grouping_values(&[service_name], grouped);
                if elevated {
                    log::log(&format!(
                        "Managed registry value restored with TrustedInstaller: {} / {}",
                        state.path.as_deref().unwrap_or(""),
                        display_registry_name(state.name.as_deref())
                    ));
                    return true;
                }
            }
            log::exception(
                &format!(
                    "Managed registry value could not be restored: {} / {}",
                    state.path.as_deref().unwrap_or(""),
                    display_registry_name(state.name.as_deref())
                ),
                &format!("{ex}"),
            );
            false
        }
    }
}

fn write_registry_state_as_trusted_installer(state: &RegistrySettingState) -> bool {
    let sub_key = state.path.as_deref().unwrap_or("").get(5..).unwrap_or("");
    let path64 = b64_utf16(sub_key);
    let name64 = b64_utf16(state.name.as_deref().unwrap_or(""));
    let kind_text = state.kind.as_deref().unwrap_or("String");
    let kind64 = b64_utf16(kind_text);
    let value64 = b64_utf16(state.value.as_deref().unwrap_or(""));
    let mut script = String::new();
    script.push_str("$ErrorActionPreference='Stop';");
    script.push_str(&format!(
        "$path=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{path64}'));"
    ));
    script.push_str(&format!(
        "$name=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{name64}'));"
    ));
    if state.exists {
        script.push_str(&format!("$kindText=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{kind64}'));"));
        script.push_str(&format!("$valueText=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{value64}'));"));
        script.push_str("$key=[Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($path,$true);");
        script.push_str("if($null -eq $key){throw 'The registry key could not be opened by TrustedInstaller.'};");
        script.push_str("$kind=[Enum]::Parse([Microsoft.Win32.RegistryValueKind],$kindText);");
        script.push_str("$value=$valueText;");
        script.push_str("switch($kindText){");
        script.push_str("'DWord'{$value=[int]::Parse($valueText,[Globalization.CultureInfo]::InvariantCulture)}");
        script.push_str("'QWord'{$value=[long]::Parse($valueText,[Globalization.CultureInfo]::InvariantCulture)}");
        script.push_str("'Binary'{$value=[Convert]::FromBase64String($valueText)}");
        script.push_str("'MultiString'{$value=if($valueText.Length -eq 0){[string[]]@()}else{$valueText -split [char]31}}");
        script.push_str("};");
        script.push_str("$key.SetValue($name,$value,$kind);$key.Close();");
        script
            .push_str("$verify=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($path,$false);");
        script.push_str("if($null -eq $verify -or -not ($verify.GetValueNames() -contains $name)){throw 'TrustedInstaller registry write verification failed.'};");
        script.push_str("$actualKind=$verify.GetValueKind($name).ToString();");
        script.push_str("if($actualKind -ne $kindText){$verify.Close();throw 'TrustedInstaller registry type verification failed.'};");
        script.push_str("$actual=$verify.GetValue($name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames);");
        script.push_str("$actualText=switch($kindText){");
        script.push_str("'Binary'{[Convert]::ToBase64String([byte[]]$actual)}");
        script.push_str("'MultiString'{[string]::Join([char]31,[string[]]$actual)}");
        script.push_str(
            "default{[Convert]::ToString($actual,[Globalization.CultureInfo]::InvariantCulture)}}",
        );
        script.push_str("if($actualText -ne $valueText){$verify.Close();throw 'TrustedInstaller registry value verification failed.'};");
        script.push_str("$verify.Close()");
    } else {
        script.push_str("$key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($path,$true);");
        script.push_str("if($key){$key.DeleteValue($name,$false);$key.Close()};");
        script
            .push_str("$verify=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($path,$false);");
        script.push_str("if($verify){if($verify.GetValueNames() -contains $name){$verify.Close();throw 'TrustedInstaller registry delete verification failed.'};$verify.Close()}");
    }
    let encoded = b64_utf16(&script);
    if !run_as_ti(
        "powershell.exe",
        &format!("-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}"),
    ) {
        return false;
    }
    log::log(&format!(
        "TrustedInstaller registry write verified in the protected context: {} / {}",
        state.path.as_deref().unwrap_or(""),
        display_registry_name(state.name.as_deref())
    ));
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    const CSHARP_SHAPE: &str = concat!(
        r#"{"format":"xos-toolkit-configuration","schemaVersion":1,"toolkitVersion":"0.2.202.0","#,
        r#""windowsBuild":26100,"exportedUtc":"2026-11-12T10:20:30.1234567Z","#,
        r#""cpuName":"AMD Ryzen 7 5800X3D 8-Core Processor \/ x","logicalProcessors":16,"#,
        r#""registry":[{"exists":true,"kind":"DWord","minimumBuild":0,"name":"EnableLUA","#,
        r#""path":"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System","value":"1"},"#,
        r#"{"exists":false,"kind":null,"minimumBuild":19041,"name":"UseUpdateClassPolicySource","#,
        r#""path":"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU","value":null}],"#,
        r#""services":[{"exists":true,"name":"WinDefend","startType":2},{"exists":false,"name":"vid","startType":-1}],"#,
        r#""scheduledTasks":[{"enabled":true,"exists":true,"path":"\\Microsoft\\Windows\\WaaSMedic\\PerformRemediation"}],"#,
        r#""windowsFeatures":[{"enabled":false,"exists":true,"name":"Printing-XPSServices-Features"}],"#,
        r#""cpuRules":{"rules":[{"cores":[true,false],"maskType":"CPUSet","processName":"game\/x.exe"}],"#,
        r#""userPresets":[{"cores":[false,true],"name":"Mine"}]},"#,
        r#""applications":[{"id":"7zip","installed":true,"name":"7-Zip"}],"#,
        r#""warnings":["Registry value not captured: HKLM\\X \/ Y"],"windowsUpdateServiceGuard":true}"#
    );

    #[test]
    fn csharp_shape_round_trips_byte_for_byte() {
        let snapshot = from_json(CSHARP_SHAPE).unwrap();
        assert_eq!(snapshot.windows_build, 26100);
        assert_eq!(snapshot.registry.len(), 2);
        assert_eq!(snapshot.services.len(), 2);
        assert_eq!(snapshot.windows_update_service_guard, Some(true));
        assert_eq!(snapshot.cpu_rules.as_ref().unwrap().rules.len(), 1);
        assert_eq!(to_json(&snapshot).unwrap(), CSHARP_SHAPE);
    }

    #[test]
    fn guard_flag_is_omitted_when_null_and_cpu_rules_null_is_emitted() {
        let mut snapshot = ToolkitConfigurationSnapshot::new();
        snapshot.windows_build = 1;
        let json = to_json(&snapshot).unwrap();
        assert!(!json.contains("windowsUpdateServiceGuard"));
        assert!(json.contains(r#""cpuRules":null"#));
        assert!(json.starts_with(
            r#"{"format":"xos-toolkit-configuration","schemaVersion":1,"toolkitVersion":null,"windowsBuild":1,"exportedUtc":null,"cpuName":null,"logicalProcessors":0,"registry":[],"#
        ));
    }

    #[test]
    fn load_validation() {
        assert!(from_json(r#"{"format":"x","schemaVersion":1}"#)
            .unwrap_err()
            .to_string()
            .contains("not an XOS Toolkit configuration file"));
        assert!(from_json("null").is_err());
        assert!(
            from_json(&CSHARP_SHAPE.replace(r#""schemaVersion":1"#, r#""schemaVersion":2"#))
                .unwrap_err()
                .to_string()
                .contains("newer Toolkit")
        );
        assert!(
            from_json(&CSHARP_SHAPE.replace(r#""schemaVersion":1"#, r#""schemaVersion":0"#))
                .unwrap_err()
                .to_string()
                .contains("unsupported schema")
        );
        assert!(from_json(
            &CSHARP_SHAPE.replace(r#""logicalProcessors":16"#, r#""logicalProcessors":5000"#)
        )
        .is_err());
        assert!(from_json(&CSHARP_SHAPE.replace("CPUSet", "cpuset")).is_err());
        let loose = from_json(
            r#"{"format":"xos-toolkit-configuration","schemaVersion":1,"registry":null,"services":[null],"cpuRules":{"rules":[{"maskType":"Affinity","cores":[true,true,true]}]},"extra":5}"#,
        )
        .unwrap();
        assert!(loose.registry.is_empty());
        assert_eq!(loose.services.len(), 1);
        assert_eq!(loose.logical_processors, 3);
    }

    #[test]
    fn save_and_load_round_trip_in_temp() {
        let dir = std::env::temp_dir().join(format!("xos-config-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("nested").join("backup.json");
        let snapshot = from_json(CSHARP_SHAPE).unwrap();
        save(&path, &snapshot).unwrap();
        save(&path, &snapshot).unwrap();
        assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);
        assert_eq!(fs::read_to_string(&path).unwrap(), CSHARP_SHAPE);
        assert_eq!(load(&path).unwrap(), snapshot);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn registry_spec_table_is_complete() {
        let s = specs();
        assert!(s.list.len() > 300, "{}", s.list.len());
        assert_eq!(s.list.len(), s.by_id.len());
        let svc = s
            .list
            .iter()
            .filter(|x| x.name == "SvcHostSplitDisable")
            .count();
        assert_eq!(svc, 39);
        assert!(s
            .list
            .iter()
            .any(|x| x.name == "Install{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}"));
        let uc = s
            .list
            .iter()
            .find(|x| x.name == "SetPolicyDrivenUpdateSourceForDriverUpdates")
            .unwrap();
        assert_eq!(uc.minimum_build, 19041);
        let st = RegistrySettingState {
            path: Some(r"hklm\software\microsoft\windows\currentversion\policies\system".into()),
            name: Some("enablelua".into()),
            ..Default::default()
        };
        assert!(get_managed_registry_spec(Some(&st)).is_some());
    }

    fn reg(
        path: &str,
        name: &str,
        exists: bool,
        value: Option<&str>,
    ) -> Option<RegistrySettingState> {
        Some(RegistrySettingState {
            path: Some(path.into()),
            name: Some(name.into()),
            exists,
            kind: exists.then(|| "DWord".to_string()),
            value: value.map(|v| v.to_string()),
            ..Default::default()
        })
    }

    #[test]
    fn defender_target_rules() {
        let all = ConfigurationSelection {
            registry: true,
            services: true,
            ..Default::default()
        };
        let mut backup = ToolkitConfigurationSnapshot::new();
        assert_eq!(get_defender_target(&backup, &all), None);
        backup.services.push(Some(ServiceSettingState {
            exists: true,
            name: Some("windefend".into()),
            start_type: 4,
        }));
        assert_eq!(get_defender_target(&backup, &all), Some(false));
        backup.services[0].as_mut().unwrap().start_type = 2;
        assert_eq!(get_defender_target(&backup, &all), Some(true));
        backup.registry.push(reg(
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender",
            "DisableAntiSpyware",
            true,
            Some("1"),
        ));
        assert_eq!(get_defender_target(&backup, &all), Some(false));
        assert_eq!(
            get_defender_target(
                &backup,
                &ConfigurationSelection {
                    services: true,
                    ..Default::default()
                }
            ),
            Some(true)
        );
        let mut rt = ToolkitConfigurationSnapshot::new();
        rt.registry.push(reg(
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager",
            "AllowRealtimeMonitoring",
            true,
            Some("1"),
        ));
        assert_eq!(get_defender_target(&rt, &all), Some(true));
        rt.registry[0].as_mut().unwrap().value = Some("0".into());
        assert_eq!(get_defender_target(&rt, &all), Some(false));
    }

    #[test]
    fn defender_difference_rules() {
        let d = |cat: &str, item: &str, applicable: bool| ConfigurationDifference {
            category: cat.into(),
            item: item.into(),
            applicable,
            ..Default::default()
        };
        assert!(is_defender_difference(&d("Services", "WinDefend", true)));
        assert!(!is_defender_difference(&d("Services", "WinDefend", false)));
        assert!(!is_defender_difference(&d("Services", "wuauserv", true)));
        assert!(is_defender_difference(&d(
            "Scheduled Tasks",
            r"\Microsoft\Windows\Windows Defender\Windows Defender Cleanup",
            true
        )));
        assert!(is_defender_difference(&d(
            "Registry",
            r"HKLM\SOFTWARE\Microsoft\Windows Defender / PassiveMode",
            true
        )));
        assert!(is_defender_difference(&d(
            "Registry",
            r"HKLM\X\Image File Execution Options\smartscreen.exe / Debugger",
            true
        )));
        assert!(!is_defender_difference(&d("Windows Features", "x", true)));
    }

    #[test]
    fn registry_value_encoding() {
        let raw = |bytes: Vec<u8>, vtype| RegValue {
            bytes: Cow::Owned(bytes),
            vtype,
        };
        assert_eq!(
            encode_registry_value(&raw(
                0xFFFFFFFFu32.to_le_bytes().to_vec(),
                RegType::REG_DWORD
            )),
            ("DWord".into(), Some("-1".into()))
        );
        assert_eq!(
            encode_registry_value(&raw(wide_bytes("a;b"), RegType::REG_SZ)),
            ("String".into(), Some("a;b".into()))
        );
        let mut multi = wide_bytes("a");
        multi.extend(wide_bytes("b"));
        multi.extend([0, 0]);
        assert_eq!(
            encode_registry_value(&raw(multi, RegType::REG_MULTI_SZ)),
            ("MultiString".into(), Some("a\u{1f}b".into()))
        );
        let written = decode_registry_value(Some("a\u{1f}b"), ValueKind::MultiString).unwrap();
        assert_eq!(
            encode_registry_value(&written),
            ("MultiString".into(), Some("a\u{1f}b".into()))
        );
        let dword = decode_registry_value(Some("-1"), ValueKind::DWord).unwrap();
        assert_eq!(&dword.bytes[..], &[0xFF, 0xFF, 0xFF, 0xFF]);
        assert!(decode_registry_value(None, ValueKind::DWord).is_err());
        assert!(parse_value_kind(Some("Bogus")).is_err());
        assert!(parse_value_kind(None).is_err());
    }

    #[test]
    fn registry_states_equality_and_text() {
        let a = reg("p", "n", true, Some("1")).unwrap();
        let mut b = a.clone();
        b.kind = Some("dword".into());
        assert!(registry_states_equal(Some(&a), Some(&b)));
        b.value = Some("2".into());
        assert!(!registry_states_equal(Some(&a), Some(&b)));
        assert!(registry_states_equal(None, None));
        assert!(!registry_states_equal(Some(&a), None));
        assert_eq!(registry_text(Some(&a)), "1 (DWord)");
        assert_eq!(registry_text(None), "Default / absent");
        assert_eq!(display_registry_name(Some("")), "(Default)");
    }

    #[test]
    fn managed_lists_are_distinct_and_include_additions() {
        let services = managed_service_names();
        let tasks = managed_task_paths();
        assert!(services.iter().any(|s| s == "AMD Crash Defender Service"));
        assert!(tasks
            .iter()
            .any(|t| t == r"\Microsoft\Windows\WaaSMedic\PerformRemediation"));
        let set: HashSet<String> = services.iter().map(|s| ci(s)).collect();
        assert_eq!(set.len(), services.len());
        assert_eq!(cpu_fingerprint(None), "");
    }
}

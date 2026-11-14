use std::sync::Mutex;

use anyhow::{anyhow, Result};
use windows::core::{BSTR, PCWSTR};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoSetProxyBlanket, CLSCTX_INPROC_SERVER,
    COINIT_MULTITHREADED, EOAC_NONE, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
};
use windows::Win32::System::Rpc::{RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE};
use windows::Win32::System::Variant::VARIANT;
use windows::Win32::System::Wmi::{
    IWbemLocator, IWbemServices, WbemLocator, WBEM_FLAG_FORWARD_ONLY, WBEM_FLAG_RETURN_IMMEDIATELY,
    WBEM_INFINITE,
};
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
use winreg::RegKey;
use xos_core::host::{Host, Page};
use xos_core::ui::*;
use xos_core::{detect, log};

const GITHUB_URL: &str = "https://github.com/imribiy/XOS";
const SLINT_URL: &str = "https://slint.dev";

#[derive(Clone, Debug, PartialEq)]
pub struct SystemOverview {
    pub cpu_name: String,
    pub cpu_detail: String,
    pub gpu_name: String,
    pub gpu_detail: String,
    pub memory: String,
    pub memory_detail: String,
    pub windows_name: String,
    pub windows_detail: String,
}

impl Default for SystemOverview {
    fn default() -> Self {
        Self {
            cpu_name: "Not detected".into(),
            cpu_detail: String::new(),
            gpu_name: "Not detected".into(),
            gpu_detail: String::new(),
            memory: "Not detected".into(),
            memory_detail: String::new(),
            windows_name: "Windows".into(),
            windows_detail: String::new(),
        }
    }
}

struct State {
    loaded: bool,
    overview: Option<SystemOverview>,
}

pub struct AboutPage {
    st: Mutex<State>,
}

impl Default for AboutPage {
    fn default() -> Self {
        Self::new()
    }
}

pub fn clean_name(value: Option<&str>) -> String {
    let value = match value {
        Some(v) if !v.trim().is_empty() => v,
        _ => return "Not detected".to_string(),
    };
    let value = value
        .replace("(R)", "")
        .replace("(TM)", "")
        .replace('\u{00AE}', "")
        .replace('\u{2122}', "");
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn to_int(value: &Option<String>) -> i32 {
    value
        .as_deref()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .and_then(|v| i32::try_from(v).ok())
        .unwrap_or(0)
}

fn to_long(value: &Option<String>) -> i64 {
    value
        .as_deref()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .unwrap_or(0)
}

fn to_ulong(value: &Option<String>) -> u64 {
    value
        .as_deref()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0)
}

fn one_decimal(value: f64) -> String {
    let text = format!("{:.1}", value);
    match text.strip_suffix(".0") {
        Some(t) => t.to_string(),
        None => text,
    }
}

fn windows_family(build: i32) -> &'static str {
    if build >= 22000 {
        "Windows 11"
    } else {
        "Windows 10"
    }
}

pub fn memory_texts(total_memory: u64, free_memory_kb: u64) -> (String, String) {
    let total_gb = total_memory as f64 / 1073741824f64;
    let free_gb = free_memory_kb as f64 / 1048576f64;
    let memory = if total_memory > 0 {
        format!("{:.0} GB", total_gb.round_ties_even())
    } else {
        "Not detected".to_string()
    };
    let detail = if free_memory_kb > 0 {
        format!("{} GB currently available", one_decimal(free_gb))
    } else {
        "Installed physical memory".to_string()
    };
    (memory, detail)
}

pub fn windows_texts(
    caption: &str,
    build: &str,
    ubr: i32,
    display_version: Option<&str>,
    os_build: i32,
) -> (String, String) {
    let name = if caption.trim().is_empty() || caption == "Not detected" {
        windows_family(os_build).to_string()
    } else {
        caption.to_string()
    };
    let full_build = if ubr > 0 {
        format!("{build}.{ubr}")
    } else {
        build.to_string()
    };
    let detail = match display_version {
        Some(v) if !v.trim().is_empty() => format!("{v} / Build {full_build}"),
        _ => format!("Build {full_build}"),
    };
    (name, detail)
}

struct Wmi {
    services: IWbemServices,
}

impl Wmi {
    fn connect() -> Result<Self> {
        unsafe {
            let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
            let locator: IWbemLocator = CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER)?;
            let services = locator.ConnectServer(
                &BSTR::from("ROOT\\CIMV2"),
                &BSTR::new(),
                &BSTR::new(),
                &BSTR::new(),
                0,
                &BSTR::new(),
                None,
            )?;
            CoSetProxyBlanket(
                &services,
                RPC_C_AUTHN_WINNT,
                RPC_C_AUTHZ_NONE,
                PCWSTR::null(),
                RPC_C_AUTHN_LEVEL_CALL,
                RPC_C_IMP_LEVEL_IMPERSONATE,
                None,
                EOAC_NONE,
            )?;
            Ok(Self { services })
        }
    }

    fn query(&self, wql: &str, props: &[&str]) -> Result<Vec<Vec<Option<String>>>> {
        let mut rows = Vec::new();
        unsafe {
            let enumerator = self.services.ExecQuery(
                &BSTR::from("WQL"),
                &BSTR::from(wql),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                None,
            )?;
            loop {
                let mut objects = [None];
                let mut returned = 0u32;
                let hr = enumerator.Next(WBEM_INFINITE, &mut objects, &mut returned);
                if hr.is_err() {
                    return Err(anyhow!("WMI enumeration failed ({:#X})", hr.0));
                }
                if returned == 0 {
                    break;
                }
                let Some(object) = objects[0].take() else {
                    break;
                };
                let mut row = Vec::new();
                for prop in props {
                    let name: Vec<u16> = prop.encode_utf16().chain(Some(0)).collect();
                    let mut value = VARIANT::default();
                    let got = object.Get(PCWSTR(name.as_ptr()), 0, &mut value, None, None);
                    let text = if got.is_ok() {
                        BSTR::try_from(&value).ok().map(|b| b.to_string())
                    } else {
                        None
                    };
                    row.push(text);
                }
                rows.push(row);
            }
        }
        Ok(rows)
    }
}

pub fn read_system_overview() -> Result<SystemOverview> {
    let mut result = SystemOverview::default();
    let wmi = Wmi::connect()?;

    let processors = wmi.query(
        "SELECT Name, NumberOfCores, NumberOfLogicalProcessors FROM Win32_Processor",
        &["Name", "NumberOfCores", "NumberOfLogicalProcessors"],
    )?;
    if !processors.is_empty() {
        let mut names: Vec<String> = Vec::new();
        for cpu in &processors {
            let name = clean_name(cpu[0].as_deref());
            if !names.iter().any(|n| n.eq_ignore_ascii_case(&name)) {
                names.push(name);
            }
        }
        result.cpu_name = names.join(" + ");
        let cores: i32 = processors.iter().map(|c| to_int(&c[1])).sum();
        let logical: i32 = processors.iter().map(|c| to_int(&c[2])).sum();
        result.cpu_detail = if cores > 0 {
            format!("{cores} cores / {logical} logical processors")
        } else {
            format!("{logical} logical processors")
        };
    }

    let video = wmi.query(
        "SELECT Name, DriverVersion, AdapterRAM FROM Win32_VideoController",
        &["Name", "DriverVersion", "AdapterRAM"],
    )?;
    let mut adapters: Vec<(String, Option<String>, i64)> = Vec::new();
    for item in &video {
        let name = clean_name(item[0].as_deref());
        if name == "Not detected" || name.to_lowercase().contains("basic display") {
            continue;
        }
        let memory = to_long(&item[2]);
        match adapters
            .iter_mut()
            .find(|a| a.0.eq_ignore_ascii_case(&name))
        {
            Some(existing) => {
                if memory > existing.2 {
                    *existing = (name, item[1].clone(), memory);
                }
            }
            None => adapters.push((name, item[1].clone(), memory)),
        }
    }
    adapters.sort_by(|a, b| b.2.cmp(&a.2));
    if !adapters.is_empty() {
        result.gpu_name = adapters
            .iter()
            .take(2)
            .map(|a| a.0.clone())
            .collect::<Vec<_>>()
            .join(" + ");
        result.gpu_detail = if adapters.len() == 1 {
            format!(
                "Driver {}",
                adapters[0].1.clone().unwrap_or_else(|| "unknown".into())
            )
        } else {
            format!("{} display adapters detected", adapters.len())
        };
    }

    let computer = wmi.query(
        "SELECT TotalPhysicalMemory FROM Win32_ComputerSystem",
        &["TotalPhysicalMemory"],
    )?;
    let total_memory = computer.first().map(|r| to_ulong(&r[0])).unwrap_or(0);

    let os_build_number = xos_sys::get_windows_build_number();
    let mut build = os_build_number.to_string();
    let os = wmi.query(
        "SELECT Caption, BuildNumber, FreePhysicalMemory FROM Win32_OperatingSystem",
        &["Caption", "BuildNumber", "FreePhysicalMemory"],
    )?;
    let first = os.first();
    let caption = clean_name(first.and_then(|r| r[0].as_deref()));
    if let Some(b) = first.and_then(|r| r[1].clone()) {
        build = b;
    }
    let free_memory_kb = first.map(|r| to_ulong(&r[2])).unwrap_or(0);

    let (memory, memory_detail) = memory_texts(total_memory, free_memory_kb);
    result.memory = memory;
    result.memory_detail = memory_detail;

    let mut display_version: Option<String> = None;
    let mut ubr = 0;
    if let Ok(key) = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", KEY_READ)
    {
        display_version = key
            .get_value::<String, _>("DisplayVersion")
            .ok()
            .or_else(|| key.get_value::<String, _>("ReleaseId").ok());
        ubr = key
            .get_value::<u32, _>("UBR")
            .map(|v| v as i32)
            .unwrap_or(0);
    }
    let (name, detail) = windows_texts(
        &caption,
        &build,
        ubr,
        display_version.as_deref(),
        os_build_number,
    );
    result.windows_name = name;
    result.windows_detail = detail;
    Ok(result)
}

fn fallback_overview() -> SystemOverview {
    let build = xos_sys::get_windows_build_number();
    SystemOverview {
        cpu_name: std::env::var("PROCESSOR_IDENTIFIER").unwrap_or_else(|_| "Not detected".into()),
        cpu_detail: format!(
            "{} logical processors",
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
        ),
        gpu_name: "Not detected".into(),
        gpu_detail: String::new(),
        memory: "Not detected".into(),
        memory_detail: String::new(),
        windows_name: windows_family(build).into(),
        windows_detail: format!("Build {build}"),
    }
}

fn open_link(host: &dyn Host, url: &str) {
    let wide = |s: &str| -> Vec<u16> { s.encode_utf16().chain(Some(0)).collect() };
    let verb = wide("open");
    let target = wide(url);
    let result = unsafe {
        ShellExecuteW(
            None,
            PCWSTR(verb.as_ptr()),
            PCWSTR(target.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        )
    };
    if result.0 as isize > 32 {
        log::action_done(
            "About",
            false,
            false,
            Some("link handed to the default browser"),
        );
    } else {
        let message = format!("ShellExecute failed with code {}", result.0 as isize);
        log::log(&format!("[About] Could not open {url}: {message}"));
        log::action_done("About", true, false, Some(&message));
        host.error(
            &format!("The link could not be opened.\n\n{url}"),
            "XOS Toolkit",
        );
    }
}

impl AboutPage {
    pub fn new() -> Self {
        Self {
            st: Mutex::new(State {
                loaded: false,
                overview: None,
            }),
        }
    }

    fn load(&self, host: &dyn Host) {
        {
            let mut st = self.st.lock().unwrap();
            if st.loaded {
                return;
            }
            st.loaded = true;
        }
        match read_system_overview() {
            Ok(info) => {
                self.st.lock().unwrap().overview = Some(info);
            }
            Err(ex) => {
                log::log(&format!("[About] System overview failed: {ex}"));
                let mut st = self.st.lock().unwrap();
                st.loaded = false;
                st.overview = Some(fallback_overview());
            }
        }
        host.publish(self.model());
    }
}

fn tile(card: Card, label: &str, name: &str, detail: &str) -> Card {
    let mut card = card
        .controls(vec![Control::heading(label)])
        .controls(vec![Control::label(name)]);
    if !detail.is_empty() {
        card = card.controls(vec![Control::muted(detail)]);
    }
    card
}

impl Page for AboutPage {
    fn id(&self) -> &'static str {
        "About"
    }

    fn label(&self) -> &'static str {
        "About"
    }

    fn model(&self) -> PageModel {
        let st = self.st.lock().unwrap();
        let is_xos = detect::is_xos();
        let (state_text, state_tone) = if is_xos {
            ("XOS ready", Tone::Green)
        } else {
            ("Standard Windows", Tone::Neutral)
        };
        let detecting = SystemOverview {
            cpu_name: "Detecting...".into(),
            gpu_name: "Detecting...".into(),
            memory: "Detecting...".into(),
            windows_name: "Detecting...".into(),
            ..SystemOverview::default()
        };
        let info = st.overview.as_ref().unwrap_or(&detecting);

        let header = Card::new(
            "about",
            "XOS Toolkit",
            "Manage the parts of Windows that matter without digging through policies, services, and command-line tools.",
        )
        .not_searchable()
        .controls(vec![
            Control::muted(format!("Version {}", env!("CARGO_PKG_VERSION"))),
            Control::spacer(),
            Control::heading("System state"),
            Control::chip(state_text, state_tone),
        ]);

        let mut overview =
            Card::new("overview", "System Overview", "Local hardware").not_searchable();
        overview = tile(overview, "Processor", &info.cpu_name, &info.cpu_detail);
        overview = tile(overview, "Graphics", &info.gpu_name, &info.gpu_detail);
        overview = tile(overview, "Memory", &info.memory, &info.memory_detail);
        overview = tile(
            overview,
            "Windows",
            &info.windows_name,
            &info.windows_detail,
        );

        PageModel::new("About", "About", "XOS Toolkit and this PC at a glance")
            .max_width(1080.0)
            .card(header.full_width())
            .card(overview.full_width())
            .card(
                Card::new(
                    "github",
                    "XOS on GitHub",
                    "Releases, source code, and bug reports.",
                )
                .not_searchable()
                .full_width()
                .actions(vec![Control::button("github", "Open GitHub", BtnStyle::Enable)]),
            )
            .card(
                Card::new("slint", "", "").not_searchable().full_width().controls(vec![
                    Control::muted("Made with Slint"),
                    Control::button("slint.link", "slint.dev", BtnStyle::Link),
                ]),
            )
    }

    fn refresh(&self, host: &dyn Host) {
        self.load(host);
    }

    fn handle(&self, host: &dyn Host, event: &Event) {
        if event.kind != EventKind::Click {
            return;
        }
        match event.control.as_str() {
            "github" => open_link(host, GITHUB_URL),
            "slint.link" => open_link(host, SLINT_URL),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(clean_name(None), "Not detected");
        assert_eq!(clean_name(Some("   ")), "Not detected");
        assert_eq!(
            clean_name(Some("Intel(R) Core(TM) i9-14900K  CPU\u{00AE} ")),
            "Intel Core i9-14900K CPU"
        );
    }

    #[test]
    fn memory() {
        assert_eq!(
            memory_texts(34_359_738_368, 20_971_520),
            ("32 GB".to_string(), "20 GB currently available".to_string())
        );
        assert_eq!(
            memory_texts(0, 0),
            (
                "Not detected".to_string(),
                "Installed physical memory".to_string()
            )
        );
        assert_eq!(memory_texts(1, 1_572_864).1, "1.5 GB currently available");
    }

    #[test]
    fn windows() {
        assert_eq!(
            windows_texts(
                "Microsoft Windows 11 Pro",
                "26100",
                4652,
                Some("24H2"),
                26100
            ),
            (
                "Microsoft Windows 11 Pro".to_string(),
                "24H2 / Build 26100.4652".to_string()
            )
        );
        assert_eq!(
            windows_texts("Not detected", "19045", 0, None, 19045),
            ("Windows 10".to_string(), "Build 19045".to_string())
        );
    }

    #[test]
    fn model_has_links_and_slint_line() {
        let page = AboutPage::new();
        let model = page.model();
        let ids: Vec<&str> = model
            .cards
            .iter()
            .flat_map(|c| c.rows.iter())
            .flat_map(|r| r.controls.iter())
            .map(|c| c.id.as_str())
            .collect();
        for id in ["github", "slint.link"] {
            assert!(ids.contains(&id));
        }
        let texts: Vec<&str> = model
            .cards
            .iter()
            .flat_map(|c| c.rows.iter())
            .flat_map(|r| r.controls.iter())
            .map(|c| c.text.as_str())
            .collect();
        assert!(texts.contains(&"Made with Slint"));
        assert_eq!(model.cards.last().unwrap().id, "slint");
    }
}

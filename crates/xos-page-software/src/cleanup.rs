use std::path::{Path, PathBuf};
use std::sync::Mutex;
use windows::core::PCWSTR;
use windows::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDrives};
use windows::Win32::UI::Shell::{SHEmptyRecycleBinW, SHQueryRecycleBinW, SHQUERYRBINFO};
use xos_core::host::{Host, Icon, Page};
use xos_core::log;
use xos_core::ui::*;

const RECYCLE_BIN: &str = "__RECYCLE_BIN__";
const DRIVE_FIXED: u32 = 3;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

#[derive(Clone)]
struct CleanupCategory {
    name: &'static str,
    size: i64,
    paths: Vec<String>,
}

struct State {
    categories: Option<Vec<CleanupCategory>>,
    scanned: bool,
    space_label: String,
    can_scan: bool,
    can_clean: bool,
}

pub struct CleanupPage {
    st: Mutex<State>,
}

fn windows_dir() -> String {
    std::env::var("SystemRoot")
        .or_else(|_| std::env::var("windir"))
        .unwrap_or_else(|_| "C:\\Windows".into())
}

fn combine(base: &str, rest: &str) -> String {
    PathBuf::from(base)
        .join(rest)
        .to_string_lossy()
        .into_owned()
}

fn temp_path() -> String {
    let mut t = std::env::temp_dir().to_string_lossy().into_owned();
    if !t.ends_with('\\') {
        t.push('\\');
    }
    t
}

fn path_root(p: &str) -> String {
    let b = p.as_bytes();
    if b.len() >= 2 && b[1] == b':' {
        format!("{}:\\", &p[..1])
    } else {
        String::new()
    }
}

fn target_names() -> [&'static str; 8] {
    [
        "User Temp",
        "Windows Temp",
        "Prefetch",
        "Crash Dumps",
        "Delivery Optimization",
        "Windows Log Files",
        "Windows.old",
        "Recycle Bin",
    ]
}

fn target_paths(name: &str) -> Vec<String> {
    let win = windows_dir();
    match name {
        "User Temp" => vec![temp_path()],
        "Windows Temp" => vec![combine(&win, "Temp")],
        "Prefetch" => vec![combine(&win, "Prefetch")],
        "Crash Dumps" => {
            let local = std::env::var("LOCALAPPDATA").unwrap_or_default();
            vec![
                combine(&local, "CrashDumps"),
                combine(&win, "Minidump"),
                combine(&win, "LiveKernelReports"),
            ]
        }
        "Delivery Optimization" => {
            vec![combine(&win, "SoftwareDistribution\\DeliveryOptimization")]
        }
        "Windows Log Files" => vec![combine(&win, "Logs")],
        "Windows.old" => vec![combine(&path_root(&win), "Windows.old")],
        _ => vec![RECYCLE_BIN.to_string()],
    }
}

fn is_reparse_point(path: &Path) -> bool {
    use std::os::windows::fs::MetadataExt;
    match std::fs::symlink_metadata(path) {
        Ok(m) => m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0,
        Err(_) => true,
    }
}

fn get_directory_size(path: &Path) -> i64 {
    if is_reparse_point(path) {
        return 0;
    }
    let mut size = 0i64;
    if let Ok(rd) = std::fs::read_dir(path) {
        let mut dirs = Vec::new();
        for entry in rd.flatten() {
            let p = entry.path();
            match entry.file_type() {
                Ok(t) if t.is_dir() => dirs.push(p),
                Ok(_) => {
                    if let Ok(m) = std::fs::symlink_metadata(&p) {
                        size += m.len() as i64;
                    }
                }
                Err(_) => {}
            }
        }
        for d in dirs {
            if !is_reparse_point(&d) {
                size += get_directory_size(&d);
            }
        }
    }
    size
}

fn fixed_drive_roots() -> Vec<String> {
    let mut roots = Vec::new();
    let mask = unsafe { GetLogicalDrives() };
    for i in 0..26u32 {
        if mask & (1 << i) != 0 {
            let root = format!("{}:\\", (b'A' + i as u8) as char);
            let wide: Vec<u16> = root.encode_utf16().chain(std::iter::once(0)).collect();
            if unsafe { GetDriveTypeW(PCWSTR(wide.as_ptr())) } == DRIVE_FIXED
                && Path::new(&root).exists()
            {
                roots.push(root);
            }
        }
    }
    roots
}

fn get_recycle_bin_size() -> i64 {
    let mut size = 0i64;
    for root in fixed_drive_roots() {
        let wide: Vec<u16> = root.encode_utf16().chain(std::iter::once(0)).collect();
        let mut info = SHQUERYRBINFO {
            cbSize: std::mem::size_of::<SHQUERYRBINFO>() as u32,
            ..Default::default()
        };
        if unsafe { SHQueryRecycleBinW(PCWSTR(wide.as_ptr()), &mut info) }.is_ok() {
            size += info.i64Size;
        }
    }
    size
}

fn empty_recycle_bin() -> bool {
    unsafe { SHEmptyRecycleBinW(None, PCWSTR::null(), 0x00000007) }.is_ok()
}

fn delete_directory_contents(path: &Path) -> i64 {
    if is_reparse_point(path) {
        return 0;
    }
    let mut freed = 0i64;
    if let Ok(rd) = std::fs::read_dir(path) {
        let mut dirs = Vec::new();
        for entry in rd.flatten() {
            let p = entry.path();
            match entry.file_type() {
                Ok(t) if t.is_dir() => dirs.push(p),
                Ok(_) => {
                    if let Ok(m) = std::fs::symlink_metadata(&p) {
                        let len = m.len() as i64;
                        if std::fs::remove_file(&p).is_ok() {
                            freed += len;
                        }
                    }
                }
                Err(_) => {}
            }
        }
        for d in dirs {
            if is_reparse_point(&d) {
                let _ = std::fs::remove_dir(&d);
                continue;
            }
            freed += delete_directory_contents(&d);
            let _ = std::fs::remove_dir(&d);
        }
    }
    freed
}

fn delete_directory(path: &Path) -> i64 {
    if is_reparse_point(path) {
        let _ = std::fs::remove_dir(path);
        return 0;
    }
    let freed = delete_directory_contents(path);
    let _ = std::fs::remove_dir(path);
    freed
}

pub(crate) fn format_size(bytes: i64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

impl CleanupPage {
    pub fn new() -> Self {
        Self {
            st: Mutex::new(State {
                categories: None,
                scanned: false,
                space_label: "Press Scan to analyze.".into(),
                can_scan: true,
                can_clean: false,
            }),
        }
    }

    fn scan(&self, host: &dyn Host) {
        {
            let mut st = self.st.lock().unwrap();
            st.can_scan = false;
            st.can_clean = false;
            st.space_label = "Scanning...".into();
        }
        host.publish(self.model());
        host.set_status("Scanning for reclaimable space...");

        let mut results = Vec::new();
        for name in target_names() {
            let mut size = 0i64;
            let paths = target_paths(name);
            for path in &paths {
                if path == RECYCLE_BIN {
                    size += get_recycle_bin_size();
                    continue;
                }
                if Path::new(path).is_dir() {
                    size += get_directory_size(Path::new(path));
                }
            }
            results.push(CleanupCategory { name, size, paths });
        }
        let total: i64 = results.iter().map(|c| c.size).sum();
        {
            let mut st = self.st.lock().unwrap();
            st.categories = Some(results);
            st.space_label = format!("{} can be freed", format_size(total));
            st.scanned = true;
            st.can_clean = total > 0;
            st.can_scan = true;
        }
        log::action_done(
            "Cleanup",
            false,
            false,
            Some(&format!("{} reclaimable", format_size(total))),
        );
        host.set_status(&format!(
            "Scan complete: {} reclaimable",
            format_size(total)
        ));
    }

    fn clean(&self, host: &dyn Host) {
        let categories = {
            let st = self.st.lock().unwrap();
            if !st.scanned {
                return;
            }
            match &st.categories {
                Some(c) => c.clone(),
                None => return,
            }
        };

        if !host.confirm(
            "This will permanently delete temporary files and system junk.\n\nProceed?",
            "Disk Cleanup",
            Icon::Warning,
        ) {
            return;
        }

        {
            let mut st = self.st.lock().unwrap();
            st.can_scan = false;
            st.can_clean = false;
            st.space_label = "Cleaning...".into();
        }
        host.publish(self.model());
        host.set_status("Cleaning...");

        let mut freed = 0i64;
        for cat in &categories {
            if cat.size == 0 {
                continue;
            }
            for path in &cat.paths {
                if path == RECYCLE_BIN {
                    if empty_recycle_bin() {
                        freed += cat.size;
                    }
                    continue;
                }
                let p = Path::new(path);
                if !p.is_dir() {
                    continue;
                }
                if cat.name == "Windows.old" {
                    freed += delete_directory(p);
                    continue;
                }
                freed += delete_directory_contents(p);
            }
        }

        log::action_done(
            "Cleanup",
            false,
            false,
            Some(&format!(
                "{} freed of {} found; files in use are skipped",
                format_size(freed),
                format_size(categories.iter().map(|c| c.size).sum())
            )),
        );
        {
            let mut st = self.st.lock().unwrap();
            st.space_label = format!("{} freed", format_size(freed));
            st.can_scan = true;
            st.can_clean = false;
            st.scanned = false;
        }
        host.set_status(&format!("Cleanup complete: {} freed", format_size(freed)));
    }
}

impl Page for CleanupPage {
    fn id(&self) -> &'static str {
        "Cleanup"
    }

    fn label(&self) -> &'static str {
        "Disk Cleanup"
    }

    fn model(&self) -> PageModel {
        let st = self.st.lock().unwrap();
        let breakdown = match &st.categories {
            None => vec![Control::muted("Press Scan to analyze disk usage.")],
            Some(cats) => {
                let rows = cats
                    .iter()
                    .enumerate()
                    .map(|(i, c)| {
                        TableRow::new(i.to_string(), vec![c.name.to_string(), format_size(c.size)])
                    })
                    .collect();
                vec![Control::table(
                    "categories",
                    Table::new(
                        vec![Column::stretch("CATEGORY"), Column::new("SIZE", 90.0)],
                        rows,
                    )
                    .height(300.0),
                )]
            }
        };
        PageModel::new(
            "Cleanup",
            "Disk Cleanup",
            "Remove temporary files and system junk to free up disk space",
        )
        .single_column()
        .max_width(1080.0)
        .card(
            Card::new("summary", "Reclaimable Space", "")
                .not_searchable()
                .controls(vec![
                    Control::muted(st.space_label.clone()),
                    Control::spacer(),
                    Control::button("scan", "Scan", BtnStyle::Action).enabled(st.can_scan),
                    Control::button("clean", "Clean", BtnStyle::Disable).enabled(st.can_clean),
                ]),
        )
        .card(
            Card::new("breakdown", "Categories", "")
                .not_searchable()
                .controls(breakdown),
        )
    }

    fn handle(&self, host: &dyn Host, event: &Event) {
        if event.is_click("scan") {
            self.scan(host);
        } else if event.is_click("clean") {
            self.clean(host);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(1536), "1.5 KB");
        assert_eq!(format_size(5 * 1024 * 1024), "5.0 MB");
        assert_eq!(format_size(3 * 1024 * 1024 * 1024), "3.00 GB");
    }

    #[test]
    fn roots() {
        assert_eq!(path_root("C:\\Windows"), "C:\\");
    }
}

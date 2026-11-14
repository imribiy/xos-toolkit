use std::sync::Mutex;
use xos_core::eventlog;
use xos_core::host::{FileFilter, Host, Page};
use xos_core::log;
use xos_core::ui::*;

#[derive(Clone)]
struct StabilityEvent {
    time: Option<chrono::DateTime<chrono::Local>>,
    category: &'static str,
    log_name: &'static str,
    level: u8,
    provider: String,
    event_id: u32,
    summary: String,
}

impl StabilityEvent {
    fn time_text(&self) -> String {
        self.time.map(|t| t.format("%Y-%m-%d %H:%M").to_string()).unwrap_or_else(|| "0001-01-01 00:00".into())
    }
    fn level_text(&self) -> &'static str {
        if self.level == 1 {
            "Critical"
        } else {
            "Error"
        }
    }
    fn source_text(&self) -> String {
        format!("{} / {}", self.provider, self.event_id)
    }
}

struct State {
    loading: bool,
    range: i32,
    events: Vec<StabilityEvent>,
    summary: String,
}

pub struct StabilityPage {
    st: Mutex<State>,
}

const RANGES: [(&str, i64); 3] = [("Last 24 hours", 1), ("Last 7 days", 7), ("Last 30 days", 30)];

fn range_text(days: i64) -> String {
    if days == 1 {
        "24 hours".into()
    } else {
        format!("{days} days")
    }
}

fn summary_of(description: Option<String>) -> String {
    match description {
        None => "Event details are unavailable. Open Event Viewer for the full record.".into(),
        Some(t) if t.trim().is_empty() => "No event description available.".into(),
        Some(t) => {
            let joined = t.split_whitespace().collect::<Vec<_>>().join(" ");
            if joined.chars().count() > 300 {
                format!("{}...", joined.chars().take(297).collect::<String>())
            } else {
                joined
            }
        }
    }
}

fn read_log(log_name: &'static str, xpath: &str, out: &mut Vec<StabilityEvent>) -> windows::core::Result<()> {
    for r in eventlog::query(log_name, xpath, true, 12000, true)? {
        let category = if r.provider.eq_ignore_ascii_case("Microsoft-Windows-WHEA-Logger") {
            "WHEA Error"
        } else if log_name == "System" {
            "System Error"
        } else {
            "Application Error"
        };
        out.push(StabilityEvent {
            time: r.time_created,
            category,
            log_name,
            level: r.level,
            provider: if r.provider.is_empty() { log_name.to_string() } else { r.provider },
            event_id: r.event_id,
            summary: summary_of(r.description),
        });
    }
    Ok(())
}

fn read_events(days: i64) -> windows::core::Result<Vec<StabilityEvent>> {
    let ms = days * 24 * 60 * 60 * 1000;
    let xpath = format!("*[System[TimeCreated[timediff(@SystemTime) <= {ms}] and (Level=1 or Level=2)]]");
    let mut results = Vec::new();
    read_log("System", &xpath, &mut results)?;
    read_log("Application", &xpath, &mut results)?;
    results.sort_by(|a, b| b.time.cmp(&a.time));
    results.truncate(500);
    Ok(results)
}

fn csv(value: &str) -> String {
    let mut safe = value.to_string();
    if safe.starts_with(['=', '+', '-', '@']) {
        safe.insert(0, '\'');
    }
    format!("\"{}\"", safe.replace('"', "\"\""))
}

impl StabilityPage {
    pub fn new() -> Self {
        Self { st: Mutex::new(State { loading: false, range: 1, events: Vec::new(), summary: "Loading events...".into() }) }
    }

    fn load(&self, host: &dyn Host) {
        let days = {
            let mut st = self.st.lock().unwrap();
            if st.loading {
                return;
            }
            st.loading = true;
            st.summary = "Reading Windows event logs...".into();
            RANGES[st.range.clamp(0, 2) as usize].1
        };
        host.publish(self.model());
        host.set_status("Reading stability events...");
        let result = read_events(days);
        let mut st = self.st.lock().unwrap();
        match result {
            Ok(events) => {
                let n = events.len();
                st.events = events;
                st.summary = if n == 0 {
                    format!("No Error or Critical events found in the last {}.", range_text(days))
                } else {
                    format!("{n} Error or Critical event{} found in the last {}.", if n == 1 { "" } else { "s" }, range_text(days))
                };
                drop(st);
                host.set_status(&if n == 0 { "No recent errors found.".to_string() } else { format!("Loaded {n} Event Viewer errors.") });
                st = self.st.lock().unwrap();
            }
            Err(e) => {
                log::log(&format!("[Stability] Event log scan failed: {}", e.message()));
                st.summary = "Windows event logs could not be read.".into();
                drop(st);
                host.set_status(&format!("Stability scan failed: {}", e.message()));
                st = self.st.lock().unwrap();
            }
        }
        st.loading = false;
    }

    fn export(&self, host: &dyn Host) {
        let events = self.st.lock().unwrap().events.clone();
        if events.is_empty() {
            host.info("There are no stability events to export.", "Stability Monitor");
            return;
        }
        let desktop = std::env::var("USERPROFILE").ok().map(|p| std::path::PathBuf::from(p).join("Desktop"));
        let name = format!("XOS-Stability-{}.csv", chrono::Local::now().format("%Y-%m-%d_%H-%M-%S"));
        let Some(path) = host.save_file("Export CSV", &[FileFilter::new("CSV file (*.csv)", &["csv"])], &name, desktop) else {
            return;
        };
        let mut text = String::from("\u{feff}Time,Level,Log,Source,Event ID,Details\r\n");
        for e in &events {
            text.push_str(&format!(
                "{},{},{},{},{},{}\r\n",
                csv(&e.time_text()),
                csv(e.level_text()),
                csv(e.log_name),
                csv(&e.provider),
                e.event_id,
                csv(&e.summary)
            ));
        }
        match std::fs::write(&path, text) {
            Ok(()) => {
                log::action_done("Stability", false, false, Some(&format!("{} event(s) written", events.len())));
                host.set_status("Stability report exported.");
            }
            Err(err) => {
                log::action_done("Stability", true, false, Some(&err.to_string()));
                host.set_status("Stability report export failed.");
                host.error(&format!("The stability report could not be saved.\n\n{err}"), "Stability Monitor");
            }
        }
    }
}

impl Page for StabilityPage {
    fn id(&self) -> &'static str {
        "Stability"
    }

    fn label(&self) -> &'static str {
        "Stability Monitor"
    }

    fn model(&self) -> PageModel {
        let st = self.st.lock().unwrap();
        let count = |f: &dyn Fn(&StabilityEvent) -> bool| st.events.iter().filter(|e| f(e)).count().to_string();
        let rows: Vec<TableRow> = st
            .events
            .iter()
            .enumerate()
            .map(|(i, e)| TableRow::new(i.to_string(), vec![e.time_text(), e.level_text().into(), e.log_name.into(), e.source_text(), e.summary.clone()]).tooltip(e.summary.clone()))
            .collect();
        PageModel::new(
            "Stability",
            "Stability Monitor",
            "Critical and Error entries from the System and Application logs. WHEA warnings and informational events are excluded.",
        )
        .single_column()
        .max_width(980.0)
        .card(
            Card::new("controls", "", "").not_searchable().controls(vec![
                Control::heading("Time range"),
                Control::combo("range", RANGES.iter().map(|r| r.0.to_string()).collect(), st.range).width(130.0).enabled(!st.loading),
                Control::spacer(),
                Control::button("export", "Export CSV", BtnStyle::Action).enabled(!st.loading && !st.events.is_empty()),
                Control::button("refresh", "Refresh", BtnStyle::Enable).enabled(!st.loading),
            ]),
        )
        .card(Card::new("counts", "", "").not_searchable().controls(vec![
            Control::stat("WHEA errors", count(&|e| e.category == "WHEA Error")),
            Control::stat("System errors", count(&|e| e.category == "System Error")),
            Control::stat("App errors", count(&|e| e.category == "Application Error")),
            Control::stat("Critical", count(&|e| e.level == 1)),
            Control::stat("Total", st.events.len().to_string()),
        ]))
        .card(
            Card::new("events", "", "")
                .not_searchable()
                .controls(vec![Control::muted(st.summary.clone())])
                .controls(vec![Control::table(
                    "list",
                    Table::new(
                        vec![
                            Column::new("TIME", 132.0),
                            Column::new("LEVEL", 75.0),
                            Column::new("LOG", 95.0),
                            Column::new("SOURCE / ID", 190.0),
                            Column::stretch("DETAIL"),
                        ],
                        rows,
                    )
                    .height(420.0),
                )]),
        )
    }

    fn refresh(&self, host: &dyn Host) {
        self.load(host);
    }

    fn handle(&self, host: &dyn Host, event: &Event) {
        match (event.control.as_str(), &event.kind) {
            ("refresh", EventKind::Click) => self.load(host),
            ("range", EventKind::Select(i)) => {
                self.st.lock().unwrap().range = (*i).clamp(0, 2);
                self.load(host);
            }
            ("export", EventKind::Click) => self.export(host),
            _ => {}
        }
    }
}

use crate::ui::{Event, PageModel, Tone};
use std::path::PathBuf;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Buttons {
    Ok,
    OkCancel,
    YesNo,
    YesNoCancel,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Icon {
    Information,
    Warning,
    Error,
    Question,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DialogResult {
    Ok,
    Cancel,
    Yes,
    No,
}

impl DialogResult {
    pub fn accepted(self) -> bool {
        matches!(self, DialogResult::Ok | DialogResult::Yes)
    }
}

#[derive(Clone, Debug, Default)]
pub struct FileFilter {
    pub name: String,
    pub extensions: Vec<String>,
}

impl FileFilter {
    pub fn new(name: impl Into<String>, exts: &[&str]) -> Self {
        Self { name: name.into(), extensions: exts.iter().map(|s| s.to_string()).collect() }
    }
}

#[derive(Clone, Debug)]
pub struct PickItem {
    pub id: String,
    pub label: String,
    pub tone: Tone,
}

pub trait Host: Send + Sync {
    fn dialog(&self, message: &str, title: &str, buttons: Buttons, icon: Icon) -> DialogResult;
    fn input_text(&self, prompt: &str, title: &str, max_len: usize, ok_label: &str) -> Option<String>;
    fn pick_many(&self, title: &str, legend: &str, filter_hint: &str, items: Vec<PickItem>, ok_label: &str) -> Vec<String>;
    fn save_file(&self, title: &str, filters: &[FileFilter], default_name: &str, initial_dir: Option<PathBuf>) -> Option<PathBuf>;
    fn open_file(&self, title: &str, filters: &[FileFilter], initial_dir: Option<PathBuf>) -> Option<PathBuf>;
    fn set_status(&self, text: &str);
    fn publish(&self, model: PageModel);
    fn navigate(&self, page_id: &str);
    fn current_page(&self) -> String;

    fn info(&self, message: &str, title: &str) {
        self.dialog(message, title, Buttons::Ok, Icon::Information);
    }
    fn warn(&self, message: &str, title: &str) {
        self.dialog(message, title, Buttons::Ok, Icon::Warning);
    }
    fn error(&self, message: &str, title: &str) {
        self.dialog(message, title, Buttons::Ok, Icon::Error);
    }
    fn confirm(&self, message: &str, title: &str, icon: Icon) -> bool {
        self.dialog(message, title, Buttons::YesNo, icon) == DialogResult::Yes
    }
}

pub trait Page: Send + Sync {
    fn id(&self) -> &'static str;
    fn label(&self) -> &'static str;
    fn model(&self) -> PageModel;
    fn refresh(&self, _host: &dyn Host) {}
    fn handle(&self, host: &dyn Host, event: &Event);
}

pub struct NullHost;

impl Host for NullHost {
    fn dialog(&self, _m: &str, _t: &str, b: Buttons, _i: Icon) -> DialogResult {
        match b {
            Buttons::Ok | Buttons::OkCancel => DialogResult::Ok,
            _ => DialogResult::No,
        }
    }
    fn input_text(&self, _p: &str, _t: &str, _m: usize, _o: &str) -> Option<String> {
        None
    }
    fn pick_many(&self, _t: &str, _l: &str, _f: &str, _i: Vec<PickItem>, _o: &str) -> Vec<String> {
        Vec::new()
    }
    fn save_file(&self, _t: &str, _f: &[FileFilter], _d: &str, _i: Option<PathBuf>) -> Option<PathBuf> {
        None
    }
    fn open_file(&self, _t: &str, _f: &[FileFilter], _i: Option<PathBuf>) -> Option<PathBuf> {
        None
    }
    fn set_status(&self, _t: &str) {}
    fn publish(&self, _m: PageModel) {}
    fn navigate(&self, _p: &str) {}
    fn current_page(&self) -> String {
        String::new()
    }
}

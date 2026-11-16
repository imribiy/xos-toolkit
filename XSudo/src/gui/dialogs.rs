use core::cell::Cell;
use core::cell::RefCell;
use core::ptr::null_mut;

use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Graphics::Gdi::*;
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::UI::Controls::CheckRadioButton;
use windows_sys::Win32::UI::Controls::Dialogs::*;
use windows_sys::Win32::UI::Controls::IsDlgButtonChecked;
use windows_sys::Win32::UI::Controls::EM_SETSEL;
use windows_sys::Win32::UI::HiDpi::GetDpiForWindow;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::SetFocus;
use windows_sys::Win32::UI::Shell::SHBrowseForFolderW;
use windows_sys::Win32::UI::Shell::SHGetPathFromIDListW;
use windows_sys::Win32::UI::Shell::BIF_NEWDIALOGSTYLE;
use windows_sys::Win32::UI::Shell::BIF_RETURNONLYFSDIRS;
use windows_sys::Win32::UI::Shell::BROWSEINFOW;
use windows_sys::Win32::UI::WindowsAndMessaging::*;

use super::hinstance;
use super::wide;
use crate::launch;
use crate::settings::Entry;
use crate::settings::Show;

const IDD_EDIT: usize = 101;
const IDD_TEXT: usize = 102;
const IDC_FILE: i32 = 1001;
const IDC_BROWSE_FILE: i32 = 1002;
const IDC_PARAMS: i32 = 1003;
const IDC_DIR: i32 = 1004;
const IDC_BROWSE_DIR: i32 = 1005;
const IDC_NORMAL: i32 = 1006;
const IDC_MAXIMIZED: i32 = 1009;
const IDC_RUN: i32 = 1010;
const IDC_TEXT: i32 = 1201;

thread_local! {
    static EDIT_STATE: RefCell<(Entry, String)> = RefCell::new((Entry::new(""), String::new()));
    static TEXT_STATE: RefCell<String> = const { RefCell::new(String::new()) };
    static TEXT_FONT: Cell<HFONT> = const { Cell::new(null_mut()) };
    static OPEN_DIALOG: Cell<HWND> = const { Cell::new(null_mut()) };
}

fn item_text(dlg: HWND, id: i32) -> String {
    unsafe {
        let h = GetDlgItem(dlg, id);
        let len = GetWindowTextLengthW(h).max(0) as usize;
        let mut buf = vec![0u16; len + 1];
        let n = GetDlgItemTextW(dlg, id, buf.as_mut_ptr(), buf.len() as i32);
        String::from_utf16_lossy(&buf[..n as usize])
    }
}

fn set_item_text(dlg: HWND, id: i32, text: &str) {
    let w = wide(text);
    unsafe {
        SetDlgItemTextW(dlg, id, w.as_ptr());
    }
}

fn read_entry(dlg: HWND) -> Entry {
    let mut show = Show::Normal;
    for (i, s) in Show::ALL.iter().enumerate() {
        if unsafe { IsDlgButtonChecked(dlg, IDC_NORMAL + i as i32) } != 0 {
            show = *s;
        }
    }
    Entry {
        file: item_text(dlg, IDC_FILE).trim().to_string(),
        params: item_text(dlg, IDC_PARAMS),
        start_dir: item_text(dlg, IDC_DIR).trim().to_string(),
        show,
    }
}

fn require_file(dlg: HWND, e: &Entry) -> bool {
    if !e.file.is_empty() {
        return true;
    }
    launch::message_box(
        dlg,
        "Enter the program or script to run in File.",
        MB_ICONWARNING | MB_OK,
    );
    unsafe {
        SetFocus(GetDlgItem(dlg, IDC_FILE));
    }
    false
}

fn browse_file(dlg: HWND) {
    let current = launch::expand_env(item_text(dlg, IDC_FILE).trim());
    let initial = wide(&launch::parent_dir(&current));
    let filter: Vec<u16> = [
        "Programs and scripts (*.exe, *.com, *.bat, *.cmd, *.ps1, *.msc)",
        "*.exe;*.com;*.bat;*.cmd;*.ps1;*.msc",
        "Programs (*.exe, *.com)",
        "*.exe;*.com",
        "Batch files (*.bat, *.cmd)",
        "*.bat;*.cmd",
        "PowerShell scripts (*.ps1)",
        "*.ps1",
        "Management consoles (*.msc)",
        "*.msc",
        "All files (*.*)",
        "*.*",
    ]
    .iter()
    .flat_map(|s| s.encode_utf16().chain(core::iter::once(0)))
    .chain(core::iter::once(0))
    .collect();
    let mut buf = vec![0u16; 32768];
    let title = wide("Choose a program or script");
    unsafe {
        let mut ofn: OPENFILENAMEW = core::mem::zeroed();
        ofn.lStructSize = core::mem::size_of::<OPENFILENAMEW>() as u32;
        ofn.hwndOwner = dlg;
        ofn.lpstrFilter = filter.as_ptr();
        ofn.nFilterIndex = 1;
        ofn.lpstrFile = buf.as_mut_ptr();
        ofn.nMaxFile = buf.len() as u32;
        if initial.len() > 1 {
            ofn.lpstrInitialDir = initial.as_ptr();
        }
        ofn.lpstrTitle = title.as_ptr();
        ofn.Flags = OFN_FILEMUSTEXIST
            | OFN_PATHMUSTEXIST
            | OFN_HIDEREADONLY
            | OFN_EXPLORER
            | OFN_NOCHANGEDIR
            | OFN_DONTADDTORECENT;
        if GetOpenFileNameW(&mut ofn) != 0 {
            let n = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
            set_item_text(dlg, IDC_FILE, &String::from_utf16_lossy(&buf[..n]));
        }
    }
}

fn browse_dir(dlg: HWND) {
    let title = wide("Choose the start directory");
    let mut name = vec![0u16; 260];
    unsafe {
        let mut bi: BROWSEINFOW = core::mem::zeroed();
        bi.hwndOwner = dlg;
        bi.pszDisplayName = name.as_mut_ptr();
        bi.lpszTitle = title.as_ptr();
        bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
        let pidl = SHBrowseForFolderW(&bi);
        if pidl.is_null() {
            return;
        }
        let mut path = vec![0u16; 32768];
        if SHGetPathFromIDListW(pidl, path.as_mut_ptr()) != 0 {
            let n = path.iter().position(|&c| c == 0).unwrap_or(path.len());
            set_item_text(dlg, IDC_DIR, &String::from_utf16_lossy(&path[..n]));
        }
        CoTaskMemFree(pidl as *const core::ffi::c_void);
    }
}

unsafe extern "system" fn edit_proc(dlg: HWND, msg: u32, wparam: WPARAM, _lparam: LPARAM) -> isize {
    match msg {
        WM_INITDIALOG => {
            let (entry, title) = EDIT_STATE.with(|s| s.borrow().clone());
            let t = wide(&title);
            SetWindowTextW(dlg, t.as_ptr());
            set_item_text(dlg, IDC_FILE, &entry.file);
            set_item_text(dlg, IDC_PARAMS, &entry.params);
            set_item_text(dlg, IDC_DIR, &entry.start_dir);
            let idx = Show::ALL.iter().position(|s| *s == entry.show).unwrap_or(0) as i32;
            CheckRadioButton(dlg, IDC_NORMAL, IDC_MAXIMIZED, IDC_NORMAL + idx);
            OPEN_DIALOG.with(|d| d.set(dlg));
            1
        }
        WM_DESTROY => {
            OPEN_DIALOG.with(|d| d.set(null_mut()));
            0
        }
        WM_COMMAND => {
            let id = (wparam & 0xFFFF) as i32;
            match id {
                IDC_BROWSE_FILE => browse_file(dlg),
                IDC_BROWSE_DIR => browse_dir(dlg),
                IDC_RUN => {
                    let e = read_entry(dlg);
                    if require_file(dlg, &e) {
                        super::run_entry(e);
                    }
                }
                x if x == IDOK => {
                    let e = read_entry(dlg);
                    if require_file(dlg, &e) {
                        EDIT_STATE.with(|s| s.borrow_mut().0 = e);
                        EndDialog(dlg, 1);
                    }
                }
                x if x == IDCANCEL => {
                    EndDialog(dlg, 0);
                }
                _ => return 0,
            }
            1
        }
        _ => 0,
    }
}

pub(super) fn open_dialog() -> Option<HWND> {
    let d = OPEN_DIALOG.with(|d| d.get());
    if d.is_null() {
        None
    } else {
        Some(d)
    }
}

pub(super) fn edit(owner: HWND, entry: Entry, title: &str) -> Option<Entry> {
    EDIT_STATE.with(|s| *s.borrow_mut() = (entry, title.to_string()));
    let r = unsafe { DialogBoxParamW(hinstance(), IDD_EDIT as _, owner, Some(edit_proc), 0) };
    if r == 1 {
        Some(EDIT_STATE.with(|s| s.borrow().0.clone()))
    } else {
        None
    }
}

unsafe extern "system" fn text_proc(dlg: HWND, msg: u32, wparam: WPARAM, _lparam: LPARAM) -> isize {
    match msg {
        WM_INITDIALOG => {
            let dpi = GetDpiForWindow(dlg).max(96) as i32;
            let face = wide("Consolas");
            let font = CreateFontW(
                -(9 * dpi + 36) / 72,
                0,
                0,
                0,
                FW_NORMAL as i32,
                0,
                0,
                0,
                DEFAULT_CHARSET as u32,
                OUT_DEFAULT_PRECIS as u32,
                CLIP_DEFAULT_PRECIS as u32,
                CLEARTYPE_QUALITY as u32,
                FIXED_PITCH as u32,
                face.as_ptr(),
            );
            TEXT_FONT.with(|f| f.set(font));
            let edit = GetDlgItem(dlg, IDC_TEXT);
            if !font.is_null() {
                SendMessageW(edit, WM_SETFONT, font as WPARAM, 0);
            }
            let text = TEXT_STATE.with(|t| t.borrow().replace("\r\n", "\n").replace('\n', "\r\n"));
            set_item_text(dlg, IDC_TEXT, &text);
            SendMessageW(edit, EM_SETSEL, 0, 0);
            SetFocus(GetDlgItem(dlg, IDOK));
            0
        }
        WM_COMMAND => {
            let id = (wparam & 0xFFFF) as i32;
            if id == IDOK || id == IDCANCEL {
                EndDialog(dlg, 0);
                return 1;
            }
            0
        }
        WM_DESTROY => {
            let font = TEXT_FONT.with(|f| f.replace(null_mut()));
            if !font.is_null() {
                DeleteObject(font);
            }
            0
        }
        _ => 0,
    }
}

pub(super) fn text(owner: HWND, body: &str) {
    TEXT_STATE.with(|t| *t.borrow_mut() = body.to_string());
    unsafe {
        DialogBoxParamW(hinstance(), IDD_TEXT as _, owner, Some(text_proc), 0);
    }
}

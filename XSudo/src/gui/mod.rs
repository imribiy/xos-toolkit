mod dialogs;
mod glyphs;

use core::cell::Cell;
use core::cell::RefCell;
use core::ptr::null;
use core::ptr::null_mut;
use std::path::PathBuf;

use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Graphics::Gdi::*;
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_NORMAL;
use windows_sys::Win32::System::Com::CoInitializeEx;
use windows_sys::Win32::System::Com::COINIT_APARTMENTTHREADED;
use windows_sys::Win32::System::Console::FreeConsole;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Threading::CreateMutexW;
use windows_sys::Win32::UI::Controls::*;
use windows_sys::Win32::UI::HiDpi::*;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::SetFocus;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::VK_DELETE;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::VK_DOWN;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::VK_F2;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::VK_INSERT;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::VK_UP;
use windows_sys::Win32::UI::Shell::DragAcceptFiles;
use windows_sys::Win32::UI::Shell::DragFinish;
use windows_sys::Win32::UI::Shell::DragQueryFileW;
use windows_sys::Win32::UI::Shell::SHGetFileInfoW;
use windows_sys::Win32::UI::Shell::HDROP;
use windows_sys::Win32::UI::Shell::SHFILEINFOW;
use windows_sys::Win32::UI::Shell::SHGFI_SMALLICON;
use windows_sys::Win32::UI::Shell::SHGFI_SYSICONINDEX;
use windows_sys::Win32::UI::Shell::SHGFI_USEFILEATTRIBUTES;
use windows_sys::Win32::UI::WindowsAndMessaging::*;

use crate::exitcode::as_process_code;
use crate::exitcode::ERR_ELEVATION;
use crate::launch;
use crate::launch::Elevation;
use crate::settings;
use crate::settings::Entry;
use crate::settings::Loaded;
use crate::settings::Placement;
use crate::settings::Settings;
use crate::settings::Show;
use crate::shellmenu;
use crate::sys;

const CLASS_NAME: &str = "XSudoWindow";
const MUTEX_NAME: &str = "Local\\XSudo.Window";

pub(crate) const IDM_RUN: u16 = 100;
pub(crate) const IDM_ADD: u16 = 101;
pub(crate) const IDM_REMOVE: u16 = 102;
pub(crate) const IDM_EXIT: u16 = 103;
pub(crate) const IDM_EDIT: u16 = 110;
pub(crate) const IDM_UP: u16 = 111;
pub(crate) const IDM_DOWN: u16 = 112;
pub(crate) const IDM_SHELL: u16 = 120;
pub(crate) const IDM_USAGE: u16 = 130;
pub(crate) const IDM_ABOUT: u16 = 131;
pub(crate) const IDM_REGEDIT: u16 = 140;
pub(crate) const IDM_CMD: u16 = 141;

const ID_TOOLBAR: usize = 200;
const ID_LIST: usize = 201;
const ID_STATUS: usize = 202;

const WM_LAUNCHED: u32 = WM_APP + 1;
const WM_COPYGLOBALDATA: u32 = 0x0049;

#[derive(Clone, Copy)]
struct Ui {
    main: HWND,
    toolbar: HWND,
    list: HWND,
    status: HWND,
    dpi: u32,
    font: HFONT,
    images: HIMAGELIST,
    accel: HACCEL,
}

thread_local! {
    static UI: Cell<Ui> = const {
        Cell::new(Ui {
            main: null_mut(),
            toolbar: null_mut(),
            list: null_mut(),
            status: null_mut(),
            dpi: 96,
            font: null_mut(),
            images: 0,
            accel: null_mut(),
        })
    };
    static ENTRIES: RefCell<Vec<Entry>> = const { RefCell::new(Vec::new()) };
    static INI: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
    static START_PLACEMENT: Cell<Option<Placement>> = const { Cell::new(None) };
}

fn ui() -> Ui {
    UI.with(|u| u.get())
}

fn update_ui(f: impl FnOnce(&mut Ui)) {
    UI.with(|u| {
        let mut v = u.get();
        f(&mut v);
        u.set(v);
    });
}

fn entries() -> Vec<Entry> {
    ENTRIES.with(|e| e.borrow().clone())
}

fn set_entries(v: Vec<Entry>) {
    ENTRIES.with(|e| *e.borrow_mut() = v);
}

pub(crate) fn wide(s: &str) -> Vec<u16> {
    sys::wide(s)
}

pub(crate) fn hinstance() -> HINSTANCE {
    unsafe { GetModuleHandleW(null()) }
}

fn scale(v: i32, dpi: u32) -> i32 {
    (v as i64 * dpi as i64 / 96) as i32
}

fn loword(v: usize) -> u16 {
    (v & 0xFFFF) as u16
}

fn hiword(v: usize) -> u16 {
    ((v >> 16) & 0xFFFF) as u16
}

fn exit(code: u32) -> ! {
    std::process::exit(as_process_code(code));
}

fn bring_to_front(hwnd: HWND) {
    unsafe {
        if IsIconic(hwnd) != 0 {
            ShowWindow(hwnd, SW_RESTORE);
        }
        SetForegroundWindow(hwnd);
    }
}

fn find_existing() -> HWND {
    let class = wide(CLASS_NAME);
    unsafe { FindWindowW(class.as_ptr(), null()) }
}

pub fn run() -> ! {
    unsafe {
        FreeConsole();
    }
    let tried = launch::take_elevation_marker();
    let existing = find_existing();
    if !existing.is_null() {
        bring_to_front(existing);
        exit(0);
    }
    if !sys::is_elevated() {
        match launch::relaunch_elevated(&[], tried) {
            Elevation::Started => exit(0),
            Elevation::Declined => exit(ERR_ELEVATION),
            Elevation::Refused => {
                launch::message_box(
                    null_mut(),
                    launch::NEEDS_ADMIN,
                    MB_ICONERROR | MB_SETFOREGROUND,
                );
                exit(ERR_ELEVATION);
            }
        }
    }
    unsafe {
        let name = wide(MUTEX_NAME);
        let mutex = CreateMutexW(null(), 1, name.as_ptr());
        if !mutex.is_null() && GetLastError() == ERROR_ALREADY_EXISTS {
            for _ in 0..30 {
                let w = find_existing();
                if !w.is_null() {
                    bring_to_front(w);
                    break;
                }
                sys::sleep_ms(100);
            }
            exit(0);
        }
        CoInitializeEx(null(), COINIT_APARTMENTTHREADED as u32);
        let icc = INITCOMMONCONTROLSEX {
            dwSize: core::mem::size_of::<INITCOMMONCONTROLSEX>() as u32,
            dwICC: ICC_BAR_CLASSES
                | ICC_LISTVIEW_CLASSES
                | ICC_STANDARD_CLASSES
                | ICC_WIN95_CLASSES,
        };
        InitCommonControlsEx(&icc);
    }
    load_settings();
    let code = unsafe { main_loop() };
    exit(code);
}

fn load_settings() {
    let path = settings::default_path();
    let (list, placement) = match &path {
        None => (Vec::new(), None),
        Some(p) => match settings::load_from(p) {
            Loaded::Missing => (settings::examples(), None),
            Loaded::Damaged => (Vec::new(), None),
            Loaded::Ok(s) => (s.entries, s.placement),
        },
    };
    set_entries(list);
    START_PLACEMENT.with(|c| c.set(placement));
    INI.with(|i| *i.borrow_mut() = path);
}

fn current_placement() -> Option<Placement> {
    unsafe {
        let mut wp: WINDOWPLACEMENT = core::mem::zeroed();
        wp.length = core::mem::size_of::<WINDOWPLACEMENT>() as u32;
        if GetWindowPlacement(ui().main, &mut wp) == 0 {
            return None;
        }
        let r = wp.rcNormalPosition;
        if r.right <= r.left || r.bottom <= r.top {
            return None;
        }
        Some(Placement {
            left: r.left,
            top: r.top,
            right: r.right,
            bottom: r.bottom,
            maximized: wp.showCmd == SW_SHOWMAXIMIZED as u32 || IsZoomed(ui().main) != 0,
            dpi: GetDpiForWindow(ui().main),
        })
    }
}

fn save() {
    let path = INI.with(|i| i.borrow().clone());
    let Some(path) = path else {
        set_status("The list could not be saved: APPDATA is not set.");
        return;
    };
    let s = Settings {
        entries: entries(),
        placement: current_placement(),
    };
    if let Err(e) = settings::save_to(&path, &s) {
        set_status(&format!(
            "The list could not be saved to {}: {e}",
            path.display()
        ));
    }
}

pub(crate) fn set_status(text: &str) {
    let st = ui().status;
    if st.is_null() {
        return;
    }
    let w = wide(text);
    unsafe {
        SendMessageW(st, SB_SETTEXTW, 0, w.as_ptr() as LPARAM);
    }
}

unsafe fn main_loop() -> u32 {
    let hinst = hinstance();
    let class = wide(CLASS_NAME);
    let mut wc: WNDCLASSEXW = core::mem::zeroed();
    wc.cbSize = core::mem::size_of::<WNDCLASSEXW>() as u32;
    wc.lpfnWndProc = Some(wnd_proc);
    wc.hInstance = hinst;
    wc.hIcon = LoadImageW(
        hinst,
        1 as _,
        IMAGE_ICON,
        GetSystemMetrics(SM_CXICON),
        GetSystemMetrics(SM_CYICON),
        LR_DEFAULTCOLOR,
    ) as HICON;
    wc.hIconSm = LoadImageW(
        hinst,
        1 as _,
        IMAGE_ICON,
        GetSystemMetrics(SM_CXSMICON),
        GetSystemMetrics(SM_CYSMICON),
        LR_DEFAULTCOLOR,
    ) as HICON;
    wc.hCursor = LoadCursorW(null_mut(), IDC_ARROW);
    wc.hbrBackground = (COLOR_WINDOW + 1) as usize as HBRUSH;
    wc.lpszClassName = class.as_ptr();
    if RegisterClassExW(&wc) == 0 {
        return 1;
    }

    let dpi = GetDpiForSystem();
    let title = wide(launch::TITLE);
    let hwnd = CreateWindowExW(
        WS_EX_ACCEPTFILES,
        class.as_ptr(),
        title.as_ptr(),
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        scale(780, dpi),
        scale(460, dpi),
        null_mut(),
        build_menu(),
        hinst,
        null(),
    );
    if hwnd.is_null() {
        return 1;
    }

    if let Some(p) = START_PLACEMENT.with(|c| c.get()) {
        let rect = RECT {
            left: p.left,
            top: p.top,
            right: p.right,
            bottom: p.bottom,
        };
        if !MonitorFromRect(&rect, MONITOR_DEFAULTTONULL).is_null() {
            let mut wp: WINDOWPLACEMENT = core::mem::zeroed();
            wp.length = core::mem::size_of::<WINDOWPLACEMENT>() as u32;
            wp.showCmd = SW_HIDE as u32;
            wp.rcNormalPosition = rect;
            SetWindowPlacement(hwnd, &wp);
            let here = GetDpiForWindow(hwnd);
            if p.dpi != 0 && here != p.dpi {
                let s = p.scaled_to(here);
                wp.rcNormalPosition = RECT {
                    left: s.left,
                    top: s.top,
                    right: s.right,
                    bottom: s.bottom,
                };
                SetWindowPlacement(hwnd, &wp);
            }
        }
    }
    let maximized = START_PLACEMENT
        .with(|c| c.get())
        .map(|p| p.maximized)
        .unwrap_or(false);
    ShowWindow(hwnd, SW_HIDE);
    ShowWindow(
        hwnd,
        if maximized {
            SW_SHOWMAXIMIZED
        } else {
            SW_SHOWNORMAL
        },
    );
    UpdateWindow(hwnd);
    SetForegroundWindow(hwnd);

    let accels = [
        ACCEL {
            fVirt: FVIRTKEY | FCONTROL,
            key: VK_UP,
            cmd: IDM_UP,
        },
        ACCEL {
            fVirt: FVIRTKEY | FCONTROL,
            key: VK_DOWN,
            cmd: IDM_DOWN,
        },
        ACCEL {
            fVirt: FVIRTKEY,
            key: VK_DELETE,
            cmd: IDM_REMOVE,
        },
        ACCEL {
            fVirt: FVIRTKEY,
            key: VK_INSERT,
            cmd: IDM_ADD,
        },
        ACCEL {
            fVirt: FVIRTKEY,
            key: VK_F2,
            cmd: IDM_EDIT,
        },
    ];
    let accel = CreateAcceleratorTableW(accels.as_ptr(), accels.len() as i32);
    update_ui(|u| u.accel = accel);

    let mut msg: MSG = core::mem::zeroed();
    while GetMessageW(&mut msg, null_mut(), 0, 0) > 0 {
        if TranslateAcceleratorW(hwnd, accel, &msg) == 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    0
}

unsafe fn append(menu: HMENU, id: u16, text: &str) {
    let w = wide(text);
    AppendMenuW(menu, MF_STRING, id as usize, w.as_ptr());
}

unsafe fn build_menu() -> HMENU {
    let bar = CreateMenu();
    let file = CreatePopupMenu();
    append(file, IDM_RUN, "&Run\tEnter");
    append(file, IDM_ADD, "&Add...\tIns");
    append(file, IDM_REMOVE, "Re&move\tDel");
    AppendMenuW(file, MF_SEPARATOR, 0, null());
    append(file, IDM_EXIT, "E&xit");
    let edit = CreatePopupMenu();
    append(edit, IDM_EDIT, "&Edit...\tF2");
    append(edit, IDM_UP, "Move &Up\tCtrl+Up");
    append(edit, IDM_DOWN, "Move &Down\tCtrl+Down");
    let options = CreatePopupMenu();
    append(
        options,
        IDM_SHELL,
        "Add the &TrustedInstaller entries to the Explorer right-click menu",
    );
    let help = CreatePopupMenu();
    append(help, IDM_USAGE, "&Command line usage");
    append(help, IDM_ABOUT, "&About XSudo");
    for (menu, text) in [
        (file, "&File"),
        (edit, "&Edit"),
        (options, "&Options"),
        (help, "&Help"),
    ] {
        let w = wide(text);
        AppendMenuW(bar, MF_POPUP, menu as usize, w.as_ptr());
    }
    bar
}

unsafe fn make_font(dpi: u32) -> HFONT {
    let mut ncm: NONCLIENTMETRICSW = core::mem::zeroed();
    ncm.cbSize = core::mem::size_of::<NONCLIENTMETRICSW>() as u32;
    if SystemParametersInfoForDpi(
        SPI_GETNONCLIENTMETRICS,
        ncm.cbSize,
        &mut ncm as *mut _ as *mut core::ffi::c_void,
        0,
        dpi,
    ) == 0
    {
        return null_mut();
    }
    CreateFontIndirectW(&ncm.lfMessageFont)
}

const TOOLBAR_LABELS: [&str; 6] = [
    "Run",
    "Add",
    "Remove",
    "Edit",
    "Registry Editor as TrustedInstaller",
    "Command Prompt as TrustedInstaller",
];

unsafe fn create_toolbar(parent: HWND, dpi: u32) -> (HWND, HIMAGELIST) {
    let tb = CreateWindowExW(
        0,
        TOOLBARCLASSNAMEW,
        null(),
        WS_CHILD | WS_VISIBLE | TBSTYLE_FLAT | TBSTYLE_LIST | TBSTYLE_TOOLTIPS | CCS_TOP as u32,
        0,
        0,
        0,
        0,
        parent,
        ID_TOOLBAR as HMENU,
        hinstance(),
        null(),
    );
    SendMessageW(tb, TB_BUTTONSTRUCTSIZE, core::mem::size_of::<TBBUTTON>(), 0);
    SendMessageW(
        tb,
        TB_SETEXTENDEDSTYLE,
        0,
        TBSTYLE_EX_MIXEDBUTTONS as LPARAM,
    );
    let images = glyphs::toolbar_images(dpi);
    SendMessageW(tb, TB_SETIMAGELIST, 0, images);
    let mut strings: Vec<u16> = Vec::new();
    for label in TOOLBAR_LABELS {
        strings.extend(label.encode_utf16());
        strings.push(0);
    }
    strings.push(0);
    let first = SendMessageW(tb, TB_ADDSTRINGW, 0, strings.as_ptr() as LPARAM);
    let button = |image: i32, id: u16, text: isize| TBBUTTON {
        iBitmap: image,
        idCommand: id as i32,
        fsState: TBSTATE_ENABLED as u8,
        fsStyle: (BTNS_BUTTON | BTNS_AUTOSIZE) as u8,
        bReserved: [0; 6],
        dwData: 0,
        iString: first + text,
    };
    let sep = TBBUTTON {
        iBitmap: scale(6, dpi),
        idCommand: 0,
        fsState: 0,
        fsStyle: BTNS_SEP as u8,
        bReserved: [0; 6],
        dwData: 0,
        iString: 0,
    };
    let buttons = [
        button(0, IDM_RUN, 0),
        button(1, IDM_ADD, 1),
        button(2, IDM_REMOVE, 2),
        button(3, IDM_EDIT, 3),
        sep,
        button(4, IDM_REGEDIT, 4),
        button(5, IDM_CMD, 5),
    ];
    SendMessageW(
        tb,
        TB_ADDBUTTONSW,
        buttons.len(),
        buttons.as_ptr() as LPARAM,
    );
    SendMessageW(tb, TB_AUTOSIZE, 0, 0);
    (tb, images)
}

const COLUMNS: [(&str, i32); 4] = [
    ("File", 260),
    ("Parameters", 200),
    ("Start directory", 170),
    ("Window", 90),
];

unsafe fn create_children(hwnd: HWND) {
    let dpi = GetDpiForWindow(hwnd);
    let font = make_font(dpi);
    let (toolbar, images) = create_toolbar(hwnd, dpi);
    let list = CreateWindowExW(
        0,
        WC_LISTVIEWW,
        null(),
        WS_CHILD
            | WS_VISIBLE
            | WS_TABSTOP
            | LVS_REPORT
            | LVS_SHOWSELALWAYS
            | LVS_SINGLESEL
            | LVS_SHAREIMAGELISTS,
        0,
        0,
        0,
        0,
        hwnd,
        ID_LIST as HMENU,
        hinstance(),
        null(),
    );
    let explorer = wide("Explorer");
    SetWindowTheme(list, explorer.as_ptr(), null());
    let ex = LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP;
    SendMessageW(
        list,
        LVM_SETEXTENDEDLISTVIEWSTYLE,
        ex as WPARAM,
        ex as LPARAM,
    );
    SendMessageW(list, WM_SETFONT, font as WPARAM, 0);
    for (i, (name, width)) in COLUMNS.iter().enumerate() {
        let mut text = wide(name);
        let mut col: LVCOLUMNW = core::mem::zeroed();
        col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        col.cx = scale(*width, dpi);
        col.pszText = text.as_mut_ptr();
        col.iSubItem = i as i32;
        SendMessageW(list, LVM_INSERTCOLUMNW, i, &col as *const _ as LPARAM);
    }
    let mut sfi: SHFILEINFOW = core::mem::zeroed();
    let root = wide("C:\\");
    let sys_small = SHGetFileInfoW(
        root.as_ptr(),
        0,
        &mut sfi,
        core::mem::size_of::<SHFILEINFOW>() as u32,
        SHGFI_SYSICONINDEX | SHGFI_SMALLICON,
    );
    SendMessageW(
        list,
        LVM_SETIMAGELIST,
        LVSIL_SMALL as WPARAM,
        sys_small as LPARAM,
    );

    let status = CreateWindowExW(
        0,
        STATUSCLASSNAMEW,
        null(),
        WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
        0,
        0,
        0,
        0,
        hwnd,
        ID_STATUS as HMENU,
        hinstance(),
        null(),
    );
    SendMessageW(status, WM_SETFONT, font as WPARAM, 0);

    update_ui(|u| {
        u.main = hwnd;
        u.toolbar = toolbar;
        u.list = list;
        u.status = status;
        u.dpi = dpi;
        u.font = font;
        u.images = images;
    });

    DragAcceptFiles(hwnd, 1);
    for m in [WM_DROPFILES, WM_COPYDATA, WM_COPYGLOBALDATA] {
        ChangeWindowMessageFilterEx(hwnd, m, MSGFLT_ALLOW, null_mut());
    }

    refill(if entries().is_empty() { None } else { Some(0) });
    set_status("Ready. Programs in this list run as TrustedInstaller.");
}

unsafe fn layout() {
    let u = ui();
    if u.list.is_null() {
        return;
    }
    let mut rc: RECT = core::mem::zeroed();
    GetClientRect(u.main, &mut rc);
    SendMessageW(u.toolbar, TB_AUTOSIZE, 0, 0);
    SendMessageW(u.status, WM_SIZE, 0, 0);
    let mut tr: RECT = core::mem::zeroed();
    let mut sr: RECT = core::mem::zeroed();
    GetWindowRect(u.toolbar, &mut tr);
    GetWindowRect(u.status, &mut sr);
    let top = tr.bottom - tr.top;
    let bottom = sr.bottom - sr.top;
    let height = (rc.bottom - top - bottom).max(0);
    MoveWindow(u.list, 0, top, rc.right, height, 1);
}

fn icon_index(file: &str) -> i32 {
    unsafe {
        let mut sfi: SHFILEINFOW = core::mem::zeroed();
        let size = core::mem::size_of::<SHFILEINFOW>() as u32;
        match launch::resolve_file(file) {
            Ok(path) => {
                let w = wide(&path);
                SHGetFileInfoW(
                    w.as_ptr(),
                    0,
                    &mut sfi,
                    size,
                    SHGFI_SYSICONINDEX | SHGFI_SMALLICON,
                );
            }
            Err(_) => {
                let w = wide(&launch::expand_env(file));
                SHGetFileInfoW(
                    w.as_ptr(),
                    FILE_ATTRIBUTE_NORMAL,
                    &mut sfi,
                    size,
                    SHGFI_SYSICONINDEX | SHGFI_SMALLICON | SHGFI_USEFILEATTRIBUTES,
                );
            }
        }
        sfi.iIcon
    }
}

fn refill(select: Option<usize>) {
    let list = ui().list;
    let items = entries();
    unsafe {
        SendMessageW(list, LVM_DELETEALLITEMS, 0, 0);
        for (i, e) in items.iter().enumerate() {
            let mut text = wide(&e.file);
            let mut item: LVITEMW = core::mem::zeroed();
            item.mask = LVIF_TEXT | LVIF_IMAGE;
            item.iItem = i as i32;
            item.pszText = text.as_mut_ptr();
            item.iImage = icon_index(&e.file);
            let idx = SendMessageW(list, LVM_INSERTITEMW, 0, &item as *const _ as LPARAM);
            if idx < 0 {
                continue;
            }
            for (sub, value) in [
                (1, &e.params),
                (2, &e.start_dir),
                (3, &e.show.name().to_string()),
            ] {
                let mut t = wide(value);
                let mut si: LVITEMW = core::mem::zeroed();
                si.iSubItem = sub;
                si.pszText = t.as_mut_ptr();
                SendMessageW(
                    list,
                    LVM_SETITEMTEXTW,
                    idx as WPARAM,
                    &si as *const _ as LPARAM,
                );
            }
        }
        if let Some(s) = select {
            if s < items.len() {
                let mut st: LVITEMW = core::mem::zeroed();
                st.stateMask = LVIS_SELECTED | LVIS_FOCUSED;
                st.state = LVIS_SELECTED | LVIS_FOCUSED;
                SendMessageW(list, LVM_SETITEMSTATE, s, &st as *const _ as LPARAM);
                SendMessageW(list, LVM_ENSUREVISIBLE, s, 0);
            }
        }
    }
    update_commands();
}

fn selected() -> Option<usize> {
    let list = ui().list;
    if list.is_null() {
        return None;
    }
    let i = unsafe { SendMessageW(list, LVM_GETNEXTITEM, usize::MAX, LVNI_SELECTED as LPARAM) };
    let n = ENTRIES.with(|e| e.borrow().len());
    if i >= 0 && (i as usize) < n {
        Some(i as usize)
    } else {
        None
    }
}

fn update_commands() {
    let u = ui();
    let sel = selected().is_some();
    unsafe {
        for id in [IDM_RUN, IDM_REMOVE, IDM_EDIT] {
            SendMessageW(u.toolbar, TB_ENABLEBUTTON, id as WPARAM, sel as LPARAM);
        }
    }
}

pub(crate) fn run_entry(e: Entry) {
    let name = launch::file_name(&e.file).to_string();
    set_status(&format!("Starting {name} as TrustedInstaller..."));
    let target = ui().main as isize;
    std::thread::spawn(move || {
        let result = launch::launch(&e.file, &e.params, &e.start_dir, e.show);
        let done = Box::new((name, result));
        let p = Box::into_raw(done);
        unsafe {
            if PostMessageW(target as HWND, WM_LAUNCHED, 0, p as LPARAM) == 0 {
                drop(Box::from_raw(p));
            }
        }
    });
}

fn on_launched(lparam: LPARAM) {
    let done =
        unsafe { Box::from_raw(lparam as *mut (String, Result<launch::Started, launch::Failure>)) };
    let (name, result) = *done;
    match result {
        Ok(s) => set_status(&format!(
            "Started {} as TrustedInstaller (PID {}).",
            launch::file_name(&s.file),
            s.pid
        )),
        Err(f) => {
            let first = f
                .summary
                .lines()
                .next()
                .unwrap_or("")
                .trim_end_matches(':')
                .to_string();
            set_status(&format!("{name} was not started: {first}"));
            let owner = dialogs::open_dialog().unwrap_or(ui().main);
            launch::show_failure(owner, &f);
        }
    }
}

fn add_entry() {
    if let Some(e) = dialogs::edit(ui().main, Entry::new(""), "Add program") {
        let mut v = entries();
        v.push(e);
        let last = v.len() - 1;
        set_entries(v);
        refill(Some(last));
        save();
        set_status("Program added.");
    }
}

fn edit_entry() {
    let Some(i) = selected() else { return };
    let current = entries()[i].clone();
    if let Some(e) = dialogs::edit(ui().main, current, "Edit program") {
        let mut v = entries();
        if i < v.len() {
            v[i] = e;
        }
        set_entries(v);
        refill(Some(i));
        save();
        set_status("Program saved.");
    }
}

fn remove_entry() {
    let Some(i) = selected() else { return };
    let file = entries()[i].file.clone();
    let answer = launch::message_box(
        ui().main,
        &format!("Remove this program from the list?\n\n{file}"),
        MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2,
    );
    if answer != IDYES {
        return;
    }
    let mut v = entries();
    if i < v.len() {
        v.remove(i);
    }
    let n = v.len();
    set_entries(v);
    refill(if n == 0 { None } else { Some(i.min(n - 1)) });
    save();
    set_status("Program removed.");
}

fn move_entry(up: bool) {
    let Some(i) = selected() else { return };
    let mut v = entries();
    let j = if up {
        if i == 0 {
            return;
        }
        i - 1
    } else {
        if i + 1 >= v.len() {
            return;
        }
        i + 1
    };
    v.swap(i, j);
    set_entries(v);
    refill(Some(j));
    save();
}

fn run_selected() {
    if let Some(i) = selected() {
        run_entry(entries()[i].clone());
    }
}

fn run_builtin(file: &str) {
    run_entry(Entry {
        file: file.to_string(),
        params: String::new(),
        start_dir: "%SystemRoot%\\System32".to_string(),
        show: Show::Normal,
    });
}

fn toggle_shell_menu() {
    let exe = launch::self_path();
    let owner = ui().main;
    let on = !shellmenu::is_enabled(&exe);
    match shellmenu::apply(on, &exe) {
        Ok(()) => set_status(if on {
            "Explorer now shows Run, Import and Open as TrustedInstaller."
        } else {
            shellmenu::REMOVED
        }),
        Err(e) => {
            let summary = if on {
                shellmenu::ADD_FAILED
            } else {
                shellmenu::REMOVE_FAILED
            };
            set_status(summary);
            let f = launch::Failure {
                code: crate::exitcode::ERR_CHILD,
                win32: e,
                summary: summary.into(),
            };
            launch::message_box(
                owner,
                &launch::failure_text(&f, &launch::windows_error_text(e)),
                MB_ICONERROR,
            );
        }
    }
}

fn about() {
    let text = format!(
        "{}\nRuns programs as TrustedInstaller, from this window or from the command line.\n\n{}\nLicensed under CC BY-NC-ND 4.0 (Creative Commons Attribution-NonCommercial-NoDerivatives 4.0 International).",
        crate::VERSION_LINE,
        crate::COPYRIGHT_LINE
    );
    launch::message_box(ui().main, &text, MB_OK | MB_ICONINFORMATION);
}

fn usage() {
    let text = format!(
        "{}\n{}\n{}",
        crate::VERSION_LINE,
        crate::COPYRIGHT_LINE,
        crate::HELP_TEXT
    );
    dialogs::text(ui().main, &text);
}

fn add_dropped(hdrop: HDROP) {
    unsafe {
        let count = DragQueryFileW(hdrop, u32::MAX, null_mut(), 0);
        let mut v = entries();
        let mut added = 0;
        for i in 0..count {
            let len = DragQueryFileW(hdrop, i, null_mut(), 0);
            let mut buf = vec![0u16; len as usize + 1];
            let n = DragQueryFileW(hdrop, i, buf.as_mut_ptr(), buf.len() as u32);
            let path = String::from_utf16_lossy(&buf[..n as usize]);
            if std::path::Path::new(&path).is_file() {
                v.push(Entry::new(&path));
                added += 1;
            }
        }
        DragFinish(hdrop);
        if added > 0 {
            let last = v.len() - 1;
            set_entries(v);
            refill(Some(last));
            save();
            set_status(&format!("{added} program(s) added."));
        }
    }
}

fn on_command(id: u16) {
    match id {
        IDM_RUN => run_selected(),
        IDM_ADD => add_entry(),
        IDM_REMOVE => remove_entry(),
        IDM_EXIT => unsafe {
            SendMessageW(ui().main, WM_CLOSE, 0, 0);
        },
        IDM_EDIT => edit_entry(),
        IDM_UP => move_entry(true),
        IDM_DOWN => move_entry(false),
        IDM_SHELL => toggle_shell_menu(),
        IDM_USAGE => usage(),
        IDM_ABOUT => about(),
        IDM_REGEDIT => run_builtin("%SystemRoot%\\regedit.exe"),
        IDM_CMD => run_builtin("%SystemRoot%\\System32\\cmd.exe"),
        _ => {}
    }
}

unsafe fn on_init_menu(menu: HMENU) {
    let sel = selected();
    let n = ENTRIES.with(|e| e.borrow().len());
    let flag = |on: bool| {
        if on {
            MF_BYCOMMAND | MF_ENABLED
        } else {
            MF_BYCOMMAND | MF_GRAYED
        }
    };
    EnableMenuItem(menu, IDM_RUN as u32, flag(sel.is_some()));
    EnableMenuItem(menu, IDM_REMOVE as u32, flag(sel.is_some()));
    EnableMenuItem(menu, IDM_EDIT as u32, flag(sel.is_some()));
    EnableMenuItem(menu, IDM_UP as u32, flag(matches!(sel, Some(i) if i > 0)));
    EnableMenuItem(
        menu,
        IDM_DOWN as u32,
        flag(matches!(sel, Some(i) if i + 1 < n)),
    );
    let on = shellmenu::is_enabled(&launch::self_path());
    CheckMenuItem(
        menu,
        IDM_SHELL as u32,
        MF_BYCOMMAND | if on { MF_CHECKED } else { MF_UNCHECKED },
    );
}

unsafe fn on_dpi_changed(hwnd: HWND, dpi: u32, suggested: *const RECT) {
    let old = ui();
    let font = make_font(dpi);
    SendMessageW(old.list, WM_SETFONT, font as WPARAM, 1);
    SendMessageW(old.status, WM_SETFONT, font as WPARAM, 1);
    for i in 0..COLUMNS.len() {
        let w = SendMessageW(old.list, LVM_GETCOLUMNWIDTH, i, 0) as i32;
        let nw = (w as i64 * dpi as i64 / old.dpi.max(1) as i64) as i32;
        SendMessageW(old.list, LVM_SETCOLUMNWIDTH, i, nw as LPARAM);
    }
    DestroyWindow(old.toolbar);
    if old.images != 0 {
        ImageList_Destroy(old.images);
    }
    if !old.font.is_null() {
        DeleteObject(old.font);
    }
    let (toolbar, images) = create_toolbar(hwnd, dpi);
    update_ui(|u| {
        u.toolbar = toolbar;
        u.images = images;
        u.font = font;
        u.dpi = dpi;
    });
    update_commands();
    if !suggested.is_null() {
        let r = *suggested;
        SetWindowPos(
            hwnd,
            null_mut(),
            r.left,
            r.top,
            r.right - r.left,
            r.bottom - r.top,
            SWP_NOZORDER | SWP_NOACTIVATE,
        );
    }
    layout();
}

unsafe extern "system" fn wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_CREATE => {
            update_ui(|u| u.main = hwnd);
            create_children(hwnd);
            0
        }
        WM_SIZE => {
            layout();
            0
        }
        WM_SETFOCUS => {
            let list = ui().list;
            if !list.is_null() {
                SetFocus(list);
            }
            0
        }
        WM_GETMINMAXINFO => {
            let dpi = GetDpiForWindow(hwnd).max(96);
            let mmi = lparam as *mut MINMAXINFO;
            (*mmi).ptMinTrackSize.x = scale(460, dpi);
            (*mmi).ptMinTrackSize.y = scale(260, dpi);
            0
        }
        WM_COMMAND => {
            on_command(loword(wparam));
            0
        }
        WM_NOTIFY => {
            let hdr = &*(lparam as *const NMHDR);
            if hdr.idFrom == ID_LIST {
                match hdr.code {
                    NM_DBLCLK | NM_RETURN => run_selected(),
                    LVN_ITEMCHANGED => update_commands(),
                    _ => {}
                }
            }
            0
        }
        WM_INITMENUPOPUP => {
            on_init_menu(wparam as HMENU);
            0
        }
        WM_DROPFILES => {
            add_dropped(wparam as HDROP);
            0
        }
        WM_LAUNCHED => {
            on_launched(lparam);
            0
        }
        WM_DPICHANGED => {
            on_dpi_changed(hwnd, hiword(wparam) as u32, lparam as *const RECT);
            0
        }
        WM_CLOSE => {
            save();
            DestroyWindow(hwnd);
            0
        }
        WM_DESTROY => {
            PostQuitMessage(0);
            0
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

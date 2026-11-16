use core::ptr::null_mut;

use windows_sys::Win32::Foundation::RECT;
use windows_sys::Win32::Graphics::Gdi::*;
use windows_sys::Win32::UI::Controls::ImageList_Add;
use windows_sys::Win32::UI::Controls::ImageList_Create;
use windows_sys::Win32::UI::Controls::HIMAGELIST;
use windows_sys::Win32::UI::Controls::ILC_COLOR32;

use super::wide;

const RUN: u16 = 0xE768;
const ADD: u16 = 0xE710;
const REMOVE: u16 = 0xE74D;
const EDIT: u16 = 0xE70F;
const REGISTRY: u16 = 0xE8D7;
const PROMPT: u16 = 0xE756;

fn rgb(r: u32, g: u32, b: u32) -> u32 {
    r | (g << 8) | (b << 16)
}

unsafe fn icon_font(dc: HDC, size: i32) -> HFONT {
    for face in ["Segoe Fluent Icons", "Segoe MDL2 Assets"] {
        let name = wide(face);
        let font = CreateFontW(
            -size,
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
            ANTIALIASED_QUALITY as u32,
            DEFAULT_PITCH as u32,
            name.as_ptr(),
        );
        if font.is_null() {
            continue;
        }
        let old = SelectObject(dc, font);
        let mut got = [0u16; 64];
        let n = GetTextFaceW(dc, got.len() as i32, got.as_mut_ptr());
        SelectObject(dc, old);
        let actual = String::from_utf16_lossy(&got[..(n.max(1) as usize - 1).min(got.len())]);
        if actual.eq_ignore_ascii_case(face) {
            return font;
        }
        DeleteObject(font);
    }
    null_mut()
}

pub(super) unsafe fn toolbar_images(dpi: u32) -> HIMAGELIST {
    let size = ((16 * dpi + 48) / 96).max(16) as i32;
    let text = GetSysColor(COLOR_BTNTEXT);
    let items = [
        (RUN, rgb(16, 124, 16)),
        (ADD, text),
        (REMOVE, rgb(196, 43, 28)),
        (EDIT, text),
        (REGISTRY, rgb(0, 95, 184)),
        (PROMPT, text),
    ];
    let list = ImageList_Create(size, size, ILC_COLOR32, items.len() as i32, 0);
    let screen = GetDC(null_mut());
    let dc = CreateCompatibleDC(screen);
    ReleaseDC(null_mut(), screen);
    let font = icon_font(dc, size);
    for (glyph, color) in items {
        let mut bmi: BITMAPINFO = core::mem::zeroed();
        bmi.bmiHeader.biSize = core::mem::size_of::<BITMAPINFOHEADER>() as u32;
        bmi.bmiHeader.biWidth = size;
        bmi.bmiHeader.biHeight = -size;
        bmi.bmiHeader.biPlanes = 1;
        bmi.bmiHeader.biBitCount = 32;
        bmi.bmiHeader.biCompression = BI_RGB;
        let mut bits: *mut core::ffi::c_void = null_mut();
        let dib = CreateDIBSection(dc, &bmi, DIB_RGB_COLORS, &mut bits, null_mut(), 0);
        if dib.is_null() || bits.is_null() {
            continue;
        }
        let count = (size * size) as usize;
        core::ptr::write_bytes(bits as *mut u32, 0, count);
        if !font.is_null() {
            let old_bmp = SelectObject(dc, dib);
            let old_font = SelectObject(dc, font);
            SetBkMode(dc, TRANSPARENT as i32);
            SetTextColor(dc, rgb(255, 255, 255));
            let mut rc = RECT {
                left: 0,
                top: 0,
                right: size,
                bottom: size,
            };
            let g = [glyph];
            DrawTextW(
                dc,
                g.as_ptr(),
                1,
                &mut rc,
                DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX,
            );
            GdiFlush();
            SelectObject(dc, old_font);
            SelectObject(dc, old_bmp);
        }
        let px = core::slice::from_raw_parts_mut(bits as *mut u32, count);
        let (r, g, b) = (color & 0xFF, (color >> 8) & 0xFF, (color >> 16) & 0xFF);
        for p in px.iter_mut() {
            let a = (*p & 0xFF).max((*p >> 8) & 0xFF).max((*p >> 16) & 0xFF);
            *p = (a << 24) | ((r * a / 255) << 16) | ((g * a / 255) << 8) | (b * a / 255);
        }
        ImageList_Add(list, dib, null_mut());
        DeleteObject(dib);
    }
    if !font.is_null() {
        DeleteObject(font);
    }
    DeleteDC(dc);
    list
}

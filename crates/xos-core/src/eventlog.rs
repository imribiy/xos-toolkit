use std::collections::HashMap;
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::System::EventLog::*;

#[derive(Clone, Debug)]
pub struct EventRecord {
    pub time_created: Option<chrono::DateTime<chrono::Local>>,
    pub provider: String,
    pub event_id: u32,
    pub level: u8,
    pub description: Option<String>,
    pub properties: Option<Vec<String>>,
}

unsafe fn variant_text(v: &EVT_VARIANT) -> String {
    let t = v.Type & 0x7F;
    let a = &v.Anonymous;
    match t {
        x if x == EvtVarTypeString.0 as u32 => {
            if a.StringVal.is_null() {
                String::new()
            } else {
                a.StringVal.to_string().unwrap_or_default()
            }
        }
        x if x == EvtVarTypeAnsiString.0 as u32 => {
            if a.AnsiStringVal.is_null() {
                String::new()
            } else {
                std::ffi::CStr::from_ptr(a.AnsiStringVal.0 as *const std::ffi::c_char).to_string_lossy().into_owned()
            }
        }
        x if x == EvtVarTypeSByte.0 as u32 => a.SByteVal.to_string(),
        x if x == EvtVarTypeByte.0 as u32 => a.ByteVal.to_string(),
        x if x == EvtVarTypeInt16.0 as u32 => a.Int16Val.to_string(),
        x if x == EvtVarTypeUInt16.0 as u32 => a.UInt16Val.to_string(),
        x if x == EvtVarTypeInt32.0 as u32 => a.Int32Val.to_string(),
        x if x == EvtVarTypeUInt32.0 as u32 => a.UInt32Val.to_string(),
        x if x == EvtVarTypeHexInt32.0 as u32 => a.UInt32Val.to_string(),
        x if x == EvtVarTypeInt64.0 as u32 => a.Int64Val.to_string(),
        x if x == EvtVarTypeUInt64.0 as u32 => a.UInt64Val.to_string(),
        x if x == EvtVarTypeHexInt64.0 as u32 => a.UInt64Val.to_string(),
        x if x == EvtVarTypeSingle.0 as u32 => a.SingleVal.to_string(),
        x if x == EvtVarTypeDouble.0 as u32 => a.DoubleVal.to_string(),
        x if x == EvtVarTypeBoolean.0 as u32 => if a.BooleanVal.as_bool() { "True".into() } else { "False".into() },
        x if x == EvtVarTypeBinary.0 as u32 => "System.Byte[]".into(),
        x if x == EvtVarTypeFileTime.0 as u32 => filetime_to_local(a.FileTimeVal)
            .map(|d| d.format("%m/%d/%Y %H:%M:%S").to_string())
            .unwrap_or_default(),
        x if x == EvtVarTypeGuid.0 as u32 => {
            if a.GuidVal.is_null() {
                String::new()
            } else {
                let g = *a.GuidVal;
                format!(
                    "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                    g.data1, g.data2, g.data3, g.data4[0], g.data4[1], g.data4[2], g.data4[3], g.data4[4], g.data4[5], g.data4[6], g.data4[7]
                )
            }
        }
        x if x == EvtVarTypeSid.0 as u32 => {
            if a.SidVal.is_invalid() {
                String::new()
            } else {
                let mut s = windows::core::PWSTR::null();
                if windows::Win32::Security::Authorization::ConvertSidToStringSidW(a.SidVal, &mut s).is_ok() {
                    let out = s.to_string().unwrap_or_default();
                    let _ = windows::Win32::Foundation::LocalFree(Some(windows::Win32::Foundation::HLOCAL(s.0 as *mut _)));
                    out
                } else {
                    String::new()
                }
            }
        }
        _ => String::new(),
    }
}

unsafe fn render_user_properties(ctx: EVT_HANDLE, event: EVT_HANDLE) -> Option<Vec<String>> {
    let mut used = 0u32;
    let mut count = 0u32;
    let _ = EvtRender(Some(ctx), event, EvtRenderEventValues.0, 0, None, &mut used, &mut count);
    if used == 0 {
        return Some(Vec::new());
    }
    let mut buf = vec![0u8; used as usize + 16];
    EvtRender(Some(ctx), event, EvtRenderEventValues.0, buf.len() as u32, Some(buf.as_mut_ptr() as *mut _), &mut used, &mut count).ok()?;
    let vals = std::slice::from_raw_parts(buf.as_ptr() as *const EVT_VARIANT, count as usize);
    Some(vals.iter().map(|v| variant_text(v)).collect())
}

struct Handle(EVT_HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = EvtClose(self.0);
            }
        }
    }
}

fn filetime_to_local(ft: u64) -> Option<chrono::DateTime<chrono::Local>> {
    if ft == 0 {
        return None;
    }
    let secs = (ft / 10_000_000) as i64 - 11_644_473_600;
    let nanos = ((ft % 10_000_000) * 100) as u32;
    chrono::DateTime::from_timestamp(secs, nanos).map(|d| d.with_timezone(&chrono::Local))
}

unsafe fn render_system(ctx: EVT_HANDLE, event: EVT_HANDLE) -> Option<(String, u32, u8, u64)> {
    let mut used = 0u32;
    let mut count = 0u32;
    let _ = EvtRender(Some(ctx), event, EvtRenderEventValues.0, 0, None, &mut used, &mut count);
    if used == 0 {
        return None;
    }
    let mut buf = vec![0u8; used as usize + 16];
    EvtRender(Some(ctx), event, EvtRenderEventValues.0, buf.len() as u32, Some(buf.as_mut_ptr() as *mut _), &mut used, &mut count).ok()?;
    let vals = std::slice::from_raw_parts(buf.as_ptr() as *const EVT_VARIANT, count as usize);
    let provider = {
        let v = &vals[EvtSystemProviderName.0 as usize];
        if v.Type == EvtVarTypeString.0 as u32 && !v.Anonymous.StringVal.is_null() {
            v.Anonymous.StringVal.to_string().unwrap_or_default()
        } else {
            String::new()
        }
    };
    let id = {
        let v = &vals[EvtSystemEventID.0 as usize];
        v.Anonymous.UInt16Val as u32
    };
    let level = {
        let v = &vals[EvtSystemLevel.0 as usize];
        if v.Type == EvtVarTypeByte.0 as u32 {
            v.Anonymous.ByteVal
        } else {
            0
        }
    };
    let time = {
        let v = &vals[EvtSystemTimeCreated.0 as usize];
        if v.Type == EvtVarTypeFileTime.0 as u32 {
            v.Anonymous.FileTimeVal
        } else {
            0
        }
    };
    Some((provider, id, level, time))
}

unsafe fn format_description(publisher: EVT_HANDLE, event: EVT_HANDLE) -> Option<String> {
    let mut used = 0u32;
    let _ = EvtFormatMessage(Some(publisher), Some(event), 0, None, EvtFormatMessageEvent.0, None, &mut used);
    if used == 0 {
        return None;
    }
    let mut buf = vec![0u16; used as usize + 1];
    if EvtFormatMessage(Some(publisher), Some(event), 0, None, EvtFormatMessageEvent.0, Some(&mut buf), &mut used).is_err() {
        return None;
    }
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    Some(String::from_utf16_lossy(&buf[..end]))
}

pub fn query(log_name: &str, xpath: &str, reverse: bool, limit: usize, with_description: bool) -> windows::core::Result<Vec<EventRecord>> {
    let mut out = Vec::new();
    unsafe {
        let mut flags = EvtQueryChannelPath.0 | EvtQueryTolerateQueryErrors.0;
        if reverse {
            flags |= EvtQueryReverseDirection.0;
        }
        let q = Handle(EvtQuery(None, &HSTRING::from(log_name), &HSTRING::from(xpath), flags)?);
        let ctx = Handle(EvtCreateRenderContext(None, EvtRenderContextSystem.0)?);
        let user_ctx = Handle(EvtCreateRenderContext(None, EvtRenderContextUser.0)?);
        let mut publishers: HashMap<String, Option<Handle>> = HashMap::new();
        'outer: loop {
            let mut events = [0isize; 64];
            let mut returned = 0u32;
            if EvtNext(q.0, &mut events, 2000, 0, &mut returned).is_err() || returned == 0 {
                break;
            }
            for raw in events.iter().take(returned as usize) {
                let ev = Handle(EVT_HANDLE(*raw));
                if out.len() >= limit {
                    continue;
                }
                let Some((provider, id, level, time)) = render_system(ctx.0, ev.0) else { continue };
                let description = if with_description {
                    let entry = publishers.entry(provider.clone()).or_insert_with(|| {
                        EvtOpenPublisherMetadata(None, &HSTRING::from(provider.as_str()), PCWSTR::null(), 0, 0).ok().map(Handle)
                    });
                    match entry {
                        Some(h) => format_description(h.0, ev.0),
                        None => None,
                    }
                } else {
                    None
                };
                let properties = if with_description && description.as_deref().map(|d| d.trim().is_empty()).unwrap_or(true) {
                    render_user_properties(user_ctx.0, ev.0)
                } else {
                    None
                };
                out.push(EventRecord { time_created: filetime_to_local(time), provider, event_id: id, level, description, properties });
            }
            if out.len() >= limit {
                break 'outer;
            }
        }
    }
    Ok(out)
}

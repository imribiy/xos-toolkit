use std::mem::ManuallyDrop;

use windows::core::{BSTR, GUID};
use windows::Win32::Foundation::VARIANT_BOOL;
use windows::Win32::System::Com::{
    CLSIDFromProgID, CoCreateInstance, CoInitializeEx, IDispatch, CLSCTX_ALL,
    COINIT_APARTMENTTHREADED, DISPATCH_FLAGS, DISPATCH_METHOD, DISPATCH_PROPERTYGET, DISPPARAMS,
};
use windows::Win32::System::Variant::{
    VariantClear, VARIANT, VARIANT_0, VARIANT_0_0, VARIANT_0_0_0, VT_BOOL, VT_BSTR, VT_DISPATCH,
    VT_I4,
};

use crate::ops::track;
use crate::util::{pcwstr, wide};
use xos_core::log;

const QUICK_ACCESS_NS: &str = "shell:::{679f85cb-0220-4080-b29b-5540cc05aab6}";

struct Disp(IDispatch);

enum Arg<'a> {
    Str(&'a str),
    Int(i32),
}

struct Var(VARIANT);

impl Var {
    fn empty() -> Var {
        Var(VARIANT::default())
    }

    fn from_str(s: &str) -> Var {
        Var(VARIANT {
            Anonymous: VARIANT_0 {
                Anonymous: ManuallyDrop::new(VARIANT_0_0 {
                    vt: VT_BSTR,
                    wReserved1: 0,
                    wReserved2: 0,
                    wReserved3: 0,
                    Anonymous: VARIANT_0_0_0 {
                        bstrVal: ManuallyDrop::new(BSTR::from(s)),
                    },
                }),
            },
        })
    }

    fn from_i32(i: i32) -> Var {
        Var(VARIANT {
            Anonymous: VARIANT_0 {
                Anonymous: ManuallyDrop::new(VARIANT_0_0 {
                    vt: VT_I4,
                    wReserved1: 0,
                    wReserved2: 0,
                    wReserved3: 0,
                    Anonymous: VARIANT_0_0_0 { lVal: i },
                }),
            },
        })
    }

    fn vt(&self) -> u16 {
        unsafe { self.0.Anonymous.Anonymous.vt.0 }
    }

    fn as_string(&self) -> String {
        if self.vt() == VT_BSTR.0 {
            unsafe { (*self.0.Anonymous.Anonymous.Anonymous.bstrVal).to_string() }
        } else {
            String::new()
        }
    }

    fn as_bool(&self) -> bool {
        self.vt() == VT_BOOL.0
            && unsafe { self.0.Anonymous.Anonymous.Anonymous.boolVal } == VARIANT_BOOL(-1)
    }

    fn as_i32(&self) -> windows::core::Result<i32> {
        if self.vt() == VT_I4.0 {
            Ok(unsafe { self.0.Anonymous.Anonymous.Anonymous.lVal })
        } else {
            Err(windows::core::Error::empty())
        }
    }

    fn as_disp(&self) -> Option<Disp> {
        if self.vt() == VT_DISPATCH.0 {
            unsafe {
                (*self.0.Anonymous.Anonymous.Anonymous.pdispVal)
                    .clone()
                    .map(Disp)
            }
        } else {
            None
        }
    }
}

impl Drop for Var {
    fn drop(&mut self) {
        unsafe {
            let _ = VariantClear(&mut self.0);
        }
    }
}

impl Disp {
    fn invoke(
        &self,
        member: &str,
        flags: DISPATCH_FLAGS,
        args: &[Arg],
    ) -> windows::core::Result<Var> {
        unsafe {
            let name = wide(member);
            let names = [pcwstr(&name)];
            let mut id = 0i32;
            self.0
                .GetIDsOfNames(&GUID::zeroed(), names.as_ptr(), 1, 0, &mut id)?;
            let mut vars: Vec<Var> = args
                .iter()
                .rev()
                .map(|a| match a {
                    Arg::Str(s) => Var::from_str(s),
                    Arg::Int(i) => Var::from_i32(*i),
                })
                .collect();
            let params = DISPPARAMS {
                rgvarg: if vars.is_empty() {
                    std::ptr::null_mut()
                } else {
                    vars.as_mut_ptr() as *mut VARIANT
                },
                rgdispidNamedArgs: std::ptr::null_mut(),
                cArgs: vars.len() as u32,
                cNamedArgs: 0,
            };
            let mut result = Var::empty();
            self.0.Invoke(
                id,
                &GUID::zeroed(),
                0,
                flags,
                &params,
                Some(&mut result.0),
                None,
                None,
            )?;
            Ok(result)
        }
    }

    fn call(&self, member: &str, args: &[Arg]) -> windows::core::Result<Var> {
        self.invoke(member, DISPATCH_METHOD | DISPATCH_PROPERTYGET, args)
    }

    fn call_obj(&self, member: &str, args: &[Arg]) -> windows::core::Result<Option<Disp>> {
        let v = self.call(member, args)?;
        Ok(v.as_disp())
    }
}

fn shell_app() -> windows::core::Result<Disp> {
    unsafe {
        let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        let prog = wide("Shell.Application");
        let clsid = CLSIDFromProgID(pcwstr(&prog))?;
        let d: IDispatch = CoCreateInstance(&clsid, None, CLSCTX_ALL)?;
        Ok(Disp(d))
    }
}

fn trim_sep(s: &str) -> &str {
    s.trim_end_matches(['\\', '/'])
}

fn find_quick_access_item(folder_path: &str) -> windows::core::Result<Option<Disp>> {
    let shell = shell_app()?;
    let ns = shell.call_obj("NameSpace", &[Arg::Str(QUICK_ACCESS_NS)])?;
    let ns = match ns {
        Some(n) => n,
        None => return Ok(None),
    };
    let items = match ns.call_obj("Items", &[])? {
        Some(i) => i,
        None => return Ok(None),
    };
    let count = items.call("Count", &[])?.as_i32()?;
    for i in 0..count {
        if let Some(item) = items.call_obj("Item", &[Arg::Int(i)])? {
            let path = item.call("Path", &[])?.as_string();
            if trim_sep(&path).eq_ignore_ascii_case(trim_sep(folder_path))
                || trim_sep(&path).to_lowercase() == trim_sep(folder_path).to_lowercase()
            {
                return Ok(Some(item));
            }
        }
    }
    Ok(None)
}

pub fn is_pinned_to_quick_access(folder_path: &str) -> bool {
    let attempt = || -> windows::core::Result<bool> {
        match find_quick_access_item(folder_path)? {
            Some(item) => {
                let v = item.call("ExtendedProperty", &[Arg::Str("System.Home.IsPinned")])?;
                Ok(v.as_bool())
            }
            None => Ok(false),
        }
    };
    attempt().unwrap_or(false)
}

pub fn quick_access_unpin(folder_path: &str) -> bool {
    let attempt = || -> windows::core::Result<bool> {
        match find_quick_access_item(folder_path)? {
            Some(item) => {
                item.call("InvokeVerb", &[Arg::Str("unpinfromhome")])?;
                Ok(true)
            }
            None => Ok(false),
        }
    };
    track(attempt().unwrap_or(false))
}

pub fn quick_access_pin(folder_path: &str) -> bool {
    let attempt = || -> windows::core::Result<bool> {
        let shell = shell_app()?;
        let mut item = match shell.call_obj("NameSpace", &[Arg::Str(folder_path)])? {
            Some(ns) => ns.call_obj("Self", &[])?,
            None => None,
        };
        if item.is_none() {
            let p = std::path::Path::new(folder_path);
            let parent = p
                .parent()
                .map(|x| x.to_string_lossy().to_string())
                .filter(|x| !x.is_empty())
                .ok_or_else(windows::core::Error::empty)?;
            let leaf = p
                .file_name()
                .map(|x| x.to_string_lossy().to_string())
                .unwrap_or_default();
            let shell = shell_app()?;
            item = match shell.call_obj("NameSpace", &[Arg::Str(&parent)])? {
                Some(ns) => ns.call_obj("ParseName", &[Arg::Str(&leaf)])?,
                None => None,
            };
        }
        match item {
            None => {
                log::log(&format!(
                    "[RESULT] FAILED Quick Access pin: the shell cannot open the folder (exists: {})",
                    if std::path::Path::new(folder_path).is_dir() { "True" } else { "False" }
                ));
                Ok(false)
            }
            Some(item) => {
                item.call("InvokeVerb", &[Arg::Str("pintohome")])?;
                Ok(true)
            }
        }
    };
    track(attempt().unwrap_or(false))
}

use std::mem::ManuallyDrop;

use windows::core::GUID;
use windows::Win32::Foundation::VARIANT_BOOL;
use windows::Win32::System::Com::{
    CLSIDFromProgID, CoCreateInstance, CoInitializeEx, IDispatch, CLSCTX_ALL,
    COINIT_APARTMENTTHREADED, DISPATCH_FLAGS, DISPATCH_METHOD, DISPATCH_PROPERTYGET, DISPPARAMS,
};
use windows::Win32::System::Variant::{
    VariantClear, VARIANT, VARIANT_0, VARIANT_0_0, VARIANT_0_0_0, VT_BOOL, VT_BSTR, VT_DISPATCH,
    VT_I4,
};

pub struct Disp(IDispatch);

pub enum Arg {
    Int(i32),
}

pub struct Var(VARIANT);

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

impl Var {
    fn empty() -> Var {
        Var(VARIANT::default())
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

    pub fn as_string(&self) -> String {
        if self.vt() == VT_BSTR.0 {
            unsafe { (*self.0.Anonymous.Anonymous.Anonymous.bstrVal).to_string() }
        } else {
            String::new()
        }
    }

    pub fn as_bool(&self) -> bool {
        self.vt() == VT_BOOL.0
            && unsafe { self.0.Anonymous.Anonymous.Anonymous.boolVal } == VARIANT_BOOL(-1)
    }

    pub fn as_i32(&self) -> windows::core::Result<i32> {
        if self.vt() == VT_I4.0 {
            Ok(unsafe { self.0.Anonymous.Anonymous.Anonymous.lVal })
        } else {
            Err(windows::core::Error::empty())
        }
    }

    pub fn as_disp(&self) -> Option<Disp> {
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
    pub fn create(prog_id: &str) -> windows::core::Result<Disp> {
        unsafe {
            let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
            let prog = wide(prog_id);
            let clsid = CLSIDFromProgID(windows::core::PCWSTR(prog.as_ptr()))?;
            let d: IDispatch = CoCreateInstance(&clsid, None, CLSCTX_ALL)?;
            Ok(Disp(d))
        }
    }

    fn invoke(
        &self,
        member: &str,
        flags: DISPATCH_FLAGS,
        args: &[Arg],
    ) -> windows::core::Result<Var> {
        unsafe {
            let name = wide(member);
            let names = [windows::core::PCWSTR(name.as_ptr())];
            let mut id = 0i32;
            self.0
                .GetIDsOfNames(&GUID::zeroed(), names.as_ptr(), 1, 0, &mut id)?;
            let mut vars: Vec<Var> = args
                .iter()
                .rev()
                .map(|a| match a {
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

    pub fn call(&self, member: &str, args: &[Arg]) -> windows::core::Result<Var> {
        self.invoke(member, DISPATCH_METHOD | DISPATCH_PROPERTYGET, args)
    }

    pub fn call_obj(&self, member: &str, args: &[Arg]) -> windows::core::Result<Option<Disp>> {
        Ok(self.call(member, args)?.as_disp())
    }
}

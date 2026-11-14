use std::ffi::c_void;

use anyhow::{anyhow, Result};
use windows::core::{BSTR, PCWSTR};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoSetProxyBlanket, CLSCTX_INPROC_SERVER,
    COINIT_MULTITHREADED, EOAC_NONE, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
};
use windows::Win32::System::Ole::{SafeArrayGetElement, SafeArrayGetLBound, SafeArrayGetUBound};
use windows::Win32::System::Rpc::{RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE};
use windows::Win32::System::Variant::{VARIANT, VT_ARRAY, VT_BOOL, VT_EMPTY, VT_NULL};
use windows::Win32::System::Wmi::{
    IWbemLocator, IWbemServices, WbemLocator, WBEM_FLAG_FORWARD_ONLY, WBEM_FLAG_RETURN_IMMEDIATELY,
    WBEM_INFINITE,
};

#[derive(Clone, Debug, PartialEq)]
pub enum Val {
    None,
    Text(String),
    Ints(Vec<i64>),
}

impl Val {
    pub fn text(&self) -> String {
        match self {
            Val::Text(t) => t.clone(),
            _ => String::new(),
        }
    }

    pub fn ints(&self) -> Option<&Vec<i64>> {
        match self {
            Val::Ints(v) => Some(v),
            _ => None,
        }
    }
}

pub struct Wmi {
    services: IWbemServices,
}

impl Wmi {
    pub fn connect(namespace: &str) -> Result<Self> {
        unsafe {
            let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
            let locator: IWbemLocator = CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER)?;
            let services = locator.ConnectServer(
                &BSTR::from(namespace),
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

    pub fn query(&self, wql: &str, props: &[&str]) -> Result<Vec<Vec<Val>>> {
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
                    row.push(if got.is_ok() {
                        read_variant(&value)
                    } else {
                        Val::None
                    });
                }
                rows.push(row);
            }
        }
        Ok(rows)
    }
}

unsafe fn read_variant(value: &VARIANT) -> Val {
    let inner = &value.Anonymous.Anonymous;
    let vt = inner.vt;
    if vt == VT_EMPTY || vt == VT_NULL {
        return Val::None;
    }
    if vt.0 & VT_ARRAY.0 != 0 {
        let psa = inner.Anonymous.parray;
        if psa.is_null() {
            return Val::None;
        }
        let (Ok(lo), Ok(hi)) = (SafeArrayGetLBound(psa, 1), SafeArrayGetUBound(psa, 1)) else {
            return Val::None;
        };
        let mut out = Vec::new();
        for i in lo..=hi {
            let mut element: i32 = 0;
            if SafeArrayGetElement(psa, &i, &mut element as *mut i32 as *mut c_void).is_ok() {
                out.push(element as u32 as i64);
            }
        }
        return Val::Ints(out);
    }
    if vt == VT_BOOL {
        return Val::Text(
            if inner.Anonymous.boolVal.as_bool() {
                "True"
            } else {
                "False"
            }
            .to_string(),
        );
    }
    match BSTR::try_from(value) {
        Ok(b) => Val::Text(b.to_string()),
        Err(_) => Val::None,
    }
}

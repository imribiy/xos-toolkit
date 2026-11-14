use chrono::{Timelike, Utc};
use xos_core::log;

use crate::regutil::{self, hklm, io_message, open_opt, read_value, Data, Kind};

pub const DEFAULT_PATH: &str = r"SOFTWARE\XOSToolkit\StockHardware";
pub const MARKER_VALUE: &str = "RestoredToStock";
pub const STAMP_VALUE: &str = "RestoredToStockUtc";
pub const MARKER_DATA: &str = "Verified";
pub const INVALIDATE_FAILURE_PREFIX: &str = "Restored-to-stock marker could not be removed";

fn has_value(key: &winreg::RegKey, name: &str) -> std::io::Result<bool> {
    Ok(read_value(key, name, true)?.is_some())
}

pub fn invalidate(path: &str) -> Option<String> {
    let attempt = || -> std::io::Result<Option<String>> {
        let key = match open_opt(&hklm(), path, true)? {
            Some(k) => k,
            None => return Ok(None),
        };
        let had = has_value(&key, MARKER_VALUE)? || has_value(&key, STAMP_VALUE)?;
        regutil::delete_value_quiet(&key, MARKER_VALUE)?;
        regutil::delete_value_quiet(&key, STAMP_VALUE)?;
        Ok(if had {
            Some("Restored-to-stock marker removed".to_string())
        } else {
            None
        })
    };
    match attempt() {
        Ok(v) => v,
        Err(e) => Some(format!("{INVALIDATE_FAILURE_PREFIX}: {}", io_message(&e))),
    }
}

pub fn invalidate_default() -> Option<String> {
    invalidate(DEFAULT_PATH)
}

pub fn try_invalidate(context: &str) -> Result<(), String> {
    match invalidate_default() {
        None => Ok(()),
        Some(outcome) => {
            if outcome.starts_with(INVALIDATE_FAILURE_PREFIX) {
                log::result(
                    false,
                    &format!("Invalidate restored-to-stock marker | {context}"),
                    &outcome,
                );
                return Err(outcome);
            }
            log::op_detail(
                &format!("Invalidate restored-to-stock marker | {context}"),
                Some(&outcome),
            );
            Ok(())
        }
    }
}

fn bool_text(value: bool) -> &'static str {
    if value {
        "True"
    } else {
        "False"
    }
}

fn utc_round_trip() -> String {
    let now = Utc::now();
    format!(
        "{}.{:07}Z",
        now.format("%Y-%m-%dT%H:%M:%S"),
        now.nanosecond() / 100
    )
}

pub fn write(groups_restored: bool, path: &str) -> String {
    let attempt = || -> std::io::Result<String> {
        let key = match open_opt(&hklm(), path, true)? {
            Some(k) => k,
            None => {
                return Ok("No StockHardware key; no restored-to-stock marker written".to_string())
            }
        };
        regutil::delete_value_quiet(&key, MARKER_VALUE)?;
        regutil::delete_value_quiet(&key, STAMP_VALUE)?;
        let complete = matches!(
            read_value(&key, "CaptureStatus", true)?,
            Some(v) if v.as_str() == Some("Complete")
        );
        let retained = key.query_info()?.sub_keys;
        if !groups_restored || !complete || retained != 0 {
            return Ok(format!(
                "No restored-to-stock marker: groupsRestored={} captureComplete={} retainedGroups={}",
                bool_text(groups_restored),
                bool_text(complete),
                retained
            ));
        }
        regutil::set_value(
            &key,
            STAMP_VALUE,
            Kind::String,
            &Data::Str(utc_round_trip()),
        )?;
        regutil::set_value(
            &key,
            MARKER_VALUE,
            Kind::String,
            &Data::Str(MARKER_DATA.to_string()),
        )?;
        let verified = matches!(
            read_value(&key, MARKER_VALUE, true)?,
            Some(v) if v.kind == Kind::String && v.as_str() == Some(MARKER_DATA)
        );
        if verified {
            return Ok(
                "Restored-to-stock marker written: every stock hardware group restored".to_string(),
            );
        }
        regutil::delete_value_quiet(&key, MARKER_VALUE)?;
        regutil::delete_value_quiet(&key, STAMP_VALUE)?;
        Ok("Restored-to-stock marker did not verify and was removed".to_string())
    };
    match attempt() {
        Ok(text) => text,
        Err(e) => {
            if let Ok(Some(key)) = open_opt(&hklm(), path, true) {
                let _ = regutil::delete_value_quiet(&key, MARKER_VALUE);
                let _ = regutil::delete_value_quiet(&key, STAMP_VALUE);
            }
            format!("Restored-to-stock marker FAILED: {}", io_message(&e))
        }
    }
}

pub fn write_default(groups_restored: bool) -> String {
    write(groups_restored, DEFAULT_PATH)
}

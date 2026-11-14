use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Deserializer, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

fn null_default<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

fn no_null_entries<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    let list = Option::<Vec<Option<T>>>::deserialize(d)?.unwrap_or_default();
    let mut out = Vec::with_capacity(list.len());
    for item in list {
        match item {
            Some(v) => out.push(v),
            None => {
                return Err(serde::de::Error::custom(
                    "The CPU configuration contains an empty entry.",
                ))
            }
        }
    }
    Ok(out)
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CpuRule {
    #[serde(default, deserialize_with = "null_default", rename = "cores")]
    pub cores: Vec<bool>,
    #[serde(default, deserialize_with = "null_default", rename = "maskType")]
    pub mask_type: String,
    #[serde(default, deserialize_with = "null_default", rename = "processName")]
    pub process_name: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct UserPreset {
    #[serde(default, deserialize_with = "null_default", rename = "cores")]
    pub cores: Vec<bool>,
    #[serde(default, deserialize_with = "null_default", rename = "name")]
    pub name: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CpuRulesConfig {
    #[serde(default, deserialize_with = "no_null_entries", rename = "rules")]
    pub rules: Vec<CpuRule>,
    #[serde(default, deserialize_with = "no_null_entries", rename = "userPresets")]
    pub user_presets: Vec<UserPreset>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CpuConfigExport {
    #[serde(default, deserialize_with = "null_default", rename = "cpuName")]
    pub cpu_name: String,
    #[serde(default, deserialize_with = "null_default", rename = "exportedUtc")]
    pub exported_utc: String,
    #[serde(default, deserialize_with = "null_default", rename = "format")]
    pub format: String,
    #[serde(
        default,
        deserialize_with = "null_default",
        rename = "logicalProcessors"
    )]
    pub logical_processors: i32,
    #[serde(default, deserialize_with = "no_null_entries", rename = "rules")]
    pub rules: Vec<CpuRule>,
    #[serde(default, deserialize_with = "no_null_entries", rename = "userPresets")]
    pub user_presets: Vec<UserPreset>,
}

impl CpuConfigExport {
    pub const FORMAT_ID: &'static str = "xos-cpu-config";
}

pub fn config_dir() -> PathBuf {
    let base = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_default();
    base.join("XOS Toolkit")
}

pub fn config_path() -> PathBuf {
    config_dir().join("CpuRules.json")
}

pub fn load() -> CpuRulesConfig {
    load_from(&config_path())
}

pub fn load_from(path: &Path) -> CpuRulesConfig {
    if !path.exists() {
        return CpuRulesConfig::default();
    }
    match read_config(path) {
        Ok(c) => c,
        Err(e) => {
            xos_core::log::exception("CPU rules configuration could not be read", &format!("{e}"));
            let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S%3f");
            let mut name = path.as_os_str().to_os_string();
            name.push(format!(".corrupt-{stamp}"));
            let recovery = PathBuf::from(name);
            let copied = (|| -> std::io::Result<()> {
                let mut src = fs::File::open(path)?;
                let mut dst = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&recovery)?;
                std::io::copy(&mut src, &mut dst)?;
                Ok(())
            })();
            if copied.is_ok() {
                xos_core::log::log(&format!(
                    "[CPU Rules] Preserved unreadable configuration at {}",
                    recovery.display()
                ));
            }
            CpuRulesConfig::default()
        }
    }
}

fn strip_bom(bytes: &[u8]) -> &[u8] {
    bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes)
}

fn read_config(path: &Path) -> Result<CpuRulesConfig> {
    let bytes = fs::read(path)?;
    let parsed: Option<CpuRulesConfig> = serde_json::from_slice(strip_bom(&bytes))?;
    let cfg = parsed.unwrap_or_default();
    normalize(&cfg)?;
    Ok(cfg)
}

pub fn save(config: &CpuRulesConfig) -> Result<()> {
    save_to(&config_path(), &config_dir(), config)
}

pub fn save_to(path: &Path, dir: &Path, config: &CpuRulesConfig) -> Result<()> {
    normalize(config)?;
    fs::create_dir_all(dir)?;
    let json = serialize(config)?;
    write_atomic(path, json.as_bytes())
}

pub fn export(path: &str, export: &CpuConfigExport) -> Result<()> {
    if path.trim().is_empty() {
        bail!("A file path is required.");
    }
    let full = std::path::absolute(path)?;
    if let Some(dir) = full.parent() {
        fs::create_dir_all(dir)?;
    }
    let json = serialize(export)?;
    write_atomic(&full, json.as_bytes())
}

pub fn import(path: &str) -> Result<CpuConfigExport> {
    if path.trim().is_empty() {
        bail!("A file path is required.");
    }
    if fs::metadata(path)?.len() > 16 * 1024 * 1024 {
        bail!("The CPU configuration file is too large.");
    }
    let bytes = fs::read(path)?;
    let parsed: Option<CpuConfigExport> = serde_json::from_slice(strip_bom(&bytes))?;
    let result = parsed.ok_or_else(|| anyhow!("File is empty or not a valid configuration."))?;
    normalize_lists(&result.rules, &result.user_presets)?;
    Ok(result)
}

fn serialize<T: Serialize>(value: &T) -> Result<String> {
    Ok(serde_json::to_string(value)?.replace('/', "\\/"))
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_name(path: &Path) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed) as u128;
    let guid = nanos ^ (u128::from(std::process::id()) << 96) ^ (n << 64);
    let mut name = path.as_os_str().to_os_string();
    name.push(format!(".{guid:032x}.tmp"));
    PathBuf::from(name)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let temp = temp_name(path);
    let result = (|| -> Result<()> {
        {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp)?;
            f.write_all(bytes)?;
            f.sync_all()?;
        }
        commit_temp_file(&temp, path)
    })();
    if temp.exists() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn commit_temp_file(temp: &Path, destination: &Path) -> Result<()> {
    if !destination.exists() {
        fs::rename(temp, destination)?;
        return Ok(());
    }
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{ReplaceFileW, REPLACE_FILE_FLAGS};
    let wide = |p: &Path| -> Vec<u16> { p.as_os_str().encode_wide().chain(Some(0)).collect() };
    let dest = wide(destination);
    let src = wide(temp);
    unsafe {
        ReplaceFileW(
            PCWSTR(dest.as_ptr()),
            PCWSTR(src.as_ptr()),
            PCWSTR::null(),
            REPLACE_FILE_FLAGS(0),
            None,
            None,
        )
    }?;
    Ok(())
}

pub fn normalize(config: &CpuRulesConfig) -> Result<()> {
    normalize_lists(&config.rules, &config.user_presets)
}

fn normalize_lists(rules: &[CpuRule], presets: &[UserPreset]) -> Result<()> {
    if rules.len() > 4096 || presets.len() > 4096 {
        bail!("The CPU configuration contains too many entries.");
    }
    for rule in rules.iter() {
        if rule.cores.len() > 4096 {
            bail!("A CPU rule contains too many logical processors.");
        }
        if rule.mask_type != "CPUSet" && rule.mask_type != "Affinity" {
            bail!("A CPU rule has an unsupported mask type.");
        }
    }
    for preset in presets.iter() {
        if preset.cores.len() > 4096 {
            bail!("A CPU preset contains too many logical processors.");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("xos-cpu-test-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn sample() -> CpuRulesConfig {
        CpuRulesConfig {
            rules: vec![CpuRule {
                cores: vec![true, false, true],
                mask_type: "CPUSet".into(),
                process_name: "game/x.exe".into(),
            }],
            user_presets: vec![UserPreset {
                cores: vec![false, true],
                name: "Mine".into(),
            }],
        }
    }

    #[test]
    fn shape_and_field_names() {
        let json = serialize(&sample()).unwrap();
        assert_eq!(
            json,
            r#"{"rules":[{"cores":[true,false,true],"maskType":"CPUSet","processName":"game\/x.exe"}],"userPresets":[{"cores":[false,true],"name":"Mine"}]}"#
        );
    }

    #[test]
    fn round_trip_save_load() {
        let dir = tmp("rt");
        let path = dir.join("CpuRules.json");
        let cfg = sample();
        save_to(&path, &dir, &cfg).unwrap();
        let mut cfg2 = sample();
        cfg2.rules[0].mask_type = "Affinity".into();
        save_to(&path, &dir, &cfg2).unwrap();
        assert_eq!(load_from(&path), cfg2);
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_members_and_nulls() {
        let cfg: CpuRulesConfig =
            serde_json::from_str(r#"{"rules":[{"maskType":"Affinity","processName":null}]}"#)
                .unwrap();
        assert_eq!(cfg.rules[0].process_name, "");
        assert!(cfg.rules[0].cores.is_empty());
        assert!(cfg.user_presets.is_empty());
        assert!(serde_json::from_str::<CpuRulesConfig>(r#"{"rules":[null]}"#).is_err());
    }

    #[test]
    fn validation_rejects_bad_mask_type() {
        let mut cfg = sample();
        cfg.rules[0].mask_type = "cpuset".into();
        assert!(normalize(&cfg).is_err());
        let mut cfg = sample();
        cfg.rules[0].cores = vec![false; 4097];
        assert!(normalize(&cfg).is_err());
    }

    #[test]
    fn corrupt_file_is_preserved_and_default_returned() {
        let dir = tmp("corrupt");
        let path = dir.join("CpuRules.json");
        fs::write(&path, b"{ not json").unwrap();
        assert_eq!(load_from(&path), CpuRulesConfig::default());
        assert!(path.exists());
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn export_import_round_trip() {
        let dir = tmp("exp");
        let path = dir.join("sub").join("cfg.json");
        let e = CpuConfigExport {
            cpu_name: "X".into(),
            exported_utc: "2026-01-01T00:00:00Z".into(),
            format: CpuConfigExport::FORMAT_ID.into(),
            logical_processors: 8,
            rules: sample().rules,
            user_presets: sample().user_presets,
        };
        export(path.to_str().unwrap(), &e).unwrap();
        assert_eq!(import(path.to_str().unwrap()).unwrap(), e);
        let _ = fs::remove_dir_all(&dir);
    }
}

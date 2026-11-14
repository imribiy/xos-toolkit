use std::io::{self, Write};
use std::path::{Path, PathBuf};

use flate2::write::DeflateEncoder;
use flate2::Compression;

fn crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    for (i, slot) in table.iter_mut().enumerate() {
        let mut c = i as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
        *slot = c;
    }
    table
}

pub fn crc32(table: &[u32; 256], data: &[u8]) -> u32 {
    let mut c = 0xFFFF_FFFFu32;
    for &b in data {
        c = table[((c ^ b as u32) & 0xFF) as usize] ^ (c >> 8);
    }
    c ^ 0xFFFF_FFFF
}

fn collect_files(root: &Path, dir: &Path, out: &mut Vec<(String, PathBuf)>) -> io::Result<()> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)?.filter_map(|e| e.ok()).collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_files(root, &path, out)?;
        } else if file_type.is_file() {
            let relative = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            out.push((relative, path));
        }
    }
    Ok(())
}

fn dos_time(now: chrono::DateTime<chrono::Local>) -> (u16, u16) {
    use chrono::{Datelike, Timelike};
    let year = (now.year().clamp(1980, 2107) - 1980) as u16;
    let date = (year << 9) | ((now.month() as u16) << 5) | now.day() as u16;
    let time =
        ((now.hour() as u16) << 11) | ((now.minute() as u16) << 5) | (now.second() as u16 / 2);
    (time, date)
}

struct Central {
    name: String,
    method: u16,
    crc: u32,
    compressed: u32,
    size: u32,
    offset: u32,
}

pub fn create_from_directory(source: &Path, destination: &Path) -> io::Result<()> {
    let mut files = Vec::new();
    collect_files(source, source, &mut files)?;
    if files.len() >= 0xFFFF {
        return Err(io::Error::other("too many files for a ZIP archive"));
    }
    let table = crc_table();
    let (time, date) = dos_time(chrono::Local::now());
    let mut out = io::BufWriter::new(std::fs::File::create(destination)?);
    let mut written: u64 = 0;
    let mut central: Vec<Central> = Vec::new();

    for (name, path) in &files {
        let data = std::fs::read(path)?;
        if data.len() as u64 >= 0xFFFF_FFFF || written >= 0xFFFF_FFFF {
            return Err(io::Error::other("file too large for a ZIP archive"));
        }
        let crc = crc32(&table, &data);
        let (method, payload): (u16, Vec<u8>) = if data.is_empty() {
            (0, Vec::new())
        } else {
            let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
            enc.write_all(&data)?;
            (8, enc.finish()?)
        };
        let name_bytes = name.as_bytes();
        let offset = written as u32;
        let mut header = Vec::with_capacity(30 + name_bytes.len());
        header.extend_from_slice(&0x0403_4B50u32.to_le_bytes());
        header.extend_from_slice(&20u16.to_le_bytes());
        header.extend_from_slice(&0x0800u16.to_le_bytes());
        header.extend_from_slice(&method.to_le_bytes());
        header.extend_from_slice(&time.to_le_bytes());
        header.extend_from_slice(&date.to_le_bytes());
        header.extend_from_slice(&crc.to_le_bytes());
        header.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        header.extend_from_slice(&(data.len() as u32).to_le_bytes());
        header.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        header.extend_from_slice(&0u16.to_le_bytes());
        header.extend_from_slice(name_bytes);
        out.write_all(&header)?;
        out.write_all(&payload)?;
        written += header.len() as u64 + payload.len() as u64;
        central.push(Central {
            name: name.clone(),
            method,
            crc,
            compressed: payload.len() as u32,
            size: data.len() as u32,
            offset,
        });
    }

    let central_start = written;
    for entry in &central {
        let name_bytes = entry.name.as_bytes();
        let mut rec = Vec::with_capacity(46 + name_bytes.len());
        rec.extend_from_slice(&0x0201_4B50u32.to_le_bytes());
        rec.extend_from_slice(&20u16.to_le_bytes());
        rec.extend_from_slice(&20u16.to_le_bytes());
        rec.extend_from_slice(&0x0800u16.to_le_bytes());
        rec.extend_from_slice(&entry.method.to_le_bytes());
        rec.extend_from_slice(&time.to_le_bytes());
        rec.extend_from_slice(&date.to_le_bytes());
        rec.extend_from_slice(&entry.crc.to_le_bytes());
        rec.extend_from_slice(&entry.compressed.to_le_bytes());
        rec.extend_from_slice(&entry.size.to_le_bytes());
        rec.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        rec.extend_from_slice(&0u16.to_le_bytes());
        rec.extend_from_slice(&0u16.to_le_bytes());
        rec.extend_from_slice(&0u16.to_le_bytes());
        rec.extend_from_slice(&0u16.to_le_bytes());
        rec.extend_from_slice(&0u32.to_le_bytes());
        rec.extend_from_slice(&entry.offset.to_le_bytes());
        rec.extend_from_slice(name_bytes);
        out.write_all(&rec)?;
        written += rec.len() as u64;
    }
    let central_size = written - central_start;
    let mut end = Vec::with_capacity(22);
    end.extend_from_slice(&0x0605_4B50u32.to_le_bytes());
    end.extend_from_slice(&0u16.to_le_bytes());
    end.extend_from_slice(&0u16.to_le_bytes());
    end.extend_from_slice(&(central.len() as u16).to_le_bytes());
    end.extend_from_slice(&(central.len() as u16).to_le_bytes());
    end.extend_from_slice(&(central_size as u32).to_le_bytes());
    end.extend_from_slice(&(central_start as u32).to_le_bytes());
    end.extend_from_slice(&0u16.to_le_bytes());
    out.write_all(&end)?;
    out.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_matches_known_value() {
        let table = crc_table();
        assert_eq!(crc32(&table, b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn archive_round_trip_structure() {
        let base = std::env::temp_dir().join(format!("xos-zipw-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let src = base.join("src");
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::write(src.join("a.txt"), b"hello hello hello hello").unwrap();
        std::fs::write(src.join("sub").join("b.txt"), b"").unwrap();
        let zip = base.join("out.zip");
        create_from_directory(&src, &zip).unwrap();
        let bytes = std::fs::read(&zip).unwrap();
        assert_eq!(&bytes[..4], &0x0403_4B50u32.to_le_bytes());
        let eocd = bytes.len() - 22;
        assert_eq!(&bytes[eocd..eocd + 4], &0x0605_4B50u32.to_le_bytes());
        assert_eq!(u16::from_le_bytes([bytes[eocd + 10], bytes[eocd + 11]]), 2);
        let _ = std::fs::remove_dir_all(&base);
    }
}

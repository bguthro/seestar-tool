/// APK/XAPK handling — mirrors apk_utils.py and the AXML parser in extract_pem.py.

use anyhow::{anyhow, Result};
use std::io::{Cursor, Read};
use zip::ZipArchive;

/// Detect whether an open ZIP is an XAPK (has manifest.json + .apk entries).
fn is_xapk(archive: &ZipArchive<Cursor<Vec<u8>>>) -> bool {
    let names: Vec<&str> = archive.file_names().collect();
    names.contains(&"manifest.json") && names.iter().any(|n| n.ends_with(".apk"))
}

/// Top-level .apk entries inside an XAPK (not in subdirectories).
fn root_apk_entries(archive: &ZipArchive<Cursor<Vec<u8>>>) -> Vec<String> {
    archive
        .file_names()
        .filter(|n| n.ends_with(".apk") && !n.contains('/'))
        .map(String::from)
        .collect()
}

/// Load a file into memory and wrap it in a ZipArchive.
fn zip_from_bytes(data: Vec<u8>) -> Result<ZipArchive<Cursor<Vec<u8>>>> {
    Ok(ZipArchive::new(Cursor::new(data))?)
}

/// Read the raw bytes of a named entry from a ZipArchive.
fn read_entry(archive: &mut ZipArchive<Cursor<Vec<u8>>>, name: &str) -> Result<Vec<u8>> {
    let mut entry = archive.by_name(name)?;
    let mut buf = Vec::new();
    entry.read_to_end(&mut buf)?;
    Ok(buf)
}

/// Returned by [`open_apk`] — gives callers access to the chosen inner APK.
pub struct ApkHandle {
    /// Which split APK was selected (empty string for plain APKs).
    pub split_name: String,
    /// In-memory bytes of the chosen APK.
    pub data: Vec<u8>,
}

impl ApkHandle {
    /// Open the APK as a ZipArchive.
    pub fn zip(&self) -> Result<ZipArchive<Cursor<Vec<u8>>>> {
        zip_from_bytes(self.data.clone())
    }

    /// Check whether a path exists inside this APK.
    pub fn contains(&self, path: &str) -> Result<bool> {
        let names = self.file_names()?;
        Ok(names.iter().any(|n| n == path))
    }

    /// Read a named entry from this APK.
    pub fn read(&self, path: &str) -> Result<Vec<u8>> {
        let mut z = self.zip()?;
        read_entry(&mut z, path)
    }

    /// List all file names inside this APK.
    pub fn file_names(&self) -> Result<Vec<String>> {
        let z = self.zip()?;
        Ok(z.file_names().map(String::from).collect())
    }
}

/// Open an APK or XAPK file from disk.
///
/// For plain APKs: returns a handle wrapping the file itself.
/// For XAPKs:
///   - If `containing` is non-empty, searches all split APKs for the first one
///     that has any of those paths.
///   - Otherwise, prefers `base.apk`, falling back to the first root-level .apk.
pub fn open_apk(path: &str, containing: &[&str]) -> Result<ApkHandle> {
    let raw = std::fs::read(path)?;
    let mut outer = zip_from_bytes(raw.clone())?;

    if !is_xapk(&outer) {
        return Ok(ApkHandle {
            split_name: String::new(),
            data: raw,
        });
    }

    let apk_entries = root_apk_entries(&outer);
    if apk_entries.is_empty() {
        return Err(anyhow!("No APK entries found inside XAPK: {}", path));
    }

    let chosen = if !containing.is_empty() {
        let mut found = None;
        for entry in &apk_entries {
            let inner_data = read_entry(&mut outer, entry)?;
            let inner = zip_from_bytes(inner_data)?;
            if containing.iter().any(|n| inner.file_names().any(|f| f == *n)) {
                found = Some(entry.clone());
                break;
            }
        }
        found.ok_or_else(|| anyhow!("No split APK in {} contains: {:?}", path, containing))?
    } else if apk_entries.contains(&"base.apk".to_string()) {
        "base.apk".to_string()
    } else {
        apk_entries[0].clone()
    };

    let inner_data = read_entry(&mut outer, &chosen)?;
    Ok(ApkHandle {
        split_name: chosen,
        data: inner_data,
    })
}

// ── AXML binary manifest parser ──────────────────────────────────────────────

/// Extract the `versionName` string from a binary AndroidManifest.xml (AXML).
/// Returns `None` if parsing fails or the attribute is absent.
pub fn parse_version_name(axml: &[u8]) -> Option<String> {
    use std::convert::TryInto;

    let u32_le = |buf: &[u8], off: usize| -> Option<u32> {
        buf.get(off..off + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()))
    };
    let u16_le = |buf: &[u8], off: usize| -> Option<u16> {
        buf.get(off..off + 2).map(|b| u16::from_le_bytes(b.try_into().unwrap()))
    };

    // String pool starts at offset 8 (after 8-byte AXML file header).
    let sp_off: usize = 8;
    let _sp_type = u32_le(axml, sp_off)?;
    let sp_size = u32_le(axml, sp_off + 4)? as usize;
    let str_count = u32_le(axml, sp_off + 8)? as usize;
    let str_data_start = u32_le(axml, sp_off + 24)? as usize;

    let offsets_base = sp_off + 28; // 7 × u32 header fields
    let str_data_base = sp_off + str_data_start;

    let mut strings: Vec<String> = Vec::with_capacity(str_count);
    for i in 0..str_count {
        let off = u32_le(axml, offsets_base + i * 4)? as usize;
        let pos = str_data_base + off;
        let slen = u16_le(axml, pos)? as usize;
        let raw = axml.get(pos + 2..pos + 2 + slen * 2)?;
        let s = String::from_utf16_lossy(
            &raw.chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect::<Vec<_>>(),
        );
        strings.push(s);
    }

    let vn_idx = strings.iter().position(|s| s == "versionName")?;

    // Walk XML chunks starting after the string pool.
    let mut pos = sp_off + sp_size;
    while pos + 8 <= axml.len() {
        let chunk_type = u16_le(axml, pos)? as u32;
        let chunk_size = u32_le(axml, pos + 4)? as usize;
        if chunk_size == 0 {
            break;
        }
        if chunk_type == 0x0102 {
            // XML_START_ELEMENT
            let name_idx = {
                let v = axml.get(pos + 20..pos + 24)?;
                i32::from_le_bytes(v.try_into().unwrap())
            };
            if name_idx >= 0
                && (name_idx as usize) < strings.len()
                && strings[name_idx as usize] == "manifest"
            {
                let attr_start = u16_le(axml, pos + 24)? as usize;
                let attr_size = u16_le(axml, pos + 26)? as usize;
                let attr_count = u16_le(axml, pos + 28)? as usize;
                let attr_base = pos + 16 + attr_start;
                for a in 0..attr_count {
                    let a_off = attr_base + a * attr_size;
                    let a_name = {
                        let v = axml.get(a_off + 4..a_off + 8)?;
                        i32::from_le_bytes(v.try_into().unwrap())
                    };
                    let a_raw = {
                        let v = axml.get(a_off + 8..a_off + 12)?;
                        i32::from_le_bytes(v.try_into().unwrap())
                    };
                    if a_name == vn_idx as i32
                        && a_raw >= 0
                        && (a_raw as usize) < strings.len()
                    {
                        return Some(strings[a_raw as usize].clone());
                    }
                }
                break;
            }
        }
        pos += chunk_size;
    }
    None
}

/// Read versionName from an APK/XAPK file. Returns "unknown" on failure.
pub fn apk_version(path: &str) -> String {
    (|| -> Result<String> {
        let handle = open_apk(path, &[])?;
        let axml = handle.read("AndroidManifest.xml")?;
        Ok(parse_version_name(&axml).unwrap_or_else(|| "unknown".to_string()))
    })()
    .unwrap_or_else(|_| "unknown".to_string())
}

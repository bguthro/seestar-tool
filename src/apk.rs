//! APK/XAPK handling — mirrors apk_utils.py and the AXML parser in extract_pem.py.

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
            if containing
                .iter()
                .any(|n| inner.file_names().any(|f| f == *n))
            {
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
        buf.get(off..off + 4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
    };
    let u16_le = |buf: &[u8], off: usize| -> Option<u16> {
        buf.get(off..off + 2)
            .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
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
                    if a_name == vn_idx as i32 && a_raw >= 0 && (a_raw as usize) < strings.len() {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};
    use zip::write::{SimpleFileOptions, ZipWriter};

    // ── ZIP builder helpers ───────────────────────────────────────────────────

    fn make_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut zw = ZipWriter::new(Cursor::new(Vec::new()));
        let opts = SimpleFileOptions::default();
        for (name, data) in files {
            zw.start_file(*name, opts).unwrap();
            zw.write_all(data).unwrap();
        }
        zw.finish().unwrap().into_inner()
    }

    /// RAII temp file — deleted when dropped.
    struct TempFile(std::path::PathBuf);
    impl TempFile {
        fn write(name: &str, data: &[u8]) -> Self {
            let path = std::env::temp_dir().join(name);
            std::fs::write(&path, data).unwrap();
            TempFile(path)
        }
        fn path(&self) -> &str {
            self.0.to_str().unwrap()
        }
    }
    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    // ── AXML builder ─────────────────────────────────────────────────────────
    //
    // Constructs a minimal binary AndroidManifest.xml (AXML) containing a
    // <manifest versionName="version"> element so that parse_version_name
    // can be exercised without real APK fixtures.
    //
    // Layout verified against the parser in parse_version_name:
    //   sp_off = 8
    //   offsets_base = sp_off + 28 = 36
    //   str_data_base = sp_off + str_data_start
    //   attr_base = chunk_pos + 16 + attr_start
    //
    // String pool indices: 0 = "versionName", 1 = "manifest", 2 = version
    fn build_axml(version: &str) -> Vec<u8> {
        let strs: &[&str] = &["versionName", "manifest", version];

        // Encode each string as UTF-16LE with a u16 length prefix.
        let mut string_data: Vec<u8> = Vec::new();
        let mut offsets: Vec<u32> = Vec::new();
        for s in strs {
            offsets.push(string_data.len() as u32);
            let units: Vec<u16> = s.encode_utf16().collect();
            string_data.extend_from_slice(&(units.len() as u16).to_le_bytes());
            for u in &units {
                string_data.extend_from_slice(&u.to_le_bytes());
            }
        }

        let str_count = strs.len() as u32;
        // str_data_start = 7 header u32s (28 bytes) + offset array
        let str_data_start = 28u32 + str_count * 4;
        let sp_size = str_data_start + string_data.len() as u32;

        let mut buf = vec![0u8; 8]; // ignored AXML file header

        // String pool header (7 × u32 at sp_off = 8)
        buf.extend_from_slice(&1u32.to_le_bytes()); // sp_type        (sp_off+0)
        buf.extend_from_slice(&sp_size.to_le_bytes()); // sp_size      (sp_off+4)
        buf.extend_from_slice(&str_count.to_le_bytes()); // str_count  (sp_off+8)
        buf.extend_from_slice(&0u32.to_le_bytes()); // style_count     (sp_off+12)
        buf.extend_from_slice(&0u32.to_le_bytes()); // flags           (sp_off+16)
        buf.extend_from_slice(&0u32.to_le_bytes()); // unused          (sp_off+20)
        buf.extend_from_slice(&str_data_start.to_le_bytes()); // str_data_start (sp_off+24)

        // Offset array at offsets_base = sp_off+28 = 36
        for o in &offsets {
            buf.extend_from_slice(&o.to_le_bytes());
        }
        // String data
        buf.extend_from_slice(&string_data);

        // XML_START_ELEMENT chunk (type 0x0102) for <manifest versionName="…">
        // attr_start=20 ⟹ attr_base = chunk_pos+16+20 = chunk_pos+36 (right after header)
        let attr_start: u16 = 20;
        let attr_size: u16 = 20;
        let attr_count: u16 = 1;
        let chunk_size: u32 = 36 + attr_count as u32 * attr_size as u32; // 56

        buf.extend_from_slice(&0x0102u16.to_le_bytes()); // chunk_type  (pos+0)
        buf.extend_from_slice(&0u16.to_le_bytes()); //  header_size     (pos+2, not read)
        buf.extend_from_slice(&chunk_size.to_le_bytes()); // chunk_size (pos+4)
        buf.extend_from_slice(&1u32.to_le_bytes()); //  line_number     (pos+8)
        buf.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // comment (pos+12)
        buf.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // ns_idx  (pos+16, ignored)
        buf.extend_from_slice(&1i32.to_le_bytes()); //  name_idx=1 "manifest" (pos+20)
        buf.extend_from_slice(&attr_start.to_le_bytes()); //             (pos+24)
        buf.extend_from_slice(&attr_size.to_le_bytes()); //              (pos+26)
        buf.extend_from_slice(&attr_count.to_le_bytes()); //             (pos+28)
        buf.extend_from_slice(&0u16.to_le_bytes()); //  id_attr          (pos+30)
        buf.extend_from_slice(&0u16.to_le_bytes()); //  class_attr       (pos+32)
        buf.extend_from_slice(&0u16.to_le_bytes()); //  style_attr       (pos+34)

        // Attribute 0: versionName (idx 0) = version (idx 2), size=20 bytes
        buf.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // ns      (a_off+0, ignored)
        buf.extend_from_slice(&0i32.to_le_bytes()); //  a_name=0 "versionName" (a_off+4)
        buf.extend_from_slice(&2i32.to_le_bytes()); //  a_raw=2  version string (a_off+8)
        buf.extend_from_slice(&0u32.to_le_bytes()); //  type hint        (a_off+12)
        buf.extend_from_slice(&0u32.to_le_bytes()); //  data             (a_off+16)

        buf
    }

    // ── zip_from_bytes ────────────────────────────────────────────────────────

    #[test]
    fn zip_from_bytes_valid_zip() {
        let data = make_zip(&[("a.txt", b"hello")]);
        assert!(zip_from_bytes(data).is_ok());
    }

    #[test]
    fn zip_from_bytes_empty_data_returns_error() {
        assert!(zip_from_bytes(vec![]).is_err());
    }

    #[test]
    fn zip_from_bytes_garbage_returns_error() {
        assert!(zip_from_bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]).is_err());
    }

    // ── is_xapk ──────────────────────────────────────────────────────────────

    #[test]
    fn is_xapk_false_for_plain_apk() {
        let data = make_zip(&[("classes.dex", b"dex")]);
        let archive = zip_from_bytes(data).unwrap();
        assert!(!is_xapk(&archive));
    }

    #[test]
    fn is_xapk_false_when_manifest_missing() {
        let data = make_zip(&[("base.apk", b"inner")]);
        let archive = zip_from_bytes(data).unwrap();
        assert!(!is_xapk(&archive));
    }

    #[test]
    fn is_xapk_false_when_apk_entry_missing() {
        let data = make_zip(&[("manifest.json", b"{}")]);
        let archive = zip_from_bytes(data).unwrap();
        assert!(!is_xapk(&archive));
    }

    #[test]
    fn is_xapk_true_with_manifest_and_apk() {
        let data = make_zip(&[("manifest.json", b"{}"), ("base.apk", b"inner")]);
        let archive = zip_from_bytes(data).unwrap();
        assert!(is_xapk(&archive));
    }

    // ── root_apk_entries ──────────────────────────────────────────────────────

    #[test]
    fn root_apk_entries_empty_when_no_apks() {
        let data = make_zip(&[("manifest.json", b"{}")]);
        let archive = zip_from_bytes(data).unwrap();
        assert!(root_apk_entries(&archive).is_empty());
    }

    #[test]
    fn root_apk_entries_excludes_subdirectory_apks() {
        let data = make_zip(&[("subdir/nested.apk", b"inner")]);
        let archive = zip_from_bytes(data).unwrap();
        assert!(root_apk_entries(&archive).is_empty());
    }

    #[test]
    fn root_apk_entries_includes_top_level_apks() {
        let data = make_zip(&[
            ("base.apk", b"inner"),
            ("split.apk", b"inner2"),
            ("subdir/ignored.apk", b"inner3"),
        ]);
        let archive = zip_from_bytes(data).unwrap();
        let entries = root_apk_entries(&archive);
        assert_eq!(entries.len(), 2);
        assert!(entries.contains(&"base.apk".to_string()));
        assert!(entries.contains(&"split.apk".to_string()));
    }

    // ── read_entry ────────────────────────────────────────────────────────────

    #[test]
    fn read_entry_returns_file_bytes() {
        let data = make_zip(&[("hello.txt", b"world")]);
        let mut archive = zip_from_bytes(data).unwrap();
        assert_eq!(read_entry(&mut archive, "hello.txt").unwrap(), b"world");
    }

    #[test]
    fn read_entry_missing_name_returns_error() {
        let data = make_zip(&[("a.txt", b"x")]);
        let mut archive = zip_from_bytes(data).unwrap();
        assert!(read_entry(&mut archive, "missing.txt").is_err());
    }

    // ── parse_version_name ────────────────────────────────────────────────────

    #[test]
    fn parse_version_name_valid_axml() {
        let axml = build_axml("3.1.1");
        assert_eq!(parse_version_name(&axml), Some("3.1.1".to_string()));
    }

    #[test]
    fn parse_version_name_empty_bytes_returns_none() {
        assert_eq!(parse_version_name(b""), None);
    }

    #[test]
    fn parse_version_name_truncated_returns_none() {
        // Fewer than 36 bytes — can't even read the string pool header
        assert_eq!(parse_version_name(&[0u8; 10]), None);
    }

    #[test]
    fn parse_version_name_no_version_name_in_pool_returns_none() {
        // Build AXML with str_count=0 (no strings at all)
        let mut buf = vec![0u8; 8]; // file header
        let sp_size: u32 = 28; // header only, no strings
        buf.extend_from_slice(&1u32.to_le_bytes()); // sp_type
        buf.extend_from_slice(&sp_size.to_le_bytes()); // sp_size
        buf.extend_from_slice(&0u32.to_le_bytes()); // str_count = 0
        buf.extend_from_slice(&[0u8; 16]); // remaining 4 header fields
                                           // No offsets, no string data, no chunks → vn_idx = None
        assert_eq!(parse_version_name(&buf), None);
    }

    #[test]
    fn parse_version_name_element_is_not_manifest_returns_none() {
        // Build AXML where the start element's name_idx points to index 0
        // ("versionName"), not "manifest" — so the condition never triggers.
        let strs: &[&str] = &["versionName", "application", "3.1.1"];
        let mut string_data: Vec<u8> = Vec::new();
        let mut offsets: Vec<u32> = Vec::new();
        for s in strs {
            offsets.push(string_data.len() as u32);
            let units: Vec<u16> = s.encode_utf16().collect();
            string_data.extend_from_slice(&(units.len() as u16).to_le_bytes());
            for u in &units {
                string_data.extend_from_slice(&u.to_le_bytes());
            }
        }
        let str_count = strs.len() as u32;
        let str_data_start = 28u32 + str_count * 4;
        let sp_size = str_data_start + string_data.len() as u32;

        let mut buf = vec![0u8; 8];
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.extend_from_slice(&sp_size.to_le_bytes());
        buf.extend_from_slice(&str_count.to_le_bytes());
        buf.extend_from_slice(&[0u8; 16]);
        buf.extend_from_slice(&str_data_start.to_le_bytes());
        for o in &offsets {
            buf.extend_from_slice(&o.to_le_bytes());
        }
        buf.extend_from_slice(&string_data);

        // Element chunk: name_idx=1 → "application" (not "manifest")
        let chunk_size: u32 = 36 + 20;
        buf.extend_from_slice(&0x0102u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&chunk_size.to_le_bytes());
        buf.extend_from_slice(&[0u8; 8]); // line + comment
        buf.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // ns
        buf.extend_from_slice(&1i32.to_le_bytes()); // name_idx=1 "application"
        buf.extend_from_slice(&20u16.to_le_bytes()); // attr_start
        buf.extend_from_slice(&20u16.to_le_bytes()); // attr_size
        buf.extend_from_slice(&1u16.to_le_bytes()); // attr_count
        buf.extend_from_slice(&[0u8; 6]); // id/class/style attrs
        buf.extend_from_slice(&[0u8; 20]); // one attribute

        assert_eq!(parse_version_name(&buf), None);
    }

    #[test]
    fn parse_version_name_zero_chunk_size_returns_none() {
        // Valid string pool, but the XML chunk has chunk_size=0 → loop breaks
        let axml_prefix = build_axml("3.1.1");
        // Truncate to end of string pool (8 + sp_size bytes), then append a
        // chunk with size=0 which the parser breaks on immediately.
        let sp_size = u32::from_le_bytes(axml_prefix[12..16].try_into().unwrap()) as usize;
        let mut buf = axml_prefix[..8 + sp_size].to_vec();
        buf.extend_from_slice(&0x0102u16.to_le_bytes()); // chunk_type
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes()); // chunk_size = 0 → break
        assert_eq!(parse_version_name(&buf), None);
    }

    // ── apk_version ───────────────────────────────────────────────────────────

    #[test]
    fn apk_version_nonexistent_file_returns_unknown() {
        assert_eq!(apk_version("/nonexistent/seestar_test.apk"), "unknown");
    }

    #[test]
    fn apk_version_not_a_zip_returns_unknown() {
        let tmp = TempFile::write("seestar_test_not_zip.apk", b"not a zip file");
        assert_eq!(apk_version(tmp.path()), "unknown");
    }

    #[test]
    fn apk_version_zip_without_manifest_returns_unknown() {
        let data = make_zip(&[("res/raw/other.txt", b"content")]);
        let tmp = TempFile::write("seestar_test_no_manifest.apk", &data);
        assert_eq!(apk_version(tmp.path()), "unknown");
    }

    #[test]
    fn apk_version_reads_from_axml() {
        let axml = build_axml("3.1.2");
        let data = make_zip(&[("AndroidManifest.xml", &axml)]);
        let tmp = TempFile::write("seestar_test_with_manifest.apk", &data);
        assert_eq!(apk_version(tmp.path()), "3.1.2");
    }

    // ── open_apk ─────────────────────────────────────────────────────────────

    #[test]
    fn open_apk_nonexistent_returns_error() {
        assert!(open_apk("/nonexistent/seestar_test.apk", &[]).is_err());
    }

    #[test]
    fn open_apk_plain_apk_returns_handle_with_empty_split_name() {
        let data = make_zip(&[("classes.dex", b"dex")]);
        let tmp = TempFile::write("seestar_test_plain.apk", &data);
        let handle = open_apk(tmp.path(), &[]).unwrap();
        assert!(handle.split_name.is_empty());
    }

    #[test]
    fn open_apk_plain_apk_can_read_entries() {
        let data = make_zip(&[("test.txt", b"hello")]);
        let tmp = TempFile::write("seestar_test_readable.apk", &data);
        let handle = open_apk(tmp.path(), &[]).unwrap();
        assert_eq!(handle.read("test.txt").unwrap(), b"hello");
    }

    #[test]
    fn open_apk_xapk_picks_base_apk_by_default() {
        let inner_base = make_zip(&[("classes.dex", b"base")]);
        let inner_split = make_zip(&[("classes.dex", b"split")]);
        let xapk = make_zip(&[
            ("manifest.json", b"{}"),
            ("base.apk", &inner_base),
            ("split.apk", &inner_split),
        ]);
        let tmp = TempFile::write("seestar_test_xapk_base.xapk", &xapk);
        let handle = open_apk(tmp.path(), &[]).unwrap();
        assert_eq!(handle.split_name, "base.apk");
    }

    #[test]
    fn open_apk_xapk_falls_back_to_first_apk_when_no_base() {
        let inner = make_zip(&[("file.txt", b"data")]);
        let xapk = make_zip(&[("manifest.json", b"{}"), ("only.apk", &inner)]);
        let tmp = TempFile::write("seestar_test_xapk_nobase.xapk", &xapk);
        let handle = open_apk(tmp.path(), &[]).unwrap();
        assert_eq!(handle.split_name, "only.apk");
    }

    #[test]
    fn open_apk_xapk_containing_finds_correct_split() {
        let base_apk = make_zip(&[("assets/other.txt", b"other")]);
        let split_apk = make_zip(&[("lib/arm64-v8a/libopenssllib.so", b"sodata")]);
        let xapk = make_zip(&[
            ("manifest.json", b"{}"),
            ("base.apk", &base_apk),
            ("split_config.arm64.apk", &split_apk),
        ]);
        let tmp = TempFile::write("seestar_test_xapk_containing.xapk", &xapk);
        let handle = open_apk(tmp.path(), &["lib/arm64-v8a/libopenssllib.so"]).unwrap();
        assert_eq!(handle.split_name, "split_config.arm64.apk");
        assert_eq!(
            handle.read("lib/arm64-v8a/libopenssllib.so").unwrap(),
            b"sodata"
        );
    }

    #[test]
    fn open_apk_xapk_containing_not_found_returns_error() {
        let inner = make_zip(&[("other.txt", b"data")]);
        let xapk = make_zip(&[("manifest.json", b"{}"), ("base.apk", &inner)]);
        let tmp = TempFile::write("seestar_test_xapk_missing.xapk", &xapk);
        let result = open_apk(tmp.path(), &["missing/file.so"]);
        assert!(result.is_err());
    }

    #[test]
    fn open_apk_xapk_no_root_apk_entries_returns_error() {
        // is_xapk returns true (has manifest.json + an .apk somewhere), but
        // root_apk_entries is empty because the .apk is in a subdirectory.
        let inner = make_zip(&[("file.txt", b"data")]);
        let xapk = make_zip(&[
            ("manifest.json", b"{}"),
            ("subdir/nested.apk", &inner), // in a subdir → excluded by root_apk_entries
        ]);
        let tmp = TempFile::write("seestar_test_xapk_subdir.xapk", &xapk);
        let result = open_apk(tmp.path(), &[]);
        assert!(result.is_err());
    }

    // ── ApkHandle ─────────────────────────────────────────────────────────────

    #[test]
    fn apk_handle_file_names_lists_all_entries() {
        let data = make_zip(&[("a.txt", b"1"), ("b/c.txt", b"2")]);
        let tmp = TempFile::write("seestar_test_handle_names.apk", &data);
        let handle = open_apk(tmp.path(), &[]).unwrap();
        let names = handle.file_names().unwrap();
        assert!(names.contains(&"a.txt".to_string()));
        assert!(names.contains(&"b/c.txt".to_string()));
    }

    #[test]
    fn apk_handle_read_missing_entry_returns_error() {
        let data = make_zip(&[("a.txt", b"1")]);
        let tmp = TempFile::write("seestar_test_handle_missing.apk", &data);
        let handle = open_apk(tmp.path(), &[]).unwrap();
        assert!(handle.read("nonexistent.txt").is_err());
    }
}

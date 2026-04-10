//! PEM private-key extraction from libopenssllib.so inside an APK.
//! Mirrors extract_pem.py.

use anyhow::Result;
use regex::Regex;
use std::collections::HashSet;
use std::path::Path;

use crate::apk::open_apk;

const SO_PATHS: &[&str] = &[
    "lib/arm64-v8a/libopenssllib.so",
    "lib/armeabi-v7a/libopenssllib.so",
];

/// Extract printable ASCII strings ≥4 chars from binary data (like `strings(1)`).
fn extract_strings(data: &[u8]) -> String {
    let mut out = String::new();
    let mut cur = String::new();
    for &b in data {
        if b.is_ascii_graphic() || b == b' ' {
            cur.push(b as char);
        } else {
            if cur.len() >= 4 {
                out.push_str(&cur);
                out.push('\n');
            }
            cur.clear();
        }
    }
    if cur.len() >= 4 {
        out.push_str(&cur);
    }
    out
}

/// Find all PEM private key blocks inside a string dump.
fn find_pem_keys(strings_output: &str) -> Vec<String> {
    let re = Regex::new(r"-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----").unwrap();
    re.find_iter(strings_output)
        .map(|m| m.as_str().to_string())
        .collect()
}

/// Result of a PEM extraction run.
pub struct PemResult {
    pub keys: Vec<String>,
}

/// Extract PEM private keys from an APK/XAPK file.
/// Searches `libopenssllib.so` in both arm64-v8a and armeabi-v7a.
pub fn extract_pem_from_apk(apk_path: &str, progress: impl Fn(String)) -> Result<PemResult> {
    let version = crate::apk::apk_version(apk_path);
    progress(format!("APK version: {}", version));

    let handle = open_apk(apk_path, SO_PATHS)?;
    let names = handle.file_names()?;

    let found: Vec<&str> = SO_PATHS
        .iter()
        .copied()
        .filter(|p| names.contains(&p.to_string()))
        .collect();

    if found.is_empty() {
        return Ok(PemResult { keys: vec![] });
    }

    let mut all_keys: HashSet<String> = HashSet::new();

    for so_path in &found {
        progress(format!("Scanning {}…", so_path));
        let data = handle.read(so_path)?;
        let strings = extract_strings(&data);
        let keys = find_pem_keys(&strings);
        progress(format!(
            "  Found {} key(s) in {}",
            keys.len(),
            Path::new(so_path).file_name().unwrap().to_string_lossy()
        ));
        all_keys.extend(keys);
    }

    let mut keys: Vec<String> = all_keys.into_iter().collect();
    keys.sort();
    Ok(PemResult { keys })
}

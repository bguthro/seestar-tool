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

#[cfg(test)]
mod tests {
    use super::*;

    // ── extract_strings ───────────────────────────────────────────────────────

    #[test]
    fn extract_strings_empty_input() {
        assert_eq!(extract_strings(b""), "");
    }

    #[test]
    fn extract_strings_all_nonprintable() {
        // Bytes below 0x20 (except space) and above 0x7e are not ascii_graphic
        assert_eq!(extract_strings(&[0x01, 0x02, 0x03, 0x80, 0xFF]), "");
    }

    #[test]
    fn extract_strings_includes_strings_of_four_or_more() {
        let out = extract_strings(b"hello");
        assert!(out.contains("hello"));
    }

    #[test]
    fn extract_strings_excludes_runs_shorter_than_four() {
        // "ab" + null + "cd" are each 2 chars — both should be dropped
        let out = extract_strings(b"ab\x00cd\x00");
        assert!(!out.contains("ab"));
        assert!(!out.contains("cd"));
    }

    #[test]
    fn extract_strings_splits_on_nonprintable() {
        // "hello" then a null then "world" → two separate strings
        let out = extract_strings(b"hello\x00world");
        assert!(out.contains("hello"));
        assert!(out.contains("world"));
    }

    #[test]
    fn extract_strings_includes_trailing_run_without_terminator() {
        // No trailing null: the final run should still be emitted
        let out = extract_strings(b"\x00abcde");
        assert!(out.contains("abcde"));
    }

    #[test]
    fn extract_strings_exactly_four_chars_is_included() {
        let out = extract_strings(b"\x00abcd\x00");
        assert!(out.contains("abcd"));
    }

    #[test]
    fn extract_strings_three_chars_is_excluded() {
        let out = extract_strings(b"\x00abc\x00");
        assert!(!out.contains("abc"));
    }

    #[test]
    fn extract_strings_space_is_printable() {
        let out = extract_strings(b"ab cd");
        assert!(out.contains("ab cd"));
    }

    // ── find_pem_keys ─────────────────────────────────────────────────────────

    const FAKE_KEY: &str = "-----BEGIN PRIVATE KEY-----\n\
                            MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEA\n\
                            -----END PRIVATE KEY-----";

    const FAKE_KEY_2: &str = "-----BEGIN PRIVATE KEY-----\n\
                              AAABBBCCC111222333\n\
                              -----END PRIVATE KEY-----";

    #[test]
    fn find_pem_keys_no_keys() {
        assert!(find_pem_keys("no keys here at all").is_empty());
    }

    #[test]
    fn find_pem_keys_begin_without_end_not_matched() {
        let input = "-----BEGIN PRIVATE KEY-----\nMIIE\nno end marker";
        assert!(find_pem_keys(input).is_empty());
    }

    #[test]
    fn find_pem_keys_end_without_begin_not_matched() {
        let input = "no begin marker\n-----END PRIVATE KEY-----";
        assert!(find_pem_keys(input).is_empty());
    }

    #[test]
    fn find_pem_keys_single_key() {
        let keys = find_pem_keys(FAKE_KEY);
        assert_eq!(keys.len(), 1);
        assert!(keys[0].contains("BEGIN PRIVATE KEY"));
        assert!(keys[0].contains("END PRIVATE KEY"));
    }

    #[test]
    fn find_pem_keys_multiple_keys() {
        let input = format!("{}\nsome junk\n{}", FAKE_KEY, FAKE_KEY_2);
        let keys = find_pem_keys(&input);
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn find_pem_keys_surrounded_by_binary_noise() {
        let input = format!("junk before\n{}\njunk after", FAKE_KEY);
        let keys = find_pem_keys(&input);
        assert_eq!(keys.len(), 1);
    }

    #[test]
    fn find_pem_keys_wrong_key_type_not_matched() {
        // RSA PRIVATE KEY is a different header — should not match PRIVATE KEY regex
        let input = "-----BEGIN RSA PRIVATE KEY-----\ndata\n-----END RSA PRIVATE KEY-----";
        // The regex requires exactly "PRIVATE KEY" not "RSA PRIVATE KEY" between delimiters
        assert!(find_pem_keys(input).is_empty());
    }
}

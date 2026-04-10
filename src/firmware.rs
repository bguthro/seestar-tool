//! Firmware extraction and OTA upload.
//! Mirrors extract_iscope() and upload_file()/wait_for_scope() from install_firmware.py.

use anyhow::{anyhow, Result};
use std::net::TcpStream;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::apk::open_apk;

const UPDATER_CMD_PORT: u16 = 4350;
const UPDATER_DATA_PORT: u16 = 4361;
const ISCOPE_ASSETS: &[&str] = &["assets/iscope", "assets/iscope_64"];
/// Typical time for the scope to install firmware before rebooting.
const INSTALL_ESTIMATE_SECS: u64 = 180;

// ── iscope extraction ─────────────────────────────────────────────────────────

/// Extract `assets/iscope` bytes from an APK or XAPK file.
/// Searches all split APKs for the asset when dealing with an XAPK.
pub fn extract_iscope(apk_path: &str, progress: impl Fn(String)) -> Result<Vec<u8>> {
    progress("Opening APK…".to_string());
    let handle = open_apk(apk_path, ISCOPE_ASSETS)?;

    if !handle.split_name.is_empty() {
        progress(format!("Using split APK: {}", handle.split_name));
    }

    let names = handle.file_names()?;
    let asset = ISCOPE_ASSETS
        .iter()
        .find(|a| names.contains(&a.to_string()))
        .ok_or_else(|| anyhow!("assets/iscope not found in APK"))?;

    progress(format!("Extracting {}…", asset));
    let data = handle.read(asset)?;
    progress(format!("Extracted {} ({} MB)", asset, data.len() >> 20));
    Ok(data)
}

// ── OTA upload ───────────────────────────────────────────────────────────────

/// Upload a firmware blob (raw iscope bytes) to a Seestar.
///
/// The protocol (observed from `zwoair_updater`):
///   1. Connect to data port 4361.
///   2. Connect to command port 4350 — scope sends a greeting JSON line.
///   3. Send `begin_recv` JSON on the command socket.
///   4. Scope replies with ACK (or error) JSON.
///   5. Stream the file on the data socket.
///   6. Scope installs, reboots, and comes back on port 4350.
pub fn upload_firmware(
    address: &str,
    iscope_data: &[u8],
    remote_filename: &str,
    progress: impl Fn(String) + Send + 'static,
    upload_progress: impl Fn(u64, u64) + Send + 'static,
) -> Result<()> {
    let file_len = iscope_data.len();
    let fmd5 = format!("{:x}", md5::compute(iscope_data));

    progress(format!("Connecting to {}…", address));

    // Connect data socket first, then command socket (order matters).
    let mut s_data = TcpStream::connect(format!("{}:{}", address, UPDATER_DATA_PORT))
        .map_err(|e| anyhow!("Cannot connect to data port {}: {}", UPDATER_DATA_PORT, e))?;
    let mut s_cmd = TcpStream::connect(format!("{}:{}", address, UPDATER_CMD_PORT))
        .map_err(|e| anyhow!("Cannot connect to command port {}: {}", UPDATER_CMD_PORT, e))?;

    s_cmd.set_read_timeout(Some(Duration::from_secs(10)))?;

    // Read greeting from command socket.
    let greeting = recv_line(&mut s_cmd)?;
    let name = serde_json::from_str::<serde_json::Value>(&greeting)
        .ok()
        .and_then(|v| v["name"].as_str().map(String::from))
        .unwrap_or_else(|| "updater".to_string());
    progress(format!("Connected to {} ({})", address, name));

    // Send begin_recv command.
    let cmd = serde_json::json!({
        "id": 1,
        "method": "begin_recv",
        "params": [{
            "file_len": file_len,
            "file_name": remote_filename,
            "run_update": true,
            "md5": fmd5
        }]
    });
    let cmd_str = format!("{}\r\n", cmd);
    use std::io::Write;
    s_cmd.write_all(cmd_str.as_bytes())?;

    // Read ACK.
    let ack = recv_line(&mut s_cmd)?;
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&ack) {
        if !v["error"].is_null() {
            return Err(anyhow!("Scope error: {}", v["error"]));
        }
    }

    // Stream firmware on data socket.
    progress("Uploading firmware…".to_string());
    let chunk_size = 4096;
    let mut sent: u64 = 0;
    for chunk in iscope_data.chunks(chunk_size) {
        s_data.write_all(chunk)?;
        sent += chunk.len() as u64;
        upload_progress(sent, file_len as u64);
    }

    drop(s_data);
    drop(s_cmd);

    progress("Firmware uploaded — scope is installing…".to_string());
    upload_progress(0, 0); // reset upload bar before wait phase
    wait_for_scope(
        address,
        UPDATER_CMD_PORT,
        Duration::from_secs(300),
        progress,
        upload_progress,
    )?;
    Ok(())
}

/// Upload a raw iscope file from disk.
pub fn upload_firmware_file(
    address: &str,
    path: &Path,
    remote_filename: &str,
    progress: impl Fn(String) + Send + 'static,
    upload_progress: impl Fn(u64, u64) + Send + 'static,
) -> Result<()> {
    let data = std::fs::read(path)?;
    upload_firmware(address, &data, remote_filename, progress, upload_progress)
}

// ── Scope availability polling ────────────────────────────────────────────────

/// Wait for the scope to go offline (reboot) and come back online.
///
/// `install_progress(done, total)` drives the egui progress bar:
///   - `(elapsed, INSTALL_ESTIMATE_SECS)` → countdown bar during install
///   - `(0, 0)` → indeterminate/bounce bar while rebooting or over-estimate
fn wait_for_scope(
    address: &str,
    port: u16,
    timeout: Duration,
    progress: impl Fn(String),
    install_progress: impl Fn(u64, u64),
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    let t0 = Instant::now();

    // Phase 1: countdown bar while scope installs; switch to indeterminate once
    // the estimate is exceeded.  Break when scope goes offline (reboot starts).
    progress("Installing firmware…".to_string());
    loop {
        if Instant::now() >= deadline {
            return Err(anyhow!("Timed out waiting for scope to reboot"));
        }
        if !can_connect(address, port) {
            progress("Scope is rebooting…".to_string());
            install_progress(0, 0);
            break;
        }
        let elapsed = t0.elapsed().as_secs();
        if elapsed < INSTALL_ESTIMATE_SECS {
            install_progress(elapsed, INSTALL_ESTIMATE_SECS);
        } else {
            install_progress(0, 0); // bounce / indeterminate
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // Phase 2: indeterminate bar while scope reboots and comes back online.
    loop {
        if Instant::now() >= deadline {
            return Err(anyhow!("Timed out waiting for scope to come back online"));
        }
        if can_connect(address, port) {
            let elapsed = t0.elapsed().as_secs();
            progress(format!("Scope is back online! ({elapsed}s)"));
            install_progress(0, 0);
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn can_connect(address: &str, port: u16) -> bool {
    use std::net::ToSocketAddrs;
    let Ok(addrs) = (address, port).to_socket_addrs() else {
        return false;
    };
    addrs
        .into_iter()
        .any(|addr| TcpStream::connect_timeout(&addr, Duration::from_secs(1)).is_ok())
}

fn recv_line(stream: &mut TcpStream) -> Result<String> {
    use std::io::Read;
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                buf.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
            }
            Err(e) => return Err(anyhow!("Read error: {}", e)),
        }
    }
    Ok(String::from_utf8_lossy(&buf).trim().to_string())
}

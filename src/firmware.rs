//! Firmware extraction and OTA upload.
//! Mirrors extract_iscope() and upload_file()/wait_for_scope() from install_firmware.py.

use anyhow::{Result, anyhow};
use std::net::TcpStream;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::apk::open_apk;

pub const UPDATER_CMD_PORT: u16 = 4350;
pub const UPDATER_DATA_PORT: u16 = 4361;
/// Typical time for the scope to install firmware before rebooting.
const INSTALL_ESTIMATE_SECS: u64 = 180;

/// Which Seestar model is being updated — determines the firmware binary variant.
#[derive(Clone, Copy, PartialEq, Default, Debug)]
pub enum ScopeModel {
    /// Auto-detect the model from the scope's API before flashing.
    #[default]
    Auto,
    /// S50 — uses the 32-bit `iscope` binary (ARMv7).
    S50,
    /// S30 — uses the 32-bit `iscope` binary (ARMv7l).
    S30,
    /// S30 Pro — uses the 64-bit `iscope_64` binary (ARM64).
    S30Pro,
}

impl ScopeModel {
    /// The APK asset path for this model's firmware binary.
    /// Panics if called on `Auto` (must be resolved first).
    pub fn asset_name(self) -> &'static str {
        match self {
            ScopeModel::S50 | ScopeModel::S30 => "assets/iscope",
            ScopeModel::S30Pro => "assets/iscope_64",
            ScopeModel::Auto => panic!("ScopeModel::Auto must be resolved before use"),
        }
    }

    /// The filename sent to the scope's OTA updater.
    /// Panics if called on `Auto` (must be resolved first).
    pub fn remote_filename(self) -> &'static str {
        match self {
            ScopeModel::S50 | ScopeModel::S30 => "iscope",
            ScopeModel::S30Pro => "iscope_64",
            ScopeModel::Auto => panic!("ScopeModel::Auto must be resolved before use"),
        }
    }

    pub fn is_auto(self) -> bool {
        matches!(self, ScopeModel::Auto)
    }

    pub fn display_name(self) -> &'static str {
        match self {
            ScopeModel::Auto => "Auto",
            ScopeModel::S50 => "S50",
            ScopeModel::S30 => "S30",
            ScopeModel::S30Pro => "S30 Pro",
        }
    }

    /// Human-readable description of the firmware variant this model requires.
    /// Panics if called on `Auto`.
    pub fn bitness_description(self) -> &'static str {
        match self {
            ScopeModel::S50 | ScopeModel::S30 => "32-bit ARM (iscope)",
            ScopeModel::S30Pro => "64-bit ARM (iscope_64)",
            ScopeModel::Auto => panic!("ScopeModel::Auto must be resolved before use"),
        }
    }
}

/// Information retrieved from the scope during model auto-detection.
#[derive(Clone, Debug)]
pub struct DeviceInfo {
    pub model: ScopeModel,
    /// Firmware version string reported by the scope (e.g. `"4.70"`).
    pub firmware_ver_string: Option<String>,
    /// Battery charge level (0–100), absent if the field was missing.
    pub battery_capacity: Option<u8>,
    /// True when the scope reports it is not discharging (i.e. charging or full).
    pub battery_charging: bool,
}

impl DeviceInfo {
    const LOW_BATTERY_BLOCK_PCT: u8 = 20;
    const LOW_BATTERY_WARN_PCT: u8 = 50;

    /// Returns `Err` if the battery is critically low and the scope is not
    /// charging.  A power-off mid-flash can brick the scope.
    pub fn check_battery(&self) -> Result<()> {
        if let Some(pct) = self.battery_capacity
            && pct < Self::LOW_BATTERY_BLOCK_PCT
            && !self.battery_charging
        {
            return Err(anyhow!(
                "Battery too low to safely flash firmware ({}%). \
                     Charge to at least {}% or connect a charger first.",
                pct,
                Self::LOW_BATTERY_BLOCK_PCT
            ));
        }
        Ok(())
    }

    /// Returns a warning string if battery is below the recommended level but
    /// not critically low.  Returns `None` when battery is fine or unknown.
    pub fn battery_warning(&self) -> Option<String> {
        let pct = self.battery_capacity?;
        if pct < Self::LOW_BATTERY_WARN_PCT && !self.battery_charging {
            Some(format!(
                "Battery at {}% — consider charging to {}%+ before flashing.",
                pct,
                Self::LOW_BATTERY_WARN_PCT
            ))
        } else {
            None
        }
    }
}

/// Raw API responses collected during a diagnostics run.
#[derive(Debug, Clone)]
pub struct DiagnosticsData {
    pub device_state: serde_json::Value,
    pub pi_info: serde_json::Value,
}

impl DiagnosticsData {
    /// Redact fields that may contain personally identifiable or sensitive
    /// information before the data is displayed or saved.
    pub fn anonymize(&mut self) {
        for ptr in ["/result/ap/passwd", "/result/location_lon_lat"] {
            if let Some(v) = self.device_state.pointer_mut(ptr) {
                *v = serde_json::Value::String("[redacted]".to_string());
            }
        }
    }
}

// ── iscope validation ─────────────────────────────────────────────────────────

/// Minimum acceptable size for an iscope firmware binary.
const ISCOPE_MIN_BYTES: usize = 256 * 1024; // 256 KB

/// Validate that `data` is a plausible iscope firmware archive for `model`.
///
/// An iscope file is a bzip2-compressed tar archive with a 128-byte RSA
/// signature appended at the end.
///
/// Checks:
/// 1. Minimum file size (of the compressed stream)
/// 2. bzip2 magic bytes `BZh` at offset 0
/// 3. Opens the tar and reads the first ELF binary found; verifies its class
///    byte matches the expected bitness for `model` (32-bit for S50, 64-bit
///    for S30 Pro).  This catches a renamed/swapped firmware file that would
///    otherwise pass the container-format check.
///
/// Returns `Err` with a human-readable message on any mismatch.
#[cfg(test)]
fn validate_iscope_data(data: &[u8], model: ScopeModel) -> Result<()> {
    validate_iscope_data_inner(data, model, ISCOPE_MIN_BYTES)
}

fn validate_iscope_data_inner(data: &[u8], model: ScopeModel, min_bytes: usize) -> Result<()> {
    if model.is_auto() {
        return Err(anyhow!(
            "BUG: model must be resolved before validating firmware."
        ));
    }
    if data.len() < min_bytes {
        return Err(anyhow!(
            "Firmware file is too small ({} bytes; minimum {}). \
             The file is likely corrupted or incomplete.",
            data.len(),
            min_bytes
        ));
    }
    // bzip2 magic: 'B' 'Z' 'h' followed by a block-size digit '1'..'9'
    if data.len() < 3 || &data[..3] != b"BZh" {
        return Err(anyhow!(
            "Firmware file does not start with a bzip2 header (expected 'BZh'). \
             The file is likely corrupted or is not a Seestar firmware archive."
        ));
    }
    validate_iscope_elf_class(data, model)
}

/// Expected ELF class for each model.
fn expected_elf_class(model: ScopeModel) -> u8 {
    match model {
        ScopeModel::S50 | ScopeModel::S30 => 1, // ELFCLASS32
        ScopeModel::S30Pro => 2,                // ELFCLASS64
        ScopeModel::Auto => unreachable!(),
    }
}

/// Open the tar.bz2, find the first ELF binary, and verify its class byte
/// matches `model`.  The 128-byte RSA signature appended after the bzip2
/// stream is ignored by the decompressor, so no stripping is needed.
fn validate_iscope_elf_class(data: &[u8], model: ScopeModel) -> Result<()> {
    use bzip2::read::BzDecoder;
    use std::io::Read;

    let decoder = BzDecoder::new(data);
    let mut archive = tar::Archive::new(decoder);

    let expected = expected_elf_class(model);
    let expected_name = if expected == 1 { "32-bit" } else { "64-bit" };
    let wrong_name = if expected == 1 { "64-bit" } else { "32-bit" };

    for entry in archive.entries()? {
        let mut entry = entry?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        // Read just the first 5 bytes (ELF ident magic + class)
        let mut header = [0u8; 5];
        let n = entry.read(&mut header)?;
        if n >= 5 && &header[..4] == b"\x7fELF" {
            let elf_class = header[4];
            if elf_class != expected {
                let name = entry
                    .path()
                    .ok()
                    .and_then(|p| p.to_str().map(String::from))
                    .unwrap_or_else(|| "(unknown)".to_string());
                return Err(anyhow!(
                    "Firmware contains a {wrong_name} binary ({name}) but \
                     the {} requires {expected_name} firmware. \
                     This would brick the scope — aborting. \
                     Check that the correct model is selected.",
                    model.display_name(),
                ));
            }
            // First ELF matched — archive is consistent with `model`.
            return Ok(());
        }
    }

    // No ELF binaries at all is suspicious but not definitely wrong
    // (could be a future firmware format); don't block the install.
    Ok(())
}

// ── iscope extraction ─────────────────────────────────────────────────────────

/// Extract the firmware binary for `model` from an APK or XAPK file.
/// Searches all split APKs for the asset when dealing with an XAPK.
pub fn extract_iscope(
    apk_path: &str,
    model: ScopeModel,
    progress: impl FnMut(String),
) -> Result<Vec<u8>> {
    extract_iscope_inner(apk_path, model, ISCOPE_MIN_BYTES, progress)
}

fn extract_iscope_inner(
    apk_path: &str,
    model: ScopeModel,
    min_bytes: usize,
    mut progress: impl FnMut(String),
) -> Result<Vec<u8>> {
    let asset = model.asset_name();
    progress("Opening APK…".to_string());
    let handle = open_apk(apk_path, &[asset])?;

    if !handle.split_name.is_empty() {
        progress(format!("Using split APK: {}", handle.split_name));
    }

    progress(format!("Extracting {}…", asset));
    let data = handle
        .read(asset)
        .map_err(|_| anyhow!("{} not found in APK", asset))?;
    progress(format!("Extracted {} ({} MB)", asset, data.len() >> 20));

    validate_iscope_data_inner(&data, model, min_bytes)?;
    progress(format!("Validated {} (bzip2 header OK, size OK)", asset));
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
    upload_firmware_inner(
        address,
        iscope_data,
        remote_filename,
        UploadPorts::default(),
        progress,
        upload_progress,
    )
}

/// Port and timeout configuration for the OTA upload — overridden in tests.
struct UploadPorts {
    cmd_port: u16,
    data_port: u16,
    wait_timeout: Duration,
}

impl Default for UploadPorts {
    fn default() -> Self {
        Self {
            cmd_port: UPDATER_CMD_PORT,
            data_port: UPDATER_DATA_PORT,
            wait_timeout: Duration::from_secs(300),
        }
    }
}

fn upload_firmware_inner(
    address: &str,
    iscope_data: &[u8],
    remote_filename: &str,
    ports: UploadPorts,
    progress: impl Fn(String) + Send + 'static,
    upload_progress: impl Fn(u64, u64) + Send + 'static,
) -> Result<()> {
    let UploadPorts {
        cmd_port,
        data_port,
        wait_timeout,
    } = ports;

    // Safety: only known firmware filenames are accepted.
    const ALLOWED_FILENAMES: &[&str] = &["iscope", "iscope_64"];
    if !ALLOWED_FILENAMES.contains(&remote_filename) {
        return Err(anyhow!(
            "Unexpected firmware filename '{}'. Only 'iscope' and 'iscope_64' are accepted. Aborting for safety.",
            remote_filename
        ));
    }

    let file_len = iscope_data.len();
    let fmd5 = format!("{:x}", md5::compute(iscope_data));

    progress(format!("Connecting to {}…", address));

    // Connect data socket first, then command socket (order matters).
    let mut s_data = TcpStream::connect(format!("{}:{}", address, data_port))
        .map_err(|e| anyhow!("Cannot connect to data port {}: {}", data_port, e))?;
    let mut s_cmd = TcpStream::connect(format!("{}:{}", address, cmd_port))
        .map_err(|e| anyhow!("Cannot connect to command port {}: {}", cmd_port, e))?;

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
    match serde_json::from_str::<serde_json::Value>(&ack) {
        Ok(v) => {
            if !v["error"].is_null() {
                return Err(anyhow!("Scope rejected firmware upload: {}", v["error"]));
            }
            let code = v["code"].as_i64().unwrap_or(0);
            if code != 0 {
                return Err(anyhow!(
                    "Scope rejected firmware upload (code {}): {}",
                    code,
                    ack
                ));
            }
        }
        Err(_) => {
            return Err(anyhow!(
                "Invalid response from scope during upload handshake: {}",
                ack
            ));
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
    let _fw_ver = wait_for_scope(
        address,
        cmd_port,
        wait_timeout,
        None,
        progress,
        upload_progress,
    )?;
    Ok(())
}

/// Upload a raw iscope file from disk.
pub fn upload_firmware_file(
    address: &str,
    path: &Path,
    model: ScopeModel,
    progress: impl Fn(String) + Send + 'static,
    upload_progress: impl Fn(u64, u64) + Send + 'static,
) -> Result<()> {
    upload_firmware_file_inner(
        address,
        path,
        model,
        ISCOPE_MIN_BYTES,
        progress,
        upload_progress,
    )
}

fn upload_firmware_file_inner(
    address: &str,
    path: &Path,
    model: ScopeModel,
    min_bytes: usize,
    progress: impl Fn(String) + Send + 'static,
    upload_progress: impl Fn(u64, u64) + Send + 'static,
) -> Result<()> {
    let data = std::fs::read(path)?;
    validate_iscope_data_inner(&data, model, min_bytes)?;
    upload_firmware(
        address,
        &data,
        model.remote_filename(),
        progress,
        upload_progress,
    )
}

// ── Scope availability polling ────────────────────────────────────────────────

/// Query the scope's firmware version by connecting to the API port.
/// Used for post-installation verification to confirm firmware actually updated.
pub(crate) fn query_firmware_version(address: &str, pem_key: &[u8]) -> Result<Option<String>> {
    detect_scope_model_on_port(address, API_PORT, pem_key, |_| {})
        .map(|info| info.firmware_ver_string)
}

/// Check network connectivity to both command and data ports before firmware install.
/// Returns `Err` with actionable guidance if either port is unreachable.
pub(crate) fn preflight_network_check(address: &str, cmd_port: u16, data_port: u16) -> Result<()> {
    use std::time::Instant;
    let start = Instant::now();

    // Check command port
    if !can_connect(address, cmd_port) {
        return Err(anyhow!(
            "Cannot connect to {}:{} (command port). \
             Verify: 1) Scope is powered on, 2) Network is connected, 3) Firewall allows connection.",
            address,
            cmd_port
        ));
    }

    // Check data port
    if !can_connect(address, data_port) {
        return Err(anyhow!(
            "Cannot connect to {}:{} (data port). \
             Verify: 1) Scope is powered on, 2) Network is connected, 3) Firewall allows connection.",
            address,
            data_port
        ));
    }

    let elapsed = start.elapsed();
    if elapsed.as_millis() > 500 {
        eprintln!(
            "⚠️  Network connection is slow ({}ms). Install may timeout if connection degrades.",
            elapsed.as_millis()
        );
    }
    Ok(())
}

/// Wait for the scope to go offline (reboot) and come back online.
/// Also queries and verifies the firmware version after coming back online.
/// Returns the new firmware version if available.
///
/// `install_progress(done, total)` drives the egui progress bar:
///   - `(elapsed, INSTALL_ESTIMATE_SECS)` → countdown bar during install
///   - `(0, 0)` → indeterminate/bounce bar while rebooting or over-estimate
///
/// Returns the firmware version string if available after coming back online.
pub(crate) fn wait_for_scope(
    address: &str,
    port: u16,
    timeout: Duration,
    pem_key: Option<&[u8]>,
    mut progress: impl FnMut(String),
    mut install_progress: impl FnMut(u64, u64),
) -> Result<Option<String>> {
    let deadline = Instant::now() + timeout;
    let t0 = Instant::now();

    // Phase 1: countdown bar while scope installs; switch to indeterminate once
    // the estimate is exceeded.  Break when scope goes offline (reboot starts).
    // Include "DO NOT POWER OFF" warning.
    progress("⚠️  Installation in progress — DO NOT power off the scope".to_string());
    let mut warned_once = false;
    loop {
        if Instant::now() >= deadline {
            return Err(anyhow!(
                "Timed out waiting for scope to reboot ({}s). \
                 The installation may still be in progress. \
                 IMPORTANT: Do not power off the scope yet. \
                 Try rebooting the scope manually if it doesn't come back within a few minutes.",
                timeout.as_secs()
            ));
        }
        if !can_connect(address, port) {
            progress("🔄 Scope is rebooting — please wait…".to_string());
            install_progress(0, 0);
            break;
        }
        // Repeat warning every ~2 seconds
        if t0.elapsed().as_secs().is_multiple_of(2) && !warned_once {
            progress("⚠️  Installation in progress — DO NOT power off the scope".to_string());
            warned_once = true;
        } else if !t0.elapsed().as_secs().is_multiple_of(2) {
            warned_once = false;
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
    // Try to actually connect and read greeting to ensure scope is fully ready.
    progress("⏳ Waiting for scope to come back online…".to_string());
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(anyhow!(
                "Timed out waiting for scope to come back online after {}s. \
                 This may indicate a failed installation. \
                 VERIFICATION NEEDED: Manually check the scope's firmware version. \
                 If it hasn't updated, you may need to reinstall.",
                timeout.as_secs()
            ));
        }
        // Try to connect and read greeting message (scope is ready once it sends this).
        if let Ok(mut stream) = TcpStream::connect(format!("{}:{}", address, port)) {
            stream.set_read_timeout(Some(Duration::from_millis(500)))?;
            if recv_line(&mut stream).is_ok() {
                let elapsed = t0.elapsed().as_secs();
                progress(format!("✓ Scope is back online! ({elapsed}s)"));
                install_progress(0, 0);

                // Phase 3: Query firmware version to verify installation succeeded.
                if let Some(key) = pem_key {
                    progress("Verifying firmware version…".to_string());
                    match query_firmware_version(address, key) {
                        Ok(fw_ver) => {
                            if let Some(ref ver) = fw_ver {
                                progress(format!("✓ Firmware verified: {}", ver));
                            }
                            return Ok(fw_ver);
                        }
                        Err(e) => {
                            // Don't fail — firmware is installed, just couldn't verify
                            progress(format!(
                                "⚠️  Could not verify firmware version: {}. \
                                 The installation appears successful but verification failed. \
                                 Please check manually.",
                                e
                            ));
                            return Ok(None);
                        }
                    }
                } else {
                    return Ok(None);
                }
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

pub(crate) fn can_connect(address: &str, port: u16) -> bool {
    use std::net::ToSocketAddrs;
    let Ok(addrs) = (address, port).to_socket_addrs() else {
        return false;
    };
    addrs
        .into_iter()
        .any(|addr| TcpStream::connect_timeout(&addr, Duration::from_secs(1)).is_ok())
}

pub(crate) fn recv_line(stream: &mut TcpStream) -> Result<String> {
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

// ── Model auto-detection ──────────────────────────────────────────────────────

const API_PORT: u16 = 4700;

/// Connect to the scope's JSON-RPC API on port 4700, authenticate with
/// RSA SHA1/PKCS1v15 challenge-response, and read device state.
///
/// Returns a [`DeviceInfo`] containing the resolved [`ScopeModel`] plus
/// optional firmware version and battery information.
pub fn detect_scope_model(
    address: &str,
    pem_key: &[u8],
    log: impl Fn(String),
) -> Result<DeviceInfo> {
    detect_scope_model_on_port(address, API_PORT, pem_key, log)
}

/// Read lines from `stream`, skipping async Event pushes, until a non-event response arrives.
fn recv_api_response(stream: &mut TcpStream, log: &impl Fn(String)) -> Result<serde_json::Value> {
    loop {
        let line = recv_line(stream)?;
        let v: serde_json::Value = serde_json::from_str(&line)
            .map_err(|_| anyhow!("Invalid JSON from scope: {}", line))?;
        if v.get("Event").is_some() {
            log(format!(
                "(skipping event: {})",
                v["Event"].as_str().unwrap_or("?")
            ));
            continue;
        }
        break Ok(v);
    }
}

/// Authenticate to the scope API and return the open `TcpStream`.
///
/// Performs the three-step challenge-response handshake (get_verify_str →
/// verify_client → pi_is_verified).  The returned stream is ready for
/// subsequent JSON-RPC calls.
fn authenticate_stream(
    address: &str,
    port: u16,
    pem_key: &[u8],
    log: &impl Fn(String),
) -> Result<TcpStream> {
    use base64::Engine;
    use rsa::pkcs1v15::SigningKey;
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::signature::{SignatureEncoding, Signer};
    use sha1::Sha1;
    use std::io::Write;
    use std::net::ToSocketAddrs;

    log(format!("Connecting to {}:{}…", address, port));
    let addrs: Vec<_> = (address, port).to_socket_addrs()?.collect();
    if addrs.is_empty() {
        return Err(anyhow!("Cannot resolve {}", address));
    }
    log(format!(
        "Resolved {} address(es): {}",
        addrs.len(),
        addrs
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    ));
    let mut stream = addrs
        .iter()
        .find_map(|addr| TcpStream::connect_timeout(addr, Duration::from_secs(5)).ok())
        .ok_or_else(|| anyhow!("Cannot connect to {}:{}: Connection refused", address, port))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    log("Connected".to_string());

    // Step 1: get_verify_str — params must be the string "verify"
    // (port 4700 does not send a greeting on connect, unlike port 4350)
    let req = serde_json::json!({"id":1,"method":"get_verify_str","params":"verify"});
    log(format!("-> {}", req));
    stream.write_all(format!("{}\r\n", req).as_bytes())?;
    let resp = recv_line(&mut stream)?;
    log(format!("<- {}", resp));
    let resp_v: serde_json::Value =
        serde_json::from_str(&resp).map_err(|_| anyhow!("Invalid JSON from scope: {}", resp))?;
    // result may be {"str":"..."} or just the string directly
    let challenge = resp_v["result"]["str"]
        .as_str()
        .or_else(|| resp_v["result"].as_str())
        .ok_or_else(|| anyhow!("No challenge string in: {}", resp))?
        .to_string();
    log(format!("Challenge: {}", challenge));

    // Sign challenge with RSA SHA1/PKCS1v15
    let pem_str = std::str::from_utf8(pem_key)?;
    let private_key = rsa::RsaPrivateKey::from_pkcs8_pem(pem_str)
        .map_err(|e| anyhow!("Failed to load PEM key: {}", e))?;
    let signing_key = SigningKey::<Sha1>::new(private_key);
    let signature = Signer::sign(&signing_key, challenge.as_bytes());
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());
    log(format!(
        "Signature (b64, first 20): {}…",
        &sig_b64[..sig_b64.len().min(20)]
    ));

    // Step 2: verify_client
    let verify_req = serde_json::json!({
        "id": 2,
        "method": "verify_client",
        "params": {"sign": sig_b64, "data": challenge}
    });
    log("-> verify_client".to_string());
    stream.write_all(format!("{}\r\n", verify_req).as_bytes())?;
    let ack = recv_line(&mut stream)?;
    log(format!("<- {}", ack));
    let ack_v: serde_json::Value =
        serde_json::from_str(&ack).map_err(|_| anyhow!("Invalid JSON from scope: {}", ack))?;
    if ack_v["code"].as_i64().unwrap_or(-1) != 0 {
        return Err(anyhow!(
            "Authentication failed (code {}): {}",
            ack_v["code"],
            ack
        ));
    }

    // Step 3: pi_is_verified — required to complete the handshake
    let pi_req = serde_json::json!({"id":3,"method":"pi_is_verified","params":"verify"});
    log("-> pi_is_verified".to_string());
    stream.write_all(format!("{}\r\n", pi_req).as_bytes())?;
    let pi_ack = recv_line(&mut stream)?;
    log(format!("<- {}", pi_ack));
    // Non-zero result is non-fatal (seestar_alp also ignores it)

    Ok(stream)
}

fn detect_scope_model_on_port(
    address: &str,
    port: u16,
    pem_key: &[u8],
    log: impl Fn(String),
) -> Result<DeviceInfo> {
    use std::io::Write;

    let mut stream = authenticate_stream(address, port, pem_key, &log)?;

    // get_device_state — skip any async event pushes while waiting for our response
    let state_req = serde_json::json!({"id":4,"method":"get_device_state","params":[]});
    stream.write_all(format!("{}\r\n", state_req).as_bytes())?;
    let state_v = recv_api_response(&mut stream, &log)?;
    let product_model = state_v["result"]["device"]["product_model"]
        .as_str()
        .ok_or_else(|| anyhow!("No product_model in: {}", state_v))?;

    log(format!("product_model: {}", product_model));

    // Be strict: only accept known model strings. Defaulting on an unrecognised
    // model would flash the wrong firmware variant and could brick the scope.
    // Check "S30 Pro" before "S30" — the latter is a substring of the former.
    let model = if product_model.contains("S30 Pro") {
        ScopeModel::S30Pro
    } else if product_model.contains("S30") {
        ScopeModel::S30
    } else if product_model.contains("S50") {
        ScopeModel::S50
    } else {
        return Err(anyhow!(
            "Unrecognized product_model '{}'. \
             Cannot safely determine the firmware variant — aborting. \
             Select your model manually (S50, S30, or S30 Pro).",
            product_model
        ));
    };

    // Parse optional device info — missing fields are treated as unknown.
    let firmware_ver_string = state_v["result"]["device"]["firmware_ver_string"]
        .as_str()
        .map(|s| s.to_string());
    let battery_capacity = state_v["result"]["pi_status"]["battery_capacity"]
        .as_u64()
        .map(|n| n.min(100) as u8);
    let battery_charging = state_v["result"]["pi_status"]["charger_status"]
        .as_str()
        .map(|s| s != "Discharging")
        .unwrap_or(false);

    log(format!(
        "firmware: {}  battery: {}{}",
        firmware_ver_string.as_deref().unwrap_or("unknown"),
        battery_capacity
            .map(|p| format!("{}%", p))
            .as_deref()
            .unwrap_or("unknown"),
        if battery_charging { " (charging)" } else { "" },
    ));

    Ok(DeviceInfo {
        model,
        firmware_ver_string,
        battery_capacity,
        battery_charging,
    })
}

/// Authenticate to the scope and collect `get_device_state` + `pi_get_info` responses.
pub fn run_diagnostics(
    address: &str,
    pem_key: &[u8],
    log: impl Fn(String),
) -> Result<DiagnosticsData> {
    run_diagnostics_on_port(address, API_PORT, pem_key, log)
}

pub(crate) fn run_diagnostics_on_port(
    address: &str,
    port: u16,
    pem_key: &[u8],
    log: impl Fn(String),
) -> Result<DiagnosticsData> {
    use std::io::Write;

    let mut stream = authenticate_stream(address, port, pem_key, &log)?;

    // get_device_state
    let state_req = serde_json::json!({"id":4,"method":"get_device_state","params":[]});
    stream.write_all(format!("{}\r\n", state_req).as_bytes())?;
    let device_state = recv_api_response(&mut stream, &log)?;
    log("get_device_state: OK".to_string());

    // pi_get_info
    let info_req = serde_json::json!({"id":5,"method":"pi_get_info","params":[]});
    stream.write_all(format!("{}\r\n", info_req).as_bytes())?;
    let pi_info = recv_api_response(&mut stream, &log)?;
    log("pi_get_info: OK".to_string());

    Ok(DiagnosticsData {
        device_state,
        pi_info,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    // ── helpers ───────────────────────────────────────────────────────────────

    /// Serve one connection that sends `data` then closes.
    fn serve_once(data: &'static [u8]) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            conn.write_all(data).unwrap();
        });
        addr
    }

    /// Build a minimal real tar.bz2 containing a single fake ELF binary of
    /// `elf_class` (1 = 32-bit, 2 = 64-bit).
    ///
    /// The compressed output is small (a few KB) — tests that need the size
    /// check to pass must call `validate_iscope_data_inner` with a small
    /// `min_bytes`, not `validate_iscope_data` which uses `ISCOPE_MIN_BYTES`.
    fn make_fake_iscope(elf_class: u8) -> Vec<u8> {
        use bzip2::Compression;
        use bzip2::write::BzEncoder;

        let mut elf = vec![0u8; 64];
        elf[0..4].copy_from_slice(b"\x7fELF");
        elf[4] = elf_class;

        let tar_buf = Vec::new();
        let enc = BzEncoder::new(tar_buf, Compression::fast());
        let mut builder = tar::Builder::new(enc);
        let mut header = tar::Header::new_gnu();
        header.set_size(elf.len() as u64);
        header.set_mode(0o755);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder
            .append_data(&mut header, "others/firmware_binary", elf.as_slice())
            .unwrap();
        let enc = builder.into_inner().unwrap();
        enc.finish().unwrap()
    }

    /// Build an in-memory APK ZIP containing `files` (path → bytes).
    fn make_apk(files: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::Cursor;
        use zip::write::{SimpleFileOptions, ZipWriter};
        let mut zw = ZipWriter::new(Cursor::new(Vec::new()));
        let opts = SimpleFileOptions::default();
        for (name, data) in files {
            zw.start_file(*name, opts).unwrap();
            zw.write_all(data).unwrap();
        }
        zw.finish().unwrap().into_inner()
    }

    /// RAII temp file deleted on drop.
    struct TempFile(std::path::PathBuf);
    impl TempFile {
        fn write(name: &str, data: &[u8]) -> Self {
            let path = std::env::temp_dir().join(name);
            std::fs::write(&path, data).unwrap();
            TempFile(path)
        }
        fn path_str(&self) -> &str {
            self.0.to_str().unwrap()
        }
    }
    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    // ── ScopeModel ────────────────────────────────────────────────────────────

    // ── validate_iscope_data ──────────────────────────────────────────────────

    #[test]
    fn validate_iscope_rejects_empty_data() {
        let err = validate_iscope_data(&[], ScopeModel::S50).unwrap_err();
        assert!(err.to_string().contains("too small"));
    }

    #[test]
    fn validate_iscope_rejects_truncated_data() {
        let err = validate_iscope_data(&[0u8; 100], ScopeModel::S50).unwrap_err();
        assert!(err.to_string().contains("too small"));
    }

    #[test]
    fn validate_iscope_rejects_bad_magic() {
        let mut data = vec![0u8; ISCOPE_MIN_BYTES + 16];
        data[0..3].copy_from_slice(b"XXX");
        let err = validate_iscope_data(&data, ScopeModel::S50).unwrap_err();
        assert!(err.to_string().contains("bzip2"));
    }

    // ELF-class tests use validate_iscope_data_inner with a small min_bytes so we
    // don't need to inflate the fake archive to 256 KB after compression.
    const TEST_MIN_BYTES: usize = 64;

    #[test]
    fn validate_iscope_accepts_32bit_for_s50() {
        let data = make_fake_iscope(1);
        validate_iscope_data_inner(&data, ScopeModel::S50, TEST_MIN_BYTES).unwrap();
    }

    #[test]
    fn validate_iscope_accepts_64bit_for_s30pro() {
        let data = make_fake_iscope(2);
        validate_iscope_data_inner(&data, ScopeModel::S30Pro, TEST_MIN_BYTES).unwrap();
    }

    #[test]
    fn validate_iscope_rejects_64bit_elf_for_s50() {
        // iscope_64 archive (64-bit ELF inside) presented as S50 firmware — must fail.
        let data = make_fake_iscope(2);
        let err = validate_iscope_data_inner(&data, ScopeModel::S50, TEST_MIN_BYTES).unwrap_err();
        assert!(
            err.to_string().contains("64-bit"),
            "expected 64-bit mismatch error, got: {}",
            err
        );
    }

    #[test]
    fn validate_iscope_rejects_32bit_elf_for_s30pro() {
        // iscope archive (32-bit ELF inside) presented as S30 Pro firmware — must fail.
        let data = make_fake_iscope(1);
        let err =
            validate_iscope_data_inner(&data, ScopeModel::S30Pro, TEST_MIN_BYTES).unwrap_err();
        assert!(
            err.to_string().contains("32-bit"),
            "expected 32-bit mismatch error, got: {}",
            err
        );
    }

    #[test]
    fn detect_scope_model_unknown_product_model_returns_error() {
        // A product_model that contains neither S50 nor S30 should be rejected.
        let addr = serve_api_once("Seestar X99", 0);
        let pem = make_test_pem_key();
        let err = detect_scope_model_on_port("127.0.0.1", addr.port(), &pem, |_| {}).unwrap_err();
        assert!(
            err.to_string().contains("Unrecognized"),
            "expected unrecognized-model error, got: {}",
            err
        );
    }

    // ── scope_model ───────────────────────────────────────────────────────────

    #[test]
    fn scope_model_default_is_auto() {
        assert_eq!(ScopeModel::default(), ScopeModel::Auto);
    }

    #[test]
    fn scope_model_auto_is_auto() {
        assert!(ScopeModel::Auto.is_auto());
        assert!(!ScopeModel::S50.is_auto());
        assert!(!ScopeModel::S30.is_auto());
        assert!(!ScopeModel::S30Pro.is_auto());
    }

    #[test]
    fn scope_model_display_names() {
        assert_eq!(ScopeModel::Auto.display_name(), "Auto");
        assert_eq!(ScopeModel::S50.display_name(), "S50");
        assert_eq!(ScopeModel::S30.display_name(), "S30");
        assert_eq!(ScopeModel::S30Pro.display_name(), "S30 Pro");
    }

    #[test]
    fn scope_model_s50_asset_name() {
        assert_eq!(ScopeModel::S50.asset_name(), "assets/iscope");
    }

    #[test]
    fn scope_model_s30_asset_name() {
        // S30 is 32-bit ARMv7l — same iscope binary as S50
        assert_eq!(ScopeModel::S30.asset_name(), "assets/iscope");
    }

    #[test]
    fn scope_model_s30pro_asset_name() {
        assert_eq!(ScopeModel::S30Pro.asset_name(), "assets/iscope_64");
    }

    #[test]
    fn scope_model_s50_remote_filename() {
        assert_eq!(ScopeModel::S50.remote_filename(), "iscope");
    }

    #[test]
    fn scope_model_s30_remote_filename() {
        assert_eq!(ScopeModel::S30.remote_filename(), "iscope");
    }

    #[test]
    fn scope_model_s30pro_remote_filename() {
        assert_eq!(ScopeModel::S30Pro.remote_filename(), "iscope_64");
    }

    // ── extract_iscope ────────────────────────────────────────────────────────

    #[test]
    fn extract_iscope_s50_from_plain_apk() {
        let firmware = make_fake_iscope(1); // 32-bit for S50
        let firmware_64 = make_fake_iscope(2);
        let apk = make_apk(&[
            ("assets/iscope", &firmware),
            ("assets/iscope_64", &firmware_64),
        ]);
        let tmp = TempFile::write("fw_test_s50.apk", &apk);
        let mut logged_asset = String::new();
        let data = extract_iscope_inner(tmp.path_str(), ScopeModel::S50, TEST_MIN_BYTES, |s| {
            if s.contains("assets/") {
                logged_asset = s;
            }
        })
        .unwrap();
        assert_eq!(data, firmware);
        assert!(logged_asset.contains("assets/iscope"));
    }

    #[test]
    fn extract_iscope_s30pro_from_plain_apk() {
        let firmware = make_fake_iscope(2); // 64-bit for S30 Pro
        let firmware_32 = make_fake_iscope(1);
        let apk = make_apk(&[
            ("assets/iscope", &firmware_32),
            ("assets/iscope_64", &firmware),
        ]);
        let tmp = TempFile::write("fw_test_s30pro.apk", &apk);
        let data = extract_iscope_inner(tmp.path_str(), ScopeModel::S30Pro, TEST_MIN_BYTES, |_| {})
            .unwrap();
        assert_eq!(data, firmware);
    }

    #[test]
    fn extract_iscope_missing_asset_returns_error() {
        // APK has no iscope asset at all
        let apk = make_apk(&[("other/file.txt", b"stuff")]);
        let tmp = TempFile::write("fw_test_noasset.apk", &apk);
        let err = extract_iscope(tmp.path_str(), ScopeModel::S50, |_| {}).unwrap_err();
        assert!(err.to_string().contains("assets/iscope"));
    }

    #[test]
    fn extract_iscope_nonexistent_file_returns_error() {
        let err = extract_iscope("/nonexistent/fw_test.apk", ScopeModel::S50, |_| {}).unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn extract_iscope_from_xapk_logs_split_name() {
        use std::io::Cursor;
        use zip::write::{SimpleFileOptions, ZipWriter};

        let firmware = make_fake_iscope(1); // 32-bit for S50
        let inner_apk = make_apk(&[("assets/iscope", &firmware)]);

        let mut zw = ZipWriter::new(Cursor::new(Vec::new()));
        let opts = SimpleFileOptions::default();
        zw.start_file("manifest.json", opts).unwrap();
        zw.write_all(b"{}").unwrap();
        zw.start_file("base.apk", opts).unwrap();
        zw.write_all(&inner_apk).unwrap();
        let xapk = zw.finish().unwrap().into_inner();

        let tmp = TempFile::write("fw_test_xapk.xapk", &xapk);
        let mut saw_split = false;
        let data = extract_iscope_inner(tmp.path_str(), ScopeModel::S50, TEST_MIN_BYTES, |s| {
            if s.contains("split APK") {
                saw_split = true;
            }
        })
        .unwrap();
        assert_eq!(data, firmware);
        assert!(saw_split);
    }

    // ── upload_firmware_file ──────────────────────────────────────────────────

    #[test]
    fn upload_firmware_file_nonexistent_path_returns_error() {
        let err = upload_firmware_file(
            "127.0.0.1",
            Path::new("/nonexistent/fw_test_iscope"),
            ScopeModel::S50,
            |_| {},
            |_, _| {},
        )
        .unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn upload_firmware_file_bad_address_returns_error() {
        // File exists and is valid, but scope address is unreachable.
        let bz2 = make_fake_iscope(2); // 64-bit for S30Pro
        let tmp = TempFile::write("fw_test_iscope_file", &bz2);
        let err = upload_firmware_file_inner(
            "127.0.0.1",
            &tmp.0,
            ScopeModel::S30Pro,
            TEST_MIN_BYTES,
            |_| {},
            |_, _| {},
        )
        .unwrap_err();
        assert!(err.to_string().contains("Cannot connect"));
    }

    // ── upload_firmware_inner ─────────────────────────────────────────────────

    fn test_ports(cmd_port: u16, data_port: u16) -> UploadPorts {
        UploadPorts {
            cmd_port,
            data_port,
            wait_timeout: Duration::from_secs(5),
        }
    }

    #[test]
    fn upload_firmware_cannot_connect_to_data_port() {
        // Neither port has a listener.
        let err = upload_firmware_inner(
            "127.0.0.1",
            b"data",
            "iscope",
            test_ports(9, 9), // port 9 = discard, always refused
            |_| {},
            |_, _| {},
        )
        .unwrap_err();
        assert!(err.to_string().contains("Cannot connect to data port"));
    }

    #[test]
    fn upload_firmware_cannot_connect_to_cmd_port() {
        // Data port has a listener, cmd port does not.
        let data_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let data_port = data_listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let _ = data_listener.accept();
        });

        let dead_port = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };

        let err = upload_firmware_inner(
            "127.0.0.1",
            b"data",
            "iscope",
            test_ports(dead_port, data_port),
            |_| {},
            |_, _| {},
        )
        .unwrap_err();
        assert!(err.to_string().contains("Cannot connect to command port"));
    }

    #[test]
    fn upload_firmware_scope_returns_error_in_ack() {
        // Data port: accept and drain.
        let data_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let data_port = data_listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut c, _)) = data_listener.accept() {
                let mut buf = [0u8; 64];
                let _ = c.read(&mut buf);
            }
        });

        // Cmd port: send greeting, then ACK with an error field.
        let cmd_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let cmd_port = cmd_listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut c, _)) = cmd_listener.accept() {
                c.write_all(b"{\"name\":\"updater\"}\r\n").unwrap();
                let mut buf = [0u8; 512];
                let _ = c.read(&mut buf); // consume begin_recv
                c.write_all(b"{\"error\":\"bad md5\"}\r\n").unwrap();
            }
        });

        let err = upload_firmware_inner(
            "127.0.0.1",
            b"firmware",
            "iscope",
            test_ports(cmd_port, data_port),
            |_| {},
            |_, _| {},
        )
        .unwrap_err();
        assert!(err.to_string().contains("bad md5"));
    }

    #[test]
    fn upload_firmware_greeting_without_name_field_uses_default() {
        use std::sync::{Arc, Mutex};

        // Greeting JSON has no "name" key → falls back to "updater".
        let data_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let data_port = data_listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut c, _)) = data_listener.accept() {
                let mut buf = [0u8; 4096];
                while c.read(&mut buf).unwrap_or(0) > 0 {}
            }
        });

        let cmd_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let cmd_port = cmd_listener.local_addr().unwrap().port();

        // No "name" in greeting; ACK OK; then go offline and come back quickly.
        std::thread::spawn(move || {
            if let Ok((mut c, _)) = cmd_listener.accept() {
                c.write_all(b"{\"status\":\"ready\"}\r\n").unwrap(); // no "name" field
                let mut buf = [0u8; 512];
                let _ = c.read(&mut buf);
                c.write_all(b"{\"result\":\"ok\"}\r\n").unwrap();
                drop(c);
                drop(cmd_listener);
                // Scope comes back on the same port.
                std::thread::sleep(Duration::from_millis(20));
                let new_l = TcpListener::bind(format!("127.0.0.1:{}", cmd_port)).unwrap();
                if let Ok((mut c, _)) = new_l.accept() {
                    c.write_all(b"{\"status\":\"ready\"}\r\n").unwrap();
                }
                std::thread::sleep(Duration::from_millis(5000));
                drop(new_l);
            }
        });

        let msgs: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let msgs_capture = Arc::clone(&msgs);
        let result = upload_firmware_inner(
            "127.0.0.1",
            b"fw",
            "iscope",
            UploadPorts {
                cmd_port,
                data_port,
                wait_timeout: Duration::from_secs(5),
            },
            move |s| msgs_capture.lock().unwrap().push(s),
            |_, _| {},
        );
        assert!(result.is_ok(), "expected ok, got {:?}", result);
        assert!(msgs.lock().unwrap().iter().any(|m| m.contains("updater")));
    }

    #[test]
    fn upload_firmware_full_success_with_named_scope() {
        let data_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let data_port = data_listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut c, _)) = data_listener.accept() {
                let mut buf = [0u8; 4096];
                while c.read(&mut buf).unwrap_or(0) > 0 {}
            }
        });

        let cmd_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let cmd_port = cmd_listener.local_addr().unwrap().port();

        std::thread::spawn(move || {
            if let Ok((mut c, _)) = cmd_listener.accept() {
                c.write_all(b"{\"name\":\"seestar-s50\"}\r\n").unwrap();
                let mut buf = [0u8; 512];
                let _ = c.read(&mut buf);
                c.write_all(b"{\"result\":\"ok\"}\r\n").unwrap();
                drop(c);
                drop(cmd_listener);
                // Stay offline long enough for the 100ms poll in wait_for_scope
                // to observe the port as closed before we rebind.
                std::thread::sleep(Duration::from_millis(200));
                let new_l = TcpListener::bind(format!("127.0.0.1:{}", cmd_port)).unwrap();
                if let Ok((mut c, _)) = new_l.accept() {
                    c.write_all(b"{\"name\":\"seestar-s50\"}\r\n").unwrap();
                }
                std::thread::sleep(Duration::from_millis(5000));
                drop(new_l);
            }
        });

        let result = upload_firmware_inner(
            "127.0.0.1",
            b"firmware payload",
            "iscope",
            UploadPorts {
                cmd_port,
                data_port,
                wait_timeout: Duration::from_secs(5),
            },
            |_| {},
            |_, _| {},
        );
        assert!(result.is_ok(), "expected ok, got {:?}", result);
    }

    // ── wait_for_scope ────────────────────────────────────────────────────────

    #[test]
    fn wait_for_scope_timeout_phase1_scope_never_reboots() {
        // Scope is always reachable → phase 1 never breaks → timeout.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(2));
            drop(listener);
        });

        let err = wait_for_scope(
            "127.0.0.1",
            port,
            Duration::from_millis(50),
            None,
            |_| {},
            |_, _| {},
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("Timed out waiting for scope to reboot")
        );
    }

    #[test]
    fn wait_for_scope_timeout_phase2_scope_never_comes_back() {
        // Scope is already offline → phase 1 breaks immediately → phase 2 times out.
        let dead_port = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };

        let err = wait_for_scope(
            "127.0.0.1",
            dead_port,
            Duration::from_millis(50),
            None,
            |_| {},
            |_, _| {},
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("Timed out waiting for scope to come back online")
        );
    }

    // ── detect_scope_model ────────────────────────────────────────────────────

    /// Spawn a mock API server that speaks the challenge-response protocol.
    /// `product_model` is what the server reports in `get_device_state`.
    /// `auth_code` is the code returned in the `verify_client` response.
    fn serve_api_once(product_model: &'static str, auth_code: i64) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let Ok((mut conn, _)) = listener.accept() else {
                return;
            };
            // 1. Send greeting

            // 2. Read get_verify_str, reply with challenge
            recv_line(&mut conn).unwrap();
            let challenge_resp =
                serde_json::json!({"id":1,"result":{"str":"test-challenge-12345"}});
            conn.write_all(format!("{}\r\n", challenge_resp).as_bytes())
                .unwrap();

            // 3. Read verify_client, reply with auth code
            recv_line(&mut conn).unwrap();
            let ack = serde_json::json!({"id":2,"code":auth_code});
            conn.write_all(format!("{}\r\n", ack).as_bytes()).unwrap();

            if auth_code != 0 {
                return;
            }

            // 4. Read pi_is_verified, send ack
            recv_line(&mut conn).unwrap();
            conn.write_all(b"{\"id\":3,\"code\":0}\r\n").unwrap();

            // 5. Read get_device_state, reply with product_model and device info
            recv_line(&mut conn).unwrap();
            let state = serde_json::json!({
                "id": 4,
                "result": {
                    "device": {
                        "product_model": product_model,
                        "firmware_ver_string": "7.18"
                    },
                    "pi_status": {
                        "battery_capacity": 80,
                        "charger_status": "Discharging"
                    }
                }
            });
            conn.write_all(format!("{}\r\n", state).as_bytes()).unwrap();
        });
        addr
    }

    fn make_test_pem_key() -> Vec<u8> {
        use rsa::pkcs8::EncodePrivateKey;
        let mut rng = rsa::rand_core::OsRng;
        let key = rsa::RsaPrivateKey::new(&mut rng, 1024).unwrap();
        key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap()
            .to_string()
            .into_bytes()
    }

    #[test]
    fn detect_scope_model_connection_refused_returns_error() {
        // Bind then immediately drop to get a port that is guaranteed closed.
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let pem = make_test_pem_key();
        let err = detect_scope_model_on_port("127.0.0.1", port, &pem, |_| {}).unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn detect_scope_model_auth_failure_returns_error() {
        let addr = serve_api_once("Seestar S50", 1); // code != 0 → auth fail
        let pem = make_test_pem_key();
        let err = detect_scope_model_on_port("127.0.0.1", addr.port(), &pem, |_| {}).unwrap_err();
        assert!(
            err.to_string().contains("Authentication failed"),
            "expected auth error, got: {}",
            err
        );
    }

    #[test]
    fn detect_scope_model_s50_product_model() {
        let addr = serve_api_once("Seestar S50", 0);
        let pem = make_test_pem_key();
        let info = detect_scope_model_on_port("127.0.0.1", addr.port(), &pem, |_| {}).unwrap();
        assert_eq!(info.model, ScopeModel::S50);
        assert_eq!(info.firmware_ver_string.as_deref(), Some("7.18"));
        assert_eq!(info.battery_capacity, Some(80));
        assert!(!info.battery_charging);
    }

    #[test]
    fn detect_scope_model_s30pro_product_model() {
        let addr = serve_api_once("Seestar S30 Pro", 0);
        let pem = make_test_pem_key();
        let info = detect_scope_model_on_port("127.0.0.1", addr.port(), &pem, |_| {}).unwrap();
        assert_eq!(info.model, ScopeModel::S30Pro);
    }

    #[test]
    fn detect_scope_model_s30_product_model() {
        // Plain "S30" (32-bit ARMv7l) must map to S30, not S30Pro.
        let addr = serve_api_once("Seestar S30", 0);
        let pem = make_test_pem_key();
        let info = detect_scope_model_on_port("127.0.0.1", addr.port(), &pem, |_| {}).unwrap();
        assert_eq!(info.model, ScopeModel::S30);
    }

    #[test]
    fn detect_scope_model_s30pro_not_confused_with_s30() {
        // "S30 Pro" contains "S30" — must match S30Pro, not S30.
        let addr = serve_api_once("Seestar S30 Pro", 0);
        let pem = make_test_pem_key();
        let info = detect_scope_model_on_port("127.0.0.1", addr.port(), &pem, |_| {}).unwrap();
        assert_eq!(info.model, ScopeModel::S30Pro);
    }

    #[test]
    fn detect_scope_model_bad_pem_returns_error() {
        // A connected server is needed so we reach PEM loading.
        let addr = serve_api_once("Seestar S50", 0);
        let err =
            detect_scope_model_on_port("127.0.0.1", addr.port(), b"not a valid pem key", |_| {})
                .unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn detect_scope_model_invalid_address_returns_error() {
        let pem = make_test_pem_key();
        let err =
            detect_scope_model_on_port("this-host-does-not-exist.invalid", 4700, &pem, |_| {})
                .unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    /// Spawn a server that sends a greeting then replies with `challenge_json`
    /// to the first request (get_verify_str), then closes.
    fn serve_bad_challenge(challenge_json: &'static [u8]) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let Ok((mut conn, _)) = listener.accept() else {
                return;
            };

            recv_line(&mut conn).unwrap(); // consume get_verify_str
            conn.write_all(challenge_json).unwrap();
        });
        addr
    }

    /// Spawn a server that completes auth successfully but sends `state_json`
    /// instead of a proper get_device_state response.
    fn serve_bad_state(state_json: &'static [u8]) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let Ok((mut conn, _)) = listener.accept() else {
                return;
            };

            recv_line(&mut conn).unwrap(); // get_verify_str
            let cr = serde_json::json!({"id":1,"result":{"str":"challenge"}});
            conn.write_all(format!("{}\r\n", cr).as_bytes()).unwrap();
            recv_line(&mut conn).unwrap(); // verify_client
            conn.write_all(b"{\"id\":2,\"code\":0}\r\n").unwrap();
            recv_line(&mut conn).unwrap(); // pi_is_verified
            conn.write_all(b"{\"id\":3,\"code\":0}\r\n").unwrap();
            recv_line(&mut conn).unwrap(); // get_device_state
            conn.write_all(state_json).unwrap();
        });
        addr
    }

    #[test]
    fn detect_scope_model_malformed_challenge_json_returns_error() {
        let addr = serve_bad_challenge(b"not-json-at-all\r\n");
        let pem = make_test_pem_key();
        let err = detect_scope_model_on_port("127.0.0.1", addr.port(), &pem, |_| {}).unwrap_err();
        assert!(
            err.to_string().contains("Invalid JSON"),
            "expected invalid-JSON error, got: {}",
            err
        );
    }

    #[test]
    fn detect_scope_model_missing_challenge_str_field_returns_error() {
        // Valid JSON but no result.str
        let addr = serve_bad_challenge(b"{\"id\":1,\"result\":{}}\r\n");
        let pem = make_test_pem_key();
        let err = detect_scope_model_on_port("127.0.0.1", addr.port(), &pem, |_| {}).unwrap_err();
        assert!(
            err.to_string().contains("No challenge string"),
            "expected missing-challenge error, got: {}",
            err
        );
    }

    #[test]
    fn detect_scope_model_missing_product_model_field_returns_error() {
        // Auth succeeds but get_device_state has no product_model
        let addr = serve_bad_state(b"{\"id\":3,\"result\":{\"device\":{}}}\r\n");
        let pem = make_test_pem_key();
        let err = detect_scope_model_on_port("127.0.0.1", addr.port(), &pem, |_| {}).unwrap_err();
        assert!(
            err.to_string().contains("No product_model"),
            "expected missing-product_model error, got: {}",
            err
        );
    }

    #[test]
    fn detect_scope_model_malformed_state_json_returns_error() {
        let addr = serve_bad_state(b"garbage\r\n");
        let pem = make_test_pem_key();
        let err = detect_scope_model_on_port("127.0.0.1", addr.port(), &pem, |_| {}).unwrap_err();
        assert!(
            err.to_string().contains("Invalid JSON"),
            "expected invalid-JSON error, got: {}",
            err
        );
    }

    #[test]
    fn detect_scope_model_missing_optional_fields_returns_none() {
        // State response has product_model but no firmware_ver_string or pi_status.
        let addr = serve_bad_state(
            b"{\"id\":3,\"result\":{\"device\":{\"product_model\":\"Seestar S50\"}}}\r\n",
        );
        let pem = make_test_pem_key();
        let info = detect_scope_model_on_port("127.0.0.1", addr.port(), &pem, |_| {}).unwrap();
        assert_eq!(info.model, ScopeModel::S50);
        assert!(info.firmware_ver_string.is_none());
        assert!(info.battery_capacity.is_none());
    }

    // ── DeviceInfo battery helpers ────────────────────────────────────────────

    fn make_device_info(battery_capacity: Option<u8>, battery_charging: bool) -> DeviceInfo {
        DeviceInfo {
            model: ScopeModel::S50,
            firmware_ver_string: None,
            battery_capacity,
            battery_charging,
        }
    }

    #[test]
    fn check_battery_blocks_critically_low_discharging() {
        let info = make_device_info(Some(10), false);
        let err = info.check_battery().unwrap_err();
        assert!(err.to_string().contains("Battery too low"), "{}", err);
        assert!(err.to_string().contains("10%"), "{}", err);
    }

    #[test]
    fn check_battery_allows_low_battery_when_charging() {
        // < 20% but charging — should not block.
        let info = make_device_info(Some(10), true);
        info.check_battery().unwrap();
    }

    #[test]
    fn check_battery_allows_sufficient_battery() {
        let info = make_device_info(Some(80), false);
        info.check_battery().unwrap();
    }

    #[test]
    fn check_battery_allows_unknown_battery() {
        // No battery info — can't block.
        let info = make_device_info(None, false);
        info.check_battery().unwrap();
    }

    #[test]
    fn battery_warning_returned_for_low_discharging() {
        let info = make_device_info(Some(30), false);
        let warn = info.battery_warning();
        assert!(warn.is_some());
        assert!(warn.unwrap().contains("30%"));
    }

    #[test]
    fn battery_warning_none_when_charging() {
        let info = make_device_info(Some(30), true);
        assert!(info.battery_warning().is_none());
    }

    #[test]
    fn battery_warning_none_when_sufficient() {
        let info = make_device_info(Some(80), false);
        assert!(info.battery_warning().is_none());
    }

    #[test]
    fn battery_warning_none_when_unknown() {
        let info = make_device_info(None, false);
        assert!(info.battery_warning().is_none());
    }

    #[test]
    fn detect_scope_model_returns_firmware_version_and_battery() {
        let addr = serve_api_once("Seestar S50", 0);
        let pem = make_test_pem_key();
        let info = detect_scope_model_on_port("127.0.0.1", addr.port(), &pem, |_| {}).unwrap();
        assert_eq!(info.firmware_ver_string.as_deref(), Some("7.18"));
        assert_eq!(info.battery_capacity, Some(80));
        assert!(!info.battery_charging);
    }

    #[test]
    fn wait_for_scope_scope_reboots_and_comes_back() {
        // Scope starts online, goes offline, then comes back.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            drop(listener); // go offline
            std::thread::sleep(Duration::from_millis(150));
            // come back and send greeting when connected
            let new_l = TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();
            if let Ok((mut c, _)) = new_l.accept() {
                c.write_all(b"{\"status\":\"ready\"}\r\n").unwrap();
            }
            std::thread::sleep(Duration::from_millis(1000));
            drop(new_l);
        });

        let result = wait_for_scope(
            "127.0.0.1",
            port,
            Duration::from_secs(5),
            None,
            |_| {},
            |_, _| {},
        );
        assert!(result.is_ok());
    }

    // ── run_diagnostics ───────────────────────────────────────────────────────

    /// Spawn a mock API server that handles the full diagnostics exchange.
    fn serve_diagnostics_once(
        product_model: &'static str,
        pi_info_result: serde_json::Value,
    ) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let Ok((mut conn, _)) = listener.accept() else {
                return;
            };
            // auth handshake
            recv_line(&mut conn).unwrap();
            let challenge_resp =
                serde_json::json!({"id":1,"result":{"str":"test-challenge-12345"}});
            conn.write_all(format!("{}\r\n", challenge_resp).as_bytes())
                .unwrap();
            recv_line(&mut conn).unwrap();
            conn.write_all(b"{\"id\":2,\"code\":0}\r\n").unwrap();
            recv_line(&mut conn).unwrap();
            conn.write_all(b"{\"id\":3,\"code\":0}\r\n").unwrap();

            // get_device_state
            recv_line(&mut conn).unwrap();
            let state = serde_json::json!({
                "id": 4,
                "result": {
                    "device": {"product_model": product_model, "firmware_ver_string": "4.70"},
                    "pi_status": {"battery_capacity": 85, "charger_status": "Discharging"}
                }
            });
            conn.write_all(format!("{}\r\n", state).as_bytes()).unwrap();

            // pi_get_info
            recv_line(&mut conn).unwrap();
            let info = serde_json::json!({"id": 5, "result": pi_info_result});
            conn.write_all(format!("{}\r\n", info).as_bytes()).unwrap();
        });
        addr
    }

    #[test]
    fn run_diagnostics_on_port_returns_both_responses() {
        let pi_info = serde_json::json!({"model": "Raspberry Pi Zero 2W", "serial": "abc123"});
        let addr = serve_diagnostics_once("Seestar S50", pi_info.clone());
        let pem = make_test_pem_key();
        let data = run_diagnostics_on_port("127.0.0.1", addr.port(), &pem, |_| {}).unwrap();
        assert_eq!(
            data.device_state["result"]["device"]["product_model"],
            "Seestar S50"
        );
        assert_eq!(data.pi_info["result"], pi_info);
    }

    #[test]
    fn run_diagnostics_on_port_connection_refused_returns_error() {
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let pem = make_test_pem_key();
        let err = run_diagnostics_on_port("127.0.0.1", port, &pem, |_| {}).unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn run_diagnostics_on_port_auth_failure_returns_error() {
        let addr = serve_api_once("Seestar S50", 1); // code != 0
        let pem = make_test_pem_key();
        let err = run_diagnostics_on_port("127.0.0.1", addr.port(), &pem, |_| {}).unwrap_err();
        assert!(
            err.to_string().contains("Authentication failed"),
            "expected auth error, got: {}",
            err
        );
    }

    // ── DiagnosticsData::anonymize ────────────────────────────────────────────

    #[test]
    fn anonymize_redacts_ap_passwd() {
        let mut data = DiagnosticsData {
            device_state: serde_json::json!({
                "result": {"ap": {"ssid": "MyNet", "passwd": "s3cr3t"}}
            }),
            pi_info: serde_json::Value::Null,
        };
        data.anonymize();
        assert_eq!(
            data.device_state["result"]["ap"]["passwd"], "[redacted]",
            "passwd should be redacted"
        );
        assert_eq!(
            data.device_state["result"]["ap"]["ssid"], "MyNet",
            "ssid should be unchanged"
        );
    }

    #[test]
    fn anonymize_redacts_location_lon_lat() {
        let mut data = DiagnosticsData {
            device_state: serde_json::json!({
                "result": {"location_lon_lat": [12.345, 67.890]}
            }),
            pi_info: serde_json::Value::Null,
        };
        data.anonymize();
        assert_eq!(
            data.device_state["result"]["location_lon_lat"], "[redacted]",
            "location_lon_lat should be redacted"
        );
    }

    #[test]
    fn anonymize_is_safe_when_fields_absent() {
        let mut data = DiagnosticsData {
            device_state: serde_json::json!({"result": {}}),
            pi_info: serde_json::Value::Null,
        };
        // Should not panic when the targeted fields don't exist.
        data.anonymize();
        assert_eq!(data.device_state, serde_json::json!({"result": {}}));
    }

    // ── recv_line ─────────────────────────────────────────────────────────────

    #[test]
    fn recv_line_reads_up_to_newline() {
        let addr = serve_once(b"hello world\n");
        let mut client = TcpStream::connect(addr).unwrap();
        assert_eq!(recv_line(&mut client).unwrap(), "hello world");
    }

    #[test]
    fn recv_line_trims_carriage_return() {
        let addr = serve_once(b"hello\r\n");
        let mut client = TcpStream::connect(addr).unwrap();
        assert_eq!(recv_line(&mut client).unwrap(), "hello");
    }

    #[test]
    fn recv_line_eof_without_newline_returns_partial() {
        let addr = serve_once(b"partial");
        let mut client = TcpStream::connect(addr).unwrap();
        assert_eq!(recv_line(&mut client).unwrap(), "partial");
    }

    #[test]
    fn recv_line_empty_connection_returns_empty() {
        let addr = serve_once(b"");
        let mut client = TcpStream::connect(addr).unwrap();
        assert_eq!(recv_line(&mut client).unwrap(), "");
    }

    // ── can_connect ───────────────────────────────────────────────────────────

    #[test]
    fn can_connect_true_when_listener_active() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(can_connect("127.0.0.1", port));
        drop(listener);
    }

    #[test]
    fn can_connect_false_when_nothing_listening() {
        let port = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        assert!(!can_connect("127.0.0.1", port));
    }

    #[test]
    fn can_connect_false_for_unresolvable_host() {
        assert!(!can_connect("invalid.host.that.does.not.exist.local", 9999));
    }
}

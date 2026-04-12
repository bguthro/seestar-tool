//! Firmware extraction and OTA upload.
//! Mirrors extract_iscope() and upload_file()/wait_for_scope() from install_firmware.py.

use anyhow::{Result, anyhow};
use std::net::TcpStream;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::apk::open_apk;

const UPDATER_CMD_PORT: u16 = 4350;
const UPDATER_DATA_PORT: u16 = 4361;
/// Typical time for the scope to install firmware before rebooting.
const INSTALL_ESTIMATE_SECS: u64 = 180;

/// Which Seestar model is being updated — determines the firmware binary variant.
#[derive(Clone, Copy, PartialEq, Default, Debug)]
pub enum ScopeModel {
    /// S50 and earlier — uses the 32-bit `iscope` binary.
    #[default]
    S50,
    /// S30 and S30 Pro — uses the 64-bit `iscope_64` binary.
    S30Pro,
}

impl ScopeModel {
    /// The APK asset path for this model's firmware binary.
    pub fn asset_name(self) -> &'static str {
        match self {
            ScopeModel::S50 => "assets/iscope",
            ScopeModel::S30Pro => "assets/iscope_64",
        }
    }

    /// The filename sent to the scope's OTA updater.
    pub fn remote_filename(self) -> &'static str {
        match self {
            ScopeModel::S50 => "iscope",
            ScopeModel::S30Pro => "iscope_64",
        }
    }
}

// ── iscope extraction ─────────────────────────────────────────────────────────

/// Extract the firmware binary for `model` from an APK or XAPK file.
/// Searches all split APKs for the asset when dealing with an XAPK.
pub fn extract_iscope(
    apk_path: &str,
    model: ScopeModel,
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
    upload_firmware_to_ports(
        address,
        iscope_data,
        remote_filename,
        UPDATER_CMD_PORT,
        UPDATER_DATA_PORT,
        progress,
        upload_progress,
    )
}

fn upload_firmware_to_ports(
    address: &str,
    iscope_data: &[u8],
    remote_filename: &str,
    cmd_port: u16,
    data_port: u16,
    progress: impl Fn(String) + Send + 'static,
    upload_progress: impl Fn(u64, u64) + Send + 'static,
) -> Result<()> {
    upload_firmware_to_ports_with_timeout(
        address,
        iscope_data,
        remote_filename,
        cmd_port,
        data_port,
        Duration::from_secs(300),
        progress,
        upload_progress,
    )
}

#[allow(clippy::too_many_arguments)]
fn upload_firmware_to_ports_with_timeout(
    address: &str,
    iscope_data: &[u8],
    remote_filename: &str,
    cmd_port: u16,
    data_port: u16,
    wait_timeout: Duration,
    progress: impl Fn(String) + Send + 'static,
    upload_progress: impl Fn(u64, u64) + Send + 'static,
) -> Result<()> {
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
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&ack)
        && !v["error"].is_null()
    {
        return Err(anyhow!("Scope error: {}", v["error"]));
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
    wait_for_scope(address, cmd_port, wait_timeout, progress, upload_progress)?;
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
    let data = std::fs::read(path)?;
    upload_firmware(
        address,
        &data,
        model.remote_filename(),
        progress,
        upload_progress,
    )
}

// ── Scope availability polling ────────────────────────────────────────────────

/// Wait for the scope to go offline (reboot) and come back online.
///
/// `install_progress(done, total)` drives the egui progress bar:
///   - `(elapsed, INSTALL_ESTIMATE_SECS)` → countdown bar during install
///   - `(0, 0)` → indeterminate/bounce bar while rebooting or over-estimate
pub(crate) fn wait_for_scope(
    address: &str,
    port: u16,
    timeout: Duration,
    mut progress: impl FnMut(String),
    mut install_progress: impl FnMut(u64, u64),
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

    #[test]
    fn scope_model_default_is_s50() {
        assert_eq!(ScopeModel::default(), ScopeModel::S50);
    }

    #[test]
    fn scope_model_s50_asset_name() {
        assert_eq!(ScopeModel::S50.asset_name(), "assets/iscope");
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
    fn scope_model_s30pro_remote_filename() {
        assert_eq!(ScopeModel::S30Pro.remote_filename(), "iscope_64");
    }

    // ── extract_iscope ────────────────────────────────────────────────────────

    #[test]
    fn extract_iscope_s50_from_plain_apk() {
        let firmware = b"fake-iscope-firmware";
        let apk = make_apk(&[("assets/iscope", firmware), ("assets/iscope_64", b"64bit")]);
        let tmp = TempFile::write("fw_test_s50.apk", &apk);
        let mut logged_asset = String::new();
        let data = extract_iscope(tmp.path_str(), ScopeModel::S50, |s| {
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
        let firmware = b"fake-iscope64-firmware";
        let apk = make_apk(&[("assets/iscope", b"32bit"), ("assets/iscope_64", firmware)]);
        let tmp = TempFile::write("fw_test_s30pro.apk", &apk);
        let data = extract_iscope(tmp.path_str(), ScopeModel::S30Pro, |_| {}).unwrap();
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

        let firmware = b"xapk-firmware";
        let inner_apk = make_apk(&[("assets/iscope", firmware)]);

        let mut zw = ZipWriter::new(Cursor::new(Vec::new()));
        let opts = SimpleFileOptions::default();
        zw.start_file("manifest.json", opts).unwrap();
        zw.write_all(b"{}").unwrap();
        zw.start_file("base.apk", opts).unwrap();
        zw.write_all(&inner_apk).unwrap();
        let xapk = zw.finish().unwrap().into_inner();

        let tmp = TempFile::write("fw_test_xapk.xapk", &xapk);
        let mut saw_split = false;
        let data = extract_iscope(tmp.path_str(), ScopeModel::S50, |s| {
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
        // File exists but scope address is unreachable.
        let tmp = TempFile::write("fw_test_iscope_file", b"firmware bytes");
        let err = upload_firmware_file("127.0.0.1", &tmp.0, ScopeModel::S30Pro, |_| {}, |_, _| {})
            .unwrap_err();
        assert!(err.to_string().contains("Cannot connect"));
    }

    // ── upload_firmware_to_ports ──────────────────────────────────────────────

    #[test]
    fn upload_firmware_cannot_connect_to_data_port() {
        // Neither port has a listener.
        let err = upload_firmware_to_ports(
            "127.0.0.1",
            b"data",
            "iscope",
            9, // cmd port — won't be reached
            9, // data port — nothing listening (port 9 = discard, always refused)
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

        let err = upload_firmware_to_ports(
            "127.0.0.1",
            b"data",
            "iscope",
            dead_port,
            data_port,
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

        let err = upload_firmware_to_ports(
            "127.0.0.1",
            b"firmware",
            "iscope",
            cmd_port,
            data_port,
            |_| {},
            |_, _| {},
        )
        .unwrap_err();
        assert!(err.to_string().contains("Scope error"));
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
                std::thread::sleep(Duration::from_millis(2000));
                drop(new_l);
            }
        });

        let msgs: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let msgs_capture = Arc::clone(&msgs);
        let result = upload_firmware_to_ports_with_timeout(
            "127.0.0.1",
            b"fw",
            "iscope",
            cmd_port,
            data_port,
            Duration::from_secs(5),
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
                std::thread::sleep(Duration::from_millis(20));
                let new_l = TcpListener::bind(format!("127.0.0.1:{}", cmd_port)).unwrap();
                std::thread::sleep(Duration::from_millis(2000));
                drop(new_l);
            }
        });

        let result = upload_firmware_to_ports_with_timeout(
            "127.0.0.1",
            b"firmware payload",
            "iscope",
            cmd_port,
            data_port,
            Duration::from_secs(5),
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
            |_| {},
            |_, _| {},
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("Timed out waiting for scope to come back online")
        );
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
            // come back
            let new_l = TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();
            std::thread::sleep(Duration::from_millis(1000));
            drop(new_l);
        });

        let result = wait_for_scope("127.0.0.1", port, Duration::from_secs(5), |_| {}, |_, _| {});
        assert!(result.is_ok());
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

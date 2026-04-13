//! Shared task-spawning functions used by both the GUI and TUI frontends.
//!
//! Each function takes an `Arc<Runtime>` and a `Sender<TaskMsg>`, spawns an
//! async task, and sends results back through the channel.  Frontends only need
//! to hold the `Receiver` end and render whatever arrives.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::firmware::ScopeModel;
use crate::task::{Sender, TaskMsg};

/// Target scope parameters shared by all install operations.
pub struct InstallTarget {
    pub host: String,
    pub model: ScopeModel,
    pub pem_key: Option<Vec<u8>>,
}

/// Fetch the Seestar version list from APKPure.
/// Sends `TaskMsg::VersionList` on success, `TaskMsg::Error` on failure.
pub fn fetch_versions(rt: &Arc<tokio::runtime::Runtime>, tx: Sender) {
    rt.spawn(async move {
        let log = {
            let tx = tx.clone();
            move |s: String| {
                let _ = tx.send(TaskMsg::Log(s));
            }
        };
        let result = match crate::apkpure::fetch_versions(|s| log(s.clone())).await {
            Ok(v) => Ok(v),
            Err(_) => {
                log("Version list failed, trying latest-only endpoint…".to_string());
                crate::apkpure::fetch_latest(|s| log(s.clone()))
                    .await
                    .map(|v| vec![v])
            }
        };
        match result {
            Ok(versions) => {
                let _ = tx.send(TaskMsg::VersionList(versions));
            }
            Err(e) => {
                let _ = tx.send(TaskMsg::Error(e.to_string()));
            }
        }
    });
}

/// Download an XAPK without installing it.
/// Sends `TaskMsg::Downloaded` then `TaskMsg::Done`.
pub fn download_only(
    rt: &Arc<tokio::runtime::Runtime>,
    tx: Sender,
    version: String,
    download_url: String,
    dest_dir: PathBuf,
) {
    rt.spawn(async move {
        let prog = {
            let tx = tx.clone();
            move |d, t| {
                let _ = tx.send(TaskMsg::Progress(d, t));
            }
        };
        match crate::apkpure::download_version(&version, &download_url, &dest_dir, prog).await {
            Ok(path) => {
                if let Err(e) = crate::apkpure::validate_download(&path) {
                    let _ = tx.send(TaskMsg::Error(e.to_string()));
                    return;
                }
                let _ = tx.send(TaskMsg::Downloaded(path));
                let _ = tx.send(TaskMsg::Done);
            }
            Err(e) => {
                let _ = tx.send(TaskMsg::Error(e.to_string()));
            }
        }
    });
}

/// Resolve `ScopeModel::Auto` by connecting to the scope and querying its model.
/// Returns `Ok(resolved_model)` or `Err` on failure.
///
/// `apk_path` is used as a fallback key source when `pem_key` was not pre-extracted
/// (e.g. when the user clicks install immediately after picking the file).
fn resolve_model(
    model: ScopeModel,
    host: &str,
    pem_key: Option<&[u8]>,
    apk_path: Option<&str>,
    tx: &Sender,
) -> anyhow::Result<ScopeModel> {
    if !model.is_auto() {
        return Ok(model);
    }
    // If no pre-extracted key, try to extract one from the APK path now.
    let extracted: Option<Vec<u8>>;
    let key: &[u8] = if let Some(k) = pem_key {
        k
    } else if let Some(path) = apk_path {
        let _ = tx.send(TaskMsg::Log("Extracting key from APK…".to_string()));
        let result = crate::pem::extract_pem_from_apk(path, |_| {})?;
        let pem_str =
            result.keys.into_iter().next().ok_or_else(|| {
                anyhow::anyhow!("No PEM key found in APK. Select a model manually.")
            })?;
        extracted = Some(pem_str.into_bytes());
        extracted.as_deref().unwrap()
    } else {
        return Err(anyhow::anyhow!(
            "Auto-detect requires an APK to extract the key from. \
             Load an APK file or select a model manually."
        ));
    };
    let tx_log = tx.clone();
    match crate::firmware::detect_scope_model(host, key, move |s| {
        let _ = tx_log.send(TaskMsg::Log(s));
    }) {
        Ok(m) => {
            let _ = tx.send(TaskMsg::Log(format!("Auto-detected: {}", m.display_name())));
            Ok(m)
        }
        Err(e) => Err(anyhow::anyhow!(
            "Could not auto-detect model: {}. Select a model manually.",
            e
        )),
    }
}

/// Download an XAPK, extract the firmware, and upload it to the scope.
pub fn download_and_install(
    rt: &Arc<tokio::runtime::Runtime>,
    tx: Sender,
    version: String,
    download_url: String,
    dest_dir: PathBuf,
    target: InstallTarget,
) {
    rt.spawn(async move {
        let prog = {
            let tx = tx.clone();
            move |d, t| {
                let _ = tx.send(TaskMsg::Progress(d, t));
            }
        };
        let path = match crate::apkpure::download_version(&version, &download_url, &dest_dir, prog)
            .await
        {
            Ok(p) => p,
            Err(e) => {
                let _ = tx.send(TaskMsg::Error(e.to_string()));
                return;
            }
        };
        if let Err(e) = crate::apkpure::validate_download(&path) {
            let _ = tx.send(TaskMsg::Error(e.to_string()));
            return;
        }
        let _ = tx.send(TaskMsg::Downloaded(path.clone()));
        let _ = tx.send(TaskMsg::Progress(0, 0));

        let InstallTarget {
            host,
            model,
            pem_key,
        } = target;
        let tx_ext = tx.clone();
        let tx_log = tx.clone();
        let tx_up = tx.clone();
        let path_str = path.to_string_lossy().into_owned();
        let result = tokio::task::spawn_blocking(move || {
            let model = resolve_model(model, &host, pem_key.as_deref(), Some(&path_str), &tx_log)?;
            let iscope = crate::firmware::extract_iscope(&path_str, model, move |s| {
                let _ = tx_ext.send(TaskMsg::Log(s));
            })?;
            let log = move |s: String| {
                let _ = tx_log.send(TaskMsg::Log(s));
            };
            let up = move |d, t| {
                let _ = tx_up.send(TaskMsg::Progress(d, t));
            };
            crate::firmware::upload_firmware(&host, &iscope, model.remote_filename(), log, up)
        })
        .await;

        match result {
            Ok(Ok(())) => {
                let _ = tx.send(TaskMsg::Done);
            }
            Ok(Err(e)) => {
                let _ = tx.send(TaskMsg::Error(e.to_string()));
            }
            Err(e) => {
                let _ = tx.send(TaskMsg::Error(e.to_string()));
            }
        }
    });
}

/// Extract the firmware from a local APK/XAPK and upload it to the scope.
pub fn install_apk(
    rt: &Arc<tokio::runtime::Runtime>,
    tx: Sender,
    apk_path: String,
    target: InstallTarget,
) {
    rt.spawn(async move {
        let InstallTarget {
            host,
            model,
            pem_key,
        } = target;
        let tx_ext = tx.clone();
        let tx_log = tx.clone();
        let tx_up = tx.clone();
        let result = tokio::task::spawn_blocking(move || {
            let model = resolve_model(model, &host, pem_key.as_deref(), Some(&apk_path), &tx_log)?;
            let iscope = crate::firmware::extract_iscope(&apk_path, model, move |s| {
                let _ = tx_ext.send(TaskMsg::Log(s));
            })?;
            let log = move |s: String| {
                let _ = tx_log.send(TaskMsg::Log(s));
            };
            let up = move |d, t| {
                let _ = tx_up.send(TaskMsg::Progress(d, t));
            };
            crate::firmware::upload_firmware(&host, &iscope, model.remote_filename(), log, up)
        })
        .await;

        match result {
            Ok(Ok(())) => {
                let _ = tx.send(TaskMsg::Done);
            }
            Ok(Err(e)) => {
                let _ = tx.send(TaskMsg::Error(e.to_string()));
            }
            Err(e) => {
                let _ = tx.send(TaskMsg::Error(e.to_string()));
            }
        }
    });
}

/// Upload a raw iscope file to the scope.
pub fn install_iscope(
    rt: &Arc<tokio::runtime::Runtime>,
    tx: Sender,
    iscope_path: String,
    target: InstallTarget,
) {
    rt.spawn(async move {
        let tx_done = tx.clone();
        let result = tokio::task::spawn_blocking(move || {
            let InstallTarget {
                host,
                model,
                pem_key,
            } = target;
            let tx_log = tx.clone();
            let tx_up = tx.clone();
            let model = resolve_model(model, &host, pem_key.as_deref(), None, &tx_log)?;
            let log = move |s: String| {
                let _ = tx_log.send(TaskMsg::Log(s));
            };
            let up = move |d, t| {
                let _ = tx_up.send(TaskMsg::Progress(d, t));
            };
            crate::firmware::upload_firmware_file(&host, Path::new(&iscope_path), model, log, up)
        })
        .await;

        match result {
            Ok(Ok(())) => {
                let _ = tx_done.send(TaskMsg::Done);
            }
            Ok(Err(e)) => {
                let _ = tx_done.send(TaskMsg::Error(e.to_string()));
            }
            Err(e) => {
                let _ = tx_done.send(TaskMsg::Error(e.to_string()));
            }
        }
    });
}

/// Extract PEM private keys from a Seestar APK/XAPK.
pub fn extract_pem(rt: &Arc<tokio::runtime::Runtime>, tx: Sender, apk_path: String) {
    rt.spawn(async move {
        let tx2 = tx.clone();
        let result = tokio::task::spawn_blocking(move || {
            crate::pem::extract_pem_from_apk(&apk_path, |s| {
                let _ = tx2.send(TaskMsg::Log(s));
            })
        })
        .await;

        match result {
            Ok(Ok(r)) => {
                let _ = tx.send(TaskMsg::PemKeys(r.keys));
                let _ = tx.send(TaskMsg::Done);
            }
            Ok(Err(e)) => {
                let _ = tx.send(TaskMsg::Error(e.to_string()));
            }
            Err(e) => {
                let _ = tx.send(TaskMsg::Error(e.to_string()));
            }
        }
    });
}

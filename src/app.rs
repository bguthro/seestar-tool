/// egui application — two tabs: Firmware Update and Extract PEM.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use eframe::egui::{self, RichText};

use crate::apkpure::ApkVersion;

// ── Shared state ──────────────────────────────────────────────────────────────

/// Messages sent from background tasks to the UI.
#[derive(Debug, Clone)]
pub enum TaskMsg {
    Log(String),
    /// (bytes_done, total_bytes) — 0 total means indeterminate
    Progress(u64, u64),
    VersionList(Vec<ApkVersion>),
    /// Path of a successfully downloaded APK
    Downloaded(PathBuf),
    PemKeys(Vec<String>),
    Done,
    Error(String),
}

type Sender = std::sync::mpsc::Sender<TaskMsg>;
type Receiver = std::sync::mpsc::Receiver<TaskMsg>;

fn channel() -> (Sender, Receiver) {
    std::sync::mpsc::channel()
}

// ── Tab state ─────────────────────────────────────────────────────────────────

#[derive(Default, PartialEq)]
enum Tab {
    #[default]
    Firmware,
    ExtractPem,
}

/// Source for the firmware to install.
#[derive(Default, PartialEq)]
enum FirmwareSource {
    #[default]
    LocalApk,   // user picks an APK/XAPK file
    LocalIscope, // user picks a raw iscope file
    Download,   // fetch from APKPure
}

struct FirmwareTab {
    source: FirmwareSource,
    apk_path: String,
    iscope_path: String,
    seestar_host: String,
    versions: Vec<ApkVersion>,
    selected_version: usize,
    versions_loaded: bool,
    /// Manual fallback: direct XAPK download URL pasted by the user.
    manual_url: String,
    log: Vec<String>,
    progress: (u64, u64), // (done, total)
    busy: bool,
    tx: Option<Sender>,
    rx: Option<Receiver>,
    rt: Arc<tokio::runtime::Runtime>,
    downloaded_apk: Option<PathBuf>,
}

impl FirmwareTab {
    fn new(rt: Arc<tokio::runtime::Runtime>) -> Self {
        Self {
            source: FirmwareSource::default(),
            apk_path: String::new(),
            iscope_path: String::new(),
            seestar_host: "seestar.local".to_string(),
            versions: vec![],
            selected_version: 0,
            versions_loaded: false,
            manual_url: String::new(),
            log: vec![],
            progress: (0, 0),
            busy: false,
            tx: None,
            rx: None,
            rt,
            downloaded_apk: None,
        }
    }

    fn poll(&mut self) {
        let msgs: Vec<TaskMsg> = self
            .rx
            .as_ref()
            .map(|rx| rx.try_iter().collect())
            .unwrap_or_default();
        for msg in msgs {
            match msg {
                TaskMsg::Log(s) => self.log.push(s),
                TaskMsg::Progress(d, t) => self.progress = (d, t),
                TaskMsg::VersionList(v) => {
                    self.versions = v;
                    self.selected_version = 0;
                    self.versions_loaded = true;
                    self.busy = false;
                }
                TaskMsg::Downloaded(p) => {
                    self.downloaded_apk = Some(p.clone());
                    self.log.push(format!("Downloaded: {}", p.display()));
                }
                TaskMsg::Done => {
                    self.log.push("Done.".to_string());
                    self.busy = false;
                    self.progress = (0, 0);
                }
                TaskMsg::Error(e) => {
                    self.log.push(format!("ERROR: {}", e));
                    self.busy = false;
                    self.progress = (0, 0);
                }
                _ => {}
            }
        }
    }

    /// Resolve (version_label, download_url) from the fetched list or manual URL field.
    fn resolved_version(&self) -> Option<(String, String)> {
        if !self.versions.is_empty() && self.versions_loaded {
            let v = &self.versions[self.selected_version];
            return Some((v.version.clone(), v.download_url.clone()));
        }
        let url = self.manual_url.trim().to_string();
        if !url.is_empty() {
            Some(("manual".to_string(), url))
        } else {
            None
        }
    }

    fn start_fetch_versions(&mut self) {
        let (tx, rx) = channel();
        self.tx = Some(tx.clone());
        self.rx = Some(rx);
        self.busy = true;
        self.log.clear();
        self.log.push("Fetching version list…".to_string());

        self.rt.spawn(async move {
            let log = |s: String| { let _ = tx.send(TaskMsg::Log(s)); };
            // Try full version list first; fall back to latest-only endpoint.
            let result = match crate::apkpure::fetch_versions(|s| log(s.clone())).await {
                Ok(v) => Ok(v),
                Err(_) => {
                    log("Version list failed, trying latest-only endpoint…".to_string());
                    crate::apkpure::fetch_latest(|s| log(s.clone())).await.map(|v| vec![v])
                }
            };
            match result {
                Ok(versions) => { let _ = tx.send(TaskMsg::VersionList(versions)); }
                Err(e) => { let _ = tx.send(TaskMsg::Error(e.to_string())); }
            }
        });
    }

    fn start_download(&mut self) {
        let Some((version, download_url)) = self.resolved_version() else { return };
        let dest_dir = std::env::current_dir().unwrap_or_default().join(format!("v{}", version));

        let (tx, rx) = channel();
        self.tx = Some(tx.clone());
        self.rx = Some(rx);
        self.busy = true;
        self.log.clear();
        self.downloaded_apk = None;
        self.progress = (0, 0);

        let tx2 = tx.clone();
        self.rt.spawn(async move {
            let prog = { let tx = tx.clone(); move |d, t| { let _ = tx.send(TaskMsg::Progress(d, t)); } };
            match crate::apkpure::download_version(&version, &download_url, &dest_dir, prog).await {
                Ok(path) => {
                    let _ = tx2.send(TaskMsg::Downloaded(path));
                    let _ = tx2.send(TaskMsg::Done);
                }
                Err(e) => { let _ = tx2.send(TaskMsg::Error(e.to_string())); }
            }
        });
    }

    fn start_download_and_install(&mut self) {
        let Some((version, download_url)) = self.resolved_version() else { return };
        let host = self.seestar_host.clone();

        let dest_dir = std::env::current_dir()
            .unwrap_or_default()
            .join(format!("v{}", version));

        let (tx, rx) = channel();
        self.tx = Some(tx.clone());
        self.rx = Some(rx);
        self.busy = true;
        self.log.clear();
        self.downloaded_apk = None;
        self.progress = (0, 0);

        let tx2 = tx.clone();
        self.rt.spawn(async move {
            // Download
            let prog = {
                let tx = tx.clone();
                move |d, t| { let _ = tx.send(TaskMsg::Progress(d, t)); }
            };
            let path = match crate::apkpure::download_version(&version, &download_url, &dest_dir, prog).await {
                Ok(p) => p,
                Err(e) => { let _ = tx2.send(TaskMsg::Error(e.to_string())); return; }
            };
            let _ = tx2.send(TaskMsg::Downloaded(path.clone()));
            let _ = tx2.send(TaskMsg::Progress(0, 0));

            // Extract + upload (blocking; run in spawn_blocking)
            let tx_log = tx2.clone();
            let tx_up  = tx2.clone();
            let tx_ext = tx2.clone();
            let host2  = host.clone();
            let path2  = path.clone();
            let result = tokio::task::spawn_blocking(move || {
                let iscope = crate::firmware::extract_iscope(
                    path2.to_str().unwrap_or_default(),
                    move |s| { let _ = tx_ext.send(TaskMsg::Log(s)); },
                )?;
                let log = move |s: String| { let _ = tx_log.send(TaskMsg::Log(s)); };
                let up  = move |d, t| { let _ = tx_up.send(TaskMsg::Progress(d, t)); };
                crate::firmware::upload_firmware(&host2, &iscope, "iscope", log, up)
            })
            .await;

            match result {
                Ok(Ok(())) => { let _ = tx2.send(TaskMsg::Done); }
                Ok(Err(e)) => { let _ = tx2.send(TaskMsg::Error(e.to_string())); }
                Err(e)     => { let _ = tx2.send(TaskMsg::Error(e.to_string())); }
            }
        });
    }

    fn start_install_apk(&mut self) {
        let apk = self.apk_path.clone();
        let host = self.seestar_host.clone();

        let (tx, rx) = channel();
        self.tx = Some(tx.clone());
        self.rx = Some(rx);
        self.busy = true;
        self.log.clear();
        self.progress = (0, 0);

        self.rt.spawn(async move {
            let tx_log = tx.clone();
            let tx_up  = tx.clone();
            let tx_ext = tx.clone();
            let result = tokio::task::spawn_blocking(move || {
                let iscope = crate::firmware::extract_iscope(&apk, move |s| {
                    let _ = tx_ext.send(TaskMsg::Log(s));
                })?;
                let log = move |s: String| { let _ = tx_log.send(TaskMsg::Log(s)); };
                let up  = move |d, t| { let _ = tx_up.send(TaskMsg::Progress(d, t)); };
                crate::firmware::upload_firmware(&host, &iscope, "iscope", log, up)
            })
            .await;

            match result {
                Ok(Ok(())) => { let _ = tx.send(TaskMsg::Done); }
                Ok(Err(e)) => { let _ = tx.send(TaskMsg::Error(e.to_string())); }
                Err(e) => { let _ = tx.send(TaskMsg::Error(e.to_string())); }
            }
        });
    }

    fn start_install_iscope(&mut self) {
        let path = PathBuf::from(&self.iscope_path);
        let host = self.seestar_host.clone();

        let (tx, rx) = channel();
        self.tx = Some(tx.clone());
        self.rx = Some(rx);
        self.busy = true;
        self.log.clear();
        self.progress = (0, 0);

        self.rt.spawn(async move {
            let tx_log = tx.clone();
            let tx_up  = tx.clone();
            let result = tokio::task::spawn_blocking(move || {
                let log = move |s: String| { let _ = tx_log.send(TaskMsg::Log(s)); };
                let up  = move |d, t| { let _ = tx_up.send(TaskMsg::Progress(d, t)); };
                crate::firmware::upload_firmware_file(&host, &path, "iscope", log, up)
            })
            .await;

            match result {
                Ok(Ok(())) => { let _ = tx.send(TaskMsg::Done); }
                Ok(Err(e)) => { let _ = tx.send(TaskMsg::Error(e.to_string())); }
                Err(e) => { let _ = tx.send(TaskMsg::Error(e.to_string())); }
            }
        });
    }
}

struct PemTab {
    apk_path: String,
    log: Vec<String>,
    keys: Vec<String>,
    busy: bool,
    tx: Option<Sender>,
    rx: Option<Receiver>,
    rt: Arc<tokio::runtime::Runtime>,
    save_status: Option<String>,
}

impl PemTab {
    fn new(rt: Arc<tokio::runtime::Runtime>) -> Self {
        Self {
            apk_path: String::new(),
            log: vec![],
            keys: vec![],
            busy: false,
            tx: None,
            rx: None,
            rt,
            save_status: None,
        }
    }

    fn poll(&mut self) {
        let msgs: Vec<TaskMsg> = self
            .rx
            .as_ref()
            .map(|rx| rx.try_iter().collect())
            .unwrap_or_default();
        for msg in msgs {
            match msg {
                TaskMsg::Log(s) => self.log.push(s),
                TaskMsg::PemKeys(k) => self.keys = k,
                TaskMsg::Done => self.busy = false,
                TaskMsg::Error(e) => {
                    self.log.push(format!("ERROR: {}", e));
                    self.busy = false;
                }
                _ => {}
            }
        }
    }

    fn start_extract(&mut self) {
        let apk = self.apk_path.clone();
        let (tx, rx) = channel();
        self.tx = Some(tx.clone());
        self.rx = Some(rx);
        self.busy = true;
        self.log.clear();
        self.keys.clear();
        self.save_status = None;

        self.rt.spawn(async move {
            let tx2 = tx.clone();
            let result = tokio::task::spawn_blocking(move || {
                crate::pem::extract_pem_from_apk(&apk, |s| {
                    let _ = tx2.send(TaskMsg::Log(s));
                })
            })
            .await;

            match result {
                Ok(Ok(r)) => {
                    let _ = tx.send(TaskMsg::PemKeys(r.keys));
                    let _ = tx.send(TaskMsg::Done);
                }
                Ok(Err(e)) => { let _ = tx.send(TaskMsg::Error(e.to_string())); }
                Err(e) => { let _ = tx.send(TaskMsg::Error(e.to_string())); }
            }
        });
    }
}

// ── Top-level App ─────────────────────────────────────────────────────────────

pub struct SeestarApp {
    tab: Tab,
    fw: FirmwareTab,
    pem: PemTab,
}

impl SeestarApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        // Slightly larger default font.
        let mut style = (*cc.egui_ctx.style()).clone();
        style.text_styles.insert(
            egui::TextStyle::Body,
            egui::FontId::new(14.0, egui::FontFamily::Proportional),
        );
        cc.egui_ctx.set_style(style);

        let rt = Arc::new(
            tokio::runtime::Runtime::new().expect("tokio runtime"),
        );

        Self {
            tab: Tab::default(),
            fw: FirmwareTab::new(rt.clone()),
            pem: PemTab::new(rt),
        }
    }
}

impl eframe::App for SeestarApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Poll background tasks.
        self.fw.poll();
        self.pem.poll();

        // Request continuous repaints while a task is running.
        if self.fw.busy || self.pem.busy {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.tab, Tab::Firmware, "Firmware Update");
                ui.selectable_value(&mut self.tab, Tab::ExtractPem, "Extract PEM");
            });
            ui.separator();

            match self.tab {
                Tab::Firmware => draw_firmware(ui, &mut self.fw),
                Tab::ExtractPem => draw_pem(ui, &mut self.pem),
            }
        });
    }
}

// ── Firmware tab UI ───────────────────────────────────────────────────────────

fn draw_firmware(ui: &mut egui::Ui, fw: &mut FirmwareTab) {
    ui.heading("Firmware Update");
    ui.add_space(6.0);

    // Source selector
    ui.horizontal(|ui| {
        ui.label("Source:");
        ui.selectable_value(&mut fw.source, FirmwareSource::LocalApk, "Local APK/XAPK");
        ui.selectable_value(&mut fw.source, FirmwareSource::LocalIscope, "Local iscope file");
        ui.selectable_value(&mut fw.source, FirmwareSource::Download, "Download from APKPure");
    });
    ui.add_space(4.0);

    match fw.source {
        FirmwareSource::LocalApk => {
            ui.horizontal(|ui| {
                ui.label("APK/XAPK:");
                ui.text_edit_singleline(&mut fw.apk_path);
                if ui.button("Browse…").clicked() {
                    if let Some(p) = rfd::FileDialog::new()
                        .add_filter("APK/XAPK", &["apk", "xapk"])
                        .pick_file()
                    {
                        fw.apk_path = p.to_string_lossy().to_string();
                    }
                }
            });
        }
        FirmwareSource::LocalIscope => {
            ui.horizontal(|ui| {
                ui.label("iscope file:");
                ui.text_edit_singleline(&mut fw.iscope_path);
                if ui.button("Browse…").clicked() {
                    if let Some(p) = rfd::FileDialog::new().pick_file() {
                        fw.iscope_path = p.to_string_lossy().to_string();
                    }
                }
            });
        }
        FirmwareSource::Download => {
            // Auto-fetch on first visit.
            if !fw.versions_loaded && !fw.busy {
                fw.start_fetch_versions();
            }

            if fw.busy && fw.versions.is_empty() {
                ui.spinner();
            } else if fw.versions_loaded && !fw.versions.is_empty() {
                ui.horizontal(|ui| {
                    ui.label("Version:");
                    egui::ComboBox::from_id_salt("version_select")
                        .selected_text(&fw.versions[fw.selected_version].version)
                        .show_ui(ui, |ui| {
                            for (i, v) in fw.versions.iter().enumerate() {
                                ui.selectable_value(&mut fw.selected_version, i, &v.version);
                            }
                        });
                    if ui.small_button("↺").on_hover_text("Refresh list").clicked() {
                        fw.versions_loaded = false;
                    }
                });
            }

            // Fallback: paste a direct URL if the list couldn't load.
            ui.horizontal(|ui| {
                ui.label("Direct URL:");
                ui.text_edit_singleline(&mut fw.manual_url)
                    .on_hover_text("Paste a direct XAPK download URL to use instead of the list above");
            });
        }
    }

    ui.add_space(4.0);
    ui.horizontal(|ui| {
        ui.label("Seestar host:");
        ui.text_edit_singleline(&mut fw.seestar_host);
    });
    ui.add_space(8.0);

    // Action buttons
    ui.horizontal(|ui| {
        match fw.source {
            FirmwareSource::LocalApk => {
                let ready = !fw.apk_path.is_empty() && !fw.busy;
                if ui.add_enabled(ready, egui::Button::new("Update Seestar")).clicked() {
                    fw.start_install_apk();
                }
            }
            FirmwareSource::LocalIscope => {
                let ready = !fw.iscope_path.is_empty() && !fw.busy;
                if ui.add_enabled(ready, egui::Button::new("Update Seestar")).clicked() {
                    fw.start_install_iscope();
                }
            }
            FirmwareSource::Download => {
                let ready = fw.resolved_version().is_some() && !fw.busy;
                if ui.add_enabled(ready, egui::Button::new("Download only")).clicked() {
                    fw.start_download();
                }
                if ui.add_enabled(ready, egui::Button::new("Download & Install")).clicked() {
                    fw.start_download_and_install();
                }
            }
        }
    });

    ui.add_space(8.0);

    // Progress bar
    if fw.busy || fw.progress.1 > 0 {
        let (done, total) = fw.progress;
        let frac = if total > 0 {
            done as f32 / total as f32
        } else {
            // Indeterminate — use a slow animated sine wave.
            let t = ui.ctx().input(|i| i.time) as f32;
            (t.sin() * 0.5 + 0.5)
        };
        ui.add(egui::ProgressBar::new(frac).show_percentage());
    }

    // Log
    ui.add_space(4.0);
    ui.label("Log:");
    egui::ScrollArea::vertical()
        .max_height(200.0)
        .stick_to_bottom(true)
        .show(ui, |ui| {
            for line in &fw.log {
                let color = if line.starts_with("ERROR") {
                    egui::Color32::RED
                } else if line.contains("Done") || line.contains("online") {
                    egui::Color32::GREEN
                } else {
                    egui::Color32::GRAY
                };
                ui.label(RichText::new(line).color(color).monospace());
            }
        });
}

// ── PEM tab UI ────────────────────────────────────────────────────────────────

fn draw_pem(ui: &mut egui::Ui, pem: &mut PemTab) {
    ui.heading("Extract PEM Private Key");
    ui.add_space(6.0);

    ui.horizontal(|ui| {
        ui.label("APK/XAPK:");
        ui.text_edit_singleline(&mut pem.apk_path);
        if ui.button("Browse…").clicked() {
            if let Some(p) = rfd::FileDialog::new()
                .add_filter("APK/XAPK", &["apk", "xapk"])
                .pick_file()
            {
                pem.apk_path = p.to_string_lossy().to_string();
            }
        }
    });
    ui.add_space(8.0);

    let ready = !pem.apk_path.is_empty() && !pem.busy;
    if ui.add_enabled(ready, egui::Button::new("Extract PEM")).clicked() {
        pem.start_extract();
    }
    ui.add_space(4.0);

    // Log
    if !pem.log.is_empty() {
        egui::ScrollArea::vertical()
            .id_salt("pem_log")
            .max_height(100.0)
            .show(ui, |ui| {
                for line in &pem.log {
                    let color = if line.starts_with("ERROR") {
                        egui::Color32::RED
                    } else {
                        egui::Color32::GRAY
                    };
                    ui.label(RichText::new(line).color(color).monospace());
                }
            });
        ui.add_space(4.0);
    }

    // Keys
    if pem.keys.is_empty() && !pem.busy {
        if !pem.log.is_empty() {
            ui.label(RichText::new("No PEM key found.").color(egui::Color32::YELLOW));
        }
    } else {
        for (i, key) in pem.keys.iter().enumerate() {
            ui.label(format!("Key {}:", i + 1));
            egui::ScrollArea::vertical()
                .id_salt(format!("pem_key_{}", i))
                .max_height(150.0)
                .show(ui, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(&mut key.as_str())
                            .font(egui::TextStyle::Monospace)
                            .desired_width(f32::INFINITY),
                    );
                });
            if ui.button("Save to file…").clicked() {
                if let Some(dest) = rfd::FileDialog::new()
                    .add_filter("PEM", &["pem"])
                    .set_file_name(format!("seestar_{}.pem", i + 1))
                    .save_file()
                {
                    match std::fs::write(&dest, format!("{}\n", key)) {
                        Ok(_) => {
                            pem.save_status =
                                Some(format!("Saved to {}", dest.display()));
                        }
                        Err(e) => {
                            pem.save_status = Some(format!("Save failed: {}", e));
                        }
                    }
                }
            }
            ui.add_space(4.0);
        }
        if let Some(ref status) = pem.save_status {
            ui.label(RichText::new(status).color(egui::Color32::GREEN));
        }
    }
}

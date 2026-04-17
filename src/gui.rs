//! egui application — two tabs: Firmware Update and Extract PEM.

use std::path::PathBuf;
use std::sync::Arc;

use eframe::egui::{self, Color32, Frame, Margin, RichText, Rounding, Stroke};

use crate::apkpure::ApkVersion;
use crate::firmware::ScopeModel;
use crate::task::{Receiver, Sender, TaskMsg, channel};

// ── Palette ───────────────────────────────────────────────────────────────────

fn c_bg() -> Color32 {
    Color32::from_rgb(11, 14, 20)
}
fn c_surface() -> Color32 {
    Color32::from_rgb(20, 26, 36)
}
fn c_surface2() -> Color32 {
    Color32::from_rgb(32, 40, 54)
}
fn c_border() -> Color32 {
    Color32::from_rgb(55, 68, 88)
}
fn c_accent() -> Color32 {
    Color32::from_rgb(96, 165, 250)
}
fn c_accent_dim() -> Color32 {
    Color32::from_rgb(37, 99, 235)
}
fn c_text() -> Color32 {
    Color32::from_rgb(236, 240, 248)
}
fn c_muted() -> Color32 {
    Color32::from_rgb(160, 174, 192)
} // was 100,116,139
fn c_success() -> Color32 {
    Color32::from_rgb(74, 222, 128)
}
fn c_error() -> Color32 {
    Color32::from_rgb(252, 100, 100)
}
fn c_warning() -> Color32 {
    Color32::from_rgb(251, 191, 36)
}

// ── Visuals setup ─────────────────────────────────────────────────────────────

fn setup_visuals(ctx: &egui::Context) {
    let mut vis = egui::Visuals::dark();

    vis.panel_fill = c_bg();
    vis.window_fill = c_surface();
    vis.extreme_bg_color = Color32::from_rgb(7, 9, 14); // text input bg

    let r = Rounding::same(6.0);

    vis.widgets.noninteractive.bg_fill = c_surface();
    vis.widgets.noninteractive.bg_stroke = Stroke::new(1.0, c_border());
    vis.widgets.noninteractive.fg_stroke = Stroke::new(1.0, c_text());
    vis.widgets.noninteractive.rounding = r;

    vis.widgets.inactive.bg_fill = c_surface2();
    vis.widgets.inactive.bg_stroke = Stroke::new(1.0, c_border());
    vis.widgets.inactive.fg_stroke = Stroke::new(1.0, c_text());
    vis.widgets.inactive.rounding = r;

    vis.widgets.hovered.bg_fill = Color32::from_rgb(40, 50, 68);
    vis.widgets.hovered.bg_stroke = Stroke::new(1.0, c_accent());
    vis.widgets.hovered.fg_stroke = Stroke::new(1.0, c_text());
    vis.widgets.hovered.rounding = r;

    vis.widgets.active.bg_fill = Color32::from_rgb(50, 62, 84);
    vis.widgets.active.bg_stroke = Stroke::new(1.0, c_accent());
    vis.widgets.active.fg_stroke = Stroke::new(1.5, Color32::WHITE);
    vis.widgets.active.rounding = r;

    // "open" = selected-but-not-hovered (used for active ComboBox entries, etc.)
    vis.widgets.open.bg_fill = Color32::from_rgb(28, 68, 156);
    vis.widgets.open.bg_stroke = Stroke::new(1.0, c_accent());
    vis.widgets.open.fg_stroke = Stroke::new(1.0, Color32::WHITE);
    vis.widgets.open.rounding = r;

    // Selection highlight (text fields, list items)
    vis.selection.bg_fill = Color32::from_rgb(28, 68, 156);
    vis.selection.stroke = Stroke::new(1.0, Color32::WHITE);

    vis.window_rounding = Rounding::same(10.0);
    vis.menu_rounding = Rounding::same(8.0);

    ctx.set_visuals(vis);

    // Typography
    let mut style = (*ctx.style()).clone();
    style.text_styles.insert(
        egui::TextStyle::Body,
        egui::FontId::new(14.0, egui::FontFamily::Proportional),
    );
    style.text_styles.insert(
        egui::TextStyle::Button,
        egui::FontId::new(14.0, egui::FontFamily::Proportional),
    );
    style.text_styles.insert(
        egui::TextStyle::Heading,
        egui::FontId::new(20.0, egui::FontFamily::Proportional),
    );
    style.text_styles.insert(
        egui::TextStyle::Monospace,
        egui::FontId::new(13.0, egui::FontFamily::Monospace),
    );
    style.spacing.item_spacing = egui::vec2(8.0, 6.0);
    style.spacing.button_padding = egui::vec2(12.0, 6.0);
    style.spacing.window_margin = Margin::same(16.0);
    ctx.set_style(style);
}

// ── UI helpers ────────────────────────────────────────────────────────────────

fn card_frame() -> Frame {
    Frame::none()
        .fill(c_surface())
        .rounding(Rounding::same(8.0))
        .inner_margin(Margin::same(14.0))
        .stroke(Stroke::new(1.0, c_border()))
}

fn code_frame() -> Frame {
    Frame::none()
        .fill(Color32::from_rgb(7, 9, 14))
        .rounding(Rounding::same(6.0))
        .inner_margin(Margin::same(10.0))
        .stroke(Stroke::new(1.0, c_border()))
}

fn primary_btn(label: &str) -> egui::Button<'_> {
    egui::Button::new(RichText::new(label).color(Color32::WHITE).strong())
        .fill(c_accent_dim())
        .rounding(Rounding::same(6.0))
        .min_size(egui::vec2(130.0, 32.0))
}

fn secondary_btn(label: &str) -> egui::Button<'_> {
    egui::Button::new(RichText::new(label).color(c_text()))
        .fill(c_surface2())
        .rounding(Rounding::same(6.0))
        .min_size(egui::vec2(100.0, 32.0))
}

/// A label + text-edit + Browse button row where all three items share the same
/// horizontal layout, so egui can center them all vertically together.
fn file_row(
    ui: &mut egui::Ui,
    label: &str,
    path: &mut String,
    hint: &str,
    filter: Option<(&str, &[&str])>,
) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(label).color(c_muted()).size(13.0));
        // Reserve the button width before sizing the TextEdit so all three
        // widgets live in the same layout pass and center correctly.
        let btn_w = 100.0 + ui.spacing().item_spacing.x;
        let te_w = (ui.available_width() - btn_w).max(60.0);
        ui.add(
            egui::TextEdit::singleline(path)
                .hint_text(hint)
                .desired_width(te_w),
        );
        if ui.add(secondary_btn("Browse")).clicked() {
            let mut dialog = rfd::FileDialog::new();
            if let Some((name, exts)) = filter {
                dialog = dialog.add_filter(name, exts);
            }
            if let Some(p) = dialog.pick_file() {
                *path = p.to_string_lossy().to_string();
            }
        }
    });
}

fn section_label(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).color(c_muted()).size(11.5).strong());
}

// ── Tab state ─────────────────────────────────────────────────────────────────

#[derive(Default, PartialEq)]
enum Tab {
    #[default]
    Firmware,
    ExtractPem,
    Diagnostics,
}

/// Source for the firmware to install.
#[derive(Default, PartialEq)]
enum FirmwareSource {
    #[default]
    LocalApk, // user picks an APK/XAPK file
    LocalIscope, // user picks a raw iscope file
    Download,    // fetch from APKPure
}

/// Which install action is awaiting confirmation.
#[derive(Clone, Copy, PartialEq)]
enum PendingAction {
    InstallApk,
    InstallIscope,
    DownloadAndInstall,
}

struct FirmwareTab {
    source: FirmwareSource,
    model: ScopeModel,
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
    /// Set when user clicks an install button; cleared on confirm or cancel.
    confirm: Option<PendingAction>,
    /// When model is Auto and install was clicked, the action is held here while
    /// detection runs.  On `ModelDetected` it moves to `confirm`.
    detection_pending: Option<PendingAction>,
    /// Device info resolved by auto-detection, shown in the confirm dialog.
    detected_model: Option<crate::firmware::DeviceInfo>,
    /// PEM private key bytes extracted from the loaded APK, used for auto-detection.
    pem_key: Option<Vec<u8>>,
    /// Background channel for PEM extraction (separate from install channel).
    pem_rx: Option<Receiver>,
    /// APK path we last started PEM extraction from, to avoid re-extracting.
    last_pem_path: String,
    /// Directory to save downloaded XAPK files into.
    download_dir: String,
}

impl FirmwareTab {
    fn new(rt: Arc<tokio::runtime::Runtime>) -> Self {
        Self {
            source: FirmwareSource::default(),
            model: ScopeModel::default(),
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
            confirm: None,
            detection_pending: None,
            detected_model: None,
            pem_key: None,
            pem_rx: None,
            last_pem_path: String::new(),
            download_dir: dirs::download_dir()
                .or_else(dirs::home_dir)
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
        }
    }

    /// If `apk_path` changed and the file exists, kick off a background PEM extraction.
    fn maybe_refresh_pem(&mut self, apk_path: &str) {
        if apk_path.is_empty() || apk_path == self.last_pem_path {
            return;
        }
        if !std::path::Path::new(apk_path).exists() {
            return;
        }
        self.last_pem_path = apk_path.to_string();
        self.pem_key = None;
        let (tx, rx) = channel();
        self.pem_rx = Some(rx);
        crate::runner::extract_pem(&self.rt, tx, apk_path.to_string());
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
                    // Extract PEM from downloaded APK for auto-detection
                    let path_str = p.to_string_lossy().to_string();
                    self.maybe_refresh_pem(&path_str);
                }
                TaskMsg::Done => {
                    self.log.push("Done.".to_string());
                    self.busy = false;
                    self.progress = (0, 0);
                }
                TaskMsg::ModelDetected(info) => {
                    self.log.push(format!(
                        "Detected: {} — {}",
                        info.model.display_name(),
                        info.model.bitness_description()
                    ));
                    self.detected_model = Some(info);
                    self.confirm = self.detection_pending.take();
                    self.busy = false;
                    self.progress = (0, 0);
                }
                TaskMsg::Error(e) => {
                    self.log.push(format!("ERROR: {}", e));
                    self.busy = false;
                    self.progress = (0, 0);
                    self.detection_pending = None;
                    self.detected_model = None;
                }
                _ => {}
            }
        }

        // Drain the background PEM extraction channel
        let pem_msgs: Vec<TaskMsg> = self
            .pem_rx
            .as_ref()
            .map(|rx| rx.try_iter().collect())
            .unwrap_or_default();
        for msg in pem_msgs {
            if let TaskMsg::PemKeys(keys) = msg
                && let Some(key) = keys.into_iter().next()
            {
                self.pem_key = Some(key.into_bytes());
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
        crate::runner::fetch_versions(&self.rt, tx);
    }

    fn start_download(&mut self) {
        let Some((version, download_url)) = self.resolved_version() else {
            return;
        };
        let dest_dir = PathBuf::from(&self.download_dir);
        let (tx, rx) = channel();
        self.tx = Some(tx.clone());
        self.rx = Some(rx);
        self.busy = true;
        self.log.clear();
        self.downloaded_apk = None;
        self.progress = (0, 0);
        crate::runner::download_only(&self.rt, tx, version, download_url, dest_dir);
    }

    /// When model is Auto, run detection first; `action` is held until `ModelDetected`.
    /// Returns `true` if detection was started (caller should not proceed to confirm).
    fn maybe_start_detection(&mut self, action: PendingAction) -> bool {
        if !self.model.is_auto() {
            return false;
        }
        // Try to get the pem_key, extracting from APK if needed.
        let pem_key = if let Some(k) = self.pem_key.clone() {
            k
        } else if !self.apk_path.is_empty() {
            // Extract PEM from APK synchronously (blocking)
            match crate::pem::extract_pem_from_apk(&self.apk_path, |_| {}) {
                Ok(result) => {
                    if let Some(key) = result.keys.into_iter().next() {
                        key.into_bytes()
                    } else {
                        self.log.push(
                            "ERROR: No PEM key found in APK. Select a model manually.".to_string(),
                        );
                        return true;
                    }
                }
                Err(e) => {
                    self.log
                        .push(format!("ERROR: Failed to extract PEM from APK: {}", e));
                    return true;
                }
            }
        } else {
            self.log.push(
                "ERROR: Auto-detect requires an APK to extract the key from. \
                 Load an APK file or select a model manually."
                    .to_string(),
            );
            return true;
        };
        let (tx, rx) = channel();
        self.tx = Some(tx.clone());
        self.rx = Some(rx);
        self.busy = true;
        self.log.clear();
        self.detection_pending = Some(action);
        self.detected_model = None;
        crate::runner::detect_model(&self.rt, tx, self.seestar_host.clone(), pem_key);
        true
    }

    /// The model to use for the actual install — either the auto-detected model
    /// (after user confirmation) or the manually selected one.
    fn resolved_model(&mut self) -> ScopeModel {
        self.detected_model
            .take()
            .map(|d| d.model)
            .unwrap_or(self.model)
    }

    fn start_download_and_install(&mut self) {
        let Some((version, download_url)) = self.resolved_version() else {
            return;
        };
        let host = self.seestar_host.clone();
        let dest_dir = PathBuf::from(&self.download_dir);
        let (tx, rx) = channel();
        self.tx = Some(tx.clone());
        self.rx = Some(rx);
        self.busy = true;
        self.log.clear();
        self.downloaded_apk = None;
        self.progress = (0, 0);
        let model = self.resolved_model();
        crate::runner::download_and_install(
            &self.rt,
            tx,
            version,
            download_url,
            dest_dir,
            crate::runner::InstallTarget {
                host,
                model,
                pem_key: self.pem_key.clone(),
            },
        );
    }

    fn start_install_apk(&mut self) {
        let (tx, rx) = channel();
        self.tx = Some(tx.clone());
        self.rx = Some(rx);
        self.busy = true;
        self.log.clear();
        self.progress = (0, 0);
        let model = self.resolved_model();
        crate::runner::install_apk(
            &self.rt,
            tx,
            self.apk_path.clone(),
            crate::runner::InstallTarget {
                host: self.seestar_host.clone(),
                model,
                pem_key: self.pem_key.clone(),
            },
        );
    }

    fn start_install_iscope(&mut self) {
        let (tx, rx) = channel();
        self.tx = Some(tx.clone());
        self.rx = Some(rx);
        self.busy = true;
        self.log.clear();
        self.progress = (0, 0);
        let model = self.resolved_model();
        crate::runner::install_iscope(
            &self.rt,
            tx,
            self.iscope_path.clone(),
            crate::runner::InstallTarget {
                host: self.seestar_host.clone(),
                model,
                pem_key: self.pem_key.clone(),
            },
        );
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
        let (tx, rx) = channel();
        self.tx = Some(tx.clone());
        self.rx = Some(rx);
        self.busy = true;
        self.log.clear();
        self.keys.clear();
        self.save_status = None;
        crate::runner::extract_pem(&self.rt, tx, self.apk_path.clone());
    }
}

// ── Diagnostics tab ───────────────────────────────────────────────────────────

struct DiagnosticsTab {
    host: String,
    apk_path: String,
    pem_file_path: String,
    log: Vec<String>,
    result: Option<crate::firmware::DiagnosticsData>,
    busy: bool,
    tx: Option<Sender>,
    rx: Option<Receiver>,
    pem_key: Option<Vec<u8>>,
    pem_rx: Option<Receiver>,
    last_pem_path: String,
    last_pem_file_path: String,
    save_status: Option<String>,
    rt: Arc<tokio::runtime::Runtime>,
}

impl DiagnosticsTab {
    fn new(rt: Arc<tokio::runtime::Runtime>) -> Self {
        Self {
            host: "seestar.local".to_string(),
            apk_path: String::new(),
            pem_file_path: String::new(),
            log: vec![],
            result: None,
            busy: false,
            tx: None,
            rx: None,
            pem_key: None,
            pem_rx: None,
            last_pem_path: String::new(),
            last_pem_file_path: String::new(),
            save_status: None,
            rt,
        }
    }

    fn maybe_refresh_pem(&mut self, apk_path: &str) {
        if apk_path.is_empty() || apk_path == self.last_pem_path {
            return;
        }
        if !std::path::Path::new(apk_path).exists() {
            return;
        }
        self.last_pem_path = apk_path.to_string();
        self.pem_key = None;
        let (tx, rx) = channel();
        self.pem_rx = Some(rx);
        crate::runner::extract_pem(&self.rt, tx, apk_path.to_string());
    }

    fn maybe_refresh_pem_file(&mut self) {
        let path = self.pem_file_path.clone();
        if path.is_empty() || path == self.last_pem_file_path {
            return;
        }
        if !std::path::Path::new(&path).exists() {
            return;
        }
        self.last_pem_file_path = path.clone();
        if let Ok(bytes) = std::fs::read(&path) {
            self.pem_key = Some(bytes);
            // Clear APK path so the two sources don't conflict
            self.apk_path.clear();
            self.last_pem_path.clear();
        }
    }

    fn poll(&mut self) {
        // Drain background PEM extraction
        if let Some(rx) = &self.pem_rx {
            for msg in rx.try_iter() {
                if let TaskMsg::PemKeys(keys) = msg
                    && let Some(key) = keys.into_iter().next()
                {
                    self.pem_key = Some(key.into_bytes());
                }
            }
        }

        let msgs: Vec<TaskMsg> = self
            .rx
            .as_ref()
            .map(|rx| rx.try_iter().collect())
            .unwrap_or_default();
        for msg in msgs {
            match msg {
                TaskMsg::Log(s) => self.log.push(s),
                TaskMsg::DiagnosticsResult(data) => self.result = Some(data),
                TaskMsg::Done => self.busy = false,
                TaskMsg::Error(e) => {
                    self.log.push(format!("ERROR: {}", e));
                    self.busy = false;
                }
                _ => {}
            }
        }
    }

    fn start_run(&mut self) {
        let Some(pem_key) = self.pem_key.clone() else {
            self.log
                .push("No PEM key available — select an APK/XAPK file first.".to_string());
            return;
        };
        let (tx, rx) = channel();
        self.tx = Some(tx.clone());
        self.rx = Some(rx);
        self.busy = true;
        self.log.clear();
        self.result = None;
        crate::runner::run_diagnostics(&self.rt, tx, self.host.clone(), pem_key);
    }
}

// ── Top-level App ─────────────────────────────────────────────────────────────

pub struct SeestarApp {
    tab: Tab,
    fw: FirmwareTab,
    pem: PemTab,
    diag: DiagnosticsTab,
}

impl SeestarApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        setup_visuals(&cc.egui_ctx);

        let rt = Arc::new(tokio::runtime::Runtime::new().expect("tokio runtime"));

        Self {
            tab: Tab::default(),
            fw: FirmwareTab::new(rt.clone()),
            pem: PemTab::new(rt.clone()),
            diag: DiagnosticsTab::new(rt),
        }
    }
}

impl eframe::App for SeestarApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.fw.poll();
        self.pem.poll();
        self.diag.poll();
        if !self.diag.apk_path.is_empty() {
            let path = self.diag.apk_path.clone();
            self.diag.maybe_refresh_pem(&path);
        }
        self.diag.maybe_refresh_pem_file();

        if self.fw.busy || self.pem.busy || self.diag.busy {
            ctx.request_repaint_after(std::time::Duration::from_millis(80));
        }

        // Header bar
        egui::TopBottomPanel::top("header")
            .frame(
                Frame::none()
                    .fill(c_surface())
                    .inner_margin(Margin::symmetric(20.0, 10.0))
                    .stroke(Stroke::new(1.0, c_border())),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Seestar Tool")
                            .size(18.0)
                            .color(c_text())
                            .strong(),
                    );

                    ui.add_space(20.0);

                    // Tab buttons
                    let fw_active = self.tab == Tab::Firmware;
                    let pem_active = self.tab == Tab::ExtractPem;
                    let diag_active = self.tab == Tab::Diagnostics;

                    if tab_btn(ui, "Firmware Update", fw_active).clicked() {
                        self.tab = Tab::Firmware;
                    }
                    if tab_btn(ui, "Extract PEM", pem_active).clicked() {
                        self.tab = Tab::ExtractPem;
                    }
                    if tab_btn(ui, "Diagnostics", diag_active).clicked() {
                        self.tab = Tab::Diagnostics;
                    }
                });
            });

        egui::CentralPanel::default()
            .frame(Frame::none().fill(c_bg()).inner_margin(Margin::same(16.0)))
            .show(ctx, |ui| match self.tab {
                Tab::Firmware => draw_firmware(ui, &mut self.fw),
                Tab::ExtractPem => draw_pem(ui, &mut self.pem),
                Tab::Diagnostics => draw_diagnostics(ui, &mut self.diag),
            });

        // Confirmation modal — blocks other interaction
        if let Some(action) = self.fw.confirm {
            let title = match action {
                PendingAction::InstallApk | PendingAction::InstallIscope => {
                    "Confirm Firmware Update"
                }
                PendingAction::DownloadAndInstall => "Confirm Download & Install",
            };

            // Build the body text.  When auto-detection ran, show model + bitness
            // and ask the user to verify before anything is flashed.
            let base = match action {
                PendingAction::InstallApk | PendingAction::InstallIscope => {
                    "This will upload firmware directly to your Seestar."
                }
                PendingAction::DownloadAndInstall => {
                    "This will download firmware from APKPure and upload it to your Seestar."
                }
            };

            let mut open = true;
            let dlg_frame = egui::Frame::window(&ctx.style())
                .fill(c_surface())
                .stroke(egui::Stroke::new(1.0, c_border()));
            egui::Window::new(egui::RichText::new(title).color(c_text()).strong())
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .frame(dlg_frame)
                .open(&mut open)
                .show(ctx, |ui| {
                    ui.add_space(4.0);
                    // Render dialog with colored sections
                    if let Some(ref info) = self.fw.detected_model {
                        // Red brick warning
                        ui.label(
                            egui::RichText::new("🔴 INSTALLING WRONG FIRMWARE WILL")
                                .color(egui::Color32::from_rgb(255, 59, 48))
                                .strong(),
                        );
                        ui.label(
                            egui::RichText::new("PERMANENTLY BRICK YOUR SCOPE 🔴")
                                .color(egui::Color32::from_rgb(255, 59, 48))
                                .strong(),
                        );
                        ui.add_space(8.0);

                        // Model info
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("Auto-detected model:").color(c_text()));
                            ui.label(
                                egui::RichText::new(format!(
                                    "{} — {}",
                                    info.model.display_name(),
                                    info.model.bitness_description()
                                ))
                                .color(c_text())
                                .strong(),
                            );
                        });

                        // Firmware version
                        if let Some(ref fw_ver) = info.firmware_ver_string {
                            ui.horizontal(|ui| {
                                ui.label(egui::RichText::new("Current firmware:").color(c_text()));
                                ui.label(egui::RichText::new(fw_ver).color(c_text()));
                            });
                        }

                        // Battery
                        if let Some(pct) = info.battery_capacity {
                            let (status, battery_color) = if info.battery_charging {
                                (" (charging)".to_string(), c_text())
                            } else if pct < 50 {
                                (
                                    " ⚠ low — consider charging first".to_string(),
                                    egui::Color32::from_rgb(255, 193, 7),
                                )
                            } else {
                                (String::new(), c_text())
                            };
                            ui.horizontal(|ui| {
                                ui.label(egui::RichText::new("Battery:").color(c_text()));
                                ui.label(
                                    egui::RichText::new(format!("{}%{}", pct, status))
                                        .color(battery_color),
                                );
                            });
                        }

                        ui.add_space(8.0);
                        ui.label(
                            egui::RichText::new(
                                "Does this match your scope? If unsure, cancel immediately and select the model manually.",
                            )
                            .color(c_text()),
                        );
                        ui.add_space(8.0);
                        ui.label(egui::RichText::new(base).color(c_text()));
                    } else {
                        // No auto-detect: red brick warning
                        ui.label(
                            egui::RichText::new("🔴 INSTALLING WRONG FIRMWARE WILL")
                                .color(egui::Color32::from_rgb(255, 59, 48))
                                .strong(),
                        );
                        ui.label(
                            egui::RichText::new("PERMANENTLY BRICK YOUR SCOPE 🔴")
                                .color(egui::Color32::from_rgb(255, 59, 48))
                                .strong(),
                        );
                        ui.add_space(8.0);

                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("Selected model:").color(c_text()));
                            ui.label(
                                egui::RichText::new(self.fw.model.display_name())
                                    .color(c_text())
                                    .strong(),
                            );
                        });
                        ui.label(
                            egui::RichText::new("Ensure the model matches your scope exactly.")
                                .color(c_text()),
                        );
                        ui.add_space(8.0);
                        ui.label(egui::RichText::new(base).color(c_text()));
                    }

                    ui.add_space(8.0);

                    // Yellow "During installation" section
                    ui.label(
                        egui::RichText::new("During installation:")
                            .color(egui::Color32::from_rgb(255, 193, 7))
                            .strong(),
                    );
                    ui.label(egui::RichText::new("• The scope will reboot").color(c_text()));
                    ui.label(egui::RichText::new("• DO NOT power off the scope").color(c_text()));
                    ui.label(
                        egui::RichText::new("• Keep the network connection stable").color(c_text()),
                    );

                    ui.add_space(12.0);
                    ui.horizontal(|ui| {
                        if ui.add(primary_btn("Yes, update")).clicked() {
                            match action {
                                PendingAction::InstallApk => self.fw.start_install_apk(),
                                PendingAction::InstallIscope => self.fw.start_install_iscope(),
                                PendingAction::DownloadAndInstall => {
                                    self.fw.start_download_and_install()
                                }
                            }
                            self.fw.confirm = None;
                        }
                        ui.add_space(8.0);
                        if ui.add(secondary_btn("Cancel")).clicked() {
                            self.fw.detected_model = None;
                            self.fw.confirm = None;
                        }
                    });
                });
            if !open {
                self.fw.detected_model = None;
                self.fw.confirm = None;
            }
        }
    }
}

fn tab_btn(ui: &mut egui::Ui, label: &str, active: bool) -> egui::Response {
    let fill = if active {
        c_accent_dim()
    } else {
        Color32::TRANSPARENT
    };
    let text_color = if active { Color32::WHITE } else { c_muted() };
    ui.add(
        egui::Button::new(RichText::new(label).color(text_color))
            .fill(fill)
            .rounding(Rounding::same(6.0))
            .min_size(egui::vec2(0.0, 28.0)),
    )
}

// ── Firmware tab ──────────────────────────────────────────────────────────────

fn draw_firmware(ui: &mut egui::Ui, fw: &mut FirmwareTab) {
    // Source + path card
    card_frame().show(ui, |ui| {
        ui.vertical(|ui| {
            section_label(ui, "FIRMWARE SOURCE");
            ui.add_space(6.0);

            ui.horizontal(|ui| {
                source_btn(
                    ui,
                    &mut fw.source,
                    FirmwareSource::LocalApk,
                    "Local APK / XAPK",
                );
                source_btn(
                    ui,
                    &mut fw.source,
                    FirmwareSource::LocalIscope,
                    "Local iscope",
                );
                source_btn(
                    ui,
                    &mut fw.source,
                    FirmwareSource::Download,
                    "Download from APKPure",
                );
            });

            ui.add_space(10.0);

            match fw.source {
                FirmwareSource::LocalApk => {
                    file_row(
                        ui,
                        "APK / XAPK",
                        &mut fw.apk_path,
                        "Path to .apk or .xapk file",
                        Some(("APK / XAPK", &["apk", "xapk"])),
                    );
                }
                FirmwareSource::LocalIscope => {
                    file_row(
                        ui,
                        "iscope file",
                        &mut fw.iscope_path,
                        "Path to iscope firmware file",
                        None,
                    );
                }
                FirmwareSource::Download => {
                    if !fw.versions_loaded && !fw.busy {
                        fw.start_fetch_versions();
                    }

                    if fw.busy && fw.versions.is_empty() {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.label(
                                RichText::new("Fetching version list…")
                                    .color(c_muted())
                                    .size(13.0),
                            );
                        });
                    } else if fw.versions_loaded && !fw.versions.is_empty() {
                        ui.horizontal(|ui| {
                            ui.add_sized(
                                [70.0, 14.0],
                                egui::Label::new(
                                    RichText::new("Version").color(c_muted()).size(13.0),
                                ),
                            );
                            egui::ComboBox::from_id_salt("version_select")
                                .selected_text(&fw.versions[fw.selected_version].version)
                                .show_ui(ui, |ui| {
                                    for (i, v) in fw.versions.iter().enumerate() {
                                        ui.selectable_value(
                                            &mut fw.selected_version,
                                            i,
                                            &v.version,
                                        );
                                    }
                                });
                            if ui
                                .add(
                                    egui::Button::new(RichText::new("↺").color(c_muted()))
                                        .fill(Color32::TRANSPARENT)
                                        .rounding(Rounding::same(4.0)),
                                )
                                .on_hover_text("Refresh list")
                                .clicked()
                            {
                                fw.versions_loaded = false;
                            }
                        });
                    }

                    ui.horizontal(|ui| {
                        ui.add_sized(
                            [70.0, 14.0],
                            egui::Label::new(
                                RichText::new("Direct URL").color(c_muted()).size(13.0),
                            ),
                        );
                        ui.add(
                            egui::TextEdit::singleline(&mut fw.manual_url)
                                .hint_text("Paste a direct XAPK download URL (optional fallback)")
                                .desired_width(f32::INFINITY),
                        );
                    });

                    ui.horizontal(|ui| {
                        ui.add_sized(
                            [70.0, 14.0],
                            egui::Label::new(RichText::new("Save to").color(c_muted()).size(13.0)),
                        );
                        let btn_w = 100.0 + ui.spacing().item_spacing.x;
                        let te_w = (ui.available_width() - btn_w).max(60.0);
                        ui.add(
                            egui::TextEdit::singleline(&mut fw.download_dir)
                                .hint_text("Folder to save downloaded XAPK")
                                .desired_width(te_w),
                        );
                        if ui.add(secondary_btn("Browse")).clicked()
                            && let Some(p) = rfd::FileDialog::new()
                                .set_directory(&fw.download_dir)
                                .pick_folder()
                        {
                            fw.download_dir = p.to_string_lossy().to_string();
                        }
                    });
                }
            }
        });
    });

    // Trigger background PEM extraction whenever the APK path changes
    let apk_path_snapshot = fw.apk_path.clone();
    fw.maybe_refresh_pem(&apk_path_snapshot);

    ui.add_space(8.0);

    // Target + actions card
    card_frame().show(ui, |ui| {
        ui.vertical(|ui| {
            section_label(ui, "TARGET DEVICE");
            ui.add_space(6.0);

            ui.horizontal(|ui| {
                ui.label(RichText::new("Seestar host").color(c_muted()).size(13.0));
                ui.add(
                    egui::TextEdit::singleline(&mut fw.seestar_host)
                        .desired_width(220.0)
                        .hint_text("e.g. seestar.local or 192.168.1.100"),
                );
            });

            ui.add_space(4.0);

            ui.horizontal(|ui| {
                ui.label(RichText::new("Model").color(c_muted()).size(13.0));
                let auto_btn = source_btn(ui, &mut fw.model, ScopeModel::Auto, "Auto-detect");
                if fw.pem_key.is_none() {
                    auto_btn.on_hover_text("Load an APK file to enable auto-detection");
                }
                source_btn(ui, &mut fw.model, ScopeModel::S50, "S50");
                source_btn(ui, &mut fw.model, ScopeModel::S30, "S30");
                source_btn(ui, &mut fw.model, ScopeModel::S30Pro, "S30 Pro");
            });

            ui.add_space(10.0);
            ui.separator();
            ui.add_space(10.0);

            ui.horizontal(|ui| {
                match fw.source {
                    FirmwareSource::LocalApk => {
                        let ready = !fw.apk_path.is_empty() && !fw.busy;
                        if ui
                            .add_enabled(ready, primary_btn("Update Seestar"))
                            .clicked()
                            && !fw.maybe_start_detection(PendingAction::InstallApk)
                        {
                            fw.confirm = Some(PendingAction::InstallApk);
                        }
                    }
                    FirmwareSource::LocalIscope => {
                        let ready = !fw.iscope_path.is_empty() && !fw.busy;
                        if ui
                            .add_enabled(ready, primary_btn("Update Seestar"))
                            .clicked()
                            && !fw.maybe_start_detection(PendingAction::InstallIscope)
                        {
                            fw.confirm = Some(PendingAction::InstallIscope);
                        }
                    }
                    FirmwareSource::Download => {
                        let ready = fw.resolved_version().is_some() && !fw.busy;
                        if ui
                            .add_enabled(ready, primary_btn("Download & Install"))
                            .clicked()
                            && !fw.maybe_start_detection(PendingAction::DownloadAndInstall)
                        {
                            fw.confirm = Some(PendingAction::DownloadAndInstall);
                        }
                        if ui
                            .add_enabled(ready, secondary_btn("Download only"))
                            .clicked()
                        {
                            fw.start_download();
                        }
                        let have_download = fw.downloaded_apk.is_some();
                        if ui
                            .add_enabled(
                                have_download && !fw.busy,
                                secondary_btn("Install downloaded"),
                            )
                            .on_hover_text("Switch to Local APK tab with the downloaded file")
                            .clicked()
                            && let Some(path) = &fw.downloaded_apk
                        {
                            fw.apk_path = path.to_string_lossy().to_string();
                            fw.source = FirmwareSource::LocalApk;
                            if !fw.maybe_start_detection(PendingAction::InstallApk) {
                                fw.confirm = Some(PendingAction::InstallApk);
                            }
                        }
                    }
                }

                if fw.busy {
                    ui.add_space(8.0);
                    ui.spinner();
                }
            });
        });
    });

    ui.add_space(8.0);

    // Progress bar (shown while busy or progress > 0)
    if fw.busy || fw.progress.1 > 0 {
        let (done, total) = fw.progress;
        let frac = if total > 0 {
            done as f32 / total as f32
        } else {
            let t = ui.ctx().input(|i| i.time) as f32;
            t.sin() * 0.5 + 0.5
        };

        let label = if total > 0 {
            let pct = (frac * 100.0) as u32;
            let done_mb = done >> 20;
            let total_mb = total >> 20;
            if total_mb > 0 {
                format!("{pct}%  ({done_mb} / {total_mb} MB)")
            } else {
                // Install countdown: done = elapsed secs, total = estimate secs
                let remaining = total.saturating_sub(done);
                format!("Installing…  ~{remaining}s remaining")
            }
        } else {
            String::new()
        };

        ui.add(
            egui::ProgressBar::new(frac)
                .text(RichText::new(label).color(c_text()).size(12.5))
                .animate(total == 0),
        );
        ui.add_space(4.0);
    }

    // Log — stretch to fill the remaining panel width and height
    let log_frame = code_frame();
    let available = ui.available_height();
    let full_width = ui.available_width();
    log_frame.show(ui, |ui| {
        ui.set_min_width(full_width - 28.0); // subtract frame inner margins (14×2)
        egui::ScrollArea::vertical()
            .max_height(available - 28.0)
            .stick_to_bottom(true)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                if fw.log.is_empty() {
                    ui.label(
                        RichText::new("Output will appear here…")
                            .color(c_muted())
                            .italics()
                            .monospace(),
                    );
                } else {
                    for line in &fw.log {
                        let (color, prefix) = log_line_style(line);
                        ui.label(
                            RichText::new(format!("{prefix}{line}"))
                                .color(color)
                                .monospace()
                                .size(12.5),
                        );
                    }
                }
            });
    });
}

fn source_btn<T: PartialEq>(
    ui: &mut egui::Ui,
    current: &mut T,
    variant: T,
    label: &str,
) -> egui::Response {
    let active = *current == variant;
    let fill = if active { c_accent_dim() } else { c_surface2() };
    let text_color = if active { Color32::WHITE } else { c_muted() };
    let resp = ui.add(
        egui::Button::new(RichText::new(label).color(text_color).size(13.0))
            .fill(fill)
            .rounding(Rounding::same(5.0))
            .min_size(egui::vec2(0.0, 26.0)),
    );
    if resp.clicked() {
        *current = variant;
    }
    resp
}

fn log_line_style(line: &str) -> (Color32, &'static str) {
    if line.starts_with("ERROR") || line.contains("Timed out") || line.contains("error") {
        (c_error(), "")
    } else if line.contains("Done") || line.contains("online") || line.contains("complete") {
        (c_success(), "")
    } else if line.starts_with("WARNING") || line.contains("warn") {
        (c_warning(), "")
    } else if line.contains("Uploading")
        || line.contains("Installing")
        || line.contains("rebooting")
    {
        (c_accent(), "")
    } else {
        (Color32::from_rgb(203, 213, 225), "")
    }
}

// ── PEM tab ───────────────────────────────────────────────────────────────────

fn draw_pem(ui: &mut egui::Ui, pem: &mut PemTab) {
    // Legal notice
    Frame::none()
        .fill(Color32::from_rgb(26, 22, 10))
        .rounding(Rounding::same(8.0))
        .inner_margin(Margin::same(14.0))
        .stroke(Stroke::new(1.0, Color32::from_rgb(110, 88, 24)))
        .show(ui, |ui| {
            ui.label(
                RichText::new("Interoperability Notice")
                    .color(c_warning())
                    .strong()
                    .size(13.0),
            );
            ui.add_space(4.0);
            ui.label(
                RichText::new(
                    "PEM key extraction is provided for interoperability purposes under \
                     17 U.S.C. \u{00a7} 1201(f) (the DMCA interoperability exemption), \
                     enabling independent programs to interoperate with your Seestar device.",
                )
                .color(c_muted())
                .size(12.5),
            );
            ui.add_space(2.0);
            ui.label(
                RichText::new(
                    "The legality of key extraction and use varies by jurisdiction. \
                     You are solely responsible for ensuring compliance with the laws \
                     of your region.",
                )
                .color(c_muted())
                .size(12.5),
            );
        });

    ui.add_space(8.0);

    card_frame().show(ui, |ui| {
        ui.vertical(|ui| {
            section_label(ui, "APK SOURCE");
            ui.add_space(6.0);

            file_row(
                ui,
                "APK / XAPK",
                &mut pem.apk_path,
                "Path to .apk or .xapk file",
                Some(("APK / XAPK", &["apk", "xapk"])),
            );

            ui.add_space(10.0);
            ui.separator();
            ui.add_space(10.0);

            ui.horizontal(|ui| {
                let ready = !pem.apk_path.is_empty() && !pem.busy;
                if ui
                    .add_enabled(ready, primary_btn("Extract PEM Key"))
                    .clicked()
                {
                    pem.start_extract();
                }
                if pem.busy {
                    ui.add_space(8.0);
                    ui.spinner();
                }
            });
        });
    });

    ui.add_space(8.0);

    // Log output
    if !pem.log.is_empty() {
        code_frame().show(ui, |ui| {
            egui::ScrollArea::vertical()
                .id_salt("pem_log")
                .max_height(80.0)
                .show(ui, |ui| {
                    for line in &pem.log {
                        let (color, _) = log_line_style(line);
                        ui.label(RichText::new(line).color(color).monospace().size(12.5));
                    }
                });
        });
        ui.add_space(8.0);
    }

    // Keys
    if pem.keys.is_empty() && !pem.busy && !pem.log.is_empty() {
        card_frame().show(ui, |ui| {
            ui.label(
                RichText::new("No PEM key found in this APK.")
                    .color(c_warning())
                    .size(13.5),
            );
        });
    } else {
        for (i, key) in pem.keys.iter().enumerate() {
            card_frame().show(ui, |ui| {
                ui.horizontal(|ui| {
                    section_label(ui, &format!("PRIVATE KEY {}", i + 1));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.add(secondary_btn("Save to file")).clicked()
                            && let Some(dest) = rfd::FileDialog::new()
                                .add_filter("PEM", &["pem"])
                                .set_file_name(format!("seestar_{}.pem", i + 1))
                                .save_file()
                        {
                            pem.save_status =
                                Some(match std::fs::write(&dest, format!("{}\n", key)) {
                                    Ok(_) => format!("Saved to {}", dest.display()),
                                    Err(e) => format!("Save failed: {e}"),
                                });
                        }
                    });
                });
                ui.add_space(6.0);
                code_frame().show(ui, |ui| {
                    egui::ScrollArea::vertical()
                        .id_salt(format!("pem_key_{i}"))
                        .max_height(150.0)
                        .show(ui, |ui| {
                            ui.add(
                                egui::TextEdit::multiline(&mut key.as_str())
                                    .font(egui::TextStyle::Monospace)
                                    .desired_width(f32::INFINITY),
                            );
                        });
                });
            });
            ui.add_space(6.0);
        }

        if let Some(ref status) = pem.save_status {
            let color = if status.starts_with("Save failed") {
                c_error()
            } else {
                c_success()
            };
            ui.label(RichText::new(status).color(color).size(13.0));
        }
    }
}

fn draw_diagnostics(ui: &mut egui::Ui, diag: &mut DiagnosticsTab) {
    card_frame().show(ui, |ui| {
        ui.vertical(|ui| {
            section_label(ui, "TARGET SCOPE");
            ui.add_space(6.0);

            ui.horizontal(|ui| {
                ui.label(RichText::new("Host").color(c_muted()).size(13.0));
                ui.add(
                    egui::TextEdit::singleline(&mut diag.host)
                        .hint_text("seestar.local")
                        .desired_width(200.0),
                );
            });

            ui.add_space(8.0);

            file_row(
                ui,
                "APK / XAPK",
                &mut diag.apk_path,
                "Path to .apk or .xapk (to extract PEM key)",
                Some(("APK / XAPK", &["apk", "xapk"])),
            );

            ui.add_space(4.0);
            ui.label(RichText::new("— or —").color(c_muted()).size(11.0));
            ui.add_space(4.0);

            file_row(
                ui,
                "PEM File",
                &mut diag.pem_file_path,
                "Path to .pem file (alternative to APK)",
                Some(("PEM File", &["pem"])),
            );

            ui.add_space(4.0);
            let key_status = if diag.pem_key.is_some() {
                RichText::new("PEM key ready").color(c_success()).size(12.0)
            } else if diag.apk_path.is_empty() && diag.pem_file_path.is_empty() {
                RichText::new("Select an APK/XAPK or a .pem file")
                    .color(c_muted())
                    .size(12.0)
            } else if !diag.pem_file_path.is_empty() {
                RichText::new("Loading PEM key…")
                    .color(c_muted())
                    .size(12.0)
            } else {
                RichText::new("Extracting PEM key…")
                    .color(c_muted())
                    .size(12.0)
            };
            ui.label(key_status);

            ui.add_space(10.0);
            ui.separator();
            ui.add_space(10.0);

            ui.horizontal(|ui| {
                let ready = diag.pem_key.is_some() && !diag.busy;
                if ui
                    .add_enabled(ready, primary_btn("Run Diagnostics"))
                    .clicked()
                {
                    diag.start_run();
                }
                if diag.busy {
                    ui.add_space(8.0);
                    ui.spinner();
                }
            });
        });
    });

    ui.add_space(8.0);

    // Wrap the log + results in a scroll area so both panels are always reachable.
    egui::ScrollArea::vertical()
        .id_salt("diag_scroll")
        .show(ui, |ui| {
            if !diag.log.is_empty() {
                code_frame().show(ui, |ui| {
                    for line in &diag.log {
                        let color = if line.starts_with("ERROR") {
                            c_error()
                        } else {
                            c_muted()
                        };
                        ui.label(
                            RichText::new(line)
                                .color(color)
                                .size(12.0)
                                .font(egui::FontId::monospace(12.0)),
                        );
                    }
                });
                ui.add_space(8.0);
            }

            if let Some(ref data) = diag.result {
                let device_state_str = serde_json::to_string_pretty(&data.device_state)
                    .unwrap_or_else(|_| data.device_state.to_string());
                let pi_info_str = serde_json::to_string_pretty(&data.pi_info)
                    .unwrap_or_else(|_| data.pi_info.to_string());

                // Save button row
                ui.horizontal(|ui| {
                    if ui.add(secondary_btn("Save to file…")).clicked() {
                        let combined = serde_json::json!({
                            "get_device_state": data.device_state,
                            "pi_get_info": data.pi_info,
                        });
                        let json = serde_json::to_string_pretty(&combined)
                            .unwrap_or_else(|_| combined.to_string());
                        diag.save_status = Some(
                            if let Some(dest) = rfd::FileDialog::new()
                                .add_filter("JSON", &["json"])
                                .set_file_name("seestar_diagnostics.json")
                                .save_file()
                            {
                                match std::fs::write(&dest, &json) {
                                    Ok(_) => format!("Saved to {}", dest.display()),
                                    Err(e) => format!("Save failed: {e}"),
                                }
                            } else {
                                return;
                            },
                        );
                    }
                    if let Some(ref status) = diag.save_status {
                        let color = if status.starts_with("Save failed") {
                            c_error()
                        } else {
                            c_success()
                        };
                        ui.label(RichText::new(status).color(color).size(13.0));
                    }
                });
                ui.add_space(6.0);

                card_frame().show(ui, |ui| {
                    section_label(ui, "GET_DEVICE_STATE");
                    ui.add_space(4.0);
                    code_frame().show(ui, |ui| {
                        egui::ScrollArea::vertical()
                            .id_salt("diag_device_state")
                            .max_height(300.0)
                            .show(ui, |ui| {
                                ui.add(
                                    egui::TextEdit::multiline(&mut device_state_str.as_str())
                                        .font(egui::FontId::monospace(12.0))
                                        .text_color(c_text())
                                        .desired_width(f32::INFINITY),
                                );
                            });
                    });
                });

                ui.add_space(6.0);

                card_frame().show(ui, |ui| {
                    section_label(ui, "PI_GET_INFO");
                    ui.add_space(4.0);
                    code_frame().show(ui, |ui| {
                        egui::ScrollArea::vertical()
                            .id_salt("diag_pi_info")
                            .max_height(300.0)
                            .show(ui, |ui| {
                                ui.add(
                                    egui::TextEdit::multiline(&mut pi_info_str.as_str())
                                        .font(egui::FontId::monospace(12.0))
                                        .text_color(c_text())
                                        .desired_width(f32::INFINITY),
                                );
                            });
                    });
                });
            }
        });
}

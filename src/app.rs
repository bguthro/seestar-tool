//! egui application — two tabs: Firmware Update and Extract PEM.

use std::path::PathBuf;
use std::sync::Arc;

use eframe::egui::{self, Color32, Frame, Margin, RichText, Rounding, Stroke};

use crate::apkpure::ApkVersion;

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
    LocalApk, // user picks an APK/XAPK file
    LocalIscope, // user picks a raw iscope file
    Download,    // fetch from APKPure
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
            let log = |s: String| {
                let _ = tx.send(TaskMsg::Log(s));
            };
            // Try full version list first; fall back to latest-only endpoint.
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

    fn start_download(&mut self) {
        let Some((version, download_url)) = self.resolved_version() else {
            return;
        };
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
            let prog = {
                let tx = tx.clone();
                move |d, t| {
                    let _ = tx.send(TaskMsg::Progress(d, t));
                }
            };
            match crate::apkpure::download_version(&version, &download_url, &dest_dir, prog).await {
                Ok(path) => {
                    let _ = tx2.send(TaskMsg::Downloaded(path));
                    let _ = tx2.send(TaskMsg::Done);
                }
                Err(e) => {
                    let _ = tx2.send(TaskMsg::Error(e.to_string()));
                }
            }
        });
    }

    fn start_download_and_install(&mut self) {
        let Some((version, download_url)) = self.resolved_version() else {
            return;
        };
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
                move |d, t| {
                    let _ = tx.send(TaskMsg::Progress(d, t));
                }
            };
            let path =
                match crate::apkpure::download_version(&version, &download_url, &dest_dir, prog)
                    .await
                {
                    Ok(p) => p,
                    Err(e) => {
                        let _ = tx2.send(TaskMsg::Error(e.to_string()));
                        return;
                    }
                };
            let _ = tx2.send(TaskMsg::Downloaded(path.clone()));
            let _ = tx2.send(TaskMsg::Progress(0, 0));

            // Extract + upload (blocking; run in spawn_blocking)
            let tx_log = tx2.clone();
            let tx_up = tx2.clone();
            let tx_ext = tx2.clone();
            let host2 = host.clone();
            let path2 = path.clone();
            let result = tokio::task::spawn_blocking(move || {
                let iscope = crate::firmware::extract_iscope(
                    path2.to_str().unwrap_or_default(),
                    move |s| {
                        let _ = tx_ext.send(TaskMsg::Log(s));
                    },
                )?;
                let log = move |s: String| {
                    let _ = tx_log.send(TaskMsg::Log(s));
                };
                let up = move |d, t| {
                    let _ = tx_up.send(TaskMsg::Progress(d, t));
                };
                crate::firmware::upload_firmware(&host2, &iscope, "iscope", log, up)
            })
            .await;

            match result {
                Ok(Ok(())) => {
                    let _ = tx2.send(TaskMsg::Done);
                }
                Ok(Err(e)) => {
                    let _ = tx2.send(TaskMsg::Error(e.to_string()));
                }
                Err(e) => {
                    let _ = tx2.send(TaskMsg::Error(e.to_string()));
                }
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
            let tx_up = tx.clone();
            let tx_ext = tx.clone();
            let result = tokio::task::spawn_blocking(move || {
                let iscope = crate::firmware::extract_iscope(&apk, move |s| {
                    let _ = tx_ext.send(TaskMsg::Log(s));
                })?;
                let log = move |s: String| {
                    let _ = tx_log.send(TaskMsg::Log(s));
                };
                let up = move |d, t| {
                    let _ = tx_up.send(TaskMsg::Progress(d, t));
                };
                crate::firmware::upload_firmware(&host, &iscope, "iscope", log, up)
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
            let tx_up = tx.clone();
            let result = tokio::task::spawn_blocking(move || {
                let log = move |s: String| {
                    let _ = tx_log.send(TaskMsg::Log(s));
                };
                let up = move |d, t| {
                    let _ = tx_up.send(TaskMsg::Progress(d, t));
                };
                crate::firmware::upload_firmware_file(&host, &path, "iscope", log, up)
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
                Ok(Err(e)) => {
                    let _ = tx.send(TaskMsg::Error(e.to_string()));
                }
                Err(e) => {
                    let _ = tx.send(TaskMsg::Error(e.to_string()));
                }
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
        setup_visuals(&cc.egui_ctx);

        let rt = Arc::new(tokio::runtime::Runtime::new().expect("tokio runtime"));

        Self {
            tab: Tab::default(),
            fw: FirmwareTab::new(rt.clone()),
            pem: PemTab::new(rt),
        }
    }
}

impl eframe::App for SeestarApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.fw.poll();
        self.pem.poll();

        if self.fw.busy || self.pem.busy {
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

                    if tab_btn(ui, "Firmware Update", fw_active).clicked() {
                        self.tab = Tab::Firmware;
                    }
                    if tab_btn(ui, "Extract PEM", pem_active).clicked() {
                        self.tab = Tab::ExtractPem;
                    }
                });
            });

        egui::CentralPanel::default()
            .frame(Frame::none().fill(c_bg()).inner_margin(Margin::same(16.0)))
            .show(ctx, |ui| match self.tab {
                Tab::Firmware => draw_firmware(ui, &mut self.fw),
                Tab::ExtractPem => draw_pem(ui, &mut self.pem),
            });
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
                            ui.label(RichText::new("Version").color(c_muted()).size(13.0));
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
                        ui.label(RichText::new("Direct URL").color(c_muted()).size(13.0));
                        ui.add(
                            egui::TextEdit::singleline(&mut fw.manual_url)
                                .hint_text("Paste a direct XAPK download URL (optional fallback)")
                                .desired_width(f32::INFINITY),
                        );
                    });
                }
            }
        });
    });

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
                        {
                            fw.start_install_apk();
                        }
                    }
                    FirmwareSource::LocalIscope => {
                        let ready = !fw.iscope_path.is_empty() && !fw.busy;
                        if ui
                            .add_enabled(ready, primary_btn("Update Seestar"))
                            .clicked()
                        {
                            fw.start_install_iscope();
                        }
                    }
                    FirmwareSource::Download => {
                        let ready = fw.resolved_version().is_some() && !fw.busy;
                        if ui
                            .add_enabled(ready, primary_btn("Download & Install"))
                            .clicked()
                        {
                            fw.start_download_and_install();
                        }
                        if ui
                            .add_enabled(ready, secondary_btn("Download only"))
                            .clicked()
                        {
                            fw.start_download();
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

fn source_btn(ui: &mut egui::Ui, current: &mut FirmwareSource, variant: FirmwareSource, label: &str)
where
    FirmwareSource: PartialEq,
{
    let active = *current == variant;
    let fill = if active { c_accent_dim() } else { c_surface2() };
    let text_color = if active { Color32::WHITE } else { c_muted() };
    if ui
        .add(
            egui::Button::new(RichText::new(label).color(text_color).size(13.0))
                .fill(fill)
                .rounding(Rounding::same(5.0))
                .min_size(egui::vec2(0.0, 26.0)),
        )
        .clicked()
    {
        *current = variant;
    }
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
                        if ui.add(secondary_btn("Save to file")).clicked() {
                            if let Some(dest) = rfd::FileDialog::new()
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

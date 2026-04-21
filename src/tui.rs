//! Ratatui-based terminal UI frontend.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossterm::ExecutableCommand;
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Clear, Gauge, List, ListItem, ListState, Paragraph, Tabs, Wrap,
};

use crate::apkpure::ApkVersion;
use crate::task::{self, TaskMsg};

const TICK_MS: u64 = 100;

// ── tabs ──────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
enum Tab {
    Firmware,
    ExtractPem,
    Diagnostics,
}

// ── firmware source ───────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
enum FirmwareSource {
    LocalApk,
    LocalIscope,
    Download,
}

// ── focus ────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
enum Focus {
    MainTabs,
    SourceTabs,
    FilePath,
    Host,
    ModelTabs,
    VersionList,
    ActionButton,
    DownloadButton,
    PemFilePath,
    PemButton,
    PemSaveButton,
    DiagHost,
    DiagApkPath,
    DiagPemFilePath,
    DiagButton,
    DiagSaveButton,
    Logs,
}

// ── confirm dialog ────────────────────────────────────────────────────────────

#[derive(Clone, PartialEq)]
enum ConfirmAction {
    InstallApk(String),
    InstallIscope(String),
    DownloadAndInstall {
        version: String,
        url: String,
        dest: PathBuf,
        host: String,
    },
}

#[derive(Clone, Copy, PartialEq)]
enum ConfirmFocus {
    Yes,
    No,
}

struct ConfirmDialog {
    action: ConfirmAction,
    focus: ConfirmFocus,
}

impl ConfirmDialog {
    fn new(action: ConfirmAction) -> Self {
        Self {
            action,
            focus: ConfirmFocus::No,
        }
    }

    fn body(&self) -> &'static str {
        match &self.action {
            ConfirmAction::InstallApk(_) | ConfirmAction::InstallIscope(_) => {
                "This will upload firmware to your Seestar.\n\
                 The scope will reboot during installation.\n\
                 Ensure it is fully charged and network is stable."
            }
            ConfirmAction::DownloadAndInstall { .. } => {
                "This will download and upload firmware to your Seestar.\n\
                 The scope will reboot during installation.\n\
                 Ensure it is fully charged and network is stable."
            }
        }
    }
}

// ── file browser ──────────────────────────────────────────────────────────────

/// What the file browser was opened for.
#[derive(Clone, Copy, PartialEq)]
enum BrowserTarget {
    Apk,
    Iscope,
    Pem,
    DiagApk,
    DiagPemFile,
    /// Directory to save the diagnostics JSON into.
    SaveDiagDir,
    /// Directory to save the PEM file into.
    SavePemDir,
    /// Directory to download the XAPK into; `install` controls whether to also flash.
    DownloadDir {
        install: bool,
    },
}

#[derive(Clone, Copy, PartialEq)]
enum BrowserMode {
    FileSelect,
    DirSelect,
}

struct FileBrowser {
    cwd: PathBuf,
    /// `(display_name, full_path, is_dir)`
    entries: Vec<(String, PathBuf, bool)>,
    state: ListState,
    target: BrowserTarget,
    /// file-extension filter (only used in FileSelect mode; empty = all files)
    filter: &'static [&'static str],
    mode: BrowserMode,
}

impl FileBrowser {
    fn open_file(start: &str, target: BrowserTarget, filter: &'static [&'static str]) -> Self {
        Self::open_impl(start, target, filter, BrowserMode::FileSelect)
    }

    fn open_dir(start: PathBuf, target: BrowserTarget) -> Self {
        let start_str = start.to_string_lossy().into_owned();
        Self::open_impl(&start_str, target, &[], BrowserMode::DirSelect)
    }

    fn open_impl(
        start: &str,
        target: BrowserTarget,
        filter: &'static [&'static str],
        mode: BrowserMode,
    ) -> Self {
        let cwd = {
            let p = PathBuf::from(start);
            if p.is_dir() {
                p
            } else if let Some(parent) = p.parent() {
                if parent.as_os_str().is_empty() {
                    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
                } else {
                    parent.to_path_buf()
                }
            } else {
                std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
            }
        };
        let mut browser = Self {
            cwd,
            entries: vec![],
            state: ListState::default(),
            target,
            filter,
            mode,
        };
        browser.reload();
        browser
    }

    fn reload(&mut self) {
        self.entries.clear();

        // In dir-select mode, first entry selects the current directory
        if self.mode == BrowserMode::DirSelect {
            self.entries.push((
                "[ Use this directory ]".to_string(),
                self.cwd.clone(),
                false,
            ));
        }

        if self.cwd.parent().is_some()
            && let Some(parent) = self.cwd.parent()
        {
            self.entries
                .push(("..".to_string(), parent.to_path_buf(), true));
        }

        let mut dirs: Vec<(String, PathBuf)> = vec![];
        let mut files: Vec<(String, PathBuf)> = vec![];

        if let Ok(rd) = std::fs::read_dir(&self.cwd) {
            for entry in rd.flatten() {
                let path = entry.path();
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with('.') {
                    continue;
                }
                if path.is_dir() {
                    dirs.push((name, path));
                } else if self.mode == BrowserMode::FileSelect
                    && (self.filter.is_empty()
                        || path
                            .extension()
                            .and_then(|e| e.to_str())
                            .map(|e| self.filter.contains(&e))
                            .unwrap_or(false))
                {
                    files.push((name, path));
                }
            }
        }

        dirs.sort_by(|a, b| a.0.cmp(&b.0));
        files.sort_by(|a, b| a.0.cmp(&b.0));

        for (name, path) in dirs {
            self.entries.push((format!("{}/", name), path, true));
        }
        for (name, path) in files {
            self.entries.push((name, path, false));
        }

        if self.entries.is_empty() {
            self.state.select(None);
        } else {
            let cur = self
                .state
                .selected()
                .unwrap_or(0)
                .min(self.entries.len() - 1);
            self.state.select(Some(cur));
        }
    }

    /// Returns `Some(path)` when a file or the "use this dir" entry is selected.
    fn enter(&mut self) -> Option<PathBuf> {
        let idx = self.state.selected()?;
        if self.entries[idx].2 {
            // directory — navigate into it
            let path = self.entries[idx].1.clone();
            self.cwd = path;
            self.state.select(Some(0));
            self.reload();
            None
        } else {
            // file or "use this directory" in DirSelect mode
            Some(self.entries[idx].1.clone())
        }
    }

    fn go_up(&mut self) {
        if let Some(parent) = self.cwd.parent() {
            self.cwd = parent.to_path_buf();
            self.state.select(Some(0));
            self.reload();
        }
    }

    fn move_up(&mut self) {
        let i = self.state.selected().unwrap_or(0);
        self.state.select(Some(i.saturating_sub(1)));
    }

    fn move_down(&mut self) {
        let i = self.state.selected().unwrap_or(0);
        let max = self.entries.len().saturating_sub(1);
        self.state.select(Some((i + 1).min(max)));
    }
}

// ── app state ─────────────────────────────────────────────────────────────────

struct App {
    tab: Tab,
    fw_source: FirmwareSource,
    fw_model: crate::firmware::ScopeModel,
    focus: Focus,

    // firmware tab
    apk_path: String,
    iscope_path: String,
    host: String,
    versions: Vec<ApkVersion>,
    version_state: ListState,
    fetching_versions: bool,

    // pem tab
    pem_path: String,
    pem_keys: Vec<String>,

    // shared
    logs: Vec<(Style, String)>,
    progress: Option<(u64, u64)>,
    busy: bool,

    // channel
    rx: task::Receiver,
    rt: Arc<tokio::runtime::Runtime>,

    // background PEM extraction for auto-detect
    pem_key: Option<Vec<u8>>,
    pem_rx: Option<task::Receiver>,
    last_pem_path: String,

    // text editing cursor positions
    apk_cursor: usize,
    iscope_cursor: usize,
    host_cursor: usize,
    pem_cursor: usize,

    // file browser overlay
    file_browser: Option<FileBrowser>,

    // confirmation dialog
    confirm: Option<ConfirmDialog>,

    // auto-detection: action waiting for model detection result
    detect_pending: Option<ConfirmAction>,
    // device info resolved by auto-detection, kept until confirm is executed
    detected_model: Option<crate::firmware::DeviceInfo>,

    // diagnostics tab
    diag_host: String,
    diag_host_cursor: usize,
    diag_apk_path: String,
    diag_apk_cursor: usize,
    diag_pem_file_path: String,
    diag_pem_file_cursor: usize,
    diag_pem_key: Option<Vec<u8>>,
    diag_pem_rx: Option<task::Receiver>,
    diag_last_pem_path: String,
    diag_last_pem_file_path: String,
    diag_result: Option<crate::firmware::DiagnosticsData>,
    diag_rx: Option<task::Receiver>,
    diag_busy: bool,

    quit: bool,
}

impl App {
    fn new(rt: Arc<tokio::runtime::Runtime>) -> Self {
        let (tx, rx) = task::channel();
        let mut app = Self {
            tab: Tab::Firmware,
            fw_source: FirmwareSource::LocalApk,
            fw_model: crate::firmware::ScopeModel::default(),
            focus: Focus::FilePath,
            apk_path: String::new(),
            iscope_path: String::new(),
            host: "seestar.local".to_string(),
            versions: vec![],
            version_state: ListState::default(),
            fetching_versions: false,
            pem_path: String::new(),
            pem_keys: vec![],
            logs: vec![],
            progress: None,
            busy: false,
            rx,
            rt,
            apk_cursor: 0,
            iscope_cursor: 0,
            host_cursor: "seestar.local".len(),
            pem_cursor: 0,
            file_browser: None,
            confirm: None,
            quit: false,
            pem_key: None,
            pem_rx: None,
            last_pem_path: String::new(),
            detect_pending: None,
            detected_model: None,
            diag_host: "seestar.local".to_string(),
            diag_host_cursor: "seestar.local".len(),
            diag_apk_path: String::new(),
            diag_apk_cursor: 0,
            diag_pem_file_path: String::new(),
            diag_pem_file_cursor: 0,
            diag_pem_key: None,
            diag_pem_rx: None,
            diag_last_pem_path: String::new(),
            diag_last_pem_file_path: String::new(),
            diag_result: None,
            diag_rx: None,
            diag_busy: false,
        };
        app.start_fetch_versions(tx);
        app
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
        let (tx, rx) = task::channel();
        self.pem_rx = Some(rx);
        crate::runner::extract_pem(&self.rt, tx, apk_path.to_string());
    }

    fn start_fetch_versions(&mut self, tx: task::Sender) {
        self.fetching_versions = true;
        self.push_log(
            Style::default().fg(Color::DarkGray),
            "Fetching version list…".to_string(),
        );
        crate::runner::fetch_versions(&self.rt, tx);
    }

    fn push_log(&mut self, style: Style, msg: String) {
        for line in msg.lines() {
            self.logs.push((style, line.to_string()));
        }
    }

    fn drain_messages(&mut self) {
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                TaskMsg::Log(s) => {
                    self.push_log(Style::default().fg(Color::White), s);
                }
                TaskMsg::Progress(d, t) => {
                    self.progress = Some((d, t));
                }
                TaskMsg::VersionList(v) => {
                    self.fetching_versions = false;
                    self.versions = v;
                    if !self.versions.is_empty() {
                        self.version_state.select(Some(0));
                    }
                    self.push_log(
                        Style::default().fg(Color::Green),
                        format!("Loaded {} versions.", self.versions.len()),
                    );
                }
                TaskMsg::Downloaded(p) => {
                    self.push_log(
                        Style::default().fg(Color::Cyan),
                        format!("Downloaded: {}", p.display()),
                    );
                    // Extract PEM from the downloaded APK for auto-detection
                    let path_str = p.to_string_lossy().to_string();
                    self.maybe_refresh_pem(&path_str);
                }
                TaskMsg::PemKeys(keys) => {
                    self.pem_keys = keys;
                    self.push_log(
                        Style::default().fg(Color::Green),
                        format!("Extracted {} PEM key(s).", self.pem_keys.len()),
                    );
                }
                TaskMsg::Done => {
                    self.busy = false;
                    self.progress = None;
                    self.push_log(
                        Style::default()
                            .fg(Color::Green)
                            .add_modifier(Modifier::BOLD),
                        "Done.".to_string(),
                    );
                }
                TaskMsg::ModelDetected(info) => {
                    self.busy = false;
                    self.progress = None;
                    self.push_log(
                        Style::default().fg(Color::Cyan),
                        format!(
                            "Detected: {} — {}",
                            info.model.display_name(),
                            info.model.bitness_description()
                        ),
                    );
                    self.detected_model = Some(info);
                    if let Some(action) = self.detect_pending.take() {
                        self.confirm = Some(ConfirmDialog::new(action));
                    }
                }
                TaskMsg::DiagnosticsResult(_) => {}
                TaskMsg::Error(e) => {
                    self.busy = false;
                    self.progress = None;
                    self.detect_pending = None;
                    self.detected_model = None;
                    self.push_log(
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                        format!("Error: {e}"),
                    );
                }
            }
        }

        // Drain background PEM extraction channel (firmware tab)
        if let Some(pem_rx) = &self.pem_rx {
            while let Ok(msg) = pem_rx.try_recv() {
                if let TaskMsg::PemKeys(keys) = msg
                    && let Some(key) = keys.into_iter().next()
                {
                    self.pem_key = Some(key.into_bytes());
                }
            }
        }

        // Drain diagnostics PEM extraction channel
        if let Some(rx) = &self.diag_pem_rx {
            while let Ok(msg) = rx.try_recv() {
                if let TaskMsg::PemKeys(keys) = msg
                    && let Some(key) = keys.into_iter().next()
                {
                    self.diag_pem_key = Some(key.into_bytes());
                }
            }
        }

        // Drain diagnostics result channel
        let diag_msgs: Vec<TaskMsg> = self
            .diag_rx
            .as_ref()
            .map(|rx| rx.try_iter().collect())
            .unwrap_or_default();
        for msg in diag_msgs {
            match msg {
                TaskMsg::Log(s) => {
                    self.push_log(Style::default().fg(Color::DarkGray), s);
                }
                TaskMsg::DiagnosticsResult(data) => {
                    self.diag_result = Some(data);
                    self.push_log(
                        Style::default()
                            .fg(Color::Green)
                            .add_modifier(Modifier::BOLD),
                        "Diagnostics complete.".to_string(),
                    );
                }
                TaskMsg::Done => {
                    self.diag_busy = false;
                }
                TaskMsg::Error(e) => {
                    self.diag_busy = false;
                    self.push_log(
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                        format!("Diagnostics error: {e}"),
                    );
                }
                _ => {}
            }
        }
    }

    /// Returns `true` if detection was started (caller should wait for `TaskMsg::ModelDetected`).
    /// Returns `false` if the model is concrete — caller should proceed with confirm dialog directly.
    fn maybe_start_detection(&mut self, action: ConfirmAction) -> bool {
        if !self.fw_model.is_auto() {
            return false;
        }
        // Try to get the pem_key, extracting from APK if needed.
        let key = if let Some(k) = self.pem_key.clone() {
            k
        } else {
            let apk_path = self.apk_path.trim();
            if apk_path.is_empty() {
                self.push_log(
                    Style::default().fg(Color::Red),
                    "Auto-detect requires an APK to extract the key from. \
                     Load an APK file or select a model manually."
                        .to_string(),
                );
                return true;
            }
            // Extract PEM from APK synchronously (blocking)
            match crate::pem::extract_pem_from_apk(apk_path, |_| {}) {
                Ok(result) => {
                    if let Some(k) = result.keys.into_iter().next() {
                        k.into_bytes()
                    } else {
                        self.push_log(
                            Style::default().fg(Color::Red),
                            "No PEM key found in APK. Select a model manually.".to_string(),
                        );
                        return true;
                    }
                }
                Err(e) => {
                    self.push_log(
                        Style::default().fg(Color::Red),
                        format!("Failed to extract PEM from APK: {}", e),
                    );
                    return true;
                }
            }
        };
        let (tx, rx) = task::channel();
        self.rx = rx;
        self.busy = true;
        self.progress = Some((0, 0)); // show indeterminate gauge while detecting
        self.detect_pending = Some(action);
        crate::runner::detect_model(&self.rt, tx, self.host.trim().to_string(), key);
        true
    }

    fn run_action(&mut self) {
        if self.busy {
            return;
        }
        match self.fw_source {
            FirmwareSource::LocalApk => {
                let path = self.apk_path.trim().to_string();
                if path.is_empty() {
                    self.push_log(
                        Style::default().fg(Color::Red),
                        "No APK path entered.".to_string(),
                    );
                    return;
                }
                let action = ConfirmAction::InstallApk(path);
                if !self.maybe_start_detection(action.clone()) {
                    self.confirm = Some(ConfirmDialog::new(action));
                }
            }
            FirmwareSource::LocalIscope => {
                let path = self.iscope_path.trim().to_string();
                if path.is_empty() {
                    self.push_log(
                        Style::default().fg(Color::Red),
                        "No iscope path entered.".to_string(),
                    );
                    return;
                }
                let action = ConfirmAction::InstallIscope(path);
                if !self.maybe_start_detection(action.clone()) {
                    self.confirm = Some(ConfirmDialog::new(action));
                }
            }
            FirmwareSource::Download => {
                // First pick a directory, then confirm
                if self.version_state.selected().is_none() {
                    self.push_log(
                        Style::default().fg(Color::Red),
                        "No version selected.".to_string(),
                    );
                    return;
                }
                let start = dirs_next::download_dir().unwrap_or_else(|| PathBuf::from("."));
                self.file_browser = Some(FileBrowser::open_dir(
                    start,
                    BrowserTarget::DownloadDir { install: true },
                ));
            }
        }
    }

    fn run_download_only(&mut self) {
        if self.busy {
            return;
        }
        if self.version_state.selected().is_none() {
            self.push_log(
                Style::default().fg(Color::Red),
                "No version selected.".to_string(),
            );
            return;
        }
        // Download-only doesn't need a confirm — just pick the directory
        let start = dirs_next::download_dir().unwrap_or_else(|| PathBuf::from("."));
        self.file_browser = Some(FileBrowser::open_dir(
            start,
            BrowserTarget::DownloadDir { install: false },
        ));
    }

    fn run_pem(&mut self) {
        if self.busy {
            return;
        }
        let path = self.pem_path.trim().to_string();
        if path.is_empty() {
            self.push_log(
                Style::default().fg(Color::Red),
                "No APK path entered.".to_string(),
            );
            return;
        }
        let (tx, rx) = task::channel();
        self.rx = rx;
        self.busy = true;
        crate::runner::extract_pem(&self.rt, tx, path);
    }

    fn save_pem(&mut self) {
        if self.pem_keys.is_empty() {
            self.push_log(
                Style::default().fg(Color::Red),
                "No PEM keys to save — extract first.".to_string(),
            );
            return;
        }
        let start = dirs_next::download_dir().unwrap_or_else(|| PathBuf::from("."));
        self.file_browser = Some(FileBrowser::open_dir(start, BrowserTarget::SavePemDir));
    }

    fn save_diagnostics(&mut self) {
        if self.diag_result.is_none() {
            self.push_log(
                Style::default().fg(Color::Red),
                "No diagnostics data — run diagnostics first.".to_string(),
            );
            return;
        }
        let start = dirs_next::download_dir().unwrap_or_else(|| PathBuf::from("."));
        self.file_browser = Some(FileBrowser::open_dir(start, BrowserTarget::SaveDiagDir));
    }

    fn do_save_diag_to(&mut self, dir: PathBuf) {
        let Some(ref data) = self.diag_result else {
            return;
        };
        let combined = serde_json::json!({
            "get_device_state": data.device_state,
            "pi_get_info": data.pi_info,
        });
        let json = serde_json::to_string_pretty(&combined).unwrap_or_else(|_| combined.to_string());
        let dest = dir.join("seestar_diagnostics.json");
        match std::fs::write(&dest, &json) {
            Ok(()) => self.push_log(
                Style::default().fg(Color::Green),
                format!("Saved diagnostics to {}", dest.display()),
            ),
            Err(e) => self.push_log(
                Style::default().fg(Color::Red),
                format!("Failed to save: {e}"),
            ),
        }
    }

    fn do_save_pem_to(&mut self, dir: PathBuf) {
        let dest = dir.join("seestar_keys.pem");
        let content = self.pem_keys.join("\n");
        match std::fs::write(&dest, content) {
            Ok(()) => self.push_log(
                Style::default().fg(Color::Green),
                format!("Saved PEM keys to {}", dest.display()),
            ),
            Err(e) => self.push_log(
                Style::default().fg(Color::Red),
                format!("Failed to save: {e}"),
            ),
        }
    }

    fn do_download(&mut self, dest: PathBuf, install: bool) {
        let idx = match self.version_state.selected() {
            Some(i) => i,
            None => return,
        };
        let ver = &self.versions[idx];
        if install && !self.host.trim().is_empty() {
            // Show confirmation before installing (or start detection first if Auto)
            let action = ConfirmAction::DownloadAndInstall {
                version: ver.version.clone(),
                url: ver.download_url.clone(),
                dest,
                host: self.host.trim().to_string(),
            };
            if !self.maybe_start_detection(action.clone()) {
                self.confirm = Some(ConfirmDialog::new(action));
            }
        } else {
            // Download-only: start immediately
            let (tx, rx) = task::channel();
            self.rx = rx;
            self.busy = true;
            self.progress = Some((0, 0));
            crate::runner::download_only(
                &self.rt,
                tx,
                ver.version.clone(),
                ver.download_url.clone(),
                dest,
            );
        }
    }

    fn execute_confirmed(&mut self) {
        let Some(dlg) = self.confirm.take() else {
            return;
        };
        // Use detected model if auto-detection ran, otherwise use the selected model.
        let resolved_model = self
            .detected_model
            .take()
            .map(|d| d.model)
            .unwrap_or(self.fw_model);
        match dlg.action {
            ConfirmAction::InstallApk(path) => {
                let (tx, rx) = task::channel();
                self.rx = rx;
                self.busy = true;
                self.progress = Some((0, 0));
                crate::runner::install_apk(
                    &self.rt,
                    tx,
                    path,
                    crate::runner::InstallTarget {
                        host: self.host.trim().to_string(),
                        model: resolved_model,
                        pem_key: self.pem_key.clone(),
                    },
                );
            }
            ConfirmAction::InstallIscope(path) => {
                let (tx, rx) = task::channel();
                self.rx = rx;
                self.busy = true;
                self.progress = Some((0, 0));
                crate::runner::install_iscope(
                    &self.rt,
                    tx,
                    path,
                    crate::runner::InstallTarget {
                        host: self.host.trim().to_string(),
                        model: resolved_model,
                        pem_key: self.pem_key.clone(),
                    },
                );
            }
            ConfirmAction::DownloadAndInstall {
                version,
                url,
                dest,
                host,
            } => {
                let (tx, rx) = task::channel();
                self.rx = rx;
                self.busy = true;
                self.progress = Some((0, 0));
                crate::runner::download_and_install(
                    &self.rt,
                    tx,
                    version,
                    url,
                    dest,
                    crate::runner::InstallTarget {
                        host,
                        model: resolved_model,
                        pem_key: self.pem_key.clone(),
                    },
                );
            }
        }
    }

    // ── file browser helpers ──────────────────────────────────────────────────

    fn open_browser_for_focus(&mut self) {
        let (target, start, filter): (BrowserTarget, &str, &'static [&'static str]) = match self
            .focus
        {
            Focus::FilePath => match self.fw_source {
                FirmwareSource::LocalApk => (BrowserTarget::Apk, &self.apk_path, &["apk", "xapk"]),
                FirmwareSource::LocalIscope => {
                    (BrowserTarget::Iscope, &self.iscope_path, &["iscope"])
                }
                FirmwareSource::Download => return,
            },
            Focus::PemFilePath => (BrowserTarget::Pem, &self.pem_path, &["apk", "xapk"]),
            Focus::DiagApkPath => (
                BrowserTarget::DiagApk,
                &self.diag_apk_path,
                &["apk", "xapk"],
            ),
            Focus::DiagPemFilePath => (
                BrowserTarget::DiagPemFile,
                &self.diag_pem_file_path,
                &["pem"],
            ),
            _ => return,
        };
        self.file_browser = Some(FileBrowser::open_file(start, target, filter));
    }

    fn apply_browser_selection(&mut self, path: PathBuf) {
        let target = self.file_browser.as_ref().map(|b| b.target);
        self.file_browser = None;
        match target {
            Some(BrowserTarget::Apk) => {
                let s = path.to_string_lossy().to_string();
                self.apk_cursor = s.len();
                self.apk_path = s.clone();
                self.maybe_refresh_pem(&s);
            }
            Some(BrowserTarget::Iscope) => {
                let s = path.to_string_lossy().to_string();
                self.iscope_cursor = s.len();
                self.iscope_path = s;
            }
            Some(BrowserTarget::Pem) => {
                let s = path.to_string_lossy().to_string();
                self.pem_cursor = s.len();
                self.pem_path = s;
            }
            Some(BrowserTarget::DiagApk) => {
                let s = path.to_string_lossy().to_string();
                self.diag_apk_cursor = s.len();
                self.diag_apk_path = s;
                self.maybe_refresh_diag_pem();
            }
            Some(BrowserTarget::DiagPemFile) => {
                let s = path.to_string_lossy().to_string();
                self.diag_pem_file_cursor = s.len();
                self.diag_pem_file_path = s;
                self.maybe_refresh_diag_pem_file();
            }
            Some(BrowserTarget::SaveDiagDir) => {
                self.do_save_diag_to(path);
            }
            Some(BrowserTarget::SavePemDir) => {
                self.do_save_pem_to(path);
            }
            Some(BrowserTarget::DownloadDir { install }) => {
                self.do_download(path, install);
            }
            None => {}
        }
    }

    // ── key handling ──────────────────────────────────────────────────────────

    fn handle_key(&mut self, code: KeyCode, modifiers: KeyModifiers) {
        match code {
            KeyCode::Char('q') if modifiers.contains(KeyModifiers::CONTROL) => {
                self.quit = true;
                return;
            }
            KeyCode::Char('c') if modifiers.contains(KeyModifiers::CONTROL) => {
                self.quit = true;
                return;
            }
            _ => {}
        }

        // Confirm dialog consumes all keys when open
        if self.confirm.is_some() {
            self.handle_key_confirm(code);
            return;
        }

        // File browser consumes all keys when open
        if self.file_browser.is_some() {
            self.handle_key_browser(code);
            return;
        }

        if self.focus == Focus::MainTabs {
            self.handle_key_main_tabs(code);
            return;
        }

        match self.tab {
            Tab::Firmware => self.handle_key_firmware(code, modifiers),
            Tab::ExtractPem => self.handle_key_pem(code, modifiers),
            Tab::Diagnostics => self.handle_key_diagnostics(code),
        }
    }

    fn handle_key_confirm(&mut self, code: KeyCode) {
        match code {
            KeyCode::Esc => {
                self.confirm = None;
                self.detected_model = None;
            }
            KeyCode::Left | KeyCode::Right | KeyCode::Tab | KeyCode::BackTab => {
                if let Some(dlg) = self.confirm.as_mut() {
                    dlg.focus = match dlg.focus {
                        ConfirmFocus::Yes => ConfirmFocus::No,
                        ConfirmFocus::No => ConfirmFocus::Yes,
                    };
                }
            }
            KeyCode::Enter | KeyCode::Char(' ') => {
                if let Some(dlg) = self.confirm.as_ref() {
                    match dlg.focus {
                        ConfirmFocus::Yes => self.execute_confirmed(),
                        ConfirmFocus::No => {
                            self.confirm = None;
                            self.detected_model = None;
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn handle_key_browser(&mut self, code: KeyCode) {
        match code {
            KeyCode::Esc => {
                self.file_browser = None;
            }
            KeyCode::Up => {
                if let Some(b) = self.file_browser.as_mut() {
                    b.move_up();
                }
            }
            KeyCode::Down => {
                if let Some(b) = self.file_browser.as_mut() {
                    b.move_down();
                }
            }
            KeyCode::Backspace => {
                if let Some(b) = self.file_browser.as_mut() {
                    b.go_up();
                }
            }
            KeyCode::Enter => {
                if let Some(b) = self.file_browser.as_mut()
                    && let Some(selected) = b.enter()
                {
                    // file selected — close browser and apply
                    self.apply_browser_selection(selected);
                }
                // directory was entered; browser stays open
            }
            _ => {}
        }
    }

    fn handle_key_main_tabs(&mut self, code: KeyCode) {
        match code {
            KeyCode::Left => {
                self.tab = match self.tab {
                    Tab::Firmware => Tab::Firmware,
                    Tab::ExtractPem => Tab::Firmware,
                    Tab::Diagnostics => Tab::ExtractPem,
                };
            }
            KeyCode::Right => {
                self.tab = match self.tab {
                    Tab::Firmware => Tab::ExtractPem,
                    Tab::ExtractPem => Tab::Diagnostics,
                    Tab::Diagnostics => Tab::Diagnostics,
                };
            }
            KeyCode::Tab => {
                self.focus = match self.tab {
                    Tab::Firmware => Focus::SourceTabs,
                    Tab::ExtractPem => Focus::PemFilePath,
                    Tab::Diagnostics => Focus::DiagHost,
                };
            }
            KeyCode::BackTab => {
                self.focus = match self.tab {
                    Tab::Firmware => Focus::Logs,
                    Tab::ExtractPem => Focus::Logs,
                    Tab::Diagnostics => Focus::Logs,
                };
            }
            _ => {}
        }
    }

    fn handle_key_firmware(&mut self, code: KeyCode, _mods: KeyModifiers) {
        match self.focus {
            Focus::SourceTabs => match code {
                KeyCode::Left => {
                    self.fw_source = match self.fw_source {
                        FirmwareSource::Download => FirmwareSource::LocalIscope,
                        FirmwareSource::LocalIscope => FirmwareSource::LocalApk,
                        FirmwareSource::LocalApk => FirmwareSource::LocalApk,
                    };
                }
                KeyCode::Right => {
                    self.fw_source = match self.fw_source {
                        FirmwareSource::LocalApk => FirmwareSource::LocalIscope,
                        FirmwareSource::LocalIscope => FirmwareSource::Download,
                        FirmwareSource::Download => FirmwareSource::Download,
                    };
                }
                KeyCode::Tab => self.focus = Focus::FilePath,
                _ => {}
            },
            Focus::FilePath => {
                match code {
                    KeyCode::Enter => {
                        self.open_browser_for_focus();
                        return;
                    }
                    KeyCode::Tab => {
                        if self.fw_source == FirmwareSource::Download {
                            self.focus = Focus::VersionList;
                        } else {
                            self.focus = Focus::Host;
                        }
                        return;
                    }
                    _ => {}
                }
                let (s, cur) = self.active_path_mut();
                match code {
                    KeyCode::Char(c) => {
                        s.insert(*cur, c);
                        *cur += 1;
                    }
                    KeyCode::Backspace if *cur > 0 => {
                        *cur -= 1;
                        s.remove(*cur);
                    }
                    KeyCode::Left => *cur = cur.saturating_sub(1),
                    KeyCode::Right => {
                        let len = s.len();
                        if *cur < len {
                            *cur += 1;
                        }
                    }
                    _ => {}
                }
            }
            Focus::VersionList => match code {
                KeyCode::Up => {
                    let i = self.version_state.selected().unwrap_or(0);
                    self.version_state.select(Some(i.saturating_sub(1)));
                }
                KeyCode::Down => {
                    let i = self.version_state.selected().unwrap_or(0);
                    let max = self.versions.len().saturating_sub(1);
                    self.version_state.select(Some((i + 1).min(max)));
                }
                KeyCode::Tab => self.focus = Focus::Host,
                _ => {}
            },
            Focus::Host => match code {
                KeyCode::Char(c) => {
                    self.host.insert(self.host_cursor, c);
                    self.host_cursor += 1;
                }
                KeyCode::Backspace if self.host_cursor > 0 => {
                    self.host_cursor -= 1;
                    self.host.remove(self.host_cursor);
                }
                KeyCode::Left => self.host_cursor = self.host_cursor.saturating_sub(1),
                KeyCode::Right if self.host_cursor < self.host.len() => {
                    self.host_cursor += 1;
                }
                KeyCode::Tab => self.focus = Focus::ModelTabs,
                _ => {}
            },
            Focus::ModelTabs => match code {
                KeyCode::Left | KeyCode::Char('h') => {
                    self.fw_model = match self.fw_model {
                        crate::firmware::ScopeModel::Auto => crate::firmware::ScopeModel::S30Pro,
                        crate::firmware::ScopeModel::S50 => crate::firmware::ScopeModel::Auto,
                        crate::firmware::ScopeModel::S30 => crate::firmware::ScopeModel::S50,
                        crate::firmware::ScopeModel::S30Pro => crate::firmware::ScopeModel::S30,
                    };
                }
                KeyCode::Right | KeyCode::Char('l') => {
                    self.fw_model = match self.fw_model {
                        crate::firmware::ScopeModel::Auto => crate::firmware::ScopeModel::S50,
                        crate::firmware::ScopeModel::S50 => crate::firmware::ScopeModel::S30,
                        crate::firmware::ScopeModel::S30 => crate::firmware::ScopeModel::S30Pro,
                        crate::firmware::ScopeModel::S30Pro => crate::firmware::ScopeModel::Auto,
                    };
                }
                KeyCode::Tab => self.focus = Focus::ActionButton,
                KeyCode::BackTab => self.focus = Focus::Host,
                _ => {}
            },
            Focus::ActionButton => match code {
                KeyCode::Enter | KeyCode::Char(' ') => self.run_action(),
                KeyCode::Tab => {
                    if self.fw_source == FirmwareSource::Download {
                        self.focus = Focus::DownloadButton;
                    } else {
                        self.focus = Focus::Logs;
                    }
                }
                KeyCode::BackTab => self.focus = Focus::ModelTabs,
                _ => {}
            },
            Focus::DownloadButton => match code {
                KeyCode::Enter | KeyCode::Char(' ') => self.run_download_only(),
                KeyCode::Tab => self.focus = Focus::Logs,
                KeyCode::BackTab => self.focus = Focus::ActionButton,
                _ => {}
            },
            Focus::Logs => match code {
                KeyCode::Tab => self.focus = Focus::MainTabs,
                KeyCode::BackTab => {
                    if self.fw_source == FirmwareSource::Download {
                        self.focus = Focus::DownloadButton;
                    } else {
                        self.focus = Focus::ActionButton;
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }

    fn handle_key_pem(&mut self, code: KeyCode, _mods: KeyModifiers) {
        match self.focus {
            Focus::PemFilePath => {
                match code {
                    KeyCode::Enter => {
                        self.open_browser_for_focus();
                        return;
                    }
                    KeyCode::Tab => {
                        self.focus = Focus::PemButton;
                        return;
                    }
                    _ => {}
                }
                match code {
                    KeyCode::Char(c) => {
                        self.pem_path.insert(self.pem_cursor, c);
                        self.pem_cursor += 1;
                    }
                    KeyCode::Backspace if self.pem_cursor > 0 => {
                        self.pem_cursor -= 1;
                        self.pem_path.remove(self.pem_cursor);
                    }
                    KeyCode::Left => self.pem_cursor = self.pem_cursor.saturating_sub(1),
                    KeyCode::Right if self.pem_cursor < self.pem_path.len() => {
                        self.pem_cursor += 1;
                    }
                    _ => {}
                }
            }
            Focus::PemButton => match code {
                KeyCode::Enter | KeyCode::Char(' ') => self.run_pem(),
                KeyCode::Tab => self.focus = Focus::PemSaveButton,
                KeyCode::BackTab => self.focus = Focus::PemFilePath,
                _ => {}
            },
            Focus::PemSaveButton => match code {
                KeyCode::Enter | KeyCode::Char(' ') => self.save_pem(),
                KeyCode::Tab => self.focus = Focus::Logs,
                KeyCode::BackTab => self.focus = Focus::PemButton,
                _ => {}
            },
            Focus::Logs => match code {
                KeyCode::Tab => self.focus = Focus::MainTabs,
                KeyCode::BackTab => self.focus = Focus::PemSaveButton,
                _ => {}
            },
            _ => {}
        }
    }

    fn maybe_refresh_diag_pem(&mut self) {
        let path = self.diag_apk_path.clone();
        if path.is_empty() || path == self.diag_last_pem_path {
            return;
        }
        if !std::path::Path::new(&path).exists() {
            return;
        }
        self.diag_last_pem_path = path.clone();
        self.diag_pem_key = None;
        let (tx, rx) = task::channel();
        self.diag_pem_rx = Some(rx);
        crate::runner::extract_pem(&self.rt, tx, path);
    }

    fn maybe_refresh_diag_pem_file(&mut self) {
        let path = self.diag_pem_file_path.clone();
        if path.is_empty() || path == self.diag_last_pem_file_path {
            return;
        }
        if !std::path::Path::new(&path).exists() {
            return;
        }
        self.diag_last_pem_file_path = path.clone();
        if let Ok(bytes) = std::fs::read(&path) {
            self.diag_pem_key = Some(bytes);
            // Clear APK path so the two sources don't conflict
            self.diag_apk_path.clear();
            self.diag_last_pem_path.clear();
        }
    }

    fn start_diagnostics(&mut self) {
        let Some(pem_key) = self.diag_pem_key.clone() else {
            self.push_log(
                Style::default().fg(Color::Yellow),
                "No PEM key — select an APK/XAPK or a .pem file first.".to_string(),
            );
            return;
        };
        let (tx, rx) = task::channel();
        self.diag_rx = Some(rx);
        self.diag_busy = true;
        self.diag_result = None;
        crate::runner::run_diagnostics(&self.rt, tx, self.diag_host.clone(), pem_key);
    }

    fn handle_key_diagnostics(&mut self, code: KeyCode) {
        match self.focus {
            Focus::DiagHost => match code {
                KeyCode::Tab => self.focus = Focus::DiagApkPath,
                KeyCode::BackTab => self.focus = Focus::MainTabs,
                KeyCode::Char(c) => {
                    self.diag_host.insert(self.diag_host_cursor, c);
                    self.diag_host_cursor += 1;
                }
                KeyCode::Backspace if self.diag_host_cursor > 0 => {
                    self.diag_host_cursor -= 1;
                    self.diag_host.remove(self.diag_host_cursor);
                }
                KeyCode::Left => self.diag_host_cursor = self.diag_host_cursor.saturating_sub(1),
                KeyCode::Right if self.diag_host_cursor < self.diag_host.len() => {
                    self.diag_host_cursor += 1;
                }
                _ => {}
            },
            Focus::DiagApkPath => match code {
                KeyCode::Enter => {
                    self.open_browser_for_focus();
                }
                KeyCode::Tab => self.focus = Focus::DiagPemFilePath,
                KeyCode::BackTab => self.focus = Focus::DiagHost,
                KeyCode::Char(c) => {
                    self.diag_apk_path.insert(self.diag_apk_cursor, c);
                    self.diag_apk_cursor += 1;
                    self.maybe_refresh_diag_pem();
                }
                KeyCode::Backspace if self.diag_apk_cursor > 0 => {
                    self.diag_apk_cursor -= 1;
                    self.diag_apk_path.remove(self.diag_apk_cursor);
                }
                KeyCode::Left => self.diag_apk_cursor = self.diag_apk_cursor.saturating_sub(1),
                KeyCode::Right if self.diag_apk_cursor < self.diag_apk_path.len() => {
                    self.diag_apk_cursor += 1;
                }
                _ => {}
            },
            Focus::DiagPemFilePath => match code {
                KeyCode::Enter => {
                    self.open_browser_for_focus();
                }
                KeyCode::Tab => self.focus = Focus::DiagButton,
                KeyCode::BackTab => self.focus = Focus::DiagApkPath,
                KeyCode::Char(c) => {
                    self.diag_pem_file_path.insert(self.diag_pem_file_cursor, c);
                    self.diag_pem_file_cursor += 1;
                    self.maybe_refresh_diag_pem_file();
                }
                KeyCode::Backspace if self.diag_pem_file_cursor > 0 => {
                    self.diag_pem_file_cursor -= 1;
                    self.diag_pem_file_path.remove(self.diag_pem_file_cursor);
                }
                KeyCode::Left => {
                    self.diag_pem_file_cursor = self.diag_pem_file_cursor.saturating_sub(1);
                }
                KeyCode::Right if self.diag_pem_file_cursor < self.diag_pem_file_path.len() => {
                    self.diag_pem_file_cursor += 1;
                }
                _ => {}
            },
            Focus::DiagButton => match code {
                KeyCode::Enter | KeyCode::Char(' ') => self.start_diagnostics(),
                KeyCode::Tab => self.focus = Focus::DiagSaveButton,
                KeyCode::BackTab => self.focus = Focus::DiagPemFilePath,
                _ => {}
            },
            Focus::DiagSaveButton => match code {
                KeyCode::Enter | KeyCode::Char(' ') => self.save_diagnostics(),
                KeyCode::Tab => self.focus = Focus::Logs,
                KeyCode::BackTab => self.focus = Focus::DiagButton,
                _ => {}
            },
            Focus::Logs => match code {
                KeyCode::Tab => self.focus = Focus::MainTabs,
                KeyCode::BackTab => self.focus = Focus::DiagSaveButton,
                _ => {}
            },
            _ => {}
        }
    }

    fn active_path_mut(&mut self) -> (&mut String, &mut usize) {
        match self.fw_source {
            FirmwareSource::LocalApk => (&mut self.apk_path, &mut self.apk_cursor),
            FirmwareSource::LocalIscope => (&mut self.iscope_path, &mut self.iscope_cursor),
            FirmwareSource::Download => (&mut self.apk_path, &mut self.apk_cursor),
        }
    }
}

// ── drawing ───────────────────────────────────────────────────────────────────

fn draw(f: &mut ratatui::Frame, app: &mut App) {
    let area = f.area();

    let top_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // main tab bar
            Constraint::Min(0),    // content
        ])
        .split(area);

    let tab_titles = ["Firmware Update", "Extract PEM", "Diagnostics"];
    let selected_tab = match app.tab {
        Tab::Firmware => 0,
        Tab::ExtractPem => 1,
        Tab::Diagnostics => 2,
    };
    let main_tabs_focused = app.focus == Focus::MainTabs && app.file_browser.is_none();
    let tabs = Tabs::new(
        tab_titles
            .iter()
            .map(|t| Line::from(*t))
            .collect::<Vec<_>>(),
    )
    .select(selected_tab)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(if main_tabs_focused {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default()
            })
            .title(" Seestar Tool "),
    )
    .highlight_style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    )
    .style(Style::default().fg(Color::DarkGray));

    f.render_widget(tabs, top_chunks[0]);

    match app.tab {
        Tab::Firmware => draw_firmware(f, app, top_chunks[1]),
        Tab::ExtractPem => draw_pem(f, app, top_chunks[1]),
        Tab::Diagnostics => draw_diagnostics(f, app, top_chunks[1]),
    }

    // Confirm dialog (drawn above file browser)
    if app.confirm.is_some() {
        draw_confirm_dialog(f, app, area);
    }

    // File browser overlay (drawn on top)
    if app.file_browser.is_some() {
        draw_file_browser(f, app, area);
    }
}

fn draw_firmware(f: &mut ratatui::Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3), // source picker
            Constraint::Length(3), // file path OR version list header
            Constraint::Min(4),    // version list (only for Download)
            Constraint::Length(3), // host
            Constraint::Length(3), // model picker
            Constraint::Length(3), // action button
            Constraint::Min(6),    // logs
            Constraint::Length(3), // progress
        ])
        .split(area);

    // ── source picker ────────────────────────────────────────────────────────
    let source_titles: Vec<&str> = vec!["Local APK/XAPK", "Local iscope", "Download"];
    let src_idx = match app.fw_source {
        FirmwareSource::LocalApk => 0,
        FirmwareSource::LocalIscope => 1,
        FirmwareSource::Download => 2,
    };
    let src_style = if app.focus == Focus::SourceTabs && app.file_browser.is_none() {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let src_tabs = Tabs::new(
        source_titles
            .iter()
            .map(|t| Line::from(*t))
            .collect::<Vec<_>>(),
    )
    .select(src_idx)
    .block(Block::default().borders(Borders::ALL).title("Source"))
    .highlight_style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )
    .style(src_style);
    f.render_widget(src_tabs, chunks[0]);

    // ── file path / version list ─────────────────────────────────────────────
    let path_focused = app.focus == Focus::FilePath && app.file_browser.is_none();
    match app.fw_source {
        FirmwareSource::LocalApk => {
            draw_text_input(
                f,
                chunks[1],
                "APK / XAPK Path  [Enter = browse]",
                &app.apk_path,
                app.apk_cursor,
                path_focused,
            );
            f.render_widget(Block::default(), chunks[2]);
        }
        FirmwareSource::LocalIscope => {
            draw_text_input(
                f,
                chunks[1],
                "iscope Path  [Enter = browse]",
                &app.iscope_path,
                app.iscope_cursor,
                path_focused,
            );
            f.render_widget(Block::default(), chunks[2]);
        }
        FirmwareSource::Download => {
            let hdr = Paragraph::new("Select a version (↑↓ to move, Tab to continue):")
                .style(Style::default().fg(Color::DarkGray));
            f.render_widget(hdr, chunks[1]);

            let items: Vec<ListItem> = app
                .versions
                .iter()
                .map(|v| {
                    ListItem::new(Line::from(vec![
                        Span::styled(&v.version, Style::default().fg(Color::White)),
                        Span::styled(
                            format!("  ({})", &v.download_url.rsplit('/').next().unwrap_or("")),
                            Style::default().fg(Color::DarkGray),
                        ),
                    ]))
                })
                .collect();

            let list_style = if app.focus == Focus::VersionList && app.file_browser.is_none() {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default()
            };
            let list = List::new(items)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("Versions")
                        .style(list_style),
                )
                .highlight_style(
                    Style::default()
                        .bg(Color::Blue)
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                )
                .highlight_symbol("▶ ");
            f.render_stateful_widget(list, chunks[2], &mut app.version_state);
        }
    }

    // ── host ─────────────────────────────────────────────────────────────────
    draw_text_input(
        f,
        chunks[3],
        "Seestar Host/IP (optional — leave blank to download only)",
        &app.host,
        app.host_cursor,
        app.focus == Focus::Host && app.file_browser.is_none(),
    );

    // ── model picker ─────────────────────────────────────────────────────────
    let model_focused = app.focus == Focus::ModelTabs && app.file_browser.is_none();
    let model_style = if model_focused {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let model_idx = match app.fw_model {
        crate::firmware::ScopeModel::Auto => 0,
        crate::firmware::ScopeModel::S50 => 1,
        crate::firmware::ScopeModel::S30 => 2,
        crate::firmware::ScopeModel::S30Pro => 3,
    };
    let model_tabs = Tabs::new(vec![
        Line::from("Auto-detect"),
        Line::from("S50"),
        Line::from("S30"),
        Line::from("S30 Pro"),
    ])
    .select(model_idx)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Model  [←/→ to switch]")
            .style(model_style),
    )
    .highlight_style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )
    .style(model_style);
    f.render_widget(model_tabs, chunks[4]);

    // ── action button(s) ─────────────────────────────────────────────────────
    if app.fw_source == FirmwareSource::Download && !app.host.trim().is_empty() {
        // Show two buttons side by side: Download & Install | Download Only
        let btn_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(chunks[5]);

        let install_style = if app.focus == Focus::ActionButton && app.file_browser.is_none() {
            Style::default()
                .fg(Color::Black)
                .bg(Color::LightGreen)
                .add_modifier(Modifier::BOLD)
        } else if app.busy {
            Style::default().fg(Color::DarkGray)
        } else {
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD)
        };
        let dl_only_style = if app.focus == Focus::DownloadButton && app.file_browser.is_none() {
            Style::default()
                .fg(Color::Black)
                .bg(Color::LightGreen)
                .add_modifier(Modifier::BOLD)
        } else if app.busy {
            Style::default().fg(Color::DarkGray)
        } else {
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD)
        };
        f.render_widget(
            Paragraph::new("[ Download & Install ]")
                .alignment(Alignment::Center)
                .style(install_style)
                .block(Block::default().borders(Borders::ALL)),
            btn_chunks[0],
        );
        f.render_widget(
            Paragraph::new("[ Download Only ]")
                .alignment(Alignment::Center)
                .style(dl_only_style)
                .block(Block::default().borders(Borders::ALL)),
            btn_chunks[1],
        );
    } else {
        // Single button
        let btn_label = if app.fw_source == FirmwareSource::Download {
            "[ Download Only ]"
        } else {
            "[ Install ]"
        };
        let btn_style = if app.focus == Focus::ActionButton && app.file_browser.is_none() {
            Style::default()
                .fg(Color::Black)
                .bg(Color::LightGreen)
                .add_modifier(Modifier::BOLD)
        } else if app.busy {
            Style::default().fg(Color::DarkGray)
        } else {
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD)
        };
        f.render_widget(
            Paragraph::new(btn_label)
                .alignment(Alignment::Center)
                .style(btn_style)
                .block(Block::default().borders(Borders::ALL)),
            chunks[5],
        );
    }

    draw_logs(f, app, chunks[6]);
    draw_progress(f, app, chunks[7]);
}

fn draw_pem(f: &mut ratatui::Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(5), // legal notice
            Constraint::Length(3), // file path
            Constraint::Length(3), // button row
            Constraint::Min(6),    // logs / key preview
            Constraint::Length(3), // progress
        ])
        .split(area);

    let notice = ratatui::widgets::Paragraph::new(vec![
        ratatui::text::Line::from(ratatui::text::Span::styled(
            "PEM extraction is provided for interoperability under 17 U.S.C. \u{00a7} 1201(f) \
             (DMCA interoperability exemption).",
            Style::default().fg(Color::Gray),
        )),
        ratatui::text::Line::from(ratatui::text::Span::styled(
            "Legality of extraction and use varies by jurisdiction. \
             You are solely responsible for compliance in your region.",
            Style::default().fg(Color::Gray),
        )),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow))
            .title(Span::styled(
                " Interoperability Notice ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )),
    )
    .wrap(Wrap { trim: false });
    f.render_widget(notice, chunks[0]);

    draw_text_input(
        f,
        chunks[1],
        "APK / XAPK Path  [Enter = browse]",
        &app.pem_path,
        app.pem_cursor,
        app.focus == Focus::PemFilePath && app.file_browser.is_none(),
    );

    let btn_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[2]);

    let extract_style = if app.focus == Focus::PemButton && app.file_browser.is_none() {
        Style::default()
            .fg(Color::Black)
            .bg(Color::Yellow)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD)
    };
    let extract_btn = Paragraph::new("[ Extract PEM Key ]")
        .alignment(Alignment::Center)
        .style(extract_style)
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(extract_btn, btn_chunks[0]);

    let save_style = if app.focus == Focus::PemSaveButton && app.file_browser.is_none() {
        Style::default()
            .fg(Color::Black)
            .bg(Color::LightGreen)
            .add_modifier(Modifier::BOLD)
    } else if app.pem_keys.is_empty() {
        Style::default().fg(Color::DarkGray)
    } else {
        Style::default().fg(Color::Cyan)
    };
    let save_btn = Paragraph::new("[ Save PEM ]")
        .alignment(Alignment::Center)
        .style(save_style)
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(save_btn, btn_chunks[1]);

    if !app.pem_keys.is_empty() {
        let key_text: Vec<Line> = app
            .pem_keys
            .iter()
            .flat_map(|k| {
                k.lines().map(|l| {
                    Line::from(Span::styled(
                        l.to_string(),
                        Style::default().fg(Color::Cyan),
                    ))
                })
            })
            .collect();
        let key_par = Paragraph::new(key_text)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Extracted Key(s)"),
            )
            .wrap(Wrap { trim: false });
        f.render_widget(key_par, chunks[3]);
    } else {
        draw_logs(f, app, chunks[3]);
    }

    draw_progress(f, app, chunks[4]);
}

fn draw_confirm_dialog(f: &mut ratatui::Frame, app: &mut App, area: Rect) {
    let Some(dlg) = app.confirm.as_ref() else {
        return;
    };

    // Build full body text, prepending detected device info when available.
    let full_body: String = if let Some(info) = &app.detected_model {
        let fw_line = info
            .firmware_ver_string
            .as_deref()
            .map(|v| format!("\nCurrent firmware:     {}", v))
            .unwrap_or_default();
        let battery_line = match info.battery_capacity {
            Some(pct) => {
                let note = if info.battery_charging {
                    " (charging)"
                } else if pct < 50 {
                    " ⚠ low"
                } else {
                    ""
                };
                format!("\nBattery:              {}%{}", pct, note)
            }
            None => String::new(),
        };
        format!(
            "Auto-detected model:  {} — {}{}{}\n\
             Does this match your scope?\n\
             If unsure, cancel and select the model manually.\n\
             \n\
             {}",
            info.model.display_name(),
            info.model.bitness_description(),
            fw_line,
            battery_line,
            dlg.body()
        )
    } else {
        dlg.body().to_string()
    };

    let popup_width = (area.width * 2 / 3).max(60).min(area.width);
    let body_line_count = full_body.lines().count() as u16;
    let popup_height = body_line_count + 7; // title + body + spacing + buttons + border
    let x = area.x + (area.width.saturating_sub(popup_width)) / 2;
    let y = area.y + (area.height.saturating_sub(popup_height)) / 2;
    let popup_area = Rect::new(x, y, popup_width, popup_height);

    f.render_widget(Clear, popup_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Red))
        .title(Span::styled(
            " ⚠  Confirm Firmware Update ",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(popup_area);
    f.render_widget(block, popup_area);

    let inner_chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Min(1),    // body text
            Constraint::Length(1), // spacer
            Constraint::Length(1), // buttons
        ])
        .split(inner);

    // Body — highlight the detected model line in cyan when present
    let body_lines: Vec<Line> = full_body
        .lines()
        .enumerate()
        .map(|(i, l)| {
            // First line is the detected-model line when auto-detection ran
            let style = if app.detected_model.is_some() && i == 0 {
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            Line::from(Span::styled(l.to_string(), style))
        })
        .collect();
    f.render_widget(Paragraph::new(body_lines), inner_chunks[0]);

    // Buttons row
    let yes_style = if dlg.focus == ConfirmFocus::Yes {
        Style::default()
            .fg(Color::Black)
            .bg(Color::Red)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Red)
    };
    let no_style = if dlg.focus == ConfirmFocus::No {
        Style::default()
            .fg(Color::Black)
            .bg(Color::LightGreen)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::LightGreen)
    };

    let btn_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(inner_chunks[2]);

    f.render_widget(
        Paragraph::new("[ Yes, update ]")
            .alignment(Alignment::Center)
            .style(yes_style),
        btn_chunks[0],
    );
    f.render_widget(
        Paragraph::new("[ Cancel ]")
            .alignment(Alignment::Center)
            .style(no_style),
        btn_chunks[1],
    );
}

fn draw_file_browser(f: &mut ratatui::Frame, app: &mut App, area: Rect) {
    let popup_width = (area.width * 4 / 5).max(40);
    let popup_height = (area.height * 7 / 10).max(10);
    let x = area.x + (area.width.saturating_sub(popup_width)) / 2;
    let y = area.y + (area.height.saturating_sub(popup_height)) / 2;
    let popup_area = Rect::new(x, y, popup_width, popup_height);

    f.render_widget(Clear, popup_area);

    if let Some(browser) = app.file_browser.as_mut() {
        let cwd_str = browser.cwd.to_string_lossy();
        let is_dir_mode = browser.mode == BrowserMode::DirSelect;
        let title = format!(" {} ", cwd_str);

        let action_hint = if is_dir_mode {
            "select dir"
        } else {
            "open/select"
        };
        let footer = Line::from(vec![
            Span::styled(" ↑↓", Style::default().fg(Color::Yellow)),
            Span::raw(" navigate  "),
            Span::styled("Enter", Style::default().fg(Color::Yellow)),
            Span::raw(format!(" {action_hint}  ")),
            Span::styled("⌫", Style::default().fg(Color::Yellow)),
            Span::raw(" parent  "),
            Span::styled("Esc", Style::default().fg(Color::Yellow)),
            Span::raw(" cancel "),
        ]);

        let inner_chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([Constraint::Min(1), Constraint::Length(1)])
            .split(popup_area);

        let items: Vec<ListItem> = browser
            .entries
            .iter()
            .map(|(name, _, is_dir)| {
                // "[ Use this directory ]" is not flagged as is_dir — style it distinctly
                if name.starts_with('[') {
                    ListItem::new(Line::from(Span::styled(
                        name.clone(),
                        Style::default()
                            .fg(Color::LightGreen)
                            .add_modifier(Modifier::BOLD),
                    )))
                } else if *is_dir {
                    ListItem::new(Line::from(Span::styled(
                        name.clone(),
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    )))
                } else {
                    ListItem::new(Line::from(Span::styled(
                        name.clone(),
                        Style::default().fg(Color::White),
                    )))
                }
            })
            .collect();

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow))
            .title(Span::styled(title, Style::default().fg(Color::Yellow)));

        let list = List::new(items)
            .block(block)
            .highlight_style(
                Style::default()
                    .bg(Color::Yellow)
                    .fg(Color::Black)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("▶ ");

        f.render_stateful_widget(list, inner_chunks[0], &mut browser.state);
        f.render_widget(Paragraph::new(footer), inner_chunks[1]);
    }
}

fn draw_text_input(
    f: &mut ratatui::Frame,
    area: Rect,
    label: &str,
    value: &str,
    cursor: usize,
    focused: bool,
) {
    let border_style = if focused {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(label, border_style))
        .border_style(border_style);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let display = if focused && cursor <= value.len() {
        let (before, after) = value.split_at(cursor);
        let mut spans = vec![Span::raw(before.to_string())];
        if after.is_empty() {
            spans.push(Span::styled(
                " ",
                Style::default().bg(Color::Yellow).fg(Color::Black),
            ));
        } else {
            let mut chars = after.chars();
            let cur_char = chars.next().unwrap_or(' ');
            spans.push(Span::styled(
                cur_char.to_string(),
                Style::default().bg(Color::Yellow).fg(Color::Black),
            ));
            spans.push(Span::raw(chars.as_str().to_string()));
        }
        Line::from(spans)
    } else {
        Line::from(Span::styled(
            value.to_string(),
            Style::default().fg(Color::White),
        ))
    };

    f.render_widget(Paragraph::new(display), inner);
}

fn draw_logs(f: &mut ratatui::Frame, app: &App, area: Rect) {
    let focused = app.focus == Focus::Logs && app.file_browser.is_none();
    let border_style = if focused {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .title("Log")
        .border_style(border_style);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let height = inner.height as usize;
    let lines: Vec<Line> = app
        .logs
        .iter()
        .rev()
        .take(height)
        .rev()
        .map(|(style, msg)| Line::from(Span::styled(msg.clone(), *style)))
        .collect();
    f.render_widget(Paragraph::new(lines), inner);
}

fn draw_progress(f: &mut ratatui::Frame, app: &App, area: Rect) {
    match app.progress {
        None => {
            f.render_widget(Block::default(), area);
        }
        Some((done, total)) => {
            if total == 0 {
                // Indeterminate — install phase or waiting for scope to come back
                let label = if app.busy { "Working…" } else { "" };
                let gauge = Gauge::default()
                    .block(Block::default().borders(Borders::ALL))
                    .gauge_style(Style::default().fg(Color::Blue).bg(Color::DarkGray))
                    .ratio(0.5)
                    .label(label);
                f.render_widget(gauge, area);
            } else if total <= 600 {
                // Seconds-based countdown from firmware install estimate
                let ratio = (done as f64 / total as f64).clamp(0.0, 1.0);
                let remaining = total.saturating_sub(done);
                let label = format!("Installing… {remaining}s remaining");
                let gauge = Gauge::default()
                    .block(Block::default().borders(Borders::ALL))
                    .gauge_style(Style::default().fg(Color::Yellow).bg(Color::DarkGray))
                    .ratio(ratio)
                    .label(label);
                f.render_widget(gauge, area);
            } else {
                // Byte-based download progress
                let ratio = (done as f64 / total as f64).clamp(0.0, 1.0);
                let label = format!(
                    "{:.1} / {:.1} MB  ({:.0}%)",
                    done as f64 / 1_048_576.0,
                    total as f64 / 1_048_576.0,
                    ratio * 100.0
                );
                let gauge = Gauge::default()
                    .block(Block::default().borders(Borders::ALL))
                    .gauge_style(Style::default().fg(Color::Green).bg(Color::DarkGray))
                    .ratio(ratio)
                    .label(label);
                f.render_widget(gauge, area);
            }
        }
    }
}

// ── entry point ───────────────────────────────────────────────────────────────

pub fn run(rt: Arc<tokio::runtime::Runtime>) -> anyhow::Result<()> {
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    stdout.execute(EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(rt);
    let tick = Duration::from_millis(TICK_MS);
    let mut last_tick = Instant::now();

    loop {
        terminal.draw(|f| draw(f, &mut app))?;

        let timeout = tick.saturating_sub(last_tick.elapsed());
        if event::poll(timeout)?
            && let Event::Key(key) = event::read()?
        {
            // Global tab switch with F1/F2 (only when browser is closed)
            if app.file_browser.is_none() {
                match key.code {
                    KeyCode::F(1) => {
                        app.tab = Tab::Firmware;
                        app.focus = Focus::FilePath;
                        continue;
                    }
                    KeyCode::F(2) => {
                        app.tab = Tab::ExtractPem;
                        app.focus = Focus::PemFilePath;
                        continue;
                    }
                    _ => {}
                }
            }
            app.handle_key(key.code, key.modifiers);
        }

        if last_tick.elapsed() >= tick {
            app.drain_messages();
            last_tick = Instant::now();
        }

        if app.quit {
            break;
        }
    }

    disable_raw_mode()?;
    terminal.backend_mut().execute(LeaveAlternateScreen)?;
    Ok(())
}

// ── dirs_next shim ────────────────────────────────────────────────────────────

mod dirs_next {
    pub fn download_dir() -> Option<std::path::PathBuf> {
        dirs::download_dir()
    }
}

fn draw_diagnostics(f: &mut ratatui::Frame, app: &App, area: Rect) {
    let has_result = app.diag_result.is_some();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3),                              // host
            Constraint::Length(3),                              // apk path
            Constraint::Length(3),                              // pem file path
            Constraint::Length(3),                              // run button + key status
            Constraint::Length(if has_result { 3 } else { 0 }), // save button row
            Constraint::Min(6),                                 // results / logs
        ])
        .split(area);

    draw_text_input(
        f,
        chunks[0],
        "Scope Host  [edit]",
        &app.diag_host,
        app.diag_host_cursor,
        app.focus == Focus::DiagHost && app.file_browser.is_none(),
    );

    draw_text_input(
        f,
        chunks[1],
        "APK / XAPK  [Enter = browse]  (or use PEM file below)",
        &app.diag_apk_path,
        app.diag_apk_cursor,
        app.focus == Focus::DiagApkPath && app.file_browser.is_none(),
    );

    draw_text_input(
        f,
        chunks[2],
        "PEM File  [Enter = browse]  (alternative to APK)",
        &app.diag_pem_file_path,
        app.diag_pem_file_cursor,
        app.focus == Focus::DiagPemFilePath && app.file_browser.is_none(),
    );

    // Button row with key status indicator
    let btn_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(chunks[3]);

    let btn_focused = app.focus == Focus::DiagButton && app.file_browser.is_none();
    let btn_ready = app.diag_pem_key.is_some() && !app.diag_busy;
    let btn_style = if btn_focused && btn_ready {
        Style::default()
            .fg(Color::Black)
            .bg(Color::Yellow)
            .add_modifier(Modifier::BOLD)
    } else if btn_ready {
        Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let btn_label = if app.diag_busy {
        "[ Running… ]"
    } else {
        "[ Run Diagnostics ]"
    };
    let run_btn = Paragraph::new(btn_label)
        .alignment(Alignment::Center)
        .style(btn_style)
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(run_btn, btn_chunks[0]);

    let key_status = if app.diag_pem_key.is_some() {
        Span::styled("PEM key ready", Style::default().fg(Color::Green))
    } else if app.diag_apk_path.is_empty() && app.diag_pem_file_path.is_empty() {
        Span::styled(
            "Select an APK/XAPK or a .pem file",
            Style::default().fg(Color::DarkGray),
        )
    } else if !app.diag_pem_file_path.is_empty() {
        Span::styled("Loading PEM key…", Style::default().fg(Color::Yellow))
    } else {
        Span::styled("Extracting PEM key…", Style::default().fg(Color::Yellow))
    };
    let status_par =
        Paragraph::new(Line::from(key_status)).block(Block::default().borders(Borders::ALL));
    f.render_widget(status_par, btn_chunks[1]);

    // Save button row (only when results are present)
    if has_result {
        let save_focused = app.focus == Focus::DiagSaveButton && app.file_browser.is_none();
        let save_style = if save_focused {
            Style::default()
                .fg(Color::Black)
                .bg(Color::LightGreen)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Cyan)
        };
        let save_btn = Paragraph::new("[ Save JSON to file ]")
            .alignment(Alignment::Center)
            .style(save_style)
            .block(Block::default().borders(Borders::ALL));
        f.render_widget(save_btn, chunks[4]);
    }

    // Results pane: show device_state and pi_info if available, else show logs
    if let Some(ref data) = app.diag_result {
        let result_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(chunks[5]);

        let ds_text = serde_json::to_string_pretty(&data.device_state)
            .unwrap_or_else(|_| data.device_state.to_string());
        let ds_lines: Vec<Line> = ds_text
            .lines()
            .map(|l| {
                Line::from(Span::styled(
                    l.to_string(),
                    Style::default().fg(Color::Cyan),
                ))
            })
            .collect();
        let ds_par = Paragraph::new(ds_lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" get_device_state ")
                    .border_style(Style::default().fg(Color::DarkGray)),
            )
            .wrap(Wrap { trim: false });
        f.render_widget(ds_par, result_chunks[0]);

        let pi_text = serde_json::to_string_pretty(&data.pi_info)
            .unwrap_or_else(|_| data.pi_info.to_string());
        let pi_lines: Vec<Line> = pi_text
            .lines()
            .map(|l| {
                Line::from(Span::styled(
                    l.to_string(),
                    Style::default().fg(Color::Cyan),
                ))
            })
            .collect();
        let pi_par = Paragraph::new(pi_lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" pi_get_info ")
                    .border_style(Style::default().fg(Color::DarkGray)),
            )
            .wrap(Wrap { trim: false });
        f.render_widget(pi_par, result_chunks[1]);
    } else {
        draw_logs(f, app, chunks[5]);
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// Build a minimal `DeviceInfo` for use in tests.
    fn make_device_info(model: crate::firmware::ScopeModel) -> crate::firmware::DeviceInfo {
        crate::firmware::DeviceInfo {
            model,
            firmware_ver_string: Some("4.70".to_string()),
            battery_capacity: Some(80),
            battery_charging: false,
            firmware_platform: None,
        }
    }

    /// Build an App for state-machine tests.
    /// The version-fetch task spawned by `new()` will fail silently — that's fine.
    fn make_app() -> App {
        let rt = Arc::new(tokio::runtime::Runtime::new().unwrap());
        App::new(rt)
    }

    // ── maybe_start_detection ────────────────────────────────────────────────

    #[test]
    fn detection_skipped_when_model_is_not_auto() {
        let mut app = make_app();
        app.fw_model = crate::firmware::ScopeModel::S50;
        app.apk_path = "/some/file.apk".to_string();

        let started =
            app.maybe_start_detection(ConfirmAction::InstallApk("/some/file.apk".to_string()));

        assert!(!started, "should return false for concrete model");
        assert!(!app.busy);
        assert!(app.detect_pending.is_none());
    }

    #[test]
    fn detection_errors_when_auto_but_no_pem_key() {
        let mut app = make_app();
        // fw_model is Auto by default; no pem_key
        assert!(app.pem_key.is_none());

        let started =
            app.maybe_start_detection(ConfirmAction::InstallApk("/some/file.apk".to_string()));

        assert!(started, "should return true (intercepted) even on error");
        assert!(!app.busy, "should NOT mark busy — task was not started");
        assert!(
            app.detect_pending.is_none(),
            "pending should not be stored when key is missing"
        );
        // An error should have been logged
        let has_error = app
            .logs
            .iter()
            .any(|(_, msg)| msg.contains("Auto-detect requires"));
        assert!(has_error, "expected error message in logs");
    }

    #[test]
    fn detection_starts_when_auto_with_pem_key() {
        let mut app = make_app();
        // fw_model is Auto by default
        app.pem_key = Some(b"fake-key-bytes".to_vec());
        app.host = "192.0.2.1".to_string(); // non-routable, task will fail but that's fine

        let action = ConfirmAction::InstallApk("/some/file.apk".to_string());
        let started = app.maybe_start_detection(action.clone());

        assert!(started, "should return true when detection is started");
        assert!(app.busy, "should mark busy");
        assert!(app.detect_pending.is_some(), "should store pending action");
        assert!(
            app.confirm.is_none(),
            "confirm dialog should NOT be shown yet"
        );
    }

    // ── run_action ───────────────────────────────────────────────────────────

    #[test]
    fn run_action_apk_empty_path_logs_error() {
        let mut app = make_app();
        app.fw_model = crate::firmware::ScopeModel::S50;
        app.apk_path = "   ".to_string(); // whitespace only

        app.run_action();

        assert!(app.confirm.is_none());
        let has_error = app.logs.iter().any(|(_, msg)| msg.contains("No APK path"));
        assert!(has_error);
    }

    #[test]
    fn run_action_apk_concrete_model_shows_confirm_immediately() {
        let mut app = make_app();
        app.fw_model = crate::firmware::ScopeModel::S50;
        app.apk_path = "/some/file.apk".to_string();

        app.run_action();

        assert!(
            app.confirm.is_some(),
            "confirm dialog should appear for concrete model"
        );
        assert!(!app.busy);
        assert!(app.detect_pending.is_none());
    }

    #[test]
    fn run_action_apk_auto_model_no_pem_logs_error_no_confirm() {
        let mut app = make_app();
        // Auto model, no pem_key, no APK path set
        // run_action should error about missing APK path

        app.run_action();

        assert!(
            app.confirm.is_none(),
            "confirm should not appear when no apk path"
        );
        assert!(!app.busy);
        let has_error = app
            .logs
            .iter()
            .any(|(_, msg)| msg.contains("No APK path entered"));
        assert!(has_error);
    }

    #[test]
    fn run_action_apk_auto_model_with_apk_and_no_pem_starts_detection() {
        let mut app = make_app();
        // Auto model, APK path set, but no pem_key yet
        // maybe_start_detection should extract PEM from APK synchronously
        // and then start model detection
        app.apk_path = "/some/file.apk".to_string();
        app.fw_model = crate::firmware::ScopeModel::default(); // Auto

        // This will try to extract PEM from the fake path and fail,
        // so it should log an error about extraction failure
        app.run_action();

        // Since detection start will fail (invalid APK), confirm should not be set
        assert!(app.confirm.is_none());
        let has_error = app.logs.iter().any(|(_, msg)| msg.contains("extract PEM"));
        assert!(has_error);
    }

    #[test]
    fn run_action_apk_auto_model_with_pem_starts_detection() {
        let mut app = make_app();
        app.pem_key = Some(b"fake-key".to_vec());
        app.apk_path = "/some/file.apk".to_string();
        app.host = "192.0.2.1".to_string();

        app.run_action();

        assert!(app.confirm.is_none(), "confirm should not appear yet");
        assert!(app.busy);
        assert!(app.detect_pending.is_some());
    }

    #[test]
    fn run_action_iscope_empty_path_logs_error() {
        let mut app = make_app();
        app.fw_source = FirmwareSource::LocalIscope;
        app.fw_model = crate::firmware::ScopeModel::S50;
        app.iscope_path = String::new();

        app.run_action();

        assert!(app.confirm.is_none());
        let has_error = app
            .logs
            .iter()
            .any(|(_, msg)| msg.contains("No iscope path"));
        assert!(has_error);
    }

    #[test]
    fn run_action_iscope_concrete_model_shows_confirm_immediately() {
        let mut app = make_app();
        app.fw_source = FirmwareSource::LocalIscope;
        app.fw_model = crate::firmware::ScopeModel::S30Pro;
        app.iscope_path = "/some/file.iscope_64".to_string();

        app.run_action();

        assert!(app.confirm.is_some());
        assert!(!app.busy);
    }

    #[test]
    fn run_action_iscope_auto_model_no_pem_logs_error() {
        let mut app = make_app();
        app.fw_source = FirmwareSource::LocalIscope;
        app.iscope_path = "/some/file.iscope".to_string();
        // pem_key is None (default)

        app.run_action();

        assert!(app.confirm.is_none());
        let has_error = app
            .logs
            .iter()
            .any(|(_, msg)| msg.contains("Auto-detect requires"));
        assert!(has_error);
    }

    #[test]
    fn run_action_busy_is_noop() {
        let mut app = make_app();
        app.fw_model = crate::firmware::ScopeModel::S50;
        app.apk_path = "/some/file.apk".to_string();
        app.busy = true;

        app.run_action();

        assert!(app.confirm.is_none(), "should not show confirm while busy");
    }

    // ── execute_confirmed ────────────────────────────────────────────────────

    #[test]
    fn execute_confirmed_uses_detected_model_and_clears_it() {
        let mut app = make_app();
        // Set up an S50 manual selection but provide a detected S30Pro
        app.fw_model = crate::firmware::ScopeModel::S50;
        app.detected_model = Some(make_device_info(crate::firmware::ScopeModel::S30Pro));
        app.host = "192.0.2.1".to_string(); // non-routable so the task fails fast
        app.confirm = Some(ConfirmDialog::new(ConfirmAction::InstallApk(
            "/dev/null".to_string(),
        )));

        app.execute_confirmed();

        // detected_model consumed
        assert!(
            app.detected_model.is_none(),
            "detected_model should be cleared after use"
        );
        // confirm cleared too
        assert!(app.confirm.is_none());
        // task was started
        assert!(app.busy);
    }

    #[test]
    fn execute_confirmed_falls_back_to_fw_model_when_no_detected() {
        let mut app = make_app();
        app.fw_model = crate::firmware::ScopeModel::S50;
        app.detected_model = None;
        app.host = "192.0.2.1".to_string();
        app.confirm = Some(ConfirmDialog::new(ConfirmAction::InstallApk(
            "/dev/null".to_string(),
        )));

        app.execute_confirmed();

        // No panic, task started using fw_model
        assert!(app.busy);
        assert!(app.detected_model.is_none());
    }

    #[test]
    fn execute_confirmed_is_noop_when_no_confirm() {
        let mut app = make_app();
        app.confirm = None;

        app.execute_confirmed(); // should not panic

        assert!(!app.busy);
    }

    // ── handle_key_confirm ───────────────────────────────────────────────────

    #[test]
    fn esc_clears_confirm_and_detected_model() {
        let mut app = make_app();
        app.confirm = Some(ConfirmDialog::new(ConfirmAction::InstallApk(
            "/dev/null".to_string(),
        )));
        app.detected_model = Some(make_device_info(crate::firmware::ScopeModel::S30Pro));

        app.handle_key_confirm(KeyCode::Esc);

        assert!(app.confirm.is_none());
        assert!(
            app.detected_model.is_none(),
            "detected_model must be cleared on Esc"
        );
    }

    #[test]
    fn cancel_button_clears_confirm_and_detected_model() {
        let mut app = make_app();
        let mut dlg = ConfirmDialog::new(ConfirmAction::InstallApk("/dev/null".to_string()));
        dlg.focus = ConfirmFocus::No; // cursor on Cancel
        app.confirm = Some(dlg);
        app.detected_model = Some(make_device_info(crate::firmware::ScopeModel::S50));

        app.handle_key_confirm(KeyCode::Enter);

        assert!(app.confirm.is_none());
        assert!(
            app.detected_model.is_none(),
            "detected_model must be cleared on cancel"
        );
    }

    #[test]
    fn yes_button_consumes_detected_model_via_execute_confirmed() {
        let mut app = make_app();
        let mut dlg = ConfirmDialog::new(ConfirmAction::InstallApk("/dev/null".to_string()));
        dlg.focus = ConfirmFocus::Yes; // cursor on Yes
        app.confirm = Some(dlg);
        app.detected_model = Some(make_device_info(crate::firmware::ScopeModel::S30Pro));
        app.host = "192.0.2.1".to_string();

        app.handle_key_confirm(KeyCode::Enter);

        assert!(
            app.detected_model.is_none(),
            "detected_model consumed by execute_confirmed"
        );
        assert!(app.busy, "task should have been started");
    }

    // ── ModelDetected poll handling ──────────────────────────────────────────

    #[test]
    fn model_detected_msg_opens_confirm_dialog() {
        let mut app = make_app();
        app.detect_pending = Some(ConfirmAction::InstallApk("/some/file.apk".to_string()));
        app.busy = true;

        // Simulate receiving ModelDetected via the channel
        let (tx, rx) = crate::task::channel();
        app.rx = rx;
        tx.send(crate::task::TaskMsg::ModelDetected(make_device_info(
            crate::firmware::ScopeModel::S30Pro,
        )))
        .unwrap();

        app.drain_messages();

        assert!(!app.busy);
        assert!(app.detected_model.is_some());
        assert!(
            app.confirm.is_some(),
            "confirm dialog should open after detection"
        );
        assert!(app.detect_pending.is_none(), "detect_pending consumed");
    }

    #[test]
    fn error_msg_clears_detect_pending_and_detected_model() {
        let mut app = make_app();
        app.detect_pending = Some(ConfirmAction::InstallApk("/some/file.apk".to_string()));
        app.detected_model = Some(make_device_info(crate::firmware::ScopeModel::S50));
        app.busy = true;

        let (tx, rx) = crate::task::channel();
        app.rx = rx;
        tx.send(crate::task::TaskMsg::Error(
            "connection refused".to_string(),
        ))
        .unwrap();

        app.drain_messages();

        assert!(!app.busy);
        assert!(
            app.detect_pending.is_none(),
            "detect_pending must be cleared on error"
        );
        assert!(
            app.detected_model.is_none(),
            "detected_model must be cleared on error"
        );
        assert!(app.confirm.is_none(), "confirm must not appear on error");
    }

    #[test]
    fn model_detected_without_pending_action_does_not_open_confirm() {
        let mut app = make_app();
        // No detect_pending — e.g. user cancelled before response arrived
        app.detect_pending = None;

        let (tx, rx) = crate::task::channel();
        app.rx = rx;
        tx.send(crate::task::TaskMsg::ModelDetected(make_device_info(
            crate::firmware::ScopeModel::S50,
        )))
        .unwrap();

        app.drain_messages();

        assert!(app.detected_model.is_some(), "model is still stored");
        assert!(app.confirm.is_none(), "no confirm without a pending action");
    }
}

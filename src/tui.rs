//! Ratatui-based terminal UI frontend.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::ExecutableCommand;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Clear, Gauge, List, ListItem, ListState, Paragraph, Tabs, Wrap,
};
use ratatui::Terminal;

use crate::apkpure::ApkVersion;
use crate::task::{self, TaskMsg};

const TICK_MS: u64 = 100;

// ── tabs ──────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
enum Tab {
    Firmware,
    ExtractPem,
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
    SourceTabs,
    FilePath,
    Host,
    VersionList,
    ActionButton,
    PemFilePath,
    PemButton,
    Logs,
}

// ── file browser ──────────────────────────────────────────────────────────────

/// Which path field the file browser was opened from.
#[derive(Clone, Copy, PartialEq)]
enum BrowserTarget {
    Apk,
    Iscope,
    Pem,
}

struct FileBrowser {
    cwd: PathBuf,
    /// `(display_name, full_path, is_dir)`
    entries: Vec<(String, PathBuf, bool)>,
    state: ListState,
    target: BrowserTarget,
    /// file-extension filter (empty = show all files)
    filter: &'static [&'static str],
}

impl FileBrowser {
    fn open(start: &str, target: BrowserTarget, filter: &'static [&'static str]) -> Self {
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
        };
        browser.reload();
        browser
    }

    fn reload(&mut self) {
        self.entries.clear();

        // always offer ".." unless already at root
        if self.cwd.parent().is_some() {
            if let Some(parent) = self.cwd.parent() {
                self.entries
                    .push(("..".to_string(), parent.to_path_buf(), true));
            }
        }

        let mut dirs: Vec<(String, PathBuf)> = vec![];
        let mut files: Vec<(String, PathBuf)> = vec![];

        if let Ok(rd) = std::fs::read_dir(&self.cwd) {
            for entry in rd.flatten() {
                let path = entry.path();
                let name = entry.file_name().to_string_lossy().to_string();
                // skip hidden files
                if name.starts_with('.') {
                    continue;
                }
                if path.is_dir() {
                    dirs.push((name, path));
                } else if self.filter.is_empty()
                    || path
                        .extension()
                        .and_then(|e| e.to_str())
                        .map(|e| self.filter.contains(&e))
                        .unwrap_or(false)
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

    fn selected_path(&self) -> Option<&PathBuf> {
        self.state.selected().map(|i| &self.entries[i].1)
    }

    fn selected_is_dir(&self) -> bool {
        self.state
            .selected()
            .map(|i| self.entries[i].2)
            .unwrap_or(false)
    }

    fn enter(&mut self) -> Option<PathBuf> {
        if self.selected_is_dir() {
            if let Some(path) = self.selected_path().cloned() {
                self.cwd = path;
                self.state.select(Some(0));
                self.reload();
            }
            None
        } else {
            self.selected_path().cloned()
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

    // text editing cursor positions
    apk_cursor: usize,
    iscope_cursor: usize,
    host_cursor: usize,
    pem_cursor: usize,

    // file browser overlay
    file_browser: Option<FileBrowser>,

    quit: bool,
}

impl App {
    fn new(rt: Arc<tokio::runtime::Runtime>) -> Self {
        let (tx, rx) = task::channel();
        let mut app = Self {
            tab: Tab::Firmware,
            fw_source: FirmwareSource::LocalApk,
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
            quit: false,
        };
        app.start_fetch_versions(tx);
        app
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
                TaskMsg::Error(e) => {
                    self.busy = false;
                    self.progress = None;
                    self.push_log(
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                        format!("Error: {e}"),
                    );
                }
            }
        }
    }

    fn action_label(&self) -> &'static str {
        match self.fw_source {
            FirmwareSource::LocalApk | FirmwareSource::LocalIscope => "Install",
            FirmwareSource::Download => {
                if self.host.trim().is_empty() {
                    "Download Only"
                } else {
                    "Download & Install"
                }
            }
        }
    }

    fn run_action(&mut self) {
        if self.busy {
            return;
        }
        let (tx, rx) = task::channel();
        self.rx = rx;
        self.busy = true;
        self.progress = Some((0, 0));

        match self.fw_source {
            FirmwareSource::LocalApk => {
                let path = self.apk_path.trim().to_string();
                if path.is_empty() {
                    self.push_log(
                        Style::default().fg(Color::Red),
                        "No APK path entered.".to_string(),
                    );
                    self.busy = false;
                    self.progress = None;
                    return;
                }
                crate::runner::install_apk(&self.rt, tx, path, self.host.trim().to_string());
            }
            FirmwareSource::LocalIscope => {
                let path = self.iscope_path.trim().to_string();
                if path.is_empty() {
                    self.push_log(
                        Style::default().fg(Color::Red),
                        "No iscope path entered.".to_string(),
                    );
                    self.busy = false;
                    self.progress = None;
                    return;
                }
                crate::runner::install_iscope(&self.rt, tx, path, self.host.trim().to_string());
            }
            FirmwareSource::Download => {
                let idx = match self.version_state.selected() {
                    Some(i) => i,
                    None => {
                        self.push_log(
                            Style::default().fg(Color::Red),
                            "No version selected.".to_string(),
                        );
                        self.busy = false;
                        self.progress = None;
                        return;
                    }
                };
                let ver = &self.versions[idx];
                let dest = dirs_next::download_dir().unwrap_or_else(|| PathBuf::from("."));
                if self.host.trim().is_empty() {
                    crate::runner::download_only(
                        &self.rt,
                        tx,
                        ver.version.clone(),
                        ver.download_url.clone(),
                        dest,
                    );
                } else {
                    crate::runner::download_and_install(
                        &self.rt,
                        tx,
                        ver.version.clone(),
                        ver.download_url.clone(),
                        dest,
                        self.host.trim().to_string(),
                    );
                }
            }
        }
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

    fn save_pem(&self) {
        if self.pem_keys.is_empty() {
            return;
        }
        let path = PathBuf::from("seestar_keys.pem");
        let content = self.pem_keys.join("\n");
        if std::fs::write(&path, content).is_ok() {
            eprintln!("Saved PEM keys to {}", path.display());
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
            _ => return,
        };
        self.file_browser = Some(FileBrowser::open(start, target, filter));
    }

    fn apply_browser_selection(&mut self, path: PathBuf) {
        let s = path.to_string_lossy().to_string();
        match self.file_browser.as_ref().map(|b| b.target) {
            Some(BrowserTarget::Apk) => {
                self.apk_cursor = s.len();
                self.apk_path = s;
            }
            Some(BrowserTarget::Iscope) => {
                self.iscope_cursor = s.len();
                self.iscope_path = s;
            }
            Some(BrowserTarget::Pem) => {
                self.pem_cursor = s.len();
                self.pem_path = s;
            }
            None => {}
        }
        self.file_browser = None;
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

        // File browser consumes all keys when open
        if self.file_browser.is_some() {
            self.handle_key_browser(code);
            return;
        }

        match self.tab {
            Tab::Firmware => self.handle_key_firmware(code, modifiers),
            Tab::ExtractPem => self.handle_key_pem(code, modifiers),
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
                if let Some(b) = self.file_browser.as_mut() {
                    if let Some(selected) = b.enter() {
                        // file selected — close browser and apply
                        self.apply_browser_selection(selected);
                    }
                    // directory was entered; browser stays open
                }
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
                    KeyCode::Backspace => {
                        if *cur > 0 {
                            *cur -= 1;
                            s.remove(*cur);
                        }
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
                KeyCode::Backspace => {
                    if self.host_cursor > 0 {
                        self.host_cursor -= 1;
                        self.host.remove(self.host_cursor);
                    }
                }
                KeyCode::Left => self.host_cursor = self.host_cursor.saturating_sub(1),
                KeyCode::Right => {
                    if self.host_cursor < self.host.len() {
                        self.host_cursor += 1;
                    }
                }
                KeyCode::Tab => self.focus = Focus::ActionButton,
                _ => {}
            },
            Focus::ActionButton => match code {
                KeyCode::Enter | KeyCode::Char(' ') => self.run_action(),
                KeyCode::Tab => self.focus = Focus::Logs,
                KeyCode::BackTab => self.focus = Focus::Host,
                _ => {}
            },
            Focus::Logs => match code {
                KeyCode::Tab => self.focus = Focus::SourceTabs,
                KeyCode::BackTab => self.focus = Focus::ActionButton,
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
                    KeyCode::Backspace => {
                        if self.pem_cursor > 0 {
                            self.pem_cursor -= 1;
                            self.pem_path.remove(self.pem_cursor);
                        }
                    }
                    KeyCode::Left => self.pem_cursor = self.pem_cursor.saturating_sub(1),
                    KeyCode::Right => {
                        if self.pem_cursor < self.pem_path.len() {
                            self.pem_cursor += 1;
                        }
                    }
                    _ => {}
                }
            }
            Focus::PemButton => match code {
                KeyCode::Enter | KeyCode::Char(' ') => self.run_pem(),
                KeyCode::Char('s') => self.save_pem(),
                KeyCode::Tab => self.focus = Focus::Logs,
                KeyCode::BackTab => self.focus = Focus::PemFilePath,
                _ => {}
            },
            Focus::Logs => match code {
                KeyCode::Tab => self.focus = Focus::PemFilePath,
                KeyCode::BackTab => self.focus = Focus::PemButton,
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

    let tab_titles = ["Firmware Update", "Extract PEM"];
    let selected_tab = match app.tab {
        Tab::Firmware => 0,
        Tab::ExtractPem => 1,
    };
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
        "Seestar Host/IP (leave blank to download only)",
        &app.host,
        app.host_cursor,
        app.focus == Focus::Host && app.file_browser.is_none(),
    );

    // ── action button ────────────────────────────────────────────────────────
    let btn_label = app.action_label();
    let btn_style = if app.focus == Focus::ActionButton && app.file_browser.is_none() {
        Style::default()
            .fg(Color::Black)
            .bg(Color::Yellow)
            .add_modifier(Modifier::BOLD)
    } else if app.busy {
        Style::default().fg(Color::DarkGray)
    } else {
        Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD)
    };
    let btn = Paragraph::new(format!("[ {} ]", btn_label))
        .alignment(Alignment::Center)
        .style(btn_style)
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(btn, chunks[4]);

    draw_logs(f, app, chunks[5]);
    draw_progress(f, app, chunks[6]);
}

fn draw_pem(f: &mut ratatui::Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3), // file path
            Constraint::Length(3), // button row
            Constraint::Min(6),    // logs / key preview
            Constraint::Length(3), // progress
        ])
        .split(area);

    draw_text_input(
        f,
        chunks[0],
        "APK / XAPK Path  [Enter = browse]",
        &app.pem_path,
        app.pem_cursor,
        app.focus == Focus::PemFilePath && app.file_browser.is_none(),
    );

    let btn_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[1]);

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

    let save_style = if app.pem_keys.is_empty() {
        Style::default().fg(Color::DarkGray)
    } else {
        Style::default().fg(Color::Cyan)
    };
    let save_btn = Paragraph::new("[ Save PEM (s) ]")
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
        f.render_widget(key_par, chunks[2]);
    } else {
        draw_logs(f, app, chunks[2]);
    }

    draw_progress(f, app, chunks[3]);
}

fn draw_file_browser(f: &mut ratatui::Frame, app: &mut App, area: Rect) {
    // Center a popup that's 80% wide and 70% tall
    let popup_width = (area.width * 4 / 5).max(40);
    let popup_height = (area.height * 7 / 10).max(10);
    let x = area.x + (area.width.saturating_sub(popup_width)) / 2;
    let y = area.y + (area.height.saturating_sub(popup_height)) / 2;
    let popup_area = Rect::new(x, y, popup_width, popup_height);

    f.render_widget(Clear, popup_area);

    if let Some(browser) = app.file_browser.as_mut() {
        let cwd_str = browser.cwd.to_string_lossy();
        let title = format!(" {} ", cwd_str);

        let footer = Line::from(vec![
            Span::styled(" ↑↓", Style::default().fg(Color::Yellow)),
            Span::raw(" navigate  "),
            Span::styled("Enter", Style::default().fg(Color::Yellow)),
            Span::raw(" open/select  "),
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
                if *is_dir {
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
                let label = if app.busy { "Working…" } else { "" };
                let gauge = Gauge::default()
                    .block(Block::default().borders(Borders::ALL))
                    .gauge_style(Style::default().fg(Color::Blue).bg(Color::DarkGray))
                    .ratio(0.5)
                    .label(label);
                f.render_widget(gauge, area);
            } else {
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
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
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

use chrono::{DateTime, Utc};
use ratatui::widgets::ListState;
use serde::Deserialize;

// --- Config (trust boundary: disk I/O + TOML deserialization) ---

#[derive(Debug, Deserialize)]
pub struct Config {
    pub feeds: FeedsConfig,
    pub llm: LlmConfig,
    pub scraper: Option<ScraperConfig>,
    pub diagram: DiagramConfig,
    pub filters: FiltersConfig,
    pub tui: TuiConfig,
}

#[derive(Debug, Deserialize)]
pub struct FeedsConfig { pub urls: Vec<String>, pub poll_interval_secs: u64 }

#[derive(Debug, Deserialize)]
pub struct LlmConfig { pub model: String, pub api_key: String, pub max_concurrent: usize }

#[derive(Debug, Deserialize)]
pub struct ScraperConfig { pub api_key: String }

#[derive(Debug, Deserialize)]
pub struct DiagramConfig { pub graph_easy_bin: String, pub perl5lib: String }

#[derive(Debug, Deserialize)]
pub struct FiltersConfig { pub days_lookback: u64 }

#[derive(Debug, Deserialize)]
pub struct TuiConfig { pub refresh_rate_ms: u64 }

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string("config/argusterm.toml")?;
        Ok(toml::from_str(&raw)?)
    }
}

// --- Domain types ---

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedSource { Nvd, Cisa, GitHub, Microsoft, Cert, Research, Community, Exploit, News }

impl FeedSource {
    pub fn label(self) -> &'static str {
        match self {
            Self::Nvd => "NVD", Self::Cisa => "CISA", Self::GitHub => "GHSA",
            Self::Microsoft => "MSRC", Self::Cert => "CERT", Self::Research => "RSCH",
            Self::Community => "COMM", Self::Exploit => "XPLT", Self::News => "NEWS",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Pane { #[default] FeedList, Detail, FilterBar }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortMode { #[default] None, ScoreDesc, ScoreAsc, DateDesc, DateAsc }

impl SortMode {
    pub fn next(self) -> Self {
        match self {
            Self::None => Self::ScoreDesc, Self::ScoreDesc => Self::ScoreAsc,
            Self::ScoreAsc => Self::DateDesc, Self::DateDesc => Self::DateAsc,
            Self::DateAsc => Self::None,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::None => "", Self::ScoreDesc => "score↓", Self::ScoreAsc => "score↑",
            Self::DateDesc => "date↓", Self::DateAsc => "date↑",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CveEntry {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: Option<String>,
    pub published: DateTime<Utc>,
    pub source: FeedSource,
    pub url: Option<String>,
    pub llm_summary: Option<String>,
    pub ascii_diagram: Option<String>,
    pub relevance_score: Option<f32>,
    pub scraped_content: Option<String>,
    pub cve_ids: Vec<String>,
    pub content_type: Option<String>,
}

// --- App state (owned by main task, no Arc/Mutex) ---

pub struct AppState {
    pub entries: Vec<CveEntry>,
    pub filtered: Vec<usize>,
    pub list_state: ListState,
    pub active_pane: Pane,
    pub filter_text: String,
    pub sort_mode: SortMode,
    pub detail_scroll: u16,
    pub detail_hscroll: u16,
    pub cve_bar_active: bool,
    pub cve_bar_index: usize,
    pub pending_g: bool,
    pub list_height: usize,
    pub is_loading: bool,
    pub should_quit: bool,
}

impl Default for AppState {
    fn default() -> Self {
        let mut list_state = ListState::default();
        list_state.select(Some(0));
        Self {
            entries: Vec::new(), filtered: Vec::new(), list_state,
            active_pane: Pane::default(), filter_text: String::new(),
            sort_mode: SortMode::default(), detail_scroll: 0, detail_hscroll: 0,
            cve_bar_active: false, cve_bar_index: 0, pending_g: false,
            list_height: 20, is_loading: false, should_quit: false,
        }
    }
}

impl AppState {
    fn reset_detail(&mut self) {
        self.detail_scroll = 0;
        self.detail_hscroll = 0;
        self.cve_bar_active = false;
        self.cve_bar_index = 0;
    }

    pub fn refilter(&mut self) {
        self.filtered = crate::filters::apply(&self.entries, &self.filter_text, self.sort_mode);
        if self.filtered.is_empty() {
            self.list_state.select(None);
        } else {
            let max = self.filtered.len() - 1;
            self.list_state.select(Some(self.list_state.selected().unwrap_or(0).min(max)));
        }
    }

    pub fn selected_entry_index(&self) -> Option<usize> {
        self.list_state.selected().and_then(|i| self.filtered.get(i).copied())
    }

    fn navigate(&mut self, idx: usize) {
        self.list_state.select(Some(idx));
        self.reset_detail();
    }

    pub fn select_next(&mut self) {
        if self.filtered.is_empty() { return; }
        let max = self.filtered.len() - 1;
        self.navigate((self.list_state.selected().unwrap_or(0).min(max) + 1).min(max));
    }
    pub fn select_prev(&mut self) {
        if self.filtered.is_empty() { return; }
        self.navigate(self.list_state.selected().unwrap_or(0).saturating_sub(1));
    }
    pub fn select_half_down(&mut self) {
        if self.filtered.is_empty() { return; }
        let max = self.filtered.len() - 1;
        self.navigate((self.list_state.selected().unwrap_or(0) + self.list_height / 2).min(max));
    }
    pub fn select_half_up(&mut self) {
        if self.filtered.is_empty() { return; }
        self.navigate(self.list_state.selected().unwrap_or(0).saturating_sub(self.list_height / 2));
    }
    pub fn select_first(&mut self) {
        if !self.filtered.is_empty() { self.navigate(0); }
    }
    pub fn select_last(&mut self) {
        if !self.filtered.is_empty() { self.navigate(self.filtered.len() - 1); }
    }

    pub fn cve_bar_next(&mut self) {
        if let Some(i) = self.selected_entry_index() {
            let max = self.entries[i].cve_ids.len().saturating_sub(1);
            self.cve_bar_index = (self.cve_bar_index + 1).min(max);
        }
    }
    pub fn cve_bar_prev(&mut self) { self.cve_bar_index = self.cve_bar_index.saturating_sub(1); }
    pub fn scroll_detail_down(&mut self) { self.detail_scroll = self.detail_scroll.saturating_add(1); }
    pub fn scroll_detail_up(&mut self) { self.detail_scroll = self.detail_scroll.saturating_sub(1); }
    pub fn scroll_detail_right(&mut self) { self.detail_hscroll = self.detail_hscroll.saturating_add(2); }
    pub fn scroll_detail_left(&mut self) { self.detail_hscroll = self.detail_hscroll.saturating_sub(2); }
}

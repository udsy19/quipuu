//! Application state — cursor, filter, mode, active tab, and per-tab state.
//!
//! All methods are pure (no terminal I/O). Test-friendly.

use seawall_core::{Finding, Policy, QuantumRiskScore, QuantumStatus, Severity};

/// The active tab in the TUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Tab {
    #[default]
    Summary,
    Inventory,
    Findings,
    Cbom,
}

impl Tab {
    pub const ALL: [Tab; 4] = [Tab::Summary, Tab::Inventory, Tab::Findings, Tab::Cbom];

    pub fn index(self) -> usize {
        match self {
            Tab::Summary => 0,
            Tab::Inventory => 1,
            Tab::Findings => 2,
            Tab::Cbom => 3,
        }
    }

    pub fn from_index(i: usize) -> Self {
        match i % 4 {
            0 => Tab::Summary,
            1 => Tab::Inventory,
            2 => Tab::Findings,
            3 => Tab::Cbom,
            _ => Tab::Summary,
        }
    }

    pub fn next(self) -> Self {
        Tab::from_index(self.index() + 1)
    }

    pub fn prev(self) -> Self {
        Tab::from_index((self.index() + 3) % 4)
    }

    pub fn title(self) -> &'static str {
        match self {
            Tab::Summary => "1 Summary",
            Tab::Inventory => "2 Inventory",
            Tab::Findings => "3 Findings",
            Tab::Cbom => "4 CBOM",
        }
    }
}

/// Interaction mode.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Mode {
    #[default]
    Browsing,
    Filtering,
    Help,
}

/// Per-tab navigation + filter for Inventory and Findings tabs (Summary and
/// CBOM don't need a scrollable cursor/filter pair of their own).
#[derive(Debug, Clone, Default)]
pub struct TabNav {
    /// Cursor into the filtered list.
    pub cursor: usize,
    /// Input buffer while in filter mode.
    pub filter_input: String,
    /// Currently applied filter.
    pub filter_active: String,
    /// Indices into the backing list that pass the filter.
    pub filtered_indices: Vec<usize>,
    /// Whether the right-hand detail pane is open.
    pub detail_open: bool,
}

impl TabNav {
    pub fn init(len: usize) -> Self {
        Self {
            cursor: 0,
            filter_input: String::new(),
            filter_active: String::new(),
            filtered_indices: (0..len).collect(),
            detail_open: false,
        }
    }

    pub fn next(&mut self) {
        if !self.filtered_indices.is_empty() {
            let last = self.filtered_indices.len() - 1;
            if self.cursor < last {
                self.cursor += 1;
            }
        }
    }

    pub fn prev(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
        }
    }

    pub fn first(&mut self) {
        self.cursor = 0;
    }

    pub fn last(&mut self) {
        if !self.filtered_indices.is_empty() {
            self.cursor = self.filtered_indices.len() - 1;
        }
    }

    pub fn page_down(&mut self, page: usize) {
        if !self.filtered_indices.is_empty() {
            let last = self.filtered_indices.len() - 1;
            self.cursor = (self.cursor + page).min(last);
        }
    }

    pub fn page_up(&mut self, page: usize) {
        self.cursor = self.cursor.saturating_sub(page);
    }

    /// Clamp cursor after a filter change.
    fn clamp(&mut self) {
        if self.filtered_indices.is_empty() {
            self.cursor = 0;
        } else {
            self.cursor = self.cursor.min(self.filtered_indices.len() - 1);
        }
    }

    pub fn selected_index(&self) -> Option<usize> {
        self.filtered_indices.get(self.cursor).copied()
    }
}

/// All mutable UI state.
#[derive(Debug, Clone)]
pub struct AppState {
    /// Active tab.
    pub tab: Tab,
    /// Current interaction mode.
    pub mode: Mode,
    /// Status-bar message.
    pub status_message: Option<String>,

    // ── Tab 3 (Findings) shared cursor state — kept for API compat ──────────
    /// Cursor into `filtered_indices` (Findings tab).
    pub cursor: usize,
    /// Filter input buffer (Findings tab).
    pub filter_input: String,
    /// Committed filter string (Findings tab).
    pub filter_active: String,
    /// Filtered finding indices (Findings tab).
    pub filtered_indices: Vec<usize>,

    // ── Per-tab nav ──────────────────────────────────────────────────────────
    pub inventory_nav: TabNav,
    pub findings_nav: TabNav,
    pub cbom_cursor: usize,
    pub cbom_scroll: usize,

    // ── Severity toggles for Findings tab ───────────────────────────────────
    pub show_critical: bool,
    pub show_high: bool,
    pub show_medium: bool,
    pub show_low: bool,
    pub show_safe: bool,

    /// Number of raw findings (cached).
    total: usize,
}

impl AppState {
    /// Initialise from a slice of findings and the active policy.
    pub fn new(findings: &[Finding], _policy: &Policy) -> Self {
        let total = findings.len();
        let filtered_indices: Vec<usize> = (0..total).collect();
        let findings_nav = TabNav::init(total);
        Self {
            tab: Tab::Summary,
            mode: Mode::Browsing,
            status_message: None,
            cursor: 0,
            filter_input: String::new(),
            filter_active: String::new(),
            filtered_indices: filtered_indices.clone(),
            inventory_nav: TabNav::init(0), // initialised later with algo count
            findings_nav,
            cbom_cursor: 0,
            cbom_scroll: 0,
            show_critical: true,
            show_high: true,
            show_medium: true,
            show_low: true,
            show_safe: true,
            total,
        }
    }

    // ── Tab switching ────────────────────────────────────────────────────────

    pub fn set_tab(&mut self, tab: Tab) {
        self.tab = tab;
        // Leave mode as-is so filter stays when switching back.
        if self.mode == Mode::Filtering {
            self.mode = Mode::Browsing;
        }
    }

    pub fn next_tab(&mut self) {
        self.set_tab(self.tab.next());
    }

    pub fn prev_tab(&mut self) {
        self.set_tab(self.tab.prev());
    }

    // ── Navigation (legacy API for Tab 3 / Findings; kept for existing tests) ─

    pub fn next_finding(&mut self) {
        if self.filtered_indices.is_empty() {
            return;
        }
        let last = self.filtered_indices.len() - 1;
        if self.cursor < last {
            self.cursor += 1;
        }
        self.findings_nav.cursor = self.cursor;
    }

    pub fn prev_finding(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
        }
        self.findings_nav.cursor = self.cursor;
    }

    pub fn g_first(&mut self) {
        self.cursor = 0;
        self.findings_nav.cursor = 0;
    }

    pub fn g_last(&mut self) {
        if !self.filtered_indices.is_empty() {
            self.cursor = self.filtered_indices.len() - 1;
            self.findings_nav.cursor = self.cursor;
        }
    }

    // ── Filtering (legacy API keeps existing tests working) ──────────────────

    /// Apply a filter string against a findings slice. `""` shows everything.
    pub fn apply_filter(&mut self, filter: &str, findings: &[Finding]) {
        let filter = filter.to_lowercase();
        self.filter_active = filter.clone();
        if filter.is_empty() {
            self.filtered_indices = (0..self.total).collect();
        } else {
            self.filtered_indices = findings
                .iter()
                .enumerate()
                .filter(|(_, f)| {
                    f.rule_id.to_lowercase().contains(&filter)
                        || f.algorithm_id.to_lowercase().contains(&filter)
                        || f.location.location.to_lowercase().contains(&filter)
                        || f.message.to_lowercase().contains(&filter)
                })
                .map(|(i, _)| i)
                .collect();
        }
        if self.filtered_indices.is_empty() {
            self.cursor = 0;
        } else {
            self.cursor = self.cursor.min(self.filtered_indices.len() - 1);
        }
        // Keep findings_nav in sync.
        self.findings_nav.filtered_indices = self.filtered_indices.clone();
        self.findings_nav.filter_active = self.filter_active.clone();
        self.findings_nav.clamp();
        self.cursor = self.findings_nav.cursor;
    }

    /// Apply a severity-aware filter for the Findings tab.
    pub fn apply_findings_filter(
        &mut self,
        filter: &str,
        findings: &[Finding],
        algorithms: &seawall_core::AlgorithmTable,
        policy: &Policy,
    ) {
        let filter_lc = filter.to_lowercase();
        self.findings_nav.filter_active = filter_lc.clone();
        self.filter_active = filter_lc.clone();

        self.findings_nav.filtered_indices = findings
            .iter()
            .enumerate()
            .filter(|(_, f)| {
                // Text match.
                let text_ok = filter_lc.is_empty()
                    || f.rule_id.to_lowercase().contains(&filter_lc)
                    || f.algorithm_id.to_lowercase().contains(&filter_lc)
                    || f.location.location.to_lowercase().contains(&filter_lc)
                    || f.message.to_lowercase().contains(&filter_lc);
                if !text_ok {
                    return false;
                }
                // Severity toggle.
                let sev = if let Some(alg) = algorithms.get(&f.algorithm_id) {
                    QuantumRiskScore::compute(f, alg, policy).severity
                } else {
                    Severity::Safe
                };
                match sev {
                    Severity::Critical => self.show_critical,
                    Severity::High => self.show_high,
                    Severity::Medium => self.show_medium,
                    Severity::Low => self.show_low,
                    Severity::Safe => self.show_safe,
                }
            })
            .map(|(i, _)| i)
            .collect();

        self.filtered_indices = self.findings_nav.filtered_indices.clone();
        self.findings_nav.clamp();
        self.cursor = self.findings_nav.cursor;
    }

    pub fn selected_finding_index(&self) -> Option<usize> {
        self.filtered_indices.get(self.cursor).copied()
    }

    // ── Mode helpers ─────────────────────────────────────────────────────────

    pub fn enter_filter_mode(&mut self) {
        self.mode = Mode::Filtering;
        self.filter_input.clone_from(&self.filter_active);
        self.findings_nav.filter_input = self.filter_input.clone();
    }

    pub fn exit_filter_mode_cancel(&mut self) {
        self.mode = Mode::Browsing;
        self.filter_input.clone_from(&self.filter_active);
        self.findings_nav.filter_input = self.filter_input.clone();
    }

    pub fn exit_filter_mode_apply(&mut self, findings: &[Finding]) {
        let text = self.filter_input.clone();
        self.mode = Mode::Browsing;
        self.apply_filter(&text, findings);
    }

    pub fn toggle_help(&mut self) {
        if self.mode == Mode::Help {
            self.mode = Mode::Browsing;
        } else {
            self.mode = Mode::Help;
        }
    }

    pub fn push_filter_char(&mut self, c: char) {
        self.filter_input.push(c);
        self.findings_nav.filter_input.push(c);
    }

    pub fn pop_filter_char(&mut self) {
        self.filter_input.pop();
        self.findings_nav.filter_input.pop();
    }

    // ── Inventory filter ─────────────────────────────────────────────────────

    pub fn apply_inventory_filter(&mut self, filter: &str, total: usize) {
        self.inventory_nav.filter_active = filter.to_lowercase();
        // The render layer re-applies the filter against the algo list;
        // here we just reset the cursor so the model rebuilds.
        self.inventory_nav.filtered_indices = (0..total).collect();
        self.inventory_nav.clamp();
    }
}

// ---------------------------------------------------------------------------
// KPI helpers (pure, exported for tests)
// ---------------------------------------------------------------------------

/// Totals for the KPI strip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kpi {
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub safe: usize,
    /// Findings marked HNDL-critical OR whose computed severity == Critical.
    pub hndl_critical: usize,
    pub quantum_vulnerable: usize,
}

/// Compute KPI totals from a findings slice.
pub fn kpi_total(
    findings: &[Finding],
    algorithms: &seawall_core::AlgorithmTable,
    policy: &Policy,
) -> Kpi {
    let mut critical = 0usize;
    let mut high = 0usize;
    let mut medium = 0usize;
    let mut low = 0usize;
    let mut safe = 0usize;
    let mut hndl_critical = 0usize;
    let mut quantum_vulnerable = 0usize;

    for f in findings {
        let severity = if let Some(alg) = algorithms.get(&f.algorithm_id) {
            let score = QuantumRiskScore::compute(f, alg, policy);
            score.severity
        } else {
            Severity::Safe
        };
        match severity {
            Severity::Critical => critical += 1,
            Severity::High => high += 1,
            Severity::Medium => medium += 1,
            Severity::Low => low += 1,
            Severity::Safe => safe += 1,
        }
        if f.hndl_critical || severity == Severity::Critical {
            hndl_critical += 1;
        }
        // Quantum-vulnerable = BrokenByShor or BrokenClassically
        if let Some(alg) = algorithms.get(&f.algorithm_id)
            && matches!(
                alg.quantum_status,
                QuantumStatus::BrokenByShor | QuantumStatus::BrokenClassically
            )
        {
            quantum_vulnerable += 1;
        }
    }

    Kpi {
        total: findings.len(),
        critical,
        high,
        medium,
        low,
        safe,
        hndl_critical,
        quantum_vulnerable,
    }
}

/// Days to the next policy deadline (rough estimate).
pub fn days_to_deadline(policy: &Policy) -> i64 {
    let target_year = policy.deprecation.asymmetric_112bit_disallowed_after as i64;
    let current_year: i64 = 2026;
    (target_year - current_year) * 365
}

// ---------------------------------------------------------------------------
// Style helper — NO_COLOR support
// ---------------------------------------------------------------------------

/// Returns `true` when `NO_COLOR` is set in the environment.
pub fn no_color() -> bool {
    std::env::var_os("NO_COLOR").is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use seawall_core::{
        Confidence, Exposure, Finding, Location, Policy, UsageContext, load_builtins,
    };

    fn dummy_finding(rule_id: &str, algorithm_id: &str, msg: &str) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            algorithm_id: algorithm_id.to_string(),
            location: Location {
                location: "main.go:15".to_string(),
                line: Some(15),
                offset: None,
                symbol: Some("rsa.GenerateKey".to_string()),
                snippet: Some("rsa.GenerateKey(rand.Reader, 2048)".to_string()),
            },
            message: msg.to_string(),
            confidence: Confidence::LiteralArg,
            usage_context: UsageContext::KeyEstablishmentLongLived,
            exposure: Exposure::PublicInternet,
            shelf_life_bucket: "medium".to_string(),
            hndl_critical: false,
        }
    }

    fn make_policy() -> Policy {
        load_builtins().expect("builtins load").policy
    }

    #[test]
    fn new_initialises_cursor_at_zero_and_browsing_mode() {
        let findings = vec![
            dummy_finding("CRYPTO-001", "rsa-2048", "RSA-2048 found"),
            dummy_finding("CRYPTO-002", "ecdsa-p256", "ECDSA-P256 found"),
        ];
        let policy = make_policy();
        let state = AppState::new(&findings, &policy);
        assert_eq!(state.cursor, 0);
        assert_eq!(state.mode, Mode::Browsing);
        assert_eq!(state.filtered_indices.len(), 2);
    }

    #[test]
    fn next_finding_increments_and_does_not_overshoot() {
        let findings = vec![
            dummy_finding("CRYPTO-001", "rsa-2048", "a"),
            dummy_finding("CRYPTO-002", "rsa-3072", "b"),
        ];
        let policy = make_policy();
        let mut state = AppState::new(&findings, &policy);
        state.next_finding();
        assert_eq!(state.cursor, 1);
        // Should not go past last.
        state.next_finding();
        assert_eq!(state.cursor, 1);
    }

    #[test]
    fn prev_finding_decrements_and_does_not_underflow() {
        let findings = vec![
            dummy_finding("CRYPTO-001", "rsa-2048", "a"),
            dummy_finding("CRYPTO-002", "rsa-3072", "b"),
        ];
        let policy = make_policy();
        let mut state = AppState::new(&findings, &policy);
        state.next_finding();
        assert_eq!(state.cursor, 1);
        state.prev_finding();
        assert_eq!(state.cursor, 0);
        // Should not underflow.
        state.prev_finding();
        assert_eq!(state.cursor, 0);
    }

    #[test]
    fn g_first_and_g_last_set_cursor_correctly() {
        let findings = vec![
            dummy_finding("CRYPTO-001", "rsa-2048", "a"),
            dummy_finding("CRYPTO-002", "rsa-3072", "b"),
            dummy_finding("CRYPTO-003", "ecdsa-p256", "c"),
        ];
        let policy = make_policy();
        let mut state = AppState::new(&findings, &policy);
        state.g_last();
        assert_eq!(state.cursor, 2);
        state.g_first();
        assert_eq!(state.cursor, 0);
    }

    #[test]
    fn apply_filter_rsa_matches_only_rsa_findings() {
        let findings = vec![
            dummy_finding("CRYPTO-001", "rsa-2048", "RSA-2048 key detected"),
            dummy_finding("CRYPTO-002", "ecdsa-p256", "ECDSA-P256 key detected"),
            dummy_finding("CRYPTO-003", "rsa-3072", "RSA-3072 key detected"),
        ];
        let policy = make_policy();
        let mut state = AppState::new(&findings, &policy);
        state.apply_filter("RSA", &findings);
        assert_eq!(state.filtered_indices.len(), 2);
    }

    #[test]
    fn apply_filter_empty_shows_all_findings() {
        let findings = vec![
            dummy_finding("CRYPTO-001", "rsa-2048", "RSA-2048"),
            dummy_finding("CRYPTO-002", "ecdsa-p256", "ECDSA"),
        ];
        let policy = make_policy();
        let mut state = AppState::new(&findings, &policy);
        state.apply_filter("ecdsa", &findings);
        assert_eq!(state.filtered_indices.len(), 1);
        state.apply_filter("", &findings);
        assert_eq!(state.filtered_indices.len(), 2);
    }

    #[test]
    fn tab_cycling_works_correctly() {
        let findings: Vec<Finding> = vec![];
        let policy = make_policy();
        let mut state = AppState::new(&findings, &policy);
        assert_eq!(state.tab, Tab::Summary);
        state.next_tab();
        assert_eq!(state.tab, Tab::Inventory);
        state.next_tab();
        assert_eq!(state.tab, Tab::Findings);
        state.next_tab();
        assert_eq!(state.tab, Tab::Cbom);
        state.next_tab();
        assert_eq!(state.tab, Tab::Summary);
    }

    #[test]
    fn tab_prev_wraps_correctly() {
        let findings: Vec<Finding> = vec![];
        let policy = make_policy();
        let mut state = AppState::new(&findings, &policy);
        assert_eq!(state.tab, Tab::Summary);
        state.prev_tab();
        assert_eq!(state.tab, Tab::Cbom);
        state.prev_tab();
        assert_eq!(state.tab, Tab::Findings);
    }

    #[test]
    fn tab_direct_set_works() {
        let findings: Vec<Finding> = vec![];
        let policy = make_policy();
        let mut state = AppState::new(&findings, &policy);
        state.set_tab(Tab::Inventory);
        assert_eq!(state.tab, Tab::Inventory);
        state.set_tab(Tab::Cbom);
        assert_eq!(state.tab, Tab::Cbom);
    }
}

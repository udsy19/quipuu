//! Application state — cursor, filter, mode, selected finding index.
//!
//! All methods are pure (no terminal I/O). Test-friendly.

use cryptoscope_core::{Finding, Policy, QuantumRiskScore, Severity};

/// Which findings to show in the left pane.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Mode {
    #[default]
    Browsing,
    Filtering,
    Help,
}

/// All mutable UI state.
#[derive(Debug, Clone)]
pub struct AppState {
    /// Index into `filtered_indices` (not the raw findings list).
    pub cursor: usize,
    /// Current text in the filter input box.
    pub filter_input: String,
    /// Committed filter string (applied after Enter in Filtering mode).
    pub filter_active: String,
    /// Indices into the raw findings list that pass the current filter.
    pub filtered_indices: Vec<usize>,
    /// Current interaction mode.
    pub mode: Mode,
    /// Status-bar message (e.g. export instructions).
    pub status_message: Option<String>,
    /// Total number of raw findings (cached so we don't borrow findings every
    /// time).
    total: usize,
}

impl AppState {
    /// Initialise from a slice of findings and the active policy.
    ///
    /// Cursor starts at 0, mode = `Browsing`, no filter.
    pub fn new(findings: &[Finding], _policy: &Policy) -> Self {
        let total = findings.len();
        let filtered_indices: Vec<usize> = (0..total).collect();
        Self {
            cursor: 0,
            filter_input: String::new(),
            filter_active: String::new(),
            filtered_indices,
            mode: Mode::Browsing,
            status_message: None,
            total,
        }
    }

    // -----------------------------------------------------------------------
    // Navigation
    // -----------------------------------------------------------------------

    /// Move cursor to the next finding. No-op when already at the last one.
    pub fn next_finding(&mut self) {
        if self.filtered_indices.is_empty() {
            return;
        }
        let last = self.filtered_indices.len() - 1;
        if self.cursor < last {
            self.cursor += 1;
        }
    }

    /// Move cursor to the previous finding. No-op when already at the first.
    pub fn prev_finding(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
        }
    }

    /// Jump to the first finding (`g`).
    pub fn g_first(&mut self) {
        self.cursor = 0;
    }

    /// Jump to the last finding (`G`).
    pub fn g_last(&mut self) {
        if !self.filtered_indices.is_empty() {
            self.cursor = self.filtered_indices.len() - 1;
        }
    }

    // -----------------------------------------------------------------------
    // Filtering
    // -----------------------------------------------------------------------

    /// Apply a filter string against a findings slice. `""` shows everything.
    ///
    /// Matches (case-insensitive) against `rule_id`, `algorithm_id`,
    /// `location.location`, and `message`.
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
        // Clamp cursor to new bounds.
        if self.filtered_indices.is_empty() {
            self.cursor = 0;
        } else {
            self.cursor = self.cursor.min(self.filtered_indices.len() - 1);
        }
    }

    /// Index into the raw findings list for the currently selected row.
    pub fn selected_finding_index(&self) -> Option<usize> {
        self.filtered_indices.get(self.cursor).copied()
    }

    // -----------------------------------------------------------------------
    // Mode helpers
    // -----------------------------------------------------------------------

    pub fn enter_filter_mode(&mut self) {
        self.mode = Mode::Filtering;
        self.filter_input.clone_from(&self.filter_active);
    }

    pub fn exit_filter_mode_cancel(&mut self) {
        self.mode = Mode::Browsing;
        self.filter_input.clone_from(&self.filter_active);
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
    }

    pub fn pop_filter_char(&mut self) {
        self.filter_input.pop();
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
}

/// Compute KPI totals from a findings slice.
///
/// The caller must also supply the algorithm table and policy for scoring;
/// findings that cannot be resolved in the algorithm table are treated as Safe.
pub fn kpi_total(
    findings: &[Finding],
    algorithms: &cryptoscope_core::AlgorithmTable,
    policy: &Policy,
) -> Kpi {
    let mut critical = 0usize;
    let mut high = 0usize;
    let mut medium = 0usize;
    let mut low = 0usize;
    let mut safe = 0usize;
    let mut hndl_critical = 0usize;

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
    }

    Kpi {
        total: findings.len(),
        critical,
        high,
        medium,
        low,
        safe,
        hndl_critical,
    }
}

/// Days to the next policy deadline (rough estimate).
///
/// Uses `policy.deprecation.asymmetric_112bit_disallowed_after` minus the
/// current year × 365.
pub fn days_to_deadline(policy: &Policy) -> i64 {
    let target_year = policy.deprecation.asymmetric_112bit_disallowed_after as i64;
    // Current year hard-coded for testability (no system-clock in pure logic).
    // The real app passes `chrono::Local::now().year()` if desired; for the
    // spec's "close enough" countdown we use a fixed reference.
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
    use cryptoscope_core::{
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
}

//! Integration tests for the TUI pure-logic layer.
//!
//! These tests never launch the event loop or touch a real terminal.

use std::env;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
use cryptoscope_core::{
    Confidence, Exposure, Finding, Location, Severity, UsageContext, load_builtins,
};
use cryptoscope_tui::{
    event::{Action, handle_key},
    model::{build_kpi_line, score_bar, severity_badge},
    state::{AppState, Kpi, Mode, days_to_deadline, kpi_total, no_color},
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent {
        code,
        modifiers: KeyModifiers::NONE,
        kind: KeyEventKind::Press,
        state: KeyEventState::NONE,
    }
}

fn finding(rule_id: &str, algorithm_id: &str, msg: &str, hndl: bool) -> Finding {
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
        hndl_critical: hndl,
    }
}

fn builtins() -> (
    Vec<Finding>,
    cryptoscope_core::AlgorithmTable,
    cryptoscope_core::Policy,
) {
    let b = load_builtins().expect("builtins must load");
    let findings = vec![
        finding("CRYPTO-001", "rsa-2048", "RSA-2048 key", false),
        finding("CRYPTO-002", "ecdsa-p256", "ECDSA-P256 key", false),
        finding("CRYPTO-003", "rsa-3072", "RSA-3072 key", false),
    ];
    (findings, b.algorithms, b.policy)
}

// ---------------------------------------------------------------------------
// Test 1: AppState::new initialises correctly
// ---------------------------------------------------------------------------

#[test]
fn appstate_new_initialises_cursor_and_mode() {
    let (findings, _, policy) = builtins();
    let state = AppState::new(&findings, &policy);
    assert_eq!(state.cursor, 0, "cursor must start at 0");
    assert_eq!(state.mode, Mode::Browsing, "mode must start as Browsing");
    assert_eq!(
        state.filtered_indices.len(),
        findings.len(),
        "all findings visible initially"
    );
}

// ---------------------------------------------------------------------------
// Test 2: next_finding increments, does not go past last
// ---------------------------------------------------------------------------

#[test]
fn next_finding_increments_and_clamps() {
    let (findings, _, policy) = builtins();
    let mut state = AppState::new(&findings, &policy);
    state.next_finding();
    assert_eq!(state.cursor, 1);
    state.next_finding();
    assert_eq!(state.cursor, 2);
    // At last element — must not exceed.
    state.next_finding();
    assert_eq!(state.cursor, 2);
}

// ---------------------------------------------------------------------------
// Test 3: prev_finding decrements, does not underflow
// ---------------------------------------------------------------------------

#[test]
fn prev_finding_decrements_and_clamps() {
    let (findings, _, policy) = builtins();
    let mut state = AppState::new(&findings, &policy);
    // Already at 0 — must not underflow.
    state.prev_finding();
    assert_eq!(state.cursor, 0);
    state.next_finding();
    state.next_finding();
    assert_eq!(state.cursor, 2);
    state.prev_finding();
    assert_eq!(state.cursor, 1);
    state.prev_finding();
    assert_eq!(state.cursor, 0);
}

// ---------------------------------------------------------------------------
// Test 4: g_first / G_last
// ---------------------------------------------------------------------------

#[test]
fn g_first_and_g_last_navigate_correctly() {
    let (findings, _, policy) = builtins();
    let mut state = AppState::new(&findings, &policy);
    state.g_last();
    assert_eq!(state.cursor, findings.len() - 1);
    state.g_first();
    assert_eq!(state.cursor, 0);
}

// ---------------------------------------------------------------------------
// Test 5: apply_filter("RSA") — case-insensitive, matches message/algorithm
// ---------------------------------------------------------------------------

#[test]
fn apply_filter_rsa_matches_rsa_findings_only() {
    let (findings, _, policy) = builtins();
    let mut state = AppState::new(&findings, &policy);
    state.apply_filter("RSA", &findings);
    // findings[0] = rsa-2048 "RSA-2048 key"  ✓
    // findings[1] = ecdsa-p256 "ECDSA-P256 key"  ✗
    // findings[2] = rsa-3072 "RSA-3072 key"  ✓
    assert_eq!(
        state.filtered_indices.len(),
        2,
        "only RSA findings should pass the filter"
    );
    assert!(state.filtered_indices.contains(&0));
    assert!(state.filtered_indices.contains(&2));
}

// ---------------------------------------------------------------------------
// Test 6: apply_filter("") shows all
// ---------------------------------------------------------------------------

#[test]
fn apply_filter_empty_shows_all_findings() {
    let (findings, _, policy) = builtins();
    let mut state = AppState::new(&findings, &policy);
    state.apply_filter("ecdsa", &findings);
    assert_eq!(state.filtered_indices.len(), 1);
    state.apply_filter("", &findings);
    assert_eq!(state.filtered_indices.len(), findings.len());
}

// ---------------------------------------------------------------------------
// Test 7: handle_key('q', Browsing) → Quit
// ---------------------------------------------------------------------------

#[test]
fn handle_key_q_in_browsing_returns_quit() {
    let (findings, _, policy) = builtins();
    let mut state = AppState::new(&findings, &policy);
    let action = handle_key(&mut state, key(KeyCode::Char('q')), &findings);
    assert_eq!(action, Action::Quit);
}

// ---------------------------------------------------------------------------
// Test 8: handle_key('/', Browsing) → Filtering; Esc → Browsing
// ---------------------------------------------------------------------------

#[test]
fn slash_enters_filter_mode_esc_returns_browsing() {
    let (findings, _, policy) = builtins();
    let mut state = AppState::new(&findings, &policy);
    assert_eq!(state.mode, Mode::Browsing);

    let action = handle_key(&mut state, key(KeyCode::Char('/')), &findings);
    assert_eq!(action, Action::Redraw);
    assert_eq!(state.mode, Mode::Filtering);

    let action = handle_key(&mut state, key(KeyCode::Esc), &findings);
    assert_eq!(action, Action::Redraw);
    assert_eq!(state.mode, Mode::Browsing);
}

// ---------------------------------------------------------------------------
// Test 9: kpi_total returns correct counts
// ---------------------------------------------------------------------------

#[test]
fn kpi_total_returns_correct_counts() {
    let b = load_builtins().expect("builtins");
    // Use known-critical findings (RSA-2048 with public internet + key establishment
    // + medium shelf life should score high).
    let findings = vec![
        finding("CRYPTO-001", "rsa-2048", "RSA-2048", false),
        finding("CRYPTO-002", "aes-256", "AES-256", false),
    ];
    let kpi = kpi_total(&findings, &b.algorithms, &b.policy);
    assert_eq!(kpi.total, 2);
    // RSA-2048 should definitely not be Safe.
    assert!(kpi.safe < 2, "rsa-2048 should not score as Safe");
}

// ---------------------------------------------------------------------------
// Test 10: NO_COLOR env handling
// ---------------------------------------------------------------------------

#[test]
fn no_color_env_returns_true_when_set() {
    // Clean up before/after to avoid polluting other tests.
    let was_set = env::var_os("NO_COLOR").is_some();
    // SAFETY: test binary is single-threaded for this test; no concurrent env access.
    unsafe {
        env::set_var("NO_COLOR", "1");
    }
    assert!(
        no_color(),
        "no_color() must return true when NO_COLOR is set"
    );
    if !was_set {
        // SAFETY: same single-threaded context.
        unsafe {
            env::remove_var("NO_COLOR");
        }
    }
}

// ---------------------------------------------------------------------------
// Bonus: score_bar and severity_badge helpers
// ---------------------------------------------------------------------------

#[test]
fn score_bar_produces_correct_format() {
    let bar = score_bar(5, 10, 10);
    assert!(bar.starts_with('['), "bar must start with [");
    assert!(bar.contains(']'), "bar must contain ]");
    assert!(bar.contains("5/10"), "bar must show 5/10");
}

#[test]
fn severity_badge_maps_all_variants() {
    assert_eq!(severity_badge(Severity::Critical), "CRIT");
    assert_eq!(severity_badge(Severity::High), "HIGH");
    assert_eq!(severity_badge(Severity::Medium), "MED ");
    assert_eq!(severity_badge(Severity::Low), "LOW ");
    assert_eq!(severity_badge(Severity::Safe), "SAFE");
}

#[test]
fn kpi_line_shows_total_and_deadline() {
    let kpi = Kpi {
        total: 10,
        critical: 3,
        high: 2,
        medium: 2,
        low: 2,
        safe: 1,
        hndl_critical: 2,
    };
    let line = build_kpi_line(&kpi, 3285);
    assert!(line.contains("10"), "should show total 10");
    assert!(line.contains("3285"), "should show 3285 days");
    assert!(line.contains("2"), "should show 2 HNDL-critical");
}

#[test]
fn days_to_deadline_is_positive_for_future_year() {
    let b = load_builtins().expect("builtins");
    let days = days_to_deadline(&b.policy);
    assert!(
        days > 0,
        "days to deadline should be positive for a future policy year"
    );
}

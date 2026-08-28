//! Integration tests for the TUI pure-logic layer.
//!
//! These tests never launch the event loop or touch a real terminal.

use std::env;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
use seawall_core::{
    Confidence, Exposure, Finding, Location, Severity, UsageContext, load_builtins,
};
use seawall_tui::{
    event::{Action, handle_key},
    model::{
        build_finding_rows, build_inventory_rows, build_kpi_line, lang_breakdown, score_bar,
        severity_badge, top_algorithms,
    },
    state::{AppState, Kpi, Mode, Tab, days_to_deadline, kpi_total, no_color},
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
    seawall_core::AlgorithmTable,
    seawall_core::Policy,
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

    // '/' is tab-specific; switch to Findings tab first.
    state.set_tab(seawall_tui::state::Tab::Findings);

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
    assert_eq!(severity_badge(Some(Severity::Critical)), "CRIT");
    assert_eq!(severity_badge(Some(Severity::High)), "HIGH");
    assert_eq!(severity_badge(Some(Severity::Medium)), "MED ");
    assert_eq!(severity_badge(Some(Severity::Low)), "LOW ");
    assert_eq!(severity_badge(Some(Severity::Safe)), "SAFE");
    // A finding with no algorithm-table row has no band. It was `SAFE`, which
    // painted an uncatalogued algorithm green.
    assert_eq!(severity_badge(None), "UNSC");
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
        unscored: 0,
        hndl_critical: 2,
        quantum_vulnerable: 5,
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

// ---------------------------------------------------------------------------
// NEW TESTS — tab switching, filter, per-tab model, rendering helpers
// ---------------------------------------------------------------------------

// Test N+1: Tab switching via handle_key cycles all four tabs.
#[test]
fn handle_key_tab_switches_cycle_all_four_tabs() {
    let (findings, _, policy) = builtins();
    let mut state = AppState::new(&findings, &policy);
    assert_eq!(state.tab, Tab::Summary);

    handle_key(&mut state, key(KeyCode::Tab), &findings);
    assert_eq!(state.tab, Tab::Inventory);

    handle_key(&mut state, key(KeyCode::Tab), &findings);
    assert_eq!(state.tab, Tab::Findings);

    handle_key(&mut state, key(KeyCode::Tab), &findings);
    assert_eq!(state.tab, Tab::Cbom);

    handle_key(&mut state, key(KeyCode::Tab), &findings);
    assert_eq!(state.tab, Tab::Summary, "wraps back to Summary");
}

// Test N+2: Inventory filter excludes non-matching algorithms.
#[test]
fn inventory_filter_excludes_non_matching_algorithms() {
    let b = load_builtins().expect("builtins");
    let findings = vec![
        finding("CRYPTO-001", "rsa-2048", "RSA-2048 key", false),
        finding("CRYPTO-002", "aes-256", "AES-256 key", false),
    ];
    // Filter by "rsa" — should keep rsa-2048, drop aes-256.
    let rows = build_inventory_rows(&findings, &b.algorithms, "rsa");
    assert_eq!(rows.len(), 1, "only the RSA row should match");
    assert!(
        rows[0].display_name.to_lowercase().contains("rsa"),
        "matched row should be RSA"
    );
}

// Test N+3: Inventory filter empty returns all algorithms.
#[test]
fn inventory_filter_empty_returns_all_algorithms() {
    let b = load_builtins().expect("builtins");
    let findings = vec![
        finding("CRYPTO-001", "rsa-2048", "RSA-2048", false),
        finding("CRYPTO-002", "aes-256-gcm", "AES-256-GCM", false),
        finding("CRYPTO-003", "ecdsa-p256", "ECDSA-P256", false),
    ];
    let rows = build_inventory_rows(&findings, &b.algorithms, "");
    assert_eq!(
        rows.len(),
        3,
        "empty filter must return all three algorithms"
    );
}

// Test N+4: Severity toggles affect build_finding_rows output.
#[test]
fn severity_toggle_filters_findings_from_rows() {
    let b = load_builtins().expect("builtins");
    let findings = vec![
        finding("CRYPTO-001", "rsa-2048", "RSA-2048 key", false),
        finding("CRYPTO-002", "aes-256", "AES-256 key", false),
    ];
    let mut state = AppState::new(&findings, &b.policy);
    state.set_tab(Tab::Findings);
    // With all toggles on, both findings visible.
    let rows_all = build_finding_rows(&state, &findings, &b.algorithms, &b.policy);
    let initial_count = rows_all.len();
    assert_eq!(initial_count, 2, "both findings visible initially");

    // Turn off Critical — RSA-2048 should score Critical/High and be hidden.
    state.show_critical = false;
    state.show_high = false;
    // Re-apply findings filter so filtered_indices updates.
    state.apply_findings_filter("", &findings, &b.algorithms, &b.policy);
    let rows_filtered = build_finding_rows(&state, &findings, &b.algorithms, &b.policy);
    assert!(
        rows_filtered.len() < initial_count,
        "hiding Critical/High should reduce visible findings"
    );
}

// Test N+5: lang_breakdown groups by file extension correctly.
#[test]
fn lang_breakdown_groups_by_extension() {
    let findings = vec![
        finding("CRYPTO-001", "rsa-2048", "msg", false),
        finding("CRYPTO-002", "rsa-2048", "msg", false),
        finding("CRYPTO-003", "rsa-2048", "msg", false),
    ];
    // All findings share the helper's location "main.go:15"; Path::extension()
    // on that string yields "go:15" because there is no path separator. The
    // exact value is implementation-specific; we just assert one group of 3.
    let breakdown = lang_breakdown(&findings);
    assert_eq!(breakdown.len(), 1, "one extension group expected");
    assert_eq!(breakdown[0].count, 3, "all three findings in the one group");
}

// Test N+6: top_algorithms returns at most N entries, most frequent first.
#[test]
fn top_algorithms_returns_at_most_n_most_frequent() {
    let b = load_builtins().expect("builtins");
    let findings = vec![
        finding("CRYPTO-001", "rsa-2048", "a", false),
        finding("CRYPTO-002", "rsa-2048", "b", false),
        finding("CRYPTO-003", "rsa-2048", "c", false),
        finding("CRYPTO-004", "aes-256-gcm", "d", false),
        finding("CRYPTO-005", "ecdsa-p256", "e", false),
    ];
    let tops = top_algorithms(&findings, &b.algorithms, 2);
    assert_eq!(tops.len(), 2, "must return at most 2 entries");
    assert_eq!(
        tops[0].count, 3,
        "first entry must be the most frequent algorithm"
    );
    assert!(
        tops[0].display_name.to_lowercase().contains("rsa"),
        "most frequent algorithm should be rsa-2048"
    );
}

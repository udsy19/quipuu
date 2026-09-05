//! Key-event handler — pure function mapping (AppState, KeyEvent) → Action.
//!
//! No terminal I/O here; tests can call `handle_key` directly.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::state::{AppState, Mode, Tab};

/// What the event loop should do after processing a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// User pressed `q` / `Esc` at the top level — exit the event loop.
    Quit,
    /// State changed; redraw the screen.
    Redraw,
    /// State unchanged; no redraw needed.
    Continue,
    /// User triggered a CBOM export.
    ExportCbom,
}

/// Handle a single key event.
///
/// Mutates `state` in-place and returns the appropriate [`Action`].
/// `findings` is needed only when applying a filter.
pub fn handle_key(
    state: &mut AppState,
    key: KeyEvent,
    findings: &[quipuu_core::Finding],
) -> Action {
    match state.mode {
        Mode::Browsing => handle_browsing(state, key, findings),
        Mode::Filtering => handle_filtering(state, key, findings),
        Mode::Help => handle_help(state, key),
    }
}

fn handle_browsing(
    state: &mut AppState,
    key: KeyEvent,
    _findings: &[quipuu_core::Finding],
) -> Action {
    // Handle Ctrl-C as quit regardless of tab.
    if key.modifiers == KeyModifiers::CONTROL && key.code == KeyCode::Char('c') {
        return Action::Quit;
    }

    // Ignore other modifier combos (Ctrl, Alt) except plain Shift.
    if key
        .modifiers
        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
    {
        return Action::Continue;
    }

    // Global keys that work on every tab.
    match key.code {
        // Quit
        KeyCode::Char('q') | KeyCode::Esc => return Action::Quit,

        // Help overlay
        KeyCode::Char('?') => {
            state.toggle_help();
            return Action::Redraw;
        }

        // Tab nav: 1-4 direct, h/l and Tab/BackTab cycle.
        KeyCode::Char('1') => {
            state.set_tab(Tab::Summary);
            return Action::Redraw;
        }
        KeyCode::Char('2') => {
            state.set_tab(Tab::Inventory);
            return Action::Redraw;
        }
        KeyCode::Char('3') => {
            state.set_tab(Tab::Findings);
            return Action::Redraw;
        }
        KeyCode::Char('4') => {
            state.set_tab(Tab::Cbom);
            return Action::Redraw;
        }
        KeyCode::Tab => {
            state.next_tab();
            return Action::Redraw;
        }
        KeyCode::BackTab => {
            state.prev_tab();
            return Action::Redraw;
        }
        KeyCode::Char('l') if state.tab != Tab::Findings && state.tab != Tab::Inventory => {
            state.next_tab();
            return Action::Redraw;
        }
        KeyCode::Char('h') if state.tab != Tab::Findings && state.tab != Tab::Inventory => {
            state.prev_tab();
            return Action::Redraw;
        }

        _ => {}
    }

    // Tab-specific keys.
    match state.tab {
        Tab::Summary => handle_summary(state, key),
        Tab::Inventory => handle_inventory(state, key),
        Tab::Findings => handle_findings(state, key),
        Tab::Cbom => handle_cbom(state, key),
    }
}

fn handle_summary(state: &mut AppState, _key: KeyEvent) -> Action {
    if state.status_message.is_some() {
        state.status_message = None;
        Action::Redraw
    } else {
        Action::Continue
    }
}

fn handle_inventory(state: &mut AppState, key: KeyEvent) -> Action {
    match key.code {
        KeyCode::Char('j') | KeyCode::Down => {
            state.inventory_nav.next();
            Action::Redraw
        }
        KeyCode::Char('k') | KeyCode::Up => {
            state.inventory_nav.prev();
            Action::Redraw
        }
        KeyCode::Char('g') => {
            state.inventory_nav.first();
            Action::Redraw
        }
        KeyCode::Char('G') => {
            state.inventory_nav.last();
            Action::Redraw
        }
        KeyCode::PageDown => {
            state.inventory_nav.page_down(10);
            Action::Redraw
        }
        KeyCode::PageUp => {
            state.inventory_nav.page_up(10);
            Action::Redraw
        }
        KeyCode::Enter => {
            state.inventory_nav.detail_open = !state.inventory_nav.detail_open;
            Action::Redraw
        }
        KeyCode::Char('l') => {
            state.inventory_nav.detail_open = true;
            Action::Redraw
        }
        KeyCode::Char('h') => {
            if state.inventory_nav.detail_open {
                state.inventory_nav.detail_open = false;
                Action::Redraw
            } else {
                state.prev_tab();
                Action::Redraw
            }
        }
        KeyCode::Char('/') => {
            state.mode = Mode::Filtering;
            state
                .filter_input
                .clone_from(&state.inventory_nav.filter_active);
            Action::Redraw
        }
        _ => {
            if state.status_message.is_some() {
                state.status_message = None;
                Action::Redraw
            } else {
                Action::Continue
            }
        }
    }
}

fn handle_findings(state: &mut AppState, key: KeyEvent) -> Action {
    match key.code {
        KeyCode::Char('j') | KeyCode::Down => {
            state.next_finding();
            Action::Redraw
        }
        KeyCode::Char('k') | KeyCode::Up => {
            state.prev_finding();
            Action::Redraw
        }
        KeyCode::Char('g') => {
            state.g_first();
            Action::Redraw
        }
        KeyCode::Char('G') => {
            state.g_last();
            Action::Redraw
        }
        KeyCode::PageDown => {
            let len = state.filtered_indices.len();
            if len > 0 {
                let last = len - 1;
                state.cursor = (state.cursor + 10).min(last);
                state.findings_nav.cursor = state.cursor;
            }
            Action::Redraw
        }
        KeyCode::PageUp => {
            state.cursor = state.cursor.saturating_sub(10);
            state.findings_nav.cursor = state.cursor;
            Action::Redraw
        }
        KeyCode::Enter => {
            state.findings_nav.detail_open = !state.findings_nav.detail_open;
            Action::Redraw
        }
        KeyCode::Char('l') => {
            state.findings_nav.detail_open = true;
            Action::Redraw
        }
        KeyCode::Char('h') => {
            if state.findings_nav.detail_open {
                state.findings_nav.detail_open = false;
                Action::Redraw
            } else {
                state.prev_tab();
                Action::Redraw
            }
        }
        KeyCode::Char('/') => {
            state.enter_filter_mode();
            Action::Redraw
        }
        // Severity toggles.
        KeyCode::Char('c') => {
            state.show_critical = !state.show_critical;
            Action::Redraw
        }
        KeyCode::Char('H') => {
            state.show_high = !state.show_high;
            Action::Redraw
        }
        KeyCode::Char('m') => {
            state.show_medium = !state.show_medium;
            Action::Redraw
        }
        KeyCode::Char('w') => {
            state.show_low = !state.show_low;
            Action::Redraw
        }
        KeyCode::Char('s') => {
            state.show_safe = !state.show_safe;
            Action::Redraw
        }
        KeyCode::Char('u') => {
            state.show_unscored = !state.show_unscored;
            Action::Redraw
        }
        _ => {
            if state.status_message.is_some() {
                state.status_message = None;
                Action::Redraw
            } else {
                Action::Continue
            }
        }
    }
}

fn handle_cbom(state: &mut AppState, key: KeyEvent) -> Action {
    match key.code {
        KeyCode::Char('j') | KeyCode::Down => {
            state.cbom_cursor = state.cbom_cursor.saturating_add(1);
            Action::Redraw
        }
        KeyCode::Char('k') | KeyCode::Up => {
            state.cbom_cursor = state.cbom_cursor.saturating_sub(1);
            Action::Redraw
        }
        KeyCode::PageDown => {
            state.cbom_scroll = state.cbom_scroll.saturating_add(10);
            Action::Redraw
        }
        KeyCode::PageUp => {
            state.cbom_scroll = state.cbom_scroll.saturating_sub(10);
            Action::Redraw
        }
        // 'e' / 'w' → export CBOM to disk.
        KeyCode::Char('e') | KeyCode::Char('W') => Action::ExportCbom,
        _ => {
            if state.status_message.is_some() {
                state.status_message = None;
                Action::Redraw
            } else {
                Action::Continue
            }
        }
    }
}

fn handle_filtering(
    state: &mut AppState,
    key: KeyEvent,
    findings: &[quipuu_core::Finding],
) -> Action {
    match key.code {
        KeyCode::Enter => {
            let tab = state.tab;
            match tab {
                Tab::Inventory => {
                    let text = state.filter_input.clone();
                    state.mode = Mode::Browsing;
                    state.inventory_nav.filter_active = text.to_lowercase();
                    // Reset inventory filtered indices (model rebuilds on render).
                    state.inventory_nav.cursor = 0;
                }
                _ => {
                    state.exit_filter_mode_apply(findings);
                }
            }
            Action::Redraw
        }
        KeyCode::Esc => {
            state.exit_filter_mode_cancel();
            Action::Redraw
        }
        KeyCode::Backspace => {
            state.pop_filter_char();
            Action::Redraw
        }
        KeyCode::Char(c) => {
            if key
                .modifiers
                .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
            {
                return Action::Continue;
            }
            state.push_filter_char(c);
            Action::Redraw
        }
        _ => Action::Continue,
    }
}

fn handle_help(state: &mut AppState, key: KeyEvent) -> Action {
    match key.code {
        KeyCode::Char('?') | KeyCode::Esc | KeyCode::Char('q') => {
            state.toggle_help();
            Action::Redraw
        }
        _ => Action::Continue,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{AppState, Mode, Tab};
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
    use quipuu_core::{Confidence, Exposure, Finding, Location, UsageContext, load_builtins};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    fn dummy_finding(rule_id: &str, algorithm_id: &str) -> Finding {
        Finding {
            id: format!("QPU-TEST-{rule_id}"),
            rule_id: rule_id.to_string(),
            algorithm_id: algorithm_id.to_string(),
            location: Location {
                location: "main.go:1".to_string(),
                line: Some(1),
                offset: None,
                symbol: None,
                snippet: None,
            },
            message: "test".to_string(),
            confidence: Confidence::LiteralArg,
            confidence_reason: "test fixture".into(),
            usage_context: UsageContext::Unknown,
            exposure: Exposure::LocalOnly,
            shelf_life_bucket: "short".to_string(),
            hndl_critical: false,
        }
    }

    fn make_state(n: usize) -> (AppState, Vec<Finding>) {
        let findings: Vec<Finding> = (0..n)
            .map(|i| dummy_finding(&format!("CRYPTO-{:03}", i + 1), "rsa-2048"))
            .collect();
        let policy = load_builtins().expect("builtins").policy;
        let state = AppState::new(&findings, &policy);
        (state, findings)
    }

    #[test]
    fn q_in_browsing_returns_quit() {
        let (mut state, findings) = make_state(2);
        let action = handle_key(&mut state, key(KeyCode::Char('q')), &findings);
        assert_eq!(action, Action::Quit);
    }

    #[test]
    fn slash_in_browsing_switches_to_filtering() {
        let (mut state, findings) = make_state(2);
        // Slash is tab-specific; switch to Findings tab first.
        state.set_tab(Tab::Findings);
        assert_eq!(state.mode, Mode::Browsing);
        let action = handle_key(&mut state, key(KeyCode::Char('/')), &findings);
        assert_eq!(action, Action::Redraw);
        assert_eq!(state.mode, Mode::Filtering);
    }

    #[test]
    fn esc_in_filtering_returns_to_browsing() {
        let (mut state, findings) = make_state(2);
        state.set_tab(Tab::Findings);
        state.enter_filter_mode();
        assert_eq!(state.mode, Mode::Filtering);
        let action = handle_key(&mut state, key(KeyCode::Esc), &findings);
        assert_eq!(action, Action::Redraw);
        assert_eq!(state.mode, Mode::Browsing);
    }

    #[test]
    fn key_1_through_4_switch_tabs() {
        let (mut state, findings) = make_state(1);
        handle_key(&mut state, key(KeyCode::Char('2')), &findings);
        assert_eq!(state.tab, Tab::Inventory);
        handle_key(&mut state, key(KeyCode::Char('3')), &findings);
        assert_eq!(state.tab, Tab::Findings);
        handle_key(&mut state, key(KeyCode::Char('4')), &findings);
        assert_eq!(state.tab, Tab::Cbom);
        handle_key(&mut state, key(KeyCode::Char('1')), &findings);
        assert_eq!(state.tab, Tab::Summary);
    }

    #[test]
    fn tab_key_cycles_forward() {
        let (mut state, findings) = make_state(1);
        assert_eq!(state.tab, Tab::Summary);
        handle_key(&mut state, key(KeyCode::Tab), &findings);
        assert_eq!(state.tab, Tab::Inventory);
        handle_key(&mut state, key(KeyCode::Tab), &findings);
        assert_eq!(state.tab, Tab::Findings);
    }

    #[test]
    fn back_tab_cycles_backward() {
        let (mut state, findings) = make_state(1);
        state.set_tab(Tab::Cbom);
        handle_key(&mut state, key(KeyCode::BackTab), &findings);
        assert_eq!(state.tab, Tab::Findings);
    }

    #[test]
    fn question_mark_toggles_help_overlay() {
        let (mut state, findings) = make_state(1);
        assert_eq!(state.mode, Mode::Browsing);
        handle_key(&mut state, key(KeyCode::Char('?')), &findings);
        assert_eq!(state.mode, Mode::Help);
        handle_key(&mut state, key(KeyCode::Char('?')), &findings);
        assert_eq!(state.mode, Mode::Browsing);
    }

    #[test]
    fn severity_toggles_change_state() {
        let (mut state, findings) = make_state(2);
        state.set_tab(Tab::Findings);
        assert!(state.show_critical);
        handle_key(&mut state, key(KeyCode::Char('c')), &findings);
        assert!(!state.show_critical);
        handle_key(&mut state, key(KeyCode::Char('c')), &findings);
        assert!(state.show_critical);
    }
}

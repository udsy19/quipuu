//! Key-event handler — pure function mapping (AppState, KeyEvent) → Action.
//!
//! No terminal I/O here; tests can call `handle_key` directly.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::state::{AppState, Mode};

/// What the event loop should do after processing a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// User pressed `q` / `Esc` at the top level — exit the event loop.
    Quit,
    /// State changed; redraw the screen.
    Redraw,
    /// State unchanged; no redraw needed.
    Continue,
}

/// Handle a single key event.
///
/// Mutates `state` in-place and returns the appropriate [`Action`].
/// `findings` is needed only when applying a filter.
pub fn handle_key(
    state: &mut AppState,
    key: KeyEvent,
    findings: &[cryptoscope_core::Finding],
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
    _findings: &[cryptoscope_core::Finding],
) -> Action {
    // Ignore key events with modifiers (Ctrl, Alt) unless it's plain Shift.
    if key
        .modifiers
        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
    {
        return Action::Continue;
    }

    match key.code {
        // Quit
        KeyCode::Char('q') | KeyCode::Esc => Action::Quit,

        // Navigation
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

        // Filter mode
        KeyCode::Char('/') => {
            state.enter_filter_mode();
            Action::Redraw
        }

        // Help overlay
        KeyCode::Char('?') => {
            state.toggle_help();
            Action::Redraw
        }

        // Export (stub)
        KeyCode::Char('e') => {
            state.status_message = Some(
                "Export from TUI: TODO — exit and use `cryptoscope report` for v1".to_string(),
            );
            Action::Redraw
        }

        // Clear status message on any other key
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
    findings: &[cryptoscope_core::Finding],
) -> Action {
    match key.code {
        KeyCode::Enter => {
            state.exit_filter_mode_apply(findings);
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
            // Ignore modifier combos.
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
    use crate::state::{AppState, Mode};
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
    use cryptoscope_core::{Confidence, Exposure, Finding, Location, UsageContext, load_builtins};

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
        assert_eq!(state.mode, Mode::Browsing);
        let action = handle_key(&mut state, key(KeyCode::Char('/')), &findings);
        assert_eq!(action, Action::Redraw);
        assert_eq!(state.mode, Mode::Filtering);
    }

    #[test]
    fn esc_in_filtering_returns_to_browsing() {
        let (mut state, findings) = make_state(2);
        state.enter_filter_mode();
        assert_eq!(state.mode, Mode::Filtering);
        let action = handle_key(&mut state, key(KeyCode::Esc), &findings);
        assert_eq!(action, Action::Redraw);
        assert_eq!(state.mode, Mode::Browsing);
    }
}

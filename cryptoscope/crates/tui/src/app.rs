//! Terminal setup + event loop.
//!
//! This module is the only place that touches crossterm / ratatui terminal
//! initialisation.  All rendering and state logic lives in render.rs,
//! model.rs, and state.rs so they can be unit-tested without a real TTY.

use std::io;
use std::time::Duration;

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
};

use crate::{
    Tui, TuiError,
    event::Action,
    event::handle_key,
    model::{build_finding_detail, build_finding_rows},
    render::{
        is_small_terminal, render_filter_bar, render_header, render_help_overlay, render_kpi,
        render_left_pane, render_right_pane, render_status_bar,
    },
    state::kpi_total as compute_kpi,
};

/// Run the main event loop.
pub fn run(mut app: Tui) -> Result<(), TuiError> {
    // Check we have a TTY before clobbering the terminal.
    if !crossterm::tty::IsTty::is_tty(&io::stdout()) {
        return Err(TuiError::NoTty(
            "stdout is not a TTY — use --no-tui or --format json for headless output".to_string(),
        ));
    }

    enable_raw_mode().map_err(|e| TuiError::NoTty(e.to_string()))?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture).map_err(TuiError::Io)?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend).map_err(TuiError::Io)?;

    let res = event_loop(&mut terminal, &mut app);

    // Restore terminal unconditionally.
    let _ = disable_raw_mode();
    let _ = execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    );
    let _ = terminal.show_cursor();

    res
}

fn event_loop(
    terminal: &mut ratatui::Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut Tui,
) -> Result<(), TuiError> {
    loop {
        let kpi = compute_kpi(&app.findings, &app.algorithms, &app.policy);

        terminal
            .draw(|frame| {
                draw(frame, app, &kpi);
            })
            .map_err(TuiError::Io)?;

        // Poll with a short timeout so the UI stays responsive.
        if event::poll(Duration::from_millis(50)).map_err(TuiError::Io)?
            && let Event::Key(key) = event::read().map_err(TuiError::Io)?
        {
            // Only handle Press/Repeat events; ignore Release.
            if key.kind == KeyEventKind::Press || key.kind == KeyEventKind::Repeat {
                let action = handle_key(&mut app.state, key, &app.findings);
                match action {
                    Action::Quit => return Ok(()),
                    Action::Redraw | Action::Continue => {}
                }
            }
        }
    }
}

fn draw(frame: &mut ratatui::Frame, app: &Tui, kpi: &crate::state::Kpi) {
    let area = frame.area();

    // Header (1 line) + KPI strip (1 line) + main area + filter bar (1 line) + status (1 line).
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // header
            Constraint::Length(1), // kpi strip
            Constraint::Min(0),    // main panes
            Constraint::Length(1), // filter bar
            Constraint::Length(1), // status bar
        ])
        .split(area);

    // Header
    frame.render_widget(
        render_header("cryptoscope", env!("CARGO_PKG_VERSION")),
        outer[0],
    );

    // KPI strip
    frame.render_widget(render_kpi(kpi, &app.policy), outer[1]);

    // Main pane area
    let main_area = outer[2];

    if is_small_terminal(&main_area) {
        draw_stacked(frame, app, main_area);
    } else {
        draw_side_by_side(frame, app, main_area);
    }

    // Filter bar
    frame.render_widget(render_filter_bar(&app.state), outer[3]);

    // Status bar
    frame.render_widget(render_status_bar(&app.state), outer[4]);

    // Help overlay — centred floating box.
    if app.state.mode == crate::state::Mode::Help {
        let help_area = centered_rect(60, 80, area);
        frame.render_widget(render_help_overlay(help_area), help_area);
    }
}

fn draw_side_by_side(frame: &mut ratatui::Frame, app: &Tui, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(area);

    let rows = build_finding_rows(&app.state, &app.findings, &app.algorithms, &app.policy);
    let (list, mut list_state) = render_left_pane(&rows, app.state.cursor);
    frame.render_stateful_widget(list, cols[0], &mut list_state);

    if let Some(idx) = app.state.selected_finding_index() {
        let detail = build_finding_detail(&app.findings[idx], &app.algorithms, &app.policy);
        frame.render_widget(render_right_pane(&detail), cols[1]);
    }
}

fn draw_stacked(frame: &mut ratatui::Frame, app: &Tui, area: Rect) {
    // In small-terminal mode: top half = list, bottom half = detail.
    let half = area.height / 2;
    let rows_area = Rect {
        x: area.x,
        y: area.y,
        width: area.width,
        height: half,
    };
    let detail_area = Rect {
        x: area.x,
        y: area.y + half,
        width: area.width,
        height: area.height - half,
    };

    let rows = build_finding_rows(&app.state, &app.findings, &app.algorithms, &app.policy);
    let (list, mut list_state) = render_left_pane(&rows, app.state.cursor);
    frame.render_stateful_widget(list, rows_area, &mut list_state);

    if let Some(idx) = app.state.selected_finding_index() {
        let detail = build_finding_detail(&app.findings[idx], &app.algorithms, &app.policy);
        frame.render_widget(render_right_pane(&detail), detail_area);
    }
}

/// Create a centred rectangle of `percent_x`% × `percent_y`% inside `r`.
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

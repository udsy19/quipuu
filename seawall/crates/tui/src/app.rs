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
use seawall_core::Finding;

use crate::{
    Tui, TuiError,
    event::{Action, handle_key},
    model::{
        build_cbom_families, build_finding_detail, build_finding_rows, build_inventory_rows,
        findings_for_algorithm, lang_breakdown, top_algorithms,
    },
    render::{
        is_small_terminal, render_cbom_tab, render_filter_bar, render_header, render_help_overlay,
        render_inventory_tab, render_kpi, render_left_pane, render_right_pane, render_status_bar,
        render_summary_tab, render_tab_bar,
    },
    state::{Kpi, Tab, kpi_total as compute_kpi},
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

    // Initialise inventory nav with the number of distinct algorithms found.
    let inv_count = build_inventory_rows(&app.findings, &app.algorithms, "").len();
    app.state.inventory_nav = crate::state::TabNav::init(inv_count);

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
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
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
                    Action::ExportCbom => export_cbom(app),
                    Action::Redraw | Action::Continue => {}
                }
            }
        }
    }
}

fn export_cbom(app: &mut Tui) {
    use seawall_cbom::emit::ScanTarget;
    use seawall_cbom::{EmitOptions, emit_cbom_json};

    let opts = EmitOptions::new(
        ScanTarget {
            name: "seawall-scan".to_string(),
            version: None,
        },
        // Static timestamp keeps CBOM export deterministic without pulling in chrono.
        // Consumers can re-scan to get a timestamped export.
        "2026-01-01T00:00:00Z".to_string(),
    );

    match emit_cbom_json(&app.findings, &app.algorithms, &opts) {
        Ok(json) => {
            let path = "cbom.json";
            match std::fs::write(path, json) {
                Ok(()) => {
                    app.state.status_message = Some(format!("CBOM written to {path}"));
                }
                Err(e) => {
                    app.state.status_message = Some(format!("Write error: {e}"));
                }
            }
        }
        Err(e) => {
            app.state.status_message = Some(format!("CBOM error: {e}"));
        }
    }
}

fn draw(frame: &mut ratatui::Frame, app: &Tui, kpi: &Kpi) {
    let area = frame.area();

    // Layout: header(2) + tab-bar(2) + kpi(1) + main + filter(1) + status(1).
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2), // header
            Constraint::Length(2), // tab bar
            Constraint::Length(1), // kpi strip
            Constraint::Min(0),    // main content
            Constraint::Length(1), // filter bar
            Constraint::Length(1), // status bar
        ])
        .split(area);

    frame.render_widget(
        render_header("seawall", env!("CARGO_PKG_VERSION")),
        outer[0],
    );
    frame.render_widget(render_tab_bar(&app.state), outer[1]);
    frame.render_widget(render_kpi(kpi, &app.policy), outer[2]);

    let main_area = outer[3];
    match app.state.tab {
        Tab::Summary => draw_summary(frame, app, kpi, main_area),
        Tab::Inventory => draw_inventory(frame, app, main_area),
        Tab::Findings => {
            if is_small_terminal(&main_area) {
                draw_findings_stacked(frame, app, main_area);
            } else {
                draw_findings_side_by_side(frame, app, main_area);
            }
        }
        Tab::Cbom => draw_cbom(frame, app, main_area),
    }

    frame.render_widget(render_filter_bar(&app.state), outer[4]);
    frame.render_widget(render_status_bar(&app.state), outer[5]);

    if app.state.mode == crate::state::Mode::Help {
        let help_area = centered_rect(70, 85, area);
        frame.render_widget(render_help_overlay(help_area), help_area);
    }
}

fn draw_summary(frame: &mut ratatui::Frame, app: &Tui, kpi: &Kpi, area: Rect) {
    let tops = top_algorithms(&app.findings, &app.algorithms, 5);
    let langs = lang_breakdown(&app.findings);
    let widget = render_summary_tab(kpi, &tops, &langs, &app.policy, "<scan target>");
    frame.render_widget(widget, area);
}

fn draw_inventory(frame: &mut ratatui::Frame, app: &Tui, area: Rect) {
    let filter = app.state.inventory_nav.filter_active.as_str();
    let rows = build_inventory_rows(&app.findings, &app.algorithms, filter);

    let cursor = app
        .state
        .inventory_nav
        .cursor
        .min(rows.len().saturating_sub(1));

    let detail_findings: Vec<&Finding> = if app.state.inventory_nav.detail_open {
        rows.get(cursor)
            .map(|r| findings_for_algorithm(&r.algorithm_id, &app.findings))
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    let (table, mut table_state, maybe_list, maybe_list_state) = render_inventory_tab(
        &rows,
        cursor,
        app.state.inventory_nav.detail_open,
        &detail_findings,
        &app.algorithms,
    );

    if let (Some(list), Some(mut list_state)) = (maybe_list, maybe_list_state) {
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
            .split(area);
        frame.render_stateful_widget(table, cols[0], &mut table_state);
        frame.render_stateful_widget(list, cols[1], &mut list_state);
    } else {
        frame.render_stateful_widget(table, area, &mut table_state);
    }
}

fn draw_findings_side_by_side(frame: &mut ratatui::Frame, app: &Tui, area: Rect) {
    let rows = build_finding_rows(&app.state, &app.findings, &app.algorithms, &app.policy);
    let (list, mut list_state) = render_left_pane(&rows, app.state.cursor);

    if app.state.findings_nav.detail_open {
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
            .split(area);
        frame.render_stateful_widget(list, cols[0], &mut list_state);
        if let Some(idx) = app.state.selected_finding_index() {
            let detail = build_finding_detail(&app.findings[idx], &app.algorithms, &app.policy);
            frame.render_widget(render_right_pane(&detail), cols[1]);
        }
    } else {
        frame.render_stateful_widget(list, area, &mut list_state);
    }
}

fn draw_findings_stacked(frame: &mut ratatui::Frame, app: &Tui, area: Rect) {
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

fn draw_cbom(frame: &mut ratatui::Frame, app: &Tui, area: Rect) {
    let families = build_cbom_families(&app.findings, &app.algorithms);
    let widget = render_cbom_tab(&families, app.state.cbom_scroll);
    frame.render_widget(widget, area);
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

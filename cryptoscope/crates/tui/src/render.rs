//! Pure ratatui widget constructors.
//!
//! Every function takes immutable references and returns owned ratatui types.
//! No terminal I/O; safe to call in tests (with a dummy Buffer if desired).

use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
};

use cryptoscope_core::Severity;

use crate::{
    Tui,
    model::{FindingDetail, FindingRow, ScoreBreakdown, build_kpi_line, score_bar, use_color},
    state::{AppState, Kpi, Mode, days_to_deadline},
};

// ---------------------------------------------------------------------------
// Colour palette (degraded when NO_COLOR)
// ---------------------------------------------------------------------------

fn sev_color(sev: Severity) -> Color {
    if !use_color() {
        return Color::Reset;
    }
    match sev {
        Severity::Critical => Color::Red,
        Severity::High => Color::LightRed,
        Severity::Medium => Color::Yellow,
        Severity::Low => Color::Cyan,
        Severity::Safe => Color::Green,
    }
}

fn accent() -> Color {
    if use_color() {
        Color::LightBlue
    } else {
        Color::Reset
    }
}

fn dim() -> Style {
    if use_color() {
        Style::default().fg(Color::DarkGray)
    } else {
        Style::default()
    }
}

// ---------------------------------------------------------------------------
// Header pane
// ---------------------------------------------------------------------------

/// Render the header bar paragraph.
pub fn render_header<'a>(tool_name: &'a str, tool_version: &'a str) -> Paragraph<'a> {
    let left = Span::styled(
        format!(" {tool_name} v{tool_version} "),
        Style::default()
            .fg(if use_color() {
                Color::White
            } else {
                Color::Reset
            })
            .add_modifier(Modifier::BOLD),
    );
    let right = Span::styled(" cryptoscope — quantum-safe crypto scanner ", dim());
    Paragraph::new(Line::from(vec![left, right])).block(Block::default().borders(Borders::BOTTOM))
}

// ---------------------------------------------------------------------------
// KPI strip
// ---------------------------------------------------------------------------

pub fn render_kpi<'a>(kpi: &'a Kpi, policy: &'a cryptoscope_core::Policy) -> Paragraph<'a> {
    let days = days_to_deadline(policy);
    let line = build_kpi_line(kpi, days);
    Paragraph::new(line).style(Style::default().add_modifier(Modifier::BOLD))
}

// ---------------------------------------------------------------------------
// Left pane — findings list
// ---------------------------------------------------------------------------

/// Build a `List` widget + matching `ListState` for the findings pane.
pub fn render_left_pane<'a>(rows: &'a [FindingRow], cursor: usize) -> (List<'a>, ListState) {
    let items: Vec<ListItem> = rows
        .iter()
        .map(|row| {
            let badge_style = Style::default()
                .fg(sev_color(row.severity))
                .add_modifier(Modifier::BOLD);
            let hndl_tag = if row.hndl { " !" } else { "  " };
            let line = Line::from(vec![
                Span::styled(format!("[{}]", row.badge), badge_style),
                Span::raw(format!(
                    "{} {} {} {}",
                    hndl_tag, row.rule_id, row.location, row.algorithm_display
                )),
            ]);
            ListItem::new(line)
        })
        .collect();

    let list = List::new(items)
        .block(Block::default().title(" Findings ").borders(Borders::ALL))
        .highlight_style(
            Style::default()
                .fg(if use_color() {
                    Color::Black
                } else {
                    Color::Reset
                })
                .bg(if use_color() {
                    Color::White
                } else {
                    Color::Reset
                })
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    let mut list_state = ListState::default();
    if !rows.is_empty() {
        list_state.select(Some(cursor));
    }

    (list, list_state)
}

// ---------------------------------------------------------------------------
// Right pane — finding detail
// ---------------------------------------------------------------------------

pub fn render_right_pane(detail: &FindingDetail) -> Paragraph<'_> {
    let mut lines: Vec<Line> = Vec::new();

    // Rule ID + algorithm
    lines.push(Line::from(vec![
        Span::styled("Rule:  ", dim()),
        Span::raw(detail.rule_id.clone()),
        Span::raw("  "),
        Span::styled("Algorithm: ", dim()),
        Span::styled(
            detail.algorithm_display.clone(),
            Style::default().fg(accent()).add_modifier(Modifier::BOLD),
        ),
    ]));

    // HNDL badge
    if detail.hndl {
        lines.push(Line::from(Span::styled(
            " !! HNDL-CRITICAL !! ",
            Style::default()
                .fg(if use_color() {
                    Color::White
                } else {
                    Color::Reset
                })
                .bg(if use_color() {
                    Color::Red
                } else {
                    Color::Reset
                })
                .add_modifier(Modifier::BOLD),
        )));
    }

    // Location
    lines.push(Line::from(vec![
        Span::styled("Location: ", dim()),
        Span::raw(detail.location.clone()),
        if let Some(ln) = detail.line {
            Span::raw(format!(":{ln}"))
        } else {
            Span::raw("")
        },
    ]));

    // Message
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("Message: ", dim()),
        Span::raw(detail.message.clone()),
    ]));

    // Snippet
    if let Some(snippet) = &detail.snippet {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("Snippet:", dim())));
        lines.push(Line::from(Span::styled(
            format!("  {snippet}"),
            Style::default().add_modifier(Modifier::DIM),
        )));
    }

    // Replacement
    lines.push(Line::from(""));
    if let Some(repl) = &detail.replacement_display {
        lines.push(Line::from(vec![
            Span::styled("Recommended replacement: ", dim()),
            Span::styled(
                repl.clone(),
                Style::default().fg(if use_color() {
                    Color::Green
                } else {
                    Color::Reset
                }),
            ),
        ]));
    } else {
        lines.push(Line::from(Span::styled("No replacement listed.", dim())));
    }

    // Score breakdown
    if let Some(score) = &detail.score {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!(
                "Risk score: {}/100 ({})",
                score.total,
                fmt_sev(score.severity)
            ),
            Style::default()
                .fg(sev_color(score.severity))
                .add_modifier(Modifier::BOLD),
        )));
        lines.extend(score_lines(score));
    }

    Paragraph::new(lines)
        .block(Block::default().title(" Detail ").borders(Borders::ALL))
        .wrap(Wrap { trim: false })
}

fn fmt_sev(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical => "Critical",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
        Severity::Safe => "Safe",
    }
}

fn score_lines(score: &ScoreBreakdown) -> Vec<Line<'static>> {
    let bar_width = 10usize;
    vec![
        score_line(
            "  AlgoVuln  ",
            score.algorithm_vulnerability,
            score.av_max,
            bar_width,
        ),
        score_line("  UsageCtx  ", score.usage_context, score.uc_max, bar_width),
        score_line(
            "  ShelfLife ",
            score.data_shelf_life,
            score.ds_max,
            bar_width,
        ),
        score_line("  Exposure  ", score.exposure, score.ex_max, bar_width),
        score_line(
            "  Confidence",
            score.detection_confidence,
            score.dc_max,
            bar_width,
        ),
    ]
}

fn score_line(label: &'static str, value: u8, max: u8, width: usize) -> Line<'static> {
    let bar = score_bar(value, max, width);
    Line::from(vec![
        Span::styled(label, dim()),
        Span::raw(" "),
        Span::raw(bar),
    ])
}

// ---------------------------------------------------------------------------
// Filter bar
// ---------------------------------------------------------------------------

pub fn render_filter_bar(state: &AppState) -> Paragraph<'_> {
    let (prefix, text) = match state.mode {
        Mode::Filtering => ("Filter: ", state.filter_input.as_str()),
        _ => ("Filter: ", state.filter_active.as_str()),
    };
    let cursor = if state.mode == Mode::Filtering {
        "_"
    } else {
        ""
    };
    Paragraph::new(format!("{}{}{}", prefix, text, cursor)).style(Style::default().fg(accent()))
}

// ---------------------------------------------------------------------------
// Status bar
// ---------------------------------------------------------------------------

pub fn render_status_bar<'a>(state: &'a AppState) -> Paragraph<'a> {
    let text = state
        .status_message
        .as_deref()
        .unwrap_or("j/k navigate  g/G first/last  / filter  e export  ? help  q quit");
    Paragraph::new(text).style(dim())
}

// ---------------------------------------------------------------------------
// Help overlay
// ---------------------------------------------------------------------------

pub fn render_help_overlay(_area: Rect) -> Paragraph<'static> {
    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  Key Bindings  ",
            Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
        )),
        Line::from(""),
        Line::from("  j / ↓        Next finding"),
        Line::from("  k / ↑        Previous finding"),
        Line::from("  g            First finding"),
        Line::from("  G            Last finding"),
        Line::from("  /            Enter filter mode"),
        Line::from("  Enter        Apply filter"),
        Line::from("  Esc          Cancel filter / quit help"),
        Line::from("  e            Export instructions"),
        Line::from("  ?            Toggle this help overlay"),
        Line::from("  q / Esc      Quit"),
        Line::from(""),
        Line::from(Span::styled(
            "  Press ? or Esc to close  ",
            Style::default().add_modifier(Modifier::DIM),
        )),
    ];
    Paragraph::new(lines).block(
        Block::default()
            .title(" Help ")
            .borders(Borders::ALL)
            .style(Style::default().fg(if use_color() {
                Color::White
            } else {
                Color::Reset
            })),
    )
}

// ---------------------------------------------------------------------------
// Small-terminal stacked view
// ---------------------------------------------------------------------------

/// Returns `true` if the terminal is too small for the side-by-side layout.
pub fn is_small_terminal(area: &Rect) -> bool {
    area.width < 80 || area.height < 24
}

// ---------------------------------------------------------------------------
// Layout helper: split finding list lines
// ---------------------------------------------------------------------------

/// Format a single row as a string for the small-terminal stacked view.
pub fn row_to_string(row: &FindingRow) -> String {
    format!(
        "[{}]  {} {} {}{}",
        row.badge,
        row.rule_id,
        row.location,
        row.algorithm_display,
        if row.hndl { " !" } else { "" }
    )
}

// Keep the Tui import used (suppress dead-code when cfg(test) is false).
const _: () = {
    let _ = std::mem::size_of::<Tui>();
};

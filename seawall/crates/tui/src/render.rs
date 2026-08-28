//! Pure ratatui widget constructors.
//!
//! Every function takes immutable references and returns owned ratatui types.
//! No terminal I/O; safe to call in tests.

use ratatui::{
    layout::{Constraint, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, BorderType, Borders, Cell, List, ListItem, ListState, Paragraph, Row, Table,
        TableState, Tabs, Wrap,
    },
};

use seawall_core::{AlgorithmTable, Finding, Policy, QuantumStatus, Severity};

use crate::{
    Tui,
    model::{
        CbomAlgoRow, FindingDetail, FindingRow, InventoryRow, LangBreakdown, ScoreBreakdown,
        TopAlgo, score_bar, use_color,
    },
    state::{AppState, Kpi, Mode, Tab, days_to_deadline},
};

// ---------------------------------------------------------------------------
// Colour palette
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

fn quantum_status_color(qs: QuantumStatus) -> Color {
    if !use_color() {
        return Color::Reset;
    }
    match qs {
        QuantumStatus::BrokenClassically => Color::Red,
        QuantumStatus::BrokenByShor => Color::LightRed,
        QuantumStatus::WeakenedByGrover => Color::Yellow,
        QuantumStatus::QuantumSafe => Color::Green,
        QuantumStatus::PqcFinal => Color::LightGreen,
        QuantumStatus::PqcDraft => Color::LightBlue,
    }
}

fn quantum_status_label(qs: QuantumStatus) -> &'static str {
    match qs {
        QuantumStatus::BrokenClassically => "BrokenClassically",
        QuantumStatus::BrokenByShor => "BrokenByShor    ",
        QuantumStatus::WeakenedByGrover => "WeakenedByGrover",
        QuantumStatus::QuantumSafe => "QuantumSafe     ",
        QuantumStatus::PqcFinal => "PQC-Final       ",
        QuantumStatus::PqcDraft => "PQC-Draft       ",
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

fn highlight_style() -> Style {
    if use_color() {
        Style::default()
            .fg(Color::Black)
            .bg(Color::White)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().add_modifier(Modifier::REVERSED)
    }
}

// ---------------------------------------------------------------------------
// Tab bar
// ---------------------------------------------------------------------------

pub fn render_tab_bar(state: &AppState) -> Tabs<'static> {
    let titles: Vec<Line> = Tab::ALL
        .iter()
        .map(|t| {
            let style = if *t == state.tab {
                Style::default()
                    .fg(if use_color() {
                        Color::White
                    } else {
                        Color::Reset
                    })
                    .add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
            } else {
                dim()
            };
            Line::from(Span::styled(format!(" {} ", t.title()), style))
        })
        .collect();

    Tabs::new(titles)
        .select(state.tab.index())
        .block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_type(BorderType::Plain),
        )
        .highlight_style(
            Style::default()
                .fg(if use_color() {
                    Color::LightBlue
                } else {
                    Color::Reset
                })
                .add_modifier(Modifier::BOLD),
        )
        .divider(Span::styled(" │ ", dim()))
}

// ---------------------------------------------------------------------------
// Header pane
// ---------------------------------------------------------------------------

pub fn render_header<'a>(tool_name: &'a str, tool_version: &'a str) -> Paragraph<'a> {
    let left = Span::styled(
        format!(" ◈ {tool_name} v{tool_version} "),
        Style::default()
            .fg(if use_color() {
                Color::LightBlue
            } else {
                Color::Reset
            })
            .add_modifier(Modifier::BOLD),
    );
    let sep = Span::styled(" │ ", dim());
    let right = Span::styled(
        "quantum-safe crypto scanner",
        Style::default().fg(if use_color() {
            Color::DarkGray
        } else {
            Color::Reset
        }),
    );
    Paragraph::new(Line::from(vec![left, sep, right]))
        .block(Block::default().borders(Borders::BOTTOM))
}

// ---------------------------------------------------------------------------
// KPI strip
// ---------------------------------------------------------------------------

pub fn render_kpi<'a>(kpi: &'a Kpi, policy: &'a Policy) -> Paragraph<'a> {
    let days = days_to_deadline(policy);

    let pct = |n: usize| -> u8 {
        if kpi.total == 0 {
            0u8
        } else {
            ((n as f64 / kpi.total as f64) * 100.0).round() as u8
        }
    };

    let spans = vec![
        Span::raw(" "),
        kpi_badge("✦", kpi.total, Color::White),
        Span::raw("  "),
        kpi_badge("CRIT", kpi.critical, Color::Red),
        Span::raw(" "),
        kpi_badge("HIGH", kpi.high, Color::LightRed),
        Span::raw(" "),
        kpi_badge("MED", kpi.medium, Color::Yellow),
        Span::raw(" "),
        kpi_badge("LOW", kpi.low, Color::Cyan),
        Span::raw(" "),
        kpi_badge("SAFE", kpi.safe, Color::Green),
        Span::raw("  "),
        Span::styled(
            format!("HNDL:{}", kpi.hndl_critical),
            Style::default()
                .fg(if kpi.hndl_critical > 0 {
                    Color::Red
                } else {
                    Color::DarkGray
                })
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(
            format!("Q-Vuln:{}%", pct(kpi.quantum_vulnerable)),
            Style::default().fg(if use_color() {
                Color::Yellow
            } else {
                Color::Reset
            }),
        ),
        Span::raw("  "),
        Span::styled(
            format!("Deadline: {days}d"),
            Style::default().fg(if use_color() {
                Color::DarkGray
            } else {
                Color::Reset
            }),
        ),
    ];

    Paragraph::new(Line::from(spans)).style(Style::default())
}

fn kpi_badge(label: &'static str, value: usize, color: Color) -> Span<'static> {
    let c = if use_color() { color } else { Color::Reset };
    Span::styled(
        format!("{label}:{value}"),
        Style::default().fg(c).add_modifier(Modifier::BOLD),
    )
}

// ---------------------------------------------------------------------------
// Tab 1 — Summary
// ---------------------------------------------------------------------------

pub fn render_summary_tab<'a>(
    kpi: &'a Kpi,
    top_algos: &'a [TopAlgo],
    lang_breakdown: &'a [LangBreakdown],
    policy: &'a Policy,
    scan_target: &'a str,
) -> Paragraph<'a> {
    let mut lines: Vec<Line<'a>> = Vec::new();

    // Header row
    lines.push(Line::from(""));
    lines.push(Line::from(vec![Span::styled(
        "  Scan Summary",
        Style::default()
            .fg(if use_color() {
                Color::LightBlue
            } else {
                Color::Reset
            })
            .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
    )]));
    lines.push(Line::from(""));

    // Target + policy
    lines.push(Line::from(vec![
        Span::styled("  Target : ", dim()),
        Span::raw(scan_target),
    ]));
    lines.push(Line::from(vec![
        Span::styled("  Policy : ", dim()),
        Span::raw(policy.meta.display_name.clone()),
    ]));
    lines.push(Line::from(""));

    // Severity bar
    lines.push(Line::from(vec![Span::styled(
        "  Risk Distribution",
        Style::default().add_modifier(Modifier::BOLD),
    )]));
    lines.push(Line::from(""));
    if kpi.total > 0 {
        let bar_line = build_sev_bar(kpi, 40);
        lines.push(Line::from(vec![Span::raw("  "), Span::raw(bar_line)]));
    }
    lines.push(Line::from(""));

    // Severity counts
    for (label, count, color) in [
        ("Critical", kpi.critical, Color::Red),
        ("High    ", kpi.high, Color::LightRed),
        ("Medium  ", kpi.medium, Color::Yellow),
        ("Low     ", kpi.low, Color::Cyan),
        ("Safe    ", kpi.safe, Color::Green),
    ] {
        let pct = (count * 100).checked_div(kpi.total).unwrap_or(0);
        let c = if use_color() { color } else { Color::Reset };
        lines.push(Line::from(vec![
            Span::raw("    "),
            Span::styled(
                label.to_string(),
                Style::default().fg(c).add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!("  {:>4} ({pct:>3}%)", count)),
        ]));
    }
    lines.push(Line::from(""));

    // HNDL + quantum-vulnerable
    lines.push(Line::from(vec![
        Span::raw("  "),
        Span::styled(
            format!("HNDL-Critical: {}", kpi.hndl_critical),
            Style::default()
                .fg(if kpi.hndl_critical > 0 && use_color() {
                    Color::Red
                } else if use_color() {
                    Color::Green
                } else {
                    Color::Reset
                })
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("   "),
        Span::styled(
            format!(
                "Quantum-Vulnerable: {} of {} ({:.0}%)",
                kpi.quantum_vulnerable,
                kpi.total,
                if kpi.total > 0 {
                    kpi.quantum_vulnerable as f64 / kpi.total as f64 * 100.0
                } else {
                    0.0
                }
            ),
            Style::default().fg(if use_color() {
                Color::Yellow
            } else {
                Color::Reset
            }),
        ),
    ]));
    lines.push(Line::from(""));

    // Top 5 algorithms
    if !top_algos.is_empty() {
        lines.push(Line::from(vec![Span::styled(
            "  Top Algorithms by Count",
            Style::default().add_modifier(Modifier::BOLD),
        )]));
        lines.push(Line::from(""));
        for (i, alg) in top_algos.iter().enumerate() {
            let c = quantum_status_color(alg.quantum_status);
            lines.push(Line::from(vec![
                Span::raw(format!("  {:>2}. ", i + 1)),
                Span::styled(
                    format!("{:<30}", alg.display_name),
                    Style::default().fg(c).add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!("  {} findings", alg.count)),
                Span::raw("  "),
                Span::styled(
                    quantum_status_label(alg.quantum_status).trim().to_string(),
                    Style::default().fg(c),
                ),
            ]));
        }
        lines.push(Line::from(""));
    }

    // Per-language breakdown
    if !lang_breakdown.is_empty() {
        lines.push(Line::from(vec![Span::styled(
            "  By File Extension",
            Style::default().add_modifier(Modifier::BOLD),
        )]));
        lines.push(Line::from(""));
        for b in lang_breakdown.iter().take(10) {
            let bar = mini_bar(b.count, kpi.total, 20);
            lines.push(Line::from(vec![
                Span::raw(format!("    .{:<8} ", b.lang)),
                Span::styled(bar, Style::default().fg(accent())),
                Span::raw(format!(" {}", b.count)),
            ]));
        }
    }

    Paragraph::new(lines)
        .block(
            Block::default()
                .title(" Summary ")
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded),
        )
        .wrap(Wrap { trim: false })
}

fn build_sev_bar(kpi: &Kpi, width: usize) -> String {
    if kpi.total == 0 {
        return format!("[{}]", " ".repeat(width));
    }
    let crit_w = (kpi.critical * width) / kpi.total;
    let high_w = (kpi.high * width) / kpi.total;
    let med_w = (kpi.medium * width) / kpi.total;
    let low_w = (kpi.low * width) / kpi.total;
    let safe_w = width.saturating_sub(crit_w + high_w + med_w + low_w);
    format!(
        "[{}{}{}{}{}]",
        "C".repeat(crit_w),
        "H".repeat(high_w),
        "M".repeat(med_w),
        "L".repeat(low_w),
        ".".repeat(safe_w),
    )
}

fn mini_bar(value: usize, total: usize, width: usize) -> String {
    if total == 0 {
        return " ".repeat(width);
    }
    let filled = (value * width) / total;
    let filled = filled.min(width);
    format!("{}{}", "█".repeat(filled), "░".repeat(width - filled))
}

// ---------------------------------------------------------------------------
// Tab 2 — Inventory
// ---------------------------------------------------------------------------

pub fn render_inventory_tab<'a>(
    rows: &'a [InventoryRow],
    nav_cursor: usize,
    detail_open: bool,
    detail_findings: &'a [&'a Finding],
    algorithms: &'a AlgorithmTable,
) -> (Table<'a>, TableState, Option<List<'a>>, Option<ListState>) {
    let header_cells = [
        "Algorithm",
        "Quantum Status",
        "Family",
        "Count",
        "Files",
        "Replacement",
    ]
    .iter()
    .map(|h| {
        Cell::from(*h).style(
            Style::default()
                .fg(if use_color() {
                    Color::White
                } else {
                    Color::Reset
                })
                .add_modifier(Modifier::BOLD),
        )
    });
    let header_row = Row::new(header_cells)
        .style(Style::default().add_modifier(Modifier::UNDERLINED))
        .height(1);

    let table_rows: Vec<Row> = rows
        .iter()
        .map(|row| {
            let qs_color = quantum_status_color(row.quantum_status);
            Row::new(vec![
                Cell::from(row.display_name.clone())
                    .style(Style::default().fg(qs_color).add_modifier(Modifier::BOLD)),
                Cell::from(quantum_status_label(row.quantum_status).trim().to_string())
                    .style(Style::default().fg(qs_color)),
                Cell::from(row.family.clone()),
                Cell::from(row.count.to_string()),
                Cell::from(row.file_count.to_string()),
                Cell::from(row.replacement_display.clone()).style(Style::default().fg(
                    if use_color() {
                        Color::Green
                    } else {
                        Color::Reset
                    },
                )),
            ])
            .height(1)
        })
        .collect();

    let widths = [
        Constraint::Percentage(22),
        Constraint::Percentage(18),
        Constraint::Percentage(13),
        Constraint::Length(7),
        Constraint::Length(7),
        Constraint::Percentage(22),
    ];

    let table = Table::new(table_rows, widths)
        .header(header_row)
        .block(
            Block::default()
                .title(format!(" Inventory ({} algorithms) ", rows.len()))
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded),
        )
        .row_highlight_style(highlight_style())
        .highlight_symbol("▶ ");

    let mut table_state = TableState::default();
    if !rows.is_empty() {
        table_state.select(Some(nav_cursor));
    }

    // Right-pane: finding sites for the selected algorithm.
    if detail_open && !detail_findings.is_empty() {
        let items: Vec<ListItem> = detail_findings
            .iter()
            .map(|f| {
                let alg_display = algorithms
                    .get(&f.algorithm_id)
                    .map(|a| a.display_name.as_str())
                    .unwrap_or(&f.algorithm_id);
                let loc = match f.location.line {
                    Some(ln) => format!("{}:{}", f.location.location, ln),
                    None => f.location.location.clone(),
                };
                let line = Line::from(vec![
                    Span::styled(format!("  {alg_display}"), Style::default().fg(accent())),
                    Span::raw("  "),
                    Span::raw(loc),
                ]);
                ListItem::new(line)
            })
            .collect();
        let list = List::new(items).block(
            Block::default()
                .title(" Occurrences ")
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded),
        );
        let list_state = ListState::default();
        (table, table_state, Some(list), Some(list_state))
    } else {
        (table, table_state, None, None)
    }
}

// ---------------------------------------------------------------------------
// Tab 3 — Findings
// ---------------------------------------------------------------------------

pub fn render_findings_tab_left<'a>(
    rows: &'a [FindingRow],
    cursor: usize,
) -> (List<'a>, ListState) {
    let items: Vec<ListItem> = rows
        .iter()
        .map(|row| {
            let badge_style = Style::default()
                .fg(sev_color(row.severity))
                .add_modifier(Modifier::BOLD);
            let hndl_tag = if row.hndl { " ⚑" } else { "  " };
            let line = Line::from(vec![
                Span::styled(format!("[{}]", row.badge), badge_style),
                Span::raw(hndl_tag),
                Span::raw(" "),
                Span::styled(
                    format!("{:<18}", row.rule_id),
                    Style::default().fg(accent()),
                ),
                Span::raw(" "),
                Span::raw(format!("{:<30}", truncate(&row.location, 30))),
                Span::raw(" "),
                Span::styled(
                    truncate(&row.algorithm_display, 20),
                    Style::default()
                        .fg(sev_color(row.severity))
                        .add_modifier(Modifier::DIM),
                ),
            ]);
            ListItem::new(line)
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .title(format!(" Findings ({}) ", rows.len()))
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded),
        )
        .highlight_style(highlight_style())
        .highlight_symbol("▶ ");

    let mut list_state = ListState::default();
    if !rows.is_empty() {
        list_state.select(Some(cursor));
    }

    (list, list_state)
}

pub fn render_findings_detail(detail: &FindingDetail) -> Paragraph<'_> {
    let mut lines: Vec<Line> = Vec::new();

    lines.push(Line::from(""));

    // Algorithm + rule
    lines.push(Line::from(vec![
        Span::styled("  Algorithm : ", dim()),
        Span::styled(
            detail.algorithm_display.clone(),
            Style::default().fg(accent()).add_modifier(Modifier::BOLD),
        ),
    ]));
    lines.push(Line::from(vec![
        Span::styled("  Rule      : ", dim()),
        Span::raw(detail.rule_id.clone()),
    ]));

    // HNDL badge
    if detail.hndl {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  !! HNDL-CRITICAL — Harvest Now Decrypt Later risk !!  ",
            Style::default()
                .fg(Color::White)
                .bg(if use_color() {
                    Color::Red
                } else {
                    Color::Reset
                })
                .add_modifier(Modifier::BOLD),
        )));
    }

    // Location
    lines.push(Line::from(""));
    let loc_str = match detail.line {
        Some(ln) => format!("{}:{}", detail.location, ln),
        None => detail.location.clone(),
    };
    lines.push(Line::from(vec![
        Span::styled("  Location  : ", dim()),
        Span::raw(loc_str),
    ]));

    // Message
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("  Message   : ", dim()),
        Span::raw(detail.message.clone()),
    ]));

    // Snippet
    if let Some(snippet) = &detail.snippet {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("  Snippet:", dim())));
        lines.push(Line::from(Span::styled(
            format!("    {snippet}"),
            Style::default().add_modifier(Modifier::DIM),
        )));
    }

    // Why this matters
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("  Why this matters:", dim())));
    // Word-wrap the explanation into ~60-char chunks.
    for chunk in wrap_text(&detail.why_this_matters, 60) {
        lines.push(Line::from(Span::raw(format!("    {chunk}"))));
    }

    // Replacement
    lines.push(Line::from(""));
    if let Some(repl) = &detail.replacement_display {
        lines.push(Line::from(vec![
            Span::styled("  Replacement: ", dim()),
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
        lines.push(Line::from(Span::styled("  No replacement listed.", dim())));
    }

    // Score breakdown
    if let Some(score) = &detail.score {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!(
                "  Risk score: {}/100 ({})",
                score.total,
                score.severity.label()
            ),
            Style::default()
                .fg(sev_color(score.severity))
                .add_modifier(Modifier::BOLD),
        )));
        lines.extend(score_lines(score));
    }

    Paragraph::new(lines)
        .block(
            Block::default()
                .title(" Detail ")
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded),
        )
        .wrap(Wrap { trim: false })
}

fn wrap_text(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if current.is_empty() {
            current.push_str(word);
        } else if current.len() + 1 + word.len() <= width {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(current.clone());
            current = word.to_string();
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
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
// Tab 4 — CBOM
// ---------------------------------------------------------------------------

pub fn render_cbom_tab(families: &[crate::model::CbomFamily], scroll: usize) -> Paragraph<'_> {
    let mut lines: Vec<Line> = Vec::new();

    lines.push(Line::from(""));
    lines.push(Line::from(vec![Span::styled(
        "  CycloneDX 1.7 CBOM — Cryptographic Inventory",
        Style::default()
            .fg(if use_color() {
                Color::LightBlue
            } else {
                Color::Reset
            })
            .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
    )]));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Press e to write cbom.json to disk",
        dim(),
    )));
    lines.push(Line::from(""));

    if families.is_empty() {
        lines.push(Line::from(Span::styled(
            "  No cryptographic assets found.",
            dim(),
        )));
    } else {
        for fam in families {
            let fam_color = fam
                .algorithms
                .first()
                .map(|a| quantum_status_color(a.quantum_status))
                .unwrap_or(Color::Reset);

            lines.push(Line::from(vec![
                Span::styled(
                    format!("  ▸ {}", fam.family),
                    Style::default().fg(fam_color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(format!(" ({} algorithms)", fam.algorithms.len()), dim()),
            ]));

            for algo in &fam.algorithms {
                lines.extend(render_cbom_algo_row(algo));
            }
            lines.push(Line::from(""));
        }
    }

    // Apply scroll offset.
    let total = lines.len();
    let lines: Vec<Line> = lines.into_iter().skip(scroll.min(total)).collect();

    Paragraph::new(lines)
        .block(
            Block::default()
                .title(" CBOM ")
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded),
        )
        .wrap(Wrap { trim: false })
}

fn render_cbom_algo_row(algo: &CbomAlgoRow) -> Vec<Line<'static>> {
    let qs_color = quantum_status_color(algo.quantum_status);
    let nist = algo
        .nist_level
        .map(|l| format!("L{l}"))
        .unwrap_or_else(|| "—".to_string());

    vec![Line::from(vec![
        Span::raw("      "),
        Span::styled(
            format!("{:<32}", algo.display_name.clone()),
            Style::default().fg(qs_color),
        ),
        Span::styled(
            format!(
                "{:<18}",
                quantum_status_label(algo.quantum_status).trim().to_string()
            ),
            Style::default().fg(qs_color),
        ),
        Span::styled(format!("  nistL:{nist}  "), dim()),
        Span::styled(format!("  prim:{}", algo.primitive.clone()), dim()),
        Span::raw(format!("  ×{}", algo.count)),
    ])]
}

// ---------------------------------------------------------------------------
// Findings tab (legacy left/right panes kept for backward compat)
// ---------------------------------------------------------------------------

/// Build a `List` widget + matching `ListState` for the findings pane.
pub fn render_left_pane<'a>(rows: &'a [FindingRow], cursor: usize) -> (List<'a>, ListState) {
    render_findings_tab_left(rows, cursor)
}

/// Right detail pane (legacy wrapper).
pub fn render_right_pane(detail: &FindingDetail) -> Paragraph<'_> {
    render_findings_detail(detail)
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
    let default_hint = match state.tab {
        Tab::Summary => "1-4/Tab navigate tabs  ? help  q quit",
        Tab::Inventory => "j/k navigate  Enter/l detail  / filter  1-4 tabs  ? help  q quit",
        Tab::Findings => {
            "j/k navigate  Enter/l detail  / filter  c/H/m/w/s toggle sev  1-4 tabs  q quit"
        }
        Tab::Cbom => "j/k scroll  e export CBOM  1-4 tabs  ? help  q quit",
    };
    let text = state.status_message.as_deref().unwrap_or(default_hint);
    Paragraph::new(text).style(dim())
}

// ---------------------------------------------------------------------------
// Help overlay
// ---------------------------------------------------------------------------

pub fn render_help_overlay(_area: Rect) -> Paragraph<'static> {
    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  Key Bindings — seawall TUI  ",
            Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
        )),
        Line::from(""),
        Line::from("  1 / 2 / 3 / 4     Switch to Summary / Inventory / Findings / CBOM tab"),
        Line::from("  Tab / Shift-Tab    Cycle tabs forward / backward"),
        Line::from(""),
        Line::from("  j / ↓             Move cursor down"),
        Line::from("  k / ↑             Move cursor up"),
        Line::from("  g                 Jump to first"),
        Line::from("  G                 Jump to last"),
        Line::from("  PgDn / PgUp       Page down / up"),
        Line::from("  Enter / l         Open detail pane"),
        Line::from("  h                 Close detail / prev tab"),
        Line::from(""),
        Line::from("  / (filter mode)   Type to filter; Enter apply; Esc cancel"),
        Line::from(""),
        Line::from("  Findings tab only:"),
        Line::from("    c               Toggle Critical severity"),
        Line::from("    H               Toggle High severity"),
        Line::from("    m               Toggle Medium severity"),
        Line::from("    w               Toggle Low severity"),
        Line::from("    s               Toggle Safe severity"),
        Line::from(""),
        Line::from("  CBOM tab:"),
        Line::from("    e               Export CBOM to cbom.json"),
        Line::from(""),
        Line::from("  ?                 Toggle this help overlay"),
        Line::from("  q / Esc / Ctrl-C  Quit"),
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
            .border_type(BorderType::Rounded)
            .style(Style::default().fg(if use_color() {
                Color::White
            } else {
                Color::Reset
            })),
    )
}

// ---------------------------------------------------------------------------
// Small-terminal detection
// ---------------------------------------------------------------------------

pub fn is_small_terminal(area: &Rect) -> bool {
    area.width < 80 || area.height < 24
}

// ---------------------------------------------------------------------------
// Row-to-string helper (stacked view)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn truncate(s: &str, max: usize) -> String {
    // Must cut on a CHARACTER boundary, not a byte index. `row.location` is a
    // scanned file path, so any repo containing a non-ASCII filename could put
    // a multibyte sequence across the cut point. The resulting panic fires
    // inside terminal.draw() while raw mode is on, so the terminal-restore
    // handler never runs and the user's shell is left unusable.
    if s.len() <= max {
        return s.to_string();
    }
    let budget = max.saturating_sub(1);
    let cut = s
        .char_indices()
        .map(|(i, c)| i + c.len_utf8())
        .take_while(|&end| end <= budget)
        .last()
        .unwrap_or(0);
    format!("{}\u{2026}", &s[..cut])
}

// Keep the Tui import used (suppress dead-code when cfg(test) is false).
const _: () = {
    let _ = std::mem::size_of::<Tui>();
};

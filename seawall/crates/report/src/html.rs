//! Self-contained HTML report emitter.
//!
//! Uses an Askama template (`templates/report.html`) compiled at build time.
//! All CSS is inlined in the template's `<style>` block — no external assets.
//!
//! Sections:
//! 1. Header  — tool name/version, policy name, scan target, timestamp.
//! 2. Executive summary — totals, severity breakdown, HNDL count, % vulnerable.
//! 3. Risk distribution — CSS-only stacked horizontal bar.
//! 4. HNDL-critical callouts — findings the active policy's `[hndl_flag]`
//!    block marks HNDL-critical, and only those. This section used to also
//!    admit `severity == Critical`, so it badged findings `HNDL-CRITICAL` that
//!    `summary.json` counted as zero from the same scan — and contradicted the
//!    `count_hndl` card three sections above it in its own document.
//! 5. Risk register table — all findings sorted by score descending.
//! 6. Compliance section — NIST IR 8547 IPD reference.
//! 7. Footer — methodology, tool version, timestamp.

use std::cmp::Reverse;

use askama::Template;

use seawall_core::{AlgorithmTable, Finding, Policy, ScanWarningKind, Severity, score_of};

use crate::{ReportError, ReportOptions, UNSCORED_LABEL, UNSCORED_SLUG};

// ── Template data rows ──────────────────────────────────────────────────────

/// One row in the HNDL callout section.
struct HndlRow {
    rule_id: String,
    algorithm: String,
    /// Pre-formatted "path:line" string.
    file_line: String,
    message: String,
}

/// One row in the scan diagnostics table.
struct DiagnosticRow {
    kind: String,
    path: String,
    message: String,
}

/// One row in the risk register table.
struct RegisterRow {
    severity_class: String,
    severity_label: String,
    rule_id: String,
    algorithm: String,
    /// Pre-formatted "path:line" string.
    file_line: String,
    message: String,
    replacement: String,
    /// Plain-English explanation of why this finding matters. Built from
    /// algorithm table fields (`quantum_status`, `notes`, `replacement`,
    /// `fips`) by mechanical concatenation — no LLM, no synthesis. Every
    /// fragment traces to a fixed enum match or a literal in the table.
    why_this_matters: String,
}

// ── Askama template ─────────────────────────────────────────────────────────

#[derive(Template)]
#[template(path = "report.html")]
struct ReportTemplate {
    // Header
    tool_version: &'static str,
    policy_name: String,
    policy_display_name: String,
    scan_target: String,
    timestamp: String,

    // Executive summary counts
    total_findings: usize,
    count_critical: usize,
    count_high: usize,
    count_medium: usize,
    count_low: usize,
    count_safe: usize,
    count_unscored: usize,
    count_hndl: usize,
    pct_vulnerable: u32,

    // Risk distribution bar (integer percentages 0–100; all six sum to ≤100)
    bar_critical_pct: u32,
    bar_high_pct: u32,
    bar_medium_pct: u32,
    bar_low_pct: u32,
    bar_safe_pct: u32,
    bar_unscored_pct: u32,

    // HNDL callout rows
    hndl_rows: Vec<HndlRow>,

    // Risk register
    register_rows: Vec<RegisterRow>,

    // Scan diagnostics (Phase 7 warnings)
    diagnostic_rows: Vec<DiagnosticRow>,
    /// Total warning count before the 20-row cap.
    diagnostic_total: usize,
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Emit a self-contained HTML report.
pub fn emit_html(
    findings: &[Finding],
    algorithms: &AlgorithmTable,
    policy: &Policy,
    opts: &ReportOptions,
) -> Result<String, ReportError> {
    // ── Score every finding ──────────────────────────────────────────────────
    struct ScoredFinding<'a> {
        finding: &'a Finding,
        /// `None` when the finding's algorithm has no table row — unscored,
        /// which is not a band. See `seawall_core::score_of`.
        score: Option<u8>,
        severity: Option<Severity>,
        display_name: String,
        replacement: String,
    }

    let mut scored: Vec<ScoredFinding<'_>> = findings
        .iter()
        .map(|f| {
            let algo = algorithms.get(&f.algorithm_id);
            let scored = score_of(f, algorithms, policy);
            let (score, severity) = (scored.map(|s| s.total), scored.map(|s| s.severity));
            let display_name = algo
                .map(|a| a.display_name.clone())
                .unwrap_or_else(|| f.algorithm_id.clone());
            let replacement = algo
                .and_then(|a| a.replacement.as_deref())
                .and_then(|repl_id| algorithms.get(repl_id))
                .map(|r| r.display_name.clone())
                .unwrap_or_default();

            ScoredFinding {
                finding: f,
                score,
                severity,
                display_name,
                replacement,
            }
        })
        .collect();

    // Sort descending by score for the risk register.
    // Unscored findings have no score to sort by and land at the bottom, after
    // every banded finding, rather than being given one.
    scored.sort_by_key(|s| Reverse(s.score.unwrap_or(0)));

    // ── Counts ───────────────────────────────────────────────────────────────
    let count_critical = scored
        .iter()
        .filter(|s| s.severity == Some(Severity::Critical))
        .count();
    let count_high = scored
        .iter()
        .filter(|s| s.severity == Some(Severity::High))
        .count();
    let count_medium = scored
        .iter()
        .filter(|s| s.severity == Some(Severity::Medium))
        .count();
    let count_low = scored
        .iter()
        .filter(|s| s.severity == Some(Severity::Low))
        .count();
    let count_safe = scored
        .iter()
        .filter(|s| s.severity == Some(Severity::Safe))
        .count();
    let count_unscored = scored.iter().filter(|s| s.severity.is_none()).count();
    let count_hndl = findings.iter().filter(|f| f.hndl_critical).count();

    let total_findings = findings.len();

    // % vulnerable = (Critical + High) / total * 100
    let pct_vulnerable = ((count_critical + count_high) * 100)
        .checked_div(total_findings)
        .unwrap_or(0) as u32;

    // ── Bar percentages (integer, must sum ≤ 100) ────────────────────────────
    let (
        bar_critical_pct,
        bar_high_pct,
        bar_medium_pct,
        bar_low_pct,
        bar_safe_pct,
        bar_unscored_pct,
    ) = {
        let c = (count_critical * 100)
            .checked_div(total_findings)
            .unwrap_or(0) as u32;
        let h = (count_high * 100).checked_div(total_findings).unwrap_or(0) as u32;
        let m = (count_medium * 100)
            .checked_div(total_findings)
            .unwrap_or(0) as u32;
        let l = (count_low * 100).checked_div(total_findings).unwrap_or(0) as u32;
        let s = (count_safe * 100).checked_div(total_findings).unwrap_or(0) as u32;
        // Unscored takes the remainder. Safe took it before there was an
        // unscored segment, which drew unscored findings as green.
        let u = 100u32.saturating_sub(c + h + m + l + s);
        (c, h, m, l, s, u)
    };

    // ── HNDL callout rows ─────────────────────────────────────────────────────
    let hndl_rows: Vec<HndlRow> = scored
        .iter()
        .filter(|s| s.finding.hndl_critical)
        .map(|s| HndlRow {
            rule_id: s.finding.rule_id.clone(),
            algorithm: s.display_name.clone(),
            file_line: file_line_str(s.finding),
            message: s.finding.message.clone(),
        })
        .collect();

    // ── Risk register rows ────────────────────────────────────────────────────
    let register_rows: Vec<RegisterRow> = scored
        .iter()
        .map(|s| {
            let algo = algorithms.get(&s.finding.algorithm_id);
            let replacement_algo = algo
                .and_then(|a| a.replacement.as_deref())
                .and_then(|repl_id| algorithms.get(repl_id));
            RegisterRow {
                severity_class: s.severity.map_or(UNSCORED_SLUG, Severity::slug).to_string(),
                severity_label: s
                    .severity
                    .map_or(UNSCORED_LABEL, Severity::label)
                    .to_string(),
                rule_id: s.finding.rule_id.clone(),
                algorithm: s.display_name.clone(),
                file_line: file_line_str(s.finding),
                message: s.finding.message.clone(),
                replacement: s.replacement.clone(),
                why_this_matters: why_this_matters(algo, replacement_algo),
            }
        })
        .collect();

    // ── Scan diagnostics rows (cap at 20 visible) ─────────────────────────────
    let diagnostic_total = opts.warnings.len();
    let diagnostic_rows: Vec<DiagnosticRow> = opts
        .warnings
        .iter()
        .take(20)
        .map(|w| DiagnosticRow {
            kind: warning_kind_label(&w.kind).to_string(),
            path: w
                .path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            message: w.message.clone(),
        })
        .collect();

    // ── Render ────────────────────────────────────────────────────────────────
    let tmpl = ReportTemplate {
        tool_version: env!("CARGO_PKG_VERSION"),
        policy_name: policy.meta.name.clone(),
        policy_display_name: policy.meta.display_name.clone(),
        scan_target: opts.scan_target.clone(),
        timestamp: opts.timestamp.clone(),
        total_findings,
        count_critical,
        count_high,
        count_medium,
        count_low,
        count_safe,
        count_unscored,
        count_hndl,
        pct_vulnerable,
        bar_critical_pct,
        bar_high_pct,
        bar_medium_pct,
        bar_low_pct,
        bar_safe_pct,
        bar_unscored_pct,
        hndl_rows,
        register_rows,
        diagnostic_rows,
        diagnostic_total,
    };

    Ok(tmpl.render()?)
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Format a "path:line" string from a finding's location.
fn file_line_str(f: &Finding) -> String {
    match f.location.line {
        Some(line) => format!("{}:{}", f.location.location, line),
        None => f.location.location.clone(),
    }
}

/// Human-readable label for a warning kind.
fn warning_kind_label(kind: &ScanWarningKind) -> &'static str {
    match kind {
        ScanWarningKind::UnreadableFile => "UnreadableFile",
        ScanWarningKind::ParseError => "ParseError",
        ScanWarningKind::WalkError => "WalkError",
        ScanWarningKind::DepManifestError => "DepManifestError",
        ScanWarningKind::CertDecodeError => "CertDecodeError",
        ScanWarningKind::Other => "Other",
    }
}

/// Build the plain-English "why this matters" sentence for a finding.
///
/// P1 (no LLM at runtime): every fragment of the output is either a fixed
/// string matched on `quantum_status` or a literal copied from the algorithm
/// table (notes, display_name, fips). No external content, no model calls.
fn why_this_matters(
    algo: Option<&seawall_core::AlgorithmRecord>,
    replacement: Option<&seawall_core::AlgorithmRecord>,
) -> String {
    use seawall_core::QuantumStatus;
    let Some(a) = algo else {
        return "Algorithm not in the seawall catalogue; classification unavailable. \
                Investigate manually."
            .to_string();
    };

    // Preamble — one sentence per quantum_status. Wording mirrors what the
    // policy / NIST guidance documents say; not editorial.
    let preamble = match a.quantum_status {
        QuantumStatus::BrokenClassically => {
            "Classically broken — practical attacks exist today, independent of any quantum threat."
        }
        QuantumStatus::BrokenByShor => {
            "Vulnerable to Shor's algorithm; a cryptographically relevant quantum computer breaks \
             this in polynomial time."
        }
        QuantumStatus::WeakenedByGrover => {
            "Weakened under Grover's algorithm; effective security halves against quantum search. \
             Keep using only at sufficiently large parameters."
        }
        QuantumStatus::QuantumSafe => {
            "Quantum-safe at the chosen parameters — Grover's algorithm does not reduce security \
             below acceptable levels."
        }
        QuantumStatus::PqcFinal => {
            "NIST-final post-quantum algorithm; designed to resist both classical and quantum \
             attacks."
        }
        QuantumStatus::PqcDraft => {
            "Draft post-quantum algorithm; expected to be standardized but the specification may \
             still change."
        }
    };

    // Algorithm-specific note from the catalogue, verbatim.
    let mut parts = vec![preamble.to_string()];
    if !a.notes.trim().is_empty() {
        parts.push(a.notes.trim().to_string());
    }

    // Replacement recommendation when one exists. Naming + FIPS reference both
    // come from the replacement record, verbatim.
    if let Some(r) = replacement {
        let fips = r
            .fips
            .as_deref()
            .map(|f| format!(" per {f}"))
            .unwrap_or_default();
        parts.push(format!(
            "Recommended replacement: {}{}.",
            r.display_name, fips
        ));
    }

    parts.join(" ")
}

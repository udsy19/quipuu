//! Pure model functions — produce display strings / structs for each pane
//! given AppState + findings.  No ratatui widgets; those live in render.rs.

use cryptoscope_core::{AlgorithmTable, Finding, Policy, QuantumRiskScore, Severity};

use crate::state::{AppState, Kpi, no_color};

// ---------------------------------------------------------------------------
// Severity helpers
// ---------------------------------------------------------------------------

/// Short badge text for a severity level.
pub fn severity_badge(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical => "CRIT",
        Severity::High => "HIGH",
        Severity::Medium => "MED ",
        Severity::Low => "LOW ",
        Severity::Safe => "SAFE",
    }
}

/// Sort key so Critical comes first.
pub fn severity_order(sev: Severity) -> u8 {
    match sev {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Safe => 4,
    }
}

// ---------------------------------------------------------------------------
// Left-pane list rows
// ---------------------------------------------------------------------------

/// One rendered row in the findings list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingRow {
    pub index: usize,
    pub severity: Severity,
    pub badge: &'static str,
    pub rule_id: String,
    pub location: String,
    pub algorithm_display: String,
    pub hndl: bool,
}

/// Build display rows from the filtered findings list.
pub fn build_finding_rows(
    state: &AppState,
    findings: &[Finding],
    algorithms: &AlgorithmTable,
    policy: &Policy,
) -> Vec<FindingRow> {
    state
        .filtered_indices
        .iter()
        .copied()
        .map(|idx| {
            let f = &findings[idx];
            let severity = if let Some(alg) = algorithms.get(&f.algorithm_id) {
                QuantumRiskScore::compute(f, alg, policy).severity
            } else {
                Severity::Safe
            };
            let algorithm_display = algorithms
                .get(&f.algorithm_id)
                .map(|a| a.display_name.clone())
                .unwrap_or_else(|| f.algorithm_id.clone());
            FindingRow {
                index: idx,
                severity,
                badge: severity_badge(severity),
                rule_id: f.rule_id.clone(),
                location: f.location.location.clone(),
                algorithm_display,
                hndl: f.hndl_critical,
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Right-pane detail
// ---------------------------------------------------------------------------

/// Full detail for the selected finding.
#[derive(Debug, Clone)]
pub struct FindingDetail {
    pub rule_id: String,
    pub algorithm_id: String,
    pub algorithm_display: String,
    pub replacement_display: Option<String>,
    pub location: String,
    pub line: Option<u32>,
    pub snippet: Option<String>,
    pub message: String,
    pub hndl: bool,
    pub score: Option<ScoreBreakdown>,
}

/// Five-axis score breakdown for display.
#[derive(Debug, Clone)]
pub struct ScoreBreakdown {
    pub total: u8,
    pub severity: Severity,
    pub algorithm_vulnerability: u8,
    pub usage_context: u8,
    pub data_shelf_life: u8,
    pub exposure: u8,
    pub detection_confidence: u8,
    /// Max value for each axis (from policy risk_weights).
    pub av_max: u8,
    pub uc_max: u8,
    pub ds_max: u8,
    pub ex_max: u8,
    pub dc_max: u8,
}

pub fn build_finding_detail(
    finding: &Finding,
    algorithms: &AlgorithmTable,
    policy: &Policy,
) -> FindingDetail {
    let algorithm_display = algorithms
        .get(&finding.algorithm_id)
        .map(|a| a.display_name.clone())
        .unwrap_or_else(|| finding.algorithm_id.clone());

    let replacement_display = algorithms
        .get(&finding.algorithm_id)
        .and_then(|a| a.replacement.as_ref())
        .and_then(|repl_id| algorithms.get(repl_id))
        .map(|r| r.display_name.clone());

    let score = algorithms.get(&finding.algorithm_id).map(|alg| {
        let s = QuantumRiskScore::compute(finding, alg, policy);
        ScoreBreakdown {
            total: s.total,
            severity: s.severity,
            algorithm_vulnerability: s.algorithm_vulnerability,
            usage_context: s.usage_context,
            data_shelf_life: s.data_shelf_life,
            exposure: s.exposure,
            detection_confidence: s.detection_confidence,
            av_max: policy.risk_weights.algorithm_vulnerability,
            uc_max: policy.risk_weights.usage_context,
            ds_max: policy.risk_weights.data_shelf_life,
            ex_max: policy.risk_weights.exposure,
            dc_max: policy.risk_weights.detection_confidence,
        }
    });

    FindingDetail {
        rule_id: finding.rule_id.clone(),
        algorithm_id: finding.algorithm_id.clone(),
        algorithm_display,
        replacement_display,
        location: finding.location.location.clone(),
        line: finding.location.line,
        snippet: finding.location.snippet.clone(),
        message: finding.message.clone(),
        hndl: finding.hndl_critical,
        score,
    }
}

// ---------------------------------------------------------------------------
// KPI strip
// ---------------------------------------------------------------------------

/// Build KPI summary strings for the top strip.
#[allow(clippy::too_many_arguments)]
pub fn build_kpi_line(kpi: &Kpi, days: i64) -> String {
    let pct = |n: usize| -> u8 {
        if kpi.total == 0 {
            0
        } else {
            ((n as f64 / kpi.total as f64) * 100.0).round() as u8
        }
    };
    format!(
        " Findings: {}  Critical: {}%  HNDL-Critical: {}  Deadline in: {}d ",
        kpi.total,
        pct(kpi.critical),
        kpi.hndl_critical,
        days
    )
}

// ---------------------------------------------------------------------------
// Small bar for score axis
// ---------------------------------------------------------------------------

/// Render a small ASCII bar: e.g. `[####......] 40/40`.
pub fn score_bar(value: u8, max: u8, width: usize) -> String {
    if max == 0 {
        return format!("[{}] {}/{}", " ".repeat(width), value, max);
    }
    let filled = ((value as usize) * width) / (max as usize);
    let filled = filled.min(width);
    let empty = width - filled;
    format!(
        "[{}{}] {}/{}",
        "#".repeat(filled),
        ".".repeat(empty),
        value,
        max
    )
}

// ---------------------------------------------------------------------------
// Style — NO_COLOR
// ---------------------------------------------------------------------------

/// Returns whether to suppress colour output.
///
/// Exported so render.rs and tests can call it.
pub fn use_color() -> bool {
    !no_color()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn score_bar_output() {
        assert_eq!(score_bar(4, 10, 10), "[####......] 4/10");
        assert_eq!(score_bar(0, 10, 10), "[..........] 0/10");
        assert_eq!(score_bar(10, 10, 10), "[##########] 10/10");
    }

    #[test]
    fn severity_badge_values() {
        assert_eq!(severity_badge(Severity::Critical), "CRIT");
        assert_eq!(severity_badge(Severity::Safe), "SAFE");
    }
}

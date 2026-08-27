//! Pure model functions — produce display strings / structs for each pane
//! given AppState + findings.  No ratatui widgets; those live in render.rs.

use std::collections::BTreeMap;

use cryptoscope_core::{
    AlgorithmRecord, AlgorithmTable, Finding, Policy, QuantumRiskScore, QuantumStatus, Severity,
};

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
// Left-pane list rows (Findings tab)
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
    pub why_this_matters: String,
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
    let algo = algorithms.get(&finding.algorithm_id);

    let algorithm_display = algo
        .map(|a| a.display_name.clone())
        .unwrap_or_else(|| finding.algorithm_id.clone());

    let replacement_algo = algo
        .and_then(|a| a.replacement.as_ref())
        .and_then(|repl_id| algorithms.get(repl_id));

    let replacement_display = replacement_algo.map(|r| r.display_name.clone());

    let why_this_matters = build_why_this_matters(algo, replacement_algo);

    let score = algo.map(|alg| {
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
        why_this_matters,
    }
}

fn build_why_this_matters(
    algo: Option<&AlgorithmRecord>,
    replacement: Option<&AlgorithmRecord>,
) -> String {
    let Some(a) = algo else {
        return "Algorithm not in the cryptoscope catalogue; classification unavailable. \
                Investigate manually."
            .to_string();
    };
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

    let mut parts = vec![preamble.to_string()];
    if !a.notes.trim().is_empty() {
        parts.push(a.notes.trim().to_string());
    }
    if let Some(r) = replacement {
        let fips = r
            .fips
            .as_deref()
            .map(|f| format!(" per {f}"))
            .unwrap_or_default();
        parts.push(format!(
            "Recommended replacement: {}{fips}.",
            r.display_name
        ));
    }
    parts.join(" ")
}

// ---------------------------------------------------------------------------
// Inventory tab rows
// ---------------------------------------------------------------------------

/// One row in the Algorithm Inventory table.
#[derive(Debug, Clone)]
pub struct InventoryRow {
    pub algorithm_id: String,
    pub display_name: String,
    pub quantum_status: QuantumStatus,
    pub family: String,
    pub count: usize,
    pub file_count: usize,
    pub replacement_display: String,
}

/// Build inventory rows from all findings, filtered by name substring.
pub fn build_inventory_rows(
    findings: &[Finding],
    algorithms: &AlgorithmTable,
    filter: &str,
) -> Vec<InventoryRow> {
    // Group findings by algorithm_id.
    let mut by_algo: BTreeMap<&str, Vec<&Finding>> = BTreeMap::new();
    for f in findings {
        by_algo.entry(&f.algorithm_id).or_default().push(f);
    }

    let filter_lc = filter.to_lowercase();

    let mut rows: Vec<InventoryRow> = by_algo
        .iter()
        .filter_map(|(id, group)| {
            let record = algorithms.get(id)?;
            // Apply filter.
            if !filter_lc.is_empty()
                && !record.display_name.to_lowercase().contains(&filter_lc)
                && !record.id.to_lowercase().contains(&filter_lc)
                && !record.family.to_lowercase().contains(&filter_lc)
            {
                return None;
            }
            let file_count = group
                .iter()
                .map(|f| f.location.location.as_str())
                .collect::<std::collections::HashSet<_>>()
                .len();
            let replacement_display = record
                .replacement
                .as_ref()
                .and_then(|r| algorithms.get(r))
                .map(|r| r.display_name.clone())
                .unwrap_or_default();
            Some(InventoryRow {
                algorithm_id: id.to_string(),
                display_name: record.display_name.clone(),
                quantum_status: record.quantum_status,
                family: record.family.clone(),
                count: group.len(),
                file_count,
                replacement_display,
            })
        })
        .collect();

    // Sort by quantum risk (most dangerous first), then by count descending.
    rows.sort_by_key(|r| {
        let risk_order: u8 = match r.quantum_status {
            QuantumStatus::BrokenClassically => 0,
            QuantumStatus::BrokenByShor => 1,
            QuantumStatus::WeakenedByGrover => 2,
            QuantumStatus::QuantumSafe => 3,
            QuantumStatus::PqcDraft => 4,
            QuantumStatus::PqcFinal => 5,
        };
        (risk_order, usize::MAX - r.count)
    });

    rows
}

/// Return all findings for a given algorithm_id.
pub fn findings_for_algorithm<'a>(algorithm_id: &str, findings: &'a [Finding]) -> Vec<&'a Finding> {
    findings
        .iter()
        .filter(|f| f.algorithm_id == algorithm_id)
        .collect()
}

// ---------------------------------------------------------------------------
// CBOM tab — grouped families
// ---------------------------------------------------------------------------

/// One family group row for the CBOM tree view.
#[derive(Debug, Clone)]
pub struct CbomFamily {
    pub family: String,
    pub algorithms: Vec<CbomAlgoRow>,
}

#[derive(Debug, Clone)]
pub struct CbomAlgoRow {
    pub display_name: String,
    pub primitive: String,
    pub nist_level: Option<u8>,
    pub quantum_status: QuantumStatus,
    pub count: usize,
}

pub fn build_cbom_families(findings: &[Finding], algorithms: &AlgorithmTable) -> Vec<CbomFamily> {
    // Group findings by algorithm_id.
    let mut by_algo: BTreeMap<&str, usize> = BTreeMap::new();
    for f in findings {
        *by_algo.entry(&f.algorithm_id).or_default() += 1;
    }

    // Build algo rows per family.
    let mut family_map: BTreeMap<String, Vec<CbomAlgoRow>> = BTreeMap::new();
    for (id, &count) in &by_algo {
        if let Some(rec) = algorithms.get(id) {
            let primitive = rec.primitive.map(|p| format!("{p:?}")).unwrap_or_default();
            family_map
                .entry(rec.family.clone())
                .or_default()
                .push(CbomAlgoRow {
                    display_name: rec.display_name.clone(),
                    primitive,
                    nist_level: rec.nist_quantum_security_level,
                    quantum_status: rec.quantum_status,
                    count,
                });
        }
    }

    // Sort families: dangerous first.
    let mut families: Vec<CbomFamily> = family_map
        .into_iter()
        .map(|(family, mut algorithms)| {
            algorithms.sort_by_key(|a| match a.quantum_status {
                QuantumStatus::BrokenClassically => 0u8,
                QuantumStatus::BrokenByShor => 1,
                QuantumStatus::WeakenedByGrover => 2,
                QuantumStatus::QuantumSafe => 3,
                QuantumStatus::PqcDraft => 4,
                QuantumStatus::PqcFinal => 5,
            });
            CbomFamily { family, algorithms }
        })
        .collect();

    // Order families by worst algorithm inside them.
    families.sort_by_key(|fam| {
        fam.algorithms
            .first()
            .map(|a| match a.quantum_status {
                QuantumStatus::BrokenClassically => 0u8,
                QuantumStatus::BrokenByShor => 1,
                QuantumStatus::WeakenedByGrover => 2,
                QuantumStatus::QuantumSafe => 3,
                QuantumStatus::PqcDraft => 4,
                QuantumStatus::PqcFinal => 5,
            })
            .unwrap_or(6)
    });

    families
}

// ---------------------------------------------------------------------------
// Summary tab — top algorithms
// ---------------------------------------------------------------------------

pub struct TopAlgo {
    pub display_name: String,
    pub count: usize,
    pub quantum_status: QuantumStatus,
}

/// Top N algorithms by finding count.
pub fn top_algorithms(findings: &[Finding], algorithms: &AlgorithmTable, n: usize) -> Vec<TopAlgo> {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for f in findings {
        *counts.entry(&f.algorithm_id).or_default() += 1;
    }
    let mut ranked: Vec<(&str, usize)> = counts.into_iter().collect();
    ranked.sort_by_key(|&(_, c)| std::cmp::Reverse(c));
    ranked
        .into_iter()
        .take(n)
        .filter_map(|(id, count)| {
            let rec = algorithms.get(id)?;
            Some(TopAlgo {
                display_name: rec.display_name.clone(),
                count,
                quantum_status: rec.quantum_status,
            })
        })
        .collect()
}

/// Per-language/extension breakdown.
pub struct LangBreakdown {
    pub lang: String,
    pub count: usize,
}

pub fn lang_breakdown(findings: &[Finding]) -> Vec<LangBreakdown> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for f in findings {
        let ext = std::path::Path::new(&f.location.location)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("?")
            .to_string();
        *counts.entry(ext).or_default() += 1;
    }
    let mut out: Vec<LangBreakdown> = counts
        .into_iter()
        .map(|(lang, count)| LangBreakdown { lang, count })
        .collect();
    out.sort_by_key(|b| std::cmp::Reverse(b.count));
    out
}

// ---------------------------------------------------------------------------
// KPI strip
// ---------------------------------------------------------------------------

/// Build KPI summary string for the top strip.
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

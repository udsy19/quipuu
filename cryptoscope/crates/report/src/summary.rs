//! CI dashboard JSON summary emitter.
//!
//! Produces a compact, stable JSON object suitable for `jq` pipelines and
//! CI threshold gates. The `by_algorithm` array is sorted by count descending,
//! then alphabetically by `algorithm_id` for determinism when counts are equal.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use cryptoscope_core::{AlgorithmTable, Finding, Policy, QuantumRiskScore, Severity};

use crate::{ReportError, ReportOptions};

/// Emit the CI dashboard JSON summary.
pub fn emit_summary_json(
    findings: &[Finding],
    algorithms: &AlgorithmTable,
    policy: &Policy,
    opts: &ReportOptions,
) -> Result<String, ReportError> {
    let mut critical = 0u32;
    let mut high = 0u32;
    let mut medium = 0u32;
    let mut low = 0u32;
    let mut safe = 0u32;
    let mut hndl_critical = 0u32;

    // Track per-algorithm { count, worst_severity }.
    // BTreeMap so the iteration order is deterministic before re-sorting.
    let mut by_algo: BTreeMap<String, (u32, Severity)> = BTreeMap::new();

    for finding in findings {
        let severity = if let Some(algo) = algorithms.get(&finding.algorithm_id) {
            let score = QuantumRiskScore::compute(finding, algo, policy);
            score.severity
        } else {
            Severity::Medium
        };

        match severity {
            Severity::Critical => critical += 1,
            Severity::High => high += 1,
            Severity::Medium => medium += 1,
            Severity::Low => low += 1,
            Severity::Safe => safe += 1,
        }

        if finding.hndl_critical {
            hndl_critical += 1;
        }

        let entry = by_algo
            .entry(finding.algorithm_id.clone())
            .or_insert((0, Severity::Safe));
        entry.0 += 1;
        // Keep the worst severity seen for this algorithm.
        if severity_ord(severity) > severity_ord(entry.1) {
            entry.1 = severity;
        }
    }

    // Sort by_algorithm: count descending, then algorithm_id ascending.
    let mut by_algo_vec: Vec<(String, u32, Severity)> = by_algo
        .into_iter()
        .map(|(id, (count, sev))| (id, count, sev))
        .collect();
    by_algo_vec.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    let by_algorithm: Vec<Value> = by_algo_vec
        .into_iter()
        .map(|(algo_id, count, sev)| {
            json!({
                "algorithm_id": algo_id,
                "count": count,
                "severity": severity_name(sev)
            })
        })
        .collect();

    let summary = json!({
        "tool": {
            "name": "cryptoscope",
            "version": env!("CARGO_PKG_VERSION")
        },
        "scan_target": opts.scan_target,
        "timestamp": opts.timestamp,
        "policy": policy.meta.name,
        "totals": {
            "findings": findings.len(),
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "safe": safe,
            "hndl_critical": hndl_critical
        },
        "by_algorithm": by_algorithm
    });

    Ok(serde_json::to_string_pretty(&summary)?)
}

/// Ordinal for severity comparison (higher = worse).
fn severity_ord(s: Severity) -> u8 {
    match s {
        Severity::Safe => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

/// Display name for severity.
fn severity_name(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "Critical",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
        Severity::Safe => "Safe",
    }
}

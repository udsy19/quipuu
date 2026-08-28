//! CI dashboard JSON summary emitter.
//!
//! Produces a compact, stable JSON object suitable for `jq` pipelines and
//! CI threshold gates. The `by_algorithm` array is sorted by count descending,
//! then alphabetically by `algorithm_id` for determinism when counts are equal.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use quipuu_core::{AlgorithmTable, Finding, Policy, Severity, severity_of};

use crate::{ReportError, ReportOptions, UNSCORED_LABEL};

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
    let mut unscored = 0u32;
    let mut hndl_critical = 0u32;

    // Track per-algorithm { count, worst_severity }. `None` is an algorithm id
    // no finding of which could be scored.
    // BTreeMap so the iteration order is deterministic before re-sorting.
    let mut by_algo: BTreeMap<String, (u32, Option<Severity>)> = BTreeMap::new();

    for finding in findings {
        // `None` is counted as `unscored`, not folded into a band. It used to
        // be counted as `medium`, which asserted a severity for a finding
        // whose algorithm we cannot look up.
        let severity = severity_of(finding, algorithms, policy);

        match severity {
            Some(Severity::Critical) => critical += 1,
            Some(Severity::High) => high += 1,
            Some(Severity::Medium) => medium += 1,
            Some(Severity::Low) => low += 1,
            Some(Severity::Safe) => safe += 1,
            None => unscored += 1,
        }

        if finding.hndl_critical {
            hndl_critical += 1;
        }

        let entry = by_algo
            .entry(finding.algorithm_id.clone())
            .or_insert((0, None));
        entry.0 += 1;
        // Keep the worst severity seen for this algorithm. An unscored finding
        // never becomes the worst: it has no rank to compare.
        if let Some(sev) = severity
            && entry.1.is_none_or(|worst| sev.rank() > worst.rank())
        {
            entry.1 = Some(sev);
        }
    }

    // Sort by_algorithm: count descending, then algorithm_id ascending.
    let mut by_algo_vec: Vec<(String, u32, Option<Severity>)> = by_algo
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
                "severity": sev.map_or(UNSCORED_LABEL, Severity::label)
            })
        })
        .collect();

    let summary = json!({
        "tool": {
            "name": "quipuu",
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
            "unscored": unscored,
            "hndl_critical": hndl_critical
        },
        "by_algorithm": by_algorithm
    });

    Ok(serde_json::to_string_pretty(&summary)?)
}

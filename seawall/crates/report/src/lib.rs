//! seawall-report — HTML, SARIF 2.1.0, and JSON summary emitters.
//!
//! Three output formats consuming [`Finding`]s + [`AlgorithmTable`] + [`Policy`]:
//!
//! * [`emit_sarif`]          — SARIF 2.1.0 for GitHub / GitLab Advanced Security.
//! * [`emit_html`]           — Self-contained auditor-grade HTML report.
//! * [`emit_summary_json`]   — Compact CI dashboard JSON.
//!
//! All three are deterministic given the same inputs and the same
//! [`ReportOptions::timestamp`].

pub mod html;
pub mod sarif;
pub mod summary;

pub use html::emit_html;
pub use sarif::emit_sarif;
pub use summary::emit_summary_json;

use seawall_core::{AlgorithmTable, Finding, Policy, ScanWarning};

/// Partition findings into (audible, suppressed) sets.
///
/// "Suppressed" = findings whose algorithm has `quantum_status.is_inventory_only()`
/// (QuantumSafe / PqcFinal / PqcDraft). They are inventory data, not alerts,
/// and would otherwise drown out real findings (e.g. a single rustls scan emits
/// ~85 AES-256-GCM Medium findings — all of which are quantum-safe noise).
///
/// Findings whose `algorithm_id` is not in the table are always audible (they
/// represent something the scanner saw but couldn't classify — surfacing them
/// helps users catch coverage gaps).
///
/// An algorithm the active policy disallows is always audible even when its
/// quantum status is inventory-only. Under `nsa-cnsa2` SHA-256 is quantum-safe
/// and still off the approved suite; hiding it would contradict the profile
/// the operator selected.
///
/// The CBOM is built from the full finding set, not the audible subset, so the
/// inventory remains complete. Only HTML / SARIF / summary / stdout filter.
pub fn partition_audible<'a>(
    findings: &'a [Finding],
    algorithms: &AlgorithmTable,
    policy: &Policy,
) -> (Vec<&'a Finding>, Vec<&'a Finding>) {
    let mut audible = Vec::with_capacity(findings.len());
    let mut suppressed = Vec::new();
    for f in findings {
        match algorithms.get(&f.algorithm_id) {
            Some(a) if a.quantum_status.is_inventory_only() && !policy.disallows(&a.id) => {
                suppressed.push(f)
            }
            _ => audible.push(f),
        }
    }
    (audible, suppressed)
}

use thiserror::Error;

/// Caller-supplied options shared by all emitters.
///
/// The `timestamp` field is supplied by the caller so that CI pipelines can
/// produce byte-for-byte identical reports given the same inputs.
#[derive(Debug, Clone, Default)]
pub struct ReportOptions {
    /// Human-readable scan target (path, host, or description).
    pub scan_target: String,
    /// RFC-3339 timestamp string, e.g. `"2026-06-15T12:00:00Z"`.
    pub timestamp: String,
    /// Non-fatal warnings collected during the scan (Phase 6).
    /// Empty by default; the HTML and SARIF emitters surface these when present.
    pub warnings: Vec<ScanWarning>,
}

/// Errors that can occur during report generation.
#[derive(Debug, Error)]
pub enum ReportError {
    /// Failure serialising the JSON payload.
    #[error("JSON serialisation error: {0}")]
    Json(#[from] serde_json::Error),

    /// Askama template render failure.
    #[error("template render error: {0}")]
    Template(#[from] askama::Error),

    /// I/O error (e.g. writing to a file).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

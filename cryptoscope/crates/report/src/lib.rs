//! cryptoscope-report — HTML, SARIF 2.1.0, and JSON summary emitters.
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

use thiserror::Error;

/// Caller-supplied options shared by all emitters.
///
/// The `timestamp` field is supplied by the caller so that CI pipelines can
/// produce byte-for-byte identical reports given the same inputs.
#[derive(Debug, Clone)]
pub struct ReportOptions {
    /// Human-readable scan target (path, host, or description).
    pub scan_target: String,
    /// RFC-3339 timestamp string, e.g. `"2026-06-15T12:00:00Z"`.
    pub timestamp: String,
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

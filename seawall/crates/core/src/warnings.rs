//! Non-fatal scan warnings.
//!
//! Phase 6: scanners surface per-file errors without aborting the whole scan.
//! A malformed file or an unreadable directory entry produces one [`ScanWarning`]
//! and the scan moves on. The CLI prints a count by default; `--show-errors`
//! dumps the structured list.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Category of a non-fatal scan warning.
///
/// Specific categories — not a free-text bucket — so downstream tooling can
/// filter / group / aggregate. Add new variants as new failure modes appear.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ScanWarningKind {
    /// Could not read the file (permission denied, broken symlink, etc.).
    UnreadableFile,
    /// Tree-sitter parse failed for a file whose extension we claimed to support.
    ParseError,
    /// Directory walk hit an unrecoverable entry (e.g. cycle, FS error).
    WalkError,
    /// A dependency manifest in a known ecosystem failed to parse.
    DepManifestError,
    /// A certificate file (PEM/DER) failed to decode.
    CertDecodeError,
    /// Anything else that doesn't fit above but shouldn't kill the scan.
    Other,
}

/// One non-fatal warning surfaced during a scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanWarning {
    pub kind: ScanWarningKind,
    /// File or path the warning concerns. None if not file-scoped.
    pub path: Option<PathBuf>,
    /// Human-readable explanation. Short — one line.
    pub message: String,
}

impl ScanWarning {
    pub fn new(kind: ScanWarningKind, path: Option<PathBuf>, message: impl Into<String>) -> Self {
        Self {
            kind,
            path,
            message: message.into(),
        }
    }
}

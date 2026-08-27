//! In-process scan-session store.
//!
//! Each `scan_source` / `scan_certs` / `scan_deps` / `scan_network` request in
//! "streaming" or "async" mode stores its result here under an opaque `scanId`.
//! The client polls `get_scan_results(scanId, cursor?)` to page through findings.

use std::collections::HashMap;

use cryptoscope_core::{Finding, ScanWarning};
use serde::{Deserialize, Serialize};

/// A completed scan result held in memory until the session ends.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub scan_id: String,
    /// Diagnostic statistics (errors, skipped files, …).
    pub stats: ScanStats,
    pub findings: Vec<Finding>,
    /// Non-fatal per-file warnings (unreadable files, parse failures, …).
    pub warnings: Vec<ScanWarning>,
    /// False for network scans (non-deterministic).
    pub deterministic: bool,
}

/// Per-scan statistics — partial-failure-as-stats (MCP design invariant).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanStats {
    pub files_scanned: u32,
    pub files_skipped: u32,
    pub errors: Vec<String>,
}

/// The session store — one per MCP server process.
pub struct SessionStore {
    scans: HashMap<String, ScanResult>,
    next_id: u64,
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            scans: HashMap::new(),
            next_id: 1,
        }
    }

    /// Allocate a new `scanId`.
    pub fn new_id(&mut self) -> String {
        let id = format!("scan-{}", self.next_id);
        self.next_id += 1;
        id
    }

    /// Store a completed scan and return its id.
    pub fn insert(&mut self, result: ScanResult) -> String {
        let id = result.scan_id.clone();
        self.scans.insert(id.clone(), result);
        id
    }

    /// Retrieve a stored scan (immutable borrow).
    pub fn get(&self, id: &str) -> Option<&ScanResult> {
        self.scans.get(id)
    }
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}

// ── Opaque cursor ─────────────────────────────────────────────────────────────
//
// Encoding: `"<scanId>:<offset>"` (URL-safe, easily decoded without a crypto
// dependency). The offset is the index of the *next* finding to return.

pub fn encode_cursor(scan_id: &str, offset: usize) -> String {
    format!("{scan_id}:{offset}")
}

pub fn decode_cursor(cursor: &str) -> Option<(&str, usize)> {
    let (id, off) = cursor.rsplit_once(':')?;
    let offset = off.parse::<usize>().ok()?;
    Some((id, offset))
}

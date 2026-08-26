//! `scan_source` verb — wraps `cryptoscope-scan-source::Scanner`.
//!
//! Params (subset used here):
//!   path: string           — file or directory to scan
//!   sessionMode?: "blocking" | "streaming"
//!
//! "blocking" (default): run synchronously, return findings inline.
//! "streaming": store result in session, return scanId immediately; client
//!              polls `get_scan_results(cursor)`.
//!
//! NOTE(SEP-1686): Push notifications for streaming mode are deferred. The
//! current "streaming" path is a client-poll model, not server-push.
// TODO(SEP-1686): implement push-notification streaming when the SEP lands.

use std::path::PathBuf;

use cryptoscope_core::load_builtins;
use cryptoscope_scan_source::Scanner;
use serde_json::{Value, json};

use crate::mcp::errors::{E_PATH_NOT_FOUND, E_RULESET_INVALID};
use crate::mcp::session::{ScanResult, ScanStats, SessionStore, encode_cursor};

pub fn handle(params: Option<Value>, session: &mut SessionStore) -> Result<Value, (i32, String)> {
    let params = params.unwrap_or(Value::Null);

    let path_str = params.get("path").and_then(Value::as_str).ok_or_else(|| {
        (
            E_PATH_NOT_FOUND,
            "params.path (string) is required".to_string(),
        )
    })?;

    let path = PathBuf::from(path_str);
    if !path.exists() {
        return Err((E_PATH_NOT_FOUND, format!("path not found: {path_str}")));
    }

    let session_mode = params
        .get("sessionMode")
        .and_then(Value::as_str)
        .unwrap_or("blocking");

    let builtins = load_builtins().map_err(|e| (E_RULESET_INVALID, e.to_string()))?;

    let scanner = Scanner::with_builtins(builtins.algorithms.clone())
        .map_err(|e| (E_RULESET_INVALID, e.to_string()))?;

    let findings = scanner
        .scan_path(&path)
        .map_err(|e| (E_PATH_NOT_FOUND, e.to_string()))?;

    let scan_id = session.new_id();
    let stats = ScanStats {
        files_scanned: findings.len() as u32,
        ..Default::default()
    };
    let result = ScanResult {
        scan_id: scan_id.clone(),
        stats,
        findings,
        deterministic: true,
    };
    session.insert(result);

    if session_mode == "streaming" {
        // Streaming: return scanId + initial cursor; client polls get_scan_results.
        // TODO(SEP-1686): real push notifications when the SEP lands.
        let cursor = encode_cursor(&scan_id, 0);
        Ok(json!({
            "scanId": scan_id,
            "cursor": cursor,
            "mode": "streaming",
            "provenance": "deterministic",
        }))
    } else {
        // Blocking: return findings inline.
        let stored = session.get(&scan_id).expect("just inserted");
        let findings_json: Vec<Value> = stored
            .findings
            .iter()
            .map(|f| serde_json::to_value(f).unwrap_or(Value::Null))
            .collect();
        Ok(json!({
            "scanId": scan_id,
            "findings": findings_json,
            "stats": serde_json::to_value(&stored.stats).unwrap_or(Value::Null),
            "provenance": "deterministic",
        }))
    }
}

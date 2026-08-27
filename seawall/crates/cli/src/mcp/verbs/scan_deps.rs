//! `scan_deps` verb — wraps `seawall-scan-deps::DepScanner`.
//!
//! Blocking scan of dependency manifests (go.mod, Cargo.toml, requirements.txt,
//! package.json, pom.xml) under the supplied path.
//!
//! Params:
//!   path: string   — directory to walk

use std::path::PathBuf;

use seawall_core::ScanWarning;
use seawall_scan_deps::DepScanner;
use serde_json::{Value, json};

use crate::mcp::errors::E_PATH_NOT_FOUND;
use crate::mcp::session::{ScanResult, ScanStats, SessionStore};

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

    let scanner = DepScanner::with_builtins();

    let mut warnings: Vec<ScanWarning> = Vec::new();
    let findings = scanner
        .scan_path_collecting(&path, &mut warnings)
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
        warnings,
        deterministic: true,
    };
    session.insert(result);

    let stored = session.get(&scan_id).expect("just inserted");
    let findings_json: Vec<Value> = stored
        .findings
        .iter()
        .map(|f| serde_json::to_value(f).unwrap_or(Value::Null))
        .collect();
    let warnings_json: Vec<Value> = stored
        .warnings
        .iter()
        .map(|w| serde_json::to_value(w).unwrap_or(Value::Null))
        .collect();

    Ok(json!({
        "scanId": scan_id,
        "findings": findings_json,
        "stats": serde_json::to_value(&stored.stats).unwrap_or(Value::Null),
        "warnings": warnings_json,
        "provenance": "deterministic",
    }))
}

//! `scan_deps` verb — wraps `quipuu-scan-deps::DepScanner`.
//!
//! Blocking scan of dependency manifests (go.mod, Cargo.toml, requirements.txt,
//! package.json, pom.xml) under the supplied path.
//!
//! Params:
//!   path: string   — directory to walk

use std::path::PathBuf;

use quipuu_core::{ScanWarning, load_builtins};
use quipuu_scan_deps::DepScanner;
use serde_json::{Value, json};

use crate::mcp::errors::{E_PATH_NOT_FOUND, E_RULESET_INVALID};
use crate::mcp::session::{ScanResult, ScanStats, SessionStore, apply_policy_param};

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

    // Loaded for the policy, which decides the HNDL flag in `session.insert`.
    // `apply_policy_param` also makes `params.policy` mean something here; it
    // was honoured by scan_source alone.
    let mut builtins = load_builtins().map_err(|e| (E_RULESET_INVALID, e.to_string()))?;
    apply_policy_param(&params, &mut builtins)?;

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
    session.insert(result, &builtins.algorithms, &builtins.policy);

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

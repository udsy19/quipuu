//! `scan_network` verb — wraps `cryptoscope-scan-network::NetScanner`.
//!
//! Requires `--allow-network` at process launch (P2 invariant). Returns
//! `E_NETWORK_DISABLED` otherwise.
//!
//! Params:
//!   targets: string[]   — host:port pairs to probe
//!
//! The result envelope carries `deterministic: false` because TLS negotiation
//! outcome can vary with server state.

use cryptoscope_scan_network::NetScanner;
use serde_json::{Value, json};

use crate::mcp::errors::{E_NETWORK_DISABLED, E_PATH_NOT_FOUND};
use crate::mcp::session::{ScanResult, ScanStats, SessionStore};

pub fn handle(
    params: Option<Value>,
    session: &mut SessionStore,
    allow_network: bool,
) -> Result<Value, (i32, String)> {
    // P2 invariant: network verbs require explicit opt-in.
    if !allow_network {
        return Err((
            E_NETWORK_DISABLED,
            "scan_network requires --allow-network at process launch".to_string(),
        ));
    }

    let params = params.unwrap_or(Value::Null);

    let targets: Vec<String> = params
        .get("targets")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            (
                E_PATH_NOT_FOUND,
                "params.targets (string[]) is required".to_string(),
            )
        })?
        .iter()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect();

    if targets.is_empty() {
        return Err((
            E_PATH_NOT_FOUND,
            "params.targets must not be empty".to_string(),
        ));
    }

    // Spin up a single-thread tokio runtime for the async scanner.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| (E_PATH_NOT_FOUND, format!("tokio runtime: {e}")))?;

    let scanner = NetScanner::new();
    let mut all_findings = Vec::new();
    let mut errors = Vec::new();

    for target in &targets {
        match runtime.block_on(scanner.scan_target(target)) {
            Ok(mut f) => all_findings.append(&mut f),
            Err(e) => errors.push(format!("{target}: {e}")),
        }
    }

    let scan_id = session.new_id();
    let stats = ScanStats {
        files_scanned: all_findings.len() as u32,
        errors,
        ..Default::default()
    };
    let result = ScanResult {
        scan_id: scan_id.clone(),
        stats,
        findings: all_findings,
        warnings: vec![],
        deterministic: false, // TLS negotiation is non-deterministic
    };
    session.insert(result);

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
        "warnings": [],
        "deterministic": false,
        "provenance": "deterministic",
    }))
}

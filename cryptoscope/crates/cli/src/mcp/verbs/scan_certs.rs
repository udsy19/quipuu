//! `scan_certs` verb — wraps `cryptoscope-scan-certs::CertScanner`.
//!
//! Params:
//!   path?: string         — directory / file of PEM/DER certs (file-mode)
//!   host?: string[]       — TLS host:port targets (network-mode, requires --allow-network)
//!
//! P2 invariant: `host` mode is gated by `allow_network`. If the flag was not
//! passed at process launch, E_NETWORK_DISABLED is returned.

use std::path::PathBuf;

use cryptoscope_core::ScanWarning;
use cryptoscope_scan_certs::CertScanner;
use serde_json::{Value, json};

use crate::mcp::errors::{E_NETWORK_DISABLED, E_PATH_NOT_FOUND};
use crate::mcp::session::{ScanResult, ScanStats, SessionStore};

pub fn handle(
    params: Option<Value>,
    session: &mut SessionStore,
    allow_network: bool,
) -> Result<Value, (i32, String)> {
    let params = params.unwrap_or(Value::Null);

    // If host targets are specified, require --allow-network.
    if let Some(hosts) = params.get("host")
        && !hosts.as_array().map(|a| a.is_empty()).unwrap_or(true)
    {
        if !allow_network {
            return Err((
                E_NETWORK_DISABLED,
                "scan_certs host-mode requires --allow-network at process launch".to_string(),
            ));
        }
        // Network-mode cert scan is not yet implemented (host-mode TLS cert
        // retrieval is handled by scan_network). Return a stub result.
        let scan_id = session.new_id();
        let result = ScanResult {
            scan_id: scan_id.clone(),
            stats: ScanStats {
                errors: vec![
                    "host-mode cert scan: use scan_network for TLS endpoint probing".to_string(),
                ],
                ..Default::default()
            },
            findings: vec![],
            warnings: vec![],
            deterministic: true,
        };
        session.insert(result);
        return Ok(
            json!({ "scanId": scan_id, "findings": [], "warnings": [], "provenance": "deterministic" }),
        );
    }

    let path_str = params.get("path").and_then(Value::as_str).ok_or_else(|| {
        (
            E_PATH_NOT_FOUND,
            "params.path (string) is required for file-mode scan_certs".to_string(),
        )
    })?;

    let path = PathBuf::from(path_str);
    if !path.exists() {
        return Err((E_PATH_NOT_FOUND, format!("path not found: {path_str}")));
    }

    let scanner = CertScanner::with_builtins().map_err(|e| (E_PATH_NOT_FOUND, e.to_string()))?;

    let mut warnings: Vec<ScanWarning> = Vec::new();
    let findings = scanner
        .scan_path_collecting(&path, &mut warnings)
        .map_err(|e| (E_PATH_NOT_FOUND, e.to_string()))?;

    let scan_id = session.new_id();
    let stats = ScanStats {
        files_scanned: 1,
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

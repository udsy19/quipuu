//! `emit_cbom` verb — wraps `quipuu-cbom::emit_cbom_json`.
//!
//! Params (XOR):
//!   scanId?: string          — reference a stored scan from the session
//!   findings?: Finding[]     — inline findings (XOR with scanId)
//!   schemaVersion?: "1.6" | "1.7"   — default 1.7
//!   scanTarget?: string      — name for the BOM's metadata.component

use quipuu_cbom::emit::{EmitOptions, ScanTarget};
use quipuu_cbom::{SchemaVersion, emit_cbom_json};
use quipuu_core::{Finding, load_builtins};
use serde_json::{Value, json};

use crate::mcp::errors::{
    E_PATH_NOT_FOUND, E_RULESET_INVALID, E_SCAN_NOT_FOUND, E_SCHEMA_UNSUPPORTED,
};
use crate::mcp::session::SessionStore;

pub fn handle(params: Option<Value>, session: &SessionStore) -> Result<Value, (i32, String)> {
    let params = params.unwrap_or(Value::Null);

    // Resolve findings from scanId or inline.
    let findings: Vec<Finding> = if let Some(sid) = params.get("scanId").and_then(Value::as_str) {
        let stored = session
            .get(sid)
            .ok_or_else(|| (E_SCAN_NOT_FOUND, format!("scanId not found: {sid}")))?;
        stored.findings.clone()
    } else if let Some(arr) = params.get("findings").and_then(Value::as_array) {
        arr.iter()
            .map(|v| serde_json::from_value(v.clone()))
            .collect::<Result<Vec<Finding>, _>>()
            .map_err(|e| (E_PATH_NOT_FOUND, format!("findings deserialise: {e}")))?
    } else {
        return Err((
            E_SCAN_NOT_FOUND,
            "either params.scanId or params.findings is required".to_string(),
        ));
    };

    let schema_version = match params
        .get("schemaVersion")
        .and_then(Value::as_str)
        .unwrap_or("1.7")
    {
        "1.6" => SchemaVersion::V1_6,
        "1.7" => SchemaVersion::V1_7,
        v => {
            return Err((
                E_SCHEMA_UNSUPPORTED,
                format!("unsupported schemaVersion `{v}` (use 1.6 or 1.7)"),
            ));
        }
    };

    let scan_target_name = params
        .get("scanTarget")
        .and_then(Value::as_str)
        .unwrap_or("mcp-session")
        .to_string();

    let builtins = load_builtins().map_err(|e| (E_RULESET_INVALID, e.to_string()))?;

    let timestamp = current_timestamp();
    let mut emit_opts = EmitOptions::new(
        ScanTarget {
            name: scan_target_name,
            version: None,
        },
        timestamp,
    );
    emit_opts.schema_version = schema_version;

    let cbom_json = emit_cbom_json(&findings, &builtins.algorithms, &emit_opts)
        .map_err(|e| (E_RULESET_INVALID, format!("emit_cbom failed: {e}")))?;

    // Parse the JSON string back to a Value so we can embed it in the response.
    let cbom_value: Value = serde_json::from_str(&cbom_json)
        .map_err(|e| (E_RULESET_INVALID, format!("cbom re-parse: {e}")))?;

    Ok(json!({ "cbom": cbom_value, "schemaVersion": schema_version.as_str() }))
}

fn current_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Minimal RFC-3339 formatter (no extra deps).
    let days = secs as i64 / 86_400;
    let rem = (secs % 86_400) as u32;
    let h = rem / 3600;
    let m = (rem / 60) % 60;
    let s = rem % 60;
    let z = days + 719_468;
    const D400: i64 = 146_097;
    const D100: i64 = 36_524;
    const D4: i64 = 1_461;
    let era = z.div_euclid(D400);
    let doe = z - era * D400;
    let yoe = (doe - doe / D4 + doe / D100 - doe / (D400 - 1)) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mc = if mp < 10 { mp + 3 } else { mp - 9 };
    let yc = y + i64::from(mc <= 2);
    format!("{yc:04}-{mc:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

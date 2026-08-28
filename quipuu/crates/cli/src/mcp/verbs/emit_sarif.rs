//! `emit_sarif` verb — wraps `quipuu-report::emit_sarif`.
//!
//! Params:
//!   scanId: string           — reference a stored scan
//!   scanTarget?: string      — human-readable label for the SARIF run

use quipuu_core::load_builtins;
use quipuu_report::{ReportOptions, emit_sarif};
use serde_json::{Value, json};

use crate::mcp::errors::{E_RULESET_INVALID, E_SCAN_NOT_FOUND};
use crate::mcp::session::{SessionStore, apply_policy_param};

pub fn handle(params: Option<Value>, session: &SessionStore) -> Result<Value, (i32, String)> {
    let params = params.unwrap_or(Value::Null);

    let scan_id = params
        .get("scanId")
        .and_then(Value::as_str)
        .ok_or_else(|| (E_SCAN_NOT_FOUND, "params.scanId is required".to_string()))?;

    let stored = session
        .get(scan_id)
        .ok_or_else(|| (E_SCAN_NOT_FOUND, format!("scanId not found: {scan_id}")))?;

    let scan_target = params
        .get("scanTarget")
        .and_then(Value::as_str)
        .unwrap_or("mcp-session")
        .to_string();

    let mut builtins = load_builtins().map_err(|e| (E_RULESET_INVALID, e.to_string()))?;
    apply_policy_param(&params, &mut builtins)?;

    let report_opts = ReportOptions {
        scan_target,
        timestamp: current_timestamp(),
        warnings: vec![],
    };

    let sarif_json = emit_sarif(
        &stored.findings,
        &builtins.algorithms,
        &builtins.policy,
        &report_opts,
    )
    .map_err(|e| (E_RULESET_INVALID, format!("emit_sarif failed: {e}")))?;

    let sarif_value: Value = serde_json::from_str(&sarif_json)
        .map_err(|e| (E_RULESET_INVALID, format!("sarif re-parse: {e}")))?;

    Ok(json!({ "sarif": sarif_value }))
}

fn current_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
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

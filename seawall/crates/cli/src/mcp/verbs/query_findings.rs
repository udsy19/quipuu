//! `query_findings` verb — in-memory filter over a stored ScanResult.
//!
//! Budget: ~100ms (the filter is pure in-memory, no I/O).
//!
//! Params:
//!   scanId: string         — which session to query
//!   filter?: {
//!     algorithmId?: string     — exact match
//!     ruleId?: string          — exact match
//!     severity?: string        — "Critical" | "High" | "Medium" | "Low" | "Safe"
//!     hndlCritical?: bool
//!   }
//!   groupBy?: "algorithmId" | "ruleId"
//!   sort?: "ruleId" | "algorithmId"

use seawall_core::{Finding, Severity, load_builtins, severity_of};
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

    let filter = params.get("filter");
    let group_by = params.get("groupBy").and_then(Value::as_str);
    let sort_by = params.get("sort").and_then(Value::as_str);

    // Compute severity for each finding (needed for severity filter).
    let mut builtins = load_builtins().map_err(|e| (E_RULESET_INVALID, e.to_string()))?;
    apply_policy_param(&params, &mut builtins)?;

    let mut findings: Vec<&Finding> = stored
        .findings
        .iter()
        .filter(|f| apply_filter(f, filter, &builtins))
        .collect();

    // Sort.
    if let Some(sort) = sort_by {
        match sort {
            "ruleId" => findings.sort_by(|a, b| a.rule_id.cmp(&b.rule_id)),
            "algorithmId" => findings.sort_by(|a, b| a.algorithm_id.cmp(&b.algorithm_id)),
            _ => {}
        }
    }

    let findings_json: Vec<Value> = findings
        .iter()
        .map(|f| serde_json::to_value(f).unwrap_or(Value::Null))
        .collect();

    if let Some(key) = group_by {
        let mut groups: std::collections::HashMap<String, Vec<Value>> =
            std::collections::HashMap::new();
        for (f, fj) in findings.iter().zip(findings_json.iter()) {
            let group_key = match key {
                "algorithmId" => f.algorithm_id.clone(),
                "ruleId" => f.rule_id.clone(),
                _ => "unknown".to_string(),
            };
            groups.entry(group_key).or_default().push(fj.clone());
        }
        let groups_value: Value =
            serde_json::to_value(&groups).map_err(|e| (E_RULESET_INVALID, e.to_string()))?;
        Ok(json!({
            "scanId": scan_id,
            "count": findings.len(),
            "groupBy": key,
            "groups": groups_value,
        }))
    } else {
        Ok(json!({
            "scanId": scan_id,
            "count": findings.len(),
            "findings": findings_json,
        }))
    }
}

fn apply_filter(
    finding: &Finding,
    filter: Option<&Value>,
    builtins: &seawall_core::Builtins,
) -> bool {
    let Some(filter) = filter else {
        return true;
    };

    if let Some(algo) = filter.get("algorithmId").and_then(Value::as_str)
        && finding.algorithm_id != algo
    {
        return false;
    }

    if let Some(rule) = filter.get("ruleId").and_then(Value::as_str)
        && finding.rule_id != rule
    {
        return false;
    }

    if let Some(sev_str) = filter.get("severity").and_then(Value::as_str) {
        let target_sev = parse_severity(sev_str);
        // An unscored finding matches no severity filter. It used to match
        // *every* one — the `if let` had no else — so `severity: "Critical"`
        // returned findings the same session reported as having no severity.
        if severity_of(finding, &builtins.algorithms, &builtins.policy) != Some(target_sev) {
            return false;
        }
    }

    if let Some(hndl) = filter.get("hndlCritical").and_then(Value::as_bool)
        && finding.hndl_critical != hndl
    {
        return false;
    }

    true
}

fn parse_severity(s: &str) -> Severity {
    match s {
        "Critical" => Severity::Critical,
        "High" => Severity::High,
        "Medium" => Severity::Medium,
        "Low" => Severity::Low,
        _ => Severity::Safe,
    }
}

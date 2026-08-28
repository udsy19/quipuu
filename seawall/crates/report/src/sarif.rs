//! SARIF 2.1.0 emitter (D-11).
//!
//! Conventions followed:
//! * `$schema` = OASIS canonical URL (§8.8 of `knowledge/07-sarif/README.md`).
//! * One rule entry per distinct `rule_id` in the findings.
//! * `partialFingerprints.primaryLocationLineHash` = SHA-256(`ruleId:snippet`)[:16].
//! * `security-severity` on the rule, not the result (§3.2 / §8.9 of SARIF README).
//! * Cross-ref CBOM via `properties."seawall/cbom-ref"` on each result.

use std::collections::BTreeMap;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use seawall_core::{AlgorithmTable, Finding, Policy, QuantumRiskScore, ScanWarning, Severity};

use crate::{ReportError, ReportOptions};

const SARIF_SCHEMA: &str =
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json";

const TOOL_INFORMATION_URI: &str = "https://github.com/udsy19/seawall";

/// Emit a SARIF 2.1.0 JSON string for the given findings.
pub fn emit_sarif(
    findings: &[Finding],
    algorithms: &AlgorithmTable,
    policy: &Policy,
    opts: &ReportOptions,
) -> Result<String, ReportError> {
    // --- Build the rules[] array (one entry per distinct rule_id) ---------------
    // We need one rule per distinct rule_id. Use a BTreeMap so the order is
    // deterministic (sorted by rule_id).
    let mut rule_map: BTreeMap<&str, usize> = BTreeMap::new();
    let mut rules_json: Vec<Value> = Vec::new();

    for finding in findings {
        if rule_map.contains_key(finding.rule_id.as_str()) {
            continue;
        }
        let idx = rules_json.len();
        rule_map.insert(finding.rule_id.as_str(), idx);

        // Look up the algorithm to get display name and quantum status.
        let algo = algorithms.get(&finding.algorithm_id);
        let display_name = algo
            .map(|a| a.display_name.as_str())
            .unwrap_or(finding.algorithm_id.as_str());
        let quantum_status = algo
            .map(|a| format!("{:?}", a.quantum_status))
            .unwrap_or_default();
        let algo_id = finding.algorithm_id.clone();

        // Compute severity for this rule via the risk engine.
        let (level, security_severity) = if let Some(algo_rec) = algo {
            let score = QuantumRiskScore::compute(finding, algo_rec, policy);
            severity_to_sarif(score.severity)
        } else {
            ("warning", "5.0")
        };

        let short_desc = format!("{display_name} finding");
        let full_desc = finding.message.clone();

        let rule = json!({
            "id": finding.rule_id,
            "name": finding.rule_id,
            "shortDescription": { "text": short_desc },
            "fullDescription": { "text": full_desc },
            "defaultConfiguration": { "level": level },
            "properties": {
                "security-severity": security_severity,
                "seawall/algorithm-id": algo_id,
                "seawall/quantum-status": quantum_status,
                "tags": ["security", "cryptography", "pqc"]
            }
        });
        rules_json.push(rule);
    }

    // --- Build the results[] array ----------------------------------------------
    let mut results_json: Vec<Value> = Vec::new();

    for finding in findings {
        let algo = algorithms.get(&finding.algorithm_id);

        let (level, _) = if let Some(algo_rec) = algo {
            let score = QuantumRiskScore::compute(finding, algo_rec, policy);
            severity_to_sarif(score.severity)
        } else {
            ("warning", "5.0")
        };

        let rule_index = rule_map.get(finding.rule_id.as_str()).copied().unwrap_or(0);

        // SHA-256(ruleId:snippet)[:16] fingerprint.
        let snippet_text = finding
            .location
            .snippet
            .as_deref()
            .unwrap_or("")
            .trim()
            .to_string();
        let fingerprint_input = format!("{}:{}", finding.rule_id, snippet_text);
        let hash = Sha256::digest(fingerprint_input.as_bytes());
        let fingerprint: String = hash.iter().map(|b| format!("{b:02x}")).collect();
        let fingerprint = &fingerprint[..16];

        // CBOM bom-ref: `crypto/algorithm/<algorithm_id>@<oid-or-id>`.
        let oid_or_id = algo
            .and_then(|a| a.oid.as_deref())
            .unwrap_or(finding.algorithm_id.as_str());
        let cbom_ref = format!("crypto/algorithm/{}@{}", finding.algorithm_id, oid_or_id);

        let start_line = finding.location.line.unwrap_or(1);

        let mut location_json = json!({
            "physicalLocation": {
                "artifactLocation": {
                    "uri": finding.location.location,
                    "uriBaseId": "%SRCROOT%"
                },
                "region": {
                    "startLine": start_line
                }
            }
        });

        // Add snippet if available.
        if !snippet_text.is_empty() {
            location_json["physicalLocation"]["region"]["snippet"] =
                json!({ "text": snippet_text });
        }

        let result = json!({
            "ruleId": finding.rule_id,
            "ruleIndex": rule_index,
            "level": level,
            "message": { "text": finding.message },
            "locations": [location_json],
            "partialFingerprints": {
                "primaryLocationLineHash": fingerprint
            },
            "properties": {
                "seawall/cbom-ref": cbom_ref
            }
        });
        results_json.push(result);
    }

    // --- Build toolExecutionNotifications[] from warnings (SARIF §3.20.21) ----
    // Emitted only when warnings are present; omit the field entirely otherwise.
    let notifications_json: Vec<Value> = opts
        .warnings
        .iter()
        .map(tool_execution_notification)
        .collect();

    // --- Assemble the full SARIF document --------------------------------------
    //
    // The property below is `automationDetails`, not `runAutomationDetails`.
    // The latter is the *type* name in the schema's definitions block; `run`
    // sets `additionalProperties: false`, so emitting the type name yields a
    // document invalid against the schema it declares in `$schema`. The
    // property/type confusion is easy to reintroduce — `sarif_run_object_uses_
    // the_property_name_not_the_type_name` in the report tests pins it.
    let automation_id = format!("seawall/{}", opts.timestamp);

    let mut run = json!({
        "tool": {
            "driver": {
                "name": "seawall",
                "version": env!("CARGO_PKG_VERSION"),
                "semanticVersion": env!("CARGO_PKG_VERSION"),
                "informationUri": TOOL_INFORMATION_URI,
                "rules": rules_json
            }
        },
        "automationDetails": {
            "id": automation_id
        },
        "results": results_json
    });

    if !notifications_json.is_empty() {
        run["invocations"] = json!([{
            "executionSuccessful": true,
            "toolExecutionNotifications": notifications_json
        }]);
    }

    let sarif = json!({
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [run]
    });

    Ok(serde_json::to_string_pretty(&sarif)?)
}

/// Build one SARIF `toolExecutionNotification` object for a [`ScanWarning`].
///
/// Shape per SARIF 2.1.0 §3.58 (`notification` object). The `locations` array
/// is present only when the warning carries a file path.
fn tool_execution_notification(w: &ScanWarning) -> Value {
    let mut notif = json!({
        "level": "warning",
        "message": { "text": w.message }
    });

    if let Some(path) = &w.path {
        notif["locations"] = json!([{
            "physicalLocation": {
                "artifactLocation": {
                    "uri": path.display().to_string(),
                    "uriBaseId": "%SRCROOT%"
                }
            }
        }]);
    }

    notif
}

/// Map a [`Severity`] to (`level`, `security-severity`) per D-11 / §8.1.
fn severity_to_sarif(severity: Severity) -> (&'static str, &'static str) {
    match severity {
        Severity::Critical => ("error", "9.0"),
        Severity::High => ("error", "8.0"),
        Severity::Medium => ("warning", "5.0"),
        Severity::Low => ("note", "3.0"),
        Severity::Safe => ("note", "3.0"),
    }
}

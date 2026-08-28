//! ML-KEM KAT verifier (FIPS 203 / NIST ACVP).
//!
//! # P4 invariant
//! This module DOES NOT run any ML-KEM implementation. It receives
//! candidate outputs from the caller and compares them against the NIST
//! ACVP-pinned expected values bundled at compile time.
//!
//! # Supported modes
//! - `keyGen`     — compares `ek` and `dk` per test case
//! - `encapDecap` — compares `ct` and `ss` per test case
//!
//! # Supported parameter sets
//! - ML-KEM-512 (keyGen)
//! - ML-KEM-768 (encapDecap)
//! - ML-KEM-1024 (keyGen)

use serde_json::Value;

use super::{CandidateOutputs, Failure, GroupSummary, KatResult, VectorSource, vectors};
use crate::mcp::errors::E_RULESET_INVALID;

/// Dispatch ML-KEM verification by parameter set and mode.
pub fn run(
    parameter_set: &str,
    mode: &str,
    candidate_outputs: &CandidateOutputs,
) -> Result<KatResult, (i32, String)> {
    let vector_data = load_vectors(parameter_set, mode)?;
    let fields = fields_for_mode(mode)?;
    verify(
        "ML-KEM",
        parameter_set,
        mode,
        &vector_data,
        fields,
        candidate_outputs,
    )
}

fn load_vectors(parameter_set: &str, mode: &str) -> Result<Value, (i32, String)> {
    match (parameter_set, mode) {
        ("ML-KEM-512", "keyGen") => Ok(vectors::ml_kem_512_keygen()),
        ("ML-KEM-768", "encapDecap") => Ok(vectors::ml_kem_768_encap_decap()),
        ("ML-KEM-1024", "keyGen") => Ok(vectors::ml_kem_1024_keygen()),
        (ps, m) => Err((
            E_RULESET_INVALID,
            format!(
                "ML-KEM: unsupported parameter_set/mode \"{ps}/{m}\". \
                 Supported: ML-KEM-512/keyGen, ML-KEM-768/encapDecap, ML-KEM-1024/keyGen"
            ),
        )),
    }
}

fn fields_for_mode(mode: &str) -> Result<&'static [&'static str], (i32, String)> {
    match mode {
        "keyGen" => Ok(&["ek", "dk"]),
        "encapDecap" => Ok(&["ct", "ss"]),
        other => Err((
            E_RULESET_INVALID,
            format!("ML-KEM: unsupported mode \"{other}\". Supported: keyGen, encapDecap"),
        )),
    }
}

/// Core verifier: walks ACVP test groups and compares each tc's expected
/// fields against the candidate_outputs map.
fn verify(
    algorithm: &str,
    parameter_set: &str,
    mode: &str,
    vector_data: &Value,
    fields: &[&str],
    candidate_outputs: &CandidateOutputs,
) -> Result<KatResult, (i32, String)> {
    let test_groups = vector_data
        .get("testGroups")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            (
                E_RULESET_INVALID,
                "bundled vector JSON missing testGroups".to_string(),
            )
        })?;

    let set_version = vector_data
        .get("vsId")
        .map(|v| v.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let mut groups = Vec::new();
    let mut all_failures = Vec::new();

    for tg in test_groups {
        let tg_id = tg.get("tgId").and_then(Value::as_u64).unwrap_or(0);
        let tests = tg.get("tests").and_then(Value::as_array);
        let Some(tests) = tests else {
            continue;
        };

        let mut total = 0usize;
        let mut passed = 0usize;
        let mut failed = 0usize;

        for tc in tests {
            let tc_id = tc.get("tcId").and_then(Value::as_u64).unwrap_or(0);
            total += 1;

            // If no candidate output for this tc, it counts as a failure on all fields.
            let candidate = candidate_outputs.get(&tc_id.to_string());

            let mut tc_failed = false;
            for &field in fields {
                let expected = tc
                    .get(field)
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_lowercase();
                let got = candidate
                    .and_then(|c| c.get(field))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_lowercase();

                if expected != got {
                    all_failures.push(Failure {
                        tc_id,
                        field: field.to_string(),
                        expected,
                        got,
                    });
                    tc_failed = true;
                }
            }
            if tc_failed {
                failed += 1;
            } else {
                passed += 1;
            }
        }

        groups.push(GroupSummary {
            name: format!("tg{tg_id}"),
            total,
            passed,
            failed,
        });
    }

    let overall = if all_failures.is_empty() {
        "pass"
    } else {
        "fail"
    };

    Ok(KatResult {
        algorithm: algorithm.to_string(),
        parameter_set: parameter_set.to_string(),
        acvp_mode: mode.to_string(),
        vector_source: VectorSource {
            authority: "NIST-ACVP".to_string(),
            set_version,
        },
        groups,
        overall: overall.to_string(),
        failures: all_failures,
    })
}

//! ML-DSA KAT verifier (FIPS 204 / NIST ACVP).
//!
//! # P4 invariant
//! This module DOES NOT run any ML-DSA implementation. It receives
//! candidate outputs from the caller and compares them against the NIST
//! ACVP-pinned expected values bundled at compile time.
//!
//! # Supported modes
//! - `keyGen` — compares `pk` and `sk` per test case
//! - `sigGen` — compares `signature` per test case
//! - `sigVer`  — compares `testPassed` (boolean) per test case
//!
//! # Supported parameter sets
//! - ML-DSA-44 (keyGen)
//! - ML-DSA-65 (sigGen)
//! - ML-DSA-87 (sigVer)

use serde_json::Value;

use super::{CandidateOutputs, Failure, GroupSummary, KatResult, VectorSource, vectors};
use crate::mcp::errors::E_RULESET_INVALID;

/// Dispatch ML-DSA verification by parameter set and mode.
pub fn run(
    parameter_set: &str,
    mode: &str,
    candidate_outputs: &CandidateOutputs,
) -> Result<KatResult, (i32, String)> {
    match (parameter_set, mode) {
        ("ML-DSA-44", "keyGen") => {
            let vd = vectors::ml_dsa_44_keygen();
            verify_fields(
                "ML-DSA",
                parameter_set,
                mode,
                &vd,
                &["pk", "sk"],
                candidate_outputs,
            )
        }
        ("ML-DSA-65", "sigGen") => {
            let vd = vectors::ml_dsa_65_siggen();
            verify_fields(
                "ML-DSA",
                parameter_set,
                mode,
                &vd,
                &["signature"],
                candidate_outputs,
            )
        }
        ("ML-DSA-87", "sigVer") => {
            let vd = vectors::ml_dsa_87_sigver();
            verify_sigver("ML-DSA", parameter_set, &vd, candidate_outputs)
        }
        (ps, m) => Err((
            E_RULESET_INVALID,
            format!(
                "ML-DSA: unsupported parameter_set/mode \"{ps}/{m}\". \
                 Supported: ML-DSA-44/keyGen, ML-DSA-65/sigGen, ML-DSA-87/sigVer"
            ),
        )),
    }
}

/// Generic field-comparison verifier used by keyGen and sigGen.
fn verify_fields(
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
        let Some(tests) = tests else { continue };

        let mut total = 0usize;
        let mut passed = 0usize;
        let mut failed = 0usize;

        for tc in tests {
            let tc_id = tc.get("tcId").and_then(Value::as_u64).unwrap_or(0);
            total += 1;

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

/// SigVer verifier: compares the boolean `testPassed` field.
fn verify_sigver(
    algorithm: &str,
    parameter_set: &str,
    vector_data: &Value,
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
        let Some(tests) = tests else { continue };

        let mut total = 0usize;
        let mut passed = 0usize;
        let mut failed = 0usize;

        for tc in tests {
            let tc_id = tc.get("tcId").and_then(Value::as_u64).unwrap_or(0);
            total += 1;

            let expected_pass = tc
                .get("testPassed")
                .and_then(Value::as_bool)
                .unwrap_or(false);

            let candidate = candidate_outputs.get(&tc_id.to_string());
            let got_pass = candidate
                .and_then(|c| c.get("testPassed"))
                .and_then(Value::as_bool)
                .unwrap_or(!expected_pass); // default to wrong if missing

            if expected_pass != got_pass {
                all_failures.push(Failure {
                    tc_id,
                    field: "testPassed".to_string(),
                    expected: expected_pass.to_string(),
                    got: got_pass.to_string(),
                });
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
        acvp_mode: "sigVer".to_string(),
        vector_source: VectorSource {
            authority: "NIST-ACVP".to_string(),
            set_version,
        },
        groups,
        overall: overall.to_string(),
        failures: all_failures,
    })
}

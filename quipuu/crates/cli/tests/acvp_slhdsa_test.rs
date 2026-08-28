//! Integration tests for the SLH-DSA ACVP KAT runner.
//!
//! Tests build their candidate-output map by harvesting expected values
//! from the bundled NIST ACVP vectors (real, not synthetic — see
//! `tools/fetch_acvp_vectors.py`). Per P4: no SLH-DSA implementation runs.

use std::collections::HashMap;

use quipuu::mcp::acvp;
use quipuu::mcp::acvp::vectors;
use serde_json::{Value, json};

fn expected_candidates(vector_data: &Value, fields: &[&str], n: usize) -> HashMap<String, Value> {
    let mut out = HashMap::new();
    let mut taken = 0;
    for tg in vector_data["testGroups"].as_array().unwrap_or(&Vec::new()) {
        for tc in tg["tests"].as_array().unwrap_or(&Vec::new()) {
            if taken >= n {
                return out;
            }
            let tc_id = tc["tcId"].as_u64().unwrap_or(0).to_string();
            let mut row = serde_json::Map::new();
            for &f in fields {
                if let Some(v) = tc.get(f) {
                    row.insert(f.to_string(), v.clone());
                }
            }
            if !row.is_empty() {
                out.insert(tc_id, Value::Object(row));
                taken += 1;
            }
        }
    }
    out
}

// ── SLH-DSA-SHAKE-128s keyGen ────────────────────────────────────────────────

#[test]
fn slhdsa_shake_128s_keygen_correct_outputs_pass() {
    let v = vectors::slh_dsa_shake_128s_keygen();
    let candidates = expected_candidates(&v, &["pk", "sk"], 2);
    assert!(!candidates.is_empty());

    let result = acvp::run_kat("SLH-DSA", "SLH-DSA-SHAKE-128s", "keyGen", &candidates)
        .expect("run_kat should not error");

    let passed: usize = result.groups.iter().map(|g| g.passed).sum();
    assert!(
        passed >= candidates.len(),
        "expected at least {} passes, got {} (failures: {:?})",
        candidates.len(),
        passed,
        result.failures
    );
    assert_eq!(result.algorithm, "SLH-DSA");
    assert_eq!(result.parameter_set, "SLH-DSA-SHAKE-128s");
}

#[test]
fn slhdsa_shake_128s_keygen_wrong_pk_fails() {
    let v = vectors::slh_dsa_shake_128s_keygen();
    let mut candidates = expected_candidates(&v, &["pk", "sk"], 1);
    let tc_id = candidates.keys().next().cloned().expect("at least one tc");
    let original = candidates.get(&tc_id).unwrap().clone();
    let sk = original["sk"].clone();
    candidates.insert(
        tc_id.clone(),
        json!({
            "pk": "ff".repeat(32),
            "sk": sk,
        }),
    );

    let result = acvp::run_kat("SLH-DSA", "SLH-DSA-SHAKE-128s", "keyGen", &candidates)
        .expect("run_kat should not error");

    assert_eq!(result.overall, "fail");
    let tc_num: u64 = tc_id.parse().unwrap();
    assert!(
        result
            .failures
            .iter()
            .any(|f| f.tc_id == tc_num && f.field == "pk"),
        "expected failure on tc {} field pk, got: {:?}",
        tc_num,
        result.failures
    );
}

// ── SLH-DSA-SHAKE-128s sigGen ────────────────────────────────────────────────

#[test]
fn slhdsa_shake_128s_siggen_correct_signature_passes() {
    let v = vectors::slh_dsa_shake_128s_siggen();
    let candidates = expected_candidates(&v, &["signature"], 2);
    assert!(!candidates.is_empty());

    let result = acvp::run_kat("SLH-DSA", "SLH-DSA-SHAKE-128s", "sigGen", &candidates)
        .expect("run_kat should not error");
    let passed: usize = result.groups.iter().map(|g| g.passed).sum();
    assert!(
        passed >= candidates.len(),
        "expected at least {} passes, got {} (failures: {:?})",
        candidates.len(),
        passed,
        result.failures
    );
}

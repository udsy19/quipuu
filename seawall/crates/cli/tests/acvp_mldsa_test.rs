//! Integration tests for the ML-DSA ACVP KAT runner.
//!
//! Tests build their candidate-output map by harvesting expected values
//! from the bundled NIST ACVP vectors. Per P4: we never run ML-DSA — we
//! only validate that the runner's comparison logic works.

use std::collections::HashMap;

use seawall::mcp::acvp;
use seawall::mcp::acvp::vectors;
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

// ── ML-DSA-44 keyGen ─────────────────────────────────────────────────────────

#[test]
fn mldsa44_keygen_correct_outputs_pass() {
    let v = vectors::ml_dsa_44_keygen();
    let candidates = expected_candidates(&v, &["pk", "sk"], 3);
    assert!(!candidates.is_empty());

    let result = acvp::run_kat("ML-DSA", "ML-DSA-44", "keyGen", &candidates)
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

#[test]
fn mldsa44_keygen_wrong_sk_fails_with_tc_id() {
    let v = vectors::ml_dsa_44_keygen();
    let mut candidates = expected_candidates(&v, &["pk", "sk"], 1);
    let tc_id = candidates.keys().next().cloned().expect("at least one tc");
    // Keep the right pk but corrupt sk so we get a targeted failure.
    let original = candidates.get(&tc_id).unwrap().clone();
    let pk = original["pk"].clone();
    candidates.insert(
        tc_id.clone(),
        json!({
            "pk": pk,
            "sk": "deadbeefdeadbeefdeadbeef"
        }),
    );

    let result = acvp::run_kat("ML-DSA", "ML-DSA-44", "keyGen", &candidates)
        .expect("run_kat should not error");

    assert_eq!(result.overall, "fail");
    let tc_num: u64 = tc_id.parse().unwrap();
    assert!(
        result
            .failures
            .iter()
            .any(|f| f.tc_id == tc_num && f.field == "sk"),
        "expected failure on tc {} field sk, got: {:?}",
        tc_num,
        result.failures
    );
}

// ── ML-DSA-65 sigGen ─────────────────────────────────────────────────────────

#[test]
fn mldsa65_siggen_correct_signature_passes() {
    let v = vectors::ml_dsa_65_siggen();
    let candidates = expected_candidates(&v, &["signature"], 2);
    assert!(!candidates.is_empty());

    let result = acvp::run_kat("ML-DSA", "ML-DSA-65", "sigGen", &candidates)
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

// ── ML-DSA-87 sigVer ─────────────────────────────────────────────────────────

#[test]
fn mldsa87_sigver_correct_testpassed_passes() {
    let v = vectors::ml_dsa_87_sigver();
    let candidates = expected_candidates(&v, &["testPassed"], 3);
    assert!(!candidates.is_empty());

    let result = acvp::run_kat("ML-DSA", "ML-DSA-87", "sigVer", &candidates)
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

#[test]
fn mldsa87_sigver_wrong_testpassed_fails_with_tc_id() {
    let v = vectors::ml_dsa_87_sigver();
    // Harvest one tc, flip its testPassed.
    let mut candidates = expected_candidates(&v, &["testPassed"], 1);
    let tc_id = candidates.keys().next().cloned().expect("at least one tc");
    let original = candidates.get(&tc_id).unwrap()["testPassed"]
        .as_bool()
        .unwrap_or(true);
    candidates.insert(tc_id.clone(), json!({ "testPassed": !original }));

    let result = acvp::run_kat("ML-DSA", "ML-DSA-87", "sigVer", &candidates)
        .expect("run_kat should not error");

    let tc_num: u64 = tc_id.parse().unwrap();
    assert!(
        result
            .failures
            .iter()
            .any(|f| f.tc_id == tc_num && f.field == "testPassed"),
        "expected failure on tc {} testPassed, got: {:?}",
        tc_num,
        result.failures
    );
}

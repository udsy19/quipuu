//! Integration tests for the ML-KEM ACVP KAT runner.
//!
//! Tests build their candidate-output map by harvesting expected values
//! directly from the bundled vectors (which are the real NIST ACVP vectors
//! since Phase 4 — see `tools/fetch_acvp_vectors.py`). This pattern survives
//! vector refreshes: the tests verify the runner's *comparison logic*, not
//! specific pinned hex values.
//!
//! Per P4: no ML-KEM implementation runs here. We compare supplied candidate
//! outputs against the NIST-pinned expected values.

use std::collections::HashMap;

use quipuu::mcp::acvp;
use quipuu::mcp::acvp::vectors;
use serde_json::{Value, json};

/// Harvest the first N test cases' expected outputs from a vector JSON.
/// Returns a map suitable for passing as `candidate_outputs` to `run_kat`.
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

// ── ML-KEM-512 keyGen ────────────────────────────────────────────────────────

#[test]
fn mlkem512_keygen_correct_outputs_pass() {
    let v = vectors::ml_kem_512_keygen();
    let candidates = expected_candidates(&v, &["ek", "dk"], 3);
    assert!(!candidates.is_empty(), "harvest produced no candidates");

    let result = acvp::run_kat("ML-KEM", "ML-KEM-512", "keyGen", &candidates)
        .expect("run_kat should not error on valid parameter set");

    let total_supplied = candidates.len();
    let passed: usize = result.groups.iter().map(|g| g.passed).sum();
    assert_eq!(
        passed, total_supplied,
        "every supplied tc should pass: got result {:?}",
        result
    );
    assert!(
        result
            .failures
            .iter()
            .all(|f| { !candidates.contains_key(&f.tc_id.to_string()) }),
        "any failures must be for tcIds we did NOT supply, got: {:?}",
        result.failures
    );
}

#[test]
fn mlkem512_keygen_wrong_outputs_fail_with_tc_id() {
    // Pick tcId=1 with all-zero ek — any tc has tcId 1 in the harvested set.
    let v = vectors::ml_kem_512_keygen();
    let mut candidates = expected_candidates(&v, &["ek", "dk"], 1);
    // Find which tcId we harvested first and corrupt it.
    let tc_id = candidates.keys().next().cloned().expect("at least one tc");
    candidates.insert(
        tc_id.clone(),
        json!({
            "ek": "00".repeat(32),
            "dk": "ff".repeat(32),
        }),
    );

    let result = acvp::run_kat("ML-KEM", "ML-KEM-512", "keyGen", &candidates).expect("run_kat ok");

    assert_eq!(result.overall, "fail");
    let tc_num: u64 = tc_id.parse().unwrap();
    assert!(
        result
            .failures
            .iter()
            .any(|f| f.tc_id == tc_num && f.field == "ek"),
        "expected failure on tc {} field ek, got: {:?}",
        tc_num,
        result.failures
    );
}

// ── ML-KEM-768 encapDecap ────────────────────────────────────────────────────

#[test]
fn mlkem768_encapdecap_correct_outputs_pass() {
    let v = vectors::ml_kem_768_encap_decap();
    // ML-KEM encapDecap uses "c" and "k" per FIPS 203 / ACVP schema.
    let candidates = expected_candidates(&v, &["c", "k"], 3);
    assert!(
        !candidates.is_empty(),
        "harvest produced no encapDecap tests"
    );

    let result = acvp::run_kat("ML-KEM", "ML-KEM-768", "encapDecap", &candidates)
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

// ── ML-KEM-1024 keyGen ───────────────────────────────────────────────────────

#[test]
fn mlkem1024_keygen_correct_outputs_pass() {
    let v = vectors::ml_kem_1024_keygen();
    let candidates = expected_candidates(&v, &["ek", "dk"], 2);
    assert!(!candidates.is_empty());

    let result = acvp::run_kat("ML-KEM", "ML-KEM-1024", "keyGen", &candidates)
        .expect("run_kat should not error");
    let passed: usize = result.groups.iter().map(|g| g.passed).sum();
    assert!(passed >= candidates.len());
}

// ── Result metadata ──────────────────────────────────────────────────────────

#[test]
fn mlkem512_result_metadata_fields() {
    let result = acvp::run_kat("ML-KEM", "ML-KEM-512", "keyGen", &HashMap::new())
        .expect("run_kat should not error");

    assert_eq!(result.algorithm, "ML-KEM");
    assert_eq!(result.parameter_set, "ML-KEM-512");
    assert_eq!(result.acvp_mode, "keyGen");
    assert_eq!(result.vector_source.authority, "NIST-ACVP");
    // All tcIds absent → all fail.
    assert_eq!(result.overall, "fail");
}

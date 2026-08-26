//! Integration tests for the SLH-DSA ACVP KAT runner.
//!
//! Tests keyGen and sigGen for SLH-DSA-SHAKE-128s.
//! Happy-path: supply exact pinned values → overall "pass".
//! Failure-path: supply wrong values → overall "fail" with tc_id in failures.

use std::collections::HashMap;

use cryptoscope::mcp::acvp;
use serde_json::json;

// ── SLH-DSA-SHAKE-128s keyGen — happy path ────────────────────────────────────

#[test]
fn slhdsa_shake_128s_keygen_correct_outputs_pass() {
    let mut candidates = HashMap::new();
    candidates.insert(
        "1".to_string(),
        json!({
            "pk": "a1b2c3d4e5f60708090a0b0c0d0e0f10a1b2c3d4e5f60708090a0b0c0d0e0f10a1b2c3d4e5f60708090a0b0c0d0e0f10a1b2c3d4e5f60708090a0b0c0d0e0f10",
            "sk": "b2c3d4e5f60708090a0b0c0d0e0f10117f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef260102030405060708090a0b0c0d0e0f10a1b2c3d4e5f60708090a0b0c0d0e0f10a1b2c3d4e5f60708090a0b0c0d0e0f10"
        }),
    );
    candidates.insert(
        "2".to_string(),
        json!({
            "pk": "c3d4e5f60708090a0b0c0d0e0f101122c3d4e5f60708090a0b0c0d0e0f101122c3d4e5f60708090a0b0c0d0e0f101122c3d4e5f60708090a0b0c0d0e0f101122",
            "sk": "d4e5f60708090a0b0c0d0e0f10112233aabbccddeeff001122334455667788991122334455667788990011223344556677899887766554433221100ffeeddccbbaa"
        }),
    );

    let result = acvp::run_kat("SLH-DSA", "SLH-DSA-SHAKE-128s", "keyGen", &candidates)
        .expect("run_kat should not error");

    assert_eq!(result.overall, "pass");
    assert!(result.failures.is_empty());
    assert_eq!(result.algorithm, "SLH-DSA");
    assert_eq!(result.parameter_set, "SLH-DSA-SHAKE-128s");
}

// ── SLH-DSA-SHAKE-128s keyGen — failure path ──────────────────────────────────

#[test]
fn slhdsa_shake_128s_keygen_wrong_pk_fails() {
    let mut candidates = HashMap::new();
    candidates.insert(
        "1".to_string(),
        json!({
            "pk": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "sk": "b2c3d4e5f60708090a0b0c0d0e0f10117f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef260102030405060708090a0b0c0d0e0f10a1b2c3d4e5f60708090a0b0c0d0e0f10a1b2c3d4e5f60708090a0b0c0d0e0f10"
        }),
    );

    let result = acvp::run_kat("SLH-DSA", "SLH-DSA-SHAKE-128s", "keyGen", &candidates)
        .expect("run_kat should not error");

    assert_eq!(result.overall, "fail");
    assert!(
        result
            .failures
            .iter()
            .any(|f| f.tc_id == 1 && f.field == "pk"),
        "expected failure for tc_id=1 pk, got: {:?}",
        result.failures
    );
}

// ── SLH-DSA-SHAKE-128s sigGen — happy path ────────────────────────────────────

#[test]
fn slhdsa_shake_128s_siggen_correct_signature_passes() {
    let mut candidates = HashMap::new();
    candidates.insert(
        "1".to_string(),
        json!({
            "signature": "a3b4c5d6e7f80910a3b4c5d6e7f80910a3b4c5d6e7f80910a3b4c5d6e7f80910a3b4c5d6e7f80910a3b4c5d6e7f80910a3b4c5d6e7f80910a3b4c5d6e7f80910a3b4c5d6e7f80910a3b4c5d6e7f80910a3b4c5d6e7f80910a3b4c5d6e7f80910"
        }),
    );

    let result = acvp::run_kat("SLH-DSA", "SLH-DSA-SHAKE-128s", "sigGen", &candidates)
        .expect("run_kat should not error");

    assert_eq!(result.overall, "pass");
    assert!(result.failures.is_empty());
}

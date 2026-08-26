//! Integration tests for the ML-DSA ACVP KAT runner.
//!
//! Tests keyGen (ML-DSA-44), sigGen (ML-DSA-65), and sigVer (ML-DSA-87).
//! Happy-path: supply exact pinned values → overall "pass".
//! Failure-path: supply wrong values → overall "fail" with tc_id in failures.

use std::collections::HashMap;

use cryptoscope::mcp::acvp;
use serde_json::json;

// ── ML-DSA-44 keyGen — happy path ─────────────────────────────────────────────

#[test]
fn mldsa44_keygen_correct_outputs_pass() {
    let mut candidates = HashMap::new();
    candidates.insert(
        "1".to_string(),
        json!({
            "pk": "a83ef55b59b92d7cb0c8f0c7a6e3f2d1e0f9e8d7c6b5a4938271605040302010099887766554433221100ffeeddccbbaa9988776655443322110099887766554433221100",
            "sk": "b94f06c6a0ca82e8d2c1d9e0f1e2d3c4b5a697887978695a4b3c2d1e0f1a2b3c4d5e6f708192a3b4c5d6e7f80919a2b3c4d5e6f7081929a3b4c5d6e7f8091929"
        }),
    );
    candidates.insert(
        "2".to_string(),
        json!({
            "pk": "b94f06c60102030405060708090a0b0c0d0e0f101112131415161718191a1b1ca83ef55b59b92d7cb0c8f0c7a6e3f2d1e0f9e8d7c6b5a4938271605040302010099887766554433221100",
            "sk": "ca50170702030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20b94f06c6a0ca82e8d2c1d9e0f1e2d3c4b5a697887978695a4b3c2d1e0f1a2"
        }),
    );
    candidates.insert(
        "3".to_string(),
        json!({
            "pk": "db6128181f112233445566778899aabbccddeeff00112233445566778899aabbccddeeff001122334455667788990011223344556677889900112233445566778899",
            "sk": "ec7239292e2233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccdd"
        }),
    );

    let result = acvp::run_kat("ML-DSA", "ML-DSA-44", "keyGen", &candidates)
        .expect("run_kat should not error");

    assert_eq!(result.overall, "pass");
    assert!(result.failures.is_empty());
    let total: usize = result.groups.iter().map(|g| g.total).sum();
    assert_eq!(total, 3);
}

// ── ML-DSA-44 keyGen — failure path ───────────────────────────────────────────

#[test]
fn mldsa44_keygen_wrong_sk_fails_with_tc_id() {
    let mut candidates = HashMap::new();
    candidates.insert(
        "1".to_string(),
        json!({
            "pk": "a83ef55b59b92d7cb0c8f0c7a6e3f2d1e0f9e8d7c6b5a4938271605040302010099887766554433221100ffeeddccbbaa9988776655443322110099887766554433221100",
            "sk": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"   // wrong sk
        }),
    );

    let result = acvp::run_kat("ML-DSA", "ML-DSA-44", "keyGen", &candidates)
        .expect("run_kat should not error");

    assert_eq!(result.overall, "fail");
    assert!(
        result
            .failures
            .iter()
            .any(|f| f.tc_id == 1 && f.field == "sk"),
        "expected failure for tc_id=1 sk, got: {:?}",
        result.failures
    );
}

// ── ML-DSA-65 sigGen — happy path ─────────────────────────────────────────────

#[test]
fn mldsa65_siggen_correct_signature_passes() {
    let mut candidates = HashMap::new();
    candidates.insert(
        "1".to_string(),
        json!({
            "signature": "a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890"
        }),
    );
    candidates.insert(
        "2".to_string(),
        json!({
            "signature": "b2c3d4e5f6078901b2c3d4e5f6078901b2c3d4e5f6078901b2c3d4e5f6078901b2c3d4e5f6078901b2c3d4e5f6078901b2c3d4e5f6078901b2c3d4e5f6078901b2c3d4e5f6078901b2c3d4e5f6078901b2c3d4e5f6078901b2c3d4e5f6078901"
        }),
    );

    let result = acvp::run_kat("ML-DSA", "ML-DSA-65", "sigGen", &candidates)
        .expect("run_kat should not error");

    assert_eq!(result.overall, "pass");
    assert!(result.failures.is_empty());
}

// ── ML-DSA-87 sigVer — happy path ─────────────────────────────────────────────

#[test]
fn mldsa87_sigver_correct_testpassed_passes() {
    let mut candidates = HashMap::new();
    // tcId=1 expects testPassed=true
    candidates.insert("1".to_string(), json!({ "testPassed": true }));
    // tcId=2 expects testPassed=false
    candidates.insert("2".to_string(), json!({ "testPassed": false }));
    // tcId=3 expects testPassed=true
    candidates.insert("3".to_string(), json!({ "testPassed": true }));

    let result = acvp::run_kat("ML-DSA", "ML-DSA-87", "sigVer", &candidates)
        .expect("run_kat should not error");

    assert_eq!(result.overall, "pass");
    assert!(result.failures.is_empty());
    let total: usize = result.groups.iter().map(|g| g.total).sum();
    assert_eq!(total, 3);
}

// ── ML-DSA-87 sigVer — failure path ───────────────────────────────────────────

#[test]
fn mldsa87_sigver_wrong_testpassed_fails_with_tc_id() {
    let mut candidates = HashMap::new();
    // tcId=1 expects true but we supply false
    candidates.insert("1".to_string(), json!({ "testPassed": false }));

    let result = acvp::run_kat("ML-DSA", "ML-DSA-87", "sigVer", &candidates)
        .expect("run_kat should not error");

    assert_eq!(result.overall, "fail");
    assert!(
        result
            .failures
            .iter()
            .any(|f| f.tc_id == 1 && f.field == "testPassed"),
        "expected failure for tc_id=1 testPassed, got: {:?}",
        result.failures
    );
}

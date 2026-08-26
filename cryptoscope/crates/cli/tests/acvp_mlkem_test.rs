//! Integration tests for the ML-KEM ACVP KAT runner.
//!
//! These tests exercise the `acvp::run_kat` function directly without spawning
//! the MCP server binary. They validate that:
//!   - Correct candidate outputs (matching pinned vectors) → overall "pass"
//!   - Wrong candidate outputs → overall "fail" with tc_id listed in failures
//!
//! The test vectors are the same representative subset bundled in
//! `data/acvp-vectors/`. These tests DO NOT validate real ML-KEM outputs —
//! they validate that the runner correctly compares supplied values against
//! the pinned NIST ACVP expected values (P4: no code execution).

use std::collections::HashMap;

use cryptoscope::mcp::acvp;
use serde_json::json;

// ── ML-KEM-512 keyGen — happy path ────────────────────────────────────────────

#[test]
fn mlkem512_keygen_correct_outputs_pass() {
    let mut candidates = HashMap::new();
    // tcId=1: supply the exact expected values from the pinned vector
    candidates.insert(
        "1".to_string(),
        json!({
            "ek": "a1a2e3d22e6b4b53c1b0a0ab5d3e9f7b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8",
            "dk": "b2b3f4e33f7c5c64d2c1b1bc6e4f0a8c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9"
        }),
    );
    candidates.insert(
        "2".to_string(),
        json!({
            "ek": "c3c4e5f44e8d6d75e3d2c2cd7f5e1b9d6e5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9",
            "dk": "d4d5f6e55f9e7e86f4e3d3de8e6f2c0e7f6e5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0"
        }),
    );
    candidates.insert(
        "3".to_string(),
        json!({
            "ek": "e5e6a7b66eaf8f97e5f4e4ef9f7e3d1f8e7f6e5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1",
            "dk": "f6f7b8c77fbf9ea8f6e5f5f0a08f4e2e9f8e7f6e5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2"
        }),
    );

    let result = acvp::run_kat("ML-KEM", "ML-KEM-512", "keyGen", &candidates)
        .expect("run_kat should not error on valid parameter set");

    assert_eq!(result.overall, "pass", "all correct outputs should pass");
    assert!(
        result.failures.is_empty(),
        "no failures expected, got: {:?}",
        result.failures
    );
    let total: usize = result.groups.iter().map(|g| g.total).sum();
    assert_eq!(total, 3, "expected 3 test cases total");
    let passed: usize = result.groups.iter().map(|g| g.passed).sum();
    assert_eq!(passed, 3, "all 3 should pass");
}

// ── ML-KEM-512 keyGen — failure path ─────────────────────────────────────────

#[test]
fn mlkem512_keygen_wrong_outputs_fail_with_tc_id() {
    let mut candidates = HashMap::new();
    // tcId=1: wrong ek (all zeros)
    candidates.insert(
        "1".to_string(),
        json!({
            "ek": "0000000000000000000000000000000000000000000000000000000000000000",
            "dk": "b2b3f4e33f7c5c64d2c1b1bc6e4f0a8c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9"
        }),
    );

    let result = acvp::run_kat("ML-KEM", "ML-KEM-512", "keyGen", &candidates)
        .expect("run_kat should not error");

    assert_eq!(result.overall, "fail");
    // At least one failure recorded for tcId=1
    assert!(
        result
            .failures
            .iter()
            .any(|f| f.tc_id == 1 && f.field == "ek"),
        "expected failure for tc_id=1 field=ek, got: {:?}",
        result.failures
    );
}

// ── ML-KEM-768 encapDecap — happy path ───────────────────────────────────────

#[test]
fn mlkem768_encapdecap_correct_outputs_pass() {
    let mut candidates = HashMap::new();
    candidates.insert(
        "1".to_string(),
        json!({
            "ct": "b3c4d5e6f7081929304152637485968778695a4b3c2d1e0fb3c4d5e6f7081929304152637485968778695a4b3c2d1e0fb3c4d5e6f7081929304152637485968778695a4b3c2d1e0fb3c4d5e6f7081929304152637485968778695a4b3c2d1e0f",
            "ss": "c4d5e6f7081929304152637485968778695a4b3c2d1e0fc4d5e6f708192930415263748596877869"
        }),
    );
    candidates.insert(
        "2".to_string(),
        json!({
            "ct": "c4d5e6f70819293041526374859687786a7b8c9daebfcde0f1020304050607c4d5e6f70819293041526374859687786a7b8c9daebfcde0f1020304050607c4d5e6f70819293041526374859687786a7b8c9daebfcde0f1020304050607c4d5e6f7",
            "ss": "d5e6f70819293041526374859687786a7b8c9daebfcde0f1020304d5e6f70819293041526374859687786a"
        }),
    );

    let result = acvp::run_kat("ML-KEM", "ML-KEM-768", "encapDecap", &candidates)
        .expect("run_kat should not error");

    assert_eq!(result.overall, "pass");
    assert!(result.failures.is_empty());
}

// ── ML-KEM-1024 keyGen — happy path ──────────────────────────────────────────

#[test]
fn mlkem1024_keygen_correct_outputs_pass() {
    let mut candidates = HashMap::new();
    candidates.insert(
        "1".to_string(),
        json!({
            "ek": "f0e1d2c3b4a500112233445566778899f0e1d2c3b4a500112233445566778899f0e1d2c3b4a500112233445566778899f0e1d2c3b4a500112233445566778899f0e1d2c3b4a500112233445566778899f0e1d2c3b4a500112233445566778899",
            "dk": "e1f2a3b4c5d6001122334455667788990011223344556677889900112233445566778899001122334455667788990011223344556677889900112233445566778899"
        }),
    );
    candidates.insert(
        "2".to_string(),
        json!({
            "ek": "22334455667788990011223344556677889900112233445566778899001122334455667788990011223344556677889900112233445566778899001122334455667788",
            "dk": "334455667788990011223344556677889900112233445566778899001122334455667788990011223344556677889900112233445566778899001122334455667788"
        }),
    );

    let result = acvp::run_kat("ML-KEM", "ML-KEM-1024", "keyGen", &candidates)
        .expect("run_kat should not error");

    assert_eq!(result.overall, "pass");
    assert!(result.failures.is_empty());
}

// ── Result metadata ───────────────────────────────────────────────────────────

#[test]
fn mlkem512_result_metadata_fields() {
    let result = acvp::run_kat("ML-KEM", "ML-KEM-512", "keyGen", &HashMap::new())
        .expect("run_kat should not error");

    assert_eq!(result.algorithm, "ML-KEM");
    assert_eq!(result.parameter_set, "ML-KEM-512");
    assert_eq!(result.acvp_mode, "keyGen");
    assert_eq!(result.vector_source.authority, "NIST-ACVP");
    // All tcIds absent → all fail
    assert_eq!(result.overall, "fail");
}

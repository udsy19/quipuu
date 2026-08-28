//! Tests that unknown algorithms return an appropriate error.

use std::collections::HashMap;

use quipuu::mcp::acvp;
use quipuu::mcp::errors::E_RULESET_INVALID;

#[test]
fn unknown_algorithm_returns_error() {
    let result = acvp::run_kat("ACORN-AEAD", "ACORN-128", "keyGen", &HashMap::new());

    assert!(result.is_err(), "unknown algorithm must return Err");
    let (code, msg) = result.unwrap_err();
    assert_eq!(code, E_RULESET_INVALID);
    assert!(
        msg.contains("unsupported algorithm"),
        "error message should mention unsupported algorithm, got: {msg}"
    );
    assert!(
        msg.contains("ACORN-AEAD"),
        "error message should echo the bad algorithm name, got: {msg}"
    );
}

#[test]
fn sha256_not_in_new_runner_returns_error() {
    // SHA-256 was wired in the old stub but is not a PQC algorithm and is
    // not part of the new ML-KEM/ML-DSA/SLH-DSA runner.
    let result = acvp::run_kat("SHA2-256", "SHA2-256", "keyGen", &HashMap::new());

    assert!(
        result.is_err(),
        "SHA2-256 must return Err in the new runner"
    );
    let (code, _) = result.unwrap_err();
    assert_eq!(code, E_RULESET_INVALID);
}

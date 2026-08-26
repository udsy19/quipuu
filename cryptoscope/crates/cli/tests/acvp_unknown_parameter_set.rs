//! Tests that unknown parameter sets return an appropriate error.

use std::collections::HashMap;

use cryptoscope::mcp::acvp;
use cryptoscope::mcp::errors::E_RULESET_INVALID;

#[test]
fn mlkem_unknown_parameter_set_returns_error() {
    let result = acvp::run_kat("ML-KEM", "ML-KEM-2048", "keyGen", &HashMap::new());

    assert!(result.is_err(), "unknown parameter set must return Err");
    let (code, msg) = result.unwrap_err();
    assert_eq!(code, E_RULESET_INVALID);
    assert!(
        msg.contains("ML-KEM-2048"),
        "error message should echo the bad parameter set, got: {msg}"
    );
}

#[test]
fn mldsa_unknown_parameter_set_returns_error() {
    let result = acvp::run_kat("ML-DSA", "ML-DSA-128", "keyGen", &HashMap::new());

    assert!(result.is_err());
    let (code, msg) = result.unwrap_err();
    assert_eq!(code, E_RULESET_INVALID);
    assert!(
        msg.contains("ML-DSA-128"),
        "error message should echo the bad parameter set, got: {msg}"
    );
}

#[test]
fn slhdsa_unknown_parameter_set_returns_error() {
    let result = acvp::run_kat("SLH-DSA", "SLH-DSA-SHA2-256f", "keyGen", &HashMap::new());

    assert!(result.is_err());
    let (code, msg) = result.unwrap_err();
    assert_eq!(code, E_RULESET_INVALID);
    assert!(
        msg.contains("SLH-DSA-SHA2-256f"),
        "error message should echo the bad parameter set, got: {msg}"
    );
}

#[test]
fn mlkem_known_paramset_unknown_mode_returns_error() {
    // ML-KEM-512 is supported, but "sigVer" is not a valid mode for ML-KEM
    let result = acvp::run_kat("ML-KEM", "ML-KEM-512", "sigVer", &HashMap::new());

    assert!(result.is_err());
    let (code, msg) = result.unwrap_err();
    assert_eq!(code, E_RULESET_INVALID);
    assert!(
        msg.contains("sigVer") || msg.contains("ML-KEM-512"),
        "error should mention the unsupported mode or parameter set, got: {msg}"
    );
}

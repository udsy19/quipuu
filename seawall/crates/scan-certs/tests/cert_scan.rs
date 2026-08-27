//! Integration tests for seawall-scan-certs.
//!
//! Fixture certs live in `tests/fixtures/` and are pre-generated PEM/DER files.

use std::path::PathBuf;

use seawall_scan_certs::{CertScanner, ScanError};

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

fn fixture(name: &str) -> PathBuf {
    fixtures_dir().join(name)
}

fn scanner() -> CertScanner {
    CertScanner::with_builtins().expect("builtins must load")
}

/// Helper: returns true if any finding in the list has the given rule_id.
fn has_rule(findings: &[seawall_core::Finding], rule_id: &str) -> bool {
    findings.iter().any(|f| f.rule_id == rule_id)
}

/// Helper: returns all findings with the given rule_id.
fn with_rule<'a>(
    findings: &'a [seawall_core::Finding],
    rule_id: &str,
) -> Vec<&'a seawall_core::Finding> {
    findings.iter().filter(|f| f.rule_id == rule_id).collect()
}

// ── Test 1: RSA-2048 SHA-256 cert ────────────────────────────────────────────

#[test]
fn test_rsa2048_sha256_resolves_algorithms() {
    let scanner = scanner();
    let findings = scanner
        .scan_path(&fixture("rsa2048.pem"))
        .expect("scan must succeed");

    // Must have at least CERT-001 (key) and CERT-002 (sig).
    assert!(
        findings.len() >= 2,
        "expected >=2 findings, got {}",
        findings.len()
    );

    // CERT-001: public key should resolve to rsa-2048.
    let key_findings = with_rule(&findings, "CERT-001");
    assert!(
        !key_findings.is_empty(),
        "expected CERT-001 finding for RSA key"
    );
    assert_eq!(
        key_findings[0].algorithm_id, "rsa-2048",
        "RSA-2048 key should resolve to rsa-2048"
    );

    // CERT-002: signature algorithm should resolve to rsa-pkcs1-sha256-2048.
    let sig_findings = with_rule(&findings, "CERT-002");
    assert!(
        !sig_findings.is_empty(),
        "expected CERT-002 finding for RSA sig"
    );
    assert_eq!(
        sig_findings[0].algorithm_id, "rsa-pkcs1-sha256-2048",
        "sha256WithRSAEncryption should resolve to rsa-pkcs1-sha256-2048"
    );

    // Should NOT have CERT-100 (no weak algorithm).
    assert!(
        !has_rule(&findings, "CERT-100"),
        "rsa2048 with sha256 must not trigger CERT-100"
    );
}

// ── Test 2: ECDSA P-256 SHA-256 cert ─────────────────────────────────────────

#[test]
fn test_ecdsa_p256_resolves_algorithms() {
    let scanner = scanner();
    let findings = scanner
        .scan_path(&fixture("ecdsa_p256.pem"))
        .expect("scan must succeed");

    assert!(
        findings.len() >= 2,
        "expected >=2 findings, got {}",
        findings.len()
    );

    // CERT-001: public key should resolve to ecdsa-p256.
    let key_findings = with_rule(&findings, "CERT-001");
    assert!(
        !key_findings.is_empty(),
        "expected CERT-001 finding for EC key"
    );
    assert_eq!(
        key_findings[0].algorithm_id, "ecdsa-p256",
        "P-256 key should resolve to ecdsa-p256"
    );

    // CERT-002: signature OID (ecdsa-with-SHA256 = 1.2.840.10045.4.3.2)
    // should also resolve to ecdsa-p256.
    let sig_findings = with_rule(&findings, "CERT-002");
    assert!(
        !sig_findings.is_empty(),
        "expected CERT-002 finding for EC sig"
    );
    assert_eq!(
        sig_findings[0].algorithm_id, "ecdsa-p256",
        "ecdsa-with-SHA256 signature should resolve to ecdsa-p256"
    );
}

// ── Test 3: RSA-2048 SHA-1 cert (should trigger CERT-100) ────────────────────

#[test]
fn test_rsa2048_sha1_triggers_cert100() {
    let scanner = scanner();
    let findings = scanner
        .scan_path(&fixture("rsa2048_sha1.pem"))
        .expect("scan must succeed");

    // Must have CERT-100.
    let weak_findings = with_rule(&findings, "CERT-100");
    assert!(
        !weak_findings.is_empty(),
        "sha1WithRSAEncryption must trigger CERT-100"
    );

    // The CERT-100 message must mention "WEAK" or "SHA-1".
    let msg = &weak_findings[0].message;
    assert!(
        msg.contains("WEAK") || msg.contains("SHA-1") || msg.contains("sha1"),
        "CERT-100 message must mention WEAK or SHA-1, got: {msg}"
    );
}

// ── Test 4: Directory scan returns >=6 findings ────────────────────────────

#[test]
fn test_directory_scan_returns_many_findings() {
    let scanner = scanner();
    let findings = scanner
        .scan_path(&fixtures_dir())
        .expect("directory scan must succeed");

    // 3 PEM certs × 2 findings each (min) = 6; rsa2048_sha1 gets an extra CERT-100.
    assert!(
        findings.len() >= 6,
        "expected >=6 findings from directory scan, got {}",
        findings.len()
    );
}

// ── Test 5: Non-existent path returns ScanError::Io ──────────────────────────

#[test]
fn test_nonexistent_path_returns_io_error() {
    let scanner = scanner();
    let result = scanner.scan_path(&PathBuf::from("/this/path/does/not/exist/cert.pem"));
    match result {
        Err(ScanError::Io(_)) => {}
        other => panic!("expected ScanError::Io, got {other:?}"),
    }
}

// ── Test 6: DER file is parsed correctly ─────────────────────────────────────

#[test]
fn test_der_file_parsed_correctly() {
    let scanner = scanner();
    let findings = scanner
        .scan_path(&fixture("rsa2048.der"))
        .expect("DER scan must succeed");

    assert!(
        findings.len() >= 2,
        "expected >=2 findings from DER file, got {}",
        findings.len()
    );

    let key_findings = with_rule(&findings, "CERT-001");
    assert!(
        !key_findings.is_empty(),
        "expected CERT-001 for DER cert key"
    );
    assert_eq!(
        key_findings[0].algorithm_id, "rsa-2048",
        "DER RSA-2048 key should resolve to rsa-2048"
    );

    // CERT-002 must also be present.
    assert!(
        has_rule(&findings, "CERT-002"),
        "expected CERT-002 for DER cert signature"
    );
}

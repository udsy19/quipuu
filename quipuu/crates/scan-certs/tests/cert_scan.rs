//! Integration tests for quipuu-scan-certs.
//!
//! Fixture certs live in `tests/fixtures/` and are pre-generated PEM/DER files.

use std::path::PathBuf;

use quipuu_scan_certs::{CertScanner, ScanError};

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
fn has_rule(findings: &[quipuu_core::Finding], rule_id: &str) -> bool {
    findings.iter().any(|f| f.rule_id == rule_id)
}

/// Helper: returns all findings with the given rule_id.
fn with_rule<'a>(
    findings: &'a [quipuu_core::Finding],
    rule_id: &str,
) -> Vec<&'a quipuu_core::Finding> {
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

    // CERT-001 states the modulus it measured, so nothing is lost by the id
    // not naming it.
    assert!(
        key_findings[0].message.contains("modulus 2048 bits"),
        "CERT-001 must report the measured modulus, got {:?}",
        key_findings[0].message
    );

    // CERT-002: sha256WithRSAEncryption encodes the digest and the padding
    // and no modulus, so it must not resolve to a sized id. This cert happens
    // to be RSA-2048; the OID would have claimed 2048 for a 512-bit key too.
    let sig_findings = with_rule(&findings, "CERT-002");
    assert!(
        !sig_findings.is_empty(),
        "expected CERT-002 finding for RSA sig"
    );
    assert_eq!(
        sig_findings[0].algorithm_id, "rsa-pkcs1-sha256",
        "sha256WithRSAEncryption should resolve to the unsized rsa-pkcs1-sha256"
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

    // CERT-002: the signature OID (ecdsa-with-SHA256 = 1.2.840.10045.4.3.2)
    // names the digest, not the curve. It resolved to `ecdsa-p256`, which was
    // right here only because this cert is on P-256 — a P-521 key signed with
    // SHA-256 got the same answer.
    let sig_findings = with_rule(&findings, "CERT-002");
    assert!(
        !sig_findings.is_empty(),
        "expected CERT-002 finding for EC sig"
    );
    assert_eq!(
        sig_findings[0].algorithm_id, "ecdsa-unattributed",
        "ecdsa-with-SHA256 names a digest and no curve"
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

// ── Test 7: RSA-2048 key signed with SHA-512 ────────────────────────────────

/// The fixture the repo did not have, and whose absence is why three passes
/// walked past this.
///
/// Every shipped cert was signed with the digest that matched its key size, so
/// the signature OID's invented modulus always agreed with the real one by
/// accident. A CA signing with SHA-384 or SHA-512 is the common real-world
/// case, and there the disagreement is visible: this certificate's key is
/// 2048-bit — 112-bit classical security — while `sha512WithRSAEncryption`
/// resolved to `rsa-pkcs1-sha512-4096`, putting `classicalSecurityLevel: 152`
/// in the CBOM beside it, from the same scan of the same file.
#[test]
fn a_sha512_signature_does_not_claim_a_4096_bit_modulus() {
    let scanner = scanner();
    let findings = scanner
        .scan_path(&fixture("rsa2048_sha512.pem"))
        .expect("scan must succeed");

    let key = with_rule(&findings, "CERT-001");
    let sig = with_rule(&findings, "CERT-002");
    assert!(!key.is_empty() && !sig.is_empty());

    // The key is measured, so it keeps its sized id.
    assert_eq!(key[0].algorithm_id, "rsa-2048");
    // The signature is not, so it does not.
    assert_eq!(sig[0].algorithm_id, "rsa-pkcs1-sha512");

    // The property that failed: two findings from one scan of one file must
    // not disagree about how strong the key is.
    let b = quipuu_core::load_builtins().expect("builtins load");
    let key_bits = b.algorithms.get(&key[0].algorithm_id).unwrap();
    let sig_bits = b.algorithms.get(&sig[0].algorithm_id).unwrap();
    assert_eq!(key_bits.classical_security_bits, Some(112));
    assert_eq!(
        sig_bits.classical_security_bits, None,
        "the signature OID states no modulus, so it must claim no classical strength"
    );

    // Nothing here is classically broken, so CERT-100 must stay quiet.
    assert!(!has_rule(&findings, "CERT-100"));
}

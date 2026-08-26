//! End-to-end scanner integration tests.
//!
//! Each test scans a fixture file and asserts which CRYPTO-NNN rule fired
//! at which line. These are the golden-file tests that catch regressions
//! in either the extract or classify layer.

use std::path::PathBuf;

use cryptoscope_core::{QuantumRiskScore, Severity, load_builtins};
use cryptoscope_scan_source::Scanner;

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

#[test]
fn scans_go_fixture() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("go/main.go"))
        .expect("scan succeeds");

    // Expected: 5 RSA findings (1024 + 2048 + 4096) + 2 ECDSA + 2 hashes = 7.
    assert!(
        findings.len() >= 7,
        "expected ≥7 findings in Go fixture, got {}: {:#?}",
        findings.len(),
        findings
            .iter()
            .map(|f| (&f.rule_id, &f.location.line))
            .collect::<Vec<_>>()
    );

    // RSA-1024 should be flagged as CRYPTO-001 (below 2048-bit floor).
    let rsa1024 = findings
        .iter()
        .find(|f| f.rule_id == "CRYPTO-001")
        .expect("RSA-1024 must trigger CRYPTO-001");
    assert_eq!(rsa1024.algorithm_id, "rsa-1024");

    // RSA-2048 → CRYPTO-002.
    let rsa2048 = findings
        .iter()
        .find(|f| f.rule_id == "CRYPTO-002")
        .expect("RSA-2048 must trigger CRYPTO-002");
    assert_eq!(rsa2048.algorithm_id, "rsa-2048");

    // RSA-4096 → CRYPTO-004.
    let rsa4096 = findings
        .iter()
        .find(|f| f.rule_id == "CRYPTO-004")
        .expect("RSA-4096 must trigger CRYPTO-004");
    assert_eq!(rsa4096.algorithm_id, "rsa-4096");

    // P-256 → CRYPTO-011, P-384 → CRYPTO-012.
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-011" && f.algorithm_id == "ecdsa-p256")
    );
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-012" && f.algorithm_id == "ecdsa-p384")
    );

    // MD5 → CRYPTO-050, SHA-1 → CRYPTO-051.
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-050" && f.algorithm_id == "md5")
    );
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-051" && f.algorithm_id == "sha-1")
    );
}

#[test]
fn scans_python_fixture() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("python/app.py"))
        .expect("scan succeeds");

    assert!(
        findings.len() >= 7,
        "expected ≥7 findings in Python fixture, got {}: {:#?}",
        findings.len(),
        findings
            .iter()
            .map(|f| (&f.rule_id, &f.location.line))
            .collect::<Vec<_>>()
    );

    // RSA-1024 → CRYPTO-101.
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-101" && f.algorithm_id == "rsa-1024")
    );
    // RSA-2048 → CRYPTO-102.
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-102" && f.algorithm_id == "rsa-2048")
    );
    // RSA-3072 → CRYPTO-103.
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-103" && f.algorithm_id == "rsa-3072")
    );
    // P-256 → CRYPTO-111, P-384 → CRYPTO-112.
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-111" && f.algorithm_id == "ecdsa-p256")
    );
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-112" && f.algorithm_id == "ecdsa-p384")
    );
    // MD5 / SHA-1.
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-140" && f.algorithm_id == "md5")
    );
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-141" && f.algorithm_id == "sha-1")
    );
}

#[test]
fn scans_directory_recursively() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner.scan_path(&fixtures_root()).expect("scan succeeds");

    // Combined Go + Python: at least 14 findings.
    assert!(
        findings.len() >= 14,
        "expected ≥14 combined findings, got {}",
        findings.len()
    );
}

#[test]
fn end_to_end_rsa_keygen_scores_high() {
    // Walking-skeleton end-to-end demo: real file in, Finding out, score out.
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms.clone()).expect("scanner builds");
    let mut findings = scanner
        .scan_path(&fixtures_root().join("go/main.go"))
        .expect("scan succeeds");

    // Mutate one finding to simulate the risk engine's per-finding inputs.
    // (The scanner emits conservative defaults; the engine consuming them adds
    // exposure/usage_context/shelf_life from policy + scope rules. We do that
    // assignment by hand here just to verify the scoring path works end-to-end.)
    let rsa2048 = findings
        .iter_mut()
        .find(|f| f.rule_id == "CRYPTO-002")
        .expect("RSA-2048 finding");
    rsa2048.usage_context = cryptoscope_core::UsageContext::KeyEstablishmentLongLived;
    rsa2048.exposure = cryptoscope_core::Exposure::PublicInternet;
    rsa2048.shelf_life_bucket = "long".into();

    let algo = b.algorithms.get(&rsa2048.algorithm_id).unwrap();
    let score = QuantumRiskScore::compute(rsa2048, algo, &b.policy);
    assert_eq!(
        score.severity,
        Severity::Critical,
        "end-to-end RSA-2048 in public-facing long-lived context must be Critical (score={})",
        score.total
    );
}

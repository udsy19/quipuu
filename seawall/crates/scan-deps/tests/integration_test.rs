//! Integration tests for `seawall-scan-deps`.

use std::path::Path;

use seawall_scan_deps::DepScanner;

fn fixtures(sub: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(sub)
}

// ============================================================================
// 1. Go — at least 2 findings (jwt + golang.org/x/crypto)
// ============================================================================

#[test]
fn go_finds_at_least_two_crypto_deps() {
    let scanner = DepScanner::with_builtins();
    let findings = scanner.scan_path(&fixtures("go")).expect("scan failed");
    assert!(
        findings.len() >= 2,
        "expected ≥2 Go findings, got {} — findings: {:?}",
        findings.len(),
        findings
    );
}

// ============================================================================
// 2. Rust — ring / rustls / sha2 found; serde NOT found
// ============================================================================

#[test]
fn rust_finds_crypto_deps_not_serde() {
    let scanner = DepScanner::with_builtins();
    let findings = scanner.scan_path(&fixtures("rust")).expect("scan failed");

    let names: Vec<String> = findings
        .iter()
        .filter_map(|f| f.location.symbol.clone())
        .collect();

    let has_ring = names.iter().any(|s| s.contains("ring"));
    let has_rustls = names.iter().any(|s| s.contains("rustls"));
    let has_sha2 = names.iter().any(|s| s.contains("sha2"));
    let has_serde = names.iter().any(|s| s.contains("serde"));

    assert!(has_ring, "expected ring in findings; got {:?}", names);
    assert!(has_rustls, "expected rustls in findings; got {:?}", names);
    assert!(has_sha2, "expected sha2 in findings; got {:?}", names);
    assert!(
        !has_serde,
        "serde must NOT appear in findings; got {:?}",
        names
    );
}

// ============================================================================
// 3. Python — cryptography + pyjwt found; requests NOT found
// ============================================================================

#[test]
fn python_finds_crypto_deps_not_requests() {
    let scanner = DepScanner::with_builtins();
    let findings = scanner.scan_path(&fixtures("python")).expect("scan failed");

    let names: Vec<String> = findings
        .iter()
        .filter_map(|f| f.location.symbol.clone())
        .collect();

    let has_cryptography = names.iter().any(|s| s.contains("cryptography"));
    let has_pyjwt = names
        .iter()
        .any(|s| s.to_lowercase().contains("pyjwt") || s.to_lowercase().contains("jwt"));
    let has_requests = names.iter().any(|s| s.contains("requests"));

    assert!(
        has_cryptography,
        "expected cryptography in findings; got {:?}",
        names
    );
    assert!(has_pyjwt, "expected pyjwt in findings; got {:?}", names);
    assert!(
        !has_requests,
        "requests must NOT appear in findings; got {:?}",
        names
    );
}

// ============================================================================
// 4. JS — jsonwebtoken + crypto-js found; react NOT found
// ============================================================================

#[test]
fn js_finds_crypto_deps_not_react() {
    let scanner = DepScanner::with_builtins();
    let findings = scanner.scan_path(&fixtures("js")).expect("scan failed");

    let names: Vec<String> = findings
        .iter()
        .filter_map(|f| f.location.symbol.clone())
        .collect();

    let has_jwt = names.iter().any(|s| s.contains("jsonwebtoken"));
    let has_crypto_js = names.iter().any(|s| s.contains("crypto-js"));
    let has_react = names.iter().any(|s| s.contains("react"));

    assert!(
        has_jwt,
        "expected jsonwebtoken in findings; got {:?}",
        names
    );
    assert!(
        has_crypto_js,
        "expected crypto-js in findings; got {:?}",
        names
    );
    assert!(
        !has_react,
        "react must NOT appear in findings; got {:?}",
        names
    );
}

// ============================================================================
// 5. Java — BouncyCastle with correct symbol
// ============================================================================

#[test]
fn java_finds_bouncy_castle_with_correct_symbol() {
    let scanner = DepScanner::with_builtins();
    let findings = scanner.scan_path(&fixtures("java")).expect("scan failed");

    assert!(!findings.is_empty(), "expected ≥1 Java finding; got none");

    let bc_finding = findings.iter().find(|f| {
        f.location
            .symbol
            .as_deref()
            .map(|s| s.contains("bouncycastle") || s.contains("bcprov"))
            .unwrap_or(false)
    });

    assert!(
        bc_finding.is_some(),
        "expected a BouncyCastle finding; findings: {:?}",
        findings
    );

    let symbol = bc_finding.unwrap().location.symbol.as_deref().unwrap_or("");
    assert_eq!(
        symbol, "maven:org.bouncycastle:bcprov-jdk18on",
        "unexpected symbol: {}",
        symbol
    );
}

// ============================================================================
// 6. Full fixtures tree — at least 10 findings total
// ============================================================================

#[test]
fn all_fixtures_return_at_least_ten_findings() {
    let scanner = DepScanner::with_builtins();
    let findings = scanner
        .scan_path(&fixtures(""))
        .expect("scan of all fixtures failed");

    assert!(
        findings.len() >= 10,
        "expected ≥10 findings across all fixtures; got {}",
        findings.len()
    );
}

// ============================================================================
// 7. Every finding has location.line > 0
// ============================================================================

#[test]
fn every_finding_has_positive_line_number() {
    let scanner = DepScanner::with_builtins();
    let findings = scanner.scan_path(&fixtures("")).expect("scan failed");

    for f in &findings {
        let line = f.location.line.unwrap_or(0);
        assert!(
            line > 0,
            "finding for {} has line = {}; expected > 0",
            f.location.location,
            line
        );
    }
}

// ============================================================================
// A manifest names a PQC family, never a parameter set
// ============================================================================

/// `ml-kem = "0.2"` says which crate, not which of ML-KEM-512/768/1024 the
/// code instantiates — that is a type parameter chosen at the call site.
///
/// It resolved to `ml-kem-768`, which `nsa-cnsa2` lists as disallowed, so a
/// codebase that had migrated to ML-KEM-1024 — the only set CNSA 2.0 approves
/// — was handed a non-compliant High and a red CI on the strength of a guess.
/// `DEP-001` is the largest rule in the product, so the guess was not cheap.
///
/// SLH-DSA is the control: CNSA 2.0 excludes it at the family level, so the
/// family id must *keep* a verdict the parameter set was never needed for.
#[test]
fn a_pqc_crate_name_does_not_pick_a_parameter_set() {
    let scanner = DepScanner::with_builtins();
    let findings = scanner.scan_path(&fixtures("rust")).expect("scan failed");
    let id_for = |pkg: &str| -> String {
        findings
            .iter()
            .find(|f| {
                f.location
                    .snippet
                    .as_deref()
                    .is_some_and(|s| s.contains(pkg))
            })
            .unwrap_or_else(|| panic!("expected a finding for `{pkg}`"))
            .algorithm_id
            .clone()
    };

    assert_eq!(id_for("ml-kem"), "ml-kem-unattributed");
    assert_eq!(id_for("ml-dsa"), "ml-dsa-unattributed");
    assert_eq!(id_for("slh-dsa"), "slh-dsa-unattributed");
    assert_eq!(id_for("rsa"), "rsa-unattributed");

    // The CNSA 2.0 verdict that survives, and the two that must not.
    let cnsa = seawall_core::Policy::load("nsa-cnsa2").expect("cnsa2 preset loads");
    assert!(
        cnsa.disallows("slh-dsa-unattributed"),
        "CNSA 2.0 excludes SLH-DSA whatever the parameter set"
    );
    for id in ["ml-kem-unattributed", "ml-dsa-unattributed"] {
        assert!(
            !cnsa.disallows(id),
            "{id} may be the 1024/87 set CNSA 2.0 approves; it must not be failed on a guess"
        );
    }
}

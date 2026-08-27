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

    // Combined all languages: at least 14 findings from Go + Python alone.
    assert!(
        findings.len() >= 14,
        "expected ≥14 combined findings, got {}",
        findings.len()
    );
}

// ============================================================================
// Java fixtures
// ============================================================================

#[test]
fn scans_java_cipher_des() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("java/Main.java"))
        .expect("scan succeeds");

    assert!(
        !findings.is_empty(),
        "expected findings in Java fixture, got none: {:#?}",
        findings
    );

    // DES in Cipher.getInstance → CRYPTO-200
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-200" && f.algorithm_id == "des"),
        "expected CRYPTO-200 (DES) in Java fixture"
    );
}

#[test]
fn scans_java_cipher_aes_ecb() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("java/Main.java"))
        .expect("scan succeeds");

    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-201" && f.algorithm_id == "aes-128-ecb"),
        "expected CRYPTO-201 (AES-ECB) in Java fixture"
    );
}

#[test]
fn scans_java_messagedigest_md5() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("java/Main.java"))
        .expect("scan succeeds");

    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-220" && f.algorithm_id == "md5"),
        "expected CRYPTO-220 (MD5) in Java fixture"
    );
}

#[test]
fn scans_java_messagedigest_sha1() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("java/Main.java"))
        .expect("scan succeeds");

    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-221" && f.algorithm_id == "sha-1"),
        "expected CRYPTO-221 (SHA-1) in Java fixture"
    );
}

#[test]
fn scans_java_keypairgenerator_rsa() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("java/Main.java"))
        .expect("scan succeeds");

    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-210" && f.algorithm_id == "rsa-2048"),
        "expected CRYPTO-210 (RSA keygen) in Java fixture"
    );
}

// ============================================================================
// JavaScript fixtures
// ============================================================================

#[test]
fn scans_js_createcipheriv_des() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("javascript/crypto.js"))
        .expect("scan succeeds");

    assert!(
        !findings.is_empty(),
        "expected findings in JS fixture, got none"
    );
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-300" && f.algorithm_id == "des"),
        "expected CRYPTO-300 (DES) in JS fixture; findings: {:#?}",
        findings
            .iter()
            .map(|f| (&f.rule_id, &f.algorithm_id))
            .collect::<Vec<_>>()
    );
}

#[test]
fn scans_js_createhash_md5() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("javascript/crypto.js"))
        .expect("scan succeeds");

    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-310" && f.algorithm_id == "md5"),
        "expected CRYPTO-310 (MD5) in JS fixture"
    );
}

#[test]
fn scans_js_createhash_sha1() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("javascript/crypto.js"))
        .expect("scan succeeds");

    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-311" && f.algorithm_id == "sha-1"),
        "expected CRYPTO-311 (SHA-1) in JS fixture"
    );
}

#[test]
fn scans_js_generatekeypair_rsa() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("javascript/crypto.js"))
        .expect("scan succeeds");

    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-320" && f.algorithm_id == "rsa-2048"),
        "expected CRYPTO-320 (RSA keygen) in JS fixture"
    );
}

#[test]
fn scans_js_generatekeypair_ec() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("javascript/crypto.js"))
        .expect("scan succeeds");

    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-321" && f.algorithm_id == "ecdsa-p256"),
        "expected CRYPTO-321 (EC keygen) in JS fixture"
    );
}

// ============================================================================
// C / C++ fixtures
// ============================================================================

#[test]
fn scans_c_rsa_generate_key_ex_weak() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("cpp/crypto.c"))
        .expect("scan succeeds");

    assert!(
        !findings.is_empty(),
        "expected findings in C fixture, got none"
    );
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-400" && f.algorithm_id == "rsa-1024"),
        "expected CRYPTO-400 (RSA-1024) in C fixture; got: {:#?}",
        findings
            .iter()
            .map(|f| (&f.rule_id, &f.algorithm_id))
            .collect::<Vec<_>>()
    );
}

#[test]
fn scans_c_evp_digest_md5() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("cpp/crypto.c"))
        .expect("scan succeeds");

    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-420" && f.algorithm_id == "md5"),
        "expected CRYPTO-420 (MD5 digest) in C fixture"
    );
}

#[test]
fn scans_c_evp_digest_sha1() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("cpp/crypto.c"))
        .expect("scan succeeds");

    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-421" && f.algorithm_id == "sha-1"),
        "expected CRYPTO-421 (SHA-1 digest) in C fixture"
    );
}

#[test]
fn scans_c_libsodium_box_keypair() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("cpp/crypto.c"))
        .expect("scan succeeds");

    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-440" && f.algorithm_id == "x25519"),
        "expected CRYPTO-440 (X25519 box_keypair) in C fixture"
    );
}

#[test]
fn scans_c_libsodium_sign_keypair() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("cpp/crypto.c"))
        .expect("scan succeeds");

    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-441" && f.algorithm_id == "ed25519"),
        "expected CRYPTO-441 (Ed25519 sign_keypair) in C fixture"
    );
}

// ============================================================================
// Rust fixtures
// ============================================================================

#[test]
fn scans_rust_rsa_weak() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("rust/main.rs"))
        .expect("scan succeeds");

    assert!(
        !findings.is_empty(),
        "expected findings in Rust fixture, got none"
    );
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-540" && f.algorithm_id == "rsa-1024"),
        "expected CRYPTO-540 (RSA-1024) in Rust fixture; got: {:#?}",
        findings
            .iter()
            .map(|f| (&f.rule_id, &f.algorithm_id))
            .collect::<Vec<_>>()
    );
}

#[test]
fn scans_rust_aes256gcm() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("rust/main.rs"))
        .expect("scan succeeds");

    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-510" && f.algorithm_id == "aes-256-gcm"),
        "expected CRYPTO-510 (AES-256-GCM) in Rust fixture"
    );
}

#[test]
fn scans_rust_ed25519_dalek() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("rust/main.rs"))
        .expect("scan succeeds");

    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-550" && f.algorithm_id == "ed25519"),
        "expected CRYPTO-550 (Ed25519 dalek) in Rust fixture"
    );
}

#[test]
fn scans_rust_ring_ecdsa() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("rust/main.rs"))
        .expect("scan succeeds");

    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-500" && f.algorithm_id == "ecdsa-p256"),
        "expected CRYPTO-500 (ring ECDSA) in Rust fixture"
    );
}

#[test]
fn scans_rust_chacha20poly1305() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("rust/main.rs"))
        .expect("scan succeeds");

    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-530" && f.algorithm_id == "chacha20-poly1305"),
        "expected CRYPTO-530 (ChaCha20-Poly1305) in Rust fixture"
    );
}

// ============================================================================
// C# fixtures
// ============================================================================

#[test]
fn scans_csharp_rsa_create() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("csharp/Crypto.cs"))
        .expect("scan succeeds");

    assert!(
        !findings.is_empty(),
        "expected findings in C# fixture, got none"
    );
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-600" && f.algorithm_id == "rsa-2048"),
        "expected CRYPTO-600 (RSA.Create) in C# fixture; got: {:#?}",
        findings
            .iter()
            .map(|f| (&f.rule_id, &f.algorithm_id))
            .collect::<Vec<_>>()
    );
}

#[test]
fn scans_csharp_md5_create() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("csharp/Crypto.cs"))
        .expect("scan succeeds");

    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-640" && f.algorithm_id == "md5"),
        "expected CRYPTO-640 (MD5.Create) in C# fixture"
    );
}

#[test]
fn scans_csharp_sha1_create() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("csharp/Crypto.cs"))
        .expect("scan succeeds");

    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-630" && f.algorithm_id == "sha-1"),
        "expected CRYPTO-630 (SHA1.Create) in C# fixture"
    );
}

#[test]
fn scans_csharp_tripledes_create() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("csharp/Crypto.cs"))
        .expect("scan succeeds");

    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-621" && f.algorithm_id == "3des"),
        "expected CRYPTO-621 (TripleDES) in C# fixture"
    );
}

#[test]
fn scans_csharp_sha256_create() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("csharp/Crypto.cs"))
        .expect("scan succeeds");

    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-631" && f.algorithm_id == "sha-256"),
        "expected CRYPTO-631 (SHA256.Create) in C# fixture"
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

// ============================================================================
// Phase 1: jjwt + java-jwt + nimbus-jose-jwt + jose4j enum-constant detection
// V2 corpus run revealed that scanning jjwt produced ZERO findings because
// the scanner only handled method_invocation / object_creation_expression,
// not field_access nodes. These tests guard against that class of regression.
// ============================================================================

#[test]
fn phase1_jjwt_rs256_detected_as_field_access() {
    // The single most important regression test in the file.
    // Before Phase 1, this returned 0 findings.
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("java/Jwt.java"))
        .expect("scan succeeds");
    assert!(
        !findings.is_empty(),
        "REGRESSION: scanning java/Jwt.java must produce findings (V2 corpus revealed silent zero)"
    );
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-242" && f.algorithm_id == "rsa-pkcs1-sha256-2048"),
        "expected CRYPTO-242 for jjwt SignatureAlgorithm.RS256/RS512: {:?}",
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

#[test]
fn phase1_jjwt_none_critical() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("java/Jwt.java"))
        .expect("scan succeeds");
    // SignatureAlgorithm.NONE → signature verification disabled.
    assert!(
        findings.iter().any(|f| f.rule_id == "CRYPTO-240"),
        "expected CRYPTO-240 for SignatureAlgorithm.NONE"
    );
}

#[test]
fn phase1_jjwt_hs256_low_severity() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("java/Jwt.java"))
        .expect("scan succeeds");
    assert!(
        findings.iter().any(|f| f.rule_id == "CRYPTO-241"),
        "expected CRYPTO-241 for SignatureAlgorithm.HS256 (HMAC)"
    );
}

#[test]
fn phase1_jjwt_es256_ecdsa() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("java/Jwt.java"))
        .expect("scan succeeds");
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-244" && f.algorithm_id == "ecdsa-p256"),
        "expected CRYPTO-244 for SignatureAlgorithm.ES256"
    );
}

#[test]
fn phase1_jjwt_ps384_rsapss() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("java/Jwt.java"))
        .expect("scan succeeds");
    assert!(
        findings.iter().any(|f| f.rule_id == "CRYPTO-243"),
        "expected CRYPTO-243 for SignatureAlgorithm.PS384 (RSA-PSS)"
    );
}

#[test]
fn phase1_nimbus_jwsalgorithm_rs384() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("java/Jwt.java"))
        .expect("scan succeeds");
    assert!(
        findings.iter().any(|f| f.rule_id == "CRYPTO-250"),
        "expected CRYPTO-250 for nimbus JWSAlgorithm.RS384"
    );
}

#[test]
fn phase1_nimbus_jwsalgorithm_es512() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("java/Jwt.java"))
        .expect("scan succeeds");
    assert!(
        findings.iter().any(|f| f.rule_id == "CRYPTO-251"),
        "expected CRYPTO-251 for nimbus JWSAlgorithm.ES512"
    );
}

#[test]
fn phase1_nimbus_jwsalgorithm_eddsa() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("java/Jwt.java"))
        .expect("scan succeeds");
    assert!(
        findings.iter().any(|f| f.rule_id == "CRYPTO-253"),
        "expected CRYPTO-253 for nimbus JWSAlgorithm.EdDSA"
    );
}

#[test]
fn phase1_nimbus_jwealgorithm_rsa_oaep() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("java/Jwt.java"))
        .expect("scan succeeds");
    assert!(
        findings.iter().any(|f| f.rule_id == "CRYPTO-254"),
        "expected CRYPTO-254 for nimbus JWEAlgorithm.RSA_OAEP_256"
    );
}

#[test]
fn phase1_jose4j_rsa_using_sha256() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("java/Jwt.java"))
        .expect("scan succeeds");
    assert!(
        findings.iter().any(|f| f.rule_id == "CRYPTO-260"),
        "expected CRYPTO-260 for jose4j AlgorithmIdentifiers.RSA_USING_SHA256"
    );
}

#[test]
fn phase1_jose4j_none_critical() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("java/Jwt.java"))
        .expect("scan succeeds");
    assert!(
        findings.iter().any(|f| f.rule_id == "CRYPTO-264"),
        "expected CRYPTO-264 for jose4j AlgorithmIdentifiers.NONE"
    );
}

#[test]
fn phase1_main_java_unchanged() {
    // Sanity: Phase 1 must not break the existing Java fixture detections.
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("java/Main.java"))
        .expect("scan succeeds");

    // The original 4 rule IDs must still fire on Main.java.
    for expected in ["CRYPTO-200", "CRYPTO-201", "CRYPTO-220", "CRYPTO-221"] {
        assert!(
            findings.iter().any(|f| f.rule_id == expected),
            "regression: Main.java must still produce {} after Phase 1 changes",
            expected
        );
    }
}

// ============================================================================
// Phase 7: Go string-table dispatch — switch { case "RS256": ... }
//
// V3 corpus run: 22/25 Go projects produced zero findings because JWT/JOSE
// libraries route algorithm choice through switch-on-string. These tests guard
// against regression of that detection class.
// ============================================================================

#[test]
fn phase7_go_switch_rs256_detected() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("go/jwt_switch.go"))
        .expect("scan succeeds");

    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-700" && f.algorithm_id == "rsa-pkcs1-sha256-2048"),
        "expected CRYPTO-700 for Go switch case \"RS256\"; got: {:#?}",
        findings
            .iter()
            .map(|f| (&f.rule_id, &f.algorithm_id))
            .collect::<Vec<_>>()
    );
}

#[test]
fn phase7_go_switch_none_critical() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("go/jwt_switch.go"))
        .expect("scan succeeds");

    let none_finding = findings
        .iter()
        .find(|f| f.rule_id == "CRYPTO-740")
        .expect("expected CRYPTO-740 for Go switch case \"none\" (CWE-347)");
    assert_eq!(
        none_finding.algorithm_id, "rsa-1024",
        "CRYPTO-740 must use rsa-1024 placeholder (same as Java NONE sentinel)"
    );
}

#[test]
fn phase7_go_switch_hmac_low_severity() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("go/jwt_switch.go"))
        .expect("scan succeeds");

    // HS256, HS384, HS512 must all fire at low severity.
    for rule_id in ["CRYPTO-730", "CRYPTO-731", "CRYPTO-732"] {
        assert!(
            findings.iter().any(|f| f.rule_id == rule_id),
            "expected {} for Go switch HS* case",
            rule_id
        );
    }
}

#[test]
fn phase7_go_main_fixture_unchanged() {
    // Sanity: Phase 7 changes must not alter findings on the original Go fixture.
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("go/main.go"))
        .expect("scan succeeds");

    for expected in [
        "CRYPTO-001",
        "CRYPTO-002",
        "CRYPTO-004",
        "CRYPTO-011",
        "CRYPTO-012",
        "CRYPTO-050",
        "CRYPTO-051",
    ] {
        assert!(
            findings.iter().any(|f| f.rule_id == expected),
            "regression: go/main.go must still produce {} after Phase 7",
            expected
        );
    }
}

// ── Phase 6: non-fatal warnings ─────────────────────────────────────────────

#[test]
fn phase6_unreadable_file_becomes_warning_not_error() {
    use cryptoscope_core::ScanWarningKind;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    // Build a fresh per-test temp dir (no external tempfile crate dep).
    let tmp = std::env::temp_dir().join(format!(
        "cryptoscope-phase6-{}-{}",
        std::process::id(),
        line!()
    ));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();

    let good = tmp.join("good.go");
    fs::write(
        &good,
        b"package main\nimport \"crypto/rsa\"\nfunc main() {\n  rsa.GenerateKey(nil, 1024)\n}\n",
    )
    .unwrap();
    let bad = tmp.join("bad.go");
    fs::write(&bad, b"package main\n").unwrap();
    fs::set_permissions(&bad, fs::Permissions::from_mode(0o000)).unwrap();

    let b = load_builtins().expect("builtins");
    let scanner = Scanner::with_builtins(b.algorithms.clone()).expect("scanner");
    let mut warnings = Vec::new();
    let findings = scanner
        .scan_path_collecting(&tmp, &mut warnings)
        .expect("scan should NOT fail on per-file errors after Phase 6");

    // Restore perms before cleanup.
    let _ = fs::set_permissions(&bad, fs::Permissions::from_mode(0o644));
    let _ = fs::remove_dir_all(&tmp);

    assert!(
        !findings.is_empty(),
        "good.go must produce an RSA-1024 finding even when bad.go is unreadable"
    );
    assert!(
        warnings
            .iter()
            .any(|w| w.kind == ScanWarningKind::UnreadableFile),
        "expected an UnreadableFile warning, got: {warnings:?}"
    );
}

#[test]
fn phase6_clean_scan_produces_no_warnings() {
    let b = load_builtins().expect("builtins");
    let scanner = Scanner::with_builtins(b.algorithms.clone()).expect("scanner");
    let mut warnings = Vec::new();
    let findings = scanner
        .scan_path_collecting(&fixtures_root().join("go/main.go"), &mut warnings)
        .expect("scan should succeed");

    assert!(!findings.is_empty(), "fixture must produce findings");
    assert!(
        warnings.is_empty(),
        "clean scan should produce no warnings, got: {warnings:?}"
    );
}

// ── Phase 8: paramiko-style runtime-variable args ───────────────────────────

#[test]
fn phase8_paramiko_variable_rsa_key_size_produces_finding() {
    // pre-fix: rsa.generate_private_key(key_size=bits) produced zero findings
    // because python_keyword_int rejected the identifier. Phase 8 captures it
    // symbolically and fires CRYPTO-104.
    let b = load_builtins().expect("builtins");
    let scanner = Scanner::with_builtins(b.algorithms.clone()).expect("scanner");
    let findings = scanner
        .scan_path(&fixtures_root().join("python/paramiko_style.py"))
        .expect("scan succeeds");

    let cr104 = findings.iter().find(|f| f.rule_id == "CRYPTO-104");
    assert!(
        cr104.is_some(),
        "expected CRYPTO-104 for rsa.generate_private_key(key_size=bits), got: {:?}",
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
    let f = cr104.unwrap();
    assert_eq!(f.algorithm_id, "rsa-2048");
    assert!(
        f.message.contains("bits"),
        "message should name the variable: {}",
        f.message
    );
}

#[test]
fn phase8_paramiko_variable_ec_curve_produces_finding() {
    // pre-fix: ec.generate_private_key(curve) produced zero findings because
    // python_first_arg_call_method required a call expression. Phase 8
    // captures bare identifiers and fires CRYPTO-115.
    let b = load_builtins().expect("builtins");
    let scanner = Scanner::with_builtins(b.algorithms.clone()).expect("scanner");
    let findings = scanner
        .scan_path(&fixtures_root().join("python/paramiko_style.py"))
        .expect("scan succeeds");

    let cr115 = findings.iter().find(|f| f.rule_id == "CRYPTO-115");
    assert!(
        cr115.is_some(),
        "expected CRYPTO-115 for ec.generate_private_key(curve), got: {:?}",
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
    let f = cr115.unwrap();
    assert_eq!(f.algorithm_id, "ecdsa-p256");
    assert!(
        f.message.contains("curve"),
        "message should name the variable: {}",
        f.message
    );
}

#[test]
fn phase8_cryptojs_two_level_member_expression_detected() {
    // pre-fix: CryptoJS.AES.encrypt etc. produced zero findings because
    // match_js_callee() had no entries for the crypto-js namespace.
    let b = load_builtins().expect("builtins");
    let scanner = Scanner::with_builtins(b.algorithms.clone()).expect("scanner");
    let findings = scanner
        .scan_path(&fixtures_root().join("javascript/crypto_js_consumer.js"))
        .expect("scan succeeds");

    // Every rule in the CRYPTO-370..377 band must fire.
    for expected in [
        "CRYPTO-370",
        "CRYPTO-371",
        "CRYPTO-372",
        "CRYPTO-373",
        "CRYPTO-374",
        "CRYPTO-375",
        "CRYPTO-376",
        "CRYPTO-377",
    ] {
        assert!(
            findings.iter().any(|f| f.rule_id == expected),
            "expected {} in findings, got: {:?}",
            expected,
            findings
                .iter()
                .map(|f| &f.rule_id)
                .collect::<std::collections::BTreeSet<_>>()
        );
    }
    assert_eq!(findings.len(), 8, "expected exactly 8 findings");
}

#[test]
fn phase8_cryptojs_des_marked_critical() {
    // The crypto-js DES path must surface as a critical finding (DES is
    // classically broken).
    let b = load_builtins().expect("builtins");
    let scanner = Scanner::with_builtins(b.algorithms.clone()).expect("scanner");
    let findings = scanner
        .scan_path(&fixtures_root().join("javascript/crypto_js_consumer.js"))
        .expect("scan succeeds");

    let des = findings
        .iter()
        .find(|f| f.rule_id == "CRYPTO-371")
        .expect("CRYPTO-371 must fire");
    assert_eq!(des.algorithm_id, "des");
}

#[test]
fn phase8_app_py_findings_unchanged() {
    // Regression guard: the original Python fixture's findings must not
    // change after the Phase 8 helper additions.
    let b = load_builtins().expect("builtins");
    let scanner = Scanner::with_builtins(b.algorithms.clone()).expect("scanner");
    let findings = scanner
        .scan_path(&fixtures_root().join("python/app.py"))
        .expect("scan succeeds");

    for expected in ["CRYPTO-101", "CRYPTO-102", "CRYPTO-103", "CRYPTO-111"] {
        assert!(
            findings.iter().any(|f| f.rule_id == expected),
            "regression: app.py must still produce {} after Phase 8 changes",
            expected
        );
    }
    // The literal-int paths must still NOT fire the symbolic rules.
    assert!(
        !findings.iter().any(|f| f.rule_id == "CRYPTO-104"),
        "literal key_size must not trigger the symbolic rule"
    );
    assert!(
        !findings.iter().any(|f| f.rule_id == "CRYPTO-115"),
        "literal curve must not trigger the symbolic rule"
    );
}

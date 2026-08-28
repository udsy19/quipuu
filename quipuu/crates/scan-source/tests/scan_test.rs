//! End-to-end scanner integration tests.
//!
//! Each test scans a fixture file and asserts which CRYPTO-NNN rule fired
//! at which line. These are the golden-file tests that catch regressions
//! in either the extract or classify layer.

use std::path::PathBuf;

use quipuu_core::{QuantumRiskScore, Severity, load_builtins};
use quipuu_scan_source::Scanner;

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

    // A key below the 2048-bit floor is flagged as CRYPTO-001. The rule
    // matches `bits < 2048`, so it knows the key is under the floor and not
    // that it is 1024 bits — the id says exactly that much.
    let undersized = findings
        .iter()
        .find(|f| f.rule_id == "CRYPTO-001")
        .expect("an undersized RSA key must trigger CRYPTO-001");
    assert_eq!(undersized.algorithm_id, "rsa-undersized");

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

    // crypto/tls.Config.CurvePreferences — GO-032.
    // The fixture lists tls.X25519, tls.CurveP256, tls.CurveP384.
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-032" && f.algorithm_id == "x25519"),
        "expected CRYPTO-032 for tls.X25519 in CurvePreferences",
    );
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-033" && f.algorithm_id == "ecdh-p256"),
        "expected CRYPTO-033 for tls.CurveP256 in CurvePreferences",
    );
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-034" && f.algorithm_id == "ecdh-p384"),
        "expected CRYPTO-034 for tls.CurveP384 in CurvePreferences",
    );

    // crypto/ecdh.<Curve> — GO-033. Fixture calls ecdh.X25519() and ecdh.P256().
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-036" && f.algorithm_id == "x25519"),
        "expected CRYPTO-036 for ecdh.X25519()",
    );
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-037" && f.algorithm_id == "ecdh-p256"),
        "expected CRYPTO-037 for ecdh.P256()",
    );
}

/// The migrated half of `CurvePreferences`. `CRYPTO-032..035` cover the
/// classical groups; without `CRYPTO-044..048` a config that already names
/// `tls.X25519MLKEM768` reports only its classical neighbours, so a migrated
/// service and an unscanned one produce the same output.
#[test]
fn go_tls_hybrid_groups_are_classified() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let path = fixtures_root().join("go/tls_pqc_groups.go");
    let findings = scanner.scan_path(&path).expect("scan succeeds");

    // (rule, algorithm_id, line in the fixture) — the line is asserted so the
    // finding is pinned to a literal source site, not just to a rule firing.
    for (rule, algorithm_id, line) in [
        ("CRYPTO-044", "x25519-mlkem768", 16),
        ("CRYPTO-045", "secp256r1-mlkem768", 17),
        ("CRYPTO-046", "secp384r1-mlkem1024", 18),
        ("CRYPTO-048", "x25519-kyber768-draft00", 27),
    ] {
        let f = findings
            .iter()
            .find(|f| f.rule_id == rule)
            .unwrap_or_else(|| panic!("{rule} must fire on the fixture"));
        assert_eq!(f.algorithm_id, algorithm_id, "{rule} algorithm_id");
        assert_eq!(f.location.line, Some(line), "{rule} line");
        assert!(
            f.location.location.ends_with("tls_pqc_groups.go"),
            "{rule} must resolve to the fixture file, got {:?}",
            f.location.location
        );
    }

    // The classical neighbour in the same slice still fires, so the new arms
    // add coverage rather than shadowing the existing ones.
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-032" && f.location.line == Some(19)),
        "tls.X25519 alongside the hybrids must still report CRYPTO-032",
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
            .any(|f| f.rule_id == "CRYPTO-101" && f.algorithm_id == "rsa-undersized")
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

    // `AES/ECB/PKCS5Padding` states the mode and not the key size, so the
    // finding carries the mode-only sentinel. Asserting `aes-128-ecb` here
    // would be asserting a width the source never wrote.
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-201" && f.algorithm_id == "aes-unattributed-ecb"),
        "expected CRYPTO-201 (AES-ECB, key size unattributed) in Java fixture"
    );
    // `AES_128/ECB/NoPadding` does state it, and is read rather than guessed.
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-207" && f.algorithm_id == "aes-128-ecb"),
        "expected CRYPTO-207 (AES-128-ECB) in Java fixture"
    );
    // Nothing in this fixture may claim a key size the JCE string omits.
    assert!(
        !findings.iter().any(|f| f.algorithm_id == "aes-256-ecb"),
        "no finding may assert a key size the transformation string omits"
    );
}

/// The `Cipher.getInstance` arms must read the key size from the JCE standard
/// name when it is there, and fall back to a sentinel when it is not — never
/// to a guessed width. Regression test for the defect where every
/// `AES/GCM/NoPadding` call site was published as `aes-256-gcm`.
#[test]
fn java_cipher_aes_gcm_key_size_is_read_not_guessed() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("java/Main.java"))
        .expect("scan succeeds");

    let gcm: Vec<_> = findings
        .iter()
        .filter(|f| f.algorithm_id.contains("gcm"))
        .map(|f| (f.rule_id.as_str(), f.algorithm_id.as_str()))
        .collect();
    assert!(
        gcm.contains(&("CRYPTO-203", "aes-unattributed-gcm")),
        "AES/GCM/NoPadding must not assert a key size; got {:?}",
        gcm
    );
    assert!(
        gcm.contains(&("CRYPTO-206", "aes-256-gcm")),
        "AES_256/GCM/NoPadding must resolve to aes-256-gcm; got {:?}",
        gcm
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
            .any(|f| f.rule_id == "CRYPTO-210" && f.algorithm_id == "rsa-unattributed"),
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
            .any(|f| f.rule_id == "CRYPTO-320" && f.algorithm_id == "rsa-unattributed"),
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
            .any(|f| f.rule_id == "CRYPTO-321" && f.algorithm_id == "ecdsa-unattributed"),
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
            .any(|f| f.rule_id == "CRYPTO-400" && f.algorithm_id == "rsa-undersized"),
        "expected CRYPTO-400 (undersized RSA) in C fixture; got: {:#?}",
        findings
            .iter()
            .map(|f| (&f.rule_id, &f.algorithm_id))
            .collect::<Vec<_>>()
    );
}

/// `CRYPTO-430` fires on a cipher-suite string that *enables* a broken
/// primitive, and it may not name which one.
///
/// Two defects, one rule. It matched `RC4|DES|MD5|NULL|EXPORT` anywhere in the
/// string, so `DEFAULT:!RC4` — which removes RC4 — was reported as a weak
/// cipher; and it emitted the unconditional literal `rc4`, so a string
/// selecting DES was reported as RC4 as well.
#[test]
fn cipher_list_reads_the_exclusion_prefix_and_names_no_single_cipher() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("cpp/crypto.c"))
        .expect("scan succeeds");

    let weak: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "CRYPTO-430")
        .collect();
    assert_eq!(
        weak.len(),
        1,
        "only the string that enables a broken cipher may fire; got {:#?}",
        weak.iter().map(|f| &f.message).collect::<Vec<_>>()
    );
    assert!(
        weak[0].message.contains("RC4-MD5"),
        "the firing site must be the enabling string, got {:?}",
        weak[0].message
    );
    assert_eq!(
        weak[0].algorithm_id, "weak-cipher-suite",
        "the string names five alternatives; the id may not pick one"
    );

    // The hardened string still gets the inventory-tier CRYPTO-431 marker —
    // suppressing the false positive must not lose the call site.
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-431" && f.message.contains("DEFAULT:!RC4")),
        "the excluding string must still be recorded as a cipher-suite config"
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
            .any(|f| f.rule_id == "CRYPTO-540" && f.algorithm_id == "rsa-undersized"),
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
            .any(|f| f.rule_id == "CRYPTO-500" && f.algorithm_id == "ecdsa-unattributed"),
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
            .any(|f| f.rule_id == "CRYPTO-600" && f.algorithm_id == "rsa-unattributed"),
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
    rsa2048.usage_context = quipuu_core::UsageContext::KeyEstablishmentLongLived;
    rsa2048.exposure = quipuu_core::Exposure::PublicInternet;
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
            .any(|f| f.rule_id == "CRYPTO-242" && f.algorithm_id == "rsa-pkcs1-sha256"),
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
    // Phase 15 split CRYPTO-250 (blanket RS256/384/512 + PS*) into per-hash
    // rules. RS384 now routes to CRYPTO-259 with algorithm_id
    // rsa-pkcs1-sha384-3072 (was the blanket sha256-2048 in CRYPTO-250).
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("java/Jwt.java"))
        .expect("scan succeeds");
    let f = findings
        .iter()
        .find(|f| f.rule_id == "CRYPTO-259")
        .expect("expected CRYPTO-259 for nimbus JWSAlgorithm.RS384");
    assert_eq!(f.algorithm_id, "rsa-pkcs1-sha384");
}

#[test]
fn phase1_nimbus_jwsalgorithm_es512() {
    // Phase 13 split CRYPTO-251 (blanket ES256/384/512) into per-curve rules.
    // ES512 now routes to CRYPTO-258 with algorithm_id ecdsa-p521 (was the
    // buggy blanket ecdsa-p256 in CRYPTO-251).
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("java/Jwt.java"))
        .expect("scan succeeds");
    let f = findings
        .iter()
        .find(|f| f.rule_id == "CRYPTO-258")
        .expect("expected CRYPTO-258 for nimbus JWSAlgorithm.ES512");
    assert_eq!(f.algorithm_id, "ecdsa-p521");
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
            .any(|f| f.rule_id == "CRYPTO-700" && f.algorithm_id == "rsa-pkcs1-sha256"),
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
    // Phase 13: rsa-1024 placeholder replaced by the dedicated jwt-alg-none
    // sentinel. The finding stays critical; only the algorithm_id changed.
    assert_eq!(
        none_finding.algorithm_id, "jwt-alg-none",
        "CRYPTO-740 must use the dedicated jwt-alg-none sentinel (Phase 13)"
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
    use quipuu_core::ScanWarningKind;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    // Build a fresh per-test temp dir (no external tempfile crate dep).
    let tmp =
        std::env::temp_dir().join(format!("quipuu-phase6-{}-{}", std::process::id(), line!()));
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
    assert_eq!(f.algorithm_id, "rsa-unattributed");
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
    assert_eq!(f.algorithm_id, "ecdsa-unattributed");
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

// ── Phase 11: pbkdf2 nested-turbofish hash extraction ──────────────────────
//
// pbkdf2 has two API shapes that both encode the hash in a turbofish:
//   pbkdf2::<Hmac<sha2::Sha256>>(...)   — generic function
//   pbkdf2_hmac::<sha2::Sha256>(...)    — newer free function
// Phase 11 routes each shape to a hash-specific classify rule based on
// the turbofish content. Builds on Phase 10's extract_turbofish_inner.

#[test]
fn phase11_pbkdf2_generic_fn_routes_by_hash() {
    let b = load_builtins().expect("builtins");
    let scanner = Scanner::with_builtins(b.algorithms.clone()).expect("scanner");
    let findings = scanner
        .scan_path(&fixtures_root().join("rust/pbkdf2_usage.rs"))
        .expect("scan succeeds");
    for (rule, algo) in [
        ("CRYPTO-580", "sha-256"),
        ("CRYPTO-581", "sha-384"),
        ("CRYPTO-582", "sha-512"),
    ] {
        let f = findings
            .iter()
            .find(|f| f.rule_id == rule)
            .unwrap_or_else(|| {
                panic!(
                    "{} must fire for pbkdf2::<Hmac<...>>, got: {:?}",
                    rule,
                    findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
                )
            });
        assert_eq!(f.algorithm_id, algo);
    }
}

#[test]
fn phase11_pbkdf2_hmac_freefn_routes_by_hash() {
    let b = load_builtins().expect("builtins");
    let scanner = Scanner::with_builtins(b.algorithms.clone()).expect("scanner");
    let findings = scanner
        .scan_path(&fixtures_root().join("rust/pbkdf2_usage.rs"))
        .expect("scan succeeds");
    for (rule, algo) in [
        ("CRYPTO-584", "sha-256"),
        ("CRYPTO-585", "sha-384"),
        ("CRYPTO-586", "sha-512"),
    ] {
        let f = findings
            .iter()
            .find(|f| f.rule_id == rule)
            .unwrap_or_else(|| {
                panic!(
                    "{} must fire for pbkdf2_hmac::<...>, got: {:?}",
                    rule,
                    findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
                )
            });
        assert_eq!(f.algorithm_id, algo);
    }
}

#[test]
fn phase11_pbkdf2_qualified_callee_falls_back_to_last_segment() {
    // `pbkdf2::pbkdf2_hmac::<Sha256>(...)` — the bare normalize gives
    // `pbkdf2::pbkdf2_hmac`. The fallback in match_rust_callee tries the
    // last segment alone (`pbkdf2_hmac`), which IS in the table.
    let b = load_builtins().expect("builtins");
    let scanner = Scanner::with_builtins(b.algorithms.clone()).expect("scanner");
    let findings = scanner
        .scan_path(&fixtures_root().join("rust/pbkdf2_usage.rs"))
        .expect("scan succeeds");
    // Line 28 in the fixture is the qualified call; must produce CRYPTO-584.
    let line28 = findings
        .iter()
        .find(|f| f.location.line == Some(28))
        .expect("expected a finding on line 28 (qualified pbkdf2::pbkdf2_hmac)");
    assert_eq!(line28.rule_id, "CRYPTO-584");
    assert_eq!(line28.algorithm_id, "sha-256");
}

#[test]
fn phase11_real_pbkdf2_benches_produces_findings() {
    // This is the canonical pre-Phase-11 zero-finding case. We hard-code
    // the expected count from the real bench file.
    use std::path::Path;
    let bench = Path::new(env!("CARGO_MANIFEST_DIR")).join(
        "../../../benchmarks/corpus-b-realworld/clones/crates-io/pbkdf2/pbkdf2/benches/lib.rs",
    );
    if !bench.exists() {
        // Corpus not cloned in CI; skip silently.
        eprintln!("skipping: {bench:?} not present");
        return;
    }
    let b = load_builtins().expect("builtins");
    let scanner = Scanner::with_builtins(b.algorithms.clone()).expect("scanner");
    let findings = scanner.scan_path(&bench).expect("scan succeeds");
    assert!(
        findings.iter().any(|f| f.rule_id == "CRYPTO-580"),
        "expected CRYPTO-580 on the real pbkdf2 bench file"
    );
    assert!(
        findings.iter().any(|f| f.rule_id == "CRYPTO-582"),
        "expected CRYPTO-582 on the real pbkdf2 bench file"
    );
}

// ── Phase 10: Rust qualified paths, variable args, turbofish, new APIs ─────
//
// RUST_COVERAGE_GAPS.md flagged five concrete bugs in the Rust scanner:
//   BUG-A  qualified-path callee miss        (p256, p384, rustls-native-certs)
//   BUG-B  RsaPrivateKey::new variable bits  (rsa src/)
//   BUG-C  KeyPair::generate_for unknown     (rustls-webpki, webpki)
//   BUG-D  ServerConfig::builder missing     (tokio-rustls)
//   BUG-F  SigningKey::<Sha*>::new turbofish (rsa pkcs1v15/pss)

#[test]
fn phase10_rust_qualified_sha_digest_normalizes() {
    // BUG-A: `sha2::Sha256::digest(b"x")` must match the same rule as the
    // bare `Sha256::digest(...)` after callee normalization.
    let b = load_builtins().expect("builtins");
    let scanner = Scanner::with_builtins(b.algorithms.clone()).expect("scanner");
    let findings = scanner
        .scan_path(&fixtures_root().join("rust/rust_advanced.rs"))
        .expect("scan succeeds");
    assert!(
        findings.iter().any(|f| f.rule_id == "CRYPTO-520"),
        "expected CRYPTO-520 for sha2::Sha256::digest, got: {:?}",
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
    assert!(
        findings.iter().any(|f| f.rule_id == "CRYPTO-521"),
        "expected CRYPTO-521 for sha2::Sha384::digest"
    );
}

#[test]
fn phase10_rust_qualified_clientconfig_normalizes() {
    // BUG-A: rustls::ClientConfig::builder must match the bare rule.
    let b = load_builtins().expect("builtins");
    let scanner = Scanner::with_builtins(b.algorithms.clone()).expect("scanner");
    let findings = scanner
        .scan_path(&fixtures_root().join("rust/rust_advanced.rs"))
        .expect("scan succeeds");
    assert!(
        findings.iter().any(|f| f.rule_id == "CRYPTO-560"),
        "expected CRYPTO-560 for rustls::ClientConfig::builder"
    );
}

#[test]
fn phase10_rust_serverconfig_builder_detected() {
    // BUG-D: rustls::ServerConfig::builder needs a parallel rule.
    let b = load_builtins().expect("builtins");
    let scanner = Scanner::with_builtins(b.algorithms.clone()).expect("scanner");
    let findings = scanner
        .scan_path(&fixtures_root().join("rust/rust_advanced.rs"))
        .expect("scan succeeds");
    assert!(
        findings.iter().any(|f| f.rule_id == "CRYPTO-561"),
        "expected CRYPTO-561 for rustls::ServerConfig::builder, got: {:?}",
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

#[test]
fn phase10_rust_rsa_variable_bits_emits_catchall() {
    // BUG-B: RsaPrivateKey::new(rng, bit_size) with bit_size = variable used
    // to silently produce nothing because every CRYPTO-540/541/542 rule
    // required a literal bits arg. CRYPTO-543 is the catch-all.
    let b = load_builtins().expect("builtins");
    let scanner = Scanner::with_builtins(b.algorithms.clone()).expect("scanner");
    let findings = scanner
        .scan_path(&fixtures_root().join("rust/rust_advanced.rs"))
        .expect("scan succeeds");
    let cr543 = findings
        .iter()
        .find(|f| f.rule_id == "CRYPTO-543")
        .expect("CRYPTO-543 must fire for variable bits");
    assert_eq!(cr543.algorithm_id, "rsa-unattributed");
    assert!(
        cr543.message.contains("runtime variable"),
        "message should mention runtime variable: {}",
        cr543.message
    );
}

#[test]
fn phase10_rust_rcgen_keypair_generate_for() {
    // BUG-C: rcgen::KeyPair::generate_for is the rustls-webpki test-utils
    // key generator; previously unrecognized.
    let b = load_builtins().expect("builtins");
    let scanner = Scanner::with_builtins(b.algorithms.clone()).expect("scanner");
    let findings = scanner
        .scan_path(&fixtures_root().join("rust/rust_advanced.rs"))
        .expect("scan succeeds");
    let cr570 = findings
        .iter()
        .find(|f| f.rule_id == "CRYPTO-570")
        .expect("CRYPTO-570 must fire for rcgen::KeyPair::generate_for");
    assert_eq!(cr570.algorithm_id, "ecdsa-unattributed");
}

#[test]
fn phase10_rust_signingkey_turbofish_routes_to_hash() {
    // BUG-F: SigningKey::<Sha256>::new must route to CRYPTO-544 (SHA256),
    // <Sha384>::new to CRYPTO-545, <Sha512>::new to CRYPTO-546.
    let b = load_builtins().expect("builtins");
    let scanner = Scanner::with_builtins(b.algorithms.clone()).expect("scanner");
    let findings = scanner
        .scan_path(&fixtures_root().join("rust/rust_advanced.rs"))
        .expect("scan succeeds");
    for (rule, algo) in [
        ("CRYPTO-544", "rsa-pkcs1-sha256"),
        ("CRYPTO-545", "rsa-pkcs1-sha384"),
        ("CRYPTO-546", "rsa-pkcs1-sha512"),
    ] {
        let f = findings
            .iter()
            .find(|f| f.rule_id == rule)
            .unwrap_or_else(|| {
                panic!(
                    "{} must fire for SigningKey::<...>::new, got: {:?}",
                    rule,
                    findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
                )
            });
        assert_eq!(f.algorithm_id, algo);
    }
}

#[test]
fn phase10_rust_main_fixture_unchanged() {
    // Regression guard: the existing rust/main.rs fixture's findings must
    // not change after Phase 10's normalize_rust_callee additions.
    let b = load_builtins().expect("builtins");
    let scanner = Scanner::with_builtins(b.algorithms.clone()).expect("scanner");
    let findings = scanner
        .scan_path(&fixtures_root().join("rust/main.rs"))
        .expect("scan succeeds");
    // Whatever the count was before, it must remain — assert non-empty
    // and that no new false positives appeared.
    assert!(!findings.is_empty(), "main.rs must still produce findings");
}

// ── Phase 9: Go algorithm-registration patterns ────────────────────────────
//
// Phase 7 handled `switch alg { case "RS256": ... }`. But the canonical
// Go JWT libraries (golang-jwt-jwt, go-jose, lestrrat-go/jwx) don't use
// switch-on-string — they REGISTER algorithm names via composite-literal,
// call-as-constructor, or const declarations. Phase 9 fires on a string
// literal that's a known JOSE name AND sits in an algorithm-registration
// syntactic position (literal_element, argument_list, const_spec, etc.).

#[test]
fn phase9_go_composite_literal_registers_rs256() {
    // golang-jwt-jwt shape: &SigningMethodRSA{"RS256", crypto.SHA256}
    let b = load_builtins().expect("builtins");
    let scanner = Scanner::with_builtins(b.algorithms.clone()).expect("scanner");
    let findings = scanner
        .scan_path(&fixtures_root().join("go/jwt_register.go"))
        .expect("scan succeeds");
    assert!(
        findings.iter().any(|f| f.rule_id == "CRYPTO-700"),
        "expected CRYPTO-700 for composite literal RS256, got: {:?}",
        findings
            .iter()
            .map(|f| &f.rule_id)
            .collect::<std::collections::BTreeSet<_>>()
    );
}

#[test]
fn phase9_go_call_constructor_registers_es256() {
    // go-jose / jwx shape: SignatureAlgorithm("ES256") or NewSignatureAlgorithm("ES256")
    let b = load_builtins().expect("builtins");
    let scanner = Scanner::with_builtins(b.algorithms.clone()).expect("scanner");
    let findings = scanner
        .scan_path(&fixtures_root().join("go/jwt_register.go"))
        .expect("scan succeeds");
    assert!(
        findings.iter().any(|f| f.rule_id == "CRYPTO-710"),
        "expected CRYPTO-710 for call-constructor ES256, got: {:?}",
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

#[test]
fn phase9_go_const_declaration_registers_none() {
    // jwx shape: const none = "none"; CRYPTO-740 must fire.
    // (Severity is High in the fixture because the usage context isn't
    // KeyEstablishmentLongLived. The rule's `severity_hint = "critical"`
    // applies when context drives the score that direction.)
    let b = load_builtins().expect("builtins");
    let scanner = Scanner::with_builtins(b.algorithms.clone()).expect("scanner");
    let findings = scanner
        .scan_path(&fixtures_root().join("go/jwt_register.go"))
        .expect("scan succeeds");
    assert!(
        findings.iter().any(|f| f.rule_id == "CRYPTO-740"),
        "CRYPTO-740 must fire on const none = \"none\", got: {:?}",
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

#[test]
fn phase9_go_doc_string_with_embedded_jose_name_does_not_fire() {
    // A raw string containing "RS256" inside doc-style text is the FULL
    // string literal, not a separate JOSE-named literal — so the whitelist
    // miss is what prevents the false positive. Guard against regressions.
    let b = load_builtins().expect("builtins");
    let scanner = Scanner::with_builtins(b.algorithms.clone()).expect("scanner");
    let findings = scanner
        .scan_path(&fixtures_root().join("go/jwt_register.go"))
        .expect("scan succeeds");
    // The docNote raw string is on line 46; ensure no finding fires for that line.
    assert!(
        !findings.iter().any(|f| f.location.line == Some(46)),
        "doc-style raw string on line 46 must not produce a finding, got: {:?}",
        findings
            .iter()
            .filter(|f| f.location.line == Some(46))
            .collect::<Vec<_>>()
    );
}

#[test]
fn phase9_go_main_fixture_unchanged() {
    // Pinned snapshot of the go/main.go fixture's finding count.
    //   - 7 from Phase 9 baseline (RSA × 3, ECDSA × 2, MD5, SHA-1)
    //   - 5 added with TLS CurvePreferences + crypto/ecdh detection:
    //     CRYPTO-032 (tls.X25519), CRYPTO-033 (tls.CurveP256),
    //     CRYPTO-034 (tls.CurveP384), CRYPTO-036 (ecdh.X25519),
    //     CRYPTO-037 (ecdh.P256)
    let b = load_builtins().expect("builtins");
    let scanner = Scanner::with_builtins(b.algorithms.clone()).expect("scanner");
    let main_findings = scanner
        .scan_path(&fixtures_root().join("go/main.go"))
        .expect("scan succeeds");
    assert_eq!(main_findings.len(), 12, "go/main.go count must not change");

    let switch_findings = scanner
        .scan_path(&fixtures_root().join("go/jwt_switch.go"))
        .expect("scan succeeds");
    assert_eq!(
        switch_findings.len(),
        15,
        "go/jwt_switch.go (Phase 7) count must not change"
    );
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

// ── Phase 13: classify-rule consistency guards ──────────────────────────────
//
// The precision audit (PRECISION_AUDIT.md) surfaced multiple copy-paste
// bugs where a rule's `when` clause names a specific hash/curve variant but
// the `algorithm_id` field references a different variant (e.g. CRYPTO-704
// claims PS384 but assigns rsa-pss-sha256-2048). These tests scan every
// shipped rule and assert variant-consistency: if a rule fires on `HS384`
// it must NOT route to `sha-256`; if it fires on `PS512` it must NOT route
// to `rsa-pss-sha256-2048`; etc.
//
// Hash and curve names from the `when` regex are compared against the
// algorithm_id text. The rule is conservative: only flag obvious
// mismatches (e.g., regex contains "384" but algorithm_id contains "256").

use quipuu_scan_source::{ClassifyRule, RulePack};

fn all_classify_rules() -> Vec<(&'static str, ClassifyRule)> {
    let mut out = Vec::new();
    for (lang, pack) in [
        ("go", RulePack::builtin_go().unwrap()),
        ("python", RulePack::builtin_python().unwrap()),
        ("java", RulePack::builtin_java().unwrap()),
        ("javascript", RulePack::builtin_javascript().unwrap()),
        ("cpp", RulePack::builtin_cpp().unwrap()),
        ("rust", RulePack::builtin_rust().unwrap()),
        ("csharp", RulePack::builtin_csharp().unwrap()),
    ] {
        for r in pack.classify {
            out.push((lang, r));
        }
    }
    out
}

#[test]
fn phase13_hash_variant_consistency() {
    // If a classify rule's `when` clause references SHA-X (X in {256,384,512})
    // — via api regex OR when.args.member regex — the algorithm_id must
    // reference the same hash width. Catches the CRYPTO-252-class bug where
    // an HS384 rule mistakenly routed to algorithm_id "sha-256".
    let rules = all_classify_rules();
    let mut violations = Vec::new();
    for (lang, r) in &rules {
        // Concatenate every regex this rule's `when` clause uses.
        let mut probe = r.when.api.clone();
        for am in r.when.args.values() {
            if let quipuu_scan_source::rules::ArgMatch::Regex(rx) = am {
                probe.push(' ');
                probe.push_str(&rx.regex);
            } else if let quipuu_scan_source::rules::ArgMatch::ExactStr(s) = am {
                probe.push(' ');
                probe.push_str(s);
            }
        }
        // Strip the body of `(256|384|512)` alternatives — a rule that handles
        // multiple variants jointly is allowed to keep a generic algorithm_id.
        // We only flag rules that pin to ONE variant in `when` but use a
        // DIFFERENT variant in algorithm_id.
        let single_variant = |needle: &str| -> bool {
            probe.contains(needle) && {
                // Make sure `needle` isn't inside an alternative like (256|384).
                let other_variants: Vec<&str> = ["256", "384", "512"]
                    .iter()
                    .filter(|v| **v != needle)
                    .copied()
                    .collect();
                !other_variants.iter().any(|o| probe.contains(o))
            }
        };
        for needle in ["256", "384", "512"] {
            if single_variant(needle) {
                // Now check the algorithm_id text.
                let other_variants: Vec<&str> = ["256", "384", "512"]
                    .iter()
                    .filter(|v| **v != needle)
                    .copied()
                    .collect();
                for wrong in &other_variants {
                    if r.algorithm_id.contains(wrong) && !r.algorithm_id.contains(needle) {
                        violations.push(format!(
                            "[{lang}] {}: when.* mentions {needle} but algorithm_id={} mentions {wrong}",
                            r.id, r.algorithm_id
                        ));
                    }
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "hash-variant consistency violations:\n  {}",
        violations.join("\n  ")
    );
}

#[test]
fn phase13_ecdsa_curve_consistency() {
    // Same shape, for ECDSA curves: a rule that matches `ES384` must not
    // route to ecdsa-p256 or ecdsa-p521.
    let rules = all_classify_rules();
    let mut violations = Vec::new();
    let curve_pairs = [
        ("ES384", "ecdsa-p256"),
        ("ES384", "ecdsa-p521"),
        ("ES512", "ecdsa-p256"),
        ("ES512", "ecdsa-p384"),
    ];
    for (lang, r) in &rules {
        let mut probe = r.when.api.clone();
        for am in r.when.args.values() {
            if let quipuu_scan_source::rules::ArgMatch::Regex(rx) = am {
                probe.push(' ');
                probe.push_str(&rx.regex);
            }
        }
        for (variant, wrong_id) in &curve_pairs {
            // Match only on a STRICT regex pin (no alternation that would
            // legitimately cover this variant + others).
            if probe.contains(variant)
                && !probe.contains(&format!("{}|", variant))
                && !probe.contains(&format!("|{}", variant))
                && r.algorithm_id == *wrong_id
            {
                violations.push(format!(
                    "[{lang}] {}: when.* pins {variant} but algorithm_id={}",
                    r.id, r.algorithm_id
                ));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "ECDSA curve consistency violations:\n  {}",
        violations.join("\n  ")
    );
}

// ── Phase 14b: schema invariants over every shipped rule pack ──────────────
//
// The Phase 12 / Phase 13 precision audit surfaced rule-authoring bugs that
// would have been caught by simple schema invariants. These tests walk every
// classify rule across every language and assert structural correctness so
// future rule edits can't silently introduce the same class of bugs.

const ALLOWED_SEVERITY_HINTS: &[&str] = &["critical", "high", "medium", "low", "auto"];

#[test]
fn phase14b_every_algorithm_id_resolves() {
    // Every classify rule's algorithm_id must be a real entry in the
    // algorithm-table. Catches typos, stale references after a rename,
    // and copy-paste of non-existent ids.
    let b = load_builtins().expect("builtins");
    let rules = all_classify_rules();
    let mut missing = Vec::new();
    for (lang, r) in &rules {
        if b.algorithms.get(&r.algorithm_id).is_none() {
            missing.push(format!(
                "[{lang}] {}: algorithm_id={} is not in the algorithm table",
                r.id, r.algorithm_id
            ));
        }
    }
    assert!(
        missing.is_empty(),
        "{} classify rules reference unknown algorithm_ids:\n  {}",
        missing.len(),
        missing.join("\n  ")
    );
}

#[test]
fn phase14b_every_severity_hint_allowed() {
    // severity_hint is a free-text TOML field. The risk engine matches it
    // against a fixed enum. Typos like "criticla" silently degrade to "auto".
    let rules = all_classify_rules();
    let mut bad = Vec::new();
    for (lang, r) in &rules {
        if !ALLOWED_SEVERITY_HINTS.contains(&r.severity_hint.as_str()) {
            bad.push(format!(
                "[{lang}] {}: severity_hint={:?} not in {:?}",
                r.id, r.severity_hint, ALLOWED_SEVERITY_HINTS
            ));
        }
    }
    assert!(
        bad.is_empty(),
        "{} classify rules use unknown severity_hint:\n  {}",
        bad.len(),
        bad.join("\n  ")
    );
}

#[test]
fn phase14b_every_when_api_regex_compiles() {
    use regex::Regex;
    let rules = all_classify_rules();
    let mut bad = Vec::new();
    for (lang, r) in &rules {
        if let Err(e) = Regex::new(&r.when.api) {
            bad.push(format!("[{lang}] {}: when.api invalid: {}", r.id, e));
        }
    }
    assert!(
        bad.is_empty(),
        "{} classify rules have invalid when.api regex:\n  {}",
        bad.len(),
        bad.join("\n  ")
    );
}

#[test]
fn phase14b_every_when_args_regex_compiles() {
    use quipuu_scan_source::rules::ArgMatch;
    use regex::Regex;
    let rules = all_classify_rules();
    let mut bad = Vec::new();
    for (lang, r) in &rules {
        for (cap, am) in &r.when.args {
            if let ArgMatch::Regex(rx) = am
                && let Err(e) = Regex::new(&rx.regex)
            {
                bad.push(format!(
                    "[{lang}] {}: when.args.{} regex invalid: {}",
                    r.id, cap, e
                ));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "{} classify rules have invalid when.args regex:\n  {}",
        bad.len(),
        bad.join("\n  ")
    );
}

#[test]
fn phase14b_every_cwe_id_well_formed() {
    use regex::Regex;
    let cwe_pattern = Regex::new(r"^CWE-\d+$").unwrap();
    let rules = all_classify_rules();
    let mut bad = Vec::new();
    for (lang, r) in &rules {
        if let Some(cwe) = &r.cwe
            && !cwe_pattern.is_match(cwe)
        {
            bad.push(format!(
                "[{lang}] {}: cwe={:?} doesn't match ^CWE-\\d+$",
                r.id, cwe
            ));
        }
    }
    assert!(
        bad.is_empty(),
        "{} classify rules have malformed cwe ids:\n  {}",
        bad.len(),
        bad.join("\n  ")
    );
}

#[test]
fn phase14b_classify_rule_ids_unique_within_language() {
    // Each language's rule pack should have unique rule ids within its TOML.
    // Cross-language duplication is permitted; within-file is a bug.
    use quipuu_scan_source::RulePack;
    use std::collections::HashSet;
    let packs: &[(&str, RulePack)] = &[
        ("go", RulePack::builtin_go().unwrap()),
        ("python", RulePack::builtin_python().unwrap()),
        ("java", RulePack::builtin_java().unwrap()),
        ("javascript", RulePack::builtin_javascript().unwrap()),
        ("cpp", RulePack::builtin_cpp().unwrap()),
        ("rust", RulePack::builtin_rust().unwrap()),
        ("csharp", RulePack::builtin_csharp().unwrap()),
    ];
    let mut dupes = Vec::new();
    for (lang, pack) in packs {
        let mut seen: HashSet<&str> = HashSet::new();
        for r in &pack.classify {
            if !seen.insert(r.id.as_str()) {
                dupes.push(format!("[{lang}] duplicate classify rule id {}", r.id));
            }
        }
    }
    assert!(
        dupes.is_empty(),
        "{} duplicate rule ids:\n  {}",
        dupes.len(),
        dupes.join("\n  ")
    );
}

// ── Phase 16: SiteContext-based FP suppression ─────────────────────────────
//
// The phase16_sitecontext.go fixture has 4 operational TPs at known lines
// and 7 non-operational lines that must NOT produce findings.

#[test]
fn phase16_operational_tps_fire() {
    let b = load_builtins().expect("builtins");
    let scanner = Scanner::with_builtins(b.algorithms.clone()).expect("scanner");
    let findings = scanner
        .scan_path(&fixtures_root().join("go/phase16_sitecontext.go"))
        .expect("scan succeeds");
    let want = [
        (23, "CRYPTO-700"),
        (26, "CRYPTO-730"),
        (31, "CRYPTO-700"),
        (33, "CRYPTO-704"),
    ];
    for (line, rule) in want {
        assert!(
            findings
                .iter()
                .any(|f| f.location.line == Some(line) && f.rule_id == rule),
            "expected {} on line {}, got: {:?}",
            rule,
            line,
            findings
                .iter()
                .map(|f| (f.location.line, &f.rule_id))
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn phase16_non_operational_fps_suppressed() {
    let b = load_builtins().expect("builtins");
    let scanner = Scanner::with_builtins(b.algorithms.clone()).expect("scanner");
    let findings = scanner
        .scan_path(&fixtures_root().join("go/phase16_sitecontext.go"))
        .expect("scan succeeds");
    let must_not_fire = [41, 44, 45, 50, 51, 56];
    for line in must_not_fire {
        assert!(
            !findings.iter().any(|f| f.location.line == Some(line)),
            "line {} should be suppressed but produced a finding",
            line
        );
    }
}

#[test]
fn phase16_total_count_matches_design() {
    let b = load_builtins().expect("builtins");
    let scanner = Scanner::with_builtins(b.algorithms.clone()).expect("scanner");
    let findings = scanner
        .scan_path(&fixtures_root().join("go/phase16_sitecontext.go"))
        .expect("scan succeeds");
    assert_eq!(
        findings.len(),
        4,
        "got: {:?}",
        findings
            .iter()
            .map(|f| (f.location.line, &f.rule_id))
            .collect::<Vec<_>>()
    );
}

// ── Phase 17: jwt.sign argument-value disambiguation ──────────────────────

#[test]
fn phase17_jwt_sign_routes_by_explicit_algorithm() {
    let b = load_builtins().expect("builtins");
    let scanner = Scanner::with_builtins(b.algorithms.clone()).expect("scanner");
    let findings = scanner
        .scan_path(&fixtures_root().join("javascript/jwt_sign_phase17.js"))
        .expect("scan succeeds");

    let expected = [
        (17, "CRYPTO-382", "sha-256"),
        (20, "CRYPTO-361", "sha-256"),
        (21, "CRYPTO-362", "sha-384"),
        (22, "CRYPTO-363", "sha-512"),
        (25, "CRYPTO-364", "rsa-pkcs1-sha256"),
        (26, "CRYPTO-365", "rsa-pkcs1-sha384"),
        (27, "CRYPTO-366", "rsa-pkcs1-sha512"),
        (30, "CRYPTO-367", "rsa-pss-sha256"),
        (31, "CRYPTO-368", "rsa-pss-sha384"),
        (32, "CRYPTO-369", "rsa-pss-sha512"),
        (35, "CRYPTO-378", "ecdsa-p256"),
        (36, "CRYPTO-379", "ecdsa-p384"),
        (37, "CRYPTO-380", "ecdsa-p521"),
        (40, "CRYPTO-381", "jwt-alg-none"),
        (43, "CRYPTO-360", "rsa-pkcs1-sha256"),
    ];
    for (line, rule, algo) in expected {
        let f = findings
            .iter()
            .find(|f| f.location.line == Some(line))
            .unwrap_or_else(|| panic!("expected finding on line {line}"));
        assert_eq!(f.rule_id, rule, "wrong rule on line {line}");
        assert_eq!(f.algorithm_id, algo, "wrong algorithm_id on line {line}");
    }
    assert_eq!(findings.len(), 15);
}

#[test]
fn phase17_jwt_sign_string_secret_routes_to_hmac() {
    let b = load_builtins().expect("builtins");
    let scanner = Scanner::with_builtins(b.algorithms.clone()).expect("scanner");
    let findings = scanner
        .scan_path(&fixtures_root().join("javascript/jwt_sign_phase17.js"))
        .expect("scan succeeds");
    let line17 = findings
        .iter()
        .find(|f| f.location.line == Some(17))
        .expect("expected finding on line 17");
    assert_eq!(line17.rule_id, "CRYPTO-382");
    assert_eq!(line17.algorithm_id, "sha-256");
    assert!(line17.message.contains("HMAC-SHA256"));
}

#[test]
fn phase17_jwt_sign_alg_none_routes_to_sentinel() {
    let b = load_builtins().expect("builtins");
    let scanner = Scanner::with_builtins(b.algorithms.clone()).expect("scanner");
    let findings = scanner
        .scan_path(&fixtures_root().join("javascript/jwt_sign_phase17.js"))
        .expect("scan succeeds");
    let line40 = findings
        .iter()
        .find(|f| f.location.line == Some(40))
        .expect("expected finding on line 40");
    assert_eq!(line40.rule_id, "CRYPTO-381");
    assert_eq!(line40.algorithm_id, "jwt-alg-none");
    assert!(line40.message.contains("CVE-2015-9235"));
}

// ── WebCrypto: classify from the algorithm argument, never from a guess ────

#[test]
fn webcrypto_classifies_from_the_algorithm_argument() {
    let b = load_builtins().expect("builtins");
    let scanner = Scanner::with_builtins(b.algorithms.clone()).expect("scanner");
    let findings = scanner
        .scan_path(&fixtures_root().join("javascript/webcrypto.js"))
        .expect("scan succeeds");

    let expected = [
        (16, "CRYPTO-342", "ml-dsa-65"),
        (20, "CRYPTO-345", "ml-kem-768"),
        (26, "CRYPTO-348", "ecdsa-p384"),
        (30, "CRYPTO-389", "rsa-pss-sha256"),
        (35, "CRYPTO-354", "ed25519"),
        (40, "CRYPTO-395", "ecdsa-unattributed"),
        (44, "CRYPTO-392", "aes-256-gcm"),
        (51, "CRYPTO-340", "webcrypto-unattributed"),
        (56, "CRYPTO-398", "webcrypto-unattributed"),
    ];
    for (line, rule, algo) in expected {
        let f = findings
            .iter()
            .find(|f| f.location.line == Some(line))
            .unwrap_or_else(|| panic!("expected finding on line {line}"));
        assert_eq!(f.rule_id, rule, "wrong rule on line {line}");
        assert_eq!(f.algorithm_id, algo, "wrong algorithm_id on line {line}");
    }
    // Line 63 is `mySubtle.sign(...)`: the receiver ends in "Subtle", not
    // ".subtle", so it must not be treated as WebCrypto.
    assert_eq!(findings.len(), expected.len(), "unexpected extra findings");
}

/// The defect this fixture exists for: `subtle.generateKey({name:'ML-DSA-65'})`
/// used to be reported as `ecdsa-p256`, High — a migrated call site flagged as
/// quantum-vulnerable, with the wrong algorithm-id then flowing into the CBOM.
#[test]
fn webcrypto_pqc_is_not_reported_as_classical() {
    let b = load_builtins().expect("builtins");
    let scanner = Scanner::with_builtins(b.algorithms.clone()).expect("scanner");
    let findings = scanner
        .scan_path(&fixtures_root().join("javascript/webcrypto.js"))
        .expect("scan succeeds");

    for line in [16, 20] {
        let f = findings
            .iter()
            .find(|f| f.location.line == Some(line))
            .unwrap_or_else(|| panic!("expected finding on line {line}"));
        assert!(
            f.algorithm_id.starts_with("ml-"),
            "line {line} classified as {}, expected a PQC algorithm",
            f.algorithm_id
        );
    }
}

/// A WebCrypto call whose algorithm argument is a variable must record the
/// call site without asserting an algorithm — the whole point of the
/// `webcrypto-unattributed` sentinel.
#[test]
fn webcrypto_non_literal_algorithm_asserts_nothing() {
    let b = load_builtins().expect("builtins");
    let scanner = Scanner::with_builtins(b.algorithms.clone()).expect("scanner");
    let findings = scanner
        .scan_path(&fixtures_root().join("javascript/webcrypto.js"))
        .expect("scan succeeds");

    let f = findings
        .iter()
        .find(|f| f.location.line == Some(51))
        .expect("expected finding on line 51");
    assert_eq!(f.algorithm_id, "webcrypto-unattributed");
    assert!(f.message.contains("not determinable"));
}

/// Real code reaches SubtleCrypto through `crypto.subtle`, `window.crypto`,
/// `self.crypto` and `globalThis.crypto` far more often than through a
/// destructured `subtle`. Matching only the destructured form meant the rules
/// fired on none of the WebCrypto call sites in the benchmark corpus.
#[test]
fn webcrypto_matches_every_receiver_chain() {
    let b = load_builtins().expect("builtins");
    let scanner = Scanner::with_builtins(b.algorithms.clone()).expect("scanner");
    let findings = scanner
        .scan_path(&fixtures_root().join("javascript/webcrypto.js"))
        .expect("scan succeeds");

    // 16 = `subtle.`, 20 = `crypto.subtle.`, 26 = `window.crypto.subtle.`,
    // 30 = `self.crypto.subtle.`, 35 = `globalThis.crypto.subtle.`.
    for line in [16, 20, 26, 30, 35] {
        assert!(
            findings.iter().any(|f| f.location.line == Some(line)),
            "no finding on line {line}"
        );
    }
}

// ============================================================================
// Broken-classical coverage — the nine planted call sites
// ============================================================================

/// Nine textbook broken-classical call sites across Java, Python and Go.
/// One of the nine was detected before this fixture existed; the other eight
/// were invisible, while `README.md` claimed the families were detected
/// "across all supported languages".
#[test]
fn broken_classical_call_sites_are_all_detected() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("brokenclassical"))
        .expect("scan succeeds");

    // (rule id, algorithm id) — the algorithm matters as much as the hit:
    // reporting DESede as single DES is a wrong component in the CBOM.
    let expected = [
        ("CRYPTO-214", "3des"),                 // Java Cipher.getInstance("DESede/…")
        ("CRYPTO-213", "rc4"),                  // Java Cipher.getInstance("RC4")
        ("CRYPTO-291", "rsa-pkcs1-sha1"),       // Java Signature.getInstance("SHA1withRSA")
        ("CRYPTO-130", "3des"),                 // pyca Cipher(algorithms.TripleDES, …)
        ("CRYPTO-131", "rc4"),                  // pyca Cipher(algorithms.ARC4, …)
        ("CRYPTO-132", "aes-unattributed-ecb"), // pyca AES + modes.ECB
        ("CRYPTO-042", "3des"),                 // Go des.NewTripleDESCipher
        ("CRYPTO-043", "rc4"),                  // Go rc4.NewCipher
        ("CRYPTO-040", "aes-unattributed"),     // Go aes.NewCipher
    ];

    let mut missing = Vec::new();
    for (rule_id, algorithm_id) in expected {
        if !findings
            .iter()
            .any(|f| f.rule_id == rule_id && f.algorithm_id == algorithm_id)
        {
            missing.push(format!("{rule_id} → {algorithm_id}"));
        }
    }
    assert!(
        missing.is_empty(),
        "{}/9 broken-classical call sites undetected:\n  {}\ngot:\n  {}",
        missing.len(),
        missing.join("\n  "),
        findings
            .iter()
            .map(|f| format!("{} {} {:?}", f.rule_id, f.algorithm_id, f.location.line))
            .collect::<Vec<_>>()
            .join("\n  ")
    );
}

// ── Registry lookups are not signing sites ─────────────────────────────────
//
// `jwa.LookupSignatureAlgorithm("PS256")` and
// `return lookupBuiltinSignatureAlgorithm("ES384")` retrieve a descriptor
// from a registry; no signature is produced. Ten of the 25 false positives in
// the corpus-B stratum sample were this shape. A lookup whose result is
// handed straight to another call is a different matter — that line does
// select the algorithm — so it stays a finding.

#[test]
fn registry_lookups_do_not_report_a_signature() {
    let b = load_builtins().expect("builtins");
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner");
    let findings = scanner
        .scan_path(&fixtures_root().join("go/jwt_registry_lookup.go"))
        .expect("scan succeeds");
    for line in [18, 21] {
        assert!(
            !findings.iter().any(|f| f.location.line == Some(line)),
            "line {} is a registry lookup and must not fire, got:\n  {}",
            line,
            findings
                .iter()
                .map(|f| format!("{} {} {:?}", f.rule_id, f.algorithm_id, f.location.line))
                .collect::<Vec<_>>()
                .join("\n  ")
        );
    }
}

#[test]
fn algorithm_selection_survives_the_lookup_suppression() {
    let b = load_builtins().expect("builtins");
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner");
    let findings = scanner
        .scan_path(&fixtures_root().join("go/jwt_registry_lookup.go"))
        .expect("scan succeeds");
    for (line, rule) in [(28, "CRYPTO-720"), (33, "CRYPTO-700")] {
        assert!(
            findings
                .iter()
                .any(|f| f.location.line == Some(line) && f.rule_id == rule),
            "expected {} on line {}, got:\n  {}",
            rule,
            line,
            findings
                .iter()
                .map(|f| format!("{} {} {:?}", f.rule_id, f.algorithm_id, f.location.line))
                .collect::<Vec<_>>()
                .join("\n  ")
        );
    }
}

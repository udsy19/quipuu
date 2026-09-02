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

    // sha256.New() → CRYPTO-948, sha512.New() → CRYPTO-952.
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-948" && f.algorithm_id == "sha-256")
    );
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-952" && f.algorithm_id == "sha-512")
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
        ("CRYPTO-047", "ml-kem-1024", 19),
        ("CRYPTO-048", "x25519-kyber768-draft00", 28),
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
            .any(|f| f.rule_id == "CRYPTO-032" && f.location.line == Some(20)),
        "tls.X25519 alongside the hybrids must still report CRYPTO-032",
    );
}

/// `golang.org/x/crypto/ssh` `Config.KeyExchanges` — SSH's counterpart to
/// `CurvePreferences`, backlog `#Y88` (RFC 10042). Covers both spellings a
/// caller can use: the package constant and the raw wire identifier string.
#[test]
fn go_ssh_key_exchanges_are_classified() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let path = fixtures_root().join("go/ssh_kex.go");
    let findings = scanner.scan_path(&path).expect("scan succeeds");

    // migratedServer: one constant-form hybrid, two string-literal-form hybrids.
    for (rule, algorithm_id, line) in [
        ("CRYPTO-1056", "x25519-mlkem768", 17),
        ("CRYPTO-1057", "secp256r1-mlkem768", 18),
        ("CRYPTO-1058", "secp384r1-mlkem1024", 19),
    ] {
        let f = findings
            .iter()
            .find(|f| f.rule_id == rule)
            .unwrap_or_else(|| panic!("{rule} must fire on the fixture"));
        assert_eq!(f.algorithm_id, algorithm_id, "{rule} algorithm_id");
        assert_eq!(f.location.line, Some(line), "{rule} line");
    }

    // classicalOnlyClient: four classical KEX groups, all constant-form.
    for (rule, algorithm_id) in [
        ("CRYPTO-1059", "x25519"),
        ("CRYPTO-1060", "ecdh-p256"),
        ("CRYPTO-1061", "ecdh-p384"),
        ("CRYPTO-1062", "ecdh-p521"),
    ] {
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == rule && f.algorithm_id == algorithm_id),
            "{rule} must fire for {algorithm_id} in classicalOnlyClient",
        );
    }
}

/// Go's own `crypto/mlkem` (stdlib, Go 1.24) — backlog `#Y30` part (a).
/// `circl`'s third-party mlkem768/1024 packages already fire (`CRYPTO-076..078`
/// above); before this, the zero-dependency stdlib package fired on nothing.
#[test]
fn go_stdlib_mlkem_is_classified() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let path = fixtures_root().join("go/stdlib_mlkem.go");
    let findings = scanner.scan_path(&path).expect("scan succeeds");

    for (rule, algorithm_id, line) in [
        ("CRYPTO-092", "ml-kem-768", 11),
        ("CRYPTO-093", "ml-kem-1024", 15),
        ("CRYPTO-092", "ml-kem-768", 19),
        ("CRYPTO-093", "ml-kem-1024", 23),
    ] {
        assert!(
            findings.iter().any(|f| f.rule_id == rule
                && f.algorithm_id == algorithm_id
                && f.location.line == Some(line)),
            "expected {rule}/{algorithm_id} at line {line} in stdlib_mlkem.go, got {:#?}",
            findings,
        );
    }
}

/// Go's own `crypto/mldsa` (stdlib, Go 1.27) — backlog `#V5`, the sibling
/// `#Y30` left uncovered when it shipped `crypto/mlkem` above. The parameter
/// set is not baked into `GenerateKey`'s name (unlike `mlkem.GenerateKey768`);
/// it is read off the `MLDSA44/65/87()` constructor call, whether inline as
/// an argument or standalone (the shape real usage — lestrrat-go/jwx — uses
/// to build a dispatch table).
#[test]
fn go_stdlib_mldsa_is_classified() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let path = fixtures_root().join("go/stdlib_mldsa.go");
    let findings = scanner.scan_path(&path).expect("scan succeeds");

    for (rule, algorithm_id, line) in [
        ("CRYPTO-1053", "ml-dsa-44", 16),
        ("CRYPTO-1055", "ml-dsa-87", 20),
        ("CRYPTO-1053", "ml-dsa-44", 24),
        ("CRYPTO-1054", "ml-dsa-65", 24),
        ("CRYPTO-1055", "ml-dsa-87", 24),
    ] {
        assert!(
            findings.iter().any(|f| f.rule_id == rule
                && f.algorithm_id == algorithm_id
                && f.location.line == Some(line)),
            "expected {rule}/{algorithm_id} at line {line} in stdlib_mldsa.go, got {:#?}",
            findings,
        );
    }
}

/// X-Wing (draft-connolly-cfrg-xwing-kem) — the X25519+ML-KEM-768 hybrid KEM
/// combiner used by HPKE, reached through circl's own `kem/xwing` package;
/// Google Tink's internal `hybrid/internal/xwing` package exports the same
/// function names under the same local identifier and is caught by the same
/// rule, verified separately against the vendored tink-go corpus clone.
#[test]
fn go_circl_xwing_is_classified() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let path = fixtures_root().join("go/circl_xwing.go");
    let findings = scanner.scan_path(&path).expect("scan succeeds");

    for (rule, algorithm_id, line) in [
        ("CRYPTO-1077", "x-wing", 16),
        ("CRYPTO-1077", "x-wing", 20),
        ("CRYPTO-1077", "x-wing", 24),
    ] {
        assert!(
            findings.iter().any(|f| f.rule_id == rule
                && f.algorithm_id == algorithm_id
                && f.location.line == Some(line)),
            "expected {rule}/{algorithm_id} at line {line} in circl_xwing.go, got {:#?}",
            findings,
        );
    }
}

/// liboqs-go's `oqs.KeyEncapsulation{}` / `oqs.Signature{}` construction —
/// backlog `#Y77`. The algorithm name arrives on a later `.Init(name, nil)`
/// call this extractor does not trace, so both sites degrade to the generic
/// unattributed sentinel rather than a specific parameter set.
#[test]
fn go_liboqs_go_construction_is_classified() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let path = fixtures_root().join("go/liboqs_go.go");
    let findings = scanner.scan_path(&path).expect("scan succeeds");

    for (rule, algorithm_id, line) in [
        ("CRYPTO-1048", "kem-unattributed", 15),
        ("CRYPTO-1049", "sig-unattributed", 25),
    ] {
        assert!(
            findings.iter().any(|f| f.rule_id == rule
                && f.algorithm_id == algorithm_id
                && f.location.line == Some(line)),
            "expected {rule}/{algorithm_id} at line {line} in liboqs_go.go, got {:#?}",
            findings,
        );
    }
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
fn scans_java_messagedigest_wider_digests() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("java/Main.java"))
        .expect("scan succeeds");

    for (rule_id, algorithm_id) in [
        ("CRYPTO-899", "sha-224"),
        ("CRYPTO-900", "sha-384"),
        ("CRYPTO-901", "sha-512"),
        ("CRYPTO-902", "sha3-256"),
        ("CRYPTO-903", "sha3-512"),
    ] {
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == rule_id && f.algorithm_id == algorithm_id),
            "expected {rule_id} ({algorithm_id}) in Java fixture"
        );
    }
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

#[test]
fn scans_java_keypairgenerator_ed25519_and_xdh() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("java/Main.java"))
        .expect("scan succeeds");

    for (rule_id, algorithm_id) in [
        ("CRYPTO-1063", "ed25519"), // KeyPairGenerator.getInstance("Ed25519")
        ("CRYPTO-1064", "xdh-unattributed"), // KeyPairGenerator.getInstance("XDH")
    ] {
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == rule_id && f.algorithm_id == algorithm_id),
            "expected {rule_id} ({algorithm_id}) in Java fixture"
        );
    }
}

#[test]
fn scans_java_pqc_keypairgenerator_and_signature_and_kem() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("java/Pqc.java"))
        .expect("scan succeeds");

    let want = [
        ("CRYPTO-216", "ml-kem-768"), // KeyPairGenerator.getInstance("ML-KEM-768")
        ("CRYPTO-219", "ml-dsa-65"),  // KeyPairGenerator.getInstance("ML-DSA-65")
        ("CRYPTO-225", "ml-dsa-65"),  // Signature.getInstance("ML-DSA-65")
        ("CRYPTO-228", "ml-kem-768"), // KEM.getInstance("ML-KEM-768")
        ("CRYPTO-770", "slh-dsa-sha2-128s"), // KeyPairGenerator.getInstance("SLH-DSA-SHA2-128S", "BC")
        ("CRYPTO-782", "slh-dsa-unattributed"), // KeyPairGenerator.getInstance("SLH-DSA", "BC")
        ("CRYPTO-790", "slh-dsa-shake-128s"), // Signature.getInstance("SLH-DSA-SHAKE-128S", "BC")
        ("CRYPTO-1006", "hqc-128"),          // KeyPairGenerator.getInstance("HQC-128", "BCPQC")
        ("CRYPTO-1009", "hqc-unattributed"), // KeyPairGenerator.getInstance("HQC", "BCPQC")
        ("CRYPTO-1011", "hqc-192"),          // KEM.getInstance("HQC-192")
        ("CRYPTO-1004", "hqc-256"),          // Cipher.getInstance("HQC-256")
        ("CRYPTO-1014", "bike-128"),         // Cipher.getInstance("BIKE128")
        ("CRYPTO-1018", "bike-unattributed"), // KeyPairGenerator.getInstance("BIKE", "BCPQC")
        ("CRYPTO-1019", "classic-mceliece-unattributed"), // KeyPairGenerator.getInstance("mceliece6960119", "BCPQC")
        ("CRYPTO-1020", "classic-mceliece-unattributed"), // KEM.getInstance("CMCE")
        ("CRYPTO-1021", "xmss"), // KeyPairGenerator.getInstance("XMSS", "BCPQC")
        ("CRYPTO-1022", "xmss-mt"), // KeyPairGenerator.getInstance("XMSSMT", "BCPQC")
        ("CRYPTO-1025", "xmss"), // Signature.getInstance("XMSS-SHA256", "BCPQC")
        ("CRYPTO-1029", "xmss-mt"), // Signature.getInstance("XMSSMT-SHA256", "BCPQC")
    ];
    for (rule_id, algorithm_id) in want {
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == rule_id && f.algorithm_id == algorithm_id),
            "expected {rule_id} ({algorithm_id}) in Java PQC fixture; findings: {:#?}",
            findings
                .iter()
                .map(|f| (&f.rule_id, &f.algorithm_id))
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn scans_java_bouncycastle_composite_kem_keygenerator() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("java/CompositeKem.java"))
        .expect("scan succeeds");

    let want = [
        ("CRYPTO-1131", "jca-unattributed"), // KeyPairGenerator.getInstance("MLKEM768-X25519-SHA3-256") — a real literal, just not one this table's arms recognize (#Y105)
        ("CRYPTO-1082", "ml-kem-unattributed"), // KeyGenerator.getInstance("MLKEM768-RSA2048-SHA3-256")
        ("CRYPTO-1083", "ml-kem-unattributed"), // KeyGenerator.getInstance("MLKEM768-RSA3072-SHA3-256")
        ("CRYPTO-1084", "ml-kem-unattributed"), // KeyGenerator.getInstance("MLKEM768-RSA4096-SHA3-256")
        ("CRYPTO-1085", "ml-kem-unattributed"), // KeyGenerator.getInstance("MLKEM768-X25519-SHA3-256")
        ("CRYPTO-1086", "ml-kem-unattributed"), // KeyGenerator.getInstance("MLKEM768-ECDH-P256-SHA3-256")
        ("CRYPTO-1087", "ml-kem-unattributed"), // KeyGenerator.getInstance("MLKEM768-ECDH-P384-SHA3-256")
        ("CRYPTO-1088", "ml-kem-unattributed"), // KeyGenerator.getInstance("MLKEM768-ECDH-BP256-SHA3-256")
        ("CRYPTO-1089", "ml-kem-unattributed"), // KeyGenerator.getInstance("MLKEM1024-RSA3072-SHA3-256")
        ("CRYPTO-1090", "ml-kem-unattributed"), // KeyGenerator.getInstance("MLKEM1024-ECDH-P384-SHA3-256")
        ("CRYPTO-1091", "ml-kem-unattributed"), // KeyGenerator.getInstance("MLKEM1024-ECDH-BP384-SHA3-256")
        ("CRYPTO-1092", "ml-kem-unattributed"), // KeyGenerator.getInstance("MLKEM1024-X448-SHA3-256")
        ("CRYPTO-1093", "ml-kem-unattributed"), // KeyGenerator.getInstance("MLKEM1024-ECDH-P521-SHA3-256")
    ];
    for (rule_id, algorithm_id) in want {
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == rule_id && f.algorithm_id == algorithm_id),
            "expected {rule_id} ({algorithm_id}) in Java composite-KEM fixture; findings: {:#?}",
            findings
                .iter()
                .map(|f| (&f.rule_id, &f.algorithm_id))
                .collect::<Vec<_>>()
        );
    }
    assert_eq!(
        findings.len(),
        13,
        "the plain KeyGenerator.getInstance(\"AES\") call must not be extracted — this is not a \
         general KeyGenerator policy; findings: {:#?}",
        findings
            .iter()
            .map(|f| (&f.rule_id, &f.algorithm_id))
            .collect::<Vec<_>>()
    );
}

#[test]
fn scans_java_bouncycastle_lightweight_pqc_classes() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("java/BcLightweight.java"))
        .expect("scan succeeds");

    let want = [
        ("CRYPTO-230", "rsa-unattributed"), // new RSAKeyPairGenerator() — classical control
        ("CRYPTO-811", "ml-kem-unattributed"), // new MLKEMKeyPairGenerator()
        ("CRYPTO-812", "ml-dsa-unattributed"), // new MLDSAKeyPairGenerator()
        ("CRYPTO-813", "slh-dsa-unattributed"), // new SLHDSAKeyPairGenerator()
        ("CRYPTO-814", "ml-kem-unattributed"), // new MLKEMGenerator(null)
        ("CRYPTO-815", "ml-kem-unattributed"), // new MLKEMExtractor(null)
        ("CRYPTO-816", "ml-dsa-unattributed"), // new MLDSASigner()
        ("CRYPTO-817", "slh-dsa-unattributed"), // new SLHDSASigner()
        ("CRYPTO-818", "ml-dsa-unattributed"), // new HashMLDSASigner()
        ("CRYPTO-819", "slh-dsa-unattributed"), // new HashSLHDSASigner()
        ("CRYPTO-958", "ml-dsa-unattributed"), // new DilithiumSigner()
        ("CRYPTO-959", "slh-dsa-unattributed"), // new SPHINCSPlusSigner()
        ("CRYPTO-1033", "xmss"),            // new XMSSSigner()
        ("CRYPTO-1034", "xmss-mt"),         // new XMSSMTSigner()
    ];
    for (rule_id, algorithm_id) in want {
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == rule_id && f.algorithm_id == algorithm_id),
            "expected {rule_id} ({algorithm_id}) in BC lightweight-API fixture; findings: {:#?}",
            findings
                .iter()
                .map(|f| (&f.rule_id, &f.algorithm_id))
                .collect::<Vec<_>>()
        );
    }
    assert_eq!(
        findings.len(),
        want.len(),
        "expected exactly {} findings (one per class instantiation), got {:#?}",
        want.len(),
        findings
            .iter()
            .map(|f| (&f.rule_id, &f.algorithm_id))
            .collect::<Vec<_>>()
    );
}

#[test]
fn scans_java_ssl_parameters_set_named_groups() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("java/TlsGroups.java"))
        .expect("scan succeeds");

    let want = [
        ("CRYPTO-798", "x25519-mlkem768"),
        ("CRYPTO-801", "x25519"),
        ("CRYPTO-802", "x448"),
        ("CRYPTO-803", "ecdh-p256"),
        ("CRYPTO-804", "ecdh-p384"),
        ("CRYPTO-805", "ecdh-p521"),
        ("CRYPTO-806", "dh-2048"),
        ("CRYPTO-807", "dh-3072"),
        ("CRYPTO-808", "dh-4096"),
    ];
    for (rule_id, algorithm_id) in want {
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == rule_id && f.algorithm_id == algorithm_id),
            "expected {rule_id} ({algorithm_id}) in TlsGroups fixture; findings: {:#?}",
            findings
                .iter()
                .map(|f| (&f.rule_id, &f.algorithm_id))
                .collect::<Vec<_>>()
        );
    }

    // 10 named-group elements across the two direct calls (secp256r1 appears
    // in both, once per call) + 1 more through the delegating-helper call +
    // 3 more through the #Y24 part (b) System.setProperty comma-delimited
    // form (secp256r1, ffdhe2048, X25519MLKEM768), plus the pre-existing
    // CRYPTO-210 RSA finding from the control method and the unrelated
    // system property (which must not fire) — nothing else.
    let set_named_groups_count = findings
        .iter()
        .filter(|f| f.rule_id.starts_with("CRYPTO-79") || f.rule_id.starts_with("CRYPTO-80"))
        .count();
    assert_eq!(
        set_named_groups_count,
        14,
        "expected exactly 14 setNamedGroups findings (one per array element / property token), got {}: {:#?}",
        set_named_groups_count,
        findings
            .iter()
            .map(|f| (&f.rule_id, &f.algorithm_id, f.location.line))
            .collect::<Vec<_>>()
    );
}

#[test]
fn scans_bc_named_groups_list() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("java/BcNamedGroups.java"))
        .expect("scan succeeds");

    let group_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id.starts_with("CRYPTO-9") && (932..=944).contains(&rule_num(f)))
        .collect();

    for (algorithm_id, expected) in [
        ("x25519-mlkem768", 1),
        ("secp256r1-mlkem768", 1),
        ("x25519", 1),
        ("ecdh-p256", 1),
        ("ecdh-p384", 1),
        ("ecdh-p521", 1),
        ("x448", 1),
        ("dh-2048", 1),
        ("dh-3072", 1),
        ("dh-4096", 1),
    ] {
        let n = group_findings
            .iter()
            .filter(|f| f.algorithm_id == algorithm_id)
            .count();
        assert_eq!(
            n,
            expected,
            "expected {expected} finding(s) for {algorithm_id}, got {n}: {:#?}",
            group_findings
                .iter()
                .map(|f| &f.algorithm_id)
                .collect::<Vec<_>>()
        );
    }

    // pqcOptIn (3 groups) + classicalOnlyDowngrade (7 groups) = 10. The
    // netty-style unrelated `addIfSupported` helper (no `TlsUtils.` receiver)
    // and the single-group overload must not add findings.
    assert_eq!(
        group_findings.len(),
        10,
        "unrelated addIfSupported / single-group overload sites must not fire: {:#?}",
        group_findings
            .iter()
            .map(|f| &f.algorithm_id)
            .collect::<Vec<_>>()
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
fn scans_js_createhash_wider_digests() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("javascript/crypto.js"))
        .expect("scan succeeds");

    for (rule_id, algorithm_id) in [
        ("CRYPTO-904", "sha-224"),
        ("CRYPTO-905", "sha-384"),
        ("CRYPTO-906", "sha-512"),
        ("CRYPTO-907", "sha3-256"),
        ("CRYPTO-908", "sha3-512"),
    ] {
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == rule_id && f.algorithm_id == algorithm_id),
            "expected {rule_id} ({algorithm_id}) in JS fixture"
        );
    }
}

#[test]
fn scans_js_createhash_sha3_384() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("javascript/crypto.js"))
        .expect("scan succeeds");

    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-969" && f.algorithm_id == "sha3-384"),
        "expected CRYPTO-969 (SHA3-384) in JS fixture"
    );
}

#[test]
fn scans_js_createsign_wider_digests() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("javascript/crypto.js"))
        .expect("scan succeeds");

    for (rule_id, algorithm_id) in [
        ("CRYPTO-330", "rsa-pkcs1-sha256"),
        ("CRYPTO-970", "rsa-pkcs1-sha1"),
        ("CRYPTO-971", "rsa-pkcs1-sha384"),
        ("CRYPTO-972", "rsa-pkcs1-sha512"),
    ] {
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == rule_id && f.algorithm_id == algorithm_id),
            "expected {rule_id} ({algorithm_id}) in JS fixture"
        );
    }
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

// `#Y4` — bare identifier calls reached through a name import, not the
// module object. Every assertion here failed before `collect_bare_bindings`.

#[test]
fn scans_js_generatekeypair_via_aliased_destructure() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("javascript/named_import_crypto.js"))
        .expect("scan succeeds");

    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-320" && f.algorithm_id == "rsa-unattributed"),
        "expected CRYPTO-320 via `const {{ generateKeyPair: generateKeyPair_ }} = require(...)`; \
         findings: {:#?}",
        findings
            .iter()
            .map(|f| (&f.rule_id, &f.algorithm_id))
            .collect::<Vec<_>>()
    );
}

#[test]
fn scans_js_createhash_via_bare_destructure() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("javascript/named_import_crypto.js"))
        .expect("scan succeeds");

    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-310" && f.algorithm_id == "md5"),
        "expected CRYPTO-310 via `const {{ createHash }} = require('crypto')`"
    );
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-311" && f.algorithm_id == "sha-1"),
        "expected CRYPTO-311 via `const {{ createHash }} = require('crypto')`"
    );
}

#[test]
fn scans_js_generatekeypair_via_esm_named_import() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("javascript/named_import_crypto.mjs"))
        .expect("scan succeeds");

    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-320" && f.algorithm_id == "rsa-unattributed"),
        "expected CRYPTO-320 via `import {{ generateKeyPair }} from 'node:crypto'`"
    );
}

#[test]
fn scans_js_jose_generatekeypair_ml_dsa() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("javascript/jose_generatekeypair.mjs"))
        .expect("scan succeeds");

    for (rule_id, algorithm_id) in [
        ("CRYPTO-1150", "ml-dsa-44"),
        ("CRYPTO-1151", "ml-dsa-65"),
        ("CRYPTO-1152", "ml-dsa-87"),
        ("CRYPTO-1153", "rsa-pss-sha256"),
        ("CRYPTO-1154", "rsa-pss-sha384"),
        ("CRYPTO-1155", "rsa-pss-sha512"),
        ("CRYPTO-1156", "rsa-pkcs1-sha256"),
        ("CRYPTO-1157", "rsa-pkcs1-sha384"),
        ("CRYPTO-1158", "rsa-pkcs1-sha512"),
        ("CRYPTO-1159", "rsa-oaep"),
        ("CRYPTO-1160", "rsa-oaep-256"),
        ("CRYPTO-1161", "rsa-oaep-384"),
        ("CRYPTO-1162", "rsa-oaep-512"),
        ("CRYPTO-1163", "ecdsa-p256"),
        ("CRYPTO-1164", "ecdsa-p384"),
        ("CRYPTO-1165", "ecdsa-p521"),
        ("CRYPTO-1167", "ecdh-unattributed"),
    ] {
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == rule_id && f.algorithm_id == algorithm_id),
            "expected {rule_id} via jose generateKeyPair('{algorithm_id}'); findings: {:#?}",
            findings
                .iter()
                .map(|f| (&f.rule_id, &f.algorithm_id))
                .collect::<Vec<_>>()
        );
    }

    assert_eq!(
        findings
            .iter()
            .filter(|f| f.rule_id == "CRYPTO-1166" && f.algorithm_id == "ed25519")
            .count(),
        2,
        "expected CRYPTO-1166/ed25519 from both 'Ed25519' and 'EdDSA'; findings: {:#?}",
        findings
            .iter()
            .map(|f| (&f.rule_id, &f.algorithm_id))
            .collect::<Vec<_>>()
    );

    assert_eq!(
        findings
            .iter()
            .filter(|f| f.rule_id == "CRYPTO-1167" && f.algorithm_id == "ecdh-unattributed")
            .count(),
        2,
        "expected CRYPTO-1167/ecdh-unattributed from both 'ECDH-ES' and 'ECDH-ES+A128KW'; findings: {:#?}",
        findings
            .iter()
            .map(|f| (&f.rule_id, &f.algorithm_id))
            .collect::<Vec<_>>()
    );

    assert_eq!(
        findings.len(),
        20,
        "a variable algorithm must yield no capture and no finding beyond the 20 literal calls; findings: {:#?}",
        findings
            .iter()
            .map(|f| (&f.rule_id, &f.algorithm_id))
            .collect::<Vec<_>>()
    );
}

#[test]
fn scans_python_hashlib_named_import() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("python/hashlib_named_import.py"))
        .expect("scan succeeds");

    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-140" && f.algorithm_id == "md5"),
        "expected CRYPTO-140 via `from hashlib import md5`; findings: {:#?}",
        findings
            .iter()
            .map(|f| (&f.rule_id, &f.algorithm_id))
            .collect::<Vec<_>>()
    );
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-141" && f.algorithm_id == "sha-1"),
        "expected CRYPTO-141 via `from hashlib import sha1 as s1`"
    );
}

#[test]
fn scans_python_hashlib_sha2_sha3() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("python/app.py"))
        .expect("scan succeeds");

    for (rule_id, algorithm_id) in [
        ("CRYPTO-962", "sha-224"),
        ("CRYPTO-963", "sha-256"),
        ("CRYPTO-964", "sha-384"),
        ("CRYPTO-965", "sha-512"),
        ("CRYPTO-966", "sha3-256"),
        ("CRYPTO-967", "sha3-384"),
        ("CRYPTO-968", "sha3-512"),
    ] {
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == rule_id && f.algorithm_id == algorithm_id),
            "expected {rule_id} ({algorithm_id}) via hashlib.* in Python fixture; findings: {:#?}",
            findings
                .iter()
                .map(|f| (&f.rule_id, &f.algorithm_id))
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn scans_python_pycryptodome_des() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("python/pycryptodome_des.py"))
        .expect("scan succeeds");

    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-809" && f.algorithm_id == "des"),
        "expected CRYPTO-809 via `Crypto.Cipher.DES.new`; findings: {:#?}",
        findings
            .iter()
            .map(|f| (&f.rule_id, &f.algorithm_id))
            .collect::<Vec<_>>()
    );
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-810" && f.algorithm_id == "3des"),
        "expected CRYPTO-810 via `Crypto.Cipher.DES3.new`"
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

/// Backlog `#Y57`: `RSA_generate_key_ex` had classify arms for `bits < 2048`,
/// `== 2048`, and `>= 4096` but nothing for the open band between — a real
/// literal like 3072 silently produced zero findings despite the extractor
/// seeing the call, the same gap `RSA_generate_key` (CRYPTO-406) and the
/// Rust `openssl` crate (CRYPTO-593) already closed.
#[test]
fn scans_c_rsa_generate_key_ex_midrange() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("cpp/crypto.c"))
        .expect("scan succeeds");

    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-407" && f.algorithm_id == "rsa-unattributed"),
        "expected CRYPTO-407 (RSA_generate_key_ex, bits=3072, catch-all) in C fixture; got: {:#?}",
        findings
            .iter()
            .map(|f| (&f.rule_id, &f.algorithm_id))
            .collect::<Vec<_>>()
    );
}

/// Legacy `RSA_generate_key(bits, e, cb, cb_arg)` puts bits in argument
/// position 1 (`_ex` puts it in position 2) and must still be caught.
#[test]
fn scans_c_rsa_generate_key_legacy() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("cpp/crypto.c"))
        .expect("scan succeeds");

    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-403" && f.algorithm_id == "rsa-undersized"),
        "expected CRYPTO-403 (undersized legacy RSA_generate_key); got: {:#?}",
        findings
            .iter()
            .map(|f| (&f.rule_id, &f.algorithm_id))
            .collect::<Vec<_>>()
    );
}

/// wolfssl's own OpenSSL-compat test suite wraps `RSA_generate_key` calls it
/// requires to FAIL in `ExpectNull(...)`, and calls it requires to SUCCEED in
/// `ExpectNotNull(...)`. Only the former is low-signal — the latter is a
/// genuine, successful key generation and must still be reported.
#[test]
fn expect_null_suppresses_but_expect_not_null_does_not() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("cpp/crypto.c"))
        .expect("scan succeeds");

    let rsa_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "CRYPTO-404" && f.algorithm_id == "rsa-2048")
        .collect();
    assert_eq!(
        rsa_findings.len(),
        1,
        "expected exactly one CRYPTO-404 (the ExpectNotNull success case); got: {:#?}",
        findings
            .iter()
            .map(|f| (&f.rule_id, &f.algorithm_id, f.location.line))
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
fn scans_c_ssl_groups_list_splits_the_colon_and_tuple_separated_names() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("cpp/crypto.c"))
        .expect("scan succeeds");

    let group_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id.starts_with("CRYPTO-9") && (909..=919).contains(&rule_num(f)))
        .collect();

    for (algorithm_id, expected) in [
        ("ecdh-p521", 1),       // P-521
        ("ecdh-p256", 2),       // *P-256 (must strip keyshare prefix) + SSL_CONF_cmd's P-256
        ("ecdh-p384", 2),       // P-384 + SSL_CONF_cmd "CURVES" alias's P-384
        ("x25519", 2),          // X25519 + SSL_CONF_cmd's X25519
        ("x25519-mlkem768", 1), // X25519MLKEM768
    ] {
        let n = group_findings
            .iter()
            .filter(|f| f.algorithm_id == algorithm_id)
            .count();
        assert_eq!(
            n,
            expected,
            "expected {expected} finding(s) for {algorithm_id}, got {n}: {:#?}",
            group_findings
                .iter()
                .map(|f| &f.algorithm_id)
                .collect::<Vec<_>>()
        );
    }

    // `?curveSM2` (unknown name, ignorable prefix) and `DEFAULT` (the
    // built-in-list pseudo-group) name no algorithm and must not fire; the
    // SSL_CONF_cmd variable-value and non-Groups-command fixture calls must
    // not fire either — so the fixture produces exactly the 8 group
    // findings above, nothing more.
    assert_eq!(
        group_findings.len(),
        8,
        "curveSM2, DEFAULT, the SSL_CONF_cmd variable value, and the non-Groups command must not add findings: {:#?}",
        group_findings
            .iter()
            .map(|f| &f.algorithm_id)
            .collect::<Vec<_>>()
    );
}

fn rule_num(f: &quipuu_core::Finding) -> u32 {
    f.rule_id
        .strip_prefix("CRYPTO-")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
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
fn scans_c_evp_digest_wider_digests() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("cpp/crypto.c"))
        .expect("scan succeeds");

    for (rule_id, algorithm_id) in [
        ("CRYPTO-423", "sha-224"),
        ("CRYPTO-424", "sha-384"),
        ("CRYPTO-425", "sha-512"),
        ("CRYPTO-426", "sha3-256"),
        ("CRYPTO-427", "sha3-384"),
        ("CRYPTO-428", "sha3-512"),
    ] {
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == rule_id && f.algorithm_id == algorithm_id),
            "expected {rule_id} ({algorithm_id}) in C fixture"
        );
    }
}

#[test]
fn scans_c_evp_aes_cbc() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("cpp/crypto.c"))
        .expect("scan succeeds");

    for (rule_id, algorithm_id) in [
        ("CRYPTO-920", "aes-128-cbc"),
        ("CRYPTO-921", "aes-192-cbc"),
        ("CRYPTO-922", "aes-256-cbc"),
    ] {
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == rule_id && f.algorithm_id == algorithm_id),
            "expected {rule_id} ({algorithm_id}) in C fixture"
        );
    }
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
    // The fixture includes <sodium.h>, so the qualified arm wins and the
    // unattributed fallback must not also fire on the same call.
    assert!(
        !findings.iter().any(|f| f.rule_id == "CRYPTO-442"),
        "a file that names sodium.h must not fall through to CRYPTO-442"
    );
}

/// `crypto_sign_keypair` in a file that names no NaCl header is not Ed25519.
///
/// Measured before the qualification arm existed: 12 findings across
/// `pq-crystals/dilithium` and `sphincsplus/sphincsplus` in the benchmark
/// corpus, every one High, every one asserting `ed25519`, every one telling a
/// FIPS 204 / FIPS 205 reference implementation to replace itself with
/// ML-DSA-65. The call site is real (P3 held); the algorithm identity was
/// invented from an identifier two families share.
#[test]
fn c_sign_keypair_without_a_nacl_header_asserts_no_algorithm() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("cpp/pqc_reference_sign.c"))
        .expect("scan succeeds");

    assert!(
        !findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-441" || f.algorithm_id == "ed25519"),
        "PQC reference shape must not be attributed to Ed25519, got: {findings:?}"
    );
    let unattributed: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "CRYPTO-442")
        .collect();
    assert_eq!(
        unattributed.len(),
        1,
        "the call site is still reported, without an algorithm claim: {findings:?}"
    );
    assert_eq!(unattributed[0].algorithm_id, "signature-unattributed");
    assert_eq!(unattributed[0].location.line, Some(24));
}

/// A `#include <sodium.h>` behind `#ifdef` still qualifies the call.
///
/// Portable C guards its optional headers, so a collector that reads only
/// top-level includes would drop the Ed25519 arm on exactly the files most
/// likely to be real consumers.
#[test]
fn c_sign_keypair_qualifies_through_a_guarded_include() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("cpp/sodium_guarded_include.c"))
        .expect("scan succeeds");

    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-441" && f.algorithm_id == "ed25519"),
        "an #ifdef-guarded sodium.h must still qualify the call: {findings:?}"
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

#[test]
fn scans_rust_kx_groups_list() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("rust/kx_groups.rs"))
        .expect("scan succeeds");

    let group_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id.starts_with("CRYPTO-9") && (920..=931).contains(&rule_num(f)))
        .collect();

    for (algorithm_id, expected) in [
        ("x25519-mlkem768", 3), // PROVIDER + DEFAULT_KX_GROUPS + rustls_post_quantum::DEFAULT_PROVIDER
        ("x25519", 1),          // PROVIDER
        ("secp256r1-mlkem768", 0),
        ("ecdh-p256", 2), // DEFAULT_KX_GROUPS + the unrelated-struct field
        ("ecdh-p384", 1), // DEFAULT_KX_GROUPS
    ] {
        let n = group_findings
            .iter()
            .filter(|f| f.algorithm_id == algorithm_id)
            .count();
        assert_eq!(
            n,
            expected,
            "expected {expected} finding(s) for {algorithm_id}, got {n}: {:#?}",
            group_findings
                .iter()
                .map(|f| &f.algorithm_id)
                .collect::<Vec<_>>()
        );
    }

    // The identifier-passthrough and vec![...] macro sites in `build`/
    // `build_vec`, and the classical `rustls_aws_lc_rs::DEFAULT_PROVIDER`
    // sibling const, must not fire — so the fixture produces exactly the 7
    // group findings counted above, nothing more.
    assert_eq!(
        group_findings.len(),
        7,
        "the identifier-passthrough, vec! macro, and classical sibling-const sites must not add findings: {:#?}",
        group_findings
            .iter()
            .map(|f| &f.algorithm_id)
            .collect::<Vec<_>>()
    );
}

#[test]
fn scans_rust_openmls_ciphersuite() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("rust/openmls_ciphersuite.rs"))
        .expect("scan succeeds");

    let ciphersuite_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id.starts_with("CRYPTO-1") && (1138..=1141).contains(&rule_num(f)))
        .collect();

    for (algorithm_id, expected) in [
        ("x-wing", 1),          // pick_hybrid
        ("ml-kem-1024", 1),     // pick_mlkem1024
        ("x25519-mlkem768", 1), // pick_mlkem768_x25519
        ("ml-kem-768", 2),      // pick_mlkem768_plain + pick_mlkem768_mldsa
    ] {
        let n = ciphersuite_findings
            .iter()
            .filter(|f| f.algorithm_id == algorithm_id)
            .count();
        assert_eq!(
            n,
            expected,
            "expected {expected} finding(s) for {algorithm_id}, got {n}: {:#?}",
            ciphersuite_findings
                .iter()
                .map(|f| &f.algorithm_id)
                .collect::<Vec<_>>()
        );
    }

    // The classical-only variant in `pick_classical` must not fire.
    assert_eq!(
        ciphersuite_findings.len(),
        5,
        "the classical-only variant must not add a finding: {:#?}",
        ciphersuite_findings
            .iter()
            .map(|f| &f.algorithm_id)
            .collect::<Vec<_>>()
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
fn scans_csharp_sha384_create() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("csharp/Crypto.cs"))
        .expect("scan succeeds");

    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-633" && f.algorithm_id == "sha-384"),
        "expected CRYPTO-633 (SHA384.Create) in C# fixture"
    );
}

#[test]
fn scans_csharp_sha3_create() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("csharp/Crypto.cs"))
        .expect("scan succeeds");

    for (rule_id, algorithm_id) in [
        ("CRYPTO-945", "sha3-256"),
        ("CRYPTO-946", "sha3-384"),
        ("CRYPTO-947", "sha3-512"),
    ] {
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == rule_id && f.algorithm_id == algorithm_id),
            "expected {rule_id} ({algorithm_id}) in C# fixture"
        );
    }
}

#[test]
fn scans_csharp_bouncycastle_mlkem_and_mldsa() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("csharp/Pqc.cs"))
        .expect("scan succeeds");

    let want = [
        ("CRYPTO-662", "ml-kem-768"), // new MLKemKeyGenerationParameters(random, MLKemParameters.ml_kem_768)
        ("CRYPTO-664", "ml-kem-unattributed"), // parameter set read from a variable
        ("CRYPTO-666", "ml-dsa-65"), // new MLDsaKeyGenerationParameters(random, MLDsaParameters.ml_dsa_65)
        ("CRYPTO-667", "ml-dsa-87"), // MLDsaParameters.ml_dsa_87_with_sha512 — same parameter set, pre-hashed
        ("CRYPTO-827", "ml-kem-768"), // new MLKemEncapsulator(MLKemParameters.ml_kem_768)
        ("CRYPTO-830", "ml-kem-512"), // new MLKemDecapsulator(MLKemParameters.ml_kem_512)
        ("CRYPTO-836", "ml-dsa-87"), // new MLDsaSigner(MLDsaParameters.ml_dsa_87, false)
    ];
    for (rule_id, algorithm_id) in want {
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == rule_id && f.algorithm_id == algorithm_id),
            "expected {rule_id} ({algorithm_id}) in C# PQC fixture; findings: {:#?}",
            findings
                .iter()
                .map(|f| (&f.rule_id, &f.algorithm_id))
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn scans_csharp_bouncycastle_lms_hss() {
    // #Y100 — LmsKeyGenerationParameters is always single-tree,
    // HssKeyGenerationParameters is always multi-tree; the constructor name
    // alone disambiguates lms from hss, no parameter-set literal to capture.
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("csharp/Pqc.cs"))
        .expect("scan succeeds");

    let want = [
        ("CRYPTO-1080", "lms"), // new LmsKeyGenerationParameters(lmsParameters, random)
        ("CRYPTO-1081", "hss"), // new HssKeyGenerationParameters(lmsParameters, random)
    ];
    for (rule_id, algorithm_id) in want {
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == rule_id && f.algorithm_id == algorithm_id),
            "expected {rule_id} ({algorithm_id}) in C# BouncyCastle LMS/HSS fixture; findings: {:#?}",
            findings
                .iter()
                .map(|f| (&f.rule_id, &f.algorithm_id))
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn scans_csharp_native_mlkem_mldsa_slhdsa() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("csharp/PqcNative.cs"))
        .expect("scan succeeds");

    let want = [
        ("CRYPTO-600", "rsa-unattributed"),      // RSA.Create() control
        ("CRYPTO-671", "ml-kem-768"),            // MLKem.GenerateKey(MLKemAlgorithm.MLKem768)
        ("CRYPTO-674", "ml-dsa-65"),             // MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65)
        ("CRYPTO-676", "slh-dsa-sha2-128s"), // SlhDsa.GenerateKey(SlhDsaAlgorithm.SlhDsaSha2_128s)
        ("CRYPTO-688", "ml-kem-unattributed"), // parameter set read from a variable
        ("CRYPTO-1046", "ml-kem-unattributed"), // new MLKemCng(key) — #Y87
        ("CRYPTO-1047", "ml-dsa-unattributed"), // new MLDsaCng(key) — #Y87
        ("CRYPTO-1052", "slh-dsa-unattributed"), // new SlhDsaCng(key) — #Y87 sibling
        ("CRYPTO-1078", "ml-dsa-unattributed"), // CompositeMLDsa.GenerateKey(…) — #Y95
        ("CRYPTO-1079", "ml-dsa-unattributed"), // new CompositeMLDsaCng(key) — #Y95's CNG sibling
        ("CRYPTO-1094", "ml-kem-unattributed"), // CompositeMLKem.GenerateKey(…) — #Y106
    ];
    for (rule_id, algorithm_id) in want {
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == rule_id && f.algorithm_id == algorithm_id),
            "expected {rule_id} ({algorithm_id}) in C# native PQC fixture; findings: {:#?}",
            findings
                .iter()
                .map(|f| (&f.rule_id, &f.algorithm_id))
                .collect::<Vec<_>>()
        );
    }

    // #Y87 — RSACng (classical CNG) is explicitly out of scope: no classify
    // rule anywhere in csharp.toml targets it, so `new RSACng(key)` in the
    // fixture must not surface as any finding's message.
    assert!(
        !findings.iter().any(|f| f.message.contains("RSACng")),
        "RSACng is out of scope for #Y87 and must not be detected; findings: {:#?}",
        findings
            .iter()
            .map(|f| (&f.rule_id, &f.algorithm_id))
            .collect::<Vec<_>>()
    );
}

#[test]
fn scans_csharp_mlkem_import_paths() {
    // #Y51 — GenerateKey isn't the only way a key enters an MLKem: a
    // provisioned key loaded from a vault or a wire payload goes through
    // MLKem.Import*, which had zero coverage before this test.
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("csharp/PqcNative.cs"))
        .expect("scan succeeds");

    let want = [
        ("CRYPTO-839", "ml-kem-768"), // ImportEncapsulationKey(MLKemAlgorithm.MLKem768, …)
        ("CRYPTO-844", "ml-kem-1024"), // ImportDecapsulationKey(MLKemAlgorithm.MLKem1024, …)
        ("CRYPTO-846", "ml-kem-512"), // ImportPrivateSeed(MLKemAlgorithm.MLKem512, …)
        ("CRYPTO-850", "ml-kem-unattributed"), // ImportPkcs8PrivateKey(…) — no algorithm arg
        ("CRYPTO-851", "ml-kem-unattributed"), // ImportSubjectPublicKeyInfo(…)
        ("CRYPTO-852", "ml-kem-unattributed"), // ImportFromPem(…)
    ];
    for (rule_id, algorithm_id) in want {
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == rule_id && f.algorithm_id == algorithm_id),
            "expected {rule_id} ({algorithm_id}) in C# MLKem.Import* fixture; findings: {:#?}",
            findings
                .iter()
                .map(|f| (&f.rule_id, &f.algorithm_id))
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn scans_csharp_mldsa_slhdsa_import_paths() {
    // #Y55 — the exact remainder #Y51 named and left open: MLDsa/SlhDsa have
    // their own Import* key-loading surface, structurally identical to
    // MLKem's, with zero coverage before this test.
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("csharp/PqcNative.cs"))
        .expect("scan succeeds");

    let want = [
        ("CRYPTO-854", "ml-dsa-65"), // MLDsa.ImportMLDsaPrivateKey(MLDsaAlgorithm.MLDsa65, …)
        ("CRYPTO-857", "ml-dsa-44"), // MLDsa.ImportMLDsaPrivateSeed(MLDsaAlgorithm.MLDsa44, …)
        ("CRYPTO-863", "ml-dsa-87"), // MLDsa.ImportMLDsaPublicKey(MLDsaAlgorithm.MLDsa87, …)
        ("CRYPTO-865", "ml-dsa-unattributed"), // MLDsa.ImportPkcs8PrivateKey(…)
        ("CRYPTO-866", "ml-dsa-unattributed"), // MLDsa.ImportSubjectPublicKeyInfo(…)
        ("CRYPTO-867", "ml-dsa-unattributed"), // MLDsa.ImportFromPem(…)
        ("CRYPTO-876", "slh-dsa-shake-192s"), // SlhDsa.ImportSlhDsaPrivateKey(…SlhDsaShake192s, …)
        ("CRYPTO-886", "slh-dsa-sha2-256f"), // SlhDsa.ImportSlhDsaPublicKey(…SlhDsaSha2_256f, …)
        ("CRYPTO-894", "slh-dsa-unattributed"), // SlhDsa.ImportPkcs8PrivateKey(…)
        ("CRYPTO-895", "slh-dsa-unattributed"), // SlhDsa.ImportSubjectPublicKeyInfo(…)
        ("CRYPTO-896", "slh-dsa-unattributed"), // SlhDsa.ImportFromPem(…)
    ];
    for (rule_id, algorithm_id) in want {
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == rule_id && f.algorithm_id == algorithm_id),
            "expected {rule_id} ({algorithm_id}) in C# MLDsa/SlhDsa Import* fixture; findings: {:#?}",
            findings
                .iter()
                .map(|f| (&f.rule_id, &f.algorithm_id))
                .collect::<Vec<_>>()
        );
    }
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
// Java JOSE dispatch: an enum constant compared, collected or tabulated.
//
// `PRECISION_AUDIT_V4.md § 2` measured this as the largest false-positive
// class in corpus B — 13 of 150 sampled stratum-A rows. The Go spelling of
// the same shape (`jwa.LookupSignatureAlgorithm("PS256")`) was suppressed by
// the registry-lookup cycle; these tests hold the Java spelling to the same
// verdict, in both directions.
// ============================================================================

fn jose_dispatch_findings() -> Vec<quipuu_core::Finding> {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    scanner
        .scan_path(&fixtures_root().join("java/JoseDispatch.java"))
        .expect("scan succeeds")
}

#[test]
fn java_jose_operational_sites_still_fire() {
    // The half of the fixture that must survive. Without this the dispatch
    // test below passes trivially for a scanner that reads no Java at all.
    let findings = jose_dispatch_findings();
    for (rule, why) in [
        ("CRYPTO-259", "declaration binding JWSAlgorithm.RS384"),
        ("CRYPTO-243", "signWith(key, SignatureAlgorithm.PS384)"),
        (
            "CRYPTO-264",
            "setAlgorithmIdentifier(AlgorithmIdentifiers.NONE)",
        ),
        (
            "CRYPTO-260",
            "super(AlgorithmIdentifiers.RSA_USING_SHA256, ...)",
        ),
    ] {
        assert!(
            findings.iter().any(|f| f.rule_id == rule),
            "{rule} must still fire — {why}; got {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }
}

#[test]
fn java_jose_dispatch_sites_do_not_fire() {
    // Every line below names a JOSE algorithm and performs none of it. Each
    // is asserted separately so a failure names the shape that regressed
    // rather than a count.
    let lines: Vec<u32> = jose_dispatch_findings()
        .iter()
        .filter_map(|f| f.location.line)
        .collect();
    for (line, shape) in [
        (
            42u32,
            "alg.equals(JWSAlgorithm.ES512) — comparison, argument side",
        ),
        (
            46,
            "JWSAlgorithm.EdDSA.equals(alg) — comparison, receiver side",
        ),
        (50, "alg == JWEAlgorithm.RSA_OAEP_256 — equality operator"),
        (56, "algs.add(JWSAlgorithm.HS512) — supported-algorithm set"),
        (61, "Arrays.asList(HS384, HS256) — preference list"),
        (
            66,
            "hashes.put(SignatureAlgorithm.ES256, ...) — resolver table",
        ),
        (73, "assertEquals(JWSAlgorithm.RS512, alg) — test assertion"),
    ] {
        assert!(
            !lines.contains(&line),
            "JoseDispatch.java:{line} must produce no finding — {shape}"
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

/// Backlog `#Y58`: pycryptodome's `Crypto.PublicKey.RSA.generate(bits)` had no
/// symbolic fallback of the kind `#Y58`'s hazmat/paramiko sibling (CRYPTO-104)
/// already had — a config-driven key size (`RSA.generate(key_size)`) produced
/// zero findings despite the extractor already seeing the call.
#[test]
fn phase8_pycryptodome_variable_rsa_bits_produces_finding() {
    let b = load_builtins().expect("builtins");
    let scanner = Scanner::with_builtins(b.algorithms.clone()).expect("scanner");
    let findings = scanner
        .scan_path(&fixtures_root().join("python/paramiko_style.py"))
        .expect("scan succeeds");

    let cr173 = findings.iter().find(|f| f.rule_id == "CRYPTO-173");
    assert!(
        cr173.is_some(),
        "expected CRYPTO-173 for RSA.generate(key_size), got: {:?}",
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
    let f = cr173.unwrap();
    assert_eq!(f.algorithm_id, "rsa-unattributed");
    assert!(
        f.message.contains("key_size"),
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
fn rust_md5_sha1_crates_are_covered() {
    // #Y65: the sha2 family (Sha256/384/512) had coverage but the md5 and
    // sha1 crates — same digest-trait shape, `New`/`Digest` — had none.
    let b = load_builtins().expect("builtins");
    let scanner = Scanner::with_builtins(b.algorithms.clone()).expect("scanner");
    let findings = scanner
        .scan_path(&fixtures_root().join("rust/rust_advanced.rs"))
        .expect("scan succeeds");
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-956" && f.algorithm_id == "md5"),
        "expected CRYPTO-956/md5 for Md5::new/Md5::digest, got: {:?}",
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-957" && f.algorithm_id == "sha-1"),
        "expected CRYPTO-957/sha-1 for Sha1::new/Sha1::digest"
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
fn y29_rust_openssl_rsa_generate_literal_and_variable_bits() {
    // #Y29: `openssl` crate's `Rsa::generate` had no arm at all, so a
    // codebase using it for RSA keygen produced zero findings for either
    // shape — the same non-literal-argument gap BUG-B fixed for the `rsa`
    // crate's RsaPrivateKey::new, one crate over.
    let b = load_builtins().expect("builtins");
    let scanner = Scanner::with_builtins(b.algorithms.clone()).expect("scanner");
    let findings = scanner
        .scan_path(&fixtures_root().join("rust/rust_advanced.rs"))
        .expect("scan succeeds");
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-591" && f.algorithm_id == "rsa-2048"),
        "expected CRYPTO-591 for openssl::rsa::Rsa::generate(2048), got: {:?}",
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
    let cr593 = findings
        .iter()
        .find(|f| f.rule_id == "CRYPTO-593")
        .expect("CRYPTO-593 catch-all must fire for variable bits");
    assert_eq!(cr593.algorithm_id, "rsa-unattributed");
}

#[test]
fn phase10_rust_rcgen_keypair_generate_for() {
    // BUG-C: rcgen::KeyPair::generate_for is the rustls-webpki test-utils
    // key generator; previously unrecognized.
    //
    // This line passes `&rcgen::PKCS_ECDSA_P256_SHA256`, so the curve is
    // stated at the call site. It used to report the unattributed sentinel
    // anyway, because nothing read the argument; the full argument matrix is
    // `rcgen_generate_for_reads_the_signature_algorithm_argument`.
    let b = load_builtins().expect("builtins");
    let scanner = Scanner::with_builtins(b.algorithms.clone()).expect("scanner");
    let findings = scanner
        .scan_path(&fixtures_root().join("rust/rust_advanced.rs"))
        .expect("scan succeeds");
    let hit = findings
        .iter()
        .find(|f| f.rule_id == "CRYPTO-575")
        .expect("CRYPTO-575 must fire for rcgen::KeyPair::generate_for(PKCS_ECDSA_P256_*)");
    assert_eq!(hit.algorithm_id, "ecdsa-p256");
}

#[test]
fn phase10_rust_signingkey_turbofish_routes_to_hash() {
    // BUG-F: SigningKey::<Sha256>::new must route to CRYPTO-544 (SHA256),
    // <Sha384>::new to CRYPTO-545, <Sha512>::new to CRYPTO-546, <Sha1>::new to
    // CRYPTO-548 — not fall through to CRYPTO-547's rsa-pkcs1-sha256 catch-all
    // (PRECISION_AUDIT_V4.md rows 3/6, crates-io/rsa's own test suite).
    let b = load_builtins().expect("builtins");
    let scanner = Scanner::with_builtins(b.algorithms.clone()).expect("scanner");
    let findings = scanner
        .scan_path(&fixtures_root().join("rust/rust_advanced.rs"))
        .expect("scan succeeds");
    for (rule, algo) in [
        ("CRYPTO-544", "rsa-pkcs1-sha256"),
        ("CRYPTO-545", "rsa-pkcs1-sha384"),
        ("CRYPTO-546", "rsa-pkcs1-sha512"),
        ("CRYPTO-548", "rsa-pkcs1-sha1"),
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

// ── rcgen: the signature algorithm is the argument ─────────────────────────
//
// `KeyPair::generate_for(SIG_ALG)` selects ECDSA, Ed25519, RSA or ML-DSA from
// one constant, so the callee decides nothing. It used to publish an ECDSA id
// unconditionally, which raised a quantum-vulnerable High against
// `generate_for(&rcgen::PKCS_ML_DSA_44)` — an alarm on code that has already
// migrated, the worst error class available to a PQC migration scanner.

#[test]
fn rcgen_generate_for_reads_the_signature_algorithm_argument() {
    let b = load_builtins().expect("builtins");
    let scanner = Scanner::with_builtins(b.algorithms.clone()).expect("scanner");
    let findings = scanner
        .scan_path(&fixtures_root().join("rust/rcgen_keypair.rs"))
        .expect("scan succeeds");

    // (line, rule id, algorithm id). The algorithm matters as much as the hit:
    // the ML-DSA lines are the defect, and an ECDSA id on them is the bug.
    let expected = [
        (16, "CRYPTO-571", "ml-dsa-44"),
        (17, "CRYPTO-573", "ml-dsa-87"),
        (18, "CRYPTO-572", "ml-dsa-65"),
        (22, "CRYPTO-575", "ecdsa-p256"),
        (23, "CRYPTO-576", "ecdsa-p384"),
        (25, "CRYPTO-577", "ecdsa-p521"),
        (26, "CRYPTO-574", "ed25519"),
        (27, "CRYPTO-579", "rsa-pkcs1-sha384"),
        // Not stated at the line: no capture, so the unattributed arm.
        (31, "CRYPTO-570", "ecdsa-unattributed"),
        (32, "CRYPTO-570", "ecdsa-unattributed"),
        (33, "CRYPTO-570", "ecdsa-unattributed"),
    ];

    let mut wrong = Vec::new();
    for (line, rule_id, algorithm_id) in expected {
        let hit = findings.iter().find(|f| f.location.line == Some(line));
        match hit {
            Some(f) if f.rule_id == rule_id && f.algorithm_id == algorithm_id => {}
            Some(f) => wrong.push(format!(
                "line {line}: expected {rule_id} → {algorithm_id}, got {} → {}",
                f.rule_id, f.algorithm_id
            )),
            None => wrong.push(format!("line {line}: no finding at all")),
        }
    }
    assert!(
        wrong.is_empty(),
        "{}/{} rcgen call sites misclassified:\n  {}",
        wrong.len(),
        expected.len(),
        wrong.join("\n  "),
    );

    // The point of the whole fixture, stated as its own assertion so a
    // regression names the defect rather than a line number.
    assert!(
        !findings
            .iter()
            .any(|f| f.algorithm_id.starts_with("ecdsa") && f.message.contains("PKCS_ML_DSA")),
        "a call site naming an ML-DSA parameter set is classified as ECDSA"
    );
}

// ── aws-lc-rs: ML-KEM / ML-DSA parameter set is the argument ───────────────
//
// DecapsulationKey::generate and PqdsaKeyPair::generate take the parameter
// set as an associated-constant argument, the same shape rcgen's
// generate_for uses. A variable there yields the unattributed sentinel
// rather than a guess.

#[test]
fn scans_rust_aws_lc_rs_ml_kem_ml_dsa() {
    let b = load_builtins().expect("builtins");
    let scanner = Scanner::with_builtins(b.algorithms.clone()).expect("scanner");
    let findings = scanner
        .scan_path(&fixtures_root().join("rust/aws_lc_rs_pqc.rs"))
        .expect("scan succeeds");

    let expected = [
        (13, "CRYPTO-1069", "ml-kem-512"),
        (14, "CRYPTO-1070", "ml-kem-768"),
        (15, "CRYPTO-1071", "ml-kem-1024"),
        (19, "CRYPTO-1073", "ml-dsa-44"),
        (20, "CRYPTO-1074", "ml-dsa-65"),
        (21, "CRYPTO-1075", "ml-dsa-87"),
        (25, "CRYPTO-1072", "kem-unattributed"),
    ];

    let mut wrong = Vec::new();
    for (line, rule_id, algorithm_id) in expected {
        let hit = findings.iter().find(|f| f.location.line == Some(line));
        match hit {
            Some(f) if f.rule_id == rule_id && f.algorithm_id == algorithm_id => {}
            Some(f) => wrong.push(format!(
                "line {line}: expected {rule_id} → {algorithm_id}, got {} → {}",
                f.rule_id, f.algorithm_id
            )),
            None => wrong.push(format!("line {line}: no finding at all")),
        }
    }
    assert!(
        wrong.is_empty(),
        "{}/{} aws-lc-rs call sites misclassified:\n  {}",
        wrong.len(),
        expected.len(),
        wrong.join("\n  "),
    );
}

// ── oqs (liboqs-rust): ML-KEM / ML-DSA parameter set is the argument ───────
//
// Kem::new and Sig::new take the parameter set as an Algorithm-variant
// argument, the same shape aws-lc-rs's constructors use above. A variable
// there yields the unattributed sentinel rather than a guess. Backlog #Y117.

#[test]
fn scans_rust_oqs_ml_kem_ml_dsa() {
    let b = load_builtins().expect("builtins");
    let scanner = Scanner::with_builtins(b.algorithms.clone()).expect("scanner");
    let findings = scanner
        .scan_path(&fixtures_root().join("rust/oqs_pqc.rs"))
        .expect("scan succeeds");

    let expected = [
        (14, "CRYPTO-1142", "ml-kem-512"),
        (15, "CRYPTO-1143", "ml-kem-768"),
        (16, "CRYPTO-1144", "ml-kem-1024"),
        (20, "CRYPTO-1146", "ml-dsa-44"),
        (21, "CRYPTO-1147", "ml-dsa-65"),
        (22, "CRYPTO-1148", "ml-dsa-87"),
        (26, "CRYPTO-1145", "kem-unattributed"),
    ];

    let mut wrong = Vec::new();
    for (line, rule_id, algorithm_id) in expected {
        let hit = findings.iter().find(|f| f.location.line == Some(line));
        match hit {
            Some(f) if f.rule_id == rule_id && f.algorithm_id == algorithm_id => {}
            Some(f) => wrong.push(format!(
                "line {line}: expected {rule_id} → {algorithm_id}, got {} → {}",
                f.rule_id, f.algorithm_id
            )),
            None => wrong.push(format!("line {line}: no finding at all")),
        }
    }
    assert!(
        wrong.is_empty(),
        "{}/{} oqs call sites misclassified:\n  {}",
        wrong.len(),
        expected.len(),
        wrong.join("\n  "),
    );
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
fn go_alg_none_fires_only_beside_another_jose_name() {
    // `"none"` is the one whitelisted JWA name that is also an English word.
    // Corroborated: a run of constructor calls in one function body, and a
    // dispatch switch — both real jwx shapes, both must still fire.
    // Uncorroborated: enum constants, SSH protocol strings, a connection
    // parameter — 91 of the 92 corpus findings, none of which may fire.
    let b = load_builtins().expect("builtins");
    let scanner = Scanner::with_builtins(b.algorithms.clone()).expect("scanner");

    let good = scanner
        .scan_path(&fixtures_root().join("go/alg_none_corroborated.go"))
        .expect("scan succeeds");
    let good_lines: Vec<_> = good
        .iter()
        .filter(|f| f.rule_id == "CRYPTO-740")
        .map(|f| f.location.line)
        .collect();
    assert_eq!(
        good_lines.len(),
        2,
        "both corroborated shapes must fire, got: {good_lines:?}"
    );

    let bad = scanner
        .scan_path(&fixtures_root().join("go/alg_none_uncorroborated.go"))
        .expect("scan succeeds");
    assert!(
        !bad.iter().any(|f| f.rule_id == "CRYPTO-740"),
        "no shape in this fixture registers an algorithm, got: {:?}",
        bad.iter()
            .filter(|f| f.rule_id == "CRYPTO-740")
            .map(|f| f.location.line)
            .collect::<Vec<_>>()
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
    //   - 2 added with sha256.New()/sha512.New() detection
    let b = load_builtins().expect("builtins");
    let scanner = Scanner::with_builtins(b.algorithms.clone()).expect("scanner");
    let main_findings = scanner
        .scan_path(&fixtures_root().join("go/main.go"))
        .expect("scan succeeds");
    assert_eq!(main_findings.len(), 14, "go/main.go count must not change");

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

// ── Go stdlib sign/verify/hash *operation* sites, not just constructors ────
//
// A key generated by rsa.GenerateKey/ecdsa.GenerateKey in one file and used
// to sign or verify in another (or received as a function argument) never
// matched a constructor rule, so the operation site produced zero findings
// instead of degrading to the unattributed sentinel every other pack uses.

#[test]
fn go_operation_sites_are_all_detected() {
    let b = load_builtins().expect("builtins");
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner");
    let findings = scanner
        .scan_path(&fixtures_root().join("go/operations.go"))
        .expect("scan succeeds");

    let expect = |line: u32, rule: &str, algorithm_id: &str| {
        let f = findings
            .iter()
            .find(|f| f.location.line == Some(line) && f.rule_id == rule);
        assert!(
            f.is_some(),
            "expected {rule} on line {line}, got:\n  {}",
            findings
                .iter()
                .map(|f| format!("{} {} {:?}", f.rule_id, f.algorithm_id, f.location.line))
                .collect::<Vec<_>>()
                .join("\n  ")
        );
        assert_eq!(
            f.unwrap().algorithm_id,
            algorithm_id,
            "wrong algorithm_id on line {line}"
        );
    };

    // ecdsa.Sign / SignASN1 / VerifyASN1 — curve unknown at the call site.
    expect(20, "CRYPTO-015", "ecdsa-unattributed");
    expect(21, "CRYPTO-015", "ecdsa-unattributed");
    expect(22, "CRYPTO-015", "ecdsa-unattributed");

    // rsa.SignPKCS1v15 / VerifyPKCS1v15 — key size unknown at the call site.
    expect(26, "CRYPTO-006", "rsa-unattributed");
    expect(27, "CRYPTO-006", "rsa-unattributed");

    // ed25519.Sign / Verify — no parameter set to lose.
    expect(31, "CRYPTO-021", "ed25519");
    expect(32, "CRYPTO-021", "ed25519");

    // md5.Sum / sha1.Sum — the one-shot form, distinct from md5.New/sha1.New.
    expect(36, "CRYPTO-052", "md5");
    expect(37, "CRYPTO-053", "sha-1");

    // sha256.Sum256/Sum224 and sha512.Sum512/Sum384 — the one-shot forms,
    // distinct from sha256.New/sha512.New in main.go.
    expect(38, "CRYPTO-949", "sha-256");
    expect(39, "CRYPTO-951", "sha-224");
    expect(40, "CRYPTO-953", "sha-512");
    expect(41, "CRYPTO-955", "sha-384");

    // dsa.GenerateKey / Sign / Verify — no parameter is ever stated at any of
    // these call sites (the prime/subprime size lives in a separate
    // dsa.GenerateParameters call this pack does not track).
    expect(45, "CRYPTO-016", "dsa-unattributed");
    expect(46, "CRYPTO-017", "dsa-unattributed");
    expect(47, "CRYPTO-017", "dsa-unattributed");
}

// Backlog #Y20: `circl`'s eddilithium{2,3} hybrid schemes AND-combine an
// Ed25519/ECDSA signature with a Dilithium/ML-DSA one in the same
// Sign/Verify function. Telling a team that already adopted the hybrid
// scheme to "replace with ML-DSA", with no mention of the co-located PQC
// call two lines away, is an active false statement — not merely an
// incomplete one — so the message must name it instead.
#[test]
fn go_ed25519_op_names_a_colocated_circl_pqc_call() {
    let b = load_builtins().expect("builtins");
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner");
    let findings = scanner
        .scan_path(&fixtures_root().join("go/circl_hybrid.go"))
        .expect("scan succeeds");

    let ed25519_sign = findings
        .iter()
        .find(|f| f.rule_id == "CRYPTO-021" && f.message.contains("Sign operation"))
        .expect("ed25519.Sign finding");
    assert!(
        ed25519_sign
            .message
            .contains("also calls ML-DSA (circl dilithium) at line"),
        "expected co-location note, got: {}",
        ed25519_sign.message
    );

    let ed25519_verify = findings
        .iter()
        .find(|f| f.rule_id == "CRYPTO-021" && f.message.contains("Verify operation"))
        .expect("ed25519.Verify finding");
    assert!(
        ed25519_verify
            .message
            .contains("also calls ML-DSA (circl dilithium) at line"),
        "expected co-location note, got: {}",
        ed25519_verify.message
    );

    // A plain ECDSA op in a function with no PQC co-occurrence keeps its
    // original message, unmodified — the note is empty, not just present.
    let plain_ecdsa = findings
        .iter()
        .find(|f| f.rule_id == "CRYPTO-015")
        .expect("ecdsa.VerifyASN1 finding");
    assert!(
        !plain_ecdsa.message.contains("also calls"),
        "unrelated ecdsa op should not carry a co-location note: {}",
        plain_ecdsa.message
    );
}

/// Backlog `#Y33`: liboqs stack-form API — algorithm baked into the function
/// name — had zero rules. All three ML-KEM-768 operations must resolve to the
/// same algorithm-id.
#[test]
fn scans_c_liboqs_stack_form_kem() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("cpp/crypto.c"))
        .expect("scan succeeds");

    let kem: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "CRYPTO-461" && f.algorithm_id == "ml-kem-768")
        .collect();
    assert_eq!(
        kem.len(),
        3,
        "expected keypair/encaps/decaps to all report ml-kem-768; got: {:#?}",
        findings
            .iter()
            .map(|f| (&f.rule_id, &f.algorithm_id))
            .collect::<Vec<_>>()
    );
}

/// Same crossing, the SIG family: liboqs stack-form ML-DSA-65.
#[test]
fn scans_c_liboqs_stack_form_sig() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("cpp/crypto.c"))
        .expect("scan succeeds");

    let sig: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "CRYPTO-464" && f.algorithm_id == "ml-dsa-65")
        .collect();
    assert_eq!(
        sig.len(),
        2,
        "expected keypair/sign to both report ml-dsa-65; got: {:#?}",
        findings
            .iter()
            .map(|f| (&f.rule_id, &f.algorithm_id))
            .collect::<Vec<_>>()
    );
}

/// liboqs heap-form API: the algorithm arrives as the `OQS_KEM_alg_*` macro
/// name, a bare identifier argument to `OQS_KEM_new`, not a string literal.
#[test]
fn scans_c_liboqs_heap_form_kem() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("cpp/crypto.c"))
        .expect("scan succeeds");

    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-467" && f.algorithm_id == "ml-kem-768"),
        "expected CRYPTO-467 (liboqs heap-form OQS_KEM_new(OQS_KEM_alg_ml_kem_768)); got: {:#?}",
        findings
            .iter()
            .map(|f| (&f.rule_id, &f.algorithm_id))
            .collect::<Vec<_>>()
    );
}

/// `OQS_SIG_STFL_new` is the stateful hash-signature API (LMS/XMSS) — a
/// separate, firmware-signing population this project has stood down on
/// covering. It must not be picked up by any liboqs rule: exactly 11 liboqs
/// findings total (3 stack-KEM, 2 stack-SIG, 1 heap-KEM, 1 heap-SIG SLH-DSA,
/// 3 heap-KEM unattributed (HQC), 1 heap-SIG unattributed (MAYO)), none on
/// the STFL line.
#[test]
fn liboqs_stfl_new_is_out_of_scope() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("cpp/crypto.c"))
        .expect("scan succeeds");

    let liboqs: Vec<_> = findings
        .iter()
        .filter(|f| f.message.contains("liboqs"))
        .collect();
    assert_eq!(
        liboqs.len(),
        11,
        "expected exactly 11 liboqs findings (STFL excluded); got: {:#?}",
        liboqs
            .iter()
            .map(|f| (&f.rule_id, &f.algorithm_id, f.location.line))
            .collect::<Vec<_>>()
    );
    assert!(
        !liboqs.iter().any(|f| f.message.contains("STFL")),
        "OQS_SIG_STFL_new must not be classified by a liboqs rule"
    );
}

/// Backlog `#Y56`: `OQS_KEM_new`/`OQS_SIG_new` extract any algorithm-name
/// macro but previously classified only a closed enumerated list with no
/// fallback arm, so HQC (NIST's own selected backup KEM, default-on in
/// liboqs since 0.16.0) and other candidate families produced zero findings
/// — not a degraded one — despite being visible to the extractor.
#[test]
fn scans_c_liboqs_heap_form_unattributed_fallback() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("cpp/crypto.c"))
        .expect("scan succeeds");

    let kem_unattributed = findings
        .iter()
        .filter(|f| f.rule_id == "CRYPTO-897" && f.algorithm_id == "kem-unattributed")
        .count();
    assert_eq!(
        kem_unattributed,
        3,
        "expected 3 HQC OQS_KEM_new sites to degrade to kem-unattributed; got: {:#?}",
        findings
            .iter()
            .map(|f| (&f.rule_id, &f.algorithm_id))
            .collect::<Vec<_>>()
    );

    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-898" && f.algorithm_id == "sig-unattributed"),
        "expected the MAYO OQS_SIG_new site to degrade to sig-unattributed; got: {:#?}",
        findings
            .iter()
            .map(|f| (&f.rule_id, &f.algorithm_id))
            .collect::<Vec<_>>()
    );
}

/// Backlog `#Y44`: liboqs heap-form SIG API had classify arms for ML-DSA but
/// none for SLH-DSA, though the extract rule (`OQS_SIG_new`) already covers
/// both families. SLH-DSA has no stack-form header upstream (no
/// `src/sig_slh_dsa/`), so this heap-form arm is its only detection path.
#[test]
fn scans_c_liboqs_heap_form_sig_slh_dsa() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("cpp/crypto.c"))
        .expect("scan succeeds");

    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-472" && f.algorithm_id == "slh-dsa-sha2-128s"),
        "expected CRYPTO-472 (liboqs heap-form OQS_SIG_new(OQS_SIG_alg_slh_dsa_pure_sha2_128s)); got: {:#?}",
        findings
            .iter()
            .map(|f| (&f.rule_id, &f.algorithm_id))
            .collect::<Vec<_>>()
    );
}

/// Backlog `#Y52`: OpenSSL 3.0+'s own generic keygen API
/// (`EVP_PKEY_CTX_new_from_name` / `EVP_PKEY_Q_keygen`) had zero coverage —
/// the documented replacement for the deprecated typed functions
/// (`RSA_generate_key_ex`, ...) already covered above. Both classical and PQC
/// algorithm names must resolve, across both call shapes.
#[test]
fn scans_c_openssl_generic_keygen() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("cpp/crypto.c"))
        .expect("scan succeeds");

    let want = [
        ("CRYPTO-484", "rsa-unattributed"), // EVP_PKEY_CTX_new_from_name(libctx, "RSA", NULL)
        ("CRYPTO-485", "ecdsa-unattributed"), // EVP_PKEY_CTX_new_from_name(libctx, "EC", NULL)
        ("CRYPTO-486", "dh-unattributed"),  // EVP_PKEY_Q_keygen(libctx, NULL, "DH")
        ("CRYPTO-489", "ml-kem-1024"),      // EVP_PKEY_Q_keygen(libctx, NULL, "ML-KEM-1024")
        ("CRYPTO-1065", "x25519-mlkem768"), // EVP_PKEY_Q_keygen(libctx, NULL, "X25519MLKEM768")
        ("CRYPTO-1066", "secp256r1-mlkem768"), // EVP_PKEY_Q_keygen(libctx, NULL, "SecP256r1MLKEM768")
        ("CRYPTO-1067", "secp384r1-mlkem1024"), // EVP_PKEY_Q_keygen(libctx, NULL, "SecP384r1MLKEM1024")
        ("CRYPTO-1068", "x448-mlkem1024"),      // EVP_PKEY_Q_keygen(libctx, NULL, "X448MLKEM1024")
    ];
    for (rule_id, algorithm_id) in want {
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == rule_id && f.algorithm_id == algorithm_id),
            "expected {rule_id} ({algorithm_id}) in cpp/crypto.c; got: {:#?}",
            findings
                .iter()
                .map(|f| (&f.rule_id, &f.algorithm_id))
                .collect::<Vec<_>>()
        );
    }
}

/// Backlog `#Y69` (KEM half): OpenSSL 3.5+'s generic KEM *operation* API
/// (`EVP_PKEY_encapsulate`/`EVP_PKEY_decapsulate`, as opposed to keygen,
/// which `scans_c_openssl_generic_keygen` already covers) had zero coverage.
/// Neither call carries an algorithm argument — it lives on the
/// `EVP_PKEY_CTX` built earlier, which this pack does not trace across
/// statements — so both must degrade to `kem-unattributed` rather than
/// produce nothing, the same convention `#Y56` shipped for liboqs's generic
/// KEM API.
#[test]
fn scans_c_openssl_kem_operation_api() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("cpp/crypto.c"))
        .expect("scan succeeds");

    let want = [
        ("CRYPTO-960", "kem-unattributed"), // EVP_PKEY_encapsulate(ctx, ...)
        ("CRYPTO-961", "kem-unattributed"), // EVP_PKEY_decapsulate(ctx, ...)
    ];
    for (rule_id, algorithm_id) in want {
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == rule_id && f.algorithm_id == algorithm_id),
            "expected {rule_id} ({algorithm_id}) in cpp/crypto.c; got: {:#?}",
            findings
                .iter()
                .map(|f| (&f.rule_id, &f.algorithm_id))
                .collect::<Vec<_>>()
        );
    }
}

/// Backlog `#Y70`: OpenSSL 3.5+'s `EVP_SIGNATURE_fetch(libctx, name, propq)`
/// had zero coverage. The originally-filed approach would have classified
/// every `EVP_PKEY_sign_message_init`/`verify_message_init` call as an
/// unattributed PQC signature, but that operation API is also how classical
/// Ed25519/Ed448 dispatch (`eddsa_sig.c`) and CMS's own generic signer
/// (`cms_sd.c`'s `cms_mdless_signing`) route — attributing at the fetch call
/// instead avoids mislabeling a classical call site as PQC and additionally
/// covers RSA/ECDSA/Ed25519/Ed448 fetches this pack had no rule for at all.
#[test]
fn scans_c_openssl_signature_fetch() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("cpp/crypto.c"))
        .expect("scan succeeds");

    let want = [
        ("CRYPTO-973", "rsa-unattributed"), // EVP_SIGNATURE_fetch(libctx, "RSA", NULL)
        ("CRYPTO-974", "ecdsa-unattributed"), // EVP_SIGNATURE_fetch(libctx, "ECDSA", NULL)
        ("CRYPTO-975", "ed25519"),          // EVP_SIGNATURE_fetch(libctx, "ED25519", NULL)
        ("CRYPTO-976", "ed448"),            // EVP_SIGNATURE_fetch(libctx, "ED448", NULL)
        ("CRYPTO-977", "ml-dsa-44"),        // EVP_SIGNATURE_fetch(libctx, "ML-DSA-44", NULL)
        ("CRYPTO-978", "ml-dsa-65"),        // EVP_SIGNATURE_fetch(libctx, "ML-DSA-65", NULL)
        ("CRYPTO-979", "ml-dsa-87"),        // EVP_SIGNATURE_fetch(libctx, "ML-DSA-87", NULL)
        ("CRYPTO-991", "slh-dsa-shake-256f"), // EVP_SIGNATURE_fetch(libctx, "SLH-DSA-SHAKE-256f", NULL)
    ];
    for (rule_id, algorithm_id) in want {
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == rule_id && f.algorithm_id == algorithm_id),
            "expected {rule_id} ({algorithm_id}) in cpp/crypto.c; got: {:#?}",
            findings
                .iter()
                .map(|f| (&f.rule_id, &f.algorithm_id))
                .collect::<Vec<_>>()
        );
    }
}

/// Backlog `#Y85`: OpenSSL 4.0+'s fetch-by-name digest API (`EVP_MD_fetch`)
/// had zero coverage, classical or PQC — including the new FIPS 204
/// external-mu pseudo-digest (`EVP_MD_fetch(libctx, "ML-DSA-MU", propq)`)
/// used for HSM-split ML-DSA signing.
#[test]
fn scans_c_openssl_md_fetch() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("cpp/crypto.c"))
        .expect("scan succeeds");

    let want = [
        ("CRYPTO-1036", "md5"),                 // EVP_MD_fetch(libctx, "MD5", NULL)
        ("CRYPTO-1037", "sha-1"),               // EVP_MD_fetch(libctx, "SHA1", NULL)
        ("CRYPTO-1039", "sha-256"),             // EVP_MD_fetch(libctx, "SHA256", NULL)
        ("CRYPTO-1044", "sha3-512"),            // EVP_MD_fetch(libctx, "SHA3-512", NULL)
        ("CRYPTO-1045", "ml-dsa-unattributed"), // EVP_MD_fetch(libctx, "ML-DSA-MU", NULL)
    ];
    for (rule_id, algorithm_id) in want {
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == rule_id && f.algorithm_id == algorithm_id),
            "expected {rule_id} ({algorithm_id}) in cpp/crypto.c; got: {:#?}",
            findings
                .iter()
                .map(|f| (&f.rule_id, &f.algorithm_id))
                .collect::<Vec<_>>()
        );
    }
}

/// Windows CNG had zero coverage for any native algorithm, classical or
/// PQC — the Backlog's Win32 CNG item, blocked pending a broader corpus
/// check than the single vendored `symcrypt` clone. That check now returns
/// a real call site: Chromium's own `net/ssl/ssl_platform_key_win_unittest.cc`
/// calls `NCryptIsAlgSupported(prov, BCRYPT_MLDSA_ALGORITHM, ...)`.
/// `BCryptGenerateKeyPair`/`BCryptImportKeyPair` against the ML-KEM
/// pseudo-handle and `BCryptOpenAlgorithmProvider` against ML-DSA are
/// Microsoft's own documented idiom for the same two algorithms. All four
/// entry points are used constantly for classical algorithms too, so the
/// classical `BCryptOpenAlgorithmProvider(&hRsaAlg, BCRYPT_RSA_ALGORITHM, ...)`
/// call in the fixture must NOT produce a finding.
#[test]
fn scans_c_windows_cng_mlkem_mldsa() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("cpp/crypto.c"))
        .expect("scan succeeds");

    let want = [
        ("CRYPTO-1050", "ml-kem-unattributed"), // BCryptGenerateKeyPair(BCRYPT_MLKEM_ALG_HANDLE, ...)
        ("CRYPTO-1050", "ml-kem-unattributed"), // BCryptImportKeyPair(BCRYPT_MLKEM_ALG_HANDLE, ...)
        ("CRYPTO-1051", "ml-dsa-unattributed"), // BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_MLDSA_ALGORITHM, ...)
        ("CRYPTO-1051", "ml-dsa-unattributed"), // NCryptIsAlgSupported(prov, BCRYPT_MLDSA_ALGORITHM, ...)
    ];
    for (rule_id, algorithm_id) in want {
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == rule_id && f.algorithm_id == algorithm_id),
            "expected {rule_id} ({algorithm_id}) in cpp/crypto.c; got: {:#?}",
            findings
                .iter()
                .map(|f| (&f.rule_id, &f.algorithm_id))
                .collect::<Vec<_>>()
        );
    }
    assert!(
        !findings
            .iter()
            .any(|f| f.message.contains("BCRYPT_RSA_ALGORITHM")),
        "classical BCryptOpenAlgorithmProvider(BCRYPT_RSA_ALGORITHM) call must not be flagged; got: {:#?}",
        findings
            .iter()
            .map(|f| (&f.rule_id, &f.algorithm_id))
            .collect::<Vec<_>>()
    );
}

/// Backlog `#Y113`: OpenSSL 3.6 shipped native LMS signature support through
/// the same generic keygen entry point ML-KEM/ML-DSA/SLH-DSA already use, but
/// `cpp.toml` had zero classify coverage for it — 11 months after GA.
#[test]
fn scans_c_openssl_native_lms() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("cpp/crypto.c"))
        .expect("scan succeeds");

    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRYPTO-1137" && f.algorithm_id == "lms"),
        "expected CRYPTO-1137 (lms) in cpp/crypto.c; got: {:#?}",
        findings
            .iter()
            .map(|f| (&f.rule_id, &f.algorithm_id))
            .collect::<Vec<_>>()
    );
}

/// Backlog `#Y47`: pyca/cryptography's own first-party ML-KEM/ML-DSA classes
/// had no classify arm at all — `python.toml` recognized every classical
/// primitive in the library but not the two it migrated to FIPS 203/204.
/// Scoped to the literal-class-name call form (`MLKEM768PrivateKey.generate()`)
/// only; the instance-method form reached through a variable
/// (`key.encapsulate()`, `sig_key.sign()`) is not resolvable to a class
/// without receiver type-tracking this codebase does not do for Python, and
/// must NOT produce an ml-kem/ml-dsa finding.
#[test]
fn scans_python_pqc_native_mlkem_mldsa() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("python/pqc_native.py"))
        .expect("scan succeeds");

    let want = [
        ("CRYPTO-821", "ml-kem-768"),           // MLKEM768PrivateKey.generate()
        ("CRYPTO-822", "ml-kem-1024"),          // MLKEM1024PrivateKey.from_seed_bytes(...)
        ("CRYPTO-821", "ml-kem-768"),           // MLKEM768PublicKey.from_public_bytes(...)
        ("CRYPTO-824", "ml-dsa-65"),            // MLDSA65PrivateKey.generate()
        ("CRYPTO-823", "ml-dsa-44"),            // MLDSA44PrivateKey.generate()
        ("CRYPTO-824", "ml-dsa-65"),            // MLDSA65PublicKey.from_public_bytes(...)
        ("CRYPTO-1035", "ml-dsa-unattributed"), // MLDSAMuHasher(public_key)
        ("CRYPTO-1035", "ml-dsa-unattributed"), // mldsa.MLDSAMuHasher(public_key, ...)
    ];
    for (rule_id, algorithm_id) in want {
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == rule_id && f.algorithm_id == algorithm_id),
            "expected {rule_id} ({algorithm_id}) in Python PQC fixture; findings: {:#?}",
            findings
                .iter()
                .map(|f| (&f.rule_id, &f.algorithm_id))
                .collect::<Vec<_>>()
        );
    }

    let pqc_count = findings
        .iter()
        .filter(|f| f.algorithm_id.starts_with("ml-kem") || f.algorithm_id.starts_with("ml-dsa"))
        .count();
    assert_eq!(
        pqc_count,
        8,
        "instance-method calls through a variable (key.encapsulate(), sig_key.sign()) must not \
         be classified as ml-kem/ml-dsa — got: {:#?}",
        findings
            .iter()
            .map(|f| (&f.rule_id, &f.algorithm_id))
            .collect::<Vec<_>>()
    );
}

/// Backlog `#Y74`: liboqs's own official Python binding (`liboqs-python`)
/// had zero `python.toml` coverage — `oqs.KeyEncapsulation(alg)` /
/// `oqs.Signature(alg)` construct via the identical `OQS_KEM_new`/
/// `OQS_SIG_new` C entry points `cpp.toml` already classifies. Both official
/// examples (examples/kem.py, examples/sig.py) pass a local variable rather
/// than a literal, so both the literal and the variable-symbol fallback must
/// fire.
#[test]
fn scans_python_liboqs_python_kem_sig() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("python/liboqs_python.py"))
        .expect("scan succeeds");

    let want = [
        ("CRYPTO-992", "ml-kem-512"),
        ("CRYPTO-993", "ml-kem-768"),
        ("CRYPTO-994", "ml-kem-1024"),
        ("CRYPTO-995", "kem-unattributed"), // literal HQC-128
        ("CRYPTO-996", "kem-unattributed"), // variable kemalg
        ("CRYPTO-997", "ml-dsa-44"),
        ("CRYPTO-998", "ml-dsa-65"),
        ("CRYPTO-999", "ml-dsa-87"),
        ("CRYPTO-1000", "sig-unattributed"), // literal SPHINCS+
        ("CRYPTO-1001", "sig-unattributed"), // variable sigalg
    ];
    for (rule_id, algorithm_id) in want {
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == rule_id && f.algorithm_id == algorithm_id),
            "expected {rule_id} ({algorithm_id}) in liboqs-python fixture; findings: {:#?}",
            findings
                .iter()
                .map(|f| (&f.rule_id, &f.algorithm_id))
                .collect::<Vec<_>>()
        );
    }
}

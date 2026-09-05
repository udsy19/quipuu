//! Integration tests for the built-in tables.
//!
//! These mirror `tests/check.py` at the workspace root — if either set of tests
//! changes, the other should change in lockstep.

use quipuu_core::{
    Confidence, Exposure, Finding, Location, Primitive, QuantumRiskScore, QuantumStatus, Severity,
    UsageContext, load_builtins,
};

#[test]
fn builtins_load() {
    let b = load_builtins().expect("built-in tables must load");
    assert!(
        b.algorithms.len() >= 60,
        "algorithm table count = {}",
        b.algorithms.len()
    );
    assert!(b.oids.len() >= 50, "OID table count = {}", b.oids.len());
}

#[test]
fn algorithm_table_cross_check_oids() {
    let b = load_builtins().unwrap();
    b.oids
        .cross_check(&b.algorithms)
        .expect("every OID's algorithm_id must resolve");
}

#[test]
fn policy_cross_check_classically_broken() {
    let b = load_builtins().unwrap();
    b.policy
        .cross_check(&b.algorithms)
        .expect("policy.classically_broken entries must be in the algorithm table");
}

#[test]
fn rsa_2048_is_quantum_vulnerable() {
    let b = load_builtins().unwrap();
    let rsa = b.algorithms.get("rsa-2048").expect("rsa-2048 must exist");
    assert_eq!(rsa.quantum_status, QuantumStatus::BrokenByShor);
    assert_eq!(rsa.nist_quantum_security_level, Some(0));
    assert_eq!(rsa.primitive, Some(Primitive::Pke));
    assert_eq!(rsa.replacement.as_deref(), Some("ml-kem-768"));
}

#[test]
fn ml_kem_768_is_pqc_final_at_level_3() {
    let b = load_builtins().unwrap();
    let ml = b
        .algorithms
        .get("ml-kem-768")
        .expect("ml-kem-768 must exist");
    assert_eq!(ml.quantum_status, QuantumStatus::PqcFinal);
    assert_eq!(ml.nist_quantum_security_level, Some(3));
    assert_eq!(ml.primitive, Some(Primitive::Kem));
    assert_eq!(ml.fips.as_deref(), Some("FIPS 203"));
}

#[test]
fn aes_256_gcm_matches_official_cbom_example() {
    // The official CycloneDX CBOM example uses:
    //   classicalSecurityLevel: 256, nistQuantumSecurityLevel: 1
    // Our algorithm-table should match.
    let b = load_builtins().unwrap();
    let aes = b
        .algorithms
        .get("aes-256-gcm")
        .expect("aes-256-gcm must exist");
    assert_eq!(aes.classical_security_bits, Some(256));
    assert_eq!(aes.primitive, Some(Primitive::Ae));
    // Our table has 5 (anchored on AES-256 category) — the example shows 1
    // because the original IBM example pre-dates the spec's clarification
    // on AES-256 category. We follow NIST's category 5 mapping; document the
    // delta in algorithm-table.toml notes.
    assert_eq!(aes.nist_quantum_security_level, Some(5));
}

/// The same defect as `dh_oids_do_not_assert_a_group_size`, one arc over.
///
/// `sha512WithRSAEncryption` encodes a digest and a padding. It encodes no
/// modulus — and it resolved to `rsa-pkcs1-sha512-4096`, so every certificate
/// a CA had signed with SHA-512 reported `classicalSecurityLevel: 152`
/// whatever its real key size. That is the unsafe direction: it makes a weak
/// key look strong in the CBOM field a compliance reader trusts.
///
/// `ecdsa-with-SHA256` names the digest and not the curve, and `id-dsa` names
/// neither prime size, so those resolve to their family rows too.
#[test]
fn signature_oids_do_not_assert_a_key_size() {
    let b = load_builtins().unwrap();

    // rsaEncryption — SPKI key type. scan-certs refines it from the parsed
    // modulus; the table row cannot.
    assert_eq!(
        b.oids.lookup("1.2.840.113549.1.1.1"),
        Some("rsa-unattributed")
    );
    for (oid, want) in [
        ("1.2.840.113549.1.1.11", "rsa-pkcs1-sha256"),
        ("1.2.840.113549.1.1.12", "rsa-pkcs1-sha384"),
        ("1.2.840.113549.1.1.13", "rsa-pkcs1-sha512"),
        // id-RSASSA-PSS carries hash, MGF and salt in parameters we do not
        // parse, so it determines even less than the PKCS#1 OIDs do.
        ("1.2.840.113549.1.1.10", "rsa-pss-unattributed"),
        ("1.2.840.10045.4.3.2", "ecdsa-unattributed"),
        ("1.2.840.10045.4.3.4", "ecdsa-unattributed"),
        ("1.2.840.10040.4.1", "dsa-unattributed"),
    ] {
        assert_eq!(b.oids.lookup(oid), Some(want), "OID {oid}");
    }

    // The migration verdict stays exact — Shor breaks RSA at every modulus —
    // so only the classical strength is withheld.
    let rec = b
        .algorithms
        .get("rsa-pkcs1-sha512")
        .expect("the unsized row must exist");
    assert!(rec.classical_security_bits.is_none());
    assert_eq!(rec.quantum_status, QuantumStatus::BrokenByShor);
}

/// The two finite-field DH OIDs name the key type and nothing else: the prime
/// size lives in the `DomainParameters` we do not parse. Resolving them to
/// `dh-2048` asserted a group size no emitter can observe, and that assertion
/// reached the CBOM as a component. `dh-unattributed` states the family and
/// declines the size, in the same role `ecdsa-unattributed` already plays.
#[test]
fn dh_oids_do_not_assert_a_group_size() {
    let b = load_builtins().unwrap();
    // dhKeyAgreement (PKCS #3) and dhpublicnumber (X9.42).
    assert_eq!(
        b.oids.lookup("1.2.840.113549.1.3.1"),
        Some("dh-unattributed")
    );
    assert_eq!(b.oids.lookup("1.2.840.10046.2.1"), Some("dh-unattributed"));

    let rec = b
        .algorithms
        .get("dh-unattributed")
        .expect("the sentinel must have a row");
    // Shor breaks finite-field DH at every group size, so the migration
    // verdict stays exact even though the classical strength is unknown.
    assert!(rec.classical_security_bits.is_none());
    assert_eq!(rec.replacement.as_deref(), Some("ml-kem-768"));
}

#[test]
fn ml_kem_oid_resolves_per_rfc_9935() {
    let b = load_builtins().unwrap();
    assert_eq!(b.oids.lookup("2.16.840.1.101.3.4.4.1"), Some("ml-kem-512"));
    assert_eq!(b.oids.lookup("2.16.840.1.101.3.4.4.2"), Some("ml-kem-768"));
    assert_eq!(b.oids.lookup("2.16.840.1.101.3.4.4.3"), Some("ml-kem-1024"));
}

#[test]
fn ml_dsa_oid_resolves_per_rfc_9881() {
    let b = load_builtins().unwrap();
    assert_eq!(b.oids.lookup("2.16.840.1.101.3.4.3.17"), Some("ml-dsa-44"));
    assert_eq!(b.oids.lookup("2.16.840.1.101.3.4.3.18"), Some("ml-dsa-65"));
    assert_eq!(b.oids.lookup("2.16.840.1.101.3.4.3.19"), Some("ml-dsa-87"));
}

#[test]
fn policy_weights_sum_to_100() {
    let b = load_builtins().unwrap();
    assert_eq!(b.policy.risk_weights.sum(), 100);
}

#[test]
fn severity_bands_monotonic() {
    let b = load_builtins().unwrap();
    let sb = &b.policy.severity_bands;
    assert!(sb.critical > sb.high);
    assert!(sb.high > sb.medium);
    assert!(sb.medium > sb.low);
    assert!(sb.low > sb.safe);
}

#[test]
fn risk_score_rsa_public_tls_is_critical() {
    let b = load_builtins().unwrap();
    let rsa = b.algorithms.get("rsa-2048").unwrap();
    let finding = Finding {
        id: "QPU-TEST".into(),
        rule_id: "CRYPTO-002".into(),
        algorithm_id: "rsa-2048".into(),
        location: Location {
            location: "main.go".into(),
            line: Some(42),
            offset: None,
            symbol: Some("rsa.GenerateKey".into()),
            snippet: None,
        },
        message: "RSA-2048 keygen".into(),
        confidence: Confidence::LiteralArg,
        confidence_reason: "test fixture".into(),
        usage_context: UsageContext::KeyEstablishmentLongLived,
        exposure: Exposure::PublicInternet,
        shelf_life_bucket: "long".into(),
        hndl_critical: false,
    };
    let score = QuantumRiskScore::compute(&finding, rsa, &b.policy);
    assert_eq!(score.severity, Severity::Critical);
    // Verify the additive breakdown lands where we expect:
    //   AlgVuln 40 (BrokenByShor) + Usage 25 (KE+long) + Shelf 15 (long)
    // + Exposure 10 + Confidence 10 = 100.
    assert_eq!(score.algorithm_vulnerability, 40);
    assert_eq!(score.usage_context, 25);
    assert_eq!(score.data_shelf_life, 15);
    assert_eq!(score.exposure, 10);
    assert_eq!(score.detection_confidence, 10);
    assert_eq!(score.total, 100);
}

#[test]
fn risk_score_aes_256_local_ephemeral_is_safe() {
    let b = load_builtins().unwrap();
    let aes = b.algorithms.get("aes-256-gcm").unwrap();
    let finding = Finding {
        id: "QPU-TEST".into(),
        rule_id: "CRYPTO-XXX".into(),
        algorithm_id: "aes-256-gcm".into(),
        location: Location {
            location: "test.go".into(),
            line: Some(10),
            offset: None,
            symbol: None,
            snippet: None,
        },
        message: "AES-256-GCM".into(),
        confidence: Confidence::TypeName,
        confidence_reason: "test fixture".into(),
        usage_context: UsageContext::SignatureEphemeral,
        exposure: Exposure::LocalOnly,
        shelf_life_bucket: "ephemeral".into(),
        hndl_critical: false,
    };
    let score = QuantumRiskScore::compute(&finding, aes, &b.policy);
    // `#T3`: AlgVuln 0 (QuantumSafe) gates the whole score to 0/Safe — the
    // other four axes summing to a nonzero total on their own (as they did
    // before the gate existed: Usage 5 + Shelf 0 + Exp 1 + Conf 8 = 14, Low)
    // is exactly the bug this test's own name always said was wrong.
    assert_eq!(score.severity, Severity::Safe);
    assert_eq!(score.total, 0);
}

#[test]
fn hndl_flag_triggers_on_long_lived_rsa() {
    let b = load_builtins().unwrap();
    let rsa = b.algorithms.get("rsa-2048").unwrap();
    let finding = Finding {
        id: "QPU-TEST".into(),
        rule_id: "CRYPTO-002".into(),
        algorithm_id: "rsa-2048".into(),
        location: Location {
            location: "x".into(),
            line: None,
            offset: None,
            symbol: None,
            snippet: None,
        },
        message: "".into(),
        confidence: Confidence::LiteralArg,
        confidence_reason: "test fixture".into(),
        usage_context: UsageContext::KeyEstablishmentLongLived,
        exposure: Exposure::PublicInternet,
        shelf_life_bucket: "long".into(),
        hndl_critical: false,
    };
    assert!(quipuu_core::risk::is_hndl_critical(
        &finding, rsa, &b.policy
    ));
}

#[test]
fn hndl_flag_does_not_trigger_on_ephemeral_signature() {
    let b = load_builtins().unwrap();
    let rsa = b.algorithms.get("rsa-2048").unwrap();
    let finding = Finding {
        id: "QPU-TEST".into(),
        rule_id: "CRYPTO-002".into(),
        algorithm_id: "rsa-2048".into(),
        location: Location {
            location: "x".into(),
            line: None,
            offset: None,
            symbol: None,
            snippet: None,
        },
        message: "".into(),
        confidence: Confidence::LiteralArg,
        confidence_reason: "test fixture".into(),
        usage_context: UsageContext::SignatureEphemeral,
        exposure: Exposure::PublicInternet,
        shelf_life_bucket: "ephemeral".into(),
        hndl_critical: false,
    };
    // Ephemeral signature → not HNDL.
    assert!(!quipuu_core::risk::is_hndl_critical(
        &finding, rsa, &b.policy
    ));
}

// ── Phase 14b: algorithm-table schema invariants ───────────────────────────
//
// Catch broken cross-references at test time rather than at corpus-run time.

#[test]
fn phase14b_every_replacement_resolves() {
    // Every `replacement` field in algorithm-table.toml must point to another
    // entry in the same table. The existing validate() in core enforces this
    // at load time, but a regression test guards future edits if someone
    // ever weakens the load-time check.
    let b = load_builtins().unwrap();
    let mut unresolved = Vec::new();
    for rec in b.algorithms.iter() {
        if let Some(repl) = &rec.replacement
            && b.algorithms.get(repl).is_none()
        {
            unresolved.push(format!(
                "{}: replacement={:?} not in algorithm table",
                rec.id, repl
            ));
        }
    }
    assert!(
        unresolved.is_empty(),
        "{} unresolved replacement references:\n  {}",
        unresolved.len(),
        unresolved.join("\n  ")
    );
}

#[test]
fn phase14b_every_pqcfinal_has_fips_reference_or_is_hybrid() {
    // Every PqcFinal entry must reference its FIPS standard, except hybrid
    // TLS groups (which are protocol-level constructs). This is the same
    // invariant the load-time validate() asserts; documenting it as an
    // independent test makes the contract explicit.
    let b = load_builtins().unwrap();
    let mut bad = Vec::new();
    for rec in b.algorithms.iter() {
        if rec.quantum_status == QuantumStatus::PqcFinal
            && rec.fips.is_none()
            && rec.family != "Hybrid-KEM"
        {
            bad.push(format!("{}: PqcFinal but no fips reference", rec.id));
        }
    }
    assert!(
        bad.is_empty(),
        "{} PqcFinal entries missing FIPS reference:\n  {}",
        bad.len(),
        bad.join("\n  ")
    );
}

#[test]
fn phase14b_no_duplicate_ids_after_load() {
    // The load-time validate() rejects duplicates, but the test makes the
    // contract explicit. If someone splits the table file into multiple
    // chunks in the future, this test will catch any merge that introduces
    // duplicate ids.
    let b = load_builtins().unwrap();
    use std::collections::HashSet;
    let mut seen: HashSet<&str> = HashSet::new();
    let mut dupes = Vec::new();
    for rec in b.algorithms.iter() {
        if !seen.insert(rec.id.as_str()) {
            dupes.push(rec.id.clone());
        }
    }
    assert!(dupes.is_empty(), "duplicate algorithm ids: {:?}", dupes);
}

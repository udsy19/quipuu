//! End-to-end CBOM emission tests.

use std::path::PathBuf;

use cryptoscope_cbom::{
    SchemaVersion, ValidationError,
    emit::{EmitOptions, ScanTarget},
    emit_cbom, emit_cbom_json, validate,
    validate::validate_str,
};
use cryptoscope_core::load_builtins;
use cryptoscope_scan_source::Scanner;
use serde_json::Value;

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../scan-source/tests/fixtures")
}

fn default_opts() -> EmitOptions {
    EmitOptions::new(
        ScanTarget {
            name: "cryptoscope-test-fixture".into(),
            version: Some("0.0.0".into()),
        },
        "2026-06-15T12:00:00Z".into(),
    )
}

#[test]
fn official_cbom_example_validates_against_embedded_schema() {
    // We embedded the same 1.7 schema we tested against in the Python suite.
    // The reference example must round-trip cleanly.
    let example = include_str!("cbom-protocol-example.json");
    validate_str(example, SchemaVersion::V1_7)
        .expect("official Protocol example must validate against embedded 1.7 schema");
}

#[test]
fn emit_validates_for_v1_7_and_v1_6() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms.clone()).unwrap();
    let findings = scanner.scan_path(&fixtures_root()).unwrap();
    assert!(!findings.is_empty());

    // 1.7 (default)
    let bom17 = emit_cbom(&findings, &b.algorithms, &default_opts()).unwrap();
    assert_eq!(bom17.spec_version, "1.7");
    assert!(!bom17.components.is_empty());

    // 1.6 (opt-in)
    let mut opts16 = default_opts();
    opts16.schema_version = SchemaVersion::V1_6;
    let bom16 = emit_cbom(&findings, &b.algorithms, &opts16).unwrap();
    assert_eq!(bom16.spec_version, "1.6");
}

#[test]
fn emit_json_round_trips_through_validator() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms.clone()).unwrap();
    let findings = scanner.scan_path(&fixtures_root()).unwrap();

    let json = emit_cbom_json(&findings, &b.algorithms, &default_opts()).unwrap();
    // Sanity: the JSON we serialised must validate, both via the emitter's
    // built-in check and again via our public validate_str.
    validate_str(&json, SchemaVersion::V1_7).expect("emitted JSON must validate");
    // Sanity check on shape:
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["bomFormat"], "CycloneDX");
    assert_eq!(parsed["specVersion"], "1.7");
    assert!(
        parsed["serialNumber"]
            .as_str()
            .unwrap()
            .starts_with("urn:uuid:")
    );
}

#[test]
fn invalid_bom_fails_validation() {
    let bad = serde_json::json!({
        "bomFormat": "NOT-CYCLONEDX",
        "specVersion": "1.7",
        "version": 1
    });
    let err = validate(&bad, SchemaVersion::V1_7).expect_err("must reject bad bomFormat");
    match err {
        ValidationError::Invalid { count, .. } => assert!(count > 0),
        other => panic!("expected Invalid, got {other:?}"),
    }
}

#[test]
fn one_component_per_algorithm_with_provenance() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms.clone()).unwrap();
    let findings = scanner.scan_path(&fixtures_root()).unwrap();

    let bom = emit_cbom(&findings, &b.algorithms, &default_opts()).unwrap();

    // Build expected unique algorithm-ids from the findings.
    let mut algos: Vec<String> = findings.iter().map(|f| f.algorithm_id.clone()).collect();
    algos.sort();
    algos.dedup();
    assert_eq!(
        bom.components.len(),
        algos.len(),
        "one cryptographic-asset component per unique algorithm_id"
    );

    // Every component must have an evidence.occurrences array with at least
    // one entry — provenance is non-optional.
    for c in &bom.components {
        let ev = c.evidence.as_ref().expect("component must have evidence");
        assert!(
            !ev.occurrences.is_empty(),
            "component {:?} has no occurrences",
            c.bom_ref
        );
        for o in &ev.occurrences {
            assert!(!o.location.is_empty());
        }
    }
}

#[test]
fn rsa_2048_emits_expected_crypto_properties() {
    let b = load_builtins().unwrap();
    let scanner = Scanner::with_builtins(b.algorithms.clone()).unwrap();
    let findings = scanner.scan_path(&fixtures_root()).unwrap();

    let json = emit_cbom_json(&findings, &b.algorithms, &default_opts()).unwrap();
    let v: Value = serde_json::from_str(&json).unwrap();
    let comps = v["components"].as_array().unwrap();
    let rsa_2048 = comps
        .iter()
        .find(|c| c["name"] == "RSA-2048")
        .expect("RSA-2048 component must be present");

    assert_eq!(rsa_2048["type"], "cryptographic-asset");
    let cp = &rsa_2048["cryptoProperties"];
    assert_eq!(cp["assetType"], "algorithm");
    let ap = &cp["algorithmProperties"];
    assert_eq!(ap["primitive"], "pke");
    // We map our internal "RSA" family to the CycloneDX 1.7 canonical
    // algorithmFamiliesEnum value — see canonicalize_family().
    assert_eq!(ap["algorithmFamily"], "RSASSA-PKCS1");
    assert_eq!(ap["parameterSetIdentifier"], "2048");
    assert_eq!(ap["nistQuantumSecurityLevel"], 0);
    assert_eq!(ap["classicalSecurityLevel"], 112);
    assert_eq!(cp["oid"], "1.2.840.113549.1.1.1");
    // Provenance — at least one occurrence from the Go fixture.
    let occ = rsa_2048["evidence"]["occurrences"].as_array().unwrap();
    assert!(!occ.is_empty());
    assert!(
        occ.iter()
            .any(|o| o["location"].as_str().unwrap().ends_with("main.go")
                && o["line"].as_u64().is_some())
    );
}

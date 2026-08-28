//! Contract round-trip tests for the 8 quipuu JSON Schemas (2020-12).
//!
//! For every entry in `schema/fixtures/manifest.toml`:
//!   * "valid"   – fixture must validate without errors
//!   * "invalid" – fixture must fail validation; if error_instance_path /
//!     error_keyword are provided in the manifest the first error must match
//!     them.
//!
//! All validation is fully offline: schemas and meta-schemas are loaded from
//! the vendored files in `schema/` via `LocalRegistry`.

mod support;
use support::registry;

use serde::Deserialize;

// ─── Manifest types ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct Manifest {
    #[serde(rename = "case")]
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
struct Case {
    schema: String,
    file: String,
    expect: String,
    #[serde(default)]
    error_instance_path: Option<String>,
    #[serde(default)]
    error_keyword: Option<String>,
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn load_manifest() -> Manifest {
    let manifest_path = concat!(env!("CARGO_MANIFEST_DIR"), "/schema/fixtures/manifest.toml");
    let raw = std::fs::read_to_string(manifest_path)
        .expect("manifest.toml must exist at schema/fixtures/manifest.toml");
    toml::from_str(&raw).expect("manifest.toml must parse")
}

// ─── Tests ───────────────────────────────────────────────────────────────────

/// Validate all fixtures in the manifest against their declared schema.
#[test]
fn all_fixtures_match_declared_expectation() {
    let manifest = load_manifest();
    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut failures: Vec<String> = Vec::new();

    for case in &manifest.cases {
        let validator = registry::compile_schema(&case.schema);
        let instance = registry::load_fixture(&case.file);

        match case.expect.as_str() {
            "valid" => {
                let errors: Vec<_> = validator.iter_errors(&instance).collect();
                if errors.is_empty() {
                    println!("[PASS valid ] {} :: {}", case.schema, case.file);
                    pass += 1;
                } else {
                    let msg = errors
                        .iter()
                        .map(|e| format!("  {} @ {}", e, e.instance_path()))
                        .collect::<Vec<_>>()
                        .join("\n");
                    let summary =
                        format!("[FAIL valid ] {} :: {}\n{}", case.schema, case.file, msg);
                    println!("{summary}");
                    failures.push(summary);
                    fail += 1;
                }
            }
            "invalid" => {
                let errors: Vec<_> = validator.iter_errors(&instance).collect();
                if errors.is_empty() {
                    let summary = format!(
                        "[FAIL invalid] {} :: {} — expected failure but schema accepted it",
                        case.schema, case.file
                    );
                    println!("{summary}");
                    failures.push(summary);
                    fail += 1;
                } else {
                    // Check that the first error matches the declared
                    // instance path and keyword when specified.
                    let first = &errors[0];
                    let mut ok = true;

                    if let Some(expected_path) = &case.error_instance_path {
                        let actual_path = first.instance_path().to_string();
                        if actual_path != *expected_path {
                            let summary = format!(
                                "[FAIL invalid] {} :: {} — instance_path mismatch: expected '{}' got '{}'",
                                case.schema, case.file, expected_path, actual_path
                            );
                            println!("{summary}");
                            failures.push(summary);
                            ok = false;
                            fail += 1;
                        }
                    }

                    if let Some(expected_kw) = &case.error_keyword {
                        // keyword() returns the keyword that triggered the
                        // error (e.g. "enum", "pattern", "const").
                        let actual_kw = first.kind().keyword();
                        if actual_kw != *expected_kw {
                            let summary = format!(
                                "[FAIL invalid] {} :: {} — keyword mismatch: expected '{}' got '{}'",
                                case.schema, case.file, expected_kw, actual_kw
                            );
                            println!("{summary}");
                            failures.push(summary);
                            ok = false;
                            fail += 1;
                        }
                    }

                    if ok {
                        println!("[PASS invalid] {} :: {}", case.schema, case.file);
                        pass += 1;
                    }
                }
            }
            other => panic!(
                "Unknown expect value '{}' in manifest for {}",
                other, case.file
            ),
        }
    }

    println!("\n=== schema_roundtrip: {pass} passed, {fail} failed ===");
    assert!(
        failures.is_empty(),
        "\n{} fixture(s) failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// P3 guard: ensure that `finding/invalid.provenance-ai.json` fails the
/// `enum` constraint on `/provenance`.  This is an explicit named test so it
/// appears clearly in CI output.
#[test]
fn p3_provenance_deterministic_only() {
    let validator = registry::compile_schema("finding");
    let instance = registry::load_fixture("finding/invalid.provenance-ai.json");
    let errors: Vec<_> = validator.iter_errors(&instance).collect();
    assert!(
        !errors.is_empty(),
        "P3 FAILED: provenance='ai-assisted' was accepted by the schema"
    );
    // At least one error must be on /provenance.
    let has_provenance_error = errors
        .iter()
        .any(|e| e.instance_path().to_string() == "/provenance");
    assert!(
        has_provenance_error,
        "P3 FAILED: no error on /provenance — errors were: {}",
        errors
            .iter()
            .map(|e| format!("{}@{}", e.kind().keyword(), e.instance_path()))
            .collect::<Vec<_>>()
            .join(", ")
    );
}

/// P4 guard: ensure that `kat-result/invalid.mode-library.json` fails the
/// `enum` constraint on `/mode`.
#[test]
fn p4_kat_mode_vectors_only() {
    let validator = registry::compile_schema("kat-result");
    let instance = registry::load_fixture("kat-result/invalid.mode-library.json");
    let errors: Vec<_> = validator.iter_errors(&instance).collect();
    assert!(
        !errors.is_empty(),
        "P4 FAILED: mode='library' was accepted by the schema"
    );
    let has_mode_error = errors
        .iter()
        .any(|e| e.instance_path().to_string() == "/mode");
    assert!(
        has_mode_error,
        "P4 FAILED: no error on /mode — errors were: {}",
        errors
            .iter()
            .map(|e| format!("{}@{}", e.kind().keyword(), e.instance_path()))
            .collect::<Vec<_>>()
            .join(", ")
    );
}

/// Verify that `callerArchetype` is truly optional — a finding without it
/// must still validate.
#[test]
fn caller_archetype_is_optional() {
    let validator = registry::compile_schema("finding");
    let instance = registry::load_fixture("finding/valid.aes256-no-score.json");
    let errors: Vec<_> = validator.iter_errors(&instance).collect();
    assert!(
        errors.is_empty(),
        "callerArchetype-less finding should be valid, got errors: {}",
        errors
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
}

/// Verify the scan-result cursor pagination field (SEP-1686).
#[test]
fn scan_result_cursor_pagination() {
    let validator = registry::compile_schema("scan-result");
    let instance = registry::load_fixture("scan-result/valid.with-cursor.json");
    let errors: Vec<_> = validator.iter_errors(&instance).collect();
    assert!(
        errors.is_empty(),
        "scan-result with cursor should be valid, got: {}",
        errors
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
}

/// Verify that all 11 MCP verbs in the method enum are accepted.
#[test]
fn mcp_all_verbs_valid() {
    let validator = registry::compile_schema("mcp");
    let verbs = [
        "scan_source",
        "scan_certs",
        "scan_deps",
        "scan_network",
        "emit_cbom",
        "emit_sarif",
        "validate_cbom",
        "run_acvp_kats",
        "query_findings",
        "get_scan_results",
        "get_capabilities",
    ];
    for verb in &verbs {
        let instance = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "test",
            "method": verb,
            "params": {}
        });
        let errors: Vec<_> = validator.iter_errors(&instance).collect();
        assert!(
            errors.is_empty(),
            "MCP verb '{}' should be valid, got: {}",
            verb,
            errors
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
}

/// OID pattern test: valid OIDs accepted, bare strings rejected.
#[test]
fn oid_pattern_enforced() {
    let validator = registry::compile_schema("crypto-asset");
    let valid = serde_json::json!({
        "algorithmId": "test", "displayName": "Test", "family": "RSA",
        "quantumStatus": "BrokenByShor", "oid": "1.2.840.113549.1.1.1"
    });
    assert!(validator.is_valid(&valid), "Valid OID should be accepted");

    let invalid = serde_json::json!({
        "algorithmId": "test", "displayName": "Test", "family": "RSA",
        "quantumStatus": "BrokenByShor", "oid": "not-an-oid"
    });
    assert!(!validator.is_valid(&invalid), "Bad OID should be rejected");
}

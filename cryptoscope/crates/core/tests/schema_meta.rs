//! Meta-schema validation: every contract schema must itself be a valid
//! JSON Schema 2020-12 document.
//!
//! Uses the built-in `jsonschema::draft202012::meta::is_valid` helper which
//! validates a schema against the Draft 2020-12 meta-schema without making
//! any network requests (the meta-schema is compiled into the `jsonschema`
//! crate itself).

mod support;

const SCHEMA_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/schema");

const CONTRACT_SCHEMAS: &[&str] = &[
    "finding",
    "crypto-asset",
    "risk-score",
    "policy",
    "kat-result",
    "error",
    "scan-result",
    "mcp",
];

/// Helper to load and parse a contract schema JSON file.
fn load_schema(name: &str) -> serde_json::Value {
    let path = format!("{SCHEMA_DIR}/{name}.schema.json");
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("Cannot read {path}: {e}"));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("Cannot parse {path}: {e}"))
}

/// Every contract schema must be a valid 2020-12 document.
#[test]
fn all_contract_schemas_are_valid_2020_12_documents() {
    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut failures: Vec<String> = Vec::new();

    for &name in CONTRACT_SCHEMAS {
        let schema = load_schema(name);

        if jsonschema::draft202012::meta::is_valid(&schema) {
            println!("[PASS meta] {name}.schema.json");
            pass += 1;
        } else {
            // Collect errors for a useful message.
            let errs: Vec<String> = jsonschema::draft202012::meta::validator()
                .as_ref()
                .iter_errors(&schema)
                .map(|e| format!("  {} @ {}", e, e.instance_path()))
                .collect();
            let summary = format!("[FAIL meta] {name}.schema.json\n{}", errs.join("\n"));
            println!("{summary}");
            failures.push(summary);
            fail += 1;
        }
    }

    println!("\n=== schema_meta: {pass} passed, {fail} failed ===");
    assert!(
        failures.is_empty(),
        "\n{} schema(s) are not valid 2020-12 documents:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Verify the vendored 2020-12 meta-schema itself parses as valid JSON and
/// contains the expected `$schema` / `$id` fields.
#[test]
fn vendored_meta_schema_is_well_formed() {
    let path = format!("{SCHEMA_DIR}/meta/2020-12.json");
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("Cannot read {path}: {e}"));
    let value: serde_json::Value =
        serde_json::from_str(&raw).expect("vendored 2020-12.json must parse as JSON");

    let schema_uri = value
        .get("$schema")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(
        schema_uri.contains("2020-12"),
        "2020-12.json $schema should reference 2020-12, got '{schema_uri}'"
    );

    let id = value
        .get("$id")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(!id.is_empty(), "2020-12.json must have a non-empty $id");
}

/// Each contract schema must declare `$schema: "https://json-schema.org/draft/2020-12/schema"`.
#[test]
fn all_contract_schemas_declare_correct_dollar_schema() {
    for &name in CONTRACT_SCHEMAS {
        let schema = load_schema(name);
        let declared = schema
            .get("$schema")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        assert_eq!(
            declared, "https://json-schema.org/draft/2020-12/schema",
            "{name}.schema.json has wrong $schema: '{declared}'"
        );
    }
}

/// Each contract schema must declare a `$id` of the form
/// `https://cryptoscope.dev/schema/0.1.0/<name>.schema.json`.
#[test]
fn all_contract_schemas_declare_correct_dollar_id() {
    for &name in CONTRACT_SCHEMAS {
        let schema = load_schema(name);
        let declared = schema
            .get("$id")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let expected = format!("https://cryptoscope.dev/schema/0.1.0/{name}.schema.json");
        assert_eq!(
            declared, expected,
            "{name}.schema.json has wrong $id: '{declared}'"
        );
    }
}

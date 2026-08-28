//! Offline LocalRegistry for schema contract tests.
//!
//! Builds a `jsonschema::Validator` for Draft 2020-12 entirely from vendored
//! files. No network I/O occurs during tests.

#![allow(dead_code)]

use std::collections::HashMap;

use jsonschema::{Retrieve, Uri, Validator};
use serde_json::Value;

/// Directory containing the 8 contract schemas + meta/ sub-directory.
const SCHEMA_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/schema");

/// A retriever that serves schemas from the vendored on-disk files only.
pub struct LocalRegistry {
    entries: HashMap<String, Value>,
}

impl LocalRegistry {
    /// Build a registry pre-loaded with every contract schema and the
    /// vendored 2020-12 meta-schema + sub-schemas.
    pub fn new() -> Self {
        let mut entries: HashMap<String, Value> = HashMap::new();

        // Load contract schemas.
        let contract_schemas = [
            "finding",
            "crypto-asset",
            "risk-score",
            "policy",
            "kat-result",
            "error",
            "scan-result",
            "mcp",
        ];
        for name in &contract_schemas {
            let path = format!("{SCHEMA_DIR}/{name}.schema.json");
            let raw = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("Cannot read {path}: {e}"));
            let value: Value =
                serde_json::from_str(&raw).unwrap_or_else(|e| panic!("Cannot parse {path}: {e}"));
            let id = format!("https://quipuu.dev/schema/0.1.0/{name}.schema.json");
            entries.insert(id, value);
        }

        // Load vendored 2020-12 meta-schema.
        let meta_dir = format!("{SCHEMA_DIR}/meta");
        let meta_files = [
            (
                "2020-12.json",
                "https://json-schema.org/draft/2020-12/schema",
            ),
            (
                "core.json",
                "https://json-schema.org/draft/2020-12/meta/core",
            ),
            (
                "applicator.json",
                "https://json-schema.org/draft/2020-12/meta/applicator",
            ),
            (
                "validation.json",
                "https://json-schema.org/draft/2020-12/meta/validation",
            ),
            (
                "meta-data.json",
                "https://json-schema.org/draft/2020-12/meta/meta-data",
            ),
            (
                "format-annotation.json",
                "https://json-schema.org/draft/2020-12/meta/format-annotation",
            ),
            (
                "content.json",
                "https://json-schema.org/draft/2020-12/meta/content",
            ),
            (
                "unevaluated.json",
                "https://json-schema.org/draft/2020-12/meta/unevaluated",
            ),
        ];
        for (filename, uri) in &meta_files {
            let path = format!("{meta_dir}/{filename}");
            let raw = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("Cannot read meta-schema {path}: {e}"));
            let value: Value = serde_json::from_str(&raw)
                .unwrap_or_else(|e| panic!("Cannot parse meta-schema {path}: {e}"));
            entries.insert((*uri).to_string(), value);
        }

        Self { entries }
    }

    /// Return the pre-parsed `Value` for the given URI, if present.
    pub fn get(&self, uri: &str) -> Option<&Value> {
        self.entries.get(uri)
    }
}

impl Retrieve for LocalRegistry {
    fn retrieve(
        &self,
        uri: &Uri<String>,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        let key = uri.as_str();
        self.entries
            .get(key)
            .cloned()
            .ok_or_else(|| format!("LocalRegistry: no entry for '{key}'").into())
    }
}

/// Load a contract schema by name and compile it into a `Validator`.
///
/// All `$ref`s that point to other contract schemas or to the 2020-12
/// meta-schemas are resolved offline via [`LocalRegistry`].
pub fn compile_schema(schema_name: &str) -> Validator {
    let path = format!("{SCHEMA_DIR}/{schema_name}.schema.json");
    let raw =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("Cannot read schema {path}: {e}"));
    let schema: Value =
        serde_json::from_str(&raw).unwrap_or_else(|e| panic!("Cannot parse schema {path}: {e}"));

    let registry = LocalRegistry::new();
    jsonschema::draft202012::options()
        .with_retriever(registry)
        .build(&schema)
        .unwrap_or_else(|e| panic!("Cannot compile schema '{schema_name}': {e}"))
}

/// Load a fixture file relative to the `fixtures/` directory.
pub fn load_fixture(rel_path: &str) -> Value {
    let path = format!("{SCHEMA_DIR}/fixtures/{rel_path}");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Cannot read fixture {path}: {e}"));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("Cannot parse fixture {path}: {e}"))
}

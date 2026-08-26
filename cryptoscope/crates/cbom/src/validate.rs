//! BOM validation against the embedded CycloneDX schemas.
//!
//! Schemas (and their referenced sub-schemas: cryptography-defs, jsf-0.82,
//! spdx) are baked into the binary at compile time. We assemble a
//! `jsonschema::Registry` on first use so external `$ref`s resolve locally —
//! the binary stays offline-only.
//!
//! Both CycloneDX 1.6 and 1.7 declare Draft 7, so a single validator factory
//! works for both.

use std::sync::OnceLock;

use jsonschema::{Draft, Registry};
use serde_json::Value;
use thiserror::Error;

use crate::model::SchemaVersion;

const BOM_16_SCHEMA: &str = include_str!("../data/bom-1.6.schema.json");
const BOM_17_SCHEMA: &str = include_str!("../data/bom-1.7.schema.json");

// Sub-schemas referenced via relative $refs from the BOM schemas.
const CRYPTO_DEFS_SCHEMA: &str = include_str!("../data/cryptography-defs.schema.json");
const JSF_SCHEMA: &str = include_str!("../data/jsf-0.82.schema.json");
const SPDX_SCHEMA: &str = include_str!("../data/spdx.schema.json");

static REGISTRY: OnceLock<Registry<'static>> = OnceLock::new();
static V16_VALIDATOR: OnceLock<jsonschema::Validator> = OnceLock::new();
static V17_VALIDATOR: OnceLock<jsonschema::Validator> = OnceLock::new();

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("BOM does not parse as JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("schema compilation failed: {0}")]
    SchemaCompile(String),
    #[error(
        "BOM does not validate against CycloneDX {version} schema: {count} error(s); first 3: {samples}"
    )]
    Invalid {
        version: &'static str,
        count: usize,
        samples: String,
    },
}

/// Validate an arbitrary JSON value against the CycloneDX schema for the given version.
pub fn validate(bom: &Value, version: SchemaVersion) -> Result<(), ValidationError> {
    let validator = compile_validator(version)?;
    let errors: Vec<_> = validator.iter_errors(bom).collect();
    if errors.is_empty() {
        return Ok(());
    }
    let samples = errors
        .iter()
        .take(3)
        .map(|e| format!("{}: {}", e.instance_path(), e))
        .collect::<Vec<_>>()
        .join(" | ");
    Err(ValidationError::Invalid {
        version: version.as_str(),
        count: errors.len(),
        samples,
    })
}

/// Convenience: validate a JSON string.
pub fn validate_str(bom_json: &str, version: SchemaVersion) -> Result<(), ValidationError> {
    let value: Value = serde_json::from_str(bom_json)?;
    validate(&value, version)
}

fn compile_validator(
    version: SchemaVersion,
) -> Result<&'static jsonschema::Validator, ValidationError> {
    let cell = match version {
        SchemaVersion::V1_6 => &V16_VALIDATOR,
        SchemaVersion::V1_7 => &V17_VALIDATOR,
    };
    if let Some(v) = cell.get() {
        return Ok(v);
    }

    // Lazily build the registry once; reuse across both schema versions.
    if REGISTRY.get().is_none() {
        let r = build_registry()?;
        let _ = REGISTRY.set(r);
    }
    let registry = REGISTRY.get().expect("registry just initialized");

    let raw = match version {
        SchemaVersion::V1_6 => BOM_16_SCHEMA,
        SchemaVersion::V1_7 => BOM_17_SCHEMA,
    };
    let schema: Value = serde_json::from_str(raw)?;
    let validator = jsonschema::draft7::options()
        .with_registry(registry)
        .build(&schema)
        .map_err(|e| ValidationError::SchemaCompile(e.to_string()))?;

    let _ = cell.set(validator);
    Ok(cell.get().expect("validator was just set"))
}

/// Register every sub-schema referenced by the CycloneDX BOM schemas under
/// the URI that the parent schema's relative `$ref` will resolve to.
///
/// Each is registered under TWO URIs:
///   * its absolute `$id` (`http://cyclonedx.org/schema/<file>`)
///   * the bare filename — covers resolvers that don't follow `$id` rewriting
///
/// Both keys point at clones of the same `Value`.
fn build_registry() -> Result<Registry<'static>, ValidationError> {
    let crypto_defs: Value = serde_json::from_str(CRYPTO_DEFS_SCHEMA)?;
    let jsf: Value = serde_json::from_str(JSF_SCHEMA)?;
    let spdx: Value = serde_json::from_str(SPDX_SCHEMA)?;

    Registry::new()
        .draft(Draft::Draft7)
        .extend([
            (
                "http://cyclonedx.org/schema/cryptography-defs.schema.json",
                crypto_defs.clone(),
            ),
            ("cryptography-defs.schema.json", crypto_defs),
            (
                "http://cyclonedx.org/schema/jsf-0.82.schema.json",
                jsf.clone(),
            ),
            ("jsf-0.82.schema.json", jsf),
            ("http://cyclonedx.org/schema/spdx.schema.json", spdx.clone()),
            ("spdx.schema.json", spdx),
        ])
        .map_err(|e| ValidationError::SchemaCompile(format!("registry extend: {e}")))?
        .prepare()
        .map_err(|e| ValidationError::SchemaCompile(format!("registry prepare: {e}")))
}

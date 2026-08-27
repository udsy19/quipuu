//! `validate_cbom` verb — wraps `seawall-cbom::validate`.
//!
//! Params:
//!   cbom: object             — CycloneDX BOM JSON object to validate
//!   schemaVersion?: "1.6" | "1.7"  — default 1.7

use seawall_cbom::{SchemaVersion, validate};
use serde_json::{Value, json};

use crate::mcp::errors::{E_RULESET_INVALID, E_SCHEMA_UNSUPPORTED};

pub fn handle(params: Option<Value>) -> Result<Value, (i32, String)> {
    let params = params.unwrap_or(Value::Null);

    let cbom = params.get("cbom").cloned().ok_or_else(|| {
        (
            E_RULESET_INVALID,
            "params.cbom (object) is required".to_string(),
        )
    })?;

    let schema_version = match params
        .get("schemaVersion")
        .and_then(Value::as_str)
        .unwrap_or("1.7")
    {
        "1.6" => SchemaVersion::V1_6,
        "1.7" => SchemaVersion::V1_7,
        v => {
            return Err((
                E_SCHEMA_UNSUPPORTED,
                format!("unsupported schemaVersion `{v}` (use 1.6 or 1.7)"),
            ));
        }
    };

    match validate(&cbom, schema_version) {
        Ok(()) => Ok(json!({ "valid": true, "schemaVersion": schema_version.as_str() })),
        Err(e) => Ok(json!({
            "valid": false,
            "schemaVersion": schema_version.as_str(),
            "error": e.to_string(),
        })),
    }
}

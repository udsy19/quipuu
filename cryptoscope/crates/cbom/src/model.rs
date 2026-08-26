//! CycloneDX BOM domain model — the slice we emit.
//!
//! We model only the fields cryptoscope produces. Optional fields use
//! `Option<T>` + `skip_serializing_if` so the output stays clean and the
//! schema validator never sees stray `null`s.
//!
//! Source-of-truth: the embedded schemas in `data/bom-1.{6,7}.schema.json`.

use serde::Serialize;

/// CycloneDX spec version we emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SchemaVersion {
    /// CycloneDX 1.6 — ECMA-424 1st Edition (June 2024).
    V1_6,
    /// CycloneDX 1.7 — ECMA-424 2nd Edition (December 2025).
    #[default]
    V1_7,
}

impl SchemaVersion {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::V1_6 => "1.6",
            Self::V1_7 => "1.7",
        }
    }
}

/// Root BOM document.
#[derive(Debug, Serialize)]
pub struct Bom {
    #[serde(rename = "bomFormat")]
    pub bom_format: &'static str,
    #[serde(rename = "specVersion")]
    pub spec_version: String,
    #[serde(rename = "serialNumber", skip_serializing_if = "Option::is_none")]
    pub serial_number: Option<String>,
    pub version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Metadata>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub components: Vec<Component>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<Dependency>,
}

#[derive(Debug, Serialize)]
pub struct Metadata {
    pub timestamp: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<Tool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub component: Option<Component>,
}

/// CycloneDX 1.6+ uses an array-form `tools` containing `{name, version, ...}`.
#[derive(Debug, Serialize)]
pub struct Tool {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    pub name: String,
    pub version: String,
}

/// One `component` entry. We emit either `application` (the metadata.component
/// describing the scanned target) or `cryptographic-asset` (a finding).
#[derive(Debug, Serialize)]
pub struct Component {
    #[serde(rename = "type")]
    pub component_type: ComponentType,
    #[serde(rename = "bom-ref", skip_serializing_if = "Option::is_none")]
    pub bom_ref: Option<String>,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(rename = "cryptoProperties", skip_serializing_if = "Option::is_none")]
    pub crypto_properties: Option<CryptoProperties>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Evidence>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ComponentType {
    Application,
    CryptographicAsset,
}

#[derive(Debug, Serialize)]
pub struct CryptoProperties {
    #[serde(rename = "assetType")]
    pub asset_type: AssetType,
    #[serde(
        rename = "algorithmProperties",
        skip_serializing_if = "Option::is_none"
    )]
    pub algorithm_properties: Option<AlgorithmProperties>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oid: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AssetType {
    Algorithm,
    Certificate,
    Protocol,
    RelatedCryptoMaterial,
}

/// Subset of `algorithmProperties` we emit. Lower-case kebab-case enums match
/// the schema's `meta:enum` values verbatim.
#[derive(Debug, Serialize, Default)]
pub struct AlgorithmProperties {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primitive: Option<&'static str>,
    #[serde(rename = "algorithmFamily", skip_serializing_if = "Option::is_none")]
    pub algorithm_family: Option<String>,
    #[serde(
        rename = "parameterSetIdentifier",
        skip_serializing_if = "Option::is_none"
    )]
    pub parameter_set_identifier: Option<String>,
    #[serde(rename = "cryptoFunctions", skip_serializing_if = "Vec::is_empty")]
    pub crypto_functions: Vec<&'static str>,
    #[serde(
        rename = "classicalSecurityLevel",
        skip_serializing_if = "Option::is_none"
    )]
    pub classical_security_level: Option<u32>,
    #[serde(
        rename = "nistQuantumSecurityLevel",
        skip_serializing_if = "Option::is_none"
    )]
    pub nist_quantum_security_level: Option<u8>,
}

#[derive(Debug, Serialize)]
pub struct Evidence {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub occurrences: Vec<Occurrence>,
}

#[derive(Debug, Serialize)]
pub struct Occurrence {
    pub location: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    #[serde(rename = "additionalContext", skip_serializing_if = "Option::is_none")]
    pub additional_context: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Dependency {
    #[serde(rename = "ref")]
    pub reference: String,
    #[serde(rename = "dependsOn", skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub provides: Vec<String>,
}

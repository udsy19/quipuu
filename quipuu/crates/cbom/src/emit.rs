//! Finding[] → CycloneDX CBOM emitter (D-01, D-02).
//!
//! Algorithm:
//!   1. For every distinct `algorithm_id` referenced by the findings,
//!      emit one `cryptographic-asset` component whose `cryptoProperties`
//!      come from the [`AlgorithmTable`].
//!   2. Each component carries an `evidence.occurrences[]` array — one
//!      entry per finding that referenced this algorithm. This is the
//!      file+line provenance (D-02).
//!   3. The `metadata.component` describes what was scanned.

use std::collections::BTreeMap;

use quipuu_core::{AlgorithmRecord, AlgorithmTable, Finding, Primitive, QuantumStatus};
use thiserror::Error;
use uuid::Uuid;

use crate::model::{
    AlgorithmProperties, AssetType, Bom, Component, ComponentType, CryptoProperties, Evidence,
    Metadata, Occurrence, SchemaVersion, Tool,
};
use crate::validate::{ValidationError, validate};

#[derive(Debug, Error)]
pub enum EmitError {
    #[error("finding references unknown algorithm `{0}`")]
    UnknownAlgorithm(String),
    #[error("JSON serialisation failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("BOM failed schema validation: {0}")]
    Validation(#[from] ValidationError),
}

/// Knobs the caller can tune. Defaults match SPEC.md §7.
pub struct EmitOptions {
    pub schema_version: SchemaVersion,
    /// The application/scan target description that lands in `metadata.component`.
    pub scan_target: ScanTarget,
    /// An RFC-3339 timestamp; supplied by the caller so we stay deterministic in tests.
    pub timestamp: String,
    /// If true (default), validate against the embedded schema before returning.
    pub validate: bool,
}

#[derive(Clone)]
pub struct ScanTarget {
    pub name: String,
    pub version: Option<String>,
}

impl EmitOptions {
    /// Defaults: CycloneDX 1.7, validation on, a unit-test-friendly timestamp.
    /// Callers normally override `timestamp` with the current time.
    pub fn new(scan_target: ScanTarget, timestamp: String) -> Self {
        Self {
            schema_version: SchemaVersion::default(),
            scan_target,
            timestamp,
            validate: true,
        }
    }
}

/// Build a [`Bom`] from findings + the algorithm table.
pub fn emit_cbom(
    findings: &[Finding],
    algorithms: &AlgorithmTable,
    opts: &EmitOptions,
) -> Result<Bom, EmitError> {
    // Group findings by algorithm_id so we emit one component per algorithm
    // with all its occurrences inside.
    let mut by_algo: BTreeMap<&str, Vec<&Finding>> = BTreeMap::new();
    for f in findings {
        by_algo.entry(&f.algorithm_id).or_default().push(f);
    }

    let mut components = Vec::with_capacity(by_algo.len());
    let mut undetermined: Vec<&str> = Vec::new();
    for (algo_id, group) in by_algo {
        // A finding whose algorithm could not be determined is NOT a
        // cryptographic-asset component, so it is omitted from the CBOM rather
        // than treated as a fatal error.
        //
        // This used to return Err, which meant a single ordinary dependency
        // line — `openssl = "0.10"` in a Cargo.toml, which scan-deps records as
        // algorithm_id "unknown" — aborted the whole run and suppressed the
        // SARIF, HTML, and summary outputs too. One benign manifest entry could
        // silently produce an empty report.
        let Some(record) = algorithms.get(algo_id) else {
            undetermined.push(algo_id);
            continue;
        };
        components.push(component_for_algorithm(record, &group, opts.schema_version));
    }
    if !undetermined.is_empty() {
        undetermined.sort_unstable();
        eprintln!(
            "quipuu: {} finding(s) had no resolvable algorithm and were omitted \
             from the CBOM ({}). They still appear in the SARIF and summary outputs.",
            undetermined.len(),
            undetermined.join(", ")
        );
    }

    let bom = Bom {
        bom_format: "CycloneDX",
        spec_version: opts.schema_version.as_str().to_owned(),
        serial_number: Some(format!("urn:uuid:{}", Uuid::new_v4())),
        version: 1,
        metadata: Some(Metadata {
            timestamp: opts.timestamp.clone(),
            tools: vec![Tool {
                vendor: Some("quipuu".into()),
                name: "quipuu".into(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
            }],
            component: Some(Component {
                component_type: ComponentType::Application,
                bom_ref: Some("quipuu/scan-target".into()),
                name: opts.scan_target.name.clone(),
                version: opts.scan_target.version.clone(),
                crypto_properties: None,
                evidence: None,
            }),
        }),
        components,
        dependencies: Vec::new(),
    };

    if opts.validate {
        let json = serde_json::to_value(&bom)?;
        validate(&json, opts.schema_version)?;
    }

    Ok(bom)
}

/// Convenience wrapper that returns pretty-printed JSON.
pub fn emit_cbom_json(
    findings: &[Finding],
    algorithms: &AlgorithmTable,
    opts: &EmitOptions,
) -> Result<String, EmitError> {
    let bom = emit_cbom(findings, algorithms, opts)?;
    Ok(serde_json::to_string_pretty(&bom)?)
}

fn component_for_algorithm(
    record: &AlgorithmRecord,
    group: &[&Finding],
    schema_version: SchemaVersion,
) -> Component {
    // bom-ref convention from the official CBOM example:
    //   crypto/{algorithm|certificate|protocol|key}/{name}@{oid-or-hash}
    let bom_ref = match (record.oid.as_deref(), record.id.as_str()) {
        (Some(oid), _) => format!("crypto/algorithm/{}@{}", record.id, oid),
        (None, id) => format!("crypto/algorithm/{id}"),
    };

    let occurrences = group
        .iter()
        .map(|f| Occurrence {
            location: f.location.location.clone(),
            line: f.location.line,
            offset: f.location.offset,
            symbol: f.location.symbol.clone(),
            additional_context: f.location.snippet.clone(),
        })
        .collect();

    Component {
        component_type: ComponentType::CryptographicAsset,
        bom_ref: Some(bom_ref),
        name: record.display_name.clone(),
        version: None,
        crypto_properties: Some(CryptoProperties {
            asset_type: AssetType::Algorithm,
            algorithm_properties: Some(AlgorithmProperties {
                primitive: record.primitive.map(primitive_to_str),
                // 1.7-only field; suppress for 1.6 emission per D-01.
                algorithm_family: match schema_version {
                    SchemaVersion::V1_7 => canonicalize_family(&record.family),
                    SchemaVersion::V1_6 => None,
                },
                parameter_set_identifier: parameter_set(record),
                crypto_functions: crypto_functions(record),
                classical_security_level: record.classical_security_bits,
                nist_quantum_security_level: record.nist_quantum_security_level,
            }),
            oid: record.oid.clone(),
        }),
        evidence: Some(Evidence { occurrences }),
    }
}

/// Map our algorithm-table `family` to CycloneDX 1.7 `algorithmFamiliesEnum`.
///
/// Returns `None` when the family has no canonical equivalent (hybrid TLS
/// groups, draft families) — we omit `algorithmFamily` rather than emit
/// something that the schema would reject.
fn canonicalize_family(family: &str) -> Option<String> {
    let mapped = match family {
        // Asymmetric variants — our table groups them under the SPKI family,
        // CycloneDX uses the more specific signature family. We bias toward
        // the PKCS#1 signature variant as the canonical "RSA" family because
        // that's how the official CBOM example labels RSA-2048 (see
        // bom-examples Protocol/bom.json).
        "RSA" => "RSASSA-PKCS1",
        // X25519 / X448 are EdDSA-family curves but the spec catalogues them
        // under ECDH (key-agree). Map there.
        "X25519" | "X448" => "ECDH",
        // Finite-Field Diffie-Hellman — our short name vs spec's FFDH.
        "DH" => "FFDH",
        // Draft / hybrid families have no canonical entry yet.
        "FN-DSA" | "Hybrid-KEM" | "Hybrid-KEM-Draft" => return None,
        // Topology / sentinel families (TLS config markers, JWT alg=none,
        // WebCrypto/JCA call sites whose algorithm the source never states)
        // are not algorithm families in the CycloneDX 1.7 enum — omit
        // `algorithmFamily` rather than emit something the schema rejects.
        // "Provider" (a JCA/JCE provider registration) and "RNG" (a CSPRNG
        // call site) are the same case: real call sites that name no
        // algorithm. "Signature" is the same case one step further in: the
        // primitive is known and the family is not, which is exactly what
        // the enum has no member for.
        // "PQC-candidate" (kem-unattributed/sig-unattributed — a liboqs
        // OQS_{KEM,SIG}_alg_* macro naming a family this table has no row
        // for, e.g. HQC, MAYO) is the same case: a real call site whose
        // specific algorithm family the enum cannot name.
        "TLS" | "JWT" | "WebCrypto" | "JCA" | "Provider" | "RNG" | "Signature"
        | "PQC-candidate" => return None,
        // Identity mapping for everything else (RSASSA-PSS, ECDSA, EdDSA,
        // ECDH, DSA, AES, DES, 3DES, RC4, ChaCha20, MD5, SHA-1/2/3,
        // ML-KEM, ML-DSA, SLH-DSA).
        other => other,
    };
    Some(mapped.to_owned())
}

/// Map our enum to the CycloneDX 1.7 `primitive` string verbatim.
fn primitive_to_str(p: Primitive) -> &'static str {
    match p {
        Primitive::Drbg => "drbg",
        Primitive::Mac => "mac",
        Primitive::BlockCipher => "block-cipher",
        Primitive::StreamCipher => "stream-cipher",
        Primitive::Signature => "signature",
        Primitive::Hash => "hash",
        Primitive::Pke => "pke",
        Primitive::Xof => "xof",
        Primitive::Kdf => "kdf",
        Primitive::KeyAgree => "key-agree",
        Primitive::Kem => "kem",
        Primitive::Ae => "ae",
        Primitive::Combiner => "combiner",
        Primitive::KeyWrap => "key-wrap",
        Primitive::Other => "other",
        Primitive::Unknown => "unknown",
    }
}

/// Derive `parameterSetIdentifier` for algorithms where it's well-defined.
/// For RSA we use the modulus length; for SHA-2 the digest size, etc.
fn parameter_set(record: &AlgorithmRecord) -> Option<String> {
    if record.family == "RSA" || record.family.starts_with("RSASSA-") {
        record
            .classical_security_bits
            .map(rsa_modulus_from_security)
    } else if record.family == "SHA-2" {
        // SHA-256 → "256", SHA-384 → "384", SHA-512 → "512". The id encodes it
        // in our table as "sha-N".
        record.id.strip_prefix("sha-").map(|s| s.to_owned())
    } else {
        None
    }
}

/// Map classical security bits back to RSA modulus length.
/// (NIST SP 800-57 Pt.1 Rev.5 §5.6.1.1 table: 2048 ≈ 112, 3072 ≈ 128, 4096 ≈ 152, 7680 ≈ 192.)
fn rsa_modulus_from_security(bits: u32) -> String {
    match bits {
        112 => "2048".into(),
        128 => "3072".into(),
        152 => "4096".into(),
        192 => "7680".into(),
        256 => "15360".into(),
        _ => bits.to_string(),
    }
}

/// Derive `cryptoFunctions` from primitive + quantum status.
fn crypto_functions(record: &AlgorithmRecord) -> Vec<&'static str> {
    match record.primitive {
        Some(Primitive::Signature) => vec!["sign", "verify"],
        Some(Primitive::Kem) => vec!["encapsulate", "decapsulate", "keygen"],
        Some(Primitive::Ae) => vec!["encrypt", "decrypt"],
        Some(Primitive::Pke) => vec!["encrypt", "decrypt", "keygen"],
        Some(Primitive::KeyAgree) => vec!["keygen"],
        Some(Primitive::Hash) => vec!["digest"],
        Some(Primitive::Mac) => vec!["tag"],
        Some(Primitive::Kdf) => vec!["keyderive"],
        Some(Primitive::BlockCipher | Primitive::StreamCipher) => vec!["encrypt", "decrypt"],
        Some(Primitive::Drbg) => vec!["generate"],
        Some(Primitive::Xof) => vec!["digest"],
        Some(Primitive::Combiner) => match record.quantum_status {
            QuantumStatus::PqcFinal => vec!["encapsulate", "decapsulate"],
            _ => vec!["other"],
        },
        Some(Primitive::KeyWrap) => vec!["encrypt", "decrypt"],
        Some(Primitive::Other) | Some(Primitive::Unknown) | None => Vec::new(),
    }
}

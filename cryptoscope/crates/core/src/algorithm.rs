//! Algorithm table — the canonical catalogue cryptoscope classifies against.
//!
//! Maps to `knowledge/11-decisions/data/algorithm-table.toml`. See that file
//! and `knowledge/02-nist-pqc-timeline/README.md` for source citations.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::LoadError;

const BUILTIN_TOML: &str = include_str!("../data/algorithm-table.toml");

/// CycloneDX 1.7 `algorithmProperties.primitive` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Primitive {
    Drbg,
    Mac,
    BlockCipher,
    StreamCipher,
    Signature,
    Hash,
    Pke,
    Xof,
    Kdf,
    KeyAgree,
    Kem,
    Ae,
    Combiner,
    KeyWrap,
    Other,
    Unknown,
}

/// Quantum security status for an algorithm.
///
/// Drives the `AlgorithmVulnerability` axis of `QuantumRiskScore`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, serde::Serialize,
)]
pub enum QuantumStatus {
    /// Broken classically (MD5, SHA-1, DES, RC4, 3DES, …).
    BrokenClassically,
    /// Vulnerable to Shor — every classical asymmetric (RSA, ECDSA, DH, ...).
    BrokenByShor,
    /// Symmetric/hash needing larger parameters under Grover (AES-128, SHA-224).
    WeakenedByGrover,
    /// Symmetric/hash that survives Grover at the parameters chosen.
    QuantumSafe,
    /// FIPS-final PQC: ML-KEM, ML-DSA, SLH-DSA.
    PqcFinal,
    /// Draft PQC: FN-DSA (FIPS 206 not yet IPD as of mid-2026).
    PqcDraft,
}

/// One row of the algorithm table.
///
/// Field semantics documented in `knowledge/11-decisions/data/algorithm-table.toml`.
#[derive(Debug, Clone, Deserialize)]
pub struct AlgorithmRecord {
    pub id: String,
    pub display_name: String,
    pub family: String,
    pub primitive: Option<Primitive>,
    pub classical_security_bits: Option<u32>,
    pub nist_quantum_security_level: Option<u8>,
    pub quantum_status: QuantumStatus,
    pub replacement: Option<String>,
    pub fips: Option<String>,
    pub oid: Option<String>,
    #[serde(default)]
    pub notes: String,
}

#[derive(Debug, Clone, Deserialize)]
struct AlgorithmTableFile {
    algorithm: Vec<AlgorithmRecord>,
}

/// In-memory algorithm catalogue. O(log n) lookup by id.
#[derive(Clone)]
pub struct AlgorithmTable {
    by_id: BTreeMap<String, AlgorithmRecord>,
}

impl AlgorithmTable {
    /// Construct from the compile-time-embedded TOML.
    pub fn from_builtin() -> Result<Self, LoadError> {
        Self::from_toml(BUILTIN_TOML)
    }

    /// Construct from an arbitrary TOML string (used by tests, `--rules`, etc.).
    pub fn from_toml(s: &str) -> Result<Self, LoadError> {
        let parsed: AlgorithmTableFile = toml::from_str(s)?;
        let mut by_id = BTreeMap::new();
        for record in parsed.algorithm {
            if let Some(prev) = by_id.insert(record.id.clone(), record) {
                return Err(LoadError::Invariant(format!(
                    "duplicate algorithm id `{}` in algorithm table",
                    prev.id
                )));
            }
        }
        let table = Self { by_id };
        table.validate()?;
        Ok(table)
    }

    /// Look up by canonical id.
    pub fn get(&self, id: &str) -> Option<&AlgorithmRecord> {
        self.by_id.get(id)
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// True when empty (clippy-pleaser).
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    /// Iterate all records.
    pub fn iter(&self) -> impl Iterator<Item = &AlgorithmRecord> {
        self.by_id.values()
    }

    /// Validation invariants. Mirrored in `tests/check.py` — if these change
    /// here, the Python suite needs to change too.
    fn validate(&self) -> Result<(), LoadError> {
        for rec in self.by_id.values() {
            if let Some(level) = rec.nist_quantum_security_level
                && level > 6
            {
                return Err(LoadError::Invariant(format!(
                    "{}: nist_quantum_security_level={} > 6",
                    rec.id, level
                )));
            }
            if rec.quantum_status == QuantumStatus::BrokenByShor {
                if rec.replacement.is_none() {
                    return Err(LoadError::Invariant(format!(
                        "{}: BrokenByShor without a replacement",
                        rec.id
                    )));
                }
                if rec.nist_quantum_security_level.unwrap_or(255) != 0 {
                    return Err(LoadError::Invariant(format!(
                        "{}: BrokenByShor must have nist_quantum_security_level == 0",
                        rec.id
                    )));
                }
            }
            // PqcFinal entries must cite a FIPS standard, EXCEPT hybrid TLS
            // groups which are protocol-level constructs, not algorithms.
            if rec.quantum_status == QuantumStatus::PqcFinal
                && rec.fips.is_none()
                && rec.family != "Hybrid-KEM"
            {
                return Err(LoadError::Invariant(format!(
                    "{}: PqcFinal (non-hybrid) without fips reference",
                    rec.id
                )));
            }
            // Replacement targets must exist.
            if let Some(repl) = &rec.replacement
                && !self.by_id.contains_key(repl)
            {
                return Err(LoadError::Invariant(format!(
                    "{}: replacement `{}` not in algorithm table",
                    rec.id, repl
                )));
            }
        }
        Ok(())
    }
}

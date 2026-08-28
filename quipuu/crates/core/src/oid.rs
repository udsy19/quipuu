//! OID table — maps X.509 / PKCS / NIST CSOR OIDs to canonical algorithm-ids.
//!
//! Source: `crates/core/data/oid-table.toml`.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::{AlgorithmTable, LoadError};

const BUILTIN_TOML: &str = include_str!("../data/oid-table.toml");

/// What an OID pins down on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Determines {
    /// The OID fixes every parameter its algorithm-id names — a curve OID, a
    /// hash OID, `id-alg-ml-kem-768`.
    Algorithm,
    /// The OID names a key type, or a padding and a digest, and the remaining
    /// parameters live somewhere this table cannot see. Such a row must
    /// resolve to an algorithm-id that names no parameter.
    Family,
}

/// One row of the OID table.
#[derive(Debug, Clone, Deserialize)]
pub struct OidMapping {
    pub oid: String,
    pub algorithm_id: String,
    pub determines: Determines,
    #[serde(default)]
    pub note: String,
}

#[derive(Debug, Clone, Deserialize)]
struct OidTableFile {
    oid: Vec<OidMapping>,
}

/// In-memory OID → algorithm-id map.
pub struct OidTable {
    by_oid: BTreeMap<String, OidMapping>,
}

impl OidTable {
    pub fn from_builtin() -> Result<Self, LoadError> {
        Self::from_toml(BUILTIN_TOML)
    }

    pub fn from_toml(s: &str) -> Result<Self, LoadError> {
        let parsed: OidTableFile = toml::from_str(s)?;
        let mut by_oid = BTreeMap::new();
        for entry in parsed.oid {
            if let Some(prev) = by_oid.insert(entry.oid.clone(), entry.clone()) {
                return Err(LoadError::Invariant(format!(
                    "duplicate OID `{}` (was `{}`, now `{}`)",
                    prev.oid, prev.algorithm_id, entry.algorithm_id
                )));
            }
        }
        Ok(Self { by_oid })
    }

    /// Resolve an OID to its algorithm-id, if known.
    pub fn lookup(&self, oid: &str) -> Option<&str> {
        self.by_oid.get(oid).map(|m| m.algorithm_id.as_str())
    }

    /// Number of mappings.
    pub fn len(&self) -> usize {
        self.by_oid.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_oid.is_empty()
    }

    /// Cross-check: every `algorithm_id` in this table exists in the algorithm table.
    pub fn cross_check(&self, algorithms: &AlgorithmTable) -> Result<(), LoadError> {
        for m in self.by_oid.values() {
            if algorithms.get(&m.algorithm_id).is_none() {
                return Err(LoadError::Invariant(format!(
                    "OID `{}` references unknown algorithm `{}`",
                    m.oid, m.algorithm_id
                )));
            }
        }
        Ok(())
    }
}

//! seawall-core — domain types and built-in data tables.
//!
//! The static data files (`algorithm-table.toml`, `oid-table.toml`,
//! `default-policy.toml`, rules/) are embedded at compile time via
//! `include_str!`. They originate at `crates/core/data/` and are
//! copied into `crates/core/data/` for the build.
//!
//! Top-level types:
//!   * [`AlgorithmRecord`] — one row of `algorithm-table.toml`
//!   * [`OidMapping`] — one row of `oid-table.toml`
//!   * [`Policy`] — `default-policy.toml`
//!   * [`Finding`] — what a scanner emits (used by every `scan-*` crate)
//!
//! Tables are accessed through the [`AlgorithmTable`], [`OidTable`], and
//! [`Policy`] structs which are constructed once via [`load_builtins`].

pub mod algorithm;
pub mod finding;
pub mod oid;
pub mod policy;
pub mod risk;
pub mod warnings;

pub use algorithm::{AlgorithmRecord, AlgorithmTable, Primitive, QuantumStatus};
pub use finding::{Confidence, Exposure, Finding, Location, Severity, SiteContext, UsageContext};
pub use oid::{Determines, OidMapping, OidTable};
pub use policy::Policy;
pub use risk::{QuantumRiskScore, score_of, severity_of};
pub use warnings::{ScanWarning, ScanWarningKind};

use thiserror::Error;

/// Errors that can occur loading the built-in or user-supplied data files.
#[derive(Debug, Error)]
pub enum LoadError {
    #[error("TOML parse error: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("policy invariant violated: {0}")]
    Invariant(String),
}

/// The bundle of built-in data shipped with the binary.
///
/// Loaded once at startup. Subsequent lookups against the tables are O(log n)
/// (BTreeMap) on the algorithm-id / OID respectively.
pub struct Builtins {
    pub algorithms: AlgorithmTable,
    pub oids: OidTable,
    pub policy: Policy,
}

/// Load all built-in tables and the default policy.
///
/// Reads from compile-time-embedded TOML strings. Verified by `cargo test` —
/// see `tests/builtins_test.rs`.
pub fn load_builtins() -> Result<Builtins, LoadError> {
    let algorithms = AlgorithmTable::from_builtin()?;
    let oids = OidTable::from_builtin()?;
    let policy = Policy::from_builtin()?;
    Ok(Builtins {
        algorithms,
        oids,
        policy,
    })
}

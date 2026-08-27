//! Policy file — NIST IR 8547 IPD defaults plus QuantumRiskScore weights.
//!
//! Source: `crates/core/data/default-policy.toml` (the `nist-default` preset)
//! and `crates/core/data/policies/` (every other built-in preset).
//!
//! A policy reweights findings. It never creates or suppresses a detection —
//! the scanners run identically under every preset.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;

use crate::{AlgorithmTable, LoadError, QuantumStatus};

const BUILTIN_TOML: &str = include_str!("../data/default-policy.toml");
const CNSA2_TOML: &str = include_str!("../data/policies/nsa-cnsa2.toml");

/// Every built-in preset, as `(name, toml)`, in the order they are listed by
/// `seawall policy list`.
///
/// This is the single source of truth for the preset vocabulary. README, SPEC,
/// MCP.md, `seawall init` and `get_capabilities` all quote it, and
/// `documented_preset_names_match_the_shipped_ones` fails the build on drift.
const PRESETS: &[(&str, &str)] = &[("nist-default", BUILTIN_TOML), ("nsa-cnsa2", CNSA2_TOML)];

#[derive(Debug, Clone, Deserialize)]
pub struct Meta {
    pub name: String,
    pub display_name: String,
    pub source_url: String,
    #[serde(default)]
    pub notes: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Deprecation {
    pub asymmetric_112bit_deprecated_after: u16,
    pub asymmetric_112bit_disallowed_after: u16,
    pub asymmetric_128bit_plus_disallowed_after: u16,
    pub aes_128_acceptable: bool,
    pub aes_192_acceptable: bool,
    pub aes_256_acceptable: bool,
    pub sha_256_acceptable: bool,
    pub sha_384_acceptable: bool,
    pub sha_512_acceptable: bool,
    pub classically_broken: Vec<String>,
    /// Algorithm ids this *jurisdiction* excludes from its approved list, even
    /// though they are not broken for anyone else. CNSA 2.0 excluding AES-128
    /// and SHA-256 from national security systems is the motivating case.
    ///
    /// Scored at the full `risk_weights.algorithm_vulnerability` and never
    /// suppressed as quantum-safe inventory. Empty in `nist-default`, which
    /// takes no position beyond NIST IR 8547.
    #[serde(default)]
    pub policy_disallowed: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RiskWeights {
    pub algorithm_vulnerability: u8,
    pub usage_context: u8,
    pub data_shelf_life: u8,
    pub exposure: u8,
    pub detection_confidence: u8,
}

impl RiskWeights {
    pub fn sum(&self) -> u32 {
        self.algorithm_vulnerability as u32
            + self.usage_context as u32
            + self.data_shelf_life as u32
            + self.exposure as u32
            + self.detection_confidence as u32
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct UsageContextWeights {
    pub key_establishment_long_lived: u8,
    pub key_establishment_ephemeral: u8,
    pub data_at_rest_encryption: u8,
    pub signature_long_lived: u8,
    pub signature_ephemeral: u8,
    pub authentication_only: u8,
    pub hashing: u8,
    pub unknown: u8,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DataShelfLifeBuckets {
    pub ephemeral: u8,
    pub short: u8,
    pub medium: u8,
    pub long: u8,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ShelfLifeDefault {
    pub bucket: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ExposureWeights {
    pub public_internet: u8,
    pub internal_service: u8,
    pub local_only: u8,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConfidenceWeights {
    pub literal_arg: u8,
    pub type_name: u8,
    pub variable: u8,
    pub string_table: u8,
    pub unknown: u8,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SeverityBands {
    pub critical: u8,
    pub high: u8,
    pub medium: u8,
    pub low: u8,
    pub safe: u8,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HndlFlag {
    pub require_quantum_status_in: Vec<QuantumStatus>,
    pub require_usage_context_in: Vec<String>,
    pub require_min_shelf_life_bucket: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Ci {
    pub fail_on: String,
}

/// Full policy bundle. Mirrors the `default-policy.toml` schema 1:1.
#[derive(Debug, Clone, Deserialize)]
pub struct Policy {
    pub meta: Meta,
    pub deprecation: Deprecation,
    pub risk_weights: RiskWeights,
    pub algorithm_vulnerability: BTreeMap<QuantumStatus, u8>,
    pub usage_context: UsageContextWeights,
    pub data_shelf_life: DataShelfLifeBuckets,
    pub shelf_life_tags: BTreeMap<String, String>,
    pub shelf_life_default: ShelfLifeDefault,
    pub exposure: ExposureWeights,
    pub detection_confidence: ConfidenceWeights,
    pub severity_bands: SeverityBands,
    pub hndl_flag: HndlFlag,
    pub ci: Ci,
}

impl Policy {
    pub fn from_builtin() -> Result<Self, LoadError> {
        Self::from_toml(BUILTIN_TOML)
    }

    /// The built-in preset names, in listing order.
    pub fn preset_names() -> impl Iterator<Item = &'static str> {
        PRESETS.iter().map(|(name, _)| *name)
    }

    /// Load a built-in preset by name. `None` when the name is not built in.
    pub fn from_preset(name: &str) -> Option<Result<Self, LoadError>> {
        PRESETS
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, toml)| Self::from_toml(toml))
    }

    /// Resolve the `--policy <name-or-path>` argument.
    ///
    /// A built-in preset name wins over a same-named file on disk, so
    /// `--policy nist-default` means the same thing in every directory.
    pub fn load(name_or_path: &str) -> Result<Self, LoadError> {
        if let Some(result) = Self::from_preset(name_or_path) {
            return result;
        }
        let path = Path::new(name_or_path);
        if !path.is_file() {
            return Err(LoadError::Invariant(format!(
                "`{}` is neither a built-in policy preset ({}) nor a readable file",
                name_or_path,
                Self::preset_names().collect::<Vec<_>>().join(", "),
            )));
        }
        Self::from_toml(&std::fs::read_to_string(path)?)
    }

    /// True when this policy's jurisdiction excludes `algorithm_id` from its
    /// approved list. See [`Deprecation::policy_disallowed`].
    pub fn disallows(&self, algorithm_id: &str) -> bool {
        self.deprecation
            .policy_disallowed
            .iter()
            .any(|id| id == algorithm_id)
    }

    pub fn from_toml(s: &str) -> Result<Self, LoadError> {
        let p: Self = toml::from_str(s)?;
        p.validate()?;
        Ok(p)
    }

    /// Static invariants the scorer relies on.
    fn validate(&self) -> Result<(), LoadError> {
        if self.risk_weights.sum() != 100 {
            return Err(LoadError::Invariant(format!(
                "risk_weights sum to {}, expected 100",
                self.risk_weights.sum()
            )));
        }
        // Severity bands must be monotonically decreasing.
        let bands = [
            ("critical", self.severity_bands.critical),
            ("high", self.severity_bands.high),
            ("medium", self.severity_bands.medium),
            ("low", self.severity_bands.low),
            ("safe", self.severity_bands.safe),
        ];
        for window in bands.windows(2) {
            if window[0].1 <= window[1].1 {
                return Err(LoadError::Invariant(format!(
                    "severity_bands not monotonically decreasing: {}={} ≤ {}={}",
                    window[0].0, window[0].1, window[1].0, window[1].1
                )));
            }
        }
        // Every QuantumStatus must have a weight in algorithm_vulnerability.
        for s in [
            QuantumStatus::BrokenClassically,
            QuantumStatus::BrokenByShor,
            QuantumStatus::WeakenedByGrover,
            QuantumStatus::QuantumSafe,
            QuantumStatus::PqcFinal,
            QuantumStatus::PqcDraft,
        ] {
            if !self.algorithm_vulnerability.contains_key(&s) {
                return Err(LoadError::Invariant(format!(
                    "algorithm_vulnerability missing weight for {:?}",
                    s
                )));
            }
        }
        // shelf_life_tags must reference a known bucket.
        let allowed_buckets = ["ephemeral", "short", "medium", "long"];
        for (glob, bucket) in &self.shelf_life_tags {
            if !allowed_buckets.contains(&bucket.as_str()) {
                return Err(LoadError::Invariant(format!(
                    "shelf_life_tags[{}] = `{}` is not a known bucket",
                    glob, bucket
                )));
            }
        }
        if !allowed_buckets.contains(&self.shelf_life_default.bucket.as_str()) {
            return Err(LoadError::Invariant(format!(
                "shelf_life_default.bucket = `{}` is not a known bucket",
                self.shelf_life_default.bucket
            )));
        }
        Ok(())
    }

    /// Cross-check: every algorithm id the policy names exists in the table.
    ///
    /// A typo in a preset would otherwise silently do nothing — the id would
    /// simply never match a finding.
    pub fn cross_check(&self, algorithms: &AlgorithmTable) -> Result<(), LoadError> {
        for (field, ids) in [
            ("classically_broken", &self.deprecation.classically_broken),
            ("policy_disallowed", &self.deprecation.policy_disallowed),
        ] {
            for id in ids {
                if algorithms.get(id).is_none() {
                    return Err(LoadError::Invariant(format!(
                        "policy.{} contains `{}` which is not in the algorithm table",
                        field, id
                    )));
                }
            }
        }
        Ok(())
    }
}

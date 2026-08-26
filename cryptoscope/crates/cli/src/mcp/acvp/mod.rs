//! ACVP Known-Answer Test (KAT) runner — `vectorsOnly` mode.
//!
//! # P4 invariant
//! This module ONLY validates **provided** outputs against NIST-pinned expected
//! values loaded from JSON files bundled at compile time via `include_bytes!`.
//! It does NOT invoke any cryptographic library, run any subprocess, or perform
//! any form of code execution. The agent layer must supply the candidate outputs;
//! this module tells it whether they match NIST's expected values.
//!
//! # Algorithms supported
//! - ML-KEM-512, ML-KEM-768, ML-KEM-1024  (FIPS 203 / NIST ACVP)
//! - ML-DSA-44, ML-DSA-65, ML-DSA-87      (FIPS 204 / NIST ACVP)
//! - SLH-DSA-SHAKE-128s                    (FIPS 205 / NIST ACVP — one param set for v0.1)
//!
//! # Bundled vector set
//! A representative subset (1-3 test groups per algorithm/mode) is bundled in
//! `data/acvp-vectors/`. The full NIST ACVP-Server vector repository is
//! available at <https://github.com/usnistgov/ACVP-Server>. Adding more
//! parameter sets or modes is straightforward: drop the JSON into
//! `data/acvp-vectors/` and extend `vectors.rs`.

pub mod ml_dsa;
pub mod ml_kem;
pub mod slh_dsa;
pub mod vectors;

use serde_json::{Value, json};

use crate::mcp::errors::E_RULESET_INVALID;

/// Candidate outputs supplied by the caller (agent layer).
///
/// The map is keyed by `tcId` (as a string). Each value is the candidate
/// output object for that test case — field names must match the algorithm's
/// ACVP response schema (e.g. `"ek"`, `"dk"` for ML-KEM keyGen; `"ct"`,
/// `"ss"` for encapDecap; `"pk"`, `"sk"` for DSA keyGen; etc.).
pub type CandidateOutputs = std::collections::HashMap<String, Value>;

/// A single test-case failure record.
#[derive(Debug, Clone)]
pub struct Failure {
    pub tc_id: u64,
    pub field: String,
    pub expected: String,
    pub got: String,
}

/// Result for one algorithm / parameter-set / mode combination.
#[derive(Debug)]
pub struct KatResult {
    pub algorithm: String,
    pub parameter_set: String,
    /// ACVP sub-mode: "keyGen", "encapDecap", "sigGen", "sigVer".
    /// Distinct from the MCP-level mode which is always "vectorsOnly".
    pub acvp_mode: String,
    pub vector_source: VectorSource,
    pub groups: Vec<GroupSummary>,
    pub overall: String,
    pub failures: Vec<Failure>,
}

#[derive(Debug)]
pub struct VectorSource {
    pub authority: String,
    pub set_version: String,
}

#[derive(Debug)]
pub struct GroupSummary {
    pub name: String,
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
}

impl KatResult {
    /// Serialize to the wire-schema `serde_json::Value`.
    pub fn to_json(&self) -> Value {
        let groups: Vec<Value> = self
            .groups
            .iter()
            .map(|g| {
                json!({
                    "name": g.name,
                    "total": g.total,
                    "passed": g.passed,
                    "failed": g.failed,
                })
            })
            .collect();

        let failures: Vec<Value> = self
            .failures
            .iter()
            .map(|f| {
                json!({
                    "tc_id": f.tc_id,
                    "field": f.field,
                    "expected": f.expected,
                    "got": f.got,
                })
            })
            .collect();

        json!({
            "algorithm": self.algorithm,
            "parameter_set": self.parameter_set,
            "mode": "vectorsOnly",
            "acvp_mode": self.acvp_mode,
            "vector_source": {
                "authority": self.vector_source.authority,
                "set_version": self.vector_source.set_version,
            },
            "groups": groups,
            "overall": self.overall,
            "failures": failures,
        })
    }
}

/// Run a KAT for the given algorithm, parameter set, and mode.
///
/// `candidate_outputs` maps tcId strings to candidate output objects.
/// Returns an `Err` if the algorithm/parameter_set/mode triple is not
/// supported.
pub fn run_kat(
    algorithm: &str,
    parameter_set: &str,
    mode: &str,
    candidate_outputs: &CandidateOutputs,
) -> Result<KatResult, (i32, String)> {
    match algorithm {
        "ML-KEM" => ml_kem::run(parameter_set, mode, candidate_outputs),
        "ML-DSA" => ml_dsa::run(parameter_set, mode, candidate_outputs),
        "SLH-DSA" => slh_dsa::run(parameter_set, mode, candidate_outputs),
        other => Err((
            E_RULESET_INVALID,
            format!("unsupported algorithm \"{other}\"; supported: ML-KEM, ML-DSA, SLH-DSA"),
        )),
    }
}

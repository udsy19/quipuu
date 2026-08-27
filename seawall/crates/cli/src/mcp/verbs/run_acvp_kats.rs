//! `run_acvp_kats` verb — ACVP Known-Answer Test runner.
//!
//! # P4 invariant
//! This verb ONLY supports `mode: "vectorsOnly"`. It compares the agent-layer-
//! supplied candidate outputs against NIST ACVP-pinned expected values. NO
//! external library/binary execution of any kind. See `crate::mcp::acvp`.
//!
//! ## Params
//! ```json
//! {
//!   "algorithm":    "ML-KEM",                 // required
//!   "parameterSet": "ML-KEM-768",              // required
//!   "mode":         "vectorsOnly",             // optional; only accepted value
//!   "acvpMode":     "encapDecap",              // optional; default "keyGen"
//!   "candidateOutputs": {                      // optional; map tcId → outputs
//!     "1": { "ct": "...", "ss": "..." }
//!   }
//! }
//! ```
//!
//! ## Response
//! See [`crate::mcp::acvp::KatResult::to_json`] for the wire shape.

use serde_json::{Value, json};

use crate::mcp::acvp::{self, CandidateOutputs};
use crate::mcp::errors::E_RULESET_INVALID;

/// P4 assertion: only vectorsOnly mode is permitted.
const SUPPORTED_MODE: &str = "vectorsOnly";

pub fn handle(params: Option<Value>) -> Result<Value, (i32, String)> {
    let params = params.unwrap_or(Value::Null);

    // P4 enforcement: reject any mode other than vectorsOnly.
    let mode = params
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or(SUPPORTED_MODE);
    if mode != SUPPORTED_MODE {
        return Err((
            E_RULESET_INVALID,
            format!(
                "run_acvp_kats only supports mode=\"vectorsOnly\" (P4: no code execution). \
                 Got \"{mode}\""
            ),
        ));
    }

    let algorithm = params
        .get("algorithm")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            (
                E_RULESET_INVALID,
                "params.algorithm (string) is required".to_string(),
            )
        })?;

    let parameter_set = params
        .get("parameterSet")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            (
                E_RULESET_INVALID,
                "params.parameterSet (string) is required for NIST ACVP runner. \
                 Example: \"ML-KEM-768\""
                    .to_string(),
            )
        })?;

    // acvpMode selects keyGen / encapDecap / sigGen / sigVer within an algorithm.
    let acvp_mode = params
        .get("acvpMode")
        .and_then(Value::as_str)
        .unwrap_or("keyGen");

    // Parse candidate outputs (optional; empty map means all tcIds will fail).
    let candidate_outputs: CandidateOutputs = params
        .get("candidateOutputs")
        .and_then(Value::as_object)
        .map(|obj| obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default();

    let kat_result = acvp::run_kat(algorithm, parameter_set, acvp_mode, &candidate_outputs)?;

    Ok(json!({
        "mode": SUPPORTED_MODE,
        "result": kat_result.to_json(),
    }))
}

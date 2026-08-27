//! `get_capabilities` verb — returns server capabilities and runtime config.
//!
//! Response shape:
//! {
//!   contractVersion: "0.1.0",
//!   rulesetVersion: string,
//!   supportedLanguages: string[],
//!   supportedSchemas: string[],
//!   policyPresets: string[],
//!   networkAllowed: bool,
//!   bundledKatSets: [],       // v0.1 stub
//!   methods: string[],        // runtime-available verb names
//! }

use cryptoscope_core::Policy;
use serde_json::{Value, json};

/// All 11 MCP verbs defined in MCP.md.
pub const ALL_METHODS: &[&str] = &[
    "initialize",
    "scan_source",
    "scan_certs",
    "scan_deps",
    "scan_network",
    "emit_cbom",
    "emit_sarif",
    "validate_cbom",
    "run_acvp_kats",
    "query_findings",
    "get_scan_results",
    "get_capabilities",
];

pub fn handle(params: Option<Value>, allow_network: bool) -> Result<Value, (i32, String)> {
    let _ = params; // no params required

    // Methods available at runtime — scan_network only if --allow-network.
    let methods: Vec<&str> = ALL_METHODS
        .iter()
        .filter(|&&m| allow_network || m != "scan_network")
        .copied()
        .collect();

    Ok(json!({
        "contractVersion": "0.1.0",
        "rulesetVersion": env!("CARGO_PKG_VERSION"),
        "supportedLanguages": [
            "go", "python", "java", "javascript", "typescript",
            "c", "cpp", "rust", "csharp",
        ],
        "supportedSchemas": ["1.6", "1.7"],
        // Quoted from core so MCP.md, `cryptoscope policy list` and the wire
        // response cannot disagree about which presets exist.
        "policyPresets": Policy::preset_names().collect::<Vec<_>>(),
        "networkAllowed": allow_network,
        "bundledKatSets": [],   // v0.1 stub — populate when ACVP vector files land
        "methods": methods,
    }))
}

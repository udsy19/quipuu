//! MCP verb implementations — one module per verb.

pub mod emit_cbom;
pub mod emit_sarif;
pub mod get_capabilities;
pub mod get_scan_results;
pub mod query_findings;
pub mod run_acvp_kats;
pub mod scan_certs;
pub mod scan_deps;
pub mod scan_network;
pub mod scan_source;
pub mod validate_cbom;

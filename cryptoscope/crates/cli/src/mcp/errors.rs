//! MCP error codes (JSON-RPC application-level errors).
//!
//! These codes live in the -32000 … -32099 range reserved for
//! implementation-defined server errors by the JSON-RPC 2.0 spec.

/// Path supplied to scan_source / scan_certs / scan_deps was not found.
pub const E_PATH_NOT_FOUND: i32 = -32001;
/// Ruleset parameter did not parse or referenced an unknown rule-id.
pub const E_RULESET_INVALID: i32 = -32002;
/// Policy parameter did not parse or violated an invariant.
pub const E_POLICY_INVALID: i32 = -32003;
/// Network verb called without `--allow-network` at process launch.
pub const E_NETWORK_DISABLED: i32 = -32004;
/// Requested CycloneDX schema version is not supported.
pub const E_SCHEMA_UNSUPPORTED: i32 = -32005;
/// `contractVersion` in `initialize` params doesn't match server version.
pub const E_CONTRACT_VERSION: i32 = -32006;
/// `scanId` not found in the in-process session store.
pub const E_SCAN_NOT_FOUND: i32 = -32007;
/// Opaque cursor is malformed or refers to an expired/evicted scan.
pub const E_CURSOR_INVALID: i32 = -32008;

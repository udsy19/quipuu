//! MCP server — JSON-RPC 2.0 over stdio.
//!
//! # Invariants (MCP.md P1–P4)
//!
//! P1 — NO LLM SDK. This module must never depend on an LLM inference library.
//!      `cargo deny check bans` or `grep -r 'openai\|anthropic\|langchain'
//!      crates/cli/src/mcp/` must produce no hits.
//!
//! P2 — NO listening socket; NO outbound connection without `--allow-network`.
//!      Transport is strictly stdio (see `transport.rs`). Network verbs
//!      (`scan_network`, `scan_certs` host-mode) check `allow_network` at
//!      call time and return E_NETWORK_DISABLED if the flag was not supplied.
//!
//! P3 — Every finding emitted carries `provenance: "deterministic"`. The
//!      `Finding` type in `seawall-core` enforces this at the type level;
//!      each verb JSON response explicitly sets the field.
//!
//! P4 — NO code execution. `run_acvp_kats` only supports `mode: "vectorsOnly"`
//!      and asserts at the top of its handler that no other mode is accepted.

pub mod acvp;
pub mod errors;
pub mod session;
pub mod transport;
pub mod verbs;

use std::io::BufReader;

use serde_json::{Value, json};

use errors::{E_CONTRACT_VERSION, E_RULESET_INVALID};
use session::SessionStore;
use transport::{JsonRpcResponse, read_request, write_response};

/// Run the MCP server loop over stdin/stdout.
///
/// Blocks until EOF on stdin (clean shutdown). Errors from individual requests
/// are returned as JSON-RPC error responses — the loop never aborts.
pub fn run(allow_network: bool) {
    let stdin = std::io::stdin();
    let mut reader = BufReader::new(stdin.lock());
    let mut session = SessionStore::new();

    loop {
        match read_request(&mut reader) {
            Ok(None) => break, // EOF — clean shutdown
            Ok(Some(req)) => {
                let id = req.id.clone().unwrap_or(Value::Null);
                let resp = dispatch(
                    req.method.as_str(),
                    req.params,
                    id,
                    allow_network,
                    &mut session,
                );
                if let Err(e) = write_response(&resp) {
                    // stdout gone — exit cleanly
                    eprintln!("mcp-serve: write failed: {e}");
                    break;
                }
            }
            Err(e) => {
                eprintln!("mcp-serve: read error: {e}");
                break;
            }
        }
    }
}

/// Route one JSON-RPC call to the appropriate verb handler.
fn dispatch(
    method: &str,
    params: Option<Value>,
    id: Value,
    allow_network: bool,
    session: &mut SessionStore,
) -> JsonRpcResponse {
    match method {
        "initialize" => handle_initialize(params, id),
        "list-tools" | "listTools" => handle_list_tools(id, allow_network),
        "call-tool" | "callTool" => {
            // MCP tool-call envelope: params.name + params.arguments
            let inner = params.as_ref();
            let tool_name = inner
                .and_then(|p| p.get("name"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let tool_params = inner.and_then(|p| p.get("arguments")).cloned();
            dispatch_verb(tool_name, tool_params, id, allow_network, session)
        }
        // Also allow verbs to be called directly (flat style).
        other => dispatch_verb(other, params, id, allow_network, session),
    }
}

fn handle_initialize(params: Option<Value>, id: Value) -> JsonRpcResponse {
    // If the client supplies a contractVersion, check compatibility.
    if let Some(cv) = params
        .as_ref()
        .and_then(|p| p.get("contractVersion"))
        .and_then(Value::as_str)
        && cv != "0.1.0"
    {
        return JsonRpcResponse::error(
            id,
            E_CONTRACT_VERSION,
            format!("contractVersion mismatch: server is 0.1.0, client asked for {cv}"),
        );
    }

    JsonRpcResponse::success(
        id,
        json!({
            "protocolVersion": "2024-11-05",
            "contractVersion": "0.1.0",
            "serverInfo": {
                "name": "seawall-mcp",
                "version": env!("CARGO_PKG_VERSION"),
            },
            "capabilities": {
                "tools": { "listChanged": false },
            },
        }),
    )
}

fn handle_list_tools(id: Value, allow_network: bool) -> JsonRpcResponse {
    let tools: Vec<Value> = build_tool_list(allow_network);
    JsonRpcResponse::success(id, json!({ "tools": tools }))
}

fn dispatch_verb(
    verb: &str,
    params: Option<Value>,
    id: Value,
    allow_network: bool,
    session: &mut SessionStore,
) -> JsonRpcResponse {
    let result = match verb {
        "scan_source" => verbs::scan_source::handle(params, session),
        "scan_certs" => verbs::scan_certs::handle(params, session, allow_network),
        "scan_deps" => verbs::scan_deps::handle(params, session),
        "scan_network" => verbs::scan_network::handle(params, session, allow_network),
        "emit_cbom" => verbs::emit_cbom::handle(params, session),
        "emit_sarif" => verbs::emit_sarif::handle(params, session),
        "validate_cbom" => verbs::validate_cbom::handle(params),
        "run_acvp_kats" => verbs::run_acvp_kats::handle(params),
        "query_findings" => verbs::query_findings::handle(params, session),
        "get_scan_results" => verbs::get_scan_results::handle(params, session),
        "get_capabilities" => verbs::get_capabilities::handle(params, allow_network),
        _ => Err((E_RULESET_INVALID, format!("unknown method: {verb}"))),
    };

    match result {
        Ok(value) => JsonRpcResponse::success(id, value),
        Err((code, msg)) => JsonRpcResponse::error(id, code, msg),
    }
}

// ── Tool list (for list-tools / MCP capability negotiation) ──────────────────

fn build_tool_list(allow_network: bool) -> Vec<Value> {
    let mut tools = vec![
        tool_def(
            "scan_source",
            "Scan source code for cryptographic API usage",
            json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "File or directory to scan" },
                    "sessionMode": {
                        "type": "string",
                        "enum": ["blocking", "streaming"],
                        "default": "blocking",
                    },
                },
                "required": ["path"],
            }),
        ),
        tool_def(
            "scan_certs",
            "Scan X.509 certificate files (PEM/DER)",
            json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "host": { "type": "array", "items": { "type": "string" } },
                },
            }),
        ),
        tool_def(
            "scan_deps",
            "Scan dependency manifests for cryptographic library usage",
            json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                },
                "required": ["path"],
            }),
        ),
        tool_def(
            "emit_cbom",
            "Emit a CycloneDX CBOM from a scan session or inline findings",
            json!({
                "type": "object",
                "properties": {
                    "scanId": { "type": "string" },
                    "findings": { "type": "array" },
                    "schemaVersion": { "type": "string", "enum": ["1.6", "1.7"] },
                    "scanTarget": { "type": "string" },
                },
            }),
        ),
        tool_def(
            "emit_sarif",
            "Emit SARIF 2.1.0 from a scan session",
            json!({
                "type": "object",
                "properties": {
                    "scanId": { "type": "string" },
                    "scanTarget": { "type": "string" },
                },
                "required": ["scanId"],
            }),
        ),
        tool_def(
            "validate_cbom",
            "Validate a CycloneDX BOM JSON against the embedded schema",
            json!({
                "type": "object",
                "properties": {
                    "cbom": { "type": "object" },
                    "schemaVersion": { "type": "string", "enum": ["1.6", "1.7"] },
                },
                "required": ["cbom"],
            }),
        ),
        tool_def(
            "run_acvp_kats",
            "Run ACVP known-answer test vectors (vectorsOnly mode — P4: no code execution)",
            json!({
                "type": "object",
                "properties": {
                    "algorithm": { "type": "string" },
                    "mode": { "type": "string", "enum": ["vectorsOnly"] },
                    "vectors": { "type": "array" },
                },
                "required": ["algorithm", "vectors"],
            }),
        ),
        tool_def(
            "query_findings",
            "Filter and group findings from a stored scan",
            json!({
                "type": "object",
                "properties": {
                    "scanId": { "type": "string" },
                    "filter": { "type": "object" },
                    "groupBy": { "type": "string" },
                    "sort": { "type": "string" },
                },
                "required": ["scanId"],
            }),
        ),
        tool_def(
            "get_scan_results",
            "Paginate findings from a stored scan via opaque cursor",
            json!({
                "type": "object",
                "properties": {
                    "scanId": { "type": "string" },
                    "cursor": { "type": "string" },
                    "pageSize": { "type": "integer" },
                },
            }),
        ),
        tool_def(
            "get_capabilities",
            "Return server capabilities and runtime configuration",
            json!({ "type": "object", "properties": {} }),
        ),
    ];

    if allow_network {
        tools.push(tool_def(
            "scan_network",
            "Probe TLS endpoints (requires --allow-network)",
            json!({
                "type": "object",
                "properties": {
                    "targets": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "host:port pairs to probe",
                    },
                },
                "required": ["targets"],
            }),
        ));
    }

    tools
}

fn tool_def(name: &str, description: &str, input_schema: Value) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": input_schema,
    })
}

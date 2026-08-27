//! JSON-RPC 2.0 transport — newline-delimited JSON over stdin/stdout.
//!
//! # P2 invariant
//! This module NEVER opens a listening socket and NEVER initiates an outbound
//! TCP connection. All I/O is strictly stdio. The only way to reach the network
//! from the MCP server is through verbs that explicitly check the
//! `allow_network` flag at call time.

use std::io::{self, BufRead, Write};

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── Wire types ──────────────────────────────────────────────────────────────

/// An incoming JSON-RPC 2.0 request (or notification when `id` is absent).
#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
    // Present for validation; not read after deserialization succeeds.
    #[allow(dead_code)]
    pub jsonrpc: String,
    #[serde(default)]
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Option<Value>,
}

/// An outgoing JSON-RPC 2.0 response (success or error).
#[derive(Debug, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: &'static str,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

/// JSON-RPC 2.0 error object.
#[derive(Debug, Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

// ── Helpers ──────────────────────────────────────────────────────────────────

impl JsonRpcResponse {
    pub fn success(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(id: Value, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }

    #[allow(dead_code)]
    pub fn error_with_data(id: Value, code: i32, message: impl Into<String>, data: Value) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data: Some(data),
            }),
        }
    }
}

// ── Main loop ────────────────────────────────────────────────────────────────

/// Read one newline-terminated JSON-RPC request from `stdin`.
///
/// Returns `None` on EOF (clean shutdown).
pub fn read_request<R: BufRead>(reader: &mut R) -> io::Result<Option<JsonRpcRequest>> {
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            return Ok(None); // EOF
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue; // skip blank lines
        }
        match serde_json::from_str(trimmed) {
            Ok(req) => return Ok(Some(req)),
            Err(e) => {
                // Emit a parse error and keep going.
                let resp = JsonRpcResponse::error(Value::Null, -32700, format!("Parse error: {e}"));
                write_response(&resp)?;
            }
        }
    }
}

/// Serialise `resp` as a single newline-terminated JSON line to stdout.
pub fn write_response(resp: &JsonRpcResponse) -> io::Result<()> {
    let mut out = io::stdout().lock();
    let json = serde_json::to_string(resp).map_err(|e| io::Error::other(e.to_string()))?;
    out.write_all(json.as_bytes())?;
    out.write_all(b"\n")?;
    out.flush()
}

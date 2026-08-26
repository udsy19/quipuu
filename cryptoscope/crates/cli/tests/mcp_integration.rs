//! Integration tests for the `cryptoscope mcp-serve` subcommand.
//!
//! Each test spawns the binary as a subprocess, sends JSON-RPC over stdin,
//! and asserts the response on stdout.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::Duration;

use serde_json::{Value, json};

// ── Helper ────────────────────────────────────────────────────────────────────

fn binary_path() -> PathBuf {
    // The integration test binary lives alongside cryptoscope in target/debug/.
    let mut p = std::env::current_exe().expect("cannot get test binary path");
    p.pop(); // remove test binary name
    // Remove the "deps" directory if present.
    if p.ends_with("deps") {
        p.pop();
    }
    p.push("cryptoscope");
    p
}

struct McpSession {
    child: Child,
    stdin: ChildStdin,
    reader: BufReader<ChildStdout>,
}

impl McpSession {
    fn start(allow_network: bool) -> Self {
        let bin = binary_path();
        let mut cmd = Command::new(&bin);
        cmd.arg("mcp-serve");
        if allow_network {
            cmd.arg("--allow-network");
        }
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());

        let mut child = cmd.spawn().expect("failed to spawn cryptoscope mcp-serve");
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        McpSession {
            child,
            stdin,
            reader: BufReader::new(stdout),
        }
    }

    fn send(&mut self, request: Value) {
        let line = serde_json::to_string(&request).unwrap() + "\n";
        self.stdin.write_all(line.as_bytes()).unwrap();
        self.stdin.flush().unwrap();
    }

    fn recv(&mut self) -> Value {
        let mut line = String::new();
        // Use a simple loop with a timeout approach via thread-local.
        self.reader.read_line(&mut line).expect("read_line failed");
        serde_json::from_str(line.trim()).expect("invalid JSON response")
    }

    fn request(&mut self, id: u64, method: &str, params: Value) -> Value {
        self.send(json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        }));
        self.recv()
    }

    fn close(mut self) {
        drop(self.stdin);
        // Give the process a moment to exit cleanly, then kill.
        std::thread::sleep(Duration::from_millis(100));
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ── Test 1: initialize handshake ─────────────────────────────────────────────

#[test]
fn test_initialize_handshake() {
    let mut s = McpSession::start(false);

    let resp = s.request(1, "initialize", json!({}));

    assert_eq!(resp["jsonrpc"], "2.0");
    assert_eq!(resp["id"], 1);
    assert!(resp["result"].is_object(), "expected result object");
    assert_eq!(resp["result"]["contractVersion"], "0.1.0");
    assert_eq!(resp["result"]["serverInfo"]["name"], "cryptoscope-mcp");

    s.close();
}

// ── Test 2: initialize with matching contractVersion ─────────────────────────

#[test]
fn test_initialize_contract_version_ok() {
    let mut s = McpSession::start(false);

    let resp = s.request(2, "initialize", json!({ "contractVersion": "0.1.0" }));

    assert!(resp["result"].is_object());
    assert_eq!(resp["result"]["contractVersion"], "0.1.0");

    s.close();
}

// ── Test 3: initialize with mismatched contractVersion → E_CONTRACT_VERSION ──

#[test]
fn test_initialize_contract_version_mismatch() {
    let mut s = McpSession::start(false);

    let resp = s.request(3, "initialize", json!({ "contractVersion": "9.9.9" }));

    assert!(resp["error"].is_object(), "expected error");
    assert_eq!(resp["error"]["code"], -32006); // E_CONTRACT_VERSION

    s.close();
}

// ── Test 4: get_capabilities ─────────────────────────────────────────────────

#[test]
fn test_get_capabilities() {
    let mut s = McpSession::start(false);

    let resp = s.request(4, "get_capabilities", json!({}));

    assert!(resp["result"].is_object());
    let result = &resp["result"];
    assert_eq!(result["contractVersion"], "0.1.0");
    assert_eq!(result["networkAllowed"], false);
    let methods = result["methods"].as_array().expect("methods must be array");
    // scan_network must NOT be in methods without --allow-network
    assert!(
        !methods.iter().any(|m| m == "scan_network"),
        "scan_network should not be listed without --allow-network"
    );
    // Core verbs must be present
    assert!(methods.iter().any(|m| m == "scan_source"));
    assert!(methods.iter().any(|m| m == "emit_cbom"));

    s.close();
}

// ── Test 5: get_capabilities with --allow-network ────────────────────────────

#[test]
fn test_get_capabilities_with_network() {
    let mut s = McpSession::start(true);

    let resp = s.request(5, "get_capabilities", json!({}));

    let result = &resp["result"];
    assert_eq!(result["networkAllowed"], true);
    let methods = result["methods"].as_array().unwrap();
    assert!(methods.iter().any(|m| m == "scan_network"));

    s.close();
}

// ── Test 6: scan_source on a fixture file ────────────────────────────────────

#[test]
fn test_scan_source_on_fixture() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/scan-source/tests/fixtures/go/main.go");
    assert!(fixture.exists(), "fixture not found: {}", fixture.display());

    let mut s = McpSession::start(false);

    let resp = s.request(
        6,
        "scan_source",
        json!({ "path": fixture.to_str().unwrap() }),
    );

    assert!(resp["result"].is_object(), "expected result, got: {resp}");
    let result = &resp["result"];
    assert!(result["scanId"].is_string());
    assert!(result["findings"].is_array());
    // The Go fixture has at least one finding (rsa.GenerateKey)
    let count = result["findings"].as_array().unwrap().len();
    assert!(
        count >= 1,
        "expected >= 1 finding from Go fixture, got {count}"
    );
    assert_eq!(result["provenance"], "deterministic");

    s.close();
}

// ── Test 7: emit_cbom round-trip ─────────────────────────────────────────────

#[test]
fn test_emit_cbom_roundtrip() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/scan-source/tests/fixtures/go/main.go");

    let mut s = McpSession::start(false);

    // First scan to get scanId
    let scan_resp = s.request(
        7,
        "scan_source",
        json!({ "path": fixture.to_str().unwrap() }),
    );
    let scan_id = scan_resp["result"]["scanId"].as_str().unwrap().to_string();

    // Then emit CBOM
    let cbom_resp = s.request(
        8,
        "emit_cbom",
        json!({ "scanId": scan_id, "schemaVersion": "1.7" }),
    );

    assert!(cbom_resp["result"].is_object());
    let result = &cbom_resp["result"];
    assert_eq!(result["schemaVersion"], "1.7");
    assert!(result["cbom"].is_object());
    // CycloneDX BOM must have bomFormat
    assert_eq!(result["cbom"]["bomFormat"], "CycloneDX");

    s.close();
}

// ── Test 8: query_findings filter ────────────────────────────────────────────

#[test]
fn test_query_findings_filter() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/scan-source/tests/fixtures/go/main.go");

    let mut s = McpSession::start(false);

    let scan_resp = s.request(
        9,
        "scan_source",
        json!({ "path": fixture.to_str().unwrap() }),
    );
    let scan_id = scan_resp["result"]["scanId"].as_str().unwrap().to_string();

    // Query with a filter that should match nothing (wrong rule_id)
    let q_resp = s.request(
        10,
        "query_findings",
        json!({
            "scanId": scan_id,
            "filter": { "ruleId": "NONEXISTENT-999" },
        }),
    );

    assert!(q_resp["result"].is_object());
    assert_eq!(q_resp["result"]["count"], 0);
    assert_eq!(q_resp["result"]["findings"].as_array().unwrap().len(), 0);

    s.close();
}

// ── Test 9: get_scan_results cursor pagination ────────────────────────────────

#[test]
fn test_get_scan_results_cursor() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/scan-source/tests/fixtures/go/main.go");

    let mut s = McpSession::start(false);

    let scan_resp = s.request(
        11,
        "scan_source",
        json!({ "path": fixture.to_str().unwrap() }),
    );
    let scan_id = scan_resp["result"]["scanId"].as_str().unwrap().to_string();

    // Page with pageSize=1
    let page_resp = s.request(
        12,
        "get_scan_results",
        json!({ "scanId": scan_id, "pageSize": 1 }),
    );

    assert!(page_resp["result"].is_object());
    let result = &page_resp["result"];
    assert!(result["findings"].as_array().unwrap().len() <= 1);
    assert_eq!(result["offset"], 0);

    s.close();
}

// ── Test 10: error — unknown scanId ──────────────────────────────────────────

#[test]
fn test_error_unknown_scan_id() {
    let mut s = McpSession::start(false);

    let resp = s.request(13, "emit_cbom", json!({ "scanId": "scan-does-not-exist" }));

    assert!(resp["error"].is_object(), "expected error");
    assert_eq!(resp["error"]["code"], -32007); // E_SCAN_NOT_FOUND

    s.close();
}

// ── Test 11: error — E_NETWORK_DISABLED for scan_network ─────────────────────

#[test]
fn test_network_disabled_error() {
    // Start WITHOUT --allow-network
    let mut s = McpSession::start(false);

    let resp = s.request(
        14,
        "scan_network",
        json!({ "targets": ["example.com:443"] }),
    );

    assert!(resp["error"].is_object(), "expected error");
    assert_eq!(resp["error"]["code"], -32004); // E_NETWORK_DISABLED

    s.close();
}

// ── Test 12: run_acvp_kats SHA-256 vector ────────────────────────────────────

#[test]
fn test_run_acvp_kats_sha256() {
    let mut s = McpSession::start(false);

    // NIST SHA-256("abc") known-answer test
    let resp = s.request(
        15,
        "run_acvp_kats",
        json!({
            "algorithm": "SHA2-256",
            "mode": "vectorsOnly",
            "vectors": [
                {
                    "input": "616263",  // "abc" in hex
                    "expected": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
                }
            ]
        }),
    );

    assert!(resp["result"].is_object(), "expected result, got: {resp}");
    let result = &resp["result"];
    assert_eq!(result["algorithm"], "SHA2-256");
    assert_eq!(result["passed"], 1);
    assert_eq!(result["failed"], 0);
    let vectors = result["vectors"].as_array().unwrap();
    assert_eq!(vectors[0]["status"], "pass");

    s.close();
}

// ── Test 13: run_acvp_kats rejects non-vectorsOnly (P4) ──────────────────────

#[test]
fn test_run_acvp_kats_rejects_code_execution() {
    let mut s = McpSession::start(false);

    let resp = s.request(
        16,
        "run_acvp_kats",
        json!({
            "algorithm": "AES-GCM",
            "mode": "promptMode",  // invalid — only vectorsOnly allowed
            "vectors": [],
        }),
    );

    assert!(
        resp["error"].is_object(),
        "P4: must reject non-vectorsOnly mode"
    );

    s.close();
}

// ── Test 14: list-tools ───────────────────────────────────────────────────────

#[test]
fn test_list_tools() {
    let mut s = McpSession::start(false);

    let resp = s.request(17, "list-tools", json!({}));

    assert!(resp["result"].is_object());
    let tools = resp["result"]["tools"]
        .as_array()
        .expect("tools must be array");
    // At minimum: scan_source, scan_certs, scan_deps, emit_cbom, emit_sarif,
    // validate_cbom, run_acvp_kats, query_findings, get_scan_results,
    // get_capabilities (10 tools without network).
    assert!(
        tools.len() >= 10,
        "expected >= 10 tools, got {}",
        tools.len()
    );
    // scan_network must NOT appear without --allow-network
    assert!(
        !tools.iter().any(|t| t["name"] == "scan_network"),
        "scan_network must not appear without --allow-network"
    );

    s.close();
}

# cryptoscope MCP wire contract

> **Scope.** This document is the authoritative specification for the `cryptoscope mcp` subcommand: its transport, protocol, tool surface, schemas, streaming semantics, failure modes, and versioning. Implementation in `crates/cli/src/mcp/` must conform exactly. Any deviation is a bug.

---

## §0 Design invariants

These four invariants are contractual. Any change is a breaking contract change and requires a major version bump.

| # | Invariant | Enforcement |
|---|---|---|
| **P1** | Never calls an LLM at runtime. | No LLM SDK or HTTP client in `crates/cli/src/mcp/`. CI lint: `cargo deny` forbids `reqwest` / `openai` / `anthropic` / `langchain` dependencies in the MCP crate. |
| **P2** | Never opens a listening socket, and makes no outbound connection by default. Outbound TLS connections are made *only* by `scan_network` and host-mode `scan_certs`, *only* when `--allow-network` is passed at process launch (never enabled over the wire). The stdio MCP transport uses no socket of any kind. | `scan_network` and host-mode `scan_certs` gate on a process-level flag set exclusively via CLI argument, not via any tool input field. The MCP server code path has no `TcpListener::bind`. |
| **P3** | Every finding traces to a literal in the source data. | Each `Finding` carries a non-null `evidence.occurrences[].location` with `file` + `line` + `snippet`. The `emit_cbom` and `emit_sarif` tools reject findings without provenance. |
| **P4** | Never executes customer code. | No `std::process::Command` or `eval`-equivalent inside any tool handler. Dependency scanning reads manifest files only; it does not invoke package managers. |

---

## §1 Transport and packaging

### 1.1 Invocation

The MCP server is a subcommand of the single `cryptoscope` binary:

```
cryptoscope mcp-serve [--allow-network]
```

The policy profile is chosen per request, not per process — pass `policy` to any
verb that scores findings (`scan_source`, `get_scan_results`, `query_findings`,
`emit_sarif`).

There is no separate binary, no daemon, and no install step beyond the binary itself.

### 1.2 Transport

**stdio JSON-RPC 2.0** only. The host process spawns `cryptoscope mcp` and communicates over stdin/stdout. Each message is a newline-delimited JSON object. No HTTP, no WebSocket, no TCP listener of any kind for the MCP transport path (P2).

### 1.3 Lifecycle

The server process is stateless between requests except for an in-memory scan result cache keyed by `session_id`. The cache is bounded: up to 4 completed scans. Oldest entry is evicted when the limit is reached.

---

## §2 Protocol foundation

### 2.1 Initialize handshake

The host sends a standard MCP `initialize` request. The server responds with:

```json
{
  "protocolVersion": "2024-11-05",
  "serverInfo": {
    "name": "cryptoscope",
    "version": "<semver>"
  },
  "capabilities": {
    "tools": {},
    "logging": {}
  },
  "meta": {
    "contractVersion": "1.0.0",
    "rulesetVersion": "<semver>",
    "allowNetwork": <bool>
  }
}
```

`contractVersion` is the version of this document. `rulesetVersion` is the version of the embedded detection rules. Both are independent of the binary's semver (see §8).

### 2.2 Idempotency

All read tools (`scan_source`, `scan_certs`, `scan_deps`, `scan_network`, `query_findings`, `get_scan_results`) are idempotent: repeating a call with identical inputs produces identical output (modulo file system changes). Emit tools (`emit_cbom`, `emit_sarif`) write to the path specified in the request; a second call with the same path overwrites the file.

### 2.3 Session IDs

Each scan tool call that initiates a new scan generates and returns a `session_id` (UUIDv4). Subsequent calls to `query_findings` and `get_scan_results` reference this ID. Callers must treat a `session_id` as opaque.

---

## §3 Tool surface

The MCP server exposes 11 tools. All tool names use `snake_case`. All inputs and outputs conform to the schemas in `crates/core/schema/` (see §4).

---

### `scan_source`

**Purpose.** Walk a directory, parse source files with the tree-sitter engine, and emit cryptographic findings.

**Input fields.**

| Field | Type | Required | Description |
|---|---|---|---|
| `path` | string | yes | Absolute path to the directory or file to scan. |
| `session_id` | string | no | Caller-supplied ID; server generates one if absent. |
| `languages` | string[] | no | Restrict to these languages (e.g. `["go","python"]`). Default: all supported. |
| `exclude` | string[] | no | Glob patterns to skip (relative to `path`). |
| `policy` | string | no | Policy preset name (see `policyPresets`) or path to a policy TOML. Defaults to `nist-default`. An unknown name is an error (`-32003`), never a silent fall-back. |

**Output.** `{ "session_id": string, "finding_count": int, "languages_scanned": string[], "warnings": ScanWarning[] }`. Findings are retrievable via `get_scan_results`. `warnings` is always present (empty array on a clean scan); each entry is `{ "kind": string, "path": string | null, "message": string }`.

**Streaming.** Progress notifications are emitted during scanning (see §5.2).

**Errors.** `PATH_NOT_FOUND` if `path` does not exist; `UNSUPPORTED_LANGUAGE` if a requested language has no grammar. Both non-fatal — scan continues for valid inputs.

**Perf budget.** p95 ≤ 30 s for a 1 M-LOC repository on a 4-core laptop (rayon parallelism).

---

### `scan_certs`

**Purpose.** Parse X.509 certificates from PEM/DER files or a live TLS host and classify each against the algorithm table.

**Input fields.**

| Field | Type | Required | Description |
|---|---|---|---|
| `path` | string | no | Directory or file path containing PEM/DER material. |
| `host` | string | no | `host:port` for live chain retrieval. Requires `--allow-network` (P2). |
| `session_id` | string | no | |

Exactly one of `path` or `host` must be provided. Findings are scored when they
are read back, so `policy` belongs on `get_scan_results` / `query_findings` /
`emit_sarif`, not here.

**Output.** `{ "session_id": string, "certificate_count": int, "finding_count": int, "warnings": ScanWarning[] }`. `warnings` follows the same shape as `scan_source`.

**Streaming.** Progress notifications for directory walks.

**Errors.** `NETWORK_NOT_ALLOWED` (fatal) if `host` is provided but `--allow-network` was not set at process launch. `PARSE_ERROR` (non-fatal) on malformed cert files — scan continues for remaining files.

**Perf budget.** p95 ≤ 2 s per certificate chain; ≤ 10 s for a directory of 500 PEM files.

---

### `scan_deps`

**Purpose.** Parse dependency manifests and flag known cryptographic libraries.

**Input fields.**

| Field | Type | Required | Description |
|---|---|---|---|
| `path` | string | yes | Root directory to search for manifests. |
| `session_id` | string | no | |
| `manifest_types` | string[] | no | Restrict to `["go.mod","Cargo.toml","requirements.txt","package.json","pom.xml"]`. Default: all. |

**Output.** `{ "session_id": string, "manifests_found": int, "finding_count": int, "warnings": ScanWarning[] }`. `warnings` follows the same shape as `scan_source`.

**Streaming.** Progress notifications per manifest file parsed.

**Errors.** `PATH_NOT_FOUND`; `UNSUPPORTED_MANIFEST` (non-fatal, scan continues).

**Perf budget.** p95 ≤ 5 s for a monorepo with 200 manifests.

---

### `scan_network`

**Purpose.** Probe TLS endpoints to enumerate protocol versions, cipher suites, key-exchange groups, and signature algorithms.

**Input fields.**

| Field | Type | Required | Description |
|---|---|---|---|
| `targets` | string[] | yes | `host:port` entries to probe. |
| `session_id` | string | no | |

Requires `--allow-network` at process launch (P2). Concurrency is capped at 5 connections per host. Connect timeout 5 s, handshake timeout 10 s.

**Output.** `{ "session_id": string, "hosts_probed": int, "finding_count": int }`.

**Streaming.** One progress notification per host probed.

**Errors.** `NETWORK_NOT_ALLOWED` (fatal). `CONNECT_FAILED`, `HANDSHAKE_TIMEOUT` (non-fatal, per-host — scan continues for remaining targets).

**Perf budget.** p95 ≤ 15 s per host (10 group probes × handshake timeout).

---

### `emit_cbom`

**Purpose.** Serialize accumulated findings from a session as a CycloneDX CBOM file.

**Input fields.**

| Field | Type | Required | Description |
|---|---|---|---|
| `session_id` | string | yes | Session whose findings to emit. |
| `output_path` | string | yes | Absolute path for the output `.json` file. |
| `schema_version` | string | no | `"1.7"` (default) or `"1.6"`. |
| `validate` | boolean | no | Run embedded schema validator before writing. Default: `true`. |

**Output.** `{ "output_path": string, "component_count": int, "valid": bool }`.

**Streaming.** No.

**Errors.** `SESSION_NOT_FOUND` (fatal). `VALIDATION_FAILED` (fatal if `validate: true` — file is not written). `WRITE_ERROR` (fatal).

**Perf budget.** p95 ≤ 3 s for 10 000 findings.

---

### `emit_sarif`

**Purpose.** Serialize findings as a SARIF 2.1.0 file.

**Input fields.**

| Field | Type | Required | Description |
|---|---|---|---|
| `session_id` | string | yes | |
| `output_path` | string | yes | |
| `include_cbom_refs` | boolean | no | Embed `cryptoscope/cbom-ref` properties. Default: `true`. |
| `policy` | string | no | Policy preset name (see `policyPresets`) or path to a policy TOML. Defaults to `nist-default`. An unknown name is an error (`-32003`), never a silent fall-back. |

**Output.** `{ "output_path": string, "result_count": int }`.

**Streaming.** No.

**Errors.** `SESSION_NOT_FOUND`, `WRITE_ERROR` (both fatal).

**Perf budget.** p95 ≤ 3 s for 10 000 findings.

---

### `validate_cbom`

**Purpose.** Validate an existing CBOM JSON file against the CycloneDX schema without performing a scan.

**Input fields.**

| Field | Type | Required | Description |
|---|---|---|---|
| `cbom_path` | string | yes | Path to the CBOM JSON file. |
| `schema_version` | string | no | `"1.7"` (default) or `"1.6"`. |

**Output.** `{ "valid": bool, "errors": string[] }`. `errors` is empty on success.

**Streaming.** No.

**Errors.** `FILE_NOT_FOUND`, `PARSE_ERROR` (both fatal — validation cannot proceed).

**Perf budget.** p95 ≤ 500 ms.

---

### `run_acvp_kats`

**Purpose.** Run the embedded ACVP known-answer tests for the algorithm table. Used as a post-install self-check.

**Input fields.** None.

**Output.** `{ "tests_run": int, "tests_passed": int, "failures": string[] }`.

**Streaming.** Progress notifications (numeric count of tests executed).

**Errors.** Tool itself never returns a JSON-RPC error. Failures are reported in the `failures` array.

**Perf budget.** p95 ≤ 10 s.

---

### `query_findings`

**Purpose.** Query findings from a completed scan with filtering and sorting.

**Input fields.**

| Field | Type | Required | Description |
|---|---|---|---|
| `session_id` | string | yes | |
| `min_score` | integer | no | Return only findings with `risk_score ≥ min_score`. |
| `algorithm_ids` | string[] | no | Filter to specific algorithm IDs. |
| `asset_types` | string[] | no | `algorithm`, `certificate`, `protocol`, `related-crypto-material`. |
| `sort_by` | string | no | `risk_score` (default) or `location`. |
| `limit` | integer | no | Maximum results to return. Default: 100. |
| `cursor` | string | no | Pagination cursor from a prior response. |
| `policy` | string | no | Policy preset name (see `policyPresets`) or path to a policy TOML. Defaults to `nist-default`. An unknown name is an error (`-32003`), never a silent fall-back. |

**Output.** `{ "findings": Finding[], "next_cursor": string | null, "total_count": int }`.

**Streaming.** No. Use cursor pagination for large result sets.

**Errors.** `SESSION_NOT_FOUND` (fatal).

**Perf budget.** p95 ≤ 200 ms for up to 10 000 findings in the session.

---

### `get_scan_results`

**Purpose.** Retrieve the full findings list for a session via cursor pagination. The primary interface for streaming large result sets to a caller.

**Input fields.**

| Field | Type | Required | Description |
|---|---|---|---|
| `session_id` | string | yes | |
| `cursor` | string | no | Opaque cursor from a prior response. Absent on first call. |
| `page_size` | integer | no | Findings per page. Default: 50. Max: 500. |
| `policy` | string | no | Policy preset name (see `policyPresets`) or path to a policy TOML. Defaults to `nist-default`. An unknown name is an error (`-32003`), never a silent fall-back. |

**Output.** `{ "findings": Finding[], "next_cursor": string | null, "total_count": int, "session_complete": bool }`.

`session_complete: false` means the underlying scan is still running; the caller should poll using the same `cursor`. `session_complete: true` with `next_cursor: null` means the entire result set has been delivered.

**Streaming.** Findings stream via cursor pagination (see §5.3).

**Errors.** `SESSION_NOT_FOUND` (fatal). `INVALID_CURSOR` (fatal).

**Perf budget.** p95 ≤ 100 ms per page.

---

### `get_capabilities`

**Purpose.** Return the server's current capability set, including enabled features and detected runtimes.

**Input fields.** None.

**Output.**

```json
{
  "contractVersion": "1.0.0",
  "rulesetVersion": "<semver>",
  "allowNetwork": false,
  "supportedLanguages": ["go", "python"],
  "supportedManifests": ["go.mod", "Cargo.toml", "requirements.txt", "package.json", "pom.xml"],
  "schemaVersions": ["1.7", "1.6"],
  "policyPresets": ["nist-default", "nsa-cnsa2"],
  "mcpTasksSupported": false
}
```

`mcpTasksSupported` reflects whether the host advertised SEP-1686 capability during `initialize` (see §5.4).

**Streaming.** No.

**Errors.** None.

**Perf budget.** p95 ≤ 10 ms.

---

## §4 Wire schemas

Tool inputs and outputs conform to JSON schemas in `crates/core/schema/`. Do not duplicate schema definitions here; reference them by path.

| Schema file | Used by |
|---|---|
| `crates/core/schema/finding.schema.json` | All scan tools, `query_findings`, `get_scan_results` — Finding object shape [VERIFY: A1 authoring] |
| `crates/core/schema/crypto-asset.schema.json` | `emit_cbom` component shape, `Finding.asset` field |
| `crates/core/schema/risk-score.schema.json` | `Finding.risk_score` object, 5-axis breakdown |
| `crates/core/schema/mcp-tool-inputs.schema.json` | All tool input objects [VERIFY: A1 authoring] |
| `crates/core/schema/mcp-tool-outputs.schema.json` | All tool output objects [VERIFY: A1 authoring] |

The `emit_cbom` and `validate_cbom` tools additionally use the embedded CycloneDX schemas:

- `bom-1.7.schema.json` — primary output format
- `bom-1.6.schema.json` — `--schema-version 1.6` downgrade path

Both CycloneDX schema files are embedded in the binary at build time.

---

## §5 Streaming and session semantics

### 5.1 Gap closure

This section closes **gap #4** from the design discussion: the absence of a defined streaming contract for large scan results.

### 5.2 Progress notifications

During long-running scans (`scan_source`, `scan_network`, `run_acvp_kats`), the server emits MCP `notifications/progress` messages. Per the MCP canonical specification, the `progress` field MUST be a **number** (not a string, not an object). The `total` field, when present, MUST also be a number.

```json
{
  "method": "notifications/progress",
  "params": {
    "progressToken": "<token from request _meta>",
    "progress": 42,
    "total": 1000
  }
}
```

Callers that do not supply a `_meta.progressToken` do not receive notifications. The server never emits notifications unsolicited.

### 5.3 Findings pagination

Findings are not streamed inline in the scan tool response. The scan tool returns a `session_id` and a count; the caller retrieves findings via `get_scan_results` using cursor pagination.

The cursor is an opaque base64-encoded offset. The server guarantees stable ordering (by `risk_score` descending, then by `location.file` + `location.line` ascending) for the lifetime of a session. Callers must not parse or construct cursors.

### 5.4 SEP-1686 opt-in (MCP Tasks)

If the host advertises `experimental.tasks: true` in the `initialize` response, the server will wrap long-running scan tools (`scan_source`, `scan_network`) as MCP Tasks per SEP-1686. In this mode:

- The tool returns immediately with a `task_id`.
- The task transitions through `pending → running → complete | failed`.
- The caller polls `tasks/get` or subscribes to `tasks/updated` notifications.

SEP-1686 is an opt-in upgrade path. Hosts that do not advertise the capability receive the synchronous (blocking) behavior described in §3. `get_capabilities` reflects the negotiated state in `mcpTasksSupported`.

---

## §6 Failure modes and error taxonomy

### 6.1 Partial-scan principle

A single unparseable file or unreachable host does not abort the session. Errors are collected per-item, attached to the session, and reported in the tool response `warnings` array. The scan result is marked `partial: true` when any item failed.

### 6.2 Fatal vs. non-fatal

| Class | Behavior |
|---|---|
| **Fatal** | Tool returns a JSON-RPC error object; no output is written; session may be incomplete. |
| **Non-fatal** | Tool succeeds; individual item errors appear in `warnings[]`; session is marked `partial: true`. |

### 6.3 Error code taxonomy

The following 8 error codes are fatal and stable across versions (codes below -32000 follow the JSON-RPC application error convention):

| Code | Name | Trigger |
|---|---|---|
| -32001 | `PATH_NOT_FOUND` | Input `path` does not exist or is not accessible. |
| -32002 | `SESSION_NOT_FOUND` | `session_id` not in the in-memory cache (evicted or invalid). |
| -32003 | `NETWORK_NOT_ALLOWED` | A network tool was called but `--allow-network` was not set at launch. |
| -32004 | `VALIDATION_FAILED` | CBOM output failed schema validation; file not written. |
| -32005 | `WRITE_ERROR` | Output file could not be written (permissions, disk full). |
| -32006 | `PARSE_ERROR` | Input file could not be parsed at all (fatal only for `validate_cbom`). |
| -32007 | `INVALID_CURSOR` | Cursor is malformed or belongs to a different session. |
| -32008 | `UNSUPPORTED_LANGUAGE` | Requested language has no grammar bundle in this binary. |

Non-fatal item errors use string codes in `warnings[].code`: `CERT_PARSE_ERROR`, `CONNECT_FAILED`, `HANDSHAKE_TIMEOUT`, `MANIFEST_PARSE_ERROR`.

---

## §7 Performance contract

All budgets are p95 on a 4-core laptop (Apple M-series or equivalent) with the binary compiled in release mode.

| Tool | Workload | p95 budget |
|---|---|---|
| `scan_source` | 1 M-LOC monorepo, Go + Python | 30 s |
| `scan_source` | 100 k-LOC repo | 3 s |
| `scan_certs` | 500 PEM files | 10 s |
| `scan_certs` | Single live chain (`--allow-network`) | 2 s |
| `scan_deps` | 200 manifests | 5 s |
| `scan_network` | Single host, 10 group probes | 15 s |
| `emit_cbom` | 10 000 findings | 3 s |
| `emit_sarif` | 10 000 findings | 3 s |
| `validate_cbom` | Any size | 500 ms |
| `query_findings` | 10 000 findings in session | 200 ms |
| `get_scan_results` | Per page (≤ 500 findings) | 100 ms |
| `get_capabilities` | — | 10 ms |

These budgets are enforced by criterion benchmarks in `crates/cli/benches/mcp_tools.rs` [VERIFY].

---

## §8 Versioning and compatibility

### 8.1 contractVersion

`contractVersion` (in the `initialize` response and `get_capabilities` output) versions this document. It follows semantic versioning:

- **Patch** bump: documentation clarification; no behavior change.
- **Minor** bump: new tool added; new optional field added to an existing tool.
- **Major** bump: any change to P1–P4 invariants; removal or rename of a tool; removal of a required field; change to error code meanings.

Hosts should check `contractVersion` and refuse to proceed if the major version is higher than the version they were built against.

### 8.2 rulesetVersion

`rulesetVersion` versions the embedded detection rule packs (`crates/core/data/rules/*.toml`). It is independent of `contractVersion`. A ruleset bump may change which findings are produced without changing the wire contract.

### 8.3 Backward compatibility window

The server supports one prior major `contractVersion` for a minimum of 6 months after a major bump. During the overlap window, hosts may request the prior contract behavior by sending `meta.requestedContractVersion` in the `initialize` request [v0.2].

---

## §9 Dependency notes

### 9.1 OSS binary (this document)

The `cryptoscope mcp` subcommand runs entirely within the Rust workspace. No Python, no Node, no JVM. Invariant P1 holds by construction.

### 9.2 Pro engine

The Pro tier wraps the OSS binary as a child process over stdio and adds an orchestration layer written in Python with Pydantic AI. LangGraph is the escape hatch for graph-structured agent workflows. The Pro engine never modifies the OSS binary's behavior; it only calls its MCP tools over stdio. All invariants (P1–P4) are preserved end-to-end because the LLM calls live exclusively in the Pro layer, not in any OSS code path.

### 9.3 Prototype

Agent clients connect to the same MCP server (`cryptoscope mcp`) over stdio, using the JSON-RPC 2.0 framing described in §1.2. No separate server or wrapper is introduced.

---

## §10 v2 open items

The following items are deferred and tracked here for completeness.

1. **Hosted networked endpoint** [v0.2]: The Pro-side hosted service is a process that spawns the OSS binary as a child and proxies MCP calls over stdio. The networked endpoint itself is Pro infrastructure; the OSS binary remains stdio-only. Callerarchetype upgrade path requires defining a `callerArchetype` field in `initialize` metadata to allow the server to tune verbosity and page sizes per caller type (IDE plugin vs. CI agent vs. human-driven agent).

2. **callerArchetype** [v0.2]: Add `meta.callerArchetype` (`"ide" | "ci" | "agent" | "human"`) to the `initialize` handshake so the server can adapt default page sizes and progress notification frequency.

3. **Layer-3 verification cost model** [v0.2]: For Pro callers, define a token-budget field in `query_findings` so the agent layer can request cost-bounded responses for LLM post-processing. No LLM calls happen inside the OSS binary (P1); this field only assists Pro-side orchestration.

4. **`contractVersion` backward compatibility negotiation** [v0.2]: `meta.requestedContractVersion` in `initialize` to let hosts pin to a prior major version during a migration window (see §8.3).

5. **SEP-1686 (MCP Tasks) full implementation** [v0.2]: The opt-in path in §5.4 is fully specified; the implementation is gated on host ecosystem adoption of the Tasks extension. Mark `mcpTasksSupported: false` until the extension is ratified.

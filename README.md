# cryptoscope

**A single Rust binary that finds every cryptographic operation in your codebase, classifies each against NIST's post-quantum migration timeline, and tells you exactly which ones a quantum adversary can harvest today.**

```bash
cargo install cryptoscope
cryptoscope scan .
open reports/cryptoscope.html
```

<!-- TODO: add screenshot or asciinema recording -->

Seven languages. Four output formats. No account. No cloud. No LLM. Runs in ~150ms per project.

---

## Why cryptoscope instead of the other tools

Every other scanner is general SAST with a crypto subset bolted on. cryptoscope is crypto-only, built around the NIST post-quantum taxonomy (FIPS 203/204/205, NIST IR 8547), with explicit Harvest-Now-Decrypt-Later (HNDL) flagging baked in from day one. The threat model drives the tool, not the other way around.

That means:

- A finding for `rsa.GenerateKey(rand.Reader, 2048)` carries its NIST IR 8547 deprecation date, not just "weak key."
- A TLS config builder finding tells you whether the negotiated group is already post-quantum or still classical.
- A dependency on `com.nimbusds:nimbus-jose-jwt` surfaces every JWT algorithm variant that touches quantum-vulnerable asymmetric crypto.

The competitive gap is not precision — it is that no other tool ships the NIST taxonomy as first-class data, auditable in a TOML file you can read in ten minutes.

---

## Trust invariants

These four invariants are contractual. They are not configuration options. Any change requires a major version bump.

**P1 — no LLM at runtime.** Detection is purely deterministic: tree-sitter parses your code, TOML rules classify the output. No model call, no network request, no probabilistic black box. The same source file produces the same findings on every machine.

**P2 — no outbound network by default.** The binary opens no sockets unless you pass `--allow-network`, which scopes network access strictly to TLS probes against hosts you explicitly name. The stdio MCP transport uses no socket of any kind.

**P3 — every finding traces to a specific literal.** No "we think you have crypto somewhere." Every finding carries a file path, line number, and the exact code fragment that triggered it. If you cannot find that line in your editor, it is a false positive — file it.

**P4 — never executes your code.** cryptoscope parses with tree-sitter; it never runs your tests, your build scripts, or your binaries. Your untrusted-code sandbox is yours.

The trust invariants are tested directly in `crates/cli/tests/mcp_integration.rs`. The test `test_run_acvp_kats_rejects_code_execution` asserts P4; `test_network_disabled_error` asserts P2.

---

## Quick start

```bash
# Install (Rust 1.96+)
cargo install cryptoscope

# Initialise a project config
cryptoscope init

# Scan source, certs, and dependency manifests
cryptoscope scan .

# Open the HTML report
open reports/cryptoscope.html

# Also emit SARIF for GitHub Advanced Security, a CycloneDX CBOM, and a JSON summary
cryptoscope scan . \
  --sarif  reports/findings.sarif \
  --cbom   reports/cbom.json \
  --html   reports/cryptoscope.html \
  --summary-json reports/summary.json

# Probe a live TLS endpoint (network mode — see Responsible Use below)
cryptoscope scan . --allow-network example.com:443
```

**Pre-built binaries** are available on the [Releases page](https://github.com/udsy19/cryptoscope/releases). The binary is fully static on Linux (musl), single-file on macOS and Windows. No JVM, no Node, no Python runtime, no Docker.

---

## What you will find

cryptoscope detects uses of the following algorithm families across all supported languages:

**Quantum-vulnerable (NIST IR 8547 deprecation scheduled)**
- RSA — key generation, PKCS1, PSS, OAEP; all key sizes
- ECDSA — P-256, P-384, P-521, secp256k1
- ECDH / ECDHE — all named curves
- DSA, DH (classical)

**Hash functions and MACs**
- SHA-1, MD5 (broken-classically flagged)
- SHA-256, SHA-384, SHA-512
- HMAC-SHA* variants (all JWT HS256/HS384/HS512 variants)
- PBKDF2, scrypt, bcrypt, Argon2 (key derivation)

**Symmetric (quantum-safe at >= 256-bit key; flagged at < 256-bit)**
- AES-128, AES-256 — GCM, CBC, ECB, CTR modes
- 3DES, RC4 (broken-classically flagged)
- ChaCha20-Poly1305

**Post-quantum (inventory, not alerts)**
- ML-KEM (FIPS 203 / Kyber)
- ML-DSA (FIPS 204 / Dilithium)
- SLH-DSA (FIPS 205 / SPHINCS+)
- X25519MLKEM768 (hybrid TLS key exchange)

**JWT and authentication**
- JWT alg=none (critical — authentication bypass)
- All JWT RS*/PS*/ES*/HS* algorithm variants
- TLS client and server config builders (classified by negotiated group)

**Dependencies**
- Crypto library declarations in `go.mod`, `Cargo.toml`, `requirements.txt`, `package.json`, `pom.xml`, `*.csproj`

---

## Output formats

**HTML report** — self-contained, auditor-grade. Every finding includes a "Why this matters" explanation tied to NIST IR 8547 policy, a severity rollup, and explicit HNDL flagging for findings that expose data to long-term harvest attacks. Open it in any browser; no server required.

**SARIF 2.1.0** — drop into GitHub Advanced Security (`security-events: write`) or GitLab Advanced Security. Findings appear inline on PRs. Rule IDs (`CRYPTO-NNN`) are stable and documented.

**CycloneDX 1.7 CBOM** — the canonical Crypto Bill of Materials format (ECMA-424 2nd Edition). Round-trips with IBM CBOMkit, Dependency-Track, and every CycloneDX consumer. Use it to track your cryptographic inventory over time and diff it across releases.

**JSON summary** — machine-readable finding counts by severity, ecosystem, and algorithm family. Pipe it into your CI dashboard, Slack alerts, or compliance reports.

**MCP server** — `cryptoscope mcp-serve` exposes every scan verb over newline-delimited JSON-RPC on stdio, following the Model Context Protocol. Agentic clients use this interface to drive the scanner programmatically. The JSON schemas for `Finding`, `CryptoAsset`, and `RiskScore` live in `crates/core/schema/`.

---

## Benchmark numbers

**V12 corpus run — 150 real-world OSS projects across 6 ecosystems:**

| Metric | Value |
|---|---|
| Total findings | 1036 |
| Projects scanned | 150 |
| Wall-clock time | ~22 seconds |
| Avg per project | ~150ms |
| Languages covered | 7 (Go, Python, Java, JavaScript/TypeScript, C/C++, Rust, C#) |

Audit-validated precision: **84.5%** on a stratified 196-finding sample (Wilson 95% CI: 78.5%–89.1%), up from 75.5% in Phase 14a — the largest single-phase gain recorded. Full methodology and per-finding verdicts are in `PRECISION_AUDIT_V3.md`.

Being precise about what that does and does not claim: the point estimate is 84.5%, but the **lower CI bound is 78.5%**, so the scanner does not yet clear an 85% precision floor at 95% confidence. The confidence interval is tighter than prior audits (±5.3 pp vs ±8.6 pp) because the sample is larger. Treat it as defensible for pilot deployments with human triage, not as a claim of 85%.

The benchmark corpus and reproduce script live in `benchmarks/corpus-b-realworld/`. Clone it, run `python3 scan_corpus.py`, and verify the numbers yourself.

---

## How it works

```
cryptoscope scan .
       │
       ├── scan-source   tree-sitter parses 7 languages
       │                 TOML rules: extract → classify
       │                 emits Vec<Finding>
       │
       ├── scan-deps     go.mod / Cargo.toml / pom.xml / package.json / ...
       │                 flags crypto library dependencies as DEP-001
       │
       ├── scan-certs    x509-parser reads PEM + DER
       │                 OID → algorithm_id, weak signature detection
       │
       └── scan-network  rustls TLS prober (--allow-network only)
                         per-group handshakes, ML-KEM group detection
                         │
                         └── core: algorithm table, QuantumRiskScore,
                                    NIST IR 8547 policy → findings ranked
                                    │
                                    ├── report: HTML + SARIF + JSON
                                    ├── cbom:   CycloneDX 1.7
                                    ├── tui:    interactive ratatui explorer
                                    └── cli:    mcp-serve stdio transport
```

**SiteContext (Phase 16)** is the current-generation context-aware filtering pass. Where earlier phases fired on any algorithm-identifier string, Phase 16 requires the match to appear in a cryptographic operation context — a signing call argument, a key constructor, a type parameter — rather than in a parser config array, a test assertion, or a generated protobuf enum table. This is the primary precision driver in the roadmap.

**Rule format.** Rules live in `crates/core/data/rules/<lang>.toml` as two-layer extract-then-classify pairs. The extract layer is a tree-sitter S-expression query; the classify layer maps captured values to an `algorithm_id` from the algorithm table, a severity hint, and a SARIF message template. The format is intentionally schema-compatible with IBMResearch's cryptobom-forge rule files. ~270 rules across 7 files; every one is plain text, readable in under a minute.

---

## Comparison

| | cryptoscope | Snyk Code | GitHub CodeQL | IBM CBOMkit | Semgrep |
|---|---|---|---|---|---|
| PQC-first, NIST IR 8547 taxonomy | Yes | No | No | Partial | No |
| HNDL flagging | Yes | No | No | No | No |
| Local-only, no account | Yes | No (SaaS) | No (SaaS) | Partial | Partial |
| Single binary | Yes | No | No | No | No |
| CycloneDX 1.7 CBOM | Yes | No | No | Yes | No |
| SARIF output | Yes | Yes | Yes | No | Yes |
| MCP server | Yes | No | No | No | No |
| Auditable open rule format | Yes (TOML) | No (binary) | Yes (QL) | No | Yes (YAML) |
| Languages (crypto-specific) | 7 | 7+ | 7+ | Java only | Any |
| Published precision (crypto findings) | 84.5% (196-sample audit) | ~49–76% (published benchmarks) | High (full data-flow) | Not published | Not published |
| Scan speed (150 projects) | ~22s | Cloud-dependent | 5–15 min/repo | Not benchmarked | ~minutes |

**Where CodeQL wins:** CodeQL has full inter-procedural data-flow. It can trace a key from generation through storage to use and flag misuse that a pattern-based scanner cannot see. If you need that depth and can absorb the scan time, CodeQL delivers it. cryptoscope does not attempt to replicate data-flow analysis — it trades that capability for speed, locality, and PQC specificity.

**Where Snyk Code wins:** Snyk has a larger ecosystem of language integrations and a mature CI integration story. If your team already runs Snyk, adding `--crypto` coverage through their platform is lower friction than adopting a new tool. The cost: your code leaves your machine.

**Where cryptoscope wins:** cryptoscope never leaves your machine, ships the NIST taxonomy as auditable data, produces a standards-compliant CBOM, and scans 150 projects in 22 seconds. It is the right starting point for a PQC inventory exercise that needs to stay inside your security boundary.

---

## Architecture

The Rust workspace (`cryptoscope/`) has nine crates, each with one responsibility:

```
crates/
├── core/           Domain types, algorithm table (~67 entries), OID table,
│                   QuantumRiskScore engine, NIST IR 8547 policy presets
├── scan-source/    tree-sitter scanning for 7 languages
├── scan-certs/     x509-parser PEM/DER scanning
├── scan-deps/      Manifest parsers: go.mod, Cargo.toml, requirements.txt,
│                   package.json, pom.xml, *.csproj
├── scan-network/   rustls TLS prober (ML-KEM group detection)
├── cbom/           CycloneDX 1.6/1.7 emitter + embedded schema validator
├── report/         HTML (askama, compile-time), SARIF 2.1.0, JSON summary
├── tui/            ratatui interactive explorer
└── cli/            Single binary entrypoint, mcp-serve stdio transport
```

All primary sources — NIST IR 8547 IPD, FIPS 203/204/205, CycloneDX 1.7 schema, SARIF 2.1.0, IANA TLS group registry, PQC OID assignments — are saved under `knowledge/sources/`. No external fetches required to understand or build the project.

---

## Roadmap

- **Clear 85% at the lower CI bound.** Phase 18 reached an 84.5% point estimate but a 78.5% lower bound. Closing that gap means both raising the point estimate and shrinking the interval with a larger audited sample.
- **Broader language coverage:** C# and C/C++ rule packs are skeletal today; Go and Java are the most complete. Expanding C# and C/C++ classify rules is the highest-leverage near-term coverage move.
- **Community rule packs:** the TOML rule format is public and stable. The path to community contributions is a contributed-rules directory and a CI gate that runs new rules against the benchmark corpus before merge.
- **Agentic remediation:** a companion engine that consumes the MCP output and proposes verified migration patches, gated on ACVP known-answer tests, oqs-provider interop, and semantic-preservation differential testing.
- **Continuous CBOM drift monitoring:** weekly re-scans, CBOM diff between runs, and a one-paragraph alert per material change in your cryptographic inventory.

---

## Responsible use

Network probes (`--allow-network`) open real TCP connections. cryptoscope performs only normal TLS handshakes — no fuzzing, no malformed messages, no exploit attempts. A consent banner prints before any network probe runs.

Source, certificate, and dependency scans are entirely local. They open files for reading; they make no network calls.

Do not probe hosts you do not own or have explicit written authorization to assess.

---

## Contributing

**Add a new detect pattern:** edit `crates/core/data/rules/<lang>.toml`. The extract layer is a tree-sitter S-expression query; the classify layer maps captures to an `algorithm_id` in `crates/core/data/algorithm-table.toml`. Run `cargo test --workspace` and verify no existing snapshot changes unexpectedly.

**Add a new language:** add the tree-sitter grammar to `Cargo.toml`, write a `crates/core/data/rules/<lang>.toml`, and wire the scanner in `crates/scan-source/src/scanner.rs`.

**Add a new manifest type:** write a parser in `crates/scan-deps/src/parsers/` and register it in `catalogue.rs`.

**Tune the risk score:** edit `crates/core/data/default-policy.toml`. Every decision lives in `knowledge/11-decisions/README.md` with the Why and the Evidence.

A `CONTRIBUTING.md` with the full patch workflow, snapshot update instructions, and the benchmark reproduce steps will land before the 0.2 release.

---

## Standards

cryptoscope's outputs and risk model are anchored on primary sources, all saved locally under `knowledge/sources/`:

- **NIST IR 8547 IPD** (November 2024) — deprecation and disallow timeline for classical asymmetric crypto
- **NIST FIPS 203 / 204 / 205** (August 2024) — ML-KEM, ML-DSA, SLH-DSA final standards
- **CycloneDX 1.7** (ECMA-424 2nd Edition, December 2025) — CBOM output format
- **SARIF 2.1.0** (OASIS) — code-scanning interchange for GitHub / GitLab
- **NSA CNSA 2.0** — alternative aggressive migration timeline (`--policy nsa-cnsa2`)
- **RFC 9881 / 9909 / 9935** — IETF LAMPS PQC certificate OIDs

---

## Testing

```bash
# Rust workspace — unit and integration tests
cd cryptoscope && cargo test --workspace

# Live-network tests (requires outbound TCP — skipped by default)
cd cryptoscope && cargo test -p cryptoscope-scan-network -- --ignored

# Knowledge-base consistency checks
python3 tests/check.py
```

---

## License

Apache-2.0. See `cryptoscope/Cargo.toml`.

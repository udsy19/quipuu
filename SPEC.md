# PROJECT SPEC — quipuu (working name; see Decision D-13)

> **Read first:** `knowledge/README.md` → `knowledge/11-decisions/README.md`. Every decision below has a `D-NN` reference. If you have to change one, update the decisions register in the same change.

> **Invariants:** This codebase is governed by four trust invariants (P1–P4) defined in `quipuu/MCP.md §0` and repeated in `README.md`. Any change to P1–P4 is a breaking contract change requiring a major version bump of `contractVersion` in the MCP wire contract.

## 0. Mission

Build the best open-source cryptographic discovery tool in existence. A single, fast, dependency-free binary that scans source code, running TLS services, X.509 certificates, and dependency manifests; identifies every cryptographic asset; scores each for quantum vulnerability against the NIST IR 8547 timeline; and produces (a) a standards-compliant CycloneDX 1.7 CBOM (with `--schema-version 1.6` opt-in), (b) a self-contained HTML report, and (c) machine outputs (JSON / SARIF 2.1.0). Ships with a sophisticated, lightweight TUI.

**Positioning (D-12):** Browsers solved the easy half of the PQC migration. The other half — internal services, dependency trees, certificates, forgotten cron jobs — is the long tail. quipuu finds it in one pass. (NIST NCCoE SP 1800-38B: *"no single product finds all vulnerable crypto."* That's the gap.)

Design tenets, in priority order:

1. **Zero-friction**: one static binary, `brew install` / `curl | sh`, no server, no JVM, no Python runtime. Runs offline. Cross-platform (Linux, macOS, Windows).
2. **Fast**: scan a 1M-LOC monorepo in seconds, fully parallel.
3. **Correct & low-noise**: precise detection, confidence scoring, minimal false positives.
4. **Beautiful**: the TUI and the HTML report should feel like a premium product.
5. **Standards-first**: CBOM output must validate against CycloneDX 1.7 (ECMA-424 2nd Edition) by default, with `--schema-version 1.6` for legacy consumers.

## 1. Tech stack (decided — do not deviate without flagging)

- **Language: Rust** (single static binary, performance, cross-compilation).
- **TUI: `ratatui` + `crossterm`** backend.
- **Source parsing: `tree-sitter`** with per-language grammars (multi-language AST, compiled in, no external deps). Start with: Go, Python. Architecture must make adding a language a matter of dropping in a grammar + a rule pack.
- **TLS scanning: two-tier (D-08)** — rustls 0.23 + aws-lc-rs + tokio-rustls for production codepoints, raw `tokio::net::TcpStream` + `tls-parser` for legacy/draft codepoints.
- **X.509 parsing: `x509-parser 0.18+`** + ship our own PQC OID table (D-09).
- **CLI args: `clap`** (derive API).
- **Serialization: `serde` / `serde_json`**.
- **Concurrency: `rayon`** for CPU-bound file scanning, `tokio` for network I/O.
- **Reporting: self-contained HTML** (inline CSS + inline SVG charts, optional vanilla JS for sorting/filtering). User can print-to-PDF. Do NOT pull a headless browser.

## 2. Architecture (workspace crates)

```
quipuu/
├─ crates/
│  ├─ core/         # domain types: CryptoAsset, Finding, RiskScore, Evidence, Location
│  │                # + the static algorithm-id → nistQuantumSecurityLevel table (D-04)
│  │                # + the OID table (D-09)
│  ├─ scan-source/  # tree-sitter engine + rule packs (per language/library)
│  ├─ scan-network/ # two-tier TLS prober (D-08), cipher/group/sigalg enumeration
│  ├─ scan-certs/   # X.509 + key material analysis (PEM/DER, dirs, hosts)
│  ├─ scan-deps/    # manifest parsers: go.mod, requirements.txt, package.json,
│  │                #   pom.xml, Cargo.toml, *.csproj, Gemfile, etc.
│  ├─ cbom/         # CycloneDX 1.7 builder + 1.6 downgrade emitter + validator (D-01)
│  ├─ report/       # HTML, SARIF 2.1.0 (D-11), JSON
│  ├─ tui/          # ratatui application
│  └─ cli/          # clap entrypoint, wires everything, headless mode
├─ rules/           # declarative TOML detection rules (D-07), embedded via include_dir!
└─ policies/        # policy presets, one TOML each (see `policy list`)
```

**No separate `risk` crate.** The 5-axis QuantumRiskScore engine (D-10) lives at
`core::risk`. The "separate scoring crate" pattern (Grype+Syft, Sentry) is the
right call when scoring normalizes heterogeneous inputs from multiple scanner
backends — CVSS, EPSS, KEV, RustSec metadata. quipuu has one scoring
formula defined in our own data (`default-policy.toml`), tightly coupled to
types in `core` (`AlgorithmRecord`, `Policy`, `Finding`, `QuantumStatus`). A
separate crate would force every dependent type to become `pub` at the `core`
boundary for the sole purpose of being re-imported. Keep it inline.

The **MCP wire contract** (`quipuu/MCP.md`) is the architectural spine between this deterministic Rust workspace and any agent layer. It specifies the stdio JSON-RPC 2.0 transport, the full 11-tool surface, streaming semantics, failure modes, and versioning rules for the `quipuu mcp` subcommand. JSON schemas for the core domain types (`Finding`, `CryptoAsset`, `RiskScore`) live in `crates/core/schema/` and are referenced by `$ref` from the wire contract. No schema definitions are duplicated between the workspace and the contract document.

## 3. The crypto knowledge base (D-04)

A static table in `crates/core/src/algorithm_table.rs` mapping algorithm-id → metadata:

```rust
pub struct AlgorithmRecord {
    pub id: &'static str,                  // canonical, e.g. "rsa-2048"
    pub display_name: &'static str,        // "RSA-2048"
    pub family: AlgorithmFamily,           // RSA, ECDSA, MLKEM, ...
    pub primitive: Primitive,              // pke, signature, kem, hash, ae, ...
    pub classical_security_bits: Option<u32>,
    pub nist_quantum_security_level: Option<u8>,  // 0–6, per CycloneDX 1.7 schema
    pub quantum_status: QuantumStatus,     // BrokenByShor, WeakenedByGrover, QuantumSafe, Broken (classically), PqcDraft
    pub replacement: Option<&'static str>, // recommended PQC replacement algorithm-id
    pub oid: Option<&'static str>,
    pub fips_certified: Option<&'static str>,  // "FIPS 203", "FIPS 204", ...
}
```

Quantum status decision tree:
- **BROKEN_BY_SHOR** (Shor-vulnerable, asymmetric): RSA (all sizes), ECDSA, ECDH, ECIES, DH, DSA, EdDSA, ElGamal, all ECC curves. → `nistQuantumSecurityLevel: 0`.
- **WEAKENED_BY_GROVER** (symmetric/hash, needs larger params): AES-128 → flag (recommend AES-256). AES-192/256, SHA-256/384/512 → retained per NIST IR 8547 §4.1.3 (`knowledge/02-nist-pqc-timeline`).
- **BROKEN_CLASSICALLY**: 3DES, MD5, MD2, SHA-1, DES. Flag as broken regardless of quantum status. Severity = max.
- **QUANTUM_SAFE**: AES-256, SHA-384/512, SHA-3, ChaCha20-Poly1305 (no specific FIPS but unaffected by Shor).
- **PQC_FINAL** (FIPS-final): ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205).
- **PQC_DRAFT** (D-06): FN-DSA / FIPS 206 → flag *"draft standard, not yet final FIPS."*

## 4. Risk-scoring engine (D-10)

`QuantumRiskScore(0–100)` is the additive sum of five axes. Severity bands: ≥75 Critical, 50–74 High, 25–49 Medium, 10–24 Low, <10 Safe.

| Axis | Max | Inputs |
|---|---|---|
| AlgorithmVulnerability | 40 | Quantum-status × classical-broken flag |
| UsageContext | 25 | KEM/long-lived-data = 25; sig-on-ephemeral = 5 |
| DataShelfLife | 15 | Policy file: scope-tag → years bucket |
| Exposure | 10 | Public internet / internal / local |
| DetectionConfidence | 10 | literal-arg=10, type-name=8, variable=5, string-table=2 |

HNDL flagging: any (BROKEN_BY_SHOR ∨ classical-broken) ∧ key-establishment ∧ shelf-life ≥ 7 yr → tag `HNDL-CRITICAL`, surface to top of report.

The report shows the **additive breakdown** for every finding so an auditor can see why a score is what it is. The Rufino et al. (2025) `V × E` interaction limitation is acknowledged in the README; `--scoring multiplicative` flag is reserved for v2.

## 5. Policy file (D-05)

`policy.toml` controls every adjustable threshold:

```toml
[deprecation]
# NIST IR 8547 IPD values; final not yet published as of mid-2026.
asymmetric_112bit_deprecated_after = 2030
asymmetric_112bit_disallowed_after = 2035
asymmetric_128bit_plus_disallowed_after = 2035
aes_128_acceptable = true   # NIST retains; CNSA 2.0 disallows (use preset)

[shelf_life_buckets]
ephemeral = 0
short = 3      # < 7 years
medium = 10    # 7–30 years
long = 15      # ≥ 30 years

[shelf_life_tags]
# repo-scoped overrides — e.g. "this folder protects 30-year medical records"
"./services/medical/**" = "long"
"./scratch/**" = "ephemeral"

[exposure]
public_internet = 10
internal_service = 4
local_only = 1
```

Built-in presets selectable via `--policy nist-default | nsa-cnsa2`; `--policy <file.toml>` takes a profile of your own. `quipuu policy list` is the authoritative list — `core::policy::PRESETS` is the single source of truth and `documented_preset_names_match_the_shipped_ones` fails the build if this line drifts from it. Report header always names the policy in force.

## 6. Scanners — required behavior

### scan-source

Walk a directory (respect `.gitignore`, `--exclude`), parse each file with the right tree-sitter grammar, run the rule pack, emit Findings with precise Location + Evidence + extracted params. Detect: crypto API calls, hardcoded algorithm strings, cipher suite configs, JWT alg fields, vendored crypto libraries.

Parallelize across files with rayon. Stream results to the TUI as they're found.

**Rule format (D-07):** declarative TOML, two-layer. Layer 1 (`extract`) records the intended tree-sitter S-expression query, capture groups, and primitive value-extractors (literal-int, literal-string, parse-split, ident-resolve) for each call shape. The queries are documentation: they are not executed, and matching is performed by the hand-written walker in `scan-source/src/scanner.rs`. A build gate keeps the two layers consistent by failing when a `classify` rule names an `api` no matcher emits. Layer 2 (`classify`) maps `(algo, keysize, curve, mode, padding, …)` tuples to canonical algorithm-ids. The classify layer's tuple-based pattern draws on cryptobom-forge's (Santandersecurityresearch/cryptobom-forge, not CBOMkit) published YAML (`knowledge/sources/cryptobom-forge-cryptocheck_schema.json`) as prior art; the two schemas use different field names and are not file-format compatible.

### scan-network (D-08)

Given host(s)/CIDR/port(s), perform TLS handshakes enumerating: protocol versions (flag TLS < 1.2), cipher suites, key-exchange groups (flag classical ECDH/DH; detect X25519MLKEM768 / SecP256r1MLKEM768 / SecP384r1MLKEM1024 as GOOD; flag X25519Kyber768Draft00 as legacy), and signature algorithms.

Two-tier prober. Production codepoints use rustls 0.23 + aws-lc-rs with per-probe `CryptoProvider`. Legacy/draft codepoints (0x6399 Kyber draft, draft ML-DSA sig-algs 0x0904–0x0906) use raw `tokio::net::TcpStream` + manual ClientHello serialization + `tls-parser` for ServerHello parsing.

Be a good citizen. Defaults: **5 concurrent connections/host, 10 s connect timeout, 10 s handshake timeout, 3 retries, exponential back-off from 1 s, no inter-connection delay.** CLI prints a scope/consent banner before any network probe. NEVER do anything exploit-like — handshake enumeration only.

### scan-certs (D-09)

Parse PEM/DER from files, directories, or live hosts. Use `x509-parser 0.18+`. Ship the static OID table covering classical (45+ OIDs from RFCs) + PQC (NIST CSOR + LAMPS composite arcs). Extract public-key algorithm + size, signature algorithm, validity, key usage. Flag weak signature algs (`md2WithRSAEncryption`, `md5WithRSAEncryption`, `sha1WithRSAEncryption`, `ecdsa-with-SHA1`, `id-dsa-with-sha1`). Walk the chain and report each level.

### scan-deps

Parse dependency manifests; match known cryptographic libraries against an embedded catalog; record library + version as crypto-relevant components in the CBOM via the `provides` relationship (D-03 / D-10 in `knowledge/01-cbom-schema` §10). Detect OpenSSL ≥ 3.5 as a positive signal (native PQC available).

## 7. CBOM output (D-01, D-02, D-03)

Emit CycloneDX 1.7 JSON by default (`bomFormat: "CycloneDX"`, `specVersion: "1.7"`). `--schema-version 1.6` produces a 1.6-compatible BOM (no 1.7-only fields like `algorithmFamily`, `ellipticCurve`, `relatedCryptographicAssets`).

Each crypto asset = a component with `type: "cryptographic-asset"` and `cryptoProperties` (note: `cryptoProperties`, NOT `cryptographicProperties`):

- `assetType`: one of `algorithm | certificate | protocol | related-crypto-material`
- `algorithmProperties`: `primitive` (enum, see `knowledge/01-cbom-schema` §5a), `parameterSetIdentifier`, `executionEnvironment`, `cryptoFunctions` (enum, §5b), `nistQuantumSecurityLevel`, `classicalSecurityLevel`, plus 1.7-only `algorithmFamily`, `ellipticCurve`
- `oid` where known

Use `evidence.occurrences[]` + `evidence.callstack.frames[]` (D-02) for file/line/symbol/snippet provenance. Use inline `protocolProperties.cipherSuites[].algorithms` bom-ref arrays (D-03) for TLS protocol → algorithm linkage. Use `dependencies[].provides` for library → algorithm relationships.

**bom-ref convention** (from official CBOM example): `crypto/{algorithm|certificate|protocol|key}/{name}@{oid-or-hash}`.

**Built-in validator** validates the emitted JSON against the embedded `bom-1.7.schema.json` / `bom-1.6.schema.json` and exits non-zero if invalid. Both schemas ship inside the binary.

## 8. SARIF output (D-11)

`quipuu scan ... --format sarif` emits a single SARIF 2.1.0 file:

- Always emit `automationDetails.id` (unique per run).
- Rule IDs `CRYPTO-001` … `CRYPTO-999`, stable across releases. Rule metadata includes `name`, `shortDescription`, `fullDescription`, `helpUri` (link to our docs), `defaultConfiguration.level`, `properties.security-severity` (on the rule, not the result).
- Severity mapping: Critical → `level: error`, `security-severity: "9.0"`; High → `error`, `"8.0"`; Medium → `warning`, `"5.0"`; Low → `note`, `"3.0"`; Safe → `note`, `"3.0"`. A finding whose `algorithm_id` has no algorithm-table row is **unscored** and maps to `level: none` — SARIF's "the concept of severity does not apply to this result" — with `security-severity` **omitted rather than zeroed**, since GitHub bands on that number. It previously mapped to `warning` / `"5.0"`, which asserted a mid-band severity the risk engine never computed.
- `partialFingerprints.primaryLocationLineHash` = SHA-256(`ruleId:snippet`)[:16].
- Cross-ref CBOM: each result has `properties."quipuu/cbom-ref": "<bom-ref>"`.
- No `fix` objects in v1.
- GitLab 18.11+ ingests SARIF natively; for older GitLab, `quipuu report --format gitlab-sast` produces `gl-sast-report.json`.

## 9. The TUI (`tui/`)

A `ratatui` app that is the signature experience. Requirements:

- **Live scan dashboard**: real-time progress (files/hosts scanned, assets found), animated, with a streaming findings feed.
- **Multi-pane explorer** (after scan):
  - Left: tree/list of findings grouped by Risk tier (Critical/High/Medium/Low/Safe), by asset type, or by location. Toggleable grouping.
  - Right: detail pane — full evidence, snippet with offending line highlighted, algorithm metadata, why it's vulnerable, deprecation dates from policy file, recommended PQC replacement.
  - Top: summary KPIs (total assets, % quantum-vulnerable, HNDL-critical count, countdown to active policy's next deadline).
- **Fuzzy search/filter** (`/` to filter), vim-style keybindings (j/k/g/G), sortable by risk. `e` exports report.
- Inline bar chart / gauge widgets showing risk distribution.
- Polished theme: cohesive palette, rounded borders, clear typographic hierarchy. Respect `NO_COLOR` and degrade gracefully on small terminals.
- Headless mode (`--no-tui` / `--json` / `--format`) for CI.

## 10. Report generator (`report/`) — auditor-grade

Generate a **single self-contained `.html` file** with:

- Executive summary: overall posture, headline numbers, risk distribution donut (inline SVG), HNDL-critical callouts, countdown to active policy's next deadline.
- Prioritized risk register table (sortable/filterable via tiny JS), severity-colored, with the **score-breakdown columns visible** (per D-10).
- Per-finding detail: location, evidence snippet, algorithm, why vulnerable, recommended migration (specific PQC replacement), effort hint.
- Compliance mapping section (NIST IR 8547 IPD / CNSA 2.0 / UK NCSC milestones, **policy preset in force named in the header**).
- Methodology + scope + timestamp + tool version + policy file hash (for audit defensibility).
- Branded, print-to-PDF clean (proper `@media print` CSS).

Also emits: `cbom.json` (CycloneDX 1.7 or 1.6), `findings.sarif`, `summary.json`.

## 11. CLI design (`cli/`)

```
quipuu scan <path>                          # source scan, opens TUI
quipuu scan <path> --no-tui --format json   # headless
quipuu scan --net 10.0.0.0/24 --ports 443,8443
quipuu scan ./certs/ --certs                # certs IN ADDITION to source + deps
quipuu scan <path> --all                    # source + deps + (opt) net/certs
quipuu report --in cbom.json --out report.html
quipuu report --in cbom.json --format gitlab-sast
quipuu validate cbom.json                   # CBOM schema validation
quipuu policy list                          # nist-default | nsa-cnsa2
```

Flags: `--rules <dir>`, `--exclude <glob>`, `--format {tui,json,sarif,html,cbom,gitlab-sast}`, `--schema-version {1.7,1.6}`, `--policy <file-or-preset>`, `--fail-on {critical,high,medium,low,safe,policy,none}` (CI gate), `--config <file>`, `--no-color`, `-v`.

`scan` takes one or more paths, interleaved with flags in any order, because the pre-commit hook appends the staged file list after its configured `args`.

Exit codes: `0` scan completed and no `--fail-on` threshold was met; `1` the threshold was met (a reported finding is at or above it), or an output file could not be written; `2` quipuu refused to run — unparseable `--fail-on` value, missing path, or `--net` without `--allow-network`. `--fail-on policy` resolves to the active policy's `[ci] fail_on`.

## 12. Build order (sequential milestones; keep `main` green)

1. Workspace + `core` domain types + the algorithm table + OID table + policy loader + unit tests.
2. `scan-source` for **Go and Python** first (matches/beats CBOMkit), ~15 high-value rules each. Headless JSON output.
3. `cbom` builder + dual-schema validator (1.6 + 1.7).
4. `core::risk` engine + prioritized register.
5. `report` HTML generator.
6. `tui` — live scan + explorer.
7. `scan-certs`, then `scan-network` (two-tier prober), then `scan-deps`.
8. Add languages: Java, JS/TS, C/C++, Rust, C#.
9. Polish: themes, perf pass, fixtures (build a `fixtures/` corpus including the BF-CBOM benchmark codebases), golden-file tests, docs.

## 13. Quality bar

- Per-rule unit tests + **golden-file tests** on fixture repos + CBOM schema-validation tests + SARIF schema-validation tests + snapshot tests for reports.
- Benchmarks (criterion) to keep the "scan 1M LOC in seconds" promise.
- `cargo clippy` clean, `cargo fmt`, deny warnings in CI.
- Reproducible cross-platform release builds (GitHub Actions matrix: linux-musl static, macOS arm64/x64, windows). `install.sh`, Homebrew formula stub.
- README: asciinema/GIF of the TUI, quickstart, "what this does / does not do," responsible-use notice for network scanning.

## 14. Explicit non-goals (v1)

- No automated code remediation / PR generation.
- No live exploitation — handshake / inventory only.
- No phone-home / telemetry. Fully local. (State this loudly in the README — it's a trust feature.)

## 15. First task for Claude Code

The data files are already written. They live at:

```
knowledge/11-decisions/data/
├── README.md                    — what's here and how to consume it
├── algorithm-table.toml         — 67 algorithms (D-04, D-06)
├── oid-table.toml               — 57 OIDs (D-09)
├── default-policy.toml          — NIST IR 8547 IPD defaults (D-05, D-10)
└── rules/
    ├── go.toml                  — 8 extract + 17 classify (D-07)
    └── python.toml              — 8 extract + 26 classify (D-07)
```

All parse, all cross-references resolve.

**Scaffold task:** Create the Cargo workspace per §2. In `core`:

1. Define Rust structs matching the TOML shapes (`AlgorithmRecord`, `OidMapping`, `Policy`, `ExtractRule`, `ClassifyRule`).
2. Use `include_str!("../../../knowledge/11-decisions/data/algorithm-table.toml")` + `toml::from_str` at build time. Same for the OID table and default policy. (When the project moves out of the analysis repo, copy `data/` into `crates/core/data/`.)
3. Implement the algorithm-id resolver: given a key (algorithm-id string, OID, or modulus-length-disambiguated RSA), return the canonical `AlgorithmRecord`.
4. Implement the policy loader: read `--policy <file>` or built-in preset; validate weights sum to 100.
5. Implement `QuantumRiskScore::compute(finding, policy) -> u8` per §4.

Then a walking-skeleton `scan-source` that loads `rules/go.toml` + `rules/python.toml`, runs the extract layer against a fixture directory, applies the classify layer, and emits findings as JSON validated against the embedded CycloneDX 1.7 schema.

After that, iterate per §12 (CBOM emitter → risk engine → HTML report → TUI → scan-certs → scan-network).

---

## References to knowledge base

| SPEC section | Knowledge folder | Decision IDs |
|---|---|---|
| §1 tech stack | 04-tls-pqc, 05-x509-pqc | D-08, D-09 |
| §2 architecture | all | all |
| §3 algorithm table | 02-nist-pqc-timeline | D-04, D-06 |
| §4 risk engine | 06-hndl-threat-model | D-10 |
| §5 policy file | 02-nist-pqc-timeline, 09-regulatory | D-05 |
| §6 scanners | 03-detection-patterns, 04-tls-pqc, 05-x509-pqc | D-07, D-08, D-09 |
| §7 CBOM | 01-cbom-schema | D-01, D-02, D-03 |
| §8 SARIF | 07-sarif | D-11 |
| §11 CLI | — | — |
| Scope framing | 11-decisions | D-12 |
| Working name | 11-decisions | D-13 |

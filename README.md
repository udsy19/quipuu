# seawall

**A single Rust binary that finds the cryptography in your codebase, classifies each finding against NIST's post-quantum migration timeline, and tells you exactly which ones a quantum adversary can harvest today.** It detects constructors and key-generation sites precisely rather than every call site exhaustively — [measured recall is below](#benchmark-numbers).

```bash
cargo install seawall
seawall scan .
open reports/seawall.html
```

<!-- TODO: add screenshot or asciinema recording -->

Seven languages. Four output formats. No account. No cloud. No LLM. Median project scans in 285ms.

> **Formerly `cryptoscope`.** The project was renamed to `seawall` in August 2026, before its first
> release. A seawall is built *before* the tide arrives — which is the Harvest-Now-Decrypt-Later
> argument exactly: the harvesting is happening now, the decryption comes later. The old name
> collided with an unrelated post-quantum crate already published on crates.io, so nothing was ever
> released under it. There is no migration to do.

---

## Why seawall instead of the other tools

Every other scanner is general SAST with a crypto subset bolted on. seawall is crypto-only, built around the NIST post-quantum taxonomy (FIPS 203/204/205, NIST IR 8547), with explicit Harvest-Now-Decrypt-Later (HNDL) flagging baked in from day one. The threat model drives the tool, not the other way around.

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

**P4 — never executes your code.** seawall parses with tree-sitter; it never runs your tests, your build scripts, or your binaries. Your untrusted-code sandbox is yours.

The trust invariants are tested directly in `crates/cli/tests/mcp_integration.rs`. The test `test_run_acvp_kats_rejects_code_execution` asserts P4; `test_network_disabled_error` asserts P2.

---

## Quick start

```bash
# Install (Rust 1.96+)
cargo install seawall

# Initialise a project config
seawall init

# Scan source, certs, and dependency manifests
seawall scan .

# Open the HTML report
open reports/seawall.html

# Also emit SARIF for GitHub Advanced Security, a CycloneDX CBOM, and a JSON summary
seawall scan . \
  --sarif  reports/findings.sarif \
  --cbom   reports/cbom.json \
  --html   reports/seawall.html \
  --summary-json reports/summary.json

# Probe a live TLS endpoint (network mode — see Responsible Use below)
seawall scan . --allow-network example.com:443

# Score against a policy profile other than the NIST IR 8547 default
seawall policy list
seawall scan . --policy nsa-cnsa2
```

**Policy profiles.** `--policy` takes a built-in preset name or a path to a
policy TOML file; `seawall policy list` prints what is built in. Two presets
ship today:

| Preset | Profile | What changes |
|---|---|---|
| `nist-default` | NIST IR 8547 IPD (Nov 2024) — the default | — |
| `nsa-cnsa2` | NSA CNSA 2.0, for national security systems | CNSA 2.0 approves AES-256 and SHA-384+ only, so SHA-256 and ChaCha20-Poly1305 stop being quantum-safe inventory and become findings, AES-128 is scored as off-suite rather than Grover-weakened, and SLH-DSA / FN-DSA / the sub-1024 ML-KEM and ML-DSA parameter sets are reported as non-compliant |

A policy reweights findings; it never creates, drops, or reclassifies a
detection. Measured on the 150-project benchmark corpus: the two profiles
produce the **same 898 findings**, of which **80 (8.9 %) land in a different
severity band**. The precision figure below therefore holds under both.

**Pre-built binaries** are available on the [Releases page](https://github.com/udsy19/seawall/releases). The binary is fully static on Linux (musl), single-file on macOS and Windows. No JVM, no Node, no Python runtime, no Docker.

---

## What you will find

seawall detects uses of the following algorithm families. Coverage is per rule
pack, not uniform across languages — the RustCrypto `des`/`rc4` crates, for one, have
no rules yet. What each language actually classifies is the `[[classify]]` list in
`seawall/crates/core/data/rules/<lang>.toml`, and a build gate
(`every_classify_rule_targets_an_api_the_extractor_can_emit`) fails when a rule there
names an API no extractor emits, so the file cannot list a detection the binary does
not perform.

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

*What is verified:* the HNDL flag is **computed from the active policy's `[hndl_flag]` block**, not asserted. Until 2026-08-28 it was not computed at all: every scanner wrote a hard-coded `false` and `summary.json.totals.hndl_critical` was `0` for every input. Today an X.509 certificate whose public key is a key-agreement key — the fixture is X25519, OID `1.3.101.110` — is flagged, and the same certificate's long-lived *signature* is not. **The scope is certificate findings.** Source and dependency findings still report zero, because `scan-source` fixes two of the flag's three inputs (`usage_context`, `shelf_life_bucket`) at compile time; over the 150-project benchmark corpus the count is **0 of 1570** (all 150 scanned, none errored). Making it non-zero there means making those axes vary, which moves severity bands across the whole corpus, and that is a calibration change we have not made. Gated by `hndl_critical_is_reachable_end_to_end` and three sibling checks in `crates/cli/tests/hndl_flag.rs`.

**SARIF 2.1.0** — drop into GitHub Advanced Security (`security-events: write`) or GitLab Advanced Security. Findings appear inline on PRs. Rule IDs (`CRYPTO-NNN`) are stable and documented.

*What is verified:* the `run` object carries the SARIF 2.1.0 property `automationDetails`. We emitted `runAutomationDetails` — the schema's *type* name — until 2026-08-28, and because `run` declares `additionalProperties: false`, every SARIF file we produced was invalid against the schema it named in its own `$schema`. Corrected at all nine sites and gated by `sarif_run_object_uses_the_property_name_not_the_type_name`, which checks the emitted document *and* the tree, so a doc page cannot teach the wrong key back into the code. **The schema violation is what is measured.** The GitHub behaviour of overwriting prior uploads for the same commit is documented ingest semantics, not a reproduced upload — we have not run this against a repo with `security-events: write`.

**CycloneDX 1.7 CBOM** — the canonical Crypto Bill of Materials format (ECMA-424 2nd Edition). Use it to track your cryptographic inventory over time and diff it across releases.

*What is verified:* a build gate emits one component for every algorithm in the table and validates it against the schema the BOM declares — **0 errors at 1.7, 0 errors at 1.6** (`--schema-version 1.6`), against the schemas vendored in `crates/cbom/data/`. **1.7 output is not 1.6-compatible:** `algorithmFamily` is a 1.7-only field, and offering default output to a 1.6 validator produces **77 errors** — one for each of the 77 components (of 92) that carry a canonical family. A consumer pinned to 1.6 needs `--schema-version 1.6`. Measured 2026-08-28 by `every_algorithm_emits_a_bom_valid_at_the_version_it_declares`. We have not tested ingestion by any third-party consumer, and no longer claim to.

**JSON summary** — machine-readable finding counts by severity, ecosystem, and algorithm family. Pipe it into your CI dashboard, Slack alerts, or compliance reports.

**MCP server** — `seawall mcp-serve` exposes every scan verb over newline-delimited JSON-RPC on stdio, following the Model Context Protocol. Agentic clients use this interface to drive the scanner programmatically. The JSON schemas for `Finding`, `CryptoAsset`, and `RiskScore` live in `crates/core/schema/`.

---

## Benchmark numbers

**Corpus B — 150 real-world OSS projects across 6 ecosystems, all 150 with a populated working tree:**

| Metric | Value |
|---|---|
| Total findings | 1570 |
| Projects scanned | 150 of 150, **0 errored** |
| Wall-clock time | 367s (6m 08s) for all 150 |
| Per project | median 285ms · mean 2448ms · p90 1.7s · max 144.5s |
| Languages covered | 7 (Go, Python, Java, JavaScript/TypeScript, C/C++, Rust, C#) |

Every row above comes from **one run**: `python3 scan_corpus.py --include-safe`, flags
`--source --deps --include-safe`, profile `nist-default`, release build, single-threaded,
on **2 cores of an AMD EPYC 9354P with 7 GB RAM**, 2026-08-28. It wrote
`results/summary.json`. `results/all_findings.json` is the per-finding dump from
`dump_findings.py` under the same binary, flags and corpus; the two agree at **1570** by
independent count, and that population is what the precision figure below is sampled from.

**Read the mean and the median as different facts.** The 8.6× gap between them is three
repositories: `aws-sdk-go-v2` alone takes 144.5s, and with `aws-sdk-go` and `wolfssl` the
top three account for 58% of the total wall-clock. **117 of 150 projects finish in under a
second.** The mean describes a corpus deliberately stocked with vendored AWS SDKs; the
median describes a project. Neither is the number to quote alone.

**Wall-clock on this box moves between runs.** A second full pass the same day, under
`regression_check.py`, came in at **329.0s** against the 367.4s above — same corpus, same
binary, same finding count, ~10% apart on two shared cores. Read the whole-corpus figure as
"about six minutes", not as three significant figures. The finding counts do not move: both
runs produced exactly 1570.

**These figures replace a published `~22s / ~150ms`, which was wrong.** That pair came from
`results/summary.json` at `include_safe:false`, in a run where **9 of 150 clones were
missing** — so it timed 141 projects and found 1036, while the 1570 printed beside it came
from a different, complete run under different flags. It was also taken on unnamed hardware,
not the machine named above, and `BENCHMARKING_RESULTS.md` reported the same run as
*1194 findings in 23.3s*, so the two source documents never agreed either. We are not
claiming the scanner got 16× slower; we are retracting a number that described 141 projects,
under one flag set, on an unnamed machine, and presenting one that names all three.

Audit-validated precision: **85.3%** (95% CI: 81.3%–89.3%) — measured 2026-08-28 on an **audited sample of 362 findings**, not on all 1570. Methodology, the full label set and per-finding verdicts are in `BENCHMARKING_RESULTS.md` and `PRECISION_AUDIT_V3.md`.

**What that interval is.** A two-stratum weighted estimate over 362 findings audited by opening every cited `file:line` — 272 rows from the 964-finding stratum that has been scanned since the beginning, 90 from the 606-finding stratum restored in the 2026-08-27 corpus repair. The interval is the stratified normal approximation `Var = Σ wᵢ² pᵢ(1−pᵢ)/nᵢ`, not a Wilson interval on a pooled sample, which is what earlier revisions of this line called it. The lower bound is 81.3%, so this is not a claim of 85%.

**What the denominator excludes.** `precision = TP / (TP + FP)`. The 362 audited rows are **287 TP, 47 FP and 28 DEPENDS**; the 28 DEPENDS rows — **7.7% of the sample** — are excluded from both sides rather than counted either way. A DEPENDS row is one whose operation is real but whose `algorithm_id` asserts a parameter the cited line does not state, typically an RSA modulus supplied by a caller. Scoring all 28 as false positives instead gives **79.0%** — which is where an independent audit of the same labels landed, and it is a convention difference, not a contradiction. Scoring them all as true positives gives **86.3%**. Every figure in the history table below uses the same exclusion, so they are comparable to each other — and any figure quoted against a scanner that uses a different convention is not.

**Why this number moved, twice.** The figures published here before — 84.5%, then 85.2% and 87.1% — were measured against a corpus in which **46 of the 150 projects had empty working trees**. `clone_all.sh` clones `--no-checkout`, and the manifest's `commit_sha` pins had been shuffled across project files, so the checkout failed, printed a warning, and the project was still counted as cloned. Those numbers were taken on a biased two-thirds sample. Re-measured on the fully populated corpus the same scanner gave **81.8%** — lower, and published as such, because a benchmark you cannot reproduce is worth nothing.

**85.3% is a real gain on top of that corrected baseline, not a return to the old number.** It comes from suppressing one false-positive shape: a JOSE algorithm-registry lookup such as `jwa.LookupSignatureAlgorithm("PS256")`, which retrieves a descriptor from a table and was being reported as a quantum-vulnerable signing operation. 34 findings were removed, every one of them labelled a false positive by hand, and no true positive was lost.

### Recall, published beside precision

**Go-only line-exact recall: 74.4%** — 303 of 407 in-scope `crypto/*` standard-library call sites, measured 2026-08-28 on the same corpus-B dump as the precision figure above. **This is a Go number and is not a recall figure for a seven-language tool**; no equivalent ground truth exists yet for the other six packs.

Ground truth is built independently of our own rule files, by scanning the 25 Go corpus projects for 33 quantum-relevant stdlib APIs and requiring the matching `crypto/*` import, so it cannot inherit our blind spots. Reproduce with `python3 recall_check.py --clones DIR --dump results/all_findings.json`, which scores against a `dump_findings.py` artifact so recall is measured on exactly the finding set the precision audit samples.

**The shape is the finding, not the headline.** Recall by API kind splits cleanly:

| API kind | in-scope sites | found | recall |
|---|---|---|---|
| Generators and constructors (`rsa.GenerateKey`, `ecdsa.GenerateKey`, `ed25519.GenerateKey`, `ecdh.*`, `md5.New`, `sha1.New`, `des.NewTripleDESCipher`, `rc4.NewCipher`) | 325 | 301 | **92.6%** |
| Operations (`ecdsa.Sign`, `ecdsa.Verify`, `rsa.SignPSS`, `rsa.VerifyPKCS1v15`, `ed25519.Sign`, `dsa.Sign`, `md5.Sum`, `sha1.Sum`, …) | 82 | 2 | **2.4%** |

Every signer and every verifier is at **0.0%** across twelve families, and so is every one-shot digest (`md5.Sum`, `sha1.Sum`). The only two operation sites we find at all are one `rsa.EncryptOAEP` and one `rsa.DecryptOAEP`. That is the extract layer working as designed: it carries 59 `[[extract]]` blocks against 280 `[[classify]]` arms, and they are almost all constructors. **A constructor-only extractor earns precision by declining exactly the ambiguous shapes.** 85.3% precision and 74.4% recall are the same architectural fact reported twice — trust invariant P3 (every finding resolves to a real `file:line`) is what makes the trade deliberate rather than accidental.

**A second denominator, which bounds the benchmark rather than the tool.** Those 407 sites are the ones inside the subtrees the harness actually hands to the scanner. Over the whole Go clone tree the ground truth is **1054 sites**, so **647 (61.4%) sit outside every scanned subtree and are never looked at**. The harness restricts 92 of 150 projects to `scan_hints.scan_paths`. Recall against the whole tree would read 28.7%, and neither number should be quoted without saying which denominator it uses.

The benchmark corpus and reproduce scripts live in `benchmarks/corpus-b-realworld/`. Run `./clone_all.sh`, then `python3 scan_corpus.py --include-safe` for the speed and finding counts, `python3 dump_findings.py` for the per-finding dump the precision audit samples, and `python3 recall_check.py` for the recall figures; all three take `--clones` if the corpus lives outside the repo. Verify the numbers yourself.

---

## How it works

```
seawall scan .
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

**Rule format.** Rules live in `crates/core/data/rules/<lang>.toml` as two-layer extract-then-classify pairs. The classify layer maps captured values to an `algorithm_id` from the algorithm table, a severity hint, and a SARIF message template; it is the live layer and the source of truth for classification. The extract layer records the intended tree-sitter S-expression for each call shape, but the queries are not executed — matching is done by a hand-written walker in `scan-source/src/scanner.rs`, and a build gate fails when a classify rule names an API that walker cannot emit. The format is intentionally schema-compatible with IBMResearch's cryptobom-forge rule files. 59 extract blocks and 280 classify arms across 7 files; every one is plain text, readable in under a minute.

---

## Comparison

| | seawall | Snyk Code | GitHub CodeQL | IBM CBOMkit | Semgrep |
|---|---|---|---|---|---|
| PQC-first, NIST IR 8547 taxonomy | Yes | No | No | Partial | No |
| HNDL flagging | Yes (certificate key establishment; scope stated under Output formats) | No | No | No | No |
| Local-only, no account | Yes | No (SaaS) | No (SaaS) | Partial | Partial |
| Single binary | Yes | No | No | No | No |
| CycloneDX 1.7 CBOM | Yes | No | No | Yes | No |
| SARIF output | Yes | Yes | Yes | No | Yes |
| MCP server | Yes | No | No | No | No |
| Auditable open rule format | Yes (TOML) | No (binary) | Yes (QL) | No | Yes (YAML) |
| Languages (crypto-specific) | 7 | 7+ | 7+ | Java only | Any |
| Published precision (crypto findings) | 85.3% (audited sample of 362, DEPENDS excluded) | ~49–76% (published benchmarks) | High (full data-flow) | Not published | Not published |
| Published recall | 74.4% (Go stdlib, 303/407 in-scope sites) | Not published | Not published | Not published | Not published |
| Scan speed | 285ms median project; 367s for the 150-project corpus (2 cores) | Cloud-dependent | 5–15 min/repo | Not benchmarked | ~minutes |

**Where CodeQL wins:** CodeQL has full inter-procedural data-flow. It can trace a key from generation through storage to use and flag misuse that a pattern-based scanner cannot see. If you need that depth and can absorb the scan time, CodeQL delivers it. seawall does not attempt to replicate data-flow analysis — it trades that capability for speed, locality, and PQC specificity.

**Where Snyk Code wins:** Snyk has a larger ecosystem of language integrations and a mature CI integration story. If your team already runs Snyk, adding `--crypto` coverage through their platform is lower friction than adopting a new tool. The cost: your code leaves your machine.

**Where seawall wins:** seawall never leaves your machine, ships the NIST taxonomy as auditable data, produces a standards-compliant CBOM, and scans a typical project in under a third of a second. It is the right starting point for a PQC inventory exercise that needs to stay inside your security boundary.

---

## Architecture

The Rust workspace (`seawall/`) has nine crates, each with one responsibility:

```
crates/
├── core/           Domain types, algorithm table (92 entries), OID table,
│                   QuantumRiskScore engine, policy presets (nist-default,
│                   nsa-cnsa2)
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

Network probes (`--allow-network`) open real TCP connections. seawall performs only normal TLS handshakes — no fuzzing, no malformed messages, no exploit attempts. A consent banner prints before any network probe runs.

Source, certificate, and dependency scans are entirely local. They open files for reading; they make no network calls.

Do not probe hosts you do not own or have explicit written authorization to assess.

---

## Contributing

**Add a new detect pattern:** edit `crates/core/data/rules/<lang>.toml`. The extract layer is a tree-sitter S-expression query; the classify layer maps captures to an `algorithm_id` in `crates/core/data/algorithm-table.toml`. Run `cargo test --workspace` and verify no existing snapshot changes unexpectedly.

**Add a new language:** add the tree-sitter grammar to `Cargo.toml`, write a `crates/core/data/rules/<lang>.toml`, and wire the scanner in `crates/scan-source/src/scanner.rs`.

**Add a new manifest type:** write a parser in `crates/scan-deps/src/parsers/` and register it in `catalogue.rs`.

**Tune the risk score:** edit `crates/core/data/default-policy.toml`, or add a
profile under `crates/core/data/policies/` and register it in the `PRESETS`
table in `crates/core/src/policy.rs`. Every decision lives in `knowledge/11-decisions/README.md` with the Why and the Evidence.

A `CONTRIBUTING.md` with the full patch workflow, snapshot update instructions, and the benchmark reproduce steps will land before the 0.2 release.

---

## Standards

seawall's outputs and risk model are anchored on primary sources, all saved locally under `knowledge/sources/`:

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
cd seawall && cargo test --workspace

# Live-network tests (requires outbound TCP — skipped by default)
cd seawall && cargo test -p seawall-scan-network -- --ignored

# Knowledge-base consistency checks
python3 tests/check.py
```

---

## License

Apache-2.0. See `seawall/Cargo.toml`.

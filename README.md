# cryptoscope

> A single static binary that finds every piece of cryptography in your codebase, your dependencies, your X.509 certificates, and your TLS endpoints — then classifies each against NIST's post-quantum migration timeline and produces a CycloneDX 1.7 CBOM, a SARIF file, and an auditor-grade HTML report.

**Status:** v0.1 — walking skeleton. The four scanners, the risk engine, and every output format work end-to-end against real fixtures and live hosts. PQC TLS group probing is Tier-1 only (deferred to v0.2 — see `[VERIFY]` markers in `crates/scan-network/`).

---

## Positioning

Browsers solved the easy half of the PQC migration. As of mid-2026, [~65% of human web traffic to Cloudflare is post-quantum-encrypted](knowledge/10-design-partners/README.md), Chrome / Firefox / iOS ship X25519MLKEM768 by default, and OpenSSL 3.5 has native ML-KEM. The other half — internal services, dependency trees, X.509 certificates, forgotten cron jobs — is the **long tail**.

The NIST NCCoE's reference architecture for cryptographic discovery states it plainly: *"no single product finds all vulnerable crypto."* That's the gap cryptoscope fills.

| What cryptoscope does | Why it matters |
|---|---|
| **Source code** — tree-sitter parses Go and Python (more langs coming) for RSA / ECDSA / EdDSA / DH / classical hashes | Finds the code that *generates* keys, not just the deployed result |
| **X.509 certificates** — PEM/DER files, OID → algorithm-id classification, weak signature flagging | Catches the long-lived signing material that doesn't show up in handshake traces |
| **Dependency manifests** — `go.mod`, `Cargo.toml`, `requirements.txt`, `package.json`, `pom.xml` | The crypto library is the upper bound on what's possible to use; flag it before the developer reaches for it |
| **TLS endpoints** — rustls-driven per-group probes against `host:port` | What does the server *actually accept*, not just what's documented |
| **Standards-compliant CBOM output** — CycloneDX 1.7 (ECMA-424 2nd Edition) or 1.6 | Round-trips with IBM CBOMkit, Dependency-Track, every CycloneDX consumer |
| **Risk prioritisation** — 5-axis additive `QuantumRiskScore` mapped to NIST IR 8547 IPD policy | One number per finding, full additive breakdown in every report — no black-box scoring |
| **Multiple report formats** — auditor-grade HTML (askama, self-contained), SARIF 2.1.0 (GitHub / GitLab), summary JSON | Hand to a CISO, ingest into GitHub Advanced Security, parse in CI |

---

## Quickstart

```bash
# Build (Rust 1.96+; install via rustup if needed)
cd cryptoscope
cargo build --release

# Scan a codebase (default: source + deps)
./target/release/cryptoscope scan ./my-project

# Add cert + dep scanning + emit every output format
./target/release/cryptoscope scan ./my-project \
  --certs \
  --deps \
  --cbom out.cbom.json \
  --html out.html \
  --sarif out.sarif \
  --summary-json out.summary.json

# Probe a TLS endpoint (network mode — see Responsible Use below)
./target/release/cryptoscope scan ./my-project --net example.com:443

# Open the interactive TUI explorer
./target/release/cryptoscope scan ./my-project --tui
```

---

## How it works

```
                ┌─────────────────────────────────────────────────────┐
                │   cryptoscope-core    (algorithm table 67 entries,   │
                │                        OID table 57 entries,         │
                │                        nist-default policy,          │
                │                        QuantumRiskScore engine)      │
                └──┬──────────────────────────────────────────────────┘
   scan-source ────┤  → Vec<Finding>  ─┐
   scan-certs  ────┤                    │
   scan-deps   ────┤                    ├──→  cryptoscope-cbom    → CycloneDX 1.6/1.7 JSON
   scan-network────┘                    ├──→  cryptoscope-report  → SARIF 2.1.0 + HTML + summary JSON
                                        └──→  cryptoscope-tui     → interactive ratatui explorer
```

Every scanner emits a `Finding` carrying `algorithm_id`, file/line provenance, and contextual signals (usage, exposure, shelf-life bucket). The risk engine looks each up in the algorithm table, computes the 5-axis score per the active policy, and feeds the result to whichever emitter you asked for.

The five score axes (full breakdown is visible in every output):

| Axis | Max | Inputs |
|---|---|---|
| AlgorithmVulnerability | 40 | Quantum status × broken-classically flag |
| UsageContext | 25 | KEM/signature/auth, ephemeral vs. long-lived |
| DataShelfLife | 15 | Policy file: scope-glob → years bucket |
| Exposure | 10 | Public-internet / internal / local |
| DetectionConfidence | 10 | Literal arg / type name / variable / string table |

Bands: ≥75 Critical, 50–74 High, 25–49 Medium, 10–24 Low, <10 Safe.

---

## Project layout

```
cryptoscope/
├── SPEC.md                     ← Build spec, every section traces to a D-NN decision
├── knowledge/                  ← Research artifacts — primary-source citations only
│   ├── 01-cbom-schema/         ← CycloneDX 1.6 + 1.7 verbatim
│   ├── 02-nist-pqc-timeline/   ← NIST IR 8547 IPD, FIPS 203/204/205, CNSA 2.0
│   ├── 03-detection-patterns/  ← tree-sitter rule format + CBOMkit interop
│   ├── 04-tls-pqc/             ← IANA TLS supported-groups + signature schemes
│   ├── 05-x509-pqc/            ← PQC X.509 OIDs (RFC 9881/9909/9935)
│   ├── 06-hndl-threat-model/   ← Mosca's inequality, primary-source HNDL definitions
│   ├── 07-sarif/               ← SARIF 2.1.0 for GitHub + GitLab ingestion
│   ├── 08-competitors/         ← IBM CBOMkit, foxguard, SandboxAQ, …
│   ├── 09-regulatory/          ← OMB M-23-02, EU CRA, UK NCSC, CNSA 2.0
│   ├── 10-design-partners/     ← Cloudflare, Apple, AWS, Microsoft PQC programs
│   ├── 11-decisions/           ← 13 Why → Evidence → Decision entries + data files
│   └── sources/                ← Downloaded primary documents (PDFs, schemas, CSVs)
├── tests/                      ← Analysis-phase Python checks (45 tests)
└── cryptoscope/                ← Rust workspace
    ├── Cargo.toml              ← Workspace manifest, all deps pre-pinned
    └── crates/
        ├── core/               ← Domain types, algorithm/OID tables, policy, risk engine
        ├── scan-source/        ← tree-sitter (Go + Python)
        ├── scan-certs/         ← x509-parser (PEM + DER)
        ├── scan-deps/          ← go.mod, Cargo.toml, requirements.txt, package.json, pom.xml
        ├── scan-network/       ← rustls TLS prober
        ├── cbom/               ← CycloneDX 1.6/1.7 emitter + embedded schema validator
        ├── report/             ← HTML (askama) + SARIF 2.1.0 + summary JSON
        ├── tui/                ← ratatui live + explorer
        └── cli/                ← Single binary entrypoint
```

---

## Responsible use

Network probes open real TCP connections to the target host. cryptoscope is **inventory-only** — it performs only normal TLS handshakes, no fuzzing, no malformed messages, no exploit attempts. Specifically:

- One handshake per probe; per-group enumeration sends *N* handshakes for *N* groups (10 in v0.1).
- Concurrency capped at 5 connections per host. Connect timeout 5 s, handshake timeout 10 s. Defaults follow SSLyze 3.x conventions.
- A consent banner prints before any network probe runs: *"opening TCP connections to N target(s) — inventory only, no exploit attempts."*
- The cert verifier accepts every chain (we're discovering, not authenticating). The CLI runs `scan-certs` alongside `scan-network` to surface chain issues.
- **Do not probe hosts you don't own or have explicit authorization to assess.** Many jurisdictions treat unauthorised TLS probing as access without permission.

Source/cert/dep scans are local-only — they never call out to the network.

---

## What this does NOT do (v0.1)

- No automated code remediation / PR generation. Reports tell you what to replace and with what; the actual edit is yours.
- No exploit attempts on network probes — handshakes only.
- No phone-home. No telemetry. Fully offline. (This is a trust property, not a feature flag — there is no network code outside `scan-network`.)
- Java, JS/TS, C/C++, Rust, C# source-code rules are not yet shipped — Go and Python only at v0.1. The two-layer rule format (D-07) is the path to adding more.
- PQC TLS group probing is Tier-1 only — the rustls `ring` backend doesn't ship ML-KEM. Tier-2 swap to `aws-lc-rs` is `[VERIFY]`-marked for v0.2.
- No CIDR / port-range network sweeps. One `host:port` at a time.

---

## Testing

```bash
# Rust workspace (offline)
cd cryptoscope && cargo test --workspace

# Live-network tests (requires outbound TCP)
cd cryptoscope && cargo test -p cryptoscope-scan-network -- --ignored

# Analysis-phase checks on the knowledge base + data files
python3 tests/check.py
```

As of this commit: **80 Rust unit/integration tests** + 3 live-network tests + **45 Python checks** = 128 passing tests.

---

## Building the binary

```bash
rustup install 1.96
cd cryptoscope
cargo build --release
./target/release/cryptoscope --version
```

The binary is fully static on Linux (musl), single-file on macOS and Windows. No JVM, no Node, no Python runtime, no Docker required.

---

## Contributing

The architecture is data-driven:

- **Add a new algorithm** → edit `knowledge/11-decisions/data/algorithm-table.toml`, run `python3 tests/check.py`, copy to `cryptoscope/crates/core/data/algorithm-table.toml`.
- **Add a new language** → drop a `crates/core/data/rules/<lang>.toml` with two-layer rules (extract + classify), wire the tree-sitter grammar in `crates/scan-source/src/scanner.rs`.
- **Add a manifest type** → write a parser in `crates/scan-deps/src/parsers/`, register it in `catalogue.rs`.
- **Tune the risk score** → edit the policy preset in `crates/core/data/default-policy.toml`.

Every decision lives at `knowledge/11-decisions/README.md` with the Why and the Evidence. Don't change behaviour without updating the decision.

---

## Standards & references

cryptoscope's outputs and risk model are anchored on:

- **CycloneDX 1.7** (ECMA-424 2nd Edition, December 2025) — primary CBOM output format
- **NIST IR 8547 IPD** (November 2024) — deprecation / disallow timeline for classical asymmetric crypto
- **NIST FIPS 203 / 204 / 205** — ML-KEM, ML-DSA, SLH-DSA (final, August 2024)
- **SARIF 2.1.0** (OASIS) — code-scanning interchange
- **NSA CNSA 2.0** — alternative aggressive timeline (`--policy nsa-cnsa2`)
- **RFC 9881 / 9909 / 9935** — IETF LAMPS PQC certificate OIDs

All primary sources are saved locally under `knowledge/sources/` — no external dependencies for understanding the project.

---

## License

Apache-2.0.

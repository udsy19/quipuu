# Decisions Register

Every load-bearing build decision for quipuu, in **Why → Evidence → Decision** form. Each entry links back to the knowledge folder that established the evidence. If new evidence later contradicts a decision, update it here first, then ripple through SPEC.md.

> **How to read this:** "Why" is the question the decision answers. "Evidence" is what we learned in the research pass that forces the answer. "Decision" is what we'll do in v1. "Revisit when" is the trigger to re-open the decision.

---

## D-01 — Target CycloneDX 1.7 as primary; emit 1.6 on `--schema-version 1.6`

**Why:** We need to choose a CBOM schema version. Wrong choice cuts us off from the ecosystem.

**Evidence:**
- CycloneDX 1.7 was released October 2025, ratified as **ECMA-424 2nd Edition December 2025** (`knowledge/01-cbom-schema`).
- The official `CycloneDX/bom-examples/CBOM/Protocol/bom.json` example uses `specVersion: "1.7"` — the canonical CBOM example already moved.
- **cdxgen defaults to 1.7** (the most-installed CBOM emitter — `npm i -g @cyclonedx/cdxgen`).
- 1.7 adds `algorithmFamily`, `ellipticCurve`, `relatedCryptographicAssets`, a `key-wrap` primitive, and lifecycle fields on certificates. All are useful to us.
- 1.6 remains supported by every parser in the ecosystem (cyclonedx-go, sbom-utility, IBM CBOMkit). 1.6 is also still ECMA-424 (1st Edition).

**Decision:** Default emitter target is **CycloneDX 1.7**. CLI flag `--schema-version 1.6` downgrades emission (skip 1.7-only fields, fall back to `signatureAlgorithmRef` / `subjectPublicKeyRef` for cert links). Validate every emitted BOM against the schema embedded in the binary before writing it out.

**Revisit when:** CycloneDX 1.8 ships, or a major consumer (Dependency-Track, IBM CBOMkit, GitHub SBOM API) declares one version end-of-life.

---

## D-02 — Use `componentEvidence.occurrences[]` + `callstack.frames[]` for file/line provenance

**Why:** Auditor-grade reporting requires file+line provenance per finding. The first research pass left this unresolved.

**Evidence:**
- Canonical `bom-1.6.schema.json` at `definitions.componentEvidence.properties.occurrences.items` defines exactly: `bom-ref, location, line (integer ≥ 0), offset (integer ≥ 0), symbol, additionalContext`. `location` is the only required field (`knowledge/01-cbom-schema` §9).
- The same definition also exposes `callstack.frames[]` with `package, module, function, parameters, line, column, fullFilename` — even richer than occurrences.
- Schema is identical in 1.6 and 1.7 for this subtree.

**Decision:** Every quipuu finding emits:
- `occurrences[]` entry with `location` = relative path, `line` = 1-based, `offset` = byte offset, `symbol` = API name matched, `additionalContext` = 1–3-line snippet (sanitized).
- When tree-sitter gives us full call-site context, also emit `callstack.frames[0]` with `package, module, function, line, column, fullFilename`.

**Revisit when:** Schema definition for `componentEvidence` changes in a future CycloneDX release.

---

## D-03 — Express TLS protocol→algorithm linkage via `protocolProperties.cipherSuites[].algorithms` bom-ref arrays

**Why:** First research pass refuted (incorrectly) the use of inline `algorithms[]` arrays. We need to know the canonical convention so the network scanner emits valid TLS CBOM.

**Evidence:**
- The official `CycloneDX/bom-examples/CBOM/Protocol/bom.json` (`knowledge/sources/cbom-protocol-example.json`, `knowledge/01-cbom-schema` §3) uses inline `cipherSuites[].algorithms` arrays containing bom-refs of the algorithm components. No top-level `dependencies` section is used for this linkage.
- The schema's `cipherSuite.algorithms` field type is `array of refType`, confirming.
- The bom-ref naming convention in the official example: `crypto/{algorithm|certificate|protocol|key}/{name}@{oid-or-hash}`.

**Decision:** TLS findings emit a `protocol` component with `protocolProperties.cipherSuites[].algorithms[]` listing bom-refs of the algorithm components. Use the official convention for bom-ref strings. Reserve `dependencies[]` for **library → algorithm** relationships (use `provides` per `knowledge/01-cbom-schema` §10).

---

## D-04 — `nistQuantumSecurityLevel` policy: hard-code the canonical 0–6 mapping; never invent

**Why:** Every algorithm component must carry the right `nistQuantumSecurityLevel`. Wrong values undermine the entire risk engine.

**Evidence:**
- `bom-1.6.schema.json` defines `nistQuantumSecurityLevel: { type: integer, minimum: 0, maximum: 6 }` with documented anchor: NIST PQC standardization security category page (`knowledge/01-cbom-schema` §4c).
- Official example: AES-256-GCM = 1, SHA-384 = 2, RSA-PKCS1-SHA512 = 0, X25519 = absent (which spec treats as unspecified, not 0). All quantum-vulnerable asymmetric (RSA / ECDSA / ECDH / DH / EdDSA) maps to **0** (`knowledge/02-nist-pqc-timeline`).
- NIST categories 1–5 are anchored to AES-128 / SHA-256 / AES-192 / SHA-384 / AES-256. Category 6 is reserved with no NIST definition.

**Decision:** Ship a static table mapping algorithm-id → `nistQuantumSecurityLevel` in `knowledge/11-decisions/algorithm-table.toml` (to be created by Claude Code during implementation). Quantum-vulnerable asymmetric → 0. Symmetric/hash table anchored on NIST categories. PQC algorithms (ML-KEM-512 → 1, ML-KEM-768 → 3, ML-KEM-1024 → 5; ML-DSA-44 → 2, ML-DSA-65 → 3, ML-DSA-87 → 5; SLH-DSA per parameter set) per FIPS 203/204/205.

---

## D-05 — Treat NIST IR 8547 dates as **policy values, not constants**

**Why:** IR 8547 is *still IPD as of mid-2026* (comment period closed Jan 2025, no final yet). Hard-coding 2030/2035 is technically betting on a draft.

**Evidence:**
- `knowledge/02-nist-pqc-timeline` §1: NIST IR 8547 status confirmed IPD as of 2026-06-12. SP 800-131A Rev 3 also IPD.
- CNSA 2.0 (NSA) is more aggressive than NIST: requires AES-256 only, SHA-384 minimum, exclusive PQC for networking/firmware by 2030 (`knowledge/02-nist-pqc-timeline`).
- UK NCSC's 2028 Phase 1 ("full discovery exercise") is the tightest national deadline today (`knowledge/09-regulatory`).
- Australia ASD ISM-1917 is the only currently-binding hard deadline globally: ML-KEM-1024/ML-DSA-87 by 2030 (`knowledge/09-regulatory`).

**Decision:** Ship a default `policy.toml` shipping NIST IR 8547 IPD values as the default. CLI accepts `--policy <file>` to override. Provide named presets, one TOML each under `crates/core/data/policies/`. Shipped as of Phase 19: `nist-default` (IR 8547 IPD) and `nsa-cnsa2` (CNSA 2.0 for NSS). `uk-ncsc`, `au-asd-ism` and `eu-cra` were listed here in June 2026 and are **not** shipped — a preset is only added once its algorithm verdicts trace to a primary source held in `knowledge/09-regulatory/`. Every report header prints the policy in force ("Risk classified per NIST IR 8547 IPD, Nov 2024").

**Revisit when:** IR 8547 reaches final, or any major regulator publishes a binding deadline that supersedes ours.

---

## D-06 — FN-DSA / FIPS 206 detections flagged as "draft standard, not yet final"

**Why:** Even though FN-DSA is the fourth NIST PQC signature algorithm, FIPS 206 is *not finalized* (not even IPD as of mid-2026).

**Evidence:**
- `knowledge/02-nist-pqc-timeline` §1: FIPS 206 presented at NIST's 6th PQC Conference (Sept 2025) but still in DoC clearance. No published IPD.
- `knowledge/05-x509-pqc` §2: No FN-DSA OIDs assigned yet; IETF drafts use `XX` placeholders.
- NSA CNSA 2.0 does **not** include FN-DSA (only ML-KEM and ML-DSA at parameter sets 87 / 1024).

**Decision:** Recognize FN-DSA-512 / FN-DSA-1024 by name but emit a separate severity class (`pqc-draft`, not `pqc-approved`). Report copy: *"FALCON/FN-DSA is selected for FIPS 206 but the standard is not yet published."* No `nistQuantumSecurityLevel` set (absent rather than 0).

**Revisit when:** FIPS 206 IPD published, or final FIPS 206 published.

---

## D-07 — Detection-rule format: declarative TOML, two-layer (extract → classify)

**Why:** Rules are the moat. The format must be human-editable, AST-aware, embeddable in the binary, AND let third parties extend without recompiling.

**Evidence:**
- `knowledge/03-detection-patterns`: cryptobom-forge's YAML rule layer is **classification only** (operates on extracted tuples). IBM Sonar-cryptography uses an in-code Java builder DSL — code, not data. CBOMkit's published rule schema (saved at `knowledge/sources/cryptobom-forge-cryptocheck_schema.json`) is the closest published prior art and is small (1.8 KB).
- Java has a unique need: `Cipher.getInstance("AES/ECB/NoPadding")` encodes three fields in one string — needs a string-split primitive.
- Rust is easiest: type-path matches (`Aes256Gcm`, `Sha256`) encode everything; no value propagation needed.

**Decision:** Two-layer declarative rules, in TOML (matches Cargo / pyproject conventions; ships in the binary via `include_dir!`).
- **Layer 1 — extract:** A rule names a language, gives a tree-sitter S-expression query, names the capture groups, and specifies primitive value-extraction primitives (literal-int, literal-string, parse-split, ident-resolve).
- **Layer 2 — classify:** A rule maps `(algo, keysize, curve, mode, padding, …)` tuples to canonical algorithm-ids and severity. This is the layer CBOMkit publishes, and we'll be schema-compatible there for round-tripping.

`--rules <dir>` overrides built-in. CBOMkit-format YAML accepted as input (their library.yml + cryptocheck_rules.yml) so we inherit their algorithm taxonomy and 70+-name library for free.

---

## D-08 — Two-tier TLS prober: rustls `CryptoProvider` for production groups, raw bytes for synthetic codepoints

**Why:** To enumerate which TLS groups/suites/sig-algs a server *accepts*, we need to send single-entry ClientHellos. Rustls is high-level and enforces consistency; raw bytes let us probe deprecated/draft codepoints (0x6399 Kyber draft, future PQC sigs).

**Evidence:**
- `knowledge/04-tls-pqc` §3–4: rustls 0.23.40 (current) exposes `CryptoProvider.kx_groups` as a public `Vec<&'static dyn SupportedKxGroup>`. Order = preference advertised. ML-KEM is in rustls core since 0.23.22.
- rustls **does NOT** allow arbitrary ClientHello extensions / out-of-spec codepoints. For those, use `tokio::net::TcpStream` + manually serialized TLS bytes + `tls-parser` for response parsing.
- IANA codepoints to probe (`knowledge/04-tls-pqc` §1–2): X25519MLKEM768 (0x11EC), SecP256r1MLKEM768 (0x11EB), SecP384r1MLKEM1024 (0x11ED), X25519Kyber768Draft00 (0x6399, deprecated), X25519 (0x001D), secp256r1 (0x0017), secp384r1 (0x0018). Plus ML-DSA sig-algs 0x0904–0x0906 (draft, raw-byte probe).
- Nmap's `ssl-enum-ciphers` chunks suites in groups of 64 per ClientHello — uses ~one connection per 64 suites, not one per suite. SSLyze caps at 5 concurrent connections per host.

**Decision:** **Tier 1** — for production codepoints, use rustls 0.23 + aws-lc-rs with per-probe `CryptoProvider`. **Tier 2** — for legacy/synthetic codepoints, manually serialize ClientHello + raw `tokio::net::TcpStream`. Use `tls-parser` for ServerHello parsing in both tiers. Default: 5 concurrent connections/host, 10 s connect timeout, 10 s handshake timeout, 3 retries, exponential back-off from 1 s, no inter-connection delay. CLI prints a scope/consent banner before any network probe.

---

## D-09 — `x509-parser` v0.18+ for cert parsing; ship our own PQC OID table

**Why:** Need a Rust crate that parses PEM/DER and exposes algorithm OIDs. PQC OIDs are too new for any registry crate.

**Evidence:**
- `knowledge/05-x509-pqc` §5: `x509-parser` v0.18.1 (Feb 2026) parses RFC 5280 X.509 v3 fully. Returns PQC keys as `PublicKey::Unknown(&[u8])` — graceful, not a crash.
- No Rust crate (oid-registry, rasn, x509-parser, picky) ships PQC OIDs natively. We have to maintain our own.
- All needed PQC OIDs are RFC-finalized as of mid-2026 (`knowledge/05-x509-pqc` §2):
  - ML-KEM: `2.16.840.1.101.3.4.4.{1,2,3}` (RFC 9935)
  - ML-DSA: `2.16.840.1.101.3.4.3.{17,18,19}` (RFC 9881)
  - SLH-DSA: `2.16.840.1.101.3.4.3.{20..31}` pure + `{35..46}` pre-hash (RFC 9909)
  - Composite sigs: `1.3.6.1.5.5.7.6.{37..54}` (draft, RFC editor queue)

**Decision:** Depend on `x509-parser 0.18` for parsing. Ship a static `OID -> AlgorithmRecord` table in `crates/core/src/algorithm_oids.rs` covering classical (45+ OIDs from RFCs) + PQC (NIST CSOR arc + LAMPS composite arc). Keep `BROKEN`/`WEAK` flags: `md2WithRSAEncryption`, `md5WithRSAEncryption`, `sha1WithRSAEncryption`, `ecdsa-with-SHA1`, `id-dsa-with-sha1` (all explicitly flagged after CA/B Forum SC097 in Feb 2026 finalized SHA-1 sub-CA revocation).

---

## D-10 — Risk scoring formula: 5-axis additive, but log V×E interaction limitation

**Why:** Need a defensible, configurable HNDL-aware risk score that we can map to severities.

**Evidence:**
- `knowledge/06-hndl-threat-model` §1: HNDL is named explicitly in NIST IR 8547, M-23-02, NSA CNSA 2.0, UK NCSC, ENISA (the only retitle is ENISA's "retrospective decryption"). All agree key-establishment is the HNDL primary axis.
- Mosca's inequality `X + Y > Z` (`knowledge/06-hndl-threat-model` §2) is the math. Planning Z = 2030–2035 is the policy consensus, not engineering ground truth.
- The only peer-reviewed HNDL scoring paper (Rufino et al., arXiv:2605.22569, 2025) flags additive scoring as missing the `V × E` interaction (Corollary 1). We're going additive anyway because (a) configurable, (b) explainable in the report, (c) auditable. We document the limitation.
- Sector regulatory floors (HIPAA 6yr, OSHA 30yr, NARA classified 25+yr) anchor the data-shelf-life dimension.

**Decision:** Composite `QuantumRiskScore (0–100)` =
- `AlgorithmVulnerability(0–40)` — Shor-broken asymmetric = 40, classically broken (MD5, SHA-1, DES) = 40, Grover-weak symmetric (AES-128) = 15, PQC-approved = 0, FN-DSA-draft = 5.
- `UsageContext(0–25)` — KEM/key-establishment for long-lived data = 25, signature-on-ephemeral = 5.
- `DataShelfLife(0–15)` — ≥30 yr = 15, 7–30 yr = 10, <7 yr = 3, ephemeral = 0. Driven by policy file (scope-tag → shelf-life).
- `Exposure(0–10)` — public-internet = 10, internal-service = 4, local-only = 1.
- `DetectionConfidence(0–10)` — literal-arg = 10, type-name-only = 8, variable propagation = 5, string-table = 2.

Severity bands: ≥75 Critical, 50–74 High, 25–49 Medium, 10–24 Low, <10 Safe. Report shows the additive breakdown. `--scoring multiplicative` flag reserved for v2.

---

## D-11 — SARIF emitter: defaults locked, partial-fingerprints via SHA-256-prefix line hash

**Why:** Reliable GitHub Advanced Security ingestion is the killer-app distribution channel for the open-source build. SARIF defaults that don't ingest = no signal.

**Evidence (from `knowledge/07-sarif`):**
- GitHub limits: 10 MB compressed file, 25,000 results accepted / 5,000 displayed. Multi-run uploads need unique `automationDetails.id`.
- `security-severity` lives on the **rule**, not the result. GitHub UI buckets: 9.0–10.0 Critical, 7.0–8.9 High, 4.0–6.9 Medium, 0.1–3.9 Low.
- `partialFingerprints.primaryLocationLineHash` is the de-dup primitive GitHub uses. Recommended algorithm: SHA-256 of `ruleId:snippet`, first 16 hex chars.
- GitLab ingests native SARIF only in 18.11+ behind the `sarif_ingestion` feature flag. For older GitLab, convert to `gl-sast-report.json`.
- No existing tool (including CodeQL) cross-references CBOM bom-refs from SARIF. We get to set the convention.

**Decision:**
- Always emit `automationDetails.id`.
- Severity mapping: Critical → `level: error`, `security-severity: "9.0"`; High → `error` / `"8.0"`; Medium → `warning` / `"5.0"`; Low → `note` / `"3.0"`.
- `partialFingerprints.primaryLocationLineHash` = SHA-256(`ruleId:snippet`)[:16].
- Rule IDs: `CRYPTO-001`–`CRYPTO-999`, stable across releases.
- Cross-ref CBOM via `properties.quipuu/cbom-ref` on each result (set the convention).
- No `fix` objects in v1 (PQC migration is not a mechanical substitution).
- Document GitLab 18.11+ requirement in the README; ship a converter sub-command (`quipuu report --format gitlab-sast`) for older GitLab.

---

## D-12 — Wedge framing: position on "the long tail", not "the cliff"

**Why:** Browser PQC is *already deployed*. The "quantum cliff" narrative is partially closed and increasingly dated. We need positioning that survives the next news cycle.

**Evidence:**
- Adoption telemetry: Cloudflare >50% of human web traffic PQC-encrypted Oct 2025; >65% April 2026. Chrome 131+, Firefox 132+, iOS 26 default-on. OpenSSL 3.5 (Apr 2025) ships native ML-KEM/ML-DSA/SLH-DSA.
- Same source: signature migration (ECDSA, P-256 auth paths) is the universal **unsolved** problem. KEM is solved.
- NIST NCCoE SP 1800-38B explicitly states *"no single product finds all vulnerable crypto."* (NCCoE SP 1800-38B).
- Meta has the most sophisticated internal monitoring (FBCrypto + Crypto Visibility) and *admits* it misses shadow dependencies.
- Competitive landscape: foxguard (Rust, source + TLS config + CBOM) is the closest open-source threat. None of {IBM CBOMkit, cryptobom-forge, SandboxAQ, PANW, QSecure, QuantumXC, Qtonic, Zerberus, Acubed, CryptoScan/CSNP} ship the full {source + net + cert + dep + risk + binary} bundle in one tool.

**Decision:** Reposition the headline. Old: *"the nmap of cryptography"* (still unclaimed, keep as tagline). New thesis: **"Browsers solved the easy half. The other half — your internal services, your dependency tree, your certificates, your forgotten cron jobs — is where the long tail lives. quipuu finds it in one pass."** Lean on the NCCoE quote in marketing copy. Track foxguard.

---

## D-13 — Working name: **KEEP `quipuu`** (resolved 2026-06-12, see `verify-resolution.md` V-05)

**Why:** Make sure the chosen name is clean across crates.io, GitHub, Homebrew, and doesn't collide with a real PQC/SBOM/scanner tool.

**Evidence (resolved):**
- crates.io API for `quipuu` → **available**, no crate published.
- GitHub: 119 repos search-match `quipuu`, but the top by stars is a 1-star cryptocurrency trading bot. None are crypto-asset/CBOM scanners.
- The neighbour we worried about — `csnp/cryptoscan` (singular) — is a different name in a different repo, not a real collision.
- Backup names checked and available on crates.io: `cbomx`, `qsight`, `pqfind`, `qbom`, `cryptotrace`, `pqsight`, `qx-scan`, `kx-scan`.
- `pqaudit` is taken (35-download active TLS scanner, March 2026). Avoid.

**Decision:** **Keep `quipuu`.** Register the crates.io name and the GitHub org **before** any public code lands. Pinned backup name: **`cbomx`** (short, descriptive, distinctive) if `quipuu` becomes contested at publication time.

**Status:** RESOLVED. SPEC.md does not need to be renamed.

---

## Quick-reference table

| ID | Decision | Source folder |
|---|---|---|
| D-01 | Emit CycloneDX 1.7 default, 1.6 via flag | 01-cbom-schema |
| D-02 | File/line provenance via occurrences + callstack | 01-cbom-schema |
| D-03 | TLS protocol→algorithm via inline cipherSuites.algorithms | 01-cbom-schema |
| D-04 | Static algorithm-id → nistQuantumSecurityLevel table | 02-nist-pqc-timeline |
| D-05 | NIST IR 8547 dates as policy file, not constants | 02-nist-pqc-timeline / 09-regulatory |
| D-06 | FN-DSA flagged "draft", separate severity | 02-nist-pqc-timeline / 05-x509-pqc |
| D-07 | Two-layer TOML rules; CBOMkit-compatible classification | 03-detection-patterns |
| D-08 | Two-tier TLS prober (rustls + raw bytes) | 04-tls-pqc |
| D-09 | x509-parser 0.18+ + ship our own PQC OID table | 05-x509-pqc |
| D-10 | 5-axis additive QuantumRiskScore | 06-hndl-threat-model |
| D-11 | SARIF defaults + SHA-256 partial-fingerprints | 07-sarif |
| D-12 | Reposition: "long tail", not "cliff" | 10-design-partners |
| D-13 | Rename — "quipuu" collides with existing tools | 08-competitors |

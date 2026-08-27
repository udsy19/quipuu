# VERIFY items — resolved

All `[VERIFY]` items flagged in the knowledge base have been resolved. Sources are saved in `knowledge/sources/` where relevant.

---

## V-01 — Pure MLKEM768 standalone TLS group: REGISTERED

**Question (`knowledge/04-tls-pqc`):** Is pure MLKEM768 in the IANA TLS Supported Groups registry, or still draft-only?

**Source:** `knowledge/sources/iana-tls-supported-groups.csv` (downloaded from IANA `tls-parameters-8.csv`, mid-2026)

**Answer:** **Registered.** Three standalone ML-KEM groups exist in the official registry:

| Decimal | Name | DTLS-OK | Recommended | Reference |
|---|---|---|---|---|
| 512 | MLKEM512 | Y | N | draft-connolly-tls-mlkem-key-agreement-05 |
| 513 | MLKEM768 | Y | N | draft-connolly-tls-mlkem-key-agreement-05 |
| 514 | MLKEM1024 | Y | N | draft-connolly-tls-mlkem-key-agreement-05 |

`Recommended: N` because the underlying draft is not yet RFC-published; the **codepoints are formally allocated**, however.

Three hybrids also live in the registry from `draft-ietf-tls-ecdhe-mlkem-04`:

| Decimal | Name | Recommended |
|---|---|---|
| 4587 | SecP256r1MLKEM768 | N |
| 4588 | X25519MLKEM768 | N |
| 4589 | SecP384r1MLKEM1024 | N |

Plus the obsolete pre-standard entries (4590 curveSM2MLKEM768, 25497/25498 Kyber Draft00 marked `D` for deprecated).

**Impact on the build:** seawall's network prober should enumerate **all six** PQC TLS groups (3 pure + 3 hybrids), plus the two deprecated codepoints (so we can *flag* legacy deployments). Updates `knowledge/04-tls-pqc` §1 (`[VERIFY]` removed).

---

## V-02 — `rustls-post-quantum` crate: 0.2.4, last updated 2025-09-23, superseded

**Question (`knowledge/04-tls-pqc`):** Confirm latest version.

**Source:** crates.io API for `rustls-post-quantum` (`https://crates.io/api/v1/crates/rustls-post-quantum`)

**Answer:** **0.2.4**, published **2025-09-23**. No updates in ~9 months. Description: *"Experimental support for post-quantum key exchange in rustls"*. The crate's purpose is **superseded** by built-in PQC in rustls core (which has X25519MLKEM768 as a default key exchange group since rustls 0.23.27).

**Impact on the build:** We do **not** depend on `rustls-post-quantum`. Use rustls 0.23.x directly with `prefer-post-quantum` feature flag (on by default) for production groups. For finer control (single-group ClientHello probes, raw codepoint enumeration), use rustls 0.23's `CryptoProvider` `kx_groups` field directly. Updates `knowledge/04-tls-pqc` §3.

---

## V-03 — Composite ML-DSA TLS codepoints: still TBD

**Question (`knowledge/05-x509-pqc`):** Are composite ML-DSA TLS signature codepoints assigned by IANA?

**Source:** [draft-reddy-tls-composite-mldsa-10 (datatracker.ietf.org)](https://datatracker.ietf.org/doc/draft-reddy-tls-composite-mldsa/) — latest revision dated 2026-05-14, expires 2026-11-15.

**Answer:** **All codepoints remain unassigned.** The draft requests 15 new entries (TBD1–TBD15: composite ML-DSA-44/65/87 with ECDSA-P256/384/521, Ed25519/448, and RSA-PSS variants), but no numeric values are allocated. Document is **individual submission**, not a WG draft, IESG state "I-D Exists."

The IANA TLS SignatureScheme registry (`knowledge/sources/iana-tls-signaturescheme.csv`) confirms: range **0x0907–0x0910 is "Unassigned"** — these are the slots the composite draft eventually targets. Range 0x091D–0x09FF is also unassigned.

**Note (positive):** The *pure* ML-DSA and SLH-DSA signature schemes **are** in the registry:

| Hex | Name | Reference |
|---|---|---|
| 0x0904 | mldsa44 | draft-ietf-tls-mldsa-00 |
| 0x0905 | mldsa65 | draft-ietf-tls-mldsa-00 |
| 0x0906 | mldsa87 | draft-ietf-tls-mldsa-00 |
| 0x0911–0x091C | slhdsa_sha2_{128,192,256}{s,f}, slhdsa_shake_{128,192,256}{s,f} | draft-reddy-tls-slhdsa-01 |

All `Recommended: N` (drafts not yet RFC). Codepoints formally allocated.

**Impact on the build:** Seawall's network prober supports the 15 pure ML-DSA/SLH-DSA signature codepoints. Composite ML-DSA support deferred until IANA allocates real numbers. Updates `knowledge/05-x509-pqc` §2 (`[VERIFY]` removed for pure entries; composite kept as `[DRAFT-TBD]`).

---

## V-04 — foxguard direct feature walkthrough

**Question (competitive landscape):** Direct feature-matrix walkthrough of foxguard's current GitHub head.

**Source:** [github.com/0sec-labs/foxguard](https://github.com/0sec-labs/foxguard) README, fetched 2026-06-12. **267 stars.**

**Feature matrix:**

| Capability | foxguard | seawall (planned) |
|---|---|---|
| Source-code scan | JS/TS, Python, Go, Ruby, Java, PHP, Rust, C#, Swift, Kotlin, C (11 langs) | Go + Python (v1), then expand |
| Taint tracking | JS/TS, Python, Go, Kotlin | not v1 |
| Dependency manifest scan | Cargo, npm, pnpm, pip, Poetry, Pipenv | the above + go.mod, pom.xml, *.csproj, Gemfile |
| **Network / TLS probe** | **NO** | **YES (two-tier)** |
| **X.509 cert scan** | **NO** | **YES (PEM/DER + live host)** |
| **HTML auditor report** | **NO** | **YES (self-contained, print-clean)** |
| CycloneDX CBOM | 1.6 only | 1.6 + 1.7 (default 1.7) |
| SARIF | Yes | Yes |
| Risk score | severity ordinal (HIGH/MED/LOW) | **5-axis additive (0–100), HNDL flagging** |
| NIST IR 8547 mapping | **NO** (CNSA 2.0 only) | **YES (configurable policy)** |
| CNSA 2.0 mapping | Yes (deadline per finding) | Yes (policy preset) |
| TUI | Yes | Yes |
| Rule format | compiled-in + Semgrep YAML bridge | declarative TOML, two-layer, CBOMkit-compatible classify layer |
| Distribution | single static binary (`cargo install foxguard`, install.sh) | same |
| Open source | Yes | Yes |

**Verdict — wedge holds, narrower than the original spec assumed:**

- foxguard is **the** open-source Rust security scanner with PQC awareness. It is not a CBOM-first tool; it is a SAST/SCA tool that happens to include PQC findings. 267 stars suggests modest but real traction.
- **Gaps seawall fills cleanly:** network/TLS, X.509, auditor-grade HTML, risk scoring (vs ordinal severity), NIST IR 8547 mapping, CycloneDX 1.7.
- **foxguard's strengths over us:** 11 languages (vs 2 at v1), taint tracking, existing momentum.

**Strategic posture:** Don't compete on language coverage in v1 — foxguard has us there. Compete on (a) the **non-code estate** (network + certs + deps as first-class), (b) **report and risk-scoring quality**, (c) **CBOM 1.7 + round-trip compatibility with CBOMkit**. Marketing line: *"foxguard scans your code. seawall scans your estate."*

**One-line collaboration possibility:** foxguard outputs CycloneDX 1.6 CBOM; seawall can **consume** that CBOM as one of its inputs (`--in-cbom foxguard-output.json`) and add the network/cert/risk layer on top. Day-one ecosystem play.

Full feature matrix added; wedge axes re-confirmed.

---

## V-05 — Working name decision: **keep `seawall`**

**Question (D-13):** Pick a working name that's available across crates.io, GitHub, Homebrew.

**Sources:**
- crates.io API for `seawall` → **not found, available**
- GitHub search `seawall` → 119 results, but **none crypto-asset-scanner adjacent**. Top result by stars is `DaveBeusing/Seawall` (1 star, "full auto crypto trading" — cryptocurrency trading bot, not a security tool). The `oscargar1978/seawall`, `Andrej094/Seawall` (web app), `Anas001989/seawall` are all empty/unrelated educational repos.
- crates.io for backup names: `qsight`, `cbomx`, `pqfind`, `qbom`, `cryptotrace`, `pqsight`, `qx-scan`, `kx-scan` — **all available**. `pqaudit` is **taken** by a 35-download Rust TLS scanner (active March 2026, but very small).
- **`csnp/cryptoscan`** (singular, no `pe`) is the credible name-space neighbour previously surfaced — different name, different ecosystem.

**Decision:** **Keep `seawall`.** The original concern (D-13) overstated the collision. The phonetic/semantic neighbours are:
- `cryptoscan` (csnp) — different name, but adjacent. Acceptable.
- `seawall` GitHub repos — all hobby/unrelated. Acceptable.
- crates.io — **clear**.

**Action:** Register the GitHub org and the crates.io name **before** any code lands publicly. Backup names if either becomes contested at publication time: `cbomx` (best — short, descriptive, distinctive), `cryptotrace`, `qsight`.

**Updates** `knowledge/11-decisions/README.md` D-13 status → **RESOLVED, keeping seawall.**

---

## Summary table

| ID | Question | Resolution | Source |
|---|---|---|---|
| V-01 | MLKEM768 standalone in IANA registry? | YES (codepoints 512/513/514) | iana-tls-supported-groups.csv |
| V-02 | rustls-post-quantum latest version? | 0.2.4 (2025-09-23, superseded by rustls core) | crates.io API |
| V-03 | Composite ML-DSA TLS codepoints assigned? | NO (still TBD1–TBD15, draft -10) | datatracker.ietf.org |
| V-04 | foxguard feature matrix? | Confirmed; wedge holds in 6/10 axes | github.com/0sec-labs/foxguard README |
| V-05 | Working name available? | YES — keeping seawall | crates.io API + GitHub search |

All `[VERIFY]` items now resolved. The build is unblocked.

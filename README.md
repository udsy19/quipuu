# quipuu

**A single Rust binary that finds the cryptography in your codebase, classifies each finding against NIST's post-quantum migration timeline, and tells you exactly which ones a quantum adversary can harvest today.** It detects constructors and key-generation sites precisely rather than every call site exhaustively — [measured recall is below](#benchmark-numbers).

```bash
cargo install quipuu
quipuu scan .
open reports/quipuu.html
```

<!-- TODO: add screenshot or asciinema recording -->

Seven languages. Four output formats. No account. No cloud. No LLM. Median project scans in 170ms; the mean is 1532ms — see the benchmark table, both are real.

> **Formerly `cryptoscope`, briefly `seawall`.** Renamed to `quipuu` in August 2026, before any
> release. A quipu is the Incan knotted-cord record system — an entire civilisation's inventory
> encoded as knots on cords, centuries before writing. That is what this tool produces: your
> codebase is the cords, the cryptographic call sites are the knots, and the scan reads them into a
> ledger. The original spelling was unavailable on crates.io, held by an unrelated post-quantum
> library, so the name carries a second `u`. Nothing was ever published under the earlier names and
> there is no migration to do.

---

## Why quipuu instead of the other tools

Every other scanner is general SAST with a crypto subset bolted on. quipuu is crypto-only, built around the NIST post-quantum taxonomy (FIPS 203/204/205, NIST IR 8547), with explicit Harvest-Now-Decrypt-Later (HNDL) flagging baked in from day one. The threat model drives the tool, not the other way around.

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

**P4 — never executes your code.** quipuu parses with tree-sitter; it never runs your tests, your build scripts, or your binaries. Your untrusted-code sandbox is yours.

The trust invariants are tested directly in `crates/cli/tests/mcp_integration.rs`. The test `test_run_acvp_kats_rejects_code_execution` asserts P4; `test_network_disabled_error` asserts P2.

---

## Quick start

```bash
# Install (Rust 1.96+)
cargo install quipuu

# Initialise a project config
quipuu init

# Scan source, certs, and dependency manifests
quipuu scan .

# Open the HTML report
open reports/quipuu.html

# Also emit SARIF for GitHub Advanced Security, a CycloneDX CBOM, and a JSON summary
quipuu scan . \
  --sarif  reports/findings.sarif \
  --cbom   reports/cbom.json \
  --html   reports/quipuu.html \
  --summary-json reports/summary.json

# Probe a live TLS endpoint (network mode — see Responsible Use below)
quipuu scan . --allow-network example.com:443

# Score against a policy profile other than the NIST IR 8547 default
quipuu policy list
quipuu scan . --policy nsa-cnsa2
```

**Policy profiles.** `--policy` takes a built-in preset name or a path to a
policy TOML file; `quipuu policy list` prints what is built in. Two presets
ship today:

| Preset | Profile | What changes |
|---|---|---|
| `nist-default` | NIST IR 8547 IPD (Nov 2024) — the default | — |
| `nsa-cnsa2` | NSA CNSA 2.0, for national security systems | CNSA 2.0 approves AES-256 and SHA-384+ only, so SHA-256 and ChaCha20-Poly1305 stop being quantum-safe inventory and become findings, AES-128 is scored as off-suite rather than Grover-weakened, and SLH-DSA / FN-DSA / the sub-1024 ML-KEM and ML-DSA parameter sets are reported as non-compliant |

A policy reweights findings; it never creates, drops, or reclassifies a
detection. Measured on the 150-project benchmark corpus: the two profiles
produce the **same 898 findings**, of which **80 (8.9 %) land in a different
severity band**. The precision figure below therefore holds under both.

**Pre-built binaries** are available on the [Releases page](https://github.com/udsy19/quipuu/releases). The binary is fully static on Linux (musl), single-file on macOS and Windows. No JVM, no Node, no Python runtime, no Docker.

---

## What you will find

quipuu detects uses of the following algorithm families. Coverage is per rule
pack, not uniform across languages — the RustCrypto `des`/`rc4` crates, for one, have
no rules yet. What each language actually classifies is the `[[classify]]` list in
`quipuu/crates/core/data/rules/<lang>.toml`, and a build gate
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

*What is verified:* the HNDL flag is **computed from the active policy's `[hndl_flag]` block**, not asserted. Until 2026-08-28 it was not computed at all: every scanner wrote a hard-coded `false` and `summary.json.totals.hndl_critical` was `0` for every input. Today an X.509 certificate whose public key is a key-agreement key — the fixture is X25519, OID `1.3.101.110` — is flagged, and the same certificate's long-lived *signature* is not. **The scope is certificate findings.** Source and dependency findings still report zero, because `scan-source` fixes two of the flag's three inputs (`usage_context`, `shelf_life_bucket`) at compile time; over the benchmark corpus the count is **0 of 1056** (149 of 150 scanned, one recorded `unscannable`, none errored). Making it non-zero there means making those axes vary, which moves severity bands across the whole corpus, and that is a calibration change we have not made. Gated by `hndl_critical_is_reachable_end_to_end` and three sibling checks in `crates/cli/tests/hndl_flag.rs`. **The HTML report used to contradict that sentence.** Its HNDL section filtered on `hndl_critical || severity == Critical`, so on one RSA-2048/SHA-256 certificate it rendered **2** `HNDL-CRITICAL` badges while `summary.json` from the same scan reported `hndl_critical: 0` — and its own HNDL card, three sections above the badges, reported 0 as well. It now filters on the flag alone; on the X25519 fixture the flag, the card and the badge count are all **1**, and the certificate's Ed25519 signature — Critical, not HNDL — is no longer badged. Gated by `every_artifact_reports_the_same_hndl_count` in `crates/cli/tests/artifact_agreement.rs`, the first test in the repo that reads the HTML.

**SARIF 2.1.0** — drop into GitHub Advanced Security (`security-events: write`) or GitLab Advanced Security. Findings appear inline on PRs. Rule IDs (`CRYPTO-NNN`) are stable and documented.

*What is verified:* the `run` object carries the SARIF 2.1.0 property `automationDetails`. We emitted `runAutomationDetails` — the schema's *type* name — until 2026-08-28, and because `run` declares `additionalProperties: false`, every SARIF file we produced was invalid against the schema it named in its own `$schema`. Corrected at all nine sites and gated by `sarif_run_object_uses_the_property_name_not_the_type_name`, which checks the emitted document *and* the tree, so a doc page cannot teach the wrong key back into the code. **The schema violation is what is measured.** The GitHub behaviour of overwriting prior uploads for the same commit is documented ingest semantics, not a reproduced upload — we have not run this against a repo with `security-events: write`.

**CycloneDX 1.7 CBOM** — the canonical Crypto Bill of Materials format (ECMA-424 2nd Edition). Use it to track your cryptographic inventory over time and diff it across releases.

*What is verified:* a build gate emits one component for every algorithm in the table and validates it against the schema the BOM declares — **0 errors at 1.7, 0 errors at 1.6** (`--schema-version 1.6`), against the schemas vendored in `crates/cbom/data/`. **1.7 output is not 1.6-compatible:** `algorithmFamily` is a 1.7-only field, and offering default output to a 1.6 validator produces **77 errors** — one for each of the 77 components (of 92) that carry a canonical family. A consumer pinned to 1.6 needs `--schema-version 1.6`. Measured 2026-08-28 by `every_algorithm_emits_a_bom_valid_at_the_version_it_declares`. We have not tested ingestion by any third-party consumer, and no longer claim to.

**JSON summary** — machine-readable finding counts by severity, ecosystem, and algorithm family. Pipe it into your CI dashboard, Slack alerts, or compliance reports.

*What is verified:* a finding whose `algorithm_id` has no algorithm-table row is reported as **`unscored`**, in every artifact, and is not folded into a band. `algorithm_vulnerability` is 40 of the 100 points the risk engine assigns and is read entirely from that row, so there is nothing to band. Until 2026-08-28 each surface decided this privately and they disagreed: on one `openssl = "0.10"` line in a `Cargo.toml` — which `scan-deps` reports with its `unknown` sentinel — stdout printed `?`, `summary.json` and the HTML report said **Medium**, SARIF said `warning` with `security-severity: 5.0`, and the TUI said **Safe**. Four answers, one finding, and the loudest of them asserted a mid-band CVSS to GitHub Advanced Security for a finding we decline to score. `totals.unscored` is a new field; `totals.medium` no longer counts these rows, SARIF emits level `none` and omits `security-severity`, and `--fail-on` still skips them and says how many it skipped. Over the benchmark corpus this is **13 of 1056 findings (1.2 %)**, all `DEP-001`. It read 131 of 1399 (9.4 %) until 2026-08-29, when the corpus scope repair stopped four projects being scanned over their whole repository: 119 of those 131 were root `Cargo.toml` and `pom.xml` manifests that the projects' declared scopes excluded. Gated by `an_unscored_finding_is_unscored_in_every_artifact` and by a source-text check that fails when a new surface derives its own band instead of calling `quipuu_core::score_of`.

**MCP server** — `quipuu mcp-serve` exposes every scan verb over newline-delimited JSON-RPC on stdio, following the Model Context Protocol. Agentic clients use this interface to drive the scanner programmatically. The JSON schemas for `Finding`, `CryptoAsset`, and `RiskScore` live in `crates/core/schema/`.

---

## Benchmark numbers

**Corpus B — 150 manifest projects across 6 ecosystems, resolving to 140 repositories (10 entries are
monorepo siblings, symlinked to the clone they share). 149 are scanned; `crates-io:rustls-pemfile` is
recorded `unscannable` because the crate has no directory at its pinned commit and its clone is the
same tree `crates-io:rustls` already scans. `crates-io:ed25519-dalek` is pinned to upstream's own
"Remove code (#327)", so its working tree really is a single `README.md` — a correctly-pinned project
with nothing to find, which `corpus-integrity.toml` records as `files_scanned = 1` so it stays provable:**

| Metric | Value |
|---|---|
| Total findings | 1056 |
| Projects scanned | 149 of 150, 1 `unscannable`, **0 errored** |
| Wall-clock time | 230.0s (3m 50s) for all 150 |
| Per project | median 170ms · mean 1532ms · p90 1.35s · max 111.0s |
| Languages covered | 7 (Go, Python, Java, JavaScript/TypeScript, C/C++, Rust, C#) |

Every row above comes from **one run**: `python3 scan_corpus.py --include-safe`, flags
`--source --deps --include-safe`, profile `nist-default`, release build, single-threaded,
on **2 cores of an AMD EPYC 9354P with 7 GB RAM**, 2026-08-29. It wrote
`results/summary.json`. `results/all_findings.json` is the per-finding dump from
`dump_findings.py` under the same binary, flags and corpus; the two agree at **1056** by
independent count, ecosystem by ecosystem, and that population is what the precision figure
below is sampled from.

**Read the mean and the median as different facts.** The 9.0× gap between them is three
repositories: `aws-sdk-go-v2` alone takes 111.0s, and with `aws-sdk-go` (24.0s) and `wolfssl`
(17.4s) the top three are 66.7% of the total wall-clock. **132 of 150 projects finish in under
a second.** The mean describes a corpus deliberately stocked with vendored AWS SDKs; the
median describes a project. Neither is the number to quote alone.

**Wall-clock on this box moves between runs.** Earlier passes over the same corpus with the
same flags gave 281.1s, 282.0s, 294.9s, 329.0s and 367.4s against the 230.0s above — the last
of those over a wider corpus scope than this one. Read the whole-corpus figure as "between four
and six minutes on two shared cores", not as three significant figures. The finding counts do
not move for timing reasons: this run's **1056** is reproduced exactly by an independent
`dump_findings.py` pass on the same binary. The steps down from 1570 — 91 findings, then 80 —
are the two false-positive suppressions recorded in `BENCHMARKING_RESULTS.md`, and the step
from 1399 to 1056 is the 2026-08-29 corpus scope repair described there and below.

**These figures replace a published `~22s / ~150ms`, which was wrong.** That pair came from
`results/summary.json` at `include_safe:false`, in a run where **9 of 150 clones were
missing** — so it timed 141 projects and found 1036, while the 1570 printed beside it came
from a different, complete run under different flags. It was also taken on unnamed hardware,
not the machine named above, and `BENCHMARKING_RESULTS.md` reported the same run as
*1194 findings in 23.3s*, so the two source documents never agreed either. We are not
claiming the scanner got 16× slower; we are retracting a number that described 141 projects,
under one flag set, on an unnamed machine, and presenting one that names all three.

Audit-validated precision: **97.15%** (95% CI: 95.9%–98.4%) — measured 2026-08-30 on **635 audited findings** out of 1811, every one labelled by opening its cited `file:line`. Methodology, the full label set and per-finding verdicts are in `BENCHMARKING_RESULTS.md`, `PRECISION_AUDIT_V4.md` and `PRECISION_AUDIT_V3.md`.

**This reverts the 97.71% published above the `#Y64`/`#Y65` Go SHA-256 fix below — not a new measurement, but `DECISION #ESTIMATOR2` (2026-08-30) undoing the fold that produced it.** `#Y64` appended a 100%-census audit of its own new rule's near-tautologically-true-positive targets (139 findings, 0 FP) directly into the anchor's per-stratum sample; `#Y65` added 12 more on top. Both moves passed `gate_precision` because the gate only blocks a drop past -0.5pp and lets any rise through unexamined — but auditing every target a brand-new rule produces and folding the result into the very sample it is measured against inflates the reported rate regardless of whether real-world precision improved, since the fold is not a random draw from the stratum. The adjudicator reverted `state/estimator.json` to its pre-`#Y64` state (`a_tp` 335→262, `b_tp` 420→354, matching `#Y63`'s last gate-passed 97.11% exactly) and ruled that `#Y64`/`#Y65`'s 151 audited findings are real coverage evidence, not anchor-sample inputs, until a periodic re-draw mechanism exists (`OPEN-ASK #ESTIMATOR1`, still open). The two paragraphs below describe what `#Y64`/`#Y65` actually shipped — real, hand-verified detection gains — separately from the anchor-sample question this correction resolves.

**`#Y65` (Rust `md5`/`sha1` crates) added 12 more hand-verified true positives on top, same fold, same revert.** Full accounting in `BENCHMARKING_RESULTS.md`, "Rust `md5`/`sha1` crates (RustCrypto) gain coverage."

**This was a 0.54-point rise from the 97.11% published for the C# SHA3 fix below, and it was coverage added, not a reanchor — the largest single-cycle rise in this chain because the gap it closed was the largest.** `go.toml` had zero coverage for `crypto/sha256`/`crypto/sha512` — every `md5.New()`/`sha1.New()` call site was detected, but `sha256.New()`/`.Sum256()` (and the `.New224`/`.Sum224`/`.New384`/`.Sum384`/`.Sum512` siblings), the far more common call in real Go code, produced no finding at all. Eight new `GO_CALLEE_APIS` dispatch entries plus eight new classify arms (`CRYPTO-948`–`CRYPTO-955`) close it; unlike `md5`/`sha1`'s shared `New`/`Sum` api needing an `args.pkg` capture to disambiguate, each new function name already states its own digest size. **139 findings added, 0 removed, 0 reclassified — every one hand-verified true positive: the cited line was checked to contain the exact call syntax the rule claims (not inside a comment or string), and the citing file's own import block was checked to reference a `sha256`/`sha512`-named package**, across 20 projects and every corpus-B ecosystem except `pypi`/`npm` alone (`aws-sdk-go`, `x/crypto`, `kubernetes`, `etcd`, `grafana`, `prometheus`, `pgx`, BoringSSL/AWS-LC/age/tweetnacl's own Go test tooling, among others) — sha256 is used broadly enough that the delta spans both audit strata, requiring two sequential single-stratum measurement passes (73 landing in stratum A, 66 in stratum B) rather than one. Full accounting in `BENCHMARKING_RESULTS.md`, "`crypto/sha256`/`crypto/sha512` gain coverage."

**97.11% was itself unchanged from the 97.11% published for the C# SHA3 fix directly below (0 findings moved), which was itself a 0.05-point rise from the 97.11% published for the `SHA384.Create()` fix, and that too was coverage added, not a reanchor.** `cpp.toml` had no rules at all for OpenSSL's `SSL_CTX_set1_groups_list`/`SSL_set1_groups_list` — the TLS key-exchange group preference list, C's counterpart to `java.toml`'s `SSLParameters.setNamedGroups` (this fires on a classical-only group list written before ML-KEM existed, the same downgrade-detection direction, not the PQC-adoption direction every other C PQC rule fires in). A new structural matcher (`match_c_ssl_groups_list`, `scanner.rs`) splits the colon/tuple-separated string into one event per group name — mirroring the array-per-element shape `java.toml`'s extract already uses — and 11 new classify arms (`CRYPTO-909`–`CRYPTO-919`) reuse the same algorithm ids `java.toml`'s `setNamedGroups` arms already cover, though the literal group names differ (OpenSSL's own `P-256`/`P-384`/`P-521`, not Java's `secp256r1`/`secp384r1`/`secp521r1` — verified directly against OpenSSL's `SSL_CTX_set1_groups_list(3)` manpage). 3 new findings, all hand-verified true positive by opening the cited line, entirely inside `aws/aws-lc` and `google/boringssl`'s own TLS test suites — every one a real `SSL_CTX_set1_groups_list` call, guarded by `ASSERT_TRUE`, naming a classical-only group (`X25519`, `P-384`). The delta lands in stratum B, appended at audited weight rather than re-stratified. Full accounting in `BENCHMARKING_RESULTS.md`, "OpenSSL `SSL_CTX_set1_groups_list`/`SSL_set1_groups_list` gain a TLS group-preference-list rule."

**97.11% was itself a 0.04-point fall from the 97.15% published for the `createHash` fix below, and no findings moved: 0 added, 0 removed.** `csharp.toml`'s `SHA384.Create()` had no entry at all in `CSHARP_CALLEE_APIS` (`scanner.rs`) — unlike `SHA1`/`SHA256`/`SHA512`/`MD5`, it was never even extracted, not merely unclassified — despite `algorithm-table.toml` already carrying a `sha-384` row. One new dispatch-table entry plus one new classify arm (`CRYPTO-633`) close the gap. Corpus B's C# projects have no `SHA384.Create()` call site, so the pre/post dump is byte-identical: 1673 findings, both binaries. The raw total jumped 1533→1673 between this measurement and the one before it — the same already-tracked, deferred `OPEN-ASK #CORPUSDRIFT`, confirmed present in the *pre-change* binary against the same `corpus-clones` checkout and therefore not an effect of this change. The 0.04-point movement is the pre-existing "fresh populations" vs. "carried constants" estimator drift described below: re-running the estimator on the unmodified pre-change dump against itself reproduces the identical 97.11%. Full accounting in `BENCHMARKING_RESULTS.md`, "C# `SHA384.Create()` gains coverage."

**97.15% was itself a 0.05-point rise from the 97.10% published for the pycryptodome `RSA.generate` fix below, and it is coverage added, not a reanchor.** `java.toml`'s `MessageDigest.getInstance` had classify arms for exactly the three digest names in the original fixture — MD5, SHA-1, SHA-256 — with no arms for the other JCA standard digest names, even though `algorithm-table.toml` already carries rows for all of them (`sha-224`, `sha-384`, `sha-512`, `sha3-256`, `sha3-512`). A call naming any of those five produced zero findings despite the extractor already seeing and capturing the call site. Five new classify arms (`CRYPTO-899`–`CRYPTO-903`) close the gap by name, reusing the existing string capture — no scanner or extractor change. 1 new finding, hand-verified true positive by opening the cited line: `org.bouncycastle:bcprov-jdk18on`'s composite ML-KEM engine (`CompositeMLKEMEngine.java:166`) hashes the combined shared secret with `MessageDigest.getInstance("SHA3-256")`. Corpus B's `pyca/cryptography` clone shrank between dumps (an already-tracked, unrelated corpus-drift artifact affecting both the pre- and post-change binary equally — see `OPEN-ASK #CORPUSDRIFT`), so the raw finding count moved 1532→1533 while the delta this change is responsible for is exactly the one row above. Full accounting in `BENCHMARKING_RESULTS.md`, "Java `MessageDigest.getInstance` gains the remaining JCA standard digest names."

**97.10% was itself a 0.04-point fall from the 97.14% published for the `RSA_generate_key_ex` fix below, and no findings moved: 0 added, 0 removed.** `python.toml`'s pycryptodome `Crypto.PublicKey.RSA.generate(bits)` had three classify arms covering every literal bit count, but the extractor only captured `bits` when the argument was a literal integer, so a config-driven call like `RSA.generate(key_size)` produced no finding at all despite the call site being real — the one API in this file missing the fallback its sibling `cryptography.hazmat.rsa.generate_private_key` already had. One new classify arm (`CRYPTO-173`) and an extractor fallback close the gap, verified against a fixture. Corpus B has no `RSA.generate` call site with a runtime `bits` argument, so the pre/post dump is byte-identical — 1672 findings, both binaries — and the audited sample composition (271 stratum-A rows, 359 stratum-B rows) is unchanged. The 0.04-point movement is the pre-existing "fresh populations" vs. "carried constants" estimator drift: re-running the estimator on the unmodified pre-change dump against itself reproduces the identical 97.10%, proving the drift predates and is independent of this change. Full accounting in `BENCHMARKING_RESULTS.md`, "pycryptodome `RSA.generate` gains an `rsa-unattributed` catch-all for a runtime `bits`."

**97.14% was itself a 0.06-point rise from the 97.08% published for the liboqs fallback below, and it is coverage added, not a reanchor.** `cpp.toml`'s three classify arms on OpenSSL's `RSA_generate_key_ex` covered `bits < 2048`, `bits == 2048`, and `bits >= 4096` — three named bands with a real gap between 2048 and 4096. A literal like 3072, or a runtime `bits` variable the scanner cannot resolve statically, matched none of the three and silently produced zero findings, despite the extractor already seeing the call site. The sibling legacy API in the same file, `RSA_generate_key` (`CRYPTO-406`), had already closed exactly this gap; `RSA_generate_key_ex` — the modern, more commonly called API — had not. One new classify arm (`CRYPTO-407`), ordered last with no `bits` constraint, mirrors `CRYPTO-406`'s existing shape. 7 new findings, all hand-verified true positive by opening the cited line, entirely inside `openssl/openssl`, `aws/aws-lc` and `google/boringssl` — every one a real `RSA_generate_key_ex(rsa, bits, ...)` call with `bits` a runtime variable, not a literal. The delta lands entirely in stratum B, appended at audited weight rather than re-stratified. Full accounting in `BENCHMARKING_RESULTS.md`, "openssl RSA_generate_key_ex gains an rsa-unattributed catch-all."

**97.08% was itself a 0.01-point fall from the 97.09% published for the OpenSSL keygen fix below, and it is coverage added, not a reanchor.** `cpp.toml`'s `OQS_KEM_new`/`OQS_SIG_new` classify arms only recognized the fifteen enumerated ML-KEM/ML-DSA/SLH-DSA parameter-set macros, so HQC — NIST's own selected backup KEM — and every other liboqs candidate family (MAYO, BIKE, Classic McEliece, FrodoKEM, ...) produced zero findings despite the extractor already seeing the call site. Two new catch-all classify arms (`CRYPTO-897`/`CRYPTO-898`) degrade any unmatched macro or variable to a `kem-unattributed`/`sig-unattributed` sentinel. 5 new findings, all hand-verified true positive by opening the cited line, entirely inside `open-quantum-safe/liboqs` and its `oqs-provider` OpenSSL provider — every one calls the API with a runtime algorithm-name variable rather than a literal macro. Unlike the OpenSSL keygen addition below, these 5 are folded into a freshly re-derived stratum-A population (796 → 801) rather than appended at audited weight, which is why the figure moves down: stratum A's own precision estimate rose slightly (257/266 → 262/271) but its population share grew relative to the higher-precision stratum B. Full accounting in `BENCHMARKING_RESULTS.md`, "liboqs OQS_KEM_new/OQS_SIG_new gain a kem-unattributed/sig-unattributed fallback."

**97.09% was itself a 0.03-point rise from the 97.06% published the day before, and it is coverage added, not a reanchor.** `cpp.toml` had zero rules for OpenSSL 3.0+'s generic keygen entry points (`EVP_PKEY_CTX_new_from_name`/`EVP_PKEY_Q_keygen`) despite the file's own header comment claiming coverage that never existed. 5 new findings, all hand-verified true positive by opening the cited line, entirely inside `openssl/openssl` itself (three EC sites in HPKE and CMS, two DH sites in the TLS handshake code) — no other corpus project calls this API yet. The 5 are appended directly to the existing 613-row audited pool rather than re-stratified, so the movement reads slightly optimistic (see the caveat below); read it as precision held with coverage added. Full accounting in `BENCHMARKING_RESULTS.md`, "OpenSSL 3.0+'s generic keygen API gains coverage."

**Coverage was added the same day with no change to this figure.** `csharp.toml` had no rule for
.NET 10's first-party `MLKem`/`MLDsa`/`SlhDsa` classes (`System.Security.Cryptography`, no NuGet
dependency) — a static-factory shape (`MLKem.GenerateKey(MLKemAlgorithm.MLKem768)`) the templated
`{cls}.Create` rule structurally cannot match. 21 new classify arms cover all 3+3+12 literal
parameter sets plus a family-sentinel fallback per class. Corpus B has no known call site for
these brand-new preview APIs, so the pre/post dump is byte-identical (0 added, 0 removed);
coverage is verified against a five-site fixture instead. Full accounting in
`BENCHMARKING_RESULTS.md`, ".NET 10+ first-party MLKem/MLDsa/SlhDsa PQC classes gain coverage."

**This is a 0.28-point rise from the 96.78% published earlier the same day, and it is coverage added, not a reanchor.** `java.toml`'s only BouncyCastle constructor rule matched four classical classes and none of BC's nine PQC lightweight-API classes (`MLKEMKeyPairGenerator`, `MLDSAKeyPairGenerator`, `SLHDSAKeyPairGenerator`, `MLKEMGenerator`, `MLKEMExtractor`, `MLDSASigner`, `SLHDSASigner`, `HashMLDSASigner`, `HashSLHDSASigner`), so any call to any of them produced zero findings. `java.toml` gained `CRYPTO-811..819`, each degrading to a family sentinel since none of the nine take a parameter set as a constructor literal. 55 new findings, all hand-verified true positive, entirely inside BouncyCastle's own `bcprov-jdk18on`/`bcpkix-jdk18on` implementation — no other corpus project has migrated to this API yet. Full accounting in `BENCHMARKING_RESULTS.md`, "BouncyCastle lightweight-API PQC classes gain coverage."

**Coverage was added the same day with no change to this figure.** `circl` — Go's own PQC library, and the only place in the 150-project corpus that calls ML-DSA/ML-KEM/SLH-DSA directly — previously matched zero rules in any pack. `go.toml` gained rules for `circl`'s `mldsa{44,65,87}` and `mlkem{512,768,1024}` packages (the parameter set is which package is imported, not an argument) and `slhdsa.GenerateKey`'s `id` argument (one package, twelve parameter sets). 6 new findings, all hand-verified true positive, entirely inside `circl`'s own tree — no other corpus project imports these packages. Full accounting in `BENCHMARKING_RESULTS.md`, "circl (Go's own PQC library) gains its own rules."

**This is a 1.46-point rise from the 94.7% published earlier the same day, and it is coverage added, not a reanchor.** `netty-handler.toml`'s `scan_hints.scan_paths` gained `pkitesting/src/main/java/` — the one module in the 150-project corpus with real Java PQC call sites, previously out of scope entirely. `java.toml` gained three catch-all classify arms (`CRYPTO-234`/`235`/`236`) for `KeyPairGenerator.getInstance`/`Signature.getInstance`/`KEM.getInstance` when the algorithm argument is a variable, or names an algorithm none of the specific arms recognise — the same degrade-to-unattributed shape Go's `rsa-unattributed` and JS's `webcrypto-unattributed` already use, now with a matching `jca-unattributed` sentinel. 125 new findings, all hand-labelled true positive — 124 mechanically re-verified as real `getInstance` calls at their cited line, plus one pre-existing BouncyCastle-provider-registration rule newly reachable once `pkitesting/` entered scope. Full accounting in `BENCHMARKING_RESULTS.md`, "Java non-literal getInstance fallback."

**94.7% was itself a 3.05-point rise from the 91.6% published earlier the same day, and it is coverage added, not a reanchor.** `go.toml` gained sign/verify/encrypt/decrypt *operation*-site rules for `crypto/rsa`, `crypto/ecdsa` and `crypto/ed25519`, plus the one-shot `md5.Sum`/`sha1.Sum` form — closing the gap this same page's recall table names below (every signer and verifier at 0.0%, only two operation sites found at all). 131 new findings, all hand-labelled true positives. Full accounting in `BENCHMARKING_RESULTS.md`, "Go stdlib sign/verify/hash operation sites."

**91.6% was itself a 1.65-point rise from the 90.4% published earlier the same day, also coverage added, not a reanchor.** Two Go classify arms (`CRYPTO-005`/`CRYPTO-014`) closed a gap where `rsa.GenerateKey`/`ecdsa.GenerateKey` calls with a non-literal size or curve argument produced no finding at all instead of an unattributed one. The fix added 29 findings, all hand-labelled true positives by construction — the argument shape it recognizes is unconditionally a key-generation call — folded into the same two-stratum estimate at their audited weight. Full accounting in `BENCHMARKING_RESULTS.md`, "Go RSA/ECDSA keygen unattributed fallback."

**88.8% was itself 2.1 points below the 90.9% published on 2026-08-28, and no rule changed between them.** What changed is the corpus population. The harness resolved each project's declared `scan_hints.scan_paths` by dropping any path that was not on disk, and when *none* of a project's paths resolved it scanned the whole repository instead and recorded `status: "ok"`. 15 of the 92 projects declaring a scope named a path that does not exist; four of them reached the published dump that way and contributed **355 of its 1399 findings**, gathered from exactly the trees their declared scope was written to exclude — `rustls-pemfile` scanning the entire rustls workspace, `jetty-server` scanning `jetty-ee8/9/10/11` and the demos, `tink` scanning the C++, Go and Python trees. The scopes are repaired, the fallback is gone, and `corpus_integrity.py` now fails the run rather than widening it silently. **49 of the 150 rows in the audited stratum no longer resolve because the trees they sat in left the corpus, and 48 of the 49 were labelled TP** — the widened scans were finding real cryptography in places the corpus had declared out of scope, and those places are easier than the ones it declared. 88.8% and 90.9% are comparable in their arithmetic and not in what they estimate.

**The 90.9% this number replaces was itself not comparable to the 86.5% published three releases before it, and that difference was not all gain either.** 86.5% carried 964 of 1570 findings — 61% of the corpus — at a constant 87.1%, taken from an audit whose per-row labels no longer identify any row. That stratum has since been re-sampled and re-labelled: 150 rows, uniform, seed 20260828, each read at its cited line. Reading the labels instead of the constant moved *the same scan of the same corpus* from 86.5% to **80.0%** before a line of code changed. Three false-positive suppressions then moved it to 84.7%, 89.9% and **90.9%**, and the 2026-08-29 corpus scope repair then moved it to **88.8%**. Under the old constant the first two of those releases read 87.3% and 87.3%, because a stratum held at a constant cannot show its own false positives being deleted; the third reads 88.3% only because the defect it fixes lives in the stratum that is measured rather than held. Both readings, the sample and the arithmetic are in `PRECISION_AUDIT_V4.md` §§ 3 and 6 — we publish the label-derived one because it is the one whose verdicts can be checked line by line.

**What that interval is.** A two-stratum weighted estimate over 635 findings audited by opening every cited `file:line` — 271 rows from the 746-finding stratum A population, 364 from the 942-finding stratum B population. The interval is the stratified normal approximation `Var = Σ wᵢ² pᵢ(1−pᵢ)/nᵢ`, not a Wilson interval on a pooled sample; its lower bound is 95.9%. Both strata's populations are re-derived fresh from the live dump on every run rather than carried forward, so they move cycle to cycle with `OPEN-ASK #CORPUSDRIFT`'s corpus-count drift independent of any detection change. This cycle's own 1 hand-verified true positive (BoringSSL's own `EVP_sha384()` test call, `crypto/evp/evp_extra_test.cc:1912`) lands in stratum B, which is why its audited composition moved 354/363 → 355/364 while stratum A's (262/271) held.

**What the denominator excludes.** `precision = TP / (TP + FP)`. The 635 audited rows are **617 TP, 18 FP and 0 DEPENDS** — every DEPENDS-shaped ambiguity found in earlier samples has since been closed by the grounding fixes described below, so nothing is excluded on this pass. A DEPENDS row, when one exists, is one whose operation is real but whose `algorithm_id` asserts a parameter the cited line does not state, typically an RSA modulus supplied by a caller. Every figure quoted here uses the same convention, so they are comparable to each other — and any figure quoted against a scanner that uses a different one is not.

**Why this number first moved down.** The figures published here before — 84.5%, then 85.2% and 87.1% — were measured against a corpus in which **46 of the 150 projects had empty working trees**. `clone_all.sh` clones `--no-checkout`, and the manifest's `commit_sha` pins had been shuffled across project files, so the checkout failed, printed a warning, and the project was still counted as cloned. Those numbers were taken on a biased two-thirds sample. Re-measured on the fully populated corpus the same scanner gave **81.8%** — lower, and published as such, because a benchmark you cannot reproduce is worth nothing.

**86.5% is a real gain on top of that corrected baseline, not a return to the old number.** It came in two steps, neither of which loosened a rule. The first suppressed one false-positive shape: a JOSE algorithm-registry lookup such as `jwa.LookupSignatureAlgorithm("PS256")`, which retrieves a descriptor from a table and was being reported as a quantum-vulnerable signing operation. 34 findings were removed, every one of them labelled a false positive by hand, and no true positive was lost — 81.8% to 85.3%.

The second removed a class rather than a shape, and it removed **no findings at all**: 283 of 1570 findings — 18.0% — were reporting an algorithm identifier that named a parameter their input never stated. `sha512WithRSAEncryption` was resolved to `rsa-pkcs1-sha512-4096`, so any certificate a CA had signed with SHA-512 claimed 152-bit classical security whatever its real key size; `ml-kem` in a `Cargo.toml` was resolved to `ml-kem-768`, failing a CNSA 2.0 scan of a codebase that had correctly migrated to ML-KEM-1024. Those identifiers now name what the input determines and no more, the measured parameter is carried in the finding message instead, and an enforced invariant (`crates/cli/tests/algorithm_parameters.rs`) fails the build when an emitter names one again. Same 1570 findings, same 1552 sites, same severity distribution — 85.3% to 86.5%.

**What this release removed: an algorithm identity read off a name two libraries share.** `crypto_sign_keypair` is libsodium's Ed25519 keygen. It is also the NIST PQC reference API name, so ML-DSA's and SLH-DSA's own reference implementations publish their keygen under it — and we matched the identifier as text, with no header check of any kind. The result was **12 High findings telling FIPS 204 and FIPS 205 reference code to migrate to ML-DSA-65**, 8 of them inside the corpus's scanned subtrees. The Ed25519 answer is now conditional on the file naming a NaCl header; where no header says which library supplies the symbol, the finding still reports the call site and asserts **no algorithm at all**. That is worth 1.0 point on both estimates — the first change in three releases the older estimator could see, and only because this defect happens to live in the stratum that is measured rather than held. It also costs one correct identification: libsodium's own test file reaches `sodium.h` through another header, and following an include would mean running the project's build, which trust invariant P4 forbids.

**And why it then moved down before it moved up.** The two gains above were measured with stratum A held at its constant, so neither of them could have been contradicted by that stratum even in principle. Auditing it contradicted both: 34 of its 150 sampled rows are false positives, and they are four shapes, not thirty-four accidents. **The release before this one removed the largest of them.** A Java JOSE algorithm constant that is only compared against, collected into a supported-algorithm set, or used as a lookup-table key — `alg.equals(JWSAlgorithm.PS256)`, `algs.add(JWSAlgorithm.HS512)`, `map.put(SignatureAlgorithm.ES256, SHA_256)` — was reported as though the line signed, wrapped or hashed something. **80 findings across four Java projects, 5.4% of the corpus; 94 Java enum-constant findings fired and 14 were on an operational line.** That is worth 5.2 points on the corrected estimate — 84.7% to 89.9% — and **0.0** on the old one, because every one of the 80 sat inside the held constant where no measurement could see them.

The release before it removed the second shape, an `alg=none` finding on a constant spelled "none": **91 findings, every one carrying a critical severity hint and CWE-347 on a line that performs no authentication.** 92 fired, 1 was real. The two shapes still open in that audit — a call a test requires to fail, and an `algorithm_id` that contradicts its own line — are 10 of the 150 rows and are named in `PRECISION_AUDIT_V4.md` § 6 as the next two worth taking.

### Recall, published beside precision

**Go-only line-exact recall: 100.0%** — 401 of 401 in-scope `crypto/*` standard-library call sites, measured 2026-08-29 on the 1244-finding dump (`dsa1_post.json`) that produced a since-superseded 94.7% precision figure, after a fix to the ground-truth builder itself (below). It has not been re-measured against the 618-row audit the precision figure above is now sampled from. **This is a Go number derived from 25 real-world projects**; the cross-language number below is a smaller, planted probe, not the same kind of measurement.

Ground truth is built independently of our own rule files, by scanning the 25 Go corpus projects for 33 quantum-relevant stdlib APIs and requiring the matching `crypto/*` import, so it cannot inherit our blind spots. Reproduce with `python3 recall_check.py --clones DIR --dump results/all_findings.json`, which scores against a `dump_findings.py` artifact so recall is measured on exactly the finding set the precision audit samples.

**The last named gap was in the instrument, not the scanner.** Every prior measurement here reported a 6-site `crypto/ecdh` miss (`P256`/`P384`/`X25519`, 2 sites each). All six turned out to be the *same line* the ground-truth regex had already matched once, re-matched a second time inside a Go test's own assertion message — e.g. `jwx/jwe/jwe_test.go:1755` calls `ecdh.P256().GenerateKey(...)`, correctly found; line 1756, `require.NoError(t, err, \`ecdh.P256().GenerateKey should succeed\`)`, quotes that same call inside a backtick string and was being counted as a second, distinct call site. The scanner never missed a real call; the ground-truth builder was matching prose. `recall_check.py` now strips single-line backtick spans before matching, the same way it already strips `//` comments, and the whole-tree ground truth drops from 1054 to 1048 sites accordingly — a correction to the denominator, not a change in what the corpus contains.

| API kind | in-scope sites | found | recall |
|---|---|---|---|
| Generators and constructors (`rsa.GenerateKey`, `ecdsa.GenerateKey`, `ed25519.GenerateKey`, `dsa.GenerateKey`, `ecdh.*`, `md5.New`, `sha1.New`, `des.NewTripleDESCipher`, `rc4.NewCipher`) | 319 | 319 | **100.0%** |
| Operations (`ecdsa.Sign`, `ecdsa.Verify`, `rsa.SignPSS`, `rsa.VerifyPKCS1v15`, `ed25519.Sign`, `dsa.Sign`, `dsa.Verify`, `md5.Sum`, `sha1.Sum`, …) | 82 | 82 | **100.0%** |

Every API in the ground truth, constructor and operation alike, is now at 100% in-scope recall. **The precision/recall trade this section used to describe no longer exists on this axis**: on the 1244-finding dump above, 94.7% precision and 100.0% recall were two different measurements of the same finding set, neither one bounding the other.

**A second denominator, which bounds the benchmark rather than the tool.** Those 401 sites are the ones inside the subtrees the harness actually hands to the scanner. Over the whole Go clone tree the ground truth is **1048 sites**, so **647 (61.7%) sit outside every scanned subtree and are never looked at**. The harness restricts 92 of 150 projects to `scan_hints.scan_paths`. Recall against the whole tree now reads **38.3%** (401/1048), and neither number should be quoted without saying which denominator it uses.

**A related measure: does a missing operation site cost a whole algorithm family in the CBOM?** Re-run on the `dsa`-inclusive dump, `work/synth_family_gap.py`'s method (family evidenced by a stdlib operation call site, absent from our findings) drops from **12 to 11** family-losses across the 25 `go-modules` projects — real but small, because the one `dsa` loss the rule closes (`x-crypto`) is in-scope while the remaining loss (`vault/helper/pkcs7/sign.go:220`, also `dsa.Sign`) sits outside `vault`'s `scan_hints.scan_paths` subtree, the same whole-tree-vs-in-scope gap the paragraph above names, not a detection defect. Not reproducible from this repo alone — the script reads a corpus-local dump path — but the method is `recall_check.py`'s own ground-truth construction applied to CBOM family coverage instead of line-exact sites.

The benchmark corpus and reproduce scripts live in `benchmarks/corpus-b-realworld/`. Run `./clone_all.sh`, then `python3 scan_corpus.py --include-safe` for the speed and finding counts, `python3 dump_findings.py` for the per-finding dump the precision audit samples, and `python3 recall_check.py` for the recall figures; all three take `--clones` if the corpus lives outside the repo. Verify the numbers yourself.

**Cross-language recall: 41.9% (49/117), measured 2026-08-30.** `benchmarks/corpus-a-ground-truth/`
is 117 hand-planted call sites, one idiomatic invocation per line, spanning all seven supported
languages and ~17 algorithm families — a probe we designed independently of `data/rules/`, not
derived from real-world projects the way corpus B and the Go recall figure above are. Scored at
family level (a `rsa-2048` finding and an `rsa-unattributed` finding both count as a hit for
`family = "rsa"`) with `python3 recall_check.py`. Read the number with its own README before
quoting it: 23 of the 117 sites (`hmac`/`scrypt`/`bcrypt`/`argon2`) can never score a hit because
`algorithm-table.toml` carries no MAC or password-KDF family yet, and the `cpp` file's 0% includes
several call shapes no real C code would actually write. Not a CI gate — narrowing an over-broad
rule to kill a false positive can cost a true positive at the same site, so recall is measured and
published, never enforced as a floor.

---

## How it works

```
quipuu scan .
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
                         per-group handshakes; PQC/hybrid groups catalogued,
                         not yet probed (ring backend has no ML-KEM impl)
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

**Rule format.** Rules live in `crates/core/data/rules/<lang>.toml` as two-layer extract-then-classify pairs. The classify layer maps captured values to an `algorithm_id` from the algorithm table, a severity hint, and a SARIF message template; it is the live layer and the source of truth for classification. The extract layer records the intended tree-sitter S-expression for each call shape, but the queries are not executed — matching is done by a hand-written walker in `scan-source/src/scanner.rs`, and a build gate fails when a classify rule names an API that walker cannot emit. The rule-authoring pattern — declarative, tuple-based classification over extracted values — draws on cryptobom-forge (Santandersecurityresearch/cryptobom-forge) as prior art; the two schemas do not share field names and are not file-format compatible. 115 extract blocks and 678 classify arms across 7 files; every one is plain text, readable in under a minute.

---

## Comparison

| | quipuu | Snyk Code | GitHub CodeQL | IBM CBOMkit | Semgrep |
|---|---|---|---|---|---|
| PQC-first, NIST IR 8547 taxonomy | Yes | No | No | Partial | No |
| HNDL flagging | Yes (certificate key establishment; scope stated under Output formats) | No | No | No | No |
| Local-only, no account | Yes | No (SaaS) | No (SaaS) | Partial | Partial |
| Single binary | Yes | No | No | No | No |
| CycloneDX 1.7 CBOM | Yes | No | No | No | No |
| SARIF output | Yes | Yes | Yes | No | Yes |
| MCP server | Yes | No | No | No | No |
| Auditable open rule format | Yes (TOML) | No (binary) | Yes (QL) | No | Yes (YAML) |
| Languages (crypto-specific) | 7 | 7+ | 7+ | Java, Python, Go, C# (comprehensive rules merged 2026-08-26) | Any |
| Published precision (crypto findings) | 97.15% (635 audited rows, DEPENDS excluded) | ~49–76% (published benchmarks) | High (full data-flow) | Not published | Not published |
| Published recall | 100.0% (Go stdlib, 401/401 in-scope sites); 41.9% cross-language (49/117 planted sites, 7 languages) | Not published | Not published | Not published | Not published |
| Scan speed | 170ms median project; 230s for the 150-project corpus (2 cores) | Cloud-dependent | 5–15 min/repo | Not benchmarked | ~minutes |

**Where CodeQL wins:** CodeQL has full inter-procedural data-flow. It can trace a key from generation through storage to use and flag misuse that a pattern-based scanner cannot see. If you need that depth and can absorb the scan time, CodeQL delivers it. quipuu does not attempt to replicate data-flow analysis — it trades that capability for speed, locality, and PQC specificity.

**Where Snyk Code wins:** Snyk has a larger ecosystem of language integrations and a mature CI integration story. If your team already runs Snyk, adding `--crypto` coverage through their platform is lower friction than adopting a new tool. The cost: your code leaves your machine.

**Where quipuu wins:** quipuu never leaves your machine, ships the NIST taxonomy as auditable data, produces a standards-compliant CBOM, and scans a typical project in under a third of a second. It is the right starting point for a PQC inventory exercise that needs to stay inside your security boundary.

---

## Architecture

The Rust workspace (`quipuu/`) has nine crates, each with one responsibility:

```
crates/
├── core/           Domain types, algorithm table (92 entries), OID table,
│                   QuantumRiskScore engine, policy presets (nist-default,
│                   nsa-cnsa2)
├── scan-source/    tree-sitter scanning for 7 languages
├── scan-certs/     x509-parser PEM/DER scanning
├── scan-deps/      Manifest parsers: go.mod, Cargo.toml, requirements.txt,
│                   package.json, pom.xml, *.csproj
├── scan-network/   rustls TLS prober (classical groups probed; PQC/hybrid
│                   groups catalogued, not yet probed — ring has no ML-KEM)
├── cbom/           CycloneDX 1.6/1.7 emitter + embedded schema validator
├── report/         HTML (askama, compile-time), SARIF 2.1.0, JSON summary
├── tui/            ratatui interactive explorer
└── cli/            Single binary entrypoint, mcp-serve stdio transport
```

All primary sources — NIST IR 8547 IPD, FIPS 203/204/205, CycloneDX 1.7 schema, SARIF 2.1.0, IANA TLS group registry, PQC OID assignments — are saved under `knowledge/sources/`. No external fetches required to understand or build the project.

---

## Roadmap

- **Clear 85% at the lower CI bound.** Phase 18 reached an 84.5% point estimate but a 78.5% lower bound. Closing that gap means both raising the point estimate and shrinking the interval with a larger audited sample.
- **Broader language coverage:** the Go rule pack is the least developed among the four largest packs today (94 classify arms vs. Java's 161, C/C++'s 117, and C#'s 115 — C/C++ grew past its earlier last-place position via the OpenSSL/liboqs PQC keygen and fetch coverage added across cycles 44–61). Expanding Go classify rules is the highest-leverage near-term coverage move.
- **Community rule packs:** the TOML rule format is public and stable. The path to community contributions is a contributed-rules directory and a CI gate that runs new rules against the benchmark corpus before merge.
- **Agentic remediation:** a companion engine that consumes the MCP output and proposes verified migration patches, gated on ACVP known-answer tests, oqs-provider interop, and semantic-preservation differential testing.
- **Continuous CBOM drift monitoring:** weekly re-scans, CBOM diff between runs, and a one-paragraph alert per material change in your cryptographic inventory.

---

## Responsible use

Network probes (`--allow-network`) open real TCP connections. quipuu performs only normal TLS handshakes — no fuzzing, no malformed messages, no exploit attempts. A consent banner prints before any network probe runs.

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

quipuu's outputs and risk model are anchored on primary sources, all saved locally under `knowledge/sources/`:

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
cd quipuu && cargo test --workspace

# Live-network tests (requires outbound TCP — skipped by default)
cd quipuu && cargo test -p quipuu-scan-network -- --ignored

# Knowledge-base consistency checks
python3 tests/check.py
```

---

## License

Apache-2.0. See `quipuu/Cargo.toml`.

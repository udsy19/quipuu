# Proving quipuu: Evidence, Benchmarking, and Reproducibility

> A scanner with no numbers is a marketing claim. This document specifies how we
> generate the numbers that turn "as good as the incumbents" from a hope into a
> public, reproducible, auditable fact.

**Read with:** `SPEC.md`.

---

## 1. What "as good or better" actually has to mean

The phrase doesn't survive a CISO interview unless we decompose it into specific, measurable axes. There are six.

| Axis | What it means | How CISOs interpret it |
|---|---|---|
| **Precision** | of N findings, how many are true positives | "How often does this waste my team's time?" |
| **Recall** | of M true positives in ground truth, how many did the scanner find | "What does it miss?" |
| **Speed** | findings/sec on a fixed corpus | "Will this run in CI?" |
| **Coverage** | which languages, manifest types, OIDs, TLS groups, cert formats | "Does it handle my stack?" |
| **Output validity** | does the emitted CBOM/SARIF actually validate against the canonical schema | "Will my downstream pipeline ingest it?" |
| **Determinism** | same input → same output, across runs and machines | "Can my auditor reproduce the report next quarter?" |

We need numbers on all six, against every credible incumbent. No hand-waving on any single one.

---

## 2. The credible incumbents to benchmark against

From the V2 data run:

| Tool | Status | Why included |
|---|---|---|
| **IBM CBOMkit** | OSS, Java/Python/Go via SonarQube plugin | The canonical CBOM tool everyone references |
| **cryptobom-forge** (Santander) | OSS, post-processes CodeQL SARIF | The Santander/IBM-adjacent OSS path |
| **foxguard** (0sec-labs) | OSS, 267⭐ Rust, source + TLS config | The closest direct OSS Rust competitor |
| **Semgrep crypto rulepack** | OSS rules, runs in Semgrep | What every SAST team already has |
| **CodeQL crypto queries** | OSS, GitHub | The default at GitHub-shop CISOs |
| **Snyk Code (crypto)** | Closed-source SaaS | The commercial dominant SAST |
| **SandboxAQ AQtive Guard** | Closed-source SaaS | The deep-pocketed PQC-focused competitor |
| **PQShield UltraScan** | Closed-source | The PQC-pure-play competitor |

For closed-source tools we can only benchmark via trial accounts / public artifacts / vendor-published numbers. We mark those clearly as "limited-access" and don't claim parity on axes we can't measure.

---

## 3. The benchmark corpus — what we run all tools against

A benchmark is only as good as its corpus. Three corpora, each with a different purpose:

### Corpus A — Ground-truth fixtures (small, hand-labeled, public)

**Purpose:** measure precision and recall against a known oracle.

**Contents:** ~200 files we author and label by hand, distributed across all 7 supported languages. Each file:
- Has between 0 and 10 cryptographic call sites
- Every call site is hand-labeled with `(algorithm_id, line, expected_finding)`
- Includes adversarial cases: vendored crypto, hardcoded strings, variable-flow, false-positive bait (variable named `aes_key` that's actually a hash output, function called `encrypt()` that's `base64.b64encode`)
- Includes negative cases: ~50 files with zero crypto

**Location:** `benchmarks/corpus-a-ground-truth/` (public). Every fixture comes with a paired `expected.toml` listing the labeled findings. The corpus is itself a published artifact — competitors can run their tools against it and report numbers.

**Composition target:**
- Go: 25 files (~150 sites)
- Python: 25 files (~150 sites)  
- Java: 20 files (~100 sites)
- JS/TS: 20 files (~100 sites)
- C/C++: 15 files (~75 sites)
- Rust: 10 files (~50 sites)
- C#: 10 files (~50 sites)
- "Adversarial" subdirectory: ~40 files (false-positive bait, vendored crypto, obfuscated)
- "Negative" subdirectory: ~50 files (zero crypto, but realistically crypto-adjacent)

**Why this works:** ground truth is the only way to compute precision/recall honestly. Hand-labeling 200 files is achievable; hand-labeling 200,000 isn't.

### Corpus B — Real-world OSS (large, derived, public)

**Purpose:** measure throughput, coverage, and *scale* — does the scanner work on real projects, not just curated fixtures.

**Contents:** the State-of-X corpus, expanded. V2 ran 14 SCANNED + 6 PROJECTED real OSS projects. Production-quality benchmarking needs ~100 projects:
- Top-30 PyPI packages (by downloads, filtered for ones containing crypto)
- Top-30 npm packages (same)
- Top-15 crates.io packages
- Top-15 Go modules
- Top-10 Maven artifacts
- And specifically: `requests`, `cryptography`, `rustls`, `ring`, `bouncycastle`, `node-forge`, `pyjwt`, `golang-jwt`, etc. — the actual crypto-heavy real-world projects

**Location:** `benchmarks/corpus-b-realworld/`. Per project: a `clone.sh` script that fetches the project at a pinned commit SHA, plus the project's metadata. The corpus *does not* include the project source itself (license/size); the benchmark runner clones fresh.

**Reproducibility:** every benchmark run records the SHAs cloned. Re-running pulls the same SHAs. If a project's history is rewritten or deleted from GitHub, we have a fallback `archive_url` in the metadata.

### Corpus C — Synthetic adversarial (designed to break scanners)

**Purpose:** measure robustness — does the scanner fail-soft, produce false negatives, crash, or hallucinate.

**Contents:** ~50 files specifically designed to be hard:
- A 50 MB file with one crypto call buried at the end (memory test)
- A file with deeply nested function calls (AST stack-overflow test)
- A file with UTF-16 BOM (encoding test)
- A file with `// rsa.GenerateKey(2048)` — *only in a comment* (false-positive test)
- A file using crypto via reflection / `eval` / dynamic class loading (intentional miss case)
- A file that's syntactically invalid in places (recovery test)
- A file with confusable unicode in identifiers (homoglyph test)

**Location:** `benchmarks/corpus-c-adversarial/`. Each file has an `expected.toml` declaring what should and should not be found.

---

## 4. The methodology — how every benchmark is run

The bedrock is: **every number we publish is reproducible by a third party who runs one script.**

### The runner

`benchmarks/run_all.py` — a single entrypoint that:

1. Verifies every tool's version (records exact version + commit SHA for reproducibility)
2. Pulls the corpora (corpus A + corpus B fresh clones at pinned SHAs + corpus C local)
3. Runs each tool against each corpus with identical inputs
4. Captures: raw findings, runtime, peak memory, exit code, stdout/stderr
5. Validates output where applicable (CBOM against `bom-1.7.schema.json`, SARIF against `sarif-2.1.0.json`)
6. Computes precision/recall against ground-truth labels (corpus A only — the others have no ground truth)
7. Emits a structured `results-<timestamp>.json` + a human-readable `report.md`

Constraints baked in:
- **Same hardware envelope.** Benchmarks run inside a Docker container with fixed CPU/memory limits (4 cores, 8 GB). Speed numbers compare apples to apples.
- **Same input bytes.** All tools see the same source on the same filesystem.
- **Repeated runs.** Each tool runs 3× per corpus; we publish median and the inter-run variance. A tool with high variance is flagged.
- **Network-disabled by default.** `--allow-network` is opt-in. We don't want a benchmark contaminated by a tool that phones home and gets different results based on a live CVE feed.

### The metrics, formally

**Precision** = TP / (TP + FP), measured on corpus A only.
**Recall** = TP / (TP + FN), measured on corpus A only.
**F1** = 2 × (P × R) / (P + R).
**Throughput** = lines-of-code-scanned-per-second, measured on corpus B.
**Peak memory** = max RSS during scan, measured on corpus B.
**Output schema-validity** = % of emitted CBOM/SARIF that validate, measured on corpus B.
**Determinism rate** = % of files where 3 successive runs produce byte-identical findings, measured on corpus C.

For tools that don't emit CBOM/SARIF directly, we measure only the axes they expose.

### The ground-truth oracle (the part where honesty matters)

For corpus A, every fixture file has an `expected.toml` we authored by hand. A **disagreement protocol**: if our scanner finds something the oracle doesn't claim, *we don't auto-call it a false positive*. We log it as a "disagreement" and route it to a human review. If on review the finding is in fact real and the oracle was wrong, we update the oracle. If it's a hallucination, we mark it FP.

This is the only honest way to do this. Without the disagreement protocol, the team authoring the oracle has an obvious incentive to label every quipuu finding as ground truth and every competitor finding as noise. The disagreement log is published as part of the benchmark output.

---

## 5. What each metric will look like in published form

Mock results table — what the published artifact contains, with the actual numbers filled in after a real run:

### Precision / Recall on Corpus A (ground truth, 200 files, ~675 sites)

| Tool | TP | FP | FN | Precision | Recall | F1 | Disagreements |
|---|---|---|---|---|---|---|---|
| quipuu | _ | _ | _ | _ | _ | _ | _ |
| CBOMkit | _ | _ | _ | _ | _ | _ | _ |
| cryptobom-forge | _ | _ | _ | _ | _ | _ | _ |
| foxguard | _ | _ | _ | _ | _ | _ | _ |
| Semgrep crypto | _ | _ | _ | _ | _ | _ | _ |
| CodeQL crypto | _ | _ | _ | _ | _ | _ | _ |

### Throughput on Corpus B (100 OSS projects)

| Tool | Median LOC/sec | p95 LOC/sec | Peak memory (median) |
|---|---|---|---|
| quipuu | _ | _ | _ |
| CBOMkit | _ | _ | _ |
| foxguard | _ | _ | _ |
| Semgrep crypto | _ | _ | _ |

### Output validity on Corpus B

| Tool | Emits CBOM? | CBOM schema-valid % | Emits SARIF? | SARIF schema-valid % |
|---|---|---|---|---|
| quipuu | 1.7 | _ | 2.1.0 | _ |
| CBOMkit | 1.6 | _ | n/a | n/a |
| cryptobom-forge | 1.6 | _ | n/a | n/a |
| foxguard | 1.6 | _ | n/a | n/a |
| Semgrep crypto | n/a | n/a | 2.1.0 | _ |

### Determinism on Corpus C (3 runs each)

| Tool | Files with identical 3-run output | Crash rate | Disagreement rate within tool |
|---|---|---|---|
| quipuu | _ | _ | _ |
| ... | _ | _ | _ |

---

## 6. Where the comparison is *not* fair, and how we handle it

Honesty about apples vs oranges:

- **CBOMkit is a SonarQube plugin.** Running it standalone requires a SonarQube server. We containerize that — Java + SonarQube + plugin — but the startup time is real and we report it separately ("first-scan latency" vs "warm scan latency"). It's not fair to count Sonar server startup against CBOMkit's throughput, but it *is* fair to flag it as a deployment friction. That same server is also what CBOMkit gets in return: a persistent CBOM database, a query API, and SonarQube's compliance-policy surface — capabilities a single local binary doesn't offer by architecture.
- **cryptobom-forge runs on top of CodeQL SARIF.** It can't find what CodeQL didn't surface. We benchmark the pipeline together (CodeQL + cryptobom-forge) and report it as a stack.
- **Snyk and SandboxAQ are closed-source.** We can run trial accounts against our corpus and report what they find. We *cannot* benchmark throughput because we don't control their infrastructure. We mark these "limited-access" and only report precision/recall.
- **Semgrep crypto rulepack is rule-driven.** It only finds what its rules describe. We measure it on the rules it has; we don't punish it for things outside its scope (e.g., it doesn't claim to do TLS probing, so it isn't compared on TLS).

Every limitation is documented in the published benchmark output. The result table is annotated, not hidden behind a marketing chart.

---

## 7. The reproducibility commitment

Three artifacts make this defensible:

### A. Public corpus + benchmark repo

`benchmarks/` ships in the quipuu repository (or a sister repo if size becomes an issue). Anyone can clone it, run `./run_all.py`, and reproduce our published numbers within 5–10% variance. The 5–10% accounts for hardware/clock-speed differences; anything outside that range is a real divergence and we want to know about it.

### B. Published methodology document

`benchmarks/METHODOLOGY.md` — the long-form version of this document, linked from the main README and from the published report. It commits to specific things:
- The exact corpus SHAs (corpus A is content-addressable; corpus B is git-SHA-pinned)
- The exact tool versions
- The disagreement protocol
- The treatment of closed-source competitors

### C. Continuous benchmarks in CI

On every push to `main`, `benchmarks/run_all.py` runs against corpus A in the GitHub Actions matrix. The CI dashboard shows trend lines — precision, recall, throughput over time. **A regression in any metric blocks the merge.** This isn't a marketing artifact; it's an engineering discipline that produces a marketing artifact as a side effect.

---

## 8. The credibility-magnet artifacts that fall out

The benchmarks generate three publishable artifacts. Each is designed to be screenshot-able, shareable, and to convert.

### Artifact 1: The leaderboard

A single page (rendered HTML, hosted at quipuu.dev/benchmarks) showing:
- The 4 metric tables above
- One sentence per row of "why does the metric look this way"
- A "last updated" timestamp + commit SHA
- A link to reproduce-it-yourself

This is the page a CISO sends their team. "Look at the F1 column. Compare deployment friction. Decide."

### Artifact 2: The "State of Quantum-Vulnerable Cryptography 2026" report


### Artifact 3: The academic paper

We submit a paper to NDSS / USENIX Security / ICSE: "An auditable, reproducible benchmark for cryptographic discovery tools." The paper itself is small (10-12 pages); the contribution is the benchmark corpus + methodology. Academic publication legitimizes our numbers in a way no vendor blog post can. NCCoE / CISA / standards bodies cite peer-reviewed papers, not vendor whitepapers.

This is also free distribution: the paper gets cited by anyone else who runs the benchmark, which means our methodology becomes the standard.

---

## 9. The roadmap to first publication

| Week | Deliverable |
|---|---|
| W1 | Corpus A skeleton: 50 fixtures with ground-truth labels (Go + Python first) |
| W2 | Corpus A complete: all 7 languages, ~200 fixtures, full ground-truth |
| W3 | Corpus B clone scripts: 100 OSS projects pinned by SHA |
| W4 | Corpus C: 50 adversarial fixtures + expected behavior |
| W5 | `run_all.py` runner: quipuu + foxguard + CBOMkit + Semgrep |
| W6 | `run_all.py` finished: + CodeQL + cryptobom-forge + Snyk (limited) + SandboxAQ (limited) |
| W7 | First full benchmark run; methodology doc; results JSON + report.md |
| W8 | Leaderboard page; CI integration; reproducibility test on a clean machine |
| W9 | "State of Q-V Crypto 2026" report published using same data |
| W10 | Academic paper draft submitted |

10 weeks to "we have public, reproducible, peer-reviewed numbers proving quipuu is at least as good as incumbents on the axes that matter, and dramatically better on output validity, determinism, and deployment friction."

---

## 10. The honest expectations

A few things I expect to find, with confidence levels:

| Prediction | Confidence |
|---|---|
| quipuu will lead on **output schema validity** (we ship a validator; competitors mostly don't) | High |
| quipuu will lead on **throughput** (Rust + parallelism vs JVM/Python stacks) | High |
| quipuu will lead on **determinism** (P3 invariant: literal-traceable findings) | High |
| quipuu will lead on **deployment friction** (single static binary, no JVM/server) | Very high |
| quipuu will be **competitive but not dominant** on raw precision/recall vs CBOMkit on Java/Python | Medium |
| quipuu will **lose** to specialized tools on language-specific edge cases (e.g., jjwt enum resolution per V2) | High |
| quipuu will lead on **CycloneDX 1.7 support** (we ship it; CBOMkit is still 1.6 per the research) | High |
| quipuu will lead on **HNDL prioritization and risk scoring** (no incumbent does this) | Very high |

The benchmarking is designed so we don't have to win every axis. We have to **measure** every axis. The marketing falls out: "we win 7 of 10; we lose 2; we tie 1; here are the numbers; here's the data; reproduce it yourself."

That's how an audit-grade tool sells in a market that's correctly suspicious of vendor claims.

---

## 11. Risks to this whole strategy

Three things that could undermine the benchmarks:

1. **Ground-truth labeling is genuinely hard.** A reasonable expert disagrees with another reasonable expert about whether a particular call site is "cryptographically relevant." The disagreement protocol helps; doesn't eliminate the issue. **Mitigation:** publish the labels as part of the corpus, invite criticism, version the labels.

2. **The competitive landscape shifts during the 10 weeks.** CBOMkit releases v2 with everything we measured against fixed. **Mitigation:** the benchmark runs continuously. New competitor version → re-run the benchmark → numbers update. The artifact is alive, not a snapshot.

3. **Closed-source competitors object to being benchmarked.** Snyk's TOS may prohibit publishing benchmark numbers without permission. **Mitigation:** consult counsel, but the academic-paper route is generally covered by fair-use / research exceptions. Worst case: we publish numbers for OSS tools and a generic "commercial tools tested under NDA" row.

---

## 12. What we do not benchmark, and why

- **Quality of remediation PRs.** The scanner does not generate PRs, so there is nothing here to measure. Whatever consumes its output and proposes a change is a separate program with a separate harness.
- **Long-term scalability.** A scanner that's fast on 100 projects might choke on 100,000. We measure throughput, not asymptotic complexity. (We may eventually add a "monorepo scale" axis, but not in v0.1.)
- **UI quality.** Subjective. The HTML report is what it is; we measure that it's standards-compliant and reproducible, not "pretty."

---

## 13. The one-sentence summary

**Build the corpus, build the runner, publish the numbers, defend them in peer review — and the question "is quipuu as good as the incumbents" stops being a marketing claim and becomes a measurable, public, audit-grade fact.**

That's the credibility moat that turns the OSS scanner from "another security tool" into "the reference standard for cryptographic discovery."

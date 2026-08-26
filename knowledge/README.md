# Knowledge Base — cryptoscope research pass

This folder is the **single source of truth** for every load-bearing technical and strategic claim that the cryptoscope build rests on. Every recommendation in `SPEC.md` and every line of code Claude Code writes should trace back to a "Why → Evidence" entry here.

> **Reading order if you're new:** start with `11-decisions/` (the synthesis), then drill into the topic folders for the underlying evidence.

## Layout

| Folder | What's in it |
|---|---|
| `01-cbom-schema/` | CycloneDX 1.6 + 1.7 CBOM schema — extracted verbatim from canonical JSON, full cryptoProperties subtree, occurrences/callstack provenance, protocol→algorithm linkage, validator landscape. |
| `02-nist-pqc-timeline/` | NIST IR 8547 (still IPD), FIPS 203/204/205 (final) + FIPS 206 (not even IPD), SP 800-131A Rev 3 status, CNSA 2.0 (NSA) timetable and where it differs from NIST. |
| `03-detection-patterns/` | tree-sitter detection patterns by language; CBOMkit rule schema; two-layer rule format proposal. |
| `04-tls-pqc/` | IANA TLS supported-groups + signature-schemes, rustls/aws-lc-rs PQC state, two-tier prober design, OpenSSL 3.5 native PQC. |
| `05-x509-pqc/` | Full classical + PQC OID tables (RFC 9881, 9909, 9935), x509-parser coverage, SHA-1 cert deprecation. |
| `06-hndl-threat-model/` | HNDL framings (NSA, NIST, ENISA, NCSC, M-23-02), Mosca's inequality, data-shelf-life taxonomy, the 5-axis QuantumRiskScore. |
| `07-sarif/` | SARIF 2.1.0 minimum fields, GitHub/GitLab ingestion quirks, working example for a single finding. |
| `08-competitors/` | IBM CBOMkit, cryptobom-forge, BF-CBOM, SandboxAQ, PANW, Qtonic, Zerberus, Acubed, CryptoScan/CSNP, foxguard. Wedge axes — confirmed vs. eroded. |
| `09-regulatory/` | OMB M-23-02, NSM-10, CNSA 2.0, CISA, UK NCSC, EU CRA, NIS2, BSI, ANSSI, Australia ASD ISM-1917, India CERT-In BOM v2.0, PCI DSS, NYDFS — what's binding today. |
| `10-design-partners/` | Cloudflare, Google, Apple PQ3 / iOS 26, AWS, Microsoft, Meta, IBM, Signal, JPMorgan PQC programs. Shortlist of who'd adopt cryptoscope. |
| `11-decisions/` | The **decisions register** — 13 Why → Evidence → Decision entries that the build should follow. Start here. Also contains `verify-resolution.md` (5 follow-ups closed) and `data/` (operational TOML files cryptoscope ships with). |
| `11-decisions/data/` | **The actual data files cryptoscope ships with** — `algorithm-table.toml` (67 algorithms), `oid-table.toml` (57 OIDs), `default-policy.toml` (NIST IR 8547 IPD defaults), `rules/go.toml`, `rules/python.toml`. All parse, all cross-references resolve. |
| `sources/` | Canonical primary sources downloaded locally: CycloneDX schemas, official CBOM example, NIST FIPS 203/204/205 PDFs, NIST IR 8547 IPD PDF, SP 800-131A Rev 3 IPD PDF, CBOMkit detection rules, IANA TLS registries. |

## How to amend this folder

1. **Find or create the relevant topic folder.** Don't write into the wrong one — the structure is how decisions get audited later.
2. **Cite primary sources.** Spec JSONs, RFCs, NIST publications, vendor engineering blogs *with concrete technical claims*. Marketing pages don't count.
3. **If a fact contradicts an existing decision in `11-decisions/`, update the decision in the same PR.** Never let evidence and decisions drift apart.
4. **`sources/` holds raw artifacts** (PDFs, schema JSON, downloaded rule files). Don't paraphrase — if the document is short enough to download, save it.

## Status — what was researched in this pass

| Topic | Status | Confidence |
|---|---|---|
| CycloneDX 1.6/1.7 schema (full subtree) | Extracted verbatim from canonical JSON | High |
| NIST IR 8547 timeline | Confirmed; still IPD | High (timeline is draft, but doc itself is current) |
| FIPS 203/204/205 status | Confirmed final, Aug 2024 | High (PDFs in sources/) |
| FIPS 206 (FN-DSA) | Confirmed: not even IPD as of mid-2026 | High |
| Detection patterns + CBOMkit rule format | CBOMkit rule schema saved; two-layer format proposed | High |
| rustls + PQC TLS state | Crate versions current to mid-2026; IANA codepoints confirmed | High |
| X.509 + PQC OIDs | RFC 9881 / 9909 / 9935 confirmed; composite drafts pending IANA | High for finalized, Medium for drafts |
| HNDL framings | 5 primary-source agreements documented | High |
| SARIF 2.1.0 | OASIS spec + GitHub/GitLab quirks documented | High |
| Competitor landscape | 13 vendors surveyed; wedge re-evaluated | Medium-High (vendor pages are marketing fog) |
| Regulatory drivers | 22 jurisdictions/regs reviewed; one binding hard deadline globally | High |
| Design-partner shortlist | 11 enterprise/OSS programs surveyed | Medium (depends on public disclosures) |

## Outstanding work

Initial `[VERIFY]` items have been resolved — see `11-decisions/verify-resolution.md` for the five-item triage (IANA codepoints, rustls-post-quantum, composite ML-DSA, foxguard walkthrough, name decision).

The only standing watch item is:

- **NIST IR 8547 final publication date** (`02-nist-pqc-timeline`). The IPD timeline is what we ship; the final could move dates and we'll need to update the default policy file when it does.

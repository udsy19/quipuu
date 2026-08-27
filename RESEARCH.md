# Research — log + index

This is the **log** of the research passes that informed the build. The actual research content lives in `knowledge/`. Start there.

| File / folder | What it is |
|---|---|
| `knowledge/README.md` | Index of the knowledge base. |
| `knowledge/11-decisions/README.md` | The decisions register (13 entries, Why → Evidence → Decision). **Read first.** |
| `knowledge/01-cbom-schema/` … `knowledge/11-decisions/` | Topic deep dives, all primary-source cited. |
| `knowledge/sources/` | Canonical primary documents downloaded locally — CycloneDX schemas, FIPS 203/204/205 PDFs, NIST IR 8547 IPD PDF, SP 800-131A Rev 3 IPD PDF, CBOMkit detection rules. |
| `SPEC.md` | Build spec, updated to reflect every decision in the register. |

## Research-pass log

### Pass 1 — 2026-06-12, deep-research workflow (108 subagents)

- Ran 5-angle decomposition (CBOM schema, NIST timeline, Rust TLS, competitors, regulatory). Fetched 26 sources, extracted 111 claims, adversarially verified 25, confirmed 15, killed 10.
- Verified: CycloneDX 1.6 schema field names + enums, NIST IR 8547 timeline (still IPD), FIPS 203/204/205 finalization.
- Workflow stalled once on a hung verifier agent; recovered with `TaskStop` + `resumeFromRunId` (31/32 cached, only the stuck one re-ran).
- Wrote the initial `RESEARCH.md` (since superseded by this index + `knowledge/`).

### Pass 2 — 2026-06-12, focused-agent fan-out (10 specialist agents)

- Direct WebFetch + curl of canonical CycloneDX 1.6 and 1.7 schemas + official Protocol CBOM example → unblocked the CBOM emitter design (`knowledge/01-cbom-schema/`).
- Ten parallel Agent runs, one per topic in `knowledge/`. Each writes its own topic file with primary-source citations. Knowledge base wired together via the index README and the decisions register.
- Surfaced four new competitors not in the original spec (foxguard, Qtonic QScout, Zerberus PQC, Acubed.IT PQC-RA) and one major thesis-tweaker (CryptoScan/CSNP has the working-name we wanted).
- Surfaced the Cloudflare/Chrome/Apple PQC default-on rollout that reshapes positioning (D-12).

## Confidence summary

| Knowledge folder | Confidence | Notes |
|---|---|---|
| 01 CBOM schema | High | Extracted verbatim from canonical JSON files saved in `sources/`. |
| 02 NIST timeline | High | FIPS 203/204/205 PDFs in `sources/`. Timeline itself is from IR 8547 *draft* — flagged. |
| 03 Detection patterns | High | CBOMkit's rule schema saved in `sources/`. |
| 04 TLS PQC | High | IANA codepoints + crate versions current to mid-2026. |
| 05 X.509 PQC | High | RFC 9881 / 9909 / 9935 confirmed; composite drafts flagged. |
| 06 HNDL threat model | High | Primary-source agreements documented; Rufino 2025 limitation acknowledged. |
| 07 SARIF | High | OASIS spec + GitHub/GitLab quirks documented; working example included. |
| 08 Competitors | Medium-High | Marketing pages are fog; technical claims verified where possible. |
| 09 Regulatory | High | 22 jurisdictions reviewed; only one binding hard deadline globally. |
| 10 Design partners | Medium | Depends on public engineering disclosures. |

## Outstanding items

All initial `[VERIFY]` items resolved in `knowledge/11-decisions/verify-resolution.md` (2026-06-12):

- ✅ MLKEM768 standalone IANA codepoint — registered (513).
- ✅ `rustls-post-quantum` latest — 0.2.4 (2025-09-23, superseded by rustls core).
- ✅ Composite ML-DSA codepoints — still TBD; pure ML-DSA/SLH-DSA registered.
- ✅ foxguard walkthrough — confirmed 6/10 wedge axes hold; collaboration play identified.
- ✅ Working name — `seawall` available on crates.io, no real collision; keep.

Standing watch item:
- NIST IR 8547 final publication date — currently still IPD. Update default `policy.toml` when final lands.

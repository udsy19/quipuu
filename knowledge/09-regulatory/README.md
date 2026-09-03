# Post-Quantum Cryptography Regulatory Landscape

> Research date: June 2026, with items 23–25 and the BSI TR-02102 update in §14 added September 2026. Primary sources only. Where no hard deadline was confirmed from a primary source, this file says so explicitly — no deadlines are invented.

---

## US FEDERAL

### 1. OMB M-23-02 — Migrating to Post-Quantum Cryptography (Nov 18, 2022)

**Issuing body:** Office of Management and Budget (Director Shalanda D. Young)
**Primary source:** https://www.whitehouse.gov/wp-content/uploads/2022/11/M-23-02-M-Memo-on-Migrating-to-Post-Quantum-Cryptography.pdf
**Archive:** https://bidenwhitehouse.archives.gov/omb/information-for-agencies/memoranda/

**Scope:** All Federal Civilian Executive Branch (FCEB) agencies.

**What is required:** Agencies must inventory all "active software or hardware implementations of one or more cryptographic algorithms that provide: (1) creation and exchange of encryption keys; (2) encrypted connections; or (3) creation and validation of digital signatures." Priority on High Value Assets (HVAs) and FIPS-199 High/Moderate systems.

**Exact deadlines:**
- **May 4, 2023** — First annual cryptographic inventory submission (one year after NSM-10 signing).
- **Within 30 days of each annual inventory** — Agencies must provide a funding/cost assessment for migration in the following fiscal year.
- **~February 2023 (90 days post-issuance)** — ONCD required to release agency instructions including cost reporting templates.
- **Annual** — Continuing inventory re-submission obligation; agencies must identify a cryptographic inventory/migration lead.
- **Statutory trigger (Quantum Computing Cybersecurity Preparedness Act, Dec 2022):** Within 1 year of NIST issuing PQC standards (FIPS 203/204/205 published Aug 13, 2024 → statutory deadline ~Aug 13, 2025), OMB must issue guidance requiring agencies to begin prioritizing migration. No public evidence this August 2025 deadline was formally met.

**2026 updates:** A January 8, 2024 technical correction was published; no substantive deadline changes confirmed. A July 2024 White House report estimated the total government-wide PQC migration cost at ~$7.1 billion (2024 dollars, 2025–2035).

**Implication for quipuu:** The inventory obligation recurs annually and OMB publishes no tooling for it, so the artifact an agency has to produce every year is a machine-generated cryptographic inventory — which is what `--cbom` emits.

---

### 2. NSM-10 — National Security Memorandum 10 (May 4, 2022) + CNSA 2.0

**Issuing body:** White House (President Biden); NSA (CNSA 2.0 implementation guidance)
**Primary sources:**
- NSM-10: https://www.whitehouse.gov/briefing-room/statements-releases/2022/05/04/national-security-memorandum-on-promoting-united-states-leadership-in-quantum-computing-while-mitigating-risks-to-vulnerable-cryptographic-systems/
- CNSA 2.0 Advisory (Sep 10, 2022): https://www.nsa.gov/Press-Room/News-Highlights/Article/Article/3148990/nsa-releases-future-quantum-resistant-qr-algorithm-requirements-for-national-se/
- CNSA 2.0 FAQ v2.1 (Dec 2024): https://media.defense.gov/2025/May/30/2003728741/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS.PDF

**Scope:** All National Security Systems (NSS), DoD, Intelligence Community, and NSS contractors.

**What is required:** Full migration to quantum-resistant cryptography. Within 1 year of NSM-10 (by May 2023), agencies operating NSS must identify and document all quantum-vulnerable cryptography. By December 31, 2023, agencies must implement symmetric-key protections (HAIPE exclusion keys / VPN symmetric key solutions).

**CNSA 2.0 staggered deadlines (binding on NSS):**

| System Category | Support & Prefer CNSA 2.0 | Exclusively Use CNSA 2.0 |
|---|---|---|
| Software & Firmware Signing | **2025** | **2030** |
| Web Browsers, Servers & Cloud Services | **2025** | **2033** |
| Traditional Networking (VPNs, Routers) | **2026** | **2030** |
| Operating Systems | **2027** | **2033** |
| Constrained Devices / Large PKIs | **2030** | **2033** |

**Exact quote (CNSA 2.0):** "Software and firmware signing applications should begin transitioning immediately, support and prefer CNSA 2.0 by 2025, and exclusively use CNSA 2.0 by 2030."

**NSS acquisition gate:** Starting **January 1, 2027**, all new acquisitions of NSS equipment must support CNSA 2.0 algorithms by default.

**Overall NSS targets:** "NSA expects the vast majority of cryptography in NSS to be quantum resistant by December 31, 2031" and "expects the transition to quantum-resistant algorithms for NSS to be complete by 2035 in line with NSM-10."

**Approved CNSA 2.0 algorithms for NSS:** ML-KEM-1024 (FIPS 203), ML-DSA-87 (FIPS 204), LMS/single-tree XMSS (NIST SP 800-208) for firmware signing, AES-256, SHA-384+. SLH-DSA (FIPS 205) and FN-DSA (FIPS 206/Falcon) are **not** approved for NSS. HSS and XMSS^MT are prohibited.

**Implication for quipuu:** The CNSA 2.0 procurement gate (Jan 2027) means NSS contractors must demonstrate algorithm-level compliance — a scanner that produces a CBOM (Cryptography Bill of Materials) per system is the natural compliance artifact.

---

### 3. CISA / NSA / NIST Joint Factsheet — Quantum-Readiness (Aug 21, 2023)

**Issuing body:** CISA, NSA, NIST (joint)
**Primary sources:**
- DoD mirror PDF: https://media.defense.gov/2023/Aug/21/2003284212/-1/-1/0/CSI-QUANTUM-READINESS.PDF
- CISA Alert: https://www.cisa.gov/news-events/alerts/2023/08/21/cisa-nsa-and-nist-publish-factsheet-quantum-readiness
- CISA resource page: https://www.cisa.gov/resources-tools/resources/quantum-readiness-preparing-post-quantum-cryptography

**Scope:** All 16 critical-infrastructure sectors, technology vendors, and general organizations.

**What is required (key exact quotes):**
- "CISA, NSA, and NIST urge organizations to begin preparing now by creating quantum-readiness roadmaps, **conducting inventories**, applying risk assessments and analysis, and engaging vendors."
- On harvest-now-decrypt-later: "cyber threat actors could be targeting data today that would still require protection in the future... using a **catch now, break later** or **harvest now, decrypt later** operation."
- On custom-built tech: these "will likely require the most effort to make quantum-resistant."

**Five key recommendations for CI operators:**
1. Establish a quantum-readiness project team and roadmap.
2. **Build a cryptographic inventory** (discovery tools across IT and OT environments, including CI/CD pipelines).
3. Engage technology vendors about their PQC roadmaps for COTS and cloud-based products.
4. Prioritize high-impact systems, ICS/SCADA, and data with long confidentiality lifetimes.
5. Address custom-built technologies — they require the most migration effort.

**Hard deadline:** None imposed on CI operators in this document. Guidance only.

**Implication for quipuu:** CISA explicitly names "cryptographic inventory" using "discovery tools across IT/OT/CI/CD" as the first technical action item — this is precisely quipuu's primary use case, cited by the top US cyber regulator.

**Also (Executive Order 14306 §(f)(i), 2025-06-06):** EO 14306 required DHS/CISA to publish a PQC
product-categories list by 2025-12-01. CISA published *"Product Categories for Technologies That
Use Post-Quantum Cryptography Standards"* 53 days late, on 2026-01-23 — a procurement-category list
organized by cryptographic function. Record-only: it sets no algorithm rules and imposes no new
deadline of its own. For "Widely Available" categories (Table 2), the list states organizations
"should acquire only PQC-capable products when planning acquisitions" — an advisory acquisition
recommendation, not a binding requirement; "Transitioning" categories (Table 3) carry no such
language.

---

### 4. NIST NCCoE Migration to PQC Project (SP 1800-38)

**Issuing body:** NIST National Cybersecurity Center of Excellence (NCCoE)
**Primary source:** https://www.nccoe.nist.gov/applied-cryptography/migration-to-pqc
**Practice Guide drafts:** NIST SP 1800-38A/B/C (all Preliminary Drafts as of mid-2026)

**Scope:** Government agencies, critical infrastructure, and any enterprise undertaking PQC migration.

**What it produces:** Two workstreams:
1. **Cryptographic Discovery (SP 1800-38B)** — How to inventory where and how cryptography is used. Demonstrates that "no single product may find all instances of vulnerable crypto" — multiple tools must be used in tandem.
2. **Interoperability & Performance Testing (SP 1800-38C)** — PQC in TLS, QUIC, SSH, and HSMs.

**Current phase:** Preliminary drafts published December 2023; expanded public comment period (CSWP 48, closed October 20, 2025); final publication not yet scheduled as of mid-2026.

**Named industry CRADA collaborators (47+, partial list):** Amazon Web Services, Cisco Systems, IBM, JPMorgan Chase, Microsoft, NSA, CISA, Palo Alto Networks, Samsung SDS, SandboxAQ, Keyfactor, Thales DIS CPL USA, InfoSec Global, MITRE, HSBC, wolfSSL, ISARA Corporation, U.S. Army DEVCOM C5ISR Center.

**Implication for quipuu:** The project's explicit finding that "no single product finds all vulnerable crypto" is the argument for scanning source, dependencies, certificates and TLS in one pass rather than doing one of them well. SP 1800-38B is the reference architecture quipuu should align to.

---

### 5. NIST IR 8547 — Transition to Post-Quantum Cryptography Standards

**Issuing body:** NIST
**Primary source (IPD):** https://csrc.nist.gov/pubs/ir/8547/ipd
**IPD PDF:** https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf

**Status as of mid-2026: STILL IN INITIAL PUBLIC DRAFT — NOT FINALIZED.**
Published November 12, 2024. Public comment period closed January 10, 2025. No second draft or final publication date announced as of June 2026. The `/final` URL returns 404.

**Proposed deprecation/disallowance framework (from IPD — not yet binding):**

| Algorithm | Deprecated After | Disallowed After |
|---|---|---|
| RSA-2048 (112-bit) | **2030** | **2035** |
| RSA-3072+ (≥128-bit) | — | **2035** |
| ECDSA P-256 (112-bit) | **2030** | **2035** |
| ECDSA P-384+ (≥128-bit) | — | **2035** |
| ECDH (all) | **2030** | **2035** |
| DSA / FFDH (112-bit) | **2030** | **2035** |
| EdDSA (≥128-bit) | — | **2035** |

**Important caveat:** These 2030/2035 dates are IPD proposals, not yet binding federal standards. They signal NIST's direction and are already being treated as de facto targets by industry.

**Implication for quipuu:** Once finalized, IR 8547 will be the statutory basis for deprecation warnings in any crypto scanner. Quipuu's severity classifications should map directly to these 2030/2035 thresholds.

---

### 6. FedRAMP PQC Requirements (2025–2026)

**Issuing body:** FedRAMP Program Management Office
**Primary source:** https://www.fedramp.gov/

**Status: No explicit PQC mandate in FedRAMP as of mid-2026.**

FedRAMP's January 16, 2025 cryptographic module policy update introduced two compliance streams (validation module stream / update stream) — neither mandates PQC. FedRAMP is awaiting NIST SP 800-53 updates and FIPS 140-3-validated PQC module availability. Formal PQC requirements expected no earlier than 2027.

**CNSA 2.0 cloud services timeline** (relevant to FedRAMP contractors operating NSS): Support and prefer CNSA 2.0 by **2025**; exclusively use by **2033**.

**Hard deadline: No hard FedRAMP PQC deadline found** as of June 2026.

**Implication for quipuu:** When FedRAMP mandates PQC (expected 2027+), cloud service providers pursuing FedRAMP authorization will need to demonstrate cryptographic compliance in their System Security Plans — quipuu output (CBOM, SARIF findings) maps directly to that evidence package.

---

### 7. FIPS 140-3 + PQC (NIST CMVP)

**Issuing body:** NIST Cryptographic Module Validation Program (CMVP)
**Primary source:** https://csrc.nist.gov/projects/cryptographic-module-validation-program

**Key milestone:** August 13, 2024 — NIST published FIPS 203/204/205. On the same day, CMVP updated SP 800-140C (added FIPS 204/205 as approved signature methods) and SP 800-140D (added FIPS 203 as an approved KEM). FIPS 140-3 IG 10.3.A updated self-test requirements; hybrid algorithms are now validatable if one component is NIST-approved.

**Does CMVP require PQC modules?** No mandatory requirement yet. FIPS 140-3 validation for PQC is available but not compulsory.

**FIPS 140-2 sunset:** September 21, 2026 — FIPS 140-2 validated modules move to the Historical list. No new FIPS 140-2 validations accepted after that date (agencies may continue using previously validated modules for existing systems).

**NSS acquisition hard gate:** January 1, 2027 — all new NSS equipment acquisitions must support CNSA 2.0 algorithms by default, creating an effective FIPS 140-3 + PQC requirement for NSS vendors.

**Hard deadline: No CMVP mandate requiring PQC for non-NSS systems found** as of June 2026.

**Implication for quipuu:** Detecting FIPS 140-2 modules in a fleet (which become non-compliant for new procurements after Sep 2026) is an immediate scanner use case with a hard date.

---

### 8. US Banking Regulators (OCC / FFIEC / Federal Reserve / FDIC / SEC)

**OCC — Issuing body:** Office of the Comptroller of the Currency
**Primary source:** OCC Semiannual Risk Perspective, Fall 2024 (Dec 16, 2024): https://www.occ.gov/publications-and-resources/publications/semiannual-risk-perspective/files/pub-semiannual-risk-perspective-fall-2024.pdf

OCC is the first US banking regulator to formally address PQC (Fall 2022, updated Fall 2024). OCC July 2025 Cybersecurity Report to Congress: "banks and service providers should be aware of the risk implications and should consider how to effectively monitor developments in quantum computing as they manage future infrastructure investments." No binding deadline.

**FFIEC:** September 23, 2022 co-hosted a virtual forum on PQC with CISA. No FFIEC IT Examination Handbook update with explicit PQC requirements as of mid-2026. Cybersecurity Assessment Tool (CAT) was sunset August 31, 2025. No binding PQC deadline.

**Federal Reserve:** July 2025 Cybersecurity and Financial System Resilience Report flags PQC as emerging risk. Published research on "harvest now decrypt later" risks for distributed ledger networks (September 2025). No binding requirement.

**FDIC:** No standalone PQC-specific guidance or bulletin found as of mid-2026.

**SEC:** No binding PQC rule. Referenced NIST PQC algorithms in proposed digital asset custody frameworks; no final rule.

**FS-ISAC (Oct 2024):** "Building Cryptographic Agility in the Financial Sector" — recommends immediate action but explicitly states it "does not create new legal or regulatory requirements."

**Hard deadline: No binding PQC deadline from any US banking regulator found** as of June 2026.

**Implication for quipuu:** US banking is in a pre-mandate awareness phase — OCC and FFIEC supervisory guidance sets expectations without hard deadlines. The G7 CEG roadmap (see §12 below) is where the financial sector's actual dates come from.

---

### 9. EU NIS2 Directive (2022/2555)

**Issuing body:** European Parliament and Council
**Primary source:** https://eur-lex.europa.eu/eli/dir/2022/2555

**Does NIS2 include explicit PQC clauses?** No — the original 2022 text contains no mention of "post-quantum" or "quantum" cryptography.

**What it says:** Article 21(2)(h) requires essential and important entities to implement "policies and procedures regarding the use of cryptography and, where appropriate, encryption" — technology-neutral language.

**Critical 2026 development:** COM(2026) 13 (proposed amendment, January 20, 2026) adds a new Article 7(2)(k) requiring Member States to adopt national cybersecurity strategies containing policies "for the transition to post-quantum cryptography, taking into account the transition timelines and relevant requirements set out in applicable Union legal acts and policies." This is in the ordinary legislative procedure — **not yet in force**. Expected adoption no earlier than late 2026 or early 2027.

**Hard deadline: No hard PQC deadline in current NIS2 text.** COM(2026)13 amendment is pending.

**Implication for quipuu:** When COM(2026)13 is adopted, NIS2-regulated essential entities will need PQC migration plans, and a cryptographic inventory is the input such a plan takes.

---

### 10. EU DORA (Regulation 2022/2554)

**Issuing body:** European Parliament and Council
**Primary source:** https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32022R2554

**Effective:** January 17, 2025

**Does DORA mention PQC?** No — DORA does not mention "post-quantum cryptography" by name.

**What is relevant:** Article 8 (ICT business continuity), Articles 24–25 (resilience testing including cryptographic agility) create implied obligations to maintain state-of-the-art cryptographic practices. Interpretive guidance increasingly treats PQC as falling under these obligations, but no explicit PQC clause exists.

**Hard deadline: No hard PQC deadline found in DORA text.**

**Implication for quipuu:** DORA's ICT risk framework requires demonstrable resilience testing — a scanner that validates cryptographic agility (i.e., can the system switch to PQC algorithms?) supports DORA audit evidence.

---

### 11. EU Cyber Resilience Act (CRA, Regulation 2024/2847)

**Issuing body:** European Parliament and Council
**Primary source:** https://eur-lex.europa.eu/eli/reg/2024/2847/oj

**Does CRA Article 13 / Annex I mention PQC explicitly?** No — "post-quantum" does not appear in the operative text. Annex I, Section 1 requires products to use "state-of-the-art" cryptography — technology-neutral language.

**Key compliance deadlines:**
- Vulnerability/incident notification (Article 14): **September 11, 2026**
- All essential cybersecurity requirements (Annex I full compliance): **December 11, 2027**
- Penalties: up to €15 million or 2.5% of global annual turnover

**Interpretation trend:** CEN/CLC JTC 13/WG10 on cryptography and ENISA guidance are increasingly interpreting "state-of-the-art" to encompass PQC for products with long operational lifespans, particularly given the December 2027 full-compliance date.

**Hard deadline: December 11, 2027** for full Annex I compliance (PQC not named but implied by "state-of-the-art" interpretation).

**Implication for quipuu:** Hardware/software product vendors selling into the EU market need to demonstrate state-of-the-art cryptography by December 2027 — quipuu scanning their codebase and generating a CBOM is exactly the evidence needed for conformity assessment.

---

### 12. European Commission Recommendation 2024/1101 — PQC Coordinated Implementation Roadmap

**Issuing body:** European Commission
**Primary sources:**
- Recommendation text: https://eur-lex.europa.eu/eli/reco/2024/1101/oj/eng
- Digital Strategy page: https://digital-strategy.ec.europa.eu/en/library/recommendation-coordinated-implementation-roadmap-transition-post-quantum-cryptography

**Adopted:** April 11, 2024. Published in OJ: April 12, 2024.

**Exact quote from Recommendation:** "The Post-Quantum Cryptography Coordinated Implementation Roadmap should be available after a period of two years following the publication of this Recommendation" — roadmap target: **April 2026**. (The NIS Cooperation Group published Version 1.1 of the roadmap on June 11, 2025, ahead of the two-year deadline.)

**Review clause:** "Member States should cooperate with the Commission to assess the effects of this Recommendation maximum three years after its publication" — review checkpoint: **April 2027**.

**Associated NIS CG roadmap milestones (June 2025):**
- By **December 31, 2026**: Member States initiate national PQC strategies and cryptographic inventories
- By **December 31, 2030**: High-risk use cases (critical infrastructure, financial systems) transition to PQC
- By **2035**: Remaining systems complete migration

**Status:** Non-binding soft law. The 2026/2030/2035 milestones are from the NIS CG roadmap, not directly from the Recommendation text.

**Implication for quipuu:** The 2026 inventory obligation is soft law, but it is the earliest EU-wide date that names an inventory as the deliverable, so it is the first milestone a CBOM has to satisfy.

---

### 13. UK NCSC PQC Migration Timelines (March 2025)

**Issuing body:** UK National Cyber Security Centre (NCSC)
**Primary source:** https://www.ncsc.gov.uk/guidance/pqc-migration-timelines

**The three-phase staged guidance (exact quotes from NCSC):**

**Phase 1 — By 2028 (Assess and Plan):**
> "Define your migration goals" and "Carry out a full discovery exercise (assessing your estate to understand which services and infrastructure that depend on cryptography need to be upgraded to PQC)"

**Phase 2 — 2028–2031 (Execute High-Priority Upgrades):**
> "Carry out your early, highest-priority PQC migration activities" and "Refine your plan so that you have a thorough roadmap for completing migration"

**Phase 3 — 2031–2035 (Complete Full Migration):**
> "Complete migration to PQC of all your systems, services and products"

**NCSC rationale for 2035:** "believes that 10 years is a sufficient period for a rich set of PQC standards to appear, for an ecosystem of products that uses them to be developed, and for uptake to become widespread."

**NCSC CTO Ollie Whitehouse:** "Our new guidance on post-quantum cryptography provides a clear roadmap for organisations to safeguard their data against these future threats."

**Status:** Guidance deadlines, not legally enforceable mandates. Aligned with NIST IR 8547's 2035 federal deprecation target.

**Implication for quipuu:** Phase 1 names the deliverable as a "full discovery exercise" and dates it to 2028 — the obligation is the inventory itself, not a migration.

**NCSC algorithm verdict, separate paper:** https://www.ncsc.gov.uk/paper/next-steps-in-preparing-for-post-quantum-cryptography
(published 14 August 2024, updated 10 April 2026) names specific algorithms rather than only phase
deadlines: "The NCSC recommends ML-KEM-768 and ML-DSA-65 as providing appropriate levels of security
and efficiency for most use cases." Unlike the timeline paper above, this is a parameter-set
recommendation a scanner can check a finding against directly.

---

### 14. Germany BSI TR-02102

**Issuing body:** Bundesamt für Sicherheit in der Informationstechnik (BSI)
**Primary source:** https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr02102/tr02102_node.html

**Current version:** TR-02102-1 through TR-02102-4, version **2026-01** (January 2026). Updated annually.

**PQC algorithm recommendations (TR-02102-1, 2026-01):**
- KEMs: FrodoKEM, Classic McEliece, ML-KEM (FIPS 203)
- Signatures: ML-DSA (FIPS 204), SLH-DSA (FIPS 205), LMS/HSS, XMSS
- Mandatory parameter baseline: AES-192/AES-256 equivalent (NIST Security Category 3)
- PQC **must be deployed in hybrid schemes** (PQC + classical) except for hash-based signatures
- **Cryptographic agility is mandated**

**Joint EU statement:** BSI, ANSSI, and 17 other European national cybersecurity authorities published a joint statement in November 2024 calling for "active transition of the most sensitive applications to quantum-resistant methods by **2030 at the latest**."

**BSI's own sunset schedule (press release, February 11, 2026, restating TR-02102-1 v2026-01):** classical asymmetric encryption should no longer be used alone after **end-2031** (standard protection) or **end-2030** (high-protection applications); classical digital signatures, after **end-2035**. These are BSI's own dates for its own guideline, more specific than the November 2024 joint EU statement above, which remains the only binding-adjacent EU-wide reference point.

**Hard deadline:** No binding German law mandating PQC adoption for private sector. BSI TR guidelines are mandatory for German federal IT systems; the 2030 target is from the joint EU statement, refined by BSI's own end-2030/end-2031/end-2035 schedule above.

**Implication for quipuu:** BSI TR-02102 is the most algorithmically specific European PQC guidance — quipuu findings should map to BSI parameter requirements (Category 3 minimum), not just NIST generic levels.

---

### 15. France ANSSI

**Issuing body:** Agence nationale de la sécurité des systèmes d'information (ANSSI)
**Primary sources:**
- ANSSI PQC page: https://cyber.gouv.fr/enjeux-technologiques/cryptographie-post-quantique/
- 2023 Position Paper PDF: https://cyber.gouv.fr/sites/default/files/document/follow_up_position_paper_on_post_quantum_cryptography.pdf
- ANSSI-PG-083 v3.00 (2026-03-20), the normative referential itself (successor to RGS Annex B1)

**Three-phase transition roadmap:**
- **Phase 1** (current): Hybridization as defense-in-depth
- **Phase 2** (not earlier than 2025): Hybridization providing actual PQ security assurance
- **Phase 3** (probably not earlier than 2030): Optional standalone PQC

**Binding obligation (exact quote):** "An obligation to integrate PQC will be imposed when entering the qualification process for cryptographic solutions, starting from 2027, at least for certain product typologies."

**Algorithm stance:** Hybridization required for all PQC deployments except hash-based signatures (SLH-DSA, XMSS, LMS). Minimum: AES-256 / SHA2-384. National Certification Centre updated cryptographic approval policy March 2025.

**Hard deadline:** 2027 for PQC requirement in ANSSI qualification process. No hard deadline for private-sector PQC adoption in binding French law.

**Normative confirmation (ANSSI-PG-083 v3.00, 2026-03-20):** The referential's own normative text —
not only ANSSI's FAQ, previously the only citation for this — states ML-KEM and ML-DSA are
non-compliant at every NIST parameter set without hybridation, and sets an RSA/DH-modulus
retirement schedule for 2030/2031 that independently matches BSI TR-02102-1's (§14, above).
FrodoKEM-640 is named as referential-compliant when deployed hybrid. Dates and thresholds above are
confirmed directly from the document; this paragraph paraphrases ANSSI's French-language text
rather than quoting it verbatim.

**Implication for quipuu:** Products seeking ANSSI qualification must demonstrate hybrid PQC implementation from 2027 — quipuu provides the audit trail.

---

### 16. Australia ASD ISM

**Issuing body:** Australian Signals Directorate (ASD)
**Primary source:** https://www.cyber.gov.au/business-government/asds-cyber-security-frameworks/ism

**Specific controls:**
- **ISM-1917 (Rev. 0, March 2024):** Requires "future cryptographic requirements and dependencies are considered during the transition to post-quantum cryptography."
- **ISM-1917 (Rev. 1, December 2024):** Development and procurement of new cryptographic equipment/software "ensures support for the use of ML-DSA-87, ML-KEM-1024, SHA-384, SHA-512, and AES-256 **by no later than 2030**."
- **ISM-1990–1996 (new December 2024):** Adopts specific ML-KEM and ML-DSA parameter sets as ASD-Approved Cryptographic Algorithms (AACAs). The two that name parameter sets read, verbatim:
  - **ISM-1991:** "When using ML-DSA for digital signatures, ML-DSA-65 or ML-DSA-87 is used, preferably ML-DSA-87."
  - **ISM-1995:** "When using ML-KEM for encapsulating encryption session keys (and similar keys), ML-KEM-768 or ML-KEM-1024 is used, preferably ML-KEM-1024."
- **ISM-1996:** hybrid schemes must include at least one AACA component.
- **ISM-2073:** "A post-quantum cryptography transition plan is developed, implemented and maintained." No date attached.

**Dates in the catalogue:** ISM-1917 is the only control in the ISM that names a year. Swept across all 1150 controls of `ISM_catalog.json` version `2026.06.18`, the years 2026, 2027, 2028, 2029, 2031 and 2035 match no control text; 2030 matches ISM-1917 alone. There is no ISM control behind an end-of-2026 planning date, an end-of-2028 implementation date, or an end-of-2030 cessation of RSA/DH/ECDH/ECDSA. What ISM-1917 obliges by 2030 is *support for* ML-DSA-87, ML-KEM-1024, SHA-384, SHA-512 and AES-256 in newly developed and procured equipment — a procurement-readiness obligation, not a cutoff for the legacy algorithms.

**Binding status:** For Commonwealth agencies, ISM compliance is mandatory. ISM-1917's 2030 date is the only year stated in binding text by any regulator in this file.

**Implication for quipuu:** ASD names exact parameter sets, and they are ranges with a preference, not single values: ML-KEM-768 and ML-KEM-1024 both satisfy ISM-1995, ML-DSA-65 and ML-DSA-87 both satisfy ISM-1991. An `au-asd-ism` preset must disallow **ML-KEM-512 and ML-DSA-44** and must not flag ML-KEM-768 or ML-DSA-65. ISM-1917 is a separate check with a separate verdict — it constrains what new equipment must *support*, which is not a property of a finding at a call site.

---

### 17. Singapore MAS

**Issuing body:** Monetary Authority of Singapore
**Primary source:** MAS Circular MAS/TCRS/2024/01 (February 20, 2024): https://www.mas.gov.sg/regulation/circulars/advisory-on-addressing-the-cybersecurity-risks-associated-with-quantum

**Scope:** All financial institutions regulated by MAS.

**What is required (three recommended actions):**
1. Maintain an inventory of all cryptographic assets and identify priority assets for migration
2. Develop strategies and build capabilities to address quantum cybersecurity risks
3. Stay informed and raise awareness of quantum computing developments

**Status:** Advisory, not mandatory. MAS–Banque de France joint PQC experiment (November 5, 2024): Successfully exchanged PQC-signed/encrypted emails using Dilithium and Kyber over conventional internet infrastructure.

**Hard deadline: No hard PQC deadline found** in MAS binding regulation.

**Implication for quipuu:** MAS advises a cryptographic asset inventory, so Singapore's financial regulator asks in as many words for the artifact this scanner emits.

---

### 18. Japan CRYPTREC

**Issuing body:** Cryptography Research and Evaluation Committee (CRYPTREC), Ministry of Internal Affairs and Communications / Ministry of Economy, Trade and Industry
**Primary source:** https://www.cryptrec.go.jp/en/

**Publications:**
- CRYPTREC Cryptographic Technology Guideline — Post-Quantum Cryptography — 2024 Edition (published 2024)
- CRYPTREC Report 2024 (published July 22, 2025)
- External evaluation of ML-KEM for CRYPTREC completed April 2026
- ML-KEM added to CRYPTREC Recommended Ciphers List, 2026-03-30 (cryptrec.go.jp/en/whatsnew.html)
- CRYPTREC Report 2025 (published July 24, 2026)

**National target: 2035** — confirmed by National Cyber Command Office interim report (late 2025). Japan aligns with US, EU, UK, and Canada.

**Financial sector:** Japan's FSA called on financial institutions to begin PQC transition immediately at a 2024 study group meeting.

**Inter-ministerial planning:** Plan put forward at Inter-Ministerial Committee (June 2025) to formulate a national PQC migration roadmap; detailed roadmap expected FY2026 (by May 2027).

**Hard deadline:** No single unified Japanese law mandating PQC as of mid-2026. The 2035 target is policy direction.

**Implication for quipuu:** Japan's financial sector is under FSA pressure without a hard mandate, so any inventory here is dated by CRYPTREC guidance rather than by law.

---

### 19. PCI DSS 4.0 / 4.0.1

**Issuing body:** PCI Security Standards Council
**Primary source:** https://www.pcisecuritystandards.org — PCI DSS 4.0.1 and "Cryptography Guidance" (August 2025)

**Does PCI DSS 4.0 include PQC requirements?** "Post-quantum" is not named in PCI DSS 4.0 or 4.0.1.

**What is relevant — Requirement 12.3.3** (fully enforceable since **April 1, 2025**): Organizations must maintain a documented cryptographic inventory and "a documented strategy to respond to anticipated changes in cryptographic vulnerabilities," with annual review. Monitoring "industry trends regarding the continued viability of all cryptographic cipher suites" is mandatory.

**PCI SSC Cryptography Guidance (August 2025):** Released as non-normative guidance covering crypto-agility, AES migration, and PQC migration. Guidance only, not a DSS requirement.

**Hard deadline: No hard PQC deadline found** in PCI DSS text.

**Implication for quipuu:** PCI DSS 12.3.3's crypto-inventory and cipher-suite-monitoring requirements have been in force since April 2025 — an inventory obligation that binds today rather than one dated to a future transition.

---

### 20. HIPAA Security Rule Proposed Update (2024)

**Issuing body:** HHS Office for Civil Rights (OCR)
**Primary source (NPRM):** https://www.federalregister.gov/documents/2025/01/06/2024-30983/hipaa-security-rule-to-strengthen-the-cybersecurity-of-electronic-protected-health-information

**NPRM issued:** December 27, 2024. Published in Federal Register: January 6, 2025 (document 2024-30983).

**Does it mention PQC?** Not as a mandate. The NPRM includes a Request for Information (RFI) soliciting public comments on "quantum computing that could put standard encryption at risk." The proposed rule requires that regulated entities "update encryption methods as standards evolve" — technology-neutral forward-looking language.

**Status as of June 2026:** Proposed, not finalized. OCR's regulatory agenda had targeted spring 2026 for a final rule; that window passed without publication. A coalition of 100+ hospital and provider groups has asked HHS to withdraw the proposal.

**Hard deadline: No hard PQC deadline found** in any current or proposed HIPAA Security Rule text.

**Implication for quipuu:** Healthcare sector lags in PQC mandate but faces the same harvest-now-decrypt-later risk as finance — HIPAA's 10-year minimum PHI retention periods make long-lived records prime HNDL targets.

---

### 21. NYDFS Part 500 (23 NYCRR Part 500, Second Amendment Nov 1, 2023)

**Issuing body:** New York State Department of Financial Services
**Primary sources:**
- Second Amendment Text: https://www.dfs.ny.gov/system/files/documents/2023/10/rf_fs_2amend23NYCRR500_text_20231101.pdf
- Amended regulation: https://www.dfs.ny.gov/system/files/documents/2023/12/rf23_nycrr_part_500_amend02_20231101.pdf

**Does Part 500 mention PQC or crypto-inventory by name?** No. The Second Amendment contains neither "post-quantum," "quantum-resistant," nor "cryptographic inventory" in its regulatory text.

**What is relevant:**
- **Section 500.13 (Asset Inventory):** Covered entities must maintain a written asset inventory policy covering all information systems (owner, location, classification, support expiration date, recovery time objectives).
- **Section 500.15 (Encryption):** Encryption of all NPI in transit over external networks required; compensating controls for NPI at rest reviewed by CISO at least annually.
- **Section 500.17(b) (Annual Certification):** Filed by April 15 each year, signed by both CEO and CISO; supporting records retained 5 years.

**Full compliance timeline:** December 1, 2023 (notification requirements); April 29, 2024 (general effective date); **November 1, 2025** (final tranche of Second Amendment requirements).

**Hard deadline: No explicit PQC obligations in NYDFS Part 500** — but the asset-inventory and encryption requirements create the implicit foundation.

**Implication for quipuu:** 500.13 already requires regulated entities to maintain asset inventories, so quipuu output is evidence against a requirement that binds today rather than one dated to a future transition.

---

### 22. US State-Level PQC Laws

**Status: No US state has enacted specific PQC legislation as of June 2026.**

**Specific findings:**
- **California SB 327 (2018):** IoT device security — not PQC.
- **California AB 940 (signed October 2025):** $4M quantum economy strategy study — development, not cryptographic mandates.
- **Colorado HB24-1325 / Illinois quantum park:** Tax incentives for quantum industry — not PQC mandates.
- Federal Quantum Computing Cybersecurity Preparedness Act (Dec 2022): Federal agencies only.
- Multiple 2025 Congressional bills (H.R. 3259, S. 3312, S. 2558): Proposed, not enacted.

**Bottom line:** "As of early 2026, no U.S. sector has a binding, mandatory PQC adoption requirement for private-sector entities." (confirmed by multiple law review analyses)

**Implication for quipuu:** No state creates an immediate compliance mandate; every binding US obligation in this file is federal, so the state layer adds no date a policy preset has to encode.

---

### 23. EO 14412 + OMB M-26-15 — Execution of the Migration to Post-Quantum Cryptography

**Issuing body:** Executive Office of the President (EO 14412, signed June 22, 2026) and OMB (M-26-15, issued June 24, 2026).
**Primary source:** https://www.whitehouse.gov/wp-content/uploads/2026/06/M-26-15-Execution-of-the-Migration-to-Post-Quantum-Cryptography.pdf

**Scope:** Federal Civilian Executive Branch (FCEB) agencies — the successor action to OMB M-23-02 (§1, above), not a replacement for it.

**Exact deadlines:**
- **October 22, 2026** (120 days after the June 24, 2026 memorandum) — agencies must submit a PQC migration plan and appoint a PQC lead.
- **Five-phase migration timeline:**

  | Phase | Years | What happens |
  |---|---|---|
  | 1 | 2026–2027 | Strategy, inventory of High Value Assets / high-impact systems, governance |
  | 2 | 2027–2028 | Pilot migrations, plan refinement |
  | 3 | 2028–2030 | Prioritized key-establishment migration for HVAs/high-impact systems; cryptographic agility required |
  | 4 | 2031 | Digital-signature migration for the same prioritized systems |
  | 5 | 2035 | Remaining systems migrated, risk- and product-availability-dependent |

**Implication for quipuu:** the same annual-inventory argument as M-23-02 (§1) applies, sharpened by a named deadline five weeks out at time of writing (October 22, 2026) — an agency building that first migration plan needs the machine-generated inventory `--cbom` produces, not a manual one.

---

### 24. NIST SP 800-227 — Recommendations for Key-Encapsulation Mechanisms

**Issuing body:** NIST
**Primary source:** https://csrc.nist.gov/pubs/sp/800/227/final

**Status:** Final since **September 18, 2025** — not a draft.

**Scope:** General recommendations for implementing and using KEMs securely, complementing (not duplicating) FIPS 203's ML-KEM specification — the document quipuu's ML-KEM classifications already cite.

**Implication for quipuu:** the direct on-topic NIST reference for any finding quipuu labels as a KEM (`ml-kem-*`, `kem-unattributed`), alongside FIPS 203 and NIST IR 8547 (§5). No new algorithm coverage follows from this citation — it is a completeness fix, closing a document that had been final for a year with no citation anywhere in `knowledge/`.

---

### 25. Canada CCCS (`ITSP.40.111` / `ITSM.40.001`)

**Issuing body:** Canadian Centre for Cyber Security (CCCS), a part of the Communications Security Establishment (CSE)
**Primary source:** https://www.cyber.gc.ca/en/guidance/cryptographic-algorithms-unclassified-protected-protected-b-information-itsp40111 — `ITSP.40.111`, Guidance on Securely Migrating to Post-Quantum Cryptography

**Version:** 5, effective **May 29, 2026**.

**Recommended algorithm set:** the full three-family NIST PQC suite — ML-KEM-512/768/1024 (FIPS 203), ML-DSA-44/65/87 (FIPS 204), all twelve SLH-DSA parameter sets (FIPS 205) — with **no CCCS-specific parameter-set restriction**, unlike Germany BSI's Category-3-minimum stance (§14, above).

**Phase-out dates:**
- Classical algorithms with no PQC alternative: retired by **end-2035**.
- RSA/FFC moduli under 3072 bits, and P-224 and binary elliptic curves: retired by **end-2030**.

**Hard deadline: end-2030** for the sub-3072-bit RSA/FFC and small-curve retirement; **end-2035** for the full classical phase-out.

**Implication for quipuu:** CCCS names concrete key-size and curve floors on a fixed timeline, the same shape as BSI TR-02102's Category-3 minimum (§14) — a `--policy` preset for Canada would flag sub-3072-bit RSA/FFC and P-224/binary-curve findings ahead of the 2030 date, without CCCS's stricter parameter-set narrowing.

---

### 26. EU ECCG "Agreed Cryptographic Mechanisms" v3 (EUCC certification)

**Issuing body:** European Cybersecurity Certification Group (ECCG), Sub-group on Cryptography — the body ENISA supports under the EU Cybersecurity Certification Framework
**Primary sources:**
- Draft v3 for public review (document `9993abb8-5f27-47d0-bdb2-f6f284cd5141`): https://certification.enisa.europa.eu/document/download/9993abb8-5f27-47d0-bdb2-f6f284cd5141_en?filename=20260507-acm-draft.pdf
- Companion ENISA report, "Hybridization of traditional cryptographic mechanisms with PQC — Standardisation Status" (document `02f54596-6a99-4c9e-88c4-8c711ebff9c1`), 30 April 2026
- Hosting page: https://certification.enisa.europa.eu/publications/eucc-guidelines-cryptography_en

**Status: draft, not adopted.** Internally dated April 2026, published for public review 2 June 2026, review closed end of July 2026. **No formal-adoption date found as of 2026-09-02** — the currently-applicable version remains v2 (6 May 2025). Cited here as the operative direction of travel, the same practice this file already applies to BSI TR-02102 (§14) and ANSSI-PG-083 (§15), both revisable technical guidelines rather than primary legislation — captioned as draft, not smoothed over.

**Scope:** Sets the cryptographic-mechanism acceptance table for ICT products undergoing EU Common Criteria (EUCC) certification, binding on national cybersecurity certification authorities (NCCAs) across EU member states once adopted.

**Two-tier classification (exact quotes from the draft):** "recommended mechanisms, that fully reflect the state of the art in cryptography, currently offer a security level of at least 125 bits"; "admissible mechanisms, that are deployed on a large scale, currently offer a security level of at least 100 bits and are considered to provide an acceptable short-term security but should be phased out" — default validity period `A[2033+]` for admissible mechanisms not expected to become vulnerable in the near term.

**Recommended tier (independently confirmed against the draft's own algorithm tables, §5.2/§5.4):** ML-KEM (FIPS 203), FrodoKEM, ML-DSA (FIPS 204, "recommended to use ML-DSA-87 or ML-DSA-65"), SLH-DSA (FIPS 205, **security levels 3 and 5 only** — the draft's own Note 54), XMSS and LMS (SP 800-208).

**Admissible-only tier, all requiring "combin[ation] with a quantum resistant mechanism" where quantum resistance is required (draft's own Note 46/62):** RSA PSS and PKCS#1v1.5, DSA, KCDSA, ECKCDSA, ECDSA (incl. deterministic), ECGDSA, ECSchnorr, EdDSA, DH, EC-DH, X25519, X448.

**Implication for quipuu:** EUCC-seeking vendors will need to demonstrate their product's cryptography sits in the Recommended tier (or admissible-with-hybridization) once v3 is adopted — the Recommended/Admissible split maps directly onto a finding-severity axis distinct from any single member state's own guideline, and the SLH-DSA levels-3/5-only carve-out is a parameter-set constraint no other cited regime in this file states this specifically.

---

### 27. IETF RFC 8784 / RFC 9867 — IKEv2 Post-Quantum Preshared Keys

**Issuing body:** IETF, IPsecME working group
**Primary sources:**
- RFC 8784, June 2020, "Mixing Preshared Keys in the Internet Key Exchange Protocol Version 2 (IKEv2) for Post-quantum Security": https://www.rfc-editor.org/rfc/rfc8784
- RFC 9867, November 2025, "Mixing Preshared Keys in the IKE_INTERMEDIATE and CREATE_CHILD_SA Exchanges of the Internet Key Exchange Protocol Version 2 (IKEv2) for Post-quantum Security": https://www.rfc-editor.org/rfc/rfc9867

**RFC 9867 does not obsolete RFC 8784** — quoted directly from RFC 9867: "This specification does not replace the approach defined in RFC 8784. Both approaches for using PPKs in IKEv2 can be used depending on the circumstances." RFC 8784 mixes a postquantum preshared key (PPK) into an already-established IKEv2 SA via CREATE_CHILD_SA; RFC 9867 extends PPK protection to the initial IKE SA (uncovered by RFC 8784's mechanism) and allows a fresh PPK to be mixed into an active SA without SA recreation.

**Scope note — citation only, no rule to build:** IKEv2 PPK configuration lives in VPN-daemon and network-device config (strongSwan, Libreswan, vendor IOS/JunOS blocks), not in any programming-language source tree. Every quipuu rule pack (`quipuu/crates/core/data/rules/`) is a tree-sitter language grammar; there is no config-file, network-protocol, or infrastructure-as-code rule pack. This entry documents a real HNDL-relevant IETF standard outside quipuu's current detection surface, not a gap in an existing rule pack.

**Implication for quipuu:** none directly detectable today. Relevant only as background for a future config-parsing rule-pack category, should one be built.

---

### 28. NIST SP 800-73 / SP 800-78 — PIV Post-Quantum Working Drafts

**Issuing body:** NIST, Computer Security Division (PIV standards)
**Primary sources:**
- Announcement: https://www.nist.gov/news-events/news/2026/06/working-drafts-post-quantum-cryptography-updates-piv-standards (June 12, 2026)
- Gap-analysis page: https://pages.nist.gov/piv-standards/pqc-overview/

**Status: "preliminary working materials, not formal public drafts"** — NIST's own characterization, not an IPD or comment-period draft. No finalization timeline given.

**Scope:** Initial working drafts of SP 800-73 Parts 1/2 (PIV card interface) and SP 800-78 (cryptographic algorithms and key sizes for PIV) add ML-DSA and ML-KEM to the federal PIV smart-card standard via a dual-stack, backward-compatible design. The gap-analysis page names seven principal gap areas: algorithm definitions, command updates, new public-key encodings, new BER-TLV containers, certificate profiles, new authentication mechanisms, and secure-messaging extensions. Both documents are currently published at Revision 5 (SP 800-73-5, SP 800-78-5); these working drafts would become Revision 6 of each, but neither cited NIST source uses that revision number anywhere — "SP 800-73-6 / SP 800-78-6" is this project's own numerically obvious inference, not NIST's stated designation, so it is not asserted as fact here.

**Implication for quipuu: none — no detection-surface action follows.** The gap these drafts describe is at the smart-card layer (APDU command formats, BER-TLV tags, card-application namespace), which quipuu cannot observe both by design and by trust invariant **P4** (never execute the scanned project's code, which includes never talking to a smart card). PIV certificates are ordinary X.509 certificates with federal policy OIDs, and that OID-level surface is already covered by the RFC 9935/RFC 9881 citations in `knowledge/05-x509-pqc/README.md`. Recorded here as a real, dated, primary-sourced NIST process this project should track, the same framing as FIPS 207/HQC (`knowledge/02-nist-pqc-timeline/README.md` §5.6) — a narrative-documentation entry, not a coverage gap.

---

## DEADLINES THAT MATTER

| Deadline | Instrument | Jurisdiction | Binding? | What triggers it |
|---|---|---|---|---|
| **Sep 21, 2026** | FIPS 140-2 → Historical | US (CMVP) | Yes (federal procurement) | FIPS 140-2 modules no longer valid for new procurements |
| **Sep 11, 2026** | EU CRA Article 14 | EU | Yes | Vulnerability/incident notification requirements live |
| **Oct 22, 2026** | EO 14412 / OMB M-26-15 | US (FCEB) | Yes | Agency PQC migration plan + lead due (120 days post-memo) |
| **Annual (ongoing)** | OMB M-23-02 | US (FCEB) | Yes | Annual crypto inventory re-submission |
| **Jan 1, 2027** | CNSA 2.0 acquisition gate | US (NSS) | Yes (NSS only) | New NSS equipment must default to CNSA 2.0 |
| **2027** | ANSSI qualification mandate | France | Yes (qualified products) | PQC required for ANSSI-qualified crypto products |
| **Dec 11, 2027** | EU CRA Annex I full compliance | EU | Yes | All essential cybersecurity requirements apply (incl. state-of-the-art crypto) |
| **2028** | UK NCSC Phase 1 end | UK | Guidance | "Full discovery exercise" must be complete |
| **2029** | Microsoft internal target | Enterprise benchmark | No | Microsoft's own early-adoption target |
| **2030** | NIST IR 8547 (IPD) deprecation | US (proposed) | Draft only | RSA-2048, P-256, ECDH deprecated (proposed) |
| **2030** | BSI/EU joint statement | EU | Guidance | Most sensitive applications quantum-resistant |
| **End 2030** | BSI TR-02102-1 v2026-01 | Germany | Mandatory (federal IT) | Classical asymmetric encryption sunset, high-protection applications |
| **2028–2030** | EO 14412 / OMB M-26-15 Phase 3 | US (FCEB) | Yes | Prioritized key-establishment migration for HVAs/high-impact systems |
| **Dec 31, 2030** | ASD ISM ISM-1917 | Australia | Yes (Commonwealth) | New equipment/software must support ML-DSA-87, ML-KEM-1024, SHA-384/512, AES-256 |
| **Dec 31, 2030** | CNSA 2.0 firmware signing | US (NSS) | Yes (NSS only) | Exclusive use of CNSA 2.0 for firmware signing |
| **End 2030** | CCCS ITSP.40.111 v5 | Canada | Guidance | RSA/FFC moduli < 3072 bits, P-224, binary curves retired |
| **2030–2032** | G7 CEG critical systems | G7 financial | Guidance | Priority critical financial systems migrate |
| **Dec 31, 2031** | NSM-10 / CNSA 2.0 | US (NSS) | Yes (NSS) | Vast majority of NSS crypto must be quantum-resistant |
| **End 2031** | BSI TR-02102-1 v2026-01 | Germany | Mandatory (federal IT) | Classical asymmetric encryption sunset, standard protection |
| **2031** | EO 14412 / OMB M-26-15 Phase 4 | US (FCEB) | Yes | Digital-signature migration for HVAs/high-impact systems |
| **2033** | CNSA 2.0 cloud/OS | US (NSS) | Yes (NSS) | Exclusive use for cloud services and operating systems |
| **2035** | NIST IR 8547 (IPD) disallowance | US (proposed) | Draft only | All quantum-vulnerable public-key algorithms disallowed |
| **2035** | NSM-10 / CNSA 2.0 | US (all federal) | Yes | Full federal transition target |
| **2035** | EO 14412 / OMB M-26-15 Phase 5 | US (FCEB) | Yes | Remaining federal systems fully migrated |
| **End 2035** | BSI TR-02102-1 v2026-01 | Germany | Mandatory (federal IT) | Classical digital signature sunset |
| **2035** | UK NCSC Phase 3 | UK | Guidance | Full migration of all systems |
| **2035** | EC/NIS CG Roadmap | EU | Soft law | Remaining EU systems complete migration |
| **2035** | Japan national target | Japan | Policy direction | National PQC migration complete |
| **End 2035** | CCCS ITSP.40.111 v5 | Canada | Guidance | Classical algorithms with no PQC alternative retired |


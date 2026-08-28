# Post-Quantum Cryptography Regulatory Landscape

> Research date: June 2026. Primary sources only. Where no hard deadline was confirmed from a primary source, this file says so explicitly — no deadlines are invented.

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

**Implication for quipuu:** The annual inventory obligation creates a recurring procurement opportunity — federal agencies need crypto-discovery tooling to satisfy this mandate every year, and OMB has published no native tooling to help them.

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

**Implication for quipuu:** This is a buyer-signal goldmine — every named collaborator is actively engaged in solving the crypto-discovery problem. The explicit finding that "no single product finds all vulnerable crypto" validates a multi-layer scanner. SP 1800-38B is the reference architecture quipuu should align to.

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

**Implication for quipuu:** US banking is in a pre-mandate awareness phase — OCC and FFIEC supervisory guidance creates reputational pressure without hard deadlines. The G7 CEG roadmap (see §12 below) is the more actionable international signal for financial sector buyers.

---

### 9. EU NIS2 Directive (2022/2555)

**Issuing body:** European Parliament and Council
**Primary source:** https://eur-lex.europa.eu/eli/dir/2022/2555

**Does NIS2 include explicit PQC clauses?** No — the original 2022 text contains no mention of "post-quantum" or "quantum" cryptography.

**What it says:** Article 21(2)(h) requires essential and important entities to implement "policies and procedures regarding the use of cryptography and, where appropriate, encryption" — technology-neutral language.

**Critical 2026 development:** COM(2026) 13 (proposed amendment, January 20, 2026) adds a new Article 7(2)(k) requiring Member States to adopt national cybersecurity strategies containing policies "for the transition to post-quantum cryptography, taking into account the transition timelines and relevant requirements set out in applicable Union legal acts and policies." This is in the ordinary legislative procedure — **not yet in force**. Expected adoption no earlier than late 2026 or early 2027.

**Hard deadline: No hard PQC deadline in current NIS2 text.** COM(2026)13 amendment is pending.

**Implication for quipuu:** When COM(2026)13 is adopted, NIS2-regulated essential entities (~100,000+ organizations across the EU) will need PQC migration plans — quipuu provides the inventory foundation those plans require.

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

**Implication for quipuu:** The 2026 inventory obligation (even soft-law) drives immediate budget allocation across EU member states for crypto-discovery tooling — the procurement window is open now.

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

**Implication for quipuu:** The 2028 "full discovery exercise" deadline is the clearest single-date driver for a crypto-inventory scanner in the UK market — Phase 1 is literally "do the inventory."

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

**Hard deadline:** No binding German law mandating PQC adoption for private sector. BSI TR guidelines are mandatory for German federal IT systems; the 2030 target is from the joint EU statement.

**Implication for quipuu:** BSI TR-02102 is the most algorithmically specific European PQC guidance — quipuu findings should map to BSI parameter requirements (Category 3 minimum), not just NIST generic levels.

---

### 15. France ANSSI

**Issuing body:** Agence nationale de la sécurité des systèmes d'information (ANSSI)
**Primary sources:**
- ANSSI PQC page: https://cyber.gouv.fr/enjeux-technologiques/cryptographie-post-quantique/
- 2023 Position Paper PDF: https://cyber.gouv.fr/sites/default/files/document/follow_up_position_paper_on_post_quantum_cryptography.pdf

**Three-phase transition roadmap:**
- **Phase 1** (current): Hybridization as defense-in-depth
- **Phase 2** (not earlier than 2025): Hybridization providing actual PQ security assurance
- **Phase 3** (probably not earlier than 2030): Optional standalone PQC

**Binding obligation (exact quote):** "An obligation to integrate PQC will be imposed when entering the qualification process for cryptographic solutions, starting from 2027, at least for certain product typologies."

**Algorithm stance:** Hybridization required for all PQC deployments except hash-based signatures (SLH-DSA, XMSS, LMS). Minimum: AES-256 / SHA2-384. National Certification Centre updated cryptographic approval policy March 2025.

**Hard deadline:** 2027 for PQC requirement in ANSSI qualification process. No hard deadline for private-sector PQC adoption in binding French law.

**Implication for quipuu:** Products seeking ANSSI qualification must demonstrate hybrid PQC implementation from 2027 — quipuu provides the audit trail.

---

### 16. Australia ASD ISM

**Issuing body:** Australian Signals Directorate (ASD)
**Primary source:** https://www.cyber.gov.au/business-government/asds-cyber-security-frameworks/ism

**Specific controls:**
- **ISM-1917 (Rev. 0, March 2024):** Requires "future cryptographic requirements and dependencies are considered during the transition to post-quantum cryptography."
- **ISM-1917 (Rev. 1, December 2024):** Development and procurement of new cryptographic equipment/software "ensures support for the use of ML-DSA-87, ML-KEM-1024, SHA-384, SHA-512, and AES-256 **by no later than 2030**."
- **ISM-1990–1996 (new December 2024):** Adopts specific ML-KEM and ML-DSA parameter sets as ASD-Approved Cryptographic Algorithms (AACAs). ISM-1996: hybrid schemes must include at least one AACA component.

**ASD phased milestones:**
- **End of 2026**: Detailed transition plan in place
- **End of 2028**: PQC implementation begins on most critical/sensitive systems
- **End of 2030**: Full transition complete; RSA, DH, ECDH, ECDSA to be ceased

**Binding status:** For Commonwealth agencies, ISM compliance is mandatory. The 2030 PQC target is the only confirmed hard deadline in any current binding law globally (for the stated agencies and scope).

**Implication for quipuu:** Australia has the hardest statutory PQC deadline of any surveyed jurisdiction (2030 for Commonwealth agencies). ASD specifies exact algorithm parameter sets — quipuu should flag any deployment using ML-KEM-512 or ML-KEM-768 in an Australian government context as non-compliant (ISM requires ML-KEM-1024).

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

**Implication for quipuu:** MAS advisory recommending cryptographic asset inventory is a direct use-case statement for quipuu, from a regulator covering Singapore's $800B+ banking sector.

---

### 18. Japan CRYPTREC

**Issuing body:** Cryptography Research and Evaluation Committee (CRYPTREC), Ministry of Internal Affairs and Communications / Ministry of Economy, Trade and Industry
**Primary source:** https://www.cryptrec.go.jp/en/

**Publications:**
- CRYPTREC Cryptographic Technology Guideline — Post-Quantum Cryptography — 2024 Edition (published 2024)
- CRYPTREC Report 2024 (published July 22, 2025)
- External evaluation of ML-KEM for CRYPTREC completed April 2026

**National target: 2035** — confirmed by National Cyber Command Office interim report (late 2025). Japan aligns with US, EU, UK, and Canada.

**Financial sector:** Japan's FSA called on financial institutions to begin PQC transition immediately at a 2024 study group meeting.

**Inter-ministerial planning:** Plan put forward at Inter-Ministerial Committee (June 2025) to formulate a national PQC migration roadmap; detailed roadmap expected FY2026 (by May 2027).

**Hard deadline:** No single unified Japanese law mandating PQC as of mid-2026. The 2035 target is policy direction.

**Implication for quipuu:** Japan's financial sector is under FSA pressure without a hard mandate — early mover tooling adoption is feasible.

---

### 19. PCI DSS 4.0 / 4.0.1

**Issuing body:** PCI Security Standards Council
**Primary source:** https://www.pcisecuritystandards.org — PCI DSS 4.0.1 and "Cryptography Guidance" (August 2025)

**Does PCI DSS 4.0 include PQC requirements?** "Post-quantum" is not named in PCI DSS 4.0 or 4.0.1.

**What is relevant — Requirement 12.3.3** (fully enforceable since **April 1, 2025**): Organizations must maintain a documented cryptographic inventory and "a documented strategy to respond to anticipated changes in cryptographic vulnerabilities," with annual review. Monitoring "industry trends regarding the continued viability of all cryptographic cipher suites" is mandatory.

**PCI SSC Cryptography Guidance (August 2025):** Released as non-normative guidance covering crypto-agility, AES migration, and PQC migration. Guidance only, not a DSS requirement.

**Hard deadline: No hard PQC deadline found** in PCI DSS text.

**Implication for quipuu:** PCI DSS 12.3.3's crypto-inventory and cipher-suite-monitoring requirements (already in force as of April 2025) are a compliance driver for quipuu today, in ~9 million merchant environments and their acquirers.

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

**Implication for quipuu:** 3,000+ NYDFS-regulated entities (banks, insurers, MSBs) must maintain asset inventories per 500.13. Quipuu output integrates directly into that evidence requirement.

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

**Implication for quipuu:** No state creates an immediate compliance mandate, but the federal+EU+UK+AU pressure is sufficient for enterprise sales without state mandates.

---

## DEADLINES THAT MATTER

| Deadline | Instrument | Jurisdiction | Binding? | What triggers it |
|---|---|---|---|---|
| **Sep 21, 2026** | FIPS 140-2 → Historical | US (CMVP) | Yes (federal procurement) | FIPS 140-2 modules no longer valid for new procurements |
| **Sep 11, 2026** | EU CRA Article 14 | EU | Yes | Vulnerability/incident notification requirements live |
| **Annual (ongoing)** | OMB M-23-02 | US (FCEB) | Yes | Annual crypto inventory re-submission |
| **Jan 1, 2027** | CNSA 2.0 acquisition gate | US (NSS) | Yes (NSS only) | New NSS equipment must default to CNSA 2.0 |
| **2027** | ANSSI qualification mandate | France | Yes (qualified products) | PQC required for ANSSI-qualified crypto products |
| **Dec 11, 2027** | EU CRA Annex I full compliance | EU | Yes | All essential cybersecurity requirements apply (incl. state-of-the-art crypto) |
| **2028** | UK NCSC Phase 1 end | UK | Guidance | "Full discovery exercise" must be complete |
| **Dec 31, 2028** | ASD ISM ISM-1917 | Australia | Yes (Commonwealth) | PQC implementation begins on critical systems |
| **2029** | Microsoft internal target | Enterprise benchmark | No | Microsoft's own early-adoption target |
| **2030** | NIST IR 8547 (IPD) deprecation | US (proposed) | Draft only | RSA-2048, P-256, ECDH deprecated (proposed) |
| **2030** | BSI/EU joint statement | EU | Guidance | Most sensitive applications quantum-resistant |
| **Dec 31, 2030** | ASD ISM ISM-1917 hard target | Australia | Yes (Commonwealth) | Full transition; RSA/ECDH/ECDSA ceased |
| **Dec 31, 2030** | CNSA 2.0 firmware signing | US (NSS) | Yes (NSS only) | Exclusive use of CNSA 2.0 for firmware signing |
| **2030–2032** | G7 CEG critical systems | G7 financial | Guidance | Priority critical financial systems migrate |
| **Dec 31, 2031** | NSM-10 / CNSA 2.0 | US (NSS) | Yes (NSS) | Vast majority of NSS crypto must be quantum-resistant |
| **2033** | CNSA 2.0 cloud/OS | US (NSS) | Yes (NSS) | Exclusive use for cloud services and operating systems |
| **2035** | NIST IR 8547 (IPD) disallowance | US (proposed) | Draft only | All quantum-vulnerable public-key algorithms disallowed |
| **2035** | NSM-10 / CNSA 2.0 | US (all federal) | Yes | Full federal transition target |
| **2035** | UK NCSC Phase 3 | UK | Guidance | Full migration of all systems |
| **2035** | EC/NIS CG Roadmap | EU | Soft law | Remaining EU systems complete migration |
| **2035** | Japan national target | Japan | Policy direction | National PQC migration complete |

---

## Buyer Pressure Ranking

**Tier 1 — Hardest buyers (budget allocated, hard dates, compliance risk):**

1. **NSA / DoD (CNSA 2.0 for NSS)** — January 2027 acquisition gate, staggered 2025–2033 exclusive-use dates, binding on the entire US defense industrial base and IC. Any contractor selling into DoD must demonstrate CNSA 2.0 readiness. Budget is allocated ($7.1B government-wide estimate). Procurement decisions happening now.

2. **US Federal Civilian (OMB M-23-02)** — Annual inventory obligation already active since May 2023. FCEB agencies are the only non-NSS sector with a current, recurring, binding crypto-inventory requirement. Creates annual recurring procurement cycle.

3. **Australian Commonwealth agencies (ASD ISM)** — Only jurisdiction with a confirmed hard 2030 compliance deadline (ISM-1917 Rev.1, December 2024) specifying exact algorithm parameter sets (ML-KEM-1024, ML-DSA-87). Binding for all Commonwealth agencies.

**Tier 2 — Strong buyers (regulatory intent, budget forming, 2027–2030 horizon):**

4. **EU product vendors (CRA, December 2027)** — ~500,000 organizations selling connected products into the EU must demonstrate "state-of-the-art" cryptography by December 2027. The 2027 date is close enough to drive current procurement. ANSSI qualification mandate from 2027 adds French government market urgency.

5. **UK critical infrastructure operators (NCSC guidance, Phase 1 by 2028)** — Phase 1 explicitly requires a "full discovery exercise" by 2028. While guidance rather than law, NCSC guidance compliance is a material factor in UK government contracts and insurance underwriting.

6. **G7 financial sector (G7 CEG roadmap, Jan 2026)** — Targets 2030–2032 for critical systems, 2035 overall. G7 finance ministries explicitly require "comprehensive inventory of cryptographic assets" — MAS, BIS Project Leap, G7 CEG all point to crypto inventory as the first deliverable.

**Tier 3 — Emerging buyers (awareness phase, 1–3 year mandate horizon):**

7. **EU NIS2 essential entities** — COM(2026)13 will force national PQC strategy adoption within ~1 year of passage; NIS2 essential entities (~100K organizations) will then need inventory plans.

8. **PCI DSS-scoped merchants/acquirers** — Requirement 12.3.3 (cipher-suite monitoring, in force April 2025) is an immediate hook; full PQC mandate likely in PCI DSS 5.x (expected 2027–2028).

9. **NYDFS-regulated entities** — 3,000+ NY-licensed financial companies with active asset-inventory requirements today, even without explicit PQC language.

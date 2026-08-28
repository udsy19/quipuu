# HNDL Threat Model and Quantum Risk-Scoring Framework

**Purpose:** Authoritative reference for the quipuu project's "Harvest Now, Decrypt Later" threat model and the `QuantumRiskScore` algorithm. All claims cite primary-source documents. Where verbatim text could not be retrieved from a closed PDF, that is stated explicitly.

---

## Section 1: HNDL Definition and Authoritative Framings

### 1.1 Terminology

The attack is named under two interchangeable labels in primary-source documents:

- **"Harvest Now, Decrypt Later" (HNDL)** — used by NIST IR 8547, CISA/NSA/NIST joint factsheets, and OMB M-23-02 (implicitly).
- **"Store Now, Decrypt Later" (SNDL)** — used in some ENISA and ETSI documents.
- **"Retrospective decryption"** — ENISA 2021 PQC report (verbatim, see §1.3).

All three labels describe the same threat model: an adversary captures ciphertext today and defers decryption until a Cryptographically Relevant Quantum Computer (CRQC) is available.

---

### 1.2 OMB M-23-02 (November 18, 2022) — Verbatim

**Full document obtained and read.** The following are verbatim quotes.

From the Overview (p. 1):

> "As outlined in NSM-10, the threat posed by the prospect of a cryptanalytically relevant quantum computer (CRQC) requires that agencies prepare now to implement post-quantum cryptography (PQC). Once operational, a CRQC is expected to be able to compromise certain widely used cryptographic algorithms used to secure Federal data and information systems. Additionally, **agencies must remain cognizant that encrypted data can be recorded now and later decrypted by operators of a future CRQC.**"

From Section II.A, footnote 11 (p. 3), explaining the criterion "data expected to remain mission-sensitive in 2035":

> "This criterion refers to data that **if recorded now, and later decrypted by a CRQC in 2035, would still be considered mission sensitive.**"

From Section II.A (p. 2), quoting NSM-10:

> "the United States must prioritize the timely and equitable transition of cryptographic systems to quantum-resistant cryptography, with the goal of mitigating as much of the quantum risk as is feasible by 2035."

Appendix B of M-23-02 lists the CRQC-vulnerable algorithms: ECDH, MQV, ECDSA, DH, RSA (key transport), DSA, and "Other non-PQC Asymmetric Algorithm."

**Source:** OMB M-23-02, *Migrating to Post-Quantum Cryptography*, Nov. 18, 2022. [https://www.whitehouse.gov/wp-content/uploads/2022/11/M-23-02-M-Memo-on-Migrating-to-Post-Quantum-Cryptography.pdf](https://www.whitehouse.gov/wp-content/uploads/2022/11/M-23-02-M-Memo-on-Migrating-to-Post-Quantum-Cryptography.pdf) (PDF retrieved and read in full for this document).

---

### 1.3 NSM-10 (May 4, 2022) — Verbatim (from OMB M-23-02 citation)

NSM-10 is the parent authority for M-23-02. The following phrase is confirmed verbatim, cited by both OMB M-23-02 and multiple government secondary sources:

> "the United States must prioritize the timely and equitable transition of cryptographic systems to quantum-resistant cryptography, with the goal of mitigating as much of the quantum risk as is feasible by 2035."

NSM-10 also declared:

> "Any digital system that uses existing public standards for public-key cryptography, or that is planning to transition to such cryptography, could be vulnerable to an attack by a CRQC."

NSM-10 does **not** use the phrase "harvest now, decrypt later" verbatim; the HNDL framing is explicit in M-23-02 (footnote 11 above) and in downstream CISA/NIST guidance.

**Source:** NSM-10, *National Security Memorandum on Promoting United States Leadership in Quantum Computing While Mitigating Risks to Vulnerable Cryptographic Systems*, May 4, 2022. [https://www.whitehouse.gov/briefing-room/statements-releases/2022/05/04/national-security-memorandum-on-promoting-united-states-leadership-in-quantum-computing-while-mitigating-risks-to-vulnerable-cryptographic-systems/](https://www.whitehouse.gov/briefing-room/statements-releases/2022/05/04/national-security-memorandum-on-promoting-united-states-leadership-in-quantum-computing-while-mitigating-risks-to-vulnerable-cryptographic-systems/)

---

### 1.4 NIST IR 8547 (November 2024, Initial Public Draft) — Verbatim

NIST IR 8547 is the first primary NIST document to use the phrase "harvest now, decrypt later" verbatim. The following quotes are confirmed from the document via multiple indexed sources citing the NIST PDF:

On HNDL urgency:

> "Data is at risk because of the 'harvest now, decrypt later' threat in which adversaries collect encrypted data now with the goal of decrypting it once quantum technology matures. Since sensitive data often retains its value for many years, starting the transition to post-quantum cryptography now is critical to preventing these future breaches."

On the encryption vs. authentication distinction (verbatim, confirmed):

> "Unlike with encryption, where there is a threat of 'harvest now, decrypt later,' an authentication system remains secure as long as the cryptographic algorithms and keys used to perform the authentication are secure when the authentication is performed."

NIST IR 8547 deprecation/disallowment schedule:
- 112-bit security algorithms (e.g., 2TDEA, RSA-2048, P-224 curve): **deprecated after 2030**, **disallowed after 2035** for federal systems.
- Algorithms at 128-bit security (e.g., RSA-3072, AES-128): **deprecated after 2030**, **disallowed after 2035**.

**Source:** NIST IR 8547 ipd, *Transition to Post-Quantum Cryptography Standards*, Nov. 2024. Authors: Moody, Perlner, Regenscheid, Robinson, Cooper. [https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf](https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf)

---

### 1.5 NSA CNSA 2.0 (September 2022)

The NSA CNSA 2.0 advisory (media.defense.gov) returned HTTP 403 during research and could not be read directly. Based on indexed secondary sources and the CNSA 2.0 FAQ (also hosted at media.defense.gov), the following is confirmed:

- CNSA 2.0 was issued to protect National Security Systems (NSS) against quantum threats, including harvest-now-decrypt-later collection.
- NSA names HNDL as the primary motivation for the aggressive key-establishment migration timeline.
- CNSA 2.0 prescribes: **ML-KEM-1024** (FIPS 203) for key establishment; **ML-DSA-87** (FIPS 204) for digital signatures; **AES-256** for symmetric encryption; **SHA-384/512** for hashing.
- Migration deadlines for NSS: support CNSA 2.0 algorithms by January 2027; exclusive use for application-layer protocols by 2030; all infrastructure by 2031–2033; full deprecation of CNSA 1.0 by 2033–2035.

**Note:** Verbatim quotes from the CNSA 2.0 PDF advisory itself could not be retrieved (HTTP 403). Deadlines are confirmed from multiple indexed US government and defense-industrial sources.

**Source:** NSA, *Commercial National Security Algorithm Suite 2.0*, Sept. 7, 2022. [https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF](https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF)

---

### 1.6 ENISA Post-Quantum Cryptography Reports

**ENISA 2021 PQC Report (May 2021, v2) — Verbatim**

The ENISA 2021 report was retrieved and read in full (PDF, 46 pages). It uses the term **"retrospective decryption"** rather than HNDL. Section 1 (Introduction), verbatim:

> "What makes matters worse is that any ciphertext intercepted by an attacker today can be decrypted by the attacker as soon as he has access to a large quantum computer (Retrospective decryption). Analysis of Advanced Persistent Threats (APT) and Nation State capabilities, along with whistle-blowers' revelations have shown that threat actors can and are casually recording all Internet traffic in their datacentres and that they select encrypted traffic as interesting and worth storing. This means that any data encrypted using any of the standard public-key systems today will need to be considered compromised once a quantum computer exists and there is no way to protect it retroactively, because a copy of the ciphertext is in the hands of the attacker."

Section 7 (Conclusions), verbatim:

> "It is thus important to have replacements in place well in advance. What makes matters worse is that any encrypted communication intercepted today can be decrypted by the attacker as soon as he has access to a large quantum computer, whether in 5, 10 or 20 years from now; an attack known as retrospective decryption."

**Source:** ENISA, *Post-Quantum Cryptography: Current State and Quantum Mitigation*, v2, May 2021. ISBN 978-92-9204-468-8. DOI 10.2824/92307. [https://www.enisa.europa.eu/publications/post-quantum-cryptography-current-state-and-quantum-mitigation](https://www.enisa.europa.eu/publications/post-quantum-cryptography-current-state-and-quantum-mitigation)

**ENISA 2022 Integration Study (October 2022)**

The 2022 ENISA Integration Study (also retrieved and read, 41 pages) focuses on protocol-level integration challenges and does not contain a HNDL-specific threat section. It discusses Shor's and Grover's algorithms and notes the retrospective decryption concern but does not use "harvest now" or "store now decrypt later" verbatim.

**Source:** ENISA, *Post-Quantum Cryptography: Integration Study*, Oct. 2022. [https://www.enisa.europa.eu/sites/default/files/publications/Post%20Quantum%20Cryptography-%20Integration%20Publication.pdf](https://www.enisa.europa.eu/sites/default/files/publications/Post%20Quantum%20Cryptography-%20Integration%20Publication.pdf)

---

### 1.7 UK NCSC — Preparing for Quantum-Safe Cryptography (November 2020)

The NCSC whitepaper uses neither "harvest now, decrypt later" nor "store now, decrypt later" verbatim. Its framing (confirmed verbatim via parliamentary evidence citation):

> "The threat to key agreement is that an adversary collecting encrypted data today would be able to decrypt it in future, should they have access to a CRQC."

The NCSC whitepaper also distinguishes threat types:

> "The threat to digital signatures is that an adversary in possession of a CRQC could 'forge' signatures and impersonate the legitimate private key owner, or tamper with information whose authenticity is protected by a digital signature. This attack should be considered **before** a CRQC exists, when deploying high-value, root-level public keys intended to have a long operational lifetime."

On CRQC uncertainty: "it is impossible to predict with confidence how progress towards large-scale general-purpose quantum computing will evolve."

**Source:** NCSC, *Preparing for Quantum-Safe Cryptography*, v2.0, Nov. 11, 2020. [https://www.ncsc.gov.uk/whitepaper/preparing-for-quantum-safe-cryptography](https://www.ncsc.gov.uk/whitepaper/preparing-for-quantum-safe-cryptography)

---

### 1.8 Where Authorities Agree and Differ

| Dimension | NSM-10 / M-23-02 | NIST IR 8547 | NSA CNSA 2.0 | ENISA 2021 | NCSC 2020 |
|---|---|---|---|---|---|
| HNDL applies to key establishment | ✓ | ✓ | ✓ | ✓ | ✓ |
| HNDL does NOT apply to authentication | Implicit (footnote 11) | Explicit verbatim | Implicit (timeline difference) | Not addressed | Partial (root key caveat) |
| Migration deadline | 2035 | 2030 deprecated / 2035 disallowed | 2031–2035 (tiered by system type) | No hard date set | No hard date set |
| Phrase used | "recorded now and later decrypted" | "harvest now, decrypt later" | Not confirmed verbatim | "retrospective decryption" | "adversary collecting…decrypt in future" |

All five authorities agree that: (1) HNDL is an active, present-day threat requiring immediate action; (2) key establishment is the primary concern; (3) the migration must begin before a CRQC exists.

---

## Section 2: Mosca's Theorem / Inequality

### 2.1 Formulation

Mosca's inequality was first published as an IACR ePrint preprint (2015/1075) and formalized in:

> M. Mosca, "Cybersecurity in an Era with Quantum Computers: Will We Be Ready?," *IEEE Security & Privacy*, vol. 16, no. 5, pp. 38–41, Sept./Oct. 2018. DOI: 10.1109/MSP.2018.3761723.

The inequality:

```
If X + Y > Z, then you will not be able to provide the required X years of security.
```

Variable definitions (from the IACR 2015/1075 preprint and IEEE 2018 paper):

- **X** — *security shelf-life*: the number of years the data or system must remain confidential. Range: X = 0 for real-time-only data; X = 100 for genomic/national security data.
- **Y** — *migration time*: how long it takes to deploy quantum-safe cryptography. Mosca notes Y ≥ 15 years if an untested public-key method must be standardized and deployed across constrained environments with many stakeholders.
- **Z** — *collapse time* (also: time to quantum): how long before a CRQC capable of breaking current public-key algorithms exists.

From the IACR preprint (2015/1075), confirmed verbatim via indexed sources:

> "If X+Y > Z, then you will not be able to provide the required X years of security."

Additional warning from Mosca:

> "If Y > Z, then cyber systems will collapse in Z years with no quick fix."

**Sources:**
- M. Mosca, IACR ePrint 2015/1075. [https://eprint.iacr.org/2015/1075](https://eprint.iacr.org/2015/1075)
- M. Mosca, *IEEE Security & Privacy*, 2018. [https://ieeexplore.ieee.org/document/8490169/](https://ieeexplore.ieee.org/document/8490169/)

### 2.2 Community Estimates for Z (Time to CRQC) as of Mid-2026

The Global Risk Institute (GRI) Annual Quantum Threat Timeline Report (led by Mosca and Piani) is the most-cited primary expert survey:

- **GRI 2024 Report**: 47 experts surveyed. Median estimate: **17–34% probability of a CRQC capable of breaking RSA-2048 in 24 hours by 2034**. Probability increases to 79% by 2044.
- **GRI 2025 Report (6th annual)**: Median expert estimate placed at 2029–2032; **34% probability by 2030** — the highest 10-year range in the survey's history.

ETSI Quantum-Safe Cryptography Working Group: uses the planning assumption of a CRQC within 10–15 years for migration timeline calculations, consistent with Z ≈ 2032–2037.

X9 Financial Services working group: same 2030–2035 planning window, consistent with GRI data.

**Sources:**
- M. Mosca and M. Piani, *Quantum Threat Timeline Report*, Global Risk Institute, 2024. [https://globalriskinstitute.org/publication/2024-quantum-threat-timeline-report/](https://globalriskinstitute.org/publication/2024-quantum-threat-timeline-report/)
- GRI 2025 Report: [https://globalriskinstitute.org/publication/2025-quantum-threat-timeline-report/](https://globalriskinstitute.org/publication/2025-quantum-threat-timeline-report/)

---

## Section 3: Time-to-CRQC Estimates (Mid-2026 Consensus)

### 3.1 Agency Positions

**NSA (CNSA 2.0, 2022):** Does not publish a predicted CRQC date. Sets NSS migration deadlines (2027, 2030, 2033, 2035) as a planning framework assuming CRQC arrival within that window. Interpreted by the community as implying Z ≤ 2033–2035.

**NIST (IR 8547 ipd, 2024):** States the gap between current quantum computers and a CRQC "is still exceedingly large (e.g., many orders of magnitude with regard to physical qubit scaling as well as the error rate at the level of logical qubits)" — while simultaneously setting a 2030/2035 deprecation schedule. NIST explicitly does not commit to a CRQC date; the 2030/2035 schedule is a planning horizon, not a prediction.

**OMB M-23-02 (2022):** References NSM-10's goal of mitigating quantum risk "as is feasible by 2035" as the planning target for federal civilian agencies.

**ENISA (2021):** Uses the phrase "whether in 5, 10 or 20 years from now" (verbatim, Section 7 Conclusions — see §1.6 above). This maps to Z ∈ [2026, 2041] from a 2021 baseline, i.e., Z ∈ [2025, 2040] from a 2026 perspective.

**NCSC (2020):** States it is "impossible to predict with confidence how progress towards large-scale general-purpose quantum computing will evolve."

### 3.2 Expert Survey Consensus (Mid-2026)

The GRI 2025 report (the most recent primary survey available as of mid-2026) gives:
- 34% probability of CRQC by 2030
- Median expert estimate: 2029–2032
- 79% probability of CRQC by 2044

**Planning consensus for enterprises:** Z = 2030–2035 is the most-cited window. For high-risk data (X ≥ 10 years), Mosca's inequality is already triggered in 2026 if Y ≥ 5 years (since 10 + 5 = 15, and a 2026 + 15 = 2041 deadline exceeds the 34% probability CRQC window of 2030).

### 3.3 Recent Hardware Developments

Neither NIST, NSA, nor ENISA policy documents reference specific vendor hardware milestones (Google Willow, IBM Heron) as changing their policy timelines. The GRI 2025 survey does note that "recent algorithmic work has reduced RSA-2048 factorization requirements by approximately 95% in physical qubit count" — this is reflected in the escalating GRI probability estimates above. No primary policy document has issued an update specifically citing Google Willow (December 2024) or IBM Heron as triggering a revised deadline.

---

## Section 4: Data Shelf-Life Taxonomy

### 4.1 Framework: Mosca's Variable X

Mosca's original 2015/2018 papers use a continuous variable X (years). The community has converged on discrete buckets for practical scoring:

| Category | Shelf-Life Range | Examples |
|---|---|---|
| Ephemeral | 0 days | TLS session keys, OTP tokens |
| Short-lived | < 7 years | Most commercial contracts, standard financial records |
| Medium-lived | 7–30 years | HIPAA compliance docs (6 yr min), SEC 17a-4 records (3–6 yr), OSHA medical records (employment + 30 yr) |
| Long-lived | 30+ years | NARA classified records (≥ 25 yr before NARA transfer), employee exposure records |
| Indefinite | Permanent | Trade secrets, genomic data, national security intelligence, IP |

### 4.2 Regulatory Retention Floors

These are the minimum retention periods required by law or regulation; actual shelf-life (X in Mosca) is the **longer** of the legal floor and the operational sensitivity:

| Regulation | Minimum Retention | Data Type |
|---|---|---|
| HIPAA (45 CFR §164.530) | 6 years from creation or last effective date | HIPAA compliance documentation, risk analyses |
| CMS / Medicare | 7–10 years from date of service | Patient medical records (Medicare) |
| OSHA (29 CFR §1910.1020) | Duration of employment + 30 years | Employee medical and exposure records |
| SEC Rule 17a-4 (17 CFR §240.17a-4) | 6 years (trade blotters, ledgers); 3 years (communications) | Broker-dealer records |
| NARA (36 CFR Part 1235) | ≥ 25 years before legal transfer for classified records; up to 30+ years before restrictions lifted | Federal classified / permanent records |
| NIST FIPS 199 / SP 800-60 | High-impact system designation = sensitivity value "High" | Federal information systems (maps to HNDL priority) |

**Source for NARA classified records:** NARA, 36 CFR Part 1235 and NARA records schedule guidance; NARA "does not usually approve records schedules proposing the legal transfer of security classified records earlier than 25 years."

**Source for HIPAA:** 45 CFR §164.530(j). Note: clinical medical records are governed by state law, not HIPAA; typical state requirements range 3–20 years, with many states requiring adult record retention until age of majority + 3–10 years.

### 4.3 ETSI TR 103 619 Guidance

ETSI TR 103 619 V1.1.1 (July 2020), *CYBER; Migration strategies and recommendations to Quantum Safe schemes*, provides a three-stage migration framework (inventory, planning, execution). It notes:

> The scope of attack considered includes those attacks against the cryptographic elements of the system…the threat of quantum computing to asymmetric cryptography has been recognized as an existential threat to the many business sectors that rely on asymmetric cryptography for their day-to-day existence.

ETSI TR 103 619 does not define data shelf-life categories directly but recommends a questionnaire covering "data assessment" as part of Stage 1 inventory, covering how long the data and associated metadata need protection.

**Source:** ETSI TR 103 619 V1.1.1, July 2020. [https://www.etsi.org/deliver/etsi_tr/103600_103699/103619/01.01.01_60/tr_103619v010101p.pdf](https://www.etsi.org/deliver/etsi_tr/103600_103699/103619/01.01.01_60/tr_103619v010101p.pdf)

### 4.4 M-23-02 Inventory Requirement (Verbatim)

M-23-02 Section II.A, item 8, requires agencies to inventory:

> "Lifecycle characteristics of the data contained in the system, including types of data (as described by national records management categories) and **how long the data and associated metadata need protection (i.e., 'time to live').**"

This is the closest primary-source definition of what quipuu should treat as "DataShelfLife" in its scoring.

---

## Section 5: HNDL Scoring — Existing Literature

### 5.1 IEQ (Quantum Exposure Index) — Rufino, Marcelino, Garcia (2025)

The most structurally rigorous formal HNDL scoring framework in the literature is:

> M. Rufino, R.D. Marcelino, J.S. Garcia, "A Formal Basis for Quantum Cryptographic Exposure Measurement under HNDL Threat," GWK Security / UNICAMP, arXiv:2605.22569, 2025.

**Four input variables (from the paper, verbatim):**

- **V ∈ (0,1]** — *quantum vulnerability fraction*: "the share of its cryptographic attack surface using algorithms breakable by Shor's algorithm — RSA, ECDH, ECDSA, and DSA: algorithms based on integer factorization or discrete logarithm problems."
- **E ∈ (0,1]** — *operational exposure*: "how accessible that surface is to an external adversary. High E means the encrypted traffic is observable and storable. Low E means the adversary cannot reach it."
- **T_D > 0** — *adversarial shelf life*: "how long the captured ciphertext retains strategic value after harvest. A trade secret may be sensitive for decades. A stock price tip expires in days."
- **μ > 0** — *effective decay rate*: rate at which harvested ciphertext loses exploitability through data-value decay, key rotation, and PQC migration.

**Main result (Eq. 5, verbatim from paper):**

```
P_HNDL = H · (V^a · E^b) / (V^a · E^b + θ)
```

Where H is the temporal hazard (probability that CRQC arrives within the data's adversarial horizon), θ = μ/λ₀ is the defense-attack intensity ratio, and a, b > 0 are elasticity parameters.

**Key finding from Corollary 1:** "Any purely additive separable exposure score of the form S = Σ w_i x_i … uses fixed marginal contributions that are independent of the organization's position in the (V,E) plane, eliminating the V×E interaction and treating vulnerability and accessibility as substitutes rather than complements in attack production. No such score preserves the interaction structure induced by [the multiplicative model]."

**Critical limitation stated in the paper:** "There is no dataset of confirmed HNDL exploitations. Absolute calibration of Eq. (5) is infeasible in the pre-CRQC regime."

**Operational consequence for quipuu:** The IEQ paper establishes that V and E must be multiplied, not summed, for structural correctness. The quipuu QuantumRiskScore (Section 8) uses an additive structure for operational simplicity and tooling integration — this is a known theoretical tradeoff, acknowledged by the IEQ authors as acceptable for "operational prioritization indices" that are "locally consistent with P_HNDL within fixed (H, θ, M) regimes."

**Source:** arXiv:2605.22569. [https://arxiv.org/abs/2605.22569](https://arxiv.org/abs/2605.22569)

### 5.2 NIST SP 1800-38 (NCCoE, December 2023)

NIST SP 1800-38 (preliminary draft) is the NCCoE playbook for PQC migration. It does not define a formal HNDL risk score. It provides a triage methodology: identify critical business processes, map to cryptographic systems, rank by FIPS 199 impact level and HNDL exposure. The triage is qualitative, not scored.

**Source:** NIST SP 1800-38, *Migration to Post-Quantum Cryptography*, Dec. 2023. [https://www.nccoe.nist.gov/applied-cryptography/migration-to-pqc](https://www.nccoe.nist.gov/applied-cryptography/migration-to-pqc)

### 5.3 IBM Research, SandboxAQ, PQShield

As of mid-2026, no standalone formally published HNDL risk-scoring paper was found from IBM Research, SandboxAQ, or PQShield in indexed academic literature. IBM Research's quantum risk analysis work (Woerner et al., *npj Quantum Information*) focuses on quantum finance (option pricing), not cryptographic risk scoring. SandboxAQ and PQShield operate cryptographic discovery platforms but have not published a primary academic scoring methodology with peer review.

---

## Section 6: Exposure Axes

### 6.1 The Primary Distinction: Key Establishment vs. Authentication

The most important exposure axis is whether the cryptographic operation establishes confidentiality or merely authenticates. **Only key establishment is HNDL-relevant.**

NIST IR 8547 ipd states this explicitly (verbatim, confirmed):

> "Unlike with encryption, where there is a threat of 'harvest now, decrypt later,' an authentication system remains secure as long as the cryptographic algorithms and keys used to perform the authentication are secure when the authentication is performed."

This means:
- An RSA or ECDH key exchange (confidentiality) = **HNDL-relevant**: an attacker who captures the key exchange transcript today can decrypt the session data retrospectively once a CRQC exists.
- An ECDSA or RSA signature on a TLS certificate (authentication only, where the attacker must be present **now** to MITM) = **not HNDL-relevant** in the same way. A signature used to authenticate a current transaction has no retrospective attack surface. (Exception: long-lived root CA keys that authenticate long-lived code signing chains — see NCSC §1.7.)

**Source:** NIST IR 8547 ipd, §2 (Authentication), Nov. 2024.

### 6.2 Public-Facing vs. Internal

Public-facing endpoints (internet-reachable TLS, VPN endpoints, public APIs) have higher operational exposure (E in the IEQ framework) because network-position adversaries can observe and record ciphertext without additional access. Internal endpoints require insider access or lateral movement — lower E.

CISA/NSA/NIST 2023 joint factsheet recommends:

> "prioritize high-impact systems, industrial control systems (ICS), and systems with long-term confidentiality needs; identify and develop plans to address quantum-vulnerable cryptography in custom-built technologies."

**Source:** CISA/NSA/NIST, *Quantum-Readiness: Migration to Post-Quantum Cryptography (PQC)*, Aug. 2023. [https://www.cisa.gov/news-events/alerts/2023/08/21/cisa-nsa-and-nist-publish-factsheet-quantum-readiness](https://www.cisa.gov/news-events/alerts/2023/08/21/cisa-nsa-and-nist-publish-factsheet-quantum-readiness)

### 6.3 Long-Term Key vs. Ephemeral Key

M-23-02 explicitly prioritizes systems using asymmetric cryptography for key establishment (ECDH, DH, RSA key transport) over systems using only digital signatures — because the former creates long-lived ciphertext subject to retrospective decryption.

CNSA 2.0 timelines reflect this: key establishment protocols (IPsec, TLS) have earlier exclusive-use deadlines (2030) than software signing (2033).

### 6.4 Data-at-Rest vs. Data-in-Transit

Both are HNDL-relevant when they use asymmetric key establishment. M-23-02 covers:
- "Encrypted connections" (in-transit)
- "Creation and exchange of encryption keys" (the wrapping key protecting at-rest data)

A long-lived data-at-rest encryption key established via RSA or ECDH key wrap is HNDL-vulnerable. A symmetric AES key derived directly from a long-term secret (e.g., hardware-secured KMS with no asymmetric key exchange) is not HNDL-vulnerable unless the KMS uses asymmetric algorithms for key establishment.

---

## Section 7: Sector-Specific HNDL Priority Signals

### 7.1 Government / National Security

**Highest priority.** NSM-10 and M-23-02 require all federal systems classified as "High Value Assets" (HVAs) or FIPS 199 High-impact systems to be inventoried by May 2023, with migration to PQC by 2035. Systems protecting data expected to remain mission-sensitive in 2035 have mandatory inventory requirements under M-23-02.

NSA CNSA 2.0 applies to all NSS (National Security Systems). 2030 is the exclusive-use deadline for key establishment in NSS networks.

CISA coordinates the civilian agency migration and issued the 2022 Insight *Preparing Critical Infrastructure for Post-Quantum Cryptography*, covering all 55 National Critical Functions.

**Source:** M-23-02; CISA, Aug. 2022. [https://www.cisa.gov/news-events/alerts/2022/08/24/preparing-critical-infrastructure-post-quantum-cryptography](https://www.cisa.gov/news-events/alerts/2022/08/24/preparing-critical-infrastructure-post-quantum-cryptography)

### 7.2 Financial Services

**High priority.** ANSI X9.146 (draft, last updated January 2024) defines X.509 Alternative Keys (chimera/Catalyst certificates) and specifies ML-KEM-1024 and ML-DSA-87 at Security Level 5 for financial sector TLS and PKI. X9.146 aligns with CNSA 2.0 algorithm choices.

No "data type must be PQ-protected by X date" matrix has been published in a finalized, publicly available X9 standard as of mid-2026. X9's assessment guidelines are under development and not yet a finalized primary source.

SEC Rule 17a-4 records (3–6 year retention) are not in the long-shelf-life category by themselves, but broker-dealer long-term records and permanent records (e.g., articles of incorporation) are indefinite and therefore HNDL-relevant for key establishment protecting access to those records.

**Source:** ANSI X9.146 draft, Jan. 2024. [https://x9.org/](https://x9.org/)

### 7.3 Healthcare

**High priority for long-lived records.** OSHA employee medical records (employment + 30 years) and Medicare records (10 years) combined with long-lived patient genetic data (indefinite) create X values of 30–100 years. By Mosca's inequality with Y ≈ 5–10 years and Z ≈ 2030–2035, healthcare HNDL risk is triggered immediately.

No HHS or ONC guidance specifically mandating PQC for healthcare data by a specific date exists as a published primary source as of mid-2026. The CISA 2022 Insight covers healthcare as a critical infrastructure sector.

### 7.4 Critical Infrastructure

CISA 2022 Insight assessed quantum vulnerabilities across all 55 National Critical Functions. CISA Director Jen Easterly (August 2023): "It is imperative for all organizations, especially critical infrastructure, to begin preparing now for migration to post-quantum cryptography."

CISA's 2023 joint factsheet with NSA and NIST recommends targeting "systems and protocols protecting critical processes and sensitive and critical assets with quantum-vulnerable algorithms" first.

**Source:** CISA/NSA/NIST factsheet, Aug. 2023. [https://www.cisa.gov/news-events/alerts/2023/08/21/cisa-nsa-and-nist-publish-factsheet-quantum-readiness](https://www.cisa.gov/news-events/alerts/2023/08/21/cisa-nsa-and-nist-publish-factsheet-quantum-readiness)

### 7.5 Summary: "Must be PQ-protected by X date" Matrix

No single primary-source document publishes a sector-by-sector "data type must be PQ-protected by date" matrix. The closest primary-source construct is the M-23-02 priority criterion: **any data "expected to remain mission-sensitive in 2035" requires PQC protection for its key establishment layer now.** This is the operational definition used for quipuu's `DataShelfLife` dimension.

---

## Section 8: Quipuu QuantumRiskScore Algorithm

### 8.1 Design Rationale

The IEQ framework (§5.1) establishes that a multiplicative V×E structure is theoretically superior to additive scoring. Quipuu uses additive scoring because:

1. Tooling integration: SARIF, CBOM, and static analysis tools produce discrete per-finding severity scores, not probability distributions.
2. Partial observability: Detection confidence (whether the algorithm was statically detected vs. inferred) is a tool-specific signal that has no place in the IEQ probabilistic model.
3. The IEQ authors explicitly acknowledge additive scores are "locally consistent" prioritization indices.

The IEQ framework informs weight ordering: V (vulnerability) and E (exposure) are the primary drivers and receive the highest combined weight (40 + 10 = 50 points out of 100). Shelf-life (T_D) and usage context add modifiers.

### 8.2 The Scoring Formula

```
QuantumRiskScore (0–100) =
    AlgorithmVulnerability (0–40)
  + UsageContext           (0–25)
  + DataShelfLife          (0–15)
  + Exposure               (0–10)
  + DetectionConfidence    (0–10)
```

Maximum score: 100. Score ≥ 70: Critical. Score 40–69: High. Score 20–39: Medium. Score < 20: Low.

---

### 8.3 Dimension 1: AlgorithmVulnerability (0–40)

Maps to V (quantum vulnerability fraction) in the IEQ. This is also where CycloneDX 1.6 CBOM `nistQuantumSecurityLevel` (integer 0–6) provides the floor signal.

**CycloneDX 1.6 CBOM `nistQuantumSecurityLevel`:** Integer 0–6. Value **0 = "none of the categories are met"** — i.e., the asset has no NIST PQC security level and is not quantum-resistant. Values 1–5 correspond to NIST PQC security strength categories I–V. Value 6 is not a NIST PQC category but may represent a vendor extension. An asset with `nistQuantumSecurityLevel = 0` and a Shor-breakable algorithm should receive the maximum AlgorithmVulnerability score.

| Condition | Score | Justification |
|---|---|---|
| Shor-breakable asymmetric algorithm in key establishment: RSA, ECDH/ECDSA, DH, DSA, ECDHE | **40** | M-23-02 Appendix B explicitly lists these as CRQC-vulnerable; NIST IR 8547 ipd targets them for deprecation by 2030/2035; `nistQuantumSecurityLevel = 0` |
| Classically broken algorithm (MD5, SHA-1, DES, 3DES, RC4, export ciphers) | **40** | Already broken; FIPS 140-3 and NIST SP 800-131A Rev. 2 disallow these; classical attacker can decrypt today — higher urgency than HNDL |
| Grover-weakened symmetric algorithm with insufficient key size: AES-128, HMAC-SHA-1 | **15** | Grover's algorithm halves effective security; ENISA 2021 §1 (verbatim): "breaking AES-128 takes 2^64 quantum operations"; remedy is to use AES-256; `nistQuantumSecurityLevel` not applicable to symmetric primitives but score reflects elevated risk |
| Approved PQC algorithm (ML-KEM, ML-DSA, SLH-DSA per FIPS 203/204/205) | **0** | NIST-standardized; `nistQuantumSecurityLevel ≥ 1` (typically 1, 3, or 5 depending on parameter set) |
| Symmetric with sufficient key size: AES-256, ChaCha20, HMAC-SHA-256/384/512 | **0** | NIST IR 8547 ipd: "doubling the key sizes" sufficient for Grover resistance; M-23-02 Appendix B does not list these as CRQC-vulnerable |
| Unknown/unrecognized algorithm | **20** | Judgment: cannot assess; conservative scoring |

**Weight justification:** 40 points is the largest single dimension because V is the primary driver in the IEQ (Rufino et al., 2025), and M-23-02 Appendix B defines the exact algorithm set as "CRQC-vulnerable." The 40-point cap anchors to the NIST/NSA consensus that Shor-breakable asymmetric algorithms represent the highest-priority HNDL exposure.

---

### 8.4 Dimension 2: UsageContext (0–25)

Captures the HNDL-relevant distinction between key establishment (which creates long-lived ciphertext) and authentication-only (which does not). This directly implements the NIST IR 8547 ipd verbatim distinction quoted in §6.1.

| Usage Context | Score | Justification |
|---|---|---|
| Key establishment (ECDH, DH, RSA key transport, ML-KEM) + long-lived key or session | **25** | Primary HNDL vector per M-23-02 footnote 11; NIST IR 8547 ipd makes this distinction explicit; CNSA 2.0 gives earliest exclusive-use deadline (2030) to key establishment protocols |
| Key establishment + ephemeral key (e.g., ECDHE with PFS) | **15** | PFS limits scope of harvest (each session independently protected), but the key exchange itself is still HNDL-vulnerable; judgment, anchored on the principle that forward secrecy limits blast radius but does not eliminate harvest risk |
| Digital signature + long-lived key (root CA, code signing key, firmware signing) | **15** | NCSC 2020 (verbatim, §1.7): signatures "should be considered before a CRQC exists, when deploying high-value, root-level public keys intended to have a long operational lifetime." Long-lived signing keys that authenticate trust chains for decades are partially HNDL-relevant via the trust-chain compromise vector |
| Digital signature + short-lived key (TLS server cert with 90-day or 1-year validity) | **5** | Per NIST IR 8547 ipd: authentication "remains secure as long as the cryptographic algorithms and keys used…are secure when authentication is performed." Short-lived ephemeral auth certs pose minimal HNDL risk |
| MAC / HMAC authentication only | **3** | Judgment: symmetric authentication; quantum risk is Grover-limited; not HNDL-relevant for confidentiality |
| Hash function (integrity only, no key establishment) | **1** | Judgment: no key material; Grover applies but integrity-only use has minimal HNDL exposure |

**Weight justification:** 25 points because usage context is the *second most important* dimension in HNDL risk, reflecting the structure of both the IEQ (where V and E drive P_HNDL multiplicatively) and the NIST/NCSC guidance that explicitly bifurcates encryption (HNDL-relevant) from authentication (not HNDL-relevant in the standard case).

---

### 8.5 Dimension 3: DataShelfLife (0–15)

Maps to T_D (adversarial shelf life) in the IEQ. Captures X in Mosca's inequality. Values derived from the regulatory taxonomy in §4.

| Shelf-Life Category | Score | Regulatory Anchor |
|---|---|---|
| Indefinite / 30+ years (e.g., classified records, genomic data, trade secrets, long-term IP) | **15** | NARA classified records ≥ 25 yr (36 CFR Part 1235); Mosca (2018): "national security information" as example of X = 100 years; M-23-02 fn.11 criterion |
| 7–30 years (e.g., OSHA medical records, Medicare records, long-term financial records) | **10** | OSHA 29 CFR §1910.1020: employment + 30 yr; CMS Medicare: 7–10 yr; Mosca (2018): trade secrets example |
| 1–7 years (e.g., HIPAA compliance docs, SEC 17a-4 communications, typical financial records) | **3** | HIPAA 45 CFR §164.530(j): 6 yr; SEC 17a-4: 3–6 yr; below the 7-year threshold means Mosca's X + Y ≤ Z for most Y and Z estimates |
| Ephemeral / < 1 year (e.g., session tokens, OTP, real-time telemetry) | **0** | M-23-02 fn.11: no HNDL risk if data has no mission sensitivity in 2035 |
| Unknown / not assessed | **8** | Judgment: conservative midpoint; tool cannot determine shelf life without data classification context |

**Weight justification:** 15 points. DataShelfLife is T_D in the IEQ framework; Rufino et al. (2025) identify it as a "sector-level prior, not an auditable metric" and note Mosca (2018) treats it as a "strategic horizon estimate." The relatively lower weight (vs. AlgorithmVulnerability) reflects the fact that at the level of a single finding, the algorithm type (V) is more precisely detectable than data classification (T_D). The 15-point maximum is set so that an ephemeral-key algorithm finding (DataShelfLife = 0) can still score high if the algorithm is broken classically.

---

### 8.6 Dimension 4: Exposure (0–10)

Maps to E (operational exposure) in the IEQ. Captures network-position accessibility.

| Exposure Context | Score | Justification |
|---|---|---|
| Public internet-facing endpoint (TLS server, public API, VPN concentrator, SMTP/IMAP) | **10** | IEQ E → 1 when adversary has full network access; CNSA 2.0 FAQ notes network protocols are the highest-priority migration target; CISA 2022 Insight focuses on internet-accessible infrastructure first |
| Internet-accessible but behind auth (enterprise SSO, API with token auth required) | **7** | Judgment: adversary with BGP manipulation or passive monitoring can still harvest ciphertext; auth requirement raises barrier but not eliminates collection |
| Internal network, not internet-facing | **4** | Judgment, anchored on CISA/NSA/NIST 2023 factsheet recommendation to prioritize "systems with long-term confidentiality needs" irrespective of internet exposure; insider threat and APT lateral movement still enable harvest |
| Local / loopback / IPC only | **1** | Judgment: harvest requires local code execution; lower risk but non-zero for APT with persistent access |

**Weight justification:** 10 points. E is a secondary driver in the IEQ (parameter b < a in Rufino et al.'s empirical calibration). Exposure is also harder to assess statically; a 10-point cap acknowledges that static analysis cannot fully determine network topology.

---

### 8.7 Dimension 5: DetectionConfidence (0–10)

Tool-specific dimension with no direct primary-source analog. Captures how certain the scanner is about the algorithm identification.

| Detection Confidence | Score | Rationale |
|---|---|---|
| Literal algorithm name as string constant or enum (e.g., `"RSA/ECB/PKCS1Padding"`, `CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`) | **10** | High confidence; scanner directly observed the algorithm specification |
| Variable or computed value (e.g., algorithm loaded from config, passed as parameter) | **5** | Medium confidence; algorithm is present but not statically resolved |
| String table / annotation / dependency manifest inference (e.g., library dependency on openssl with detected RSA calls) | **2** | Low confidence; algorithm inferred from library presence, not direct usage |
| Unresolved / inferred from dataflow without concrete algorithm evidence | **1** | Very low confidence; risk of false positive |

**Weight justification:** 10 points. Judgment, anchored on the principle that scanner findings should be weighted by their reliability. A lower DetectionConfidence score reduces total score, preventing false-positive noise from dominating the risk queue. The 10-point cap prevents DetectionConfidence from overriding true risk signals; a high-confidence detection of a low-vulnerability algorithm still scores low.

---

### 8.8 Score Interpretation

| Score Range | Severity Level | Policy Implication |
|---|---|---|
| 70–100 | **Critical** | Immediate remediation required. Key establishment using Shor-vulnerable algorithm on public-facing system protecting long-lived data. Triggers M-23-02 inventory priority criterion. |
| 40–69 | **High** | Migration planning required. Address before CNSA 2.0 2030 deadline. |
| 20–39 | **Medium** | Migration recommended. Address before 2035 deprecation. |
| 1–19 | **Low** | Informational. Monitor for algorithm sunset guidance. |
| 0 | **Informational** | PQC-compliant or non-HNDL-relevant. |

---

### 8.9 Example Scores

| Finding | AlgVuln | UsageCtx | ShelfLife | Exposure | DetectConf | Total | Severity |
|---|---|---|---|---|---|---|---|
| RSA-2048 key exchange, public TLS server, healthcare records, literal string | 40 | 25 | 15 | 10 | 10 | **100** | Critical |
| ECDHE-RSA, public TLS, short-lived session, literal | 40 | 15 | 0 | 10 | 10 | **75** | Critical |
| ECDSA (signature only), 90-day cert, public HTTPS, literal | 40 | 5 | 0 | 10 | 10 | **65** | High |
| AES-128 symmetric, internal API, short-lived, literal | 15 | 3 | 3 | 4 | 10 | **35** | Medium |
| ML-KEM-1024, public TLS, any shelf life | 0 | 25 | 15 | 10 | 10 | **60** | Note: PQC algorithm scores 0 AlgVuln but may score non-zero on other dimensions if usage context is misconfigured — this is expected; total ≤ 60 without AlgVuln contribution |
| AES-256-GCM, local encryption, ephemeral, literal | 0 | 3 | 0 | 1 | 10 | **14** | Low |

---

## References

[1] OMB M-23-02, *Migrating to Post-Quantum Cryptography*, Office of Management and Budget, Nov. 18, 2022. [https://www.whitehouse.gov/wp-content/uploads/2022/11/M-23-02-M-Memo-on-Migrating-to-Post-Quantum-Cryptography.pdf](https://www.whitehouse.gov/wp-content/uploads/2022/11/M-23-02-M-Memo-on-Migrating-to-Post-Quantum-Cryptography.pdf)

[2] NSM-10, *National Security Memorandum on Promoting United States Leadership in Quantum Computing While Mitigating Risks to Vulnerable Cryptographic Systems*, White House, May 4, 2022. [https://www.whitehouse.gov/briefing-room/statements-releases/2022/05/04/national-security-memorandum-on-promoting-united-states-leadership-in-quantum-computing-while-mitigating-risks-to-vulnerable-cryptographic-systems/](https://www.whitehouse.gov/briefing-room/statements-releases/2022/05/04/national-security-memorandum-on-promoting-united-states-leadership-in-quantum-computing-while-mitigating-risks-to-vulnerable-cryptographic-systems/)

[3] NIST IR 8547 ipd, *Transition to Post-Quantum Cryptography Standards*, D. Moody et al., NIST, Nov. 2024. [https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf](https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf)

[4] NSA, *Commercial National Security Algorithm Suite 2.0*, Sept. 7, 2022. [https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF](https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF) (PDF not directly accessible during research; deadlines confirmed from indexed secondary sources.)

[5] ENISA, *Post-Quantum Cryptography: Current State and Quantum Mitigation*, v2, May 2021. ISBN 978-92-9204-468-8. DOI 10.2824/92307. [https://www.enisa.europa.eu/publications/post-quantum-cryptography-current-state-and-quantum-mitigation](https://www.enisa.europa.eu/publications/post-quantum-cryptography-current-state-and-quantum-mitigation) (PDF retrieved and read in full.)

[6] ENISA, *Post-Quantum Cryptography: Integration Study*, Oct. 2022. [https://www.enisa.europa.eu/sites/default/files/publications/Post%20Quantum%20Cryptography-%20Integration%20Publication.pdf](https://www.enisa.europa.eu/sites/default/files/publications/Post%20Quantum%20Cryptography-%20Integration%20Publication.pdf) (PDF retrieved and read in full.)

[7] NCSC, *Preparing for Quantum-Safe Cryptography*, v2.0, Nov. 2020. [https://www.ncsc.gov.uk/whitepaper/preparing-for-quantum-safe-cryptography](https://www.ncsc.gov.uk/whitepaper/preparing-for-quantum-safe-cryptography)

[8] M. Mosca, "Cybersecurity in an Era with Quantum Computers: Will We Be Ready?," *IEEE Security & Privacy*, vol. 16, no. 5, pp. 38–41, 2018. DOI: 10.1109/MSP.2018.3761723. [https://ieeexplore.ieee.org/document/8490169/](https://ieeexplore.ieee.org/document/8490169/)

[9] M. Mosca, "Cybersecurity in an era with quantum computers: will we be ready?" IACR ePrint 2015/1075. [https://eprint.iacr.org/2015/1075](https://eprint.iacr.org/2015/1075)

[10] M. Mosca and M. Piani, *2024 Quantum Threat Timeline Report*, Global Risk Institute, 2024. [https://globalriskinstitute.org/publication/2024-quantum-threat-timeline-report/](https://globalriskinstitute.org/publication/2024-quantum-threat-timeline-report/)

[11] M. Mosca and M. Piani, *2025 Quantum Threat Timeline Report*, Global Risk Institute, 2025. [https://globalriskinstitute.org/publication/2025-quantum-threat-timeline-report/](https://globalriskinstitute.org/publication/2025-quantum-threat-timeline-report/)

[12] CISA, NSA, NIST, *Quantum-Readiness: Migration to Post-Quantum Cryptography*, Joint Factsheet, Aug. 2023. [https://www.cisa.gov/news-events/alerts/2023/08/21/cisa-nsa-and-nist-publish-factsheet-quantum-readiness](https://www.cisa.gov/news-events/alerts/2023/08/21/cisa-nsa-and-nist-publish-factsheet-quantum-readiness)

[13] CISA, *Preparing Critical Infrastructure for Post-Quantum Cryptography*, CISA Insight, Aug. 24, 2022. [https://www.cisa.gov/news-events/alerts/2022/08/24/preparing-critical-infrastructure-post-quantum-cryptography](https://www.cisa.gov/news-events/alerts/2022/08/24/preparing-critical-infrastructure-post-quantum-cryptography)

[14] NIST SP 1800-38, *Migration to Post-Quantum Cryptography*, NCCoE, Dec. 2023 (preliminary draft). [https://www.nccoe.nist.gov/applied-cryptography/migration-to-pqc](https://www.nccoe.nist.gov/applied-cryptography/migration-to-pqc)

[15] ETSI TR 103 619 V1.1.1, *CYBER; Migration strategies and recommendations to Quantum Safe schemes*, July 2020. [https://www.etsi.org/deliver/etsi_tr/103600_103699/103619/01.01.01_60/tr_103619v010101p.pdf](https://www.etsi.org/deliver/etsi_tr/103600_103699/103619/01.01.01_60/tr_103619v010101p.pdf)

[16] ANSI X9.146 (draft), *Quantum TLS for Financial Services (X.509 Alternative Keys)*, X9F5 Financial PKI workgroup, last updated Jan. 2024. [https://x9.org/](https://x9.org/) (Paywalled; confirmed details from vendor implementation reports.)

[17] M. Rufino, R.D. Marcelino, J.S. Garcia, "A Formal Basis for Quantum Cryptographic Exposure Measurement under HNDL Threat," GWK Security / UNICAMP, arXiv:2605.22569, 2025. [https://arxiv.org/abs/2605.22569](https://arxiv.org/abs/2605.22569) (PDF retrieved and read in full.)

[18] CycloneDX 1.6 Specification, *Cryptography Bill of Materials (CBOM)*, `nistQuantumSecurityLevel` field definition. [https://cyclonedx.org/specification/overview/](https://cyclonedx.org/specification/overview/)

[19] NIST FIPS 199, *Standards for Security Categorization of Federal Information and Information Systems*, Feb. 2004. [https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.199.pdf](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.199.pdf)

[20] NIST SP 800-131A Rev. 2, *Transitioning the Use of Cryptographic Algorithms and Key Lengths*, Mar. 2019. [https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf)

[21] NIST FIPS 203 (*ML-KEM*), FIPS 204 (*ML-DSA*), FIPS 205 (*SLH-DSA*), Aug. 2024. [https://csrc.nist.gov/pubs/fips/203/final](https://csrc.nist.gov/pubs/fips/203/final)

---

*Document version: 2026-06-12. Research performed via direct PDF retrieval (M-23-02, ENISA 2021, ENISA 2022, arXiv:2605.22569) and web search of primary-source indexed content. Where documents returned HTTP 403 (NSA CNSA 2.0 PDF), that is noted; confirmed details are cited only from indexed sources reproducing primary-source language.*

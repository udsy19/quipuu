# NIST PQC Migration Timeline — Authoritative Reference

**For:** seawall risk engine  
**As of:** 2026-06-12  
**Sources:** Primary only (NIST CSRC, NSA media.defense.gov). Blog summaries excluded.  
**Files in `/knowledge/sources/`:** NIST.IR.8547.ipd.pdf, NIST.FIPS.203.pdf, NIST.FIPS.204.pdf, NIST.FIPS.205.pdf, NIST.SP.800-131Ar3.ipd.pdf

---

## 1. NIST IR 8547 — Current Status (mid-2026)

**Status: STILL IPD (Initial Public Draft). No final version published as of 2026-06-12.**

| Field | Value |
|---|---|
| Title | Transition to Post-Quantum Cryptography Standards |
| Published | 2024-11-12 |
| Stage | Initial Public Draft (IPD) |
| Comment period closed | 2025-01-10 |
| Final version | NOT YET PUBLISHED |
| Canonical URL | https://csrc.nist.gov/pubs/ir/8547/ipd |
| PDF | https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf |

**Implication for seawall:** All deprecation/disallow years below are from the IPD. They may change in the final. Monitor https://csrc.nist.gov/pubs/ir/8547 for a non-IPD URL to appear.

---

## 2. Algorithm-by-Algorithm Deprecation/Disallow Timeline

Source: NIST IR 8547 IPD, Tables 2–4 (https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf)

### Terminology
- **Deprecated:** No new deployments permitted after this date. Existing legacy systems must be on documented migration path. Risk justification required for continued use.
- **Disallowed:** Full prohibition in all systems including legacy. Risk acceptance is no longer an option.

### 2.1 Digital Signature Algorithms (NIST IR 8547 Table 2)

| Algorithm | Standard | Security Strength | Operation | Deprecated After | Disallowed After |
|---|---|---|---|---|---|
| RSA | FIPS 186-5 | 112-bit (e.g., RSA-2048) | Signature gen + verify | 2030 | 2035 |
| RSA | FIPS 186-5 | ≥128-bit (e.g., RSA-3072, RSA-4096) | Signature gen + verify | — (not deprecated) | 2035 |
| ECDSA | FIPS 186-5 (SP 800-186 curves) | 112-bit (e.g., P-224) | Signature gen + verify | 2030 | 2035 |
| ECDSA | FIPS 186-5 (SP 800-186 curves) | ≥128-bit (e.g., P-256, P-384, P-521) | Signature gen + verify | — (not deprecated) | 2035 |
| EdDSA (Ed25519, Ed448) | FIPS 186-5 / RFC 8032 | ≥128-bit | Signature gen + verify | — (not deprecated) | 2035 |
| DSA | FIPS 186-5 | 112-bit | Signature gen | 2030 | 2035 |
| DSA | FIPS 186-5 | ≥128-bit | Signature gen | — | 2035 |

**Key note on DSA:** NIST SP 800-131A Rev 3 IPD (Oct 2024) additionally retires DSA for **signature generation** (not just deprecates). DSA for signature *verification* of legacy data may have different treatment — consult SP 800-131A final when published.

### 2.2 Key Establishment Algorithms (NIST IR 8547 Tables 3–4)

| Algorithm | Standard | Security Strength | Operation | Deprecated After | Disallowed After |
|---|---|---|---|---|---|
| RSA key transport | FIPS 186 / SP 800-56B | 112-bit | Key establishment | 2030 | 2035 |
| RSA key transport | SP 800-56B | ≥128-bit | Key establishment | — | 2035 |
| ECDH / ECMQV | SP 800-56A | 112-bit (e.g., P-224) | Key agreement | 2030 | 2035 |
| ECDH / ECMQV | SP 800-56A | ≥128-bit (e.g., P-256, P-384, P-521) | Key agreement | — | 2035 |
| Finite-Field DH (FFDH) | SP 800-56A | 112-bit (e.g., 2048-bit DH) | Key agreement | 2030 | 2035 |
| Finite-Field DH (FFDH) | SP 800-56A | ≥128-bit (e.g., 3072-bit DH) | Key agreement | — | 2035 |
| Finite-Field MQV | SP 800-56A | 112-bit | Key agreement | 2030 | 2035 |
| Finite-Field MQV | SP 800-56A | ≥128-bit | Key agreement | — | 2035 |

**Summary rule from IR 8547:**
> "Under IR 8547, the following algorithms become deprecated after 2030: RSA (all key sizes), elliptic-curve Diffie-Hellman (ECDH), elliptic-curve digital signature algorithm (ECDSA), digital signature algorithm (DSA), and finite-field Diffie-Hellman (FFDH)."

The critical distinction is:
- 112-bit variants: **Deprecated 2030, Disallowed 2035**
- ≥128-bit variants: **NOT deprecated 2030, but Disallowed 2035 directly**

This was a revision from prior NIST guidance. SP 800-57 Part 1 had projected disallow of 112-bit by 2031; IR 8547 softens this to *deprecate* 112-bit by 2030 and *disallow* everything by 2035.

### 2.3 Security Strength to Key-Size Mapping (for seawall classifier)

| Algorithm | Key/Parameter | Security Strength (classical) |
|---|---|---|
| RSA | 1024-bit | 80-bit (already disallowed) |
| RSA | 2048-bit | 112-bit |
| RSA | 3072-bit | 128-bit |
| RSA | 4096-bit | 140-bit |
| RSA | 7680-bit | 192-bit |
| RSA | 15360-bit | 256-bit |
| ECDSA/ECDH | P-224 / secp224r1 | 112-bit |
| ECDSA/ECDH | P-256 / secp256r1 | 128-bit |
| ECDSA/ECDH | P-384 / secp384r1 | 192-bit |
| ECDSA/ECDH | P-521 / secp521r1 | 260-bit |
| EdDSA | Ed25519 | 128-bit |
| EdDSA | Ed448 | 224-bit |
| DH / DSA | 2048-bit group | 112-bit |
| DH / DSA | 3072-bit group | 128-bit |

Source: SP 800-57 Part 1 Rev 5, Table 2.

---

## 3. AES — Status Under NIST IR 8547

Source: NIST IR 8547 IPD, Section 4.1.3

**AES-128, AES-192, AES-256 are NOT deprecated and NOT disallowed under the PQC migration.**

Direct quote from IR 8547 Section 4.1.3:
> "The existing algorithm standards for symmetric cryptography are less vulnerable to attacks by quantum computers. NIST does not expect to need to transition away from these standards as part of the PQC migration."

| Algorithm | IR 8547 Status | Notes |
|---|---|---|
| AES-128 (FIPS 197) | Allowed — no deprecation/disallow date | Grover's reduces effective strength to ~64-bit quantum; NIST considers this acceptable |
| AES-192 (FIPS 197) | Allowed — no deprecation/disallow date | Grover's reduces to ~96-bit quantum |
| AES-256 (FIPS 197) | Allowed — no deprecation/disallow date | Grover's reduces to ~128-bit quantum; NSA CNSA 2.0 mandates AES-256 exclusively |

**CNSA 2.0 distinction:** NSA requires AES-256 (not AES-128 or AES-192) for National Security Systems. AES-128/192 remain NIST-allowed but are not NSA-approved for NSS.

---

## 4. SHA-2 Family — Status Under NIST IR 8547

Source: NIST IR 8547 IPD; NIST SP 800-131A Rev 3 IPD, Section on hash functions.

| Algorithm | IR 8547 Status | SP 800-131A Rev 3 IPD Status | Notes |
|---|---|---|---|
| SHA-224 | Not explicitly disallowed by IR 8547 | **Deprecated after 2030, Disallowed after 2035** per SP 800-131A r3 | 224-bit output deprecated alongside SHA-1 timeline |
| SHA-256 | Allowed — no PQC deprecation | Allowed | Collision resistance ~128-bit classical; acceptable |
| SHA-384 | Allowed — no PQC deprecation | Allowed | NSA CNSA 2.0 mandates SHA-384 for NSS |
| SHA-512 | Allowed — no PQC deprecation | Allowed | Conservative choice for PQC contexts |
| SHA-512/256 | Allowed — no PQC deprecation | Allowed | Truncated variant; same security basis |
| SHA-1 | Already disallowed (pre-IR 8547) | **Disallowed** | Broken classically; irrelevant to PQC timeline |

**Quote from SP 800-131A Rev 3 IPD:**
> "This revision of SP 800-131A deprecates SHA-1 and the 224-bit hash functions."

SHA-256, SHA-384, SHA-512, and SHA-512/256 are not subject to deprecation or disallowance under either IR 8547 or SP 800-131A Rev 3.

---

## 5. FIPS 203/204/205/206 — Status

### 5.1 FIPS 203 — ML-KEM

| Field | Value |
|---|---|
| Full title | Module-Lattice-Based Key-Encapsulation Mechanism Standard |
| Status | **FINAL** |
| Finalized | **2024-08-13** |
| DOI | https://doi.org/10.6028/NIST.FIPS.203 |
| CSRC page | https://csrc.nist.gov/pubs/fips/203/final |
| Based on | CRYSTALS-Kyber |
| Parameter sets | ML-KEM-512 (Cat 1), ML-KEM-768 (Cat 3), ML-KEM-1024 (Cat 5) |
| Local PDF | /knowledge/sources/NIST.FIPS.203.pdf |

### 5.2 FIPS 204 — ML-DSA

| Field | Value |
|---|---|
| Full title | Module-Lattice-Based Digital Signature Standard |
| Status | **FINAL** |
| Finalized | **2024-08-13** |
| DOI | https://doi.org/10.6028/NIST.FIPS.204 |
| CSRC page | https://csrc.nist.gov/pubs/fips/204/final |
| Based on | CRYSTALS-Dilithium |
| Parameter sets | ML-DSA-44 (Cat 2), ML-DSA-65 (Cat 3), ML-DSA-87 (Cat 5) |
| Local PDF | /knowledge/sources/NIST.FIPS.204.pdf |

### 5.3 FIPS 205 — SLH-DSA

| Field | Value |
|---|---|
| Full title | Stateless Hash-Based Digital Signature Standard |
| Status | **FINAL** |
| Finalized | **2024-08-13** |
| DOI | https://doi.org/10.6028/NIST.FIPS.205 |
| CSRC page | https://csrc.nist.gov/pubs/fips/205/final |
| Based on | SPHINCS+ |
| Parameter sets | Multiple (SLH-DSA-SHAKE-128s/f, SLH-DSA-SHAKE-192s/f, SLH-DSA-SHAKE-256s/f, etc.) |
| Local PDF | /knowledge/sources/NIST.FIPS.205.pdf |
| NSA CNSA 2.0 | NOT included in CNSA 2.0 |

### 5.4 FIPS 206 — FN-DSA

| Field | Value |
|---|---|
| Full title | FFT over NTRU-Lattice-Based Digital Signature Algorithm Standard (FN-DSA) |
| Status | **IN DEVELOPMENT — NO IPD PUBLISHED AS OF 2026-06-12** |
| Based on | FALCON |
| Expected | IPD expected 2025–2026; final ~2026–2027 (UNCONFIRMED) |
| CSRC page | https://csrc.nist.gov/pubs/fips/206 (not yet live) |
| Note | NIST presented FIPS 206 progress at 6th PQC Standardization Conference, Sept 2025 |

**UNCONFIRMED:** The exact IPD publication date for FIPS 206. As of the 6th PQC Standardization Conference (September 24–26, 2025), the draft was still in NIST/DoC clearance. No public IPD URL confirmed from primary sources as of 2026-06-12.

---

## 6. CNSA 2.0 Timeline (NSA)

Source: NSA Cybersecurity Advisory "Announcing Commercial National Security Algorithm Suite 2.0 (CNSA 2.0)" — Updated May 30, 2025.  
URL: https://media.defense.gov/2025/May/30/2003728741/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS.PDF  
(Note: Direct PDF fetch returns HTTP 403; content sourced from NSA-published materials and CNSA 2.0 FAQ v2.1, Dec 2024.)

### 6.1 CNSA 2.0 Algorithm Suite

| Function | CNSA 2.0 Algorithm | Standard | Parameters |
|---|---|---|---|
| Key establishment | ML-KEM | FIPS 203 | ML-KEM-1024 |
| Digital signature | ML-DSA | FIPS 204 | ML-DSA-87 |
| Software/firmware signing | LMS, XMSS | SP 800-208 | LMS with SHA-256/192 preferred |
| Symmetric encryption | AES | FIPS 197 | AES-256 only |
| Hashing | SHA | FIPS 180-4 | SHA-384 (SHA-512 also accepted) |

**Not in CNSA 2.0:** SLH-DSA (FIPS 205), EdDSA, RSA, ECDSA, ECDH.  
**Not in CNSA 2.0:** HSS (multi-tree LMS) and XMSS^MT are explicitly excluded.

### 6.2 CNSA 2.0 Transition Timeline by System Class

Source: NSA CNSA 2.0 Advisory (May 2025) and CNSA 2.0 FAQ v2.1 (Dec 2024).

| System/Device Class | Support & Prefer CNSA 2.0 By | Exclusively Use CNSA 2.0 By |
|---|---|---|
| Software & firmware signing | **2025** | **2030** |
| Web browsers / cloud services / TLS | **2025** | **2033** |
| Traditional networking (VPNs, routers) | **2026** | **2030** |
| Operating systems | **2027** | **2033** |
| Large PKI / niche equipment | **2030** | **2033** |
| Custom applications / legacy equipment | — | **2033** (update or replace) |
| All NSS (complete transition goal) | — | **2035** |

**Key policy note:**
> "CNSA 2.0 algorithms will become mandatory to select at the given date, and selecting CNSA 1.0 algorithms alone will no longer be approved."

Starting **2027-01-01**, all new NSS acquisitions must support CNSA 2.0 unless an exception is noted in acquisition documentation.

### 6.3 NSA vs. NIST: Where Timelines Differ

| Dimension | NIST IR 8547 | NSA CNSA 2.0 |
|---|---|---|
| Applies to | All U.S. federal systems, industry | National Security Systems (NSS) only |
| Classical asymmetric deprecated | 2030 (112-bit variants) | N/A — binary: allowed until replaced |
| Classical asymmetric disallowed | 2035 (all variants) | 2033 (exclusive CNSA 2.0 required) |
| Networking exclusive PQC | 2035 | **2030** (more aggressive) |
| Software signing exclusive PQC | 2035 | **2030** (more aggressive) |
| Symmetric requirement | AES-128/192/256 all allowed | **AES-256 only** |
| Hash requirement | SHA-256/384/512 all allowed | **SHA-384 minimum** |
| SLH-DSA (FIPS 205) | Approved | **Not approved for NSS** |

**NSA is generally more aggressive and restrictive.** NSA requires AES-256 where NIST allows AES-128. NSA excludes SLH-DSA. NSA sets 2030 for networking/firmware exclusive PQC vs. NIST's 2035.

---

## 7. NIST SP 800-131A Revision 3

| Field | Value |
|---|---|
| Full title | Transitioning the Use of Cryptographic Algorithms and Key Lengths |
| Status | **STILL IPD — NOT FINALIZED as of 2026-06-12** |
| IPD published | **2024-10-21** |
| Comment period closed | 2024-12-04 |
| Final Rev 2 (still active) | 2019-03-21 |
| CSRC IPD page | https://csrc.nist.gov/pubs/sp/800/131/a/r3/ipd |
| PDF | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar3.ipd.pdf |
| Local PDF | /knowledge/sources/NIST.SP.800-131Ar3.ipd.pdf |

**Key changes in Rev 3 IPD:**

1. **DSA signature generation retired** (not deprecated — retired outright).
2. **ECB mode for confidentiality retired.**
3. **SHA-1 deprecated through 2030-12-31; disallowed after 2031-01-01.**
4. **224-bit hash functions (SHA-224, SHA-512/224) deprecated through 2030-12-31; disallowed after 2031-01-01.**
5. Discusses transition from **112-bit minimum security strength to 128-bit minimum**, with the threshold change planned for end of December 31, 2030.
6. Prior SP 800-57 guidance projected **disallow of 112-bit public-key schemes on 2031-01-01**. Rev 3 revises this: NIST now intends to *deprecate* (not disallow) 112-bit classical asymmetric by 2030, deferring full disallowance to 2035 (aligned with IR 8547).

**Quote from Rev 3 IPD:**
> "Based on the need to migrate to quantum-resistant algorithms during this timeframe, NIST intends to instead deprecate classical digital signatures at the 112-bit security level."

**Until Rev 3 is finalized, SP 800-131A Rev 2 (2019) remains the active governing document.** Rev 2 disallows 112-bit public-key by 2030 — this is the currently-operative deadline.

---

## 8. NIST PQC Security Strength Categories and CycloneDX Mapping

### 8.1 Official NIST PQC Security Categories (from NIST PQC Call for Proposals)

Source: NIST PQC Standardization process call for proposals; confirmed in FIPS 203/204/205 preambles.

NIST defines **five security categories** (not six). The CycloneDX 1.6 schema adds 0 for "not quantum-safe":

| Category | Reference Primitive | Attack Type | Classical Equivalent | CycloneDX nistQuantumSecurityLevel |
|---|---|---|---|---|
| — (quantum-vulnerable) | N/A | Shor's algorithm breaks it | N/A | **0** |
| 1 | AES-128 | Exhaustive key search | ~128-bit | **1** |
| 2 | SHA-256 / SHA3-256 | Collision search | ~128-bit | **2** |
| 3 | AES-192 | Exhaustive key search | ~192-bit | **3** |
| 4 | SHA-384 / SHA3-384 | Collision search | ~192-bit | **4** |
| 5 | AES-256 | Exhaustive key search | ~256-bit | **5** |
| — (reserved) | — | — | — | **6** |

**CycloneDX 1.6 JSON Schema constraint:**
```json
"nistQuantumSecurityLevel": {
  "type": "integer",
  "minimum": 0,
  "maximum": 6
}
```
Source: https://github.com/CycloneDX/specification/blob/1.6/schema/bom-1.6.schema.json

**Level 6 is reserved in the CycloneDX schema** (maximum = 6) but has no corresponding NIST-defined category. It is likely reserved for future use or implementation-defined extensions.

### 8.2 Algorithm-to-Level Mapping for seawall

| Algorithm | nistQuantumSecurityLevel | Rationale |
|---|---|---|
| RSA (any key size) | 0 | Broken by Shor's algorithm |
| ECDSA (any curve) | 0 | Broken by Shor's algorithm |
| EdDSA / Ed25519 / Ed448 | 0 | Broken by Shor's algorithm |
| ECDH (any curve) | 0 | Broken by Shor's algorithm |
| DH / FFDH (any group) | 0 | Broken by Shor's algorithm |
| DSA (any key size) | 0 | Broken by Shor's algorithm |
| AES-128 | 1 | AES-128 key search defines Cat 1 |
| AES-192 | 3 | AES-192 key search defines Cat 3 |
| AES-256 | 5 | AES-256 key search defines Cat 5 |
| SHA-256 | 2 | SHA-256 collision search defines Cat 2 |
| SHA-384 | 4 | SHA-384 collision search defines Cat 4 |
| SHA-512 | 5 | Stronger than Cat 5 reference; assign Cat 5 |
| ML-KEM-512 | 1 | FIPS 203 parameter set; Category 1 |
| ML-KEM-768 | 3 | FIPS 203 parameter set; Category 3 |
| ML-KEM-1024 | 5 | FIPS 203 parameter set; Category 5 |
| ML-DSA-44 | 2 | FIPS 204 parameter set; Category 2 |
| ML-DSA-65 | 3 | FIPS 204 parameter set; Category 3 |
| ML-DSA-87 | 5 | FIPS 204 parameter set; Category 5 |
| SLH-DSA-128* | 1 | Category 1 parameter sets |
| SLH-DSA-192* | 3 | Category 3 parameter sets |
| SLH-DSA-256* | 5 | Category 5 parameter sets |

---

## 9. DECISIONS — seawall Risk Engine

### Hard-code

| Decision | Value | Why |
|---|---|---|
| nistQuantumSecurityLevel for all classical asymmetric (RSA, ECDSA, EdDSA, ECDH, DH, DSA) | **0** | These are broken by Shor's algorithm; this is not configurable per NIST/CNSA policy |
| disallow_year for all classical asymmetric | **2035** | IR 8547 Table 2–4: universal disallow year regardless of key size |
| deprecate_year for 112-bit security classical asymmetric | **2030** | IR 8547 explicit; applies to RSA-2048, P-224, 2048-bit DH/DSA |
| SHA-1 status | **DISALLOWED (current)** | Disallowed pre-PQC; SP 800-131A Rev 2 active |
| SHA-224 / 224-bit hashes | **DEPRECATED 2030 / DISALLOWED 2031** | SP 800-131A Rev 3 IPD; likely to survive into final |
| FIPS 203/204/205 as PQC-approved replacements | Yes | Finalized 2024-08-13 |

### Make Configurable

| Decision | Default | Why |
|---|---|---|
| Policy mode: NIST vs. NSA CNSA 2.0 | NIST | NSA timeline applies only to NSS; civilian/commercial users follow NIST |
| AES-128 risk level | Warn (not error) | NIST allows; NSA disallows for NSS. Configurable by compliance target. |
| SHA-256 risk level | No risk | NIST and NSA both allow |
| SLH-DSA allowance | Allowed (FIPS 205) | Not in CNSA 2.0, but is a valid NIST standard; depends on policy target |
| FIPS 206 / FN-DSA allowance | UNCONFIRMED/WARN | No final standard as of 2026-06-12; cannot hard-code as approved yet |
| deprecate_year override | 2030 | Some organizations may have waivers or non-federal scope |
| disallow_year override | 2035 | Some high-security environments may adopt NSA 2030/2033 timeline instead |

### UNCONFIRMED Items (do not hard-code until confirmed)

| Item | Status |
|---|---|
| NIST IR 8547 final publication | NOT YET PUBLISHED — monitor csrc.nist.gov/pubs/ir/8547 |
| SP 800-131A Rev 3 final publication | NOT YET PUBLISHED — monitor csrc.nist.gov/pubs/sp/800/131/a/r3 |
| FIPS 206 (FN-DSA) IPD date | NOT CONFIRMED from primary source |
| FIPS 206 (FN-DSA) final date | Estimated 2026–2027; UNCONFIRMED |
| Whether IR 8547 final will change any deprecation/disallow years | UNKNOWN |
| CycloneDX nistQuantumSecurityLevel=6 meaning | Reserved in schema; no NIST definition |

---

## 10. Source Index

| Document | Local Path | Primary URL | Status |
|---|---|---|---|
| NIST IR 8547 IPD (Nov 2024) | /knowledge/sources/NIST.IR.8547.ipd.pdf | https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf | IPD |
| FIPS 203 — ML-KEM | /knowledge/sources/NIST.FIPS.203.pdf | https://doi.org/10.6028/NIST.FIPS.203 | FINAL |
| FIPS 204 — ML-DSA | /knowledge/sources/NIST.FIPS.204.pdf | https://doi.org/10.6028/NIST.FIPS.204 | FINAL |
| FIPS 205 — SLH-DSA | /knowledge/sources/NIST.FIPS.205.pdf | https://doi.org/10.6028/NIST.FIPS.205 | FINAL |
| SP 800-131A Rev 3 IPD (Oct 2024) | /knowledge/sources/NIST.SP.800-131Ar3.ipd.pdf | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar3.ipd.pdf | IPD |
| NSA CNSA 2.0 Advisory (May 2025) | Not downloadable (403) | https://media.defense.gov/2025/May/30/2003728741/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS.PDF | Final |
| NSA CNSA 2.0 FAQ v2.1 (Dec 2024) | Not downloadable (403) | https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/1/CSI_CNSA_2.0_FAQ_.PDF | Final |
| CycloneDX 1.6 JSON Schema | /knowledge/sources/bom-1.6.schema.json | https://github.com/CycloneDX/specification/blob/1.6/schema/bom-1.6.schema.json | Final |

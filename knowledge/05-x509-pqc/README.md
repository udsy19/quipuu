# X.509 Certificates and Post-Quantum Cryptography
## Knowledge Reference for quipuu/scan-certs

**Status:** Authoritative reference as of June 2026  
**Scope:** OID classification, PQC cert landscape, Rust crate APIs, risk classification

---

## Table of Contents

1. [OID Reference: Classical Algorithms](#1-oid-reference-classical-algorithms)
2. [OID Reference: Post-Quantum Algorithms](#2-oid-reference-post-quantum-algorithms)
3. [PQC Certificates in Production](#3-pqc-certificates-in-production)
4. [Hybrid Certificate Formats](#4-hybrid-certificate-formats)
5. [Rust Crate Coverage](#5-rust-crate-coverage)
6. [Weak and Broken Signature Algorithms](#6-weak-and-broken-signature-algorithms)
7. [Certificate Chain Analysis](#7-certificate-chain-analysis)
8. [Extracting Algorithm, Key Size, and Curve](#8-extracting-algorithm-key-size-and-curve)
9. [Comprehensive OID Table for quipuu Risk Engine](#9-comprehensive-oid-table-for-quipuu-risk-engine)
10. [DECISIONS for quipuu/scan-certs](#10-decisions-for-quipuuscan-certs)

---

## 1. OID Reference: Classical Algorithms

### Why This Matters
The `signatureAlgorithm` field (at the top of `Certificate` and mirrored inside `TbsCertificate.signature`) and `subjectPublicKeyInfo.algorithm.algorithm` are two distinct OID slots. The signature OID names the hash-plus-signature combination (e.g., `sha256WithRSAEncryption`); the SPKI OID names the key type (e.g., `rsaEncryption`). quipuu must classify both independently and cross-check them.

### 1.1 RSA

**Primary sources:** RFC 3279 §2.2–2.3 (April 2002), RFC 4055 §3 (June 2005), RFC 8017 (PKCS #1 v2.2, November 2016).

| OID Name | Dotted OID | RFC | Notes |
|---|---|---|---|
| rsaEncryption | 1.2.840.113549.1.1.1 | RFC 3279 §2.3.1 | SPKI key type; parameters MUST be NULL |
| md2WithRSAEncryption | 1.2.840.113549.1.1.2 | RFC 3279 §2.2.1 | **BROKEN** — MD2 collision attack 1995, preimage 2009 |
| md5WithRSAEncryption | 1.2.840.113549.1.1.4 | RFC 3279 §2.2.2 | **BROKEN** — MD5 collisions Lenstra 2005 / Sotirov 2008 |
| sha1WithRSAEncryption | 1.2.840.113549.1.1.5 | RFC 3279 §2.2.3 | **WEAK** — SHA-1 deprecated 2017 (see §6) |
| id-RSAES-OAEP | 1.2.840.113549.1.1.7 | RFC 4055 §3.1 | Key transport (CMS/PKCS#7); not used in X.509 certs |
| id-RSASSA-PSS | 1.2.840.113549.1.1.10 | RFC 4055 §3.3 | Probabilistic padding; stronger than PKCS#1 v1.5 |
| sha256WithRSAEncryption | 1.2.840.113549.1.1.11 | RFC 4055 §5 | Current baseline for RSA signatures |
| sha384WithRSAEncryption | 1.2.840.113549.1.1.12 | RFC 4055 §5 | Higher security margin |
| sha512WithRSAEncryption | 1.2.840.113549.1.1.13 | RFC 4055 §5 | |
| sha224WithRSAEncryption | 1.2.840.113549.1.1.14 | RFC 4055 §5 | Rarely seen in practice |

**RSASSA-PSS encoding note:** When `id-RSASSA-PSS` appears as the `signatureAlgorithm`, the `AlgorithmIdentifier.parameters` carry a `RSASSA-PSS-params` structure naming the hash and salt length. The default (parameters absent) historically implies SHA-1 with saltLen=20 — flag as weak.

### 1.2 ECDSA and EC Keys

**Primary sources:** RFC 5480 §2 (March 2009), RFC 3279 §2.3.5, RFC 5758 §3.2 (January 2010).

| OID Name | Dotted OID | RFC | Notes |
|---|---|---|---|
| id-ecPublicKey | 1.2.840.10045.2.1 | RFC 5480 §2.1 | SPKI key type for all EC keys (ECDSA + ECDH unrestricted) |
| id-ecDH | 1.3.132.1.12 | RFC 5480 §2.1 | ECDH-only key; rarely seen in X.509 |
| ecdsa-with-SHA1 | 1.2.840.10045.4.1 | RFC 3279 §2.2.3 | **WEAK** — SHA-1 deprecated |
| ecdsa-with-SHA256 | 1.2.840.10045.4.3.2 | RFC 5758 §3.2 | Current baseline for ECDSA signatures |
| ecdsa-with-SHA384 | 1.2.840.10045.4.3.3 | RFC 5758 §3.2 | |
| ecdsa-with-SHA512 | 1.2.840.10045.4.3.4 | RFC 5758 §3.2 | |

**EC Curve OIDs** (encoded in `subjectPublicKeyInfo.algorithm.parameters`):

| Curve | OID | RFC / Source | Security Level |
|---|---|---|---|
| secp192r1 (P-192) | 1.2.840.10045.3.1.1 | RFC 5480 §2.1.1.1 | 96-bit (below NIST minimum) |
| secp224r1 (P-224) | 1.3.132.0.33 | RFC 5480 §2.1.1.1 | 112-bit (legacy) |
| secp256r1 (P-256) | 1.2.840.10045.3.1.7 | RFC 5480 §2.1.1.1 | 128-bit — current baseline |
| secp384r1 (P-384) | 1.3.132.0.34 | RFC 5480 §2.1.1.1 | 192-bit |
| secp521r1 (P-521) | 1.3.132.0.35 | RFC 5480 §2.1.1.1 | 260-bit |
| secp256k1 | 1.3.132.0.10 | SEC 2 v2 §2.4.1 | 128-bit; Bitcoin/Ethereum curve; no RFC |
| brainpoolP256r1 | 1.3.36.3.3.2.8.1.1.7 | RFC 5639 §3.4 | 128-bit; BSI/German gov use |
| brainpoolP384r1 | 1.3.36.3.3.2.8.1.1.11 | RFC 5639 §3.6 | 192-bit |

### 1.3 EdDSA and ECDH (Curve25519 / Curve448)

**Primary source:** RFC 8410 (August 2018, updated by RFC 9295 August 2022).

| OID Name | Dotted OID | Use | Notes |
|---|---|---|---|
| id-X25519 | 1.3.101.110 | Key agreement | AlgorithmIdentifier parameters MUST be absent |
| id-X448 | 1.3.101.111 | Key agreement | AlgorithmIdentifier parameters MUST be absent |
| id-Ed25519 | 1.3.101.112 | Digital signature | AlgorithmIdentifier parameters MUST be absent |
| id-Ed448 | 1.3.101.113 | Digital signature | AlgorithmIdentifier parameters MUST be absent |

Private key format: `CurvePrivateKey ::= OCTET STRING` wrapped in `OneAsymmetricKey` (RFC 5958 / PKCS #8). X25519/X448 appear in SPKI but must not appear in `signatureAlgorithm`.

### 1.4 DSA

**Primary source:** RFC 3279 §2.2.2, RFC 5758 §3.1.

| OID Name | Dotted OID | RFC | Notes |
|---|---|---|---|
| id-dsa | 1.2.840.10040.4.1 | RFC 3279 §2.3.2 | SPKI key type |
| id-dsa-with-sha1 | 1.2.840.10040.4.3 | RFC 3279 §2.2.2 | **WEAK** |
| id-dsa-with-sha224 | 2.16.840.1.101.3.4.3.1 | RFC 5758 §3.1 | |
| id-dsa-with-sha256 | 2.16.840.1.101.3.4.3.2 | RFC 5758 §3.1 | Parameters field SHALL be absent |

### 1.5 Diffie-Hellman

**Primary source:** RFC 3279 §2.3.3 (from ANSI X9.42).

| OID Name | Dotted OID | Notes |
|---|---|---|
| dhpublicnumber | 1.2.840.10046.2.1 | DH public key; rarely in X.509 end-entity certs |

---

## 2. OID Reference: Post-Quantum Algorithms

### Why This Matters
FIPS 203/204/205 were finalized August 13, 2024. The corresponding RFCs for X.509 encoding were published in 2025–2026. As of mid-2026, any scanner encountering these OIDs in production is likely looking at a PQC pilot or hybrid deployment. FIPS 206 (FN-DSA/Falcon) is NOT yet finalized; no production OIDs exist.

### 2.1 ML-KEM (FIPS 203) — Key Encapsulation

**Primary sources:** NIST CSOR (https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration, last updated June 13, 2025); RFC 9935 ("Internet X.509 PKI — Algorithm Identifiers for ML-KEM", March 2026).

OID arc: `id-alg-ml-kem ::= { 2.16.840.1.101.3.4.4 }`

| OID Name | Dotted OID | NIST Security Level | Encap Key Size | Key Usage |
|---|---|---|---|---|
| id-alg-ml-kem-512 | 2.16.840.1.101.3.4.4.1 | 1 (≈AES-128) | 800 bytes | keyEncipherment only |
| id-alg-ml-kem-768 | 2.16.840.1.101.3.4.4.2 | 3 (≈AES-192) | 1184 bytes | keyEncipherment only |
| id-alg-ml-kem-1024 | 2.16.840.1.101.3.4.4.3 | 5 (≈AES-256) | 1568 bytes | keyEncipherment only |

RFC 9935 rules: `AlgorithmIdentifier` parameters MUST be absent; private key is a CHOICE of seed (64 bytes, RECOMMENDED), expandedKey, or both. ML-KEM keys MUST NOT be used for key agreement (`keyAgreement` bit), only `keyEncipherment`.

### 2.2 ML-DSA (FIPS 204) — Digital Signature

**Primary sources:** NIST CSOR (same URL); RFC 9881 ("Internet X.509 PKI — Algorithm Identifiers for ML-DSA", October 2025).

OID arc: `sigAlgs ::= { 2.16.840.1.101.3.4.3 }`

| OID Name | Dotted OID | NIST Level | Signature Size | Public Key Size |
|---|---|---|---|---|
| id-ml-dsa-44 | 2.16.840.1.101.3.4.3.17 | 2 (≈AES-128) | 2,420 bytes | 1,312 bytes |
| id-ml-dsa-65 | 2.16.840.1.101.3.4.3.18 | 3 (≈AES-192) | 3,309 bytes | 1,952 bytes |
| id-ml-dsa-87 | 2.16.840.1.101.3.4.3.19 | 5 (≈AES-256) | 4,627 bytes | 2,592 bytes |

RFC 9881 rules: Parameters MUST be absent. `HashML-DSA` variants (pre-hash) MUST NOT be used in X.509 certificates (only in CMS). Permitted key usages: `digitalSignature`, `nonRepudiation`, `keyCertSign`, `cRLSign`. Prohibited: `keyEncipherment`, `dataEncipherment`, `keyAgreement`. Private key: seed (32 bytes, RECOMMENDED) or expandedKey (2560/4032/4896 bytes respectively).

The `HashML-DSA` OIDs (if encountered in the wild — should not appear in X.509):

| Hypothetical name | Use |
|---|---|
| id-hash-ml-dsa-44 | Pre-hash; CMS/applications only, NOT X.509 |
| id-hash-ml-dsa-65 | Pre-hash; CMS/applications only, NOT X.509 |
| id-hash-ml-dsa-87 | Pre-hash; CMS/applications only, NOT X.509 |

### 2.3 SLH-DSA (FIPS 205) — Stateless Hash-Based Signature

**Primary sources:** NIST CSOR; RFC 9909 ("Internet X.509 PKI — Algorithm Identifiers for SLH-DSA", December 2025).

OID arc: `sigAlgs ::= { 2.16.840.1.101.3.4.3 }` (same arc as ML-DSA, different leaf values)

#### Pure SLH-DSA variants (for use in X.509):

| OID Name | Dotted OID | Security | Sig Size | Public Key |
|---|---|---|---|---|
| id-slh-dsa-sha2-128s | 2.16.840.1.101.3.4.3.20 | L1 SHA-2 small | 7,856 B | 32 B |
| id-slh-dsa-sha2-128f | 2.16.840.1.101.3.4.3.21 | L1 SHA-2 fast | 17,088 B | 32 B |
| id-slh-dsa-sha2-192s | 2.16.840.1.101.3.4.3.22 | L3 SHA-2 small | 16,224 B | 48 B |
| id-slh-dsa-sha2-192f | 2.16.840.1.101.3.4.3.23 | L3 SHA-2 fast | 35,664 B | 48 B |
| id-slh-dsa-sha2-256s | 2.16.840.1.101.3.4.3.24 | L5 SHA-2 small | 29,792 B | 64 B |
| id-slh-dsa-sha2-256f | 2.16.840.1.101.3.4.3.25 | L5 SHA-2 fast | 49,856 B | 64 B |
| id-slh-dsa-shake-128s | 2.16.840.1.101.3.4.3.26 | L1 SHAKE small | 7,856 B | 32 B |
| id-slh-dsa-shake-128f | 2.16.840.1.101.3.4.3.27 | L1 SHAKE fast | 17,088 B | 32 B |
| id-slh-dsa-shake-192s | 2.16.840.1.101.3.4.3.28 | L3 SHAKE small | 16,224 B | 48 B |
| id-slh-dsa-shake-192f | 2.16.840.1.101.3.4.3.29 | L3 SHAKE fast | 35,664 B | 48 B |
| id-slh-dsa-shake-256s | 2.16.840.1.101.3.4.3.30 | L5 SHAKE small | 29,792 B | 64 B |
| id-slh-dsa-shake-256f | 2.16.840.1.101.3.4.3.31 | L5 SHAKE fast | 49,856 B | 64 B |

#### HashSLH-DSA pre-hash variants (for CMS / non-X.509 use):

| OID Name | Dotted OID | Hash used |
|---|---|---|
| id-hash-slh-dsa-sha2-128s-with-sha256 | 2.16.840.1.101.3.4.3.35 | SHA-256 |
| id-hash-slh-dsa-sha2-128f-with-sha256 | 2.16.840.1.101.3.4.3.36 | SHA-256 |
| id-hash-slh-dsa-sha2-192s-with-sha512 | 2.16.840.1.101.3.4.3.37 | SHA-512 |
| id-hash-slh-dsa-sha2-192f-with-sha512 | 2.16.840.1.101.3.4.3.38 | SHA-512 |
| id-hash-slh-dsa-sha2-256s-with-sha512 | 2.16.840.1.101.3.4.3.39 | SHA-512 |
| id-hash-slh-dsa-sha2-256f-with-sha512 | 2.16.840.1.101.3.4.3.40 | SHA-512 |
| id-hash-slh-dsa-shake-128s-with-shake128 | 2.16.840.1.101.3.4.3.41 | SHAKE128 |
| id-hash-slh-dsa-shake-128f-with-shake128 | 2.16.840.1.101.3.4.3.42 | SHAKE128 |
| id-hash-slh-dsa-shake-192s-with-shake256 | 2.16.840.1.101.3.4.3.43 | SHAKE256 |
| id-hash-slh-dsa-shake-192f-with-shake256 | 2.16.840.1.101.3.4.3.44 | SHAKE256 |
| id-hash-slh-dsa-shake-256s-with-shake256 | 2.16.840.1.101.3.4.3.45 | SHAKE256 |
| id-hash-slh-dsa-shake-256f-with-shake256 | 2.16.840.1.101.3.4.3.46 | SHAKE256 |

### 2.4 FN-DSA / Falcon (FIPS 206 — NOT YET FINALIZED)

**Why:** FIPS 203/204/205 were finalized August 13, 2024. FIPS 206 (FN-DSA, the FFT over NTRU-Lattice-Based Digital Signature Algorithm) was submitted to the Department of Commerce ~August 28, 2025 for approval. Final publication is expected late 2026 or early 2027.

**IETF drafts exist** (`draft-ietf-lamps-fn-dsa-certificates-00`, `draft-ietf-lamps-cms-fn-dsa-00`, both May 20, 2026) but use `XX` OID placeholders under `2.16.840.1.101.3.4.3`. No production OIDs are assigned.

**Decision for quipuu:** Do NOT hardcode Falcon/FN-DSA OIDs. Add a comment in the OID table noting that values in `2.16.840.1.101.3.4.3.{32..34}` (the gap after SLH-DSA) are likely candidates. Watch NIST CSOR for finalization.

Public key sizes for reference (so the scanner can emit "unknown PQC key" with helpful context): 897 bytes (FN-DSA-512/Falcon-512), 1793 bytes (FN-DSA-1024/Falcon-1024).

### 2.5 Composite Signature OIDs (IETF LAMPS)

**Primary source:** `draft-ietf-lamps-pq-composite-sigs-19` (RFC Editor Queue, In Progress: First Edit, last updated 2026-08-26).  
Authors: Mike Ounsworth, John Gray (Entrust), Massimiliano Pala, Jan Klaußner, Scott Fluhrer.

OID arc: `id-composite-sig-algs ::= { 1.3.6.1.5.5.7.6 }`, leaves 37–54.

| Dotted OID | Algorithm Combination |
|---|---|
| 1.3.6.1.5.5.7.6.37 | id-MLDSA44-RSA2048-PSS-SHA256 |
| 1.3.6.1.5.5.7.6.38 | id-MLDSA44-RSA2048-PKCS15-SHA256 |
| 1.3.6.1.5.5.7.6.39 | id-MLDSA44-Ed25519-SHA512 |
| 1.3.6.1.5.5.7.6.40 | id-MLDSA44-ECDSA-P256-SHA256 |
| 1.3.6.1.5.5.7.6.41 | id-MLDSA65-RSA3072-PSS-SHA512 |
| 1.3.6.1.5.5.7.6.42 | id-MLDSA65-RSA3072-PKCS15-SHA512 |
| 1.3.6.1.5.5.7.6.43 | id-MLDSA65-RSA4096-PSS-SHA512 |
| 1.3.6.1.5.5.7.6.44 | id-MLDSA65-RSA4096-PKCS15-SHA512 |
| 1.3.6.1.5.5.7.6.45 | id-MLDSA65-ECDSA-P256-SHA512 |
| 1.3.6.1.5.5.7.6.46 | id-MLDSA65-ECDSA-P384-SHA512 |
| 1.3.6.1.5.5.7.6.47 | id-MLDSA65-ECDSA-brainpoolP256r1-SHA512 |
| 1.3.6.1.5.5.7.6.48 | id-MLDSA65-Ed25519-SHA512 |
| 1.3.6.1.5.5.7.6.49 | id-MLDSA87-ECDSA-P384-SHA512 |
| 1.3.6.1.5.5.7.6.50 | id-MLDSA87-ECDSA-brainpoolP384r1-SHA512 |
| 1.3.6.1.5.5.7.6.51 | id-MLDSA87-Ed448-SHAKE256 |
| 1.3.6.1.5.5.7.6.52 | id-MLDSA87-RSA3072-PSS-SHA512 |
| 1.3.6.1.5.5.7.6.53 | id-MLDSA87-RSA4096-PSS-SHA512 |
| 1.3.6.1.5.5.7.6.54 | id-MLDSA87-ECDSA-P521-SHA512 |

Composite public key encoding: concatenation `mldsaPK || tradPK`. Signature prefix: `"CompositeAlgorithmSignatures2025"` (fixed ASCII domain separator). Security property: EUF-CMA. Constraint: component keys MUST NOT be reused across composite and non-composite contexts.

### 2.6 Composite KEM OIDs (IETF LAMPS)

**Primary source:** `draft-ietf-lamps-pq-composite-kem-21` (returned to authors — IESG state 'Revised I-D Needed' — after the 2026-09-03 telechat; a revised draft, not an RFC number, is the next expected artifact).

OID arc: leaves 55–66 of same `1.3.6.1.5.5.7.6` arc.

| Dotted OID | Algorithm Combination |
|---|---|
| 1.3.6.1.5.5.7.6.55 | id-MLKEM768-RSA2048-SHA3-256 |
| 1.3.6.1.5.5.7.6.56 | id-MLKEM768-RSA3072-SHA3-256 |
| 1.3.6.1.5.5.7.6.57 | id-MLKEM768-RSA4096-SHA3-256 |
| 1.3.6.1.5.5.7.6.58 | id-MLKEM768-X25519-SHA3-256 |
| 1.3.6.1.5.5.7.6.59 | id-MLKEM768-ECDH-P256-SHA3-256 |
| 1.3.6.1.5.5.7.6.60 | id-MLKEM768-ECDH-P384-SHA3-256 |
| 1.3.6.1.5.5.7.6.61 | id-MLKEM768-ECDH-brainpoolP256r1-SHA3-256 |
| 1.3.6.1.5.5.7.6.62 | id-MLKEM1024-RSA3072-SHA3-256 |
| 1.3.6.1.5.5.7.6.63 | id-MLKEM1024-ECDH-P384-SHA3-256 |
| 1.3.6.1.5.5.7.6.64 | id-MLKEM1024-ECDH-brainpoolP384r1-SHA3-256 |
| 1.3.6.1.5.5.7.6.65 | id-MLKEM1024-X448-SHA3-256 |
| 1.3.6.1.5.5.7.6.66 | id-MLKEM1024-ECDH-P521-SHA3-256 |

Combined shared secret: `SHA3-256(mlkemSS || tradSS || tradCT || tradPK || Label)`.

---

## 3. PQC Certificates in Production

### 3.1 State as of Mid-2026

**Why:** quipuu's live-host scanning mode (`--host`) will encounter these in the wild. Understanding what is deployed tells us which OIDs need to be recognized first.

### 3.2 Let's Encrypt

Let's Encrypt issues approximately 54.4% of all public TLS certificates (Q1 2026). Their current PQC path is **Merkle Tree Certificates (MTCs)**, co-proposed with Google and Cloudflare. Chrome has designated MTCs as the preferred PQC web authentication approach. Target: late 2026 staging, 2027 production.

Let's Encrypt has NOT issued ML-DSA or composite X.509 certificates to the public as of mid-2026. Their existing certificate chain uses ECDSA (P-256) throughout.

### 3.3 Cloudflare

Cloudflare has been the most aggressive adopter of PQC in TLS:
- **Since October 2022:** All websites and APIs proxied by Cloudflare support hybrid PQ key exchange in TLS 1.3 (`X25519MLKEM768`).
- **September 2023:** Most internal Cloudflare connections upgraded to PQC key agreement.
- **Mid-2025:** ~43% of human-generated HTTPS connections to Cloudflare use `X25519MLKEM768`.

Note: This is all TLS key exchange (KEM), not certificate signature algorithms. Cloudflare's TLS certificates themselves still use ECDSA for the certificate signature. No production ML-DSA certificate issuance as of mid-2026.

### 3.4 DigiCert

DigiCert offers PQC pilot certificates under the DigiCert Labs umbrella:
- Supports ML-KEM (encryption), ML-DSA (signatures), SLH-DSA (long-lived certificates).
- Hybrid toolkit was built on CRYSTALS-Dilithium before FIPS 204 finalization (now ML-DSA).
- Free quantum-safe certificates available via DigiCert Labs for interop testing.

### 3.5 CA/Browser Forum Position

**S/MIME (Ballot SMC-013, effective August 22, 2025):** ML-DSA (FIPS 204) and ML-KEM (FIPS 203) are now permitted for S/MIME certificates. This is the first CA/B Forum ballot explicitly enabling PQC.

**TLS:** No PQC ballot as of mid-2026. Active discussion in Server Certificate WG (PRs #622, #624). Key blocker: Certificate Transparency log scalability — ML-DSA signatures are 2,420–4,627 bytes vs. ECDSA's 64–132 bytes. CT log operators have not yet committed to handling PQC cert sizes.

**SHA-1 Sunset (Ballot SC097, February 25, 2026):** All unexpired sub-CA certificates signed with SHA-1 must be revoked. SHA-1 in CRLs also sunsetted. Exception: SHA-1 still permitted in OCSP `issuerKeyHash`/`issuerNameHash` per RFC 5019 (OCSP pre-dates SHA-2 requirement).

### 3.6 IETF / Interop Infrastructure

**Best public PQC TLS test server:** `https://test.openquantumsafe.org/`  
Operated by the Open Quantum Safe project; supports all PQC algorithms from liboqs including ML-KEM, ML-DSA, SLH-DSA, Falcon hybrid combinations. This is the primary interop testing target for quipuu's live-host mode.

**testpqc.io:** No confirmed public presence as of mid-2026.

### 3.7 Microsoft

Windows Server 2025 (KB5087539, May 2026): Active Directory Certificate Services (ADCS) can issue ML-DSA-44/65/87 certificates natively. This means enterprise environments running WS2025 PKI may issue PQC internal certificates to domains starting mid-2026.

Azure Front Door hybrid TLS key exchange groups: `X25519_MLKEM768` (IANA group `0x11ec`), `SecP256r1_MLKEM768`, `SecP384r1_MLKEM1024`.

---

## 4. Hybrid Certificate Formats

### 4.1 Composite Public Key (IETF LAMPS WG — Primary Approach)

**Sources:** `draft-ietf-lamps-pq-composite-sigs-19` (RFC Editor Queue, In Progress: First Edit, last updated 2026-08-26); `draft-ietf-lamps-pq-composite-kem-21` (returned to authors, 'Revised I-D Needed,' after the 2026-09-03 IESG telechat).

**Mechanism:** A single X.509 certificate carries a composite OID in both `subjectPublicKeyInfo.algorithm.algorithm` and `signatureAlgorithm`. The composite public key is the concatenation of the component keys (`mldsaPK || tradPK`); the composite signature is a DER-encoded sequence of the two component signatures with a fixed domain-separation prefix `"CompositeAlgorithmSignatures2025"`.

**Backward compatibility:** A verifier that does not recognize the composite OID will reject the certificate entirely. There is no fallback to a classical-only path. This is a deliberate design choice — the composite approach requires explicit support.

**quipuu implication:** When a composite OID (1.3.6.1.5.5.7.6.37–66) is seen in `signatureAlgorithm`, report it as "HYBRID-COMPOSITE: PQC + Classical". Both component algorithms should be decoded and their classical component risk-classified independently.

### 4.2 Chameleon Certificates

**Source:** `draft-bonnell-lamps-chameleon-certs-07` (last updated October 18, 2025, expired individual submission — not an IETF WG document).  
Authors: Corey Bonnell, John Gray (Entrust), D. Hook (Keyfactor), Tomofumi Okubo (DigiCert), Mike Ounsworth.

**Mechanism:** A "base certificate" carries a `DeltaCertificateDescriptor` extension (non-critical, SHOULD NOT be critical) containing only the fields that differ from the base. The "delta certificate" can be reconstructed by replacing those fields. The `subjectPublicKeyInfo` MUST differ between base and delta — typically classical key in base, PQC key in delta (or vice versa).

**OIDs (temporary, Entrust arc — permanent IANA OIDs not yet assigned):**
- `id-ce-deltaCertificateDescriptor` = `2.16.840.1.114027.80.6.1`
- `id-at-deltaCertificateRequest` = `2.16.840.1.114027.80.6.2`
- `id-at-deltaCertificateRequestSignature` = `2.16.840.1.114027.80.6.3`

**Status:** Individual submission (not a WG document). Expired October 2025. Unlikely to advance to RFC in current form.

**quipuu implication:** If the scanner sees OID `2.16.840.1.114027.80.6.1` in extensions, report "CHAMELEON-CERT: delta certificate descriptor present; base key is classical, delta key likely PQC (or vice versa)".

Known implementations: `chamcert` (Rust, github.com/carl-wallace/chamcert), `snakefoot` (Python, github.com/CBonnell/snakefoot), Bouncy Castle Java/Kotlin.

### 4.3 Catalyst / Extension-Based Hybrid

**Sources:** Referenced in ITU-T X.509 (2019 Amendment), X9.146, and ISO 15118-20.

**Mechanism:** The primary (classical) key and signature are in the standard certificate fields. An additional PQC public key and signature are carried in non-critical extensions. Verifiers that do not understand the extensions validate only the classical path — backward compatible by design.

**Security concern:** Because the classical path is still independently valid, a quantum-capable attacker can simply forge the classical portion and ignore the PQC extension. This is a downgrade risk if the relying party does not enforce the PQC extension check.

**quipuu implication:** Look for non-standard extensions with PQC OIDs in the extension value. No standardized OID arc as of mid-2026.

---

## 5. Rust Crate Coverage

### 5.1 `x509-parser` (v0.18.1)

**Source:** https://docs.rs/x509-parser/latest/x509_parser/  
**License:** MIT OR Apache-2.0  
**MSRV:** Rust 1.67.1  
**Recommendation for quipuu:** PRIMARY parsing crate.

**What it does:** Pure Rust X.509 v3 (RFC 5280) parser using `nom`; zero-copy lifetime-tied design. Parses PEM and DER, file and stream. Supports extensions via `ParsedExtension` enum.

**PQC OID support:** None natively. The `oid-registry` companion crate (v0.8.1) covers only classical algorithms. PQC OIDs must be added to a custom `OidRegistry` at runtime:
```rust
let mut registry = OidRegistry::default();
registry.insert(
    Oid::from_str("2.16.840.1.101.3.4.3.17").unwrap(),
    OidEntry::new("id-ml-dsa-44", "FIPS 204, RFC 9881"),
);
```

**Feature flags relevant to quipuu:**
- `verify` — uses `ring` for signature verification (no PQC support in ring)
- `validate` — structural validation without cryptographic verification (use this)
- Default: parsing only, no verification

**Key dependencies:** `asn1-rs ^0.7.0`, `der-parser ^10.0`, `nom ^7.0`, `oid-registry ^0.8.1`

### 5.2 `der` + `spki` (RustCrypto formats family, v0.8.0)

**Sources:** https://docs.rs/der/latest/der/, https://docs.rs/spki/latest/spki/  
**MSRV:** Rust 1.85+  
**License:** Apache-2.0 OR MIT  
**Recommendation for quipuu:** Use as SUPPORTING crates for re-encoding and type-level OID handling, not as the primary parser.

`der` provides a pure-Rust, `#[no_std]`-compatible DER/ASN.1 codec with derive macros (`AsnType`, `Decode`, `Encode`). No heap allocation required. `ObjectIdentifier` type from this crate is the canonical representation used throughout the RustCrypto ecosystem.

`spki` implements RFC 5280 §4.1.2.7 `SubjectPublicKeyInfo` on top of `der`. Relevant structs:
```rust
pub struct AlgorithmIdentifier<Params> { algorithm: ObjectIdentifier, parameters: Option<Params> }
pub struct SubjectPublicKeyInfoRef<'a> { algorithm: AlgorithmIdentifier<AnyRef<'a>>, subject_public_key: BitStringRef<'a> }
```
Neither `der` nor `spki` include PQC OID constants. The RustCrypto `ml-kem`, `ml-dsa`, and `slh-dsa` crates (still maturing as of mid-2026) wire in their own OID constants using `der::ObjectIdentifier::new_unwrap("...")`.

### 5.3 `rustls-pki-types` (v1.14.1)

**Source:** https://docs.rs/rustls-pki-types/latest/rustls_pki_types/  
**License:** MIT OR Apache-2.0

Provides newtype wrappers for certificate bytes (`CertificateDer`, `SubjectPublicKeyInfoDer`) and the `SignatureVerificationAlgorithm` trait. This crate defines the pluggable algorithm interface that `rustls` uses. The `alg_id` module exposes `AlgorithmIdentifier` constants for supported classical algorithms.

**PQC support:** None in v1.14.1. However, the `SignatureVerificationAlgorithm` trait is the intended extension point; a PQC implementation could implement this trait.

**quipuu use:** Not directly useful for scanning — it is a runtime verification crate, not a parsing crate.

### 5.4 `webpki` (via `webpki` or `rustls-webpki`)

**Source:** https://docs.rs/webpki/latest/webpki/

Pure-Rust X.509 chain validator. Supported algorithms: `ECDSA_P256_SHA256`, `ECDSA_P384_SHA384`, `ED25519`, `RSA_PKCS1_2048_8192_SHA256/384/512`, `RSA_PSS_2048_8192_SHA256/384/512_LEGACY_KEY`. **No PQC.**

**Chain validation:** `EndEntityCert::verify_is_valid_tls_server_cert(supported_sig_algs, trust_anchors, intermediate_certs, time)` returns `Ok(())` or a detailed `Error` enum. The error variants include `UnsupportedSignatureAlgorithm` (returned for any unknown OID), `UnknownIssuer`, `CertExpired`, `InvalidSignatureForPublicKey`, `PathLenConstraintViolated`, and `NameConstraintViolation` among others.

**quipuu use:** Useful for classical chain validation to confirm a chain is structurally valid. Will return `UnsupportedSignatureAlgorithm` for any PQC cert — which is itself informative signal for the scanner.

### 5.5 `picky` (v6.3.0)

**Source:** https://docs.rs/picky/latest/picky/

Full RFC 5280 Rust implementation with modules: `x509` (Cert, Csr, extensions), `key`, `pem`, `oids`, `signature`, `hash`, `jose`. Provides `Cert::from_der()`, `Cert::from_pem()`, `cert.public_key()`, `cert.signature_algorithm()`, `cert.is_parent_of()`, and a chain `verifier()`.

**PQC support:** None. `SignatureAlgorithm` enum covers only `RsaPkcs1v15(HashAlgorithm)` variants with SHA-1/SHA-2/SHA-3. Marked `#[non_exhaustive]` for future extension.

**quipuu use:** Lower priority. x509-parser is more actively maintained and more widely used.

### 5.6 `rasn` + `rasn-pkix`

**Source:** https://docs.rs/rasn/latest/rasn/

Safe `#[no_std]` ASN.1 codec framework (BER, CER, DER, APER, UPER, JER, OER, COER, XER) with derive macros. The companion `rasn-pkix` crate implements RFC 5280 types: `Certificate`, `TbsCertificate`, `SubjectPublicKeyInfo`, `AlgorithmIdentifier`. `rasn_pkix::algorithms` provides RFC 3279 OID constants.

**OID handling:** Excellent. `ObjectIdentifier` implements `Eq`, `Hash`, `Display`, `Ord`. The `oid!()` macro creates static OID refs. `AlgorithmIdentifier.algorithm` is an arbitrary `ObjectIdentifier`; unknown PQC OIDs parse as raw bytes in the `parameters: Option<Any>` field — no crash on unknown algorithm.

**PQC support:** None in `rasn-pkix::algorithms`. However, because `AlgorithmIdentifier` is generic over any `ObjectIdentifier`, adding PQC OID constants is straightforward.

**quipuu use:** An alternative to x509-parser if `#[no_std]` support is needed (e.g., WASM target). Not the primary recommendation.

### 5.7 `oid-registry` (v0.8.1)

**Source:** https://docs.rs/oid-registry/latest/oid_registry/

Registry for naming OIDs. No PQC OIDs are included. Classical OID constants available: `OID_PKCS1_RSAENCRYPTION`, `OID_SIG_ECDSA_WITH_SHA256`, `OID_SIG_ED25519`, `OID_EC_P256`, `OID_NIST_EC_P384`, etc.

Custom PQC OIDs can be inserted at runtime with `registry.insert(oid, OidEntry::new("ML-DSA-65", "FIPS 204"))`. This is the correct approach for quipuu — build the PQC OID table in Rust code and register at startup.

---

## 6. Weak and Broken Signature Algorithms

### 6.1 Immediately Broken (Hash Level)

These must be flagged `BROKEN` regardless of key type or size.

| Algorithm | Weakness | Broken Since |
|---|---|---|
| md2WithRSAEncryption | MD2 collision attack 1995; preimage 2009. No longer computationally secure at any RSA key size. | 2009 |
| md5WithRSAEncryption | MD5 chosen-prefix collisions (Lenstra et al. 2005, Sotirov/Stevens 2008). Used to create a rogue CA cert in December 2008. | 2008 |
| ecdsa-with-SHA1 | SHA-1 SHAttered collision (CWI/Google, February 2017). Practical collision cost ~$110k. | 2017 |
| sha1WithRSAEncryption | Same SHA-1 weakness. | 2017 |
| id-dsa-with-sha1 | Same SHA-1 weakness. | 2017 |

**Evidence — SHA-1 deprecation milestones:**
- **Chrome 39** (November 2014): Displayed yellow "caution" icon for SHA-1 certs expiring on or after January 1, 2017.
- **Chrome 56** (January 2017): Removed support for SHA-1 certificates in TLS connections.
- **Firefox 52** (February 2017): Disabled SHA-1 entirely. Extended validation orgs affected; self-signed roots still allowed.
- **Apple Safari/WebKit** (Spring 2017): Same enforcement.
- **CA/Browser Forum Ballot 118** (October 2014): CAs prohibited from issuing new SHA-1 subscriber or sub-CA certificates after January 1, 2016.
- **CA/Browser Forum Ballot SC097** (effective February 25, 2026): All unexpired sub-CA certificates signed with SHA-1 must be revoked. SHA-1 usage in CRLs also sunsetted. SHA-1 is now entirely gone from the Web PKI hierarchy.

**Exception (for scanner logic):** The CA/B Forum still permits SHA-1 in OCSP responses' `issuerKeyHash` and `issuerNameHash` fields per RFC 5019. Do NOT flag OCSP-internal usage — flag certificate `signatureAlgorithm` only.

### 6.2 Quantum-Vulnerable (But Classically Valid)

These are not broken today but will be broken by a cryptographically-relevant quantum computer (CRQC). NSA CNSA 2.0 targets deprecation by 2030–2035; NIST plans to deprecate RSA-2048 and P-256 after 2030.

| Category | Algorithm | Flag Level |
|---|---|---|
| RSA | Any RSA key < 2048 bits | CRITICAL (classically weak too) |
| RSA | RSA-2048 with SHA-256 | QUANTUM-VULNERABLE |
| RSA | RSA-3072/4096 with SHA-256/384/512 | QUANTUM-VULNERABLE (higher classical margin) |
| ECDSA | P-256/secp256k1 | QUANTUM-VULNERABLE |
| ECDSA | P-384/P-521 | QUANTUM-VULNERABLE (higher margin) |
| EdDSA | Ed25519, Ed448 | QUANTUM-VULNERABLE |
| DH | dhpublicnumber | QUANTUM-VULNERABLE |
| DSA | id-dsa (any SHA-2) | QUANTUM-VULNERABLE |

---

## 7. Certificate Chain Analysis

### 7.1 Walking the Chain

A full X.509 chain consists of: end-entity certificate, zero or more intermediate CA certificates, and a trust anchor (root CA). Each level has its own `signatureAlgorithm` and `subjectPublicKeyInfo`. For a complete risk picture, quipuu must report all three independently.

**Why walking matters:**
- A quantum-resistant leaf cert signed by a classical intermediate = quantum-vulnerable chain
- A SHA-1 intermediate in 2026 = CA/B Forum violation (SC097)
- Algorithm mismatches between levels signal misconfiguration

### 7.2 Chain Validation Crate Recommendation

For detailed structural analysis (not just yes/no), use **`x509-parser` + manual chain walking** combined with **`webpki` for classical trust validation**.

Pattern:
```rust
// 1. Parse all certs in chain with x509-parser — gives full field access
let certs: Vec<X509Certificate> = pem_chain
    .iter()
    .map(|pem| parse_x509_pem(pem).unwrap().1)
    .collect();

// 2. Walk and classify each level
for (i, cert) in certs.iter().enumerate() {
    let sig_oid = &cert.tbs_certificate.signature.algorithm;
    let spki_oid = &cert.tbs_certificate.subject_pki.algorithm.algorithm;
    // ... classify using OID table
}

// 3. Verify classical chain trust with webpki
let result = EndEntityCert::from(&end_entity_cert_der)
    .verify_is_valid_tls_server_cert(
        &[ECDSA_P256_SHA256, RSA_PKCS1_2048_8192_SHA256],
        &trust_anchors,
        &intermediate_cert_ders,
        SystemTime::now().into(),
    );
// webpki returns Err(UnsupportedSignatureAlgorithm) for PQC certs — log this explicitly
```

**webpki errors to surface to the user:**
- `UnsupportedSignatureAlgorithm` — likely PQC cert, chain validation skipped
- `UnknownIssuer` — incomplete chain presented, cannot validate
- `CertExpired` / `CertNotValidYet` — time-validity issue at a specific chain level

---

## 8. Extracting Algorithm, Key Size, and Curve

### 8.1 Relationship Between the Two Algorithm Fields

An X.509 certificate contains two `AlgorithmIdentifier` structures that serve different purposes:

| Field path | ASN.1 name | What it identifies |
|---|---|---|
| `Certificate.signatureAlgorithm` | `signatureAlgorithm` (outer) | The algorithm the issuer used to SIGN this certificate. Same value as `TbsCertificate.signature`. |
| `TbsCertificate.subject_pki.algorithm` | `subjectPublicKeyInfo.algorithm` | The algorithm for which the SUBJECT's public key is valid (key type + parameters). |

These MUST agree on key type but differ in granularity. For example:
- `signatureAlgorithm` = `sha256WithRSAEncryption` (1.2.840.113549.1.1.11) — names hash+signature
- `subjectPublicKeyInfo.algorithm.algorithm` = `rsaEncryption` (1.2.840.113549.1.1.1) — names only key type

For ECDSA the split is:
- `signatureAlgorithm` = `ecdsa-with-SHA256` (1.2.840.10045.4.3.2)
- `subjectPublicKeyInfo.algorithm.algorithm` = `id-ecPublicKey` (1.2.840.10045.2.1)
- `subjectPublicKeyInfo.algorithm.parameters` = named-curve OID (e.g., `1.2.840.10045.3.1.7` for P-256)

For ML-DSA the situation collapses — the same OID (`id-ml-dsa-65` = `2.16.840.1.101.3.4.3.18`) appears in both `signatureAlgorithm` and `subjectPublicKeyInfo.algorithm.algorithm`. No separate hash OID is needed because the hash is baked into the ML-DSA parameter set.

### 8.2 x509-parser Struct Paths

```rust
use x509_parser::prelude::*;

let (_, cert) = X509Certificate::from_der(der_bytes)?;
let tbs = &cert.tbs_certificate;

// --- Signature algorithm (how issuer signed this cert) ---
let sig_algo_oid: &Oid = tbs.signature.oid();
// OR from the outer Certificate struct (should match):
let sig_algo_oid2: &Oid = cert.signature_algorithm.oid();

// --- Subject public key info (what key type the subject holds) ---
let spki: &SubjectPublicKeyInfo = tbs.public_key();
let spki_algo_oid: &Oid = spki.algorithm.oid();

// --- Extracting key size and curve ---
match spki.parsed()? {
    PublicKey::RSA(rsa) => {
        let key_bits = rsa.key_size();  // strips leading sign byte correctly
        // rsa.modulus: &[u8]; rsa.exponent: &[u8]
        // rsa.try_exponent() -> Result<u64, X509Error>
    }
    PublicKey::EC(_ec_point) => {
        // Curve OID is NOT inside the ECPoint bytes — it is in algorithm.parameters
        let curve_oid: Option<Oid> = spki.algorithm.parameters
            .as_ref()
            .and_then(|p| p.as_oid().ok())
            .map(|o| o.to_owned());
        // key_size() on PublicKey::EC gives field size in bits from point bytes,
        // but use curve_oid for identity (e.g., secp384r1 vs secp256r1)
    }
    PublicKey::DSA(_bytes) => { /* raw DER of DSAPublicKey integer */ }
    PublicKey::Unknown(_bytes) => {
        // PQC keys land here — raw bytes of subjectPublicKey BIT STRING
        // Use spki_algo_oid to classify
    }
    _ => {}
}
```

**Critical gotcha:** Do NOT compute RSA key size as `modulus_bytes.len() * 8`. The modulus encoding includes a leading `0x00` sign byte for positive integers. Use `rsa.key_size()` which strips this correctly.

**PQC key extraction:** All PQC public keys (`PublicKey::Unknown(&[u8])`) are raw DER in the `subjectPublicKey` BIT STRING content. For ML-DSA-65, the bytes will be exactly 1,952 bytes. For ML-KEM-768, exactly 1,184 bytes. The length itself is a secondary classification signal when the OID is not recognized.

### 8.3 OID String Conversion

```rust
// From Oid to dotted string
let oid_str = sig_algo_oid.to_string();  // e.g., "1.2.840.113549.1.1.11"

// Comparison
use oid_registry::OID_PKCS1_SHA256WITHRSA;
if sig_algo_oid == &OID_PKCS1_SHA256WITHRSA { ... }

// For PQC OIDs not in oid-registry, compare by string or construct manually:
let ml_dsa_44: Oid = Oid::from_str("2.16.840.1.101.3.4.3.17").unwrap();
```

---

## 9. Comprehensive OID Table for quipuu Risk Engine

This is the authoritative lookup table quipuu should hardcode. Classification levels:
- `BROKEN` — actively exploitable today
- `WEAK` — deprecated, flagged by browsers/CAs
- `CLASSICAL` — secure classically, quantum-vulnerable
- `PQC-STANDARD` — NIST-standardized PQC (FIPS 203/204/205 + RFCs)
- `PQC-DRAFT` — IETF draft, not yet RFC
- `PQC-UNKNOWN` — seen but no known assignment

```
OID                           Name                                  Class         Key/Algorithm
─────────────────────────────────────────────────────────────────────────────────────────────
# RSA Key Type
1.2.840.113549.1.1.1          rsaEncryption                         CLASSICAL     RSA key type
# RSA Signature Algorithms
1.2.840.113549.1.1.2          md2WithRSAEncryption                  BROKEN        RSA+MD2
1.2.840.113549.1.1.4          md5WithRSAEncryption                  BROKEN        RSA+MD5
1.2.840.113549.1.1.5          sha1WithRSAEncryption                 WEAK          RSA+SHA-1
1.2.840.113549.1.1.7          id-RSAES-OAEP                         CLASSICAL     RSA-OAEP key transport
1.2.840.113549.1.1.10         id-RSASSA-PSS                         CLASSICAL     RSA-PSS (params required)
1.2.840.113549.1.1.11         sha256WithRSAEncryption               CLASSICAL     RSA+SHA-256
1.2.840.113549.1.1.12         sha384WithRSAEncryption               CLASSICAL     RSA+SHA-384
1.2.840.113549.1.1.13         sha512WithRSAEncryption               CLASSICAL     RSA+SHA-512
1.2.840.113549.1.1.14         sha224WithRSAEncryption               CLASSICAL     RSA+SHA-224
# EC Key Type
1.2.840.10045.2.1             id-ecPublicKey                        CLASSICAL     EC key type (ECDSA+ECDH)
1.3.132.1.12                  id-ecDH                               CLASSICAL     ECDH-only key
# ECDSA Signature Algorithms
1.2.840.10045.4.1             ecdsa-with-SHA1                       WEAK          ECDSA+SHA-1
1.2.840.10045.4.3.2           ecdsa-with-SHA256                     CLASSICAL     ECDSA+SHA-256
1.2.840.10045.4.3.3           ecdsa-with-SHA384                     CLASSICAL     ECDSA+SHA-384
1.2.840.10045.4.3.4           ecdsa-with-SHA512                     CLASSICAL     ECDSA+SHA-512
# Named EC Curves (in subjectPublicKeyInfo.algorithm.parameters)
1.2.840.10045.3.1.1           secp192r1 (P-192)                     WEAK          96-bit security
1.3.132.0.33                  secp224r1 (P-224)                     CLASSICAL     112-bit (legacy)
1.2.840.10045.3.1.7           secp256r1 (P-256)                     CLASSICAL     128-bit baseline
1.3.132.0.34                  secp384r1 (P-384)                     CLASSICAL     192-bit
1.3.132.0.35                  secp521r1 (P-521)                     CLASSICAL     260-bit
1.3.132.0.10                  secp256k1                             CLASSICAL     128-bit; SECG arc
1.3.36.3.3.2.8.1.1.7         brainpoolP256r1                       CLASSICAL     128-bit; BSI
1.3.36.3.3.2.8.1.1.11        brainpoolP384r1                       CLASSICAL     192-bit; BSI
# EdDSA / ECDH (Curve25519/448)
1.3.101.110                   id-X25519                             CLASSICAL     X25519 key agreement
1.3.101.111                   id-X448                               CLASSICAL     X448 key agreement
1.3.101.112                   id-Ed25519                            CLASSICAL     Ed25519 signature
1.3.101.113                   id-Ed448                              CLASSICAL     Ed448 signature
# DSA
1.2.840.10040.4.1             id-dsa                                CLASSICAL     DSA key type
1.2.840.10040.4.3             id-dsa-with-sha1                      WEAK          DSA+SHA-1
2.16.840.1.101.3.4.3.1        id-dsa-with-sha224                    CLASSICAL     DSA+SHA-224
2.16.840.1.101.3.4.3.2        id-dsa-with-sha256                    CLASSICAL     DSA+SHA-256
# Diffie-Hellman
1.2.840.10046.2.1             dhpublicnumber                        CLASSICAL     DH key type (ANSI X9.42)
# ML-KEM (FIPS 203, RFC 9935)
2.16.840.1.101.3.4.4.1        id-alg-ml-kem-512                     PQC-STANDARD  ML-KEM L1 KEM
2.16.840.1.101.3.4.4.2        id-alg-ml-kem-768                     PQC-STANDARD  ML-KEM L3 KEM
2.16.840.1.101.3.4.4.3        id-alg-ml-kem-1024                    PQC-STANDARD  ML-KEM L5 KEM
# ML-DSA (FIPS 204, RFC 9881)
2.16.840.1.101.3.4.3.17       id-ml-dsa-44                          PQC-STANDARD  ML-DSA L2 signature
2.16.840.1.101.3.4.3.18       id-ml-dsa-65                          PQC-STANDARD  ML-DSA L3 signature
2.16.840.1.101.3.4.3.19       id-ml-dsa-87                          PQC-STANDARD  ML-DSA L5 signature
# SLH-DSA pure variants (FIPS 205, RFC 9909)
2.16.840.1.101.3.4.3.20       id-slh-dsa-sha2-128s                  PQC-STANDARD  SLH-DSA L1 SHA-2 small
2.16.840.1.101.3.4.3.21       id-slh-dsa-sha2-128f                  PQC-STANDARD  SLH-DSA L1 SHA-2 fast
2.16.840.1.101.3.4.3.22       id-slh-dsa-sha2-192s                  PQC-STANDARD  SLH-DSA L3 SHA-2 small
2.16.840.1.101.3.4.3.23       id-slh-dsa-sha2-192f                  PQC-STANDARD  SLH-DSA L3 SHA-2 fast
2.16.840.1.101.3.4.3.24       id-slh-dsa-sha2-256s                  PQC-STANDARD  SLH-DSA L5 SHA-2 small
2.16.840.1.101.3.4.3.25       id-slh-dsa-sha2-256f                  PQC-STANDARD  SLH-DSA L5 SHA-2 fast
2.16.840.1.101.3.4.3.26       id-slh-dsa-shake-128s                 PQC-STANDARD  SLH-DSA L1 SHAKE small
2.16.840.1.101.3.4.3.27       id-slh-dsa-shake-128f                 PQC-STANDARD  SLH-DSA L1 SHAKE fast
2.16.840.1.101.3.4.3.28       id-slh-dsa-shake-192s                 PQC-STANDARD  SLH-DSA L3 SHAKE small
2.16.840.1.101.3.4.3.29       id-slh-dsa-shake-192f                 PQC-STANDARD  SLH-DSA L3 SHAKE fast
2.16.840.1.101.3.4.3.30       id-slh-dsa-shake-256s                 PQC-STANDARD  SLH-DSA L5 SHAKE small
2.16.840.1.101.3.4.3.31       id-slh-dsa-shake-256f                 PQC-STANDARD  SLH-DSA L5 SHAKE fast
# HashSLH-DSA pre-hash variants (RFC 9909; NOT for X.509 signatureAlgorithm — flag as anomaly if seen there)
2.16.840.1.101.3.4.3.35       id-hash-slh-dsa-sha2-128s-with-sha256   PQC-STANDARD  HashSLH-DSA (CMS only)
2.16.840.1.101.3.4.3.36       id-hash-slh-dsa-sha2-128f-with-sha256   PQC-STANDARD  HashSLH-DSA (CMS only)
2.16.840.1.101.3.4.3.37       id-hash-slh-dsa-sha2-192s-with-sha512   PQC-STANDARD  HashSLH-DSA (CMS only)
2.16.840.1.101.3.4.3.38       id-hash-slh-dsa-sha2-192f-with-sha512   PQC-STANDARD  HashSLH-DSA (CMS only)
2.16.840.1.101.3.4.3.39       id-hash-slh-dsa-sha2-256s-with-sha512   PQC-STANDARD  HashSLH-DSA (CMS only)
2.16.840.1.101.3.4.3.40       id-hash-slh-dsa-sha2-256f-with-sha512   PQC-STANDARD  HashSLH-DSA (CMS only)
2.16.840.1.101.3.4.3.41       id-hash-slh-dsa-shake-128s-with-shake128 PQC-STANDARD HashSLH-DSA (CMS only)
2.16.840.1.101.3.4.3.42       id-hash-slh-dsa-shake-128f-with-shake128 PQC-STANDARD HashSLH-DSA (CMS only)
2.16.840.1.101.3.4.3.43       id-hash-slh-dsa-shake-192s-with-shake256 PQC-STANDARD HashSLH-DSA (CMS only)
2.16.840.1.101.3.4.3.44       id-hash-slh-dsa-shake-192f-with-shake256 PQC-STANDARD HashSLH-DSA (CMS only)
2.16.840.1.101.3.4.3.45       id-hash-slh-dsa-shake-256s-with-shake256 PQC-STANDARD HashSLH-DSA (CMS only)
2.16.840.1.101.3.4.3.46       id-hash-slh-dsa-shake-256f-with-shake256 PQC-STANDARD HashSLH-DSA (CMS only)
# Composite Signatures (draft-ietf-lamps-pq-composite-sigs-19)
1.3.6.1.5.5.7.6.37            id-MLDSA44-RSA2048-PSS-SHA256          PQC-DRAFT     Composite sig
1.3.6.1.5.5.7.6.38            id-MLDSA44-RSA2048-PKCS15-SHA256       PQC-DRAFT     Composite sig
1.3.6.1.5.5.7.6.39            id-MLDSA44-Ed25519-SHA512              PQC-DRAFT     Composite sig
1.3.6.1.5.5.7.6.40            id-MLDSA44-ECDSA-P256-SHA256           PQC-DRAFT     Composite sig
1.3.6.1.5.5.7.6.41            id-MLDSA65-RSA3072-PSS-SHA512          PQC-DRAFT     Composite sig
1.3.6.1.5.5.7.6.42            id-MLDSA65-RSA3072-PKCS15-SHA512       PQC-DRAFT     Composite sig
1.3.6.1.5.5.7.6.43            id-MLDSA65-RSA4096-PSS-SHA512          PQC-DRAFT     Composite sig
1.3.6.1.5.5.7.6.44            id-MLDSA65-RSA4096-PKCS15-SHA512       PQC-DRAFT     Composite sig
1.3.6.1.5.5.7.6.45            id-MLDSA65-ECDSA-P256-SHA512           PQC-DRAFT     Composite sig
1.3.6.1.5.5.7.6.46            id-MLDSA65-ECDSA-P384-SHA512           PQC-DRAFT     Composite sig
1.3.6.1.5.5.7.6.47            id-MLDSA65-ECDSA-brainpoolP256r1-SHA512 PQC-DRAFT    Composite sig
1.3.6.1.5.5.7.6.48            id-MLDSA65-Ed25519-SHA512              PQC-DRAFT     Composite sig
1.3.6.1.5.5.7.6.49            id-MLDSA87-ECDSA-P384-SHA512           PQC-DRAFT     Composite sig
1.3.6.1.5.5.7.6.50            id-MLDSA87-ECDSA-brainpoolP384r1-SHA512 PQC-DRAFT    Composite sig
1.3.6.1.5.5.7.6.51            id-MLDSA87-Ed448-SHAKE256              PQC-DRAFT     Composite sig
1.3.6.1.5.5.7.6.52            id-MLDSA87-RSA3072-PSS-SHA512          PQC-DRAFT     Composite sig
1.3.6.1.5.5.7.6.53            id-MLDSA87-RSA4096-PSS-SHA512          PQC-DRAFT     Composite sig
1.3.6.1.5.5.7.6.54            id-MLDSA87-ECDSA-P521-SHA512           PQC-DRAFT     Composite sig
# Composite KEMs (draft-ietf-lamps-pq-composite-kem-21)
1.3.6.1.5.5.7.6.55            id-MLKEM768-RSA2048-SHA3-256           PQC-DRAFT     Composite KEM
1.3.6.1.5.5.7.6.56            id-MLKEM768-RSA3072-SHA3-256           PQC-DRAFT     Composite KEM
1.3.6.1.5.5.7.6.57            id-MLKEM768-RSA4096-SHA3-256           PQC-DRAFT     Composite KEM
1.3.6.1.5.5.7.6.58            id-MLKEM768-X25519-SHA3-256            PQC-DRAFT     Composite KEM
1.3.6.1.5.5.7.6.59            id-MLKEM768-ECDH-P256-SHA3-256         PQC-DRAFT     Composite KEM
1.3.6.1.5.5.7.6.60            id-MLKEM768-ECDH-P384-SHA3-256         PQC-DRAFT     Composite KEM
1.3.6.1.5.5.7.6.61            id-MLKEM768-ECDH-brainpoolP256r1-SHA3-256 PQC-DRAFT  Composite KEM
1.3.6.1.5.5.7.6.62            id-MLKEM1024-RSA3072-SHA3-256          PQC-DRAFT     Composite KEM
1.3.6.1.5.5.7.6.63            id-MLKEM1024-ECDH-P384-SHA3-256        PQC-DRAFT     Composite KEM
1.3.6.1.5.5.7.6.64            id-MLKEM1024-ECDH-brainpoolP384r1-SHA3-256 PQC-DRAFT Composite KEM
1.3.6.1.5.5.7.6.65            id-MLKEM1024-X448-SHA3-256             PQC-DRAFT     Composite KEM
1.3.6.1.5.5.7.6.66            id-MLKEM1024-ECDH-P521-SHA3-256        PQC-DRAFT     Composite KEM
# Chameleon Certificate extension OIDs (Entrust temp arc; no IANA assignment)
2.16.840.1.114027.80.6.1      id-ce-deltaCertificateDescriptor        PQC-DRAFT     Chameleon ext
```

**OID gap to watch:** Arc `2.16.840.1.101.3.4.3.{32..34}` is currently unassigned between SLH-DSA (ends at .31) and HashSLH-DSA (starts at .35). FN-DSA/Falcon (FIPS 206) will likely land in this range at finalization.

**Reference databases:**
- NIST CSOR: https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration
- IANA PKIX algorithms: https://www.iana.org/assignments/smi-numbers/smi-numbers.xhtml#smi-numbers-1.3.6.1.5.5.7.6
- oid-info.com: https://oid-info.com/get/1.2.840.113549.1.1.11 (pattern works for any OID)

---

## 10. DECISIONS for quipuu/scan-certs

### D1: Primary Parsing Crate

**Decision:** Use `x509-parser` (v0.18+) as the primary and only X.509 parsing crate.

**Evidence:** It is the most widely used pure-Rust X.509 parser (the `oid-registry` companion confirms its ecosystem centrality), has a zero-copy design suitable for bulk scanning (files and dirs), exposes all the field paths needed (`tbs_certificate.signature.oid()`, `tbs_certificate.subject_pki.algorithm.oid()`, `subject_pki.parsed()` for key extraction), and handles unknown OIDs gracefully via `PublicKey::Unknown` — which is exactly how PQC keys will arrive.

Do NOT use `picky` (less maintained, SignatureAlgorithm enum non-exhaustive in a limiting way), `webpki` (verification-only, not a parser), or `rasn` (correct but heavier for this use case).

### D2: PQC OID Table Structure

**Decision:** Maintain the OID classifier as a static `HashMap<&'static str, AlgorithmInfo>` keyed on dotted OID string, loaded at startup. Register into an `OidRegistry` for human-readable names in output.

```rust
pub struct AlgorithmInfo {
    pub name: &'static str,           // "id-ml-dsa-65"
    pub class: AlgorithmClass,        // BROKEN | WEAK | CLASSICAL | PQC_STANDARD | PQC_DRAFT
    pub key_type: KeyType,            // RSA | EC | EdDSA | MLDSA | MLKEM | SLHDSA | COMPOSITE | ...
    pub nist_level: Option<u8>,       // 1-5 for PQC; None for classical
    pub source: &'static str,         // "RFC 9881" / "FIPS 204" etc.
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlgorithmClass {
    Broken,           // actively exploitable
    Weak,             // deprecated (SHA-1 era)
    Classical,        // secure classically, quantum-vulnerable
    PqcStandard,      // NIST-standardized FIPS + published RFC
    PqcDraft,         // IETF draft, not yet RFC
    Unknown,          // seen but not in table
}
```

**Evidence:** Static map is O(1) lookup, trivially serializable to JSON for CBOM output, and extensible without code changes (add entries from a bundled OID file at runtime for FN-DSA when FIPS 206 lands).

### D3: RSA Key Size Classification

**Decision:** Always use `rsa.key_size()` from x509-parser's `RSAPublicKey::key_size()` method. Never compute `modulus.len() * 8`.

**Evidence:** The RSA modulus encoding includes a leading `0x00` sign byte when the high bit is set. Direct multiplication by 8 overestimates by 8 bits. x509-parser's `key_size()` strips this byte before computing length.

**Classification thresholds:** `< 1024`: CRITICAL; `1024 – 2047`: WEAK; `2048 – 3071`: CLASSICAL (QUANTUM-VULNERABLE); `>= 3072`: CLASSICAL (higher margin, still QUANTUM-VULNERABLE).

### D4: EC Curve Extraction

**Decision:** Extract the curve OID from `subjectPublicKeyInfo.algorithm.parameters.as_oid()`, not from the EC point bytes.

**Evidence:** The `id-ecPublicKey` SPKI format (RFC 5480 §2) stores the named curve OID as the `parameters` field of the `AlgorithmIdentifier`. The `ECPoint` bytes (the public key itself) contain only the curve point, not its identity. The `PublicKey::EC::key_size()` method returns the field bit-length derived from point byte count, which is a rough approximation — use curve OID for definitive classification.

### D5: Chain Walking Strategy

**Decision:** Walk the full chain with x509-parser for classification. Use webpki for classical trust validation as a secondary check. Do not block on webpki returning `UnsupportedSignatureAlgorithm` for PQC certs — log it as informational.

**Evidence:** webpki does not know PQC OIDs and will always return `Err(UnsupportedSignatureAlgorithm)` for chains containing PQC certs. This is expected behavior and must not be treated as a classification failure. The scanner's primary job is to read and classify, not to validate trust.

### D6: FN-DSA / Falcon OIDs

**Decision:** Do not hardcode any FN-DSA OIDs. FIPS 206 is not finalized; no CSOR OIDs are assigned. Add a comment in the OID table noting the likely arc (`2.16.840.1.101.3.4.3.{32..34}`) and ship a runtime-loadable OID supplement file so the table can be updated without recompilation when FIPS 206 finalizes (expected late 2026 / early 2027).

### D7: Broken Algorithm Flags

**Decision:** Flag `BROKEN` for: `md2WithRSAEncryption`, `md5WithRSAEncryption`, `ecdsa-with-SHA1`, `sha1WithRSAEncryption`, `id-dsa-with-sha1`. Exit code should be non-zero (e.g., 2) when BROKEN algorithms are found.

**Evidence:** CA/B Forum Ballot SC097 (February 2026) has revoked all SHA-1 sub-CA certificates. Chrome and Firefox dropped SHA-1 in 2017. Any cert with these OIDs in `signatureAlgorithm` today is either expired, revoked, or from a non-compliant issuer.

### D8: Composite Cert Detection

**Decision:** When a composite OID (arc `1.3.6.1.5.5.7.6.37–66`) is seen in `signatureAlgorithm`, report `HYBRID-COMPOSITE` and decode both component algorithm names from the OID string (they are embedded in the OID name). Do not attempt to split the composite signature bytes — report at the OID level only. If the composite OID is from the draft range, note that OIDs may change before RFC publication.

**Evidence:** `draft-ietf-lamps-pq-composite-sigs-19` is in the RFC Editor Queue (In Progress: First Edit) as of 2026-08-26, meaning OIDs are stable but not formally IANA-registered until RFC publication. `draft-ietf-lamps-pq-composite-kem-21` was returned to authors (IESG state 'Revised I-D Needed') after the 2026-09-03 IESG telechat, not advancing toward an RFC number. Draft-19/-21 OIDs are safe to hardcode with a `PQC-DRAFT` flag.

---

## Primary Sources Summary

| Source | URL | Content |
|---|---|---|
| NIST CSOR | https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration | ML-KEM/ML-DSA/SLH-DSA OIDs |
| RFC 9881 | https://www.rfc-editor.org/rfc/rfc9881 | ML-DSA in X.509 (October 2025) |
| RFC 9935 | https://www.rfc-editor.org/rfc/rfc9935 | ML-KEM in X.509 (March 2026) |
| RFC 9909 | https://www.rfc-editor.org/rfc/rfc9909 | SLH-DSA in X.509 (December 2025) |
| RFC 8410 | https://www.rfc-editor.org/rfc/rfc8410 | Ed25519/Ed448/X25519/X448 |
| RFC 5480 | https://www.rfc-editor.org/rfc/rfc5480 | EC SPKI, named curves |
| RFC 5758 | https://www.rfc-editor.org/rfc/rfc5758 | ECDSA-with-SHA2, DSA-with-SHA2 |
| RFC 4055 | https://www.rfc-editor.org/rfc/rfc4055 | RSASSA-PSS, RSAES-OAEP, SHA-2 |
| RFC 3279 | https://www.rfc-editor.org/rfc/rfc3279 | Classic algorithm identifiers |
| draft-ietf-lamps-pq-composite-sigs-19 | https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/ | Composite sig OIDs |
| draft-ietf-lamps-pq-composite-kem-21 | https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-kem/ | Composite KEM OIDs |
| draft-bonnell-lamps-chameleon-certs-07 | https://datatracker.ietf.org/doc/draft-bonnell-lamps-chameleon-certs/ | Chameleon certificate format |
| CA/B Forum Baseline Req. | https://cabforum.org/working-groups/server/baseline-requirements/ | SHA-1 sunset, SC097, SMC-013 |
| x509-parser docs | https://docs.rs/x509-parser/latest/x509_parser/ | Rust crate API |
| spki docs | https://docs.rs/spki/latest/spki/ | RustCrypto SPKI |
| oid-registry docs | https://docs.rs/oid-registry/latest/oid_registry/ | Rust OID registry crate |
| OQS test server | https://test.openquantumsafe.org/ | Live PQC TLS interop |

# Corpus B — Crypto-Adjacent Ecosystem (25 projects)

## Selection Methodology

The crypto-adjacent tier is hand-curated rather than derived from download rankings. Projects are selected because they are canonical security libraries, post-quantum cryptography reference implementations, or production crypto infrastructure that every PQC scanner must handle correctly. Inclusion criteria:
- Directly implements cryptographic algorithms or protocols (not a consumer)
- Either widely deployed, a NIST standard, or represents an important migration surface
- Permissive OSS license
- Active repository (or intentionally-stable reference implementation)

## Entries

| Rank | Project | canonical_id | Why Included |
|------|---------|--------------|--------------|
| 1 | openssl | `crypto-adjacent:github.com/openssl/openssl` | Canonical C TLS library; most deployed globally |
| 2 | aws-lc | `crypto-adjacent:github.com/aws/aws-lc` | AWS production crypto; ML-KEM/ML-DSA; FIPS 140-3 |
| 3 | boringssl | `crypto-adjacent:github.com/google/boringssl` | Google TLS library; HPKE; hybrid PQC experiments |
| 4 | libsodium | `crypto-adjacent:github.com/jedisct1/libsodium` | Portable easy-crypto; X25519/Ed25519 |
| 5 | curl | `crypto-adjacent:github.com/curl/curl` | Ubiquitous HTTPS; multi-backend TLS |
| 6 | nodejs | `crypto-adjacent:github.com/nodejs/node` | Node.js built-in crypto module |
| 7 | liboqs | `crypto-adjacent:github.com/open-quantum-safe/liboqs` | OQS reference PQC library; ML-KEM/ML-DSA/SLH-DSA |
| 8 | wolfssl | `crypto-adjacent:github.com/wolfSSL/wolfssl` | Embedded TLS; Kyber/Dilithium; FIPS 140-3 |
| 9 | mbedtls | `crypto-adjacent:github.com/Mbed-TLS/mbedtls` | ARM embedded TLS; PSA Crypto API |
| 10 | sslyze | `crypto-adjacent:github.com/nabla-c0d3/sslyze` | TLS scanner reference tool |
| 11 | oqs-provider | `crypto-adjacent:github.com/open-quantum-safe/oqs-provider` | OpenSSL 3.x PQC provider |
| 12 | oqs-rs | `crypto-adjacent:github.com/open-quantum-safe/liboqs-rust` | PQC Rust bindings for liboqs |
| 13 | liboqs-python | `crypto-adjacent:github.com/open-quantum-safe/liboqs-python` | PQC Python bindings for liboqs |
| 14 | pyca-cryptography | `crypto-adjacent:github.com/pyca/cryptography` | Canonical Python crypto (cross-listed) |
| 15 | symcrypt | `crypto-adjacent:github.com/microsoft/SymCrypt` | Microsoft core crypto; FIPS 140-3; ML-KEM/ML-DSA |
| 16 | symcrypt-openssl | `crypto-adjacent:github.com/microsoft/SymCrypt-OpenSSL` | SymCrypt as OpenSSL 3.x provider |
| 17 | kyber | `crypto-adjacent:github.com/pq-crystals/kyber` | CRYSTALS-Kyber reference (ML-KEM/FIPS 203) |
| 18 | dilithium | `crypto-adjacent:github.com/pq-crystals/dilithium` | CRYSTALS-Dilithium reference (ML-DSA/FIPS 204) |
| 19 | sphincsplus | `crypto-adjacent:github.com/sphincsplus/sphincsplus` | SPHINCS+ reference (SLH-DSA/FIPS 205) |
| 20 | tink-go | `crypto-adjacent:github.com/tink-crypto/tink-go` | Google Tink Go (AEAD, hybrid, JWT) |
| 21 | swift-crypto | `crypto-adjacent:github.com/apple/swift-crypto` | Apple Swift CryptoKit open-source |
| 22 | crypten | `crypto-adjacent:github.com/facebookresearch/CrypTen` | Privacy-preserving ML / MPC |
| 23 | aws-encryption-sdk-c | `crypto-adjacent:github.com/aws/aws-encryption-sdk-c` | AWS envelope encryption SDK (C) |
| 24 | pqcrypto | `crypto-adjacent:github.com/rustpq/pqcrypto` | PQClean Rust bindings (all PQC algs) |
| 25 | tink-java | `crypto-adjacent:github.com/tink-crypto/tink-java` | Google Tink Java/Android |

## Notes

- Ranks 17-19 (kyber, dilithium, sphincsplus) are the NIST PQC standard reference implementations; `commit_sha` pinned to the latest release branch. These serve as ground-truth for PQC algorithm detection.
- `google/tink` monorepo is archived. Active releases are per-language repos under `tink-crypto/` org. This tier includes `tink-go` (rank 20) and `tink-java` (rank 25). `substituted_for` field documents the transition.
- `sslyze` (rank 10) correct repository is `nabla-c0d3/sslyze`; original candidate `philipl/sslyze` was invalid.
- `pyca/cryptography` (rank 14) is cross-listed from the pypi tier; it appears here to ensure the crypto-adjacent scanner coverage includes the canonical Python crypto library.
- `liboqs-python` (rank 13) was previously `open-quantum-safe/oqs-python`; `substituted_for` field documents the rename.

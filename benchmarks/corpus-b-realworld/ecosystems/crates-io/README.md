# Corpus B — Crates.io Ecosystem (25 projects)

## Selection Methodology

Projects were selected as the top-25 most-downloaded cryptographically-relevant crates on crates.io (measured by all-time + recent downloads, snapshot June 2026) that meet all quality gates:
- OSS with permissive license (MIT, Apache-2.0, BSD, or similar)
- > 1,000 lines of code
- At least one commit in the last 12 months (or intentionally-stable crates)
- Cryptographically relevant: TLS, PKI, cipher/hash/MAC/KEM/signature primitives, key derivation, or authentication

## Ranking (by crates.io downloads, June 2026)

| Rank | Crate | canonical_id | Primary Crypto Surface |
|------|-------|--------------|------------------------|
| 1 | ring | `crates-io:ring` | RSA/ECDSA/ECDH/AES/SHA (C+Rust) |
| 2 | rustls | `crates-io:rustls` | TLS 1.2/1.3 pure Rust |
| 3 | rustls-pemfile | `crates-io:rustls-pemfile` | PEM parsing (rustls monorepo) |
| 4 | webpki | `crates-io:webpki` | X.509 certificate validation |
| 5 | rustls-webpki | `crates-io:rustls-webpki` | X.509 validation (webpki fork) |
| 6 | rustls-pki-types | `crates-io:rustls-pki-types` | PKI type definitions |
| 7 | rustls-native-certs | `crates-io:rustls-native-certs` | System CA bundle integration |
| 8 | tokio-rustls | `crates-io:tokio-rustls` | Async TLS via rustls |
| 9 | hyper-rustls | `crates-io:hyper-rustls` | HTTPS for hyper via rustls |
| 10 | sha2 | `crates-io:sha2` | SHA-256/SHA-512 (RustCrypto) |
| 11 | sha-1 | `crates-io:sha-1` | SHA-1 (RustCrypto) |
| 12 | md-5 | `crates-io:md-5` | MD5 (RustCrypto) |
| 13 | rsa | `crates-io:rsa` | RSA encryption/signing (pure Rust) |
| 14 | ed25519-dalek | `crates-io:ed25519-dalek` | Ed25519 signatures |
| 15 | x25519-dalek | `crates-io:x25519-dalek` | X25519 key exchange |
| 16 | p256 | `crates-io:p256` | NIST P-256 ECDH/ECDSA |
| 17 | p384 | `crates-io:p384` | NIST P-384 ECDH/ECDSA |
| 18 | k256 | `crates-io:k256` | secp256k1 (Bitcoin/Ethereum) |
| 19 | hmac | `crates-io:hmac` | HMAC-SHA2 (RustCrypto) |
| 20 | pbkdf2 | `crates-io:pbkdf2` | PBKDF2 key derivation |
| 21 | scrypt | `crates-io:scrypt` | scrypt key derivation |
| 22 | argon2 | `crates-io:argon2` | Argon2 password hashing |
| 23 | age | `crates-io:age` | age file encryption (X25519) |
| 24 | jsonwebtoken | `crates-io:jsonwebtoken` | JWT HS/RS/ES/EdDSA |
| 25 | openssl | `crates-io:openssl` | OpenSSL Rust FFI bindings |

## Notes

- Several crates share monorepos:
  - `rustls-pemfile` (rank 3) is now part of the `rustls/rustls` monorepo; `substituted_for` field documents this.
  - `sha2`/`sha-1`/`md-5` (ranks 10-12) share `RustCrypto/hashes` monorepo.
  - `p256`/`p384`/`k256` (ranks 16-18) share `RustCrypto/elliptic-curves` monorepo.
  - `pbkdf2`/`scrypt`/`argon2` (ranks 20-22) share `RustCrypto/password-hashes` monorepo.
  - `rustls-webpki` (rank 5) shares `rustls/webpki` monorepo with `webpki` (rank 4).
- All monorepo entries have distinct `scan_paths` to scope the scanner correctly.

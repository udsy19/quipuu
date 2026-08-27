# Rust Coverage Gaps — V5 Corpus Second Opinion

Generated: 2026-06-16. Read-only analysis of 18 zero-finding crates-io projects.

---

## 1. Summary Table

| Project | Verdict | Brief note |
|---|---|---|
| ring | LEGITIMATE | `scan_hints` scopes to `src/`; library-definition only there. Tests (which do call `Ed25519KeyPair::generate_pkcs8`) are explicitly excluded via `exclude_paths`. |
| argon2 | LEGITIMATE (scan-scope) | `scan_hints` scopes to `argon2/src/` in a mono-repo; consumer calls are in sibling crates (`pbkdf2/`, `yescrypt/`) outside scan path. |
| ed25519-dalek | LEGITIMATE | Clone contains only `README.md` (archived repo). Nothing to scan. |
| hmac | LEGITIMATE (scan-scope) | `scan_hints` scopes to `hmac/src/`; consumer-style tests (`Hmac<sha2::Sha256>`) live in `hmac/hmac/tests/` outside scan path. |
| md-5 | LEGITIMATE (scan-scope) | Same mono-repo as sha-1 and sha2. `scan_hints` scopes to `md5/src/`; that subtree is pure digest-definition. |
| p256 | BUG — MISSING PATTERN | `sha2::Sha384::digest(b"test")` at `p256/src/ecdsa.rs:118` is inside scan path but callee text is `sha2::Sha384::digest` (qualified). Scanner only matches `Sha384::digest` (unqualified). |
| p384 | BUG — MISSING PATTERN | Same issue: `sha2::Sha256::digest(b"test")` at `p384/src/ecdsa.rs:124` — qualified callee missed. |
| pbkdf2 | BUG — TYPE-NAME DETECTION | `pbkdf2::<Hmac<sha2::Sha256>>(...)` at `pbkdf2/pbkdf2/benches/lib.rs:16,30,40,50`. Algorithm encoded entirely in turbofish type parameters; no recognized callee name. |
| rsa | BUG — MISSING PATTERN + TYPE-NAME | `RsaPrivateKey::new(rng, bit_size)` in `src/pkcs1v15/signing_key.rs:58,85` — recognized callee but classify rules require literal `bits`; variable silently drops all three rules. Also `SigningKey::<Sha256>::new(priv_key)` at `src/pkcs1v15.rs:468` — turbofish-encoded hash; callee text `SigningKey::<Sha256>::new` matches nothing. |
| rustls-native-certs | BUG — MISSING PATTERN | `rustls::ClientConfig::builder()` at `examples/google.rs:11` and `tests/smoketests.rs:43`. Scanner matches `ClientConfig::builder` but callee text is `rustls::ClientConfig::builder` (module-qualified). |
| rustls-pki-types | LEGITIMATE | Pure type-definition crate. No crypto operations in `src/` or tests. `RsaPrivateKey` only names an enum variant, not a constructor. |
| rustls-webpki | BUG — MISSING PATTERN | `KeyPair::generate_for(RCGEN_SIGNATURE_ALG)` at `src/test_utils.rs:7,18`. `scan_hints` excludes `tests/` but this file is in `src/`. Callee `KeyPair::generate_for` is not in `match_rust_callee`. |
| scrypt | LEGITIMATE (scan-scope) | `scan_hints` scopes to `scrypt/src/`; KDF primitives (`scrypt()`, `Params::new`) are not in scanner's recognized-callee list regardless. |
| sha-1 | LEGITIMATE (scan-scope) | `scan_hints` scopes to `sha1/src/`; consumer call `Sha1::new()` at `sha1/sha1/tests/mod.rs:10` is outside scan path. Also `Sha1::new` is not in `match_rust_callee`. |
| sha2 | LEGITIMATE (scan-scope) | `scan_hints` scopes to `sha2/src/`; `Sha256::new()` at `sha2/sha2/tests/mod.rs:24` is outside scan path. |
| tokio-rustls | BUG — MISSING PATTERN | `ServerConfig::builder()` at `examples/server.rs:48` and `tests/utils.rs:28`. `scan_hints` excludes `tests/`, but `examples/server.rs` is not excluded. `ServerConfig::builder` is absent from `match_rust_callee`. |
| webpki | BUG — MISSING PATTERN | Byte-identical clone of rustls-webpki. Same `KeyPair::generate_for` gap at `src/test_utils.rs:7,18`. |
| x25519-dalek | LEGITIMATE (scan-scope) | `scan_hints` scopes to `src/` and excludes `tests/`. Consumer calls `EphemeralSecret::new`, `StaticSecret::random_from_rng` live in `tests/x25519_tests.rs:189–229` which is excluded. |

---

## 2. BUG Sections

### BUG-A: Qualified-path callee miss (p256, p384, rustls-native-certs)

**Root cause.** `match_rust_callee` checks exact strings like `"Sha384::digest"` and `"ClientConfig::builder"`. When the caller writes a module-qualified path (`sha2::Sha384::digest`, `rustls::ClientConfig::builder`), tree-sitter renders the function node as the full text including the module prefix. The exact-match fails silently.

**p256** — `p256/p256/src/ecdsa.rs:118`:
```rust
let digest = sha2::Sha384::digest(b"test");
let signature: Signature = signer.sign_prehash(&digest).unwrap();
```

**p384** — `p384/p384/src/ecdsa.rs:124`:
```rust
let digest = sha2::Sha256::digest(b"test");
let signature: Signature = signer.sign_prehash(&digest).unwrap();
```

**rustls-native-certs** — `examples/google.rs:11`:
```rust
let config = rustls::ClientConfig::builder()
    .with_root_certificates(roots)
    .with_no_client_auth();
```

**Minimal fix.** In `match_rust_callee`, strip any leading `<crate>::` prefix before matching, or add suffix-match variants. Example: match both `"Sha384::digest"` and `"sha2::Sha384::digest"`. The three immediately impacted pairs are: `sha2::Sha{256,384,512}::digest`, `rustls::ClientConfig::builder`, `rustls::ServerConfig::builder`.

---

### BUG-B: `RsaPrivateKey::new` with variable bit size silently drops (rsa)

**Root cause.** Scanner extracts `RsaPrivateKey::new(rng, bit_size)` as a `RawMatch` but `populate_args` only inserts `bits` when the second argument is an integer literal. All three classify rules (`CRYPTO-540/541/542`) require `when.args.bits` to be set. When `bits` is absent, every rule fails — no finding is emitted.

**rsa** — `src/pkcs1v15/signing_key.rs:56–58`:
```rust
pub fn random<R: CryptoRng + ?Sized>(rng: &mut R, bit_size: usize) -> Result<Self> {
    Ok(Self {
        inner: RsaPrivateKey::new(rng, bit_size)?,
```

**Minimal fix.** Add a catch-all classify rule for `rsa.RsaPrivateKey.new` with no `args` predicate, mapping to a `rsa-unknown-bits` algorithm id at `info` severity. Emits a finding even when the bit size is a runtime variable.

---

### BUG-C: `KeyPair::generate_for` not in scanner (rustls-webpki, webpki)

**Root cause.** `rcgen::KeyPair::generate_for` is an asymmetric key-generation call (generates ECDSA P-256 keypairs by default). It is used in `src/test_utils.rs` (within `scan_paths`), not in an excluded `tests/` file.

**rustls-webpki / webpki** — `src/test_utils.rs:7`:
```rust
let signing_key = KeyPair::generate_for(RCGEN_SIGNATURE_ALG).unwrap();
```
`RCGEN_SIGNATURE_ALG` resolves to `rcgen::PKCS_ECDSA_P256_SHA256`.

**Minimal fix.** Add `"KeyPair::generate_for" => "rcgen.KeyPair.generate_for"` to `match_rust_callee` and a corresponding classify rule mapping to `ecdsa-p256`.

---

### BUG-D: `ServerConfig::builder` absent from scanner (tokio-rustls)

**Root cause.** Scanner has `ClientConfig::builder` but not `ServerConfig::builder`. The `examples/server.rs` is outside `exclude_paths` (only `tests/` is excluded).

**tokio-rustls** — `examples/server.rs:48`:
```rust
let config = rustls::ServerConfig::builder()
    .with_no_client_auth()
    .with_single_cert(certs, key)?;
```

**Minimal fix.** Add `"ServerConfig::builder" | "rustls::ServerConfig::builder"` to `match_rust_callee`, mapping to a new rule `rustls.ServerConfig.builder` (parallel to `CRYPTO-560`).

---

### BUG-E (TYPE-NAME): `pbkdf2::<Hmac<ShaXXX>>` turbofish encoding (pbkdf2)

**Root cause.** The entire algorithm selection for PBKDF2 is encoded in a turbofish generic: `pbkdf2::<Hmac<sha2::Sha256>>(...)`. Tree-sitter sees the callee as `pbkdf2` — an unrecognized name. The hash choice (`Sha256`) is an inner generic type argument, invisible to callee-name matching.

**pbkdf2** — `pbkdf2/pbkdf2/benches/lib.rs:16`:
```rust
pbkdf2::<Hmac<sha2::Sha256>>(password, salt, 16_384, &mut buf).unwrap();
pbkdf2::<Hmac<sha2::Sha512>>(password, salt, 210_000, &mut buf).unwrap();
```

This is the canonical Phase 11 detection shape: detect `pbkdf2(...)` as a call, then walk the turbofish `type_arguments` node to extract the innermost named type (`Sha256`, `Sha512`).

---

### BUG-F (TYPE-NAME): `SigningKey::<ShaXXX>::new` turbofish in RSA (rsa)

**Root cause.** RSA signing key construction uses `SigningKey::<Sha256>::new(key)`. Tree-sitter renders the function node as `SigningKey::<Sha256>::new` — no entry in `match_rust_callee`. The pattern is structurally different from `ecdsa::SigningKey::generate`.

**rsa** — `src/pkcs1v15.rs:468` (inside `#[test]`, but in `src/` which is scanned):
```rust
let signing_key = SigningKey::<Sha256>::new(priv_key);
```

Detection shape: match callee text `SigningKey::new` after stripping turbofish, then read the turbofish inner type to recover the hash algorithm.

---

## 3. Final Aggregation

### Legitimate library-internals → keep zero: **10**

ring, argon2, ed25519-dalek, hmac, md-5, rustls-pki-types, scrypt, sha-1, sha2, x25519-dalek.

Note: 6 of these (argon2, hmac, md-5, sha-1, sha2, scrypt) are legitimate because `scan_hints` consciously scopes the scan to a specific `src/` subtree; the zero-finding verdict is policy-correct given those hints. The hints themselves may warrant review (see below).

### Missing-pattern bugs → fix list: **5**

Ranked by impact (number of affected projects × call-site frequency):

1. **Qualified path prefix miss** (BUG-A) — affects p256, p384, rustls-native-certs and likely many consumer codebases. Fix: strip or suffix-match `<crate>::` prefix in `match_rust_callee`. High impact, low risk.
2. **`RsaPrivateKey::new` with variable bits drops silently** (BUG-B) — affects rsa `src/`. Fix: add a no-args-predicate catch-all classify rule. Medium impact; prevents false-negative on the most security-sensitive pattern in the crate.
3. **`KeyPair::generate_for` not recognized** (BUG-C) — affects rustls-webpki and webpki. Fix: add callee entry + classify rule for rcgen's key-gen API. Medium impact.
4. **`ServerConfig::builder` absent** (BUG-D) — affects tokio-rustls. Fix: add parallel rule alongside existing `ClientConfig::builder`. Low effort.
5. **`SigningKey::<ShaXXX>::new` turbofish in RSA** (BUG-F) — straddles missing-pattern and type-name. Partial fix possible: match callee text `SigningKey::new` (after turbofish strip) and record it as "RSA signing key, hash unknown" pending type-arg extraction.

### Type-name detection needed → Phase 11 candidates: **2**

- **BUG-E**: `pbkdf2::<Hmac<sha2::Sha256>>(...)` — algorithm in nested turbofish. Requires walking `type_arguments` → inner `generic_type` → inner `type_identifier` to recover `Sha256`.
- **BUG-F**: `SigningKey::<Sha256>::new(key)` — hash algorithm in outermost turbofish. Same extraction pattern.

Both follow the same design: detect a known callee (`pbkdf2`, `SigningKey::new`) as a trigger, then extract the first `type_identifier` leaf under the `type_arguments` node and map it to an algorithm id. This is a self-contained tree-sitter subtree walk that does not require a full type-inference engine — it can be added to `run_extract` as a Rust-specific post-pass.

Together, BUG-E and BUG-F represent the canonical Rust "algorithm-in-generic" pattern that the COVERAGE_GAPS_REPORT described as opaque. The second opinion confirms that pattern is real and detectable without full type inference — the algorithm name always appears as a concrete `type_identifier` leaf in the turbofish, not as an erased type variable.

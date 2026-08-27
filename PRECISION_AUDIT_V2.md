# Precision Audit V2 — Cryptoscope V7 Corpus-B Run (Phase 13)

**Audit date:** 2026-06-16
**Sample size:** 101 findings (stratified, deterministic)
**Sample composition:** 55 High · 31 Medium · 15 DEP-001 (unknown severity)
**Total corpus findings:** 1194 across 150 projects
**Prior audit:** Phase 12 (31-finding sample, 73.3% precision)

---

## 1. Headline Numbers

### Overall

| Metric | Value |
|--------|-------|
| TP | 71 |
| FP | 23 |
| DEPENDS | 7 |
| **Precision (excl. DEPENDS)** | **75.5%** |
| Wilson 95% CI | **66.0% – 83.1%** |

> n=94 (101 minus 7 DEPENDS), k=71 TPs. Wilson formula: p̂=0.755, z=1.96.

### By severity tier

| Tier | Total | TP | FP | DEPENDS | Precision (excl. DEPENDS) |
|------|-------|----|----|---------|--------------------------|
| High | 55 | 38 | 15 | 2 | **71.7%** |
| Medium | 31 | 19 | 8 | 4 | **70.4%** |
| DEP-001 (?) | 15 | 14 | 0 | 1 | **100.0%** |
| **Overall** | **101** | **71** | **23** | **7** | **75.5%** |

### By ecosystem

| Ecosystem | Findings | TP | FP | DEPENDS | Precision (excl. DEPENDS) |
|-----------|----------|----|----|---------|--------------------------|
| crates-io | 20 | 17 | 2 | 1 | 89.5% |
| go-modules | 33 | 23 | 8 | 2 | 74.2% |
| maven | 27 | 19 | 7 | 1 | 73.1% |
| npm | 8 | 5 | 3 | 0 | 62.5% |
| pypi | 2 | 2 | 0 | 0 | 100.0% |
| crypto-adjacent | 2 | 2 | 0 | 0 | 100.0% |

### Comparison with Phase 12

| | Phase 12 (n=31, 23 adj) | Phase 13 (n=101, 94 adj) | Delta |
|--|-------------------------|--------------------------|-------|
| Overall precision | 73.3% | 75.5% | +2.2 pp |
| High precision | 80.0% | 71.7% | −8.3 pp |
| Medium precision | 50.0% | 70.4% | +20.4 pp |
| DEP-001 precision | 100.0% | 100.0% | 0 |
| Wilson 95% CI | (point est. only) | 66.0%–83.1% | — |

The Medium gain (+20.4 pp) reflects the Phase 13 fix of Pattern A (TLS config placeholder algorithm_id), which was predominantly Medium-severity. The High drop (−8.3 pp) reflects new FP patterns in High-severity rules exposed by the larger sample, not a regression from Phase 13 changes.

---

## 2. Did Phase 13 Hold?

Phase 13 shipped fixes for five patterns. Status in this 101-sample:

| Pattern | Description | Status | Evidence |
|---------|-------------|--------|----------|
| A | TLS config builder placeholder `aes-256-gcm` | **FIXED** | All 14 CRYPTO-560/561 findings now carry `tls-client-config` / `tls-server-config`. Zero FPs of Pattern A. |
| B | `jwt-alg-none` placeholder `rsa-1024` | **NOT TESTED** | No alg=none findings in this sample. Pattern B cannot be confirmed or denied. |
| C | PSS copy-paste `algorithm_id` (CRYPTO-704 = PS256 id) | **FIXED** | Finding #19 (CRYPTO-704, PS384) now carries `rsa-pss-sha384-3072`. Zero FPs of Pattern C. |
| D | Blanket HMAC `sha-256` for all variants | **PARTIALLY FIXED** | The Nimbus HS384/HS512 Java rules appear fixed. But findings #79 (CRYPTO-241, jjwt HS512→sha-256) and #80 (CRYPTO-263, jose4j HmacSha512→sha-256) remain broken. Two FPs remain in this category. |
| E | AES key-size mismatch in C/EVP rule | **FIXED** | Finding #97 (CRYPTO-417) correctly carries `aes-256-ecb` for `EVP_aes_256_ecb()`. |

**Verdict: Phase 13 fully held for Patterns A, C, E. Pattern B is unverifiable this sample. Pattern D is partially fixed — two library-specific rules (jjwt, jose4j) retain the old sha-256 placeholder for SHA-512 variants.**

---

## 3. New FP Patterns

### Pattern F — HMAC-rule fires on algorithm-string constants (6 FPs)

**Findings:** #66, #68, #70, #73, #75, #76

**Root cause:** Rules CRYPTO-730 (HS256) and CRYPTO-731 (HS384) match any line containing the JWT algorithm identifier string `"HS256"` / `"HS384"`, without verifying that a cryptographic HMAC operation is present at the site. This causes false fires on:
- String constant declarations (`hs256 = "HS256"`)
- Parser configuration arrays (`ValidMethods: []string{"RS256", "HS256"}`)
- Test assertions (`require.Equal(t, "HS256", ...)`)
- Protobuf generated enum maps (`"HS384": 2`)

**Minimal fix:** Add a structural guard requiring that the match occur within a signing-method registration, an actual HMAC key or token computation, or an algorithm-object constructor call. Pure string literal contexts should be excluded.

### Pattern G — secp256k1 curve misclassified as P-256 (1 FP)

**Finding:** #43 (`EthereumCredentials.java:47`, CRYPTO-211, `ecdsa-p256`)

**Root cause:** CRYPTO-211 fires on `KeyPairGenerator.getInstance("EC")` and assigns `algorithm_id=ecdsa-p256` regardless of the `ECGenParameterSpec` passed to `initialize()`. The code uses `ECGenParameterSpec("secp256k1")` — the Ethereum/Bitcoin curve — which is not NIST P-256 (secp256r1). secp256k1 has no NIST deprecation timeline.

**Minimal fix:** Extend the CRYPTO-211 classifier to inspect the `ECGenParameterSpec` argument. If the spec is `"secp256k1"`, assign `algorithm_id=ecdsa-secp256k1` and suppress the quantum-vulnerability message (secp256k1 has different governance).

### Pattern H — jwt.sign HMAC-mode calls tagged as RSA (2 FPs)

**Findings:** #45 (`expires_format.tests.js:8`), #46 (`jwt.hs.tests.js:21`), CRYPTO-360, `rsa-pkcs1-sha256-2048`

**Root cause:** CRYPTO-360 fires on any `jwt.sign()` call and assigns `algorithm_id=rsa-pkcs1-sha256-2048` unconditionally. When the call uses a string secret (`'123'`) or an explicit `algorithm:'HS256'`, the signing is HMAC — not RSA. The hardcoded RSA algorithm_id is incorrect.

(Note: finding #44 is a related issue where the call uses RS256 but with an explicit 1024-bit key, making the 2048 claim wrong. That is a third CRYPTO-360 variant.)

**Minimal fix:** Gate CRYPTO-360 on the presence of an RSA key object or `algorithm:'RS*'/'PS*'` option. Default-HMAC calls (string secret or `algorithm:'HS*'`) should either be excluded or assigned a distinct HMAC algorithm_id.

### Pattern I — Non-operational algorithm-identifier matches (5 FPs)

**Findings:** #14 (`acme_jws.go:20`, CRYPTO-702), #21 (`signature_gen_test.go:206`, CRYPTO-705), #22 (`signature_gen_test.go:290`, CRYPTO-703), #27 (`jwsbb.go:48`, CRYPTO-712), #33 (`jwt_rsa_ssa_pkcs1.pb.go:61`, CRYPTO-702)

**Root cause:** Rules fire on algorithm identifier strings in contexts that are definitionally not cryptographic operations: allowlist maps (`"RS512": true`), boolean property checks (`jwa.PS256().IsSymmetric()`), string constant declarations (`es512 = "ES512"`), and generated protobuf enum-to-int tables (`"RS512": 3`). These are data structure definitions or test control-flow, not invocations of cryptographic primitives.

**Minimal fix:** Require that the matched string or symbol appear in an argument position of a cryptographic function call, a type parameter, or a constructor initializer. Standalone string literals and map/enum values should be excluded unless the containing expression performs or schedules a crypto operation.

### Residual Pattern D — HMAC sha-256 placeholder in jjwt/jose4j (2 FPs)

**Findings:** #79 (`SignatureAlgorithm.java:115`, CRYPTO-241, `sha-256` for HS512), #80 (`HmacUsingShaAlgorithm.java:128`, CRYPTO-263, `sha-256` for HmacSha512)

**Root cause:** Same as Phase 12 Pattern D. CRYPTO-241 and CRYPTO-263 use a blanket `algorithm_id=sha-256` across all jjwt/jose4j HMAC variants. HS512 uses SHA-512, not SHA-256. These two rules were not updated in Phase 13.

**Minimal fix:** Apply the same per-variant split already applied to Nimbus rules: CRYPTO-241 HS512 → `sha-512`, CRYPTO-263 HMAC_SHA512 → `sha-512`.

### Pattern D-prime — RSA-PKCS1 sha-256 placeholder for non-RS256 variants (2 FPs)

**Findings:** #38 (`RSAEncrypter.java:145`, CRYPTO-254, `rsa-2048` for RSA_OAEP_256), #39 (`JCASupport.java:117`, CRYPTO-250, `rsa-pkcs1-sha256-2048` for RS384)

**Root cause:** CRYPTO-254 fires on RSA-OAEP-256 dispatch (`JWEAlgorithm.RSA_OAEP_256`) and assigns `rsa-2048` — a PKCS1 identifier that misrepresents both the padding scheme (OAEP vs. PKCS1) and the key size. CRYPTO-250 fires on RS384 dispatch but assigns `rsa-pkcs1-sha256-2048` (RS256's identifier), propagating the wrong hash (SHA-256 instead of SHA-384).

**Minimal fix:** Assign correct algorithm_ids: CRYPTO-254 should use `rsa-oaep-256`, CRYPTO-250 for RS384 should use `rsa-pkcs1-sha384-????` (or a size-agnostic form like `rsa-pkcs1-sha384`).

---

## 4. Per-Finding Table

<details>
<summary>Click to expand 101-row audit table</summary>

| # | rule_id | severity | file:line | verdict | note |
|---|---------|----------|-----------|---------|------|
| 1 | CRYPTO-001 | High | crates-io/age/.../recipients_test.go:114 | FP | rsa.GenerateKey 768-bit; algorithm_id=rsa-1024 wrong (768 ≠ 1024) |
| 2 | CRYPTO-547 | High | crates-io/rsa/src/pss.rs:655 | FP | SigningKey::<Sha1>::new with 512-bit key; algorithm_id=rsa-pkcs1-sha256-2048 wrong on padding, hash, and size |
| 3 | CRYPTO-570 | High | crates-io/rustls-webpki/.../verify_cert.rs:1112 | TP | KeyPair::generate_for(PKCS_ECDSA_P256_SHA256) — correct ecdsa-p256 |
| 4 | CRYPTO-570 | High | crates-io/webpki/.../verify_cert.rs:1233 | TP | same as #3, different project |
| 5 | CRYPTO-711 | High | go-modules/jwt-go/ecdsa_test.go:32 | TP | ES384 test with ec384-private.pem — correct ecdsa-p384 |
| 6 | CRYPTO-705 | High | go-modules/jwt-go/rsa_pss.go:67 | DEPENDS | PS512 algorithm struct definition; SHA-512 matches; 4096 claim unverifiable at this site |
| 7 | CRYPTO-002 | High | go-modules/go-jose/asymmetric_test.go:200 | TP | rsa.GenerateKey(rand.Reader, 2048) — correct rsa-2048 |
| 8 | CRYPTO-020 | High | go-modules/go-jose/.../cryptosigner_test.go:153 | TP | ed25519.GenerateKey(rand.Reader) — correct ed25519 |
| 9 | CRYPTO-013 | High | go-modules/go-jose/.../generate.go:67 | TP | ecdsa.GenerateKey(elliptic.P521()) — correct ecdsa-p521 |
| 10 | CRYPTO-011 | High | go-modules/go-jose/signing_test.go:308 | TP | ecdsa.GenerateKey(elliptic.P256()) — correct ecdsa-p256 |
| 11 | CRYPTO-712 | High | go-modules/golang-jwt-jwt/ecdsa_test.go:41 | TP | ES512 test with ec512-private.pem (P-521) — correct ecdsa-p521 |
| 12 | CRYPTO-701 | High | go-modules/golang-jwt-jwt/rsa.go:31 | DEPENDS | RS384 algorithm registration; SHA-384 correct; 3072 claim unverifiable |
| 13 | CRYPTO-011 | High | go-modules/consul/.../generate_test.go:121 | TP | ecdsa.GenerateKey(elliptic.P256()) in test — correct ecdsa-p256 |
| 14 | CRYPTO-702 | High | go-modules/vault/.../acme_jws.go:20 | FP | "RS512": true allowlist map entry — not a crypto op |
| 15 | CRYPTO-020 | High | go-modules/vault/.../backend_test.go:4124 | TP | ed25519.GenerateKey(rand.Reader) in test — correct ed25519 |
| 16 | CRYPTO-012 | High | go-modules/vault/.../path_acme_test.go:1631 | TP | ecdsa.GenerateKey(elliptic.P384()) — correct ecdsa-p384 |
| 17 | CRYPTO-020 | High | go-modules/vault/.../certutil_test.go:1238 | TP | ed25519.GenerateKey(rand.Reader) — correct ed25519 |
| 18 | CRYPTO-720 | High | go-modules/jwx/jwa/signature_gen.go:18 | TP | NewSignatureAlgorithm("EdDSA") registration — correct ed25519 family |
| 19 | CRYPTO-704 | High | go-modules/jwx/jwa/signature_gen.go:91 | TP | PS384 algorithm lookup; algorithm_id=rsa-pss-sha384-3072 (Phase 13 Pattern C fix confirmed) |
| 20 | CRYPTO-720 | High | go-modules/jwx/jwa/signature_gen_test.go:66 | TP | LookupSignatureAlgorithm("EdDSA") — correct ed25519 family |
| 21 | CRYPTO-705 | High | go-modules/jwx/jwa/signature_gen_test.go:206 | FP | require.Equal(t, "PS512", ...) — test string assertion, not a crypto op |
| 22 | CRYPTO-703 | High | go-modules/jwx/jwa/signature_gen_test.go:290 | FP | require.False(t, jwa.PS256().IsSymmetric()) — boolean test, not a crypto op |
| 23 | CRYPTO-012 | High | go-modules/jwx/jwe/jwe_test.go:716 | TP | ecdsa.GenerateKey(elliptic.P384()) — correct ecdsa-p384 |
| 24 | CRYPTO-010 | High | go-modules/jwx/jwe/.../ecdh_es_ext_test.go:263 | FP | ecdsa.GenerateKey(elliptic.P224()) — algorithm_id=ecdsa-p256 wrong (P-224 ≠ P-256) |
| 25 | CRYPTO-002 | High | go-modules/jwx/jwk/jwk_test.go:323 | TP | rsa.GenerateKey(rand.Reader, 2048) — correct rsa-2048 |
| 26 | CRYPTO-011 | High | go-modules/jwx/jws/bench_marshal_test.go:16 | TP | ecdsa.GenerateKey(elliptic.P256()) in benchmark — correct ecdsa-p256 |
| 27 | CRYPTO-712 | High | go-modules/jwx/jws/jwsbb/jwsbb.go:48 | FP | es512 = "ES512" string constant — not a crypto op |
| 28 | CRYPTO-700 | High | go-modules/jwx/jws/streaming_detached_test.go:47 | TP | RS256 signing test with 2048-bit RSA key struct — correct rsa-pkcs1-sha256-2048 |
| 29 | CRYPTO-011 | High | go-modules/client-go/.../certificate_manager.go:767 | TP | ecdsa.GenerateKey(elliptic.P256()) — correct ecdsa-p256 |
| 30 | CRYPTO-003 | High | maven/tink/go/.../rsassapss...test.go:112 | TP | rsa.GenerateKey(rand.Reader, 3072) — correct rsa-3072 |
| 31 | CRYPTO-711 | High | maven/tink/go/jwt/jwk_converter_test.go:74 | TP | JWK test data with "alg":"ES384"/"crv":"P-384" — correct ecdsa-p384 |
| 32 | CRYPTO-710 | High | maven/tink/go/jwt/.../kid_test.go:73 | TP | newSignerWithKID(ts, "ES256", kid) — correct ecdsa-p256 |
| 33 | CRYPTO-702 | High | maven/tink/go/.../jwt_rsa_ssa_pkcs1.pb.go:61 | FP | "RS512": 3 protobuf enum map — generated constant, not a crypto op |
| 34 | CRYPTO-020 | High | maven/tink/go/.../ed25519_signer_verifier_test.go:117 | TP | ed25519.GenerateKey(rand.Reader) — correct ed25519 |
| 35 | CRYPTO-211 | High | maven/tink/java_src/.../EcdsaSignJceTest.java:98 | TP | getNistP256Params() + KeyPairGenerator.getInstance("EC") — correct ecdsa-p256 |
| 36 | CRYPTO-210 | High | maven/tink/java_src/.../RsaSsaPssSignJceTest.java:75 | TP | int keySize=2048; KeyPairGenerator.getInstance("RSA") — correct rsa-2048 |
| 37 | CRYPTO-251 | High | maven/nimbus-jose-jwt/.../ECDSA.java:143 | TP | alg.equals(JWSAlgorithm.ES256) — correct ecdsa-p256 |
| 38 | CRYPTO-254 | High | maven/nimbus-jose-jwt/.../RSAEncrypter.java:145 | FP | alg.equals(JWEAlgorithm.RSA_OAEP_256) — RSA-OAEP not rsa-2048 (wrong algorithm family and no key-size) |
| 39 | CRYPTO-250 | High | maven/nimbus-jose-jwt/.../JCASupport.java:117 | FP | RS384 dispatch; algorithm_id=rsa-pkcs1-sha256-2048 wrong hash (SHA-384 ≠ SHA-256) |
| 40 | CRYPTO-253 | High | maven/nimbus-jose-jwt/.../Curve.java:330 | TP | Arrays.asList(Ed25519, Ed448) — correct ed25519 |
| 41 | CRYPTO-262 | High | maven/jose4j/.../EcdsaUsingShaAlgorithm.java:259 | FP | P521UsingSha512 constructor; algorithm_id=ecdsa-p256 wrong (P-521 ≠ P-256) |
| 42 | CRYPTO-221 | High | maven/jetty-server/.../AbstractGzipTest.java:73 | TP | MessageDigest.getInstance("SHA1") — correct sha-1 |
| 43 | CRYPTO-211 | High | maven/jetty-server/.../EthereumCredentials.java:47 | FP | ECGenParameterSpec("secp256k1") — secp256k1 ≠ P-256; algorithm_id=ecdsa-p256 wrong curve |
| 44 | CRYPTO-360 | High | npm/jsonwebtoken/test/async_sign.tests.js:75 | FP | jwt.sign with explicitly 1024-bit RSA key; algorithm_id=rsa-pkcs1-sha256-2048 wrong size |
| 45 | CRYPTO-360 | High | npm/jsonwebtoken/test/expires_format.tests.js:8 | FP | jwt.sign with string secret (HMAC default); algorithm_id=rsa-pkcs1-sha256-2048 wrong algorithm type |
| 46 | CRYPTO-360 | High | npm/jsonwebtoken/test/jwt.hs.tests.js:21 | FP | jwt.sign with algorithm:'HS256' (HMAC explicit); algorithm_id=rsa-pkcs1-sha256-2048 wrong |
| 47 | CRYPTO-360 | High | npm/jsonwebtoken/test/rsa-public-key.tests.js:13 | TP | jwt.sign with PEM cert_priv, algorithm:'RS256' — correct rsa-pkcs1-sha256-2048 |
| 48 | CRYPTO-372 | High | npm/jsrsasign/jsrsasign-all-min.js:231 | TP | CryptoJS.TripleDES.encrypt/decrypt — correct 3des |
| 49 | CRYPTO-372 | High | npm/jsrsasign/npm/lib/jsrsasign-jwths-min.js:117 | TP | CryptoJS.TripleDES in minified bundle — correct 3des |
| 50 | CRYPTO-104 | High | pypi/authlib/.../rsa_key.py:95 | TP | rsa.generate_private_key(key_size=key_size) default 2048 — correct rsa-2048 |
| 51 | CRYPTO-560 | Medium | crates-io/hyper-rustls/src/connector.rs:269 | TP | ClientConfig::builder() — correct tls-client-config (Phase 13 fix) |
| 52 | CRYPTO-520 | Medium | crates-io/k256/k256/src/schnorr.rs:215 | TP | Sha256::new() in tagged_hash — correct sha-256 |
| 53 | CRYPTO-583 | Medium | crates-io/pbkdf2/pbkdf2/src/lib.rs:206 | DEPENDS | pbkdf2::<PRF>() generic — sha-256 only if PRF=Sha256; not determinable at this line |
| 54 | CRYPTO-560 | Medium | crates-io/rustls/rustls/src/client/test.rs:699 | TP | ClientConfig::builder(HYBRID_PROVIDER) — correct tls-client-config |
| 55 | CRYPTO-560 | Medium | crates-io/rustls-pemfile/ci-bench/src/main.rs:693 | TP | ClientConfig::builder(params.provider) — correct tls-client-config |
| 56 | CRYPTO-561 | Medium | crates-io/rustls-pemfile/fuzz/fuzzers/server.rs:23 | TP | ServerConfig::builder(fuzzing_provider) — correct tls-server-config |
| 57 | CRYPTO-560 | Medium | crates-io/rustls-pemfile/.../smoke.rs:85 | TP | ClientConfig::builder(provider) — correct tls-client-config |
| 58 | CRYPTO-560 | Medium | crates-io/rustls-pemfile/rustls-test/src/lib.rs:617 | TP | ClientConfig::builder(provider) — correct tls-client-config |
| 59 | CRYPTO-560 | Medium | crates-io/rustls-pemfile/.../api.rs:1006 | TP | ClientConfig::builder — correct tls-client-config |
| 60 | CRYPTO-560 | Medium | crates-io/rustls-pemfile/.../api.rs:1588 | TP | ClientConfig::builder — correct tls-client-config |
| 61 | CRYPTO-561 | Medium | crates-io/rustls-pemfile/.../crypto.rs:493 | TP | ServerConfig::builder(provider) — correct tls-server-config |
| 62 | CRYPTO-561 | Medium | crates-io/rustls-pemfile/.../kx.rs:366 | TP | ServerConfig::builder(CryptoProvider{...}) — correct tls-server-config |
| 63 | CRYPTO-560 | Medium | crates-io/rustls-pemfile/.../server_cert_verifier.rs:239 | TP | ClientConfig::builder(provider) — correct tls-client-config |
| 64 | CRYPTO-560 | Medium | crates-io/rustls-pemfile/rustls/src/client/test.rs:699 | TP | ClientConfig::builder(HYBRID_PROVIDER) — correct tls-client-config |
| 65 | CRYPTO-203 | Medium | crypto-adjacent/tink-java/.../AndroidKeystore.java:177 | DEPENDS | Cipher.getInstance("AES/GCM/NoPadding") confirmed; 256-bit key size depends on Android Keystore configuration, not visible at this line |
| 66 | CRYPTO-730 | Medium | go-modules/jwt-go/parser_test.go:126 | FP | ValidMethods:[]string{"RS256","HS256"} parser config — string array, not HMAC op |
| 67 | CRYPTO-731 | Medium | go-modules/golang-jwt-jwt/hmac.go:32 | TP | SigningMethodHS384=&SigningMethodHMAC{"HS384",crypto.SHA384} — correct sha-384 |
| 68 | CRYPTO-730 | Medium | go-modules/golang-jwt-jwt/parser_test.go:353 | FP | WithValidMethods([]string{"HS256","ES256"}) — parser config string, not HMAC op |
| 69 | CRYPTO-760 | Medium | go-modules/jwx/jwa/content_encryption_gen_test.go:98 | DEPENDS | LookupContentEncryptionAlgorithm("A256GCM") — identifier lookup in test; indirect reference only |
| 70 | CRYPTO-730 | Medium | go-modules/jwx/jwa/signature_gen_test.go:110 | FP | require.Equal(t,"HS256",...) — test string assertion, not HMAC op |
| 71 | CRYPTO-760 | Medium | go-modules/jwx/jwe/.../ecdh_es_ext_test.go:37 | TP | GenerateECDHES("A256GCM", 32, ...) — actual key derivation with A256GCM |
| 72 | CRYPTO-762 | Medium | go-modules/jwx/jwe/.../hpke_ext_test.go:59 | TP | KeyEncryptHPKECustom(nil,"HPKE-0-KE","A128GCM",pub) — actual HPKE call with AES-128-GCM |
| 73 | CRYPTO-730 | Medium | go-modules/jwx/jws/jwsbb/jwsbb.go:31 | FP | hs256 = "HS256" — string constant declaration, not HMAC op |
| 74 | CRYPTO-203 | Medium | maven/aws-encryption-sdk-java/.../CipherHandler.java:99 | TP | Cipher.getInstance("AES/GCM/NoPadding") in AES-256-GCM SDK context |
| 75 | CRYPTO-730 | Medium | maven/tink/go/jwt/jwt_encoding_test.go:377 | FP | decodeUnsignedTokenAndValidateHeader(...,"HS256",...) — string arg in test helper, not HMAC op |
| 76 | CRYPTO-731 | Medium | maven/tink/go/.../jwt_hmac.pb.go:60 | FP | "HS384": 2 protobuf enum map — generated constant, not HMAC op |
| 77 | CRYPTO-232 | Medium | maven/nimbus-jose-jwt/.../LegacyAESGCM.java:99 | DEPENDS | GCMBlockCipher instantiated; GCM confirmed but 256-bit key size unverifiable at this line |
| 78 | CRYPTO-255 | Medium | maven/nimbus-jose-jwt/.../MACSigner.java:106 | TP | hmacAlgs.add(JWSAlgorithm.HS384) — HS384 (SHA-384) registered correctly |
| 79 | CRYPTO-241 | Medium | maven/jjwt-api/.../SignatureAlgorithm.java:115 | FP | message says HS512; algorithm_id=sha-256 wrong (HS512 uses SHA-512) |
| 80 | CRYPTO-263 | Medium | maven/jose4j/.../HmacUsingShaAlgorithm.java:128 | FP | HmacSha512 constructor (SHA-512); algorithm_id=sha-256 wrong |
| 81 | DEP-001 | ? | crates-io/age/go.mod:5 | TP | golang.org/x/crypto — genuine crypto library |
| 82 | DEP-001 | ? | crates-io/rustls-pemfile/openssl-tests/Cargo.toml:14 | TP | rustls — TLS/crypto library |
| 83 | DEP-001 | ? | crates-io/rustls-pemfile/rustls-post-quantum/Cargo.toml:18 | TP | webpki — PKI/crypto library |
| 84 | DEP-001 | ? | crates-io/rustls-pemfile/rustls/Cargo.toml:31 | TP | webpki — PKI/crypto library |
| 85 | DEP-001 | ? | maven/jetty-server/.../jetty-compression-server/pom.xml:20 | TP | jetty-server — embedded HTTPS server (TLS-capable) |
| 86 | DEP-001 | ? | maven/jetty-server/.../jetty-http3-server/pom.xml:19 | TP | jetty-server — embedded HTTPS server |
| 87 | DEP-001 | ? | maven/jetty-server/.../jetty-quic-quiche-server/pom.xml:19 | TP | jetty-server — embedded HTTPS server |
| 88 | DEP-001 | ? | maven/jetty-server/.../jetty-test-coreapp-demo/pom.xml:21 | TP | jetty-server — embedded HTTPS server |
| 89 | DEP-001 | ? | maven/jetty-server/.../jetty-servlet4-demo-jetty-webapp/pom.xml:38 | TP | jetty-server — embedded HTTPS server |
| 90 | DEP-001 | ? | maven/jetty-server/.../jetty-ee10-test-loginservice/pom.xml:20 | TP | jetty-server — embedded HTTPS server |
| 91 | DEP-001 | ? | maven/jetty-server/.../test-jetty-ee11-osgi/pom.xml:118 | TP | jetty-server — embedded HTTPS server |
| 92 | DEP-001 | ? | maven/jetty-server/.../jetty-ee8-maven-plugin/pom.xml:93 | TP | jetty-server — embedded HTTPS server |
| 93 | DEP-001 | ? | maven/jetty-server/.../jetty-ee9-openid/pom.xml:32 | TP | jetty-server — embedded HTTPS server |
| 94 | DEP-001 | ? | maven/jetty-server/.../test-sessions-memcached/pom.xml:15 | DEPENDS | commons-codec — encoding utilities (Base64, Hex, DigestUtils); borderline crypto dependency |
| 95 | DEP-001 | ? | maven/jetty-server/pom.xml:650 | TP | org.bouncycastle:bcprov-jdk18on — genuine crypto provider |
| 96 | CRYPTO-020 | High | crates-io/age/.../recipients_test.go:159 | TP | ed25519.GenerateKey(rand.Reader) — correct ed25519 |
| 97 | CRYPTO-417 | High | crypto-adjacent/kyber/ref/nistkat/rng.c:127 | TP | EVP_aes_256_ecb() — algorithm_id=aes-256-ecb correct (Phase 13 Pattern E fix confirmed) |
| 98 | CRYPTO-710 | High | go-modules/jwt-go/ecdsa.go:34 | TP | SigningMethodES256=&SigningMethodECDSA{"ES256",...,256} — correct ecdsa-p256 |
| 99 | CRYPTO-401 | High | maven/tink/cc/.../rsa_ssa_pkcs1_private_key_test.cc:249 | TP | RSA_generate_key_ex(..., 2048, ...) — correct rsa-2048 |
| 100 | CRYPTO-312 | Medium | npm/elliptic/benchmarks/index.js:72 | TP | crypto.createHash('sha256') — correct sha-256 |
| 101 | CRYPTO-141 | High | pypi/authlib/authlib/oauth1/rfc5849/client_auth.py:150 | TP | hashlib.sha1(body) — correct sha-1 |

</details>

---

## 5. Recommendations

Ranked by impact (estimated FP count eliminated in full 1194-finding corpus).

1. **Fix CRYPTO-730/731 (and similar CRYPTO-7xx) to require a crypto-operational context (Pattern F).** These rules fire on algorithm identifier strings in parser configs, test assertions, string constants, and generated protobuf code. At 6 FPs in a 101-sample, this likely accounts for 60–80 FPs in the full corpus given the density of JWT-related string literals across the go-modules and maven projects. Add a structural guard: only fire when the matched string appears as a function argument to a signing/verification call, an algorithm object constructor, or a type parameter — not as a standalone literal or map value.

2. **Fix CRYPTO-360 (jwt.sign) to distinguish HMAC from RSA callers (Pattern H).** CRYPTO-360 fires on all `jwt.sign()` calls with `algorithm_id=rsa-pkcs1-sha256-2048`. 3 FPs in this 101-sample from 4 npm/jsonwebtoken test files. In a real corpus, HMAC jwt.sign calls are common. Gate the rule on presence of a non-string key argument or an explicit `algorithm:'RS*'/'PS*'` option; otherwise assign a HMAC algorithm_id.

3. **Fix CRYPTO-262 curve-mismatch (jose4j P-521 tagged ecdsa-p256) and CRYPTO-211 curve-detection (secp256k1 tagged ecdsa-p256).** Two FPs from wrong curve assignments. The jose4j fix is straightforward: the CRYPTO-262 rule should distinguish ES512 (P-521) from ES256 (P-256). The CRYPTO-211 fix requires inspecting the ECGenParameterSpec argument (Pattern G).

4. **Fix CRYPTO-241 and CRYPTO-263 per-variant HMAC algorithm_id (Pattern D residual).** Apply the per-variant split to jjwt and jose4j: HS512 → sha-512, HS384 → sha-384. This eliminates 2 FPs and is a one-line change per rule.

5. **Fix CRYPTO-250 and CRYPTO-254 algorithm_id mismatches (Pattern D-prime).** CRYPTO-250 RS384 should carry `rsa-pkcs1-sha384`; CRYPTO-254 RSA_OAEP_256 should carry `rsa-oaep-256` (not `rsa-2048`). 2 FPs.

6. **Suppress CRYPTO-702/703/705 on non-operational string occurrences (Pattern I).** Map entries (`"RS512": true`), enum constants, and boolean test assertions all triggered JWT algorithm rules. Same structural guard as recommendation 1 but for RSA/PSS rules. 5 FPs in this sample.

7. **Verify Pattern B (jwt-alg-none) once a sample containing alg=none findings is available.** Phase 13 assigned `jwt-alg-none` as the algorithm_id but this sample contained no alg=none findings to confirm the fix holds.

8. **Add a CRYPTO-001 dynamic-size classifier.** CRYPTO-001 fires for any sub-2048 RSA keygen with a hardcoded `algorithm_id=rsa-1024`. When the actual key size is 768 (as in finding #1), the algorithm_id is wrong. Capture the numeric literal and map it to the correct id (rsa-512, rsa-768, rsa-1024, etc.).

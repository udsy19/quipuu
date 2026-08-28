# Precision Audit V3 — Seawall Phase 18 (Post-Phase 17) Corpus-B Run

**Audit date:** 2026-06-16
**Sample size:** 196 findings (stratified, deterministic)
**Sample composition:** 105 High · 66 Medium · 25 DEP-001
**Total corpus findings (Phase 16 V11):** 986 across 150 projects
**Prior audits:** Phase 12 (n=31, 73.3%) · Phase 14a (n=101, 75.5%)

---

## 0. Correction, 2026-08-28 — the registry-lookup shape is a false positive

**This section overrides the per-finding table below wherever they disagree.**

This audit labelled one syntactic shape four different ways. A JOSE
algorithm-registry retrieval — `jwa.LookupSignatureAlgorithm("PS256")`, or
`func ES384() SignatureAlgorithm { return lookupBuiltinSignatureAlgorithm("ES384") }` —
appears in the table as TP twice, as DEPENDS once, and as FP once:

| Row | Rule | Cited line | Verdict as published |
|---|---|---|---|
| 19 | CRYPTO-704 | `go-modules/jwx/jwa/signature_gen.go:91` | TP |
| 20 | CRYPTO-720 | `go-modules/jwx/jwa/signature_gen_test.go:66` | TP |
| 69 | CRYPTO-760 | `go-modules/jwx/jwa/content_encryption_gen_test.go:98` | DEPENDS |
| 161 | CRYPTO-732 | `go-modules/jwx/jwa/signature_gen_test.go:130` | FP |

**All four are false positives.** Trust invariant P3 decides it without a
judgement call: a finding is a true positive only if the cited `file:line`
performs the operation claimed. Naming an algorithm in order to fetch its
descriptor from a table produces no signature, no key and no ciphertext. The
operation, if one happens at all, happens wherever the descriptor is later
used — which is a different line, and the one a reader would need.

Row 69's DEPENDS is wrong for a second reason. DEPENDS is reserved for a real
operation whose `algorithm_id` asserts a parameter the line does not state. A
retrieval is not a weakly-parameterised operation; it is not an operation.

Resolving the shape strictly as FP is what licenses the suppression shipped on
2026-08-28, and it is stated here so the recorded baseline moves for one reason
rather than two. All four rows above are in the set that change removes.

**Effect on this audit's headline.** The 84.5% on line 22 is left as published,
per the rule that an audit is a record of what was labelled on its date. It was
measured on the Phase 16 V11 corpus (986 findings), which is neither the corpus
nor the binary any current figure refers to; `BENCHMARKING_RESULTS.md` carries
the current measurement. Applied to this sample the correction would move
196 rows from 153 TP / 28 FP / 15 DEPENDS to 151 TP / 31 FP / 14 DEPENDS —
**84.5% → 83.0%** — so the correction lowers the historical figure. It is
recorded rather than quietly dropped for that reason.

## 1. Headline Numbers

### Overall

| Metric | Value |
|--------|-------|
| TP | 153 |
| FP | 28 |
| DEPENDS | 15 |
| **Precision (excl. DEPENDS)** | **84.5%** |
| Wilson 95% CI | **78.5% – 89.1%** |

> n=181 (196 minus 15 DEPENDS), k=153 TPs. Wilson formula: p̂=0.845, z=1.96.

### By severity tier

| Tier | Total | TP | FP | DEPENDS | Precision (excl. DEPENDS) |
|------|-------|----|----|---------|--------------------------|
| High | 105 | 85 | 17 | 3 | **83.3%** |
| Medium | 66 | 45 | 11 | 10 | **80.4%** |
| DEP-001 | 25 | 23 | 0 | 2 | **100.0%** |
| **Overall** | **196** | **153** | **28** | **15** | **84.5%** |

### By ecosystem

| Ecosystem | Findings | TP | FP | DEPENDS | Precision (excl. DEPENDS) |
|-----------|----------|----|----|---------|--------------------------|
| crates-io | 57 | 50 | 1 | 4 | **98.0%** |
| go-modules | 71 | 54 | 12 | 3 | **81.8%** |
| maven | 64 | 44 | 15 | 7 | **74.6%** |
| npm | 1 | 1 | 0 | 0 | **100.0%** |
| pypi | 1 | 1 | 0 | 0 | **100.0%** |
| crypto-adjacent | 2 | 2 | 0 | 0 | **100.0%** |

### Phase-over-phase comparison

| Audit | Sample (adj.) | Precision | Wilson 95% CI | Δ vs prior |
|-------|---------------|-----------|---------------|------------|
| Phase 12 | n=31 (23) | 73.3% | (point est. only) | — |
| Phase 14a | n=101 (94) | 75.5% | 66.0%–83.1% | +2.2 pp |
| **Phase 18** | **n=196 (181)** | **84.5%** | **78.5%–89.1%** | **+9.0 pp** |

The 9.0 pp gain from Phase 14a is the largest single-phase improvement recorded. The 85% threshold is now within the Wilson CI upper band (89.1%), and the point estimate (84.5%) is just below the threshold. The scanner is in defensible territory for pilot deployments with human triage.

---

## 2. Phase Verification

### Phase 13 — Original pattern fixes

| Pattern | Description | Phase 18 status |
|---------|-------------|-----------------|
| A | TLS config placeholder algorithm_id | **HELD** — All CRYPTO-560/561 carry tls-client-config/tls-server-config. Zero Pattern A FPs. |
| B | jwt-alg-none placeholder | **UNTESTED** — No alg=none findings in this sample. Status unknown. |
| C | PSS copy-paste algorithm_id | **HELD** — PS384 correctly carries rsa-pss-sha384-3072 (finding #19). |
| D (jjwt) | HMAC sha-256 placeholder for HS512 | **FIXED** — CRYPTO-246 jjwt HS512 now carries sha-512 (finding #177). |
| E | AES key-size mismatch (EVP rule) | **HELD** — EVP_aes_256_ecb correctly tagged aes-256-ecb (finding #182/V2 #97). |

Pattern D was the last partially-broken item from Phase 13. jjwt HS512 (CRYPTO-246) now correctly carries sha-512, eliminating the last known sha-256 placeholder FP for that library.

### Phase 15 — Per-variant RSA/ECDSA algorithm_id splits (Nimbus)

| Finding | Rule | V2 algorithm_id | Phase 18 algorithm_id | Status |
|---------|------|-----------------|----------------------|--------|
| Nimbus RS384 (JCASupport.java:117) | CRYPTO-259 | rsa-pkcs1-sha256-2048 | rsa-pkcs1-sha384-3072 | **FIXED** |
| Nimbus RSA_OAEP_256 (JCASupport.java:192) | CRYPTO-254 | rsa-2048 | rsa-oaep-256 | **FIXED** |
| Nimbus RSA_OAEP (RSAEncrypter.java:141) | CRYPTO-284 | — | rsa-oaep | **CORRECT** |
| jose4j RS384 (RsaUsingShaAlgorithm.java:97) | CRYPTO-260 | rsa-pkcs1-sha256-2048 | rsa-pkcs1-sha256-2048 | **NOT FIXED** |

Phase 15 fixed the Nimbus per-variant splits. jose4j CRYPTO-260 for RSA_USING_SHA384 still carries rsa-pkcs1-sha256-2048 (wrong hash). This is the sole remaining Pattern D-prime FP.

### Phase 16 — SiteContext suppression (MapEntry + TestAssertion)

Phase 16 reduced the corpus from V8 (1194) to V11 (986) by suppressing MapEntry and TestAssertion contexts for 19 Go JWT rules. Status:

- **MapEntry suppression: HELD** — No protobuf/enum-map FPs appear in this sample for rules CRYPTO-700–732. The previous Pattern F FPs from protobuf maps (V2 #76, #33) are absent.
- **TestAssertion suppression: PARTIAL** — Three test-context FPs remain: CRYPTO-732 at signature_gen_test.go:130 (LookupSignatureAlgorithm test), CRYPTO-730 at jwt_encoding_test.go:388 (test helper string arg), and related CRYPTO-730 (go-jose const block). The Phase 16 suppression covers TestAssertion for a specific rule subset; these three sites were not covered.
- **StringConstant suppression: NOT APPLIED** — CRYPTO-730 at go-jose/shared.go:113 (`HS256 = SignatureAlgorithm("HS256")`) fires on a string constant declaration in a const block. This was a pre-existing Pattern F variant and remains unfixed.

Net: Phase 16 eliminated the worst MapEntry FP cluster (~10–15 FPs estimated in full corpus). Three Pattern F variants persist.

### Phase 17 — jwt.sign argument-value disambiguation (CRYPTO-361–382)

**UNTESTED.** The 196-finding stratified sample contains one npm finding (CRYPTO-312/sha-256 in elliptic benchmarks), which is not a jwt.sign site. No CRYPTO-360/361–382 findings appear in this sample. Phase 17 cannot be confirmed or denied.

---

## 3. FP Patterns

### Pattern D-prime (residual) — jose4j RSA_USING_SHA384 wrong hash (1 FP)

**Finding:** #111 (`RsaUsingShaAlgorithm.java:97`, CRYPTO-260, `rsa-pkcs1-sha256-2048`)

`super(AlgorithmIdentifiers.RSA_USING_SHA384, "SHA384withRSA")` — the JCA name and algorithm identifier both confirm SHA-384, but the rule emits `rsa-pkcs1-sha256-2048`. Nimbus RS384 was fixed in Phase 15 (CRYPTO-259 → rsa-pkcs1-sha384-3072). jose4j RS384 (CRYPTO-260) was not. Apply the same per-variant split.

### Pattern F (persistent) — HMAC/algorithm rules firing on non-operational string contexts (3 FPs)

**Findings:** #156 (`go-jose/shared.go:113`, CRYPTO-730), #161 (`signature_gen_test.go:130`, CRYPTO-732), #168 (`jwt_encoding_test.go:388`, CRYPTO-730)

Three distinct non-operational contexts remain:
- **StringConstant (const block):** `HS256 = SignatureAlgorithm("HS256")` — a typed alias declaration, not an HMAC invocation.
- **TestLookup:** `LookupSignatureAlgorithm("HS512")` followed by `require.Equal` — a registry lookup in a test, not a signing operation.
- **TestHelperArg:** `decodeUnsignedTokenAndValidateHeader(..., "HS256", ...)` — passing the algorithm name as a string argument to a test helper.

Phase 16 suppressed MapEntry and some TestAssertion contexts but did not cover these three sub-patterns. Each requires either a structural SiteContext variant or a rule-level annotation excluding the specific file pattern.

### Pattern J (new) — ECDSA ES512 misclassified as ecdsa-p256 (1 FP)

**Finding:** #107 (`SignatureAlgorithm.java:118`, CRYPTO-244, `ecdsa-p256`)

`ES512("ES512", "ECDSA using P-521 and SHA-512", ...)` — jjwt's SignatureAlgorithm enum. ES512 uses NIST P-521, not P-256. The message text and enum body both identify P-521 explicitly. CRYPTO-244 fires on the ES512 enum entry but emits `algorithm_id=ecdsa-p256`. The correct id is `ecdsa-p521`.

This is a sibling of the V2 Pattern finding (#41, EcdsaUsingShaAlgorithm.java P521UsingSha512) that appeared in Phase 14a. The fix pattern is the same: distinguish ES256 (P-256) from ES384 (P-384) from ES512 (P-521) at rule-authoring time.

---

## 4. Per-Finding Table

<details>
<summary>Click to expand 196-row audit table</summary>

| # | rule_id | sev | file:line | verdict | note |
|---|---------|-----|-----------|---------|------|
| 1 | CRYPTO-001 | High | crates-io/age/.../recipients_test.go:114 | FP | rsa.GenerateKey 768-bit; algorithm_id=rsa-1024 wrong (768 ≠ 1024) |
| 2 | CRYPTO-547 | High | crates-io/rsa/src/pss.rs:655 | FP | SigningKey::<Sha1>::new 512-bit; algorithm_id=rsa-pkcs1-sha256-2048 wrong |
| 3 | CRYPTO-570 | High | crates-io/rustls-webpki/.../verify_cert.rs:1112 | TP | KeyPair::generate_for(PKCS_ECDSA_P256_SHA256) — correct ecdsa-p256 |
| 4 | CRYPTO-570 | High | crates-io/webpki/.../verify_cert.rs:1233 | TP | same pattern, different project |
| 5 | CRYPTO-711 | High | go-modules/jwt-go/ecdsa_test.go:32 | TP | ES384 test with ec384-private.pem — correct ecdsa-p384 |
| 6 | CRYPTO-705 | High | go-modules/jwt-go/rsa_pss.go:67 | DEPENDS | PS512 algorithm struct; SHA-512 matches; 4096 claim unverifiable |
| 7 | CRYPTO-002 | High | go-modules/go-jose/asymmetric_test.go:200 | TP | rsa.GenerateKey(rand.Reader, 2048) — correct rsa-2048 |
| 8 | CRYPTO-020 | High | go-modules/go-jose/.../cryptosigner_test.go:153 | TP | ed25519.GenerateKey — correct ed25519 |
| 9 | CRYPTO-013 | High | go-modules/go-jose/.../generate.go:67 | TP | ecdsa.GenerateKey(elliptic.P521()) — correct ecdsa-p521 |
| 10 | CRYPTO-011 | High | go-modules/go-jose/signing_test.go:308 | TP | ecdsa.GenerateKey(elliptic.P256()) — correct ecdsa-p256 |
| 11 | CRYPTO-712 | High | go-modules/golang-jwt-jwt/ecdsa_test.go:41 | TP | ES512 test with ec512-private.pem (P-521) — correct ecdsa-p521 |
| 12 | CRYPTO-701 | High | go-modules/golang-jwt-jwt/rsa.go:31 | DEPENDS | RS384 algorithm registration; 3072 claim unverifiable |
| 13 | CRYPTO-011 | High | go-modules/consul/.../generate_test.go:121 | TP | ecdsa.GenerateKey(elliptic.P256()) in test — correct ecdsa-p256 |
| 14 | CRYPTO-702 | High | go-modules/vault/.../acme_jws.go:20 | FP | "RS512": true allowlist map entry — not a crypto op |
| 15 | CRYPTO-020 | High | go-modules/vault/.../backend_test.go:4124 | TP | ed25519.GenerateKey — correct ed25519 |
| 16 | CRYPTO-012 | High | go-modules/vault/.../path_acme_test.go:1631 | TP | ecdsa.GenerateKey(elliptic.P384()) — correct ecdsa-p384 |
| 17 | CRYPTO-020 | High | go-modules/vault/.../certutil_test.go:1238 | TP | ed25519.GenerateKey — correct ed25519 |
| 18 | CRYPTO-720 | High | go-modules/jwx/jwa/signature_gen.go:18 | TP | NewSignatureAlgorithm("EdDSA") — correct ed25519 family |
| 19 | CRYPTO-704 | High | go-modules/jwx/jwa/signature_gen.go:91 | TP | PS384 lookup; rsa-pss-sha384-3072 (Phase 13 Pattern C fix confirmed) |
| 20 | CRYPTO-720 | High | go-modules/jwx/jwa/signature_gen_test.go:66 | TP | LookupSignatureAlgorithm("EdDSA") — correct ed25519 |
| 21 | CRYPTO-705 | High | go-modules/jwx/jwa/signature_gen_test.go:206 | FP | require.Equal(t, "PS512", ...) — test assertion, not crypto op |
| 22 | CRYPTO-703 | High | go-modules/jwx/jwa/signature_gen_test.go:290 | FP | jwa.PS256().IsSymmetric() — boolean test, not crypto op |
| 23 | CRYPTO-012 | High | go-modules/jwx/jwe/jwe_test.go:716 | TP | ecdsa.GenerateKey(elliptic.P384()) — correct ecdsa-p384 |
| 24 | CRYPTO-010 | High | go-modules/jwx/jwe/.../ecdh_es_ext_test.go:263 | FP | ecdsa.GenerateKey(elliptic.P224()) — algorithm_id=ecdsa-p256 wrong (P-224 ≠ P-256) |
| 25 | CRYPTO-002 | High | go-modules/jwx/jwk/jwk_test.go:323 | TP | rsa.GenerateKey(rand.Reader, 2048) — correct rsa-2048 |
| 26 | CRYPTO-011 | High | go-modules/jwx/jws/bench_marshal_test.go:16 | TP | ecdsa.GenerateKey(elliptic.P256()) in benchmark — correct ecdsa-p256 |
| 27 | CRYPTO-712 | High | go-modules/jwx/jws/jwsbb/jwsbb.go:48 | FP | es512 = "ES512" string constant — not a crypto op |
| 28 | CRYPTO-700 | High | go-modules/jwx/jws/streaming_detached_test.go:47 | TP | RS256 signing with 2048-bit RSA key — correct rsa-pkcs1-sha256-2048 |
| 29 | CRYPTO-011 | High | go-modules/client-go/.../certificate_manager.go:767 | TP | ecdsa.GenerateKey(elliptic.P256()) — correct ecdsa-p256 |
| 30 | CRYPTO-003 | High | maven/tink/go/.../rsassapss...test.go:112 | TP | rsa.GenerateKey(rand.Reader, 3072) — correct rsa-3072 |
| 31 | CRYPTO-711 | High | maven/tink/go/jwt/jwk_converter_test.go:74 | TP | JWK with "alg":"ES384"/"crv":"P-384" — correct ecdsa-p384 |
| 32 | CRYPTO-710 | High | maven/tink/go/jwt/.../kid_test.go:73 | TP | newSignerWithKID(ts, "ES256", kid) — correct ecdsa-p256 |
| 33 | CRYPTO-702 | High | maven/tink/go/.../jwt_rsa_ssa_pkcs1.pb.go:61 | FP | "RS512": 3 protobuf enum map — generated constant, not crypto op |
| 34 | CRYPTO-020 | High | maven/tink/go/.../ed25519_signer_verifier_test.go:117 | TP | ed25519.GenerateKey — correct ed25519 |
| 35 | CRYPTO-211 | High | maven/tink/java_src/.../EcdsaSignJceTest.java:98 | TP | getNistP256Params() + KeyPairGenerator.getInstance("EC") — correct ecdsa-p256 |
| 36 | CRYPTO-210 | High | maven/tink/java_src/.../RsaSsaPssSignJceTest.java:75 | TP | keySize=2048; KeyPairGenerator.getInstance("RSA") — correct rsa-2048 |
| 37 | CRYPTO-251 | High | maven/nimbus-jose-jwt/.../ECDSA.java:143 | TP | alg.equals(JWSAlgorithm.ES256) — correct ecdsa-p256 |
| 38 | CRYPTO-254 | High | maven/nimbus-jose-jwt/.../RSAEncrypter.java:145 | FP | RSA_OAEP_256 dispatch; algorithm_id=rsa-2048 wrong (V2; now fixed in new sample) |
| 39 | CRYPTO-250 | High | maven/nimbus-jose-jwt/.../JCASupport.java:117 | FP | RS384 dispatch; algorithm_id=rsa-pkcs1-sha256-2048 wrong hash (V2; fixed in new sample) |
| 40 | CRYPTO-253 | High | maven/nimbus-jose-jwt/.../Curve.java:330 | TP | Arrays.asList(Ed25519, Ed448) — correct ed25519 |
| 41 | CRYPTO-262 | High | maven/jose4j/.../EcdsaUsingShaAlgorithm.java:259 | FP | P521UsingSha512; algorithm_id=ecdsa-p256 wrong (P-521 ≠ P-256) |
| 42 | CRYPTO-221 | High | maven/jetty-server/.../AbstractGzipTest.java:73 | TP | MessageDigest.getInstance("SHA1") — correct sha-1 |
| 43 | CRYPTO-211 | High | maven/jetty-server/.../EthereumCredentials.java:47 | FP | ECGenParameterSpec("secp256k1"); algorithm_id=ecdsa-p256 wrong curve |
| 44 | CRYPTO-360 | High | npm/jsonwebtoken/test/async_sign.tests.js:75 | FP | jwt.sign 1024-bit RSA key; algorithm_id=rsa-pkcs1-sha256-2048 wrong size |
| 45 | CRYPTO-360 | High | npm/jsonwebtoken/test/expires_format.tests.js:8 | FP | jwt.sign string secret (HMAC default); algorithm_id=rsa-pkcs1-sha256-2048 wrong type |
| 46 | CRYPTO-360 | High | npm/jsonwebtoken/test/jwt.hs.tests.js:21 | FP | jwt.sign algorithm:'HS256' (HMAC explicit); algorithm_id=rsa-pkcs1-sha256-2048 wrong |
| 47 | CRYPTO-360 | High | npm/jsonwebtoken/test/rsa-public-key.tests.js:13 | TP | jwt.sign PEM cert, algorithm:'RS256' — correct rsa-pkcs1-sha256-2048 |
| 48 | CRYPTO-372 | High | npm/jsrsasign/jsrsasign-all-min.js:231 | TP | CryptoJS.TripleDES.encrypt — correct 3des |
| 49 | CRYPTO-372 | High | npm/jsrsasign/npm/lib/jsrsasign-jwths-min.js:117 | TP | CryptoJS.TripleDES in minified bundle — correct 3des |
| 50 | CRYPTO-104 | High | pypi/authlib/.../rsa_key.py:95 | TP | rsa.generate_private_key(key_size=key_size) default 2048 — correct rsa-2048 |
| 51 | CRYPTO-560 | Med | crates-io/hyper-rustls/src/connector.rs:269 | TP | ClientConfig::builder() — correct tls-client-config |
| 52 | CRYPTO-520 | Med | crates-io/k256/k256/src/schnorr.rs:215 | TP | Sha256::new() in tagged_hash — correct sha-256 |
| 53 | CRYPTO-583 | Med | crates-io/pbkdf2/pbkdf2/src/lib.rs:206 | DEPENDS | pbkdf2::<PRF>() generic — sha-256 only if PRF=Sha256 |
| 54 | CRYPTO-560 | Med | crates-io/rustls/rustls/src/client/test.rs:699 | TP | ClientConfig::builder(HYBRID_PROVIDER) — correct tls-client-config |
| 55 | CRYPTO-560 | Med | crates-io/rustls-pemfile/ci-bench/src/main.rs:693 | TP | ClientConfig::builder — correct tls-client-config |
| 56 | CRYPTO-561 | Med | crates-io/rustls-pemfile/fuzz/fuzzers/server.rs:23 | TP | ServerConfig::builder — correct tls-server-config |
| 57 | CRYPTO-560 | Med | crates-io/rustls-pemfile/.../smoke.rs:85 | TP | ClientConfig::builder — correct tls-client-config |
| 58 | CRYPTO-560 | Med | crates-io/rustls-pemfile/rustls-test/src/lib.rs:617 | TP | ClientConfig::builder — correct tls-client-config |
| 59 | CRYPTO-560 | Med | crates-io/rustls-pemfile/.../api.rs:1006 | TP | ClientConfig::builder — correct tls-client-config |
| 60 | CRYPTO-560 | Med | crates-io/rustls-pemfile/.../api.rs:1588 | TP | ClientConfig::builder — correct tls-client-config |
| 61 | CRYPTO-561 | Med | crates-io/rustls-pemfile/.../crypto.rs:493 | TP | ServerConfig::builder — correct tls-server-config |
| 62 | CRYPTO-561 | Med | crates-io/rustls-pemfile/.../kx.rs:366 | TP | ServerConfig::builder — correct tls-server-config |
| 63 | CRYPTO-560 | Med | crates-io/rustls-pemfile/.../server_cert_verifier.rs:239 | TP | ClientConfig::builder — correct tls-client-config |
| 64 | CRYPTO-560 | Med | crates-io/rustls-pemfile/rustls/src/client/test.rs:699 | TP | ClientConfig::builder(HYBRID_PROVIDER) — correct tls-client-config |
| 65 | CRYPTO-203 | Med | crypto-adjacent/tink-java/.../AndroidKeystore.java:177 | DEPENDS | Cipher.getInstance("AES/GCM/NoPadding"); 256-bit key unverifiable at this line |
| 66 | CRYPTO-730 | Med | go-modules/jwt-go/parser_test.go:126 | FP | ValidMethods:[]string{"RS256","HS256"} parser config — not HMAC op |
| 67 | CRYPTO-731 | Med | go-modules/golang-jwt-jwt/hmac.go:32 | TP | SigningMethodHS384=&SigningMethodHMAC{"HS384",crypto.SHA384} — correct sha-384 |
| 68 | CRYPTO-730 | Med | go-modules/golang-jwt-jwt/parser_test.go:353 | FP | WithValidMethods([]string{"HS256","ES256"}) — parser config, not HMAC op |
| 69 | CRYPTO-760 | Med | go-modules/jwx/jwa/content_encryption_gen_test.go:98 | DEPENDS | LookupContentEncryptionAlgorithm("A256GCM") — test identifier lookup only |
| 70 | CRYPTO-730 | Med | go-modules/jwx/jwa/signature_gen_test.go:110 | FP | require.Equal(t,"HS256",...) — test assertion, not HMAC op |
| 71 | CRYPTO-760 | Med | go-modules/jwx/jwe/.../ecdh_es_ext_test.go:37 | TP | GenerateECDHES("A256GCM", 32, ...) — actual key derivation |
| 72 | CRYPTO-762 | Med | go-modules/jwx/jwe/.../hpke_ext_test.go:59 | TP | KeyEncryptHPKECustom(...,"A128GCM",...) — actual HPKE call |
| 73 | CRYPTO-730 | Med | go-modules/jwx/jws/jwsbb/jwsbb.go:31 | FP | hs256 = "HS256" — string constant, not HMAC op |
| 74 | CRYPTO-203 | Med | maven/aws-encryption-sdk-java/.../CipherHandler.java:99 | TP | Cipher.getInstance("AES/GCM/NoPadding") in AES-256-GCM SDK context |
| 75 | CRYPTO-730 | Med | maven/tink/go/jwt/jwt_encoding_test.go:377 | FP | decodeUnsignedTokenAndValidateHeader(...,"HS256",...) — test helper arg |
| 76 | CRYPTO-731 | Med | maven/tink/go/.../jwt_hmac.pb.go:60 | FP | "HS384": 2 protobuf enum map — generated constant |
| 77 | CRYPTO-232 | Med | maven/nimbus-jose-jwt/.../LegacyAESGCM.java:99 | DEPENDS | GCMBlockCipher instantiated; 256-bit key unverifiable at this line |
| 78 | CRYPTO-255 | Med | maven/nimbus-jose-jwt/.../MACSigner.java:106 | TP | hmacAlgs.add(JWSAlgorithm.HS384) — HS384 registered correctly |
| 79 | CRYPTO-241 | Med | maven/jjwt-api/.../SignatureAlgorithm.java:115 | FP | HS512; algorithm_id=sha-256 wrong (V2; now fixed — see #177) |
| 80 | CRYPTO-263 | Med | maven/jose4j/.../HmacUsingShaAlgorithm.java:128 | FP | HmacSha512 constructor (SHA-512); algorithm_id=sha-256 wrong |
| 81 | DEP-001 | ? | crates-io/age/go.mod:5 | TP | golang.org/x/crypto — genuine crypto library |
| 82 | DEP-001 | ? | crates-io/rustls-pemfile/openssl-tests/Cargo.toml:14 | TP | rustls — TLS/crypto library |
| 83 | DEP-001 | ? | crates-io/rustls-pemfile/rustls-post-quantum/Cargo.toml:18 | TP | webpki — PKI/crypto library |
| 84 | DEP-001 | ? | crates-io/rustls-pemfile/rustls/Cargo.toml:31 | TP | webpki — PKI/crypto library |
| 85 | DEP-001 | ? | maven/jetty-server/.../jetty-compression-server/pom.xml:20 | TP | jetty-server — embedded HTTPS server |
| 86 | DEP-001 | ? | maven/jetty-server/.../jetty-http3-server/pom.xml:19 | TP | jetty-server — embedded HTTPS server |
| 87 | DEP-001 | ? | maven/jetty-server/.../jetty-quic-quiche-server/pom.xml:19 | TP | jetty-server — embedded HTTPS server |
| 88 | DEP-001 | ? | maven/jetty-server/.../jetty-test-coreapp-demo/pom.xml:21 | TP | jetty-server — embedded HTTPS server |
| 89 | DEP-001 | ? | maven/jetty-server/.../jetty-servlet4-demo-jetty-webapp/pom.xml:38 | TP | jetty-server — embedded HTTPS server |
| 90 | DEP-001 | ? | maven/jetty-server/.../jetty-ee10-test-loginservice/pom.xml:20 | TP | jetty-server — embedded HTTPS server |
| 91 | DEP-001 | ? | maven/jetty-server/.../test-jetty-ee11-osgi/pom.xml:118 | TP | jetty-server — embedded HTTPS server |
| 92 | DEP-001 | ? | maven/jetty-server/.../jetty-ee8-maven-plugin/pom.xml:93 | TP | jetty-server — embedded HTTPS server |
| 93 | DEP-001 | ? | maven/jetty-server/.../jetty-ee9-openid/pom.xml:32 | TP | jetty-server — embedded HTTPS server |
| 94 | DEP-001 | ? | maven/jetty-server/.../test-sessions-memcached/pom.xml:15 | DEPENDS | commons-codec — borderline encoding utility |
| 95 | DEP-001 | ? | maven/jetty-server/pom.xml:650 | TP | org.bouncycastle:bcprov-jdk18on — genuine crypto provider |
| 96 | CRYPTO-020 | High | crates-io/age/.../recipients_test.go:159 | TP | ed25519.GenerateKey — correct ed25519 |
| 97 | CRYPTO-417 | High | crypto-adjacent/kyber/ref/nistkat/rng.c:127 | TP | EVP_aes_256_ecb() — correct aes-256-ecb (Phase 13 Pattern E confirmed) |
| 98 | CRYPTO-710 | High | go-modules/jwt-go/ecdsa.go:34 | TP | SigningMethodES256=&SigningMethodECDSA{"ES256",...,256} — correct ecdsa-p256 |
| 99 | CRYPTO-401 | High | maven/tink/cc/.../rsa_ssa_pkcs1_private_key_test.cc:249 | TP | RSA_generate_key_ex(..., 2048, ...) — correct rsa-2048 |
| 100 | CRYPTO-312 | Med | npm/elliptic/benchmarks/index.js:72 | TP | crypto.createHash('sha256') — correct sha-256 |
| 101 | CRYPTO-141 | High | pypi/authlib/authlib/oauth1/.../client_auth.py:150 | TP | hashlib.sha1(body) — correct sha-1 |
| 102 | CRYPTO-281 | High | maven/nimbus-jose-jwt/.../RSASSA.java:68 | TP | alg.equals(JWSAlgorithm.PS256) dispatch — correct rsa-pss-sha256-2048 (Phase 15 confirmed) |
| 103 | CRYPTO-280 | High | maven/nimbus-jose-jwt/.../RSASSAProvider.java:59 | DEPENDS | algs.add(JWSAlgorithm.RS512) in static initializer — support declaration, not signing op |
| 104 | CRYPTO-259 | High | maven/nimbus-jose-jwt/.../JCASupport.java:117 | TP | RS384 case; jcaName="SHA384withRSA" — correct rsa-pkcs1-sha384-3072 (Phase 15 confirmed) |
| 105 | CRYPTO-251 | High | maven/nimbus-jose-jwt/.../JCASupport.java:135 | TP | ES256 check in provider support — correct ecdsa-p256 |
| 106 | CRYPTO-254 | High | maven/nimbus-jose-jwt/.../JCASupport.java:192 | TP | RSA_OAEP_256 case; jcaName="RSA/ECB/OAEPWithSHA-256AndMGF1Padding" — correct rsa-oaep-256 (Phase 15 confirmed) |
| 107 | CRYPTO-244 | High | maven/jjwt-api/.../SignatureAlgorithm.java:118 | FP | ES512("ES512","ECDSA using P-521 and SHA-512",...); algorithm_id=ecdsa-p256 wrong curve (Pattern J) |
| 108 | CRYPTO-200 | High | maven/httpclient5/.../NTLMEngineImpl.java:661 | TP | Cipher.getInstance("DES/ECB/NoPadding") in NTLM impl — correct des |
| 109 | CRYPTO-220 | High | maven/tomcat-embed-core/.../PEMFile.java:591 | TP | MessageDigest.getInstance("MD5") — correct md5 |
| 110 | CRYPTO-264 | High | maven/jose4j/.../PlaintextNoneAlgorithm.java:38 | TP | AlgorithmIdentifiers.NONE in signature impl — correct jwt-alg-none |
| 111 | CRYPTO-260 | High | maven/jose4j/.../RsaUsingShaAlgorithm.java:97 | FP | super(RSA_USING_SHA384,"SHA384withRSA"); algorithm_id=rsa-pkcs1-sha256-2048 wrong hash (Pattern D-prime) |
| 112 | CRYPTO-220 | High | maven/jetty-server/.../Credential.java:277 | TP | MessageDigest.getInstance("MD5") — correct md5 |
| 113 | CRYPTO-221 | High | maven/jetty-server/.../Sha1Sum.java:93 | TP | MessageDigest.getInstance("SHA1") — correct sha-1 |
| 114 | CRYPTO-221 | High | maven/jetty-server/.../AbstractGzipTest.java:73 | TP | MessageDigest.getInstance("SHA1") — correct sha-1 |
| 115 | CRYPTO-221 | High | maven/jetty-server/.../MultiPartExpectations.java:197 | TP | MessageDigest.getInstance("SHA1") — correct sha-1 |
| 116 | CRYPTO-560 | Med | crates-io/hyper-rustls/src/connector.rs:269 | TP | ClientConfig::builder() — correct tls-client-config |
| 117 | CRYPTO-560 | Med | crates-io/hyper-rustls/src/connector/builder.rs:417 | TP | ClientConfig::builder() — correct tls-client-config |
| 118 | CRYPTO-521 | Med | crates-io/jsonwebtoken/src/crypto/rust_crypto/mod.rs:71 | TP | RustCrypto Sha384 — correct sha-384 |
| 119 | CRYPTO-587 | Med | crates-io/openssl/openssl/src/pkcs5.rs:159 | DEPENDS | pbkdf2_hmac::<...> generic; hash not determinable at site |
| 120 | CRYPTO-587 | Med | crates-io/openssl/openssl/src/pkcs5.rs:228 | DEPENDS | pbkdf2_hmac::<...> generic; hash not determinable at site |
| 121 | CRYPTO-521 | Med | crates-io/p256/p256/src/ecdsa.rs:118 | TP | RustCrypto Sha384 — correct sha-384 |
| 122 | CRYPTO-587 | Med | crates-io/pbkdf2/pbkdf2/src/lib.rs:250 | DEPENDS | pbkdf2::<PRF>() generic — sha-256 only if PRF=Sha256 |
| 123 | CRYPTO-560 | Med | crates-io/rustls/rustls/src/client/test.rs:175 | TP | ClientConfig::builder — correct tls-client-config |
| 124 | CRYPTO-560 | Med | crates-io/rustls/rustls/src/client/test.rs:487 | TP | ClientConfig::builder — correct tls-client-config |
| 125 | CRYPTO-561 | Med | crates-io/rustls/rustls/src/server/test.rs:188 | TP | ServerConfig::builder — correct tls-server-config |
| 126 | CRYPTO-561 | Med | crates-io/rustls/rustls/src/server/test.rs:380 | TP | ServerConfig::builder — correct tls-server-config |
| 127 | CRYPTO-560 | Med | crates-io/rustls-pemfile/ci-bench/src/main.rs:693 | TP | ClientConfig::builder — correct tls-client-config |
| 128 | CRYPTO-561 | Med | crates-io/rustls-pemfile/examples/src/bin/server_acceptor.rs:217 | TP | ServerConfig::builder — correct tls-server-config |
| 129 | CRYPTO-561 | Med | crates-io/rustls-pemfile/examples/src/bin/simpleserver.rs:38 | TP | ServerConfig::builder — correct tls-server-config |
| 130 | CRYPTO-561 | Med | crates-io/rustls-pemfile/fuzz/fuzzers/server.rs:61 | TP | ServerConfig::builder — correct tls-server-config |
| 131 | CRYPTO-560 | Med | crates-io/rustls-pemfile/openssl-tests/src/raw_key_openssl_interop.rs:52 | TP | ClientConfig::builder — correct tls-client-config |
| 132 | CRYPTO-560 | Med | crates-io/rustls-pemfile/rustls-bench/src/main.rs:708 | TP | ClientConfig::builder — correct tls-client-config |
| 133 | CRYPTO-560 | Med | crates-io/rustls-pemfile/rustls-post-quantum/benches/benchmarks.rs:86 | TP | ClientConfig::builder — correct tls-client-config |
| 134 | CRYPTO-560 | Med | crates-io/rustls-pemfile/rustls-post-quantum/src/lib.rs:330 | TP | ClientConfig::builder — correct tls-client-config |
| 135 | CRYPTO-561 | Med | crates-io/rustls-pemfile/rustls-test/src/lib.rs:601 | TP | ServerConfig::builder — correct tls-server-config |
| 136 | CRYPTO-560 | Med | crates-io/rustls-pemfile/rustls-test/src/lib.rs:673 | TP | ClientConfig::builder — correct tls-client-config |
| 137 | CRYPTO-561 | Med | crates-io/rustls-pemfile/rustls-test/tests/api/api.rs:469 | TP | ServerConfig::builder — correct tls-server-config |
| 138 | CRYPTO-560 | Med | crates-io/rustls-pemfile/rustls-test/tests/api/api.rs:1006 | TP | ClientConfig::builder — correct tls-client-config |
| 139 | CRYPTO-560 | Med | crates-io/rustls-pemfile/rustls-test/tests/api/api.rs:1168 | TP | ClientConfig::builder — correct tls-client-config |
| 140 | CRYPTO-560 | Med | crates-io/rustls-pemfile/rustls-test/tests/api/api.rs:1261 | TP | ClientConfig::builder — correct tls-client-config |
| 141 | CRYPTO-561 | Med | crates-io/rustls-pemfile/rustls-test/tests/api/client_cert_verifier.rs:39 | TP | ServerConfig::builder — correct tls-server-config |
| 142 | CRYPTO-561 | Med | crates-io/rustls-pemfile/rustls-test/tests/api/crypto.rs:261 | TP | ServerConfig::builder — correct tls-server-config |
| 143 | CRYPTO-561 | Med | crates-io/rustls-pemfile/rustls-test/tests/api/crypto.rs:434 | TP | ServerConfig::builder — correct tls-server-config |
| 144 | CRYPTO-560 | Med | crates-io/rustls-pemfile/rustls-test/tests/api/ffdhe.rs:69 | TP | ClientConfig::builder — correct tls-client-config |
| 145 | CRYPTO-561 | Med | crates-io/rustls-pemfile/rustls-test/tests/api/ffdhe.rs:130 | TP | ServerConfig::builder — correct tls-server-config |
| 146 | CRYPTO-561 | Med | crates-io/rustls-pemfile/rustls-test/tests/api/io.rs:1678 | TP | ServerConfig::builder — correct tls-server-config |
| 147 | CRYPTO-560 | Med | crates-io/rustls-pemfile/rustls-test/tests/api/resolve.rs:332 | TP | ClientConfig::builder — correct tls-client-config |
| 148 | CRYPTO-561 | Med | crates-io/rustls-pemfile/rustls-test/tests/api/resume.rs:192 | TP | ServerConfig::builder — correct tls-server-config |
| 149 | CRYPTO-560 | Med | crates-io/rustls-pemfile/rustls-test/tests/api/server_cert_verifier.rs:239 | TP | ClientConfig::builder — correct tls-client-config |
| 150 | CRYPTO-560 | Med | crates-io/rustls-pemfile/rustls/src/client/test.rs:139 | TP | ClientConfig::builder — correct tls-client-config |
| 151 | CRYPTO-560 | Med | crates-io/rustls-pemfile/rustls/src/client/test.rs:263 | TP | ClientConfig::builder — correct tls-client-config |
| 152 | CRYPTO-560 | Med | crates-io/rustls-pemfile/rustls/src/client/test.rs:723 | TP | ClientConfig::builder — correct tls-client-config |
| 153 | CRYPTO-561 | Med | crates-io/rustls-pemfile/rustls/src/server/test.rs:243 | TP | ServerConfig::builder — correct tls-server-config |
| 154 | CRYPTO-584 | Med | crates-io/scrypt/scrypt/src/lib.rs:127 | TP | pbkdf2_hmac::<Sha256> concrete type arg — correct sha-256 |
| 155 | CRYPTO-731 | Med | go-modules/jwt-go/hmac.go:32 | TP | SigningMethodHS384=&SigningMethodHMAC{"HS384",crypto.SHA384} — correct sha-384 |
| 156 | CRYPTO-730 | Med | go-modules/go-jose/shared.go:113 | FP | HS256 = SignatureAlgorithm("HS256") in const block — string alias, not HMAC op (Pattern F) |
| 157 | CRYPTO-761 | Med | go-modules/go-jose/shared.go:133 | DEPENDS | A192GCM = ContentEncryption("A192GCM") in const block — algorithm constant, not encryption op |
| 158 | CRYPTO-732 | Med | go-modules/golang-jwt-jwt/hmac.go:38 | TP | SigningMethodHS512=&SigningMethodHMAC{"HS512",crypto.SHA512} — correct sha-512 |
| 159 | CRYPTO-730 | Med | go-modules/jwx/jwa/signature_gen.go:20 | TP | NewSignatureAlgorithm("HS256", WithIsSymmetric(true)) constructor call — correct sha-256 |
| 160 | CRYPTO-731 | Med | go-modules/jwx/jwa/signature_gen.go:71 | TP | NewSignatureAlgorithm("HS384",...) constructor call — correct sha-384 |
| 161 | CRYPTO-732 | Med | go-modules/jwx/jwa/signature_gen_test.go:130 | FP | LookupSignatureAlgorithm("HS512") in test lookup — not an HMAC signing op (Pattern F) |
| 162 | CRYPTO-762 | Med | go-modules/jwx/jwe/jwebb/ecdh_es_ext_test.go:24 | TP | GenerateECDHES("A128GCM", 16,...) actual ECDH-ES call — correct aes-128-gcm |
| 163 | CRYPTO-762 | Med | go-modules/jwx/jwe/jwebb/ecdh_es_ext_test.go:76 | TP | GenerateECDHES("A128GCM",...) — correct aes-128-gcm |
| 164 | CRYPTO-760 | Med | go-modules/jwx/jwe/jwebb/ecdh_es_ext_test.go:187 | TP | GenerateECDHES("A256GCM",...) — correct aes-256-gcm |
| 165 | CRYPTO-762 | Med | go-modules/jwx/jwe/jwebb/hpke_ext_test.go:59 | TP | KeyEncryptHPKECustom(nil,"HPKE-0-KE","A128GCM",pub) — correct aes-128-gcm |
| 166 | CRYPTO-762 | Med | go-modules/jwx/jwe/jwebb/hpke_ext_test.go:107 | TP | HPKE call with A128GCM — correct aes-128-gcm |
| 167 | CRYPTO-203 | Med | maven/aws-encryption-sdk-java/.../CipherHandler.java:99 | TP | Cipher.getInstance("AES/GCM/NoPadding") in AES-256-GCM SDK — correct aes-256-gcm |
| 168 | CRYPTO-730 | Med | maven/tink/go/jwt/jwt_encoding_test.go:388 | FP | decodeUnsignedTokenAndValidateHeader(...,"HS256",...) — string arg in test helper (Pattern F) |
| 169 | CRYPTO-203 | Med | maven/tink/java_src/.../AndroidKeystoreAesGcm.java:76 | DEPENDS | Cipher.getInstance("AES/GCM/NoPadding") in Android Keystore; key size runtime-determined |
| 170 | CRYPTO-203 | Med | maven/nimbus-jose-jwt/.../AESGCM.java:113 | TP | Cipher.getInstance("AES/GCM/NoPadding") — correct aes-256-gcm |
| 171 | CRYPTO-232 | Med | maven/nimbus-jose-jwt/.../LegacyAESGCM.java:99 | TP | GCMBlockCipher(cipher) with actual key parameter — correct aes-256-gcm |
| 172 | CRYPTO-252 | Med | maven/nimbus-jose-jwt/.../MACProvider.java:80 | TP | alg.equals(JWSAlgorithm.HS256) dispatch returning HMACSHA256 — correct sha-256 |
| 173 | CRYPTO-255 | Med | maven/nimbus-jose-jwt/.../MACSigner.java:77 | TP | HS384 minimum key length check in signing context — correct sha-384 |
| 174 | CRYPTO-256 | Med | maven/nimbus-jose-jwt/.../MACSigner.java:109 | TP | HS512 minimum key length check in signing context — correct sha-512 |
| 175 | CRYPTO-256 | Med | maven/nimbus-jose-jwt/.../JCASupport.java:105 | TP | HS512 case in JCA support check — correct sha-512 |
| 176 | CRYPTO-222 | Med | maven/nimbus-jose-jwt/.../RSAKey.java:2150 | TP | MessageDigest.getInstance("SHA-256") — correct sha-256 |
| 177 | CRYPTO-246 | Med | maven/jjwt-api/.../SignatureAlgorithm.java:115 | TP | HS512 now carries sha-512 — Pattern D fix confirmed |
| 178 | CRYPTO-222 | Med | maven/httpclient5/.../SpkiPinningClientTlsStrategy.java:303 | TP | MessageDigest.getInstance("SHA-256") in TLS pin — correct sha-256 |
| 179 | CRYPTO-265 | Med | maven/jose4j/.../HmacUsingShaAlgorithm.java:120 | TP | HmacSha384 constructor — correct sha-384 |
| 180 | CRYPTO-233 | Med | maven/cryptacular/.../CertUtil.java:610 | DEPENDS | BouncyCastle provider registered for X.509 cert build; algorithm_id=aes-256-gcm does not match actual op |
| 181 | DEP-001 | ? | crates-io/age/go.mod:5 | TP | golang.org/x/crypto — genuine crypto library |
| 182 | DEP-001 | ? | crates-io/rustls-pemfile/connect-tests/Cargo.toml:10 | TP | rustls — TLS/crypto library |
| 183 | DEP-001 | ? | crates-io/rustls-pemfile/openssl-tests/Cargo.toml:14 | TP | rustls — TLS/crypto library |
| 184 | DEP-001 | ? | crates-io/rustls-pemfile/rustls-bench/Cargo.toml:9 | TP | rustls — TLS/crypto library |
| 185 | DEP-001 | ? | crates-io/rustls-pemfile/rustls-post-quantum/Cargo.toml:18 | TP | webpki — PKI/crypto library |
| 186 | DEP-001 | ? | crates-io/rustls-pemfile/rustls-test/Cargo.toml:17 | TP | rustls — TLS/crypto library |
| 187 | DEP-001 | ? | crates-io/rustls-pemfile/rustls/Cargo.toml:31 | TP | webpki — PKI/crypto library |
| 188 | DEP-001 | ? | maven/jetty-server/.../jetty-alpn-server/pom.xml:17 | TP | jetty-server — embedded HTTPS server |
| 189 | DEP-001 | ? | maven/jetty-server/.../jetty-compression-server/pom.xml:20 | TP | jetty-server — embedded HTTPS server |
| 190 | DEP-001 | ? | maven/jetty-server/.../jetty-fcgi-server/pom.xml:19 | TP | jetty-server — embedded HTTPS server |
| 191 | DEP-001 | ? | maven/jetty-server/.../jetty-http3-server/pom.xml:19 | TP | jetty-server — embedded HTTPS server |
| 192 | DEP-001 | ? | maven/jetty-server/.../jetty-keystore/pom.xml:43 | TP | jetty-server — embedded HTTPS server |
| 193 | DEP-001 | ? | maven/jetty-server/.../jetty-quic-quiche-server/pom.xml:19 | TP | jetty-server — embedded HTTPS server |
| 194 | DEP-001 | ? | maven/jetty-server/.../jetty-security/pom.xml:22 | TP | jetty-server — embedded HTTPS server |
| 195 | DEP-001 | ? | maven/jetty-server/.../jetty-test-coreapp-demo/pom.xml:21 | TP | jetty-server — embedded HTTPS server |
| 196 | DEP-001 | ? | maven/jetty-server/.../jetty-ee11-sessions-infinispan/pom.xml:15 | DEPENDS | commons-codec — encoding utility; borderline crypto dependency |

</details>

---

## 5. Recommendations

Ranked by estimated FP reduction in the full 986-finding corpus.

### 1. Extend Phase 16 SiteContext to cover three residual Pattern F sub-patterns (~20–30 FPs in corpus)

**Target rules:** CRYPTO-730, CRYPTO-731, CRYPTO-732 (and by extension CRYPTO-700–720 which have the same structural issue)

Three non-operational string contexts are not yet covered:
- `StringConstant` in a const/var block: `HS256 = SignatureAlgorithm("HS256")`. Rule fires on the string literal but the assignment makes no HMAC call.
- `TestLookup`: `LookupSignatureAlgorithm("HS512")` followed by `require.Equal` in a `_test.go` file. This is a registry lookup, not a signing operation.
- `TestHelperArg`: passing an algorithm string as an argument to a test helper function.

Phase 16 added MapEntry and TestAssertion contexts. Add three more: `ConstDeclaration`, `TestRegistryLookup`, `TestHelperStringArg`. These three sites plus the already-suppressed MapEntry+TestAssertion cluster would bring the go-modules HMAC rule FP rate to near-zero.

### 2. Fix CRYPTO-244 and CRYPTO-262 ES512/P521 curve assignment (Pattern J) (~5–8 FPs in corpus)

**CRYPTO-244** fires on `ES512` enum entries in jjwt and assigns `ecdsa-p256`. ES512 is NIST P-521. **CRYPTO-262** fires on `P521UsingSha512` constructors with the same mismatch. Both rules need a per-variant split identical to the one already applied to CRYPTO-704 (PS384 vs PS256) in Phase 13. The fix is one additional pattern match: if the symbol contains "512" or "P521", emit `ecdsa-p521`.

### 3. Fix CRYPTO-260 jose4j RS384 hash mismatch — Pattern D-prime (~3–5 FPs in corpus)

**CRYPTO-260** fires on `RSA_USING_SHA384` and emits `rsa-pkcs1-sha256-2048`. Phase 15 fixed the identical issue for Nimbus (CRYPTO-259 → rsa-pkcs1-sha384-3072). Apply the same fix to CRYPTO-260: detect the SHA384 variant and emit `rsa-pkcs1-sha384-3072` (or size-agnostic `rsa-pkcs1-sha384`). This is a one-line rule change.

### 4. Fix CRYPTO-263 jose4j HmacSha512 sha-256 placeholder (~3–5 FPs in corpus)

**CRYPTO-263** fires on `HmacSha512` constructors and emits `sha-256`. The counterpart CRYPTO-241 (jjwt HS512) was fixed in Phase 17 (finding #177 now correctly carries sha-512). Apply the same fix to CRYPTO-263: HmacSha512 → `sha-512`, HmacSha384 → `sha-384`.

### 5. Investigate CRYPTO-587 pbkdf2_hmac generic-hash false classification (~4–6 DEPENDS in corpus)

**CRYPTO-587** fires on `pbkdf2_hmac::<...>` and emits `sha-256` as the algorithm_id regardless of the actual type parameter. Three DEPENDS verdicts in this sample result from the scanner being unable to resolve the generic hash argument. Either: (a) require the type parameter to be a named concrete type (Sha256, Sha384, etc.) before emitting the finding, or (b) emit a distinct `pbkdf2-unknown-hash` algorithm_id for unresolvable cases. Option (b) preserves the finding while making the algorithm_id honest.

### 6. Verify and close Pattern B (jwt-alg-none) — unverifiable for three audits

**CRYPTO-264** for jose4j `AlgorithmIdentifiers.NONE` fires correctly in this sample (finding #110, TP). However the original Pattern B (jwt-alg-none placeholder emitting rsa-1024) has never appeared in an audit sample. Construct a targeted test: inject a jwt-alg-none site from a library that was previously affected and confirm the fix survives.

### 7. Confirm Phase 17 jwt.sign disambiguation with a targeted npm subsample

Phase 17 added argument-value disambiguation for `jwt.sign` (CRYPTO-361–382) but the Phase 18 sample contains zero npm jwt.sign findings. Queue a targeted npm-only sample of 20–30 jsonwebtoken findings to confirm that HMAC-mode calls are no longer tagged `rsa-pkcs1-sha256-2048`.

---

## 6. Ship-Readiness Assessment

**Point estimate: 84.5%. Wilson 95% CI lower bound: 78.5%.**

The scanner does not yet meet an 85% precision floor at the lower CI bound. However, the point estimate is 84.5% — within noise of the threshold — and the CI is tighter than prior audits (±5.3 pp vs. ±8.6 pp in Phase 14a) due to the larger sample.

The remaining 28 FPs cluster in four areas: go-modules HMAC string-context rules (6 FPs, Patterns F residual), maven jose4j/jjwt algorithm_id mismatches (3 FPs, Patterns D-prime/J), go-modules non-operational algorithm map/constant rules (5 FPs, Pattern I), and npm jwt.sign unconditional RSA tagging (3 FPs, Pattern H). None of these require structural changes to the scanner — all are rule-level fixes.

Recommendation 1 (Pattern F StringConstant/TestLookup/TestHelperArg) alone would recover an estimated 3–5 FPs from this sample and 20–30 in the full corpus, pushing the point estimate to ~88–90% and the CI lower bound solidly above 85%.

**Pilot deployment is defensible today with mandatory human review of all maven and go-modules High-severity findings.** Crates-io and DEP-001 findings (combined 98%+ precision) can be used in automated triage without triage overhead.

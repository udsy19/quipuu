# Precision Audit — Seawall V7 Corpus-B Run

**Audit date:** 2026-06-16
**Sample size:** 31 findings (stratified, deterministic)
**Total corpus findings:** 1194 across 150 projects

---

## 1. Headline Numbers

| Tier | Total | TP | FP | DEPENDS | Precision (excl. DEPENDS) |
|------|-------|----|----|---------|--------------------------|
| High | 16 | 12 | 3 | 1 | 80.0% |
| Medium | 10 | 5 | 5 | 0 | 50.0% |
| ? (DEP-001) | 5 | 5 | 0 | 0 | 100.0% |
| **Overall** | **31** | **22** | **8** | **1** | **73.3%** |

> Precision calculated as TP / (TP + FP), excluding the single DEPENDS finding from the denominator. Including DEPENDS as FP gives 71.0%.

| Ecosystem | Findings in sample | TP | FP | Precision |
|-----------|-------------------|----|----|-----------|
| crates-io | 7 | 4 | 3 | 57% |
| go-modules | 11 | 9 | 2 | 82% |
| maven | 8 | 6 | 1 (+ 1 DEPENDS) | 86% (excl. DEPENDS) |
| npm | 3 | 3 | 0 | 100% |
| crypto-adjacent | 1 | 0 | 1 | 0% |
| pypi | 1 | 1 | 0 | 100% |

---

## 2. Per-Finding Table

| # | rule_id | file:line | Verdict | Note |
|---|---------|-----------|---------|------|
| 1 | CRYPTO-001 | age/internal/age/recipients_test.go:114 | TP | `rsa.GenerateKey(rand.Reader, 768)` — real undersized RSA keygen in test |
| 2 | CRYPTO-740 | go-modules/jwt-go/none.go:24 | FP | Line is `return "none"` in Alg(); detection is correct but `algorithm_id="rsa-1024"` is a hardcoded placeholder unrelated to alg=none |
| 3 | CRYPTO-710 | go-modules/go-jose/shared.go:119 | TP | `ES256 = SignatureAlgorithm("ES256")` — canonical algorithm constant registration |
| 4 | CRYPTO-700 | go-modules/vault/builtin/logical/pki/acme_jws.go:18 | TP | `"RS256": true` in AllowedOuterJWSTypes map — explicit algorithm allowlist configuration |
| 5 | CRYPTO-703 | go-modules/jwx/jwa/signature_gen.go:24 | TP | `NewSignatureAlgorithm("PS256")` — algorithm registration; algorithm_id matches |
| 6 | CRYPTO-002 | go-modules/jwx/jwe/bench_encrypt_test.go:14 | TP | `rsa.GenerateKey(rand.Reader, 2048)` — RSA-2048 keygen in benchmark |
| 7 | CRYPTO-704 | go-modules/jwx/jws/jwsbb/jwsbb.go:42 | FP | Line is `ps384 = "PS384"` (PS384/SHA-384) but `algorithm_id="rsa-pss-sha256-2048"` is copy-pasted from CRYPTO-703 (PS256); algorithm_id misidentifies the algorithm |
| 8 | CRYPTO-711 | maven/tink/go/jwt/jwk_converter_test.go:74 | TP | Test data JSON contains `"alg":"ES384"` — real algorithm in JWK test fixture |
| 9 | CRYPTO-211 | maven/tink/java_src/.../EcdsaVerifyJceTest.java:219 | TP | `KeyPairGenerator.getInstance("EC")` + `generateKeyPair()` — real EC keypair generation |
| 10 | CRYPTO-254 | maven/nimbus-jose-jwt/src/.../JCASupport.java:188 | DEPENDS | `alg.equals(JWEAlgorithm.RSA1_5)` — real RSA1_5 check; algorithm_id="rsa-2048" overspecifies key size, RSA1_5 does not guarantee 2048 bits |
| 11 | CRYPTO-360 | npm/jsonwebtoken/test/async_sign.tests.js:57 | TP | `jwt.sign({...}, secret, { algorithm: 'RS256' })` — real JWT sign call in test |
| 12 | CRYPTO-372 | npm/jsrsasign/jsrsasign-all-min.js:235 | TP | `TripleDES` present in minified library bundle — real 3DES usage |
| 13 | CRYPTO-560 | crates-io/hyper-rustls/src/connector.rs:269 | FP | `rustls::ClientConfig::builder()` call correctly detected, but `algorithm_id="aes-256-gcm"` is a placeholder unrelated to what this line does |
| 14 | CRYPTO-560 | crates-io/rustls-pemfile/bogo/src/main.rs:1767 | FP | `ClientConfig::builder(provider.clone())` — same placeholder algorithm_id issue as #13 |
| 15 | CRYPTO-560 | crates-io/rustls-pemfile/rustls-test/tests/api/api.rs:483 | FP | `ClientConfig::builder(...)` — same placeholder algorithm_id issue as #13 |
| 16 | CRYPTO-561 | crates-io/rustls-pemfile/rustls-test/tests/api/server_cert_verifier.rs:177 | FP | `ServerConfig::builder(...)` — same placeholder algorithm_id pattern; CRYPTO-561 hardcodes "aes-256-gcm" |
| 17 | CRYPTO-762 | go-modules/go-jose/shared.go:132 | TP | `A128GCM = ContentEncryption("A128GCM")` — AES-128-GCM algorithm constant registration |
| 18 | CRYPTO-732 | go-modules/jwx/jwa/signature_gen_test.go:142 | TP | `jwa.HS512()` in generated test — real algorithm reference exercising the HS512 constant |
| 19 | CRYPTO-732 | maven/tink/go/jwt/jwt_encoding_test.go:296 | TP | `alg: "HS512"` in test data struct literal — real algorithm in JWT test fixture |
| 20 | CRYPTO-252 | maven/nimbus-jose-jwt/src/.../JCASupport.java:103 | FP | `alg.equals(JWSAlgorithm.HS384)` — real HS384 branch, but `algorithm_id="sha-256"` is wrong (HS384 uses SHA-384; CRYPTO-252 uses "sha-256" as a blanket HMAC placeholder) |
| 21 | DEP-001 | crates-io/age/go.mod:5 | TP | `golang.org/x/crypto` dependency — genuine cryptographic library |
| 22 | DEP-001 | crates-io/rustls-pemfile/rustls/Cargo.toml:31 | TP | `webpki` dependency — Web PKI certificate validation library |
| 23 | DEP-001 | maven/jetty-server/.../jetty-quic-quiche-server/pom.xml:19 | TP | `jetty-server` dependency — embedded HTTPS server with TLS |
| 24 | DEP-001 | maven/jetty-server/.../jetty-ee10-test-loginservice/pom.xml:20 | TP | `jetty-server` dependency — same as #23 |
| 25 | DEP-001 | maven/jetty-server/.../jetty-ee9-openid/pom.xml:32 | TP | `jetty-server` dependency — same as #23 |
| 26 | CRYPTO-020 | crates-io/age/internal/age/recipients_test.go:159 | TP | `ed25519.GenerateKey(rand.Reader)` — real Ed25519 keygen in test |
| 27 | CRYPTO-412 | crypto-adjacent/kyber/ref/nistkat/rng.c:127 | FP | `EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), ...)` — `algorithm_id="aes-128-ecb"` is wrong; code uses AES-256-ECB; message text even says "EVP_aes_256_ecb" contradicting the algorithm_id |
| 28 | CRYPTO-710 | go-modules/jwt-go/ecdsa.go:34 | TP | `SigningMethodES256 = &SigningMethodECDSA{"ES256", ...}` — algorithm struct registration |
| 29 | CRYPTO-203 | maven/aws-encryption-sdk-java/src/.../CipherHandler.java:99 | TP | `Cipher.getInstance("AES/GCM/NoPadding")` — real AES-GCM instantiation in production code |
| 30 | CRYPTO-312 | npm/elliptic/benchmarks/index.js:72 | TP | `crypto.createHash('sha256')` — real SHA-256 hash in benchmark |
| 31 | CRYPTO-104 | pypi/authlib/authlib/jose/rfc7518/rsa_key.py:95 | TP | `rsa.generate_private_key(key_size=key_size, ...)` — real RSA keygen with runtime-variable size |

---

## 3. False-Positive Patterns

### Pattern A — Placeholder `algorithm_id` for TLS config builder calls (CRYPTO-560, CRYPTO-561) — 4 FPs

**Findings:** #13, #14, #15, #16

**Root cause:** `rust.toml` rules CRYPTO-560 and CRYPTO-561 hardcode `algorithm_id = "aes-256-gcm"` for any `rustls::ClientConfig::builder()` / `rustls::ServerConfig::builder()` call. No AES-256-GCM is present at the matched site; the placeholder was chosen arbitrarily as a "representative TLS algorithm." The message text is accurate, but the algorithm_id field is structurally wrong, corrupting CBOM output and any algorithm-level filtering downstream.

### Pattern B — Placeholder `algorithm_id` for JWT `alg=none` (CRYPTO-740) — 1 FP

**Findings:** #2

**Root cause:** `go.toml` comment explicitly acknowledges `algorithm_id = "rsa-1024"` as a "placeholder" for `alg=none` findings. The detection (CVE-2015-9235) is correct, but the algorithm_id misrepresents the finding. Any filter on `rsa-1024` will incorrectly bucket this with actual weak-RSA findings.

### Pattern C — Copy-paste `algorithm_id` across PSS variant rules (CRYPTO-703/704) — 1 FP

**Findings:** #7

**Root cause:** `go.toml` CRYPTO-703 (PS256) uses `algorithm_id = "rsa-pss-sha256-2048"` and CRYPTO-704 (PS384) uses the identical value. PS384 uses SHA-384, so the correct id would be `rsa-pss-sha384-2048`. The same pattern likely affects CRYPTO-705 (PS512).

### Pattern D — Blanket HMAC `algorithm_id = "sha-256"` for all HMAC variants (CRYPTO-252) — 1 FP

**Findings:** #20

**Root cause:** `java.toml` CRYPTO-252 matches `JWSAlgorithm.HS(256|384|512)` with a single `algorithm_id = "sha-256"`. An HS384 match (SHA-384) is incorrectly tagged `sha-256`. This misrepresents any HS384 or HS512 finding in CBOM output.

### Pattern E — AES key-size mismatch in C/EVP rule (CRYPTO-412) — 1 FP

**Findings:** #27

**Root cause:** The rule matched `EVP_aes_256_ecb()` but assigned `algorithm_id = "aes-128-ecb"`. The message text correctly reports the 256-bit variant, indicating the classification table looked up the wrong id after extraction. The extract query likely captures `EVP_aes_*_ecb` generically and the classify step defaults to the 128-bit id regardless of the captured bit-width.

---

## 4. Recommendations

1. **Assign a dedicated `algorithm_id` (or `none`) for TLS-topology findings (CRYPTO-560, CRYPTO-561).** Introduce `tls-client-config` and `tls-server-config` as first-class algorithm_ids in `algorithm-table.toml`, or use `"unknown"` like DEP-001. Do not repurpose `aes-256-gcm` as a proxy. This single fix eliminates 4 FPs (Pattern A) and will likely eliminate many more in the full 1194-finding corpus given how widely rustls is used.

2. **Replace the `alg=none` placeholder `algorithm_id` with `jwt-alg-none` (CRYPTO-740).** Add a corresponding entry to `algorithm-table.toml`. This eliminates Pattern B and ensures alg=none findings are not mixed with weak-RSA findings in severity rollups.

3. **Fix the copy-paste `algorithm_id` in PSS variant rules (CRYPTO-703/704/705).** Set CRYPTO-704 to `rsa-pss-sha384-2048` and CRYPTO-705 to `rsa-pss-sha512-4096`. Add a schema-level test asserting that all classify entries referencing a PSS algorithm use a PSS-compatible id — this would have caught the copy-paste.

4. **Use per-variant `algorithm_id` in the HMAC rule family (CRYPTO-252).** Split the single `algorithm_id = "sha-256"` entry into three separate classify rules: HS256 → `sha-256`, HS384 → `sha-384`, HS512 → `sha-512`. The `{member}` capture is already available in the query; use it in a `when.args.member` guard. This eliminates Pattern D.

5. **Propagate the captured AES bit-width into `algorithm_id` for C/EVP rules (CRYPTO-412).** The extract query for `EVP_aes_*_ecb` should capture the numeric width (128/192/256) as a separate capture group and the classify entry should use it to select among `aes-128-ecb`, `aes-192-ecb`, `aes-256-ecb`. As a quick fix, add separate classify entries for each captured function name rather than matching all with a single id.

6. **Add an `algorithm_id` consistency test to CI.** For every `[[classify]]` entry that references a PSS, HMAC, or AES variant in its `when` condition, assert that the `algorithm_id` field matches the expected variant. This would catch copy-paste regressions (Pattern C) and incorrect bit-widths (Pattern E) at rule-authoring time before they reach the corpus run.

# Precision Audit V4 — the held stratum, audited

**Audit date:** 2026-08-28
**Sample size:** 150 findings, uniform random, **seed 20260828**, drawn from the 964-finding
stratum A of the 1570-finding corpus-B dump at `e76a6e4`
**Verdicts:** 111 TP · 34 FP · 5 DEPENDS → **stratum A precision 76.6 %** (Wilson 69.0–82.7)
**What it replaces:** the constant `A_TP, A_FP, A_DEPENDS = 217, 32, 23` — a carried 87.1 % whose
per-row labels do not survive, and which every figure published since the 2026-08-27 corpus
restoration has weighted at ~60 % of the total.

---

## 0. Why a second audit of a stratum that already had one

The published precision figure is a two-stratum weighted estimate. Stratum B — the 606 findings
from the 46 projects whose working trees were restored on 2026-08-27 — carries per-row labels in
the open (`c11_labels.py`, 100 rows, every row read at its cited `file:line`). Stratum A carried a
tuple. Its labels were taken during Phase 18, against a different corpus revision, and the rows
they applied to can no longer be identified.

A held stratum cannot fall, and it cannot rise either:

- It cannot fall. Carrying 32 FP among 249 scored rows implies on the order of 120 false
  positives across stratum A's 964 findings. Two false-positive classes in that stratum account
  for most of that budget on their own: **77** `CRYPTO-740` `alg=none` findings, counted exactly
  on the dump, and the Java JOSE-dispatch shape, which is 13 of the 150 rows sampled here and so
  extrapolates to about 84. That put the published figure at or above its own ceiling, and no
  audit of the held stratum could show it.
- It cannot rise. The change audited below removes 77 stratum-A false positives, and the
  estimator of record reports stratum A at 87.1 % before and after — necessarily, since it is a
  constant. The 150-row sample here shows 11 of its rows stop resolving; the constant's 272 rows
  cannot show that, because nobody can say which findings they were.

So this audit is not a second opinion on the same rows. It is the first per-row evidence for 61 %
of the published number.

## 1. Method, quoted from the stratum it has to match

Labelling rule, taken verbatim from `c11_labels.py` so the two strata cannot drift:

- **TP** — the cited line invokes an API that performs, or configures the performance of, the
  named operation, and `algorithm_id` is correct for that line.
- **FP** — the cited line performs no cryptographic operation (a string constant, a registry
  lookup, a switch comparison operand, a call the test asserts must fail, an unrelated token),
  **or** `algorithm_id` contradicts what the line states.
- **DEPENDS** — the operation is real but `algorithm_id` asserts a parameter (modulus, key size,
  hash) the line does not state. Excluded from both sides of the ratio.

And its two sub-rules, applied unchanged: a line that *yields* the object an operation is
performed with configures that operation (TP); a line that only *compares* against a name does
not. A call the surrounding assertion requires to fail produces no key, no signature and no
ciphertext (FP).

Every one of the 150 rows was labelled by opening the file at the cited line. The sample is
uniform over stratum A, not stratified within it: 49 maven · 35 crates-io · 25 go-modules ·
25 npm · 14 pypi · 2 crypto-adjacent, against a population of 36.2 % · 23.4 % · 18.7 % · 13.2 % ·
7.9 % · 0.6 %.

## 2. The 34 false positives are four shapes, not thirty-four accidents

| shape | rows | example |
|---|---|---|
| `alg=none` on a constant spelled "none" | 11 | `SSETypeNone SSEType = "none"` reported as a disabled JWT signature |
| Java JOSE dispatch — an enum constant compared or collected | 13 | `} else if (alg.equals(JWSAlgorithm.PS256))` reported as RSA-PSS signing |
| a call the test requires to fail | 6 | `jwt.encode(..., p384_key, algorithm="ES256")` inside `pytest.raises(InvalidKeyError)` |
| `algorithm_id` contradicts the cited line | 4 | `SigningKey::<Sha1>::new(priv_key)` reported as `rsa-pkcs1-sha256` |

**The Java JOSE-dispatch decision, in writing, because it cuts both ways.** These 13 rows sit in
`nimbus-jose-jwt`, `jjwt-api` and `jose4j`, where `alg.equals(JWSAlgorithm.ES256)` and
`algs.add(JWSAlgorithm.HS512)` arguably declare a *capability*. No new rule was needed to decide
it and none was invented: the labelling rule already names "switch comparison operand" and
"string constant" as FP, and the Java shape is those two things in Java. The identical shape in
its Go spelling — `jwa.LookupSignatureAlgorithm("PS256")` — was labelled FP, suppressed, and
booked as a 81.8 % → 85.3 % gain in `PRECISION_AUDIT_V3.md § 0`. Labelling the Java spelling TP
would require revisiting that. **Both spellings are FP.** The sensitivity of the whole figure to
reversing that decision is published in § 3 rather than left implicit.

The 11 `alg=none` rows are the class the change measured in `BENCHMARKING_RESULTS.md` removes;
they were labelled before that change was written, from the pre-change dump, and 11 of them stop
resolving afterwards. That is why the post figure moves.

## 3. The figure, under both estimators

Same corpus, same flags (`--source --deps --include-safe`), same profile (`nist-default`), same
two dumps. The only thing that differs between the two rows is whether stratum A is held at its
constant or read from the table in § 5.

| estimator | pre (1570 findings) | post (1479 findings) | delta |
|---|---|---|---|
| of record — stratum A held at 217/32/23 | **86.5 %** (82.7–90.3) | **87.3 %** (83.6–91.0) | +0.8 pp |
| corrected — stratum A audited, this document | **80.0 %** (74.9–85.1) | **84.7 %** (80.0–89.4) | +4.7 pp |

**The two movements must not be added.** 86.5 → 80.0 is the same scanner on the same dump,
measured instead of assumed; it is the cost of the constant, not a regression. 80.0 → 84.7 is
this cycle's diff.

Sensitivity, so no reading is hidden — all on the post dump:

| variation | figure |
|---|---|
| published (DEPENDS excluded) | **84.7 %** |
| Java JOSE-dispatch rows scored TP instead of FP | 90.5 % |
| DEPENDS all scored FP | 82.9 % |
| DEPENDS all scored TP | 85.1 % |
| dependency-manifest (`DEP-001`) rows excluded from stratum A | 83.1 % |

`DEP-001` rows are ~100 % correct by construction — a manifest line either declares the library or
it does not — and there are 18 of them in the sample, so the source-only reading is the more
conservative one.

## 4. What this means for the recorded baseline

`state/precision.json` holds the estimator of record. **A cycle must not write that file**; the
recommendation, with the evidence above behind it, is that the recorded baseline be re-anchored
to **84.7 %** and the constant deleted from the estimator, so that the next change is measured
against labels rather than against a memory of labels.

Reproduce both rows: `/opt/cryptoscope/work/v1b_precision.py`, which asserts that the estimator of
record reproduces its own 86.5 % baseline before printing anything else, and refuses to report at
all if the change under audit added a finding or removed one outside `CRYPTO-740`.

## 5. The 150 verdicts

Rows marked *(removed this cycle)* are findings the `alg=none` corroboration removed; they are
labelled from the pre-change dump and drop out of the post figure.

| # | rule | algorithm_id | file:line | verdict | tag | why |
|---|---|---|---|---|---|---|
| 0 | `CRYPTO-520` | `sha-256` | `crates-io/openssl/openssl/src/sha.rs:412` | **TP** | — | Sha256::new() then update/finish — real SHA-256 |
| 1 | `CRYPTO-521` | `sha-384` | `crates-io/openssl/openssl/src/sha.rs:435` | **TP** | — | Sha384::new() then update/finish — real SHA-384 |
| 2 | `CRYPTO-520` | `sha-256` | `crates-io/p384/p384/src/ecdsa.rs:122` | **TP** | — | sha2::Sha256::digest(b"test") — real SHA-256 |
| 3 | `CRYPTO-547` | `rsa-pkcs1-sha256` | `crates-io/rsa/src/pkcs1v15.rs:448` | **FP** | — | CRYPTO-547 publishes rsa-pkcs1-sha256 for SigningKey::<Sha1>::new — the line states Sha1 |
| 4 | `CRYPTO-544` | `rsa-pkcs1-sha256` | `crates-io/rsa/src/pkcs1v15.rs:468` | **TP** | — | SigningKey::<Sha256>::new(priv_key) — id matches the turbofish at the line |
| 5 | `CRYPTO-547` | `rsa-pkcs1-sha256` | `crates-io/rsa/src/pkcs1v15.rs:511` | **DEPENDS** | — | SigningKey::new(priv_key) — real RSA signing key; no hash at the line, id asserts sha256 |
| 6 | `CRYPTO-547` | `rsa-pkcs1-sha256` | `crates-io/rsa/src/pss.rs:593` | **FP** | — | pss.rs SigningKey::<Sha1>::new published as rsa-pkcs1-sha256 — wrong hash and wrong padding |
| 7 | `CRYPTO-560` | `tls-client-config` | `crates-io/rustls/rustls/src/client/test.rs:263` | **TP** | — | ClientConfig::builder(provider) — real TLS client config; tls-client-config asserts no algorithm |
| 8 | `CRYPTO-561` | `tls-server-config` | `crates-io/rustls/rustls/src/server/test.rs:223` | **TP** | — | ServerConfig::builder(CryptoProvider{..}) — real TLS server config |
| 9 | `CRYPTO-561` | `tls-server-config` | `crates-io/rustls/rustls/src/server/test.rs:243` | **TP** | — | ServerConfig::builder(CryptoProvider{..}) — real TLS server config |
| 10 | `DEP-001` | `unknown` | `crates-io/rustls-pemfile/bogo/Cargo.toml:14` | **TP** | dep | bogo/Cargo.toml declares webpki — the manifest line does declare the dependency |
| 11 | `DEP-001` | `unknown` | `crates-io/rustls-pemfile/connect-tests/Cargo.toml:14` | **TP** | dep | connect-tests/Cargo.toml declares ring |
| 12 | `CRYPTO-561` | `tls-server-config` | `crates-io/rustls-pemfile/examples/src/bin/server_acceptor.rs:217` | **TP** | — | ServerConfig::builder(self.provider.clone()) |
| 13 | `CRYPTO-561` | `tls-server-config` | `crates-io/rustls-pemfile/openssl-tests/src/early_exporter.rs:27` | **TP** | — | ServerConfig::builder(provider::DEFAULT_PROVIDER.into()) |
| 14 | `CRYPTO-561` | `tls-server-config` | `crates-io/rustls-pemfile/openssl-tests/src/ffdhe_kx_with_openssl.rs:212` | **TP** | — | ServerConfig::builder(provider.into()) |
| 15 | `CRYPTO-560` | `tls-client-config` | `crates-io/rustls-pemfile/rustls-fuzzing-provider/tests/smoke.rs:85` | **TP** | — | ClientConfig::builder(provider.into()) |
| 16 | `CRYPTO-570` | `ecdsa-unattributed` | `crates-io/rustls-pemfile/rustls-post-quantum/src/lib.rs:312` | **FP** | rcgen | KeyPair::generate_for(&rcgen::PKCS_ML_DSA_87) published as ecdsa-unattributed — the line names ML-DSA-87 (#T2b) |
| 17 | `CRYPTO-561` | `tls-server-config` | `crates-io/rustls-pemfile/rustls-post-quantum/src/lib.rs:319` | **TP** | — | ServerConfig::builder(provider.clone()) |
| 18 | `CRYPTO-561` | `tls-server-config` | `crates-io/rustls-pemfile/rustls-test/src/lib.rs:522` | **TP** | — | ServerConfig::builder(provider.clone().into()) |
| 19 | `CRYPTO-561` | `tls-server-config` | `crates-io/rustls-pemfile/rustls-test/src/lib.rs:530` | **TP** | — | ServerConfig::builder(CryptoProvider{kx_groups..}) |
| 20 | `CRYPTO-560` | `tls-client-config` | `crates-io/rustls-pemfile/rustls-test/tests/api/api.rs:492` | **TP** | — | ClientConfig::builder(provider::DEFAULT_TLS13_PROVIDER.into()) |
| 21 | `CRYPTO-560` | `tls-client-config` | `crates-io/rustls-pemfile/rustls-test/tests/api/api.rs:1168` | **TP** | — | ClientConfig::builder(rustls_ring::DEFAULT_PROVIDER.into()) |
| 22 | `CRYPTO-560` | `tls-client-config` | `crates-io/rustls-pemfile/rustls-test/tests/api/api.rs:1234` | **TP** | — | ClientConfig::builder(CryptoProvider{secure_random..}) |
| 23 | `CRYPTO-561` | `tls-server-config` | `crates-io/rustls-pemfile/rustls-test/tests/api/crypto.rs:202` | **TP** | — | ServerConfig::builder(provider_with_one_suite(..)) |
| 24 | `CRYPTO-560` | `tls-client-config` | `crates-io/rustls-pemfile/rustls-test/tests/api/ffdhe.rs:69` | **TP** | — | ClientConfig::builder(provider.clone()) |
| 25 | `CRYPTO-561` | `tls-server-config` | `crates-io/rustls-pemfile/rustls-test/tests/api/io.rs:1639` | **TP** | — | ServerConfig::builder(provider::DEFAULT_TLS12_PROVIDER.into()) |
| 26 | `CRYPTO-561` | `tls-server-config` | `crates-io/rustls-pemfile/rustls-test/tests/api/kx.rs:366` | **TP** | — | ServerConfig::builder(CryptoProvider{kx_groups: SECP384R1}) |
| 27 | `CRYPTO-560` | `tls-client-config` | `crates-io/rustls-pemfile/rustls-test/tests/api/kx.rs:393` | **TP** | — | ClientConfig::builder(CryptoProvider{kx_groups: FakeHybrid, SECP384R1}) |
| 28 | `CRYPTO-560` | `tls-client-config` | `crates-io/rustls-pemfile/rustls-test/tests/api/server_cert_verifier.rs:239` | **TP** | — | ClientConfig::builder(provider.clone().into()) |
| 29 | `CRYPTO-560` | `tls-client-config` | `crates-io/rustls-pemfile/rustls-test/tests/api/server_cert_verifier.rs:249` | **TP** | — | ClientConfig::builder(provider.clone().into()) |
| 30 | `CRYPTO-561` | `tls-server-config` | `crates-io/rustls-pemfile/rustls/src/server/test.rs:264` | **TP** | — | ServerConfig::builder(CryptoProvider{..ffdhe_provider}) |
| 31 | `CRYPTO-570` | `ecdsa-unattributed` | `crates-io/rustls-webpki/src/verify_cert.rs:1358` | **DEPENDS** | rcgen | KeyPair::generate_for(test_utils::RCGEN_SIGNATURE_ALG) — real keygen, the constant is not at the line |
| 32 | `CRYPTO-584` | `sha-256` | `crates-io/scrypt/scrypt/src/lib.rs:120` | **TP** | — | pbkdf2_hmac::<Sha256>(password, salt, 1, &mut b) — real PBKDF2-HMAC-SHA256 |
| 33 | `CRYPTO-570` | `ecdsa-unattributed` | `crates-io/webpki/src/end_entity.rs:196` | **DEPENDS** | rcgen | rcgen::KeyPair::generate_for(RCGEN_SIGNATURE_ALG) — real keygen, algorithm not at the line |
| 34 | `CRYPTO-570` | `ecdsa-unattributed` | `crates-io/webpki/src/verify_cert.rs:1320` | **DEPENDS** | rcgen | KeyPair::generate_for(test_utils::RCGEN_SIGNATURE_ALG) — real keygen, algorithm not at the line |
| 35 | `CRYPTO-417` | `aes-256-ecb` | `crypto-adjacent/kyber/ref/nistkat/rng.c:127` | **TP** | — | EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), ...) — AES-256-ECB named at the line |
| 36 | `CRYPTO-210` | `rsa-unattributed` | `crypto-adjacent/tink-java/src/main/java/com/google/crypto/tink/hybrid/subtle/RsaKem.java:108` | **TP** | — | KeyPairGenerator.getInstance("RSA") — real RSA generator; rsa-unattributed asserts no modulus |
| 37 | `CRYPTO-004` | `rsa-4096` | `go-modules/aws-sdk-go/awstesting/certificate_utils.go:134` | **TP** | — | rsa.GenerateKey(rand.Reader, 4096) — id matches the literal |
| 38 | `CRYPTO-740` | `jwt-alg-none` | `go-modules/aws-sdk-go/service/cloudfront/api.go:37026` | **FP** | 740 | OriginRequestPolicyCookieBehaviorNone = "none" — an AWS CloudFront enum value *(removed this cycle)* |
| 39 | `CRYPTO-051` | `sha-1` | `go-modules/aws-sdk-go/service/cloudfront/sign/policy.go:200` | **TP** | — | sha1.New() in signEncodedPolicy — real SHA-1 |
| 40 | `CRYPTO-001` | `rsa-undersized` | `go-modules/aws-sdk-go/service/cloudfront/sign/privkey_test.go:15` | **TP** | — | rsa.GenerateKey(randReader, 1024) — id matches the literal |
| 41 | `CRYPTO-740` | `jwt-alg-none` | `go-modules/aws-sdk-go/service/cloudsearch/api.go:7640` | **FP** | 740 | SuggesterFuzzyMatchingNone = "none" — a CloudSearch enum value *(removed this cycle)* |
| 42 | `CRYPTO-740` | `jwt-alg-none` | `go-modules/aws-sdk-go/service/iam/api.go:41443` | **FP** | 740 | PolicySourceTypeNone = "none" — an IAM enum value *(removed this cycle)* |
| 43 | `CRYPTO-011` | `ecdsa-p256` | `go-modules/aws-sdk-go-v2/credentials/logincreds/provider_test.go:88` | **TP** | — | ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader) — real |
| 44 | `CRYPTO-001` | `rsa-undersized` | `go-modules/aws-sdk-go-v2/feature/cloudfront/sign/policy_test.go:154` | **TP** | — | rsa.GenerateKey(r, 1024) — id matches the literal |
| 45 | `CRYPTO-051` | `sha-1` | `go-modules/aws-sdk-go-v2/feature/cloudfront/sign/policy_test.go:164` | **TP** | — | sha1.New() — real SHA-1 |
| 46 | `CRYPTO-050` | `md5` | `go-modules/aws-sdk-go-v2/feature/s3/manager/integ_upload_test.go:133` | **TP** | — | hexSum(md5.New(), singlePartBytes) — real MD5 |
| 47 | `CRYPTO-051` | `sha-1` | `go-modules/aws-sdk-go-v2/feature/s3/manager/integ_upload_test.go:146` | **TP** | — | base64SumOfSums(sha1.New(), ...) — real SHA-1 |
| 48 | `CRYPTO-740` | `jwt-alg-none` | `go-modules/aws-sdk-go-v2/service/apigatewayv2/serializers.go:10237` | **FP** | 740 | ok := object.Key("none") — an apigatewayv2 JSON serializer key *(removed this cycle)* |
| 49 | `CRYPTO-740` | `jwt-alg-none` | `go-modules/aws-sdk-go-v2/service/autoscaling/types/enums.go:191` | **FP** | 740 | DeletionProtectionNone DeletionProtection = "none" — an autoscaling enum value *(removed this cycle)* |
| 50 | `CRYPTO-740` | `jwt-alg-none` | `go-modules/aws-sdk-go-v2/service/cloudfront/types/enums.go:32` | **FP** | 740 | CachePolicyHeaderBehaviorNone = "none" — a CloudFront enum value *(removed this cycle)* |
| 51 | `CRYPTO-740` | `jwt-alg-none` | `go-modules/aws-sdk-go-v2/service/cloudfront/types/enums.go:51` | **FP** | 740 | CachePolicyQueryStringBehaviorNone = "none" — a CloudFront enum value *(removed this cycle)* |
| 52 | `CRYPTO-740` | `jwt-alg-none` | `go-modules/aws-sdk-go-v2/service/cloudfront/types/enums.go:491` | **FP** | 740 | ItemSelectionNone = "none" — a CloudFront enum value *(removed this cycle)* |
| 53 | `CRYPTO-740` | `jwt-alg-none` | `go-modules/aws-sdk-go-v2/service/databasemigrationservice/types/enums.go:244` | **FP** | 740 | DmsSslModeValueNone = "none" — a DMS TLS-mode enum value *(removed this cycle)* |
| 54 | `CRYPTO-740` | `jwt-alg-none` | `go-modules/aws-sdk-go-v2/service/databasemigrationservice/types/enums.go:472` | **FP** | 740 | NestingLevelValueNone = "none" — a DMS enum value *(removed this cycle)* |
| 55 | `CRYPTO-740` | `jwt-alg-none` | `go-modules/aws-sdk-go-v2/service/ec2/types/enums.go:10829` | **FP** | 740 | SSETypeNone SSEType = "none" — an EC2 encryption-type enum value *(removed this cycle)* |
| 56 | `CRYPTO-002` | `rsa-2048` | `go-modules/vault/builtin/logical/pki/backend_test.go:7945` | **TP** | — | rsa.GenerateKey(rand.Reader, 2048) — id matches the literal |
| 57 | `CRYPTO-020` | `ed25519` | `go-modules/vault/builtin/logical/pki/ca_test.go:126` | **TP** | — | ed25519.GenerateKey(rand.Reader) — real |
| 58 | `CRYPTO-002` | `rsa-2048` | `go-modules/vault/builtin/logical/pki/path_acme_test.go:753` | **TP** | — | rsa.GenerateKey(rand.Reader, 2048) — id matches the literal |
| 59 | `CRYPTO-011` | `ecdsa-p256` | `go-modules/vault/builtin/logical/pki/path_acme_test.go:777` | **TP** | — | ecdsa.GenerateKey(elliptic.P256(), rand.Reader) — real |
| 60 | `CRYPTO-011` | `ecdsa-p256` | `go-modules/vault/builtin/logical/pki/path_tidy_test.go:936` | **TP** | — | ecdsa.GenerateKey(elliptic.P256(), rand.Reader) — real |
| 61 | `CRYPTO-011` | `ecdsa-p256` | `go-modules/vault/sdk/helper/certutil/certutil_test.go:673` | **TP** | — | ecdsa.GenerateKey(elliptic.P256(), rand.Reader) — real |
| 62 | `CRYPTO-040` | `aes-unattributed` | `maven/tink/go/aead/subtle/aes_gcm_siv.go:212` | **TP** | — | aes.NewCipher(encKey) — real AES; aes-unattributed asserts no key size |
| 63 | `CRYPTO-040` | `aes-unattributed` | `maven/tink/go/aead/subtle/aes_gcm_siv.go:230` | **TP** | — | aes.NewCipher(key) — real AES |
| 64 | `CRYPTO-040` | `aes-unattributed` | `maven/tink/go/internal/aead/aes_gcm_insecure_iv.go:145` | **TP** | — | aes.NewCipher(i.key) — real AES |
| 65 | `CRYPTO-003` | `rsa-3072` | `maven/tink/go/internal/signature/rsassapss_signer_verifier_test.go:34` | **TP** | — | rsa.GenerateKey(rand.Reader, 3072) — id matches the literal |
| 66 | `CRYPTO-710` | `ecdsa-p256` | `maven/tink/go/jwt/jwt_signer_verifier_kid_test.go:61` | **TP** | — | newVerifierWithKID(tv, "ES256", kid) — yields the verifier the operation runs on (c11 sub-rule 1) |
| 67 | `CRYPTO-040` | `aes-unattributed` | `maven/tink/go/streamingaead/subtle/aes_ctr_hmac.go:183` | **TP** | — | aes.NewCipher(aesKey) — real AES |
| 68 | `CRYPTO-040` | `aes-unattributed` | `maven/tink/go/streamingaead/subtle/aes_ctr_hmac.go:280` | **TP** | — | aes.NewCipher(aesKey) — real AES |
| 69 | `CRYPTO-203` | `aes-unattributed-gcm` | `maven/tink/java_src/src/main/java/com/google/crypto/tink/integration/android/AndroidKeystoreAesGcm.java:107` | **TP** | — | Cipher.getInstance("AES/GCM/NoPadding") — real AES-GCM; sentinel asserts mode only |
| 70 | `CRYPTO-211` | `ecdsa-unattributed` | `maven/tink/java_src/src/test/java/com/google/crypto/tink/signature/KeyConversionTest.java:56` | **TP** | — | KeyPairGenerator.getInstance("EC") — real EC generator; ecdsa-unattributed asserts no curve |
| 71 | `CRYPTO-210` | `rsa-unattributed` | `maven/tink/java_src/src/test/java/com/google/crypto/tink/signature/KeyConversionTest.java:120` | **TP** | — | KeyPairGenerator.getInstance("RSA") — real RSA generator |
| 72 | `CRYPTO-211` | `ecdsa-unattributed` | `maven/tink/java_src/src/test/java/com/google/crypto/tink/subtle/EcdsaSignJceTest.java:115` | **TP** | — | KeyPairGenerator.getInstance("EC") — real EC generator |
| 73 | `CRYPTO-210` | `rsa-unattributed` | `maven/tink/java_src/src/test/java/com/google/crypto/tink/subtle/RsaSsaPkcs1SignJceTest.java:114` | **TP** | — | KeyPairGenerator.getInstance("RSA") — real RSA generator |
| 74 | `CRYPTO-232` | `aes-unattributed-gcm` | `maven/nimbus-jose-jwt/src/main/java/com/nimbusds/jose/crypto/LegacyAESGCM.java:99` | **TP** | — | new GCMBlockCipher(cipher) — real GCM construction |
| 75 | `CRYPTO-256` | `sha-512` | `maven/nimbus-jose-jwt/src/main/java/com/nimbusds/jose/crypto/MACProvider.java:61` | **FP** | dispatch | algs.add(JWSAlgorithm.HS512) building SUPPORTED_ALGORITHMS — an enum constant in a collection, no HMAC |
| 76 | `CRYPTO-256` | `sha-512` | `maven/nimbus-jose-jwt/src/main/java/com/nimbusds/jose/crypto/MACSigner.java:79` | **FP** | dispatch | } else if (JWSAlgorithm.HS512.equals(alg)) — comparison operand |
| 77 | `CRYPTO-255` | `sha-384` | `maven/nimbus-jose-jwt/src/main/java/com/nimbusds/jose/crypto/MACSigner.java:106` | **FP** | dispatch | hmacAlgs.add(JWSAlgorithm.HS384) — enum constant in a collection, no HMAC computed |
| 78 | `CRYPTO-281` | `rsa-pss-sha256` | `maven/nimbus-jose-jwt/src/main/java/com/nimbusds/jose/crypto/RSASSA.java:68` | **FP** | dispatch | } else if (alg.equals(JWSAlgorithm.PS256)) — comparison operand |
| 79 | `CRYPTO-282` | `rsa-pss-sha384` | `maven/nimbus-jose-jwt/src/main/java/com/nimbusds/jose/crypto/RSASSAProvider.java:61` | **FP** | dispatch | algs.add(JWSAlgorithm.PS384) building SUPPORTED_ALGORITHMS — enum constant |
| 80 | `CRYPTO-256` | `sha-512` | `maven/nimbus-jose-jwt/src/main/java/com/nimbusds/jose/jca/JCASupport.java:105` | **FP** | dispatch | } else if (alg.equals(JWSAlgorithm.HS512)) in JCASupport — comparison operand |
| 81 | `CRYPTO-283` | `rsa-pss-sha512` | `maven/nimbus-jose-jwt/src/main/java/com/nimbusds/jose/jca/JCASupport.java:125` | **FP** | dispatch | } else if (alg.equals(JWSAlgorithm.PS512)) — comparison operand |
| 82 | `CRYPTO-251` | `ecdsa-p256` | `maven/nimbus-jose-jwt/src/main/java/com/nimbusds/jose/jca/JCASupport.java:135` | **FP** | dispatch | if (alg.equals(JWSAlgorithm.ES256)) — comparison operand |
| 83 | `CRYPTO-254` | `rsa-oaep-256` | `maven/nimbus-jose-jwt/src/main/java/com/nimbusds/jose/jca/JCASupport.java:192` | **FP** | dispatch | } else if (alg.equals(JWEAlgorithm.RSA_OAEP_256)) — comparison operand |
| 84 | `CRYPTO-251` | `ecdsa-p256` | `maven/nimbus-jose-jwt/src/main/java/com/nimbusds/jose/jwk/Curve.java:324` | **FP** | dispatch | if (JWSAlgorithm.ES256.equals(alg)) in Curve.forJWSAlgorithm — comparison operand |
| 85 | `CRYPTO-222` | `sha-256` | `maven/nimbus-jose-jwt/src/main/java/com/nimbusds/jose/jwk/ECKey.java:1430` | **TP** | — | MessageDigest.getInstance("SHA-256") — real SHA-256 |
| 86 | `CRYPTO-245` | `sha-384` | `maven/jjwt-api/api/src/main/java/io/jsonwebtoken/SignatureAlgorithm.java:115` | **FP** | dispatch | Arrays.asList(HS512, HS384, HS256) — a preference list of enum constants |
| 87 | `CRYPTO-246` | `sha-512` | `maven/jjwt-api/api/src/main/java/io/jsonwebtoken/SignatureAlgorithm.java:115` | **FP** | dispatch | Arrays.asList(HS512, HS384, HS256) — a preference list of enum constants |
| 88 | `CRYPTO-244` | `ecdsa-p256` | `maven/jjwt-api/api/src/main/java/io/jsonwebtoken/SignatureAlgorithm.java:118` | **FP** | dispatch | Arrays.asList(ES512, ES384, ES256) — a preference list; the id also says ecdsa-p256 while the message says ES384 |
| 89 | `CRYPTO-222` | `sha-256` | `maven/tomcat-embed-core/java/org/apache/catalina/webresources/AbstractResource.java:141` | **TP** | — | MessageDigest.getInstance("SHA-256") in AbstractResource — real SHA-256 |
| 90 | `CRYPTO-261` | `rsa-pss-sha256` | `maven/jose4j/src/main/java/org/jose4j/jws/RsaUsingShaAlgorithm.java:67` | **FP** | — | super(AlgorithmIdentifiers.RSA_PSS_USING_SHA384, "SHA384withRSAandMGF1") published as rsa-pss-sha256 — id contradicts the line |
| 91 | `CRYPTO-260` | `rsa-pkcs1-sha256` | `maven/jose4j/src/main/java/org/jose4j/jws/RsaUsingShaAlgorithm.java:89` | **TP** | — | super(AlgorithmIdentifiers.RSA_USING_SHA256, "SHA256withRSA") — constructs the signer; id matches |
| 92 | `CRYPTO-222` | `sha-256` | `maven/conscrypt-openjdk-uber/common/src/main/java/org/conscrypt/ct/CertificateEntry.java:106` | **TP** | — | MessageDigest.getInstance("SHA-256") then update/digest — real |
| 93 | `DEP-001` | `unknown` | `maven/jetty-server/jetty-core/jetty-annotations/pom.xml:20` | **TP** | dep | jetty-annotations/pom.xml declares org.eclipse.jetty:jetty-server |
| 94 | `DEP-001` | `unknown` | `maven/jetty-server/jetty-core/jetty-client/pom.xml:67` | **TP** | dep | jetty-client/pom.xml declares jetty-server (test scope) |
| 95 | `DEP-001` | `unknown` | `maven/jetty-server/jetty-core/jetty-coreapp/pom.xml:20` | **TP** | dep | jetty-coreapp/pom.xml declares jetty-server |
| 96 | `DEP-001` | `unknown` | `maven/jetty-server/jetty-core/jetty-fcgi/jetty-fcgi-server/pom.xml:19` | **TP** | dep | jetty-fcgi-server/pom.xml declares jetty-server |
| 97 | `DEP-001` | `unknown` | `maven/jetty-server/jetty-core/jetty-keystore/pom.xml:43` | **TP** | dep | jetty-keystore/pom.xml declares jetty-server (test scope) |
| 98 | `DEP-001` | `unknown` | `maven/jetty-server/jetty-core/jetty-tests/jetty-test-coreapps/jetty-test-coreapp-http2-client/pom.xml:20` | **TP** | dep | jetty-test-coreapp-http2-client/pom.xml declares jetty-server |
| 99 | `DEP-001` | `unknown` | `maven/jetty-server/jetty-core/jetty-tests/jetty-test-jmx/pom.xml:24` | **TP** | dep | jetty-test-jmx/pom.xml declares jetty-server |
| 100 | `CRYPTO-220` | `md5` | `maven/jetty-server/jetty-core/jetty-util/src/main/java/org/eclipse/jetty/util/security/Credential.java:277` | **TP** | — | MessageDigest.getInstance("MD5") then digest(password) — real MD5 |
| 101 | `DEP-001` | `unknown` | `maven/jetty-server/jetty-demos/jetty-core-demos/jetty-core-demo-handler/pom.xml:25` | **TP** | dep | jetty-core-demo-handler/pom.xml declares jetty-server |
| 102 | `DEP-001` | `unknown` | `maven/jetty-server/jetty-ee10/jetty-ee10-fcgi-proxy/pom.xml:18` | **TP** | dep | jetty-ee10-fcgi-proxy/pom.xml declares jetty-server |
| 103 | `CRYPTO-221` | `sha-1` | `maven/jetty-server/jetty-ee10/jetty-ee10-servlets/src/test/java/org/eclipse/jetty/ee10/servlets/AbstractGzipTest.java:73` | **TP** | — | MessageDigest.getInstance("SHA1") — real SHA-1 |
| 104 | `DEP-001` | `unknown` | `maven/jetty-server/jetty-ee11/jetty-ee11-fcgi-proxy/pom.xml:18` | **TP** | dep | jetty-ee11-fcgi-proxy/pom.xml declares jetty-server |
| 105 | `DEP-001` | `unknown` | `maven/jetty-server/jetty-ee11/jetty-ee11-servlet/pom.xml:33` | **TP** | dep | jetty-ee11-servlet/pom.xml declares jetty-server |
| 106 | `DEP-001` | `unknown` | `maven/jetty-server/jetty-ee11/jetty-ee11-tests/jetty-ee11-test-loginservice/pom.xml:20` | **TP** | dep | jetty-ee11-test-loginservice/pom.xml declares jetty-server |
| 107 | `DEP-001` | `unknown` | `maven/jetty-server/jetty-ee9/jetty-ee9-fcgi-proxy/pom.xml:18` | **TP** | dep | jetty-ee9-fcgi-proxy/pom.xml declares jetty-server |
| 108 | `DEP-001` | `unknown` | `maven/jetty-server/jetty-ee9/jetty-ee9-tests/jetty-ee9-test-sessions/jetty-ee9-test-sessions-jdbc/pom.xml:25` | **TP** | dep | jetty-ee9-test-sessions-jdbc/pom.xml declares jetty-server |
| 109 | `DEP-001` | `unknown` | `maven/jetty-server/jetty-integrations/jetty-ethereum/pom.xml:31` | **TP** | dep | jetty-ethereum/pom.xml declares jetty-server |
| 110 | `DEP-001` | `unknown` | `maven/jetty-server/tests/test-distribution/test-distribution-common/pom.xml:76` | **TP** | dep | test-distribution-common/pom.xml declares org.bouncycastle:bcprov-jdk18on |
| 111 | `CRYPTO-340` | `webcrypto-unattributed` | `npm/jose/src/key/generate_key_pair.ts:177` | **TP** | — | crypto.subtle.generateKey(algorithm, ...) — real generateKey; the sentinel asserts no algorithm |
| 112 | `CRYPTO-398` | `webcrypto-unattributed` | `npm/jose/src/lib/content_encryption.ts:106` | **TP** | — | crypto.subtle.sign('HMAC', macKey, macData) — real HMAC sign |
| 113 | `CRYPTO-340` | `webcrypto-unattributed` | `npm/jose/src/lib/content_encryption.ts:150` | **TP** | — | crypto.subtle.generateKey(algorithm, false, ['sign']) — real generateKey |
| 114 | `CRYPTO-340` | `webcrypto-unattributed` | `npm/jose/src/lib/key_management.ts:193` | **TP** | — | crypto.subtle.generateKey(key.algorithm as EcKeyAlgorithm, true, ['deriveBits']) — real |
| 115 | `CRYPTO-382` | `sha-256` | `npm/jsonwebtoken/test/async_sign.tests.js:24` | **TP** | — | jwt.sign({abc:1}, "secret", {}, cb) — real HS256 signature |
| 116 | `CRYPTO-382` | `sha-256` | `npm/jsonwebtoken/test/async_sign.tests.js:31` | **TP** | — | jwt.sign({abc:1}, "secret", cb) — real HS256 signature |
| 117 | `CRYPTO-367` | `rsa-pss-sha256` | `npm/jsonwebtoken/test/async_sign.tests.js:81` | **FP** | throws | jwt.sign(..., {algorithm:'PS256'}) in a test whose comment says it throws; expect(err).to.be.ok |
| 118 | `CRYPTO-382` | `sha-256` | `npm/jsonwebtoken/test/async_sign.tests.js:97` | **FP** | throws | jwt.sign('string','secret',...) in 'should return error on wrong arguments'; expect(err).to.be.ok |
| 119 | `CRYPTO-382` | `sha-256` | `npm/jsonwebtoken/test/buffer.tests.js:7` | **TP** | — | jwt.sign(payload, "signing key") — real HS256 signature |
| 120 | `CRYPTO-360` | `rsa-pkcs1-sha256` | `npm/jsonwebtoken/test/jwt.asymmetric_signing.tests.js:48` | **DEPENDS** | — | jwt.sign({foo:'bar'}, priv, {algorithm: algorithm}) — real signature, the algorithm is a loop variable |
| 121 | `CRYPTO-361` | `sha-256` | `npm/jsonwebtoken/test/jwt.hs.tests.js:15` | **FP** | throws | jwt.sign(...) inside expect(...).to.throw('must be a symmetric key') |
| 122 | `CRYPTO-361` | `sha-256` | `npm/jsonwebtoken/test/jwt.hs.tests.js:21` | **FP** | throws | jwt.sign(undefined, ...) inside expect(...).to.throw('payload is required') |
| 123 | `CRYPTO-361` | `sha-256` | `npm/jsonwebtoken/test/option-nonce.test.js:12` | **TP** | — | jwt.sign({nonce:'abcde'}, 'secret', {algorithm:'HS256'}) in beforeEach — real signature |
| 124 | `CRYPTO-364` | `rsa-pkcs1-sha256` | `npm/jsonwebtoken/test/rsa-public-key.tests.js:22` | **FP** | throws | jwt.sign(...) inside expect(...).to.throw('minimum key size') |
| 125 | `CRYPTO-364` | `rsa-pkcs1-sha256` | `npm/jsonwebtoken/test/rsa-public-key.tests.js:31` | **TP** | — | jwt.sign(..., {algorithm:'RS256', allowInsecureKeySizes:true}, done) — succeeds, real RS256 |
| 126 | `CRYPTO-382` | `sha-256` | `npm/jsonwebtoken/test/set_headers.tests.js:7` | **TP** | — | jwt.sign({foo:123},'123',{header:{...}}) — real HS256 signature |
| 127 | `CRYPTO-372` | `3des` | `npm/jsrsasign/jsrsasign-all-min.js:231` | **TP** | — | minified line carries CryptoJS.TripleDES.encrypt/decrypt verbatim — real 3DES |
| 128 | `CRYPTO-372` | `3des` | `npm/jsrsasign/jsrsasign-rsa-min.js:98` | **TP** | — | minified line carries CryptoJS.TripleDES.encrypt/decrypt verbatim |
| 129 | `CRYPTO-372` | `3des` | `npm/jsrsasign/min/crypto-1.1.min.js:1` | **TP** | — | minified line carries CryptoJS.TripleDES.encrypt/decrypt verbatim |
| 130 | `CRYPTO-370` | `aes-unattributed` | `npm/jsrsasign/npm/lib/jsrsasign-all-min.js:231` | **TP** | — | minified line carries CryptoJS.AES.encrypt/decrypt verbatim |
| 131 | `CRYPTO-372` | `3des` | `npm/jsrsasign/npm/lib/jsrsasign-all-min.js:231` | **TP** | — | minified line carries CryptoJS.TripleDES.encrypt/decrypt verbatim |
| 132 | `CRYPTO-370` | `aes-unattributed` | `npm/jsrsasign/npm/lib/jsrsasign.js:236` | **TP** | — | minified line carries CryptoJS.AES.encrypt/decrypt verbatim |
| 133 | `CRYPTO-372` | `3des` | `npm/jsrsasign/npm/lib/jsrsasign.js:240` | **TP** | — | var KEYUTIL=... k(CryptoJS.TripleDES,p,r,q) — real 3DES |
| 134 | `CRYPTO-370` | `aes-unattributed` | `npm/jsrsasign/src/crypto-1.1.js:1435` | **TP** | — | wEnc = CryptoJS.AES.encrypt(wPlain, wKey, {iv: wIV}) — real AES |
| 135 | `CRYPTO-370` | `aes-unattributed` | `npm/jsrsasign/src/crypto-1.1.js:1485` | **TP** | — | wDec = CryptoJS.AES.decrypt({ciphertext: wEnc}, wKey, {iv: wIV}) — real AES |
| 136 | `CRYPTO-161` | `sha-256` | `pypi/jose/tests/test_jwt.py:181` | **TP** | — | jwt.encode({...}, key, algorithm="HS256") — real HS256 |
| 137 | `CRYPTO-104` | `rsa-unattributed` | `pypi/paramiko/paramiko/rsakey.py:184` | **TP** | — | rsa.generate_private_key(public_exponent=65537, key_size=bits) — real; id asserts no modulus |
| 138 | `CRYPTO-170` | `rsa-undersized` | `pypi/pycryptodome/lib/Crypto/SelfTest/Signature/test_pkcs1_15.py:61` | **TP** | — | RSA.generate(1024).public_key() — id matches the literal |
| 139 | `CRYPTO-170` | `rsa-undersized` | `pypi/pycryptodome/lib/Crypto/SelfTest/Signature/test_pss.py:232` | **TP** | — | RSA.generate(1280) — rsa-undersized is correct for 1280 |
| 140 | `CRYPTO-171` | `rsa-2048` | `pypi/pycryptodome/pct-speedtest.py:246` | **TP** | — | RSA.generate(2048) — id matches the literal |
| 141 | `CRYPTO-163` | `ecdsa-p256` | `pypi/pyjwt/tests/test_algorithms.py:1431` | **FP** | throws | jwt.encode(..., p384_key, algorithm="ES256") inside pytest.raises(InvalidKeyError) |
| 142 | `CRYPTO-161` | `sha-256` | `pypi/pyjwt/tests/test_api_jwt.py:960` | **TP** | — | jwt.encode({}, secret, algorithm="HS256") — succeeds; the raises is on decode |
| 143 | `CRYPTO-161` | `sha-256` | `pypi/pyjwt/tests/test_api_jwt.py:972` | **TP** | — | jwt.encode(payload, secret, algorithm="HS256") — succeeds |
| 144 | `CRYPTO-161` | `sha-256` | `pypi/pyjwt/tests/test_api_jwt.py:1005` | **TP** | — | jwt.encode(payload, secret, algorithm="HS256") — succeeds |
| 145 | `CRYPTO-161` | `sha-256` | `pypi/pyjwt/tests/test_jwt.py:16` | **TP** | — | jwt.encode(payload, secret, algorithm="HS256") — real |
| 146 | `CRYPTO-440` | `x25519` | `pypi/pynacl/src/libsodium/test/default/box7.c:27` | **TP** | — | crypto_box_keypair(bobpk, bobsk) in libsodium's own tests — real X25519 |
| 147 | `CRYPTO-440` | `x25519` | `pypi/pynacl/src/libsodium/test/default/box_easy2.c:46` | **TP** | — | crypto_box_keypair(bobpk, bobsk) — real X25519 |
| 148 | `CRYPTO-441` | `ed25519` | `pypi/pynacl/src/libsodium/test/default/sign.c:1282` | **TP** | — | crypto_sign_keypair(pk, sk) in libsodium's own sign.c — genuinely Ed25519 here |
| 149 | `CRYPTO-140` | `md5` | `pypi/requests/src/requests/auth.py:179` | **TP** | — | hashlib.md5(x, usedforsecurity=False).hexdigest() — real MD5 |

---

## 6. Follow-up, 2026-08-28 — the dispatch shape from § 2 is suppressed

§ 2 named four false-positive shapes in the held stratum. This section records what happened when
the second and largest of them — **Java JOSE dispatch, 13 of the 150 rows** — was removed from the
scanner, measured on the same two label sets and with no row of either re-scored.

**The decision § 2 recorded in advance is the one that shipped.** *"Both spellings are FP"* — the
Go registry lookup, already suppressed in `PRECISION_AUDIT_V3.md § 0`, and the Java comparison /
collection. Nothing was relabelled to make this change look better; the 13 rows were labelled FP
before the change existed, and they simply stop resolving afterwards.

### What moved on the corpus

| | pre (`ea447cb`) | post |
|---|---|---|
| Findings, `nist-default` | 1479 | **1399** |
| Call sites added / removed | — | **0 / 80** |
| Existing call sites re-classified | — | **0** |
| Java enum-constant findings | 94 | **14** |
| — on a line that only compares or collects the name | 71 | **0** |
| Ecosystems that moved | — | **`maven` only**, 366 → 286 |
| Go line-exact recall | 74.4 % | **74.4 %**, re-measured |

The 80 removed sites are 76 distinct lines: 44 `equals` / `==` comparisons, 18 `algs.add(…)`,
9 `map.put(…)`, 6 findings on 2 `Arrays.asList(…)` lines, and 3 `return JWSAlgorithm.ESxxx;`.

### The 13 rows, and the ones that were not in the sample

All 13 rows tagged `dispatch` in § 5 — 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 86, 87, 88 — stop
resolving on the post dump. Stratum A's surviving audited set goes **111 TP / 23 FP / 5 DEPENDS →
111 TP / 10 FP / 5 DEPENDS**, i.e. 82.8 % → **91.7 %** (Wilson 85.5–95.4). No row moved from one
verdict to another; 13 rows left the population.

Three removed sites were **not** in any audited sample and are labelled here, by opening the file:
`nimbus-jose-jwt/.../crypto/ECDSA.java:75, 77, 79` are the three arms of
`public static JWSAlgorithm resolveAlgorithm(final Curve curve)`, which returns the JWS algorithm
matching a curve. Returning an algorithm's name signs nothing — the caller that receives it is
where the operation happens — so they are **FP**, the Java spelling of the `RegistryLookup` shape.
They are removed because they fall outside the new allow-list, not because the scanner recognises
a resolver return; that distinction is recorded rather than smoothed over.

Row 89 of § 5 — `jose4j/.../RsaUsingShaAlgorithm.java:67`, `super(AlgorithmIdentifiers.
RSA_PSS_USING_SHA384, …)` published as `rsa-pss-sha256` — **survives, and is still FP**. It is a
different defect in the same file: `CRYPTO-261` matches `RSA_PSS_USING_SHA(256|384|512)` and
publishes `rsa-pss-sha256` for all three. That is the ungrounded-identity class, not the dispatch
class, and it is left open here rather than fixed in a cycle that is removing findings.

### The figure, under both estimators

| estimator | pre (1479) | post (1399) | delta |
|---|---|---|---|
| of record — stratum A held at `217/32/23` | 87.3 % (83.6–91.0) | **87.3 %** (83.5–91.1) | +0.0 pp |
| corrected — stratum A read from § 5 | 84.7 % (80.0–89.4) | **89.9 %** (85.9–94.0) | **+5.2 pp** |

**§ 0's second claim is now demonstrated rather than argued.** It said a held stratum cannot rise,
and predicted that fixing its false positives would be invisible to the published number. Deleting
80 stratum-A false positives moves the estimator of record by **+0.0 pp**: all it can see is the
stratum's weight falling from 0.600 to 0.577 against a stratum B at 87.5 %. The same estimator
gave `alg=none` +0.8 pp for removing 91.

Sensitivity on the post dump, so no reading is hidden:

| variation | figure |
|---|---|
| published (DEPENDS excluded) | **89.9 %** |
| DEPENDS all scored FP | 87.8 % |
| DEPENDS all scored TP | 90.1 % |

§ 3's *"Java JOSE-dispatch rows scored TP instead of FP → 90.5 %"* row no longer has a subject:
those rows are gone from the population, so the whole figure's sensitivity to reversing that call
is now zero on the post dump. The call itself still has to stand behind the Go relabel in
`PRECISION_AUDIT_V3.md § 0`, which is why § 2 put it in writing before either was acted on.

### What § 2 leaves open

Of the four shapes, `alg=none` (11 rows) and dispatch (13 rows) are now both suppressed. The
remaining two are **a call the test requires to fail** (6 rows, cross-language — `jwt.encode(…)`
inside `pytest.raises`, `jwt.sign(…)` inside `expect(…).to.throw`) and **`algorithm_id`
contradicts the cited line** (4 rows, the ungrounded-identity class). They are 10 of the 150 and
are the next two worth taking.

Reproduce both rows: `/opt/cryptoscope/work/w2_precision.py`, which asserts that the pre dump is
row-identical to the dump the recorded baseline was taken on, that the estimator of record
reproduces its own 87.3 % and the corrected estimator its own 84.7 %, that no finding was added,
that nothing outside the Java enum-constant rules lost a site, and that row 91 survives — all
before it prints a figure.

**The recommendation in § 4 is unchanged and is now worth more.** `state/precision.json` holds the
estimator of record; two consecutive cycles have now removed a combined 171 false positives and
been reported to the gate as +0.8 pp and +0.0 pp. Re-anchor the baseline to the figure whose
verdicts are published here.

## 7. Re-derivation, 2026-08-28 — both label sets carried, no row re-scored

A CLI change to scan-mode composition (`--certs` made additive) was measured against corpus B on
the same two dumps this audit uses. **It moved nothing: 1399 findings before, 1399 after, row-
identical on project, rule, file, line, `algorithm_id`, severity and message.** Both estimators
therefore return their own baselines exactly — 87.3 % of record, 89.9 % corrected — and this
section re-scores no verdict in § 5 or § 6.

It is recorded because a figure was reported for that change, and a reported figure with no
written sample behind it is the thing this document exists to prevent. The run is in
`BENCHMARKING_RESULTS.md § "--certs adds a scan mode"`, with the sample sizes and verdicts.

**§ 4's recommendation now has a third consecutive data point.** `state/precision.json` holds the
estimator of record, and the three most recent changes to reach it were reported as **+0.8 pp**
(91 false positives removed), **+0.0 pp** (80 removed) and **+0.0 pp** (a correctness fix the
corpus is structurally unable to see). The estimator of record has not been able to register a
real improvement in three attempts, because the stratum being improved is the one held constant.
Re-anchoring the baseline to the figure whose verdicts are published here remains a human's
decision, and remains the right one.

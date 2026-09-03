/* Fixture: C crypto API calls for quipuu scanner tests. */
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <sodium.h>
#include <mbedtls/rsa.h>
#include <mbedtls/pk.h>

/* CPP-001 / CRYPTO-400 — RSA below 2048 */
void openssl_rsa_weak(void) {
    RSA *rsa = RSA_new();
    RSA_generate_key_ex(rsa, 1024, NULL, NULL);
}

/* CPP-001 / CRYPTO-401 — RSA 2048 */
void openssl_rsa_2048(void) {
    RSA *rsa = RSA_new();
    RSA_generate_key_ex(rsa, 2048, NULL, NULL);
}

/* CPP-001 / CRYPTO-407 — RSA_generate_key_ex, bits in (2048, 4096), e.g.
 * 3072. Backlog #Y57: no named band above matches this; without the
 * catch-all it silently disappears despite the extractor seeing it. */
void openssl_rsa_3072(void) {
    RSA *rsa = RSA_new();
    RSA_generate_key_ex(rsa, 3072, NULL, NULL);
}

/* CPP-002 / CRYPTO-403 — legacy RSA_generate_key, bits in position 1 */
void openssl_rsa_legacy_weak(void) {
    RSA *rsa = RSA_generate_key(1024, 3, NULL, NULL);
}

/* CPP-002 — wrapped in a wolfssl-style assertion that requires the call to
 * FAIL; must not be reported (SiteContext::TestAssertion excludes it). */
void openssl_rsa_legacy_expected_to_fail(void) {
    RSA *rsa;
    ExpectNull(rsa = RSA_generate_key(2048, 0, NULL, NULL));
}

/* CPP-002 — wrapped in the sibling macro that requires the call to SUCCEED;
 * must still be reported as a true positive. */
void openssl_rsa_legacy_expected_to_succeed(void) {
    RSA *rsa;
    ExpectNotNull(rsa = RSA_generate_key(2048, 3, NULL, NULL));
}

/* CPP-010 / CRYPTO-410 — DES cipher */
void openssl_evp_des(void) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_des_cbc(), NULL, key, iv);
}

/* CPP-010 / CRYPTO-411 — AES-GCM cipher */
void openssl_evp_aes_gcm(void) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
}

/* CPP-010 / CRYPTO-920..922 — AES-CBC cipher, all three key sizes */
void openssl_evp_aes_cbc(void) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_EncryptInit_ex(ctx, EVP_aes_192_cbc(), NULL, key, iv);
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
}

/* CPP-020 / CRYPTO-420 — MD5 digest */
void openssl_digest_md5(void) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
}

/* CPP-020 / CRYPTO-421 — SHA-1 digest */
void openssl_digest_sha1(void) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
}

/* CPP-020 / CRYPTO-422 — SHA-256 digest */
void openssl_digest_sha256(void) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
}

/* CPP-020 / CRYPTO-423..428 — the wider SHA-2/SHA-3 digest_fn names */
void openssl_digest_wider(void) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha224(), NULL);
    EVP_DigestInit_ex(ctx, EVP_sha384(), NULL);
    EVP_DigestInit_ex(ctx, EVP_sha512(), NULL);
    EVP_DigestInit_ex(ctx, EVP_sha3_256(), NULL);
    EVP_DigestInit_ex(ctx, EVP_sha3_384(), NULL);
    EVP_DigestInit_ex(ctx, EVP_sha3_512(), NULL);
}

/* CPP-030 / CRYPTO-430 — weak cipher string */
void openssl_cipher_list_weak(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    SSL_CTX_set_cipher_list(ctx, "RC4-MD5:DES-CBC-SHA");
}

/* CPP-030 / CRYPTO-431 — the `!` prefix EXCLUDES RC4; this hardens the
   context and must not be reported as enabling it. */
void openssl_cipher_list_excludes_rc4(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    SSL_CTX_set_cipher_list(ctx, "DEFAULT:!RC4:!MD5:!EXPORT");
}

/* #Y62(a) / CRYPTO-909..919 — TLS group preference list, classical-only,
   with a tuple separator and a predicted-keyshare prefix that must be
   stripped before matching. */
void openssl_groups_list_classical_only(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    SSL_CTX_set1_groups_list(ctx, "P-521:*P-256/P-384:X25519");
}

/* #Y62(a) / CRYPTO-909, CRYPTO-1209 — the hybrid ML-KEM groups, plus a
   `?`-ignorable unknown name and the `DEFAULT` pseudo-group, neither of
   which may fire. */
void openssl_groups_list_hybrid(SSL *ssl) {
    SSL_set1_groups_list(ssl, "X25519MLKEM768:curveSM2MLKEM768:?curveSM2:DEFAULT");
}

/* #Y62(b) / CRYPTO-912, CRYPTO-914 — SSL_CONF_cmd's "Groups" config-string
   form, literal value: reuses (a)'s classify block through the
   command-dispatch API rather than the direct setter. */
void openssl_conf_cmd_groups_literal(SSL_CONF_CTX *cctx) {
    SSL_CONF_cmd(cctx, "Groups", "X25519:P-256");
}

/* #Y62(b) / CRYPTO-915 — the pre-3.0 "Curves" alias for the same command,
   command-name matching is case-insensitive per SSL_CONF_cmd(3). */
void openssl_conf_cmd_curves_alias(SSL_CONF_CTX *cctx) {
    SSL_CONF_cmd(cctx, "CURVES", "P-384");
}

/* #Y62(b) — the overwhelming-majority real shape: the value is sourced from
   a config file/CLI argument, not a literal. Must not fire — P4 forbids
   resolving what a runtime config value would be. */
void openssl_conf_cmd_groups_variable(SSL_CONF_CTX *cctx, const char *value) {
    SSL_CONF_cmd(cctx, "Groups", value);
}

/* #Y62(b) — a different SSL_CONF_cmd command name; must not fire even though
   the value looks like a group list. */
void openssl_conf_cmd_other_command(SSL_CONF_CTX *cctx) {
    SSL_CONF_cmd(cctx, "Options", "X25519");
}

/* CPP-040 / CRYPTO-440 — libsodium box keypair */
void sodium_box_kp(void) {
    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    unsigned char sk[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(pk, sk);
}

/* CPP-041 / CRYPTO-441 — libsodium sign keypair */
void sodium_sign_kp(void) {
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk, sk);
}

/* CPP-050 / CRYPTO-450 — mbedTLS RSA init */
void mbedtls_rsa(void) {
    mbedtls_rsa_context rsa;
    mbedtls_rsa_init(&rsa);
}

/* CPP-051 / CRYPTO-451 — mbedTLS pk setup */
void mbedtls_pk(void) {
    mbedtls_pk_context pk;
    mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
}

/* CPP-060 / CRYPTO-461 — liboqs stack-form ML-KEM-768 */
void liboqs_kem_stack(uint8_t *pk, uint8_t *sk, uint8_t *ct, uint8_t *ss, uint8_t *ss2) {
    OQS_KEM_ml_kem_768_keypair(pk, sk);
    OQS_KEM_ml_kem_768_encaps(ct, ss, pk);
    OQS_KEM_ml_kem_768_decaps(ss2, ct, sk);
}

/* CPP-061 / CRYPTO-464 — liboqs stack-form ML-DSA-65 */
void liboqs_sig_stack(uint8_t *pk, uint8_t *sk, uint8_t *msg, size_t msglen, uint8_t *sig, size_t *siglen) {
    OQS_SIG_ml_dsa_65_keypair(pk, sk);
    OQS_SIG_ml_dsa_65_sign(sig, siglen, msg, msglen, sk);
}

/* CPP-062 / CRYPTO-467 — liboqs heap-form KEM, algorithm as a macro argument */
void liboqs_kem_heap(void) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
}

/* CPP-063 / CRYPTO-472..483 — liboqs heap-form SIG, SLH-DSA has no stack-form
   header so OQS_SIG_new is its only call shape. */
void liboqs_sig_heap_slh_dsa(void) {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_slh_dsa_pure_sha2_128s);
}

/* Backlog #Y56 — liboqs heap-form KEM/SIG, algorithm family not in the
   quipuu table (HQC, NIST's selected backup KEM; MAYO, a signature
   on-ramp candidate). Extracted and recorded, not silently dropped. */
void liboqs_kem_heap_unattributed(void) {
    OQS_KEM *hqc128 = OQS_KEM_new(OQS_KEM_alg_hqc_128);
    OQS_KEM *hqc192 = OQS_KEM_new(OQS_KEM_alg_hqc_192);
    OQS_KEM *hqc256 = OQS_KEM_new(OQS_KEM_alg_hqc_256);
}

void liboqs_sig_heap_unattributed(void) {
    OQS_SIG *mayo = OQS_SIG_new(OQS_SIG_alg_mayo_1);
}

/* Out of scope: OQS_SIG_STFL_* is the stateful hash-signature API (LMS/XMSS),
   a firmware-signing population this project does not target. Must not fire. */
void liboqs_stfl_out_of_scope(void) {
    OQS_SIG_STFL *sig = OQS_SIG_STFL_new("LMS_SHA256_H10_W8");
}

/* CPP-064 / CRYPTO-484..486 — OpenSSL 3.0+ generic keygen, classical algorithms */
void openssl_generic_keygen_classical(OSSL_LIB_CTX *libctx) {
    EVP_PKEY_CTX *rsa_ctx = EVP_PKEY_CTX_new_from_name(libctx, "RSA", NULL);
    EVP_PKEY_CTX *ec_ctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", NULL);
    EVP_PKEY *dh_key = EVP_PKEY_Q_keygen(libctx, NULL, "DH");
}

/* CPP-065 / CRYPTO-489 — OpenSSL 3.0+ generic keygen, ML-KEM-1024 via the
   one-shot EVP_PKEY_Q_keygen form (mirrors #Y52's cited
   ml_kem_evp_extra_test.c call shape). */
void openssl_generic_keygen_ml_kem(OSSL_LIB_CTX *libctx) {
    EVP_PKEY *kem_key = EVP_PKEY_Q_keygen(libctx, NULL, "ML-KEM-1024");
}

/* CRYPTO-1065..1068 — OpenSSL 3.5's hybrid PQ/T KEM key types, reachable
   through the same generic keygen entry points (backlog #Y92). Verified
   against docs.openssl.org/master/man7/EVP_PKEY-MLX-KEM/, fetched
   2026-09-01. X448MLKEM1024 has no IANA TLS supported_groups codepoint as
   of that fetch, so unlike its three siblings it has no matching arm on
   SSL_CTX_set1_groups_list above — only on this generic keygen API. */
void openssl_generic_keygen_hybrid(OSSL_LIB_CTX *libctx) {
    EVP_PKEY *hybrid1 = EVP_PKEY_Q_keygen(libctx, NULL, "X25519MLKEM768");
    EVP_PKEY *hybrid2 = EVP_PKEY_Q_keygen(libctx, NULL, "SecP256r1MLKEM768");
    EVP_PKEY *hybrid3 = EVP_PKEY_Q_keygen(libctx, NULL, "SecP384r1MLKEM1024");
    EVP_PKEY *hybrid4 = EVP_PKEY_Q_keygen(libctx, NULL, "X448MLKEM1024");
}

/* CRYPTO-1137 — OpenSSL 3.6's native LMS support (backlog #Y113, narrowed by
   #Y115). LMS keygen is not implemented by any OpenSSL provider — SP 800-208
   treats key generation as a deliberate out-of-band process — so the only
   real call shape is EVP_PKEY_CTX_new_from_name() followed by
   EVP_PKEY_fromdata() to import an externally-generated key for
   verification. Verified against docs.openssl.org/3.6/man7/EVP_PKEY-LMS/,
   fetched 2026-09-02. */
void openssl_generic_keygen_lms(OSSL_LIB_CTX *libctx, OSSL_PARAM *params) {
    EVP_PKEY_CTX *lms_ctx = EVP_PKEY_CTX_new_from_name(libctx, "LMS", NULL);
    EVP_PKEY *lms_key = EVP_PKEY_fromdata(lms_ctx, EVP_PKEY_PUBLIC_KEY, params);
}

/* CPP-066 / CPP-067, CRYPTO-960 / CRYPTO-961 — OpenSSL 3.5+ generic KEM
   operation API (EVP_PKEY_encapsulate/decapsulate). Neither call carries an
   algorithm argument of its own — it lives on the EVP_PKEY_CTX built earlier
   — so both must degrade to kem-unattributed rather than produce nothing.
   Backlog #Y69 (KEM half). Mirrors the shape of cms_kemri.c's real
   RFC 9629 KEMRecipientInfo call sites. */
void openssl_kem_operation(EVP_PKEY_CTX *ctx, unsigned char *wrapped,
                            size_t *wrapped_len, unsigned char *genkey,
                            size_t *genkey_len, unsigned char *unwrapped,
                            size_t *unwrapped_len) {
    EVP_PKEY_encapsulate(ctx, wrapped, wrapped_len, genkey, genkey_len);
    EVP_PKEY_decapsulate(ctx, unwrapped, unwrapped_len, wrapped, wrapped_len);
}

/* CPP-068, CRYPTO-973..991 — OpenSSL 3.5+'s EVP_SIGNATURE_fetch(libctx, name,
   propq), the constructing call behind the generic message-signing operation
   API (EVP_PKEY_sign_message_init/verify_message_init). Unlike that operation
   pair, the fetch call names its algorithm as a literal string directly, so
   it needs no cross-statement trace and correctly attributes both classical
   (RSA/ECDSA/Ed25519/Ed448) and PQC (ML-DSA/SLH-DSA) fetches. Backlog #Y70,
   scoped away from the originally-filed blanket sig-unattributed approach
   because corpus evidence (eddsa_sig.c, cms_sd.c's cms_mdless_signing) shows
   classical EdDSA also dispatches through sign_message_init/verify_message_init. */
void openssl_signature_fetch(OSSL_LIB_CTX *libctx) {
    EVP_SIGNATURE *rsa_sig = EVP_SIGNATURE_fetch(libctx, "RSA", NULL);
    EVP_SIGNATURE *ecdsa_sig = EVP_SIGNATURE_fetch(libctx, "ECDSA", NULL);
    EVP_SIGNATURE *ed25519_sig = EVP_SIGNATURE_fetch(libctx, "ED25519", NULL);
    EVP_SIGNATURE *ed448_sig = EVP_SIGNATURE_fetch(libctx, "ED448", NULL);
    EVP_SIGNATURE *mldsa44_sig = EVP_SIGNATURE_fetch(libctx, "ML-DSA-44", NULL);
    EVP_SIGNATURE *mldsa65_sig = EVP_SIGNATURE_fetch(libctx, "ML-DSA-65", NULL);
    EVP_SIGNATURE *mldsa87_sig = EVP_SIGNATURE_fetch(libctx, "ML-DSA-87", NULL);
    EVP_SIGNATURE *slhdsa_sig = EVP_SIGNATURE_fetch(libctx, "SLH-DSA-SHAKE-256f", NULL);
}

/* CPP-069, CRYPTO-1036..1045 — OpenSSL 4.0+'s fetch-by-name digest API
   (EVP_MD_fetch(libctx, name, propq)), the documented replacement for the
   typed EVP_DigestInit_ex(ctx, EVP_sha256(), ...) form above, plus the same
   entry point's FIPS 204 external-mu pseudo-digest ("ML-DSA-MU"), added in
   OpenSSL 4.0.0 for HSM-split ML-DSA signing. Backlog #Y85. */
void openssl_md_fetch(OSSL_LIB_CTX *libctx) {
    EVP_MD *md5_md = EVP_MD_fetch(libctx, "MD5", NULL);
    EVP_MD *sha1_md = EVP_MD_fetch(libctx, "SHA1", NULL);
    EVP_MD *sha256_md = EVP_MD_fetch(libctx, "SHA256", NULL);
    EVP_MD *sha3_512_md = EVP_MD_fetch(libctx, "SHA3-512", NULL);
    EVP_MD *mldsamu_md = EVP_MD_fetch(libctx, "ML-DSA-MU", NULL);
}

/* CPP-070 / CRYPTO-1050 — Windows CNG BCryptGenerateKeyPair against the
   ML-KEM pseudo-handle, Microsoft's own cng-mlkem-examples idiom. */
void cng_mlkem_generate(void) {
    BCRYPT_KEY_HANDLE hKeyPair;
    BCryptGenerateKeyPair(BCRYPT_MLKEM_ALG_HANDLE, &hKeyPair, 0, 0);
}

/* CPP-071 / CRYPTO-1050 — the server-side ML-KEM import half of the same
   Microsoft example. */
void cng_mlkem_import(unsigned char *blob, unsigned long cbBlob) {
    BCRYPT_KEY_HANDLE hKeyPair;
    BCryptImportKeyPair(BCRYPT_MLKEM_ALG_HANDLE, NULL,
                         BCRYPT_MLKEM_ENCAPSULATION_BLOB, &hKeyPair, blob,
                         cbBlob, 0);
}

/* CPP-072 / CRYPTO-1051 — Windows CNG BCryptOpenAlgorithmProvider against
   ML-DSA, Microsoft's own cng-mldsa-examples idiom; must not fire on a
   classical algorithm through the same entry point. */
void cng_mldsa_open_provider(void) {
    BCRYPT_ALG_HANDLE hAlg;
    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_MLDSA_ALGORITHM,
                                 MS_PRIMITIVE_PROVIDER, NULL);
    BCRYPT_ALG_HANDLE hRsaAlg;
    BCryptOpenAlgorithmProvider(&hRsaAlg, BCRYPT_RSA_ALGORITHM, NULL, 0);
}

/* CPP-073 / CRYPTO-1051 — Windows CNG NCryptIsAlgSupported against ML-DSA, a
   real call site independently found in Chromium's
   net/ssl/ssl_platform_key_win_unittest.cc. */
void cng_mldsa_is_supported(NCRYPT_PROV_HANDLE prov) {
    NCryptIsAlgSupported(prov, BCRYPT_MLDSA_ALGORITHM, NCRYPT_SILENT_FLAG);
}

/* CPP-074..079 / CRYPTO-1193..1198 — Backlog #Y136's six real, idiomatic
   pre-3.0 OpenSSL call shapes, previously zero coverage. */
void legacy_openssl_1x(void) {
    EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    MD5_CTX md5_ctx;
    MD5_Init(&md5_ctx);
    SHA_CTX sha1_ctx;
    SHA1_Init(&sha1_ctx);
    SHA256_CTX sha256_ctx;
    SHA256_Init(&sha256_ctx);
    PKCS5_PBKDF2_HMAC("pass", 4, NULL, 0, 600000, EVP_sha256(), 32, NULL);
    ECDSA_sign(0, NULL, 0, NULL, NULL, eckey);
}

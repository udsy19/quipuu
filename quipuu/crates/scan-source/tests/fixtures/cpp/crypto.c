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

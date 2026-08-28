/* Fixture: C crypto API calls for seawall scanner tests. */
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

#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>
#include <openssl/des.h>
#include <openssl/rc4.h>

void probe(void) {
    EVP_RSA_gen(2048);                                              /* EXPECT rsa */
    EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);                 /* EXPECT ecdsa */
    EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);                         /* EXPECT dh */
    MD5_Init(NULL);                                                 /* EXPECT md5 */
    SHA1_Init(NULL);                                                /* EXPECT sha1 */
    SHA256_Init(NULL);                                              /* EXPECT sha256 */
    EVP_sha384();                                                   /* EXPECT sha384 */
    HMAC(EVP_sha256(), NULL, 0, NULL, 0, NULL, NULL);               /* EXPECT hmac */
    PKCS5_PBKDF2_HMAC(NULL, 0, NULL, 0, 600000, EVP_sha256(), 32, NULL); /* EXPECT pbkdf2 */
    EVP_aes_128_gcm();                                              /* EXPECT aes128 */
    EVP_aes_256_gcm();                                              /* EXPECT aes256 */
    EVP_des_ede3_cbc();                                             /* EXPECT 3des */
    EVP_rc4();                                                      /* EXPECT rc4 */
    EVP_chacha20_poly1305();                                        /* EXPECT chacha20 */
    ECDSA_sign(0, NULL, 0, NULL, NULL, NULL);                       /* EXPECT ecdsa */
}

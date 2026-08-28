/* Fixture: the NIST PQC reference-implementation shape.
 *
 * `crypto_sign_keypair` is not libsodium's name alone — every PQC reference
 * implementation publishes its keygen under it, because it is the SUPERCOP
 * signature API. This file is the shape of `dilithium/ref/test/test_dilithium.c`
 * and `sphincsplus/ref/test/spx.c`: the same call, no NaCl header anywhere.
 *
 * Reading the identifier alone reported ed25519 on both of those trees and
 * told a FIPS 204 implementation to migrate to FIPS 204. The pair
 * crypto.c / this file is what holds the qualification in place: the call is
 * byte-identical in both, and only the includes differ.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "../randombytes.h"
#include "../params.h"
#include "../sign.h"

int main(void) {
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];

    crypto_sign_keypair(pk, sk);
    return 0;
}

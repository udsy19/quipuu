/* Fixture: the NaCl header behind a portability guard.
 *
 * Real libsodium consumers rarely include it unconditionally. If the import
 * collector only reads top-level `#include`, this file looks exactly like a
 * PQC reference implementation and the Ed25519 arm goes quiet on a genuine
 * Ed25519 call — a branch that is written but never reached is the failure
 * mode this pack has hit before.
 */
#include <stdio.h>

#ifdef HAVE_LIBSODIUM
#include <sodium.h>
#endif

void guarded_sign_kp(void) {
    unsigned char pk[32];
    unsigned char sk[64];
    crypto_sign_keypair(pk, sk);
}

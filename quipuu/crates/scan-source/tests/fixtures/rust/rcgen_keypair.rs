// rcgen::KeyPair::generate_for — the algorithm is entirely the argument.
//
// One call shape selects ECDSA on three curves, Ed25519, RSA with three
// digests, or ML-DSA at all three parameter sets, so nothing about the callee
// decides the identity. The first two lines are the ones this fixture exists
// for: they had been reported as quantum-vulnerable ECDSA on code that has
// already migrated to FIPS 204.
//
// Shapes covered deliberately: `&rcgen::CONST`, a bare imported `CONST`, a
// `module::CONST` path, and three non-literals (a local, a struct field, a
// re-exported alias) that name no algorithm at this line.

use rcgen::{KeyPair, PKCS_ED25519, PKCS_RSA_SHA384};

fn migrated() {
    let ca = KeyPair::generate_for(&rcgen::PKCS_ML_DSA_44).unwrap();
    let ee = KeyPair::generate_for(&rcgen::PKCS_ML_DSA_87).unwrap();
    let mid = KeyPair::generate_for(&rcgen::PKCS_ML_DSA_65).unwrap();
}

fn classical() {
    let p256 = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let p384 = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
    // P-521 is offered with three digests; the curve is the same in all three.
    let p521 = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P521_SHA256).unwrap();
    let ed = KeyPair::generate_for(PKCS_ED25519).unwrap();
    let rsa = KeyPair::generate_for(&PKCS_RSA_SHA384).unwrap();
}

fn not_stated_here(alg: &'static rcgen::SignatureAlgorithm) {
    let from_local = KeyPair::generate_for(alg).unwrap();
    let from_alias = KeyPair::generate_for(test_utils::RCGEN_SIGNATURE_ALG).unwrap();
    let from_field = KeyPair::generate_for(self.inner).unwrap();
}

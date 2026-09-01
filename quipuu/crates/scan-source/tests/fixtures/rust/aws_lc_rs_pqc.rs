// aws-lc-rs — DecapsulationKey::generate (ML-KEM) / PqdsaKeyPair::generate
// (ML-DSA). Both constructors take the parameter set as their sole argument
// — an associated constant, the same shape rcgen::KeyPair::generate_for
// uses — so nothing about the callee alone decides the identity.
//
// Shapes covered: `&module::CONST`, a bare imported `CONST`, and a local
// variable that names no algorithm at this line.

use aws_lc_rs::kem::{DecapsulationKey, ML_KEM_768};
use aws_lc_rs::signature::PqdsaKeyPair;

fn kem() {
    let k512 = DecapsulationKey::generate(&aws_lc_rs::kem::ML_KEM_512).unwrap();
    let k768 = DecapsulationKey::generate(&ML_KEM_768).unwrap();
    let k1024 = DecapsulationKey::generate(&aws_lc_rs::kem::ML_KEM_1024).unwrap();
}

fn sig() {
    let s44 = PqdsaKeyPair::generate(&aws_lc_rs::signature::ML_DSA_44_SIGNING).unwrap();
    let s65 = PqdsaKeyPair::generate(&aws_lc_rs::signature::ML_DSA_65_SIGNING).unwrap();
    let s87 = PqdsaKeyPair::generate(&aws_lc_rs::signature::ML_DSA_87_SIGNING).unwrap();
}

fn not_stated_here(alg: &'static aws_lc_rs::kem::Algorithm) {
    let from_local = DecapsulationKey::generate(alg).unwrap();
}

// oqs (liboqs-rust, open-quantum-safe/liboqs-rust on crates.io) —
// Kem::new(Algorithm) / Sig::new(Algorithm). Both constructors take the
// parameter set as their sole argument — an `Algorithm` enum variant, the
// same shape rcgen::KeyPair::generate_for and aws-lc-rs's constructors use
// — so nothing about the callee alone decides the identity.
//
// Shapes covered: a scoped enum variant and a local variable that names no
// algorithm at this line.

use oqs::kem::{Algorithm as KemAlgorithm, Kem};
use oqs::sig::{Algorithm as SigAlgorithm, Sig};

fn kem() {
    let k512 = Kem::new(KemAlgorithm::MlKem512).unwrap();
    let k768 = Kem::new(KemAlgorithm::MlKem768).unwrap();
    let k1024 = Kem::new(KemAlgorithm::MlKem1024).unwrap();
}

fn sig() {
    let s44 = Sig::new(SigAlgorithm::MlDsa44).unwrap();
    let s65 = Sig::new(SigAlgorithm::MlDsa65).unwrap();
    let s87 = Sig::new(SigAlgorithm::MlDsa87).unwrap();
}

fn not_stated_here(alg: KemAlgorithm) {
    let from_local = Kem::new(alg).unwrap();
}

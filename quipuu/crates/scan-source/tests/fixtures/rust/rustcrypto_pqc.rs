// Fixture: RustCrypto's own `ml-kem` / `ml-dsa` crates (crates.io/crates/
// ml-kem, crates.io/crates/ml-dsa) — distinct call shapes from the
// already-covered aws-lc-rs (`DecapsulationKey::generate`/`PqdsaKeyPair::
// generate`) and oqs (`Kem::new`/`Sig::new`) paths (#Y145). Verified
// against RustCrypto/KEMs and RustCrypto/signatures source directly:
// `MlKemNNN::generate_keypair()` takes no arguments — the parameter set is
// the receiver type, not a call argument — while `SigningKey::<MlDsaNNN>::
// generate()` carries the parameter set in the turbofish, the same shape
// rsa's `SigningKey::<Sha256>::new()` already uses for its hash algorithm.

use ml_dsa::{MlDsa44, MlDsa65, MlDsa87, SigningKey};
use ml_kem::{MlKem512, MlKem768, MlKem1024};

fn kem() {
    let (_dk512, _ek512) = MlKem512::generate_keypair();
    let (_dk768, _ek768) = MlKem768::generate_keypair();
    let (_dk1024, _ek1024) = MlKem1024::generate_keypair();
}

fn dsa() {
    let _sk44 = SigningKey::<MlDsa44>::generate();
    let _sk65 = SigningKey::<MlDsa65>::generate();
    let _sk87 = SigningKey::<MlDsa87>::generate();
}

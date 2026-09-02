// Fixture: OpenMLS `Ciphersuite::MLS_*` hybrid/PQC ciphersuite enum variants
// (#Y114). Verified against openmls/traits/src/types.rs's `Ciphersuite`
// definition — a bare enum-variant path expression, not a call.

pub enum Ciphersuite {
    MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
    MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519,
    MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87,
    MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519,
    MLS_128_MLKEM768_AES256GCM_SHA384_P256,
    MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65,
}

fn pick_hybrid() -> Ciphersuite {
    // X-Wing arm — must classify as x-wing, not ml-kem-1024/768.
    Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519
}

fn pick_mlkem1024() -> Ciphersuite {
    Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87
}

fn pick_mlkem768_x25519() -> Ciphersuite {
    // Must classify as x25519-mlkem768, not the plain ml-kem-768 arm below.
    Ciphersuite::MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519
}

fn pick_mlkem768_plain() -> Ciphersuite {
    Ciphersuite::MLS_128_MLKEM768_AES256GCM_SHA384_P256
}

fn pick_mlkem768_mldsa() -> Ciphersuite {
    Ciphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65
}

fn pick_classical() -> Ciphersuite {
    // Classical-only variant — no MLKEM/XWING in the name, must NOT fire.
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
}

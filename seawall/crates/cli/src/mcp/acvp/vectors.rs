//! Compile-time vector loader.
//!
//! Each JSON file is embedded via `include_bytes!` so the binary is
//! self-contained — no filesystem access at runtime. The JSON is parsed
//! lazily on first call. Adding a new parameter set requires:
//!   1. Dropping the JSON file into `data/acvp-vectors/`.
//!   2. Adding an `include_bytes!` entry in this module.
//!
//! The bundled set is a representative subset of the full NIST ACVP-Server
//! test vectors. The full repository is available at
//! <https://github.com/usnistgov/ACVP-Server>.

use serde_json::Value;

// ── ML-KEM ───────────────────────────────────────────────────────────────────

pub fn ml_kem_512_keygen() -> Value {
    parse(include_bytes!(
        "../../../data/acvp-vectors/ML-KEM-512-keyGen.json"
    ))
}

pub fn ml_kem_768_encap_decap() -> Value {
    parse(include_bytes!(
        "../../../data/acvp-vectors/ML-KEM-768-encapDecap.json"
    ))
}

pub fn ml_kem_1024_keygen() -> Value {
    parse(include_bytes!(
        "../../../data/acvp-vectors/ML-KEM-1024-keyGen.json"
    ))
}

// ── ML-DSA ───────────────────────────────────────────────────────────────────

pub fn ml_dsa_44_keygen() -> Value {
    parse(include_bytes!(
        "../../../data/acvp-vectors/ML-DSA-44-keyGen.json"
    ))
}

pub fn ml_dsa_65_siggen() -> Value {
    parse(include_bytes!(
        "../../../data/acvp-vectors/ML-DSA-65-sigGen.json"
    ))
}

pub fn ml_dsa_87_sigver() -> Value {
    parse(include_bytes!(
        "../../../data/acvp-vectors/ML-DSA-87-sigVer.json"
    ))
}

// ── SLH-DSA ──────────────────────────────────────────────────────────────────

pub fn slh_dsa_shake_128s_keygen() -> Value {
    parse(include_bytes!(
        "../../../data/acvp-vectors/SLH-DSA-SHAKE-128s-keyGen.json"
    ))
}

pub fn slh_dsa_shake_128s_siggen() -> Value {
    parse(include_bytes!(
        "../../../data/acvp-vectors/SLH-DSA-SHAKE-128s-sigGen.json"
    ))
}

// ── Internal helper ──────────────────────────────────────────────────────────

/// Parse a compile-time-embedded JSON byte slice.
/// Panics on invalid JSON — malformed bundled vectors are a build-time bug.
fn parse(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes)
        .expect("bundled ACVP vector JSON is malformed — this is a compile-time bug")
}

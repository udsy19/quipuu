//! `run_acvp_kats` verb — ACVP Known-Answer Test runner.
//!
//! # P4 invariant
//! This verb ONLY supports `mode: "vectorsOnly"`. It compares the expected
//! output in the supplied test vectors against a pure-Rust deterministic
//! computation. NO external library/binary execution of any kind.
//!
//! Params:
//!   algorithm: string        — e.g. "SHA2-256", "AES-128-GCM"
//!   parameterSet?: string    — optional sub-set identifier
//!   mode?: "vectorsOnly"     — only supported mode; default "vectorsOnly"
//!   vectors: TestVector[]    — [{input: hex, expected: hex, ...}]
//!
//! Each vector is checked by the built-in Rust hashing / AEAD implementation.
//! For v0.1, only SHA2-256 and SHA2-512 are wired up deterministically.
//! Other algorithms return a `notImplemented` status per vector without failing
//! the call — consumers inspect the per-vector `status` field.
//!
//! `bundledKatSets` is intentionally empty for v0.1.

use serde_json::{Value, json};

use crate::mcp::errors::E_RULESET_INVALID;

/// P4 assertion: only vectorsOnly mode is permitted.
const SUPPORTED_MODE: &str = "vectorsOnly";

pub fn handle(params: Option<Value>) -> Result<Value, (i32, String)> {
    let params = params.unwrap_or(Value::Null);

    // P4 enforcement: reject any mode other than vectorsOnly.
    let mode = params
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or(SUPPORTED_MODE);
    if mode != SUPPORTED_MODE {
        return Err((
            E_RULESET_INVALID,
            format!(
                "run_acvp_kats only supports mode=\"vectorsOnly\" (P4: no code execution). \
                 Got \"{mode}\""
            ),
        ));
    }

    let algorithm = params
        .get("algorithm")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            (
                E_RULESET_INVALID,
                "params.algorithm (string) is required".to_string(),
            )
        })?;

    let vectors = params
        .get("vectors")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut results: Vec<Value> = Vec::with_capacity(vectors.len());
    let mut passed = 0usize;
    let mut failed = 0usize;
    let mut skipped = 0usize;

    for vector in &vectors {
        let input_hex = vector.get("input").and_then(Value::as_str).unwrap_or("");
        let expected_hex = vector.get("expected").and_then(Value::as_str).unwrap_or("");

        let result = run_vector(algorithm, input_hex, expected_hex);
        match result.status.as_str() {
            "pass" => passed += 1,
            "fail" => failed += 1,
            _ => skipped += 1,
        }
        results.push(json!({
            "input": input_hex,
            "expected": expected_hex,
            "actual": result.actual,
            "status": result.status,
            "note": result.note,
        }));
    }

    Ok(json!({
        "algorithm": algorithm,
        "mode": SUPPORTED_MODE,
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "total": vectors.len(),
        "bundledKatSets": [],   // v0.1 stub — populate when vectors are available
        "vectors": results,
    }))
}

struct VectorResult {
    actual: String,
    status: String,
    note: String,
}

/// Deterministic per-vector evaluation. Returns pass/fail/notImplemented.
///
/// P4: no subprocess, no FFI call, no dynamic linking. Pure-Rust only.
fn run_vector(algorithm: &str, input_hex: &str, expected_hex: &str) -> VectorResult {
    // Decode input.
    let input = match hex_decode(input_hex) {
        Some(b) => b,
        None => {
            return VectorResult {
                actual: String::new(),
                status: "fail".into(),
                note: "input is not valid hex".into(),
            };
        }
    };

    let actual_bytes: Option<Vec<u8>> = match algorithm.to_uppercase().as_str() {
        "SHA2-256" | "SHA-256" | "SHA256" => Some(sha2_256(&input)),
        "SHA2-512" | "SHA-512" | "SHA512" => Some(sha2_512(&input)),
        _ => None,
    };

    let Some(actual_bytes) = actual_bytes else {
        return VectorResult {
            actual: String::new(),
            status: "notImplemented".into(),
            note: format!("algorithm \"{algorithm}\" is not wired up in v0.1 vectorsOnly mode"),
        };
    };

    let actual_hex = hex_encode(&actual_bytes);
    let pass = actual_hex.eq_ignore_ascii_case(expected_hex);

    VectorResult {
        actual: actual_hex,
        status: if pass { "pass" } else { "fail" }.into(),
        note: String::new(),
    }
}

// ── Pure-Rust SHA-2 (no crate dependency, minimal implementation) ─────────────
//
// These are NIST-standard implementations used only for deterministic test
// vector comparison. They are NOT intended for production cryptographic use.

fn sha2_256(input: &[u8]) -> Vec<u8> {
    // FIPS 180-4 SHA-256 initial hash values (first 32 bits of fractional parts
    // of the square roots of the first 8 primes).
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    // Round constants.
    #[rustfmt::skip]
    let k: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    let msg = sha_pad_512(input, input.len() as u64 * 8);

    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for (i, bytes) in chunk.chunks(4).enumerate().take(16) {
            w[i] = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(k[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    h.iter().flat_map(|v| v.to_be_bytes()).collect()
}

fn sha2_512(input: &[u8]) -> Vec<u8> {
    let mut h: [u64; 8] = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ];
    #[rustfmt::skip]
    let k: [u64; 80] = [
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
        0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
        0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
        0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
        0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
        0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
        0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
        0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
        0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
        0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
        0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
    ];

    let bit_len = (input.len() as u128) * 8;
    let msg = sha_pad_1024(input, bit_len);

    for chunk in msg.chunks(128) {
        let mut w = [0u64; 80];
        for (i, bytes) in chunk.chunks(8).enumerate().take(16) {
            w[i] = u64::from_be_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]);
        }
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(k[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    h.iter().flat_map(|v| v.to_be_bytes()).collect()
}

fn sha_pad_512(input: &[u8], bit_len: u64) -> Vec<u8> {
    let mut msg = input.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    msg
}

fn sha_pad_1024(input: &[u8], bit_len: u128) -> Vec<u8> {
    let mut msg = input.to_vec();
    msg.push(0x80);
    while msg.len() % 128 != 112 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    msg
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_empty_string() {
        // NIST vector: SHA-256("") = e3b0c44298fc1c149afb...
        let digest = sha2_256(b"");
        let hex = hex_encode(&digest);
        assert_eq!(
            hex,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_abc() {
        // NIST vector: SHA-256("abc")
        let digest = sha2_256(b"abc");
        let hex = hex_encode(&digest);
        assert_eq!(
            hex,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha512_empty_string() {
        // NIST vector: SHA-512("")
        let digest = sha2_512(b"");
        let hex = hex_encode(&digest);
        assert_eq!(
            hex,
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
    }
}

// Fixture: Rust call patterns the Phase 10 fixes address.
//
// Pre-Phase-10 fix, each line below produced zero findings even though
// the patterns are common in real-world Rust crypto consumer code. The
// V5 corpus run (RUST_COVERAGE_GAPS.md) cited specific file:line
// citations for each — every example here mirrors a real one.

use md5::Md5;
use rsa::{RsaPrivateKey, pkcs1v15::SigningKey};
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};

fn shapes(mut rng: impl rand::CryptoRng + rand::RngCore) {
    // BUG-A: qualified-path callee.
    // p256/p256/src/ecdsa.rs:118 - sha2::Sha384::digest(b"test")
    let _ = sha2::Sha256::digest(b"hello");    // CRYPTO-530 (suppressed inventory)
    let _ = sha2::Sha384::digest(b"hello");    // CRYPTO-531 (suppressed inventory)
    let _ = rustls::ClientConfig::builder();   // CRYPTO-560 (suppressed inventory)
    let _ = rustls::ServerConfig::builder();   // CRYPTO-561 (NEW, suppressed inventory)

    // BUG-B: RsaPrivateKey::new with runtime-variable bit size.
    // rsa/src/pkcs1v15/signing_key.rs:58 - RsaPrivateKey::new(rng, bit_size)
    let bits: usize = 2048;
    let _ = RsaPrivateKey::new(&mut rng, bits);  // CRYPTO-543 catch-all

    // BUG-C: rcgen::KeyPair::generate_for, used by rustls-webpki test utils.
    // rustls-webpki/src/test_utils.rs:7
    let _ = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256); // CRYPTO-570

    // BUG-F: turbofish-encoded hash in rsa SigningKey.
    // rsa/src/pkcs1v15.rs:468 - SigningKey::<Sha256>::new(priv_key)
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let _ = SigningKey::<Sha256>::new(priv_key.clone()); // CRYPTO-544
    let _ = SigningKey::<Sha384>::new(priv_key.clone()); // CRYPTO-545
    let _ = SigningKey::<Sha512>::new(priv_key.clone()); // CRYPTO-546
    let _ = SigningKey::<Sha1>::new(priv_key);           // CRYPTO-548, was misrouted to CRYPTO-547's rsa-pkcs1-sha256 fallback

    // #Y29: openssl crate Rsa::generate — same non-literal-argument gap as
    // BUG-B, one crate over (competitors cycle 12).
    let _ = openssl::rsa::Rsa::generate(2048).unwrap(); // CRYPTO-591
    let _ = openssl::rsa::Rsa::generate(bits as u32).unwrap(); // CRYPTO-593 catch-all

    // md5/sha1 crates — same digest-trait shape as sha2's Sha256/384/512
    // above (BUG-A-adjacent gap: coverage existed for the sha2 family only).
    let _ = Md5::new();      // CRYPTO-956
    let _ = Md5::digest(b"hello");  // CRYPTO-956
    let _ = Sha1::new();     // CRYPTO-957
    let _ = Sha1::digest(b"hello"); // CRYPTO-957
}

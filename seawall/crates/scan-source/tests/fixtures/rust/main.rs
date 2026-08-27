// Fixture: Rust crypto API calls for seawall scanner tests.
#![allow(unused_variables, dead_code)]

use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;
use ed25519_dalek::SigningKey;
use ring::signature::{EcdsaKeyPair, Ed25519KeyPair};
use rsa::RsaPrivateKey;
use rustls::ClientConfig;
use sha2::Sha256;

// RST-001 / CRYPTO-500 — ring EcdsaKeyPair::generate_pkcs8
fn ring_ecdsa_keygen() {
    let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
}

// RST-002 / CRYPTO-501 — ring Ed25519KeyPair::generate_pkcs8
fn ring_ed25519_keygen() {
    let doc = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
}

// RST-010 / CRYPTO-510 — RustCrypto Aes256Gcm::new
fn aes256_gcm_new() {
    let cipher = Aes256Gcm::new(&key);
}

// RST-011 / CRYPTO-511 — RustCrypto Aes128Gcm::new
fn aes128_gcm_new() {
    let cipher = Aes128Gcm::new(&key);
}

// RST-020 / CRYPTO-520 — sha2 Sha256::new
fn sha256_hash() {
    let hasher = Sha256::new();
}

// RST-030 / CRYPTO-530 — ChaCha20Poly1305::new
fn chacha20_new() {
    let cipher = ChaCha20Poly1305::new(&key);
}

// RST-040 / CRYPTO-540 — rsa RsaPrivateKey::new (weak, 1024)
fn rsa_keygen_weak() {
    let priv_key = RsaPrivateKey::new(&mut rng, 1024).unwrap();
}

// RST-040 / CRYPTO-541 — rsa RsaPrivateKey::new (2048)
fn rsa_keygen_2048() {
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
}

// RST-050 / CRYPTO-550 — ed25519_dalek SigningKey::generate
fn ed25519_dalek_keygen() {
    let signing_key = SigningKey::generate(&mut rng);
}

// RST-060 / CRYPTO-560 — rustls ClientConfig::builder
fn rustls_client_config() {
    let config = ClientConfig::builder();
}

fn main() {
    ring_ecdsa_keygen();
    ring_ed25519_keygen();
    aes256_gcm_new();
    aes128_gcm_new();
    sha256_hash();
    chacha20_new();
    rsa_keygen_weak();
    rsa_keygen_2048();
    ed25519_dalek_keygen();
    rustls_client_config();
}

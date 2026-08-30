use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use sha1::Sha1;
use sha2::{Sha256, Sha384, Digest};
use md5::Md5;
use hmac::Hmac;
use rsa::RsaPrivateKey;
use p256::ecdsa::SigningKey;
use x25519_dalek::EphemeralSecret;
use argon2::Argon2;
use scrypt::scrypt;
use bcrypt::hash;

fn probe() {
    let _ = RsaPrivateKey::new(&mut rand::thread_rng(), 2048);      // EXPECT rsa
    let _ = SigningKey::random(&mut rand::thread_rng());            // EXPECT ecdsa
    let _ = EphemeralSecret::random_from_rng(rand::thread_rng());   // EXPECT ecdh
    let _ = Md5::new();                                             // EXPECT md5
    let _ = Sha1::new();                                            // EXPECT sha1
    let _ = Sha256::new();                                          // EXPECT sha256
    let _ = Sha384::new();                                          // EXPECT sha384
    let _ = Hmac::<Sha256>::new_from_slice(b"k");                   // EXPECT hmac
    let _ = pbkdf2::pbkdf2_hmac::<Sha256>(b"pw", b"s", 600000, &mut [0u8; 32]); // EXPECT pbkdf2
    let _ = scrypt(b"pw", b"s", &Default::default(), &mut [0u8; 32]);           // EXPECT scrypt
    let _ = hash("pw", 10);                                         // EXPECT bcrypt
    let _ = Argon2::default();                                      // EXPECT argon2
    let _ = Aes128Gcm::new((&[0u8; 16]).into());                    // EXPECT aes128
    let _ = Aes256Gcm::new((&[0u8; 32]).into());                    // EXPECT aes256
    let _ = ChaCha20Poly1305::new((&[0u8; 32]).into());             // EXPECT chacha20
}

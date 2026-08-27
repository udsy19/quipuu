// Fixture: pbkdf2 turbofish patterns (Phase 11).
//
// Pre-Phase-11 fix, these call sites produced zero findings. The pbkdf2
// crate uses two API shapes that both encode the hash algorithm in a
// turbofish generic. Phase 11 captures the turbofish content and routes
// to the right CRYPTO-580..587 rule based on the hash name.

use pbkdf2::{pbkdf2, pbkdf2_hmac};
use hmac::Hmac;
use sha2::{Sha256, Sha384, Sha512};

fn shapes(password: &[u8], salt: &[u8]) {
    let mut buf = [0u8; 32];

    // Shape 1: pbkdf2 generic-fn API.
    // pbkdf2/pbkdf2/benches/lib.rs:16 - pbkdf2::<Hmac<sha2::Sha256>>(...)
    pbkdf2::<Hmac<Sha256>>(password, salt, 600_000, &mut buf).unwrap();   // CRYPTO-580
    pbkdf2::<Hmac<Sha384>>(password, salt, 600_000, &mut buf).unwrap();   // CRYPTO-581
    pbkdf2::<Hmac<Sha512>>(password, salt, 210_000, &mut buf).unwrap();   // CRYPTO-582

    // Shape 2: pbkdf2_hmac free-function API.
    pbkdf2_hmac::<Sha256>(password, salt, 600_000, &mut buf);             // CRYPTO-584
    pbkdf2_hmac::<Sha384>(password, salt, 600_000, &mut buf);             // CRYPTO-585
    pbkdf2_hmac::<Sha512>(password, salt, 210_000, &mut buf);             // CRYPTO-586

    // Shape 3: fully qualified — `pbkdf2::pbkdf2_hmac::<Sha256>` —
    // normalize_rust_callee falls back to the last segment.
    pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, 600_000, &mut buf);     // CRYPTO-584
}

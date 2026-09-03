// Fixture: rustls `SignatureScheme::ML_DSA_{44,65,87}` — the IANA TLS
// SignatureScheme registry's PQC certificate-authentication variants
// (#Y142). Verified against docs.rs/rustls/latest/rustls/enum.
// SignatureScheme.html — a bare enum-variant path expression, not a call.

pub enum SignatureScheme {
    ED25519,
    ECDSA_NISTP256_SHA256,
    ML_DSA_44,
    ML_DSA_65,
    ML_DSA_87,
}

fn array_literal() -> &'static [SignatureScheme] {
    // array-literal shape — must fire for both ML-DSA variants listed.
    &[SignatureScheme::ML_DSA_65, SignatureScheme::ED25519]
}

fn standalone(scheme: SignatureScheme) -> bool {
    // bare-reference shape — must fire. (Not `matches!(...)`: like `vec!`,
    // its macro body flattens to bare identifier tokens with no
    // scoped_identifier structure, so it would not be a fair test of this
    // shape.)
    scheme == SignatureScheme::ML_DSA_87
}

fn classical_only() -> &'static [SignatureScheme] {
    // no ML_DSA variant present — must not fire.
    &[SignatureScheme::ED25519, SignatureScheme::ECDSA_NISTP256_SHA256]
}

fn build_vec() -> Vec<SignatureScheme> {
    // vec! macro body — named, disclosed gap; must NOT fire (tree-sitter
    // flattens this to bare identifier tokens, no scoped_identifier node).
    vec![SignatureScheme::ML_DSA_44]
}

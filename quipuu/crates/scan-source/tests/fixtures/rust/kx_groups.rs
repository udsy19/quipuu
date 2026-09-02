// Fixture: rustls TLS key-exchange group preference list (#Y62c).
//
// Two real shapes found by the corpus-B prevalence grep: a `CryptoProvider`
// field initializer (examples/limitedclient.rs) and a provider crate's own
// `DEFAULT_KX_GROUPS`/`ALL_KX_GROUPS` static list (rustls-ring,
// rustls-aws-lc-rs). Both wrap an array literal in `Cow::Borrowed`/
// `Cow::Owned`/a bare `&`.

use std::borrow::Cow;

pub mod kx_group {
    pub const X25519: u8 = 0;
    pub const SECP256R1: u8 = 1;
    pub const SECP384R1: u8 = 2;
    pub const X25519MLKEM768: u8 = 3;
}

struct CryptoProvider {
    kx_groups: Cow<'static, [u8]>,
}

// Shape 1: CryptoProvider { kx_groups: Cow::Borrowed(&[...]), .. }.
const PROVIDER: CryptoProvider = CryptoProvider {
    kx_groups: Cow::Borrowed(&[kx_group::X25519MLKEM768, kx_group::X25519]),
};

// Shape 2: a provider crate's own list definition.
pub static DEFAULT_KX_GROUPS: &[u8] = &[
    kx_group::X25519MLKEM768,
    kx_group::SECP256R1,
    kx_group::SECP384R1,
];

fn build(kx_groups: Vec<u8>) -> CryptoProvider {
    // An identifier passthrough, not an array literal — no group name is
    // visible at this site, so this must NOT fire.
    CryptoProvider {
        kx_groups: Cow::Owned(kx_groups),
    }
}

fn build_vec() -> CryptoProvider {
    // vec![...] macro bodies are a token tree, not structured elements — a
    // named, unclaimed gap, and this line must NOT fire either.
    CryptoProvider {
        kx_groups: Cow::Owned(vec![kx_group::X25519]),
    }
}

// A field named `kx_groups` on an unrelated struct still fires — the group
// name, not the struct type, carries the semantics, same as upstream naming
// this field consistently across every provider crate.
struct Unrelated {
    kx_groups: Cow<'static, [u8]>,
}
const OTHER: Unrelated = Unrelated {
    kx_groups: Cow::Borrowed(&[kx_group::SECP256R1]),
};

// Shape 3: `rustls_post_quantum::DEFAULT_PROVIDER`, referenced by its fully
// qualified path at a use site — not a field_initializer or a
// `KX_GROUPS`-named item, so it needs its own matcher.
mod rustls_post_quantum {
    pub const DEFAULT_PROVIDER: u8 = 0;
}

// A sibling crate's own classical-only const of the identical bare name —
// must NOT fire; only the fully qualified `rustls_post_quantum::` path is
// PQC here.
mod rustls_aws_lc_rs {
    pub const DEFAULT_PROVIDER: u8 = 0;
}

fn build_pq_config() -> u8 {
    rustls_post_quantum::DEFAULT_PROVIDER
}

fn build_classical_config() -> u8 {
    rustls_aws_lc_rs::DEFAULT_PROVIDER
}

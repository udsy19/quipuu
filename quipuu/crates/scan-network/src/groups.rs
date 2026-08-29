//! Canonical IANA TLS Supported Groups catalogue (D-08).
//!
//! Source: `knowledge/sources/iana-tls-supported-groups.csv` (verified
//! 2026-06-12). We probe each group individually to enumerate which the
//! server accepts.

use rustls::crypto::SupportedKxGroup;

/// One supported group we know how to probe.
#[derive(Clone, Copy)]
pub struct ProbeGroup {
    /// IANA codepoint (`NamedGroup` value).
    pub codepoint: u16,
    /// Display name as it appears in the IANA registry.
    pub name: &'static str,
    /// Algorithm-id from `core::algorithm-table` to attribute findings to.
    /// Hybrid groups attribute to the combined `x25519-mlkem768` etc; pure
    /// PQC groups to `ml-kem-768` etc.
    pub algorithm_id: &'static str,
    /// True if the group is a draft / deprecated codepoint we expect to fail.
    pub legacy: bool,
    /// The rustls `SupportedKxGroup` impl we ship through a per-probe
    /// `CryptoProvider`. `None` means "not in rustls 0.23 core" — that's
    /// the Tier-2 raw-bytes path which v0 doesn't implement.
    pub kx_group: Option<&'static dyn SupportedKxGroup>,
}

// The codepoints below come from
// `knowledge/sources/iana-tls-supported-groups.csv`.

/// Return the canonical probe-group list. Ordered roughly best → worst.
pub fn builtin_groups() -> Vec<ProbeGroup> {
    use rustls::crypto::ring::kx_group;
    vec![
        // Classical key-agreements that rustls/ring supports out of the box.
        ProbeGroup {
            codepoint: 0x001D,
            name: "X25519",
            algorithm_id: "x25519",
            legacy: false,
            kx_group: Some(kx_group::X25519),
        },
        // NamedGroup entries come from the TLS `supported_groups` extension,
        // which negotiates key exchange only — never a signature algorithm.
        // Do not "fix" these back to `ecdsa-*`: that id is `primitive =
        // "signature"` in the algorithm table and asserts a capability this
        // probe never observes.
        ProbeGroup {
            codepoint: 0x0017,
            name: "secp256r1",
            algorithm_id: "ecdh-p256",
            legacy: false,
            kx_group: Some(kx_group::SECP256R1),
        },
        ProbeGroup {
            codepoint: 0x0018,
            name: "secp384r1",
            algorithm_id: "ecdh-p384",
            legacy: false,
            kx_group: Some(kx_group::SECP384R1),
        },
        // secp521r1 (0x0019) is catalogued but rustls's `ring` backend ships
        // only SECP256R1 / SECP384R1 / X25519. Promote to Tier-2 in v0.2.
        ProbeGroup {
            codepoint: 0x0019,
            name: "secp521r1",
            algorithm_id: "ecdh-p521",
            legacy: false,
            kx_group: None,
        },
        // PQC hybrids. rustls's `ring` backend does NOT carry ML-KEM kx
        // groups — that's the `aws-lc-rs` backend's territory. We list the
        // groups anyway for cataloguing; v0 reports them as "not probed"
        // (`kx_group: None`) and a future revision will switch the default
        // CryptoProvider to aws-lc-rs to enable real probes. [VERIFY: aws-lc-rs
        // backend swap in v0.2]
        ProbeGroup {
            codepoint: 0x11EC,
            name: "X25519MLKEM768",
            algorithm_id: "x25519-mlkem768",
            legacy: false,
            kx_group: None,
        },
        ProbeGroup {
            codepoint: 0x11EB,
            name: "SecP256r1MLKEM768",
            algorithm_id: "secp256r1-mlkem768",
            legacy: false,
            kx_group: None,
        },
        ProbeGroup {
            codepoint: 0x11ED,
            name: "SecP384r1MLKEM1024",
            algorithm_id: "secp384r1-mlkem1024",
            legacy: false,
            kx_group: None,
        },
        // Pure ML-KEM groups (codepoints 512/513/514). Not in rustls core.
        ProbeGroup {
            codepoint: 0x0200,
            name: "MLKEM512",
            algorithm_id: "ml-kem-512",
            legacy: false,
            kx_group: None,
        },
        ProbeGroup {
            codepoint: 0x0201,
            name: "MLKEM768",
            algorithm_id: "ml-kem-768",
            legacy: false,
            kx_group: None,
        },
        ProbeGroup {
            codepoint: 0x0202,
            name: "MLKEM1024",
            algorithm_id: "ml-kem-1024",
            legacy: false,
            kx_group: None,
        },
        // Deprecated pre-standard codepoint — useful to flag if a target
        // still advertises it. Tier-2 raw-bytes probe in v0.2.
        ProbeGroup {
            codepoint: 0x6399,
            name: "X25519Kyber768Draft00",
            algorithm_id: "x25519-kyber768-draft00",
            legacy: true,
            kx_group: None,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use quipuu_core::{AlgorithmTable, Primitive};

    /// A `NamedGroup` is always a key-exchange mechanism, never a signature
    /// algorithm — the TLS `supported_groups` extension and the
    /// `signature_algorithms` extension are disjoint. Every `algorithm_id`
    /// this module attributes a probe to must resolve in the algorithm table
    /// and carry a primitive consistent with that: key agreement, KEM, or a
    /// hybrid combiner. Catches the `ecdsa-p256`-for-`secp256r1` mislabel
    /// class if it recurs.
    #[test]
    fn every_probe_group_algorithm_id_is_a_key_exchange_primitive() {
        let algorithms = AlgorithmTable::from_builtin().expect("builtin algorithm table loads");
        for group in builtin_groups() {
            let record = algorithms.get(group.algorithm_id).unwrap_or_else(|| {
                panic!(
                    "ProbeGroup {} attributes to unknown algorithm id `{}`",
                    group.name, group.algorithm_id
                )
            });
            let primitive = record.primitive.unwrap_or_else(|| {
                panic!(
                    "ProbeGroup {} (`{}`) has no primitive in the algorithm table",
                    group.name, group.algorithm_id
                )
            });
            assert!(
                matches!(
                    primitive,
                    Primitive::KeyAgree | Primitive::Kem | Primitive::Combiner
                ),
                "ProbeGroup {} (`{}`) has primitive {:?}, not a key-exchange primitive — \
                 a TLS supported group can never be a signature algorithm",
                group.name,
                group.algorithm_id,
                primitive
            );
        }
    }
}

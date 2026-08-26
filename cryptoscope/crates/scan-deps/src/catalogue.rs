//! Static catalogue of known cryptographic libraries, organised by ecosystem.
//!
//! Each [`CatalogueEntry`] maps a package name (matched by regex) in a particular
//! ecosystem to a canonical algorithm-id and a short human-readable note that
//! appears in the finding message.

/// Which dependency-manifest ecosystem this entry belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ecosystem {
    Go,
    Rust,
    Python,
    JavaScript,
    Maven,
}

impl Ecosystem {
    /// Short label used in `location.symbol` and messages.
    pub fn label(self) -> &'static str {
        match self {
            Ecosystem::Go => "go",
            Ecosystem::Rust => "cargo",
            Ecosystem::Python => "python",
            Ecosystem::JavaScript => "npm",
            Ecosystem::Maven => "maven",
        }
    }
}

/// One entry in the catalogue.
#[derive(Debug, Clone)]
pub struct CatalogueEntry {
    pub ecosystem: Ecosystem,
    /// Regex pattern matched against the package name (full match against the
    /// whole package name string, not a substring search).
    pub package_pattern: &'static str,
    /// Canonical algorithm-id from the algorithm table, or `"unknown"`.
    pub algorithm_id: &'static str,
    /// Short note surfaced in the finding message.
    pub note: &'static str,
}

/// The built-in catalogue.  All entries are compiled into the binary.
pub static CATALOGUE: &[CatalogueEntry] = &[
    // =========================================================================
    // Go (go.mod)
    // =========================================================================
    CatalogueEntry {
        ecosystem: Ecosystem::Go,
        package_pattern: r"^golang\.org/x/crypto$",
        algorithm_id: "unknown",
        note: "Go extended crypto library (AES, ChaCha20, bcrypt, SSH, …)",
    },
    CatalogueEntry {
        ecosystem: Ecosystem::Go,
        package_pattern: r"^github\.com/golang-jwt/jwt(/v\d+)?$",
        algorithm_id: "unknown",
        note: "JWT library — HMAC/RSA/ECDSA signing",
    },
    CatalogueEntry {
        ecosystem: Ecosystem::Go,
        package_pattern: r"^github\.com/pkg/sftp$",
        algorithm_id: "unknown",
        note: "SFTP client/server — uses golang.org/x/crypto/ssh",
    },
    CatalogueEntry {
        ecosystem: Ecosystem::Go,
        package_pattern: r"^google\.golang\.org/grpc$",
        algorithm_id: "unknown",
        note: "gRPC-Go — TLS via crypto/tls or custom credentials",
    },
    // =========================================================================
    // Rust (Cargo.toml)
    // =========================================================================
    CatalogueEntry {
        ecosystem: Ecosystem::Rust,
        package_pattern: r"^ring$",
        algorithm_id: "unknown",
        note: "ring — safe Rust bindings over BoringSSL primitives (RSA, ECDSA, AES-GCM, …)",
    },
    CatalogueEntry {
        ecosystem: Ecosystem::Rust,
        package_pattern: r"^rustls$",
        algorithm_id: "unknown",
        note: "rustls — modern TLS 1.2/1.3 implementation in Rust",
    },
    CatalogueEntry {
        ecosystem: Ecosystem::Rust,
        package_pattern: r"^rustls-post-quantum$",
        algorithm_id: "x25519-mlkem768",
        note: "rustls post-quantum extension — X25519MLKEM768 hybrid KEM",
    },
    CatalogueEntry {
        ecosystem: Ecosystem::Rust,
        package_pattern: r"^aws-lc-rs$",
        algorithm_id: "unknown",
        note: "aws-lc-rs — AWS Libcrypto (ML-KEM, ML-DSA, classical crypto)",
    },
    CatalogueEntry {
        ecosystem: Ecosystem::Rust,
        package_pattern: r"^boring$",
        algorithm_id: "unknown",
        note: "boring — Rust bindings to BoringSSL",
    },
    CatalogueEntry {
        ecosystem: Ecosystem::Rust,
        package_pattern: r"^openssl$",
        algorithm_id: "unknown",
        note: "openssl crate — Rust bindings to OpenSSL",
    },
    CatalogueEntry {
        ecosystem: Ecosystem::Rust,
        package_pattern: r"^webpki$",
        algorithm_id: "unknown",
        note: "webpki — Web PKI certificate path validation",
    },
    CatalogueEntry {
        ecosystem: Ecosystem::Rust,
        package_pattern: r"^x509-parser$",
        algorithm_id: "unknown",
        note: "x509-parser — X.509 certificate parser",
    },
    CatalogueEntry {
        ecosystem: Ecosystem::Rust,
        package_pattern: r"^tls-parser$",
        algorithm_id: "unknown",
        note: "tls-parser — TLS record/handshake parser",
    },
    CatalogueEntry {
        ecosystem: Ecosystem::Rust,
        package_pattern: r"^tokio-rustls$",
        algorithm_id: "unknown",
        note: "tokio-rustls — async TLS for Tokio via rustls",
    },
    CatalogueEntry {
        ecosystem: Ecosystem::Rust,
        package_pattern: r"^sha2$",
        algorithm_id: "sha-256",
        note: "sha2 — SHA-224/256/384/512 (RustCrypto)",
    },
    CatalogueEntry {
        ecosystem: Ecosystem::Rust,
        package_pattern: r"^sha-1$",
        algorithm_id: "sha-1",
        note: "sha-1 crate — SHA-1 (broken; avoid for new use)",
    },
    CatalogueEntry {
        ecosystem: Ecosystem::Rust,
        package_pattern: r"^md-5$",
        algorithm_id: "md5",
        note: "md-5 crate — MD5 (broken; avoid for new use)",
    },
    CatalogueEntry {
        ecosystem: Ecosystem::Rust,
        package_pattern: r"^rsa$",
        algorithm_id: "rsa-2048",
        note: "rsa crate — pure-Rust RSA implementation",
    },
    CatalogueEntry {
        ecosystem: Ecosystem::Rust,
        package_pattern: r"^ed25519-dalek$",
        algorithm_id: "ed25519",
        note: "ed25519-dalek — Ed25519 signatures",
    },
    CatalogueEntry {
        ecosystem: Ecosystem::Rust,
        package_pattern: r"^x25519-dalek$",
        algorithm_id: "x25519",
        note: "x25519-dalek — X25519 Diffie-Hellman",
    },
    CatalogueEntry {
        ecosystem: Ecosystem::Rust,
        package_pattern: r"^p256$",
        algorithm_id: "ecdsa-p256",
        note: "p256 crate — P-256 (NIST secp256r1) ECDSA/ECDH",
    },
    CatalogueEntry {
        ecosystem: Ecosystem::Rust,
        package_pattern: r"^p384$",
        algorithm_id: "ecdsa-p384",
        note: "p384 crate — P-384 (NIST secp384r1) ECDSA/ECDH",
    },
    CatalogueEntry {
        ecosystem: Ecosystem::Rust,
        package_pattern: r"^k256$",
        algorithm_id: "ecdsa-secp256k1",
        note: "k256 crate — secp256k1 (Bitcoin/Ethereum curve)",
    },
    CatalogueEntry {
        ecosystem: Ecosystem::Rust,
        package_pattern: r"^pem$",
        algorithm_id: "unknown",
        note: "pem crate — PEM encoding/decoding for certificate material",
    },
    CatalogueEntry {
        ecosystem: Ecosystem::Rust,
        package_pattern: r"^jsonwebtoken$",
        algorithm_id: "unknown",
        note: "jsonwebtoken — JWT encode/decode (HMAC, RSA, ECDSA)",
    },
    CatalogueEntry {
        ecosystem: Ecosystem::Rust,
        package_pattern: r"^ml-kem$",
        algorithm_id: "ml-kem-768",
        note: "ml-kem crate — ML-KEM (FIPS 203) pure-Rust implementation",
    },
    CatalogueEntry {
        ecosystem: Ecosystem::Rust,
        package_pattern: r"^ml-dsa$",
        algorithm_id: "ml-dsa-65",
        note: "ml-dsa crate — ML-DSA (FIPS 204) pure-Rust implementation",
    },
    CatalogueEntry {
        ecosystem: Ecosystem::Rust,
        package_pattern: r"^slh-dsa$",
        algorithm_id: "slh-dsa-sha2-128s",
        note: "slh-dsa crate — SLH-DSA (FIPS 205) pure-Rust implementation",
    },
    // =========================================================================
    // Python (requirements.txt)
    // =========================================================================
    CatalogueEntry {
        ecosystem: Ecosystem::Python,
        package_pattern: r"^cryptography$",
        algorithm_id: "unknown",
        note: "cryptography — Python cryptography primitives (OpenSSL backend)",
    },
    CatalogueEntry {
        ecosystem: Ecosystem::Python,
        package_pattern: r"^pycryptodome$",
        algorithm_id: "unknown",
        note: "pycryptodome — drop-in replacement for PyCrypto",
    },
    CatalogueEntry {
        ecosystem: Ecosystem::Python,
        package_pattern: r"^pycrypto$",
        algorithm_id: "unknown",
        note: "pycrypto — legacy crypto library (unmaintained; prefer pycryptodome)",
    },
    CatalogueEntry {
        ecosystem: Ecosystem::Python,
        package_pattern: r"^pyOpenSSL$",
        algorithm_id: "unknown",
        note: "pyOpenSSL — Python bindings to OpenSSL",
    },
    CatalogueEntry {
        ecosystem: Ecosystem::Python,
        package_pattern: r"^[Pp][Yy][Jj][Ww][Tt]$",
        algorithm_id: "unknown",
        note: "pyjwt — JWT encode/decode (HMAC, RSA, ECDSA)",
    },
    CatalogueEntry {
        ecosystem: Ecosystem::Python,
        package_pattern: r"^pynacl$",
        algorithm_id: "unknown",
        note: "pynacl — Python bindings to libsodium (NaCl)",
    },
    CatalogueEntry {
        ecosystem: Ecosystem::Python,
        package_pattern: r"^python-jose$",
        algorithm_id: "unknown",
        note: "python-jose — JOSE (JWT/JWS/JWE/JWK) implementation",
    },
    // =========================================================================
    // JavaScript / TypeScript (package.json)
    // =========================================================================
    CatalogueEntry {
        ecosystem: Ecosystem::JavaScript,
        package_pattern: r"^node-forge$",
        algorithm_id: "unknown",
        note: "node-forge — pure-JS TLS, PKI, and crypto library",
    },
    CatalogueEntry {
        ecosystem: Ecosystem::JavaScript,
        package_pattern: r"^jsonwebtoken$",
        algorithm_id: "unknown",
        note: "jsonwebtoken — JWT encode/decode for Node.js",
    },
    CatalogueEntry {
        ecosystem: Ecosystem::JavaScript,
        package_pattern: r"^crypto-js$",
        algorithm_id: "unknown",
        note: "crypto-js — standard crypto algorithms in JavaScript",
    },
    CatalogueEntry {
        ecosystem: Ecosystem::JavaScript,
        package_pattern: r"^bcryptjs$",
        algorithm_id: "unknown",
        note: "bcryptjs — bcrypt password hashing in pure JavaScript",
    },
    CatalogueEntry {
        ecosystem: Ecosystem::JavaScript,
        package_pattern: r"^tweetnacl$",
        algorithm_id: "unknown",
        note: "tweetnacl — NaCl port in JavaScript (X25519, Ed25519, …)",
    },
    // =========================================================================
    // Java / Maven (pom.xml)
    // =========================================================================
    CatalogueEntry {
        ecosystem: Ecosystem::Maven,
        package_pattern: r"^org\.bouncycastle:bcprov-jdk18on$",
        algorithm_id: "unknown",
        note: "Bouncy Castle provider — full JCE/JCA crypto provider",
    },
    CatalogueEntry {
        ecosystem: Ecosystem::Maven,
        package_pattern: r"^org\.bouncycastle:bcpkix-jdk18on$",
        algorithm_id: "unknown",
        note: "Bouncy Castle PKIX — X.509/CMS/PKCS extensions",
    },
    CatalogueEntry {
        ecosystem: Ecosystem::Maven,
        package_pattern: r"^io\.netty:netty-handler$",
        algorithm_id: "unknown",
        note: "Netty handler — includes SSL/TLS handler",
    },
    CatalogueEntry {
        ecosystem: Ecosystem::Maven,
        package_pattern: r"^org\.eclipse\.jetty:jetty-server$",
        algorithm_id: "unknown",
        note: "Jetty server — embedded HTTP/HTTPS server",
    },
    CatalogueEntry {
        ecosystem: Ecosystem::Maven,
        package_pattern: r"^commons-codec:commons-codec$",
        algorithm_id: "unknown",
        note: "Apache Commons Codec — Base64, Hex, DigestUtils",
    },
];

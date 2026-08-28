//! quipuu-scan-network — TLS endpoint probe.
//!
//! Connects to a `host:port`, performs a normal TLS 1.3 handshake using
//! rustls, then per D-08 also performs *probe handshakes* with single-entry
//! key-exchange groups to enumerate what the server actually accepts.
//!
//! What v0 ships:
//!   * Negotiated state of a default handshake (TLS version, cipher suite,
//!     key-exchange group, peer cert chain).
//!   * Per-group probes for the 6 canonical PQC + classical groups from
//!     `knowledge/04-tls-pqc` §1.
//!   * Cert-chain findings via the existing [`quipuu_scan_certs`] crate.
//!   * One [`quipuu_core::Finding`] per probe outcome (Accepted / Rejected / Timeout).
//!
//! Deferred to v0.2 (`[VERIFY]` markers in the code):
//!   * Tier-2 raw-bytes probes for legacy / draft sig-alg codepoints
//!     (0x6399 Kyber draft, ML-DSA sig-algs not yet wired into rustls).
//!   * Nmap-style chunked cipher-suite enumeration.
//!   * `--ports` / CIDR sweeps (only `host:port` for now).
//!
//! # Responsible use
//!
//! The prober opens TCP connections to the supplied host. It is **inventory
//! only** — no fuzzing, no exploit attempts. The CLI prints a consent banner
//! before any probe runs. Concurrency capped at 5 connections/host with 10 s
//! timeouts per the SSLyze defaults documented in `knowledge/04-tls-pqc`.

pub mod groups;
pub mod prober;

pub use groups::{ProbeGroup, builtin_groups};
pub use prober::{NetScanner, ScanError, ScanOptions};

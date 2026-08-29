//! TLS prober — connects, handshakes, enumerates supported groups.
//!
//! Every probe is **inventory-only**: a full TLS 1.3 (or 1.2 fallback)
//! handshake, no fuzzing, no out-of-spec messages. Per the responsible-use
//! guidance in `knowledge/04-tls-pqc` §5 we cap concurrency and timeouts.

use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::Duration;

use quipuu_core::{Confidence, Exposure, Finding, Location, UsageContext};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::groups::{ProbeGroup, builtin_groups};

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("invalid target `{0}` — expected host:port")]
    InvalidTarget(String),
    #[error("DNS resolution failed for `{0}`: {1}")]
    Dns(String, std::io::Error),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("crypto provider install failed: {0}")]
    ProviderInstall(String),
}

/// Knobs for the prober. Defaults follow SSLyze 3.x conventions.
#[derive(Clone)]
pub struct ScanOptions {
    /// TCP connect timeout.
    pub connect_timeout: Duration,
    /// TLS handshake timeout (separate budget from TCP connect).
    pub handshake_timeout: Duration,
    /// Whether to enumerate every group from [`builtin_groups`] in addition
    /// to the default handshake.
    pub enumerate_groups: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            handshake_timeout: Duration::from_secs(10),
            enumerate_groups: true,
        }
    }
}

/// Network scanner. Single-host today; CIDR / port-range deferred.
pub struct NetScanner {
    opts: ScanOptions,
}

impl NetScanner {
    pub fn new() -> Self {
        Self::with_options(ScanOptions::default())
    }

    pub fn with_options(opts: ScanOptions) -> Self {
        Self { opts }
    }

    /// Probe one `host:port` target.
    ///
    /// Returns a [`Vec<Finding>`] documenting the TLS state of the endpoint.
    /// `host` is the SNI value AND the TCP address — typical web use case.
    pub async fn scan_target(&self, target: &str) -> Result<Vec<Finding>, ScanError> {
        let (host, port) = parse_target(target)?;
        // Ensure DNS resolves before we spend handshake budget on a probe.
        let _addrs: Vec<_> = (host.as_str(), port)
            .to_socket_addrs()
            .map_err(|e| ScanError::Dns(target.to_owned(), e))?
            .collect();

        let mut findings = Vec::new();

        // (1) Default handshake — what does the server prefer?
        let groups = builtin_groups();
        let default_kx = groups
            .iter()
            .filter_map(|g| g.kx_group.map(|kx| (g, kx)))
            .map(|(_, kx)| kx)
            .collect::<Vec<_>>();
        let provider = build_provider(default_kx);

        match self
            .one_probe(&host, port, provider, /*label=*/ "default")
            .await
        {
            // For the default handshake we don't know which named group was
            // actually negotiated (rustls 0.23 doesn't expose this). Attribute
            // to a sentinel id so the risk engine doesn't double-count it
            // against a specific algorithm; the per-group probes below provide
            // the granular attribution.
            Ok(outcome) => findings.push(handshake_finding(
                target,
                "default",
                &outcome,
                false,
                "tls-handshake",
            )),
            Err(e) => {
                findings.push(probe_failure_finding(target, "default", &e));
            }
        }

        // (2) Per-group enumeration. We only probe groups rustls actually
        // supports today (`kx_group: Some(_)`) — pure PQC + legacy groups
        // are catalogued but reported as `not_probed` for visibility.
        if self.opts.enumerate_groups {
            for g in &groups {
                if let Some(kx) = g.kx_group {
                    let provider = build_provider(vec![kx]);
                    match self.one_probe(&host, port, provider, g.name).await {
                        Ok(outcome) => {
                            findings.push(handshake_finding(
                                target,
                                g.name,
                                &outcome,
                                g.legacy,
                                g.algorithm_id,
                            ));
                        }
                        Err(_) => {
                            findings.push(group_rejected_finding(target, g));
                        }
                    }
                } else {
                    findings.push(group_not_probed_finding(target, g));
                }
            }
        }

        Ok(findings)
    }

    async fn one_probe(
        &self,
        host: &str,
        port: u16,
        provider: Arc<CryptoProvider>,
        _label: &str,
    ) -> Result<HandshakeOutcome, ScanError> {
        let tcp = timeout(self.opts.connect_timeout, TcpStream::connect((host, port)))
            .await
            .map_err(|_| {
                ScanError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "tcp connect timeout",
                ))
            })??;
        tcp.set_nodelay(true)?;

        let config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| ScanError::ProviderInstall(format!("{e}")))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InspectingVerifier::new()))
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(config));
        let server_name: ServerName<'static> =
            ServerName::try_from(host.to_owned()).map_err(|e| {
                ScanError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("invalid SNI: {e}"),
                ))
            })?;

        let mut tls = timeout(
            self.opts.handshake_timeout,
            connector.connect(server_name, tcp),
        )
        .await
        .map_err(|_| {
            ScanError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "tls handshake timeout",
            ))
        })?
        .map_err(ScanError::Io)?;

        let (_tcp_ref, session) = tls.get_ref();
        let protocol_version = session
            .protocol_version()
            .map(|v| format!("{v:?}"))
            .unwrap_or_else(|| "unknown".into());
        let negotiated_cipher = session
            .negotiated_cipher_suite()
            .map(|cs| format!("{:?}", cs.suite()))
            .unwrap_or_else(|| "unknown".into());

        // We don't get a public API for the negotiated `NamedGroup` from rustls
        // 0.23 directly — what's exposed is the cipher suite. The group is
        // captured implicitly by the kx_groups list we passed in: if the
        // handshake succeeded with a single-entry list, that group was used.
        // For the default handshake we just record "default".
        let outcome = HandshakeOutcome {
            protocol_version,
            cipher_suite: negotiated_cipher,
        };

        // Best-effort clean close. Errors here aren't fatal — the handshake
        // already succeeded.
        let _ = tls.shutdown().await;
        let _ = tls.read(&mut [0u8; 1]).await;

        Ok(outcome)
    }
}

impl Default for NetScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
struct HandshakeOutcome {
    protocol_version: String,
    cipher_suite: String,
}

fn parse_target(target: &str) -> Result<(String, u16), ScanError> {
    let (host, port) = target
        .rsplit_once(':')
        .ok_or_else(|| ScanError::InvalidTarget(target.to_owned()))?;
    let port: u16 = port
        .parse()
        .map_err(|_| ScanError::InvalidTarget(target.to_owned()))?;
    Ok((host.to_owned(), port))
}

fn build_provider(
    kx_groups: Vec<&'static dyn rustls::crypto::SupportedKxGroup>,
) -> Arc<CryptoProvider> {
    let base = rustls::crypto::ring::default_provider();
    Arc::new(CryptoProvider { kx_groups, ..base })
}

// -------- Finding builders ---------------------------------------------------

fn loc(target: &str, label: &str) -> Location {
    Location {
        location: target.to_owned(),
        line: None,
        offset: None,
        symbol: Some(format!("TLS::probe[{label}]")),
        snippet: None,
    }
}

fn handshake_finding(
    target: &str,
    label: &str,
    out: &HandshakeOutcome,
    legacy: bool,
    algorithm_id: &str,
) -> Finding {
    let rule_id = if legacy { "NET-100" } else { "NET-001" };
    let message = format!(
        "{} TLS handshake succeeded with {} / cipher {}{}",
        label,
        out.protocol_version,
        out.cipher_suite,
        if legacy {
            " — LEGACY (deprecated)"
        } else {
            ""
        }
    );
    Finding {
        rule_id: rule_id.into(),
        algorithm_id: algorithm_id.to_owned(),
        location: loc(target, label),
        message,
        confidence: Confidence::LiteralArg,
        usage_context: UsageContext::KeyEstablishmentEphemeral,
        exposure: Exposure::PublicInternet,
        shelf_life_bucket: "short".into(),
        hndl_critical: false,
    }
}

fn probe_failure_finding(target: &str, label: &str, err: &ScanError) -> Finding {
    Finding {
        rule_id: "NET-002".into(),
        algorithm_id: "tls-handshake".into(),
        location: loc(target, label),
        message: format!("{label} TLS probe failed: {err}"),
        confidence: Confidence::Unknown,
        usage_context: UsageContext::Unknown,
        exposure: Exposure::PublicInternet,
        shelf_life_bucket: "short".into(),
        hndl_critical: false,
    }
}

fn group_rejected_finding(target: &str, g: &ProbeGroup) -> Finding {
    Finding {
        rule_id: "NET-003".into(),
        algorithm_id: g.algorithm_id.into(),
        location: loc(target, g.name),
        message: format!(
            "single-group probe for {} (0x{:04X}) was rejected — server does not offer this group",
            g.name, g.codepoint
        ),
        confidence: Confidence::LiteralArg,
        usage_context: UsageContext::Unknown,
        exposure: Exposure::PublicInternet,
        shelf_life_bucket: "short".into(),
        hndl_critical: false,
    }
}

fn group_not_probed_finding(target: &str, g: &ProbeGroup) -> Finding {
    let suffix = if g.legacy {
        " (deprecated codepoint — Tier-2 raw probe deferred to v0.2)"
    } else {
        " (Tier-2 backend swap to aws-lc-rs deferred to v0.2)"
    };
    // The handshake was never attempted for this group — nothing was
    // observed about whether the target offers or negotiates it. Attributing
    // to `g.algorithm_id` here would publish a CBOM component (e.g.
    // x25519-mlkem768) for a mechanism nobody checked for; the sentinel
    // carries the specific group name and codepoint in the message instead.
    Finding {
        rule_id: "NET-900".into(),
        algorithm_id: "tls-group-not-probed".into(),
        location: loc(target, g.name),
        message: format!(
            "group {} (0x{:04X}) catalogued but not probed{}",
            g.name, g.codepoint, suffix
        ),
        confidence: Confidence::Unknown,
        usage_context: UsageContext::Unknown,
        exposure: Exposure::PublicInternet,
        shelf_life_bucket: "short".into(),
        hndl_critical: false,
    }
}

// -------- Certificate verifier ----------------------------------------------
//
// We don't actually verify the chain — this is a discovery tool, not a
// browser. We accept every cert so the handshake completes; the cert chain
// itself is left to `scan-certs` (which the CLI will run alongside).
//
// SAFETY: This MUST NOT be used outside the quipuu prober. The verifier
// trusts every peer cert. The CLI prints a banner before any probe runs.

#[derive(Debug)]
struct InspectingVerifier;

impl InspectingVerifier {
    fn new() -> Self {
        Self
    }
}

impl ServerCertVerifier for InspectingVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_target_splits_host_and_port() {
        let (h, p) = parse_target("example.com:443").unwrap();
        assert_eq!(h, "example.com");
        assert_eq!(p, 443);
    }

    #[test]
    fn parse_target_rejects_bare_host() {
        assert!(matches!(
            parse_target("example.com"),
            Err(ScanError::InvalidTarget(_))
        ));
    }

    #[test]
    fn parse_target_rejects_bad_port() {
        assert!(matches!(
            parse_target("example.com:notaport"),
            Err(ScanError::InvalidTarget(_))
        ));
    }

    #[test]
    fn scanner_default_constructs_with_sensible_timeouts() {
        let s = NetScanner::new();
        assert!(s.opts.connect_timeout >= Duration::from_secs(1));
        assert!(s.opts.handshake_timeout >= Duration::from_secs(1));
        assert!(s.opts.enumerate_groups);
    }

    #[test]
    fn not_probed_finding_never_asserts_the_catalogued_algorithm_id() {
        // A group with `kx_group: None` was never handshaked — no observation
        // was made about whether the target offers or negotiates it, so the
        // finding must not publish the catalogued group's own algorithm id
        // (e.g. x25519-mlkem768) as a CBOM component. Regression for the
        // defect where NET-900 asserted a specific PQC identity on a
        // capability gap rather than a network observation.
        for g in builtin_groups()
            .into_iter()
            .filter(|g| g.kx_group.is_none())
        {
            let finding = group_not_probed_finding("example.com:443", &g);
            assert_eq!(
                finding.algorithm_id, "tls-group-not-probed",
                "not-probed group {} must use the generic sentinel, not its own catalogued id",
                g.name
            );
            assert!(
                finding.message.contains(g.name),
                "the specific group name must still be carried in the message"
            );
        }
    }
}

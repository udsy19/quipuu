//! quipuu-scan-certs — X.509 certificate scanner.
//!
//! Parses PEM and DER certificate files (or directories of them), classifies
//! the public-key and signature algorithms using the built-in OID table from
//! `quipuu-core`, and emits [`Finding`]s per SPEC.md §6 (scan-certs).
//!
//! # Rule IDs
//! * `CERT-001` — public-key algorithm classification
//! * `CERT-002` — signature algorithm classification
//! * `CERT-100` — weak / broken signature algorithm flag

use std::path::Path;

use quipuu_core::{
    AlgorithmTable, Confidence, Exposure, Finding, Location, OidTable, QuantumStatus, UsageContext,
};
use thiserror::Error;
use x509_parser::prelude::*;
use x509_parser::public_key::PublicKey;

/// Errors that can occur during certificate scanning.
#[derive(Debug, Error)]
pub enum ScanError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse error: {0}")]
    Parse(String),
    #[error("unknown algorithm: {0}")]
    UnknownAlgorithm(String),
}

/// Map a [`ScanError`] from a specific cert file into a structured warning.
fn cert_warning(path: &Path, err: &ScanError) -> quipuu_core::ScanWarning {
    use quipuu_core::{ScanWarning, ScanWarningKind};
    let kind = match err {
        ScanError::Io(_) => ScanWarningKind::UnreadableFile,
        ScanError::Parse(_) => ScanWarningKind::CertDecodeError,
        ScanError::UnknownAlgorithm(_) => ScanWarningKind::Other,
    };
    ScanWarning::new(kind, Some(path.to_path_buf()), err.to_string())
}

/// OID for RSA public key type.
const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
/// OID for EC public key type.
const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";

/// One RSA modulus length and the algorithm-id it resolves to.
struct ModulusRow {
    bits: usize,
    algorithm_id: &'static str,
}

/// Modulus length → algorithm-id, matched **exactly**.
///
/// A bucket cannot name a modulus. The previous mapping sent everything below
/// 2048 bits to `rsa-1024`, so a 512-bit key was reported as RSA-1024 — twice
/// the strength it has, in the direction that makes a weak key look strong.
const RSA_BY_MODULUS: &[ModulusRow] = &[
    ModulusRow {
        bits: 1024,
        algorithm_id: "rsa-1024",
    },
    ModulusRow {
        bits: 2048,
        algorithm_id: "rsa-2048",
    },
    ModulusRow {
        bits: 3072,
        algorithm_id: "rsa-3072",
    },
    ModulusRow {
        bits: 4096,
        algorithm_id: "rsa-4096",
    },
];

/// Where a modulus that matches no row above lands. `bits` is the exclusive
/// upper bound of the range each row covers; the measured length is carried in
/// the finding message either way, so nothing is lost by not naming it here.
const RSA_UNSIZED: &[ModulusRow] = &[
    ModulusRow {
        bits: 2048,
        algorithm_id: "rsa-undersized",
    },
    ModulusRow {
        bits: usize::MAX,
        algorithm_id: "rsa-unattributed",
    },
];

/// OIDs for weak/broken signature algorithms that always get CERT-100.
const WEAK_SIG_OIDS: &[(&str, &str)] = &[
    (
        "1.2.840.113549.1.1.2",
        "md2WithRSAEncryption — BROKEN: MD2 collision attack",
    ),
    (
        "1.2.840.113549.1.1.4",
        "md5WithRSAEncryption — BROKEN: MD5 collision attack",
    ),
    (
        "1.2.840.113549.1.1.5",
        "sha1WithRSAEncryption — WEAK: SHA-1 deprecated (CA/B Forum SC097)",
    ),
    (
        "1.2.840.10045.4.1",
        "ecdsa-with-SHA1 — WEAK: SHA-1 deprecated",
    ),
    (
        "1.2.840.10040.4.3",
        "id-dsa-with-sha1 — WEAK: SHA-1 deprecated",
    ),
];

/// The certificate scanner.
///
/// Constructed once via [`CertScanner::with_builtins`]; the tables are
/// read-only after construction so the same instance can be shared across
/// threads.
pub struct CertScanner {
    algorithms: AlgorithmTable,
    oids: OidTable,
}

impl CertScanner {
    /// Construct using the built-in OID + algorithm tables.
    pub fn with_builtins() -> Result<Self, ScanError> {
        let builtins = quipuu_core::load_builtins().map_err(|e| ScanError::Parse(e.to_string()))?;
        Ok(Self {
            algorithms: builtins.algorithms,
            oids: builtins.oids,
        })
    }

    /// Scan a single PEM or DER file, or a directory of certificate files.
    /// Directories are walked recursively; `.gitignore` is honoured.
    pub fn scan_path(&self, root: &Path) -> Result<Vec<Finding>, ScanError> {
        let mut warnings = Vec::new();
        self.scan_path_collecting(root, &mut warnings)
    }

    /// Like [`scan_path`] but converts per-file PEM/DER decode errors into
    /// [`ScanWarning`]s pushed onto `warnings` instead of aborting. Phase 6.
    pub fn scan_path_collecting(
        &self,
        root: &Path,
        warnings: &mut Vec<quipuu_core::ScanWarning>,
    ) -> Result<Vec<Finding>, ScanError> {
        use quipuu_core::{ScanWarning, ScanWarningKind};

        if !root.exists() {
            return Err(ScanError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("path does not exist: {}", root.display()),
            )));
        }

        let mut findings = Vec::new();

        if root.is_file() {
            if let Err(e) = self.scan_file_into(root, &mut findings) {
                warnings.push(cert_warning(root, &e));
            }
        } else {
            for entry in ignore::WalkBuilder::new(root)
                .standard_filters(true)
                .build()
            {
                let entry = match entry {
                    Ok(e) => e,
                    Err(e) => {
                        warnings.push(ScanWarning::new(
                            ScanWarningKind::WalkError,
                            None,
                            format!("scan-certs walk: {e}"),
                        ));
                        continue;
                    }
                };
                if entry.file_type().map(|t| t.is_file()).unwrap_or(false)
                    && let Err(e) = self.scan_file_into(entry.path(), &mut findings)
                {
                    warnings.push(cert_warning(entry.path(), &e));
                }
            }
        }

        Ok(findings)
    }

    fn scan_file_into(&self, path: &Path, out: &mut Vec<Finding>) -> Result<(), ScanError> {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        let data = std::fs::read(path)?;

        match ext.as_str() {
            "pem" | "crt" | "cer" => {
                // Try PEM first, then DER fallback.
                let pem_findings = self.parse_pem_bytes(&data, path)?;
                if pem_findings.is_empty() {
                    // PEM parse found nothing — attempt DER.
                    self.parse_der_bytes(&data, path, out)?;
                } else {
                    out.extend(pem_findings);
                }
            }
            "der" => {
                self.parse_der_bytes(&data, path, out)?;
            }
            _ => {
                // Unknown extension — try PEM, then DER.
                let pem_findings = self.parse_pem_bytes(&data, path)?;
                if pem_findings.is_empty() {
                    self.parse_der_bytes(&data, path, out)?;
                } else {
                    out.extend(pem_findings);
                }
            }
        }

        Ok(())
    }

    /// Try to parse `data` as PEM, extracting all CERTIFICATE blocks.
    /// Returns an empty vec (not an error) if no PEM blocks were found.
    fn parse_pem_bytes(&self, data: &[u8], path: &Path) -> Result<Vec<Finding>, ScanError> {
        // Quick UTF-8 check: if it's not valid UTF-8 it can't be PEM.
        if std::str::from_utf8(data).is_err() {
            return Ok(Vec::new()); // binary data — not PEM
        }

        let mut findings = Vec::new();
        let mut found_any = false;

        // Use the leading `::` to reference the top-level `pem` crate, not the
        // re-export from `x509_parser::prelude::*` which shadows it.
        let pem_blocks: Vec<::pem::Pem> =
            ::pem::parse_many(data).map_err(|e| ScanError::Parse(format!("PEM decode: {e}")))?;

        for block in &pem_blocks {
            if block.tag() != "CERTIFICATE" {
                continue;
            }
            found_any = true;
            match parse_x509_certificate(block.contents()) {
                Ok((_, cert)) => {
                    findings.extend(self.classify_cert(&cert, path));
                }
                Err(e) => {
                    return Err(ScanError::Parse(format!(
                        "{}: x509 parse: {e}",
                        path.display()
                    )));
                }
            }
        }

        if !found_any {
            return Ok(Vec::new()); // signal caller to try DER
        }

        Ok(findings)
    }

    /// Try to parse `data` as raw DER.
    fn parse_der_bytes(
        &self,
        data: &[u8],
        path: &Path,
        out: &mut Vec<Finding>,
    ) -> Result<(), ScanError> {
        match parse_x509_certificate(data) {
            Ok((_, cert)) => {
                out.extend(self.classify_cert(&cert, path));
                Ok(())
            }
            Err(e) => Err(ScanError::Parse(format!(
                "{}: DER parse: {e}",
                path.display()
            ))),
        }
    }

    /// Produce findings for one certificate.
    fn classify_cert(&self, cert: &X509Certificate<'_>, path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let path_str = path.to_string_lossy().into_owned();

        // Extract CN for the snippet.
        let subject_cn = cert
            .tbs_certificate
            .subject
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .unwrap_or("(no CN)")
            .to_owned();
        let snippet = format!("X.509 cert subject=CN={subject_cn}");

        // ── 1. Public-key finding ─────────────────────────────────────────
        let spki = cert.tbs_certificate.public_key();
        let spki_oid_str = spki.algorithm.oid().to_id_string();

        let (pk_algo_id, pk_detail) = self.resolve_spki_algo(cert, &spki_oid_str);
        let pk_record = self.algorithms.get(&pk_algo_id);

        let pk_usage = match pk_record.map(|r| r.primitive) {
            Some(Some(quipuu_core::Primitive::Kem))
            | Some(Some(quipuu_core::Primitive::KeyAgree)) => {
                UsageContext::KeyEstablishmentLongLived
            }
            _ => UsageContext::SignatureLongLived,
        };

        let pk_msg = if pk_algo_id == "unknown" {
            format!("UNKNOWN public-key algorithm OID {spki_oid_str}")
        } else {
            // The measured parameter goes in the message, not into the id: the
            // id may name only what the certificate states.
            match &pk_detail {
                Some(detail) => {
                    format!("Public-key algorithm: {pk_algo_id} (OID {spki_oid_str}, {detail})")
                }
                None => format!("Public-key algorithm: {pk_algo_id} (OID {spki_oid_str})"),
            }
        };

        findings.push(Finding {
            id: quipuu_core::stable_finding_id(
                "CERT-001",
                &pk_algo_id,
                &path_str,
                None,
                Some("X509::SubjectPublicKey"),
            ),
            rule_id: "CERT-001".into(),
            algorithm_id: pk_algo_id.clone(),
            location: Location {
                location: path_str.clone(),
                line: None,
                offset: None,
                symbol: Some("X509::SubjectPublicKey".into()),
                snippet: Some(snippet.clone()),
            },
            message: pk_msg,
            confidence: Confidence::LiteralArg,
            confidence_reason: format!(
                "SubjectPublicKeyInfo algorithm OID {spki_oid_str} resolved via the certificate OID table"
            ),
            usage_context: pk_usage,
            exposure: Exposure::InternalService,
            shelf_life_bucket: "medium".into(),
            hndl_critical: false,
        });

        // ── 2. Signature-algorithm finding ────────────────────────────────
        let sig_oid_str = cert.signature_algorithm.oid().to_id_string();
        let sig_algo_id = self
            .oids
            .lookup(&sig_oid_str)
            .unwrap_or("unknown")
            .to_owned();

        let sig_msg = if sig_algo_id == "unknown" {
            format!("UNKNOWN signature algorithm OID {sig_oid_str}")
        } else {
            format!("Signature algorithm: {sig_algo_id} (OID {sig_oid_str})")
        };

        let sig_record = self.algorithms.get(&sig_algo_id);
        let is_classically_broken = sig_record
            .map(|r| r.quantum_status == QuantumStatus::BrokenClassically)
            .unwrap_or(false);

        // Check the WEAK_SIG_OIDS table for broken/weak flag.
        let weak_reason = WEAK_SIG_OIDS
            .iter()
            .find(|(oid, _)| *oid == sig_oid_str)
            .map(|(_, reason)| *reason);

        findings.push(Finding {
            id: quipuu_core::stable_finding_id(
                "CERT-002",
                &sig_algo_id,
                &path_str,
                None,
                Some("X509::Signature"),
            ),
            rule_id: "CERT-002".into(),
            algorithm_id: sig_algo_id.clone(),
            location: Location {
                location: path_str.clone(),
                line: None,
                offset: None,
                symbol: Some("X509::Signature".into()),
                snippet: Some(snippet.clone()),
            },
            message: sig_msg,
            confidence: Confidence::LiteralArg,
            confidence_reason: format!(
                "signature algorithm OID {sig_oid_str} resolved via the certificate OID table"
            ),
            usage_context: UsageContext::SignatureLongLived,
            exposure: Exposure::InternalService,
            shelf_life_bucket: "medium".into(),
            hndl_critical: false,
        });

        // ── 3. Weak/broken signature algorithm — CERT-100 ─────────────────
        if let Some(reason) = weak_reason {
            findings.push(Finding {
                id: quipuu_core::stable_finding_id(
                    "CERT-100",
                    &sig_algo_id,
                    &path_str,
                    None,
                    Some("X509::Signature"),
                ),
                rule_id: "CERT-100".into(),
                algorithm_id: sig_algo_id.clone(),
                location: Location {
                    location: path_str.clone(),
                    line: None,
                    offset: None,
                    symbol: Some("X509::Signature".into()),
                    snippet: Some(snippet.clone()),
                },
                message: format!("WEAK: {reason}"),
                confidence: Confidence::LiteralArg,
                confidence_reason: format!(
                    "signature algorithm OID {sig_oid_str} matched the weak/broken-signature OID table: {reason}"
                ),
                usage_context: UsageContext::SignatureLongLived,
                exposure: Exposure::InternalService,
                shelf_life_bucket: "medium".into(),
                hndl_critical: false,
            });
        } else if is_classically_broken {
            // Catch anything in the algorithm table flagged BrokenClassically
            // that is not in our explicit WEAK list (belt-and-suspenders).
            findings.push(Finding {
                id: quipuu_core::stable_finding_id(
                    "CERT-100",
                    &sig_algo_id,
                    &path_str,
                    None,
                    Some("X509::Signature"),
                ),
                rule_id: "CERT-100".into(),
                algorithm_id: sig_algo_id.clone(),
                location: Location {
                    location: path_str.clone(),
                    line: None,
                    offset: None,
                    symbol: Some("X509::Signature".into()),
                    snippet: Some(snippet.clone()),
                },
                message: format!("WEAK: signature algorithm {sig_algo_id} is classically broken"),
                confidence: Confidence::LiteralArg,
                confidence_reason: format!(
                    "signature algorithm {sig_algo_id} is flagged BrokenClassically in the \
                     algorithm table (OID {sig_oid_str} is not in the explicit weak-OID list)"
                ),
                usage_context: UsageContext::SignatureLongLived,
                exposure: Exposure::InternalService,
                shelf_life_bucket: "medium".into(),
                hndl_critical: false,
            });
        }

        findings
    }

    /// Resolve the public-key algorithm-id, refining RSA by modulus length and
    /// EC by the named-curve OID in `algorithm.parameters`.
    ///
    /// Returns the id and, where one was measured, the parameter that justifies
    /// it — so a key that lands on an unsized row still reports its size,
    /// rather than the id inventing one.
    fn resolve_spki_algo(
        &self,
        cert: &X509Certificate<'_>,
        spki_oid_str: &str,
    ) -> (String, Option<String>) {
        let spki = cert.tbs_certificate.public_key();

        if spki_oid_str == OID_RSA_ENCRYPTION {
            // Refine RSA by modulus bit length.
            if let Ok(PublicKey::RSA(rsa)) = spki.parsed() {
                let bits = rsa.key_size();
                let id = RSA_BY_MODULUS
                    .iter()
                    .find(|row| row.bits == bits)
                    .or_else(|| RSA_UNSIZED.iter().find(|row| bits < row.bits))
                    .map(|row| row.algorithm_id)
                    .unwrap_or("unknown");
                return (id.to_owned(), Some(format!("modulus {bits} bits")));
            }
            // Cannot parse the modulus — the OID names the key type only.
            return (
                self.oids
                    .lookup(spki_oid_str)
                    .unwrap_or("unknown")
                    .to_owned(),
                None,
            );
        }

        if spki_oid_str == OID_EC_PUBLIC_KEY {
            // Refine ECDSA by the named-curve OID in algorithm.parameters.
            let curve_oid = spki
                .algorithm
                .parameters()
                .and_then(|p| p.as_oid().ok())
                .map(|o| o.to_id_string());

            if let Some(curve_oid_str) = curve_oid
                && let Some(algo_id) = self.oids.lookup(&curve_oid_str)
            {
                return (algo_id.to_owned(), Some(format!("curve {curve_oid_str}")));
            }
            // Explicit (unnamed) curve parameters — the key type OID is all we
            // have, and it names no curve.
            return (
                self.oids
                    .lookup(spki_oid_str)
                    .unwrap_or("unknown")
                    .to_owned(),
                None,
            );
        }

        // Everything else (EdDSA, PQC, …) — straight OID lookup.
        (
            self.oids
                .lookup(spki_oid_str)
                .unwrap_or("unknown")
                .to_owned(),
            None,
        )
    }
}

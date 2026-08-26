//! 5-axis additive QuantumRiskScore (D-10).
//!
//! Score = AlgorithmVulnerability + UsageContext + DataShelfLife
//!       + Exposure + DetectionConfidence
//! Bands: ≥75 Critical, 50–74 High, 25–49 Medium, 10–24 Low, <10 Safe.

use crate::{AlgorithmRecord, Confidence, Exposure, Finding, Policy, Severity, UsageContext};

/// Result of scoring one finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuantumRiskScore {
    pub algorithm_vulnerability: u8,
    pub usage_context: u8,
    pub data_shelf_life: u8,
    pub exposure: u8,
    pub detection_confidence: u8,
    pub total: u8,
    pub severity: Severity,
}

impl QuantumRiskScore {
    /// Compute the score given a finding, the algorithm record it refers to,
    /// and the active policy.
    pub fn compute(finding: &Finding, algorithm: &AlgorithmRecord, policy: &Policy) -> Self {
        let av = score_algorithm_vulnerability(algorithm, policy);
        let uc = score_usage_context(finding.usage_context, policy);
        let ds = score_data_shelf_life(&finding.shelf_life_bucket, policy);
        let ex = score_exposure(finding.exposure, policy);
        let dc = score_detection_confidence(finding.confidence, policy);

        // Each axis is capped at its weight in policy.risk_weights, so the sum
        // can never exceed 100. We cap each axis defensively all the same.
        let av = av.min(policy.risk_weights.algorithm_vulnerability);
        let uc = uc.min(policy.risk_weights.usage_context);
        let ds = ds.min(policy.risk_weights.data_shelf_life);
        let ex = ex.min(policy.risk_weights.exposure);
        let dc = dc.min(policy.risk_weights.detection_confidence);

        let total = (av as u16 + uc as u16 + ds as u16 + ex as u16 + dc as u16).min(100) as u8;
        let severity = map_severity(total, policy);

        Self {
            algorithm_vulnerability: av,
            usage_context: uc,
            data_shelf_life: ds,
            exposure: ex,
            detection_confidence: dc,
            total,
            severity,
        }
    }
}

fn score_algorithm_vulnerability(algorithm: &AlgorithmRecord, policy: &Policy) -> u8 {
    policy
        .algorithm_vulnerability
        .get(&algorithm.quantum_status)
        .copied()
        .unwrap_or(0)
}

fn score_usage_context(ctx: UsageContext, policy: &Policy) -> u8 {
    match ctx {
        UsageContext::KeyEstablishmentLongLived => {
            policy.usage_context.key_establishment_long_lived
        }
        UsageContext::KeyEstablishmentEphemeral => policy.usage_context.key_establishment_ephemeral,
        UsageContext::DataAtRestEncryption => policy.usage_context.data_at_rest_encryption,
        UsageContext::SignatureLongLived => policy.usage_context.signature_long_lived,
        UsageContext::SignatureEphemeral => policy.usage_context.signature_ephemeral,
        UsageContext::AuthenticationOnly => policy.usage_context.authentication_only,
        UsageContext::Hashing => policy.usage_context.hashing,
        UsageContext::Unknown => policy.usage_context.unknown,
    }
}

fn score_data_shelf_life(bucket: &str, policy: &Policy) -> u8 {
    match bucket {
        "ephemeral" => policy.data_shelf_life.ephemeral,
        "short" => policy.data_shelf_life.short,
        "medium" => policy.data_shelf_life.medium,
        "long" => policy.data_shelf_life.long,
        // Unknown bucket = conservative default (short).
        _ => policy.data_shelf_life.short,
    }
}

fn score_exposure(exposure: Exposure, policy: &Policy) -> u8 {
    match exposure {
        Exposure::PublicInternet => policy.exposure.public_internet,
        Exposure::InternalService => policy.exposure.internal_service,
        Exposure::LocalOnly => policy.exposure.local_only,
    }
}

fn score_detection_confidence(conf: Confidence, policy: &Policy) -> u8 {
    match conf {
        Confidence::LiteralArg => policy.detection_confidence.literal_arg,
        Confidence::TypeName => policy.detection_confidence.type_name,
        Confidence::Variable => policy.detection_confidence.variable,
        Confidence::StringTable => policy.detection_confidence.string_table,
        Confidence::Unknown => policy.detection_confidence.unknown,
    }
}

fn map_severity(score: u8, policy: &Policy) -> Severity {
    let b = &policy.severity_bands;
    if score >= b.critical {
        Severity::Critical
    } else if score >= b.high {
        Severity::High
    } else if score >= b.medium {
        Severity::Medium
    } else if score >= b.low {
        Severity::Low
    } else {
        Severity::Safe
    }
}

/// Decide whether a finding should carry the HNDL-CRITICAL tag.
///
/// All three conditions in `policy.hndl_flag` must be met.
pub fn is_hndl_critical(finding: &Finding, algorithm: &AlgorithmRecord, policy: &Policy) -> bool {
    let status_ok = policy
        .hndl_flag
        .require_quantum_status_in
        .contains(&algorithm.quantum_status);

    let context_name = usage_context_name(finding.usage_context);
    let context_ok = policy
        .hndl_flag
        .require_usage_context_in
        .iter()
        .any(|s| s.as_str() == context_name);

    let shelf_ok = shelf_life_at_least(
        &finding.shelf_life_bucket,
        &policy.hndl_flag.require_min_shelf_life_bucket,
    );

    status_ok && context_ok && shelf_ok
}

fn usage_context_name(c: UsageContext) -> &'static str {
    match c {
        UsageContext::KeyEstablishmentLongLived => "key_establishment_long_lived",
        UsageContext::KeyEstablishmentEphemeral => "key_establishment_ephemeral",
        UsageContext::DataAtRestEncryption => "data_at_rest_encryption",
        UsageContext::SignatureLongLived => "signature_long_lived",
        UsageContext::SignatureEphemeral => "signature_ephemeral",
        UsageContext::AuthenticationOnly => "authentication_only",
        UsageContext::Hashing => "hashing",
        UsageContext::Unknown => "unknown",
    }
}

fn shelf_life_at_least(bucket: &str, min: &str) -> bool {
    let order = |b: &str| match b {
        "ephemeral" => 0u8,
        "short" => 1,
        "medium" => 2,
        "long" => 3,
        _ => 0,
    };
    order(bucket) >= order(min)
}

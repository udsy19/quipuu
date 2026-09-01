//! 5-axis additive QuantumRiskScore (D-10).
//!
//! Score = AlgorithmVulnerability + UsageContext + DataShelfLife
//!       + Exposure + DetectionConfidence
//! Bands: ≥75 Critical, 50–74 High, 25–49 Medium, 10–24 Low, <10 Safe.

use crate::{
    AlgorithmRecord, AlgorithmTable, Confidence, Exposure, Finding, Policy, Severity, UsageContext,
};

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
        let av = score_algorithm_vulnerability(algorithm, policy)
            .min(policy.risk_weights.algorithm_vulnerability);

        // A policy that scores this quantum_status at 0 has made a categorical
        // judgement that the algorithm is not vulnerable — `disallows` always
        // returns the full weight, never 0, so this never fires for a
        // jurisdiction-excluded algorithm. The remaining axes describe how a
        // vulnerable algorithm is being used; letting them add up to an alert
        // band on their own would score a migrated codebase worse than an
        // unmigrated one, so a zero algorithm-vulnerability term zeroes the
        // whole score instead of leaving it to arithmetic.
        if av == 0 {
            return Self {
                algorithm_vulnerability: 0,
                usage_context: 0,
                data_shelf_life: 0,
                exposure: 0,
                detection_confidence: 0,
                total: 0,
                severity: map_severity(0, policy),
            };
        }

        let uc = score_usage_context(finding.usage_context, policy)
            .min(policy.risk_weights.usage_context);
        let ds = score_data_shelf_life(&finding.shelf_life_bucket, policy)
            .min(policy.risk_weights.data_shelf_life);
        let ex = score_exposure(finding.exposure, policy).min(policy.risk_weights.exposure);
        let dc = score_detection_confidence(finding.confidence, policy)
            .min(policy.risk_weights.detection_confidence);

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
    // A jurisdiction that excludes an algorithm from its approved list has
    // already made the judgement; the quantum_status weight would understate
    // it. CNSA 2.0 vs AES-128 is the motivating case — unbroken, non-compliant.
    if policy.disallows(&algorithm.id) {
        return policy.risk_weights.algorithm_vulnerability;
    }
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

/// The risk score of one finding, or `None` when its `algorithm_id` has no row
/// in the algorithm table.
///
/// **`None` means *unscored*. It does not mean Safe and it does not mean
/// Medium.** `algorithm_vulnerability` is 40 of the 100 available points — the
/// largest single axis — and it is read entirely from the algorithm record, so
/// a finding with no record cannot be banded at all. Substituting a band for
/// the missing one is the same defect as naming a parameter the input never
/// stated: an assertion the evidence does not carry.
///
/// This exists because every surface used to make that substitution privately,
/// and they did not agree. One `openssl = "0.10"` line in a `Cargo.toml`
/// produces `DEP-001` carrying the `unknown` sentinel — what `scan-deps` sets
/// its algorithm id to for a manifest that names a crypto library but no
/// algorithm — and the same scan reported it as `?` on stdout, `Medium` in
/// `summary.json` and the HTML report, `warning` with
/// `security-severity: 5.0` in SARIF, and `Safe` in the TUI. `--fail-on`
/// alone got it right, and only because R27 had to reason about it to write
/// the gate. Callers now share that reasoning instead of each re-deriving it.
///
/// Render `None` as unscored and say so; do not fold it into a band.
pub fn score_of(
    finding: &Finding,
    algorithms: &AlgorithmTable,
    policy: &Policy,
) -> Option<QuantumRiskScore> {
    algorithms
        .get(&finding.algorithm_id)
        .map(|algorithm| QuantumRiskScore::compute(finding, algorithm, policy))
}

/// [`score_of`], keeping only the band. `None` is unscored — read that doc
/// before choosing what to do with it.
pub fn severity_of(
    finding: &Finding,
    algorithms: &AlgorithmTable,
    policy: &Policy,
) -> Option<Severity> {
    score_of(finding, algorithms, policy).map(|s| s.severity)
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

/// Decide `hndl_critical` for every finding, in place.
///
/// The scanners construct findings without a policy — they cannot decide this,
/// and they were all writing a hard-coded `false`. That made
/// `summary.json.totals.hndl_critical` and the HTML report's HNDL section
/// permanently zero, and `is_hndl_critical` reachable from tests only: the
/// product answered "no HNDL exposure" for every input, including inputs that
/// meet all three of the active policy's conditions.
///
/// This is the one place the flag is decided, so it runs once over the whole
/// finding set after collection and before anything reads it. It overwrites
/// rather than or-s: the value a scanner wrote carries no information, and a
/// stale `true` surviving a policy change would be the same defect mirrored.
///
/// A finding whose `algorithm_id` has no table row keeps `false` — the flag
/// requires a `quantum_status` to test, and inventing one would be a claim we
/// cannot ground.
pub fn apply_hndl_flags(findings: &mut [Finding], algorithms: &AlgorithmTable, policy: &Policy) {
    for finding in findings.iter_mut() {
        finding.hndl_critical = match algorithms.get(&finding.algorithm_id) {
            Some(algorithm) => is_hndl_critical(finding, algorithm, policy),
            None => false,
        };
    }
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

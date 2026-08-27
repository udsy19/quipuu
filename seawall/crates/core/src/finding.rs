//! Findings — what scanners emit and what the risk engine consumes.

use serde::{Deserialize, Serialize};

/// A code/network/cert location, used in CBOM `evidence.occurrences[]` and
/// SARIF `physicalLocation`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    /// File path (relative for source scans), host:port for net, cert path for certs.
    pub location: String,
    /// 1-based line number when available.
    pub line: Option<u32>,
    /// Byte offset when available.
    pub offset: Option<u32>,
    /// API symbol matched (e.g. `rsa.GenerateKey`).
    pub symbol: Option<String>,
    /// Sanitised snippet for the report.
    pub snippet: Option<String>,
}

/// Detection confidence — drives the `DetectionConfidence` axis of the score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Confidence {
    /// Literal argument captured (e.g. `rsa.GenerateKey(rand.Reader, 2048)`).
    LiteralArg,
    /// Type-name match (Rust paths, Java fully-qualified names).
    TypeName,
    /// Value flowed in from a const/var; partial propagation.
    Variable,
    /// Algorithm chosen via runtime string lookup.
    StringTable,
    /// Fallback when nothing else fits.
    Unknown,
}

/// Site-level syntactic context for a match — Phase 16.
///
/// Distinguishes WHERE in the AST a match was found, separately from the
/// `Confidence` axis (which captures HOW the algorithm-id was derived).
/// The classify layer can opt rules in or out per site context via the
/// `when.site_context` TOML predicate, suppressing matches in
/// non-operational positions (config arrays, test assertions, enum tables)
/// while keeping matches in real call sites.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SiteContext {
    /// Match is an argument to a call expression — the canonical
    /// "operational" position (e.g. `jwt.sign(payload, key, {algorithm:'RS256'})`).
    Call,
    /// Match is a const or var declaration value
    /// (e.g. `const RS256 = "RS256"`). Operational at definition time; the
    /// downstream consumer of the const is where the actual crypto happens.
    StringConstant,
    /// Match is a value in a struct / composite literal whose surrounding
    /// type registers a crypto algorithm (e.g. golang-jwt's
    /// `&SigningMethodRSA{"RS256", crypto.SHA256}`). High-signal operational.
    StructLiteral,
    /// Match is the value side of a map literal entry
    /// (e.g. `"RS512": true` allowlist, `"HS384": 2` protobuf enum table).
    /// Almost always non-operational data.
    MapEntry,
    /// Match is an argument to a test-framework assertion or helper
    /// (e.g. `require.Equal(t, "HS256", got)`). Test scaffolding, not crypto.
    TestAssertion,
    /// Anything else — default for matches that don't fit above. Treated
    /// as Default by classify rules unless the rule narrows on a specific
    /// context.
    Default,
}

/// Usage context — drives the `UsageContext` axis of the score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UsageContext {
    KeyEstablishmentLongLived,
    KeyEstablishmentEphemeral,
    DataAtRestEncryption,
    SignatureLongLived,
    SignatureEphemeral,
    AuthenticationOnly,
    Hashing,
    Unknown,
}

/// Exposure axis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Exposure {
    PublicInternet,
    InternalService,
    LocalOnly,
}

/// Severity band — output of the QuantumRiskScore severity map.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Safe,
}

/// One cryptographic finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// SARIF rule id (CRYPTO-NNN).
    pub rule_id: String,
    /// Canonical algorithm-id from the algorithm table.
    pub algorithm_id: String,
    /// Where it was found.
    pub location: Location,
    /// Why the scanner reports this finding.
    pub message: String,
    /// Detection confidence at extraction time.
    pub confidence: Confidence,
    /// How the algorithm is being used.
    pub usage_context: UsageContext,
    /// Exposure assessment.
    pub exposure: Exposure,
    /// Shelf-life bucket name resolved from policy.shelf_life_tags.
    pub shelf_life_bucket: String,
    /// True if this finding meets the HNDL flagging criteria.
    pub hndl_critical: bool,
}

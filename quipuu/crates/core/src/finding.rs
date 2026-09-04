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
    /// Match is an operand of an equality test — `alg.equals(JWSAlgorithm.PS256)`,
    /// `JWSAlgorithm.HS512.equals(alg)`, `alg == RS256`. Naming an algorithm in
    /// order to compare against it selects a branch; the operation, if any,
    /// happens inside the branch and cites its own line.
    Comparison,
    /// Match is an element handed to a collection-membership call —
    /// `algs.add(JWSAlgorithm.PS384)`, `Arrays.asList(HS512, HS384, HS256)`.
    /// A supported-algorithm set declares a capability; it computes nothing.
    CollectionElement,
    /// Match is the argument of a registry-retrieval call whose result is not
    /// handed straight to another call — `jwa.LookupSignatureAlgorithm("PS256")`,
    /// `return lookupBuiltinSignatureAlgorithm("ES384")`. Naming an algorithm
    /// to fetch its descriptor produces no signature; the operation, if any,
    /// happens wherever the descriptor is later used.
    RegistryLookup,
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

impl Severity {
    /// Every band, most severe first.
    pub const ALL: [Severity; 5] = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Safe,
    ];

    /// Comparison rank — **higher is worse**. `a.rank() >= b.rank()` reads as
    /// "a is at least as severe as b", which is the `--fail-on` gate test.
    pub fn rank(self) -> u8 {
        match self {
            Severity::Safe => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }

    /// Title-case display name, as it appears in reports and on stdout.
    pub fn label(self) -> &'static str {
        match self {
            Severity::Critical => "Critical",
            Severity::High => "High",
            Severity::Medium => "Medium",
            Severity::Low => "Low",
            Severity::Safe => "Safe",
        }
    }

    /// Lowercase machine name — the CSS class in the HTML report and the
    /// spelling `--fail-on` accepts.
    pub fn slug(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Safe => "safe",
        }
    }

    /// Parse a [`Severity::slug`], case-insensitively. `None` for anything
    /// else — callers decide whether an unknown spelling is fatal.
    pub fn parse(s: &str) -> Option<Self> {
        let lowered = s.to_ascii_lowercase();
        Severity::ALL.into_iter().find(|s| s.slug() == lowered)
    }
}

/// Derive a stable finding id from the fields that identify a call site.
///
/// FNV-1a over `rule_id|algorithm_id|location|line|symbol`, not
/// `std::hash::DefaultHasher` — `RandomState` reseeds per process, so a
/// `DefaultHasher` id would change on every scan of the same tree and
/// silently defeat `diff`/`baseline` (M3), which key on this id staying put
/// across scans of unchanged code.
pub fn stable_finding_id(
    rule_id: &str,
    algorithm_id: &str,
    location: &str,
    line: Option<u32>,
    symbol: Option<&str>,
) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    let input = format!(
        "{rule_id}|{algorithm_id}|{location}|{}|{}",
        line.unwrap_or(0),
        symbol.unwrap_or("")
    );
    for byte in input.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("QPU-{:08X}", hash as u32)
}

/// One cryptographic finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Stable finding id (`QPU-XXXXXXXX`), derived from
    /// [`stable_finding_id`]. Survives across scans of an unchanged tree —
    /// the key `diff`/`baseline` (Program M3) need to tell a carried-forward
    /// finding from a new one.
    #[serde(default)]
    pub id: String,
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

#[cfg(test)]
mod stable_id_tests {
    use super::stable_finding_id;

    #[test]
    fn same_inputs_produce_the_same_id() {
        let a = stable_finding_id(
            "CRYPTO-340",
            "rsa-2048",
            "src/keys.rs",
            Some(84),
            Some("rsa.GenerateKey"),
        );
        let b = stable_finding_id(
            "CRYPTO-340",
            "rsa-2048",
            "src/keys.rs",
            Some(84),
            Some("rsa.GenerateKey"),
        );
        assert_eq!(a, b);
        assert!(a.starts_with("QPU-"));
    }

    #[test]
    fn different_lines_produce_different_ids() {
        let a = stable_finding_id(
            "CRYPTO-340",
            "rsa-2048",
            "src/keys.rs",
            Some(84),
            Some("rsa.GenerateKey"),
        );
        let b = stable_finding_id(
            "CRYPTO-340",
            "rsa-2048",
            "src/keys.rs",
            Some(85),
            Some("rsa.GenerateKey"),
        );
        assert_ne!(a, b);
    }
}

//! Two-layer rule loader (D-07).
//!
//! Rules live in TOML under `quipuu-core/data/rules/<lang>.toml`. Each
//! file has two top-level arrays:
//!
//! * `[[extract]]` — tree-sitter query + capture list + logical API name.
//! * `[[classify]]` — maps `(api, captures)` tuples to canonical algorithm-ids
//!   with severity hints.
//!
//! See `crates/core/data/README.md` and `data/rules/go.toml` for
//! the field reference.

use std::collections::BTreeMap;

use serde::Deserialize;
use thiserror::Error;

/// Languages we have rule packs for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    Go,
    Python,
    Java,
    JavaScript,
    TypeScript,
    C,
    Cpp,
    Rust,
    CSharp,
}

impl Language {
    /// Get the language from a string (e.g. from rule TOML).
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "go" => Some(Self::Go),
            "python" => Some(Self::Python),
            "java" => Some(Self::Java),
            "javascript" => Some(Self::JavaScript),
            "typescript" => Some(Self::TypeScript),
            "c" => Some(Self::C),
            "cpp" | "c++" => Some(Self::Cpp),
            "rust" => Some(Self::Rust),
            "csharp" | "c#" => Some(Self::CSharp),
            _ => None,
        }
    }

    /// File extensions quipuu scans for this language.
    pub fn extensions(self) -> &'static [&'static str] {
        match self {
            Self::Go => &["go"],
            Self::Python => &["py"],
            Self::Java => &["java"],
            Self::JavaScript => &["js", "mjs", "cjs"],
            Self::TypeScript => &["ts", "tsx", "mts"],
            Self::C => &["c", "h"],
            Self::Cpp => &["cpp", "cc", "cxx", "hpp", "hxx"],
            Self::Rust => &["rs"],
            Self::CSharp => &["cs"],
        }
    }
}

/// Layer 1: tree-sitter extraction. Finds a call site and captures arg values.
#[derive(Debug, Clone, Deserialize)]
pub struct ExtractRule {
    pub id: String,
    pub language: String,
    pub query: String,
    /// Map of capture name → expected kind. Kept verbatim so the loader can
    /// validate that the query's `@captures` are documented.
    #[serde(default)]
    pub captures: BTreeMap<String, String>,
    pub api: String,
    #[serde(default)]
    pub description: String,
}

/// Predicates the classify layer can apply to extracted values.
///
/// Variant order matters: serde's `untagged` deserializer tries variants
/// top-to-bottom and uses the first that fits. `Regex` carries a required
/// `regex` field that `Range` lacks, so the more specific variants must come
/// before the more permissive ones.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum ArgMatch {
    /// Exact integer match: `key_size = 2048`.
    ExactInt(i64),
    /// Exact string match: `curve_name = "SECP256R1"`.
    ExactStr(String),
    /// Regex match: `{ regex = "^SECP256R1$" }`.
    Regex(RegexMatch),
    /// Numeric range: `{ lt = 2048 }`, `{ ge = 3072 }`.
    Range(RangeMatch),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RangeMatch {
    pub lt: Option<i64>,
    pub le: Option<i64>,
    pub gt: Option<i64>,
    pub ge: Option<i64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegexMatch {
    pub regex: String,
}

/// Layer 2: classification.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClassifyRule {
    pub id: String,
    pub when: WhenClause,
    pub algorithm_id: String,
    pub severity_hint: String,
    pub message: String,
    #[serde(default)]
    pub cwe: Option<String>,
    /// Why this rule may name a parameter that does not appear in its own
    /// match — `ES512` determines P-521 by RFC 7518 § 3.4, and no amount of
    /// reading the string will show a `521`.
    ///
    /// Its reader is `crates/cli/tests/algorithm_parameters.rs`, which
    /// otherwise rejects the rule. `deny_unknown_fields` is on this struct so
    /// that a misspelled key is a load error rather than a waiver that
    /// silently does not apply — the failure mode this whole field exists to
    /// prevent is a claim nobody checked.
    #[serde(default)]
    pub parameter_source: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WhenClause {
    /// Regex against `ExtractRule.api`.
    pub api: String,
    /// Map of capture name → predicate.
    #[serde(default)]
    pub args: BTreeMap<String, ArgMatch>,
    /// Phase 16: allow-list of `SiteContext` variants the match must be in.
    /// Default (None) keeps prior behavior — match any context. When set,
    /// the rule fires only if the match's site_context is in the list.
    /// TOML form: `site_context = ["Call", "StructLiteral"]`.
    #[serde(default)]
    pub site_context: Option<Vec<String>>,
}

/// One language's rule pack — parsed from a single TOML file.
#[derive(Debug, Clone, Deserialize)]
pub struct RulePack {
    #[serde(default)]
    pub extract: Vec<ExtractRule>,
    #[serde(default)]
    pub classify: Vec<ClassifyRule>,
}

#[derive(Debug, Error)]
pub enum LoadError {
    #[error("TOML parse error: {0}")]
    Toml(#[from] toml::de::Error),
}

impl RulePack {
    /// Parse a rule pack from a TOML string.
    pub fn from_toml(s: &str) -> Result<Self, LoadError> {
        Ok(toml::from_str(s)?)
    }

    /// Load the built-in Go rule pack.
    pub fn builtin_go() -> Result<Self, LoadError> {
        Self::from_toml(include_str!("../../core/data/rules/go.toml"))
    }

    /// Load the built-in Python rule pack.
    pub fn builtin_python() -> Result<Self, LoadError> {
        Self::from_toml(include_str!("../../core/data/rules/python.toml"))
    }

    /// Load the built-in Java rule pack.
    pub fn builtin_java() -> Result<Self, LoadError> {
        Self::from_toml(include_str!("../../core/data/rules/java.toml"))
    }

    /// Load the built-in JavaScript/TypeScript rule pack.
    pub fn builtin_javascript() -> Result<Self, LoadError> {
        Self::from_toml(include_str!("../../core/data/rules/javascript.toml"))
    }

    /// Load the built-in C/C++ rule pack.
    pub fn builtin_cpp() -> Result<Self, LoadError> {
        Self::from_toml(include_str!("../../core/data/rules/cpp.toml"))
    }

    /// Load the built-in Rust rule pack.
    pub fn builtin_rust() -> Result<Self, LoadError> {
        Self::from_toml(include_str!("../../core/data/rules/rust.toml"))
    }

    /// Load the built-in C# rule pack.
    pub fn builtin_csharp() -> Result<Self, LoadError> {
        Self::from_toml(include_str!("../../core/data/rules/csharp.toml"))
    }
}

/// The curve a classify rule's `when` clause pins, if it pins one.
///
/// Reads the spellings the seven packs actually use: `P521` / `P-521`
/// (`curve_fn`, `CurveP521`, `elliptic.P521`), `SECP521R1` / `secp521r1`
/// (pyca, JCA `ECGenParameterSpec`), and `prime256v1` (OpenSSL's name for
/// P-256). Returns `None` when the clause names no curve at all, which is
/// the common and legitimate case — the curve then comes from a JOSE
/// algorithm name or from off-site, and neither is this check's business.
#[cfg(test)]
fn curve_named_by(evidence: &str) -> Option<&'static str> {
    let upper = evidence.to_ascii_uppercase();
    if upper.contains("PRIME256V1") {
        return Some("256");
    }
    ["224", "256", "384", "521"].into_iter().find(|bits| {
        upper.contains(&format!("P{bits}"))
            || upper.contains(&format!("P-{bits}"))
            || upper.contains(&format!("SECP{bits}R1"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression test for an ArgMatch deserializer bug: `{ regex = "..." }`
    /// must parse as `ArgMatch::Regex`, not as an empty `ArgMatch::Range`.
    /// Variant order in the untagged enum is load-bearing.
    #[test]
    fn argmatch_regex_does_not_deserialize_as_empty_range() {
        let toml_src = r#"
[[classify]]
id = "X-001"
algorithm_id = "rsa-2048"
severity_hint = "auto"
message = "test"
when = { api = "^foo$", args = { curve = { regex = "^BAR$" } } }
"#;
        let pack: RulePack = toml::from_str(toml_src).unwrap();
        let arg = pack.classify[0].when.args.get("curve").unwrap();
        match arg {
            ArgMatch::Regex(r) => assert_eq!(r.regex, "^BAR$"),
            other => panic!("expected Regex variant, got {:?}", other),
        }
    }

    #[test]
    fn argmatch_range_parses() {
        let toml_src = r#"
[[classify]]
id = "X-002"
algorithm_id = "rsa-2048"
severity_hint = "auto"
message = "test"
when = { api = "^foo$", args = { bits = { lt = 2048 } } }
"#;
        let pack: RulePack = toml::from_str(toml_src).unwrap();
        let arg = pack.classify[0].when.args.get("bits").unwrap();
        match arg {
            ArgMatch::Range(r) => assert_eq!(r.lt, Some(2048)),
            other => panic!("expected Range variant, got {:?}", other),
        }
    }

    /// Every AES key size and every elliptic curve a classify rule publishes
    /// must be observable from that rule's own `when` clause — either the api
    /// regex names it (`EVP_aes_256_gcm`, `Aes128Gcm`, `A256GCM`) or an arg
    /// predicate pins it (`AES_128.*/GCM`, `curve_fn = "P521"`). A rule that
    /// names a parameter its `when` never reads is publishing a guess, and
    /// that guess ships as an asserted `parameterSetIdentifier` in the CBOM.
    ///
    /// Regression gate, key sizes: `Cipher.getInstance("AES/GCM/NoPadding")`,
    /// `AESEngine`, `BouncyCastleProvider`, `Aes.Create()`, `aes.NewCipher`
    /// and `CryptoJS.AES.encrypt` were all published as `aes-256-gcm`. Use an
    /// `aes-unattributed*` sentinel when the source does not state the width.
    ///
    /// Regression gate, curves: `CRYPTO-035` / `CRYPTO-039` matched `P521`
    /// and published `ecdh-p384`; `CRYPTO-010` / `CRYPTO-110` matched `P224`
    /// and published `ecdsa-p256` with the comment "map to nearest baseline".
    /// Mapping a curve to a neighbouring one is not a rounding error — it
    /// reports a security level the code does not have, in both directions.
    /// Use `ecdsa-unattributed` when the curve is genuinely off-site.
    ///
    /// RSA moduli are deliberately out of scope: a rule that reads `bits` as
    /// a range (`{ lt = 2048 }`) cannot name the exact modulus in its `when`,
    /// so the same check would reject every correct RSA rule.
    #[test]
    fn classify_rules_never_publish_a_parameter_their_when_clause_contradicts() {
        let packs = [
            ("go", RulePack::builtin_go().unwrap()),
            ("python", RulePack::builtin_python().unwrap()),
            ("java", RulePack::builtin_java().unwrap()),
            ("javascript", RulePack::builtin_javascript().unwrap()),
            ("cpp", RulePack::builtin_cpp().unwrap()),
            ("rust", RulePack::builtin_rust().unwrap()),
            ("csharp", RulePack::builtin_csharp().unwrap()),
        ];
        let mut offenders = Vec::new();
        for (lang, pack) in &packs {
            for rule in &pack.classify {
                // Everything the `when` clause can actually see.
                let evidence = format!("{} {:?}", rule.when.api, rule.when.args);
                let width = rule
                    .algorithm_id
                    .strip_prefix("aes-")
                    .and_then(|rest| ["128", "192", "256"].iter().find(|w| rest.starts_with(**w)));
                if let Some(width) = width
                    && !evidence.contains(width)
                {
                    offenders.push(format!(
                        "{}/{} publishes `{}` but its `when` never reads {}",
                        lang, rule.id, rule.algorithm_id, width
                    ));
                }
                // Curves, checked as a CONTRADICTION rather than as missing
                // evidence. Plenty of rules legitimately derive the curve
                // from something other than a curve name — RFC 7518 fixes
                // ES256 to P-256, ES384 to P-384, ES512 to P-521 — and those
                // are correct. What is never correct is a `when` that pins
                // one curve while the id names another.
                let published = rule
                    .algorithm_id
                    .strip_prefix("ecdsa-p")
                    .or_else(|| rule.algorithm_id.strip_prefix("ecdh-p"))
                    .filter(|rest| rest.chars().all(|c| c.is_ascii_digit()));
                if let Some(published) = published
                    && let Some(matched) = curve_named_by(&evidence)
                    && matched != published
                {
                    offenders.push(format!(
                        "{}/{} matches P-{} but publishes `{}`",
                        lang, rule.id, matched, rule.algorithm_id
                    ));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "classify rules asserting a parameter their `when` clause cannot observe:\n  {}",
            offenders.join("\n  ")
        );
    }

    /// A `[[classify]]` rule can only fire on a `RawMatch` some matcher
    /// produced. There is no query engine — `[[extract]]` blocks are
    /// documentation — so a rule naming an api that no matcher emits is
    /// silently dead. Nothing in the output distinguishes "this codebase is
    /// clean" from "this rule has never run", which is how `CRYPTO-130`
    /// (3DES) and `CRYPTO-131` (RC4) shipped as Critical rules that had never
    /// produced a finding.
    ///
    /// The api surface comes from the same tables `match_*_callee` dispatches
    /// on, so it cannot drift from the matchers.
    #[test]
    fn every_classify_rule_targets_an_api_the_extractor_can_emit() {
        let surface = crate::scanner::api_surface();
        let packs = [
            ("go", RulePack::builtin_go().unwrap()),
            ("python", RulePack::builtin_python().unwrap()),
            ("java", RulePack::builtin_java().unwrap()),
            ("javascript", RulePack::builtin_javascript().unwrap()),
            ("cpp", RulePack::builtin_cpp().unwrap()),
            ("rust", RulePack::builtin_rust().unwrap()),
            ("csharp", RulePack::builtin_csharp().unwrap()),
        ];
        let mut stranded = Vec::new();
        for (lang, pack) in &packs {
            for rule in &pack.classify {
                let re = regex::Regex::new(&rule.when.api)
                    .unwrap_or_else(|e| panic!("[{lang}] {}: bad api regex: {e}", rule.id));
                if !surface.iter().any(|api| re.is_match(api)) {
                    stranded.push(format!(
                        "{}/{}: when.api = {:?} matches no api the extract layer emits",
                        lang, rule.id, rule.when.api
                    ));
                }
            }
        }
        assert!(
            stranded.is_empty(),
            "{} classify rules can never fire. Either add a matcher that emits \
             the api — and its row to the callee table, so `api_surface()` sees \
             it — or delete the rule:\n  {}",
            stranded.len(),
            stranded.join("\n  ")
        );
    }

    #[test]
    fn builtin_rules_load() {
        let go = RulePack::builtin_go().expect("Go rule pack must parse");
        let py = RulePack::builtin_python().expect("Python rule pack must parse");
        let java = RulePack::builtin_java().expect("Java rule pack must parse");
        let js = RulePack::builtin_javascript().expect("JS rule pack must parse");
        let cpp = RulePack::builtin_cpp().expect("C/C++ rule pack must parse");
        let rust = RulePack::builtin_rust().expect("Rust rule pack must parse");
        let cs = RulePack::builtin_csharp().expect("C# rule pack must parse");
        assert!(!go.classify.is_empty());
        assert!(!py.classify.is_empty());
        assert!(!java.classify.is_empty());
        assert!(!js.classify.is_empty());
        assert!(!cpp.classify.is_empty());
        assert!(!rust.classify.is_empty());
        assert!(!cs.classify.is_empty());
    }
}

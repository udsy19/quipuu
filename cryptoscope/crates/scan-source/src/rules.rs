//! Two-layer rule loader (D-07).
//!
//! Rules live in TOML under `cryptoscope-core/data/rules/<lang>.toml`. Each
//! file has two top-level arrays:
//!
//! * `[[extract]]` — tree-sitter query + capture list + logical API name.
//! * `[[classify]]` — maps `(api, captures)` tuples to canonical algorithm-ids
//!   with severity hints.
//!
//! See `knowledge/11-decisions/data/README.md` and `data/rules/go.toml` for
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
}

impl Language {
    /// Get the language from a string (e.g. from rule TOML).
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "go" => Some(Self::Go),
            "python" => Some(Self::Python),
            _ => None,
        }
    }

    /// File extensions cryptoscope scans for this language.
    pub fn extensions(self) -> &'static [&'static str] {
        match self {
            Self::Go => &["go"],
            Self::Python => &["py"],
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
pub struct ClassifyRule {
    pub id: String,
    pub when: WhenClause,
    pub algorithm_id: String,
    pub severity_hint: String,
    pub message: String,
    #[serde(default)]
    pub cwe: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WhenClause {
    /// Regex against `ExtractRule.api`.
    pub api: String,
    /// Map of capture name → predicate.
    #[serde(default)]
    pub args: BTreeMap<String, ArgMatch>,
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

    #[test]
    fn builtin_rules_load() {
        let go = RulePack::builtin_go().expect("Go rule pack must parse");
        let py = RulePack::builtin_python().expect("Python rule pack must parse");
        assert!(!go.classify.is_empty());
        assert!(!py.classify.is_empty());
    }
}

// Re-export `WhenClause` as `WhenMatch` for backwards compat with the
// scanner's earlier prototype. We keep it lightly aliased to make refactors
// painless.
pub type WhenMatch = WhenClause;

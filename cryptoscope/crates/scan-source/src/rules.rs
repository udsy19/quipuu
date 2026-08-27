//! Two-layer rule loader (D-07).
//!
//! Rules live in TOML under `cryptoscope-core/data/rules/<lang>.toml`. Each
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

    /// File extensions cryptoscope scans for this language.
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

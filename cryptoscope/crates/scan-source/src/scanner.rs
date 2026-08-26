//! Scanner — walks files and produces [`Finding`]s.
//!
//! The walking skeleton uses tree-sitter to parse each file and walks the
//! tree looking for call sites that match well-known crypto API shapes.
//! It does NOT execute the raw tree-sitter S-expression queries from the
//! rule TOML yet — that's deferred (the rule queries need polishing against
//! each grammar). Instead the matcher hard-codes a handful of shapes for
//! the v0 rule set and uses the `classify` layer of the TOML to look up
//! algorithm-id + message + severity.
//!
//! This keeps the rule pack as the *source of truth* for classification
//! while we build out the query engine in a follow-up pass.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use cryptoscope_core::{AlgorithmTable, Confidence, Exposure, Finding, Location, UsageContext};
use thiserror::Error;
use tree_sitter::{Node, Parser};

use crate::rules::{ArgMatch, ClassifyRule, Language, RulePack};

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("tree-sitter language load failed for {0:?}")]
    GrammarLoad(Language),
    #[error("unknown algorithm id: {0}")]
    UnknownAlgorithm(String),
    #[error("regex compile failed: {0}")]
    RegexCompile(#[from] regex::Error),
    #[error("walk: {0}")]
    Walk(#[from] ignore::Error),
}

/// One detected call site, before classify-layer lookup.
#[derive(Debug, Clone)]
pub struct RawMatch {
    pub api: String,
    pub args: HashMap<String, ArgValue>,
    pub line: u32,
    pub offset: u32,
    pub symbol: String,
    pub snippet: String,
}

/// A captured argument from an extract pattern.
#[derive(Debug, Clone)]
pub enum ArgValue {
    Int(i64),
    Str(String),
}

impl ArgValue {
    fn as_str(&self) -> String {
        match self {
            ArgValue::Int(n) => n.to_string(),
            ArgValue::Str(s) => s.clone(),
        }
    }
}

/// The scanner. Construct with the rule packs and the algorithm table; call
/// [`Scanner::scan_path`] to walk a directory or file.
pub struct Scanner {
    rules_by_lang: HashMap<Language, RulePack>,
    algorithms: AlgorithmTable,
}

impl Scanner {
    /// Build a scanner using the built-in rule packs (Go + Python) and the
    /// built-in algorithm table.
    pub fn with_builtins(algorithms: AlgorithmTable) -> Result<Self, ScanError> {
        let mut rules_by_lang = HashMap::new();
        rules_by_lang.insert(
            Language::Go,
            RulePack::builtin_go().expect("built-in Go rules must parse"),
        );
        rules_by_lang.insert(
            Language::Python,
            RulePack::builtin_python().expect("built-in Python rules must parse"),
        );
        Ok(Self {
            rules_by_lang,
            algorithms,
        })
    }

    /// Scan a single file or recurse over a directory. Honors `.gitignore`.
    pub fn scan_path(&self, root: &Path) -> Result<Vec<Finding>, ScanError> {
        let mut findings = Vec::new();
        if root.is_file() {
            self.scan_file_into(root, &mut findings)?;
            return Ok(findings);
        }
        for entry in ignore::WalkBuilder::new(root)
            .standard_filters(true)
            .build()
        {
            let entry = entry?;
            if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                self.scan_file_into(entry.path(), &mut findings)?;
            }
        }
        Ok(findings)
    }

    fn scan_file_into(&self, path: &Path, out: &mut Vec<Finding>) -> Result<(), ScanError> {
        let Some(language) = detect_language(path) else {
            return Ok(());
        };
        let Some(rules) = self.rules_by_lang.get(&language) else {
            return Ok(());
        };
        let source = std::fs::read(path)?;
        let matches = run_extract(&source, language)?;
        for m in matches {
            for classify in &rules.classify {
                if let Some(finding) = apply_classify(&m, classify, &self.algorithms, path)? {
                    out.push(finding);
                    break; // first matching classify rule wins
                }
            }
        }
        Ok(())
    }
}

/// Decide a language from a file path.
fn detect_language(path: &Path) -> Option<Language> {
    let ext = path.extension()?.to_str()?;
    match ext {
        "go" => Some(Language::Go),
        "py" => Some(Language::Python),
        _ => None,
    }
}

/// Run the v0 hard-coded extract pass. Returns one [`RawMatch`] per detected
/// call site. The TOML rule pack drives classification; what we detect is:
///
/// * Go: `rsa.GenerateKey(rand.Reader, <int>)`, `ecdsa.GenerateKey(elliptic.PCURVE(), …)`,
///   `ed25519.GenerateKey(...)`, `md5.New()` / `sha1.New()`.
/// * Python: `rsa.generate_private_key(public_exponent=…, key_size=<int>)`,
///   `ec.generate_private_key(ec.SECP256R1())`, `hashlib.md5()` / `hashlib.sha1()`.
fn run_extract(source: &[u8], language: Language) -> Result<Vec<RawMatch>, ScanError> {
    let mut parser = Parser::new();
    let ts_lang = match language {
        Language::Go => tree_sitter_go::LANGUAGE,
        Language::Python => tree_sitter_python::LANGUAGE,
    };
    parser
        .set_language(&ts_lang.into())
        .map_err(|_| ScanError::GrammarLoad(language))?;

    let tree = parser
        .parse(source, None)
        .ok_or(ScanError::GrammarLoad(language))?;

    let mut matches = Vec::new();
    let root = tree.root_node();
    walk(root, source, language, &mut matches);
    Ok(matches)
}

fn walk(node: Node<'_>, source: &[u8], language: Language, out: &mut Vec<RawMatch>) {
    if (node.kind() == "call_expression" || node.kind() == "call")
        && let Some(m) = match_call(node, source, language)
    {
        out.push(m);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk(child, source, language, out);
    }
}

/// Inspect one call node and decide if it's a known crypto API site.
fn match_call(call: Node<'_>, source: &[u8], language: Language) -> Option<RawMatch> {
    let (callee, args_node) = match language {
        Language::Go => {
            // (call_expression function: <expr> arguments: (argument_list ...))
            let function = call.child_by_field_name("function")?;
            let args = call.child_by_field_name("arguments")?;
            (function, args)
        }
        Language::Python => {
            // (call function: <expr> arguments: (argument_list ...))
            let function = call.child_by_field_name("function")?;
            let args = call.child_by_field_name("arguments")?;
            (function, args)
        }
    };

    let callee_text = node_text(callee, source);

    let (api, mut args) = match language {
        Language::Go => match_go_callee(&callee_text)?,
        Language::Python => match_python_callee(&callee_text)?,
    };

    // Extract argument values per API.
    populate_args(language, &api, args_node, source, &mut args);

    let start = call.start_position();
    Some(RawMatch {
        api,
        args,
        line: (start.row + 1) as u32,
        offset: call.start_byte() as u32,
        symbol: callee_text.clone(),
        snippet: node_text(call, source),
    })
}

fn match_go_callee(callee: &str) -> Option<(String, HashMap<String, ArgValue>)> {
    let api = match callee {
        "rsa.GenerateKey" => "crypto/rsa.GenerateKey",
        "ecdsa.GenerateKey" => "crypto/ecdsa.GenerateKey",
        "ed25519.GenerateKey" => "crypto/ed25519.GenerateKey",
        "md5.New" => "crypto/md5_sha1.New",
        "sha1.New" => "crypto/md5_sha1.New",
        _ => return None,
    };
    let mut args = HashMap::new();
    // For md5/sha1, the classifier reads `args.pkg` to disambiguate.
    if callee == "md5.New" {
        args.insert("pkg".into(), ArgValue::Str("md5".into()));
    } else if callee == "sha1.New" {
        args.insert("pkg".into(), ArgValue::Str("sha1".into()));
    }
    Some((api.into(), args))
}

fn match_python_callee(callee: &str) -> Option<(String, HashMap<String, ArgValue>)> {
    let api = match callee {
        "rsa.generate_private_key" => "cryptography.hazmat.rsa.generate_private_key",
        "ec.generate_private_key" => "cryptography.hazmat.ec.generate_private_key",
        "hashlib.md5" => "hashlib.md5",
        "hashlib.sha1" => "hashlib.sha1",
        _ => return None,
    };
    Some((api.into(), HashMap::new()))
}

fn populate_args(
    language: Language,
    api: &str,
    args_node: Node<'_>,
    source: &[u8],
    out: &mut HashMap<String, ArgValue>,
) {
    match (language, api) {
        (Language::Go, "crypto/rsa.GenerateKey") => {
            // arguments: (rand.Reader, <int>)
            if let Some(bits) = nth_arg_int(args_node, 1, source) {
                out.insert("bits".into(), ArgValue::Int(bits));
            }
        }
        (Language::Go, "crypto/ecdsa.GenerateKey") => {
            // arguments: (elliptic.P256(), rand.Reader)
            if let Some(curve) = nth_arg_call_method(args_node, 0, source) {
                out.insert("curve_fn".into(), ArgValue::Str(curve));
            }
        }
        (Language::Python, "cryptography.hazmat.rsa.generate_private_key") => {
            // keyword arg `key_size=<int>`
            if let Some(n) = python_keyword_int(args_node, "key_size", source) {
                out.insert("key_size".into(), ArgValue::Int(n));
            }
        }
        (Language::Python, "cryptography.hazmat.ec.generate_private_key") => {
            // positional arg ec.SECP256R1()
            if let Some(curve) = python_first_arg_call_method(args_node, source) {
                out.insert("curve_name".into(), ArgValue::Str(curve));
            }
        }
        _ => {}
    }
}

fn nth_arg_int(args: Node<'_>, n: usize, source: &[u8]) -> Option<i64> {
    let mut cursor = args.walk();
    let mut idx = 0;
    for child in args.children(&mut cursor) {
        if !is_real_arg(child) {
            continue;
        }
        if idx == n {
            let text = node_text(child, source);
            return text.parse::<i64>().ok();
        }
        idx += 1;
    }
    None
}

fn nth_arg_call_method(args: Node<'_>, n: usize, source: &[u8]) -> Option<String> {
    // Returns the method name of a `pkg.Method()` call in position n.
    let mut cursor = args.walk();
    let mut idx = 0;
    for child in args.children(&mut cursor) {
        if !is_real_arg(child) {
            continue;
        }
        if idx == n {
            // child should be a `call_expression`; descend to its function selector
            let function = child.child_by_field_name("function")?;
            // function is `selector_expression`: operand.field
            let field = function.child_by_field_name("field")?;
            return Some(node_text(field, source));
        }
        idx += 1;
    }
    None
}

fn python_keyword_int(args: Node<'_>, name: &str, source: &[u8]) -> Option<i64> {
    let mut cursor = args.walk();
    for child in args.children(&mut cursor) {
        if child.kind() == "keyword_argument" {
            let kw_name = child.child_by_field_name("name")?;
            if node_text(kw_name, source) == name {
                let kw_val = child.child_by_field_name("value")?;
                return node_text(kw_val, source).parse::<i64>().ok();
            }
        }
    }
    None
}

fn python_first_arg_call_method(args: Node<'_>, source: &[u8]) -> Option<String> {
    let mut cursor = args.walk();
    for child in args.children(&mut cursor) {
        if child.kind() == "call" {
            let function = child.child_by_field_name("function")?;
            // function is an `attribute`: object.attribute
            let attribute = function.child_by_field_name("attribute")?;
            return Some(node_text(attribute, source));
        }
    }
    None
}

fn is_real_arg(node: Node<'_>) -> bool {
    // Skip punctuation/whitespace nodes inside argument_list.
    !matches!(node.kind(), "(" | ")" | "," | "comment")
}

fn node_text(node: Node<'_>, source: &[u8]) -> String {
    String::from_utf8_lossy(&source[node.start_byte()..node.end_byte()]).into_owned()
}

/// Try every classify rule's `when` against a raw match. On the first hit,
/// look up the algorithm record and build a [`Finding`].
fn apply_classify(
    raw: &RawMatch,
    rule: &ClassifyRule,
    algorithms: &AlgorithmTable,
    path: &Path,
) -> Result<Option<Finding>, ScanError> {
    // 1. API regex
    let api_re = regex::Regex::new(&rule.when.api)?;
    if !api_re.is_match(&raw.api) {
        return Ok(None);
    }

    // 2. All arg predicates must match
    for (cap_name, predicate) in &rule.when.args {
        let Some(value) = raw.args.get(cap_name) else {
            return Ok(None);
        };
        if !arg_matches(value, predicate)? {
            return Ok(None);
        }
    }

    // 3. Build the finding
    let _algo = algorithms
        .get(&rule.algorithm_id)
        .ok_or_else(|| ScanError::UnknownAlgorithm(rule.algorithm_id.clone()))?;

    let mut message = rule.message.clone();
    for (k, v) in &raw.args {
        message = message.replace(&format!("{{{}}}", k), &v.as_str());
    }

    let path_str: PathBuf = path.to_path_buf();

    Ok(Some(Finding {
        rule_id: rule.id.clone(),
        algorithm_id: rule.algorithm_id.clone(),
        location: Location {
            location: path_str.to_string_lossy().into_owned(),
            line: Some(raw.line),
            offset: Some(raw.offset),
            symbol: Some(raw.symbol.clone()),
            snippet: Some(raw.snippet.lines().next().unwrap_or("").to_string()),
        },
        message,
        confidence: Confidence::LiteralArg,
        // v0 defaults; the risk engine consumes these. Network/cert scanners
        // and per-rule overrides will refine these in subsequent passes.
        usage_context: UsageContext::Unknown,
        exposure: Exposure::InternalService,
        shelf_life_bucket: "short".into(),
        hndl_critical: false,
    }))
}

fn arg_matches(value: &ArgValue, predicate: &ArgMatch) -> Result<bool, ScanError> {
    match (value, predicate) {
        (ArgValue::Int(n), ArgMatch::ExactInt(m)) => Ok(n == m),
        (ArgValue::Str(s), ArgMatch::ExactStr(t)) => Ok(s == t),
        (ArgValue::Int(n), ArgMatch::Range(r)) => Ok(r.lt.is_none_or(|x| *n < x)
            && r.le.is_none_or(|x| *n <= x)
            && r.gt.is_none_or(|x| *n > x)
            && r.ge.is_none_or(|x| *n >= x)),
        (ArgValue::Str(s), ArgMatch::Regex(r)) => {
            let re = regex::Regex::new(&r.regex)?;
            Ok(re.is_match(s))
        }
        // Cross-type mismatches just fail-soft.
        _ => Ok(false),
    }
}

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

use cryptoscope_core::{
    AlgorithmTable, Confidence, Exposure, Finding, Location, ScanWarning, ScanWarningKind,
    UsageContext,
};
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
    /// Phase 16: syntactic site context captured by walking the AST
    /// up from the matched node. Drives `when.site_context` filtering
    /// in the classify layer.
    pub site_context: cryptoscope_core::SiteContext,
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
    /// Build a scanner using the built-in rule packs (all languages) and the
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
        rules_by_lang.insert(
            Language::Java,
            RulePack::builtin_java().expect("built-in Java rules must parse"),
        );
        // Both JS and TS share the same rule pack (grammar node shapes are identical).
        let js_pack = RulePack::builtin_javascript().expect("built-in JS rules must parse");
        rules_by_lang.insert(Language::JavaScript, js_pack.clone());
        rules_by_lang.insert(Language::TypeScript, js_pack);
        rules_by_lang.insert(
            Language::C,
            RulePack::builtin_cpp().expect("built-in C/C++ rules must parse"),
        );
        rules_by_lang.insert(
            Language::Cpp,
            RulePack::builtin_cpp().expect("built-in C/C++ rules must parse"),
        );
        rules_by_lang.insert(
            Language::Rust,
            RulePack::builtin_rust().expect("built-in Rust rules must parse"),
        );
        rules_by_lang.insert(
            Language::CSharp,
            RulePack::builtin_csharp().expect("built-in C# rules must parse"),
        );
        Ok(Self {
            rules_by_lang,
            algorithms,
        })
    }

    /// Scan a single file or recurse over a directory. Honors `.gitignore`.
    pub fn scan_path(&self, root: &Path) -> Result<Vec<Finding>, ScanError> {
        let mut warnings = Vec::new();
        self.scan_path_collecting(root, &mut warnings)
    }

    /// Like [`scan_path`] but converts per-file errors into [`ScanWarning`]s
    /// pushed onto `warnings` instead of aborting. The whole-scan return value
    /// only fails for truly catastrophic errors (root path doesn't exist, etc.).
    ///
    /// Phase 6: a single unreadable file or grammar parse failure shouldn't
    /// kill the scan over a 150-project corpus.
    pub fn scan_path_collecting(
        &self,
        root: &Path,
        warnings: &mut Vec<ScanWarning>,
    ) -> Result<Vec<Finding>, ScanError> {
        let mut findings = Vec::new();
        if root.is_file() {
            if let Err(e) = self.scan_file_into(root, &mut findings) {
                warnings.push(scan_warning_for(root, &e));
            }
            return Ok(findings);
        }
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
                        format!("walk: {e}"),
                    ));
                    continue;
                }
            };
            if entry.file_type().map(|t| t.is_file()).unwrap_or(false)
                && let Err(e) = self.scan_file_into(entry.path(), &mut findings)
            {
                warnings.push(scan_warning_for(entry.path(), &e));
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
/// Map a [`ScanError`] surfaced for a specific file into a structured warning.
fn scan_warning_for(path: &Path, err: &ScanError) -> ScanWarning {
    let kind = match err {
        ScanError::Io(_) => ScanWarningKind::UnreadableFile,
        ScanError::GrammarLoad(_) => ScanWarningKind::ParseError,
        ScanError::RegexCompile(_) => ScanWarningKind::Other,
        ScanError::Walk(_) => ScanWarningKind::WalkError,
        ScanError::UnknownAlgorithm(_) => ScanWarningKind::Other,
    };
    ScanWarning::new(kind, Some(path.to_path_buf()), err.to_string())
}

fn detect_language(path: &Path) -> Option<Language> {
    let ext = path.extension()?.to_str()?;
    match ext {
        "go" => Some(Language::Go),
        "py" => Some(Language::Python),
        "java" => Some(Language::Java),
        "js" | "mjs" | "cjs" => Some(Language::JavaScript),
        "ts" | "tsx" | "mts" => Some(Language::TypeScript),
        "c" | "h" => Some(Language::C),
        "cpp" | "cc" | "cxx" | "hpp" | "hxx" => Some(Language::Cpp),
        "rs" => Some(Language::Rust),
        "cs" => Some(Language::CSharp),
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
        Language::Java => tree_sitter_java::LANGUAGE,
        Language::JavaScript => tree_sitter_javascript::LANGUAGE,
        // TypeScript: use the `typescript` sub-grammar (not `tsx`)
        Language::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT,
        Language::C => tree_sitter_c::LANGUAGE,
        Language::Cpp => tree_sitter_cpp::LANGUAGE,
        Language::Rust => tree_sitter_rust::LANGUAGE,
        Language::CSharp => tree_sitter_c_sharp::LANGUAGE,
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
    let kind = node.kind();
    // call_expression     — Go, JS/TS, C, C++, Rust
    // call                — Python
    // method_invocation   — Java (non-static: obj.method(…))
    // invocation_expression — C#
    // object_creation_expression — Java (new ClassName()) / C# (new ClassName())
    let is_call_like = matches!(
        kind,
        "call_expression"
            | "call"
            | "method_invocation"
            | "invocation_expression"
            | "object_creation_expression"
    );
    if is_call_like && let Some(m) = match_call(node, source, language) {
        out.push(m);
    }
    // Java enum-constant references like `SignatureAlgorithm.RS256` are
    // `field_access` nodes — not calls. The jjwt / java-jwt / jose4j /
    // nimbus-jose-jwt libraries surface algorithm choice this way, so
    // detecting them is essential for any non-trivial Java JWT scan.
    // See V2 corpus run: scanning jjwt itself produced ZERO findings
    // because tree-sitter-java parses SignatureAlgorithm.RS256 as a
    // field_access, not a call_expression.
    if language == Language::Java
        && kind == "field_access"
        && let Some(m) = match_java_field_access(node, source)
    {
        out.push(m);
    }
    // Go runtime string-table dispatch: `switch alg { case "RS256": ... }`.
    // V3 corpus run: 22 of 25 Go projects produced zero findings because
    // golang-jwt, go-jose, lestrrat-go/jwx and similar libraries route
    // algorithm choice through switch-on-string, not direct API calls.
    // The whitelist is intentional — matching every switch on a string would
    // flood any Go codebase; we only fire on known JOSE/JWA algorithm names.
    if language == Language::Go
        && kind == "expression_switch_statement"
        && let Some(ms) = match_go_alg_switch(node, source)
    {
        out.extend(ms);
    }
    // Go algorithm-registration shapes: composite-literal / call-as-constructor
    // / const / var. golang-jwt-jwt registers via `&SigningMethodRSA{"RS256",
    // ...}`, go-jose via `SignatureAlgorithm("RS256")`, jwx via `const rs256
    // = "RS256"`. All three end with a JOSE alg name as a string literal in
    // a constrained syntactic position. Same whitelist as the switch path.
    if language == Language::Go
        && (kind == "interpreted_string_literal" || kind == "raw_string_literal")
        && let Some(m) = match_go_alg_string_literal(node, source)
    {
        out.push(m);
    }
    // Go `CurvePreferences: []tls.CurveID{tls.X25519, …}` — the v0.1 PQC
    // migration target. The walker hooks `keyed_element` and the matcher
    // emits one RawMatch per inner curve identifier.
    if language == Language::Go
        && kind == "keyed_element"
        && let Some(ms) = match_go_curve_preferences(node, source)
    {
        out.extend(ms);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk(child, source, language, out);
    }
}

/// Inspect one call node and decide if it's a known crypto API site.
fn match_call(call: Node<'_>, source: &[u8], language: Language) -> Option<RawMatch> {
    let kind = call.kind();

    // For object_creation_expression (Java `new Foo()` / C# `new Foo()`)
    // the relevant "callee" is the type name.
    if kind == "object_creation_expression" {
        return match_object_creation(call, source, language);
    }

    // For method_invocation (Java): object.method(args)
    // Node fields: object, name, arguments
    if kind == "method_invocation" {
        return match_java_method_invocation(call, source);
    }

    // For invocation_expression (C#): function(arguments)
    if kind == "invocation_expression" {
        let function = call.child_by_field_name("function")?;
        let args = call.child_by_field_name("arguments")?;
        let callee_text = node_text(function, source);
        let (api, mut args_map) = match_csharp_callee(&callee_text)?;
        populate_args(language, &api, args, source, &mut args_map);
        let start = call.start_position();
        return Some(RawMatch {
            api,
            args: args_map,
            line: (start.row + 1) as u32,
            offset: call.start_byte() as u32,
            symbol: callee_text,
            snippet: node_text(call, source),
            site_context: cryptoscope_core::SiteContext::Call,
        });
    }

    // Standard call_expression / call (Go, Python, JS, TS, C, C++, Rust)
    let function = call.child_by_field_name("function")?;
    let args = call.child_by_field_name("arguments")?;
    let callee_text = node_text(function, source);

    let (api, mut args_map) = match language {
        Language::Go => match_go_callee(&callee_text)?,
        Language::Python => match_python_callee(&callee_text)?,
        Language::JavaScript | Language::TypeScript => match_js_callee(&callee_text)?,
        Language::C | Language::Cpp => match_c_callee(&callee_text)?,
        Language::Rust => match_rust_callee(&callee_text)?,
        Language::Java | Language::CSharp => return None, // handled above
    };

    populate_args(language, &api, args, source, &mut args_map);

    let start = call.start_position();
    Some(RawMatch {
        api,
        args: args_map,
        line: (start.row + 1) as u32,
        offset: call.start_byte() as u32,
        symbol: callee_text,
        snippet: node_text(call, source),
        site_context: cryptoscope_core::SiteContext::Call,
    })
}

/// Handle Java `SomeClass.method(args)` invocations.
fn match_java_method_invocation(call: Node<'_>, source: &[u8]) -> Option<RawMatch> {
    // tree-sitter-java method_invocation fields:
    //   object: the receiver expression
    //   name:   the method identifier
    //   arguments: argument_list
    let object = call.child_by_field_name("object")?;
    let name = call.child_by_field_name("name")?;
    let args = call.child_by_field_name("arguments")?;

    let obj_text = node_text(object, source);
    let method_text = node_text(name, source);
    let callee_text = format!("{}.{}", obj_text, method_text);

    let (api, mut args_map) = match_java_callee(&callee_text)?;
    populate_java_args(&api, args, source, &mut args_map);

    let start = call.start_position();
    Some(RawMatch {
        api,
        args: args_map,
        line: (start.row + 1) as u32,
        offset: call.start_byte() as u32,
        symbol: callee_text,
        snippet: node_text(call, source),
        site_context: cryptoscope_core::SiteContext::Call,
    })
}

/// Handle `new ClassName()` — Java and C#.
fn match_object_creation(call: Node<'_>, source: &[u8], language: Language) -> Option<RawMatch> {
    // Java: object_creation_expression has a `type` field (type_identifier)
    // C#:  object_creation_expression has a `type` field (identifier)
    let type_node = call.child_by_field_name("type")?;
    let type_text = node_text(type_node, source);

    let (api, args_map) = match language {
        Language::Java => match_java_ctor(&type_text)?,
        Language::CSharp => match_csharp_ctor(&type_text)?,
        _ => return None,
    };

    let start = call.start_position();
    Some(RawMatch {
        api,
        args: args_map,
        line: (start.row + 1) as u32,
        offset: call.start_byte() as u32,
        symbol: type_text,
        snippet: node_text(call, source),
        site_context: cryptoscope_core::SiteContext::Call,
    })
}

fn match_go_callee(callee: &str) -> Option<(String, HashMap<String, ArgValue>)> {
    // crypto/ecdh.<Curve>() calls: ecdh.X25519, ecdh.P256, ecdh.P384, ecdh.P521.
    // The classify layer maps `args.curve_fn` to ecdh-pNNN / x25519 algorithm-ids.
    if let Some(curve_fn) = callee.strip_prefix("ecdh.")
        && matches!(curve_fn, "X25519" | "P256" | "P384" | "P521")
    {
        let mut args = HashMap::new();
        args.insert("curve_fn".into(), ArgValue::Str(curve_fn.into()));
        return Some(("crypto/ecdh.Curve".into(), args));
    }

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

fn match_java_callee(callee: &str) -> Option<(String, HashMap<String, ArgValue>)> {
    // Java method invocations: "ClassName.methodName"
    let api = match callee {
        "Cipher.getInstance" => "javax.crypto.Cipher.getInstance",
        "KeyPairGenerator.getInstance" => "java.security.KeyPairGenerator.getInstance",
        "MessageDigest.getInstance" => "java.security.MessageDigest.getInstance",
        _ => return None,
    };
    Some((api.into(), HashMap::new()))
}

/// Handle Java enum-constant references like `SignatureAlgorithm.RS256`.
///
/// These are `field_access` nodes — NOT calls. The jjwt, java-jwt, jose4j
/// and nimbus-jose-jwt libraries are the canonical Java JWT stacks and they
/// all surface algorithm choice this way (e.g. `Jwts.builder().signWith(key,
/// SignatureAlgorithm.RS256)`). Without this matcher, the scanner produces
/// silent zero findings on every codebase using these libraries.
///
/// The detection is narrow on purpose: we only fire on known crypto-enum
/// classes. A general "any field_access" pattern would flood the output
/// with false positives. Adding a new library = adding its enum class to
/// `KNOWN_CRYPTO_ENUM_CLASSES` and a classify rule in `java.toml`.
fn match_java_field_access(node: Node<'_>, source: &[u8]) -> Option<RawMatch> {
    // tree-sitter-java field_access has children: object, field
    // For `SignatureAlgorithm.RS256` → object="SignatureAlgorithm", field="RS256"
    let object = node.child_by_field_name("object")?;
    let field = node.child_by_field_name("field")?;

    let class_name = node_text(object, source);
    let member_name = node_text(field, source);

    // The object must be a simple identifier matching a known crypto-enum class.
    // We don't try to handle qualified imports here (e.g. `io.jsonwebtoken.SignatureAlgorithm.RS256`
    // would appear as a nested field_access whose innermost object is `SignatureAlgorithm`;
    // tree-sitter walks that recursively so we'll still see the right node).
    if object.kind() != "identifier" {
        return None;
    }

    let api = match class_name.as_str() {
        // jjwt
        "SignatureAlgorithm" => "io.jsonwebtoken.SignatureAlgorithm",
        // auth0 java-jwt
        "Algorithm" => "com.auth0.jwt.Algorithm",
        // nimbus-jose-jwt
        "JWSAlgorithm" => "com.nimbusds.jose.JWSAlgorithm",
        "JWEAlgorithm" => "com.nimbusds.jose.JWEAlgorithm",
        "EncryptionMethod" => "com.nimbusds.jose.EncryptionMethod",
        // jose4j
        "AlgorithmIdentifiers" => "org.jose4j.jws.AlgorithmIdentifiers",
        // Apache Shiro
        "DefaultPasswordService" => return None, // not an enum
        _ => return None,
    };

    let mut args = HashMap::new();
    args.insert("member".into(), ArgValue::Str(member_name));

    let start = node.start_position();
    Some(RawMatch {
        api: api.into(),
        args,
        line: (start.row + 1) as u32,
        offset: node.start_byte() as u32,
        symbol: node_text(node, source),
        snippet: node_text(node, source),
        // A Java field_access is itself a value reference, not a call;
        // classify based on the surrounding context.
        site_context: classify_site_context(node, source, Language::Java),
    })
}

/// Match Go `switch alg { case "RS256": ... }` patterns emitted by JWT/JOSE libraries.
///
/// Returns one [`RawMatch`] per `case` clause whose value is a recognized JOSE
/// algorithm string. Walks the `expression_case` children of the switch, extracts
/// the string literal from the `value` → `expression_list` → first child, and
/// filters against `GO_ALG_SWITCH_WHITELIST`. Returns `None` when the switch
/// contains no recognized literals — i.e. this function never produces noise on
/// unrelated switches.
fn match_go_alg_switch(switch: Node<'_>, source: &[u8]) -> Option<Vec<RawMatch>> {
    let mut results = Vec::new();
    let mut cursor = switch.walk();
    for child in switch.children(&mut cursor) {
        if child.kind() != "expression_case" {
            continue;
        }
        // expression_case field: value → expression_list → first element
        let value_list = child.child_by_field_name("value")?;
        let Some(expr) = value_list.named_child(0) else {
            continue;
        };
        // Go string literals: "interpreted_string_literal" (double-quoted)
        // or "raw_string_literal" (backtick). We only expect double-quoted
        // here for JWT alg values, but handle both for completeness.
        let kind = expr.kind();
        if kind != "interpreted_string_literal" && kind != "raw_string_literal" {
            continue;
        }
        let raw = node_text(expr, source);
        let value = raw.trim_matches(|c| c == '"' || c == '`');
        if !GO_ALG_SWITCH_WHITELIST.contains(&value) {
            continue;
        }
        let api = format!("go.alg-switch.{}", value);
        let mut args = HashMap::new();
        args.insert("member".into(), ArgValue::Str(value.to_string()));
        let start = child.start_position();
        results.push(RawMatch {
            api,
            args,
            line: (start.row + 1) as u32,
            offset: child.start_byte() as u32,
            symbol: value.to_string(),
            snippet: node_text(child, source)
                .lines()
                .next()
                .unwrap_or("")
                .to_string(),
            site_context: cryptoscope_core::SiteContext::Call,
        });
    }
    if results.is_empty() {
        None
    } else {
        Some(results)
    }
}

/// Match Go `CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256, ...}`.
///
/// The AST is `keyed_element(literal_element identifier, literal_element
/// composite_literal(slice_type qualified_type{tls,CurveID}, literal_value{
/// literal_element selector_expression{tls,<Curve>}}))`. This function
/// pulls one RawMatch per inner selector_expression so the classify layer
/// can route each curve to its own `algorithm_id`.
///
/// Returns None when the keyed_element does not name `CurvePreferences` OR
/// when the slice's element type is not `tls.CurveID` — avoids false
/// positives on unrelated `Curve*` field names.
fn match_go_curve_preferences(keyed: Node<'_>, source: &[u8]) -> Option<Vec<RawMatch>> {
    // Children layout for `CurvePreferences: []tls.CurveID{...}` is:
    //   keyed_element
    //     literal_element  (key: identifier "CurvePreferences")
    //     literal_element  (value: composite_literal {slice_type, literal_value})
    let key_le = keyed.named_child(0)?;
    let value_le = keyed.named_child(1)?;

    let key_inner = key_le.named_child(0)?;
    if key_inner.kind() != "identifier" {
        return None;
    }
    if node_text(key_inner, source) != "CurvePreferences" {
        return None;
    }

    let composite = value_le.named_child(0)?;
    if composite.kind() != "composite_literal" {
        return None;
    }

    // Slice-type guard: must be []tls.CurveID, not []SomethingElse.
    let slice_type = composite.child_by_field_name("type")?;
    if slice_type.kind() != "slice_type" {
        return None;
    }
    let element_type = slice_type.named_child(0)?;
    if element_type.kind() != "qualified_type" {
        return None;
    }
    let pkg = element_type.child_by_field_name("package")?;
    let name = element_type.child_by_field_name("name")?;
    if node_text(pkg, source) != "tls" || node_text(name, source) != "CurveID" {
        return None;
    }

    // Iterate the literal_value's elements, each of which is a literal_element
    // wrapping a selector_expression tls.<Curve>.
    let body = composite.child_by_field_name("body")?;
    if body.kind() != "literal_value" {
        return None;
    }

    let mut results = Vec::new();
    let mut cursor = body.walk();
    for element in body.children(&mut cursor) {
        if element.kind() != "literal_element" {
            continue;
        }
        let Some(sel) = element.named_child(0) else {
            continue;
        };
        if sel.kind() != "selector_expression" {
            continue;
        }
        let operand = sel.child_by_field_name("operand")?;
        let field = sel.child_by_field_name("field")?;
        if operand.kind() != "identifier" || node_text(operand, source) != "tls" {
            continue;
        }
        let curve = node_text(field, source);
        let mut args = HashMap::new();
        args.insert("curve".into(), ArgValue::Str(curve.clone()));
        let start = element.start_position();
        results.push(RawMatch {
            api: "crypto/tls.Config.CurvePreferences".into(),
            args,
            line: (start.row + 1) as u32,
            offset: element.start_byte() as u32,
            symbol: format!("tls.{}", curve),
            snippet: node_text(element, source),
            site_context: cryptoscope_core::SiteContext::Call,
        });
    }

    if results.is_empty() {
        None
    } else {
        Some(results)
    }
}

/// Detect a Go JOSE algorithm string literal in an algorithm-registration
/// position. The literal's value must match [`GO_ALG_SWITCH_WHITELIST`]; its
/// syntactic context must be one of:
///
/// * `composite_literal` — golang-jwt-jwt: `&SigningMethodRSA{"RS256", ...}`
/// * `argument_list` — go-jose: `SignatureAlgorithm("RS256")`, jwx:
///   `NewSignatureAlgorithm("RS256")`
/// * `const_spec` / `var_spec`
/// * `expression_list` (assignment RHS, including `=` and `:=`)
///
/// The context guard avoids matching every doc-comment / log-message string
/// that happens to contain a JOSE name. Together with the whitelist, the
/// false-positive rate stays low while we light up the registration paths
/// the V3 benchmark missed.
fn match_go_alg_string_literal(literal: Node<'_>, source: &[u8]) -> Option<RawMatch> {
    let raw = node_text(literal, source);
    let value = raw.trim_matches(|c| c == '"' || c == '`');
    if !GO_ALG_SWITCH_WHITELIST.contains(&value) {
        return None;
    }
    // Reject if we're inside an expression_case — the switch detector
    // already owns that path; emitting twice would double-count.
    let mut walker = literal.parent();
    while let Some(p) = walker {
        match p.kind() {
            "expression_case" | "type_case" | "default_case" => return None,
            // Stop climbing at statement / declaration boundaries; we've
            // either matched an allowed context by now, or we won't.
            "source_file" => break,
            _ => {}
        }
        walker = p.parent();
    }
    // Now check the immediate context. We accept the literal in any of:
    //   * literal_element     (composite_literal positional element, e.g.
    //                          golang-jwt's &SigningMethodRSA{"RS256", ...})
    //   * literal_value       (composite_literal child without literal_element)
    //   * argument_list       (positional arg of a call expression,
    //                          e.g. go-jose's SignatureAlgorithm("RS256"))
    //   * const_spec / var_spec      (declaration RHS)
    //   * expression_list     (assignment RHS, := or =; also wraps the
    //                          var_spec / const_spec value)
    //   * keyed_element / element    (composite literal field-name : value)
    let parent = literal.parent()?;
    let ok = matches!(
        parent.kind(),
        "literal_element"
            | "literal_value"
            | "argument_list"
            | "const_spec"
            | "var_spec"
            | "expression_list"
            | "keyed_element"
            | "element"
    );
    if !ok {
        return None;
    }
    let api = format!("go.alg-register.{}", value);
    let mut args = HashMap::new();
    args.insert("member".into(), ArgValue::Str(value.to_string()));
    let start = literal.start_position();
    Some(RawMatch {
        api,
        args,
        line: (start.row + 1) as u32,
        offset: literal.start_byte() as u32,
        symbol: value.to_string(),
        snippet: node_text(literal, source),
        // Phase 16: capture the real syntactic context. The classify layer
        // can then opt out of MapEntry / TestAssertion via when.site_context.
        site_context: classify_site_context(literal, source, Language::Go),
    })
}

/// JOSE/JWA algorithm names that trigger `go.alg-switch.*` rules.
///
/// Narrow whitelist by design: matching every switch on a string literal would
/// flood any Go codebase (config keys, HTTP method strings, etc.). Adding a new
/// library's algorithm = add its string here + a classify rule in go.toml.
const GO_ALG_SWITCH_WHITELIST: &[&str] = &[
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES384",
    "ES512",
    "EdDSA",
    "HS256",
    "HS384",
    "HS512",
    "none",
    "RSA-OAEP",
    "RSA-OAEP-256",
    "A256GCM",
    "A192GCM",
    "A128GCM",
];

fn match_java_ctor(class_name: &str) -> Option<(String, HashMap<String, ArgValue>)> {
    // BouncyCastle constructor detection
    let api = match class_name {
        "RSAKeyPairGenerator" => "org.bouncycastle.RSAKeyPairGenerator",
        "AESEngine" => "org.bouncycastle.AESEngine",
        "GCMBlockCipher" => "org.bouncycastle.GCMBlockCipher",
        "BouncyCastleProvider" => "org.bouncycastle.BouncyCastleProvider",
        _ => return None,
    };
    Some((api.into(), HashMap::new()))
}

fn match_js_callee(callee: &str) -> Option<(String, HashMap<String, ArgValue>)> {
    // JS/TS member expression callees. tree-sitter renders nested member
    // expressions as their full source text, so two-level chains like
    // `CryptoJS.AES.encrypt` come through as a single &str here.
    let api = match callee {
        "crypto.createCipheriv" => "node:crypto.createCipheriv",
        "crypto.createHash" => "node:crypto.createHash",
        "crypto.generateKeyPair" | "crypto.generateKeyPairSync" => "node:crypto.generateKeyPair",
        "crypto.createSign" => "node:crypto.createSign",
        "subtle.generateKey" => "webcrypto.subtle.generateKey",
        "subtle.sign" => "webcrypto.subtle.sign",
        "jwt.sign" => "jsonwebtoken.jwt.sign",
        // crypto-js namespace. Two-level member expressions
        // (CryptoJS.<Algo>.<method>) plus single-level helpers
        // (CryptoJS.MD5(msg)). Every algorithm covered here is on the
        // "broken classically" tier — DES, 3DES, RC4, MD5, SHA-1 — so
        // they map to existing rules without needing new algorithm-ids.
        "CryptoJS.AES.encrypt" | "CryptoJS.AES.decrypt" => "crypto-js.AES.encrypt",
        "CryptoJS.DES.encrypt" | "CryptoJS.DES.decrypt" => "crypto-js.DES.encrypt",
        "CryptoJS.TripleDES.encrypt" | "CryptoJS.TripleDES.decrypt" => {
            "crypto-js.TripleDES.encrypt"
        }
        "CryptoJS.RC4.encrypt" | "CryptoJS.RC4.decrypt" => "crypto-js.RC4.encrypt",
        "CryptoJS.MD5" => "crypto-js.MD5",
        "CryptoJS.SHA1" => "crypto-js.SHA1",
        "CryptoJS.HmacMD5" => "crypto-js.HmacMD5",
        "CryptoJS.HmacSHA1" => "crypto-js.HmacSHA1",
        _ => return None,
    };
    Some((api.into(), HashMap::new()))
}

fn match_c_callee(callee: &str) -> Option<(String, HashMap<String, ArgValue>)> {
    // C/C++ simple function identifiers
    let api = match callee {
        "RSA_generate_key_ex" => "openssl.RSA_generate_key_ex",
        "EVP_EncryptInit_ex" => "openssl.EVP_EncryptInit_ex",
        "EVP_DigestInit_ex" => "openssl.EVP_DigestInit_ex",
        "SSL_CTX_set_cipher_list" => "openssl.SSL_CTX_set_cipher_list",
        "crypto_box_keypair" => "libsodium.crypto_box_keypair",
        "crypto_sign_keypair" => "libsodium.crypto_sign_keypair",
        "mbedtls_rsa_init" => "mbedtls.mbedtls_rsa_init",
        "mbedtls_pk_setup" => "mbedtls.mbedtls_pk_setup",
        _ => return None,
    };
    Some((api.into(), HashMap::new()))
}

fn match_rust_callee(callee: &str) -> Option<(String, HashMap<String, ArgValue>)> {
    // Rust scoped paths — tree-sitter renders them verbatim. The raw callee
    // text can carry module prefixes (`sha2::Sha256::digest`) and turbofish
    // generics (`SigningKey::<Sha256>::new`). We strip both before matching
    // against the exact-match table below. The bare table is the single
    // source of truth for which Type::method shapes we recognise.
    let normalized = normalize_rust_callee(callee);

    // Helper closure so we can try matching the 2-segment normalized form
    // first, then fall back to just the last segment alone. This handles
    // free functions like `pbkdf2_hmac` (often called as either
    // `pbkdf2_hmac` or `pbkdf2::pbkdf2_hmac`).
    let resolve = |s: &str| -> Option<&'static str> {
        Some(match s {
            "EcdsaKeyPair::generate_pkcs8" => "ring.EcdsaKeyPair.generate_pkcs8",
            "Ed25519KeyPair::generate_pkcs8" => "ring.Ed25519KeyPair.generate_pkcs8",
            "Aes256Gcm::new" => "rustcrypto.Aes256Gcm.new",
            "Aes128Gcm::new" => "rustcrypto.Aes128Gcm.new",
            "Sha256::new" | "Sha256::digest" => "rustcrypto.Sha256.digest",
            "Sha384::new" | "Sha384::digest" => "rustcrypto.Sha384.digest",
            "Sha512::new" | "Sha512::digest" => "rustcrypto.Sha512.digest",
            "ChaCha20Poly1305::new" => "rustcrypto.ChaCha20Poly1305.new",
            "RsaPrivateKey::new" => "rsa.RsaPrivateKey.new",
            "SigningKey::generate" => "ed25519_dalek.SigningKey.generate",
            // RSA pkcs1v15 / pss SigningKey — turbofish stripped by normalize_*.
            // The hash algorithm is encoded in the turbofish (e.g. `<Sha256>`)
            // and is captured separately as the `turbofish` arg below.
            "SigningKey::new" => "rsa.SigningKey.new",
            "ClientConfig::builder" => "rustls.ClientConfig.builder",
            "ServerConfig::builder" => "rustls.ServerConfig.builder",
            // rcgen — used by rustls-webpki / webpki test utilities. Defaults
            // to ECDSA P-256 SHA-256 when called with PKCS_ECDSA_P256_SHA256.
            "KeyPair::generate_for" => "rcgen.KeyPair.generate_for",
            // pbkdf2 crate — Phase 11. Two API shapes:
            //   pbkdf2::<Hmac<sha2::Sha256>>(...)   — older generic-fn API
            //   pbkdf2_hmac::<sha2::Sha256>(...)    — newer free-function API
            // The hash algorithm is in the turbofish either way; classify
            // rules dispatch on the `turbofish` capture.
            "pbkdf2" => "pbkdf2.pbkdf2",
            "pbkdf2_hmac" | "pbkdf2_hmac_array" => "pbkdf2.pbkdf2_hmac",
            _ => return None,
        })
    };

    let api = resolve(&normalized).or_else(|| {
        // Fall back: try just the trailing segment alone. Catches free
        // functions like `pbkdf2_hmac` when called as
        // `pbkdf2::pbkdf2_hmac::<Sha256>`.
        normalized.rsplit("::").next().and_then(resolve)
    })?;
    let mut args = HashMap::new();
    // If the original callee text had a turbofish, expose the inside as a
    // capture so classify rules can dispatch on the hash algorithm.
    if let Some(turbo) = extract_turbofish_inner(callee) {
        args.insert("turbofish".into(), ArgValue::Str(turbo));
    }
    Some((api.into(), args))
}

/// Strip Rust callee text down to the bare `Type::method` form by removing
/// (a) leading module path segments and (b) turbofish generic parameters.
///
/// Examples:
///   `sha2::Sha384::digest`            → `Sha384::digest`
///   `rustls::ClientConfig::builder`   → `ClientConfig::builder`
///   `SigningKey::<Sha256>::new`       → `SigningKey::new`
///   `ring::signature::RsaKeyPair::from_pkcs8` → `RsaKeyPair::from_pkcs8`
///
/// The heuristic: collapse to the last two `::`-separated segments after
/// stripping turbofish. That captures `Type::method` for every Rust shape
/// we currently match and matches the form of the existing match-table
/// entries.
fn normalize_rust_callee(callee: &str) -> String {
    // Drop everything inside <...> turbofish groups. Nesting depth matters
    // for cases like `<Hmac<Sha256>>`.
    let mut stripped = String::with_capacity(callee.len());
    let mut depth: i32 = 0;
    for ch in callee.chars() {
        match ch {
            '<' => depth += 1,
            '>' if depth > 0 => depth -= 1,
            _ if depth == 0 => stripped.push(ch),
            _ => {}
        }
    }
    // Collapse any `::::` left over from `Foo::<...>::method` → `Foo::method`.
    while stripped.contains("::::") {
        stripped = stripped.replace("::::", "::");
    }
    // Keep only the last two `::`-separated segments.
    let segments: Vec<&str> = stripped.split("::").filter(|s| !s.is_empty()).collect();
    match segments.len() {
        0 => stripped,
        1 => segments[0].to_string(),
        _ => format!(
            "{}::{}",
            segments[segments.len() - 2],
            segments[segments.len() - 1]
        ),
    }
}

/// Pull the contents of the first `<...>` turbofish group out of a Rust
/// callee text. Returns the inner text trimmed of whitespace. Used to
/// expose the hash algorithm in `SigningKey::<Sha256>::new` to the
/// classify layer.
fn extract_turbofish_inner(callee: &str) -> Option<String> {
    let lt = callee.find('<')?;
    // Match the outermost angle pair from `lt`.
    let bytes = callee.as_bytes();
    let mut depth: i32 = 0;
    let mut end = None;
    for (i, &b) in bytes.iter().enumerate().skip(lt) {
        match b {
            b'<' => depth += 1,
            b'>' => {
                depth -= 1;
                if depth == 0 {
                    end = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }
    let end = end?;
    let inner = callee[lt + 1..end].trim();
    if inner.is_empty() {
        None
    } else {
        Some(inner.to_string())
    }
}

fn match_csharp_callee(callee: &str) -> Option<(String, HashMap<String, ArgValue>)> {
    // C# member_access_expression text: "TypeName.MethodName"
    let api = match callee {
        "RSA.Create" => "System.Security.Cryptography.RSA.Create",
        "ECDsa.Create" | "ECDiffieHellman.Create" => "System.Security.Cryptography.ECDsa.Create",
        "Aes.Create" => "System.Security.Cryptography.Aes.Create",
        "TripleDES.Create" | "DES.Create" => "System.Security.Cryptography.TripleDES.Create",
        "SHA1.Create" => "System.Security.Cryptography.SHA1.Create",
        "SHA256.Create" => "System.Security.Cryptography.SHA256.Create",
        "SHA512.Create" => "System.Security.Cryptography.SHA512.Create",
        "MD5.Create" => "System.Security.Cryptography.MD5.Create",
        "RandomNumberGenerator.Create"
        | "RandomNumberGenerator.GetBytes"
        | "RandomNumberGenerator.Fill" => {
            "System.Security.Cryptography.RandomNumberGenerator.Create"
        }
        _ => return None,
    };
    Some((api.into(), HashMap::new()))
}

fn match_csharp_ctor(class_name: &str) -> Option<(String, HashMap<String, ArgValue>)> {
    let api = match class_name {
        "RijndaelManaged" => "System.Security.Cryptography.RijndaelManaged.new",
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
            // keyword arg `key_size=<int>`; paramiko passes a variable here.
            if let Some(n) = python_keyword_int(args_node, "key_size", source) {
                out.insert("key_size".into(), ArgValue::Int(n));
            } else if let Some(name) = python_keyword_identifier(args_node, "key_size", source) {
                out.insert("key_size_symbol".into(), ArgValue::Str(name));
            }
        }
        (Language::Python, "cryptography.hazmat.ec.generate_private_key") => {
            // positional arg ec.SECP256R1(); paramiko passes a bare identifier.
            if let Some(curve) = python_first_arg_call_method(args_node, source) {
                out.insert("curve_name".into(), ArgValue::Str(curve));
            } else if let Some(curve) = python_first_arg_identifier(args_node, source) {
                out.insert("curve_symbol".into(), ArgValue::Str(curve));
            }
        }
        (Language::C | Language::Cpp, "openssl.RSA_generate_key_ex") => {
            // RSA_generate_key_ex(rsa, bits, e, cb) — bits is arg 1 (0-indexed)
            if let Some(bits) = nth_arg_int(args_node, 1, source) {
                out.insert("bits".into(), ArgValue::Int(bits));
            }
        }
        (Language::C | Language::Cpp, "openssl.EVP_EncryptInit_ex") => {
            // EVP_EncryptInit_ex(ctx, cipher_fn(), impl, key, iv) — arg 1 is a call
            if let Some(cipher) = nth_arg_call_ident(args_node, 1, source) {
                out.insert("cipher_fn".into(), ArgValue::Str(cipher));
            }
        }
        (Language::C | Language::Cpp, "openssl.EVP_DigestInit_ex") => {
            // EVP_DigestInit_ex(ctx, digest_fn(), impl) — arg 1 is a call
            if let Some(digest) = nth_arg_call_ident(args_node, 1, source) {
                out.insert("digest_fn".into(), ArgValue::Str(digest));
            }
        }
        (Language::C | Language::Cpp, "openssl.SSL_CTX_set_cipher_list") => {
            // SSL_CTX_set_cipher_list(ctx, cipher_str) — arg 1 is a string
            if let Some(s) = nth_arg_string(args_node, 1, source) {
                out.insert("cipher_str".into(), ArgValue::Str(s));
            }
        }
        (Language::Rust, "rsa.RsaPrivateKey.new") => {
            // RsaPrivateKey::new(rng, bits) — bits is arg 1
            if let Some(bits) = nth_arg_int(args_node, 1, source) {
                out.insert("bits".into(), ArgValue::Int(bits));
            }
        }
        (
            Language::JavaScript | Language::TypeScript,
            "node:crypto.createCipheriv"
            | "node:crypto.createHash"
            | "node:crypto.generateKeyPair"
            | "node:crypto.createSign",
        ) => {
            // First positional arg is the algorithm/type string, e.g. "des-cbc", "md5", "rsa"
            if let Some(s) = nth_arg_string(args_node, 0, source) {
                out.insert("algo".into(), ArgValue::Str(s));
            }
        }
        _ => {}
    }
}

/// Java-specific argument extraction for method invocations.
/// Called separately because java uses a different arg-list field structure.
fn populate_java_args(
    api: &str,
    args_node: Node<'_>,
    source: &[u8],
    out: &mut HashMap<String, ArgValue>,
) {
    match api {
        "javax.crypto.Cipher.getInstance"
        | "java.security.KeyPairGenerator.getInstance"
        | "java.security.MessageDigest.getInstance" => {
            // First arg is a string literal like "AES/GCM/NoPadding"
            let key = match api {
                "javax.crypto.Cipher.getInstance" => "spec",
                _ => "algo",
            };
            if let Some(s) = nth_arg_string(args_node, 0, source) {
                out.insert(key.into(), ArgValue::Str(s));
            }
        }
        _ => {}
    }
}

/// Extract the identifier name of a no-arg call at position n.
/// Handles C patterns like `EVP_aes_256_gcm()` where the argument is a
/// call_expression whose function is a plain identifier.
fn nth_arg_call_ident(args: Node<'_>, n: usize, source: &[u8]) -> Option<String> {
    let mut cursor = args.walk();
    let mut idx = 0;
    for child in args.children(&mut cursor) {
        if !is_real_arg(child) {
            continue;
        }
        if idx == n {
            // The arg should be a call_expression or call with a simple identifier function.
            if child.kind() == "call_expression" {
                let function = child.child_by_field_name("function")?;
                return Some(node_text(function, source));
            }
            // Might just be an identifier (function pointer variable, etc.)
            if child.kind() == "identifier" {
                return Some(node_text(child, source));
            }
            return None;
        }
        idx += 1;
    }
    None
}

/// Extract a string literal value (without surrounding quotes) at position n.
fn nth_arg_string(args: Node<'_>, n: usize, source: &[u8]) -> Option<String> {
    let mut cursor = args.walk();
    let mut idx = 0;
    for child in args.children(&mut cursor) {
        if !is_real_arg(child) {
            continue;
        }
        if idx == n {
            let raw = node_text(child, source);
            // Strip surrounding quotes (single, double, or Java-style)
            let trimmed = raw.trim_matches(|c| c == '"' || c == '\'' || c == '`');
            return Some(trimmed.to_string());
        }
        idx += 1;
    }
    None
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

/// Look up a keyword argument by name and, when its value isn't an integer
/// literal, return the identifier's text instead. Used to capture cases like
/// `rsa.generate_private_key(..., key_size=bits)` where the size is a runtime
/// variable — paramiko hits this exact shape (rsakey.py:184).
fn python_keyword_identifier(args: Node<'_>, name: &str, source: &[u8]) -> Option<String> {
    let mut cursor = args.walk();
    for child in args.children(&mut cursor) {
        if child.kind() == "keyword_argument" {
            let kw_name = child.child_by_field_name("name")?;
            if node_text(kw_name, source) == name {
                let kw_val = child.child_by_field_name("value")?;
                if kw_val.kind() == "identifier" {
                    return Some(node_text(kw_val, source));
                }
                return None;
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

/// Like [`python_first_arg_call_method`] but returns the identifier text when
/// the first positional argument is a bare identifier instead of a call.
/// paramiko's ecdsakey.py:268 passes `curve` as a variable rather than a call
/// like `ec.SECP256R1()`.
fn python_first_arg_identifier(args: Node<'_>, source: &[u8]) -> Option<String> {
    let mut cursor = args.walk();
    for child in args.children(&mut cursor) {
        if !is_real_arg(child) {
            continue;
        }
        if child.kind() == "identifier" {
            return Some(node_text(child, source));
        }
        // Stop at the first real argument; we only care about position 0.
        return None;
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

/// Phase 16: walk up from a matched node and classify its syntactic site
/// context. The classification is conservative — when a match could fit
/// multiple buckets (e.g. a string in a struct literal positional element
/// inside an argument list), the most specific bucket wins.
///
/// Strategy:
/// - Walk parents up to a fixed depth (max 6 frames; deeper than that and
///   the relationship is too distant to be meaningful for classification).
/// - First match wins in priority order:
///   MapEntry > TestAssertion > StructLiteral > Call > StringConstant > Default
/// - Test detection is name-based on the call target (require.Equal,
///   assert.Equal, etc.) — language-specific lists.
pub(crate) fn classify_site_context(
    node: Node<'_>,
    source: &[u8],
    language: Language,
) -> cryptoscope_core::SiteContext {
    use cryptoscope_core::SiteContext;

    // Walk parents up to depth 6 collecting the chain. Then classify by
    // priority — more-specific patterns win over less-specific ones, even
    // if they appear deeper in the chain.
    let mut chain: Vec<Node<'_>> = Vec::new();
    let mut walker = node.parent();
    let mut frames = 0;
    while let Some(p) = walker {
        chain.push(p);
        frames += 1;
        if frames >= 6 {
            break;
        }
        // Stop at function body / source root.
        if matches!(
            p.kind(),
            "source_file"
                | "program"
                | "compilation_unit"
                | "function_declaration"
                | "method_declaration"
                | "function_definition"
        ) {
            break;
        }
        walker = p.parent();
    }

    // Priority 1: MapEntry. Most non-operational — allowlist maps, protobuf
    // enum tables, JS/TS object literals. Wins over StructLiteral because
    // a `keyed_element` IS technically a kind of composite literal field
    // but the map-key semantics dominate.
    if chain.iter().any(|p| {
        matches!(
            p.kind(),
            "keyed_element" | "key_value_expression" | "pair" | "dictionary"
        )
    }) {
        return SiteContext::MapEntry;
    }

    // Priority 2: TestAssertion. Walk up looking for argument_list whose
    // call_expression's callee is a known test helper.
    for p in &chain {
        let kind = p.kind();
        if matches!(kind, "argument_list" | "arguments")
            && let Some(call) = p.parent()
            && let Some(callee) = call.child_by_field_name("function")
        {
            let callee_text = node_text(callee, source);
            if is_test_assertion_callee(&callee_text, language) {
                return SiteContext::TestAssertion;
            }
        }
    }

    // Priority 3: StructLiteral, but ONLY when the composite_literal's type
    // is a struct (or a struct pointer), not a slice/array/map type. A Go
    // `[]string{"RS256", ...}` array is non-operational despite having a
    // `literal_element` parent — treat it as Default so default-allow
    // policies still suppress unless the rule explicitly opts in.
    for (i, p) in chain.iter().enumerate() {
        if matches!(
            p.kind(),
            "literal_element" | "literal_value" | "struct_initializer"
        ) {
            // Find the surrounding composite_literal (if any) and inspect
            // its type. If the type is an array / slice / map type, this
            // is NOT a struct literal — fall through to default. tree-sitter-go
            // exposes the type as the first NAMED child (no `type` field
            // name available; use the indexed child instead).
            if let Some(composite) = chain
                .get(i..)
                .and_then(|tail| tail.iter().find(|q| q.kind() == "composite_literal"))
                && let Some(type_node) = composite.named_child(0)
            {
                let tk = type_node.kind();
                if matches!(tk, "slice_type" | "array_type" | "map_type") {
                    continue;
                }
            }
            return SiteContext::StructLiteral;
        }
    }

    // Priority 4: Call. Any argument_list we didn't classify as
    // TestAssertion is a regular call site — UNLESS the literal sits inside
    // a slice / array / map composite literal that's then PASSED to a call
    // (e.g. `WithValidMethods([]string{"HS256"})`). The collection-literal
    // semantics dominate: the string is data, not an operational arg.
    if chain
        .iter()
        .any(|p| matches!(p.kind(), "argument_list" | "arguments"))
    {
        // Check whether a non-struct composite_literal sits BETWEEN the
        // matched node and the argument_list.
        let mut nonstruct_collection_present = false;
        for p in &chain {
            if matches!(p.kind(), "argument_list" | "arguments") {
                break;
            }
            if p.kind() == "composite_literal"
                && let Some(type_node) = p.named_child(0)
                && matches!(type_node.kind(), "slice_type" | "array_type" | "map_type")
            {
                nonstruct_collection_present = true;
                break;
            }
        }
        if !nonstruct_collection_present {
            return SiteContext::Call;
        }
        // Fall through — collection-as-call-arg is non-operational.
    }

    // Priority 5: StringConstant. const/var declarations — but ONLY when
    // the literal is a DIRECT child (via expression_list / spec). If the
    // literal sits inside a composite_literal that's inside the var_spec
    // (e.g. `var x = []string{"RS256"}`), the array semantics dominate and
    // we don't want to classify the inner element as a StringConstant.
    let has_composite_in_chain = chain.iter().any(|p| p.kind() == "composite_literal");
    if !has_composite_in_chain
        && chain.iter().any(|p| {
            matches!(
                p.kind(),
                "const_spec" | "var_spec" | "const_declaration" | "var_declaration"
            )
        })
    {
        return SiteContext::StringConstant;
    }

    SiteContext::Default
}

/// Recognise test-framework assertion callees so SiteContext can mark
/// matches inside them as TestAssertion (low signal).
fn is_test_assertion_callee(callee: &str, language: Language) -> bool {
    // Strip turbofish / generics; lowercase for case-insensitive check
    // (some frameworks use capitalized names).
    let head = callee
        .split('.')
        .next_back()
        .unwrap_or(callee)
        .split('<')
        .next()
        .unwrap_or(callee);
    match language {
        Language::Go => matches!(
            head,
            "Equal"
                | "Equals"
                | "Equalf"
                | "NotEqual"
                | "True"
                | "False"
                | "Nil"
                | "NotNil"
                | "Empty"
                | "NotEmpty"
                | "Contains"
                | "NotContains"
                | "Error"
                | "NoError"
                | "ErrorIs"
                | "ErrorContains"
                | "EqualValues"
                | "Same"
                | "NotSame"
                | "JSONEq"
                | "ElementsMatch"
                | "Len"
                | "EqualError"
                | "Regexp"
        ),
        Language::Java => matches!(
            head,
            "assertEquals"
                | "assertNotEquals"
                | "assertTrue"
                | "assertFalse"
                | "assertNull"
                | "assertNotNull"
                | "assertThat"
                | "assertSame"
                | "assertArrayEquals"
        ),
        Language::JavaScript | Language::TypeScript => matches!(
            head,
            "equal"
                | "deepEqual"
                | "strictEqual"
                | "notEqual"
                | "toBe"
                | "toEqual"
                | "toMatch"
                | "toContain"
                | "expect"
        ),
        Language::Python => matches!(
            head,
            "assertEqual"
                | "assertNotEqual"
                | "assertTrue"
                | "assertFalse"
                | "assertIs"
                | "assertIsNone"
                | "assertIn"
                | "assertRaises"
                | "assertAlmostEqual"
        ),
        Language::Rust => matches!(
            head,
            "assert_eq" | "assert_ne" | "assert" | "debug_assert_eq" | "debug_assert_ne"
        ),
        Language::C | Language::Cpp => matches!(
            head,
            "EXPECT_EQ"
                | "ASSERT_EQ"
                | "EXPECT_NE"
                | "ASSERT_NE"
                | "EXPECT_TRUE"
                | "ASSERT_TRUE"
                | "EXPECT_STREQ"
                | "ASSERT_STREQ"
        ),
        Language::CSharp => matches!(
            head,
            "Equal" | "True" | "False" | "Same" | "NotEqual" | "AreEqual"
        ),
    }
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

    // 1.5. Phase 16: site-context filter. When the rule names an allow-list,
    // the match's site_context must be in it.
    if let Some(allow) = &rule.when.site_context {
        let ctx_name = format!("{:?}", raw.site_context);
        if !allow.iter().any(|s| s == &ctx_name) {
            return Ok(None);
        }
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

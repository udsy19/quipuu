//! Scanner — walks files and produces [`Finding`]s.
//!
//! tree-sitter parses each file; this module walks the tree looking for call
//! sites that match known crypto API shapes, then hands each candidate to the
//! `classify` layer of the rule TOML for algorithm-id, message, and severity.
//!
//! Note on the rule format: the `[[extract]]` S-expression queries in the rule
//! packs are NOT executed. Matching is done by the hand-written walker below,
//! and `[[extract]]` currently serves as documentation of intended shapes. The
//! `[[classify]]` layer is fully live and is the source of truth for
//! classification. Do not read an `[[extract]]` block as describing what the
//! scanner actually matches — read `match_*_callee` for that.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock, RwLock};

use quipuu_core::{
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
    #[error("file too large to scan: {path} ({size} bytes)")]
    FileTooLarge { path: PathBuf, size: u64 },
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
    pub site_context: quipuu_core::SiteContext,
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
        // Size cap before reading. quipuu runs in CI against arbitrary
        // repositories, and an uncapped read of a vendored multi-GB blob is an
        // OOM kill of the whole job. Real source files are orders of magnitude
        // below this; anything above it is generated, minified, or hostile.
        if let Ok(meta) = std::fs::metadata(path)
            && meta.len() > MAX_SOURCE_BYTES
        {
            return Err(ScanError::FileTooLarge {
                path: path.to_path_buf(),
                size: meta.len(),
            });
        }
        let source = std::fs::read(path)?;
        let extracted = run_extract(&source, language)?;
        for m in &extracted.matches {
            for classify in &rules.classify {
                if let Some(finding) =
                    apply_classify(m, classify, &self.algorithms, path, &extracted.imports)?
                {
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
        ScanError::FileTooLarge { .. } => ScanWarningKind::UnreadableFile,
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
/// call site, plus the file's import set for the classify layer to qualify
/// them with. The TOML rule pack drives classification; what we detect is:
///
/// * Go: `rsa.GenerateKey(rand.Reader, <int>)`, `ecdsa.GenerateKey(elliptic.PCURVE(), …)`,
///   `ed25519.GenerateKey(...)`, `md5.New()` / `sha1.New()`.
/// * Python: `rsa.generate_private_key(public_exponent=…, key_size=<int>)`,
///   `ec.generate_private_key(ec.SECP256R1())`, `hashlib.md5()` / `hashlib.sha1()`.
fn run_extract(source: &[u8], language: Language) -> Result<ExtractedFile, ScanError> {
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
    let bare_bindings = collect_bare_bindings(root, source, language);
    let pq_aliases = if language == Language::Go {
        collect_go_pq_aliases(root, source)
    } else {
        HashMap::new()
    };
    walk(
        root,
        source,
        language,
        &mut matches,
        0,
        &bare_bindings,
        &pq_aliases,
    );
    let imports = collect_imports(root, source, language);
    Ok(ExtractedFile { matches, imports })
}

/// One file's extract pass: the call sites, plus the file-scope facts a
/// classify rule may qualify them with.
struct ExtractedFile {
    matches: Vec<RawMatch>,
    imports: Vec<String>,
}

/// Every import target named in the file, verbatim.
///
/// C and C++ only. `#include <sodium.h>` and `#include "../sign.h"` both
/// yield the text between the delimiters; nothing is resolved, followed, or
/// normalised, because resolving an include path means reproducing the
/// project's build (P4). A rule matches against these strings with a regex,
/// so it decides for itself how much of the path it cares about.
///
/// Returns empty for the other languages. Their import statements have the
/// same shape and would slot in here, but nothing reads them yet and an
/// unread collector is a claim that something is qualified when it is not.
fn collect_imports(root: Node<'_>, source: &[u8], language: Language) -> Vec<String> {
    if !matches!(language, Language::C | Language::Cpp) {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut cursor = root.walk();
    // `preproc_include` is a top-level node in the C and C++ grammars; an
    // include inside `#ifdef` sits one level down, under `preproc_ifdef`.
    // One extra level covers the guarded case without walking the whole tree.
    for child in root.children(&mut cursor) {
        push_include_target(child, source, &mut out);
        if child.kind().starts_with("preproc_if") {
            let mut inner = child.walk();
            for grandchild in child.children(&mut inner) {
                push_include_target(grandchild, source, &mut out);
            }
        }
    }
    out
}

/// Local names bound directly (not through a member expression) from a
/// crypto module import, mapped to the same `module.method` key the
/// member-expression form already produces — `generateKeyPair` destructured
/// from `require('node:crypto')` maps to `"crypto.generateKeyPair"`, the
/// existing [`JS_CALLEE_APIS`] key, and `md5` from `from hashlib import md5`
/// maps to `"hashlib.md5"`, the existing [`PYTHON_CALLEE_APIS`] key. A bare
/// call resolves through this map before the normal callee lookup
/// (see `match_call`), so no new api table or classify rule is needed —
/// see `#Y4`: every JS/Python extract query only recognised a call reached
/// through the module object, so a name-imported binding was invisible.
fn collect_bare_bindings(
    root: Node<'_>,
    source: &[u8],
    language: Language,
) -> HashMap<String, String> {
    match language {
        Language::JavaScript | Language::TypeScript => collect_js_bare_bindings(root, source),
        Language::Python => collect_python_bare_bindings(root, source),
        _ => HashMap::new(),
    }
}

/// `circl`'s post-quantum signature package import paths, mapped to a
/// human-readable family name. Go only. Backlog `#Y20`: the corpus's only
/// live PQC signature package (`cloudflare/circl`) is invisible to every
/// rule pack, and the one place it *is* touched — the `eddilithium{2,3}`
/// hybrid schemes — combines it with `ed25519`/`ecdsa` in the same
/// function, so [`find_go_pq_colocation`] needs to recognise these package
/// paths to soften the classical-only message. This is deliberately not a
/// standalone PQC-detection rule (that is `#Y20`'s larger, unscoped item).
fn go_pq_signature_family(import_path: &str) -> Option<&'static str> {
    if import_path.contains("circl/sign/dilithium") {
        Some("ML-DSA (circl dilithium)")
    } else if import_path.contains("circl/sign/mldsa") {
        Some("ML-DSA (circl mldsa)")
    } else if import_path.contains("circl/sign/slhdsa") {
        Some("SLH-DSA (circl slhdsa)")
    } else {
        None
    }
}

/// Local package aliases in this Go file that resolve to one of `circl`'s
/// post-quantum signature packages (see [`go_pq_signature_family`]), mapped
/// to that family's human-readable name. Empty for every file that doesn't
/// import one — the common case, so [`find_go_pq_colocation`] can skip the
/// search entirely.
fn collect_go_pq_aliases(root: Node<'_>, source: &[u8]) -> HashMap<String, String> {
    let mut out = HashMap::new();
    walk_all(root, &mut |node| {
        if node.kind() != "import_spec" {
            return;
        }
        let Some(path_node) = node.child_by_field_name("path") else {
            return;
        };
        let path = string_literal_value(path_node, source);
        let Some(family) = go_pq_signature_family(&path) else {
            return;
        };
        let local = node
            .child_by_field_name("name")
            .map(|n| node_text(n, source))
            .unwrap_or_else(|| path.rsplit('/').next().unwrap_or(&path).to_string());
        out.insert(local, family.to_string());
    });
    out
}

/// Does the enclosing function/method also call `Sign`/`SignTo`/`Verify` on
/// one of `pq_aliases`? If so, a classical ed25519/ecdsa operation-site
/// finding at `call` is only half the story — see backlog `#Y20`: `circl`'s
/// `eddilithium2`/`eddilithium3` AND-combine an Ed25519 signature with a
/// Dilithium/ML-DSA one in the same `Sign`/`Verify` function, and telling a
/// team that already adopted the hybrid scheme to "replace with ML-DSA" is
/// an active false statement, not just an incomplete one.
fn find_go_pq_colocation(
    call: Node<'_>,
    source: &[u8],
    pq_aliases: &HashMap<String, String>,
) -> Option<(String, u32)> {
    if pq_aliases.is_empty() {
        return None;
    }
    let mut scope = call.parent()?;
    while !matches!(scope.kind(), "function_declaration" | "method_declaration") {
        scope = scope.parent()?;
    }
    let mut found = None;
    walk_all(scope, &mut |node| {
        if found.is_some() || node.id() == call.id() || node.kind() != "call_expression" {
            return;
        }
        let Some(function) = node.child_by_field_name("function") else {
            return;
        };
        if function.kind() != "selector_expression" {
            return;
        }
        let Some(operand) = function.child_by_field_name("operand") else {
            return;
        };
        let Some(family) = pq_aliases.get(&node_text(operand, source)) else {
            return;
        };
        let Some(field) = function.child_by_field_name("field") else {
            return;
        };
        let method = node_text(field, source);
        if method.starts_with("Sign") || method.starts_with("Verify") {
            found = Some((family.clone(), (node.start_position().row + 1) as u32));
        }
    });
    found
}

fn walk_all<'a>(node: Node<'a>, f: &mut impl FnMut(Node<'a>)) {
    f(node);
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_all(child, f);
    }
}

/// Strip the delimiters off a JS `string` node's text (`'x'`, `"x"`, `` `x` ``).
fn string_literal_value(node: Node<'_>, source: &[u8]) -> String {
    node_text(node, source)
        .trim_matches(['\'', '"', '`'].as_slice())
        .to_string()
}

/// `const { generateKeyPair } = require('node:crypto')`, the ESM
/// `import { generateKeyPair } from 'node:crypto'`, and both forms with an
/// alias (`{ generateKeyPair: generateKeyPair_ }`, `as`). Out of scope, named
/// per `#Y4`: barrel files, re-exports, dynamic specifiers, `import * as c`.
fn collect_js_bare_bindings(root: Node<'_>, source: &[u8]) -> HashMap<String, String> {
    let mut out = HashMap::new();
    walk_all(root, &mut |node| match node.kind() {
        "variable_declarator" => {
            let (Some(name), Some(value)) = (
                node.child_by_field_name("name"),
                node.child_by_field_name("value"),
            ) else {
                return;
            };
            if name.kind() != "object_pattern" || value.kind() != "call_expression" {
                return;
            }
            let Some(function) = value.child_by_field_name("function") else {
                return;
            };
            if node_text(function, source) != "require" {
                return;
            }
            if !requires_crypto_module(value, source) {
                return;
            }
            add_js_pattern_bindings(name, source, &mut out);
        }
        "import_statement" => {
            let Some(source_node) = node.child_by_field_name("source") else {
                return;
            };
            if !matches!(
                string_literal_value(source_node, source).as_str(),
                "crypto" | "node:crypto"
            ) {
                return;
            }
            let mut cursor = node.walk();
            for specifier in node
                .named_children(&mut cursor)
                .filter(|n| n.kind() == "import_clause")
                .flat_map(|clause| {
                    let mut c = clause.walk();
                    clause
                        .named_children(&mut c)
                        .filter(|n| n.kind() == "named_imports")
                        .flat_map(|ni| {
                            let mut c2 = ni.walk();
                            ni.named_children(&mut c2)
                                .filter(|n| n.kind() == "import_specifier")
                                .collect::<Vec<_>>()
                        })
                        .collect::<Vec<_>>()
                })
            {
                let Some(orig) = specifier.child_by_field_name("name") else {
                    continue;
                };
                let original = node_text(orig, source);
                let local = specifier
                    .child_by_field_name("alias")
                    .map(|a| node_text(a, source))
                    .unwrap_or_else(|| original.clone());
                out.insert(local, format!("crypto.{original}"));
            }
        }
        _ => {}
    });
    out
}

/// Does `require(...)`'s sole argument name the Node `crypto` module?
fn requires_crypto_module(call: Node<'_>, source: &[u8]) -> bool {
    let Some(args) = call.child_by_field_name("arguments") else {
        return false;
    };
    let mut cursor = args.walk();
    args.named_children(&mut cursor)
        .next()
        .map(|arg| {
            matches!(
                string_literal_value(arg, source).as_str(),
                "crypto" | "node:crypto"
            )
        })
        .unwrap_or(false)
}

/// Walk a JS destructuring `object_pattern`, recording each bound local name
/// against its original (pre-alias) property name.
fn add_js_pattern_bindings(pattern: Node<'_>, source: &[u8], out: &mut HashMap<String, String>) {
    let mut cursor = pattern.walk();
    for element in pattern.named_children(&mut cursor) {
        match element.kind() {
            // `{ generateKeyPair }` — key and local name are the same token.
            "shorthand_property_identifier_pattern" => {
                let name = node_text(element, source);
                out.insert(name.clone(), format!("crypto.{name}"));
            }
            // `{ generateKeyPair: generateKeyPair_ }`
            "pair_pattern" => {
                let (Some(key), Some(value)) = (
                    element.child_by_field_name("key"),
                    element.child_by_field_name("value"),
                ) else {
                    continue;
                };
                let original = node_text(key, source);
                let local = node_text(value, source);
                out.insert(local, format!("crypto.{original}"));
            }
            _ => {}
        }
    }
}

/// `from hashlib import md5, sha1 as s1`. Out of scope, named per `#Y4`:
/// everything beyond `hashlib` — the `cryptography.hazmat` classes are
/// already reachable bare (see [`PYTHON_CALLEE_APIS`]) because they are
/// imported as classes, not as the function that is actually called.
fn collect_python_bare_bindings(root: Node<'_>, source: &[u8]) -> HashMap<String, String> {
    let mut out = HashMap::new();
    walk_all(root, &mut |node| {
        if node.kind() != "import_from_statement" {
            return;
        }
        let Some(module) = node.child_by_field_name("module_name") else {
            return;
        };
        if node_text(module, source) != "hashlib" {
            return;
        }
        let mut cursor = node.walk();
        for name in node.children_by_field_name("name", &mut cursor) {
            match name.kind() {
                "dotted_name" | "identifier" => {
                    let n = node_text(name, source);
                    out.insert(n.clone(), format!("hashlib.{n}"));
                }
                "aliased_import" => {
                    let (Some(orig), Some(alias)) = (
                        name.child_by_field_name("name"),
                        name.child_by_field_name("alias"),
                    ) else {
                        continue;
                    };
                    out.insert(
                        node_text(alias, source),
                        format!("hashlib.{}", node_text(orig, source)),
                    );
                }
                _ => {}
            }
        }
    });
    out
}

fn push_include_target(node: Node<'_>, source: &[u8], out: &mut Vec<String>) {
    if node.kind() != "preproc_include" {
        return;
    }
    let Some(path) = node.child_by_field_name("path") else {
        return;
    };
    // `<sodium.h>` is a `system_lib_string`, `"sign.h"` a `string_literal`;
    // both carry their delimiters in the node text.
    let text = node_text(path, source);
    let trimmed = text.trim_matches(['<', '>', '"'].as_slice());
    if !trimmed.is_empty() {
        out.push(trimmed.to_string());
    }
}

/// Maximum AST depth we will descend.
///
/// This is a hard safety bound, not a tuning knob. `walk` recurses once per AST
/// node, and tree-sitter will happily build a tree thousands of levels deep for
/// a file of nested parentheses or braces — which minified and generated code
/// produces routinely, and a hostile repository produces deliberately.
/// Overflowing the stack is a SIGSEGV, not a catchable panic, so it would kill
/// the whole scan rather than skipping one file. quipuu runs in CI against
/// arbitrary untrusted repositories, so that is a real defect.
///
/// 512 is far beyond any hand-written source: real code rarely exceeds ~60.
const MAX_AST_DEPTH: usize = 512;

/// Largest source file we will read into memory (16 MiB).
///
/// Hand-written source is never close to this. Generated, minified, or
/// deliberately hostile files are, and an uncapped `fs::read` of a vendored
/// blob is an OOM kill of a CI container rather than a skipped file.
const MAX_SOURCE_BYTES: u64 = 16 * 1024 * 1024;

fn walk(
    node: Node<'_>,
    source: &[u8],
    language: Language,
    out: &mut Vec<RawMatch>,
    depth: usize,
    bare_bindings: &HashMap<String, String>,
    pq_aliases: &HashMap<String, String>,
) {
    if depth >= MAX_AST_DEPTH {
        return;
    }
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
    if is_call_like && let Some(m) = match_call(node, source, language, bare_bindings, pq_aliases) {
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
    // Java `sslParams.setNamedGroups(new String[]{...})` — an instance
    // method, so it runs alongside (not instead of) `match_call`'s
    // `method_invocation` handling, the same way `match_java_field_access`
    // above runs alongside the call-site check. Backlog `#Y24`.
    if language == Language::Java
        && kind == "method_invocation"
        && let Some(ms) = match_java_set_named_groups(node, source)
    {
        out.extend(ms);
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
    // Go `MinVersion: tls.VersionTLS10` — a protocol-level setting on the same
    // `keyed_element` node kind as CurvePreferences.
    if language == Language::Go
        && kind == "keyed_element"
        && let Some(m) = match_go_tls_min_version(node, source)
    {
        out.push(m);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk(
            child,
            source,
            language,
            out,
            depth + 1,
            bare_bindings,
            pq_aliases,
        );
    }
}

/// Inspect one call node and decide if it's a known crypto API site.
fn match_call(
    call: Node<'_>,
    source: &[u8],
    language: Language,
    bare_bindings: &HashMap<String, String>,
    pq_aliases: &HashMap<String, String>,
) -> Option<RawMatch> {
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
            site_context: quipuu_core::SiteContext::Call,
        });
    }

    // Standard call_expression / call (Go, Python, JS, TS, C, C++, Rust)
    let function = call.child_by_field_name("function")?;
    let args = call.child_by_field_name("arguments")?;
    let callee_text = node_text(function, source);

    // A bare identifier callee (`generateKeyPair(...)`, `md5(...)`) carries no
    // module qualifier for `match_python_callee`/`match_js_callee` to key on.
    // If the file's own imports bound that exact name from a crypto module,
    // resolve it to the same `module.method` key the qualified call already
    // produces, so it reaches the existing callee tables unqualified — see
    // `collect_bare_bindings`.
    let resolved_callee = if function.kind() == "identifier"
        && matches!(
            language,
            Language::Python | Language::JavaScript | Language::TypeScript
        ) {
        bare_bindings
            .get(&callee_text)
            .cloned()
            .unwrap_or_else(|| callee_text.clone())
    } else {
        callee_text.clone()
    };

    let (api, mut args_map) = match language {
        Language::Go => match_go_callee(&callee_text)?,
        Language::Python => match_python_callee(&resolved_callee)?,
        Language::JavaScript | Language::TypeScript => match_js_callee(&resolved_callee)?,
        Language::C | Language::Cpp => match_c_callee(&callee_text)?,
        Language::Rust => match_rust_callee(&callee_text)?,
        Language::Java | Language::CSharp => return None, // handled above
    };

    populate_args(language, &api, args, source, &mut args_map);

    // Backlog #Y20: soften an ed25519/ecdsa operation-site message when the
    // same function also calls a circl PQC signature package — see
    // `find_go_pq_colocation`.
    if language == Language::Go && (api == "crypto/ed25519.Op" || api == "crypto/ecdsa.Op") {
        let note = find_go_pq_colocation(call, source, pq_aliases)
            .map(|(family, line)| {
                format!(
                    " This function also calls {family} at line {line} — the classical \
                     component alone is insufficient to forge a signature accepted by this code."
                )
            })
            .unwrap_or_default();
        args_map.insert("pq_note".into(), ArgValue::Str(note));
    }

    // C/C++ callee-table matches (RSA_generate_key & co) previously hardcoded
    // `Call` unconditionally, so `when.site_context` filtering — the
    // mechanism that already suppresses Go/Java test-assertion FPs — had no
    // effect for this pack. Walking up from the first real argument (mirrors
    // the literal-node walk `classify_site_context`'s other callers use)
    // correctly classifies a call passed straight to a wolfssl-style
    // `ExpectNull(...)` wrapper as `TestAssertion`, and falls back to `Call`
    // — identical to the old behavior — when there is no argument to walk
    // from. Other languages are unchanged.
    let site_context = match language {
        Language::C | Language::Cpp => nth_real_arg(args, 0)
            .map(|n| classify_site_context(n, source, language))
            .unwrap_or(quipuu_core::SiteContext::Call),
        _ => quipuu_core::SiteContext::Call,
    };

    let start = call.start_position();
    Some(RawMatch {
        api,
        args: args_map,
        line: (start.row + 1) as u32,
        offset: call.start_byte() as u32,
        symbol: callee_text,
        snippet: node_text(call, source),
        site_context,
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
        site_context: quipuu_core::SiteContext::Call,
    })
}

/// Match Java `sslParams.setNamedGroups(new String[]{"x25519", "SecP256r1MLKEM768", ...})`.
///
/// `SSLParameters.setNamedGroups` is reached through an instance variable —
/// `sslParams`, `params`, whatever the caller named it — not a static class
/// name, so unlike every `JAVA_CALLEE_APIS` row there is no receiver text to
/// key a lookup table on (resolving the variable's declared type means
/// building the project, which P4 forbids). The method name alone is
/// specific enough that a false match is not a real risk, the same
/// assumption `WEBCRYPTO_METHOD_APIS`'s method-only rows already make.
/// Backlog `#Y24`: this is TLS hardening configuration written for reasons
/// unrelated to PQC, so a classical-only group list here silently blocks the
/// PQC upgrade JDK 27's own default would otherwise make.
///
/// Emits one `RawMatch` per string literal in the array initializer, mirroring
/// `match_go_curve_preferences`'s per-element shape so each group routes to
/// its own `algorithm_id`.
fn match_java_set_named_groups(call: Node<'_>, source: &[u8]) -> Option<Vec<RawMatch>> {
    let name = call.child_by_field_name("name")?;
    if node_text(name, source) != "setNamedGroups" {
        return None;
    }
    // The array literal is the sole argument on the real instance-method
    // call (`sslParams.setNamedGroups(new String[]{...})`) but the second of
    // two on the delegating-helper shape corpus B's own conscrypt test suite
    // uses (`setNamedGroups(parameters, new String[]{...})`), so scan every
    // argument rather than assume a position.
    let args = call.child_by_field_name("arguments")?;
    let mut args_cursor = args.walk();
    let array_arg = args
        .named_children(&mut args_cursor)
        .find(|a| a.kind() == "array_creation_expression")?;
    let initializer = array_arg.child_by_field_name("value")?;
    if initializer.kind() != "array_initializer" {
        return None;
    }

    let mut results = Vec::new();
    let mut cursor = initializer.walk();
    for element in initializer.children(&mut cursor) {
        if element.kind() != "string_literal" {
            continue;
        }
        let group = string_literal_value(element, source);
        let mut group_args = HashMap::new();
        group_args.insert("group".into(), ArgValue::Str(group.clone()));
        let start = element.start_position();
        results.push(RawMatch {
            api: "javax.net.ssl.SSLParameters.setNamedGroups".into(),
            args: group_args,
            line: (start.row + 1) as u32,
            offset: element.start_byte() as u32,
            symbol: format!("setNamedGroups({group})"),
            snippet: node_text(element, source),
            site_context: quipuu_core::SiteContext::Call,
        });
    }

    if results.is_empty() {
        None
    } else {
        Some(results)
    }
}

/// Handle `new ClassName()` — Java and C#.
fn match_object_creation(call: Node<'_>, source: &[u8], language: Language) -> Option<RawMatch> {
    // Java: object_creation_expression has a `type` field (type_identifier)
    // C#:  object_creation_expression has a `type` field (identifier)
    let type_node = call.child_by_field_name("type")?;
    let type_text = node_text(type_node, source);

    let (api, mut args_map) = match language {
        Language::Java => match_java_ctor(&type_text)?,
        Language::CSharp => match_csharp_ctor(&type_text)?,
        _ => return None,
    };
    if let Some(args) = call.child_by_field_name("arguments") {
        populate_args(language, &api, args, source, &mut args_map);
    }

    let start = call.start_position();
    Some(RawMatch {
        api,
        args: args_map,
        line: (start.row + 1) as u32,
        offset: call.start_byte() as u32,
        symbol: type_text,
        snippet: node_text(call, source),
        site_context: quipuu_core::SiteContext::Call,
    })
}

/// Go callee text → logical api name.
///
/// One row per recognised call shape. The right-hand column is the extract
/// layer's Go api surface, and [`api_surface`] enumerates the same column, so
/// a classify rule can never name an api this table does not produce.
const GO_CALLEE_APIS: &[(&str, &str)] = &[
    ("rsa.GenerateKey", "crypto/rsa.GenerateKey"),
    ("ecdsa.GenerateKey", "crypto/ecdsa.GenerateKey"),
    ("ed25519.GenerateKey", "crypto/ed25519.GenerateKey"),
    ("md5.New", "crypto/md5_sha1.New"),
    ("sha1.New", "crypto/md5_sha1.New"),
    ("md5.Sum", "crypto/md5_sha1.Sum"),
    ("sha1.Sum", "crypto/md5_sha1.Sum"),
    ("aes.NewCipher", "crypto/aes.NewCipher"),
    ("des.NewCipher", "crypto/des.NewCipher"),
    ("des.NewTripleDESCipher", "crypto/des.NewTripleDESCipher"),
    ("rc4.NewCipher", "crypto/rc4.NewCipher"),
    // golang-jwt is imported under three spellings in the wild.
    ("jwt.NewWithClaims", "jwt.NewWithClaims"),
    ("jwt_go.NewWithClaims", "jwt.NewWithClaims"),
    ("jwtgo.NewWithClaims", "jwt.NewWithClaims"),
    // Sign/verify/encrypt/decrypt *operation* sites, distinct from the
    // constructors above. A key generated in one file and used in another (or
    // received as a function argument, e.g. certificate validation) never
    // matches a constructor rule, so these were invisible entirely rather
    // than degrading to the unattributed sentinel. None of these captures a
    // parameter set — the size/curve lives on the key, not at this call site.
    ("rsa.SignPKCS1v15", "crypto/rsa.Op"),
    ("rsa.VerifyPKCS1v15", "crypto/rsa.Op"),
    ("rsa.SignPSS", "crypto/rsa.Op"),
    ("rsa.VerifyPSS", "crypto/rsa.Op"),
    ("rsa.EncryptOAEP", "crypto/rsa.Op"),
    ("rsa.DecryptOAEP", "crypto/rsa.Op"),
    ("rsa.EncryptPKCS1v15", "crypto/rsa.Op"),
    ("rsa.DecryptPKCS1v15", "crypto/rsa.Op"),
    ("ecdsa.Sign", "crypto/ecdsa.Op"),
    ("ecdsa.SignASN1", "crypto/ecdsa.Op"),
    ("ecdsa.Verify", "crypto/ecdsa.Op"),
    ("ecdsa.VerifyASN1", "crypto/ecdsa.Op"),
    ("ed25519.Sign", "crypto/ed25519.Op"),
    ("ed25519.Verify", "crypto/ed25519.Op"),
    // crypto/dsa — classical (non-elliptic) DSA. GenerateKey takes an
    // already-parameterised *dsa.PrivateKey (the prime/subprime size lives in
    // a separate dsa.GenerateParameters call this pack does not track), and
    // Sign/Verify carry no parameter either, so all three degrade straight to
    // the `dsa-unattributed` sentinel Java's KeyPairGenerator.getInstance
    // ("DSA") already publishes.
    ("dsa.GenerateKey", "crypto/dsa.GenerateKey"),
    ("dsa.Sign", "crypto/dsa.Op"),
    ("dsa.Verify", "crypto/dsa.Op"),
    // circl's PQC packages are one Go package per parameter set — the
    // package name itself is the parameter, unlike WebCrypto's algorithm
    // string argument. Backlog `#Y20`'s second item: the co-occurrence
    // check above only softens a classical finding when circl is used
    // alongside it; these rows make a circl call a finding in its own
    // right, the same status webcrypto's ML-DSA/ML-KEM arms already give
    // JS. `SignMuTo`/`ComputeMu`/the `crypto.Signer` method form are left
    // out — real call shapes not yet seen in the corpus.
    ("mldsa44.GenerateKey", "circl/sign/mldsa.GenerateKey"),
    ("mldsa65.GenerateKey", "circl/sign/mldsa.GenerateKey"),
    ("mldsa87.GenerateKey", "circl/sign/mldsa.GenerateKey"),
    ("mldsa44.NewKeyFromSeed", "circl/sign/mldsa.GenerateKey"),
    ("mldsa65.NewKeyFromSeed", "circl/sign/mldsa.GenerateKey"),
    ("mldsa87.NewKeyFromSeed", "circl/sign/mldsa.GenerateKey"),
    ("mldsa44.SignTo", "circl/sign/mldsa.Op"),
    ("mldsa65.SignTo", "circl/sign/mldsa.Op"),
    ("mldsa87.SignTo", "circl/sign/mldsa.Op"),
    ("mldsa44.Verify", "circl/sign/mldsa.Op"),
    ("mldsa65.Verify", "circl/sign/mldsa.Op"),
    ("mldsa87.Verify", "circl/sign/mldsa.Op"),
    (
        "mlkem512.GenerateKeyPair",
        "circl/kem/mlkem.GenerateKeyPair",
    ),
    (
        "mlkem768.GenerateKeyPair",
        "circl/kem/mlkem.GenerateKeyPair",
    ),
    (
        "mlkem1024.GenerateKeyPair",
        "circl/kem/mlkem.GenerateKeyPair",
    ),
    ("mlkem512.NewKeyFromSeed", "circl/kem/mlkem.GenerateKeyPair"),
    ("mlkem768.NewKeyFromSeed", "circl/kem/mlkem.GenerateKeyPair"),
    (
        "mlkem1024.NewKeyFromSeed",
        "circl/kem/mlkem.GenerateKeyPair",
    ),
    // slhdsa.GenerateKey(rand, id) — one package for all twelve parameter
    // sets, disambiguated by the `id` argument rather than the package
    // name; see populate_args below for the capture.
    ("slhdsa.GenerateKey", "circl/sign/slhdsa.GenerateKey"),
    // crypto/mlkem — Go's own stdlib ML-KEM (Go 1.24), zero-dependency next
    // to circl's third-party equivalent above. Unlike circl's per-package-
    // per-parameter-set layout, stdlib puts the parameter set in the
    // function name (one "mlkem" package): GenerateKey768/1024 are key
    // generation, New{Encapsulation,Decapsulation}Key768/1024 rebuild a key
    // from an encoded seed/point — both are real key-establishment sites,
    // not just the constructor. Backlog `#Y30` part (a).
    ("mlkem.GenerateKey768", "crypto/mlkem.KeyOp"),
    ("mlkem.GenerateKey1024", "crypto/mlkem.KeyOp"),
    ("mlkem.NewDecapsulationKey768", "crypto/mlkem.KeyOp"),
    ("mlkem.NewDecapsulationKey1024", "crypto/mlkem.KeyOp"),
    ("mlkem.NewEncapsulationKey768", "crypto/mlkem.KeyOp"),
    ("mlkem.NewEncapsulationKey1024", "crypto/mlkem.KeyOp"),
];

/// Exact-match lookup in one of the callee → api tables.
fn lookup(table: &'static [(&'static str, &'static str)], key: &str) -> Option<&'static str> {
    table
        .iter()
        .find_map(|(k, api)| (*k == key).then_some(*api))
}

/// APIs emitted by the structural matchers — the ones keyed on an AST shape
/// rather than on a callee string, so they have no entry in a callee table.
const STRUCTURAL_APIS: &[&str] = &[
    // match_go_callee's ecdh.<Curve> prefix arm
    "crypto/ecdh.Curve",
    // match_go_curve_preferences
    "crypto/tls.Config.CurvePreferences",
    // match_go_tls_min_version
    "crypto/tls.Config.MinVersion",
    // match_java_set_named_groups
    "javax.net.ssl.SSLParameters.setNamedGroups",
];

/// The apis reached through `match_java_field_access` — a bare enum-constant
/// reference, with no call around it to say what is being done with the name.
///
/// Read by `java_enum_classify_rules_declare_the_sites_they_fire_in`: these
/// are the rules that cannot infer operationality from their own match and so
/// must name the site contexts they accept.
pub fn java_enum_api_surface() -> Vec<String> {
    JAVA_ENUM_CLASS_APIS
        .iter()
        .map(|(_, api)| api.to_string())
        .collect()
}

/// Every `api` string the extract layer can emit.
///
/// This is the reachability contract between the two rule layers: a
/// `[[classify]]` rule whose `when.api` matches nothing in here can never
/// fire, and `every_classify_rule_targets_an_api_the_extractor_can_emit`
/// fails the build when one does. Derived from the same tables the matchers
/// dispatch on, so it cannot drift from them.
pub fn api_surface() -> Vec<String> {
    let mut out: Vec<String> = STRUCTURAL_APIS.iter().map(|s| s.to_string()).collect();
    for table in [
        GO_CALLEE_APIS,
        PYTHON_CALLEE_APIS,
        JAVA_CALLEE_APIS,
        JAVA_CTOR_APIS,
        JAVA_ENUM_CLASS_APIS,
        JS_CALLEE_APIS,
        WEBCRYPTO_METHOD_APIS,
        C_CALLEE_APIS,
        RUST_CALLEE_APIS,
        CSHARP_CALLEE_APIS,
        CSHARP_CTOR_APIS,
    ] {
        out.extend(table.iter().map(|(_, api)| api.to_string()));
    }
    // The two Go JOSE families are built by formatting a whitelisted
    // algorithm name into a prefix, so enumerate the product.
    for alg in GO_ALG_SWITCH_WHITELIST {
        out.push(format!("go.alg-switch.{alg}"));
        out.push(format!("go.alg-register.{alg}"));
    }
    out.sort();
    out.dedup();
    out
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

    let api = lookup(GO_CALLEE_APIS, callee)?;
    let mut args = HashMap::new();
    // For md5/sha1, the classifier reads `args.pkg` to disambiguate.
    if callee == "md5.New" || callee == "md5.Sum" {
        args.insert("pkg".into(), ArgValue::Str("md5".into()));
    } else if callee == "sha1.New" || callee == "sha1.Sum" {
        args.insert("pkg".into(), ArgValue::Str("sha1".into()));
    }
    // circl's ML-DSA/ML-KEM packages carry the parameter set in their own
    // name (mldsa44, mlkem768, ...); the classify layer reads `args.pkg` the
    // same way it reads md5/sha1 above.
    if api.starts_with("circl/sign/mldsa") || api.starts_with("circl/kem/mlkem") {
        if let Some(pkg) = callee.split('.').next() {
            args.insert("pkg".into(), ArgValue::Str(pkg.into()));
        }
        if let Some(fn_name) = callee.split('.').nth(1) {
            args.insert("fn".into(), ArgValue::Str(fn_name.into()));
        }
    }
    // The *.Op apis have no parameter set to capture; the message names the
    // specific function called instead (Sign vs. VerifyASN1 vs. EncryptOAEP).
    // `crypto/mlkem.KeyOp` is the odd one out: unlike the others, its `fn`
    // capture IS the parameter set (768 vs. 1024 is baked into the function
    // name, there being only one `mlkem` package), so the classify layer
    // reads `args.fn` rather than a package name.
    if (api == "crypto/rsa.Op"
        || api == "crypto/ecdsa.Op"
        || api == "crypto/ed25519.Op"
        || api == "crypto/dsa.Op"
        || api == "crypto/mlkem.KeyOp")
        && let Some(fn_name) = callee.split('.').nth(1)
    {
        args.insert("fn".into(), ArgValue::Str(fn_name.into()));
    }
    Some((api.into(), args))
}

/// Python callee text → logical api name.
///
/// pyca's key-generation classes are reached either through the module
/// (`ed25519.Ed25519PrivateKey.generate`) or imported bare
/// (`Ed25519PrivateKey.generate`); both spellings are in the table because
/// both are idiomatic and the walker only sees the callee text.
const PYTHON_CALLEE_APIS: &[(&str, &str)] = &[
    (
        "rsa.generate_private_key",
        "cryptography.hazmat.rsa.generate_private_key",
    ),
    (
        "ec.generate_private_key",
        "cryptography.hazmat.ec.generate_private_key",
    ),
    ("hashlib.md5", "hashlib.md5"),
    ("hashlib.sha1", "hashlib.sha1"),
    ("hashlib.new", "hashlib.new"),
    (
        "ed25519.Ed25519PrivateKey.generate",
        "cryptography.hazmat.ed25519.generate",
    ),
    (
        "Ed25519PrivateKey.generate",
        "cryptography.hazmat.ed25519.generate",
    ),
    (
        "ed448.Ed448PrivateKey.generate",
        "cryptography.hazmat.ed448.generate",
    ),
    (
        "Ed448PrivateKey.generate",
        "cryptography.hazmat.ed448.generate",
    ),
    (
        "x25519.X25519PrivateKey.generate",
        "cryptography.hazmat.x25519.generate",
    ),
    (
        "X25519PrivateKey.generate",
        "cryptography.hazmat.x25519.generate",
    ),
    (
        "x448.X448PrivateKey.generate",
        "cryptography.hazmat.x448.generate",
    ),
    (
        "X448PrivateKey.generate",
        "cryptography.hazmat.x448.generate",
    ),
    ("ciphers.Cipher", "cryptography.hazmat.ciphers.Cipher"),
    ("Cipher", "cryptography.hazmat.ciphers.Cipher"),
    ("ssl.SSLContext", "ssl.SSLContext"),
    ("jwt.encode", "jwt.encode"),
    ("RSA.generate", "Crypto.PublicKey.RSA.generate"),
    ("DES.new", "Crypto.Cipher.DES.new"),
    ("DES3.new", "Crypto.Cipher.DES3.new"),
];

fn match_python_callee(callee: &str) -> Option<(String, HashMap<String, ArgValue>)> {
    let api = lookup(PYTHON_CALLEE_APIS, callee)?;
    Some((api.into(), HashMap::new()))
}

/// Java method-invocation callee text ("ClassName.methodName") → api name.
const JAVA_CALLEE_APIS: &[(&str, &str)] = &[
    ("Cipher.getInstance", "javax.crypto.Cipher.getInstance"),
    (
        "KeyPairGenerator.getInstance",
        "java.security.KeyPairGenerator.getInstance",
    ),
    (
        "MessageDigest.getInstance",
        "java.security.MessageDigest.getInstance",
    ),
    (
        "Signature.getInstance",
        "java.security.Signature.getInstance",
    ),
    ("KEM.getInstance", "javax.crypto.KEM.getInstance"),
];

fn match_java_callee(callee: &str) -> Option<(String, HashMap<String, ArgValue>)> {
    let api = lookup(JAVA_CALLEE_APIS, callee)?;
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

    let api = lookup(JAVA_ENUM_CLASS_APIS, &class_name)?;

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
        if value == GO_ALG_NONE && !go_alg_name_is_corroborated(child, source) {
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
            site_context: quipuu_core::SiteContext::Call,
        });
    }
    if results.is_empty() {
        None
    } else {
        Some(results)
    }
}

/// Match Go `MinVersion: tls.VersionTLS10` inside a `tls.Config` literal.
///
/// The AST is `keyed_element(literal_element (identifier "MinVersion"),
/// literal_element (selector_expression tls.VersionTLS10))`. The `tls.`
/// operand guard keeps unrelated `MinVersion` struct fields out.
fn match_go_tls_min_version(keyed: Node<'_>, source: &[u8]) -> Option<RawMatch> {
    let key_le = keyed.named_child(0)?;
    let value_le = keyed.named_child(1)?;

    let key_inner = key_le.named_child(0)?;
    if key_inner.kind() != "identifier" || node_text(key_inner, source) != "MinVersion" {
        return None;
    }

    let sel = value_le.named_child(0)?;
    if sel.kind() != "selector_expression" {
        return None;
    }
    let operand = sel.child_by_field_name("operand")?;
    let field = sel.child_by_field_name("field")?;
    if operand.kind() != "identifier" || node_text(operand, source) != "tls" {
        return None;
    }

    let version = node_text(field, source);
    let mut args = HashMap::new();
    args.insert("version".into(), ArgValue::Str(version.clone()));
    let start = keyed.start_position();
    Some(RawMatch {
        api: "crypto/tls.Config.MinVersion".into(),
        args,
        line: (start.row + 1) as u32,
        offset: keyed.start_byte() as u32,
        symbol: format!("tls.{version}"),
        snippet: node_text(keyed, source),
        site_context: quipuu_core::SiteContext::StructLiteral,
    })
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
            site_context: quipuu_core::SiteContext::Call,
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
    // `"none"` is the one whitelisted value that is also an ordinary English
    // word, so it needs a second witness before it counts as a registration.
    if value == GO_ALG_NONE && !go_alg_name_is_corroborated(literal, source) {
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

/// The JWA name for an unsigned token, and the only entry in
/// [`GO_ALG_SWITCH_WHITELIST`] that is also an ordinary English word.
const GO_ALG_NONE: &str = "none";

/// Go syntax that bounds "these names are declared together".
///
/// A JOSE registry declares its algorithm names as a group: one `const` or
/// `var` block, one composite literal, one `switch`, or one function body of
/// `NewSignatureAlgorithm(...)` calls. That group is the window in which one
/// name can vouch for another.
const GO_ALG_SIBLING_SCOPES: &[&str] = &[
    "const_declaration",
    "var_declaration",
    "composite_literal",
    "expression_switch_statement",
    "type_switch_statement",
    "block",
];

/// Is this `"none"` literal declared alongside another JOSE algorithm name?
///
/// `"none"` matches `IpcModeNone = "none"`, `require_auth = "none"`, `ssh -F
/// none` and every other place a program spells "absent" — 91 of the 92
/// `CRYPTO-740` findings on the 150-project benchmark corpus were that, and
/// the one that was real (`jwx/jwa/signature_gen.go`) sits three lines below
/// `NewSignatureAlgorithm("HS512")`. So require the sibling rather than the
/// import: the pinning fixture `go/jwt_register.go` imports only `crypto`,
/// and 6 of the 92 false positives imported a JOSE package anyway.
///
/// Deliberately not a file-wide search: `x-crypto/ssh` names `"none"` for its
/// null compression algorithm in a file whose neighbours mention JOSE names
/// nowhere near it.
fn go_alg_name_is_corroborated(node: Node<'_>, source: &[u8]) -> bool {
    let mut scope = node;
    while !GO_ALG_SIBLING_SCOPES.contains(&scope.kind()) {
        match scope.parent() {
            Some(parent) => scope = parent,
            None => return false,
        }
    }
    let mut stack = vec![scope];
    while let Some(n) = stack.pop() {
        if matches!(
            n.kind(),
            "interpreted_string_literal" | "raw_string_literal"
        ) {
            let raw = node_text(n, source);
            let value = raw.trim_matches(|c| c == '"' || c == '`');
            if value != GO_ALG_NONE && GO_ALG_SWITCH_WHITELIST.contains(&value) {
                return true;
            }
        }
        let mut cursor = n.walk();
        stack.extend(n.named_children(&mut cursor));
    }
    false
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

/// Java crypto-enum classes whose members name an algorithm. Narrow by
/// design: a general "any field_access" rule would flood the output.
/// Deliberately absent: Apache Shiro's `DefaultPasswordService`, which is a
/// class with static members, not an algorithm enum.
const JAVA_ENUM_CLASS_APIS: &[(&str, &str)] = &[
    // jjwt
    ("SignatureAlgorithm", "io.jsonwebtoken.SignatureAlgorithm"),
    // auth0 java-jwt
    ("Algorithm", "com.auth0.jwt.Algorithm"),
    // nimbus-jose-jwt
    ("JWSAlgorithm", "com.nimbusds.jose.JWSAlgorithm"),
    ("JWEAlgorithm", "com.nimbusds.jose.JWEAlgorithm"),
    ("EncryptionMethod", "com.nimbusds.jose.EncryptionMethod"),
    // jose4j
    (
        "AlgorithmIdentifiers",
        "org.jose4j.jws.AlgorithmIdentifiers",
    ),
];

/// BouncyCastle `new Foo()` constructors.
const JAVA_CTOR_APIS: &[(&str, &str)] = &[
    (
        "RSAKeyPairGenerator",
        "org.bouncycastle.RSAKeyPairGenerator",
    ),
    ("AESEngine", "org.bouncycastle.AESEngine"),
    ("GCMBlockCipher", "org.bouncycastle.GCMBlockCipher"),
    (
        "BouncyCastleProvider",
        "org.bouncycastle.BouncyCastleProvider",
    ),
    // Lightweight-API PQC classes. Bare class name is unchanged across the
    // 2026-04 relocation from org.bouncycastle.pqc.crypto.* to
    // org.bouncycastle.crypto.*, so one table row covers both.
    (
        "MLKEMKeyPairGenerator",
        "org.bouncycastle.MLKEMKeyPairGenerator",
    ),
    (
        "MLDSAKeyPairGenerator",
        "org.bouncycastle.MLDSAKeyPairGenerator",
    ),
    (
        "SLHDSAKeyPairGenerator",
        "org.bouncycastle.SLHDSAKeyPairGenerator",
    ),
    ("MLKEMGenerator", "org.bouncycastle.MLKEMGenerator"),
    ("MLKEMExtractor", "org.bouncycastle.MLKEMExtractor"),
    ("MLDSASigner", "org.bouncycastle.MLDSASigner"),
    ("SLHDSASigner", "org.bouncycastle.SLHDSASigner"),
    ("HashMLDSASigner", "org.bouncycastle.HashMLDSASigner"),
    ("HashSLHDSASigner", "org.bouncycastle.HashSLHDSASigner"),
];

fn match_java_ctor(class_name: &str) -> Option<(String, HashMap<String, ArgValue>)> {
    let api = lookup(JAVA_CTOR_APIS, class_name)?;
    Some((api.into(), HashMap::new()))
}

fn match_js_callee(callee: &str) -> Option<(String, HashMap<String, ArgValue>)> {
    // WebCrypto is reached through a different receiver in almost every
    // codebase — a destructured `subtle`, `crypto.subtle`,
    // `window.crypto.subtle`, `self.crypto.subtle`, `globalThis.crypto.subtle`,
    // `util.globalScope.msCrypto.subtle`. Matching the receiver exactly caught
    // only the destructured form, which is the rarest of them, so the rules
    // fired on none of the WebCrypto call sites in corpus B. Match on the
    // trailing `subtle.<method>` segment instead.
    if let Some(api) = match_webcrypto_callee(callee) {
        return Some((api.into(), HashMap::new()));
    }
    // JS/TS member expression callees. tree-sitter renders nested member
    // expressions as their full source text, so two-level chains like
    // `CryptoJS.AES.encrypt` come through as a single &str here.
    let api = lookup(JS_CALLEE_APIS, callee)?;
    Some((api.into(), HashMap::new()))
}

/// JS/TS member-expression callee text → api name. tree-sitter renders nested
/// member expressions as their full source text, so two-level chains like
/// `CryptoJS.AES.encrypt` arrive as a single key.
///
/// Every crypto-js algorithm here is on the "broken classically" tier — DES,
/// 3DES, RC4, MD5, SHA-1 — so they map to existing algorithm-ids.
const JS_CALLEE_APIS: &[(&str, &str)] = &[
    ("crypto.createCipheriv", "node:crypto.createCipheriv"),
    ("crypto.createHash", "node:crypto.createHash"),
    ("crypto.generateKeyPair", "node:crypto.generateKeyPair"),
    ("crypto.generateKeyPairSync", "node:crypto.generateKeyPair"),
    ("crypto.createSign", "node:crypto.createSign"),
    ("subtle.generateKey", "webcrypto.subtle.generateKey"),
    ("subtle.sign", "webcrypto.subtle.sign"),
    ("jwt.sign", "jsonwebtoken.jwt.sign"),
    ("CryptoJS.AES.encrypt", "crypto-js.AES.encrypt"),
    ("CryptoJS.AES.decrypt", "crypto-js.AES.encrypt"),
    ("CryptoJS.DES.encrypt", "crypto-js.DES.encrypt"),
    ("CryptoJS.DES.decrypt", "crypto-js.DES.encrypt"),
    ("CryptoJS.TripleDES.encrypt", "crypto-js.TripleDES.encrypt"),
    ("CryptoJS.TripleDES.decrypt", "crypto-js.TripleDES.encrypt"),
    ("CryptoJS.RC4.encrypt", "crypto-js.RC4.encrypt"),
    ("CryptoJS.RC4.decrypt", "crypto-js.RC4.encrypt"),
    ("CryptoJS.MD5", "crypto-js.MD5"),
    ("CryptoJS.SHA1", "crypto-js.SHA1"),
    ("CryptoJS.HmacMD5", "crypto-js.HmacMD5"),
    ("CryptoJS.HmacSHA1", "crypto-js.HmacSHA1"),
];

/// `SubtleCrypto` method name → api name, for calls reached through any
/// receiver chain ending in `.subtle`.
const WEBCRYPTO_METHOD_APIS: &[(&str, &str)] = &[
    ("generateKey", "webcrypto.subtle.generateKey"),
    ("sign", "webcrypto.subtle.sign"),
];

/// Resolve a `SubtleCrypto` method call reached through any receiver chain.
///
/// The `subtle` segment must be a whole identifier, so `mySubtle.sign` and
/// `jwt.sign` do not match. Receiver text can span lines when the chain is
/// formatted vertically, hence the `trim_end`.
fn match_webcrypto_callee(callee: &str) -> Option<&'static str> {
    let (receiver, method) = callee.rsplit_once('.')?;
    let api = lookup(WEBCRYPTO_METHOD_APIS, method.trim())?;
    let receiver = receiver.trim_end();
    (receiver == "subtle" || receiver.ends_with(".subtle")).then_some(api)
}

/// C/C++ function identifier → api name.
const C_CALLEE_APIS: &[(&str, &str)] = &[
    ("RSA_generate_key_ex", "openssl.RSA_generate_key_ex"),
    // Legacy pre-3.0 spelling, no `_ex` suffix and no output-parameter RSA*:
    // `RSA_generate_key(bits, e, callback, cb_arg)` returns the key instead
    // of taking it as arg 0, so bits moves from position 1 to position 0.
    ("RSA_generate_key", "openssl.RSA_generate_key"),
    ("EVP_EncryptInit_ex", "openssl.EVP_EncryptInit_ex"),
    ("EVP_DigestInit_ex", "openssl.EVP_DigestInit_ex"),
    ("SSL_CTX_set_cipher_list", "openssl.SSL_CTX_set_cipher_list"),
    ("crypto_box_keypair", "libsodium.crypto_box_keypair"),
    // Not `libsodium.` — `crypto_sign_keypair` is the NaCl signature keygen
    // name and the NIST PQC reference API name, so the identifier alone does
    // not say whose it is. The cpp pack qualifies it on the file's headers.
    // `crypto_box_keypair` above keeps the libsodium prefix because the PQC
    // reference API spells its KEM `crypto_kem_keypair`, so it does not
    // collide.
    ("crypto_sign_keypair", "nacl-api.crypto_sign_keypair"),
    ("mbedtls_rsa_init", "mbedtls.mbedtls_rsa_init"),
    ("mbedtls_pk_setup", "mbedtls.mbedtls_pk_setup"),
    // liboqs "stack" API generation: algorithm baked into the function
    // name (OQS_KEM_ml_kem_768_keypair), unlike the "heap"/generic API
    // below whose algorithm is a runtime string argument. Backlog #Y33.
    // Bounded to the six NIST-selected parameter sets crossed with their
    // base operation suffixes; `_derand`/`_with_ctx_str` variants and the
    // wider liboqs algorithm zoo are out of scope on the same standing
    // rejection as the heap-form item.
    // All nine map to one shared api per family; `match_c_callee` captures
    // the callee text itself as `args.fn` so classify differentiates the
    // parameter set the same way Go's `crypto/mlkem.KeyOp` does.
    ("OQS_KEM_ml_kem_512_keypair", "liboqs.OQS_KEM_stack"),
    ("OQS_KEM_ml_kem_512_encaps", "liboqs.OQS_KEM_stack"),
    ("OQS_KEM_ml_kem_512_decaps", "liboqs.OQS_KEM_stack"),
    ("OQS_KEM_ml_kem_768_keypair", "liboqs.OQS_KEM_stack"),
    ("OQS_KEM_ml_kem_768_encaps", "liboqs.OQS_KEM_stack"),
    ("OQS_KEM_ml_kem_768_decaps", "liboqs.OQS_KEM_stack"),
    ("OQS_KEM_ml_kem_1024_keypair", "liboqs.OQS_KEM_stack"),
    ("OQS_KEM_ml_kem_1024_encaps", "liboqs.OQS_KEM_stack"),
    ("OQS_KEM_ml_kem_1024_decaps", "liboqs.OQS_KEM_stack"),
    ("OQS_SIG_ml_dsa_44_keypair", "liboqs.OQS_SIG_stack"),
    ("OQS_SIG_ml_dsa_44_sign", "liboqs.OQS_SIG_stack"),
    ("OQS_SIG_ml_dsa_44_verify", "liboqs.OQS_SIG_stack"),
    ("OQS_SIG_ml_dsa_65_keypair", "liboqs.OQS_SIG_stack"),
    ("OQS_SIG_ml_dsa_65_sign", "liboqs.OQS_SIG_stack"),
    ("OQS_SIG_ml_dsa_65_verify", "liboqs.OQS_SIG_stack"),
    ("OQS_SIG_ml_dsa_87_keypair", "liboqs.OQS_SIG_stack"),
    ("OQS_SIG_ml_dsa_87_sign", "liboqs.OQS_SIG_stack"),
    ("OQS_SIG_ml_dsa_87_verify", "liboqs.OQS_SIG_stack"),
    // liboqs "heap"/generic API: the algorithm is a runtime string passed
    // via the `OQS_{KEM,SIG}_alg_*` macros — tree-sitter sees the macro
    // name as a bare identifier argument. `populate_args` below captures it
    // as `alg`.
    ("OQS_KEM_new", "liboqs.OQS_KEM_new"),
    ("OQS_SIG_new", "liboqs.OQS_SIG_new"),
];

fn match_c_callee(callee: &str) -> Option<(String, HashMap<String, ArgValue>)> {
    let api = lookup(C_CALLEE_APIS, callee)?;
    let mut args = HashMap::new();
    // liboqs stack-form: the parameter set is baked into the function name
    // (there being no per-parameter-set api target, unlike the heap form),
    // so the classify layer reads `args.fn` the same way
    // `crypto/mlkem.KeyOp` does for Go's stdlib mlkem.
    if api == "liboqs.OQS_KEM_stack" || api == "liboqs.OQS_SIG_stack" {
        args.insert("fn".into(), ArgValue::Str(callee.to_string()));
    }
    Some((api.into(), args))
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
    let api = lookup(RUST_CALLEE_APIS, &normalized).or_else(|| {
        // Fall back: try just the trailing segment alone. Catches free
        // functions like `pbkdf2_hmac` when called as
        // `pbkdf2::pbkdf2_hmac::<Sha256>`.
        normalized
            .rsplit("::")
            .next()
            .and_then(|seg| lookup(RUST_CALLEE_APIS, seg))
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
/// Normalised Rust `Type::method` (or bare free function) → api name.
///
/// `SigningKey::new` is the RSA pkcs1v15 / pss shape; the hash algorithm
/// lives in the turbofish and is captured separately as `turbofish`. The
/// pbkdf2 crate has two call shapes (`pbkdf2::<Hmac<Sha256>>` and
/// `pbkdf2_hmac::<Sha256>`) and classify rules dispatch on the same capture.
const RUST_CALLEE_APIS: &[(&str, &str)] = &[
    (
        "EcdsaKeyPair::generate_pkcs8",
        "ring.EcdsaKeyPair.generate_pkcs8",
    ),
    (
        "Ed25519KeyPair::generate_pkcs8",
        "ring.Ed25519KeyPair.generate_pkcs8",
    ),
    ("Aes256Gcm::new", "rustcrypto.Aes256Gcm.new"),
    ("Aes128Gcm::new", "rustcrypto.Aes128Gcm.new"),
    ("Sha256::new", "rustcrypto.Sha256.digest"),
    ("Sha256::digest", "rustcrypto.Sha256.digest"),
    ("Sha384::new", "rustcrypto.Sha384.digest"),
    ("Sha384::digest", "rustcrypto.Sha384.digest"),
    ("Sha512::new", "rustcrypto.Sha512.digest"),
    ("Sha512::digest", "rustcrypto.Sha512.digest"),
    ("ChaCha20Poly1305::new", "rustcrypto.ChaCha20Poly1305.new"),
    ("RsaPrivateKey::new", "rsa.RsaPrivateKey.new"),
    ("Rsa::generate", "openssl.Rsa.generate"),
    ("SigningKey::generate", "ed25519_dalek.SigningKey.generate"),
    ("SigningKey::new", "rsa.SigningKey.new"),
    ("ClientConfig::builder", "rustls.ClientConfig.builder"),
    ("ServerConfig::builder", "rustls.ServerConfig.builder"),
    // rcgen — used by rustls-webpki / webpki test utilities.
    ("KeyPair::generate_for", "rcgen.KeyPair.generate_for"),
    ("pbkdf2", "pbkdf2.pbkdf2"),
    ("pbkdf2_hmac", "pbkdf2.pbkdf2_hmac"),
    ("pbkdf2_hmac_array", "pbkdf2.pbkdf2_hmac"),
];

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

/// C# member_access_expression text ("TypeName.MethodName") → api name.
const CSHARP_CALLEE_APIS: &[(&str, &str)] = &[
    ("RSA.Create", "System.Security.Cryptography.RSA.Create"),
    ("ECDsa.Create", "System.Security.Cryptography.ECDsa.Create"),
    (
        "ECDiffieHellman.Create",
        "System.Security.Cryptography.ECDsa.Create",
    ),
    ("Aes.Create", "System.Security.Cryptography.Aes.Create"),
    (
        "TripleDES.Create",
        "System.Security.Cryptography.TripleDES.Create",
    ),
    ("DES.Create", "System.Security.Cryptography.DES.Create"),
    ("SHA1.Create", "System.Security.Cryptography.SHA1.Create"),
    (
        "SHA256.Create",
        "System.Security.Cryptography.SHA256.Create",
    ),
    (
        "SHA512.Create",
        "System.Security.Cryptography.SHA512.Create",
    ),
    ("MD5.Create", "System.Security.Cryptography.MD5.Create"),
    (
        "RandomNumberGenerator.Create",
        "System.Security.Cryptography.RandomNumberGenerator.Create",
    ),
    (
        "RandomNumberGenerator.GetBytes",
        "System.Security.Cryptography.RandomNumberGenerator.Create",
    ),
    (
        "RandomNumberGenerator.Fill",
        "System.Security.Cryptography.RandomNumberGenerator.Create",
    ),
];

/// C# `new Foo()` constructors.
const CSHARP_CTOR_APIS: &[(&str, &str)] = &[
    (
        "RijndaelManaged",
        "System.Security.Cryptography.RijndaelManaged.new",
    ),
    (
        "MLKemKeyGenerationParameters",
        "Org.BouncyCastle.Crypto.Parameters.MLKemKeyGenerationParameters.new",
    ),
    (
        "MLDsaKeyGenerationParameters",
        "Org.BouncyCastle.Crypto.Parameters.MLDsaKeyGenerationParameters.new",
    ),
];

fn match_csharp_callee(callee: &str) -> Option<(String, HashMap<String, ArgValue>)> {
    let api = lookup(CSHARP_CALLEE_APIS, callee)?;
    Some((api.into(), HashMap::new()))
}

fn match_csharp_ctor(class_name: &str) -> Option<(String, HashMap<String, ArgValue>)> {
    let api = lookup(CSHARP_CTOR_APIS, class_name)?;
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
        (Language::Go, "jwt.NewWithClaims") => {
            // NewWithClaims(jwt.SigningMethodRS256, claims) — arg 0 is a
            // selector whose field names the signing method.
            if let Some(alg) = nth_arg_selector_field(args_node, 0, source) {
                out.insert("alg".into(), ArgValue::Str(alg));
            }
        }
        (Language::Go, "circl/sign/slhdsa.GenerateKey") => {
            // GenerateKey(random, slhdsa.SHA2_128s) — arg 1 is a selector
            // whose field names the parameter set. A variable there (an ID
            // computed or passed through) captures nothing and the classify
            // layer degrades to slh-dsa-unattributed.
            if let Some(id) = nth_arg_selector_field(args_node, 1, source) {
                out.insert("id".into(), ArgValue::Str(id));
            }
        }
        (Language::Python, "hashlib.new") => {
            // hashlib.new("md5") — the name is only knowable when it is a
            // literal. A variable yields no capture, and the classify layer
            // then has nothing to assert.
            if let Some(name) = nth_arg_string(args_node, 0, source) {
                out.insert("name".into(), ArgValue::Str(name));
            }
        }
        (Language::Python, "cryptography.hazmat.ciphers.Cipher") => {
            // Cipher(algorithms.TripleDES(key), modes.CBC(iv))
            if let Some(algo) = nth_arg_call_attr(args_node, 0, source) {
                out.insert("algo".into(), ArgValue::Str(algo));
            }
            if let Some(mode) = nth_arg_call_attr(args_node, 1, source) {
                out.insert("mode".into(), ArgValue::Str(mode));
            }
        }
        (Language::Python, "ssl.SSLContext") => {
            // ssl.SSLContext(ssl.PROTOCOL_TLSv1)
            if let Some(proto) = nth_arg_attr_name(args_node, 0, source) {
                out.insert("proto".into(), ArgValue::Str(proto));
            }
        }
        (Language::Python, "jwt.encode") => {
            // jwt.encode(payload, key, algorithm="RS256")
            if let Some(alg) = python_keyword_string(args_node, "algorithm", source) {
                out.insert("alg".into(), ArgValue::Str(alg));
            }
        }
        (Language::Python, "Crypto.PublicKey.RSA.generate") => {
            if let Some(bits) = nth_arg_int(args_node, 0, source) {
                out.insert("bits".into(), ArgValue::Int(bits));
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
        (Language::C | Language::Cpp, "openssl.RSA_generate_key") => {
            // RSA_generate_key(bits, e, callback, cb_arg) — bits is arg 0
            if let Some(bits) = nth_arg_int(args_node, 0, source) {
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
        (Language::C | Language::Cpp, "liboqs.OQS_KEM_new" | "liboqs.OQS_SIG_new") => {
            // OQS_KEM_new(OQS_KEM_alg_ml_kem_768) / OQS_SIG_new(OQS_SIG_alg_ml_dsa_65)
            // — arg 0 is the algorithm-name macro, a bare identifier.
            // `nth_arg_call_ident` already falls back to a plain identifier
            // when the argument isn't a call, which is exactly this shape.
            if let Some(alg) = nth_arg_call_ident(args_node, 0, source) {
                out.insert("alg".into(), ArgValue::Str(alg));
            }
        }
        (
            Language::CSharp,
            "Org.BouncyCastle.Crypto.Parameters.MLKemKeyGenerationParameters.new"
            | "Org.BouncyCastle.Crypto.Parameters.MLDsaKeyGenerationParameters.new",
        ) => {
            // new MLKemKeyGenerationParameters(random, MLKemParameters.ml_kem_768)
            // new MLDsaKeyGenerationParameters(random, MLDsaParameters.ml_dsa_65)
            // arg 1 is a member access naming the static parameter-set field;
            // the OID-lookup overload passes an expression here instead, and a
            // variable is always possible, so this can legitimately capture
            // nothing.
            if let Some(paramset) = nth_csharp_arg_member_access_name(args_node, 1, source) {
                out.insert("paramset".into(), ArgValue::Str(paramset));
            }
        }
        (Language::Rust, "rsa.RsaPrivateKey.new") => {
            // RsaPrivateKey::new(rng, bits) — bits is arg 1
            if let Some(bits) = nth_arg_int(args_node, 1, source) {
                out.insert("bits".into(), ArgValue::Int(bits));
            }
        }
        (Language::Rust, "openssl.Rsa.generate") => {
            // Rsa::generate(bits) — single positional argument
            if let Some(bits) = nth_arg_int(args_node, 0, source) {
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
        (
            Language::JavaScript | Language::TypeScript,
            "webcrypto.subtle.generateKey" | "webcrypto.subtle.sign",
        ) => {
            // WebCrypto argument 0 is the algorithm: either a bare name string
            // (`subtle.sign('Ed25519', …)`) or an object whose `name` property
            // carries it (`{ name: 'ML-DSA-65' }`). Everything else — a
            // variable, a spread, a property read — is not knowable from this
            // expression, and we insert no `alg` capture so the classify layer
            // falls through to the unattributed arm rather than guessing.
            if let Some(alg) = js_arg_algorithm_name(args_node, 0, source) {
                out.insert("alg".into(), ArgValue::Str(alg));
            }
            // Parameters that pin down which member of a family this is.
            // `namedCurve` selects the ECDSA/ECDH curve, `hash` selects the
            // RSA signature/OAEP variant, `length` the AES key size.
            for (prop, capture) in [("namedCurve", "curve"), ("hash", "hash")] {
                if let Some(v) = js_object_arg_prop(args_node, 0, prop, source) {
                    out.insert(capture.into(), ArgValue::Str(v));
                }
            }
            if let Some(len) = js_object_arg_prop(args_node, 0, "length", source)
                && let Ok(n) = len.parse::<i64>()
            {
                out.insert("length".into(), ArgValue::Int(n));
            }
        }
        (Language::JavaScript | Language::TypeScript, "jsonwebtoken.jwt.sign") => {
            // Phase 17 — jwt.sign(payload, key, options?) disambiguation.
            //   - key (arg 1): if a string literal → HMAC default.
            //                  otherwise → non-string (RSA/EC/HMAC-from-Buffer).
            //   - options (arg 2): if present and carries `algorithm: 'XX'`,
            //                      the explicit algorithm wins.
            let key_kind = match nth_real_arg_kind(args_node, 1) {
                Some("string") => "string",
                Some(_) => "non-string",
                None => "unknown",
            };
            out.insert("key_kind".into(), ArgValue::Str(key_kind.into()));
            if let Some(alg) = js_object_arg_prop(args_node, 2, "algorithm", source) {
                out.insert("algorithm".into(), ArgValue::Str(alg));
            }
        }
        _ => {}
    }
}

/// Return the Nth real argument node of an `arguments` list, skipping the
/// punctuation and comment children tree-sitter interleaves.
fn nth_real_arg(args: Node<'_>, n: usize) -> Option<Node<'_>> {
    let mut cursor = args.walk();
    args.children(&mut cursor)
        .filter(|c| is_real_arg(*c))
        .nth(n)
}

/// Phase 17 — return the tree-sitter kind of the Nth real argument in an
/// `arguments` node, normalised to one of: "string", "identifier", "object",
/// "call", "other". Used by `jwt.sign` to distinguish a string-secret HMAC
/// call from a Buffer/KeyObject RSA call.
fn nth_real_arg_kind(args: Node<'_>, n: usize) -> Option<&'static str> {
    Some(match nth_real_arg(args, n)?.kind() {
        "string" | "string_fragment" | "template_string" => "string",
        "identifier" => "identifier",
        "object" | "object_expression" => "object",
        "call_expression" => "call",
        _ => "other",
    })
}

/// Strip the quote characters a JS/TS string literal can be written with.
fn unquote_js(s: &str) -> String {
    s.trim_matches(|c| c == '"' || c == '\'' || c == '`')
        .to_string()
}

/// Read property `key` off the object literal at argument position `n`.
///
/// Handles both shapes the WebCrypto and jsonwebtoken option objects use for a
/// value: a plain literal (`hash: "SHA-256"`, `length: 256`) and a nested
/// algorithm object (`hash: { name: "SHA-256" }`), which is resolved to its
/// `name`. Returns None when the argument is not an object literal, the key is
/// absent, or the value is a variable — in which case the caller records no
/// capture and the classify layer must not assume a value.
fn js_object_arg_prop(args: Node<'_>, n: usize, key: &str, source: &[u8]) -> Option<String> {
    let arg = nth_real_arg(args, n)?;
    if !matches!(arg.kind(), "object" | "object_expression") {
        return None;
    }
    js_object_prop(arg, key, source)
}

fn js_object_prop(obj: Node<'_>, key: &str, source: &[u8]) -> Option<String> {
    let mut cursor = obj.walk();
    for prop in obj.children(&mut cursor) {
        if !matches!(prop.kind(), "pair" | "property") {
            continue;
        }
        let prop_key = prop
            .child_by_field_name("key")
            .map(|k| unquote_js(&node_text(k, source)));
        if prop_key.as_deref() != Some(key) {
            continue;
        }
        let value = prop.child_by_field_name("value")?;
        return match value.kind() {
            "string" | "string_fragment" | "template_string" | "number" => {
                Some(unquote_js(&node_text(value, source)))
            }
            // `{ name: "ECDSA", hash: { name: "SHA-256" } }`
            "object" | "object_expression" => js_object_prop(value, "name", source),
            _ => None,
        };
    }
    None
}

/// Resolve the algorithm name of a WebCrypto call's algorithm argument.
///
/// WebCrypto accepts either a bare name (`subtle.sign('Ed25519', …)`) or an
/// algorithm object (`{ name: 'ML-DSA-65', … }`). Anything else is a variable
/// and yields None, which is the signal that the algorithm is not knowable
/// from this expression.
fn js_arg_algorithm_name(args: Node<'_>, n: usize, source: &[u8]) -> Option<String> {
    let arg = nth_real_arg(args, n)?;
    match arg.kind() {
        "string" | "string_fragment" | "template_string" => {
            Some(unquote_js(&node_text(arg, source)))
        }
        "object" | "object_expression" => js_object_prop(arg, "name", source),
        _ => None,
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
        | "java.security.MessageDigest.getInstance"
        | "java.security.Signature.getInstance"
        | "javax.crypto.KEM.getInstance" => {
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

/// Field name of a `pkg.Field` selector at argument position `n`.
/// `jwt.NewWithClaims(jwt.SigningMethodRS256, …)` → `SigningMethodRS256`.
fn nth_arg_selector_field(args: Node<'_>, n: usize, source: &[u8]) -> Option<String> {
    let arg = nth_real_arg(args, n)?;
    if arg.kind() != "selector_expression" {
        return None;
    }
    Some(node_text(arg.child_by_field_name("field")?, source))
}

/// C# field name of a `TypeName.field` member access at argument position `n`.
/// `new MLKemKeyGenerationParameters(random, MLKemParameters.ml_kem_768)` →
/// `ml_kem_768`. C# wraps every argument in an `argument` node (tree-sitter-
/// c-sharp's `argument_list` has no bare-expression children the way Go's
/// `argument_list` does), so this unwraps that layer before matching
/// `member_access_expression` the same way `nth_arg_selector_field` does for
/// Go's `selector_expression`.
fn nth_csharp_arg_member_access_name(args: Node<'_>, n: usize, source: &[u8]) -> Option<String> {
    let arg = nth_real_arg(args, n)?;
    let expr = if arg.kind() == "argument" {
        arg.named_child(0)?
    } else {
        arg
    };
    if expr.kind() != "member_access_expression" {
        return None;
    }
    Some(node_text(expr.child_by_field_name("name")?, source))
}

/// Attribute name of a `mod.Attr(...)` call at argument position `n`.
/// `Cipher(algorithms.TripleDES(key), …)` → `TripleDES`.
fn nth_arg_call_attr(args: Node<'_>, n: usize, source: &[u8]) -> Option<String> {
    let arg = nth_real_arg(args, n)?;
    if arg.kind() != "call" {
        return None;
    }
    let function = arg.child_by_field_name("function")?;
    if function.kind() != "attribute" {
        return None;
    }
    Some(node_text(
        function.child_by_field_name("attribute")?,
        source,
    ))
}

/// Attribute name of a bare `mod.NAME` attribute at argument position `n`.
/// `ssl.SSLContext(ssl.PROTOCOL_TLSv1)` → `PROTOCOL_TLSv1`.
fn nth_arg_attr_name(args: Node<'_>, n: usize, source: &[u8]) -> Option<String> {
    let arg = nth_real_arg(args, n)?;
    if arg.kind() != "attribute" {
        return None;
    }
    Some(node_text(arg.child_by_field_name("attribute")?, source))
}

/// Value of a string-literal keyword argument, quotes stripped.
fn python_keyword_string(args: Node<'_>, name: &str, source: &[u8]) -> Option<String> {
    let mut cursor = args.walk();
    for child in args.children(&mut cursor) {
        if child.kind() != "keyword_argument" {
            continue;
        }
        let kw_name = child.child_by_field_name("name")?;
        if node_text(kw_name, source) != name {
            continue;
        }
        let kw_val = child.child_by_field_name("value")?;
        if kw_val.kind() != "string" {
            return None;
        }
        return Some(
            node_text(kw_val, source)
                .trim_matches(|c| c == '"' || c == '\'')
                .to_string(),
        );
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
    // Clamp to the node's FIRST LINE.
    //
    // The snippet is only ever shown as a single line, but this used to copy
    // the entire matched subtree. For nested calls that is quadratic: 3000
    // nested crypto.createHash() calls allocated ~225 MB from a 57 KB file,
    // because each of the 3000 matches copied the whole remaining tree.
    let start = node.start_byte().min(source.len());
    let end = node.end_byte().min(source.len());
    if start >= end {
        return String::new();
    }
    let slice = &source[start..end];
    let cut = slice
        .iter()
        .position(|&b| b == b'\n')
        .unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..cut])
        .trim_end()
        .to_string()
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
///   MapEntry > TestAssertion > RegistryLookup > StructLiteral > Call >
///   StringConstant > Default
/// - Test detection is name-based on the call target (require.Equal,
///   assert.Equal, etc.) — language-specific lists.
pub(crate) fn classify_site_context(
    node: Node<'_>,
    source: &[u8],
    language: Language,
) -> quipuu_core::SiteContext {
    use quipuu_core::SiteContext;

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
    // but the map-key semantics dominate. A `map.put(k, v)` call is the same
    // table written in Java's spelling, so it lands here too.
    if chain.iter().any(|p| {
        matches!(
            p.kind(),
            "keyed_element" | "key_value_expression" | "pair" | "dictionary"
        )
    }) {
        return SiteContext::MapEntry;
    }
    if enclosing_callee_matches(&chain, source, is_map_insert_callee) {
        return SiteContext::MapEntry;
    }

    // Priority 2: TestAssertion. Walk up looking for argument_list whose
    // call_expression's callee is a known test helper.
    if enclosing_callee_matches(&chain, source, |callee| {
        is_test_assertion_callee(callee, language)
    }) {
        return SiteContext::TestAssertion;
    }

    // Priority 3: RegistryLookup. A lookup call names an algorithm in order
    // to fetch its descriptor; it performs no cryptography. `ES384()` in
    // jwx's `func ES384() SignatureAlgorithm { return
    // lookupBuiltinSignatureAlgorithm("ES384") }` signs nothing, and neither
    // does `v, ok := jwa.LookupSignatureAlgorithm("PS256")`.
    //
    // The result NOT being consumed by an enclosing call is what separates
    // retrieval from configuration: `jwt.New(getMethod("RS256"))` does select
    // RS256 for a token at that line, so it stays a Call. Only the immediate
    // parent counts — climbing further would let the `t.Run(…, func(){…})`
    // wrapper around a lookup in a test reinstate it.
    for p in &chain {
        if matches!(p.kind(), "argument_list" | "arguments")
            && let Some(call) = p.parent()
            && let Some(callee) = callee_of(call)
            && is_registry_lookup_callee(&node_text(callee, source))
        {
            let consumed_by_a_call = call
                .parent()
                .is_some_and(|q| matches!(q.kind(), "argument_list" | "arguments"));
            if !consumed_by_a_call {
                return SiteContext::RegistryLookup;
            }
        }
    }

    // Priority 4: Comparison. Naming an algorithm in order to test a value
    // against it selects a branch and computes nothing — the operation the
    // branch guards cites its own line. Both operands are comparison
    // operands, so `alg.equals(JWSAlgorithm.PS256)` and
    // `JWSAlgorithm.HS512.equals(alg)` are the same site, and an equality
    // method reached through either field is enough on its own.
    if chain.iter().any(|p| {
        p.kind() == "binary_expression"
            && p.child_by_field_name("operator")
                .is_some_and(|op| matches!(node_text(op, source).as_str(), "==" | "!="))
    }) {
        return SiteContext::Comparison;
    }
    for p in &chain {
        if matches!(p.kind(), "method_invocation" | "call_expression")
            && let Some(callee) = callee_of(*p)
            && is_equality_callee(&node_text(callee, source))
        {
            return SiteContext::Comparison;
        }
    }

    // Priority 5: CollectionElement. A supported-algorithm set —
    // `algs.add(JWSAlgorithm.PS384)`, `Arrays.asList(HS512, HS384, HS256)` —
    // declares which algorithms the surrounding class can handle. That is a
    // capability, not a use; nothing is signed, wrapped or hashed at the line.
    if chain.iter().any(|p| p.kind() == "array_initializer")
        || enclosing_callee_matches(&chain, source, is_collection_membership_callee)
    {
        return SiteContext::CollectionElement;
    }

    // Priority 6: StructLiteral, but ONLY when the composite_literal's type
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

    // Priority 7: Call. Any argument_list we didn't classify as TestAssertion,
    // RegistryLookup, Comparison or CollectionElement is a regular call site —
    // UNLESS the literal sits inside
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

    // Priority 8: StringConstant. const/var declarations — but ONLY when
    // the literal is a DIRECT child (via expression_list / spec). If the
    // literal sits inside a composite_literal that's inside the var_spec
    // (e.g. `var x = []string{"RS256"}`), the array semantics dominate and
    // we don't want to classify the inner element as a StringConstant.
    //
    // `local_variable_declaration` / `field_declaration` are the Java
    // spellings of the same thing: `JWSAlgorithm ns = JWSAlgorithm.RS384;`
    // binds an algorithm exactly as `const RS256 = "RS256"` does. Without
    // them every Java enum reference outside a call reads as Default, which
    // is indistinguishable from "we did not look".
    let has_composite_in_chain = chain.iter().any(|p| p.kind() == "composite_literal");
    if !has_composite_in_chain
        && chain.iter().any(|p| {
            matches!(
                p.kind(),
                "const_spec"
                    | "var_spec"
                    | "const_declaration"
                    | "var_declaration"
                    | "local_variable_declaration"
                    | "field_declaration"
            )
        })
    {
        return SiteContext::StringConstant;
    }

    SiteContext::Default
}

/// Recognise registry-retrieval callees so SiteContext can mark their
/// arguments as [`SiteContext::RegistryLookup`].
///
/// Deliberately one shape, not a table of library function names: a callee
/// whose own name begins with `lookup` is announcing that it retrieves rather
/// than computes, in any language and any library. That covers every instance
/// in corpus B — jwx's `jwa.LookupSignatureAlgorithm`,
/// `lookupBuiltinSignatureAlgorithm`, `LookupContentEncryptionAlgorithm`,
/// `LookupKeyEncryptionAlgorithm` — without a list that goes stale.
///
/// Names like `Get*` and `Parse*` are deliberately NOT included. They are
/// ambiguous by usage rather than by name: golang-jwt's
/// `jwt.New(jwt.GetSigningMethod("RS256"))` selects the algorithm a token is
/// signed with, and suppressing it would lose a real signing site.
fn is_registry_lookup_callee(callee: &str) -> bool {
    callee
        .rsplit(['.', ':'])
        .next()
        .unwrap_or(callee)
        .to_ascii_lowercase()
        .starts_with("lookup")
}

/// The callee node of a call, across the two field spellings tree-sitter uses.
///
/// Go, JavaScript and Rust expose the whole callee expression under
/// `function`. Java's `method_invocation` splits it into `object` + `name`,
/// so a `function` lookup returns `None` at every Java call site — which is
/// why the TestAssertion and RegistryLookup arms above, both written against
/// `function`, had never once fired on Java.
fn callee_of(call: Node<'_>) -> Option<Node<'_>> {
    call.child_by_field_name("function")
        .or_else(|| call.child_by_field_name("name"))
}

/// True when some enclosing call in `chain` has a callee the predicate accepts
/// and the matched node sits in that call's argument list.
fn enclosing_callee_matches(
    chain: &[Node<'_>],
    source: &[u8],
    predicate: impl Fn(&str) -> bool,
) -> bool {
    chain.iter().any(|p| {
        matches!(p.kind(), "argument_list" | "arguments")
            && p.parent()
                .and_then(callee_of)
                .is_some_and(|callee| predicate(&node_text(callee, source)))
    })
}

/// Last dotted / path segment of a callee, generics stripped — `Arrays.asList`
/// and `asList` have to answer the same.
fn callee_head(callee: &str) -> &str {
    callee
        .rsplit(['.', ':'])
        .next()
        .unwrap_or(callee)
        .split('<')
        .next()
        .unwrap_or(callee)
}

/// Recognise equality tests. `equals` is Java's `==` for objects and the only
/// spelling the JOSE stacks use to dispatch on an algorithm — jose4j's
/// identifiers are `String`s, so the case-insensitive form is the same test.
/// `compareTo` is deliberately absent: it orders as often as it compares, and
/// no corpus site reaches an algorithm name through it.
fn is_equality_callee(callee: &str) -> bool {
    matches!(callee_head(callee), "equals" | "equalsIgnoreCase")
}

/// Recognise collection-membership callees — the shape that builds a
/// `SUPPORTED_ALGORITHMS` set. Membership, not computation: adding an
/// algorithm to a set and asking whether a set contains one are both
/// statements about a capability.
fn is_collection_membership_callee(callee: &str) -> bool {
    matches!(
        callee_head(callee),
        "add" | "addAll" | "asList" | "of" | "contains" | "containsAll" | "remove"
    )
}

/// Recognise map-insertion callees. `map.put(alg, hash)` is the call spelling
/// of the keyed-literal table [`SiteContext::MapEntry`] already covers.
fn is_map_insert_callee(callee: &str) -> bool {
    matches!(callee_head(callee), "put" | "putAll" | "putIfAbsent")
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
        // `ExpectNotNull` is deliberately absent: wolfssl's own test suite
        // wraps genuine, successful crypto calls in it (e.g.
        // `ExpectNotNull(rsa = RSA_generate_key(2048, ...))`), so treating it
        // as low-signal would suppress true positives. `ExpectNull` wraps a
        // call the test requires to FAIL (invalid params, unsupported build),
        // which is the same "asserted to fail" shape PyJWT's `pytest.raises`
        // wrapping already gets scored FP for by hand — see `#Y29`.
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
                | "ExpectNull"
        ),
        Language::CSharp => matches!(
            head,
            "Equal" | "True" | "False" | "Same" | "NotEqual" | "AreEqual"
        ),
    }
}

/// Process-wide compiled-regex cache.
///
/// `apply_classify` runs once per (raw match x classify rule). The Go pack
/// alone has 44 classify rules, so a file yielding 10k matches previously
/// compiled ~440k regexes — the patterns are identical every time, and
/// compilation dominates the scan. Caching makes this linear in DISTINCT
/// patterns (a few hundred, fixed by the rule packs) instead of quadratic in
/// matches x rules.
fn cached_regex(pattern: &str) -> Result<Arc<regex::Regex>, ScanError> {
    static CACHE: OnceLock<RwLock<HashMap<String, Arc<regex::Regex>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| RwLock::new(HashMap::new()));

    // A poisoned lock means another thread panicked mid-insert. The cache holds
    // no invariant worth preserving, so recover rather than propagating.
    if let Ok(map) = cache.read()
        && let Some(re) = map.get(pattern)
    {
        return Ok(Arc::clone(re));
    }
    let compiled = Arc::new(regex::Regex::new(pattern)?);
    if let Ok(mut map) = cache.write() {
        map.insert(pattern.to_string(), Arc::clone(&compiled));
    }
    Ok(compiled)
}

/// Try every classify rule's `when` against a raw match. On the first hit,
/// look up the algorithm record and build a [`Finding`].
fn apply_classify(
    raw: &RawMatch,
    rule: &ClassifyRule,
    algorithms: &AlgorithmTable,
    path: &Path,
    imports: &[String],
) -> Result<Option<Finding>, ScanError> {
    // 1. API regex
    let api_re = cached_regex(&rule.when.api)?;
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

    // 1.75. File-scope import qualification. When the rule names a header
    // set, some import in the file holding the match must match one of them.
    // This is what stops an identifier shared by two libraries from being
    // attributed to whichever one the rule was written for.
    if let Some(required) = &rule.when.imports {
        let mut qualified = false;
        for pattern in required {
            let re = cached_regex(pattern)?;
            if imports.iter().any(|i| re.is_match(i)) {
                qualified = true;
                break;
            }
        }
        if !qualified {
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
            let re = cached_regex(&r.regex)?;
            Ok(re.is_match(s))
        }
        // Cross-type mismatches just fail-soft.
        _ => Ok(false),
    }
}

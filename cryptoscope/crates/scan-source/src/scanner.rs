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
    })
}

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
    // JS/TS member expression callees: "object.method"
    let api = match callee {
        "crypto.createCipheriv" => "node:crypto.createCipheriv",
        "crypto.createHash" => "node:crypto.createHash",
        "crypto.generateKeyPair" | "crypto.generateKeyPairSync" => "node:crypto.generateKeyPair",
        "crypto.createSign" => "node:crypto.createSign",
        "subtle.generateKey" => "webcrypto.subtle.generateKey",
        "subtle.sign" => "webcrypto.subtle.sign",
        "jwt.sign" => "jsonwebtoken.jwt.sign",
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
    // Rust scoped paths — tree-sitter renders them as "Type::method"
    // when the path has a single segment (local import) or the full
    // scoped_identifier text for deeper paths.
    let api = match callee {
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
        "ClientConfig::builder" => "rustls.ClientConfig.builder",
        _ => return None,
    };
    Some((api.into(), HashMap::new()))
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

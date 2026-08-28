//! An emitter may not name a parameter its input does not determine.
//!
//! P3 guarantees the `file:line` on a finding is real. Nothing guaranteed the
//! *algorithm name* at that line was, and the gap was fixed pairwise four
//! times before anyone ranked the class:
//!
//!   * `9e60ffe` — Diffie-Hellman group sizes the DH OIDs do not carry;
//!   * a later pass — Rust crate paths;
//!   * `sha512WithRSAEncryption` → `rsa-pkcs1-sha512-4096`, which put
//!     `classicalSecurityLevel: 152` in the CBOM for any certificate a CA had
//!     signed with SHA-512, whatever its real modulus;
//!   * `ml-kem` in a `Cargo.toml` → `ml-kem-768`, which handed a codebase that
//!     had migrated to ML-KEM-1024 — the only set CNSA 2.0 approves — a
//!     non-compliant High and a red CI.
//!
//! Each of those was fixed where it was found, and the class regrew in a file
//! nobody re-checked. So this is not another pairwise fix. It is the rule:
//!
//! > Where the input is silent, emit the family id and let the algorithm table
//! > carry the unsized row.
//!
//! # What counts as naming a parameter
//!
//! An algorithm-id's parameters are the hyphen-separated segments after the
//! first that are entirely a number — `2048` in `rsa-2048`, `768` in
//! `ml-kem-768` — optionally with a `p` prefix (`p256`) or an SLH-DSA `s`/`f`
//! suffix (`128s`). `sha256` inside `rsa-pkcs1-sha256` is not one: it is a
//! digest the input does name, and it is not a bare number.
//!
//! An emitter justifies a parameter by containing that number in its own
//! *matching* text — the query, the `when` clause, the package pattern. For a
//! classify rule that is the rule block plus every extract block whose `api`
//! it matches, so `elliptic.P256()` justifies `ecdsa-p256` while `JWT RS256`
//! does not justify `rsa-pkcs1-sha256-2048`. Prose fields (`message`, `note`,
//! `description`) and comments are stripped first: moving the size into the
//! message is the fix, and it must not also be the excuse.
//!
//! Where the parameter really is determined but no digit shows it — `ES512` is
//! ECDSA on P-521 — the rule carries `parameter_source` naming the standard
//! that says so. Four rules do.
//!
//! The check is not trying to prove a parameter is *correct*. It catches the
//! case where the parameter appears nowhere in the input at all, which is what
//! every instance of the class has been.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root resolves")
}

fn read(root: &Path, rel: &str) -> String {
    fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// The numbers an algorithm-id asserts about its own parameters.
fn asserted_parameters(id: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for seg in id.split('-').skip(1) {
        let seg = seg.strip_prefix('p').unwrap_or(seg);
        let seg = seg
            .strip_suffix('s')
            .or_else(|| seg.strip_suffix('f'))
            .unwrap_or(seg);
        if !seg.is_empty() && seg.chars().all(|c| c.is_ascii_digit()) {
            out.insert(seg.to_string());
        }
    }
    out
}

/// Prose fields, and comments. A number here is something we wrote about the
/// match, not something the match found — so they are stripped before the
/// evidence is read. Without this, "put the size in the message" would satisfy
/// the check while leaving the id exactly as wrong as it was.
const PROSE: &[&str] = &["message", "description", "note", "notes", "help_uri"];

fn strip_prose(text: &str) -> String {
    text.lines()
        .filter(|line| {
            let t = line.trim_start();
            if t.starts_with('#') || t.starts_with("//") {
                return false;
            }
            !PROSE.iter().any(|key| {
                t.strip_prefix(key)
                    .is_some_and(|rest| rest.trim_start().starts_with(['=', ':']))
            })
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Every number appearing in a block of emitter text.
fn numbers_in(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut cur = String::new();
    for c in text.chars() {
        if c.is_ascii_digit() {
            cur.push(c);
        } else if !cur.is_empty() {
            out.insert(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        out.insert(cur);
    }
    out
}

/// Split a TOML rule pack into its `[[extract]]` / `[[classify]]` blocks.
fn toml_blocks(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut cur: Vec<&str> = Vec::new();
    for line in text.lines() {
        if line.starts_with("[[") {
            if !cur.is_empty() {
                out.push(cur.join("\n"));
            }
            cur = vec![line];
        } else if !cur.is_empty() {
            cur.push(line);
        }
    }
    if !cur.is_empty() {
        out.push(cur.join("\n"));
    }
    out
}

fn field<'a>(block: &'a str, key: &str) -> Option<&'a str> {
    block.lines().find_map(|line| {
        let rest = line.strip_prefix(key)?.trim_start();
        let rest = rest.strip_prefix('=')?.trim_start();
        let rest = rest.strip_prefix('"')?;
        rest.split('"').next()
    })
}

/// One emitter site: what it emits, and the text that has to justify it.
struct Site {
    where_: String,
    algorithm_id: String,
    evidence: String,
    /// A cited reason the parameter is determined even though no digit in the
    /// match says so — `ES512` is ECDSA on P-521 by RFC 7518 § 3.4.
    parameter_source: Option<String>,
}

/// Classify rules, joined to the extract blocks whose `api` they match.
///
/// The join is the whole point: a rule pack is two layers, and the parameter a
/// classify arm may name is one the *extract* query captured.
fn rule_pack_sites(root: &Path, pack: &str) -> Vec<Site> {
    let rel = format!("crates/core/data/rules/{pack}.toml");
    let text = read(root, &rel);
    let blocks = toml_blocks(&text);

    let mut by_api: BTreeMap<&str, Vec<&String>> = BTreeMap::new();
    for block in &blocks {
        if block.starts_with("[[extract]]")
            && let Some(api) = field(block, "api")
        {
            by_api.entry(api).or_default().push(block);
        }
    }

    let mut sites = Vec::new();
    for block in &blocks {
        if !block.starts_with("[[classify]]") {
            continue;
        }
        let Some(algorithm_id) = field(block, "algorithm_id") else {
            continue;
        };
        let rule_id = field(block, "id").unwrap_or("(unnamed)");
        let mut evidence = block.clone();
        if let Some(pattern) = field(block, "when.api") {
            // `when.api` is a regex over extract `api` values. Matching it
            // properly needs a regex engine; a substring test on the literal
            // part is enough here and errs towards *more* evidence, which can
            // only make this check more permissive, never less.
            let literal: String = pattern
                .trim_start_matches('^')
                .trim_end_matches('$')
                .replace("\\\\", "\\")
                .replace("\\.", ".");
            for (api, api_blocks) in &by_api {
                let matches = api.contains(literal.trim_end_matches('$'))
                    || literal
                        .split(['(', ')', '|'])
                        .any(|part| !part.is_empty() && part.len() > 3 && api.contains(part));
                if matches {
                    for api_block in api_blocks {
                        evidence.push('\n');
                        evidence.push_str(api_block);
                    }
                }
            }
        }
        sites.push(Site {
            where_: format!("{rel} {rule_id}"),
            algorithm_id: algorithm_id.to_string(),
            evidence,
            parameter_source: field(block, "parameter_source").map(str::to_string),
        });
    }
    sites
}

/// Rust emitters that carry their evidence in the same struct literal — the
/// dependency catalogue and the TLS group tables.
fn struct_literal_sites(root: &Path, rel: &str) -> Vec<Site> {
    let text = read(root, rel);
    let mut sites = Vec::new();
    let mut block = String::new();
    for line in text.lines() {
        block.push_str(line);
        block.push('\n');
        if line.trim_end().ends_with('}') || line.trim_end().ends_with("},") {
            if let Some(algorithm_id) = field(&block, "        algorithm_id")
                .or_else(|| field(&block, "            algorithm_id"))
            {
                sites.push(Site {
                    where_: format!("{rel} {algorithm_id}"),
                    algorithm_id: algorithm_id.to_string(),
                    evidence: block.clone(),
                    parameter_source: None,
                });
            }
            block.clear();
        }
    }
    sites
}

/// The rule the whole file exists for.
#[test]
fn no_emitter_names_a_parameter_its_input_does_not_carry() {
    let root = workspace_root();

    let mut sites: Vec<Site> = Vec::new();
    for pack in [
        "cpp",
        "csharp",
        "go",
        "java",
        "javascript",
        "python",
        "rust",
    ] {
        sites.extend(rule_pack_sites(&root, pack));
    }
    sites.extend(struct_literal_sites(
        &root,
        "crates/scan-deps/src/catalogue.rs",
    ));
    sites.extend(struct_literal_sites(
        &root,
        "crates/scan-network/src/groups.rs",
    ));

    let mut invented: Vec<String> = Vec::new();
    let mut waived: Vec<&str> = Vec::new();
    for site in &sites {
        let asserted = asserted_parameters(&site.algorithm_id);
        if asserted.is_empty() {
            continue;
        }
        if let Some(source) = &site.parameter_source {
            // A waiver has to cite something. The one failure mode worse than
            // an invented parameter is an invented justification for one.
            assert!(
                source.len() >= 30,
                "{}: `parameter_source` must name where the parameter comes from, \
                 got {source:?}",
                site.where_,
            );
            waived.push(&site.where_);
            continue;
        }
        // The id itself is in the block; it cannot justify itself.
        let evidence = site
            .evidence
            .replace(&format!("\"{}\"", site.algorithm_id), " ");
        let available = numbers_in(&strip_prose(&evidence));
        let missing: Vec<&String> = asserted
            .iter()
            .filter(|p| !available.contains(*p))
            .collect();
        if !missing.is_empty() {
            invented.push(format!(
                "{} emits `{}` but its input never states {:?}",
                site.where_, site.algorithm_id, missing
            ));
        }
    }

    assert!(
        invented.is_empty(),
        "these emitters name a parameter the matched input does not carry:\n  {}\n\n\
         Emit the family id instead and let the algorithm table carry the unsized row \
         (rsa-unattributed, ml-kem-unattributed, rsa-pkcs1-sha256, …). Do not add the \
         number to the message to satisfy this check — put it in the message *and* take \
         it out of the id.",
        invented.join("\n  "),
    );
    println!(
        "checked {} emitter sites; {} carry a cited parameter_source: {waived:?}",
        sites.len(),
        waived.len(),
    );
}

/// The OID table states, per row, whether the OID pins the full
/// parameterisation. A row that says it does not may not resolve to a
/// parameterised id.
///
/// This half cannot be textual: an OID *is* an opaque number, so nothing in
/// `2.16.840.1.101.3.4.4.2` looks like `768` even though it determines it. The
/// declaration is the evidence.
#[test]
fn a_family_level_oid_does_not_resolve_to_a_parameterised_id() {
    let root = workspace_root();
    let text = read(&root, "crates/core/data/oid-table.toml");
    let parsed: toml::Value = toml::from_str(&text).expect("oid table parses");
    let rows = parsed["oid"].as_array().expect("[[oid]] array");

    let mut bad: Vec<String> = Vec::new();
    for row in rows {
        let oid = row["oid"].as_str().expect("oid is a string");
        let algorithm_id = row["algorithm_id"].as_str().expect("algorithm_id");
        let determines = row
            .get("determines")
            .unwrap_or_else(|| panic!("{oid}: every row must declare `determines`"))
            .as_str()
            .expect("determines is a string");
        assert!(
            determines == "algorithm" || determines == "family",
            "{oid}: `determines` must be \"algorithm\" or \"family\", got {determines:?}",
        );
        if determines == "family" {
            let asserted = asserted_parameters(algorithm_id);
            if !asserted.is_empty() {
                bad.push(format!(
                    "{oid} determines the family only, but resolves to `{algorithm_id}`, \
                     which asserts {asserted:?}"
                ));
            }
        }
    }

    assert!(
        bad.is_empty(),
        "these OID rows assert a parameter the OID does not encode:\n  {}",
        bad.join("\n  "),
    );
    println!("checked {} OID rows", rows.len());
}

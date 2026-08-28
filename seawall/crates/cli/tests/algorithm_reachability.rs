//! Every algorithm-table id is reachable from an enumerated emitter, or says
//! why it is not.
//!
//! Two published reachability counts for this table were wrong — 24, then 2 —
//! and both were wrong the same way: the emitter set was assumed rather than
//! enumerated. The first sweep read only `data/rules/*.toml`; the second added
//! three more emitters and still missed `scan-network/src/prober.rs`, which
//! emits its id directly rather than through `groups.rs`.
//!
//! So this gate does not check a number. It checks the *set*, in three
//! directions:
//!
//!   1. every table row is emitted by something, or carries an `undetectable`
//!      reason;
//!   2. no row carries an `undetectable` reason once something emits it, so
//!      the reason is retired rather than left to rot;
//!   3. no file outside `EMITTERS` assigns a literal algorithm id — the check
//!      that fails when a sixth emitter appears, which is the failure the two
//!      wrong counts needed and did not have.
//!
//! This test lives in `cli` because that is the only crate that can see every
//! other one. It reads source text rather than calling APIs: direction 3 is a
//! statement about the repository, not about any loaded value.
//!
//! `scan-certs` was a twelfth emitter the first eleven-emitter sweep could not
//! see: it resolved RSA by modulus length through a `match` whose arms were
//! bare string literals, so direction 3 walked past it. It is enumerated now
//! because those arms became a table with an `algorithm_id` field — the shape
//! this check can read.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

/// The complete set of places an `algorithm_id` can originate.
///
/// `data/policies/*.toml` is deliberately absent. A policy names an algorithm
/// in order to forbid it; a disallow list cannot produce a finding that
/// carries the id. Counting one as an emitter is what hid `fn-dsa-512` in the
/// previous sweep.
const EMITTERS: &[&str] = &[
    "crates/core/data/oid-table.toml",
    "crates/core/data/rules/cpp.toml",
    "crates/core/data/rules/csharp.toml",
    "crates/core/data/rules/go.toml",
    "crates/core/data/rules/java.toml",
    "crates/core/data/rules/javascript.toml",
    "crates/core/data/rules/python.toml",
    "crates/core/data/rules/rust.toml",
    "crates/scan-certs/src/lib.rs",
    "crates/scan-deps/src/catalogue.rs",
    "crates/scan-network/src/groups.rs",
    "crates/scan-network/src/prober.rs",
];

/// The one emitted id with no table row: `scan-deps` uses it for a dependency
/// whose manifest names a crypto library but not an algorithm.
const SENTINEL_WITHOUT_A_ROW: &str = "unknown";

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root resolves")
}

/// Every `algorithm_id = "…"` / `algorithm_id: "…"` literal in `src`.
///
/// Deliberately textual and deliberately dumb: it matches the TOML rule packs
/// and the Rust catalogues with one pass, and anything it cannot read it does
/// not silently skip — an id built at runtime is not a literal and would fail
/// direction 1 by being absent, which is the safe way round.
fn literal_ids(src: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for (idx, _) in src.match_indices("algorithm_id") {
        let rest = &src[idx + "algorithm_id".len()..];
        let rest = rest.trim_start();
        let Some(rest) = rest.strip_prefix([':', '=']) else {
            continue;
        };
        let rest = rest.trim_start();
        let Some(rest) = rest.strip_prefix('"') else {
            continue;
        };
        let Some(end) = rest.find('"') else { continue };
        let id = &rest[..end];
        if !id.is_empty()
            && id
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.')
        {
            out.insert(id.to_string());
        }
    }
    out
}

/// Source text with any `#[cfg(test)]` tail removed. Fixture ids constructed
/// inside a test module are not shipped emitters.
fn without_test_modules(src: &str) -> &str {
    match src.find("#[cfg(test)]") {
        Some(i) => &src[..i],
        None => src,
    }
}

fn read(root: &Path, rel: &str) -> String {
    fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// Table rows keyed by id, with the `undetectable` reason when present.
fn table_rows(root: &Path) -> BTreeMap<String, Option<String>> {
    let text = read(root, "crates/core/data/algorithm-table.toml");
    let parsed: toml::Value = toml::from_str(&text).expect("algorithm table parses");
    parsed["algorithm"]
        .as_array()
        .expect("[[algorithm]] array")
        .iter()
        .map(|row| {
            (
                row["id"].as_str().expect("id is a string").to_string(),
                row.get("undetectable")
                    .map(|v| v.as_str().expect("undetectable is a string").to_string()),
            )
        })
        .collect()
}

fn emitted_ids(root: &Path) -> BTreeSet<String> {
    EMITTERS
        .iter()
        .flat_map(|rel| literal_ids(&read(root, rel)))
        .collect()
}

/// Directions 1 and 2: unreachable iff `undetectable`.
#[test]
fn every_algorithm_id_is_emitted_or_says_why_not() {
    let root = workspace_root();
    let rows = table_rows(&root);
    let emitted = emitted_ids(&root);

    let unreachable_without_reason: Vec<&str> = rows
        .iter()
        .filter(|(id, reason)| reason.is_none() && !emitted.contains(id.as_str()))
        .map(|(id, _)| id.as_str())
        .collect();
    assert!(
        unreachable_without_reason.is_empty(),
        "no emitter can produce these ids and no row says why they are carried: {unreachable_without_reason:?}\n\
         Either add an emitter, or add `undetectable = \"…\"` to the row.",
    );

    let reachable_with_a_stale_reason: Vec<&str> = rows
        .iter()
        .filter(|(id, reason)| reason.is_some() && emitted.contains(id.as_str()))
        .map(|(id, _)| id.as_str())
        .collect();
    assert!(
        reachable_with_a_stale_reason.is_empty(),
        "these rows are emitted now, so their `undetectable` reason is stale and must be removed: {reachable_with_a_stale_reason:?}",
    );

    let reasons: Vec<&str> = rows
        .iter()
        .filter(|(_, reason)| reason.is_some())
        .map(|(id, _)| id.as_str())
        .collect();
    println!(
        "checked {} algorithm ids against {} emitters: {} emitted, {} carried with a reason: {reasons:?}",
        rows.len(),
        EMITTERS.len(),
        rows.len() - reasons.len(),
        reasons.len(),
    );
}

/// Every emitted id resolves to a table row, so a typo in a rule pack is a
/// test failure rather than a finding nothing can classify.
#[test]
fn every_emitted_id_resolves_to_a_table_row() {
    let root = workspace_root();
    let rows = table_rows(&root);

    let dangling: Vec<String> = emitted_ids(&root)
        .into_iter()
        .filter(|id| id != SENTINEL_WITHOUT_A_ROW && !rows.contains_key(id))
        .collect();
    assert!(
        dangling.is_empty(),
        "emitted but absent from the algorithm table: {dangling:?}",
    );
}

/// Direction 3: the enumeration is complete.
#[test]
fn no_emitter_exists_outside_the_enumerated_set() {
    let root = workspace_root();
    let mut unenumerated: Vec<String> = Vec::new();
    let mut walked = 0usize;

    let mut stack = vec![root.join("crates")];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).expect("crates/ is readable") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                // `tests/` holds fixtures and assertions, not shipped emitters;
                // `target/` is build output.
                let name = path.file_name().unwrap_or_default().to_string_lossy();
                if name != "tests" && name != "target" {
                    stack.push(path);
                }
                continue;
            }
            let is_rust = path.extension().is_some_and(|e| e == "rs");
            let is_toml = path.extension().is_some_and(|e| e == "toml");
            if !is_rust && !is_toml {
                continue;
            }
            let rel = path
                .strip_prefix(&root)
                .expect("under root")
                .to_string_lossy()
                .replace('\\', "/");
            let text = fs::read_to_string(&path).unwrap_or_default();
            let text = if is_rust {
                without_test_modules(&text)
            } else {
                &text
            };
            walked += 1;
            if !literal_ids(text).is_empty() && !EMITTERS.contains(&rel.as_str()) {
                unenumerated.push(rel);
            }
        }
    }

    unenumerated.sort();
    assert!(
        unenumerated.is_empty(),
        "these files emit an algorithm id but are not in EMITTERS, so the reachability check above \
         was computed against an incomplete set: {unenumerated:?}\n\
         Add them to EMITTERS (or stop emitting ids from them) — do not adjust the reachability \
         counts without doing so.",
    );
    println!(
        "walked {walked} files under crates/; {} emitters",
        EMITTERS.len()
    );
}

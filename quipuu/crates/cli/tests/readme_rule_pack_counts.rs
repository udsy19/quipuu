//! `README.md` states the extract/classify rule-pack counts twice, in prose,
//! and nothing re-derived them: the "115 extract blocks and 675 classify arms"
//! sentence and the "93 classify arms vs. Java's 167" sentence both drifted
//! stale against the actual rule packs, independently, at least three times
//! across three consecutive days (`8dd1b4d`, `cfb1c27`, then `f4fa883` again 52
//! minutes after the second correction) — each `*.toml` rule-pack change
//! landed without anyone re-running the `grep -c '^\[\[classify\]\]'` the
//! numbers describe. This test runs it every build instead.
//!
//! Deliberately textual, like `algorithm_reachability.rs`'s `literal_ids`: it
//! counts `[[classify]]`/`[[extract]]` table headers at line start, the same
//! shape `grep -c '^\[\[classify\]\]'` matches, and compares against the two
//! README sentences by locating the digits immediately adjacent to fixed
//! anchor text, rather than trusting either number to have been kept in sync
//! by hand.

use std::fs;
use std::path::{Path, PathBuf};

const RULE_TOML_FILES: &[&str] = &[
    "crates/core/data/rules/cpp.toml",
    "crates/core/data/rules/csharp.toml",
    "crates/core/data/rules/go.toml",
    "crates/core/data/rules/java.toml",
    "crates/core/data/rules/javascript.toml",
    "crates/core/data/rules/python.toml",
    "crates/core/data/rules/rust.toml",
];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root resolves")
}

fn count_headers(text: &str, header: &str) -> usize {
    text.lines().filter(|line| line.trim() == header).count()
}

fn rule_pack_counts(root: &Path) -> Vec<(&'static str, usize, usize)> {
    RULE_TOML_FILES
        .iter()
        .map(|&rel| {
            let text = fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"));
            (
                rel,
                count_headers(&text, "[[extract]]"),
                count_headers(&text, "[[classify]]"),
            )
        })
        .collect()
}

fn classify_count_for(counts: &[(&'static str, usize, usize)], filename: &str) -> usize {
    counts
        .iter()
        .find(|(rel, _, _)| rel.ends_with(filename))
        .map(|(_, _, classify)| *classify)
        .unwrap_or_else(|| panic!("no rule pack named {filename}"))
}

/// The run of ASCII digits immediately before `needle` in `haystack`. Panics
/// naming the missing anchor if the sentence has been reworded, so this test
/// fails loudly on a rewrite rather than silently matching nothing.
fn number_before(haystack: &str, needle: &str) -> usize {
    let at = haystack.find(needle).unwrap_or_else(|| {
        panic!(
            "README.md no longer contains {needle:?} — update this test to match the new wording"
        )
    });
    let head = &haystack[..at];
    let digits: String = head
        .chars()
        .rev()
        .take_while(|c| c.is_ascii_digit())
        .collect::<Vec<char>>()
        .into_iter()
        .rev()
        .collect();
    digits
        .parse()
        .unwrap_or_else(|_| panic!("no digits immediately before {needle:?} in README.md"))
}

#[test]
fn readme_rule_pack_counts_match_the_rule_packs() {
    let root = workspace_root();
    let counts = rule_pack_counts(&root);

    let total_extract: usize = counts.iter().map(|(_, e, _)| e).sum();
    let total_classify: usize = counts.iter().map(|(_, _, c)| c).sum();

    let readme = fs::read_to_string(root.join("../README.md")).expect("README.md readable");

    // "115 extract blocks and 675 classify arms across 7 files"
    let claimed_extract = number_before(&readme, " extract blocks and ");
    let claimed_classify_total = number_before(&readme, " classify arms across ");
    assert_eq!(
        claimed_extract, total_extract,
        "README.md's \"{{n}} extract blocks\" sentence says {claimed_extract}, but summing \
         `[[extract]]` headers across {RULE_TOML_FILES:?} gives {total_extract}",
    );
    assert_eq!(
        claimed_classify_total, total_classify,
        "README.md's \"{{n}} classify arms across 7 files\" sentence says {claimed_classify_total}, \
         but summing `[[classify]]` headers across {RULE_TOML_FILES:?} gives {total_classify}",
    );

    // "93 classify arms vs. Java's 181, C/C++'s 114, and C#'s 115"
    let go = classify_count_for(&counts, "go.toml");
    let java = classify_count_for(&counts, "java.toml");
    let cpp = classify_count_for(&counts, "cpp.toml");
    let csharp = classify_count_for(&counts, "csharp.toml");

    let claimed_go = number_before(&readme, " classify arms vs. Java's ");
    let claimed_java = number_before(&readme, ", C/C++'s ");
    let claimed_cpp = number_before(&readme, ", and C#'s ");
    let claimed_csharp = number_before(
        &readme,
        " — C/C++ grew past its earlier last-place position",
    );

    assert_eq!(claimed_go, go, "README.md's Go classify-arm count is stale");
    assert_eq!(
        claimed_java, java,
        "README.md's Java classify-arm count is stale"
    );
    assert_eq!(
        claimed_cpp, cpp,
        "README.md's C/C++ classify-arm count is stale"
    );
    assert_eq!(
        claimed_csharp, csharp,
        "README.md's C# classify-arm count is stale"
    );

    println!(
        "extract {total_extract}, classify {total_classify} across {} files; \
         go {go} java {java} cpp {cpp} csharp {csharp}",
        RULE_TOML_FILES.len(),
    );
}

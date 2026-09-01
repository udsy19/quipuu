//! `README.md` states the corpus B finding total twice, 38 lines apart: once
//! in the benchmark table's "Total findings" row, once as the denominator of
//! the audit-validated precision sentence ("out of `N`"). Nothing re-derived
//! one from the other, so ordinary rule-pack coverage commits landed against
//! the precision paragraph without anyone re-running the benchmark table —
//! `#Y84` found the two had drifted from 1056 to 1853 (a 75.5% gap) after two
//! days and two coverage cycles of silent divergence. `#Y84`'s own fix named
//! this exact check as the right follow-up so the gap can't reopen the same
//! way; this test is that follow-up.
//!
//! Deliberately textual, the same shape `readme_rule_pack_counts.rs` already
//! uses for the rule-pack-count sentences: locate the digits adjacent to
//! fixed anchor text rather than parsing the table or trusting either number
//! to have been kept in sync by hand.

use std::fs;
use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root resolves")
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
fn readme_benchmark_table_total_matches_the_precision_denominator() {
    let root = workspace_root();
    let readme = fs::read_to_string(root.join("../README.md")).expect("README.md readable");

    // "| Total findings | 1853 |"
    let table_total = number_before(&readme, " |\n| Projects scanned |");
    // "measured 2026-08-31 on 635 audited findings out of 1853, every one labelled"
    let precision_denominator = number_before(&readme, ", every one labelled by opening its cited");

    assert_eq!(
        table_total, precision_denominator,
        "README.md's benchmark table says \"Total findings | {table_total}\", but the \
         audit-validated precision sentence's \"out of {{n}}\" denominator says \
         {precision_denominator} — one was updated without the other. See `#Y84` in \
         03-Product/Backlog.md for why this drift recurs."
    );

    println!("benchmark table and precision denominator agree at {table_total}");
}

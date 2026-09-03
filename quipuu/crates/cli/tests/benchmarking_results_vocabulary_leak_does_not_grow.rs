//! Rule 2 forbids any reference in this public repo to how the work is
//! produced. `BENCHMARKING_RESULTS.md` leaks internal-process vocabulary
//! (`OPEN-ASK`, `DECISION #`, `adjudicator`) that has no place in a public
//! benchmarking doc — filed as `#Y96`, "flag, don't touch" was the adopted
//! containment policy, but that policy was never backed by a gate. The
//! line-count grew near-monotonically across roughly a week (70 -> 78 -> 83
//! -> 120) with almost every commit touching the file adding one or two
//! instances, and the tracking item itself went unmeasured for ~3,800
//! `Backlog.md` lines because nothing forced a re-check.
//!
//! This test counts occurrences, not matching lines (some lines carry more
//! than one instance, e.g. two `OPEN-ASK`s in one sentence) — 139 at the
//! time this test was introduced, against the 120 *lines* `grep -c` reported.
//!
//! It does not clean up the 139 existing instances — that is a
//! separately-scoped, deliberate edit, not a side effect of a growth gate.
//! It only stops the count from rising further: any commit that adds a new
//! leaked instance fails the build. Lowering the baseline (as instances are
//! cleaned up) is a normal, welcome change to the constant below.
//!
//! `README.md` is checked as a regression guard at its current true count
//! (0) so a leak cannot start there unnoticed either.

use std::fs;
use std::path::PathBuf;

/// Checked-in ceiling for `BENCHMARKING_RESULTS.md`'s leaked-vocabulary
/// occurrence count, as of this test's introduction. Lower it when
/// instances are cleaned up; never raise it to silence a real new leak.
const BENCHMARKING_RESULTS_BASELINE: usize = 139;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root resolves")
}

fn leaked_vocabulary_count(text: &str) -> usize {
    text.matches("OPEN-ASK")
        .count()
        .checked_add(text.matches("DECISION #").count())
        .and_then(|n| n.checked_add(text.matches("adjudicator").count()))
        .expect("leak count fits in usize")
}

#[test]
fn benchmarking_results_vocabulary_leak_does_not_grow() {
    let root = workspace_root();
    let path = root.join("../BENCHMARKING_RESULTS.md");
    let text = fs::read_to_string(&path).expect("BENCHMARKING_RESULTS.md readable");

    let count = leaked_vocabulary_count(&text);
    assert!(
        count <= BENCHMARKING_RESULTS_BASELINE,
        "BENCHMARKING_RESULTS.md's leaked-vocabulary count (OPEN-ASK / DECISION # / \
         adjudicator) is {count}, above the checked-in baseline of \
         {BENCHMARKING_RESULTS_BASELINE} — rule 2 forbids referencing how this work is \
         produced; find and remove the new instance(s) rather than raising this constant"
    );
}

#[test]
fn readme_has_no_leaked_vocabulary() {
    let root = workspace_root();
    let path = root.join("../README.md");
    let text = fs::read_to_string(&path).expect("README.md readable");

    let count = leaked_vocabulary_count(&text);
    assert_eq!(
        count, 0,
        "README.md now contains {count} instance(s) of leaked internal-process vocabulary \
         (OPEN-ASK / DECISION # / adjudicator) — rule 2 forbids this in the public repo"
    );
}

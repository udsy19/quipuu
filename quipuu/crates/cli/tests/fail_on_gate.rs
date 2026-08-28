//! `--fail-on` is a CI gate, and a CI gate that cannot fail is worse than none.
//!
//! `.pre-commit-hooks.yaml` has shipped `args: [--fail-on, critical]` since the
//! hook was written. The binary had no such argument. Two defects compounded:
//!
//!   1. `--fail-on` fell through to `ignoring unknown flag` and the process
//!      exited 0 with High findings on stdout; and
//!   2. because the path was read from a fixed argv slot, `--fail-on` *itself*
//!      became the scan target and the staged filenames pre-commit appended
//!      were discarded as unknown flags — so the hook reported "0 findings"
//!      on a tree it had never opened.
//!
//! Someone who installed the hook from our own INTEGRATIONS.md got a commit
//! gate that reported success on every commit. These tests pin both halves:
//! the gate fires, and it fires on the argv shape pre-commit actually produces.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn binary_path() -> PathBuf {
    let mut p = std::env::current_exe().expect("cannot get test binary path");
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.push("quipuu");
    p
}

/// A fixture tree containing exactly one High finding: pyca's
/// `rsa.generate_private_key` at a 2048-bit size, which the default policy
/// scores High (`CRYPTO-102`, deprecated after 2030 by NIST IR 8547) and never
/// Critical. That gap between High and Critical is what lets one tree exercise
/// both directions of the threshold.
fn high_finding_tree(suffix: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("quipuu_fail_on_{suffix}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create fixture dir");
    std::fs::write(
        dir.join("keys.py"),
        b"from cryptography.hazmat.primitives.asymmetric import rsa\n\
          \x20\x20\ndef make():\n    return rsa.generate_private_key(public_exponent=65537, key_size=2048)\n",
    )
    .expect("write fixture");
    dir
}

/// A tree with no cryptography in it at all.
fn clean_tree(suffix: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("quipuu_fail_on_clean_{suffix}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create fixture dir");
    std::fs::write(dir.join("plain.py"), b"def add(a, b):\n    return a + b\n")
        .expect("write fixture");
    dir
}

fn scan(args: &[&str]) -> Output {
    Command::new(binary_path())
        .arg("scan")
        .args(args)
        .output()
        .expect("failed to run quipuu scan")
}

fn code(out: &Output) -> i32 {
    out.status.code().expect("process was killed by a signal")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

// ── The measure from the backlog item ────────────────────────────────────────

/// A known High finding, scanned the way pre-commit invokes us — flags first,
/// staged filenames appended — must exit non-zero.
#[test]
fn hook_argv_shape_fails_on_a_high_finding() {
    let dir = high_finding_tree("hook_shape");
    let file = dir.join("keys.py");
    let out = scan(&["--fail-on", "high", file.to_str().unwrap()]);

    assert_eq!(
        code(&out),
        1,
        "expected exit 1 from the hook argv shape; stdout was:\n{}",
        stdout(&out),
    );
    // The filename must have been *scanned*, not swallowed as an unknown flag.
    assert!(
        stdout(&out).contains("keys.py:4"),
        "the staged filename was not scanned; stdout was:\n{}",
        stdout(&out),
    );
}

/// The same tree at `--fail-on critical`, with no Critical finding present,
/// exits 0. The gate is a threshold, not a "any finding fails" switch.
#[test]
fn critical_threshold_passes_a_tree_whose_worst_is_high() {
    let dir = high_finding_tree("critical_threshold");
    let out = scan(&["--fail-on", "critical", dir.to_str().unwrap()]);

    assert_eq!(code(&out), 0, "stdout was:\n{}", stdout(&out));
    assert!(
        stdout(&out).contains("High"),
        "the High finding should still be reported, just not gated on:\n{}",
        stdout(&out),
    );
}

// ── Threshold semantics ──────────────────────────────────────────────────────

/// "At or above", not "equal to": a High finding trips a `medium` gate.
#[test]
fn threshold_is_at_or_above() {
    let dir = high_finding_tree("at_or_above");
    for threshold in ["medium", "low", "safe"] {
        let out = scan(&["--fail-on", threshold, dir.to_str().unwrap()]);
        assert_eq!(
            code(&out),
            1,
            "--fail-on {threshold} should trip on a High finding; stdout was:\n{}",
            stdout(&out),
        );
    }
}

/// A clean tree passes every threshold.
#[test]
fn clean_tree_passes_every_threshold() {
    let dir = clean_tree("all_thresholds");
    for threshold in ["critical", "high", "medium", "low", "safe"] {
        let out = scan(&["--fail-on", threshold, dir.to_str().unwrap()]);
        assert_eq!(
            code(&out),
            0,
            "--fail-on {threshold} should pass a clean tree; stdout was:\n{}",
            stdout(&out),
        );
    }
}

/// Without `--fail-on`, the exit code says only whether quipuu ran. That is
/// the documented default in INTEGRATIONS.md and changing it silently would
/// break every existing pipeline.
#[test]
fn absent_flag_leaves_exit_code_at_zero() {
    let dir = high_finding_tree("absent_flag");
    let out = scan(&[dir.to_str().unwrap()]);
    assert_eq!(code(&out), 0, "stdout was:\n{}", stdout(&out));
    assert!(stdout(&out).contains("High"));
}

/// `--fail-on none` is the explicit way to say the same thing.
#[test]
fn none_disables_the_gate() {
    let dir = high_finding_tree("none");
    let out = scan(&["--fail-on", "none", dir.to_str().unwrap()]);
    assert_eq!(code(&out), 0, "stdout was:\n{}", stdout(&out));
}

/// `--fail-on policy` reads the active policy's `[ci] fail_on`, which is the
/// only thing that field has ever been documented to mean. `nsa-cnsa2` sets
/// `high`, so the same tree that passes under nist-default's `critical` fails
/// under CNSA 2.0.
#[test]
fn policy_threshold_tracks_the_active_preset() {
    let dir = high_finding_tree("policy_threshold");
    let path = dir.to_str().unwrap();

    let cnsa = scan(&["--policy", "nsa-cnsa2", "--fail-on", "policy", path]);
    assert_eq!(
        code(&cnsa),
        1,
        "nsa-cnsa2 sets ci.fail_on = high; stdout was:\n{}",
        stdout(&cnsa),
    );

    let default = scan(&["--policy", "nist-default", "--fail-on", "policy", path]);
    assert_eq!(
        code(&default),
        0,
        "nist-default sets ci.fail_on = critical; stdout was:\n{}",
        stdout(&default),
    );
}

// ── Refusals: a gate that cannot read its own threshold must not run ─────────

#[test]
fn unknown_threshold_is_fatal() {
    let dir = high_finding_tree("unknown_threshold");
    let out = scan(&["--fail-on", "criticall", dir.to_str().unwrap()]);
    assert_eq!(code(&out), 2, "stdout was:\n{}", stdout(&out));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("unknown --fail-on threshold"),
        "stderr was:\n{}",
        String::from_utf8_lossy(&out.stderr),
    );
}

#[test]
fn missing_threshold_value_is_fatal() {
    let out = scan(&["--fail-on"]);
    assert_eq!(code(&out), 2);
}

/// A path that is not there is refused. Walking it produced a warning and
/// "0 finding(s)", which a gate cannot tell apart from a clean tree.
#[test]
fn missing_path_is_fatal() {
    let missing = std::env::temp_dir().join("quipuu_fail_on_definitely_absent");
    let _ = std::fs::remove_dir_all(&missing);
    let out = scan(&["--fail-on", "high", missing.to_str().unwrap()]);
    assert_eq!(code(&out), 2, "stdout was:\n{}", stdout(&out));
}

#[test]
fn no_path_at_all_is_fatal() {
    let out = scan(&["--fail-on", "high"]);
    assert_eq!(code(&out), 2);
}

// ── Multiple paths ───────────────────────────────────────────────────────────

/// `pass_filenames: true` hands us the whole staged list. Every one of them is
/// scanned; scanning only the first would be a silent false negative on the
/// rest of the commit.
#[test]
fn every_positional_path_is_scanned() {
    let dir = high_finding_tree("multi_path");
    let second = dir.join("more.py");
    std::fs::copy(dir.join("keys.py"), &second).expect("copy fixture");

    let out = scan(&[
        dir.join("keys.py").to_str().unwrap(),
        second.to_str().unwrap(),
        "--fail-on",
        "high",
    ]);
    assert_eq!(code(&out), 1, "stdout was:\n{}", stdout(&out));
    assert!(
        stdout(&out).contains("→ 2 finding(s)"),
        "both paths should have been scanned; stdout was:\n{}",
        stdout(&out),
    );
}

// ── The shipped hook definition and this binary must agree ───────────────────

/// The threshold `.pre-commit-hooks.yaml` ships has to be one the binary
/// accepts. This is the coupling that broke: the yaml was written against a
/// flag nobody implemented, and nothing checked.
#[test]
fn shipped_pre_commit_hook_threshold_is_accepted() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("repo root")
        .to_path_buf();
    let yaml = std::fs::read_to_string(repo_root.join(".pre-commit-hooks.yaml"))
        .expect("read .pre-commit-hooks.yaml");

    let mut lines = yaml.lines().map(str::trim);
    let threshold = loop {
        match lines.next() {
            Some("- --fail-on") => break lines.next().expect("a value after --fail-on"),
            Some(_) => continue,
            None => panic!("the shipped hook no longer passes --fail-on"),
        }
    };
    let threshold = threshold.trim_start_matches("- ");

    let dir = clean_tree("hook_yaml");
    let out = scan(&["--fail-on", threshold, dir.to_str().unwrap()]);
    assert_ne!(
        code(&out),
        2,
        "the hook ships `--fail-on {threshold}`, which the binary rejects; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr),
    );
}

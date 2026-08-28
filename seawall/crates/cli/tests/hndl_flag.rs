//! The HNDL flag is decided, and it is decided by the policy.
//!
//! `is_hndl_critical` shipped for cycles with exactly two callers, both tests.
//! Every scanner wrote `hndl_critical: false` into the `Finding` it built,
//! nothing overwrote it, and so `summary.json.totals.hndl_critical` was `0` for
//! every input that has ever been scanned — including inputs that meet all
//! three of the active policy's `[hndl_flag]` conditions. That is a wrong
//! answer rather than a missing feature, in the field the product is named
//! after.
//!
//! These tests pin the fix from both ends:
//!
//!   1. a real certificate whose SPKI is a key-agreement key produces
//!      `hndl_critical > 0` end to end, through the scanner, the flag pass and
//!      the summary emitter;
//!   2. the flag tracks the *policy*, not the scanner — swapping the preset
//!      changes the answer on an identical finding set;
//!   3. the pass overwrites rather than or-s, so a stale `true` cannot survive;
//!   4. no scanner in the workspace writes anything but `false`, which is the
//!      direction that fails when a sixth scanner appears and invents a value
//!      it has no policy to justify.
//!
//! This file lives in `cli` because that is the only crate that can see the
//! scanners and the report emitters at once.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use seawall_core::risk::{apply_hndl_flags, is_hndl_critical};
use seawall_core::{Finding, Policy, load_builtins};
use seawall_report::{ReportOptions, emit_summary_json};
use seawall_scan_certs::CertScanner;

/// An X25519 certificate: the SPKI algorithm is `1.3.101.110`, whose table row
/// carries `primitive = "key-agree"` and `quantum_status = "BrokenByShor"`, so
/// `scan-certs` gives it `KeyEstablishmentLongLived` and a `medium` shelf life.
/// That is the shape the default policy's `[hndl_flag]` describes, and before
/// this gate no input of any shape could produce a non-zero count.
fn x25519_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../scan-certs/tests/fixtures")
}

fn scan_x25519() -> Vec<Finding> {
    let scanner = CertScanner::with_builtins().expect("cert scanner builds");
    scanner
        .scan_path(&x25519_fixture().join("x25519_keyagreement.pem"))
        .expect("cert scan succeeds")
}

fn opts() -> ReportOptions {
    ReportOptions {
        scan_target: "x25519_keyagreement.pem".to_string(),
        timestamp: "2026-08-28T00:00:00Z".to_string(),
        warnings: vec![],
    }
}

#[test]
fn hndl_critical_is_reachable_end_to_end() {
    let b = load_builtins().expect("builtins load");
    let mut findings = scan_x25519();
    assert!(
        !findings.is_empty(),
        "the X25519 fixture must produce findings, or this gate proves nothing"
    );
    assert!(
        findings.iter().all(|f| !f.hndl_critical),
        "scanners must leave the flag unset; a scanner holds no policy"
    );

    apply_hndl_flags(&mut findings, &b.algorithms, &b.policy);

    let flagged: Vec<&Finding> = findings.iter().filter(|f| f.hndl_critical).collect();
    assert_eq!(
        flagged.len(),
        1,
        "expected exactly the key-agreement public key to be HNDL-critical, got {:?}",
        findings
            .iter()
            .map(|f| (&f.rule_id, &f.algorithm_id, f.hndl_critical))
            .collect::<Vec<_>>()
    );
    assert_eq!(flagged[0].algorithm_id, "x25519");

    // The certificate's *signature* algorithm is ed25519 — long-lived, and
    // Shor-broken, but a signature is not harvestable: an attacker needs the
    // key now, not in fifteen years. The policy says so and the flag agrees.
    assert!(
        findings
            .iter()
            .any(|f| f.algorithm_id == "ed25519" && !f.hndl_critical),
        "a long-lived signature must not be flagged HNDL-critical"
    );

    let summary = emit_summary_json(&findings, &b.algorithms, &b.policy, &opts())
        .expect("summary emission succeeds");
    let val: serde_json::Value = serde_json::from_str(&summary).expect("valid JSON");
    assert_eq!(
        val["totals"]["hndl_critical"], 1,
        "summary.json must report the count the flag pass produced"
    );
}

#[test]
fn the_policy_decides_the_flag_not_the_scanner() {
    let b = load_builtins().expect("builtins load");
    let base = scan_x25519();

    // CNSA 2.0 defaults every unmatched path to a `medium` shelf life and keeps
    // the same three usage contexts, so the key-agreement key stays flagged.
    let cnsa2 = Policy::load("nsa-cnsa2").expect("preset loads");

    let mut under_default = base.clone();
    apply_hndl_flags(&mut under_default, &b.algorithms, &b.policy);
    let mut under_cnsa2 = base.clone();
    apply_hndl_flags(&mut under_cnsa2, &b.algorithms, &cnsa2);

    let count = |fs: &[Finding]| fs.iter().filter(|f| f.hndl_critical).count();
    assert_eq!(count(&under_default), 1);
    assert_eq!(count(&under_cnsa2), 1);

    // Now a policy that requires a shelf life no cert finding carries. The
    // finding set is byte-identical; only the policy moved, and the answer
    // moves with it. If the flag were still a scanner constant this would
    // read 1.
    let mut strict = b.policy.clone();
    strict.hndl_flag.require_min_shelf_life_bucket = "long".to_string();
    let mut under_strict = base.clone();
    apply_hndl_flags(&mut under_strict, &b.algorithms, &strict);
    assert_eq!(
        count(&under_strict),
        0,
        "raising the shelf-life floor above what the finding carries must clear the flag"
    );
}

#[test]
fn the_pass_overwrites_a_stale_flag_rather_than_or_ing_it() {
    let b = load_builtins().expect("builtins load");
    let mut findings = scan_x25519();
    for f in &mut findings {
        f.hndl_critical = true;
    }
    apply_hndl_flags(&mut findings, &b.algorithms, &b.policy);

    let stale: Vec<&String> = findings
        .iter()
        .filter(|f| {
            f.hndl_critical
                && !is_hndl_critical(f, b.algorithms.get(&f.algorithm_id).unwrap(), &b.policy)
        })
        .map(|f| &f.rule_id)
        .collect();
    assert!(
        stale.is_empty(),
        "a value the pass did not decide survived on {stale:?}"
    );
    assert_eq!(findings.iter().filter(|f| f.hndl_critical).count(), 1);
}

/// Direction four: the scanners may not decide this.
///
/// A scanner has no policy, so any literal other than `false` is a value it
/// cannot justify — and a `true` written there would slip past the pass only
/// if the pass were later removed, which is exactly the regression this file
/// exists to catch. Textual, and deliberately so: it is a statement about the
/// repository, not about any loaded value.
#[test]
fn no_scanner_writes_a_literal_hndl_flag_other_than_false() {
    let root = workspace_root();
    let mut offenders: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for crate_dir in [
        "crates/scan-source/src",
        "crates/scan-certs/src",
        "crates/scan-deps/src",
        "crates/scan-network/src",
    ] {
        for (path, text) in rust_files(&root.join(crate_dir), &root) {
            for (n, line) in text.lines().enumerate() {
                let Some(rest) = line.split_once("hndl_critical:") else {
                    continue;
                };
                if rest.1.trim().trim_end_matches(',') != "false" {
                    offenders.entry(path.clone()).or_default().push(n + 1);
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "a scanner assigns `hndl_critical` a value it has no policy to justify: {offenders:?}"
    );
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root resolves")
}

fn rust_files(dir: &Path, root: &Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(rust_files(&path, root));
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs")
            && let Ok(text) = fs::read_to_string(&path)
        {
            out.push((
                path.strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .into_owned(),
                text,
            ));
        }
    }
    out
}

//! One scan, one finding set, one answer per finding — in every artifact.
//!
//! The HTML report filtered its HNDL-critical section on
//! `hndl_critical || severity == Critical`, and `summary.json` counted only the
//! first. On a single RSA-2048/SHA-256 certificate that produced two artifacts
//! from the same scan saying `"hndl_critical": 0` and rendering two
//! `HNDL-CRITICAL` badges — and the HTML contradicted *itself*, because its own
//! summary card reads the same count `summary.json` does, three sections above
//! the badges. The section's doc comment recorded the wrong rule as if it were
//! the intended one. No test read the HTML, so nothing could see any of it.
//!
//! The same defect had a second, larger instance nothing had filed. A finding
//! whose `algorithm_id` has no algorithm-table row cannot be scored:
//! `algorithm_vulnerability` is 40 of the 100 available points and is read
//! entirely from the record. Every surface handled that privately and they did
//! not agree. Measured on one `openssl = "0.10"` line in a `Cargo.toml`, which
//! `scan-deps` reports as `DEP-001` with the `unknown` sentinel:
//!
//! | surface | before | after |
//! |---|---|---|
//! | stdout | `?` | `?` |
//! | `summary.json` | `medium: 1` | `unscored: 1` |
//! | HTML | Medium card, score 25 | Unscored card |
//! | SARIF | `warning`, `security-severity: 5.0` | `none`, property omitted |
//! | TUI | `Safe` | `UNSC` |
//! | `--fail-on` | unscored | unscored |
//!
//! Four answers for one finding, and the one asserting a mid-band CVSS to
//! GitHub Advanced Security was the loudest. `seawall_core::score_of` is now
//! the single place that decision is made; these tests pin that the artifacts
//! agree, and the source-text direction pins that a seventh surface cannot
//! quietly re-derive it.
//!
//! This file lives in `cli` because that is the only crate that can see every
//! emitter at once, and because the artifacts have to be read as the product
//! writes them, not as a library returns them.

use std::path::{Path, PathBuf};
use std::process::Command;

fn binary_path() -> PathBuf {
    let mut p = std::env::current_exe().expect("cannot get test binary path");
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.push("seawall");
    p
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/cli has two ancestors")
        .to_path_buf()
}

fn cert_fixtures() -> PathBuf {
    workspace_root().join("crates/scan-certs/tests/fixtures")
}

/// Scan `dir`, writing all three file artifacts into it, and return
/// `(stdout, summary_json, html, sarif)`.
fn scan_all_artifacts(
    dir: &Path,
    mode: &str,
) -> (String, serde_json::Value, String, serde_json::Value) {
    let html = dir.join("report.html");
    let summary = dir.join("summary.json");
    let sarif = dir.join("out.sarif");

    let out = Command::new(binary_path())
        .arg("scan")
        .arg(dir)
        .arg(mode)
        .arg("--html")
        .arg(&html)
        .arg("--summary-json")
        .arg(&summary)
        .arg("--sarif")
        .arg(&sarif)
        .output()
        .expect("seawall binary runs");

    let read_json = |p: &Path| -> serde_json::Value {
        serde_json::from_str(&std::fs::read_to_string(p).expect("artifact written"))
            .expect("artifact is JSON")
    };

    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        read_json(&summary),
        std::fs::read_to_string(&html).expect("html written"),
        read_json(&sarif),
    )
}

fn tmp_tree(suffix: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("seawall_artifact_agreement_{suffix}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create fixture dir");
    dir
}

/// The count in the HTML's HNDL-Critical summary card.
fn html_card(html: &str, label: &str) -> usize {
    let needle = format!(">{label}</div>");
    let at = html
        .find(&needle)
        .unwrap_or_else(|| panic!("HTML has no `{label}` summary card"));
    let rest = &html[at + needle.len()..];
    let open = rest.find("\">").expect("card value follows its label") + 2;
    let close = rest[open..].find('<').expect("card value is closed");
    rest[open..open + close]
        .trim()
        .parse()
        .expect("card value is a number")
}

// ── The filed defect: the HNDL section is the HNDL flag, and nothing else ────

#[test]
fn every_artifact_reports_the_same_hndl_count() {
    let dir = tmp_tree("hndl");
    // Two certificates. The X25519 one is genuinely HNDL-critical: its SPKI is
    // a key-agreement key, which is what the default policy's `[hndl_flag]`
    // block describes. The RSA-2048/SHA-256 one is not — and both of its
    // findings score `Critical`, which is exactly the input that used to make
    // the HTML disagree with the JSON.
    for f in ["x25519_keyagreement.pem", "rsa2048.pem"] {
        std::fs::copy(cert_fixtures().join(f), dir.join(f)).expect("copy cert fixture");
    }

    let (_stdout, summary, html, _sarif) = scan_all_artifacts(&dir, "--certs");

    let json_count = summary["totals"]["hndl_critical"]
        .as_u64()
        .expect("summary.json carries totals.hndl_critical") as usize;
    let badge_count = html.matches("HNDL-CRITICAL").count();
    let card_count = html_card(&html, "HNDL-Critical");

    assert_eq!(
        json_count, 1,
        "the X25519 fixture must be flagged, or this gate proves nothing: {summary}"
    );
    assert_eq!(
        badge_count, json_count,
        "the HTML rendered {badge_count} HNDL-CRITICAL badges for a scan whose \
         summary.json counts {json_count}; these are two artifacts of one scan"
    );
    assert_eq!(
        card_count, json_count,
        "the HTML's own HNDL-Critical card says {card_count} while the same \
         document renders {badge_count} badges"
    );
}

#[test]
fn a_critical_finding_that_is_not_hndl_is_not_badged_hndl() {
    let dir = tmp_tree("critical_not_hndl");
    // Every finding on this certificate scores Critical and none is HNDL.
    // `README.md` states the signature is not flagged; before this gate the
    // HTML badged it anyway.
    std::fs::copy(cert_fixtures().join("rsa2048.pem"), dir.join("rsa2048.pem"))
        .expect("copy cert fixture");

    let (stdout, summary, html, _sarif) = scan_all_artifacts(&dir, "--certs");

    assert!(
        stdout.contains("Critical"),
        "the fixture must produce Critical findings, or this gate proves \
         nothing: {stdout}"
    );
    assert_eq!(
        summary["totals"]["hndl_critical"].as_u64(),
        Some(0),
        "no finding on this certificate meets the policy's HNDL conditions"
    );
    assert_eq!(
        html.matches("HNDL-CRITICAL").count(),
        0,
        "a Critical severity band is not an HNDL flag; the HTML badged one anyway"
    );
    assert!(
        !html.contains("HNDL-Critical Findings"),
        "the HNDL section must not render at all when nothing is flagged"
    );
}

// ── The larger instance: a finding with no algorithm-table row ───────────────

/// A manifest naming a crypto library but no algorithm. `scan-deps` reports it
/// with the `unknown` sentinel, which has no algorithm-table row by design.
fn unscored_tree(suffix: &str) -> PathBuf {
    let dir = tmp_tree(suffix);
    std::fs::write(
        dir.join("Cargo.toml"),
        b"[package]\nname = \"probe\"\nversion = \"0.1.0\"\n\n[dependencies]\nopenssl = \"0.10\"\n",
    )
    .expect("write manifest");
    dir
}

#[test]
fn an_unscored_finding_is_unscored_in_every_artifact() {
    let dir = unscored_tree("unscored");
    let (stdout, summary, html, sarif) = scan_all_artifacts(&dir, "--deps");

    // stdout — the one surface that was already right.
    assert!(
        stdout.contains("?\tDEP-001\tunknown"),
        "stdout must mark an uncatalogued algorithm `?`: {stdout}"
    );

    // summary.json — was `medium: 1`.
    let totals = &summary["totals"];
    assert_eq!(totals["unscored"].as_u64(), Some(1), "totals: {totals}");
    for band in ["critical", "high", "medium", "low", "safe"] {
        assert_eq!(
            totals[band].as_u64(),
            Some(0),
            "an unscored finding must not be counted in `{band}`: {totals}"
        );
    }
    assert_eq!(
        summary["by_algorithm"][0]["severity"].as_str(),
        Some("Unscored"),
        "by_algorithm must not band an algorithm it cannot look up: {summary}"
    );

    // HTML — was a Medium card and a Medium register badge at score 25.
    assert_eq!(html_card(&html, "Unscored"), 1);
    assert_eq!(html_card(&html, "Medium"), 0);
    assert_eq!(html_card(&html, "Safe"), 0);
    assert!(
        html.contains(r#"<span class="badge-sev unscored">Unscored</span>"#),
        "the risk register must label the row Unscored"
    );

    // SARIF — was `warning` with `security-severity: 5.0`, a mid-band CVSS
    // asserted to GitHub Advanced Security for a finding we decline to score.
    let run = &sarif["runs"][0];
    let rule = &run["tool"]["driver"]["rules"][0];
    assert_eq!(
        rule["defaultConfiguration"]["level"].as_str(),
        Some("none"),
        "SARIF `none` is defined as \"severity does not apply\"; that is the claim: {rule}"
    );
    assert!(
        rule["properties"].get("security-severity").is_none(),
        "`security-severity` must be omitted, not zeroed — GitHub bands on it: {rule}"
    );
    assert_eq!(run["results"][0]["level"].as_str(), Some("none"));
}

#[test]
fn an_unscored_finding_cannot_trip_the_fail_on_gate() {
    let dir = unscored_tree("unscored_gate");
    // `--fail-on safe` is the lowest threshold the gate accepts. If an unscored
    // finding were being banded anywhere in the CLI path, this would exit 1.
    let out = Command::new(binary_path())
        .arg("scan")
        .arg(&dir)
        .arg("--deps")
        .arg("--fail-on")
        .arg("safe")
        .output()
        .expect("seawall binary runs");

    assert_eq!(
        out.status.code(),
        Some(0),
        "an unscored finding has no band and so cannot clear any threshold; \
         stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("uncatalogued algorithm"),
        "and the gate must say it skipped one rather than count it clean"
    );
}

// ── The direction that fails when a seventh surface appears ──────────────────

/// The only files allowed to call `QuantumRiskScore::compute` directly.
///
/// Everything else goes through `score_of` / `severity_of`, which is where the
/// "no table row means unscored, not Safe and not Medium" decision lives. This
/// is the check the previous state of the tree needed and did not have: six
/// surfaces each wrote their own `else` arm, and no test compared them.
const DIRECT_COMPUTE_ALLOWED: &[&str] = &["crates/core/src/risk.rs"];

#[test]
fn no_surface_derives_its_own_severity_for_a_missing_algorithm_row() {
    let root = workspace_root();
    let mut offenders: Vec<String> = Vec::new();

    for path in rust_sources(&root.join("crates")) {
        let rel = path
            .strip_prefix(&root)
            .expect("path is under the workspace root")
            .to_string_lossy()
            .replace('\\', "/");

        // Tests may score a known algorithm directly; they are asserting about
        // the engine, not emitting an artifact.
        if rel.contains("/tests/") || DIRECT_COMPUTE_ALLOWED.contains(&rel.as_str()) {
            continue;
        }

        let text = std::fs::read_to_string(&path).expect("source file reads");
        if text.contains("QuantumRiskScore::compute") {
            offenders.push(rel);
        }
    }

    assert!(
        offenders.is_empty(),
        "these files score findings without going through `score_of`, so each \
         one decides for itself what a finding with no algorithm-table row is: \
         {offenders:?}"
    );
}

fn rust_sources(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            out.extend(rust_sources(&path));
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    out
}

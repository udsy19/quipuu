//! Integration tests for the `quipuu-report` crate.
//!
//! Tests use fixtures from `../scan-source/tests/fixtures/` to produce real
//! findings, then assert the three emitters meet their correctness contracts.

use std::path::PathBuf;

use quipuu_core::{ScanWarning, ScanWarningKind, load_builtins};
use quipuu_report::{ReportOptions, emit_html, emit_sarif, emit_summary_json};
use quipuu_scan_source::Scanner;

fn fixtures_root() -> PathBuf {
    // Navigate from this crate's manifest dir to scan-source's fixtures.
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../scan-source/tests/fixtures")
}

/// Produce a stable set of findings from the Go fixture file.
fn make_findings() -> (
    Vec<quipuu_core::Finding>,
    quipuu_core::AlgorithmTable,
    quipuu_core::Policy,
) {
    let b = load_builtins().expect("builtins load");
    let scanner = Scanner::with_builtins(b.algorithms.clone()).expect("scanner builds");
    let findings = scanner
        .scan_path(&fixtures_root().join("go/main.go"))
        .expect("scan succeeds");
    (findings, b.algorithms, b.policy)
}

fn default_opts() -> ReportOptions {
    ReportOptions {
        scan_target: "tests/fixtures/go/main.go".to_string(),
        timestamp: "2026-06-15T00:00:00Z".to_string(),
        warnings: vec![],
    }
}

// ── SARIF tests ──────────────────────────────────────────────────────────────

/// T1 — emit_sarif returns valid JSON with correct version and $schema.
#[test]
fn sarif_is_valid_json_with_version_and_schema() {
    let (findings, algorithms, policy) = make_findings();
    let json_str = emit_sarif(&findings, &algorithms, &policy, &default_opts())
        .expect("emit_sarif should succeed");

    let val: serde_json::Value =
        serde_json::from_str(&json_str).expect("SARIF output must be valid JSON");

    assert_eq!(
        val["version"].as_str().unwrap(),
        "2.1.0",
        "version must be \"2.1.0\""
    );
    assert!(
        val["$schema"].is_string() && !val["$schema"].as_str().unwrap().is_empty(),
        "$schema must be a non-empty string"
    );

    let runs = val["runs"].as_array().expect("runs must be an array");
    assert!(!runs.is_empty(), "runs must not be empty");

    let rules = runs[0]["tool"]["driver"]["rules"]
        .as_array()
        .expect("rules must be an array");
    let results = runs[0]["results"]
        .as_array()
        .expect("results must be an array");

    // At least one rule per distinct rule_id.
    let mut rule_ids: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for f in &findings {
        rule_ids.insert(f.rule_id.as_str());
    }
    assert!(
        rules.len() >= rule_ids.len(),
        "expected ≥{} rules (one per distinct rule_id), got {}",
        rule_ids.len(),
        rules.len()
    );

    // results.len() == findings.len()
    assert_eq!(
        results.len(),
        findings.len(),
        "results count must equal findings count"
    );

    // Every result has a primaryLocationLineHash of exactly 16 hex chars.
    for (i, result) in results.iter().enumerate() {
        let hash = result["partialFingerprints"]["primaryLocationLineHash"]
            .as_str()
            .unwrap_or_else(|| panic!("result[{i}] missing primaryLocationLineHash"));
        assert_eq!(
            hash.len(),
            16,
            "result[{i}] primaryLocationLineHash must be 16 chars, got {hash:?}"
        );
        assert!(
            hash.chars().all(|c| c.is_ascii_hexdigit()),
            "result[{i}] primaryLocationLineHash must be lowercase hex, got {hash:?}"
        );
    }
}

/// T2 — SARIF severity mapping: a Critical finding gets level "error" and
///       security-severity "9.0" on its rule.
#[test]
fn sarif_critical_finding_maps_to_error_and_9_0() {
    use quipuu_core::{Exposure, Severity, UsageContext};

    let (mut findings, algorithms, policy) = make_findings();

    // Force the first RSA-2048 finding to be Critical by upgrading its context.
    let critical_rule_id = {
        let rsa2048 = findings
            .iter_mut()
            .find(|f| f.algorithm_id == "rsa-2048")
            .expect("RSA-2048 finding must exist");
        rsa2048.usage_context = UsageContext::KeyEstablishmentLongLived;
        rsa2048.exposure = Exposure::PublicInternet;
        rsa2048.shelf_life_bucket = "long".to_string();
        // Verify the score is actually Critical before asserting SARIF output.
        let algo = algorithms.get("rsa-2048").unwrap();
        let score = quipuu_core::QuantumRiskScore::compute(rsa2048, algo, &policy);
        assert_eq!(
            score.severity,
            Severity::Critical,
            "pre-condition: RSA-2048 long-lived public-internet must score Critical"
        );
        rsa2048.rule_id.clone()
    };

    let json_str = emit_sarif(&findings, &algorithms, &policy, &default_opts())
        .expect("emit_sarif should succeed");
    let val: serde_json::Value = serde_json::from_str(&json_str).unwrap();

    let rules = val["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .unwrap();
    let results = val["runs"][0]["results"].as_array().unwrap();

    // Find the result for the critical finding.
    let critical_result = results
        .iter()
        .find(|r| r["ruleId"].as_str() == Some(critical_rule_id.as_str()))
        .expect("critical result must appear");

    let level = critical_result["level"].as_str().unwrap();
    assert_eq!(level, "error", "Critical finding must have level=error");

    // Find the corresponding rule.
    let rule = rules
        .iter()
        .find(|r| r["id"].as_str() == Some(critical_rule_id.as_str()))
        .expect("rule for critical finding must exist");

    let sec_sev = rule["properties"]["security-severity"]
        .as_str()
        .expect("security-severity must be a string on the rule");
    assert_eq!(
        sec_sev, "9.0",
        "Critical rule must have security-severity=9.0"
    );
}

// ── HTML tests ───────────────────────────────────────────────────────────────

/// T3 — emit_html returns a string starting with DOCTYPE or html, containing
///       scan target, policy name, and at least one algorithm display name.
#[test]
fn html_starts_with_doctype_and_contains_key_content() {
    let (findings, algorithms, policy) = make_findings();
    let html = emit_html(&findings, &algorithms, &policy, &default_opts())
        .expect("emit_html should succeed");

    let lower = html.to_lowercase();
    assert!(
        lower.starts_with("<!doctype html") || lower.starts_with("<html"),
        "HTML output must start with <!DOCTYPE html or <html"
    );

    assert!(
        html.contains(&default_opts().scan_target),
        "HTML must contain the scan target name"
    );

    assert!(
        html.contains(&policy.meta.name) || html.contains(&policy.meta.display_name),
        "HTML must contain the policy name"
    );

    // At least one algorithm display name must appear.
    let has_any_algo = algorithms
        .iter()
        .any(|a| html.contains(a.display_name.as_str()));
    assert!(
        has_any_algo,
        "HTML must contain at least one algorithm display name"
    );
}

/// T4 — emit_html contains CSS with the required severity colour codes.
#[test]
fn html_contains_severity_css_colors() {
    let (findings, algorithms, policy) = make_findings();
    let html = emit_html(&findings, &algorithms, &policy, &default_opts())
        .expect("emit_html should succeed");

    for (color, name) in [
        ("#dc2626", "Critical"),
        ("#ea580c", "High"),
        ("#ca8a04", "Medium"),
        ("#2563eb", "Low"),
        ("#16a34a", "Safe"),
    ] {
        assert!(
            html.contains(color),
            "HTML must contain CSS color {color} for {name}"
        );
    }
}

// ── Summary JSON tests ───────────────────────────────────────────────────────

/// T5 — emit_summary_json parses as JSON and has correct totals.
#[test]
fn summary_json_parses_and_has_correct_totals() {
    let (findings, algorithms, policy) = make_findings();
    let json_str = emit_summary_json(&findings, &algorithms, &policy, &default_opts())
        .expect("emit_summary_json should succeed");

    let val: serde_json::Value =
        serde_json::from_str(&json_str).expect("summary_json must be valid JSON");

    let total = val["totals"]["findings"]
        .as_u64()
        .expect("totals.findings must be a number");
    assert_eq!(
        total,
        findings.len() as u64,
        "totals.findings must match the number of findings"
    );

    // The individual severity counts must sum to the total.
    let sum_by_sev = val["totals"]["critical"].as_u64().unwrap_or(0)
        + val["totals"]["high"].as_u64().unwrap_or(0)
        + val["totals"]["medium"].as_u64().unwrap_or(0)
        + val["totals"]["low"].as_u64().unwrap_or(0)
        + val["totals"]["safe"].as_u64().unwrap_or(0);
    assert_eq!(
        sum_by_sev, total,
        "sum of per-severity counts must equal totals.findings"
    );

    // Structural checks.
    assert!(val["tool"]["name"].is_string());
    assert!(val["tool"]["version"].is_string());
    assert!(val["policy"].is_string());
    assert!(val["scan_target"].is_string());
    assert!(val["timestamp"].is_string());
}

/// T6 — emit_summary_json by_algorithm is sorted with highest-count first;
///       when counts tie, order is alphabetical by algorithm_id.
#[test]
fn summary_json_by_algorithm_sorted_by_count_desc_then_alpha() {
    let (findings, algorithms, policy) = make_findings();
    let json_str = emit_summary_json(&findings, &algorithms, &policy, &default_opts())
        .expect("emit_summary_json should succeed");

    let val: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    let by_algo = val["by_algorithm"]
        .as_array()
        .expect("by_algorithm must be an array");

    if by_algo.len() < 2 {
        return; // Nothing to check.
    }

    for pair in by_algo.windows(2) {
        let a_count = pair[0]["count"].as_u64().unwrap_or(0);
        let b_count = pair[1]["count"].as_u64().unwrap_or(0);
        let a_id = pair[0]["algorithm_id"].as_str().unwrap_or("");
        let b_id = pair[1]["algorithm_id"].as_str().unwrap_or("");

        if a_count == b_count {
            assert!(
                a_id <= b_id,
                "when counts are equal, by_algorithm must be alphabetical: \
                 {a_id} should precede {b_id}"
            );
        } else {
            assert!(
                a_count >= b_count,
                "by_algorithm must be sorted by count descending: \
                 count={a_count} for {a_id} should be ≥ count={b_count} for {b_id}"
            );
        }
    }
}

// ── Phase 2: audible-vs-suppressed partition tests ──────────────────────────
//
// The V2 corpus run produced ~85 AES-256-GCM "Medium" findings on a single
// rustls scan — all quantum-safe, all inventory, all noise on the alert
// channel. Phase 2 hides QuantumSafe / PqcFinal / PqcDraft from HTML / SARIF /
// summary / stdout by default. The CBOM keeps everything because it's an
// inventory. These tests guard the partition behaviour.

fn finding_for(algo_id: &str) -> quipuu_core::Finding {
    use quipuu_core::{Confidence, Exposure, Finding, Location, UsageContext};
    Finding {
        rule_id: format!("TEST-{algo_id}"),
        algorithm_id: algo_id.to_string(),
        location: Location {
            location: "test.rs".to_string(),
            line: Some(1),
            offset: None,
            symbol: None,
            snippet: Some(format!("call({algo_id})")),
        },
        message: format!("{algo_id} usage detected"),
        confidence: Confidence::LiteralArg,
        usage_context: UsageContext::DataAtRestEncryption,
        exposure: Exposure::InternalService,
        shelf_life_bucket: "medium".to_string(),
        hndl_critical: false,
    }
}

#[test]
fn phase2_partition_audible_separates_inventory_from_real_findings() {
    use quipuu_report::partition_audible;

    let b = quipuu_core::load_builtins().expect("builtins load");
    let findings = vec![
        finding_for("rsa-2048"),    // BrokenByShor — audible
        finding_for("aes-256-gcm"), // QuantumSafe — suppressed
        finding_for("md5"),         // BrokenClassically — audible
        finding_for("ml-kem-768"),  // PqcFinal — suppressed
        finding_for("sha-256"),     // QuantumSafe-ish (hash) — suppressed
        finding_for("ecdsa-p256"),  // BrokenByShor — audible
    ];

    let (audible, suppressed) = partition_audible(&findings, &b.algorithms, &b.policy);

    let audible_ids: Vec<&str> = audible.iter().map(|f| f.algorithm_id.as_str()).collect();
    let suppressed_ids: Vec<&str> = suppressed.iter().map(|f| f.algorithm_id.as_str()).collect();

    assert!(
        audible_ids.contains(&"rsa-2048"),
        "RSA-2048 must be audible"
    );
    assert!(audible_ids.contains(&"md5"), "MD5 must be audible");
    assert!(
        audible_ids.contains(&"ecdsa-p256"),
        "ECDSA-P256 must be audible"
    );

    assert!(
        suppressed_ids.contains(&"aes-256-gcm"),
        "AES-256-GCM (QuantumSafe) must be suppressed"
    );
    assert!(
        suppressed_ids.contains(&"ml-kem-768"),
        "ML-KEM-768 (PqcFinal) must be suppressed — it's inventory, not an alert"
    );

    assert_eq!(audible.len() + suppressed.len(), findings.len());
}

#[test]
fn policy_disallowed_algorithm_is_audible_even_when_quantum_safe() {
    // Under nsa-cnsa2, SHA-256 and AES-128-GCM are quantum-safe and off the
    // approved suite. Suppressing them as "inventory" would hide exactly the
    // findings the operator selected that profile to see.
    use quipuu_core::Policy;
    use quipuu_report::partition_audible;

    let b = quipuu_core::load_builtins().expect("builtins load");
    let cnsa2 = Policy::from_preset("nsa-cnsa2")
        .expect("nsa-cnsa2 is a built-in preset")
        .expect("nsa-cnsa2 parses");
    let findings = vec![
        finding_for("sha-256"),
        finding_for("aes-128-gcm"),
        finding_for("aes-256-gcm"),
    ];

    let (audible, suppressed) = partition_audible(&findings, &b.algorithms, &cnsa2);
    let audible_ids: Vec<&str> = audible.iter().map(|f| f.algorithm_id.as_str()).collect();
    let suppressed_ids: Vec<&str> = suppressed.iter().map(|f| f.algorithm_id.as_str()).collect();
    assert!(audible_ids.contains(&"sha-256"));
    assert!(audible_ids.contains(&"aes-128-gcm"));
    assert!(
        suppressed_ids.contains(&"aes-256-gcm"),
        "AES-256-GCM is CNSA 2.0 approved and stays inventory-only"
    );

    // ...and the default profile still suppresses SHA-256, unchanged.
    let (_, default_suppressed) = partition_audible(&findings, &b.algorithms, &b.policy);
    let default_suppressed_ids: Vec<&str> = default_suppressed
        .iter()
        .map(|f| f.algorithm_id.as_str())
        .collect();
    assert!(default_suppressed_ids.contains(&"sha-256"));
}

#[test]
fn phase2_unknown_algorithm_id_stays_audible() {
    // If the scanner produced a finding whose algorithm_id we can't classify
    // (table miss, dep scanner unknown), we surface it — better to overcount
    // than to silently drop something we don't understand.
    use quipuu_report::partition_audible;

    let b = quipuu_core::load_builtins().expect("builtins load");
    let findings = vec![finding_for("not-an-algorithm-in-the-table")];
    let (audible, suppressed) = partition_audible(&findings, &b.algorithms, &b.policy);
    assert_eq!(audible.len(), 1, "unknown algo-ids must stay audible");
    assert_eq!(suppressed.len(), 0);
}

#[test]
fn phase2_sarif_excludes_suppressed_when_audible_subset_passed() {
    // Mirrors how the CLI calls emit_sarif with the partitioned subset:
    // SARIF must contain only the audible findings.
    use quipuu_report::partition_audible;

    let b = quipuu_core::load_builtins().expect("builtins load");
    let findings = vec![
        finding_for("rsa-2048"),
        finding_for("aes-256-gcm"),
        finding_for("ml-kem-768"),
    ];
    let (audible, _) = partition_audible(&findings, &b.algorithms, &b.policy);
    let displayed: Vec<quipuu_core::Finding> = audible.iter().map(|f| (*f).clone()).collect();

    let sarif =
        emit_sarif(&displayed, &b.algorithms, &b.policy, &default_opts()).expect("emit_sarif");
    let val: serde_json::Value = serde_json::from_str(&sarif).unwrap();
    let results = val["runs"][0]["results"].as_array().unwrap();

    let rule_ids: Vec<&str> = results
        .iter()
        .map(|r| r["ruleId"].as_str().unwrap_or(""))
        .collect();

    assert!(
        rule_ids.contains(&"TEST-rsa-2048"),
        "SARIF must include RSA-2048 finding (audible)"
    );
    assert!(
        !rule_ids.contains(&"TEST-aes-256-gcm"),
        "SARIF must NOT include AES-256-GCM finding (suppressed)"
    );
    assert!(
        !rule_ids.contains(&"TEST-ml-kem-768"),
        "SARIF must NOT include ML-KEM-768 finding (suppressed)"
    );
}

#[test]
fn phase2_sarif_includes_everything_when_full_set_passed() {
    // Mirrors `--include-safe`: when the CLI passes the full findings set,
    // every finding appears in SARIF (inventory + alerts together).
    let b = quipuu_core::load_builtins().expect("builtins load");
    let findings = vec![
        finding_for("rsa-2048"),
        finding_for("aes-256-gcm"),
        finding_for("ml-kem-768"),
    ];

    let sarif =
        emit_sarif(&findings, &b.algorithms, &b.policy, &default_opts()).expect("emit_sarif");
    let val: serde_json::Value = serde_json::from_str(&sarif).unwrap();
    let results = val["runs"][0]["results"].as_array().unwrap();
    assert_eq!(
        results.len(),
        3,
        "with --include-safe, SARIF must contain every finding"
    );
}

// ── Phase 5: "Why this matters" plain-English explanations ──────────────────
//
// Every finding in the HTML report should carry a plain-English explanation
// of why the algorithm is in trouble and what to do. Built mechanically from
// algorithm-table fields (quantum_status, notes, replacement, fips) — no LLM
// involved (P1). These tests guard the rendered output.

#[test]
fn phase5_html_contains_why_matters_disclosure_per_finding() {
    let (findings, algorithms, policy) = make_findings();
    let html = emit_html(&findings, &algorithms, &policy, &default_opts())
        .expect("emit_html should succeed");

    assert!(!findings.is_empty(), "test prerequisite: findings exist");

    // Every register row gets a <details class="why-matters"> block.
    let detail_count = html.matches("class=\"why-matters\"").count();
    assert_eq!(
        detail_count,
        findings.len(),
        "expected one why-matters disclosure per finding (got {} for {} findings)",
        detail_count,
        findings.len()
    );

    // The disclosure label must appear at least once.
    assert!(
        html.contains("Why this matters"),
        "HTML must contain the disclosure label"
    );
}

#[test]
fn phase5_why_matters_includes_shor_preamble_for_rsa() {
    let (findings, algorithms, policy) = make_findings();
    // The Go fixture has RSA findings; RSA is BrokenByShor, so the report
    // must surface the Shor preamble somewhere.
    assert!(
        findings.iter().any(|f| f.algorithm_id.starts_with("rsa-")),
        "test prerequisite: fixture has RSA findings"
    );
    let html = emit_html(&findings, &algorithms, &policy, &default_opts())
        .expect("emit_html should succeed");

    assert!(
        html.contains("Shor"),
        "HTML must contain a Shor's algorithm reference in the why-matters \
         body for RSA findings"
    );
}

#[test]
fn phase5_why_matters_recommends_replacement_when_known() {
    let (findings, algorithms, policy) = make_findings();
    // RSA-2048 → replacement = ML-KEM-768 per the algorithm table.
    let html = emit_html(&findings, &algorithms, &policy, &default_opts())
        .expect("emit_html should succeed");

    assert!(
        html.contains("Recommended replacement"),
        "HTML why-matters body must surface the 'Recommended replacement' phrase"
    );
    assert!(
        html.contains("ML-KEM-768") || html.contains("ML-DSA"),
        "HTML must recommend a specific NIST-final replacement"
    );
}

#[test]
fn phase5_why_matters_uses_verbatim_notes_from_table() {
    let (findings, algorithms, policy) = make_findings();
    let html = emit_html(&findings, &algorithms, &policy, &default_opts())
        .expect("emit_html should succeed");

    // The Go fixture generates an RSA key below the 2048-bit floor, which
    // resolves to `rsa-undersized` — the rule matches `bits < 2048` and so
    // knows the key is under the floor, not that it is 1024 bits. Its
    // algorithm-table `notes` must appear verbatim in the report,
    // demonstrating that the why-matters layer reads straight from the table
    // (P1 — no LLM rewording).
    assert!(
        findings.iter().any(|f| f.algorithm_id == "rsa-undersized"),
        "test prerequisite: fixture has an undersized RSA key"
    );
    assert!(
        html.contains("Classically below the NIST SP 800-131A 112-bit minimum"),
        "HTML must reproduce the rsa-undersized `notes` field verbatim, got HTML \
         length {}",
        html.len()
    );
}

// ── Phase 7: warnings surfaced in HTML and SARIF ────────────────────────────

fn two_warnings() -> Vec<ScanWarning> {
    vec![
        ScanWarning::new(
            ScanWarningKind::UnreadableFile,
            Some(PathBuf::from("src/secret.go")),
            "permission denied".to_string(),
        ),
        ScanWarning::new(
            ScanWarningKind::ParseError,
            Some(PathBuf::from("pkg/crypto/util.go")),
            "tree-sitter parse failed at line 42".to_string(),
        ),
    ]
}

#[test]
fn phase7_html_omits_diagnostics_when_no_warnings() {
    let (findings, algorithms, policy) = make_findings();
    let html = emit_html(&findings, &algorithms, &policy, &default_opts())
        .expect("emit_html should succeed");

    assert!(
        !html.contains("Scan Diagnostics"),
        "HTML must not contain a diagnostics section when there are no warnings"
    );
}

#[test]
fn phase7_html_renders_diagnostics_section_with_warnings() {
    let (findings, algorithms, policy) = make_findings();
    let opts = ReportOptions {
        scan_target: "tests/fixtures/go/main.go".to_string(),
        timestamp: "2026-06-15T00:00:00Z".to_string(),
        warnings: two_warnings(),
    };
    let html = emit_html(&findings, &algorithms, &policy, &opts).expect("emit_html should succeed");

    assert!(
        html.contains("Scan Diagnostics"),
        "HTML must contain a 'Scan Diagnostics' heading when warnings are present"
    );
    assert!(
        html.contains("permission denied"),
        "HTML must render the first warning's message"
    );
    assert!(
        html.contains("tree-sitter parse failed at line 42"),
        "HTML must render the second warning's message"
    );
    assert!(
        html.contains("src/secret.go"),
        "HTML must render the first warning's path"
    );
    assert!(
        html.contains("UnreadableFile"),
        "HTML must render the warning kind label"
    );
}

#[test]
fn phase7_sarif_omits_invocations_when_no_warnings() {
    let (findings, algorithms, policy) = make_findings();
    let json_str = emit_sarif(&findings, &algorithms, &policy, &default_opts())
        .expect("emit_sarif should succeed");
    let val: serde_json::Value = serde_json::from_str(&json_str).unwrap();

    assert!(
        val["runs"][0]["invocations"].is_null(),
        "SARIF must not include an 'invocations' field when there are no warnings"
    );
}

#[test]
fn phase7_sarif_emits_tool_execution_notifications_per_warning() {
    let (findings, algorithms, policy) = make_findings();
    let opts = ReportOptions {
        scan_target: "tests/fixtures/go/main.go".to_string(),
        timestamp: "2026-06-15T00:00:00Z".to_string(),
        warnings: two_warnings(),
    };
    let json_str =
        emit_sarif(&findings, &algorithms, &policy, &opts).expect("emit_sarif should succeed");
    let val: serde_json::Value = serde_json::from_str(&json_str).unwrap();

    let invocations = val["runs"][0]["invocations"]
        .as_array()
        .expect("runs[0].invocations must be an array when warnings are present");
    assert!(!invocations.is_empty(), "invocations must not be empty");

    let notifications = invocations[0]["toolExecutionNotifications"]
        .as_array()
        .expect("invocations[0].toolExecutionNotifications must be an array");
    assert_eq!(
        notifications.len(),
        2,
        "expected one notification per warning, got {}",
        notifications.len()
    );

    for (i, notif) in notifications.iter().enumerate() {
        assert_eq!(
            notif["level"].as_str().unwrap_or(""),
            "warning",
            "notification[{i}] must have level=warning"
        );
        let text = notif["message"]["text"].as_str().unwrap_or("");
        assert!(
            !text.is_empty(),
            "notification[{i}] must have a non-empty message.text"
        );
    }
}

/// The SARIF `run` object carries `automationDetails`, and the string
/// `runAutomationDetails` appears nowhere in the published tree.
///
/// `runAutomationDetails` is the *type* name in the SARIF 2.1.0 schema's
/// definitions block; the property on `run` is `automationDetails`, and `run`
/// declares `additionalProperties: false`. We shipped the type name at nine
/// sites — the emitter plus eight lines of `SPEC.md`, the decision log and the
/// SARIF knowledge base. Eight of the nine were prose telling the next author
/// to emit the wrong key, so a code-only fix regrows within a cycle.
///
/// Hence the second direction: the assertion is about the repository, not just
/// about the emitted document. The knowledge base may still *discuss* the type
/// name in §8.7, which it does inside a sentence — so the check is on the JSON
/// property form (`"runAutomationDetails"` as a key, or `runAutomationDetails.`
/// as a path) rather than on the bare token.
#[test]
fn sarif_run_object_uses_the_property_name_not_the_type_name() {
    let (findings, algorithms, policy) = make_findings();
    let json_str = emit_sarif(&findings, &algorithms, &policy, &default_opts())
        .expect("SARIF emission succeeds");
    let val: serde_json::Value = serde_json::from_str(&json_str).expect("valid JSON");
    let run = &val["runs"][0];

    assert!(
        run.get("runAutomationDetails").is_none(),
        "`run.runAutomationDetails` is a type name, not a property; `run` sets \
         additionalProperties:false so this fails schema validation"
    );
    assert!(
        run["automationDetails"]["id"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        "`run.automationDetails.id` must be a non-empty string"
    );

    // Direction two: no page in the tree teaches the wrong key.
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("repo root resolves");
    // This file is the one place the wrong form is written on purpose — the
    // assertion above has to name what it forbids. Excluded by path, not by
    // some cleverness that would also hide a real second offender.
    const GATE_SELF: &str = "quipuu/crates/report/tests/report_test.rs";
    let mut offenders: Vec<String> = Vec::new();
    for (path, text) in walk_text_files(&repo_root) {
        if path == GATE_SELF {
            continue;
        }
        for (n, line) in text.lines().enumerate() {
            if line.contains("\"runAutomationDetails\"") || line.contains("runAutomationDetails.") {
                offenders.push(format!("{}:{}", path, n + 1));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "`runAutomationDetails` used as a JSON property or path at {} site(s):\n  {}",
        offenders.len(),
        offenders.join("\n  ")
    );
}

/// Every tracked `.rs` / `.md` / `.json` / `.toml` file under `root`, as
/// (repo-relative path, contents). Build outputs and VCS internals are skipped;
/// unreadable files are skipped rather than silently treated as empty.
fn walk_text_files(root: &std::path::Path) -> Vec<(String, String)> {
    fn rec(dir: &std::path::Path, root: &std::path::Path, out: &mut Vec<(String, String)>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name == "target" || name == ".git" || name == "corpus-clones" {
                continue;
            }
            if path.is_dir() {
                rec(&path, root, out);
            } else if matches!(
                path.extension().and_then(|e| e.to_str()),
                Some("rs" | "md" | "json" | "toml" | "txt")
            ) && let Ok(text) = std::fs::read_to_string(&path)
            {
                let rel = path
                    .strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .into_owned();
                out.push((rel, text));
            }
        }
    }
    let mut out = Vec::new();
    rec(root, root, &mut out);
    out
}

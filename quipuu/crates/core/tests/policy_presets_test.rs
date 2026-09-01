//! Built-in policy presets.
//!
//! The `--policy` flag was documented on five public surfaces and implemented
//! on none; these tests exist so it cannot drift back. In particular
//! `documented_preset_names_match_the_shipped_ones` reads the public docs and
//! fails the build — not the reader — when they disagree with the code.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use quipuu_core::{
    Confidence, Exposure, Finding, Location, Policy, QuantumRiskScore, Severity, UsageContext,
    load_builtins,
};

fn repo_root() -> PathBuf {
    // crates/core → crates → quipuu → repo root
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("repo root above crates/core")
        .to_path_buf()
}

fn shipped_names() -> BTreeSet<String> {
    Policy::preset_names().map(str::to_string).collect()
}

/// Every preset name mentioned in a doc file, as `--policy <name>`,
/// `preset = "<name>"`, or inside the `policyPresets` array.
fn names_documented_in(text: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for (marker, terminators) in [
        ("--policy ", &[' ', '`', '\n', '|', ',', ')'][..]),
        ("preset = \"", &['"'][..]),
        ("preset=\"", &['"'][..]),
    ] {
        let mut rest = text;
        while let Some(i) = rest.find(marker) {
            rest = &rest[i + marker.len()..];
            let end = rest.find(terminators).unwrap_or(rest.len());
            let name = rest[..end].trim().trim_matches('`');
            // `--policy <file-or-preset>` and friends are placeholders.
            if !name.is_empty() && !name.starts_with('<') && !name.starts_with('$') {
                found.insert(name.to_string());
            }
        }
    }
    if let Some(i) = text.find("\"policyPresets\"") {
        let rest = &text[i..];
        if let (Some(a), Some(b)) = (rest.find('['), rest.find(']')) {
            for part in rest[a + 1..b].split(',') {
                let name = part.trim().trim_matches('"');
                if !name.is_empty() {
                    found.insert(name.to_string());
                }
            }
        }
    }
    found
}

#[test]
fn every_preset_loads_and_cross_checks() {
    let b = load_builtins().expect("builtins");
    for name in Policy::preset_names() {
        let policy = Policy::from_preset(name)
            .unwrap_or_else(|| panic!("`{name}` is listed but not built in"))
            .unwrap_or_else(|e| panic!("preset `{name}` failed to load: {e}"));
        assert_eq!(
            policy.meta.name, name,
            "meta.name must equal the preset key"
        );
        policy
            .cross_check(&b.algorithms)
            .unwrap_or_else(|e| panic!("preset `{name}` names an unknown algorithm: {e}"));
        assert!(
            !policy.meta.source_url.is_empty(),
            "preset `{name}` must cite a primary source"
        );
    }
}

/// Acronyms a preset's prose may use that are not algorithm names. Kept
/// short on purpose: an unrecognised capitalised token fails the test, so a
/// new one is a deliberate decision by whoever adds it rather than a silent
/// pass.
const NON_ALGORITHM_ACRONYMS: &[&str] = &["CNSA", "IPD", "IR", "NIST", "NOT", "NSA", "NSS", "SP"];

/// Tokens in `text` that look like algorithm names.
///
/// A candidate is a run of `[A-Za-z0-9^-]` carrying an uppercase letter
/// somewhere other than its first character — the shape shared by the
/// standards spellings (`ML-KEM-1024`, `XMSS^MT`, `SHA-384`) and by the
/// CamelCase ones (`FrodoKEM`). Ordinary sentence-initial words have their
/// only capital at position 0 and are not candidates; bare numbers have no
/// letter at all.
fn algorithm_like_tokens(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut push = |token: &str| {
        let token = token.trim_matches(|c| c == '-' || c == '^');
        let capitalised_after_start = token.chars().skip(1).any(|c: char| c.is_ascii_uppercase());
        if token.len() > 2 && capitalised_after_start {
            out.insert(token.to_string());
        }
    };
    let mut current = String::new();
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '^' {
            current.push(ch);
        } else {
            push(&current);
            current.clear();
        }
    }
    push(&current);
    out
}

/// A preset's `[meta].notes` may not name an algorithm the table lacks.
///
/// `nsa-cnsa2` advertised LMS and single-tree XMSS for firmware signing while
/// the table had no row for either, so a user selecting the preset read a
/// promise no finding could keep. The id lists were checked by
/// `Policy::cross_check` and the prose beside them was not, which is why the
/// defect survived being reported: it lived in the one part of the file
/// nothing read.
#[test]
fn preset_notes_name_only_algorithms_the_table_has() {
    let builtins = load_builtins().expect("builtins load");
    let table = &builtins.algorithms;

    for name in Policy::preset_names() {
        let policy = Policy::from_preset(name)
            .unwrap_or_else(|| panic!("preset `{name}` must exist"))
            .unwrap_or_else(|e| panic!("preset `{name}` failed to load: {e}"));

        for token in algorithm_like_tokens(&policy.meta.notes) {
            if NON_ALGORITHM_ACRONYMS.contains(&token.as_str()) {
                continue;
            }
            // `XMSS^MT` is the standards spelling of the id `xmss-mt`.
            let normalised = token.to_ascii_lowercase().replace('^', "-");
            let resolves = table.get(&normalised).is_some()
                || table.iter().any(|r| {
                    r.family.eq_ignore_ascii_case(&normalised)
                        || r.id.starts_with(&format!("{normalised}-"))
                });
            assert!(
                resolves,
                "preset `{name}` names `{token}` in [meta].notes, but no algorithm-table id, \
                 family or parameter set resolves it. Either add the row, stop naming it, or — \
                 if it is not an algorithm — add it to NON_ALGORITHM_ACRONYMS.",
            );
        }
    }
}

#[test]
fn nist_default_preset_is_the_builtin_default() {
    // `--policy nist-default` must be a no-op relative to passing no flag,
    // or every published precision figure quietly stops applying.
    let default = Policy::from_builtin().expect("builtin");
    let preset = Policy::from_preset("nist-default")
        .expect("listed")
        .expect("loads");
    assert_eq!(default.meta.name, preset.meta.name);
    assert_eq!(
        default.deprecation.policy_disallowed,
        preset.deprecation.policy_disallowed
    );
    assert!(
        default.deprecation.policy_disallowed.is_empty(),
        "nist-default must take no jurisdiction-specific position"
    );
    assert_eq!(
        default.severity_bands.critical,
        preset.severity_bands.critical
    );
}

#[test]
fn load_accepts_a_preset_name_a_path_and_rejects_anything_else() {
    assert!(Policy::load("nsa-cnsa2").is_ok());
    let path = repo_root().join("quipuu/crates/core/data/policies/nsa-cnsa2.toml");
    assert!(
        Policy::load(path.to_str().unwrap()).is_ok(),
        "a policy file path must load: {}",
        path.display()
    );
    let err = Policy::load("no-such-preset").expect_err("unknown names must be fatal");
    let msg = err.to_string();
    assert!(
        msg.contains("nist-default") && msg.contains("nsa-cnsa2"),
        "{msg}"
    );
}

#[test]
fn cnsa2_scores_aes_128_as_a_compliance_finding_and_nist_does_not() {
    let b = load_builtins().expect("builtins");
    let cnsa2 = Policy::from_preset("nsa-cnsa2")
        .expect("listed")
        .expect("loads");
    let aes128 = b.algorithms.get("aes-128-gcm").expect("aes-128-gcm");
    let finding = Finding {
        rule_id: "CRYPTO-XXX".into(),
        algorithm_id: "aes-128-gcm".into(),
        location: Location {
            location: "svc.go".into(),
            line: Some(7),
            offset: None,
            symbol: None,
            snippet: None,
        },
        message: String::new(),
        confidence: Confidence::TypeName,
        usage_context: UsageContext::DataAtRestEncryption,
        exposure: Exposure::PublicInternet,
        shelf_life_bucket: "short".into(),
        hndl_critical: false,
    };

    let nist = QuantumRiskScore::compute(&finding, aes128, &b.policy);
    let nss = QuantumRiskScore::compute(&finding, aes128, &cnsa2);
    // WeakenedByGrover 15 + 22 + 3 + 10 + 8 = 58 → High under IR 8547.
    assert_eq!(nist.algorithm_vulnerability, 15);
    assert_eq!(nist.severity, Severity::High);
    // Off the CNSA 2.0 suite: full 40 on the vulnerability axis, and the NSS
    // shelf-life default lifts the third axis from short to medium.
    assert_eq!(nss.algorithm_vulnerability, 40);
    assert_eq!(nss.severity, Severity::Critical);
    assert!(nss.total > nist.total);
}

#[test]
fn cnsa2_leaves_approved_algorithms_alone() {
    let b = load_builtins().expect("builtins");
    let cnsa2 = Policy::from_preset("nsa-cnsa2")
        .expect("listed")
        .expect("loads");
    for id in [
        "aes-256-gcm",
        "sha-384",
        "sha-512",
        "ml-kem-1024",
        "ml-dsa-87",
    ] {
        assert!(
            !cnsa2.disallows(id),
            "{id} is on the CNSA 2.0 approved list and must not be disallowed"
        );
        assert!(
            b.algorithms.get(id).is_some(),
            "{id} must exist in the table"
        );
    }
    for id in ["aes-128-gcm", "sha-256", "fn-dsa-512", "ml-kem-768"] {
        assert!(cnsa2.disallows(id), "{id} is off the CNSA 2.0 suite");
    }
}

#[test]
fn pqc_final_scores_safe_not_medium() {
    // `#T3`: a migrated PqcFinal algorithm must score Safe outright — none of
    // the other four axes may add up to an alert band on their own, or a
    // migrated codebase scores worse than an unmigrated one.
    let b = load_builtins().expect("builtins");
    let ml_kem_1024 = b.algorithms.get("ml-kem-1024").expect("ml-kem-1024");
    let finding = Finding {
        rule_id: "CRYPTO-XXX".into(),
        algorithm_id: "ml-kem-1024".into(),
        location: Location {
            location: "svc.go".into(),
            line: Some(7),
            offset: None,
            symbol: None,
            snippet: None,
        },
        message: String::new(),
        confidence: Confidence::TypeName,
        usage_context: UsageContext::KeyEstablishmentLongLived,
        exposure: Exposure::PublicInternet,
        shelf_life_bucket: "long".into(),
        hndl_critical: false,
    };

    let score = QuantumRiskScore::compute(&finding, ml_kem_1024, &b.policy);
    assert_eq!(score.algorithm_vulnerability, 0);
    assert_eq!(score.usage_context, 0);
    assert_eq!(score.data_shelf_life, 0);
    assert_eq!(score.exposure, 0);
    assert_eq!(score.detection_confidence, 0);
    assert_eq!(score.total, 0);
    assert_eq!(score.severity, Severity::Safe);
}

#[test]
fn pqc_final_disallowed_by_cnsa2_still_alerts() {
    // The Safe gate must key off the resolved algorithm_vulnerability score,
    // not off the quantum_status alone: ml-kem-768 is PqcFinal (same status as
    // ml-kem-1024 above) but CNSA 2.0 disallows it, which resolves to the full
    // axis weight via `Policy::disallows` before quantum_status is consulted —
    // it must not be gated to Safe just because its status says "final".
    let b = load_builtins().expect("builtins");
    let cnsa2 = Policy::from_preset("nsa-cnsa2")
        .expect("listed")
        .expect("loads");
    let ml_kem_768 = b.algorithms.get("ml-kem-768").expect("ml-kem-768");
    let finding = Finding {
        rule_id: "CRYPTO-XXX".into(),
        algorithm_id: "ml-kem-768".into(),
        location: Location {
            location: "svc.go".into(),
            line: Some(7),
            offset: None,
            symbol: None,
            snippet: None,
        },
        message: String::new(),
        confidence: Confidence::TypeName,
        usage_context: UsageContext::KeyEstablishmentLongLived,
        exposure: Exposure::PublicInternet,
        shelf_life_bucket: "long".into(),
        hndl_critical: false,
    };

    let score = QuantumRiskScore::compute(&finding, ml_kem_768, &cnsa2);
    assert_eq!(score.algorithm_vulnerability, 40);
    assert_ne!(score.severity, Severity::Safe);
    assert_eq!(score.severity, Severity::Critical);
}

#[test]
fn pqc_draft_is_not_gated_to_safe() {
    // PqcDraft = 5 under nist-default is deliberately nonzero (FN-DSA is
    // present but not yet final FIPS); the Safe gate must not fire for it.
    let b = load_builtins().expect("builtins");
    let fn_dsa = b.algorithms.get("fn-dsa-512").expect("fn-dsa-512");
    let finding = Finding {
        rule_id: "CRYPTO-XXX".into(),
        algorithm_id: "fn-dsa-512".into(),
        location: Location {
            location: "svc.go".into(),
            line: Some(7),
            offset: None,
            symbol: None,
            snippet: None,
        },
        message: String::new(),
        confidence: Confidence::TypeName,
        usage_context: UsageContext::KeyEstablishmentLongLived,
        exposure: Exposure::PublicInternet,
        shelf_life_bucket: "long".into(),
        hndl_critical: false,
    };

    let score = QuantumRiskScore::compute(&finding, fn_dsa, &b.policy);
    assert_eq!(score.algorithm_vulnerability, 5);
    assert!(score.total > 0);
    assert_ne!(score.severity, Severity::Safe);
}

#[test]
fn documented_preset_names_match_the_shipped_ones() {
    let shipped = shipped_names();
    let root = repo_root();
    let surfaces = [
        "README.md",
        "SPEC.md",
        "llms.txt",
        "llms-full.txt",
        "quipuu/MCP.md",
    ];
    let mut drift = Vec::new();
    for surface in surfaces {
        let path = root.join(surface);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
        for name in names_documented_in(&text) {
            if !shipped.contains(&name) {
                drift.push(format!("{surface} advertises `--policy {name}`"));
            }
        }
    }
    assert!(
        drift.is_empty(),
        "docs name presets the binary does not ship ({:?}):\n  {}",
        shipped,
        drift.join("\n  ")
    );
}

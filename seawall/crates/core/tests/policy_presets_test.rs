//! Built-in policy presets.
//!
//! The `--policy` flag was documented on five public surfaces and implemented
//! on none; these tests exist so it cannot drift back. In particular
//! `documented_preset_names_match_the_shipped_ones` reads the public docs and
//! fails the build — not the reader — when they disagree with the code.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use seawall_core::{
    Confidence, Exposure, Finding, Location, Policy, QuantumRiskScore, Severity, UsageContext,
    load_builtins,
};

fn repo_root() -> PathBuf {
    // crates/core → crates → seawall → repo root
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
    let path = repo_root().join("seawall/crates/core/data/policies/nsa-cnsa2.toml");
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
fn documented_preset_names_match_the_shipped_ones() {
    let shipped = shipped_names();
    let root = repo_root();
    let surfaces = [
        "README.md",
        "SPEC.md",
        "llms.txt",
        "llms-full.txt",
        "seawall/MCP.md",
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

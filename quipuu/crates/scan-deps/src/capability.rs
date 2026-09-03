//! PQC-capability version-floor signals.
//!
//! A **capability** signal is not a [`Finding`](quipuu_core::finding::Finding):
//! it does not claim a cryptographic operation happened anywhere, only that
//! the project's declared toolchain/language version is new enough to make a
//! PQC primitive available without any source change. Keeping it out of the
//! finding pipeline (no severity, no CBOM entry, no HNDL flag) is deliberate —
//! folding it in would silently upgrade "the runtime could do this" into "the
//! code does this", which is a false claim [[Precision-Tracker]] exists to
//! prevent.
//!
//! Four entries today, all picked for being the nearest, highest-certainty
//! version floors: Go's `go.mod` `go` directive at two separate floors —
//! stdlib `crypto/mlkem` (FIPS 203), available since Go 1.24, and stdlib
//! `crypto/mldsa` (FIPS 204), available since Go 1.27 — Maven's
//! `maven.compiler.release` property (JDK 27's default-on hybrid PQC TLS
//! groups, JEP 527, GA 2026-09-15), and `requirements.txt`'s `cryptography`
//! package pin (pyca/cryptography 50.0.0's X.509 verification APIs accept
//! ML-DSA-44/65/87 certificates by default, no call site needed). The two Go
//! floors are separate entries, not one: `go.dev/blog/go1.27` documents
//! `crypto/mldsa` as new in 1.27, three minor versions after `crypto/mlkem`
//! shipped at 1.24, so a project on `go 1.24`-`1.26` clears the mlkem floor
//! without clearing the mldsa one.

use std::path::{Path, PathBuf};

use ignore::WalkBuilder;

/// One version-floor entry: an ecosystem, the manifest field it reads, the
/// floor version, and what clearing it unlocks.
#[derive(Debug, Clone, Copy)]
pub struct CapabilityEntry {
    /// Manifest file name this entry applies to.
    pub manifest_file: &'static str,
    /// Human-readable name of the versioned field (e.g. "go.mod `go` directive").
    pub field: &'static str,
    /// Version floor, as `(major, minor)`. Met if the declared version is `>=`.
    pub floor: (u32, u32),
    /// What clearing the floor unlocks — kept factual and non-committal about
    /// whether the project actually uses it.
    pub unlocks: &'static str,
}

/// The built-in capability table.
pub static CAPABILITY_TABLE: &[CapabilityEntry] = &[
    CapabilityEntry {
        manifest_file: "go.mod",
        field: "go.mod `go` directive",
        floor: (1, 24),
        unlocks: "stdlib crypto/mlkem (FIPS 203) becomes available in the standard library — \
                  no third-party dependency needed to call it, though a project must still \
                  write the call site to use it",
    },
    CapabilityEntry {
        manifest_file: "go.mod",
        field: "go.mod `go` directive",
        floor: (1, 27),
        unlocks: "stdlib crypto/mldsa (FIPS 204) becomes available in the standard library — \
                  no third-party dependency needed to call it, though a project must still \
                  write the call site to use it. This is a separate, later floor than \
                  crypto/mlkem above: go.dev/blog/go1.27 documents crypto/mldsa as new in \
                  1.27, three minor versions after crypto/mlkem shipped at 1.24",
    },
    CapabilityEntry {
        manifest_file: "pom.xml",
        field: "maven.compiler.release",
        floor: (27, 0),
        unlocks: "javac targets JDK 27, which ships JEP 527's hybrid post-quantum TLS \
                  groups (X25519MLKEM768) default-on in javax.net.ssl for callers that use \
                  the default configuration — the JEP's own text states this needs no code \
                  change, so this floor alone is sufficient for TLS key establishment, \
                  unlike the Go entry above",
    },
    CapabilityEntry {
        manifest_file: "requirements.txt",
        field: "cryptography package version constraint",
        floor: (50, 0),
        unlocks: "pyca/cryptography's X.509 verification APIs (PolicyBuilder/Store) accept \
                  ML-DSA-44/65/87 (RFC 9881) public keys and signatures by default — like the \
                  Maven entry above, this needs no call site referencing ML-DSA at all, only \
                  ordinary X.509 chain verification through the library's standard path",
    },
];

/// One capability floor cleared by a project's manifest.
#[derive(Debug, Clone)]
pub struct CapabilitySignal {
    /// Manifest that declared the version.
    pub manifest_path: PathBuf,
    /// The [`CapabilityEntry`] whose floor was met.
    pub entry: &'static CapabilityEntry,
    /// The version actually declared in the manifest (e.g. `"1.26.0"`, `"27"`).
    pub declared_version: String,
}

/// Walk `root` for `go.mod` and `pom.xml` files and return every capability
/// floor they clear. Manifests that don't declare a parseable version for the
/// relevant field are silently skipped — this reports what is provably true,
/// not a best-effort guess about an unresolved Maven property.
pub fn scan_capabilities(root: &Path) -> Vec<CapabilitySignal> {
    let mut signals = Vec::new();
    let walker = WalkBuilder::new(root).follow_links(false).build();

    for result in walker {
        let entry = match result {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let file_name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };
        if file_name != "go.mod" && file_name != "pom.xml" && file_name != "requirements.txt" {
            continue;
        }

        let src = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(_) => continue,
        };

        match file_name {
            "go.mod" => {
                if let Some(declared) = parse_go_directive_version(&src) {
                    check_and_push(&mut signals, path, "go.mod", declared, &src);
                }
            }
            "pom.xml" => {
                if let Some(declared) = parse_maven_compiler_release(&src) {
                    check_and_push(&mut signals, path, "pom.xml", declared, &src);
                }
            }
            "requirements.txt" => {
                if let Some(declared) = parse_requirements_cryptography_version(&src) {
                    check_and_push(&mut signals, path, "requirements.txt", declared, &src);
                }
            }
            _ => unreachable!("filtered above"),
        }
    }

    signals
}

fn check_and_push(
    signals: &mut Vec<CapabilitySignal>,
    path: &Path,
    manifest_file: &'static str,
    declared: (u32, u32),
    raw_version: &str,
) {
    for capability_entry in CAPABILITY_TABLE {
        if capability_entry.manifest_file != manifest_file {
            continue;
        }
        if declared >= capability_entry.floor {
            signals.push(CapabilitySignal {
                manifest_path: path.to_path_buf(),
                entry: capability_entry,
                declared_version: format_declared(manifest_file, raw_version, declared),
            });
        }
    }
}

/// The raw text isn't kept per-field above; re-derive a display string from
/// the parsed `(major, minor)` pair so both ecosystems format consistently.
fn format_declared(manifest_file: &str, _raw: &str, declared: (u32, u32)) -> String {
    match manifest_file {
        "go.mod" | "requirements.txt" => format!("{}.{}", declared.0, declared.1),
        _ => declared.0.to_string(),
    }
}

/// Parse the top-level `go X.Y` (or `go X.Y.Z`) directive from a `go.mod`
/// file. Only the line starting with `go ` at the top level counts — this is
/// the module's minimum Go version, not a dependency's.
fn parse_go_directive_version(src: &str) -> Option<(u32, u32)> {
    for line in src.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("go ") {
            return parse_major_minor(rest.trim());
        }
    }
    None
}

/// Parse `maven.compiler.release` out of a `pom.xml`'s `<properties>` block.
/// Returns `None` for an unresolved property reference (e.g.
/// `${jdk.version}`) rather than guessing.
fn parse_maven_compiler_release(src: &str) -> Option<(u32, u32)> {
    let start = src.find("<maven.compiler.release>")? + "<maven.compiler.release>".len();
    let end = src[start..].find("</maven.compiler.release>")? + start;
    let value = src[start..end].trim();
    let major: u32 = value.parse().ok()?;
    Some((major, 0))
}

/// Parse the `cryptography` package's version constraint out of a
/// `requirements.txt` file. Only `==`, `>=`, and `~=` are treated as
/// establishing a floor a declared version can clear — a bare unversioned
/// name, `<`, `!=`, or an environment-marker suffix that leaves no
/// recognised operator is skipped rather than guessed, matching this
/// module's own "report what's provably true" principle already applied to
/// an unresolved Maven property above.
fn parse_requirements_cryptography_version(src: &str) -> Option<(u32, u32)> {
    for raw_line in src.lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('-') {
            continue;
        }
        let line = match trimmed.find('#') {
            Some(pos) => trimmed[..pos].trim(),
            None => trimmed,
        };

        let name_end = line
            .find(|c: char| !(c.is_alphanumeric() || c == '-' || c == '_' || c == '.'))
            .unwrap_or(line.len());
        let name = &line[..name_end];
        if !name.eq_ignore_ascii_case("cryptography") {
            continue;
        }

        let rest = line[name_end..].trim_start();
        // Skip past an extras marker: `cryptography[ssh]>=50.0`.
        let rest = match rest.strip_prefix('[') {
            Some(after_bracket) => {
                let end = after_bracket.find(']')?;
                after_bracket[end + 1..].trim_start()
            }
            None => rest,
        };

        return rest
            .strip_prefix(">=")
            .or_else(|| rest.strip_prefix("=="))
            .or_else(|| rest.strip_prefix("~="))
            .and_then(|version| parse_major_minor(version.trim()));
    }
    None
}

/// Parse a leading `X.Y` (ignoring any further `.Z` patch component) out of a
/// version string like `1.26.0` or `1.24`.
fn parse_major_minor(s: &str) -> Option<(u32, u32)> {
    let mut parts = s.split('.');
    let major: u32 = parts.next()?.parse().ok()?;
    let minor: u32 = parts.next().unwrap_or("0").parse().ok()?;
    Some((major, minor))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// A fresh, self-cleaning scratch directory — mirrors the pattern already
    /// used in `scan-source`'s tests (no `tempfile` dependency in this crate).
    struct ScratchDir(PathBuf);

    impl ScratchDir {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "quipuu-capability-{tag}-{}-{}",
                std::process::id(),
                line!()
            ));
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for ScratchDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn go_directive_below_floor_produces_no_signal() {
        let dir = ScratchDir::new("go-below");
        fs::write(
            dir.path().join("go.mod"),
            "module example.com/x\n\ngo 1.21\n",
        )
        .unwrap();
        let signals = scan_capabilities(dir.path());
        assert!(signals.is_empty());
    }

    #[test]
    fn go_directive_at_floor_produces_a_signal() {
        let dir = ScratchDir::new("go-at");
        fs::write(
            dir.path().join("go.mod"),
            "module example.com/x\n\ngo 1.24\n",
        )
        .unwrap();
        let signals = scan_capabilities(dir.path());
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].declared_version, "1.24");
        assert_eq!(signals[0].entry.manifest_file, "go.mod");
    }

    #[test]
    fn go_directive_above_floor_with_patch_version_produces_a_signal() {
        let dir = ScratchDir::new("go-above");
        fs::write(
            dir.path().join("go.mod"),
            "module example.com/x\n\ngo 1.26.3\n",
        )
        .unwrap();
        let signals = scan_capabilities(dir.path());
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].declared_version, "1.26");
    }

    /// `go 1.24`-`1.26` clears only the `crypto/mlkem` floor (FIPS 203); the
    /// `crypto/mldsa` floor (FIPS 204) is later, at 1.27 — the split #Y150
    /// fixed after the two were shipped bundled under a single 1.24 floor.
    #[test]
    fn go_directive_below_mldsa_floor_unlocks_only_mlkem() {
        for version in ["1.24", "1.25", "1.26"] {
            let dir = ScratchDir::new("go-mlkem-only");
            fs::write(
                dir.path().join("go.mod"),
                format!("module example.com/x\n\ngo {version}\n"),
            )
            .unwrap();
            let signals = scan_capabilities(dir.path());
            assert_eq!(
                signals.len(),
                1,
                "go {version} should clear exactly one floor"
            );
            assert!(
                signals[0].entry.unlocks.contains("crypto/mlkem"),
                "go {version} should unlock crypto/mlkem"
            );
            assert!(
                !signals[0].entry.unlocks.contains("crypto/mldsa"),
                "go {version} should not unlock crypto/mldsa"
            );
        }
    }

    #[test]
    fn go_directive_at_mldsa_floor_unlocks_both() {
        let dir = ScratchDir::new("go-both");
        fs::write(
            dir.path().join("go.mod"),
            "module example.com/x\n\ngo 1.27\n",
        )
        .unwrap();
        let signals = scan_capabilities(dir.path());
        assert_eq!(signals.len(), 2);
        assert!(
            signals
                .iter()
                .any(|s| s.entry.unlocks.contains("crypto/mlkem"))
        );
        assert!(
            signals
                .iter()
                .any(|s| s.entry.unlocks.contains("crypto/mldsa"))
        );
    }

    #[test]
    fn maven_release_below_floor_produces_no_signal() {
        let dir = ScratchDir::new("maven-below");
        fs::write(
            dir.path().join("pom.xml"),
            "<project><properties><maven.compiler.release>8</maven.compiler.release></properties></project>",
        )
        .unwrap();
        let signals = scan_capabilities(dir.path());
        assert!(signals.is_empty());
    }

    #[test]
    fn maven_release_at_floor_produces_a_signal() {
        let dir = ScratchDir::new("maven-at");
        fs::write(
            dir.path().join("pom.xml"),
            "<project><properties><maven.compiler.release>27</maven.compiler.release></properties></project>",
        )
        .unwrap();
        let signals = scan_capabilities(dir.path());
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].declared_version, "27");
        assert_eq!(signals[0].entry.manifest_file, "pom.xml");
    }

    #[test]
    fn maven_release_unresolved_property_is_skipped_not_guessed() {
        let dir = ScratchDir::new("maven-unresolved");
        fs::write(
            dir.path().join("pom.xml"),
            "<project><properties><maven.compiler.release>${jdk.version}</maven.compiler.release></properties></project>",
        )
        .unwrap();
        let signals = scan_capabilities(dir.path());
        assert!(signals.is_empty());
    }

    #[test]
    fn requirements_txt_cryptography_below_floor_produces_no_signal() {
        let dir = ScratchDir::new("reqs-below");
        fs::write(
            dir.path().join("requirements.txt"),
            "cryptography>=48.0.0\n",
        )
        .unwrap();
        let signals = scan_capabilities(dir.path());
        assert!(signals.is_empty());
    }

    #[test]
    fn requirements_txt_cryptography_at_floor_produces_a_signal() {
        let dir = ScratchDir::new("reqs-at");
        fs::write(
            dir.path().join("requirements.txt"),
            "cryptography>=50.0.0\n",
        )
        .unwrap();
        let signals = scan_capabilities(dir.path());
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].declared_version, "50.0");
        assert_eq!(signals[0].entry.manifest_file, "requirements.txt");
    }

    #[test]
    fn requirements_txt_cryptography_unpinned_dependency_is_skipped_not_guessed() {
        let dir = ScratchDir::new("reqs-unpinned");
        fs::write(dir.path().join("requirements.txt"), "cryptography\n").unwrap();
        let signals = scan_capabilities(dir.path());
        assert!(signals.is_empty());
    }

    #[test]
    fn requirements_txt_cryptography_upper_bound_only_is_skipped_not_guessed() {
        let dir = ScratchDir::new("reqs-upper-bound");
        fs::write(dir.path().join("requirements.txt"), "cryptography<50.0.0\n").unwrap();
        let signals = scan_capabilities(dir.path());
        assert!(signals.is_empty());
    }

    #[test]
    fn manifest_with_no_relevant_field_produces_no_signal() {
        let dir = ScratchDir::new("go-no-directive");
        fs::write(dir.path().join("go.mod"), "module example.com/x\n").unwrap();
        let signals = scan_capabilities(dir.path());
        assert!(signals.is_empty());
    }
}

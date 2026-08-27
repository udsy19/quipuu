//! `seawall-scan-deps` — dependency-manifest scanner.
//!
//! Walks a directory tree, finds known manifest files (`go.mod`, `Cargo.toml`,
//! `requirements.txt`, `package.json`, `pom.xml`), parses them, matches every
//! declared dependency against the built-in crypto-library catalogue, and
//! returns [`Finding`]s.
//!
//! # Quick start
//! ```no_run
//! use seawall_scan_deps::DepScanner;
//! use std::path::Path;
//!
//! let scanner = DepScanner::with_builtins();
//! let findings = scanner.scan_path(Path::new(".")).unwrap();
//! println!("{} findings", findings.len());
//! ```

pub mod catalogue;
pub mod parsers;

use std::path::{Path, PathBuf};

use ignore::WalkBuilder;
use regex::Regex;
use seawall_core::finding::{Confidence, Exposure, Finding, Location, UsageContext};
use thiserror::Error;

use catalogue::{CatalogueEntry, Ecosystem};
use parsers::RawDep;

// ============================================================================
// Error type
// ============================================================================

/// Errors that can occur during a dependency scan.
#[derive(Debug, Error)]
pub enum ScanError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("parse error in {manifest}: {reason}")]
    Parse { manifest: PathBuf, reason: String },

    #[error("directory walk error: {0}")]
    Walk(#[from] ignore::Error),
}

// ============================================================================
// Compiled catalogue entry
// ============================================================================

struct CompiledEntry {
    regex: Regex,
    entry: &'static CatalogueEntry,
}

// ============================================================================
// DepScanner
// ============================================================================

/// Scanner that parses dependency manifests and emits [`Finding`]s for every
/// dependency that matches the built-in cryptographic-library catalogue.
pub struct DepScanner {
    entries: Vec<CompiledEntry>,
}

impl DepScanner {
    /// Build a [`DepScanner`] pre-loaded with the built-in catalogue.
    pub fn with_builtins() -> Self {
        let entries = catalogue::CATALOGUE
            .iter()
            .map(|e| CompiledEntry {
                regex: Regex::new(e.package_pattern).expect("catalogue regex must compile"),
                entry: e,
            })
            .collect();
        Self { entries }
    }

    /// Scan `root` recursively and return all findings.
    ///
    /// The walk respects `.gitignore` rules (via the `ignore` crate).
    /// Parse errors for individual manifests are **not** fatal — they are
    /// logged via `tracing::warn!`. Only I/O errors on the walk itself
    /// propagate. To capture per-manifest errors in a structured form use
    /// [`scan_path_collecting`](Self::scan_path_collecting).
    pub fn scan_path(&self, root: &Path) -> Result<Vec<Finding>, ScanError> {
        let mut warnings = Vec::new();
        self.scan_path_collecting(root, &mut warnings)
    }

    /// Like [`scan_path`] but pushes per-manifest parse failures onto
    /// `warnings` as structured [`ScanWarning`]s. Phase 6.
    pub fn scan_path_collecting(
        &self,
        root: &Path,
        warnings: &mut Vec<seawall_core::ScanWarning>,
    ) -> Result<Vec<Finding>, ScanError> {
        use seawall_core::{ScanWarning, ScanWarningKind};

        let mut findings = Vec::new();
        let walker = WalkBuilder::new(root).follow_links(false).build();

        for result in walker {
            let entry = match result {
                Ok(e) => e,
                Err(e) => {
                    warnings.push(ScanWarning::new(
                        ScanWarningKind::WalkError,
                        None,
                        format!("scan-deps walk: {e}"),
                    ));
                    continue;
                }
            };
            let path = entry.path();

            if !path.is_file() {
                continue;
            }

            let file_name = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n,
                None => continue,
            };

            let manifest_findings = match file_name {
                "go.mod" => self.scan_manifest(path, Ecosystem::Go, parsers::parse_go_mod),
                "Cargo.toml" => {
                    self.scan_manifest(path, Ecosystem::Rust, parsers::parse_cargo_toml)
                }
                "requirements.txt" => {
                    self.scan_manifest(path, Ecosystem::Python, parsers::parse_requirements_txt)
                }
                "package.json" => {
                    self.scan_manifest(path, Ecosystem::JavaScript, parsers::parse_package_json)
                }
                "pom.xml" => self.scan_manifest(path, Ecosystem::Maven, parsers::parse_pom_xml),
                _ => continue,
            };

            match manifest_findings {
                Ok(mut fs) => findings.append(&mut fs),
                Err(e) => {
                    tracing::warn!("scan-deps: skipping {}: {}", path.display(), e);
                    warnings.push(ScanWarning::new(
                        ScanWarningKind::DepManifestError,
                        Some(path.to_path_buf()),
                        e.to_string(),
                    ));
                }
            }
        }

        Ok(findings)
    }

    // ------------------------------------------------------------------------

    fn scan_manifest<F>(
        &self,
        path: &Path,
        ecosystem: Ecosystem,
        parse: F,
    ) -> Result<Vec<Finding>, ScanError>
    where
        F: FnOnce(&Path) -> Result<Vec<RawDep>, ScanError>,
    {
        let raw_deps = parse(path)?;
        let mut findings = Vec::new();

        for dep in &raw_deps {
            for compiled in &self.entries {
                if compiled.entry.ecosystem != ecosystem {
                    continue;
                }
                // Match against the package name.  For Maven the name is
                // `groupId:artifactId`; for all others it's the plain name.
                if !compiled.regex.is_match(&dep.name) {
                    continue;
                }

                let entry = compiled.entry;
                let symbol = build_symbol(ecosystem, &dep.name);
                let version_label = if dep.version.is_empty() {
                    "(unknown version)".to_string()
                } else {
                    dep.version.clone()
                };

                let finding = Finding {
                    rule_id: "DEP-001".to_string(),
                    algorithm_id: entry.algorithm_id.to_string(),
                    location: Location {
                        location: path.to_string_lossy().into_owned(),
                        line: Some(dep.line),
                        offset: None,
                        symbol: Some(symbol.clone()),
                        snippet: Some(dep.snippet.clone()),
                    },
                    message: format!(
                        "{} package {} {} matches catalogue entry: {}",
                        ecosystem.label(),
                        dep.name,
                        version_label,
                        entry.note,
                    ),
                    confidence: Confidence::TypeName,
                    usage_context: UsageContext::Unknown,
                    exposure: Exposure::InternalService,
                    shelf_life_bucket: "short".to_string(),
                    hndl_critical: false,
                };

                findings.push(finding);
                // One match per dep per entry is sufficient; a dep should only
                // match one catalogue entry in practice (patterns are precise).
                break;
            }
        }

        Ok(findings)
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn build_symbol(ecosystem: Ecosystem, name: &str) -> String {
    match ecosystem {
        Ecosystem::Maven => format!("maven:{}", name),
        other => format!("{}:{}", other.label(), name),
    }
}

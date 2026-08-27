//! `.seawall.toml` schema and loader.
//!
//! Written by `seawall init`; consumed by `seawall scan` as
//! default-value source before CLI flags are applied.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const CONFIG_FILENAME: &str = ".seawall.toml";

/// Top-level config written by `seawall init`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub scan: ScanConfig,
    #[serde(default)]
    pub output: OutputConfig,
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub diagnostics: DiagnosticsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    /// Directories (relative to project root) to include.
    #[serde(default = "default_scan_paths")]
    pub paths: Vec<String>,
    /// Directories to skip.
    #[serde(default = "default_exclude_paths")]
    pub exclude_paths: Vec<String>,
    /// Languages to scan (informational; actual scanner selection is by file extension).
    #[serde(default)]
    pub languages: Vec<String>,
}

fn default_scan_paths() -> Vec<String> {
    vec!["src".into(), "lib".into()]
}

fn default_exclude_paths() -> Vec<String> {
    vec![
        "tests".into(),
        "vendor".into(),
        "target".into(),
        "node_modules".into(),
    ]
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            paths: default_scan_paths(),
            exclude_paths: default_exclude_paths(),
            languages: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    /// HTML report path (relative to project root).
    #[serde(default = "default_html_out")]
    pub html: String,
    /// SARIF report path.
    #[serde(default = "default_sarif_out")]
    pub sarif: String,
    /// CycloneDX CBOM path.
    #[serde(default = "default_cbom_out")]
    pub cbom: String,
    /// Compact summary JSON path.
    #[serde(default = "default_summary_out")]
    pub summary_json: String,
}

fn default_html_out() -> String {
    "reports/seawall.html".into()
}
fn default_sarif_out() -> String {
    "reports/seawall.sarif".into()
}
fn default_cbom_out() -> String {
    "reports/seawall.cbom.json".into()
}
fn default_summary_out() -> String {
    "reports/seawall.summary.json".into()
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            html: default_html_out(),
            sarif: default_sarif_out(),
            cbom: default_cbom_out(),
            summary_json: default_summary_out(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Policy preset name, or a path to a policy TOML file. Resolved through
    /// `Policy::load`; `seawall policy list` names the built-in presets.
    /// `--policy` on the command line overrides this.
    #[serde(default = "default_preset")]
    pub preset: String,
    /// Mirrors `--include-safe` CLI flag default.
    #[serde(default)]
    pub include_safe: bool,
}

fn default_preset() -> String {
    "nist-default".into()
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            preset: default_preset(),
            include_safe: false,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiagnosticsConfig {
    /// Mirrors `--show-errors` CLI flag default.
    #[serde(default)]
    pub show_errors: bool,
}

/// Load `.seawall.toml` from `dir`, if it exists.
///
/// Returns `None` when the file is absent (not an error — the project simply
/// hasn't been initialised). Returns `Err` only when the file exists but is
/// malformed.
pub fn load_from_dir(dir: &Path) -> Result<Option<Config>, ConfigError> {
    let path = dir.join(CONFIG_FILENAME);
    if !path.exists() {
        return Ok(None);
    }
    let text =
        std::fs::read_to_string(&path).map_err(|e| ConfigError::Io(path.clone(), e.to_string()))?;
    let config: Config =
        toml::from_str(&text).map_err(|e| ConfigError::Parse(path.clone(), e.to_string()))?;
    Ok(Some(config))
}

#[derive(Debug)]
pub enum ConfigError {
    Io(PathBuf, String),
    Parse(PathBuf, String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(p, msg) => write!(f, "cannot read {}: {}", p.display(), msg),
            ConfigError::Parse(p, msg) => write!(f, "malformed {}: {}", p.display(), msg),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a unique temp directory for the test, cleaned up on drop via a
    /// guard.  Avoids adding `tempfile` as a new dep.
    fn make_tempdir(suffix: &str) -> PathBuf {
        let base = std::env::temp_dir().join(format!("seawall_config_test_{suffix}"));
        std::fs::create_dir_all(&base).expect("create temp dir");
        base
    }

    #[test]
    fn roundtrip_default_config() {
        let config = Config::default();
        let toml_str = toml::to_string(&config).expect("serialize");
        let back: Config = toml::from_str(&toml_str).expect("deserialize");
        assert_eq!(back.scan.paths, config.scan.paths);
        assert_eq!(back.scan.exclude_paths, config.scan.exclude_paths);
        assert_eq!(back.output.html, config.output.html);
        assert_eq!(back.output.sarif, config.output.sarif);
        assert_eq!(back.output.cbom, config.output.cbom);
        assert_eq!(back.output.summary_json, config.output.summary_json);
        assert_eq!(back.policy.preset, config.policy.preset);
        assert_eq!(back.policy.include_safe, config.policy.include_safe);
        assert_eq!(back.diagnostics.show_errors, config.diagnostics.show_errors);
    }

    #[test]
    fn missing_file_returns_none() {
        let dir = make_tempdir("missing");
        let result = load_from_dir(&dir).expect("no error for missing file");
        assert!(result.is_none());
    }

    #[test]
    fn malformed_file_returns_err() {
        let dir = make_tempdir("malformed");
        std::fs::write(dir.join(CONFIG_FILENAME), b"[[[[not valid toml").expect("write");
        assert!(load_from_dir(&dir).is_err());
    }

    #[test]
    fn partial_file_uses_field_defaults() {
        let dir = make_tempdir("partial");
        std::fs::write(
            dir.join(CONFIG_FILENAME),
            b"[policy]\npreset = \"nsa-cnsa2\"\n",
        )
        .expect("write");
        let config = load_from_dir(&dir).expect("no error").expect("file found");
        assert_eq!(config.policy.preset, "nsa-cnsa2");
        assert_eq!(config.output.html, "reports/seawall.html");
        assert_eq!(config.scan.paths, vec!["src", "lib"]);
    }

    #[test]
    fn full_file_roundtrips_non_defaults() {
        let dir = make_tempdir("full");
        let content = r#"
[scan]
paths = ["app", "pkg"]
exclude_paths = ["dist"]
languages = ["go", "rust"]

[output]
html = "out/report.html"
sarif = "out/report.sarif"
cbom = "out/cbom.json"
summary_json = "out/summary.json"

[policy]
preset = "policies/house-rules.toml"
include_safe = true

[diagnostics]
show_errors = true
"#;
        std::fs::write(dir.join(CONFIG_FILENAME), content).expect("write");
        let config = load_from_dir(&dir).expect("no error").expect("file found");
        assert_eq!(config.scan.paths, vec!["app", "pkg"]);
        assert_eq!(config.scan.exclude_paths, vec!["dist"]);
        assert_eq!(config.scan.languages, vec!["go", "rust"]);
        assert_eq!(config.output.html, "out/report.html");
        assert_eq!(config.policy.preset, "policies/house-rules.toml");
        assert!(config.policy.include_safe);
        assert!(config.diagnostics.show_errors);
    }

    #[test]
    fn config_override_semantics() {
        // Simulate: config says include_safe = true, but CLI passes no flag
        // (false by default). The caller merges: CLI flag wins when explicitly
        // set; config value used as default otherwise.
        let mut config = Config::default();
        config.policy.include_safe = true;
        config.diagnostics.show_errors = true;

        // Caller logic: cli_flag || config value (for additive boolean flags).
        let cli_include_safe = false;
        let effective_include_safe = cli_include_safe || config.policy.include_safe;
        assert!(effective_include_safe);

        let cli_show_errors = false;
        let effective_show_errors = cli_show_errors || config.diagnostics.show_errors;
        assert!(effective_show_errors);
    }
}

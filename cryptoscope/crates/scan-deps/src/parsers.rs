//! Manifest parsers — one sub-module per file type.
//!
//! Each parser returns a [`Vec<RawDep>`]: the package name, optional version,
//! and the 1-based line number where the declaration was found.

use std::path::Path;

use crate::ScanError;

/// A raw dependency extracted from a manifest file before catalogue matching.
#[derive(Debug, Clone)]
pub struct RawDep {
    /// Normalised package name (lowercase for ecosystems that are case-insensitive).
    pub name: String,
    /// Version string as written in the manifest (empty if absent).
    pub version: String,
    /// 1-based line number in the manifest file.
    pub line: u32,
    /// The verbatim line from the file.
    pub snippet: String,
}

// ============================================================================
// go.mod
// ============================================================================

/// Parse a `go.mod` file and return all direct + indirect dependencies.
///
/// Lines of interest:
/// * `require <pkg> <version>` (single-line form)
/// * Inside a `require ( ... )` block: `<pkg> <version>`
/// * Lines ending with `// indirect` are still captured (they are real
///   dependencies that may be crypto-relevant).
pub fn parse_go_mod(path: &Path) -> Result<Vec<RawDep>, ScanError> {
    let src = std::fs::read_to_string(path).map_err(ScanError::Io)?;
    let mut deps = Vec::new();
    let mut in_require_block = false;

    for (idx, raw_line) in src.lines().enumerate() {
        let lineno = (idx + 1) as u32;
        let trimmed = raw_line.trim();

        // Strip inline comments: `foo v1.0.0 // indirect`
        let line = if let Some(pos) = trimmed.find("//") {
            trimmed[..pos].trim()
        } else {
            trimmed
        };

        if line == "require (" || line == "require(" {
            in_require_block = true;
            continue;
        }
        if in_require_block && line == ")" {
            in_require_block = false;
            continue;
        }

        if in_require_block {
            // `\t<pkg> <version>`
            let mut parts = line.split_whitespace();
            if let (Some(pkg), Some(ver)) = (parts.next(), parts.next()) {
                deps.push(RawDep {
                    name: pkg.to_string(),
                    version: ver.to_string(),
                    line: lineno,
                    snippet: raw_line.to_string(),
                });
            }
        } else if let Some(rest) = line.strip_prefix("require ") {
            // single-line: `require <pkg> <version>`
            let mut parts = rest.split_whitespace();
            if let (Some(pkg), Some(ver)) = (parts.next(), parts.next()) {
                deps.push(RawDep {
                    name: pkg.to_string(),
                    version: ver.to_string(),
                    line: lineno,
                    snippet: raw_line.to_string(),
                });
            }
        }
    }

    Ok(deps)
}

// ============================================================================
// Cargo.toml
// ============================================================================

/// Parse a `Cargo.toml` file and return dependencies from all dep sections.
///
/// Supports:
/// * `[dependencies]`, `[dev-dependencies]`, `[build-dependencies]`
/// * Simple form: `crate = "version"`
/// * Table form: `crate = { version = "...", ... }`
/// * Workspace form: `crate = { workspace = true }` — captured without version
pub fn parse_cargo_toml(path: &Path) -> Result<Vec<RawDep>, ScanError> {
    let src = std::fs::read_to_string(path).map_err(ScanError::Io)?;
    let mut deps = Vec::new();

    let in_dep_section = |header: &str| -> bool {
        matches!(
            header,
            "[dependencies]" | "[dev-dependencies]" | "[build-dependencies]"
        )
    };

    let mut active_section = false;

    for (idx, raw_line) in src.lines().enumerate() {
        let lineno = (idx + 1) as u32;
        let trimmed = raw_line.trim();

        // Detect section headers
        if trimmed.starts_with('[') {
            active_section = in_dep_section(trimmed);
            continue;
        }

        if !active_section {
            continue;
        }

        // Skip comments and blank lines
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Parse `name = ...`
        if let Some(eq_pos) = trimmed.find('=') {
            let name = trimmed[..eq_pos].trim().to_string();
            let rhs = trimmed[eq_pos + 1..].trim();

            // Simple string version: `name = "0.1"`
            let version = if rhs.starts_with('"') {
                rhs.trim_matches('"').to_string()
            } else if rhs.starts_with('{') {
                // Table form — extract `version = "..."` if present
                extract_toml_inline_version(rhs).unwrap_or_default()
            } else {
                String::new()
            };

            deps.push(RawDep {
                name,
                version,
                line: lineno,
                snippet: raw_line.to_string(),
            });
        }
    }

    Ok(deps)
}

/// Crude inline-table version extractor: `{ version = "0.1", ... }` → `"0.1"`.
fn extract_toml_inline_version(s: &str) -> Option<String> {
    // Look for `version = "..."` inside the inline table
    let needle = "version";
    let pos = s.find(needle)?;
    let after = s[pos + needle.len()..].trim_start();
    let after = after.strip_prefix('=')?;
    let after = after.trim_start();
    if after.starts_with('"') {
        let inner = after.trim_start_matches('"');
        let end = inner.find('"')?;
        Some(inner[..end].to_string())
    } else {
        None
    }
}

// ============================================================================
// requirements.txt
// ============================================================================

/// Parse a `requirements.txt` file.
///
/// Handles:
/// * `pkg==1.0.0`
/// * `pkg>=1.0.0`
/// * `pkg~=1.0.0`
/// * `pkg` (no version constraint)
/// * Lines starting with `#` are comments; `-r`, `-c`, `-e` are skipped.
pub fn parse_requirements_txt(path: &Path) -> Result<Vec<RawDep>, ScanError> {
    let src = std::fs::read_to_string(path).map_err(ScanError::Io)?;
    let mut deps = Vec::new();

    for (idx, raw_line) in src.lines().enumerate() {
        let lineno = (idx + 1) as u32;
        let trimmed = raw_line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // Skip pip flags
        if trimmed.starts_with('-') {
            continue;
        }

        // Strip inline comments
        let line = if let Some(pos) = trimmed.find('#') {
            trimmed[..pos].trim()
        } else {
            trimmed
        };

        // Find the operator boundary (==, >=, <=, ~=, !=, >)
        let (name, version) = split_requirement(line);

        deps.push(RawDep {
            name: name.to_string(),
            version: version.to_string(),
            line: lineno,
            snippet: raw_line.to_string(),
        });
    }

    Ok(deps)
}

/// Split `pkg==1.0` into `("pkg", "1.0")`.
fn split_requirement(s: &str) -> (&str, &str) {
    // Find the first occurrence of `=`, `>`, `<`, `~`, `!`
    if let Some(pos) = s.find(['=', '>', '<', '~', '!']) {
        let name = s[..pos].trim();
        let rest = s[pos..]
            .trim_start_matches(['=', '>', '<', '~', '!'])
            .trim();
        (name, rest)
    } else {
        (s.trim(), "")
    }
}

// ============================================================================
// package.json
// ============================================================================

/// Parse `dependencies` and `devDependencies` from a `package.json` file.
pub fn parse_package_json(path: &Path) -> Result<Vec<RawDep>, ScanError> {
    let src = std::fs::read_to_string(path).map_err(ScanError::Io)?;
    let value: serde_json::Value = serde_json::from_str(&src).map_err(|e| ScanError::Parse {
        manifest: path.to_path_buf(),
        reason: e.to_string(),
    })?;

    let mut deps = Vec::new();

    for section_key in &["dependencies", "devDependencies"] {
        if let Some(obj) = value.get(section_key).and_then(|v| v.as_object()) {
            for (name, ver_val) in obj {
                let version = ver_val.as_str().unwrap_or("").to_string();
                // Determine the line number by searching for the key in the
                // source text (best-effort; line numbers are informational).
                let lineno = find_line_in_source(&src, name);
                deps.push(RawDep {
                    name: name.clone(),
                    version,
                    line: lineno,
                    snippet: format!("\"{}\"", name),
                });
            }
        }
    }

    Ok(deps)
}

/// Return the 1-based line number of the first occurrence of `needle` in `src`,
/// or 1 as a safe fallback.
fn find_line_in_source(src: &str, needle: &str) -> u32 {
    for (idx, line) in src.lines().enumerate() {
        if line.contains(needle) {
            return (idx + 1) as u32;
        }
    }
    1
}

// ============================================================================
// pom.xml
// ============================================================================

/// Parse `<dependency>` elements from a Maven `pom.xml`.
///
/// We look for the pattern:
/// ```xml
/// <dependency>
///   <groupId>...</groupId>
///   <artifactId>...</artifactId>
///   <version>...</version>   (optional)
/// </dependency>
/// ```
pub fn parse_pom_xml(path: &Path) -> Result<Vec<RawDep>, ScanError> {
    use quick_xml::Reader;
    use quick_xml::events::Event;

    let src = std::fs::read_to_string(path).map_err(ScanError::Io)?;

    let mut reader = Reader::from_str(&src);
    reader.config_mut().trim_text(true);

    let mut deps: Vec<RawDep> = Vec::new();

    // State machine
    let mut in_dependency = false;
    let mut depth_at_entry: usize = 0;
    let mut depth: usize = 0;
    let mut group_id = String::new();
    let mut artifact_id = String::new();
    let mut version = String::new();
    let mut current_tag = String::new();
    let mut dep_start_line: u32 = 1;

    // Track line numbers by counting newlines up to the byte offset.
    // quick-xml exposes `reader.buffer_position()` which is byte offset.
    let byte_to_line =
        |offset: usize| -> u32 { src[..offset].chars().filter(|&c| c == '\n').count() as u32 + 1 };

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) => {
                depth += 1;
                let tag = std::str::from_utf8(e.name().as_ref())
                    .unwrap_or("")
                    .to_string();
                if tag == "dependency" && !in_dependency {
                    in_dependency = true;
                    depth_at_entry = depth;
                    group_id.clear();
                    artifact_id.clear();
                    version.clear();
                    dep_start_line = byte_to_line(reader.buffer_position() as usize);
                }
                current_tag = tag;
            }
            Ok(Event::Text(ref e)) => {
                if in_dependency {
                    let text = e.decode().map(|c| c.into_owned()).unwrap_or_default();
                    match current_tag.as_str() {
                        "groupId" => group_id = text,
                        "artifactId" => artifact_id = text,
                        "version" => version = text,
                        _ => {}
                    }
                }
            }
            Ok(Event::End(ref e)) => {
                let tag = std::str::from_utf8(e.name().as_ref())
                    .unwrap_or("")
                    .to_string();
                if in_dependency && tag == "dependency" && depth == depth_at_entry {
                    if !group_id.is_empty() && !artifact_id.is_empty() {
                        let name = format!("{}:{}", group_id, artifact_id);
                        deps.push(RawDep {
                            name,
                            version: version.clone(),
                            line: dep_start_line,
                            snippet: format!(
                                "<dependency>{}:{}</dependency>",
                                group_id, artifact_id
                            ),
                        });
                    }
                    in_dependency = false;
                }
                depth = depth.saturating_sub(1);
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(ScanError::Parse {
                    manifest: path.to_path_buf(),
                    reason: e.to_string(),
                });
            }
            _ => {}
        }
    }

    Ok(deps)
}

//! cryptoscope CLI — walking-skeleton entrypoint.
//!
//! Full `clap` derive integration follows per SPEC.md §11. For now the CLI
//! supports a minimal `scan <path>` subcommand so we can demo the end-to-end
//! pipeline.

use std::path::PathBuf;
use std::process::ExitCode;

use cryptoscope_cbom::SchemaVersion;
use cryptoscope_cbom::emit::{EmitOptions, ScanTarget};
use cryptoscope_cbom::emit_cbom_json;
use cryptoscope_core::{QuantumRiskScore, load_builtins};
use cryptoscope_scan_source::Scanner;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        None | Some("--help") | Some("-h") => {
            print_help();
            ExitCode::SUCCESS
        }
        Some("--version") | Some("-V") => {
            println!("cryptoscope {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some("scan") => match args.get(2) {
            Some(path) => {
                let opts = parse_scan_flags(&args[3..]);
                run_scan(PathBuf::from(path), opts)
            }
            None => {
                eprintln!("cryptoscope: scan requires a path argument");
                ExitCode::FAILURE
            }
        },
        Some(other) => {
            eprintln!("cryptoscope: unknown command `{other}`");
            print_help();
            ExitCode::FAILURE
        }
    }
}

fn print_help() {
    println!(
        r#"cryptoscope {ver} — cryptographic discovery scanner

USAGE:
    cryptoscope scan <path> [FLAGS]

FLAGS:
    --cbom <file>             Emit a CycloneDX CBOM to <file>
    --schema-version <ver>    1.6 or 1.7 (default 1.7)
    --version                 Print version
    --help                    Print this help

This is a walking-skeleton build. Full clap CLI per SPEC.md §11 to follow."#,
        ver = env!("CARGO_PKG_VERSION"),
    );
}

#[derive(Default)]
struct ScanFlags {
    cbom_out: Option<PathBuf>,
    schema_version: Option<SchemaVersion>,
}

fn parse_scan_flags(tail: &[String]) -> ScanFlags {
    let mut flags = ScanFlags::default();
    let mut it = tail.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--cbom" => {
                if let Some(p) = it.next() {
                    flags.cbom_out = Some(PathBuf::from(p));
                }
            }
            "--schema-version" => {
                if let Some(v) = it.next() {
                    flags.schema_version = match v.as_str() {
                        "1.6" => Some(SchemaVersion::V1_6),
                        "1.7" => Some(SchemaVersion::V1_7),
                        _ => {
                            eprintln!(
                                "cryptoscope: unknown --schema-version `{v}` (use 1.6 or 1.7)"
                            );
                            None
                        }
                    };
                }
            }
            other => {
                eprintln!("cryptoscope: ignoring unknown flag `{other}`");
            }
        }
    }
    flags
}

fn run_scan(path: PathBuf, flags: ScanFlags) -> ExitCode {
    let builtins = match load_builtins() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("cryptoscope: failed to load built-in tables: {e}");
            return ExitCode::FAILURE;
        }
    };

    let scanner = match Scanner::with_builtins(builtins.algorithms.clone()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cryptoscope: scanner init failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    let findings = match scanner.scan_path(&path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("cryptoscope: scan failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    println!(
        "cryptoscope: scanned {} → {} finding(s) (policy: {})",
        path.display(),
        findings.len(),
        builtins.policy.meta.name,
    );

    for f in &findings {
        let algo = builtins
            .algorithms
            .get(&f.algorithm_id)
            .expect("algorithm in built-in table");
        let score = QuantumRiskScore::compute(f, algo, &builtins.policy);
        println!(
            "  {sev:?}\t{rule}\t{algo}\t{file}:{line}\t{msg}",
            sev = score.severity,
            rule = f.rule_id,
            algo = f.algorithm_id,
            file = f.location.location,
            line = f.location.line.unwrap_or(0),
            msg = f.message,
        );
    }

    if let Some(out_path) = flags.cbom_out {
        let version = flags.schema_version.unwrap_or_default();
        let mut emit_opts = EmitOptions::new(
            ScanTarget {
                name: path.to_string_lossy().into_owned(),
                version: None,
            },
            current_timestamp(),
        );
        emit_opts.schema_version = version;

        match emit_cbom_json(&findings, &builtins.algorithms, &emit_opts) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&out_path, json) {
                    eprintln!(
                        "cryptoscope: failed to write CBOM to {}: {e}",
                        out_path.display()
                    );
                    return ExitCode::FAILURE;
                }
                eprintln!(
                    "cryptoscope: wrote CycloneDX {} CBOM → {}",
                    version.as_str(),
                    out_path.display()
                );
            }
            Err(e) => {
                eprintln!("cryptoscope: CBOM emission failed: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    ExitCode::SUCCESS
}

fn current_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    // RFC-3339 seconds-resolution UTC timestamp, no extra deps.
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_unix_to_rfc3339(secs)
}

/// Tiny pure-Rust unix → RFC3339 formatter so we don't pull `chrono` for one timestamp.
fn format_unix_to_rfc3339(secs: u64) -> String {
    const DAYS_PER_400Y: i64 = 146097;
    const DAYS_PER_100Y: i64 = 36524;
    const DAYS_PER_4Y: i64 = 1461;

    let secs = secs as i64;
    let days = secs / 86_400;
    let rem_secs = (secs % 86_400) as u32;

    let h = rem_secs / 3600;
    let m = (rem_secs / 60) % 60;
    let s = rem_secs % 60;

    // 1970-01-01 = day 0. Compute calendar date.
    // Algorithm from Howard Hinnant's date.h, public-domain.
    let z = days + 719468;
    let era = z.div_euclid(DAYS_PER_400Y);
    let doe = z - era * DAYS_PER_400Y;
    let yoe = (doe - doe / DAYS_PER_4Y + doe / DAYS_PER_100Y - doe / (DAYS_PER_400Y - 1)) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m_cal = if mp < 10 { mp + 3 } else { mp - 9 };
    let y_cal = y + i64::from(m_cal <= 2);

    format!(
        "{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z",
        y = y_cal,
        mo = m_cal,
        d = d,
        h = h,
        mi = m,
        s = s,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_formats_unix_epoch() {
        assert_eq!(format_unix_to_rfc3339(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn timestamp_formats_known_date() {
        // 2026-06-15 12:00:00 UTC = 1781524800
        assert_eq!(format_unix_to_rfc3339(1781524800), "2026-06-15T12:00:00Z");
    }

    #[test]
    fn timestamp_formats_y2k() {
        // 2000-01-01 00:00:00 UTC = 946684800
        assert_eq!(format_unix_to_rfc3339(946684800), "2000-01-01T00:00:00Z");
    }
}

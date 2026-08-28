//! seawall CLI — walking-skeleton entrypoint.
//!
//! Full `clap` derive integration follows per SPEC.md §11. For now the CLI
//! supports a minimal `scan <path>` subcommand wiring together every scanner
//! and emitter the workspace ships.
//!
//! ## Subcommands
//! * `init [PATH]`          — onboarding wizard, writes `.seawall.toml`
//! * `scan <path> [FLAGS]`  — file/directory scan (existing)
//! * `policy list`          — print the built-in policy presets
//! * `mcp-serve [FLAGS]`    — JSON-RPC 2.0 MCP server over stdio

mod config;
mod init;

use seawall::mcp;

use std::path::PathBuf;
use std::process::ExitCode;

use seawall_cbom::SchemaVersion;
use seawall_cbom::emit::{EmitOptions, ScanTarget};
use seawall_cbom::emit_cbom_json;
use seawall_core::risk::apply_hndl_flags;
use seawall_core::{Finding, Policy, QuantumRiskScore, load_builtins};
use seawall_report::{ReportOptions, emit_html, emit_sarif, emit_summary_json, partition_audible};
use seawall_scan_certs::CertScanner;
use seawall_scan_deps::DepScanner;
use seawall_scan_network::NetScanner;
use seawall_scan_source::Scanner;
use seawall_tui::Tui;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        None | Some("--help") | Some("-h") => {
            print_help();
            ExitCode::SUCCESS
        }
        Some("--version") | Some("-V") => {
            println!("seawall {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some("init") => {
            let path = args
                .get(2)
                .map(std::path::PathBuf::from)
                .unwrap_or_default();
            init::run(path)
        }
        Some("scan") => match args.get(2) {
            Some(path) => {
                let opts = parse_scan_flags(&args[3..]);
                run_scan(PathBuf::from(path), opts)
            }
            None => {
                eprintln!("seawall: scan requires a path argument");
                ExitCode::FAILURE
            }
        },
        Some("policy") => match args.get(2).map(String::as_str) {
            Some("list") => {
                print_policy_list();
                ExitCode::SUCCESS
            }
            other => {
                eprintln!(
                    "seawall: usage: seawall policy list{}",
                    other.map(|o| format!(" (got `{o}`)")).unwrap_or_default()
                );
                ExitCode::FAILURE
            }
        },
        Some("mcp-serve") => {
            let allow_network = args[2..].iter().any(|a| a == "--allow-network");
            mcp::run(allow_network);
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("seawall: unknown command `{other}`");
            print_help();
            ExitCode::FAILURE
        }
    }
}

fn print_help() {
    println!(
        r#"seawall {ver} — cryptographic discovery scanner

USAGE:
    seawall init [PATH]                   Walk through setup, write .seawall.toml
    seawall scan [PATH] [FLAGS]           Scan a file or directory
    seawall policy list                   List the built-in policy presets
    seawall mcp-serve [--allow-network]   Start MCP server over stdio

INIT:
    init [PATH]               Detect languages, ask 5 setup questions, emit
                              .seawall.toml at PATH (default: current dir).
                              Safe in CI — uses defaults when stdin is closed.

MCP SERVER:
    mcp-serve                 Start JSON-RPC 2.0 MCP server over stdin/stdout
    --allow-network           Enable scan_network verb and scan_certs host-mode

SCAN MODES (default: --source --deps; --certs and --net are opt-in):
    --source                  Scan source code (tree-sitter: Go, Python, Java,
                              JavaScript/TypeScript, C/C++, Rust, C#)
    --certs                   Scan X.509 certificates (PEM/DER)
    --deps                    Scan dependency manifests
    --net <host:port>         Probe a TLS endpoint (requires --allow-network)
    --allow-network           Permit outbound sockets. Without it, --net refuses (P2).
    --all                     Enable every scan mode (--net still requires --net <host>)

OUTPUT:
    --cbom <file>             Emit a CycloneDX CBOM
    --schema-version <ver>    CBOM spec version: 1.6 or 1.7 (default 1.7)
    --html <file>             Emit an auditor-grade HTML report
    --sarif <file>            Emit SARIF 2.1.0 (GitHub / GitLab Advanced Security)
    --summary-json <file>     Emit a compact CI dashboard JSON
    --tui                     Open the interactive TUI explorer

POLICY:
    --policy <name|file>      Score against a built-in preset or a policy TOML
                              file. `seawall policy list` names the presets;
                              the default is nist-default. A policy reweights
                              findings — it never changes what is detected.

FILTERS:
    --include-safe            Show inventory-only findings (QuantumSafe, PqcFinal,
                              PqcDraft) in HTML / SARIF / summary / stdout. They
                              are always present in the CBOM. Default: hidden
                              because they drown out actionable findings.

DIAGNOSTICS:
    --show-errors             Print the per-file scan warnings (parse failures,
                              unreadable files, malformed manifests). By default
                              seawall prints a one-line count and continues —
                              a single bad file should not kill the run.

MISC:
    --version                 Print version
    --help                    Print this help

This is a walking-skeleton build. Full clap CLI per SPEC.md §11 to follow."#,
        ver = env!("CARGO_PKG_VERSION"),
    );
}

/// Print the built-in presets. `Policy::preset_names` is the single source of
/// truth quoted by README, SPEC.md, MCP.md and `seawall init`.
fn print_policy_list() {
    println!("Built-in policy presets (use with `--policy <name>`):");
    for name in Policy::preset_names() {
        match Policy::from_preset(name) {
            Some(Ok(p)) => println!(
                "  {name:<14} {} — {}",
                p.meta.display_name, p.meta.source_url
            ),
            Some(Err(e)) => println!("  {name:<14} <failed to load: {e}>"),
            None => unreachable!("preset_names yields only built-in names"),
        }
    }
    println!("\n`--policy <file.toml>` also accepts a policy file of your own.");
}

#[derive(Default)]
struct ScanFlags {
    scan_source: bool,
    scan_certs: bool,
    scan_deps: bool,
    net_targets: Vec<String>,
    /// P2: the binary opens no sockets unless the operator passes
    /// `--allow-network`. Without this the flag was silently ignored in scan
    /// mode and `--net` opened TCP connections regardless.
    allow_network: bool,
    explicit_modes: bool,
    cbom_out: Option<PathBuf>,
    schema_version: Option<SchemaVersion>,
    html_out: Option<PathBuf>,
    sarif_out: Option<PathBuf>,
    summary_out: Option<PathBuf>,
    open_tui: bool,
    include_safe: bool,
    show_errors: bool,
    /// `--policy <name-or-path>`. `None` means "whatever .seawall.toml
    /// says", falling back to the built-in nist-default.
    policy: Option<String>,
}

fn parse_scan_flags(tail: &[String]) -> ScanFlags {
    let mut flags = ScanFlags::default();
    let mut it = tail.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--source" => {
                flags.scan_source = true;
                flags.explicit_modes = true;
            }
            "--certs" => {
                flags.scan_certs = true;
                flags.explicit_modes = true;
            }
            "--deps" => {
                flags.scan_deps = true;
                flags.explicit_modes = true;
            }
            "--all" => {
                flags.scan_source = true;
                flags.scan_certs = true;
                flags.scan_deps = true;
                flags.explicit_modes = true;
            }
            "--allow-network" => {
                flags.allow_network = true;
            }
            "--net" => {
                if let Some(t) = it.next() {
                    flags.net_targets.push(t.clone());
                    flags.explicit_modes = true;
                } else {
                    eprintln!("seawall: --net requires a host:port argument");
                }
            }
            "--cbom" => {
                if let Some(p) = it.next() {
                    flags.cbom_out = Some(PathBuf::from(p));
                }
            }
            "--html" => {
                if let Some(p) = it.next() {
                    flags.html_out = Some(PathBuf::from(p));
                }
            }
            "--sarif" => {
                if let Some(p) = it.next() {
                    flags.sarif_out = Some(PathBuf::from(p));
                }
            }
            "--summary-json" => {
                if let Some(p) = it.next() {
                    flags.summary_out = Some(PathBuf::from(p));
                }
            }
            "--tui" => {
                flags.open_tui = true;
            }
            "--include-safe" => {
                flags.include_safe = true;
            }
            "--show-errors" => {
                flags.show_errors = true;
            }
            "--policy" => match it.next() {
                Some(p) => flags.policy = Some(p.clone()),
                None => eprintln!("seawall: --policy requires a preset name or file path"),
            },
            "--schema-version" => {
                if let Some(v) = it.next() {
                    flags.schema_version = match v.as_str() {
                        "1.6" => Some(SchemaVersion::V1_6),
                        "1.7" => Some(SchemaVersion::V1_7),
                        _ => {
                            eprintln!("seawall: unknown --schema-version `{v}` (use 1.6 or 1.7)");
                            None
                        }
                    };
                }
            }
            other => {
                eprintln!("seawall: ignoring unknown flag `{other}`");
            }
        }
    }

    // If no mode flag was passed, default to source + deps (the safe set —
    // network/cert scans require explicit opt-in per the responsible-use
    // principle in SPEC.md §6).
    if !flags.explicit_modes {
        flags.scan_source = true;
        flags.scan_deps = true;
    }
    flags
}

fn run_scan(path: PathBuf, mut flags: ScanFlags) -> ExitCode {
    // Load .seawall.toml from the scan target directory (or current dir if
    // it is a file) and apply it as defaults. Explicit CLI flags still win.
    let config_dir = if path.is_dir() {
        path.clone()
    } else {
        path.parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
    };
    let mut config_preset: Option<String> = None;
    if let Ok(Some(cfg)) = config::load_from_dir(&config_dir) {
        if cfg.policy.include_safe {
            flags.include_safe = true;
        }
        if cfg.diagnostics.show_errors {
            flags.show_errors = true;
        }
        config_preset = Some(cfg.policy.preset);
    }

    let mut builtins = match load_builtins() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("seawall: failed to load built-in tables: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Policy resolution: --policy wins over .seawall.toml's `preset`,
    // which wins over the built-in nist-default already in `builtins`.
    // An unresolvable name is fatal — silently scoring against NIST defaults
    // when the operator asked for CNSA 2.0 is the bug this replaces.
    if let Some(requested) = flags.policy.as_deref().or(config_preset.as_deref()) {
        match Policy::load(requested) {
            Ok(p) => {
                if let Err(e) = p.cross_check(&builtins.algorithms) {
                    eprintln!("seawall: policy `{requested}` is inconsistent: {e}");
                    return ExitCode::FAILURE;
                }
                builtins.policy = p;
            }
            Err(e) => {
                eprintln!("seawall: cannot load policy `{requested}`: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    let mut findings: Vec<Finding> = Vec::new();
    let mut warnings: Vec<seawall_core::ScanWarning> = Vec::new();

    if flags.scan_source {
        match Scanner::with_builtins(builtins.algorithms.clone())
            .and_then(|s| s.scan_path_collecting(&path, &mut warnings))
        {
            Ok(mut f) => findings.append(&mut f),
            Err(e) => {
                eprintln!("seawall: source scan failed: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    if flags.scan_certs {
        match CertScanner::with_builtins()
            .and_then(|s| s.scan_path_collecting(&path, &mut warnings))
        {
            Ok(mut f) => findings.append(&mut f),
            Err(e) => {
                eprintln!("seawall: cert scan failed: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    if flags.scan_deps {
        let scanner = DepScanner::with_builtins();
        match scanner.scan_path_collecting(&path, &mut warnings) {
            Ok(mut f) => findings.append(&mut f),
            Err(e) => {
                eprintln!("seawall: deps scan failed: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    // Network probes — spin up a small tokio runtime only if needed.
    //
    // P2 is contractual: no socket is opened unless the operator explicitly
    // passes --allow-network. Refusing here rather than warning is the whole
    // point; a trust invariant that only prints a banner is not an invariant.
    if !flags.net_targets.is_empty() && !flags.allow_network {
        eprintln!(
            "seawall: --net requires --allow-network.\n\
             \x20 seawall refuses to open a socket unless you say so explicitly (trust invariant P2).\n\
             \x20 Re-run as: seawall scan . --allow-network --net {}",
            flags.net_targets.join(" --net ")
        );
        std::process::exit(2);
    }
    if !flags.net_targets.is_empty() {
        eprintln!(
            "seawall: opening TCP connections to {} target(s) — inventory only, no exploit attempts",
            flags.net_targets.len()
        );
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                eprintln!("seawall: failed to start tokio runtime: {e}");
                return ExitCode::FAILURE;
            }
        };
        let scanner = NetScanner::new();
        for target in &flags.net_targets {
            match runtime.block_on(scanner.scan_target(target)) {
                Ok(mut f) => findings.append(&mut f),
                Err(e) => {
                    eprintln!("seawall: net scan of {target} failed: {e}");
                    return ExitCode::FAILURE;
                }
            }
        }
    }

    // Decide the HNDL flag before anything reads it. Every scanner writes a
    // hard-coded `false` because none of them holds a policy; leaving it there
    // shipped a permanent zero in the field the product is named after.
    apply_hndl_flags(&mut findings, &builtins.algorithms, &builtins.policy);

    // Partition into "audible" (alert-worthy) and "suppressed" (inventory-only:
    // QuantumSafe / PqcFinal / PqcDraft). The CBOM consumes the full set —
    // it's an inventory. Everything else defaults to the audible subset so
    // ~85 AES-256-GCM findings from a single rustls scan don't drown out the
    // real signals. `--include-safe` collapses the two back together.
    let (audible_refs, suppressed_refs) =
        partition_audible(&findings, &builtins.algorithms, &builtins.policy);
    let displayed_findings: Vec<Finding> = if flags.include_safe {
        findings.clone()
    } else {
        audible_refs.iter().map(|f| (*f).clone()).collect()
    };

    println!(
        "seawall: scanned {} → {} finding(s) (policy: {})",
        path.display(),
        findings.len(),
        builtins.policy.meta.name,
    );
    if !flags.include_safe && !suppressed_refs.is_empty() {
        println!(
            "  ({} shown, {} hidden as quantum-safe inventory; pass --include-safe to see all)",
            displayed_findings.len(),
            suppressed_refs.len(),
        );
    }

    for f in &displayed_findings {
        let where_ = match f.location.line {
            Some(l) => format!("{}:{}", f.location.location, l),
            None => f.location.location.clone(),
        };
        let Some(algo) = builtins.algorithms.get(&f.algorithm_id) else {
            // Unknown algorithm-ids (e.g. cert with an OID we don't yet
            // catalogue, or `unknown` from scan-deps) are still informative.
            println!(
                "  ?\t{rule}\t{algo}\t{where_}\t{msg}",
                rule = f.rule_id,
                algo = f.algorithm_id,
                msg = f.message,
            );
            continue;
        };
        let score = QuantumRiskScore::compute(f, algo, &builtins.policy);
        println!(
            "  {sev:?}\t{rule}\t{algo}\t{where_}\t{msg}",
            sev = score.severity,
            rule = f.rule_id,
            algo = f.algorithm_id,
            msg = f.message,
        );
    }

    let timestamp = current_timestamp();
    let scan_target = path.to_string_lossy().into_owned();
    // Any emitter may fail without preventing the others from running; the
    // process exit code still reflects that something went wrong.
    let mut emit_failed = false;

    if let Some(out_path) = &flags.cbom_out {
        let version = flags.schema_version.unwrap_or_default();
        let mut emit_opts = EmitOptions::new(
            ScanTarget {
                name: scan_target.clone(),
                version: None,
            },
            timestamp.clone(),
        );
        emit_opts.schema_version = version;

        match emit_cbom_json(&findings, &builtins.algorithms, &emit_opts) {
            Ok(json) => {
                // Record the failure but keep going: the SARIF and summary
                // outputs are written further down and are independently
                // useful. Returning here made one emitter's problem look like
                // a total scan failure.
                if let Err(e) = std::fs::write(out_path, json) {
                    eprintln!(
                        "seawall: failed to write CBOM to {}: {e}",
                        out_path.display()
                    );
                    emit_failed = true;
                } else {
                    eprintln!(
                        "seawall: wrote CycloneDX {} CBOM → {}",
                        version.as_str(),
                        out_path.display()
                    );
                }
            }
            Err(e) => {
                eprintln!("seawall: CBOM emission failed: {e}");
                emit_failed = true;
            }
        }
    }

    let report_opts = ReportOptions {
        scan_target: scan_target.clone(),
        timestamp: timestamp.clone(),
        warnings: warnings.clone(),
    };

    if let Some(out_path) = &flags.html_out {
        match emit_html(
            &displayed_findings,
            &builtins.algorithms,
            &builtins.policy,
            &report_opts,
        ) {
            Ok(html) => match std::fs::write(out_path, html) {
                Ok(()) => eprintln!("seawall: wrote HTML report → {}", out_path.display()),
                Err(e) => {
                    eprintln!("seawall: failed to write HTML: {e}");
                    return ExitCode::FAILURE;
                }
            },
            Err(e) => {
                eprintln!("seawall: HTML emission failed: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    if let Some(out_path) = &flags.sarif_out {
        match emit_sarif(
            &displayed_findings,
            &builtins.algorithms,
            &builtins.policy,
            &report_opts,
        ) {
            Ok(sarif) => match std::fs::write(out_path, sarif) {
                Ok(()) => eprintln!("seawall: wrote SARIF → {}", out_path.display()),
                Err(e) => {
                    eprintln!("seawall: failed to write SARIF: {e}");
                    return ExitCode::FAILURE;
                }
            },
            Err(e) => {
                eprintln!("seawall: SARIF emission failed: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    if let Some(out_path) = &flags.summary_out {
        match emit_summary_json(
            &displayed_findings,
            &builtins.algorithms,
            &builtins.policy,
            &report_opts,
        ) {
            Ok(json) => match std::fs::write(out_path, json) {
                Ok(()) => eprintln!("seawall: wrote summary JSON → {}", out_path.display()),
                Err(e) => {
                    eprintln!("seawall: failed to write summary: {e}");
                    return ExitCode::FAILURE;
                }
            },
            Err(e) => {
                eprintln!("seawall: summary emission failed: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    if flags.open_tui {
        let tui = Tui::new(displayed_findings, builtins.algorithms, builtins.policy);
        if let Err(e) = tui.run() {
            eprintln!("seawall: TUI failed: {e}");
            return ExitCode::FAILURE;
        }
    }

    // ── Phase 6: surface non-fatal scan warnings ───────────────────────────
    // Default: one-line count so the user knows something was skipped.
    // --show-errors: dump the structured list (kind, path, message).
    if !warnings.is_empty() {
        eprintln!(
            "seawall: {} non-fatal scan warning(s)\
             ; pass --show-errors to list them",
            warnings.len()
        );
        if flags.show_errors {
            for w in &warnings {
                let path = w
                    .path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "<no path>".into());
                eprintln!("  {:?}\t{}\t{}", w.kind, path, w.message);
            }
        }
    }

    if emit_failed {
        return ExitCode::FAILURE;
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

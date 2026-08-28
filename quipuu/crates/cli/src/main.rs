//! quipuu CLI — walking-skeleton entrypoint.
//!
//! Full `clap` derive integration follows per SPEC.md §11. For now the CLI
//! supports a minimal `scan <path>` subcommand wiring together every scanner
//! and emitter the workspace ships.
//!
//! ## Subcommands
//! * `init [PATH]`          — onboarding wizard, writes `.quipuu.toml`
//! * `scan <path> [FLAGS]`  — file/directory scan (existing)
//! * `policy list`          — print the built-in policy presets
//! * `mcp-serve [FLAGS]`    — JSON-RPC 2.0 MCP server over stdio

mod config;
mod init;

use quipuu::mcp;

use std::path::PathBuf;
use std::process::ExitCode;

use quipuu_cbom::SchemaVersion;
use quipuu_cbom::emit::{EmitOptions, ScanTarget};
use quipuu_cbom::emit_cbom_json;
use quipuu_core::risk::apply_hndl_flags;
use quipuu_core::{Finding, Policy, Severity, load_builtins, severity_of};
use quipuu_report::{ReportOptions, emit_html, emit_sarif, emit_summary_json, partition_audible};
use quipuu_scan_certs::CertScanner;
use quipuu_scan_deps::DepScanner;
use quipuu_scan_network::NetScanner;
use quipuu_scan_source::Scanner;
use quipuu_tui::Tui;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        None | Some("--help") | Some("-h") => {
            print_help();
            ExitCode::SUCCESS
        }
        Some("--version") | Some("-V") => {
            println!("quipuu {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some("init") => {
            let path = args
                .get(2)
                .map(std::path::PathBuf::from)
                .unwrap_or_default();
            init::run(path)
        }
        Some("scan") => match parse_scan_args(&args[2..]) {
            Ok(flags) if flags.paths.is_empty() => {
                eprintln!("quipuu: scan requires at least one path argument");
                ExitCode::from(2)
            }
            Ok(flags) => run_scan(flags),
            Err(msg) => {
                eprintln!("quipuu: {msg}");
                ExitCode::from(2)
            }
        },
        Some("policy") => match args.get(2).map(String::as_str) {
            Some("list") => {
                print_policy_list();
                ExitCode::SUCCESS
            }
            other => {
                eprintln!(
                    "quipuu: usage: quipuu policy list{}",
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
            eprintln!("quipuu: unknown command `{other}`");
            print_help();
            ExitCode::FAILURE
        }
    }
}

fn print_help() {
    println!(
        r#"quipuu {ver} — cryptographic discovery scanner

USAGE:
    quipuu init [PATH]                   Walk through setup, write .quipuu.toml
    quipuu scan <PATH...> [FLAGS]        Scan one or more files or directories
    quipuu policy list                   List the built-in policy presets
    quipuu mcp-serve [--allow-network]   Start MCP server over stdio

INIT:
    init [PATH]               Detect languages, ask 5 setup questions, emit
                              .quipuu.toml at PATH (default: current dir).
                              Safe in CI — uses defaults when stdin is closed.

MCP SERVER:
    mcp-serve                 Start JSON-RPC 2.0 MCP server over stdin/stdout
    --allow-network           Enable scan_network verb and scan_certs host-mode

SCAN MODES (default: --source --deps):
    --source                  Scan source code (tree-sitter: Go, Python, Java,
                              JavaScript/TypeScript, C/C++, Rust, C#).
                              Narrows the base set: `--source` alone skips deps.
    --deps                    Scan dependency manifests. Narrows the base set.
    --certs                   ALSO scan X.509 certificates (PEM/DER). Additive:
                              it never suppresses the source/deps default.
    --net <host:port>         ALSO probe a TLS endpoint (requires
                              --allow-network). Additive, like --certs.
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
                              file. `quipuu policy list` names the presets;
                              the default is nist-default. A policy reweights
                              findings — it never changes what is detected.

CI GATE:
    --fail-on <threshold>     Exit 1 when a reported finding is at least this
                              severe. One of: critical, high, medium, low, safe;
                              `policy` to use the active policy's [ci] fail_on;
                              `none` to disable. Omitted: quipuu always exits 0
                              on a successful scan.

EXIT CODES:
    0                         Scan completed; no --fail-on threshold was met
    1                         --fail-on threshold met, or an output file failed
                              to write
    2                         quipuu refused to run (bad argument, missing
                              path, or --net without --allow-network)

FILTERS:
    --include-safe            Show inventory-only findings (QuantumSafe, PqcFinal,
                              PqcDraft) in HTML / SARIF / summary / stdout. They
                              are always present in the CBOM. Default: hidden
                              because they drown out actionable findings.

DIAGNOSTICS:
    --show-errors             Print the per-file scan warnings (parse failures,
                              unreadable files, malformed manifests). By default
                              quipuu prints a one-line count and continues —
                              a single bad file should not kill the run.

MISC:
    --version                 Print version
    --help                    Print this help

This is a walking-skeleton build. Full clap CLI per SPEC.md §11 to follow."#,
        ver = env!("CARGO_PKG_VERSION"),
    );
}

/// Print the built-in presets. `Policy::preset_names` is the single source of
/// truth quoted by README, SPEC.md, MCP.md and `quipuu init`.
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
    /// Every positional argument, in the order given. More than one because
    /// the pre-commit hook sets `pass_filenames: true` and hands us the whole
    /// staged file list.
    paths: Vec<PathBuf>,
    scan_source: bool,
    scan_certs: bool,
    scan_deps: bool,
    net_targets: Vec<String>,
    /// P2: the binary opens no sockets unless the operator passes
    /// `--allow-network`. Without this the flag was silently ignored in scan
    /// mode and `--net` opened TCP connections regardless.
    allow_network: bool,
    /// Set only by the *base-set selectors* `--source`, `--deps` and `--all`.
    /// `--certs` and `--net` are documented as opt-in **additions**, so they
    /// must not clear the default base set: naming one used to silently
    /// replace source+deps, which turned a failing `--fail-on` gate green on
    /// a tree that had simply not been looked at.
    explicit_base: bool,
    cbom_out: Option<PathBuf>,
    schema_version: Option<SchemaVersion>,
    html_out: Option<PathBuf>,
    sarif_out: Option<PathBuf>,
    summary_out: Option<PathBuf>,
    open_tui: bool,
    include_safe: bool,
    show_errors: bool,
    /// `--policy <name-or-path>`. `None` means "whatever .quipuu.toml
    /// says", falling back to the built-in nist-default.
    policy: Option<String>,
    /// `--fail-on <severity|policy|none>` — the CI gate. `None` means no gate
    /// was requested and the exit code reflects only whether quipuu itself
    /// ran, which is the documented default.
    fail_on: Option<FailOn>,
}

/// Resolved `--fail-on` argument. `Policy` defers to the active policy's
/// `[ci] fail_on`, so `--policy nsa-cnsa2 --fail-on policy` gates at High
/// because that preset says so.
#[derive(Clone, Copy)]
enum FailOn {
    Never,
    AtLeast(Severity),
    Policy,
}

impl FailOn {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "none" => Ok(FailOn::Never),
            "policy" => Ok(FailOn::Policy),
            other => Severity::parse(other).map(FailOn::AtLeast).ok_or_else(|| {
                let names: Vec<&str> = Severity::ALL.iter().map(|s| s.slug()).collect();
                format!(
                    "unknown --fail-on threshold `{other}` (expected one of: {}, policy, none)",
                    names.join(", "),
                )
            }),
        }
    }

    /// The severity at or above which the scan should exit non-zero, or `None`
    /// for "never fail". Resolving `policy` can fail: a policy file is free to
    /// carry a `fail_on` string we do not recognise, and a gate we cannot read
    /// must refuse to run rather than default to open.
    fn threshold(self, policy: &Policy) -> Result<Option<Severity>, String> {
        match self {
            FailOn::Never => Ok(None),
            FailOn::AtLeast(s) => Ok(Some(s)),
            FailOn::Policy => match policy.ci.fail_on.as_str() {
                "none" => Ok(None),
                other => Severity::parse(other).map(Some).ok_or_else(|| {
                    format!(
                        "policy `{}` sets ci.fail_on = \"{other}\", which is not a severity",
                        policy.meta.name,
                    )
                }),
            },
        }
    }
}

fn parse_scan_args(tail: &[String]) -> Result<ScanFlags, String> {
    let mut flags = ScanFlags::default();
    let mut it = tail.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            // `--source` and `--deps` select the base set: naming one
            // narrows the scan, which is the whole point of naming it.
            "--source" => {
                flags.scan_source = true;
                flags.explicit_base = true;
            }
            "--deps" => {
                flags.scan_deps = true;
                flags.explicit_base = true;
            }
            // `--certs` is additive. It says "also read certificates", not
            // "read certificates instead of the code".
            "--certs" => {
                flags.scan_certs = true;
            }
            "--all" => {
                flags.scan_source = true;
                flags.scan_certs = true;
                flags.scan_deps = true;
                flags.explicit_base = true;
            }
            "--allow-network" => {
                flags.allow_network = true;
            }
            "--net" => {
                if let Some(t) = it.next() {
                    // Additive, like `--certs`: probing an endpoint is not a
                    // reason to stop reading the tree that talks to it.
                    flags.net_targets.push(t.clone());
                } else {
                    eprintln!("quipuu: --net requires a host:port argument");
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
                None => return Err("--policy requires a preset name or file path".into()),
            },
            // A CI gate that mis-parses its own threshold is worse than no
            // gate, so every failure here is fatal rather than a warning.
            "--fail-on" => match it.next() {
                Some(v) => flags.fail_on = Some(FailOn::parse(v)?),
                None => return Err("--fail-on requires a threshold".into()),
            },
            "--schema-version" => {
                if let Some(v) = it.next() {
                    flags.schema_version = match v.as_str() {
                        "1.6" => Some(SchemaVersion::V1_6),
                        "1.7" => Some(SchemaVersion::V1_7),
                        _ => {
                            eprintln!("quipuu: unknown --schema-version `{v}` (use 1.6 or 1.7)");
                            None
                        }
                    };
                }
            }
            other if other.starts_with('-') => {
                eprintln!("quipuu: ignoring unknown flag `{other}`");
            }
            // Anything that is not a flag is a path to scan. Flags and paths
            // may be interleaved: pre-commit appends the staged file list
            // after the configured `args:`.
            path => flags.paths.push(PathBuf::from(path)),
        }
    }

    // A path that isn't there is refused, not skipped. Scanning nothing and
    // reporting "0 findings" is indistinguishable from a clean tree, which is
    // the exact failure this gate exists to prevent.
    if let Some(missing) = flags.paths.iter().find(|p| !p.exists()) {
        return Err(format!("no such file or directory: {}", missing.display()));
    }

    // Unless a base-set selector narrowed it, scan source + deps (the safe
    // set — network/cert scans require explicit opt-in per the
    // responsible-use principle in SPEC.md §6). This runs *after* the
    // additive flags, so `--certs` yields source + deps + certs rather than
    // certs alone.
    if !flags.explicit_base {
        flags.scan_source = true;
        flags.scan_deps = true;
    }
    Ok(flags)
}

fn run_scan(mut flags: ScanFlags) -> ExitCode {
    let paths = std::mem::take(&mut flags.paths);
    // Load .quipuu.toml from the first scan target's directory (or current
    // dir if it is a file) and apply it as defaults. Explicit CLI flags win.
    let first = &paths[0];
    let config_dir = if first.is_dir() {
        first.clone()
    } else {
        first
            .parent()
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
            eprintln!("quipuu: failed to load built-in tables: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Policy resolution: --policy wins over .quipuu.toml's `preset`,
    // which wins over the built-in nist-default already in `builtins`.
    // An unresolvable name is fatal — silently scoring against NIST defaults
    // when the operator asked for CNSA 2.0 is the bug this replaces.
    if let Some(requested) = flags.policy.as_deref().or(config_preset.as_deref()) {
        match Policy::load(requested) {
            Ok(p) => {
                if let Err(e) = p.cross_check(&builtins.algorithms) {
                    eprintln!("quipuu: policy `{requested}` is inconsistent: {e}");
                    return ExitCode::FAILURE;
                }
                builtins.policy = p;
            }
            Err(e) => {
                eprintln!("quipuu: cannot load policy `{requested}`: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    let mut findings: Vec<Finding> = Vec::new();
    let mut warnings: Vec<quipuu_core::ScanWarning> = Vec::new();

    // Each scanner is built once and walked over every path, so a 200-file
    // pre-commit invocation doesn't reload the rule tables 200 times.
    if flags.scan_source {
        let scanner = match Scanner::with_builtins(builtins.algorithms.clone()) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("quipuu: source scan failed: {e}");
                return ExitCode::FAILURE;
            }
        };
        for path in &paths {
            match scanner.scan_path_collecting(path, &mut warnings) {
                Ok(mut f) => findings.append(&mut f),
                Err(e) => {
                    eprintln!("quipuu: source scan of {} failed: {e}", path.display());
                    return ExitCode::FAILURE;
                }
            }
        }
    }

    if flags.scan_certs {
        let scanner = match CertScanner::with_builtins() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("quipuu: cert scan failed: {e}");
                return ExitCode::FAILURE;
            }
        };
        for path in &paths {
            match scanner.scan_path_collecting(path, &mut warnings) {
                Ok(mut f) => findings.append(&mut f),
                Err(e) => {
                    eprintln!("quipuu: cert scan of {} failed: {e}", path.display());
                    return ExitCode::FAILURE;
                }
            }
        }
    }

    if flags.scan_deps {
        let scanner = DepScanner::with_builtins();
        for path in &paths {
            match scanner.scan_path_collecting(path, &mut warnings) {
                Ok(mut f) => findings.append(&mut f),
                Err(e) => {
                    eprintln!("quipuu: deps scan of {} failed: {e}", path.display());
                    return ExitCode::FAILURE;
                }
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
            "quipuu: --net requires --allow-network.\n\
             \x20 quipuu refuses to open a socket unless you say so explicitly (trust invariant P2).\n\
             \x20 Re-run as: quipuu scan . --allow-network --net {}",
            flags.net_targets.join(" --net ")
        );
        std::process::exit(2);
    }
    if !flags.net_targets.is_empty() {
        eprintln!(
            "quipuu: opening TCP connections to {} target(s) — inventory only, no exploit attempts",
            flags.net_targets.len()
        );
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                eprintln!("quipuu: failed to start tokio runtime: {e}");
                return ExitCode::FAILURE;
            }
        };
        let scanner = NetScanner::new();
        for target in &flags.net_targets {
            match runtime.block_on(scanner.scan_target(target)) {
                Ok(mut f) => findings.append(&mut f),
                Err(e) => {
                    eprintln!("quipuu: net scan of {target} failed: {e}");
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

    let scan_target = paths
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(" ");
    println!(
        "quipuu: scanned {scan_target} → {} finding(s) (policy: {})",
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
        // Unknown algorithm-ids (e.g. cert with an OID we don't yet catalogue,
        // or `unknown` from scan-deps) are still informative, and print `?`
        // rather than a band. `severity_of` is the shared statement of that;
        // stdout was the only surface that already got it right.
        let Some(severity) = severity_of(f, &builtins.algorithms, &builtins.policy) else {
            println!(
                "  ?\t{rule}\t{algo}\t{where_}\t{msg}",
                rule = f.rule_id,
                algo = f.algorithm_id,
                msg = f.message,
            );
            continue;
        };
        println!(
            "  {sev:?}\t{rule}\t{algo}\t{where_}\t{msg}",
            sev = severity,
            rule = f.rule_id,
            algo = f.algorithm_id,
            msg = f.message,
        );
    }

    let timestamp = current_timestamp();
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
                        "quipuu: failed to write CBOM to {}: {e}",
                        out_path.display()
                    );
                    emit_failed = true;
                } else {
                    eprintln!(
                        "quipuu: wrote CycloneDX {} CBOM → {}",
                        version.as_str(),
                        out_path.display()
                    );
                }
            }
            Err(e) => {
                eprintln!("quipuu: CBOM emission failed: {e}");
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
                Ok(()) => eprintln!("quipuu: wrote HTML report → {}", out_path.display()),
                Err(e) => {
                    eprintln!("quipuu: failed to write HTML: {e}");
                    return ExitCode::FAILURE;
                }
            },
            Err(e) => {
                eprintln!("quipuu: HTML emission failed: {e}");
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
                Ok(()) => eprintln!("quipuu: wrote SARIF → {}", out_path.display()),
                Err(e) => {
                    eprintln!("quipuu: failed to write SARIF: {e}");
                    return ExitCode::FAILURE;
                }
            },
            Err(e) => {
                eprintln!("quipuu: SARIF emission failed: {e}");
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
                Ok(()) => eprintln!("quipuu: wrote summary JSON → {}", out_path.display()),
                Err(e) => {
                    eprintln!("quipuu: failed to write summary: {e}");
                    return ExitCode::FAILURE;
                }
            },
            Err(e) => {
                eprintln!("quipuu: summary emission failed: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    if flags.open_tui {
        // Clone: the --fail-on gate below is the last word on the exit code,
        // so it still needs the findings and tables after the TUI closes.
        let tui = Tui::new(
            displayed_findings.clone(),
            builtins.algorithms.clone(),
            builtins.policy.clone(),
        );
        if let Err(e) = tui.run() {
            eprintln!("quipuu: TUI failed: {e}");
            return ExitCode::FAILURE;
        }
    }

    // ── Phase 6: surface non-fatal scan warnings ───────────────────────────
    // Default: one-line count so the user knows something was skipped.
    // --show-errors: dump the structured list (kind, path, message).
    if !warnings.is_empty() {
        eprintln!(
            "quipuu: {} non-fatal scan warning(s)\
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

    // ── CI gate ───────────────────────────────────────────────────────────
    // Gate on what was reported, not on the full inventory: a finding hidden
    // as quantum-safe should not block a commit the operator never saw it in.
    if let Some(fail_on) = flags.fail_on {
        let threshold = match fail_on.threshold(&builtins.policy) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("quipuu: {e}");
                return ExitCode::from(2);
            }
        };
        if let Some(threshold) = threshold {
            let (mut tripped, mut unscored) = (0usize, 0usize);
            for f in &displayed_findings {
                match severity_of(f, &builtins.algorithms, &builtins.policy) {
                    // The `?` rows on stdout: an algorithm-id we do not
                    // catalogue has no severity, so it can neither trip the
                    // gate nor be quietly counted as clean.
                    None => unscored += 1,
                    Some(sev) => {
                        if sev.rank() >= threshold.rank() {
                            tripped += 1;
                        }
                    }
                }
            }
            if unscored > 0 {
                eprintln!(
                    "quipuu: {unscored} finding(s) have an uncatalogued algorithm and were not \
                     scored against --fail-on",
                );
            }
            if tripped > 0 {
                eprintln!(
                    "quipuu: {tripped} finding(s) at or above `{}` — failing per --fail-on",
                    threshold.slug(),
                );
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

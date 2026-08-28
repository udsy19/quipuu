//! Live network tests. Gated behind `--ignored` because:
//!   * they require outbound TCP access
//!   * CI environments may not have it
//!
//! Run with:
//!   cargo test -p quipuu-scan-network -- --ignored

use quipuu_scan_network::{NetScanner, ScanOptions};
use std::time::Duration;

fn fast_opts() -> ScanOptions {
    ScanOptions {
        connect_timeout: Duration::from_secs(5),
        handshake_timeout: Duration::from_secs(10),
        enumerate_groups: true,
    }
}

#[tokio::test]
#[ignore = "requires network access"]
async fn probes_cloudflare() {
    // Cloudflare advertises X25519MLKEM768 by default since 2024. We expect:
    //   * default handshake succeeds → at least one NET-001 finding
    //   * X25519 single-group probe succeeds → NET-001 for X25519
    //   * the PQC hybrid groups (0x11EC etc) are catalogued as "not probed"
    //     because rustls's `ring` backend doesn't carry them (v0 limitation).
    let scanner = NetScanner::with_options(fast_opts());
    let findings = scanner.scan_target("cloudflare.com:443").await.unwrap();
    assert!(!findings.is_empty());
    assert!(
        findings.iter().any(|f| f.rule_id == "NET-001"),
        "expected at least one successful handshake finding"
    );
    // Every PQC hybrid we don't probe should produce a NET-900 placeholder
    // so the report explicitly catalogues coverage gaps.
    assert!(
        findings.iter().any(|f| f.rule_id == "NET-900"),
        "expected NET-900 placeholders for catalogued-but-not-probed groups"
    );
}

#[tokio::test]
#[ignore = "requires network access"]
async fn probes_google() {
    let scanner = NetScanner::with_options(fast_opts());
    let findings = scanner.scan_target("www.google.com:443").await.unwrap();
    assert!(!findings.is_empty());
    assert!(findings.iter().any(|f| f.rule_id == "NET-001"));
}

#[tokio::test]
#[ignore = "requires network access"]
async fn invalid_host_returns_error() {
    let scanner = NetScanner::with_options(fast_opts());
    let result = scanner
        .scan_target("this-host-should-not-exist-xyz123.example.invalid:443")
        .await;
    assert!(result.is_err(), "DNS for invalid host must fail");
}

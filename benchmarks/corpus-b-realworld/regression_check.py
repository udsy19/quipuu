#!/usr/bin/env python3
"""regression_check.py — assert V8 corpus headline numbers as a floor.

Runs scan_corpus.py, then asserts that each ecosystem produced AT LEAST the
floor count of findings established by V8. Floors are intentionally
conservative — a 5-10% drop in any ecosystem fails CI loudly. Coverage
improvements always cause the test to pass; coverage regressions fail.

Designed for CI. Skips if `clones/` is absent (so it doesn't run in plain
unit-test contexts). Exits 1 on regression.

The corpus is routinely cloned outside the repo, so `--clones` (and `--bin`)
are passed straight through to scan_corpus.py. Without them this skips, and a
gate that silently skips is not a gate.

Usage:
    python3 regression_check.py [--clones DIR] [--bin PATH]
    python3 regression_check.py [--update]    # update floors after intentional regression
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
CLONES_DIR = SCRIPT_DIR / "clones"

# Floors are 5% below an observed run, so a real coverage regression fails and
# ordinary run-to-run variation does not.
#
# Re-taken 2026-08-29 against the corpus scope repair. Every floor here was set
# on runs in which three projects were scanned over a tree their manifest did
# not declare: `scan_corpus.py` dropped a `scan_path` that was not on disk and,
# when none of a project's paths resolved, scanned the whole repository. The
# maven and crates-io floors were carrying that widening as if it were
# coverage — `rustls-pemfile` alone contributed 140 findings from the entire
# rustls workspace, 33 of them CRYPTO-560 sites that `crates-io:rustls` already
# reports from the same clone. Holding the old numbers would demand that the
# harness keep double-counting one repository to stay green.
#
# The V11 values they replace are kept beside each row: a floor that moves has
# to say what it moved from.
V11_FLOOR = {
    "pypi":             73,   # observed 77   (V11 floor 36, observed 38)
    "npm":             120,   # observed 127  (V11 floor 111, observed 117)
    "maven":            76,   # observed 81   (V11 floor 292 — jetty-server 119
                              #   and tink 93 of it came from whole-repo scans)
    "crates-io":        81,   # observed 86   (V11 floor 214 — 140 of it was
                              #   rustls-pemfile scanning the rustls workspace)
    "go-modules":      460,   # observed 485  (V11 floor 276, observed 291)
    "crypto-adjacent": 190,   # observed 200  (V11 floor 6 — a floor of 6
                              #   against 200 cannot detect an ecosystem
                              #   vanishing, which is the failure that started
                              #   this; see corpus_integrity.py)
    "total":          1003,   # observed 1056 (V11 floor 936, observed 986)
}
V8_FLOOR = V11_FLOOR  # Backwards-compatible alias for existing references

# Per-rule floors for the most-important rules. If any of these drop to zero
# we want a hard fail — those rules represent corpus-validated detection that
# downstream users depend on.
RULE_FLOORS = {
    "CRYPTO-700": 10,   # Go JWT RS256 (V11: 13; SiteContext suppressed FPs)
    "CRYPTO-740":  1,   # JWT alg=none. 92 -> 1 on 2026-08-28, when `"none"`
                        # began requiring a sibling JOSE name: 91 of the 92
                        # were constants spelled "none" (`SSETypeNone`,
                        # `compressionNone`, `require_auth`), and the one that
                        # registers an algorithm is jwx's own signature table.
                        # Floor is 1 because one real site is what the corpus
                        # contains — see BENCHMARKING_RESULTS.md.
    "CRYPTO-704":  4,   # Go JWT PS384  (V11: 6)
    "CRYPTO-705":  4,   # Go JWT PS512  (V11: 6)
    "CRYPTO-560": 16,   # rustls::ClientConfig::builder. Floor was 50 until
                        # 2026-08-29. The corpus reported 79 of these, and 62
                        # were the rustls workspace counted a second time under
                        # the `rustls-pemfile` name, whose declared scope does
                        # not exist at its pinned commit and which symlinks to
                        # the same clone. Observed 17 over the repaired scope —
                        # 10 from `crates-io:rustls`, 7 from
                        # `crates-io:hyper-rustls`.
    # CRYPTO-241 (jjwt HS256) was floored at 1 as "the canonical jjwt-api
    # regression". Removed on 2026-08-28: the corpus contained exactly one
    # CRYPTO-241 site, `Arrays.asList(HS512, HS384, HS256)` at
    # jjwt-api SignatureAlgorithm.java:115, and `PRECISION_AUDIT_V4.md § 5`
    # rows 86-87 label it a false positive — a preference list of enum
    # constants, no HMAC computed. jjwt-api's other 4 findings are the same
    # two lines. A floor of 1 therefore demanded that one false positive be
    # kept forever, and 0 would be a floor that cannot fail.
    # The regression it was built to catch — the scanner going silent on
    # jjwt — is now held by fixtures instead, which is where a shape this
    # narrow belongs: phase1_jjwt_* and java_jose_operational_sites_still_fire
    # in crates/scan-source/tests/scan_test.rs.
}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--clones", default=CLONES_DIR, type=Path,
                    help="Root directory holding cloned projects")
    ap.add_argument("--bin", default=None, help="Path to the quipuu binary")
    ap.add_argument("--update", action="store_true")
    args = ap.parse_args()

    if args.update:
        print("Use of --update is intentional; review floors in this file by hand.", file=sys.stderr)
        return 0
    if not args.clones.exists():
        print(f"SKIP: {args.clones} not present (corpus not cloned).")
        return 0

    # Re-run the scan into a scratch directory. The floors below were set at
    # `include_safe:false`, while the committed results/ artifacts are the
    # `--include-safe` run the README cites — so writing into results/ would
    # silently replace a published artifact with a differently-flagged one.
    with tempfile.TemporaryDirectory() as scratch:
        print("Running scan_corpus.py...")
        cmd = [
            sys.executable, str(SCRIPT_DIR / "scan_corpus.py"),
            "--clones", str(args.clones),
            "--out", scratch,
        ]
        if args.bin:
            cmd += ["--bin", args.bin]
        rc = subprocess.run(cmd, cwd=SCRIPT_DIR, timeout=1800)
        if rc.returncode != 0:
            print(f"FAIL: scan_corpus.py exited with {rc.returncode}", file=sys.stderr)
            return 1

        summary_path = Path(scratch) / "summary.json"
        if not summary_path.exists():
            print(f"FAIL: {summary_path} not written", file=sys.stderr)
            return 1
        summary = json.loads(summary_path.read_text())

        failures: list[str] = []

        # Per-ecosystem floors.
        total = 0
        for eco, agg in summary["by_ecosystem"].items():
            actual = agg["total_findings"]
            total += actual
            floor = V8_FLOOR.get(eco, 0)
            if actual < floor:
                failures.append(
                    f"REGRESSION: {eco} produced {actual} findings, below V8 floor {floor}"
                )
            else:
                print(f"OK: {eco:20} {actual:5} >= {floor:5}")

        if total < V8_FLOOR["total"]:
            failures.append(
                f"REGRESSION: total {total} findings below V8 floor {V8_FLOOR['total']}"
            )
        else:
            print(f"OK: total                {total:5} >= {V8_FLOOR['total']:5}")

        # Per-rule floors — read all_findings.json. If dump_findings.py hasn't run
        # in this CI cycle, skip per-rule checks (the ecosystem floors are
        # sufficient for the main regression signal).
        all_findings_path = SCRIPT_DIR / "results" / "all_findings.json"
        if all_findings_path.exists():
            from dump_findings import load_dump

            all_findings = load_dump(all_findings_path)["findings"]
            from collections import Counter
            rule_counts = Counter(f["rule_id"] for f in all_findings)
            print()
            for rule, floor in sorted(RULE_FLOORS.items()):
                actual = rule_counts.get(rule, 0)
                if actual < floor:
                    failures.append(
                        f"REGRESSION: rule {rule} fired {actual} times, below floor {floor}"
                    )
                else:
                    print(f"OK: rule {rule:12} {actual:4} >= {floor}")
        else:
            print(f"\nSKIP per-rule floors: {all_findings_path} not present")
            print("    (run dump_findings.py to enable per-rule regression checks)")

        print()
        if failures:
            for f in failures:
                print(f"  {f}", file=sys.stderr)
            print(f"\n{len(failures)} regression(s)", file=sys.stderr)
            return 1
        print("All floors met. No regressions.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

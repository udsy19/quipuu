#!/usr/bin/env python3
"""regression_check.py — assert V8 corpus headline numbers as a floor.

Runs scan_corpus.py, then asserts that each ecosystem produced AT LEAST the
floor count of findings established by V8. Floors are intentionally
conservative — a 5-10% drop in any ecosystem fails CI loudly. Coverage
improvements always cause the test to pass; coverage regressions fail.

Designed for CI. Skips if `clones/` is absent (so it doesn't run in plain
unit-test contexts). Exits 1 on regression.

Usage:
    python3 regression_check.py [--update]    # update floors after intentional regression
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SUMMARY_PATH = SCRIPT_DIR / "results" / "summary.json"
CLONES_DIR = SCRIPT_DIR / "clones"

# V8 floor (commit 89d35cb). A 5% margin below the observed V8 numbers gives
# us room for legitimate scan_hints changes while still catching real
# regressions (e.g., a rule rewrite that breaks the Java JWT path).
V8_FLOOR = {
    "pypi":            36,   # V8: 38
    "npm":            111,   # V8: 117
    "maven":          347,   # V8: 366
    "crates-io":      214,   # V8: 226
    "go-modules":     418,   # V8: 441
    "crypto-adjacent":  5,   # V8: 6
    "total":         1133,   # V8: 1194  (5% under)
}

# Per-rule floors for the most-important rules. If any of these drop to zero
# we want a hard fail — those rules represent corpus-validated detection that
# downstream users depend on.
RULE_FLOORS = {
    "CRYPTO-700": 25,   # Go JWT RS256
    "CRYPTO-740": 10,   # JWT alg=none
    "CRYPTO-704": 10,   # Go JWT PS384
    "CRYPTO-705": 10,   # Go JWT PS512
    "CRYPTO-560": 50,   # rustls::ClientConfig::builder
    "CRYPTO-241": 1,    # jjwt HS256 — the canonical jjwt-api regression
}


def main() -> int:
    if "--update" in sys.argv:
        print("Use of --update is intentional; review floors in this file by hand.", file=sys.stderr)
        return 0
    if not CLONES_DIR.exists():
        print(f"SKIP: {CLONES_DIR} not present (corpus not cloned).")
        return 0

    # Re-run the scan to refresh summary.json.
    print("Running scan_corpus.py...")
    rc = subprocess.run(
        [sys.executable, str(SCRIPT_DIR / "scan_corpus.py")],
        cwd=SCRIPT_DIR,
        timeout=600,
    )
    if rc.returncode != 0:
        print(f"FAIL: scan_corpus.py exited with {rc.returncode}", file=sys.stderr)
        return 1

    if not SUMMARY_PATH.exists():
        print(f"FAIL: {SUMMARY_PATH} not written", file=sys.stderr)
        return 1
    summary = json.loads(SUMMARY_PATH.read_text())

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
        all_findings = json.loads(all_findings_path.read_text())
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

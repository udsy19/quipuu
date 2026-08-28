#!/usr/bin/env python3
"""fetch_acvp_vectors.py — pull real NIST ACVP test vectors and bundle them.

Replaces the synthetic placeholders in `crates/cli/data/acvp-vectors/` with
the real, SHA-pinned vectors from https://github.com/usnistgov/ACVP-Server.

Per the trust invariants (P1: no LLM at runtime; P2: no listening sockets;
P4: no customer-code execution), this script is OFFLINE INFRA — it runs at
development time (or in CI on a refresh) and produces JSON files that ship
inside the quipuu binary via `include_bytes!`. The compiled binary never
makes a network call.

The NIST ACVP test format splits inputs and outputs across two files:
  - prompt.json           — inputs (seeds, plaintexts, signatures to verify, …)
  - expectedResults.json  — outputs (ek/dk, ct/ss, sig, verifyResult, …)

quipuu's runner consumes a SINGLE merged file per (algorithm, parameterSet,
mode). This script merges them, filters to the parameter sets we care about,
and writes the trimmed JSON to data/acvp-vectors/.

Usage:
    python3 tools/fetch_acvp_vectors.py [--commit <sha>] [--max-tests <N>]
                                        [--out <dir>] [--check]

Options:
    --commit <sha>     ACVP-Server commit to pin. Default: master HEAD.
    --max-tests <N>    Cap the test cases per parameter set (default: 25).
                       The full vectors are large (>800 KB per algo); we
                       embed a representative subset.
    --out <dir>        Output directory (default: crates/cli/data/acvp-vectors)
    --check            Compare existing bundled vectors against the live
                       upstream; print diffs without writing anything.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

ACVP_SERVER_REPO = "usnistgov/ACVP-Server"
DEFAULT_BRANCH = "master"

# (subset of parameter sets quipuu's runner supports today)
TARGETS = [
    {
        "out_name": "ML-KEM-512-keyGen.json",
        "directory": "ML-KEM-keyGen-FIPS203",
        "parameter_set": "ML-KEM-512",
        "mode": "keyGen",
        "input_fields": ["d", "z"],
        "output_fields": ["ek", "dk"],
    },
    {
        "out_name": "ML-KEM-768-encapDecap.json",
        "directory": "ML-KEM-encapDecap-FIPS203",
        "parameter_set": "ML-KEM-768",
        "mode": "encapDecap",
        "input_fields": ["ek", "m"],  # encap input
        "output_fields": ["c", "k"],   # encap output (NIST uses "c" and "k")
    },
    {
        "out_name": "ML-KEM-1024-keyGen.json",
        "directory": "ML-KEM-keyGen-FIPS203",
        "parameter_set": "ML-KEM-1024",
        "mode": "keyGen",
        "input_fields": ["d", "z"],
        "output_fields": ["ek", "dk"],
    },
    {
        "out_name": "ML-DSA-44-keyGen.json",
        "directory": "ML-DSA-keyGen-FIPS204",
        "parameter_set": "ML-DSA-44",
        "mode": "keyGen",
        "input_fields": ["seed"],
        "output_fields": ["pk", "sk"],
    },
    {
        "out_name": "ML-DSA-65-sigGen.json",
        "directory": "ML-DSA-sigGen-FIPS204",
        "parameter_set": "ML-DSA-65",
        "mode": "sigGen",
        "input_fields": ["message", "sk", "rnd"],
        "output_fields": ["signature"],
    },
    {
        "out_name": "ML-DSA-87-sigVer.json",
        "directory": "ML-DSA-sigVer-FIPS204",
        "parameter_set": "ML-DSA-87",
        "mode": "sigVer",
        "input_fields": ["message", "signature", "pk"],
        "output_fields": ["testPassed"],
    },
    {
        "out_name": "SLH-DSA-SHAKE-128s-keyGen.json",
        "directory": "SLH-DSA-keyGen-FIPS205",
        "parameter_set": "SLH-DSA-SHAKE-128s",
        "mode": "keyGen",
        "input_fields": ["skSeed", "skPrf", "pkSeed"],
        "output_fields": ["pk", "sk"],
    },
    {
        "out_name": "SLH-DSA-SHAKE-128s-sigGen.json",
        "directory": "SLH-DSA-sigGen-FIPS205",
        "parameter_set": "SLH-DSA-SHAKE-128s",
        "mode": "sigGen",
        "input_fields": ["message", "sk"],
        "output_fields": ["signature"],
    },
]


def github_raw(commit: str, path: str) -> str:
    return f"https://raw.githubusercontent.com/{ACVP_SERVER_REPO}/{commit}/{path}"


def resolve_master_sha() -> str:
    """Pin to the current master HEAD SHA so reruns are reproducible."""
    url = f"https://api.github.com/repos/{ACVP_SERVER_REPO}/commits/{DEFAULT_BRANCH}"
    with urllib.request.urlopen(url) as resp:
        data = json.loads(resp.read())
    return data["sha"]


def fetch_json(url: str) -> dict:
    print(f"  GET {url}")
    try:
        with urllib.request.urlopen(url) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        print(f"  HTTP {e.code}: {url}", file=sys.stderr)
        raise


def merge_prompt_with_results(prompt: dict, results: dict, target: dict) -> dict:
    """Merge prompt + expectedResults, filter to target parameter set."""
    by_tc: dict[int, dict] = {}

    # First pass: collect prompt inputs keyed by (tgId, tcId)
    for tg in prompt.get("testGroups", []):
        if tg.get("parameterSet") != target["parameter_set"]:
            continue
        tg_id = tg.get("tgId")
        for tc in tg.get("tests", []):
            tc_id = tc.get("tcId")
            key = (tg_id, tc_id)
            row = {"tcId": tc_id}
            for f in target["input_fields"]:
                if f in tc:
                    row[f] = tc[f]
            by_tc[key] = row

    # Second pass: merge expectedResults outputs.
    # expectedResults doesn't repeat parameterSet on the test group, so we use
    # the (tgId, tcId) lookup we just built.
    for tg in results.get("testGroups", []):
        tg_id = tg.get("tgId")
        for tc in tg.get("tests", []):
            tc_id = tc.get("tcId")
            key = (tg_id, tc_id)
            if key not in by_tc:
                continue  # different parameter set
            row = by_tc[key]
            for f in target["output_fields"]:
                if f in tc:
                    row[f] = tc[f]

    # Re-group by tgId, preserving order from prompt
    test_groups: list[dict] = []
    seen_tg = {}
    for tg in prompt.get("testGroups", []):
        if tg.get("parameterSet") != target["parameter_set"]:
            continue
        tg_id = tg.get("tgId")
        if tg_id in seen_tg:
            continue
        seen_tg[tg_id] = True
        tests = []
        for tc in tg.get("tests", []):
            tc_id = tc.get("tcId")
            row = by_tc.get((tg_id, tc_id))
            if row is None:
                continue
            tests.append(row)
        if not tests:
            continue
        test_groups.append(
            {
                "tgId": tg_id,
                "testType": tg.get("testType", "AFT"),
                "parameterSet": target["parameter_set"],
                "tests": tests,
            }
        )

    return {
        "vsId": prompt.get("vsId"),
        "algorithm": prompt.get("algorithm"),
        "mode": prompt.get("mode"),
        "revision": prompt.get("revision"),
        "isSample": prompt.get("isSample", False),
        "parameterSet": target["parameter_set"],
        "testGroups": test_groups,
    }


def truncate(merged: dict, max_tests: int) -> dict:
    """Cap to the first max_tests test cases per parameter set, preserving
    group structure. Embedding all ~50 test cases would balloon the binary."""
    remaining = max_tests
    out_groups = []
    for tg in merged["testGroups"]:
        if remaining <= 0:
            break
        new_tests = tg["tests"][:remaining]
        if not new_tests:
            continue
        out_groups.append({**tg, "tests": new_tests})
        remaining -= len(new_tests)
    merged["testGroups"] = out_groups
    return merged


def fetch_target(commit: str, target: dict, max_tests: int) -> dict:
    """Fetch + merge one target's prompt and expectedResults."""
    base = f"gen-val/json-files/{target['directory']}"
    prompt = fetch_json(github_raw(commit, f"{base}/prompt.json"))
    results = fetch_json(github_raw(commit, f"{base}/expectedResults.json"))
    merged = merge_prompt_with_results(prompt, results, target)
    truncated = truncate(merged, max_tests)
    truncated["_source"] = {
        "authority": "NIST ACVP-Server",
        "repository": f"https://github.com/{ACVP_SERVER_REPO}",
        "commit": commit,
        "directory": target["directory"],
        "max_tests_embedded": max_tests,
    }
    return truncated


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--commit", default=None)
    p.add_argument("--max-tests", type=int, default=25)
    p.add_argument(
        "--out",
        default=str(
            Path(__file__).resolve().parent.parent / "crates/cli/data/acvp-vectors"
        ),
    )
    p.add_argument("--check", action="store_true")
    args = p.parse_args()

    commit = args.commit or resolve_master_sha()
    print(f"ACVP-Server pinned commit: {commit}")
    print(f"Vector cap: {args.max_tests} test cases per parameter set")
    print()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    changed: list[str] = []
    unchanged: list[str] = []
    errors: list[tuple[str, str]] = []

    for target in TARGETS:
        out_path = out_dir / target["out_name"]
        print(f"=== {target['out_name']} ({target['parameter_set']} {target['mode']})")
        try:
            merged = fetch_target(commit, target, args.max_tests)
        except urllib.error.HTTPError as e:
            print(f"  SKIP (HTTP {e.code})", file=sys.stderr)
            errors.append((target["out_name"], f"HTTP {e.code}"))
            continue
        except Exception as e:  # noqa: BLE001  — this is a sync, run-and-die script
            print(f"  SKIP ({e})", file=sys.stderr)
            errors.append((target["out_name"], str(e)))
            continue

        n_tests = sum(len(tg["tests"]) for tg in merged["testGroups"])
        print(f"  OK ({len(merged['testGroups'])} groups, {n_tests} tests)")

        new_json = json.dumps(merged, indent=2, sort_keys=False) + "\n"

        if args.check:
            if not out_path.exists():
                changed.append(target["out_name"])
                continue
            old = out_path.read_text()
            if old != new_json:
                changed.append(target["out_name"])
            else:
                unchanged.append(target["out_name"])
        else:
            out_path.write_text(new_json)
            changed.append(target["out_name"])

    print()
    print("=" * 60)
    if args.check:
        print(f"Differs from upstream: {len(changed)} file(s)")
        for n in changed:
            print(f"  - {n}")
        print(f"Matches: {len(unchanged)} file(s)")
        if errors:
            print(f"Errors: {len(errors)}")
            for n, msg in errors:
                print(f"  - {n}: {msg}")
        return 1 if changed or errors else 0
    else:
        print(f"Wrote {len(changed)} file(s) to {out_dir}")
        if errors:
            print(f"Errors: {len(errors)}")
            for n, msg in errors:
                print(f"  - {n}: {msg}")
            return 1
        return 0


if __name__ == "__main__":
    sys.exit(main())

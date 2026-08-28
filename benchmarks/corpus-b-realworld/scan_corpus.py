#!/usr/bin/env python3
"""scan_corpus.py — run quipuu across the 150-project corpus.

For each project in manifest.toml:
  1. Resolve the cloned path under clones/<ecosystem>/<name>/.
  2. Apply scan_hints.scan_paths if present (else scan the repo root).
  3. Invoke quipuu binary on each scan path; aggregate finding count,
     wall-clock duration, and stderr.
  4. Emit results/<canonical-id>.json with per-project data.
  5. Emit results/summary.json with aggregate counts and per-ecosystem
     headline numbers.

Usage:
    python3 scan_corpus.py [--clones clones/] [--bin <path>] [--ecosystem E]
                           [--out results/] [--include-safe]

Exit codes:
    0  All scans completed (may include per-project errors recorded in JSON)
    1  Binary not found / corpus directory missing / fatal I/O

This is intentionally simple: each project gets one quipuu invocation
with --source --deps. We never run any code from the cloned repos (P4).
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

try:
    import tomllib as toml_lib
except ImportError:
    import tomli as toml_lib

SCRIPT_DIR = Path(__file__).resolve().parent


def load_manifest() -> list[dict]:
    """Return the list of project entries from manifest.toml."""
    with open(SCRIPT_DIR / "manifest.toml", "rb") as f:
        manifest = toml_lib.load(f)
    return manifest["projects"]


def load_project(file_path: Path) -> dict:
    """Read a project file given its path relative to SCRIPT_DIR."""
    full = SCRIPT_DIR / file_path
    with open(full, "rb") as f:
        return toml_lib.load(f)


def discover_quipuu() -> Path:
    """Find the quipuu binary built earlier."""
    # Prefer the workspace target/release if present; fall back to debug.
    workspace = SCRIPT_DIR.parent.parent / "quipuu"
    for profile in ("release", "debug"):
        candidate = workspace / "target" / profile / "quipuu"
        if candidate.exists():
            return candidate
    raise SystemExit(
        "quipuu binary not found; build with `cargo build --workspace` "
        "from the quipuu/ directory first"
    )


def corpus_rel(target: Path, clone_path: Path, ecosystem: str, name: str) -> str:
    """Name a scan target by its corpus position (`<ecosystem>/<name>/...`).

    Everything written under results/ is committed, so it must not carry the
    absolute path of whichever machine produced it. Ten clones are symlinks to
    another clone, so resolve both sides before stripping; the prefix put back
    is the logical `ecosystem/name` that was scanned, not the link target.
    """
    try:
        rel = target.resolve().relative_to(clone_path.resolve())
    except ValueError:
        return f"{ecosystem}/{name}"
    return str(Path(ecosystem) / name / rel)


def scan_one(
    binary: Path,
    project: dict,
    clone_root: Path,
    include_safe: bool,
) -> dict:
    """Run quipuu against one project; return a result dict.

    The result dict captures:
      canonical_id, ecosystem, scan_paths, total_findings, audible_findings,
      suppressed_findings, duration_seconds, exit_code, errors, sample_findings
    """
    p_info = project["project"]
    name = p_info["name"]
    ecosystem = p_info["ecosystem"]
    canonical_id = p_info["canonical_id"]

    clone_path = clone_root / ecosystem / name
    if not clone_path.is_dir():
        # Record the clone by its position in the corpus, not by its absolute
        # path: the clone root moves between machines and an absolute path
        # committed under results/ names an operator's home directory.
        rel = f"{ecosystem}/{name}"
        return {
            "canonical_id": canonical_id,
            "ecosystem": ecosystem,
            "status": "missing_clone",
            "clone_path": rel,
            "total_findings": 0,
            "audible_findings": 0,
            "suppressed_findings": 0,
            "duration_seconds": 0.0,
            "errors": [f"clone path does not exist: {rel}"],
        }

    hints = project.get("scan_hints", {})
    scan_paths = hints.get("scan_paths") or [""]
    resolved = []
    for sp in scan_paths:
        target = clone_path / sp if sp else clone_path
        if target.exists():
            resolved.append(target)
    if not resolved:
        resolved = [clone_path]

    sample_findings: list[dict] = []
    total = 0
    audible = 0
    suppressed = 0
    errors: list[str] = []
    duration_total = 0.0
    exit_code = 0

    import tempfile

    for target in resolved:
        # Use a real tempfile for summary-json so we don't have to disentangle
        # JSON from the scanner's human-readable stdout listing.
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as tf:
            summary_path = tf.name
        try:
            cmd = [
                str(binary),
                "scan",
                str(target),
                "--source",
                "--deps",
                "--summary-json",
                summary_path,
            ]
            if include_safe:
                cmd.append("--include-safe")

            start = time.monotonic()
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=600,  # 10 min per target — anything more is a hang
                )
                duration_total += time.monotonic() - start
                exit_code = max(exit_code, proc.returncode)
            except subprocess.TimeoutExpired:
                duration_total += time.monotonic() - start
                errors.append(
                    f"timeout (>600s) on "
                    f"{corpus_rel(target, clone_path, ecosystem, name)}"
                )
                continue
            except OSError as e:
                errors.append(
                    f"exec error on "
                    f"{corpus_rel(target, clone_path, ecosystem, name)}: {e}"
                )
                continue

            # Parse the summary file the scanner wrote.
            summary = None
            try:
                with open(summary_path) as f:
                    summary = json.load(f)
            except (OSError, json.JSONDecodeError):
                pass

            # The "(N shown, M hidden as quantum-safe…)" line lives on stdout.
            # The summary JSON itself reflects ONLY the displayed subset when
            # the filter is active, so we read the hidden count from stdout.
            target_shown = 0
            target_hidden = 0
            for line in proc.stdout.splitlines():
                if "shown" in line and "hidden" in line and "quantum-safe" in line:
                    parts = (
                        line.replace("(", " ")
                        .replace(")", " ")
                        .replace(",", " ")
                        .split()
                    )
                    try:
                        shown_idx = parts.index("shown") - 1
                        hidden_idx = parts.index("hidden") - 1
                        target_shown = int(parts[shown_idx])
                        target_hidden = int(parts[hidden_idx])
                    except (ValueError, IndexError):
                        pass

            if summary is not None:
                # Schema: {"totals": {"findings": N, ...}, "by_algorithm": [...]}
                # This count reflects only what quipuu passed to the
                # emitter — i.e. audible-only unless --include-safe.
                summary_total = (summary.get("totals") or {}).get("findings", 0)
                if include_safe:
                    total += summary_total
                    audible += summary_total  # nothing is hidden in this mode
                else:
                    audible += summary_total
                    suppressed += target_hidden
                    total += summary_total + target_hidden
                # Capture a small sample of algorithm IDs for diagnostics.
                by_algo = summary.get("by_algorithm") or []
                for entry in by_algo[:5]:
                    sample_findings.append(
                        {
                            "algorithm_id": entry.get("algorithm_id"),
                            "count": entry.get("count"),
                        }
                    )
            else:
                # Couldn't parse the summary file — fall back to scraping the
                # human-readable header line on stdout.
                for line in proc.stdout.splitlines() + proc.stderr.splitlines():
                    if "finding(s)" in line and "→" in line:
                        try:
                            n = int(line.split("→")[1].strip().split()[0])
                            total += n
                            audible += target_shown
                            suppressed += target_hidden
                        except (ValueError, IndexError):
                            pass

            if proc.returncode != 0 and proc.stderr:
                errors.append(proc.stderr[-2000:])
        finally:
            try:
                os.unlink(summary_path)
            except OSError:
                pass

    return {
        "canonical_id": canonical_id,
        "ecosystem": ecosystem,
        "scan_paths": [str(r.relative_to(clone_path)) or "." for r in resolved],
        "total_findings": total,
        "audible_findings": audible,
        "suppressed_findings": suppressed,
        "duration_seconds": round(duration_total, 2),
        "exit_code": exit_code,
        "status": "ok" if not errors and exit_code == 0 else "errors",
        "errors": errors,
        "sample_findings": sample_findings,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--clones",
        default=str(SCRIPT_DIR / "clones"),
        help="Root directory holding cloned projects",
    )
    parser.add_argument(
        "--bin",
        default=None,
        help="Path to quipuu binary (auto-detected if omitted)",
    )
    parser.add_argument(
        "--ecosystem",
        default=None,
        help="Limit to one ecosystem (pypi, npm, maven, crates-io, go-modules, crypto-adjacent)",
    )
    parser.add_argument(
        "--out",
        default=str(SCRIPT_DIR / "results"),
        help="Where to write per-project JSON and summary.json",
    )
    parser.add_argument(
        "--include-safe",
        action="store_true",
        help="Pass --include-safe through to quipuu (default: do not)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Scan only the first N projects (for testing)",
    )
    args = parser.parse_args()

    clones = Path(args.clones)
    if not clones.is_dir():
        print(f"clones dir does not exist: {clones}", file=sys.stderr)
        return 1

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    per_proj_dir = out / "per-project"
    per_proj_dir.mkdir(exist_ok=True)

    binary = Path(args.bin) if args.bin else discover_quipuu()
    print(f"Using quipuu binary: {binary}")
    print(f"Clones root: {clones}")
    print(f"Output dir:  {out}")
    if args.ecosystem:
        print(f"Ecosystem filter: {args.ecosystem}")

    manifest_entries = load_manifest()
    results: list[dict] = []
    started = time.monotonic()

    scanned_count = 0
    for i, entry in enumerate(manifest_entries):
        project = load_project(Path(entry["file_path"]))
        ecosystem = project["project"]["ecosystem"]
        if args.ecosystem and ecosystem != args.ecosystem:
            continue
        if args.limit is not None and scanned_count >= args.limit:
            break

        canonical = project["project"]["canonical_id"]
        print(f"[{scanned_count + 1:>3}/{len(manifest_entries)}] {canonical} ... ", end="", flush=True)
        scanned_count += 1
        result = scan_one(binary, project, clones, args.include_safe)
        status = result["status"]
        n = result["total_findings"]
        sec = result["duration_seconds"]
        print(f"{status} ({n} findings, {sec:.1f}s)")

        # Go modules use slashed paths in their canonical IDs; flatten to be
        # safe across all ecosystems.
        safe_id = canonical.replace(":", "_").replace("/", "_")
        per_proj_path = per_proj_dir / f"{safe_id}.json"
        per_proj_path.write_text(json.dumps(result, indent=2))
        results.append(result)

    # Aggregate summary
    total_elapsed = time.monotonic() - started
    by_eco: dict[str, dict] = {}
    for r in results:
        eco = r["ecosystem"]
        agg = by_eco.setdefault(
            eco,
            {
                "projects_scanned": 0,
                "projects_with_findings": 0,
                "projects_with_errors": 0,
                "total_findings": 0,
                "audible_findings": 0,
                "suppressed_findings": 0,
                "total_duration_seconds": 0.0,
            },
        )
        agg["projects_scanned"] += 1
        if r["total_findings"] > 0:
            agg["projects_with_findings"] += 1
        if r["errors"]:
            agg["projects_with_errors"] += 1
        agg["total_findings"] += r["total_findings"]
        agg["audible_findings"] += r["audible_findings"]
        agg["suppressed_findings"] += r["suppressed_findings"]
        agg["total_duration_seconds"] += r["duration_seconds"]

    summary = {
        "corpus": "corpus-b-realworld",
        "include_safe": args.include_safe,
        "total_projects_scanned": len(results),
        "total_elapsed_seconds": round(total_elapsed, 2),
        "by_ecosystem": by_eco,
        "top_10_by_findings": sorted(
            results, key=lambda r: r["total_findings"], reverse=True
        )[:10],
        "projects_with_zero_findings": [
            r["canonical_id"] for r in results if r["total_findings"] == 0
        ],
        "projects_with_errors": [
            {"canonical_id": r["canonical_id"], "errors": r["errors"][:3]}
            for r in results
            if r["errors"]
        ],
    }

    summary_path = out / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2))
    print()
    print("=" * 60)
    print(f"Done. {len(results)} projects scanned in {total_elapsed:.1f}s.")
    print(f"Summary: {summary_path}")
    for eco, agg in by_eco.items():
        print(
            f"  {eco}: {agg['projects_scanned']} projects, "
            f"{agg['total_findings']} findings "
            f"({agg['projects_with_findings']} non-zero, "
            f"{agg['projects_with_errors']} errored)"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())

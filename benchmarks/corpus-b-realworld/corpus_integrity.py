#!/usr/bin/env python3
"""corpus_integrity.py — prove the corpus is intact before it may produce a number.

Every published corpus figure is a ratio whose denominator is "the 150 projects
in manifest.toml". That denominator is only true if the 150 checkouts on disk
are actually the 150 commits the manifest names, walked over the paths the
manifest declares. Two silent substitutions used to break that:

  * When a checkout is absent or its working tree is empty, `scan_corpus.py` and
    `dump_findings.py` recorded zero findings for it — indistinguishable, in
    every artifact downstream, from a project that was scanned in full and
    genuinely contains no cryptography. A corpus can lose a third of its
    projects and still emit a confident total.

  * When a declared `scan_hints.scan_paths` entry did not exist on disk, both
    scripts dropped it, and when none of them existed they scanned the whole
    repository instead — recording `status: "ok"`. The scope silently widened
    to include exactly the trees the manifest set out to exclude.

This script closes both. For each manifest project it records

    (head_sha, files_scanned, bytes_scanned)

over exactly the paths `scan_hints.scan_paths` would hand to the scanner,
compares them against the committed baseline in `corpus-integrity.toml`, and
exits non-zero **naming every project that failed and why**.

States, most severe first:

  absent        no clone directory, or no .git inside it
  empty         .git present but the working tree has no tracked files —
                the failure mode this script exists to catch
  unpinnable    the manifest's commit_sha is not a commit in the repository, so
                the project can never be restored from the manifest. A defect in
                the corpus definition, not in the checkout.
  scope-missing a declared scan_path is not on disk. Ranked above off-sha
                because its consequence is worse: an off-sha project is scanned
                over the right shape of tree at the wrong commit, while a
                scope-missing one used to be scanned over a different tree
                entirely and reported as if it were the declared one.
  off-sha       HEAD is a real commit but not the pinned one
  drift         right commit, but the file/byte census differs from the baseline
                (untracked build output, a partial checkout, a truncated file)
  unscannable   the project file declares `scan_hints.unscannable = "<reason>"`.
                A recorded, named exclusion — it passes, contributes no
                findings, and every total says how many there are. This exists
                so that "we know this project cannot be scoped, here is why" is
                never expressed as an empty scan_paths list, which means
                "scan the whole repository".
  ok

`--write` regenerates the baseline from the current state; do that only when
the corpus has been deliberately re-pinned, and commit the diff.

Usage:
    python3 corpus_integrity.py --clones <dir>              # check, exit 1 on any failure
    python3 corpus_integrity.py --clones <dir> --write      # regenerate the baseline
    python3 corpus_integrity.py --clones <dir> --json out.json

P4: every git invocation here is read-only metadata (rev-parse, cat-file,
ls-files). Nothing in a scanned project is ever executed, and no hook, filter
or checkout is run.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

try:
    import tomllib as toml_lib
except ImportError:  # Python < 3.11
    import tomli as toml_lib

SCRIPT_DIR = Path(__file__).resolve().parent
BASELINE = SCRIPT_DIR / "corpus-integrity.toml"

# Most severe first. A state's index is its severity; `ok` and `unscannable`
# are the only two that pass.
STATES = (
    "absent",
    "empty",
    "unpinnable",
    "scope-missing",
    "off-sha",
    "drift",
    "unscannable",
    "ok",
)
PASSING = ("unscannable", "ok")


def load_manifest() -> list[dict]:
    with open(SCRIPT_DIR / "manifest.toml", "rb") as f:
        return toml_lib.load(f)["projects"]


def load_project(rel: str) -> dict:
    with open(SCRIPT_DIR / rel, "rb") as f:
        return toml_lib.load(f)


def git(repo: Path, *args: str) -> str | None:
    """Run a read-only git command; return stripped stdout, or None on failure."""
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.strip()


def unscannable_reason(project: dict) -> str:
    return project.get("scan_hints", {}).get("unscannable", "")


def resolve_scan_paths(clone: Path, project: dict) -> tuple[list[Path], list[str]]:
    """Split the declared scan scope into what is on disk and what is not.

    There is deliberately no fallback. A declared path that does not exist is a
    corpus defect and is returned as `missing` so the caller can refuse; it is
    never replaced by the repository root. That substitution is how 355 of 1399
    findings — 25.4% of the corpus, and 119 of its 131 dependency-manifest
    findings — came to be gathered from trees the manifest excludes.

    An empty or absent `scan_paths` means "the whole repository", which is a
    declaration and not a fallback.
    """
    resolved: list[Path] = []
    missing: list[str] = []
    for sp in project.get("scan_hints", {}).get("scan_paths") or [""]:
        target = clone / sp if sp else clone
        if target.exists():
            resolved.append(target)
        else:
            missing.append(sp)
    return resolved, missing


def census(paths: list[Path]) -> tuple[int, int]:
    """Count regular files and total bytes under `paths`, ignoring .git."""
    files = 0
    total = 0
    for root in paths:
        if root.is_file():
            files += 1
            total += root.stat().st_size
            continue
        for entry in root.rglob("*"):
            if ".git" in entry.parts:
                continue
            try:
                if entry.is_file() and not entry.is_symlink():
                    files += 1
                    total += entry.stat().st_size
            except OSError:
                continue
    return files, total


def inspect(project: dict, clones: Path, baseline: dict | None) -> dict:
    """Census one project. `baseline is None` censuses without comparing."""
    p = project["project"]
    canonical = p["canonical_id"]
    clone = clones / p["ecosystem"] / p["name"]
    pin = project.get("repo", {}).get("commit_sha", "")
    row = {
        "canonical_id": canonical,
        "ecosystem": p["ecosystem"],
        "clone_path": f"{p['ecosystem']}/{p['name']}",
        "pinned_sha": pin,
        "head_sha": None,
        "files_scanned": 0,
        "bytes_scanned": 0,
        "state": "absent",
        "detail": "",
    }

    if not (clone / ".git").exists():
        row["detail"] = f"no clone at {row['clone_path']}"
        return row

    head = git(clone, "rev-parse", "HEAD")
    row["head_sha"] = head

    reason = unscannable_reason(project)
    if reason:
        row["state"] = "unscannable"
        row["detail"] = reason
        return row

    tracked = git(clone, "ls-files")
    if not tracked:
        row["state"] = "empty"
        row["detail"] = "working tree has no tracked files (checkout never happened)"
        return row

    resolved, missing = resolve_scan_paths(clone, project)
    files, nbytes = census(resolved)
    row["files_scanned"] = files
    row["bytes_scanned"] = nbytes

    if pin and git(clone, "cat-file", "-e", f"{pin}^{{commit}}") is None:
        row["state"] = "unpinnable"
        row["detail"] = (
            f"manifest pins {pin[:12]} which is not a commit in this repository; "
            f"HEAD is {(head or '?')[:12]}"
        )
        return row

    if missing:
        row["state"] = "scope-missing"
        row["detail"] = (
            f"declared scan_path(s) not on disk: {', '.join(missing)}; "
            f"{len(resolved)} of {len(resolved) + len(missing)} resolve"
        )
        return row

    if pin and head != pin:
        row["state"] = "off-sha"
        row["detail"] = f"HEAD {(head or '?')[:12]} != pinned {pin[:12]}"
        return row

    if baseline is None:
        row["state"] = "ok"
        return row

    want = baseline.get(canonical)
    if want is None:
        row["state"] = "drift"
        row["detail"] = "no baseline row for this project"
        return row
    if files != want["files_scanned"] or nbytes != want["bytes_scanned"]:
        row["state"] = "drift"
        row["detail"] = (
            f"census {files} files / {nbytes} bytes != baseline "
            f"{want['files_scanned']} files / {want['bytes_scanned']} bytes"
        )
        return row

    row["state"] = "ok"
    return row


def load_baseline() -> dict:
    if not BASELINE.exists():
        return {}
    with open(BASELINE, "rb") as f:
        data = toml_lib.load(f)
    return {r["canonical_id"]: r for r in data.get("project", [])}


def write_baseline(rows: list[dict], recorded_at: str) -> None:
    scanned = [r for r in rows if r["state"] != "unscannable"]
    lines = [
        "# corpus-integrity.toml — the census `corpus_integrity.py` checks against.",
        "#",
        "# Regenerate with `corpus_integrity.py --clones <dir> --write` ONLY after the",
        "# corpus has been deliberately re-pinned, and commit the diff alongside the",
        "# manifest change that caused it. A silent regeneration turns the check into",
        "# a no-op, which is the exact failure it exists to prevent.",
        "#",
        "# files_scanned/bytes_scanned are counted over the declared scan_paths, not",
        "# over the repository, so a project whose scope moves fails as `drift` even",
        "# when its HEAD is right.",
        "",
        "[baseline]",
        f'recorded_at = "{recorded_at}"',
        f"total_projects = {len(rows)}",
        f"unscannable_projects = {len(rows) - len(scanned)}",
        f'files_scanned_total = {sum(r["files_scanned"] for r in scanned)}',
        f'bytes_scanned_total = {sum(r["bytes_scanned"] for r in scanned)}',
        "",
    ]
    for r in sorted(rows, key=lambda r: r["canonical_id"]):
        lines += [
            "[[project]]",
            f'canonical_id = "{r["canonical_id"]}"',
            f'head_sha = "{r["head_sha"] or ""}"',
            f"files_scanned = {r['files_scanned']}",
            f"bytes_scanned = {r['bytes_scanned']}",
            "",
        ]
    BASELINE.write_text("\n".join(lines))


def worst_state(rows: list[dict]) -> str:
    return min((r["state"] for r in rows), key=STATES.index, default="ok")


def failed(rows: list[dict]) -> list[dict]:
    return [r for r in rows if r["state"] not in PASSING]


def check(clones: Path, use_baseline: bool = True) -> list[dict]:
    """Census every manifest project. Importable entry point for the harness."""
    baseline = load_baseline() if use_baseline else None
    return [
        inspect(load_project(e["file_path"]), clones, baseline)
        for e in load_manifest()
    ]


def report(rows: list[dict], stream=sys.stdout) -> None:
    bad = failed(rows)
    unscannable = [r for r in rows if r["state"] == "unscannable"]
    populated = sum(1 for r in rows if r["state"] not in ("absent", "empty"))
    print(
        f"corpus integrity: {populated}/{len(rows)} populated, "
        f"{len(rows) - len(bad)}/{len(rows)} match the committed baseline, "
        f"{len(unscannable)} recorded unscannable",
        file=stream,
    )
    for r in unscannable:
        print(f"  unscannable  {r['canonical_id']}: {r['detail']}", file=stream)
    if not bad:
        return
    by_state: dict[str, list[dict]] = {}
    for r in bad:
        by_state.setdefault(r["state"], []).append(r)
    for state in STATES:
        for r in by_state.get(state, []):
            print(f"  {state:<13} {r['canonical_id']}: {r['detail']}", file=stream)
    print(
        f"  {len(bad)} project(s) failed. Any figure computed over this corpus "
        f"has a denominator of {len(rows)} and a numerator drawn from "
        f"{len(rows) - len(bad)}.",
        file=stream,
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--clones", required=True, help="Root directory holding cloned projects")
    ap.add_argument("--write", action="store_true", help="Regenerate corpus-integrity.toml")
    ap.add_argument("--recorded-at", default="", help="Date stamp for --write")
    ap.add_argument("--json", default=None, help="Also write the per-project rows here")
    args = ap.parse_args()

    rows = check(Path(args.clones), use_baseline=not args.write)
    report(rows)

    if args.json:
        Path(args.json).write_text(json.dumps(rows, indent=2))

    if args.write:
        blocking = [
            r for r in rows
            if r["state"] in ("absent", "empty", "unpinnable", "scope-missing")
        ]
        if blocking:
            print(
                "refusing to write a baseline over an unrestored corpus; "
                "fix the projects listed above first",
                file=sys.stderr,
            )
            return 1
        write_baseline(rows, args.recorded_at or "unspecified")
        print(f"wrote {BASELINE}")
        return 0

    return 0 if not failed(rows) else 1


if __name__ == "__main__":
    sys.exit(main())

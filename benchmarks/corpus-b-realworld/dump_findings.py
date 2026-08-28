#!/usr/bin/env python3
"""dump_findings.py — re-scan the corpus and write a flat JSON list of every
finding for the precision audit.

Output: results/all_findings.json — an array of
  { project, ecosystem, rule_id, algorithm_id, severity, file, line, message, snippet }
records, one per finding across the whole corpus.

`file` is recorded **relative to the clone root**, as `<ecosystem>/<name>/<path>`,
so the artifact is identical no matter where the clones live. Absolute paths in a
committed artifact record one operator's home directory, not a corpus, and cannot
be diffed across machines; main() exits non-zero if any survives.

The clone root, the binary and the output path all default to the in-repo layout
and are overridable, because the corpus is routinely cloned outside the repo:

    python3 dump_findings.py --clones DIR --bin PATH --out FILE
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

try:
    import tomllib as toml_lib
except ImportError:
    import tomli as toml_lib

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_BINARY = SCRIPT_DIR.parent.parent / "quipuu/target/release/quipuu"
DEFAULT_CLONES = SCRIPT_DIR / "clones"
DEFAULT_OUT = SCRIPT_DIR / "results" / "all_findings.json"

# Match the human-readable scan output:
#   "  High\tCRYPTO-001\trsa-1024\t<path>:<line>\t<message>"
ROW_RE = re.compile(r"^\s+(\S+)\t(\S+)\t(\S+)\t(.+):(\d+)\t(.+)$")
# Some rows have no line number (e.g. DEP findings): "<path>\t..."
ROW_RE_NOLINE = re.compile(r"^\s+(\S+)\t(\S+)\t(\S+)\t([^\t]+)\t(.+)$")


def load_manifest() -> list[dict]:
    with open(SCRIPT_DIR / "manifest.toml", "rb") as f:
        m = toml_lib.load(f)
    return m["projects"]


def load_project(rel: Path) -> dict:
    with open(SCRIPT_DIR / rel, "rb") as f:
        return toml_lib.load(f)


def relativise(path: str, clone: Path, eco: str, name: str) -> str:
    """Rewrite an absolute finding path to `<ecosystem>/<name>/<path>`.

    Ten corpus clones are symlinks to another clone (`crates-io/sha2` ->
    `crates-io/md-5`), so the scanner reports the resolved target while the
    prefix we hold is the link. Resolve BOTH sides before stripping, or the
    strip silently fails and leaves the absolute path in.

    The prefix put back is the *logical* `eco/name`, not the resolved one:
    two corpus projects may share one working tree, and the finding belongs
    to the project that was scanned.
    """
    try:
        rel = Path(path).resolve().relative_to(clone.resolve())
    except ValueError:
        return path
    return str(Path(eco) / name / rel)


def scan_one(project: dict, binary: Path, clones: Path) -> list[dict]:
    p = project["project"]
    name = p["name"]
    eco = p["ecosystem"]
    canonical = p["canonical_id"]
    clone = clones / eco / name
    if not clone.is_dir():
        return []

    hints = project.get("scan_hints", {})
    scan_paths = hints.get("scan_paths") or [""]
    resolved = []
    for sp in scan_paths:
        target = clone / sp if sp else clone
        if target.exists():
            resolved.append(target)
    if not resolved:
        resolved = [clone]

    findings: list[dict] = []
    for target in resolved:
        cmd = [
            str(binary),
            "scan",
            str(target),
            "--source",
            "--deps",
            "--include-safe",  # We audit ALL findings including suppressed.
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        except subprocess.TimeoutExpired:
            continue

        for line in proc.stdout.splitlines():
            m = ROW_RE.match(line)
            if m:
                sev, rule, algo, path, lineno, msg = m.groups()
                findings.append(
                    {
                        "project": canonical,
                        "ecosystem": eco,
                        "rule_id": rule,
                        "algorithm_id": algo,
                        "severity": sev,
                        "file": relativise(path, clone, eco, name),
                        "line": int(lineno),
                        "message": msg.strip(),
                    }
                )
            elif (mn := ROW_RE_NOLINE.match(line)) and ":" not in mn.group(4):
                # DEP-style findings with no source line.
                sev, rule, algo, path, msg = mn.groups()
                findings.append(
                    {
                        "project": canonical,
                        "ecosystem": eco,
                        "rule_id": rule,
                        "algorithm_id": algo,
                        "severity": sev,
                        "file": relativise(path, clone, eco, name),
                        "line": None,
                        "message": msg.strip(),
                    }
                )
    return findings


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bin", default=DEFAULT_BINARY, type=Path,
                    help="Path to the quipuu binary")
    ap.add_argument("--clones", default=DEFAULT_CLONES, type=Path,
                    help="Root directory holding cloned projects")
    ap.add_argument("--out", default=DEFAULT_OUT, type=Path,
                    help="Where to write the flat findings array")
    args = ap.parse_args()

    if not args.bin.exists():
        print(f"missing binary: {args.bin}", file=sys.stderr)
        return 1
    if not args.clones.is_dir():
        print(f"missing clone root: {args.clones}", file=sys.stderr)
        return 1

    out: list[dict] = []
    entries = load_manifest()
    for i, entry in enumerate(entries):
        project = load_project(Path(entry["file_path"]))
        fs = scan_one(project, args.bin, args.clones)
        out.extend(fs)
        print(f"[{i + 1:>3}/{len(entries)}] {project['project']['canonical_id']}: {len(fs)} findings")

    # A single absolute path makes the whole artifact machine-specific, which
    # is the defect this script was fixed to stop producing. Fail rather than
    # write one.
    leaked = sorted({f["file"] for f in out if Path(f["file"]).is_absolute()})
    if leaked:
        print(
            f"\n{len(leaked)} finding path(s) could not be made relative to "
            f"{args.clones}; refusing to write a machine-specific artifact:",
            file=sys.stderr,
        )
        for path in leaked[:10]:
            print(f"  {path}", file=sys.stderr)
        return 1

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(out, indent=2))
    print(f"\nWrote {len(out)} findings to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

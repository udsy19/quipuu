#!/usr/bin/env python3
"""dump_findings.py — re-scan the corpus and write a flat JSON list of every
finding for the precision audit.

Output: results/all_findings.json — an array of
  { project, ecosystem, rule_id, algorithm_id, severity, file, line, message, snippet }
records, one per finding across the whole corpus.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    import tomllib as toml_lib
except ImportError:
    import tomli as toml_lib

SCRIPT_DIR = Path(__file__).resolve().parent
BINARY = SCRIPT_DIR.parent.parent / "cryptoscope/target/release/cryptoscope"
CLONES = SCRIPT_DIR / "clones"

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


def scan_one(project: dict) -> list[dict]:
    p = project["project"]
    name = p["name"]
    eco = p["ecosystem"]
    canonical = p["canonical_id"]
    clone = CLONES / eco / name
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
            str(BINARY),
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
                        "file": path,
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
                        "file": path,
                        "line": None,
                        "message": msg.strip(),
                    }
                )
    return findings


def main() -> int:
    if not BINARY.exists():
        print(f"missing binary: {BINARY}", file=sys.stderr)
        return 1
    out: list[dict] = []
    entries = load_manifest()
    for i, entry in enumerate(entries):
        project = load_project(Path(entry["file_path"]))
        fs = scan_one(project)
        out.extend(fs)
        print(f"[{i + 1:>3}/{len(entries)}] {project['project']['canonical_id']}: {len(fs)} findings")

    out_path = SCRIPT_DIR / "results" / "all_findings.json"
    out_path.parent.mkdir(exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2))
    print(f"\nWrote {len(out)} findings to {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

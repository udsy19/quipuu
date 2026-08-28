#!/usr/bin/env python3
"""recall_check.py — measure line-exact recall over the Go corpus projects.

Precision alone cannot tell you whether a scanner is good; a scanner that
reports one finding and gets it right has 100% precision. This is the other
half, and it is published beside precision in `README.md`.

GROUND TRUTH IS BUILT INDEPENDENTLY OF OUR RULE FILES. The API list below is
the Go standard-library crypto surface NIST IR 8547 puts on a timeline, taken
from the pkg.go.dev package indexes rather than from `data/rules/go.toml`. A
ground truth derived from our own rules would inherit our blind spots and score
100% by construction.

TWO DENOMINATORS, AND YOU MUST SAY WHICH ONE YOU MEAN.

  in-scope  call sites inside the subtrees `scan_hints.scan_paths` actually
            hands to the scanner. This is the recall of the *scanner*.
  whole     every call site in the clone tree. The gap between the two is the
            recall of the *benchmark harness*, and it is large: 92 of 150
            corpus projects are scanned only inside hand-picked subtrees.

Quoting either number without naming its denominator is how a coverage figure
becomes a lie. Both are printed.

    python3 recall_check.py --clones DIR --dump results/all_findings.json

`--dump` takes an artifact from `dump_findings.py`, so recall is measured on
exactly the finding set the precision audit samples, not on a separate run.
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import re
import sys
from pathlib import Path

try:
    import tomllib as toml_lib
except ImportError:
    import tomli as toml_lib

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_CLONES = SCRIPT_DIR / "clones"
DEFAULT_DUMP = SCRIPT_DIR / "results" / "all_findings.json"

# (regex, label). Anchored on `pkg.Func(` selector calls.
APIS = [
    (r"\brsa\.GenerateKey\s*\(", "rsa.GenerateKey"),
    (r"\brsa\.SignPKCS1v15\s*\(", "rsa.SignPKCS1v15"),
    (r"\brsa\.VerifyPKCS1v15\s*\(", "rsa.VerifyPKCS1v15"),
    (r"\brsa\.SignPSS\s*\(", "rsa.SignPSS"),
    (r"\brsa\.VerifyPSS\s*\(", "rsa.VerifyPSS"),
    (r"\brsa\.EncryptOAEP\s*\(", "rsa.EncryptOAEP"),
    (r"\brsa\.DecryptOAEP\s*\(", "rsa.DecryptOAEP"),
    (r"\brsa\.EncryptPKCS1v15\s*\(", "rsa.EncryptPKCS1v15"),
    (r"\brsa\.DecryptPKCS1v15\s*\(", "rsa.DecryptPKCS1v15"),
    (r"\becdsa\.GenerateKey\s*\(", "ecdsa.GenerateKey"),
    (r"\becdsa\.Sign\s*\(", "ecdsa.Sign"),
    (r"\becdsa\.SignASN1\s*\(", "ecdsa.SignASN1"),
    (r"\becdsa\.Verify\s*\(", "ecdsa.Verify"),
    (r"\becdsa\.VerifyASN1\s*\(", "ecdsa.VerifyASN1"),
    (r"\bed25519\.GenerateKey\s*\(", "ed25519.GenerateKey"),
    (r"\bed25519\.Sign\s*\(", "ed25519.Sign"),
    (r"\bed25519\.Verify\s*\(", "ed25519.Verify"),
    (r"\bdsa\.Sign\s*\(", "dsa.Sign"),
    (r"\bdsa\.Verify\s*\(", "dsa.Verify"),
    (r"\bdsa\.GenerateKey\s*\(", "dsa.GenerateKey"),
    (r"\becdh\.X25519\s*\(", "ecdh.X25519"),
    (r"\becdh\.P256\s*\(", "ecdh.P256"),
    (r"\becdh\.P384\s*\(", "ecdh.P384"),
    (r"\becdh\.P521\s*\(", "ecdh.P521"),
    (r"\bmd5\.New\s*\(", "md5.New"),
    (r"\bmd5\.Sum\s*\(", "md5.Sum"),
    (r"\bsha1\.New\s*\(", "sha1.New"),
    (r"\bsha1\.Sum\s*\(", "sha1.Sum"),
    (r"\bdes\.NewCipher\s*\(", "des.NewCipher"),
    (r"\bdes\.NewTripleDESCipher\s*\(", "des.NewTripleDESCipher"),
    (r"\brc4\.NewCipher\s*\(", "rc4.NewCipher"),
    (r"\bmlkem\.GenerateKey768\s*\(", "mlkem.GenerateKey768"),
    (r"\bmlkem\.GenerateKey1024\s*\(", "mlkem.GenerateKey1024"),
]
COMPILED = [(re.compile(p), lab) for p, lab in APIS]

# Require the matching stdlib import, so `foo.md5.New` and a same-named local
# package do not enter the ground truth as call sites we then score ourselves
# against.
IMPORT_PKG = {
    "rsa": "crypto/rsa",
    "ecdsa": "crypto/ecdsa",
    "ed25519": "crypto/ed25519",
    "dsa": "crypto/dsa",
    "ecdh": "crypto/ecdh",
    "md5": "crypto/md5",
    "sha1": "crypto/sha1",
    "des": "crypto/des",
    "rc4": "crypto/rc4",
    "mlkem": "crypto/mlkem",
}

# A site whose API constructs a key or a hash/cipher object, as opposed to one
# that performs an operation with an already-constructed key. The split is the
# whole story of the number, so it is named here rather than left to the reader.
def is_constructor(label: str) -> bool:
    return (
        label.endswith("GenerateKey")
        or label.endswith(".New")
        or label.endswith("NewCipher")
        or label.endswith("NewTripleDESCipher")
        or label.startswith("ecdh.")
    )


def load_manifest() -> list[dict]:
    with open(SCRIPT_DIR / "manifest.toml", "rb") as f:
        return toml_lib.load(f)["projects"]


def load_project(rel: str) -> dict:
    with open(SCRIPT_DIR / rel, "rb") as f:
        return toml_lib.load(f)


def go_scan_paths() -> dict[str, list[str]]:
    """Per Go project, the subtrees the harness hands to the scanner."""
    out: dict[str, list[str]] = {}
    for entry in load_manifest():
        project = load_project(entry["file_path"])
        p = project["project"]
        if p["ecosystem"] != "go-modules":
            continue
        out[p["name"]] = project.get("scan_hints", {}).get("scan_paths") or [""]
    return out


def ground_truth(clones: Path) -> list[tuple[str, str, int, str]]:
    root = clones / "go-modules"
    sites: list[tuple[str, str, int, str]] = []
    for proj in sorted(os.listdir(root)):
        pdir = root / proj
        if not pdir.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(pdir):
            dirnames[:] = [d for d in dirnames if d != ".git"]
            for fn in filenames:
                if not fn.endswith(".go"):
                    continue
                fp = Path(dirpath) / fn
                try:
                    text = fp.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if "crypto/" not in text:
                    continue
                imports = {m for pkg, m in IMPORT_PKG.items() if m in text}
                for i, line in enumerate(text.split("\n"), 1):
                    stripped = line.split("//")[0]
                    for rx, label in COMPILED:
                        if rx.search(stripped):
                            if IMPORT_PKG[label.split(".")[0]] not in imports:
                                continue
                            sites.append(
                                (proj, str(fp.relative_to(pdir)), i, label)
                            )
                            break
    return sites


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--clones", default=DEFAULT_CLONES, type=Path)
    ap.add_argument("--dump", default=DEFAULT_DUMP, type=Path,
                    help="a dump_findings.py artifact")
    args = ap.parse_args()

    if not (args.clones / "go-modules").is_dir():
        print(f"missing go-modules under clone root: {args.clones}", file=sys.stderr)
        return 1
    if not args.dump.exists():
        print(f"missing dump: {args.dump} (run dump_findings.py first)", file=sys.stderr)
        return 1

    gt = ground_truth(args.clones)
    scoped = go_scan_paths()

    # `dump_findings.py` writes `file` as `<ecosystem>/<name>/<path>`.
    found = set()
    for f in json.load(open(args.dump)):
        if f["ecosystem"] != "go-modules":
            continue
        parts = f["file"].split("/", 2)
        if len(parts) == 3 and parts[0] == "go-modules":
            found.add((parts[1], parts[2], f["line"]))

    def in_scope(proj: str, rel: str) -> bool:
        for sp in scoped.get(proj, []):
            if sp == "" or rel == sp or rel.startswith(sp.rstrip("/") + "/"):
                return True
        return False

    ins = [k for k in gt if in_scope(k[0], k[1])]
    hit_all = [k for k in gt if (k[0], k[1], k[2]) in found]
    hit = [k for k in ins if (k[0], k[1], k[2]) in found]
    miss = [k for k in ins if (k[0], k[1], k[2]) not in found]

    print(f"ground truth, whole Go clone tree : {len(gt)}")
    print(f"  inside a scanned subtree        : {len(ins)}")
    print(f"  outside every scanned subtree   : {len(gt) - len(ins)}"
          f"  ({(len(gt) - len(ins)) / len(gt) * 100:.1f}% never looked at)")
    print()
    print(f"IN-SCOPE recall (the scanner)     : "
          f"{len(hit)}/{len(ins)} = {len(hit) / len(ins) * 100:.1f}%")
    print(f"WHOLE-TREE recall (the harness)   : "
          f"{len(hit_all)}/{len(gt)} = {len(hit_all) / len(gt) * 100:.1f}%")

    print("\n=== in-scope recall by API kind ===")
    for name, pred in (("constructors", is_constructor),
                       ("operations", lambda lab: not is_constructor(lab))):
        sub = [k for k in ins if pred(k[3])]
        sub_hit = [k for k in sub if (k[0], k[1], k[2]) in found]
        print(f"  {name:14s} sites={len(sub):4d}  found={len(sub_hit):4d}  "
              f"recall={len(sub_hit) / len(sub) * 100:5.1f}%")

    print("\n=== in-scope recall by API (worst first) ===")
    tot = collections.Counter(k[3] for k in ins)
    mis = collections.Counter(k[3] for k in miss)
    print(f"{'api':28s} {'sites':>6s} {'missed':>7s} {'recall':>8s}")
    for api, n in sorted(tot.items(), key=lambda kv: -mis[kv[0]]):
        print(f"{api:28s} {n:6d} {mis[api]:7d} {(n - mis[api]) / n * 100:7.1f}%")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

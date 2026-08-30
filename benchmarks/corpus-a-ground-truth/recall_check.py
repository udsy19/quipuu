#!/usr/bin/env python3
"""recall_check.py — measure family-level recall over the planted probe corpus.

corpus-b-realworld/recall_check.py answers "what fraction of Go stdlib crypto
calls in real projects did we find" — a derived-from-reality ground truth, but
one language and one direction (recall of a scanner that already runs there).
This corpus answers a different question: across the **seven** languages the
scanner claims to support, does an idiomatic, one-call-per-line invocation of
each of ~17 algorithm families get *any* correctly-attributed finding, on a
corpus we hand-wrote and fully control?

GROUND TRUTH IS THE `expected.toml` NEXT TO EACH PROBE FILE, not this script
and not `data/rules/`. Each `[[site]]` names a line and the coarse family
(`family = "rsa"`) a correct finding at that line must resolve to. Regenerating
`expected.toml` from the source files' own `EXPECT <family>` comments is a
sanity check, not this script's job — the checked-in file is authoritative so
a future edit to a probe file cannot silently move the ground truth with it.

SCORING IS FAMILY-LEVEL, NOT ALGORITHM-ID-LEVEL. A python `rsa-2048` finding
and a Java `rsa-unattributed` finding both count as a hit for `family = "rsa"`.
This is deliberately coarser than the precision audit (which requires the
exact cited operation) because this corpus is measuring *whether the call is
seen and attributed to the right primitive at all*, across languages whose
extract queries and callee tables are entirely independent code paths. See
FAMILY_ALIASES below for the exact id-family -> EXPECT-tag mapping, and read
it before trusting a number: `hmac`, `scrypt`, `bcrypt`, and `argon2` map to
nothing, on purpose — `algorithm-table.toml` carries no MAC or password-KDF
family at all, so those four EXPECT tags (27 of 117 sites) can never score a
hit no matter what the scanner does. That is not a scoring bug; it is the
recall gap this corpus exists to make visible instead of erasing it from the
denominator.

NOT A CI GATE. `03-Product/Backlog.md #T11(a)` and three independent
self-doubt-lens passes over 2026-08-27 all reached the same conclusion: a
recall floor blocks every honest change that narrows a rule to kill a false
positive, because narrowing a rule can cost a true positive at the same call
site. This script measures and prints; nothing reads its exit code as a gate.

    python3 recall_check.py [--bin PATH]
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

try:
    import tomllib as toml_lib
except ImportError:
    import tomli as toml_lib

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent
DEFAULT_BINARY = REPO_ROOT / "quipuu/target/release/quipuu"
ALGORITHM_TABLE = REPO_ROOT / "quipuu/crates/core/data/algorithm-table.toml"

LANG_DIRS = ["cpp", "csharp", "go", "java", "js", "python", "rust"]

ROW_RE = re.compile(r"^\s+(\S+)\t(\S+)\t(\S+)\t(.+):(\d+)\t(.+)$")

# EXPECT tag -> the algorithm-table `family` values that count as a correct
# attribution. Several tags (hmac/scrypt/bcrypt/argon2) map to no family
# because none exists yet — left explicit rather than omitted, so the miss is
# visible in the per-family table instead of silently shrinking the corpus.
FAMILY_ALIASES: dict[str, set[str]] = {
    "rsa": {"RSA"},
    "ecdsa": {"ECDSA"},
    "ecdh": {"ECDH", "X25519", "X448"},
    "dsa": {"DSA"},
    "dh": {"DH"},
    "md5": {"MD5"},
    "sha1": {"SHA-1"},
    "sha256": {"SHA-2"},
    "sha384": {"SHA-2"},
    "hmac": set(),  # no MAC family in algorithm-table.toml
    "pbkdf2": {"PBKDF2"},
    "scrypt": set(),  # no password-KDF family in algorithm-table.toml
    "bcrypt": set(),  # ditto
    "argon2": set(),  # ditto
    "aes": {"AES"},
    "aes128": {"AES"},
    "aes256": {"AES"},
    "aesgcm": {"AES"},
    "3des": {"3DES"},
    "des": {"DES", "3DES"},
    "rc4": {"RC4"},
    "chacha20": {"ChaCha20"},
    "mlkem": {"ML-KEM"},
    "mldsa": {"ML-DSA"},
    "slhdsa": {"SLH-DSA"},
}


def load_algorithm_families() -> dict[str, str]:
    with open(ALGORITHM_TABLE, "rb") as f:
        table = toml_lib.load(f)
    return {row["id"]: row["family"] for row in table["algorithm"]}


def load_expected() -> list[tuple[str, str, int, str]]:
    """[(lang, rel_file, line, family), ...]"""
    sites = []
    for lang in LANG_DIRS:
        lang_dir = SCRIPT_DIR / lang
        src = next(p for p in lang_dir.iterdir() if p.name != "expected.toml")
        with open(lang_dir / "expected.toml", "rb") as f:
            data = toml_lib.load(f)
        for site in data["site"]:
            sites.append((lang, src.name, site["line"], site["family"]))
    return sites


def scan(binary: Path) -> list[tuple[str, int, str]]:
    """[(abs_file, line, algorithm_id), ...] from a live `quipuu scan`."""
    proc = subprocess.run(
        [str(binary), "scan", str(SCRIPT_DIR), "--include-safe"],
        capture_output=True, text=True, timeout=120,
    )
    findings = []
    for line in proc.stdout.split("\n"):
        m = ROW_RE.match(line)
        if not m:
            continue
        _severity, _rule, algorithm_id, file_path, file_line, _msg = m.groups()
        findings.append((file_path, int(file_line), algorithm_id))
    return findings


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bin", default=DEFAULT_BINARY, type=Path)
    args = ap.parse_args()

    if not args.bin.exists():
        print(f"missing binary: {args.bin} (cargo build --release first)", file=sys.stderr)
        return 1

    families = load_algorithm_families()
    expected = load_expected()
    found = scan(args.bin)

    # Index findings by (relative "lang/file", line) -> set of families they assert.
    by_site: dict[tuple[str, int], set[str]] = {}
    for file_path, line, algorithm_id in found:
        fam = families.get(algorithm_id)
        try:
            rel = str(Path(file_path).resolve().relative_to(SCRIPT_DIR))
        except ValueError:
            continue
        by_site.setdefault((rel, line), set()).add(fam)

    hits = []
    misses = []
    for lang, fname, line, tag in expected:
        want = FAMILY_ALIASES.get(tag, set())
        got = by_site.get((f"{lang}/{fname}", line), set())
        if want and (want & got):
            hits.append((lang, fname, line, tag))
        else:
            misses.append((lang, fname, line, tag, sorted(got)))

    total = len(expected)
    print(f"planted sites          : {total}")
    print(f"RECALL (family-level)  : {len(hits)}/{total} = {len(hits) / total * 100:.1f}%")

    print("\n=== by language ===")
    for lang in LANG_DIRS:
        sub_total = [s for s in expected if s[0] == lang]
        sub_hit = [h for h in hits if h[0] == lang]
        n = len(sub_total)
        print(f"  {lang:8s} {len(sub_hit):3d}/{n:3d} = {len(sub_hit) / n * 100:5.1f}%")

    print("\n=== by EXPECT tag (worst first) ===")
    tags = sorted({t for *_r, t in expected})
    for tag in sorted(tags, key=lambda t: sum(1 for m in misses if m[3] == t), reverse=True):
        n = sum(1 for s in expected if s[3] == tag)
        h = sum(1 for h in hits if h[3] == tag)
        no_family = " (no algorithm-table family exists)" if not FAMILY_ALIASES.get(tag) else ""
        print(f"  {tag:10s} {h:2d}/{n:2d}{no_family}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

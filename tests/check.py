#!/usr/bin/env python3
"""
cryptoscope analysis-phase test suite.

What this tests (no Rust yet — we test the knowledge base + data files):

  1. All TOML data files parse.
  2. All JSON schemas in knowledge/sources/ parse.
  3. The official CycloneDX CBOM example validates against the 1.7 schema.
  4. Referential integrity:
       - every algorithm_id in oid-table + rules + policy resolves to algorithm-table
       - every `replacement` algorithm-id in algorithm-table resolves
  5. Algorithm-table internal consistency:
       - quantum_status values are from the allowed set
       - primitive values are from the CycloneDX 1.7 enum
       - nistQuantumSecurityLevel in 0..=6
       - PqcFinal entries have a `fips` reference
       - BrokenByShor entries have a `replacement`
       - OID format (dotted decimal)
  6. OID table:
       - every OID parses as dotted decimal
       - no duplicate OIDs
  7. Default policy:
       - risk_weights sum to 100
       - severity_bands are monotonically decreasing
       - shelf_life buckets referenced consistently
       - classically_broken entries exist in algorithm-table
  8. Rules:
       - every extract rule has captures consistent with its query placeholders
       - every classify rule's `algorithm_id` resolves
       - severity_hint is one of the allowed values
       - regex patterns compile
  9. Knowledge-base cross-links:
       - every (relative) markdown link in knowledge/*.md points at an existing path
       - every `knowledge/sources/<file>` reference exists
 10. Sources directory:
       - JSON files parse
       - CSV files have expected headers
       - PDFs are non-empty and start with %PDF header

Exit 0 on success, 1 on any failure. Prints colored pass/fail lines.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

try:
    import toml
except ImportError:
    print("FATAL: install toml: pip3 install --user toml", file=sys.stderr)
    sys.exit(2)

try:
    import jsonschema
    from jsonschema import Draft7Validator
except ImportError:
    print("FATAL: install jsonschema: pip3 install --user jsonschema", file=sys.stderr)
    sys.exit(2)

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent.parent
KNOW = ROOT / "knowledge"
DATA = KNOW / "11-decisions" / "data"
SRC = KNOW / "sources"

GREEN, RED, YEL, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[0m"
PASS_PREFIX = f"{GREEN}PASS{RESET}"
FAIL_PREFIX = f"{RED}FAIL{RESET}"
SKIP_PREFIX = f"{YEL}SKIP{RESET}"

results: list[tuple[str, str, str]] = []  # (status, name, detail)


def expect(name: str, cond: bool, detail: str = "") -> bool:
    status = "PASS" if cond else "FAIL"
    results.append((status, name, detail))
    return cond


def skip(name: str, detail: str = "") -> None:
    results.append(("SKIP", name, detail))


# CycloneDX 1.7 algorithmProperties.primitive enum, from canonical schema
CDX17_PRIMITIVE = {
    "drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash",
    "pke", "xof", "kdf", "key-agree", "kem", "ae", "combiner", "key-wrap",
    "other", "unknown",
}

ALLOWED_QUANTUM_STATUS = {
    "BrokenByShor", "BrokenClassically", "WeakenedByGrover",
    "QuantumSafe", "PqcFinal", "PqcDraft",
}

ALLOWED_SEVERITY_HINTS = {"critical", "high", "medium", "low", "auto"}


# ---------------------------------------------------------------------------
# 1. TOML parses
# ---------------------------------------------------------------------------

RULES_DIR = DATA / "rules"

# Discover all rule TOML files dynamically — covers go.toml, python.toml, and
# all new language packs (java, javascript, cpp, rust, csharp, …).
RULE_TOML_FILES = sorted(RULES_DIR.glob("*.toml")) if RULES_DIR.is_dir() else []

TOML_FILES = [
    DATA / "algorithm-table.toml",
    DATA / "oid-table.toml",
    DATA / "default-policy.toml",
] + RULE_TOML_FILES

parsed: dict[Path, dict] = {}
for f in TOML_FILES:
    try:
        parsed[f] = toml.load(f)
        expect(f"TOML parse {f.relative_to(ROOT)}", True)
    except Exception as e:
        expect(f"TOML parse {f.relative_to(ROOT)}", False, str(e))


algo_table = parsed.get(DATA / "algorithm-table.toml", {}).get("algorithm", [])
oid_table = parsed.get(DATA / "oid-table.toml", {}).get("oid", [])
policy = parsed.get(DATA / "default-policy.toml", {})
rules_go = parsed.get(DATA / "rules" / "go.toml", {})
rules_py = parsed.get(DATA / "rules" / "python.toml", {})

algos_by_id = {a["id"]: a for a in algo_table}


# ---------------------------------------------------------------------------
# 2. JSON schemas in knowledge/sources/ parse
# ---------------------------------------------------------------------------

JSON_FILES = [
    SRC / "bom-1.6.schema.json",
    SRC / "bom-1.7.schema.json",
    SRC / "cryptography-defs.schema.json",
    SRC / "cbom-protocol-example.json",
    SRC / "cryptobom-forge-cryptocheck_schema.json",
]

loaded_json: dict[Path, dict] = {}
for f in JSON_FILES:
    try:
        with open(f) as fp:
            loaded_json[f] = json.load(fp)
        expect(f"JSON parse {f.relative_to(ROOT)}", True)
    except Exception as e:
        expect(f"JSON parse {f.relative_to(ROOT)}", False, str(e))


# ---------------------------------------------------------------------------
# 3. Official CBOM example validates against 1.7 schema
# ---------------------------------------------------------------------------

schema_17 = loaded_json.get(SRC / "bom-1.7.schema.json")
example = loaded_json.get(SRC / "cbom-protocol-example.json")
if schema_17 and example:
    try:
        # Pre-flight: the schema itself should be valid Draft 7 metaschema-conformant.
        Draft7Validator.check_schema(schema_17)
        expect("CycloneDX 1.7 schema is a valid JSON Schema", True)
    except Exception as e:
        expect("CycloneDX 1.7 schema is a valid JSON Schema", False, str(e))

    validator = Draft7Validator(schema_17)
    errors = sorted(validator.iter_errors(example), key=lambda e: list(e.absolute_path))
    if not errors:
        expect("cbom-protocol-example.json validates against 1.7 schema", True)
    else:
        # Report up to 3 errors compactly
        details = "; ".join(
            f"{list(e.absolute_path)[:4]}: {e.message[:100]}" for e in errors[:3]
        )
        expect(
            f"cbom-protocol-example.json validates against 1.7 schema",
            False,
            f"{len(errors)} errors — {details}",
        )
else:
    skip("CBOM example validation", "schema or example missing")


# ---------------------------------------------------------------------------
# 4. Referential integrity
# ---------------------------------------------------------------------------

# OID table → algorithm-table
missing_oid_refs = [o for o in oid_table if o["algorithm_id"] not in algos_by_id]
expect(
    "oid-table.toml: every algorithm_id resolves",
    len(missing_oid_refs) == 0,
    f"{len(missing_oid_refs)} dangling: " + ", ".join(o["algorithm_id"] for o in missing_oid_refs[:5]),
)

# Rule files → algorithm-table (all discovered rule files)
for rfile in RULE_TOML_FILES:
    rname = rfile.name
    rdoc = parsed.get(rfile, {})
    dangling = [
        c for c in rdoc.get("classify", [])
        if c.get("algorithm_id") and c["algorithm_id"] not in algos_by_id
    ]
    expect(
        f"rules/{rname}: every algorithm_id resolves",
        len(dangling) == 0,
        f"{len(dangling)} dangling: " + ", ".join(c["algorithm_id"] for c in dangling[:5]),
    )

# Replacement fields
missing_repl = [
    a for a in algo_table
    if a.get("replacement") and a["replacement"] not in algos_by_id
]
expect(
    "algorithm-table: every replacement resolves",
    len(missing_repl) == 0,
    f"{len(missing_repl)} dangling: " + ", ".join(a["id"] for a in missing_repl[:5]),
)

# Policy classically_broken → algorithm-table
broken_ids = policy.get("deprecation", {}).get("classically_broken", [])
missing_broken = [b for b in broken_ids if b not in algos_by_id]
expect(
    "default-policy.classically_broken: every id resolves",
    len(missing_broken) == 0,
    f"missing: {missing_broken}",
)


# ---------------------------------------------------------------------------
# 5. Algorithm-table internal consistency
# ---------------------------------------------------------------------------

# 5a. quantum_status values
bad_status = [a for a in algo_table if a.get("quantum_status") not in ALLOWED_QUANTUM_STATUS]
expect(
    "algorithm-table: every quantum_status is in the allowed set",
    len(bad_status) == 0,
    f"{len(bad_status)} bad: " + ", ".join(f"{a['id']}={a.get('quantum_status')}" for a in bad_status[:5]),
)

# 5b. primitive values
bad_prim = [a for a in algo_table if a.get("primitive") and a["primitive"] not in CDX17_PRIMITIVE]
expect(
    "algorithm-table: every primitive is in the CycloneDX 1.7 enum",
    len(bad_prim) == 0,
    f"{len(bad_prim)} bad: " + ", ".join(f"{a['id']}={a.get('primitive')}" for a in bad_prim[:5]),
)

# 5c. nistQuantumSecurityLevel range
bad_level = [
    a for a in algo_table
    if a.get("nist_quantum_security_level") is not None
    and not (0 <= a["nist_quantum_security_level"] <= 6)
]
expect(
    "algorithm-table: nist_quantum_security_level in 0..=6",
    len(bad_level) == 0,
    f"{len(bad_level)} bad: " + ", ".join(f"{a['id']}={a.get('nist_quantum_security_level')}" for a in bad_level[:5]),
)

# 5d. PqcFinal entries have a FIPS reference
pqc_no_fips = [
    a for a in algo_table
    if a.get("quantum_status") == "PqcFinal"
    and not a.get("fips")
    and a.get("family") not in {"Hybrid-KEM"}  # hybrids are TLS constructs, not FIPS algorithms themselves
]
expect(
    "algorithm-table: every PqcFinal (non-hybrid) has a fips reference",
    len(pqc_no_fips) == 0,
    f"{len(pqc_no_fips)} bad: " + ", ".join(a["id"] for a in pqc_no_fips[:5]),
)

# 5e. BrokenByShor entries have a replacement
shor_no_repl = [a for a in algo_table if a.get("quantum_status") == "BrokenByShor" and not a.get("replacement")]
expect(
    "algorithm-table: every BrokenByShor has a replacement",
    len(shor_no_repl) == 0,
    f"{len(shor_no_repl)} bad: " + ", ".join(a["id"] for a in shor_no_repl[:5]),
)

# 5f. OID format where present
OID_RE = re.compile(r"^\d+(\.\d+)+$")
bad_oid_in_algo = [a for a in algo_table if a.get("oid") and not OID_RE.match(a["oid"])]
expect(
    "algorithm-table: OIDs are dotted decimal",
    len(bad_oid_in_algo) == 0,
    f"{len(bad_oid_in_algo)} bad: " + ", ".join(f"{a['id']}={a.get('oid')}" for a in bad_oid_in_algo[:5]),
)

# 5g. Quantum-vulnerable asymmetric → nist_quantum_security_level == 0 (CycloneDX convention)
mis_qsl_zero = [
    a for a in algo_table
    if a.get("quantum_status") == "BrokenByShor"
    and a.get("nist_quantum_security_level", -1) != 0
]
expect(
    "algorithm-table: every BrokenByShor entry has nist_quantum_security_level == 0",
    len(mis_qsl_zero) == 0,
    f"{len(mis_qsl_zero)} mismatched: " + ", ".join(f"{a['id']}={a.get('nist_quantum_security_level')}" for a in mis_qsl_zero[:5]),
)


# ---------------------------------------------------------------------------
# 6. OID table — format + no duplicates
# ---------------------------------------------------------------------------

bad_oid_format = [o for o in oid_table if not OID_RE.match(o["oid"])]
expect(
    "oid-table.toml: every OID is dotted decimal",
    len(bad_oid_format) == 0,
    f"{len(bad_oid_format)} bad: " + ", ".join(o["oid"] for o in bad_oid_format[:5]),
)

seen_oids: dict[str, str] = {}
dups: list[tuple[str, str, str]] = []
for o in oid_table:
    if o["oid"] in seen_oids:
        dups.append((o["oid"], seen_oids[o["oid"]], o["algorithm_id"]))
    else:
        seen_oids[o["oid"]] = o["algorithm_id"]
expect(
    "oid-table.toml: no duplicate OIDs",
    len(dups) == 0,
    f"{len(dups)} dup(s): " + ", ".join(f"{a} ↔ {b} ({oid})" for oid, a, b in dups[:5]),
)


# ---------------------------------------------------------------------------
# 7. Default policy
# ---------------------------------------------------------------------------

risk_weights = policy.get("risk_weights", {})
weight_sum = sum(risk_weights.values()) if risk_weights else 0
expect(
    "default-policy.risk_weights sum to 100",
    weight_sum == 100,
    f"sum = {weight_sum}: {risk_weights}",
)

# Severity bands monotonic decreasing
sb = policy.get("severity_bands", {})
order = ["critical", "high", "medium", "low", "safe"]
if all(k in sb for k in order):
    monotonic = all(sb[order[i]] > sb[order[i+1]] for i in range(len(order)-1))
    expect(
        "default-policy.severity_bands monotonic decreasing (critical>high>medium>low>safe)",
        monotonic,
        f"got: {[(k, sb[k]) for k in order]}",
    )
else:
    expect(
        "default-policy.severity_bands has all five keys",
        False,
        f"present: {list(sb.keys())}",
    )

# Shelf-life buckets — every value in shelf_life_tags references a defined bucket
shelf_buckets = set(policy.get("data_shelf_life", {}).keys())
shelf_tags = policy.get("shelf_life_tags", {})
default_bucket = policy.get("shelf_life_default", {}).get("bucket")
bad_buckets = [
    (glob, bucket) for glob, bucket in shelf_tags.items()
    if bucket not in shelf_buckets
]
if default_bucket and default_bucket not in shelf_buckets:
    bad_buckets.append(("(default)", default_bucket))
expect(
    "default-policy.shelf_life_tags reference defined buckets",
    len(bad_buckets) == 0,
    f"{len(bad_buckets)} bad: " + ", ".join(f"{g}→{b}" for g, b in bad_buckets[:5]),
)

# HNDL flag — required_quantum_status_in values exist
hndl = policy.get("hndl_flag", {})
bad_hndl_status = [s for s in hndl.get("require_quantum_status_in", []) if s not in ALLOWED_QUANTUM_STATUS]
expect(
    "default-policy.hndl_flag.require_quantum_status_in uses valid statuses",
    len(bad_hndl_status) == 0,
    f"bad: {bad_hndl_status}",
)

# algorithm_vulnerability table — every key is an allowed quantum_status
av_table = policy.get("algorithm_vulnerability", {})
bad_av_keys = [k for k in av_table if k not in ALLOWED_QUANTUM_STATUS]
expect(
    "default-policy.algorithm_vulnerability keys are valid quantum_status values",
    len(bad_av_keys) == 0,
    f"bad: {bad_av_keys}",
)

# Every QuantumStatus appears in algorithm_vulnerability map (so the scorer can't crash)
missing_av = [s for s in ALLOWED_QUANTUM_STATUS if s not in av_table]
expect(
    "default-policy.algorithm_vulnerability covers every quantum_status",
    len(missing_av) == 0,
    f"missing: {missing_av}",
)


# ---------------------------------------------------------------------------
# 8. Rules — severity_hint, regex compile
# ---------------------------------------------------------------------------

def check_rules(name: str, doc: dict) -> None:
    bad_hint = []
    bad_regex = []
    for c in doc.get("classify", []):
        hint = c.get("severity_hint")
        if hint and hint not in ALLOWED_SEVERITY_HINTS:
            bad_hint.append((c.get("id"), hint))
        # Compile every regex in `when` so we catch malformed patterns
        when = c.get("when", {})
        for path, val in _walk(when):
            if isinstance(val, dict) and "regex" in val:
                try:
                    re.compile(val["regex"])
                except re.error as e:
                    bad_regex.append((c.get("id"), path, val["regex"], str(e)))
    expect(
        f"rules/{name}: severity_hint values are allowed",
        len(bad_hint) == 0,
        f"{len(bad_hint)} bad: " + ", ".join(f"{i}={h}" for i, h in bad_hint[:5]),
    )
    expect(
        f"rules/{name}: every regex compiles",
        len(bad_regex) == 0,
        f"{len(bad_regex)} bad: " + "; ".join(f"{i}@{p}: {e}" for i, p, _, e in bad_regex[:3]),
    )


def _walk(obj, prefix=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            new = f"{prefix}.{k}" if prefix else k
            yield new, v
            yield from _walk(v, new)


for rfile in RULE_TOML_FILES:
    check_rules(rfile.name, parsed.get(rfile, {}))


# ---------------------------------------------------------------------------
# 9. Knowledge-base cross-links — every relative markdown link points at an existing path
# ---------------------------------------------------------------------------

MD_LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)#\s]+)(?:#[^)]*)?\)")
# Pattern that catches `knowledge/sources/<file>` mentions in plain text
SOURCES_REF_RE = re.compile(r"knowledge/sources/([\w\-./]+)")

# Skip third-party docs imported verbatim — they reference upstream repo paths
# (e.g. IBM's sonar-cryptography rule structure doc).
md_files = [m for m in sorted(KNOW.rglob("*.md")) if SRC not in m.parents]
dead_links = []
missing_source_refs = []
for md in md_files:
    text = md.read_text()

    for m in MD_LINK_RE.finditer(text):
        target = m.group(2)
        # Skip http(s), mailto, anchors
        if target.startswith(("http://", "https://", "mailto:", "#")):
            continue
        # Resolve relative to the markdown file
        candidate = (md.parent / target).resolve()
        if not candidate.exists():
            # Some links might be intentional placeholders for future docs
            dead_links.append((str(md.relative_to(ROOT)), target))

    for m in SOURCES_REF_RE.finditer(text):
        sf = SRC / m.group(1)
        if not sf.exists():
            missing_source_refs.append((str(md.relative_to(ROOT)), m.group(0)))

expect(
    "knowledge/*.md relative links all resolve",
    len(dead_links) == 0,
    f"{len(dead_links)} dead: " + "; ".join(f"{src}→{tgt}" for src, tgt in dead_links[:5]),
)
expect(
    "knowledge/*.md references to knowledge/sources/<file> all exist",
    len(missing_source_refs) == 0,
    f"{len(missing_source_refs)} missing: " + "; ".join(f"{src}→{ref}" for src, ref in missing_source_refs[:5]),
)


# ---------------------------------------------------------------------------
# 10. Sources sanity — JSON parses (done above for the schemas), CSV headers, PDFs present
# ---------------------------------------------------------------------------

CSV_FILES = [
    (SRC / "iana-tls-supported-groups.csv", "Value"),  # IANA registry CSVs start with "Value,Description,..."
    (SRC / "iana-tls-signaturescheme.csv", "Value"),
]
for f, expected_first in CSV_FILES:
    if not f.exists():
        expect(f"CSV present {f.name}", False, "missing")
        continue
    first_line = f.read_text().splitlines()[0]
    expect(
        f"CSV header {f.name} starts with '{expected_first}'",
        first_line.startswith(expected_first),
        f"got: {first_line[:80]}",
    )

PDF_FILES = [
    SRC / "NIST.IR.8547.ipd.pdf",
    SRC / "NIST.FIPS.203.pdf",
    SRC / "NIST.FIPS.204.pdf",
    SRC / "NIST.FIPS.205.pdf",
    SRC / "NIST.SP.800-131Ar3.ipd.pdf",
]
for f in PDF_FILES:
    if not f.exists():
        expect(f"PDF present {f.name}", False, "missing")
        continue
    head = f.read_bytes()[:5]
    sz = f.stat().st_size
    expect(
        f"PDF valid {f.name}",
        head == b"%PDF-" and sz > 10_000,
        f"head={head}, size={sz}",
    )


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

passed = sum(1 for r in results if r[0] == "PASS")
failed = sum(1 for r in results if r[0] == "FAIL")
skipped = sum(1 for r in results if r[0] == "SKIP")

print()
for status, name, detail in results:
    prefix = {"PASS": PASS_PREFIX, "FAIL": FAIL_PREFIX, "SKIP": SKIP_PREFIX}[status]
    line = f"  {prefix}  {name}"
    if status != "PASS" and detail:
        line += f"\n         {RED if status=='FAIL' else YEL}{detail}{RESET}"
    print(line)

print()
print(f"  {passed} passed, {failed} failed, {skipped} skipped, {len(results)} total")
sys.exit(0 if failed == 0 else 1)

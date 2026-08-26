#!/usr/bin/env bash
# verify.sh — Verify that each cloned repository matches its pinned commit SHA
#
# Usage:
#   ./verify.sh [--clones <directory>] [--ecosystem <name>] [--report <file>]
#
# Options:
#   --clones <dir>       Directory where clones live (default: ./clones)
#   --ecosystem <name>   Verify only one ecosystem
#   --report <file>      Write JSON summary to this file (default: ./verify-report.json)
#
# Exit codes:
#   0  All verified
#   1  One or more mismatches or missing clones
#
# Requirements: git, python3 (3.11+ for tomllib), jq (optional, for pretty report)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLONES_DIR="./clones"
FILTER_ECO=""
REPORT_FILE="./verify-report.json"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --clones)
      CLONES_DIR="$2"; shift 2 ;;
    --ecosystem)
      FILTER_ECO="$2"; shift 2 ;;
    --report)
      REPORT_FILE="$2"; shift 2 ;;
    *)
      echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

CLONES_DIR="$(realpath -m "$CLONES_DIR")"

parse_toml_field() {
  local file="$1"
  local field="$2"
  python3 - <<EOF
import tomllib, sys
with open('$file', 'rb') as f:
    d = tomllib.load(f)
parts = '$field'.split('.')
val = d
for p in parts:
    val = val[p]
print(val)
EOF
}

OK=0
MISSING=0
MISMATCH=0
RESULTS="[]"

TOML_GLOB="$SCRIPT_DIR/ecosystems/*/*.toml"

for toml in $TOML_GLOB; do
  eco=$(basename "$(dirname "$toml")")

  if [[ -n "$FILTER_ECO" && "$eco" != "$FILTER_ECO" ]]; then
    continue
  fi

  name=$(parse_toml_field "$toml" "project.name")
  expected_sha=$(parse_toml_field "$toml" "repo.commit_sha")
  clone_path="$CLONES_DIR/$eco/$name"

  # Resolve symlinks
  real_path=$(realpath -m "$clone_path" 2>/dev/null || echo "$clone_path")

  if [[ ! -d "$real_path/.git" ]]; then
    echo "MISSING  $eco/$name  (expected at $clone_path)"
    MISSING=$((MISSING + 1))
    RESULTS=$(python3 -c "
import json, sys
r = json.loads('''$RESULTS''')
r.append({'project': '$eco/$name', 'status': 'missing', 'expected': '$expected_sha', 'actual': None})
print(json.dumps(r))
")
    continue
  fi

  actual_sha=$(git -C "$real_path" rev-parse HEAD 2>/dev/null || echo "unknown")

  if [[ "$actual_sha" == "$expected_sha"* || "$expected_sha" == "$actual_sha"* ]]; then
    echo "OK       $eco/$name  ($actual_sha)"
    OK=$((OK + 1))
    RESULTS=$(python3 -c "
import json
r = json.loads('''$RESULTS''')
r.append({'project': '$eco/$name', 'status': 'ok', 'expected': '$expected_sha', 'actual': '$actual_sha'})
print(json.dumps(r))
")
  else
    echo "MISMATCH $eco/$name  expected=${expected_sha:0:12} actual=${actual_sha:0:12}"
    MISMATCH=$((MISMATCH + 1))
    RESULTS=$(python3 -c "
import json
r = json.loads('''$RESULTS''')
r.append({'project': '$eco/$name', 'status': 'mismatch', 'expected': '$expected_sha', 'actual': '$actual_sha'})
print(json.dumps(r))
")
  fi
done

# Write JSON report
python3 - <<EOF
import json
results = $RESULTS
report = {
    'corpus': 'corpus-b-realworld',
    'clones_dir': '$CLONES_DIR',
    'summary': {
        'total': $OK + $MISSING + $MISMATCH,
        'ok': $OK,
        'missing': $MISSING,
        'mismatch': $MISMATCH
    },
    'results': results
}
with open('$REPORT_FILE', 'w') as f:
    json.dump(report, f, indent=2)
print("Report written to $REPORT_FILE")
EOF

echo ""
echo "============================================"
echo "Verify results:"
echo "  OK:       $OK"
echo "  Missing:  $MISSING"
echo "  Mismatch: $MISMATCH"
echo "============================================"

if [[ $MISSING -gt 0 || $MISMATCH -gt 0 ]]; then
  exit 1
fi
exit 0

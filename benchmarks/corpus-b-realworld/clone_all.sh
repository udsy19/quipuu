#!/usr/bin/env bash
# clone_all.sh — Clone all 125 Corpus B projects at pinned commit SHAs
#
# Usage:
#   ./clone_all.sh [--dest <directory>] [--ecosystem <name>] [--dry-run]
#
# Options:
#   --dest <dir>         Target directory for clones (default: ./clones)
#   --ecosystem <name>   Clone only one ecosystem (pypi, npm, maven, crates-io,
#                        go-modules, crypto-adjacent)
#   --dry-run            Print commands without executing
#
# Requirements: git, python3 (3.11+ for tomllib)
#
# Each project is cloned into: <dest>/<ecosystem>/<project-name>/
# After cloning, the repo is checked out to the pinned commit_sha.
#
# Repos that share a monorepo (e.g. sha2/sha-1/md-5 → RustCrypto/hashes)
# are cloned once and symlinked for subsequent entries pointing to the same URL.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST_DIR="./clones"
FILTER_ECO=""
DRY_RUN=false

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dest)
      DEST_DIR="$2"; shift 2 ;;
    --ecosystem)
      FILTER_ECO="$2"; shift 2 ;;
    --dry-run)
      DRY_RUN=true; shift ;;
    *)
      echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

DEST_DIR="$(realpath -m "$DEST_DIR")"
echo "Cloning to: $DEST_DIR"
echo "Ecosystem filter: ${FILTER_ECO:-all}"
echo "Dry run: $DRY_RUN"
echo ""

# Use Python tomllib to parse each project toml
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

# Track already-cloned repos to avoid re-cloning monorepos
declare -A CLONED_URLS  # url -> clone_path

TOML_GLOB="$SCRIPT_DIR/ecosystems/*/*.toml"
CLONED=0
SKIPPED=0
ERRORS=0

for toml in $TOML_GLOB; do
  eco=$(basename "$(dirname "$toml")")

  # Apply ecosystem filter
  if [[ -n "$FILTER_ECO" && "$eco" != "$FILTER_ECO" ]]; then
    continue
  fi

  name=$(parse_toml_field "$toml" "project.name")
  url=$(parse_toml_field "$toml" "repo.url")
  sha=$(parse_toml_field "$toml" "repo.commit_sha")

  clone_path="$DEST_DIR/$eco/$name"

  echo "--- $eco/$name"
  echo "    url : $url"
  echo "    sha : ${sha:0:12}..."

  # Check if we already cloned this URL (monorepo case)
  if [[ -n "${CLONED_URLS[$url]:-}" ]]; then
    existing="${CLONED_URLS[$url]}"
    echo "    [monorepo] already cloned at $existing — creating symlink"
    if [[ "$DRY_RUN" == false ]]; then
      mkdir -p "$(dirname "$clone_path")"
      if [[ ! -e "$clone_path" ]]; then
        ln -s "$existing" "$clone_path"
      fi
    fi
    SKIPPED=$((SKIPPED + 1))
    continue
  fi

  if [[ -d "$clone_path/.git" ]]; then
    echo "    [skip] already cloned"
    CLONED_URLS[$url]="$clone_path"
    SKIPPED=$((SKIPPED + 1))
    continue
  fi

  if [[ "$DRY_RUN" == true ]]; then
    echo "    [dry-run] git clone --no-checkout $url $clone_path"
    echo "    [dry-run] git -C $clone_path checkout $sha"
    CLONED=$((CLONED + 1))
    continue
  fi

  mkdir -p "$(dirname "$clone_path")"

  if git clone --no-checkout --depth 1 "$url" "$clone_path" 2>&1; then
    # Fetch the exact SHA if depth=1 didn't get it
    if ! git -C "$clone_path" cat-file -e "${sha}^{commit}" 2>/dev/null; then
      git -C "$clone_path" fetch --depth 1 origin "$sha" 2>/dev/null || \
      git -C "$clone_path" fetch origin 2>/dev/null || true
    fi
    if git -C "$clone_path" checkout "$sha" -- 2>&1; then
      echo "    [ok] checked out $sha"
      CLONED_URLS[$url]="$clone_path"
      CLONED=$((CLONED + 1))
    else
      echo "    [warn] checkout failed for $sha — leaving at HEAD"
      CLONED_URLS[$url]="$clone_path"
      CLONED=$((CLONED + 1))
    fi
  else
    echo "    [ERROR] git clone failed for $url" >&2
    ERRORS=$((ERRORS + 1))
  fi
done

echo ""
echo "============================================"
echo "Done. Cloned: $CLONED  Skipped: $SKIPPED  Errors: $ERRORS"
echo "============================================"

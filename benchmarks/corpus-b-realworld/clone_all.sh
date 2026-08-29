#!/usr/bin/env bash
# clone_all.sh — Clone all 150 Corpus B projects at pinned commit SHAs
#
# 150 manifest entries resolve to 140 repositories: 10 entries are monorepo
# siblings and are symlinked to the clone they share.
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

# `realpath -m` is GNU-only; macOS realpath rejects it. Use python's
# os.path.abspath which doesn't require the path to exist and works on both.
DEST_DIR="$(python3 -c 'import os, sys; print(os.path.abspath(sys.argv[1]))' "$DEST_DIR")"
echo "Cloning to: $DEST_DIR"
echo "Ecosystem filter: ${FILTER_ECO:-all}"
echo "Dry run: $DRY_RUN"
echo ""

# Use Python's TOML lib to parse each project toml.
# tomllib is stdlib on 3.11+, tomli is the backport for 3.7–3.10 (preinstalled
# in many environments). Try both.
parse_toml_field() {
  local file="$1"
  local field="$2"
  python3 - "$file" "$field" <<'EOF'
import sys
try:
    import tomllib as _toml
except ImportError:
    import tomli as _toml
file_path, field = sys.argv[1], sys.argv[2]
with open(file_path, 'rb') as f:
    d = _toml.load(f)
val = d
for p in field.split('.'):
    val = val[p]
print(val)
EOF
}

# Track already-cloned repos to avoid re-cloning monorepos.
# Associative arrays need bash 4+; macOS ships bash 3.2. Use a tempdir of
# files named after a SHA-256 of the URL instead — portable to any POSIX shell.
URL_INDEX_DIR="$(mktemp -d)"
# bash 3.2 (macOS) inherits the EXIT trap into command-substitution subshells,
# so a plain `trap 'rm -rf' EXIT` would nuke the tempdir on the first lookup.
# We use a sentinel file: the trap deletes only when the file still exists,
# and we touch it once at script end. Simpler than $BASHPID checks across
# different bash versions.
URL_INDEX_DONE_SENTINEL="$URL_INDEX_DIR/.done"
trap '[[ -f "$URL_INDEX_DONE_SENTINEL" ]] && rm -rf "$URL_INDEX_DIR"' EXIT
url_key() {
  printf '%s' "$1" | shasum -a 256 | cut -d' ' -f1
}
url_seen_path() {
  local key
  key="$(url_key "$1")"
  # Always return 0 — printing nothing is a valid "not seen" answer.
  # Without this explicit return, bash 3.2 + `set -e` propagates the
  # `[[ -f ... ]]` false-exit and kills the calling script.
  if [[ -f "$URL_INDEX_DIR/$key" ]]; then
    cat "$URL_INDEX_DIR/$key"
  fi
  return 0
}
url_seen_set() {
  printf '%s' "$2" > "$URL_INDEX_DIR/$(url_key "$1")"
}

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
  existing="$(url_seen_path "$url")"
  if [[ -n "$existing" ]]; then
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
    url_seen_set "$url" "$clone_path"
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
      url_seen_set "$url" "$clone_path"
      CLONED=$((CLONED + 1))
    else
      # The clone above used --no-checkout, so a failed checkout leaves the
      # working tree EMPTY. Every corpus figure then counts this project as
      # "scanned, zero findings". Forty-six projects sat in exactly that state
      # because their pinned SHA was not a commit in the repository at all.
      # This must be loud and must fail the run.
      echo "    [ERROR] checkout failed for $sha — working tree is EMPTY." >&2
      echo "            Fix the commit_sha in the project file; do not scan this corpus." >&2
      ERRORS=$((ERRORS + 1))
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
if [[ "$ERRORS" -gt 0 ]]; then
  echo "$ERRORS project(s) are not at their pinned commit and some may have an" >&2
  echo "empty working tree. Run corpus_integrity.py before scanning anything." >&2
fi

# Signal to the EXIT trap that the script reached the end cleanly and the
# index tempdir is now safe to remove. Without this, subshells exiting would
# wipe the index mid-loop on bash 3.2 (macOS).
: > "$URL_INDEX_DONE_SENTINEL"

# A partially-cloned corpus must not look like a successful one to a caller.
if [[ "$ERRORS" -gt 0 ]]; then exit 1; fi

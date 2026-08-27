#!/usr/bin/env sh
# install.sh — seawall installer
#
# Usage (once binary releases land):
#   curl -sSL https://raw.githubusercontent.com/<TBD>/seawall/main/scripts/install.sh | sh
#
# The script detects your OS and architecture, downloads the correct pre-built
# binary from the latest GitHub release, verifies its SHA-256 checksum, and
# installs it to /usr/local/bin (or $INSTALL_DIR if set).
#
# Environment variables:
#   INSTALL_DIR   — override install directory (default: /usr/local/bin)
#   SEAWALL_VERSION — pin a specific release tag  (default: latest)

set -eu

# ── Config ─────────────────────────────────────────────────────────────────
REPO_URL="https://github.com/<TBD>/seawall"
RELEASES_URL="${REPO_URL}/releases"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
BIN_NAME="seawall"

# ── Helpers ────────────────────────────────────────────────────────────────
say()  { printf '\033[1;32m==> \033[0m%s\n' "$*"; }
warn() { printf '\033[1;33mWARN: \033[0m%s\n' "$*" >&2; }
die()  { printf '\033[1;31mERROR: \033[0m%s\n' "$*" >&2; exit 1; }

need() {
  command -v "$1" >/dev/null 2>&1 || die "Required tool not found: $1"
}

# ── Detect OS ──────────────────────────────────────────────────────────────
detect_os() {
  case "$(uname -s)" in
    Linux*)  echo "linux" ;;
    Darwin*) echo "macos" ;;
    *)       die "Unsupported OS: $(uname -s). Install manually: cargo install seawall" ;;
  esac
}

# ── Detect architecture ────────────────────────────────────────────────────
detect_arch() {
  case "$(uname -m)" in
    x86_64 | amd64)          echo "x86_64" ;;
    aarch64 | arm64)          echo "aarch64" ;;
    *)                        die "Unsupported architecture: $(uname -m). Install manually: cargo install seawall" ;;
  esac
}

# ── Map (os, arch) → release target triple ────────────────────────────────
target_triple() {
  OS="$1"
  ARCH="$2"
  case "${OS}-${ARCH}" in
    linux-x86_64)   echo "x86_64-unknown-linux-musl" ;;
    linux-aarch64)  echo "aarch64-unknown-linux-musl" ;;
    macos-x86_64)   echo "x86_64-apple-darwin" ;;
    macos-aarch64)  echo "aarch64-apple-darwin" ;;
    *)              die "No pre-built binary for ${OS}-${ARCH}. Install manually: cargo install seawall" ;;
  esac
}

# ── Resolve latest release version via GitHub API ─────────────────────────
latest_version() {
  need curl
  VERSION=$(curl -sSf \
    "https://api.github.com/repos/<TBD>/seawall/releases/latest" \
    | grep '"tag_name"' \
    | sed 's/.*"tag_name": *"\(.*\)".*/\1/')
  [ -n "${VERSION}" ] || die "Could not determine latest release version."
  echo "${VERSION}"
}

# ── Verify SHA-256 checksum ────────────────────────────────────────────────
verify_checksum() {
  ARCHIVE="$1"
  EXPECTED="$2"

  if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL=$(sha256sum "${ARCHIVE}" | awk '{print $1}')
  elif command -v shasum >/dev/null 2>&1; then
    ACTUAL=$(shasum -a 256 "${ARCHIVE}" | awk '{print $1}')
  else
    warn "No sha256sum or shasum found — skipping checksum verification."
    return
  fi

  [ "${ACTUAL}" = "${EXPECTED}" ] || \
    die "Checksum mismatch for ${ARCHIVE}.\n  expected: ${EXPECTED}\n  got:      ${ACTUAL}"
  say "Checksum OK"
}

# ── Main ───────────────────────────────────────────────────────────────────
main() {
  # ── Pre-release notice ────────────────────────────────────────────────────
  # Binary releases are not yet published.  Once the first GitHub Release is
  # tagged, delete this block and the script will work end-to-end.
  #
  # ┌───────────────────────────────────────────────────────────────────────┐
  # │  Releases coming soon.                                                │
  # │                                                                       │
  # │  For now, install from source:                                        │
  # │    cargo install --git https://github.com/<TBD>/seawall          │
  # │                                                                       │
  # │  Or, if you have the repo cloned:                                     │
  # │    cargo install --path seawall/crates/cli                       │
  # └───────────────────────────────────────────────────────────────────────┘
  printf '\n'
  printf '  seawall pre-built binaries are not yet available.\n'
  printf '\n'
  printf '  Install from source with Cargo:\n'
  printf '    cargo install --git https://github.com/<TBD>/seawall\n'
  printf '\n'
  printf '  Or clone and build locally:\n'
  printf '    git clone https://github.com/<TBD>/seawall\n'
  printf '    cargo install --path seawall/crates/cli\n'
  printf '\n'
  exit 0

  # ── Everything below executes once binary releases land ───────────────────
  need curl
  need tar

  OS="$(detect_os)"
  ARCH="$(detect_arch)"
  TARGET="$(target_triple "${OS}" "${ARCH}")"

  VERSION="${SEAWALL_VERSION:-$(latest_version)}"
  # Strip leading 'v' for archive naming consistency.
  VER="${VERSION#v}"

  say "Installing seawall ${VERSION} (${TARGET})"

  ARCHIVE_NAME="${BIN_NAME}-${VER}-${TARGET}.tar.gz"
  CHECKSUM_NAME="${ARCHIVE_NAME}.sha256"
  DOWNLOAD_BASE="${RELEASES_URL}/download/${VERSION}"

  TMP_DIR="$(mktemp -d)"
  trap 'rm -rf "${TMP_DIR}"' EXIT

  say "Downloading ${ARCHIVE_NAME}"
  curl -sSfL "${DOWNLOAD_BASE}/${ARCHIVE_NAME}"  -o "${TMP_DIR}/${ARCHIVE_NAME}"
  curl -sSfL "${DOWNLOAD_BASE}/${CHECKSUM_NAME}" -o "${TMP_DIR}/${CHECKSUM_NAME}"

  EXPECTED="$(awk '{print $1}' "${TMP_DIR}/${CHECKSUM_NAME}")"
  verify_checksum "${TMP_DIR}/${ARCHIVE_NAME}" "${EXPECTED}"

  say "Extracting"
  tar -xzf "${TMP_DIR}/${ARCHIVE_NAME}" -C "${TMP_DIR}"

  say "Installing to ${INSTALL_DIR}/${BIN_NAME}"
  if [ -w "${INSTALL_DIR}" ]; then
    mv "${TMP_DIR}/${BIN_NAME}" "${INSTALL_DIR}/${BIN_NAME}"
    chmod +x "${INSTALL_DIR}/${BIN_NAME}"
  else
    sudo mv "${TMP_DIR}/${BIN_NAME}" "${INSTALL_DIR}/${BIN_NAME}"
    sudo chmod +x "${INSTALL_DIR}/${BIN_NAME}"
  fi

  say "Done — seawall ${VERSION} installed"
  "${INSTALL_DIR}/${BIN_NAME}" --version
}

main "$@"

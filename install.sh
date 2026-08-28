#!/usr/bin/env bash
# install.sh — curl | sh installer for quipuu
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/quipuu/quipuu/main/install.sh | sh
#
# Environment variable overrides (set before piping or exporting):
#   VERSION=v0.1.0      — pin to a specific release (default: latest)
#   INSTALL_DIR=/path   — override the installation directory
#
# Flags:
#   --help              — print this help and exit 0
#
# Behavior:
#   1. Detects OS + architecture
#   2. Picks the right release artifact from GitHub Releases
#   3. Downloads SHA256SUMS and verifies the archive
#   4. Extracts and installs the binary
#   5. Prints PATH guidance if needed
#
# Idempotent: running again upgrades to the requested (or latest) version.
#
# This script targets bash 3.2+ (ships on macOS) and requires:
#   curl, sha256sum (or shasum -a 256 on macOS), tar, mktemp

set -euo pipefail

# ── Constants ─────────────────────────────────────────────────────────────────
REPO="quipuu/quipuu"
GITHUB_API="https://api.github.com/repos/${REPO}/releases/latest"
GITHUB_RELEASES="https://github.com/${REPO}/releases/download"
BIN_NAME="quipuu"

# ── Colour helpers (suppressed when stdout is not a tty) ──────────────────────
# These are intentionally simple so they work without tput.
if [ -t 1 ] && [ "${NO_COLOR:-}" = "" ]; then
    BOLD=$'\033[1m'
    GREEN=$'\033[0;32m'
    YELLOW=$'\033[0;33m'
    RED=$'\033[0;31m'
    RESET=$'\033[0m'
else
    BOLD=""
    GREEN=""
    YELLOW=""
    RED=""
    RESET=""
fi

info()    { printf '%s[info]%s  %s\n' "${GREEN}"  "${RESET}" "$*"; }
warn()    { printf '%s[warn]%s  %s\n' "${YELLOW}" "${RESET}" "$*"; }
error()   { printf '%s[error]%s %s\n' "${RED}"    "${RESET}" "$*" >&2; }
fatal()   { error "$*"; exit 1; }
heading() { printf '\n%s%s%s\n' "${BOLD}" "$*" "${RESET}"; }

# ── --help ────────────────────────────────────────────────────────────────────
usage() {
    cat <<EOF
${BOLD}quipuu installer${RESET}

Usage:
  curl -fsSL https://raw.githubusercontent.com/quipuu/quipuu/main/install.sh | sh

  # Pin a version:
  VERSION=v0.1.0 sh install.sh

  # Choose the install directory:
  INSTALL_DIR=~/.local/bin sh install.sh

Environment variables:
  VERSION     Release tag to install (default: latest release).
  INSTALL_DIR Directory to install the binary into.
              Default: /usr/local/bin if writable, otherwise ~/.local/bin.

Flags:
  --help      Print this message and exit.

Supported platforms:
  Linux   x86_64, aarch64 (fully static musl binary)
  macOS   x86_64, arm64

Windows users:
  Download the .zip from the GitHub Releases page:
  https://github.com/${REPO}/releases

EOF
}

# Parse arguments — even when invoked as "curl | sh", $@ may carry args passed
# via "sh -s -- --help" convention.
for arg in "$@"; do
    case "${arg}" in
        --help|-h)
            usage
            exit 0
            ;;
        *)
            fatal "Unknown argument: ${arg}.  Run with --help for usage."
            ;;
    esac
done

# ── Platform detection ────────────────────────────────────────────────────────
detect_platform() {
    local os arch

    os="$(uname -s)"
    arch="$(uname -m)"

    case "${os}" in
        Linux)
            case "${arch}" in
                x86_64)          echo "x86_64-unknown-linux-musl" ;;
                aarch64|arm64)   echo "aarch64-unknown-linux-musl" ;;
                *)               fatal "Unsupported Linux architecture: ${arch}" ;;
            esac
            ;;
        Darwin)
            case "${arch}" in
                x86_64)          echo "x86_64-apple-darwin" ;;
                arm64)           echo "aarch64-apple-darwin" ;;
                *)               fatal "Unsupported macOS architecture: ${arch}" ;;
            esac
            ;;
        MINGW*|MSYS*|CYGWIN*|Windows_NT)
            cat <<'EOF'
Windows is not supported by this shell installer.

Please download the .zip archive from the GitHub Releases page:
  https://github.com/udsy19/quipuu/releases

Extract quipuu.exe and place it somewhere on your PATH.
EOF
            exit 1
            ;;
        *)
            fatal "Unsupported operating system: ${os}"
            ;;
    esac
}

# ── Dependency checks ─────────────────────────────────────────────────────────
require_cmd() {
    if ! command -v "$1" > /dev/null 2>&1; then
        fatal "Required command not found: $1.  Please install it and try again."
    fi
}

check_deps() {
    require_cmd curl
    require_cmd tar
    require_cmd mktemp
    # sha256sum is standard on Linux; macOS ships shasum instead.
    if ! command -v sha256sum > /dev/null 2>&1; then
        require_cmd shasum
    fi
}

# ── SHA-256 verification helper ───────────────────────────────────────────────
# Usage: verify_sha256 <file> <expected_hash>
verify_sha256() {
    local file="$1"
    local expected="$2"
    local actual

    if command -v sha256sum > /dev/null 2>&1; then
        actual="$(sha256sum "${file}" | awk '{print $1}')"
    else
        # macOS
        actual="$(shasum -a 256 "${file}" | awk '{print $1}')"
    fi

    if [ "${actual}" != "${expected}" ]; then
        error "SHA-256 mismatch for ${file}"
        error "  expected: ${expected}"
        error "  actual:   ${actual}"
        fatal "Aborting — the download may be corrupted or tampered with."
    fi
}

# ── Resolve installation directory ───────────────────────────────────────────
resolve_install_dir() {
    if [ -n "${INSTALL_DIR:-}" ]; then
        echo "${INSTALL_DIR}"
        return
    fi

    # Prefer /usr/local/bin if we can write to it (i.e., running as root or
    # with sudo, or it's owned by the current user).
    if [ -w "/usr/local/bin" ]; then
        echo "/usr/local/bin"
    else
        # Fall back to ~/.local/bin (XDG convention).
        echo "${HOME}/.local/bin"
    fi
}

# ── Fetch the latest release tag via GitHub API ──────────────────────────────
resolve_version() {
    if [ -n "${VERSION:-}" ]; then
        echo "${VERSION}"
        return
    fi

    info "Fetching latest release from GitHub..."
    local tag
    tag="$(curl -fsSL "${GITHUB_API}" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')"

    if [ -z "${tag}" ]; then
        fatal "Could not determine the latest release.  Set VERSION=vX.Y.Z to pin."
    fi

    echo "${tag}"
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    heading "quipuu installer"

    check_deps

    local target version install_dir archive_name archive_url sha256sums_url
    local tmp_dir archive_path sha256sums_path expected_hash

    target="$(detect_platform)"
    version="$(resolve_version)"
    install_dir="$(resolve_install_dir)"

    # Strip leading "v" from version for the filename (tag is "v0.1.0",
    # archive is "quipuu-0.1.0-<triple>.tar.gz").
    local ver_no_v="${version#v}"

    archive_name="${BIN_NAME}-${ver_no_v}-${target}.tar.gz"
    archive_url="${GITHUB_RELEASES}/${version}/${archive_name}"
    sha256sums_url="${GITHUB_RELEASES}/${version}/SHA256SUMS"

    info "Target platform : ${target}"
    info "Version         : ${version}"
    info "Archive         : ${archive_name}"
    info "Install dir     : ${install_dir}"

    # ── Download into a temp directory ───────────────────────────────────────
    tmp_dir="$(mktemp -d)"
    # shellcheck disable=SC2064
    trap "rm -rf '${tmp_dir}'" EXIT

    archive_path="${tmp_dir}/${archive_name}"
    sha256sums_path="${tmp_dir}/SHA256SUMS"

    info "Downloading ${archive_name}..."
    if ! curl -fsSL --progress-bar -o "${archive_path}" "${archive_url}"; then
        fatal "Download failed.  Check that ${version} exists at:
  https://github.com/${REPO}/releases"
    fi

    info "Downloading SHA256SUMS..."
    if ! curl -fsSL -o "${sha256sums_path}" "${sha256sums_url}"; then
        fatal "Could not download SHA256SUMS from the release.  Aborting."
    fi

    # ── SHA-256 verification ──────────────────────────────────────────────────
    info "Verifying checksum..."
    # Extract the expected hash for our specific archive from SHA256SUMS.
    expected_hash="$(grep " ${archive_name}" "${sha256sums_path}" | awk '{print $1}')"

    if [ -z "${expected_hash}" ]; then
        fatal "No checksum entry for '${archive_name}' in SHA256SUMS."
    fi

    verify_sha256 "${archive_path}" "${expected_hash}"
    info "Checksum verified."

    # ── Extract and install ───────────────────────────────────────────────────
    local extract_dir="${tmp_dir}/extract"
    mkdir -p "${extract_dir}"
    tar -xzf "${archive_path}" -C "${extract_dir}"

    # Ensure the install directory exists.
    mkdir -p "${install_dir}"

    local bin_src="${extract_dir}/${BIN_NAME}"
    if [ ! -f "${bin_src}" ]; then
        fatal "Binary '${BIN_NAME}' not found in archive."
    fi

    local bin_dest="${install_dir}/${BIN_NAME}"

    # Overwrite any existing installation (idempotent upgrade).
    if [ -f "${bin_dest}" ]; then
        warn "Overwriting existing installation at ${bin_dest}"
    fi

    cp "${bin_src}" "${bin_dest}"
    chmod 755 "${bin_dest}"

    # ── PATH guidance ─────────────────────────────────────────────────────────
    heading "Installation complete"
    info "${BIN_NAME} ${version} installed to ${bin_dest}"

    # Check whether install_dir is on the current PATH.
    case ":${PATH}:" in
        *":${install_dir}:"*)
            # Already on PATH — nothing to do.
            ;;
        *)
            warn "${install_dir} is not on your PATH."
            warn "Add the following line to your shell profile (~/.bashrc, ~/.zshrc, etc.):"
            warn ""
            warn "  export PATH=\"${install_dir}:\$PATH\""
            warn ""
            warn "Then reload your shell or run:  source ~/.bashrc"
            ;;
    esac

    # Smoke test — only possible when install_dir is reachable right now.
    if command -v "${BIN_NAME}" > /dev/null 2>&1; then
        info "Smoke test: $(${BIN_NAME} --version 2>&1 || true)"
    fi
}

main "$@"

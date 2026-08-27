# Formula/seawall.rb — Homebrew formula for seawall
#
# This is a stub formula pinned to v0.1.0.  SHA-256 digests are placeholder
# values; they will be replaced by `brew bump-formula-pr` (or manual update)
# when the v0.1.0 binaries are published to GitHub Releases.
#
# To update after a new release:
#   brew bump-formula-pr --tag=v<NEW_VERSION> --revision=<GIT_SHA> seawall
#
# Or update the url / sha256 values manually from SHA256SUMS on the release page:
#   https://github.com/udsy19/seawall/releases

class Seawall < Formula
  desc "Single static binary that finds every piece of cryptography in your codebase, " \
       "dependencies, X.509 certificates, and TLS endpoints, then scores each for " \
       "quantum vulnerability against the NIST IR 8547 timeline"
  homepage "https://github.com/udsy19/seawall"
  version "0.1.0"
  license "Apache-2.0"

  # ── Per-platform bottles (pre-built binaries) ─────────────────────────────
  #
  # Each `on_*` block selects the right release artifact for the host platform.
  # SHA-256 values are placeholders — replace with the real digests from
  # SHA256SUMS on the GitHub Releases page before submitting to a tap.

  on_macos do
    on_arm do
      url "https://github.com/udsy19/seawall/releases/download/v#{version}/seawall-#{version}-aarch64-apple-darwin.tar.gz"
      # TODO: replace with real SHA-256 from SHA256SUMS
      sha256 "0000000000000000000000000000000000000000000000000000000000000001"
    end

    on_intel do
      url "https://github.com/udsy19/seawall/releases/download/v#{version}/seawall-#{version}-x86_64-apple-darwin.tar.gz"
      # TODO: replace with real SHA-256 from SHA256SUMS
      sha256 "0000000000000000000000000000000000000000000000000000000000000002"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/udsy19/seawall/releases/download/v#{version}/seawall-#{version}-aarch64-unknown-linux-musl.tar.gz"
      # TODO: replace with real SHA-256 from SHA256SUMS
      sha256 "0000000000000000000000000000000000000000000000000000000000000003"
    end

    on_intel do
      url "https://github.com/udsy19/seawall/releases/download/v#{version}/seawall-#{version}-x86_64-unknown-linux-musl.tar.gz"
      # TODO: replace with real SHA-256 from SHA256SUMS
      sha256 "0000000000000000000000000000000000000000000000000000000000000004"
    end
  end

  def install
    bin.install "seawall"
  end

  # ── Smoke test run by `brew test seawall` ────────────────────────────
  test do
    assert_match version.to_s, shell_output("#{bin}/seawall --version")
  end
end

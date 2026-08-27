# Corpus B — Real-World OSS Projects

Corpus B is a stratified sample of **150 real open-source projects** spanning six package ecosystems (25 per ecosystem). It is one of three corpora in the QuantumOSS-Analysis benchmark suite (see `BENCHMARKING.md`). The corpus is designed to stress-test the seawall PQC scanner across:

- Varied languages and build systems
- Diverse cryptographic surfaces (TLS, JWT, KEM, signature, MAC, hash, KDF)
- Negative-control packages (widely-used non-crypto utilities)
- PQC-forward libraries (circl, liboqs, pqcrypto, kyber, dilithium, sphincsplus)
- Legacy/archived but widely-deployed code (dgrijalva/jwt-go, six)

---

## Directory Structure

```
corpus-b-realworld/
  README.md             — this file
  manifest.toml         — machine-readable list of all 125 projects
  clone_all.sh          — clone every project at its pinned SHA
  verify.sh             — verify every clone matches its pinned SHA
  ecosystems/
    pypi/               — 25 PyPI projects + README.md
    npm/                — 25 npm projects + README.md
    maven/              — 25 Maven projects + README.md
    crates-io/          — 25 crates.io projects + README.md
    go-modules/         — 25 Go modules + README.md
    crypto-adjacent/    — 25 curated crypto/PQC libraries + README.md
```

Each project is described by a `.toml` file with the following schema:

```toml
[project]
name = "..."
ecosystem = "..."
canonical_id = "ecosystem:name"
description = "..."
why_included = "..."

[repo]
url = "https://github.com/..."
commit_sha = "<40-char SHA>"   # pinned via git ls-remote
license = "..."
language_primary = "..."
languages_secondary = [...]

[metadata]
downloads_monthly = <integer>
captured_at = "YYYY-MM-DD"
stars = <integer>
last_commit_date = "YYYY-MM-DD"

[selection]
selection_method = "top-25-pypi-downloads"  # or ecosystem-specific value
selection_rank = <integer>
substituted_for = ""  # non-empty if repo was renamed/moved

[scan_hints]
scan_paths = [...]
exclude_paths = [...]
expected_languages = [...]
```

---

## Selection Methodology

### PyPI, npm, Maven, crates.io, Go modules (5 ecosystems × 25 projects)

For each ecosystem, the starting set is the top-25 most-downloaded packages by the canonical download metric for that registry (pypistats, npmjs.com weekly downloads, Maven Central downloads, crates.io all-time downloads, pkg.go.dev/proxy.golang.org). Packages are then filtered by:

1. **OSS license**: MIT, Apache-2.0, BSD-2/3-Clause, LGPL-2.1, ISC, EPL, or similar permissive/copyleft with no commercial restriction.
2. **Size**: > 1,000 lines of code.
3. **Activity**: At least one commit in the past 12 months. Archived repositories may be included if they have a sufficiently high active install base (e.g. `dgrijalva/jwt-go`).

Download-metric snapshot: June 2026. `captured_at` field records the date in each `.toml`.

### Crypto-Adjacent tier (hand-curated, 25 projects)

The crypto-adjacent tier selects projects that are canonical cryptographic libraries, NIST PQC reference implementations, or production crypto infrastructure that no download ranking would surface correctly. Selection rationale for each entry is documented in the `why_included` field of each `.toml` and in `ecosystems/crypto-adjacent/README.md`.

---

## Pinned Commit SHAs

Every project has a `commit_sha` pinned via:

```bash
git ls-remote <url> HEAD
```

The SHA is the HEAD of the default branch at the time of corpus creation (June 2026). This ensures reproducible scanning results.

**Monorepo entries** (multiple projects in one repository) share the same `url` and `commit_sha` but have different `scan_paths` in `[scan_hints]` to scope the scanner to the relevant crate/module/artifact.

---

## Cloning the Corpus

```bash
cd benchmarks/corpus-b-realworld

# Clone all 125 projects into ./clones/
./clone_all.sh

# Clone only one ecosystem
./clone_all.sh --ecosystem crates-io

# Dry run (print commands without executing)
./clone_all.sh --dry-run

# Clone to a custom directory
./clone_all.sh --dest /data/corpus-b
```

**Requirements**: `git`, `python3` (3.11+ for built-in `tomllib`)

The script automatically detects monorepos and creates symlinks instead of re-cloning. Clones are checked out to the pinned `commit_sha`.

---

## Verifying Clones

After cloning, run the verifier to confirm each clone matches its pinned SHA:

```bash
./verify.sh

# Verify one ecosystem
./verify.sh --ecosystem pypi

# Write JSON report
./verify.sh --report verify-report.json
```

Exit code `0` means all clones match. Exit code `1` means at least one clone is missing or at the wrong SHA. The JSON report lists per-project `ok`/`missing`/`mismatch` status.

---

## Known Substitutions

The following projects were originally identified by a different name/URL but were corrected during corpus construction. The `substituted_for` field in each `.toml` documents the original candidate.

| Ecosystem | File | Substitution |
|-----------|------|--------------|
| npm | `node-forge.toml` | `digitalbazaar/node-forge` → `digitalbazaar/forge` (renamed) |
| npm | `jsrsasign.toml` | `nicowillis/jsrsasign` → `kjur/jsrsasign` (wrong owner) |
| npm | `oauth.toml` | `oauthjs/node-oauth` → `ciaranj/node-oauth` (wrong org) |
| crates-io | `rustls-pemfile.toml` | Was separate repo; now merged into `rustls/rustls` monorepo |
| crypto-adjacent | `sslyze.toml` | `philipl/sslyze` → `nabla-c0d3/sslyze` (incorrect user) |
| crypto-adjacent | `liboqs-python.toml` | `open-quantum-safe/oqs-python` → `open-quantum-safe/liboqs-python` (renamed) |
| crypto-adjacent | `oqs-rs.toml` | `liboqs-rust/oqs-rs` → `open-quantum-safe/liboqs-rust` (moved) |
| crypto-adjacent | `tink-go.toml` | `google/tink-cc` (invalid); `google/tink` monorepo archived; use `tink-crypto/tink-go` |
| go-modules | `moby.toml` | `docker/docker` → `moby/moby` (renamed) |

---

## Reproducibility Commitment

- All commit SHAs were verified with `git ls-remote` at corpus creation time.
- Download statistics are informational only (for ranking); they do not affect scan results.
- The corpus schema is stable for Corpus B v1.0.0; any future changes will increment the version in `manifest.toml`.
- Do not modify `.toml` files without updating `commit_sha` via a fresh `git ls-remote` call.

---

## Relationship to Other Corpora

| Corpus | Purpose | Location |
|--------|---------|----------|
| Corpus A | Ground-truth synthetic fixtures with known crypto usage | `benchmarks/corpus-a-fixtures/` |
| **Corpus B** | **Real-world OSS projects (this corpus)** | `benchmarks/corpus-b-realworld/` |
| Corpus C | Adversarial/obfuscated cases | `benchmarks/corpus-c-adversarial/` |

See `BENCHMARKING.md` for the full benchmark methodology, precision/recall metrics, throughput requirements, and output-validity (CycloneDX CBOM / SARIF) specifications.

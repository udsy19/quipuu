# Corpus B — Real-World OSS Projects

Corpus B is a stratified sample of **150 real open-source projects** spanning six package ecosystems (25 per ecosystem). It is one of three corpora in the QuantumOSS-Analysis benchmark suite (see `BENCHMARKING.md`). The corpus is designed to stress-test the quipuu PQC scanner across:

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
  manifest.toml         — machine-readable list of all 150 projects
  clone_all.sh          — clone every project at its pinned SHA
  corpus_integrity.py   — census every checkout against corpus-integrity.toml
  corpus-integrity.toml — the committed census the check compares against
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
scan_paths = [...]          # the ONLY field the harness reads
exclude_paths = [...]       # declared but never consumed — see below
expected_languages = [...]
unscannable = "reason"      # optional; see "Unscannable projects"
```

**`scan_paths` is the scan scope and nothing else is.** `exclude_paths` and
`expected_languages` are descriptive: no script in this directory reads them,
and the scanner is never passed an exclusion derived from them. A subtree is
out of scope only by not being under a `scan_paths` entry. Two claims in
`RUST_COVERAGE_GAPS.md` were written on the opposite assumption and are
corrected there.

An absent or empty `scan_paths` means "scan the whole repository", which is a
declaration. A `scan_paths` entry that does not exist on disk is a defect, not
a declaration, and `corpus_integrity.py` fails the run for it.

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

The SHA is the HEAD of the default branch at the time of corpus creation (June 2026).

**This did not, until 2026-08-29, ensure reproducible scanning results, and it
still only half does.** Two facts, both measured against the clones on disk:

1. **46 of the 150 pins were not commits in the repository the project clones.**
   Ten of the 46 were the pinned or current SHA of a *different* project in this
   same corpus — the pins were shuffled across project files at construction, not
   lost since. `clone_all.sh` clones `--no-checkout`, so the checkout of a SHA the
   remote has never heard of failed, the script printed `[warn] leaving at HEAD`
   and counted the project as cloned, and the project was left with an empty
   working tree that every corpus figure counted as "scanned, zero findings".
   All 46 are now re-pinned to the commit actually checked out, each carrying the
   unreachable SHA it replaces in a comment above it.

2. **149 of the 150 checkouts are `--depth 1`.** A shallow clone of a moving
   default branch cannot check out a pin that is not its tip, so re-running
   `clone_all.sh` on a fresh machine today will not reproduce these pins either.
   Fixing that means fetching the pinned SHA directly rather than depth-1
   cloning the branch; it is not fixed here, and `corpus_integrity.py` will say
   so loudly (`off-sha`) rather than let the difference pass silently.

Run `corpus_integrity.py` after cloning and before quoting any figure.

**Monorepo entries** (multiple projects in one repository) share the same `url` and `commit_sha` but have different `scan_paths` in `[scan_hints]` to scope the scanner to the relevant crate/module/artifact.

---

## Cloning the Corpus

```bash
cd benchmarks/corpus-b-realworld

# Clone all 150 projects into ./clones/
./clone_all.sh

# Clone only one ecosystem
./clone_all.sh --ecosystem crates-io

# Dry run (print commands without executing)
./clone_all.sh --dry-run

# Clone to a custom directory
./clone_all.sh --dest /data/corpus-b
```

**Requirements**: `git`, `python3` (3.11+ for built-in `tomllib`)

The script automatically detects monorepos and creates symlinks instead of re-cloning. Clones are checked out to the pinned `commit_sha`. **The 150 manifest entries resolve to 140 repositories**: 10 entries are monorepo siblings and are symlinked to the clone they share. A failed checkout is now an error that fails the script, not a warning.

---

## Verifying the Corpus

Nothing in this directory may produce a number before the corpus has been
censused:

```bash
python3 corpus_integrity.py --clones DIR              # exit 1 on any failure
python3 corpus_integrity.py --clones DIR --write      # re-record the baseline
```

For each manifest project it records `(head_sha, files_scanned, bytes_scanned)`
over **exactly the paths `scan_paths` would hand to the scanner**, compares them
against the committed `corpus-integrity.toml`, and names every failure:

| state | meaning |
|---|---|
| `absent` | no clone directory, or no `.git` in it |
| `empty` | `.git` present, working tree has no tracked files — the checkout never happened |
| `unpinnable` | `commit_sha` is not a commit in this repository; the project can never be restored from the manifest |
| `scope-missing` | a declared `scan_path` is not on disk |
| `off-sha` | HEAD is a real commit, but not the pinned one |
| `drift` | right commit, wrong census — untracked build output, a partial checkout, a truncated file |
| `unscannable` | a recorded, named exclusion (see below); passes |
| `ok` | passes |

`scan_corpus.py`, `dump_findings.py` and `recall_check.py` all run this first
and **refuse to emit a total when it fails**. `--allow-degraded-corpus` stamps
the output `partial`, and `load_dump()` then refuses to read it, so a figure
taken over a broken corpus cannot be quoted as a whole-corpus figure by
accident. `verify.sh` did the pin half of this, was documented as optional, was
not in the pipeline, and is deleted: it could not have caught either of the two
failures above.

### Unscannable projects

`scan_hints.unscannable = "<reason>"` records a project that is in the corpus —
so the denominator stays 150 — but has no scannable scope, and states why on the
project file. It exists so that "we know this cannot be scoped, here is the
reason" is never expressed as an empty `scan_paths`, which means "scan the whole
repository". One project is currently declared unscannable:
`crates-io:rustls-pemfile`, whose crate was split back out of the rustls
workspace upstream. Until 2026-08-29 the harness answered its missing scope by
scanning the whole rustls workspace and recording it as this project — 140
findings, a superset of the 16 that `crates-io:rustls` reports from the same
clone, which `crates-io/rustls` symlinks to.

---

## Known Substitutions

The following projects were originally identified by a different name/URL but were corrected during corpus construction. The `substituted_for` field in each `.toml` documents the original candidate.

| Ecosystem | File | Substitution |
|-----------|------|--------------|
| npm | `node-forge.toml` | `digitalbazaar/node-forge` → `digitalbazaar/forge` (renamed) |
| npm | `jsrsasign.toml` | `nicowillis/jsrsasign` → `kjur/jsrsasign` (wrong owner) |
| npm | `oauth.toml` | `oauthjs/node-oauth` → `ciaranj/node-oauth` (wrong org) |
| crates-io | `rustls-pemfile.toml` | Was separate repo; merged into `rustls/rustls`, then split back out upstream — **no longer present at the pinned commit**, and declared `unscannable` |
| crypto-adjacent | `sslyze.toml` | `philipl/sslyze` → `nabla-c0d3/sslyze` (incorrect user) |
| crypto-adjacent | `liboqs-python.toml` | `open-quantum-safe/oqs-python` → `open-quantum-safe/liboqs-python` (renamed) |
| crypto-adjacent | `oqs-rs.toml` | `liboqs-rust/oqs-rs` → `open-quantum-safe/liboqs-rust` (moved) |
| crypto-adjacent | `tink-go.toml` | `google/tink-cc` (invalid); `google/tink` monorepo archived; use `tink-crypto/tink-go` |
| go-modules | `moby.toml` | `docker/docker` → `moby/moby` (renamed) |

---

## Reproducibility Commitment

- Commit SHAs were **claimed** to be verified with `git ls-remote` at corpus creation time. They were not: 46 of the 150 named a commit that is not in the repository the project clones. Corrected 2026-08-29 — see "Pinned Commit SHAs" above.
- `scan_paths` were **not** checked against any tree at construction: 15 of the 92 projects declaring one named a path that does not exist at the pinned commit, and 9 of those 15 are at exactly the commit they pin, so the paths were wrong when they were written rather than stale since. Repaired 2026-08-29.
- Download statistics are informational only (for ranking); they do not affect scan results.
- The corpus schema is stable for Corpus B v1.0.0; any future changes will increment the version in `manifest.toml`.
- Do not modify `.toml` files without re-running `corpus_integrity.py --write` and committing the baseline diff alongside.

---

## Relationship to Other Corpora

| Corpus | Purpose | Location |
|--------|---------|----------|
| Corpus A | Ground-truth synthetic fixtures with known crypto usage | `benchmarks/corpus-a-fixtures/` |
| **Corpus B** | **Real-world OSS projects (this corpus)** | `benchmarks/corpus-b-realworld/` |
| Corpus C | Adversarial/obfuscated cases | `benchmarks/corpus-c-adversarial/` |

See `BENCHMARKING.md` for the full benchmark methodology, precision/recall metrics, throughput requirements, and output-validity (CycloneDX CBOM / SARIF) specifications.

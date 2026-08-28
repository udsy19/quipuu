# quipuu integrations

quipuu requires no account, no signup, and no paid plan.
The only credential in play is the `GITHUB_TOKEN` that GitHub Actions
auto-provisions on every run.

---

## GitHub Actions

The fastest path: copy one file into your repo.

### 1. Copy the template workflow

```sh
curl -sSL \
  https://raw.githubusercontent.com/<TBD>/quipuu/main/.github/workflows/quipuu-template.yml \
  -o .github/workflows/quipuu.yml
```

Or copy it manually from `.github/workflows/quipuu-template.yml` in the
quipuu repo.

### 2. Commit and push

```sh
git add .github/workflows/quipuu.yml
git commit -m "Add quipuu scan"
git push
```

That's it. quipuu will now:

- Run on every push and pull request.
- Post a findings summary as a PR comment (idempotent — updates on re-runs).
- Upload SARIF results to **Security → Code scanning alerts**.
- Attach the HTML report and CycloneDX CBOM as downloadable workflow artifacts.

### Config knobs

All tunable settings are marked with `✎` in the template file.
The most common ones:

| Setting | Where | Default |
|---------|-------|---------|
| Scan target path | `env.SCAN_TARGET` | `.` (whole repo) |
| Fail on severity  | `--fail-on` arg   | not set (exit 0 on any finding) |
| Artifact retention | `retention-days` | 30 days |
| Scan category (Code Scanning UI) | `category:` | `quipuu` |

To fail the workflow on critical findings, add `--fail-on critical` to the
`quipuu scan` step args. The threshold is *at or above*: `--fail-on medium`
fails on Medium, High and Critical alike. `--fail-on policy` defers to the
active policy's `[ci] fail_on` — `nist-default` says `critical`, `nsa-cnsa2`
says `high` — so a policy switch moves the gate with it.

Exit codes: **0** the scan ran and no threshold was met; **1** the threshold was
met, or an output file could not be written; **2** quipuu refused to run — a bad
argument, a path that does not exist, or `--net` without `--allow-network`. A
threshold quipuu cannot parse is a refusal, not a warning, so a typo in the
gate never reads as a pass.

---

## Pre-commit

quipuu ships a [pre-commit framework](https://pre-commit.com) hook so
findings are caught before code ever leaves your machine.

### 1. Install pre-commit (if you haven't)

```sh
pip install pre-commit   # or: brew install pre-commit
pre-commit install
```

### 2. Add the hook to your `.pre-commit-config.yaml`

```yaml
repos:
  - repo: https://github.com/<TBD>/quipuu
    rev: v0.1.0   # pin to a release tag
    hooks:
      - id: quipuu-scan
```

### 3. Run against all files (first-time check)

```sh
pre-commit run quipuu-scan --all-files
```

Subsequent `git commit` invocations will run quipuu on staged files only.

The hook exits non-zero only when a **critical** severity finding is present
(configurable via `args: [--fail-on, high]` in your `.pre-commit-config.yaml`).
pre-commit passes the staged files as positional arguments; quipuu scans every
one of them, and refuses to run if any is unreadable rather than reporting a
clean commit for a tree it never opened.

Your `.quipuu.toml` at the repo root is picked up automatically.

---

## Local CI / scripted pipelines

For any CI system that can run shell commands (CircleCI, GitLab CI, Jenkins,
Buildkite, etc.), the integration is a single command:

```sh
quipuu scan . --sarif out/quipuu.sarif
```

### Install in CI

```sh
# Option A — from crates.io (once published)
cargo install quipuu --locked

# Option B — from git
cargo install --git https://github.com/<TBD>/quipuu --locked
```

### Minimal GitLab CI example

```yaml
quipuu:
  stage: test
  image: rust:latest
  before_script:
    - cargo install quipuu --locked
  script:
    - mkdir -p reports
    - quipuu scan . --sarif reports/quipuu.sarif --summary-json reports/quipuu.summary.json
  artifacts:
    paths:
      - reports/
    when: always
```

### Minimal CircleCI example

```yaml
jobs:
  quipuu:
    docker:
      - image: cimg/rust:stable
    steps:
      - checkout
      - run:
          name: Install quipuu
          command: cargo install quipuu --locked
      - run:
          name: Run quipuu scan
          command: |
            mkdir -p reports
            quipuu scan . --sarif reports/quipuu.sarif
      - store_artifacts:
          path: reports
```

---

## Roadmap: future integration templates

The following are planned but not yet available:

- **GitLab CI** — a reusable component (`include:` style) with MR comment posting.
- **CircleCI** — an orb (`quipuu/scan@1`) wrapping the install + scan steps.
- **Bitbucket Pipelines** — a pipe definition.
- **VS Code extension** — inline diagnostics from the JSON output.

Contributions welcome — open a PR against the quipuu repo.

---

## Verifying SARIF output

SARIF files produced by quipuu conform to SARIF 2.1.0 and can be
validated locally with Microsoft's SARIF SDK or viewed with the SARIF Viewer
extension for VS Code:

```sh
# Validate with the SARIF multitool (requires Node.js)
npx @microsoft/sarif-multitool validate out/quipuu.sarif
```

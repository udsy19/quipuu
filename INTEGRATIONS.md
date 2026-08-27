# cryptoscope integrations

cryptoscope requires no account, no signup, and no paid plan.
The only credential in play is the `GITHUB_TOKEN` that GitHub Actions
auto-provisions on every run.

---

## GitHub Actions

The fastest path: copy one file into your repo.

### 1. Copy the template workflow

```sh
curl -sSL \
  https://raw.githubusercontent.com/<TBD>/cryptoscope/main/.github/workflows/cryptoscope-template.yml \
  -o .github/workflows/cryptoscope.yml
```

Or copy it manually from `.github/workflows/cryptoscope-template.yml` in the
cryptoscope repo.

### 2. Commit and push

```sh
git add .github/workflows/cryptoscope.yml
git commit -m "Add cryptoscope scan"
git push
```

That's it. cryptoscope will now:

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
| Fail on severity  | `--fail-on` arg   | not set (always exit 0) |
| Artifact retention | `retention-days` | 30 days |
| Scan category (Code Scanning UI) | `category:` | `cryptoscope` |

To fail the workflow on critical findings, add `--fail-on critical` to the
`cryptoscope scan` step args.

---

## Pre-commit

cryptoscope ships a [pre-commit framework](https://pre-commit.com) hook so
findings are caught before code ever leaves your machine.

### 1. Install pre-commit (if you haven't)

```sh
pip install pre-commit   # or: brew install pre-commit
pre-commit install
```

### 2. Add the hook to your `.pre-commit-config.yaml`

```yaml
repos:
  - repo: https://github.com/<TBD>/cryptoscope
    rev: v0.1.0   # pin to a release tag
    hooks:
      - id: cryptoscope-scan
```

### 3. Run against all files (first-time check)

```sh
pre-commit run cryptoscope-scan --all-files
```

Subsequent `git commit` invocations will run cryptoscope on staged files only.

The hook exits non-zero only when a **critical** severity finding is present
(configurable via `args: [--fail-on, high]` in your `.pre-commit-config.yaml`).

Your `.cryptoscope.toml` at the repo root is picked up automatically.

---

## Local CI / scripted pipelines

For any CI system that can run shell commands (CircleCI, GitLab CI, Jenkins,
Buildkite, etc.), the integration is a single command:

```sh
cryptoscope scan . --sarif out/cryptoscope.sarif
```

### Install in CI

```sh
# Option A — from crates.io (once published)
cargo install cryptoscope --locked

# Option B — from git
cargo install --git https://github.com/<TBD>/cryptoscope --locked
```

### Minimal GitLab CI example

```yaml
cryptoscope:
  stage: test
  image: rust:latest
  before_script:
    - cargo install cryptoscope --locked
  script:
    - mkdir -p reports
    - cryptoscope scan . --sarif reports/cryptoscope.sarif --summary-json reports/cryptoscope.summary.json
  artifacts:
    paths:
      - reports/
    when: always
```

### Minimal CircleCI example

```yaml
jobs:
  cryptoscope:
    docker:
      - image: cimg/rust:stable
    steps:
      - checkout
      - run:
          name: Install cryptoscope
          command: cargo install cryptoscope --locked
      - run:
          name: Run cryptoscope scan
          command: |
            mkdir -p reports
            cryptoscope scan . --sarif reports/cryptoscope.sarif
      - store_artifacts:
          path: reports
```

---

## Roadmap: future integration templates

The following are planned but not yet available:

- **GitLab CI** — a reusable component (`include:` style) with MR comment posting.
- **CircleCI** — an orb (`cryptoscope/scan@1`) wrapping the install + scan steps.
- **Bitbucket Pipelines** — a pipe definition.
- **VS Code extension** — inline diagnostics from the JSON output.

Contributions welcome — open a PR against the cryptoscope repo.

---

## Verifying SARIF output

SARIF files produced by cryptoscope conform to SARIF 2.1.0 and can be
validated locally with Microsoft's SARIF SDK or viewed with the SARIF Viewer
extension for VS Code:

```sh
# Validate with the SARIF multitool (requires Node.js)
npx @microsoft/sarif-multitool validate out/cryptoscope.sarif
```

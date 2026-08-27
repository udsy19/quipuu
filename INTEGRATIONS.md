# seawall integrations

seawall requires no account, no signup, and no paid plan.
The only credential in play is the `GITHUB_TOKEN` that GitHub Actions
auto-provisions on every run.

---

## GitHub Actions

The fastest path: copy one file into your repo.

### 1. Copy the template workflow

```sh
curl -sSL \
  https://raw.githubusercontent.com/<TBD>/seawall/main/.github/workflows/seawall-template.yml \
  -o .github/workflows/seawall.yml
```

Or copy it manually from `.github/workflows/seawall-template.yml` in the
seawall repo.

### 2. Commit and push

```sh
git add .github/workflows/seawall.yml
git commit -m "Add seawall scan"
git push
```

That's it. seawall will now:

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
| Scan category (Code Scanning UI) | `category:` | `seawall` |

To fail the workflow on critical findings, add `--fail-on critical` to the
`seawall scan` step args.

---

## Pre-commit

seawall ships a [pre-commit framework](https://pre-commit.com) hook so
findings are caught before code ever leaves your machine.

### 1. Install pre-commit (if you haven't)

```sh
pip install pre-commit   # or: brew install pre-commit
pre-commit install
```

### 2. Add the hook to your `.pre-commit-config.yaml`

```yaml
repos:
  - repo: https://github.com/<TBD>/seawall
    rev: v0.1.0   # pin to a release tag
    hooks:
      - id: seawall-scan
```

### 3. Run against all files (first-time check)

```sh
pre-commit run seawall-scan --all-files
```

Subsequent `git commit` invocations will run seawall on staged files only.

The hook exits non-zero only when a **critical** severity finding is present
(configurable via `args: [--fail-on, high]` in your `.pre-commit-config.yaml`).

Your `.seawall.toml` at the repo root is picked up automatically.

---

## Local CI / scripted pipelines

For any CI system that can run shell commands (CircleCI, GitLab CI, Jenkins,
Buildkite, etc.), the integration is a single command:

```sh
seawall scan . --sarif out/seawall.sarif
```

### Install in CI

```sh
# Option A — from crates.io (once published)
cargo install seawall --locked

# Option B — from git
cargo install --git https://github.com/<TBD>/seawall --locked
```

### Minimal GitLab CI example

```yaml
seawall:
  stage: test
  image: rust:latest
  before_script:
    - cargo install seawall --locked
  script:
    - mkdir -p reports
    - seawall scan . --sarif reports/seawall.sarif --summary-json reports/seawall.summary.json
  artifacts:
    paths:
      - reports/
    when: always
```

### Minimal CircleCI example

```yaml
jobs:
  seawall:
    docker:
      - image: cimg/rust:stable
    steps:
      - checkout
      - run:
          name: Install seawall
          command: cargo install seawall --locked
      - run:
          name: Run seawall scan
          command: |
            mkdir -p reports
            seawall scan . --sarif reports/seawall.sarif
      - store_artifacts:
          path: reports
```

---

## Roadmap: future integration templates

The following are planned but not yet available:

- **GitLab CI** — a reusable component (`include:` style) with MR comment posting.
- **CircleCI** — an orb (`seawall/scan@1`) wrapping the install + scan steps.
- **Bitbucket Pipelines** — a pipe definition.
- **VS Code extension** — inline diagnostics from the JSON output.

Contributions welcome — open a PR against the seawall repo.

---

## Verifying SARIF output

SARIF files produced by seawall conform to SARIF 2.1.0 and can be
validated locally with Microsoft's SARIF SDK or viewed with the SARIF Viewer
extension for VS Code:

```sh
# Validate with the SARIF multitool (requires Node.js)
npx @microsoft/sarif-multitool validate out/seawall.sarif
```

# Contributing

## The fastest useful contribution: a false positive

cryptoscope's precision is measured, published, and treated as a release gate. A reproducible false
positive is therefore one of the most valuable things you can send.

Open an issue with the file, the line, the rule ID (`CRYPTO-NNN`), and why the match is wrong.
If you cannot find the cited line in your editor, that is by definition a bug — invariant **P3**
promises every finding resolves to a real literal.

## Building

```bash
cd cryptoscope
cargo build --release --workspace
cargo test --workspace
```

Rust 1.96+. No other runtime is required — no JVM, Node, Python, or Docker.

## Before you open a pull request

The CI gate runs exactly these, and they run in this order because the cheap ones should fail first:

```bash
cargo fmt --all --check
cargo build --release --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

If you touched detection rules, **re-run the benchmark corpus and include the precision number**.
A rule change without a measurement is not a finished change — see `BENCHMARKING.md`.

## Writing rules

Rules live in `crates/core/data/rules/<lang>.toml` as two-layer extract-then-classify pairs:

- the **extract** layer is a tree-sitter S-expression query;
- the **classify** layer maps captured values to an `algorithm_id` from the algorithm table,
  a severity hint, and a SARIF message template.

Every rule is plain text and readable in under a minute. That is deliberate — the taxonomy being
auditable is the point of the project, so a rule that only its author can understand is a
regression even if it matches correctly.

Prefer a **narrow rule that fires in a real cryptographic context** over a broad one that matches an
identifier anywhere. Most historical false positives came from matching algorithm names inside
parser config arrays, test assertions, and generated protobuf enum tables.

## The four invariants

P1 no LLM at runtime · P2 no outbound network without `--allow-network` ·
P3 every finding resolves to a real `file:line` · P4 never execute the scanned code.

These are contractual. A change that touches one is a major version bump and needs discussion in an
issue first, not a pull request. Two are pinned by tests in `crates/cli/tests/mcp_integration.rs`.

## Style

Match the surrounding code. Explain *why* in comments, not *what* — the code already says what.
When you supersede something, delete the old path, its tests, and its imports in the same change.

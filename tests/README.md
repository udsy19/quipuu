# Tests

Until the Rust scaffold lands, "tests" means: every data file we ship parses, every cross-reference resolves, every claim in the knowledge base that has a machine-checkable invariant has one.

## Run

```bash
python3 tests/check.py
```

Exit 0 on success, 1 on failure. Colored pass/fail lines. Last run: **45 passed, 0 failed.**

## Dependencies

```bash
pip3 install --user toml jsonschema
```

## What it covers

1. **TOML parse** — all five operational data files (algorithm-table, oid-table, default-policy, rules/go.toml, rules/python.toml).
2. **JSON parse** — every schema and example in `knowledge/sources/` (bom-1.6, bom-1.7, cryptography-defs, the CBOM Protocol example, CBOMkit's rule schema).
3. **CBOM example validates** — the official `cbom-protocol-example.json` validates against `bom-1.7.schema.json` using Draft 7 JSON Schema semantics. (Pre-flight: the schema itself is metaschema-valid.)
4. **Referential integrity** — every `algorithm_id` in the OID table, rule files, and policy `classically_broken` list resolves to a real entry in `algorithm-table.toml`. Every `replacement` field resolves.
5. **Algorithm-table internal consistency** — `quantum_status` from the allowed set, `primitive` from the CycloneDX 1.7 enum, `nist_quantum_security_level` in 0..=6, every `PqcFinal` (non-hybrid) has a FIPS reference, every `BrokenByShor` has a `replacement`, OIDs are dotted decimal, every `BrokenByShor` has `nist_quantum_security_level == 0` (CycloneDX convention).
6. **OID table** — dotted decimal format, no duplicate OIDs.
7. **Default policy** — `risk_weights` sum to 100, `severity_bands` monotonically decreasing, `shelf_life_tags` reference defined buckets, `hndl_flag` uses valid quantum_status values, `algorithm_vulnerability` covers every quantum_status (the scorer can't crash on a status without a weight).
8. **Rules** — `severity_hint` from the allowed set, every regex in `when` clauses compiles.
9. **Knowledge-base cross-links** — every relative markdown link in `knowledge/**/*.md` (excluding `sources/` which contains third-party docs) resolves to an existing file. Every plain-text reference to `knowledge/sources/<file>` exists.
10. **Sources sanity** — CSV files have expected headers; PDF files start with `%PDF-` and are non-empty.

## Negative-case verification

Confirmed the suite actually fails when something is wrong: injected a dangling `algorithm_id` into the OID table, suite exited 1 with 2 specific failures. Restored, suite exited 0 with 45/45.

## What this does NOT yet test

- Tree-sitter S-expression queries — we don't have a tree-sitter Python binding installed, and validating them properly requires the actual grammars. When the Rust scaffold lands and tree-sitter is a real dependency, `cargo test` covers this.
- The classify rules' `when` clauses against real captures — same reason.
- Actual Rust code — there is none yet.

## When to add tests here

- Any new TOML data file under `knowledge/11-decisions/data/` → add to the `TOML_FILES` list, add structural checks.
- Any new claim in a knowledge file that's machine-checkable → encode it.
- Any new source artifact under `knowledge/sources/` → add a format-sanity check.

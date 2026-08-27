# Operational data files

These TOML files are the *what seawall ships with* — the static data its Rust code will deserialize. They live here (under decisions) because each one **implements** one or more decisions in `../README.md`. Validated 2026-06-15: all parse, all cross-references resolve.

| File | Implements | Contents (validated) |
|---|---|---|
| `algorithm-table.toml` | D-04, D-06 | 67 algorithm records: id, family, primitive, classical_security_bits, nistQuantumSecurityLevel, quantum_status, replacement, FIPS ref, OID. |
| `oid-table.toml` | D-09 | 57 OID → algorithm-id mappings: RSA/EC/Ed/DH/DSA/AES/SHA classical + ML-KEM (RFC 9935) + ML-DSA (RFC 9881) + SLH-DSA pure (RFC 9909). |
| `default-policy.toml` | D-05, D-10 | NIST IR 8547 IPD defaults: deprecation years, QuantumRiskScore weights, shelf-life buckets, severity bands, HNDL flagging rules, CI gate. |
| `rules/go.toml` | D-07 | 8 extract + 17 classify rules covering crypto/rsa, ecdsa, ed25519, tls, aes, md5/sha1, golang-jwt. |
| `rules/python.toml` | D-07 | 8 extract + 26 classify rules covering cryptography.hazmat (rsa/ec/ed/x/ciphers), hashlib, ssl, PyJWT, pycryptodome. |

## Referential integrity (automated check)

```
algorithm-table has 67 algorithm IDs
oid-table.toml: 57 entries, 0 dangling algorithm_id refs
rules/go.toml: 17 classify rules, 0 dangling algorithm_id refs
rules/python.toml: 26 classify rules, 0 dangling algorithm_id refs
algorithm-table: 0 dangling replacement refs
default-policy classically_broken: 6 entries, 0 missing from algorithm-table
```

Re-run with:

```bash
cd knowledge/11-decisions/data && python3 -c "
import toml
algos = {a['id'] for a in toml.load('algorithm-table.toml')['algorithm']}
for src, key in [('oid-table.toml', 'oid'), ('rules/go.toml', 'classify'),
                 ('rules/python.toml', 'classify')]:
    missing = [r for r in toml.load(src)[key]
               if r.get('algorithm_id') and r['algorithm_id'] not in algos]
    print(f'{src}: {len(missing)} dangling')
"
```

## How Claude Code will consume these

When the Rust scaffold lands:

1. The `core` crate will define structs that mirror these TOML shapes (`AlgorithmRecord`, `OidMapping`, `Policy`, `ExtractRule`, `ClassifyRule`).
2. `include_dir!` (or `include_str!` + `toml::from_str`) embeds these files into the binary at build time. No filesystem dependency at runtime.
3. The `--policy <file>` CLI flag overrides `default-policy.toml`; everything else is fixed in-binary.
4. `--rules <dir>` overrides the rule packs for adding language coverage without recompiling.

## Why TOML, not YAML

- **Cargo / pyproject convention** — Rust developers expect TOML config.
- **Stricter spec than YAML** — no surprise YAML 1.1 "no" → false, no significant whitespace, no anchors/refs ambiguity.
- **One canonical Rust parser** — `toml` crate is in the RustCrypto-adjacent core ecosystem.
- **Round-trip with CBOMkit's YAML** — the classify-layer shape mirrors `cryptobom-forge-cryptocheck_rules.yml` (in `knowledge/sources/`), so a YAML → TOML converter is a few hundred lines if we want to import third-party rule packs.

## Editing checklist

When changing one of these files:

1. Re-run the referential-integrity check above. Zero dangling references is the bar.
2. If you remove an `algorithm_id`, update the OID table and every rule file that uses it.
3. If `default-policy.toml` weights change, document the *why* in `../README.md` (this is observable behavior).
4. If NIST IR 8547 final lands with different years, change them only in `default-policy.toml` — every other file should be unaffected.

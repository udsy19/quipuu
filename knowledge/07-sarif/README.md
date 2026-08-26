# SARIF 2.1.0 — Knowledge File for cryptoscope

**Purpose**: Reference for the cryptoscope SARIF emitter (`report` package). Covers spec minimums, GitHub/GitLab ingestion quirks, CBOM cross-referencing, and fix objects.

**Primary sources**:
- OASIS SARIF v2.1.0 spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html
- GitHub Code Scanning SARIF support: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
- GitHub SARIF upload: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/uploading-a-sarif-file-to-github
- GitLab SAST: https://docs.gitlab.com/ee/user/application_security/sast/

---

## 1. File Envelope

**Extension**: `.sarif` (SHOULD per OASIS spec §3.2). `.sarif.json` is also valid.  
**MIME type**: `application/sarif+json` — IANA-registered.

**Schema URLs** — two exist; they are not the same document:

| Source | URL |
|---|---|
| OASIS canonical (spec §3.13.3, normative) | `https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json` |
| SchemaStore (commonly used, redirects) | `https://json.schemastore.org/sarif-2.1.0.json` |
| oasis-tcs GitHub mirror | `https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json` |

Use the OASIS canonical URL in `$schema` for strict conformance. GitHub accepts all three in practice.

**Minimum valid `sarifLog`** — JSON schema `required`: `["version", "$schema", "runs"]`

```json
{
  "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": []
}
```

---

## 2. Object Hierarchy and Required Fields

### 2.1 `sarifLog`

| Field | Schema required | Notes |
|---|---|---|
| `version` | YES | Must be string `"2.1.0"` |
| `$schema` | YES | URI string |
| `runs` | YES | Array of `run` objects; may be empty array by schema but useless |

### 2.2 `run`

| Field | Schema required | Notes |
|---|---|---|
| `tool` | YES | Contains `driver` |
| `results` | NO | Array of `result`; omit entirely if zero findings |
| `artifacts` | NO | Recommended for resolving `artifactLocation.index` |
| `invocations` | NO | Execution metadata |
| `runAutomationDetails.id` | NO | **Required by GitHub for multi-tool/multi-run uploads to the same commit**; must be unique per upload category |

### 2.3 `tool.driver` (toolComponent)

JSON schema `required`: `["name"]`

| Field | Required | Recommended | Notes |
|---|---|---|---|
| `name` | YES | — | E.g., `"cryptoscope"` |
| `version` | NO | YES | Semver string, e.g., `"0.1.0"` |
| `semanticVersion` | NO | YES | Same semver; GitHub uses this for rule versioning display |
| `informationUri` | NO | YES | Project URL |
| `rules` | NO | YES | Array of `reportingDescriptor`; if absent GitHub can't link results to rule metadata |

### 2.4 `tool.driver.rules[]` (reportingDescriptor)

JSON schema `required`: `["id"]`

| Field | Required | Recommended | Notes |
|---|---|---|---|
| `id` | YES | — | Rule identifier, e.g., `"CRYPTO-001"` |
| `name` | NO | YES | CamelCase short name, e.g., `"WeakRsaKeySize"` |
| `shortDescription.text` | NO | YES | One sentence; GitHub shows this in the rule panel |
| `fullDescription.text` | NO | YES | Paragraph; shown in expanded rule view |
| `helpUri` | NO | YES | Link to advisory / docs page |
| `defaultConfiguration.level` | NO | YES | One of `none`/`note`/`warning`/`error`; defaults to `"warning"` if absent |
| `properties.security-severity` | NO | YES for security tools | String `"0.0"`–`"10.0"`; enables GitHub Advanced Security severity buckets |
| `properties.tags` | NO | YES | Array of strings; e.g., `["security", "cryptography", "pqc"]` |

> **`security-severity` is a string, not a JSON number.** Use `"9.5"`, not `9.5`. GitHub rejects numeric values. (Source: GitHub SARIF support docs.)

### 2.5 `results[]`

JSON schema `required`: `["message"]`

| Field | Required | Recommended | Notes |
|---|---|---|---|
| `message.text` | YES (effectively) | — | Free text; `message.id` + `messageStrings` also valid |
| `ruleId` | NO (schema) | **MUST** (practice) | GitHub dedup depends on it; GitLab drops results without it |
| `level` | NO | YES | One of `none`/`note`/`warning`/`error`; defaults to rule's `defaultConfiguration.level`, then `"warning"` |
| `locations` | NO (schema) | **MUST** (practice) | Spec §3.27.12: SHOULD be present; code scanning UIs won't display without it |
| `partialFingerprints` | NO | YES | See §2.7 |
| `properties` | NO | YES | For custom data (e.g., CBOM bom-ref) |
| `fixes` | NO | Optional | See §6 |
| `relatedLocations` | NO | Optional | See §6 |

### 2.6 `locations[].physicalLocation`

```
physicalLocation
├── artifactLocation
│   ├── uri            (string; relative path preferred, e.g. "src/crypto/rsa.go")
│   ├── uriBaseId      (string; use "%SRCROOT%" for repo-root-relative paths)
│   └── index          (integer; index into run.artifacts[] — optional cross-ref)
└── region
    ├── startLine      (integer ≥ 1)  ← most important
    ├── startColumn    (integer ≥ 1)
    ├── endLine        (integer ≥ 1)
    ├── endColumn      (integer ≥ 1)
    └── snippet.text   (string; the actual source line/fragment)
```

- All `region` fields are optional by schema but `startLine` is universally expected.
- Use `uriBaseId: "%SRCROOT%"` so paths are portable regardless of where the scanner runs.
- `snippet.text` is shown inline in GitHub's code scanning UI — include it.

### 2.7 `partialFingerprints` (Spec §3.27.17)

A property bag (object) where keys are fingerprint algorithm names, values are strings. Spec defines it as *"a set of strings that contribute to the stable, unique identity of the result."*

**GitHub only uses `primaryLocationLineHash`** — confirmed by GitHub docs. The value is a hash of the relevant source line, stripped of leading/trailing whitespace and normalized.

```json
"partialFingerprints": {
  "primaryLocationLineHash": "a1b2c3d4e5f6a7b8"
}
```

If absent, the `upload-sarif` GitHub Action auto-computes it. For self-hosted or GitLab use, emit it explicitly.

**Recommended algorithm for cryptoscope**: SHA-256 of `(ruleId + ":" + normalized_snippet_text)`, truncated to 16 hex chars. This ensures stability across refactors that don't change the flagged line.

---

## 3. GitHub Code Scanning Ingestion Quirks

Source: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning

| Constraint | Value |
|---|---|
| Max file size (gzip-compressed) | **10 MB** |
| Max results per run (accepted) | **25,000** |
| Max results displayed (top N by severity) | **5,000** — extras silently dropped |
| Max rules per run | **25,000** |

### 3.1 `level` → GitHub UI severity

| SARIF `level` | GitHub UI label |
|---|---|
| `error` | Error |
| `warning` | Warning |
| `note` | Note |
| `none` | None (suppressed from default view) |

### 3.2 `security-severity` → GitHub Advanced Security severity

When `properties.security-severity` is set on a rule, the result is classified as a **security alert** and appears in the Security tab (not just the Code tab):

| `security-severity` value | GitHub bucket |
|---|---|
| `> 9.0` | Critical |
| `7.0` – `8.9` | High |
| `4.0` – `6.9` | Medium |
| `0.1` – `3.9` | Low |

> `security-severity` and `level` serve different axes: `level` drives the error/warning/note filter chip; `security-severity` drives the Critical/High/Medium/Low severity badge in the Security Alerts view. Set both.

### 3.3 Deduplication

GitHub deduplicates alerts using the combination of `ruleId` + `partialFingerprints.primaryLocationLineHash`. A finding is considered the same across commits if both match. Missing `primaryLocationLineHash` → GitHub computes it from the snippet; inconsistent snippet normalization can cause phantom duplicates.

### 3.4 Multi-upload (multiple SARIF files for the same commit)

Each SARIF upload must set `run.runAutomationDetails.id` to a unique string **or** pass a unique `category` to the upload action. Without this, subsequent uploads for the same commit/tool overwrite prior uploads.

### 3.5 Common rejection causes

- File exceeds 10 MB compressed
- `ruleId` absent from results
- `uri` scheme conflicts with configured source root
- Empty string where a non-empty string is required
- `results` count exceeds 25,000 per run
- `version` is not the string `"2.1.0"`

---

## 4. GitLab SAST Ingestion

Source: https://docs.gitlab.com/ee/user/application_security/sast/

### 4.1 GitLab ≤ 17.x — no native SARIF

GitLab's SAST pipeline expects the proprietary **`gl-sast-report.json`** format under `artifacts:reports:sast`. SARIF is not accepted at this path. Schema: https://gitlab.com/gitlab-org/security-products/security-report-schemas

To use SARIF with GitLab ≤ 17: convert to `gl-sast-report.json` using a community converter (e.g., `sarif-converter` or a custom jq transform). Not recommended — the GitLab format diverges significantly.

### 4.2 GitLab 18.11+ — native SARIF (feature flag)

GitLab 18.11 introduced `artifacts:reports:sarif` artifact type under feature flag `sarif_ingestion`. Pipeline config:

```yaml
cryptoscope:
  script:
    - cryptoscope scan --sarif --output cryptoscope.sarif ./
  artifacts:
    reports:
      sarif: cryptoscope.sarif
```

> **Caveat**: The feature flag `sarif_ingestion` was disabled by default at 18.11 launch. Check your GitLab instance's feature flag status before relying on this. For GitLab.com SaaS, check the GitLab changelog for the version when it was enabled by default.

### 4.3 GitLab severity resolution from SARIF

GitLab reads severity in priority order:
1. `rule.properties.security-severity` (float × 10 → 0–100 bucket)
2. `result.level` (`error` → High, `warning` → Medium, `note` → Low, `none` → Info)

`security-severity ≥ 9.0` → **Critical** in GitLab's model; `level: error` alone only maps to **High**.

### 4.4 Practical recommendation for cryptoscope

Target GitLab 18.11+ with `artifacts:reports:sarif`. For users on older GitLab, document that they should use the `--format gl-sast` flag (if cryptoscope adds one) or manually convert with `sarif-to-gl-sast`.

---

## 5. Linking SARIF Findings to CBOM Components

No established standard exists for cross-referencing SARIF results to an SBOM/CBOM. CodeQL's SARIF output does not reference any SBOM. Two mechanisms in the spec are suitable:

### 5.1 Option A — `result.properties` bag (recommended for cryptoscope)

Store the CBOM `bom-ref` directly in the result's property bag:

```json
"properties": {
  "cbom/bom-ref": "urn:cdx:rsa-keygen-component-uuid",
  "cbom/component-type": "cryptographic-asset",
  "cbom/algorithm": "RSA",
  "cbom/keySize": 2048
}
```

Pros: simple, survives any SARIF consumer, no spec extensions needed.  
Cons: consumers don't know how to interpret it without documentation.

### 5.2 Option B — SARIF Taxonomies (`run.taxonomies[]` + `result.taxa[]`)

Define a custom taxonomy named `"CBOM"` in `run.taxonomies[]`, add the component as a taxon, then reference it from each result via `result.taxa[]`. This is the formally correct SARIF mechanism for classification cross-references.

```json
"run": {
  "taxonomies": [{
    "name": "CBOM",
    "version": "1.0",
    "guid": "xxxxxxxx-...",
    "taxa": [
      { "id": "urn:cdx:rsa-keygen-component-uuid", "name": "RSA-2048 keygen in main.go" }
    ]
  }],
  "results": [{
    "taxa": [{
      "id": "urn:cdx:rsa-keygen-component-uuid",
      "toolComponent": { "name": "CBOM" }
    }]
  }]
}
```

Pros: formally correct, enables tooling to understand the cross-reference relationship.  
Cons: verbose; taxonomies must be reconstructed from the CBOM; no existing tooling consumes it.

**Decision**: Use Option A (property bag) for v0. It's readable, debuggable, and survives all consumers. Add an `x-cryptoscope` namespace prefix to avoid collisions: `"cryptoscope/cbom-ref"`.

---

## 6. `fix` Objects and `relatedLocations` for Crypto Migration

### 6.1 `fix` Object (Spec §3.55)

The `fix` object models an **auto-applicable code change**. JSON schema `required`: `["artifactChanges"]`.

For crypto migration, we usually **cannot** emit an auto-applicable `fix` because:
- The replacement algorithm requires coordinating key sizes, padding schemes, IV handling, etc.
- The fix location may differ from the detection location (e.g., cipher defined elsewhere).

### 6.2 Advisory-only fix recommendation

Use `fix.description` with an empty `artifactChanges` array? — **No**: the schema requires `artifactChanges` to be non-empty (minItems: 1).

**Correct convention for advisory-only fixes**: Do not use the `fix` object. Instead, use:

1. **`result.message.text`**: Include the recommendation in the message text itself.
2. **`rule.help.text` / `rule.help.markdown`**: Put the migration guidance in the rule's `help` field — this is specifically designed for remediation guidance that isn't auto-applicable.
3. **`relatedLocations[]`**: Point to related code locations (e.g., where the key is used, where the cert is validated) with descriptive `message.text` like `"All callsites that use this key must be updated"`.

```json
"rule": {
  "id": "CRYPTO-001",
  "help": {
    "text": "Replace RSA-2048 with ML-DSA-65 (FIPS 204) for post-quantum resistance. See https://cryptoscope.io/rules/CRYPTO-001",
    "markdown": "Replace RSA-2048 with **ML-DSA-65** (FIPS 204)..."
  }
}
```

If you do want to emit a `fix`, use it only when the replacement is mechanical and safe (e.g., updating a constant string `"AES-128"` → `"AES-256-GCM"`). Set `fix.description.text` to explain what the change does.

---

## 7. Working Example — Minimal Complete SARIF 2.1.0

One finding: RSA-2048 key generation in `main.go` line 42.

```json
{
  "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "cryptoscope",
          "version": "0.1.0",
          "semanticVersion": "0.1.0",
          "informationUri": "https://github.com/your-org/cryptoscope",
          "rules": [
            {
              "id": "CRYPTO-001",
              "name": "WeakRsaKeySize",
              "shortDescription": {
                "text": "RSA key size is below the post-quantum-safe threshold."
              },
              "fullDescription": {
                "text": "RSA-2048 provides approximately 112 bits of classical security but is vulnerable to Shor's algorithm on a sufficiently powerful quantum computer. NIST recommends migrating to ML-DSA (FIPS 204) or ML-KEM (FIPS 203) for new deployments and planning migration for existing ones."
              },
              "helpUri": "https://cryptoscope.io/rules/CRYPTO-001",
              "help": {
                "text": "Replace RSA-2048 with ML-DSA-65 (FIPS 204) for signatures or ML-KEM-768 (FIPS 203) for key encapsulation. See NIST SP 800-208 and NIST IR 8547.",
                "markdown": "Replace RSA-2048 with **ML-DSA-65** ([FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)) for signatures or **ML-KEM-768** ([FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)) for key encapsulation."
              },
              "defaultConfiguration": {
                "level": "error"
              },
              "properties": {
                "security-severity": "8.5",
                "tags": ["security", "cryptography", "pqc", "rsa", "key-size"]
              }
            }
          ]
        }
      },
      "runAutomationDetails": {
        "id": "cryptoscope/2024-01-15T10:30:00Z"
      },
      "results": [
        {
          "ruleId": "CRYPTO-001",
          "ruleIndex": 0,
          "level": "error",
          "message": {
            "text": "RSA key generated with 2048-bit modulus. RSA-2048 is not post-quantum safe. Recommended replacement: ML-DSA-65 (FIPS 204) for signatures."
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "main.go",
                  "uriBaseId": "%SRCROOT%"
                },
                "region": {
                  "startLine": 42,
                  "startColumn": 13,
                  "endLine": 42,
                  "endColumn": 45,
                  "snippet": {
                    "text": "privateKey, err := rsa.GenerateKey(rand.Reader, 2048)"
                  }
                }
              }
            }
          ],
          "partialFingerprints": {
            "primaryLocationLineHash": "a1b2c3d4e5f6a7b8"
          },
          "properties": {
            "cryptoscope/cbom-ref": "urn:cdx:f47ac10b-58cc-4372-a567-0e02b2c3d479",
            "cryptoscope/algorithm": "RSA",
            "cryptoscope/keySize": 2048,
            "cryptoscope/primitive": "signature",
            "cryptoscope/pqcStatus": "vulnerable",
            "cryptoscope/recommendedReplacement": "ML-DSA-65"
          }
        }
      ]
    }
  ]
}
```

**Validation**: This JSON is valid against the OASIS SARIF 2.1.0 JSON schema. Required fields at each level are satisfied: `sarifLog` has `version`+`$schema`+`runs`; `run` has `tool`; `tool.driver` has `name`; `rule` has `id`; `result` has `message`.

---

## 8. DECISIONS for cryptoscope/report SARIF Emitter

### 8.1 Severity mapping by finding class

| cryptoscope finding class | `level` | `security-severity` | GitHub bucket | Rationale |
|---|---|---|---|---|
| Algorithm broken (e.g., MD5, RC4, DES) | `error` | `"9.0"` | Critical | Exploitable today |
| Algorithm quantum-vulnerable, large-scale (RSA, ECDH, ECDSA) | `error` | `"8.5"` | High | Harvest-now-decrypt-later risk |
| Algorithm quantum-vulnerable, symmetric short-key (AES-128) | `warning` | `"6.5"` | Medium | Not immediately critical |
| Deprecated but not broken (e.g., SHA-1 outside signatures) | `warning` | `"4.0"` | Medium | Context-dependent risk |
| Compliance gap only (e.g., non-FIPS algorithm in FIPS scope) | `note` | `"3.0"` | Low | No direct exploitability |
| Informational / inventory-only | `none` | omit | — | Do not set `security-severity` |

### 8.2 `partialFingerprints` algorithm

Emit `primaryLocationLineHash` as:

```
hex(sha256(ruleId + ":" + strings.TrimSpace(snippet_text)))[:16]
```

- Stable across line number shifts (refactors that add/remove unrelated lines)
- Unstable when the flagged line actually changes — correct behavior for dedup
- If snippet is unavailable, fall back to `hex(sha256(ruleId + ":" + uri + ":" + strconv.Itoa(startLine)))[:16]`

### 8.3 CBOM cross-referencing

Put CBOM `bom-ref` in `result.properties["cryptoscope/cbom-ref"]`. Use `"urn:cdx:<uuid>"` format matching the CBOM component's `bom-ref`. Also include `cryptoscope/algorithm`, `cryptoscope/keySize`, `cryptoscope/primitive`, `cryptoscope/pqcStatus` as convenience fields.

Do not use SARIF taxonomies for CBOM linking in v0 — complexity is not justified until there are consumers that understand it.

### 8.4 Rule IDs

Use a `CRYPTO-NNN` scheme. Reserve ranges:

| Range | Category |
|---|---|
| CRYPTO-001–099 | Asymmetric algorithms (RSA, ECC, DH) |
| CRYPTO-100–199 | Symmetric algorithms and modes |
| CRYPTO-200–299 | Hash functions and MACs |
| CRYPTO-300–399 | Key derivation, RNG |
| CRYPTO-400–499 | Protocol-level findings (TLS version, cipher suite) |
| CRYPTO-500–599 | Certificate and PKI findings |
| CRYPTO-900–999 | Reserved / experimental |

### 8.5 `fix` objects

Do **not** emit `fix` objects for quantum-migration findings. Place remediation guidance in `rule.help.text` and `rule.help.markdown`. Reserve `fix` objects for mechanical, safe substitutions only (e.g., correcting a string constant like `"MD5"` → `"SHA-256"`).

### 8.6 GitLab support

- Target GitLab 18.11+ via `artifacts:reports:sarif`.
- Document the 18.11 feature flag requirement in the cryptoscope GitLab CI integration guide.
- Do not implement `gl-sast-report.json` output in v0.

### 8.7 `runAutomationDetails.id`

Always emit:
```json
"runAutomationDetails": {
  "id": "cryptoscope/<ISO8601-timestamp>"
}
```
Required for GitHub to correctly handle multiple SARIF uploads for the same commit (e.g., when running on multiple packages or languages in separate jobs).

### 8.8 Schema URL in `$schema`

Use the OASIS canonical URL:
```
https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json
```

### 8.9 Ambiguities / open questions

- **GitHub `level: none` display**: The GitHub docs list `note/warning/error` as the filter values. `none` is valid SARIF but its exact behavior in the GitHub UI (hidden vs. shown as "informational") is not explicitly documented. Use `none` only for pure inventory results; confirm display behavior empirically before shipping.
- **GitLab `sarif_ingestion` feature flag default**: Was disabled by default in 18.11 GA. Check GitLab changelog for the version where it was enabled by default on GitLab.com. Do not assume it's on.
- **`security-severity` on `result` vs `rule`**: The property lives on the **rule** (`tool.driver.rules[].properties["security-severity"]`), not on individual results. If the same rule ID covers different severity levels for different instances, use separate rule IDs.

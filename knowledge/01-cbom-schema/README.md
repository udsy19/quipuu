# CycloneDX CBOM Schema — Authoritative Reference

> All facts in this file are extracted **verbatim** from the canonical JSON Schema files saved in `knowledge/sources/`. Verified 2026-06-12. If anything here conflicts with `knowledge/sources/bom-1.6.schema.json`, the schema wins.

## Files in `knowledge/sources/`

| File | Purpose |
|---|---|
| `bom-1.6.schema.json` | CycloneDX 1.6 canonical schema (5,673 lines) |
| `bom-1.7.schema.json` | CycloneDX 1.7 canonical schema (6,700 lines) |
| `cryptography-defs.schema.json` | Standalone crypto definitions (master branch) |
| `cbom-protocol-example.json` | Official TLS 1.2 CBOM example from `CycloneDX/bom-examples` |

## TL;DR — load-bearing facts

1. The container field on a `cryptographic-asset` component is **`cryptoProperties`** (not `cryptographicProperties`).
2. The official `bom-examples/CBOM/Protocol/bom.json` uses **`specVersion: "1.7"`** — the ecosystem already moved.
3. **CycloneDX 1.6 and 1.7 share the same `cryptoProperties` top-level shape**: `{ assetType, algorithmProperties, certificateProperties, relatedCryptoMaterialProperties, protocolProperties, oid }`. The differences are *additive* and *inside* each sub-object — see §6 below.
4. **`componentEvidence.occurrences[]`** has these exact fields: `bom-ref, location, line, offset, symbol, additionalContext`. `location` is required. `line` is `integer ≥ 0`. This gives us full file+line+column-ish provenance for free.
5. **`componentEvidence.callstack.frames[]`** exists with `package, module, function, parameters, line, column, fullFilename` — we should emit this for AST-detected call sites, not just occurrences.
6. **Protocol → algorithm linkage** is done via `protocolProperties.cipherSuites[].algorithms` — a **bom-ref array** pointing at algorithm components (see §3, official example).
7. The `dependency` object supports **both `dependsOn` and `provides`** — `provides` is the "library implements this algorithm" relationship, valuable for the deps-scanner output.

---

## 1. Component-type enum (1.6 and 1.7 identical)

```
[application, framework, library, container, platform, operating-system,
 device, device-driver, firmware, file, machine-learning-model, data,
 cryptographic-asset]
```

13 values. `cryptographic-asset` is the one we set on every crypto finding.

## 2. `cryptoProperties.assetType` (1.6 and 1.7 identical)

```
enum: [algorithm, certificate, protocol, related-crypto-material]
```

Exactly four values. `assetType` is **required** when `cryptoProperties` is present.

## 3. Canonical CBOM example structure (from `CycloneDX/bom-examples`)

The official example models a **TLS 1.2 connection to google.com** as 8 cryptographic-asset components:

| bom-ref | assetType | Notes |
|---|---|---|
| `crypto/protocol/tls@1.2` | `protocol` | Top — TLS 1.2 with one cipher suite |
| `crypto/certificate/google.com@sha256:…` | `certificate` | X.509 cert; references `signatureAlgorithmRef` and `subjectPublicKeyRef` |
| `crypto/algorithm/sha-512-rsa@1.2.840.113549.1.1.13` | `algorithm` | RSA-PKCS1-1.5-SHA512 signature |
| `crypto/algorithm/rsa-2048@1.2.840.113549.1.1.11` | `algorithm` | RSA-2048 (referenced by the public key) |
| `crypto/algorithm/ecdh-curve25519@1.3.132.1.12` | `algorithm` | X25519 key-agree |
| `crypto/algorithm/aes-256-gcm@2.16.840.1.101.3.4.1.46` | `algorithm` | AES-256-GCM (`primitive: ae`) |
| `crypto/algorithm/sha-384@2.16.840.1.101.3.4.2.9` | `algorithm` | SHA-384 (`primitive: hash` implied via family) |
| `crypto/key/rsa-2048@…` | `related-crypto-material` | The actual 2048-bit public key |

**The convention:** `crypto/{algorithm|certificate|protocol|key}/{name}@{oid-or-hash}` for bom-refs.

**Protocol → cipher-suite → algorithm linkage** (verbatim from the example):

```json
"protocolProperties": {
  "type": "tls",
  "version": "1.2",
  "cipherSuites": [{
    "name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "algorithms": [
      "crypto/algorithm/ecdh-curve25519@1.3.132.1.12",
      "crypto/algorithm/rsa-2048@1.2.840.113549.1.1.1",
      "crypto/algorithm/aes-256-gcm@2.16.840.1.101.3.4.1.46",
      "crypto/algorithm/sha-384@2.16.840.1.101.3.4.2.9"
    ],
    "identifiers": ["0xC0", "0x30"]
  }],
  "cryptoRefArray": [
    "crypto/certificate/google.com@sha256:..."
  ]
}
```

The `algorithms` field is `array of refType` — bom-ref strings pointing at the algorithm components. This is the canonical way to express TLS cipher-suite composition. No top-level `dependencies` section is needed for this linkage.

## 4. `algorithmProperties` — full field list

### 4a. CycloneDX 1.6

```
[primitive, parameterSetIdentifier, curve, executionEnvironment,
 implementationPlatform, certificationLevel, mode, padding,
 cryptoFunctions, classicalSecurityLevel, nistQuantumSecurityLevel]
```

### 4b. CycloneDX 1.7 (adds two)

```
+ algorithmFamily   (string, e.g. "AES", "RSASSA-PKCS1", "ECDH", "SHA-2")
+ ellipticCurve     (string, replaces "curve" — both present in 1.7)
```

### 4c. Field-by-field reference

| Field | Type | Notes |
|---|---|---|
| `primitive` | enum (see §5) | The crypto primitive class. |
| `algorithmFamily` | string (1.7 only) | Free-form family label. Examples in the official CBOM: `"AES"`, `"RSASSA-PKCS1"`, `"ECDH"`, `"SHA-2"`. |
| `parameterSetIdentifier` | string | e.g. `"128"` for AES-128, `"256"` for SHA-256, `"SHA2-128s"` for SLH-DSA. |
| `curve` (1.6+) / `ellipticCurve` (1.7+) | string | Curve name. Spec recommends names from `https://neuromancer.sk/std/`. Example value: `"other/Curve25519"`. |
| `executionEnvironment` | enum | `[software-plain-ram, software-encrypted-ram, software-tee, hardware, other, unknown]`. |
| `implementationPlatform` | enum | `[generic, x86_32, x86_64, armv7-a, armv7-m, armv8-a, armv8-m, armv9-a, armv9-m, s390x, ppc64, ppc64le, other, unknown]`. |
| `certificationLevel` | array of enum | FIPS 140-1/2/3 levels 1-4 and CC-EAL 1-7 (+augmented variants), plus `none/other/unknown`. |
| `mode` | enum | `[cbc, ecb, ccm, gcm, cfb, ofb, ctr, other, unknown]`. |
| `padding` | enum | `[pkcs5, pkcs7, pkcs1v15, oaep, raw, other, unknown]`. |
| `cryptoFunctions` | array of enum (see §5) | What operations the algorithm performs. |
| `classicalSecurityLevel` | integer ≥ 0 | Classical security in bits. AES-256-GCM example: `256`. |
| `nistQuantumSecurityLevel` | integer 0–6 | NIST PQC category. `0` = none of the categories are met. AES-256-GCM example: `1`. SHA-384 example: `2`. RSA-PKCS1-SHA512 example: `0`. |

## 5. Key enums (verbatim)

### 5a. `primitive` — 1.6 has 15 values, 1.7 adds `key-wrap` (16 values)

**1.6:**
```
[drbg, mac, block-cipher, stream-cipher, signature, hash, pke, xof,
 kdf, key-agree, kem, ae, combiner, other, unknown]
```

**1.7:**
```
[drbg, mac, block-cipher, stream-cipher, signature, hash, pke, xof,
 kdf, key-agree, kem, ae, combiner, key-wrap, other, unknown]
```

`kem` is what we set for ML-KEM. `ae` is what we set for AES-GCM/ChaCha20-Poly1305 (authenticated encryption is a primitive, not a mode). `pke` is for RSA-OAEP. `key-agree` is for ECDH/X25519.

### 5b. `cryptoFunctions` — 13 values (1.6 and 1.7 identical)

```
[generate, keygen, encrypt, decrypt, digest, tag, keyderive,
 sign, verify, encapsulate, decapsulate, other, unknown]
```

For KEM: emit `[encapsulate, decapsulate]` (plus `keygen` if generation site detected).
For signatures: `[sign, verify]`.
For AEAD: `[encrypt, decrypt]`.

## 6. `certificateProperties` — 1.6 vs 1.7 (this is where the diff is big)

### 6a. 1.6 fields (8)

```
[subjectName, issuerName, notValidBefore, notValidAfter,
 signatureAlgorithmRef, subjectPublicKeyRef,
 certificateFormat, certificateExtension]
```

`signatureAlgorithmRef` and `subjectPublicKeyRef` are **bom-ref cross-references** to other crypto-asset components (see §3).

### 6b. 1.7 fields (19) — major superset

```
[serialNumber, subjectName, issuerName, notValidBefore, notValidAfter,
 signatureAlgorithmRef, subjectPublicKeyRef,
 certificateFormat, certificateExtension, certificateFileExtension,
 fingerprint, certificateState,
 creationDate, activationDate, deactivationDate, revocationDate, destructionDate,
 certificateExtensions,
 relatedCryptographicAssets]
```

New in 1.7:
- `serialNumber`, `fingerprint`, `certificateState`, `certificateExtensions` (a full X.509 extensions array, not just a file extension)
- Lifecycle dates: `creationDate, activationDate, deactivationDate, revocationDate, destructionDate`
- `relatedCryptographicAssets` (see §6c) — the new uniform mechanism for cert ↔ algorithm / cert ↔ key links

**1.7 deprecation note:** the spec recommends migrating from `signatureAlgorithmRef` / `subjectPublicKeyRef` to entries in `relatedCryptographicAssets`. However the old fields are **still present and valid** in the 1.7 schema — so a 1.6-style emission validates under 1.7.

### 6c. `relatedCryptographicAssets` (1.7 only)

```json
{
  "type": "array",
  "items": {
    "type": "object",
    "properties": {
      "type": {
        "type": "string",
        "examples": ["publicKey", "privateKey", "algorithm"]
      },
      "ref": { "$ref": "#/definitions/refType" }
    }
  }
}
```

`type` is **free-form string** (with examples — not an enum), `ref` is a bom-ref.

## 7. `relatedCryptoMaterialProperties` — for keys, IVs, nonces, etc.

`type` enum (18 values):
```
[private-key, public-key, secret-key, key, ciphertext, signature, digest,
 initialization-vector, nonce, seed, salt, shared-secret, tag,
 additional-data, password, credential, token, other, unknown]
```

Other fields: `id, state, algorithmRef, creationDate, activationDate, updateDate, expirationDate, value, size, format, securedBy`.

`state` enum (NIST SP 800-57 key states):
```
[pre-activation, active, suspended, deactivated, compromised, destroyed]
```

`securedBy` is a sub-object describing the mechanism that protects the material (HSM, software encryption, TPM, etc.) — useful for HNDL risk scoring.

## 8. `protocolProperties` — TLS / SSH / IPsec / IKE / SSTP / WPA

`type` enum (8 values):
```
[tls, ssh, ipsec, ike, sstp, wpa, other, unknown]
```

Fields: `type, version, cipherSuites, ikev2TransformTypes, cryptoRefArray`.

For TLS: `cipherSuites` is the right field (see §3 example).
For IKE: there's a dedicated `ikev2TransformTypes` sub-object with `encr, prf, integ, ke, esn, auth` — each is a `cryptoRefArray` (bom-ref array) per RFC 7296 / RFC 9370.

## 9. `componentEvidence` — the file+line provenance mechanism (full schema)

This is what got falsely refuted by the deep-research verifiers. The canonical schema **fully supports** file+line+symbol provenance.

```json
"componentEvidence": {
  "properties": {
    "identity": [...],
    "occurrences": {
      "type": "array",
      "items": {
        "required": ["location"],
        "properties": {
          "bom-ref": refType,
          "location": "string (required)",
          "line": "integer ≥ 0",
          "offset": "integer ≥ 0",
          "symbol": "string",
          "additionalContext": "string (e.g. a code snippet)"
        }
      }
    },
    "callstack": {
      "frames": [{
        "required": ["module"],
        "package": "string",
        "module": "string (required)",
        "function": "string",
        "parameters": "array of strings",
        "line": "integer",
        "column": "integer",
        "fullFilename": "string"
      }]
    },
    "licenses": [...],
    "copyright": [...]
  }
}
```

**For quipuu's emitter:**
- Every finding → an `occurrences[]` entry on the relevant component:
  - `location` = relative file path
  - `line` = 1-based line number from tree-sitter
  - `offset` = byte offset (we have this from tree-sitter)
  - `symbol` = the API name we matched (e.g. `rsa.GenerateKey`)
  - `additionalContext` = a 1–3 line snippet (sanitized)
- For high-confidence findings where we have full AST context, also emit `callstack.frames[]` with `package, module, function, line, column, fullFilename`.

## 10. `dependency` — the cross-component graph

```json
{
  "required": ["ref"],
  "properties": {
    "ref": refLinkType,
    "dependsOn": "array of refLinkType",
    "provides": "array of refLinkType"
  }
}
```

`provides` is documented verbatim as: *"a cryptographic library which implements a cryptographic algorithm. A component which implements another component does not imply that the implementation is in use."*

**For quipuu's emitter:**
- Use `dependsOn` for the protocol↔suite↔algorithm tree where the linkage isn't already captured inside `cipherSuites[].algorithms` (it usually is — see §3).
- Use `provides` to say "this library (component A) implements this algorithm (component B)", e.g. `openssl@3.2.0` provides `rsa-2048`, `aes-256-gcm`, etc. This is how the `scan-deps` output integrates with `scan-source` findings.

## 11. Where the official schema lives

| Resource | URL |
|---|---|
| 1.6 schema (JSON) | `https://github.com/CycloneDX/specification/blob/1.6/schema/bom-1.6.schema.json` |
| 1.7 schema (JSON) | `https://github.com/CycloneDX/specification/blob/master/schema/bom-1.7.schema.json` |
| Crypto defs (standalone) | `https://github.com/CycloneDX/specification/blob/master/schema/cryptography-defs.schema.json` |
| 1.6 JSON docs (human-readable) | `https://cyclonedx.org/docs/1.6/json/` |
| Official CBOM examples | `https://github.com/CycloneDX/bom-examples/tree/master/CBOM` |
| Cert use-case walkthrough | `https://cyclonedx.org/use-cases/cryptographic-certificate/` |

**Validators:**
- `sbom-utility` (CycloneDX official CLI validator) — multi-version, validates JSON BOMs against the schema. Use as the build oracle.
- `cyclonedx-go` library — typed structs; what IBM CBOMkit emits.
- `cyclonedx-python-lib` — Python lib used by `cryptobom-forge`.

## 12. ECMA standardization status

- **ECMA-424 1st Edition** = CycloneDX 1.6 (June 2024).
- **ECMA-424 2nd Edition** = CycloneDX 1.7 (December 2025).

**Why this matters for quipuu:** "ECMA-standardized format" is a positioning lever for the auditor-grade-report claim. We can say "ECMA-424 conformant" in the report header. To make that true under the 2nd Edition, we either target 1.7 or stamp `specVersion: "1.6"` (which is ECMA-424 1st Edition — also valid).

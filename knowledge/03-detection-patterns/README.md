# Detection Patterns for quipuu

> **Purpose**: Authoritative reference for rule design in the quipuu Rust/tree-sitter crypto scanner. Covers existing rule formats we can borrow, high-value API targets per language, parameter extraction patterns, and the competitive landscape.

---

## Table of Contents

1. [CBOMkit / Existing Rule Formats](#1-cbomkit--existing-rule-formats)
2. [High-Value Crypto APIs per Language](#2-high-value-crypto-apis-per-language)
3. [Parameter Extraction Patterns](#3-parameter-extraction-patterns)
4. [Cross-Language Considerations](#4-cross-language-considerations)
5. [State of Crypto Detection Beyond CBOMkit](#5-state-of-crypto-detection-beyond-cbomkit)
6. [Confidence Scoring](#6-confidence-scoring)
7. [Proposed quipuu Rule Schema](#7-proposed-quipuu-rule-schema)

---

## 1. CBOMkit / Existing Rule Formats

### 1.1 PQCA/cbomkit — No Declarative Rule Schema

**Why**: Understanding what to borrow (or avoid) from the primary OSS CBOM generator.

**Evidence**: CBOMkit (`github.com/PQCA/cbomkit`) is a Quarkus REST server that delegates detection entirely to `cbomkit-lib`, which in turn depends on `IBM/sonar-cryptography-plugin` (v1.5.1). There are **zero YAML or JSON detection rule files** in either cbomkit or cbomkit-lib. All rules are Java builder-DSL code in sonar-cryptography.

CBOMkit does include one policy file, not a detection rule:

```
opa/quantum_safe.rego
```

This OPA policy runs *post-scan* over already-detected CBOM components and classifies them as `quantum-safe`, `quantum-vulnerable`, or `unknown`. It checks `component.type == "cryptographic-asset"` and matches component names / OIDs against a whitelist (`"ml-kem"`, `"ml-dsa"`, `"slh-dsa"`, approved OIDs). This is a compliance layer, not detection.

**Takeaway**: Nothing in CBOMkit is directly borrowable as a detection rule format.

---

### 1.2 IBM/sonar-cryptography — Java Builder-DSL Rules

**Why**: This is the actual detection engine behind CBOMkit. Understanding its structure informs what a fully expressive rule schema must encode.

**Evidence**: Rules are constructed in Java using `DetectionRuleBuilder<Tree>`. Representative example (BouncyCastle CFB cipher):

```java
new DetectionRuleBuilder<Tree>()
    .createDetectionRule()
    .forObjectTypes("org.bouncycastle.crypto.modes.CFBBlockCipher")
    .forMethods("newInstance")
    .shouldBeDetectedAs(new ValueActionFactory<>("CFB"))
    .withMethodParameter("org.bouncycastle.crypto.BlockCipher")
        .addDependingDetectionRules(BcBlockCipherEngine.rules())
    .withMethodParameter("int")
        .shouldBeDetectedAs(new BlockSizeFactory<>(Size.UnitType.BIT))
        .asChildOfParameterWithId(-1)
    .buildForContext(new CipherContext(CipherContext.Kind.MODE))
    .inBundle(() -> "Bc")
    .withDependingDetectionRules(BcBlockCipherInit.rules());
```

Key builder primitives that any expressive rule schema must replicate:

| DSL method | Meaning |
|---|---|
| `forObjectTypes(String...)` | Match call receiver by type (includes subtypes) |
| `forObjectExactTypes(String...)` | Exact type only (no subtype widening) |
| `forMethods(String...)` | Method name |
| `forConstructor()` | Constructor call |
| `withoutParameters()` / `withAnyParameters()` | Arity guards |
| `withMethodParameter(String type)` | Named parameter at position |
| `shouldBeDetectedAs(IValueFactory)` | How to label the matched node |
| `addDependingDetectionRules(...)` | Recurse into a parameter's definition |
| `asChildOfParameterWithId(int)` | Attach extracted value as child of another parameter |
| `buildForContext(IDetectionContext)` | Assign semantic context: `CipherContext`, `KeyContext`, `SignatureContext`, `ProtocolContext`, `KemContext` |
| `inBundle(() -> "LibName")` | Library attribution |
| `withDependingDetectionRules(...)` | Top-level follow-on rules after this call |

Factory types for value extraction:

| Factory | Produces |
|---|---|
| `AlgorithmFactory` | String parameter → algorithm name |
| `KeySizeFactory(Size.UnitType.BIT)` | int parameter → key bit-length |
| `BlockSizeFactory(Size.UnitType.BIT)` | int parameter → block size |
| `ValueActionFactory<>(String label)` | Constant label regardless of parameter |
| `PaddingFactory` | Padding scheme name |
| `ModeFactory` | Cipher mode name |

Algorithm enrichers (post-detection) map detected nodes to CycloneDX OIDs. Example: `AESEnricher` maps AES + key size + mode → OID `2.16.840.1.101.3.4.1.*`.

**Concrete Go rule examples** (from `sonar-cryptography/go/src/main/java/com/ibm/plugin/rules/detection/gocrypto/`):

- `GoCryptoAES.java`: Detects `crypto/aes.NewCipher([]byte key)` → label `"AES"`, extract key size, chain to `GoCryptoCipherModes.rules()`
- `GoCryptoCipherModes.java`: Detects 10 `crypto/cipher` functions (`NewGCM`, `NewCBCEncrypter`, `NewCFBEncrypter`, `NewCTR`, `NewOFB`, etc.)
- `GoCryptoRSA.java`: Detects `rsa.GenerateKey(random, bits)` with `KeySizeFactory` on the int param
- `GoCryptoTLS.java`: Detects `tls.Dial`, `tls.Listen`, etc., chains to CONFIG rule for `cipher_suites`, `MinVersion`, `MaxVersion`
- `GoCryptoMLKEM.java`: Detects 12 `crypto/mlkem` functions for FIPS 203 (ML-KEM-768, ML-KEM-1024)

**Takeaway**: The Java DSL is expressive but not portable. Key ideas worth capturing in quipuu's YAML schema: context types (cipher/key/sign/tls/kem), recursive parameter dependencies, factory-based value extraction, library attribution.

---

### 1.3 cryptobom-forge — Declarative YAML/JSON (Borrowable)

**Why**: The only truly declarative rule schema in the ecosystem. We should be compatible with its pattern language for the post-detection classification layer.

**Source**: `github.com/Santandersecurityresearch/cryptobom-forge`

**Important caveat**: cryptobom-forge does NOT scan source code. It consumes CodeQL SARIF output and applies rules to `(algo, keylen, mode, padding)` tuples already extracted by CodeQL. Our scanner would produce those tuples natively, making the rule layer directly applicable.

#### Rule file: `cbom/resources/cryptocheck_rules.yml`

Array of rule objects. Complete field set (from `cryptocheck_schema.json`):

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes | Rule identifier |
| `detection.type` | enum | yes | `"error"` / `"warning"` / `"note"` |
| `detection.severity` | float 0–10 | yes | CVSS-like score |
| `detection.description` | string | yes | Human-readable explanation |
| `patterns[]` | list of tuple strings | yes | AND-conjunct match conditions |
| `default` | object (same as detection) | no | Fallback when no patterns match |

#### Pattern tuple format

Each pattern string is a Python-parseable tuple: `('field', 'operator', value)`

**Fields**: `algo`, `keylen`, `mode`, `padding`

**Operators**:

| Operator | Type | Meaning |
|---|---|---|
| `r` | string | Regex match |
| `s` | string | Substring contains |
| `eq` | string or int | Equals |
| `neq` | string or int | Not equals |
| `lt` | int | Less than |
| `gt` | int | Greater than |
| `lteq` | int | Less than or equal |
| `gteq` | int | Greater than or equal |

All patterns in a rule are AND-conjunct (all must match simultaneously).

#### Representative rules

```yaml
- name: MD5-detect
  detection:
    type: error
    severity: 9.0
    description: MD5 was detected, which is a deprecated hashing algorithm.
  patterns:
    - ('algo', 'r', '(?i)MD5')

- name: RSA-unsafe-key
  detection:
    type: warning
    severity: 5.0
    description: The RSA key was found to be too short.
  patterns:
    - ('algo', 'eq', 'RSA')
    - ('keylen', 'lt', 2048)

- name: AES-ECB-mode
  detection:
    type: error
    severity: 9.0
    description: AES was found operating in ECB mode.
  patterns:
    - ('algo', 's', 'AES')
    - ('mode', 's', 'ECB')
```

#### Algorithm taxonomy: `cbom/resources/library.yml`

Canonical lists (not detection rules — these are normalisation vocabularies):

- `algorithms`: 70+ names (AES, RSA, ECDH, Ed25519, ChaCha20, SHA-256, SHA-3, Kyber, Dilithium, …)
- `block_modes`: CBC, GCM, CTR, ECB, OFB, XTS, CCM, SIV, …
- `functions`: encrypt, decrypt, sign, verify, digest, keygen, keyderive, encapsulate, decapsulate
- `key_lengths`: 128, 192, 256, 384, 512, 1024, 2048, 3072, 4096
- `padding_schemes`: OAEP, PKCS1V15, PKCS7, NoPadding
- `primitive_mappings`: algorithm → CycloneDX primitive type (block_cipher, stream_cipher, hash, aead, signature, elliptic_curve, kdf, kem)

**Takeaway**: Adopt the `(field, operator, value)` pattern language for quipuu's classification layer. Extend the field set beyond the four cryptobom-forge fields to add `language`, `library`, `confidence`, `curve`, `iv_source`.

---

### 1.4 BF-CBOM (Boegli, ICPC 2026) — No New Format

**Why**: Referenced paper — verify whether it introduces a new detection rule format.

**Source**: https://romanboegli.ch/assets/pdf/Boegli_2026_BFCBOM_ICPC.pdf

**Evidence**: The paper does NOT describe a detection rule format. It is an orchestration and multi-tool comparison study that:

1. Runs CBOMKit v2.1.10, cdxgen v11.7.0, and CryptobomForge v1.1.0 in Docker containers behind a uniform message-driven interface
2. Applies n-way matching of their JSON CBOM outputs using the RaQuN algorithm (vector-space clustering with MiniLM-v2 sentence embeddings) to identify common and divergent findings
3. Tests a fourth "worker" using DeepSeek LLM (zero-shot) as an experimental CBOM generator

Key finding: the three tools almost never agree lexically on the same finding in the same repository. Runtimes range from seconds (CBOMKit) to minutes (CryptobomForge due to CodeQL dependency). CryptobomForge failed on several repos due to fragile toolchain setup.

**Takeaway**: Confirms the fragmentation problem quipuu addresses. No new schema to adopt.

---

## 2. High-Value Crypto APIs per Language

For each language: the API surface, the algorithm/parameter it implies, and the tree-sitter capture strategy.

Tree-sitter capture notation:
- `(call_expression function: (selector_expression ...) @fn)` — function call
- `(interpreted_string_literal) @str` — string literal argument  
- `(int_literal) @int` — integer literal argument
- `(identifier) @id` — bare name (lower confidence)

---

### 2.1 Go

| Priority | Package / Function | Algorithm / Parameter | tree-sitter capture |
|---|---|---|---|
| 1 | `crypto/rsa.GenerateKey(rand, bits)` | RSA; `bits` → key size | call on `rsa.GenerateKey`, arg[1] int literal → keylen |
| 2 | `crypto/ecdsa.GenerateKey(curve, rand)` | ECDSA; arg[0] → curve | call on `ecdsa.GenerateKey`, arg[0] selector → curve name |
| 3 | `crypto/ecdh.X25519().GenerateKey(rand)` | ECDH/X25519 | call on `ecdh.X25519` or `ecdh.P256/P384/P521` |
| 4 | `crypto/aes.NewCipher(key)` | AES; len(key)*8 → keylen | call on `aes.NewCipher` |
| 5 | `crypto/cipher.NewGCM(block)` | AES-GCM mode | call on `cipher.NewGCM` |
| 6 | `crypto/cipher.NewCBCEncrypter/Decrypter` | AES-CBC mode | call on `cipher.NewCBC*` |
| 7 | `crypto/cipher.NewCFBEncrypter/Decrypter` | AES-CFB mode | call on `cipher.NewCFB*` |
| 8 | `crypto/cipher.NewCTR` | AES-CTR mode | call on `cipher.NewCTR` |
| 9 | `crypto/des.NewCipher(key)` | DES (deprecated) | call on `des.NewCipher` |
| 10 | `crypto/des.NewTripleDESCipher(key)` | 3DES (deprecated) | call on `des.NewTripleDESCipher` |
| 11 | `crypto/md5.New()` / `crypto/md5.Sum(data)` | MD5 (deprecated) | call on `md5.New` or `md5.Sum` |
| 12 | `crypto/sha1.New()` / `crypto/sha1.Sum(data)` | SHA-1 (deprecated) | call on `sha1.New` or `sha1.Sum` |
| 13 | `crypto/sha256.New()` / `crypto/sha256.Sum256(data)` | SHA-256 | call on `sha256.New` or `sha256.Sum256` |
| 14 | `crypto/tls.Config{...}` | TLS; fields `MinVersion`, `MaxVersion`, `CipherSuites`, `Certificates` | struct literal with type `tls.Config`, capture field values |
| 15 | `crypto/tls.Dial(network, addr, config)` | TLS connection | call on `tls.Dial` / `tls.DialWithDialer` |
| 16 | `crypto/x509.ParseCertificate(data)` | X.509 handling | call on `x509.Parse*` |
| 17 | `crypto/x509.CreateCertificate(rand, template, parent, pub, priv)` | Cert issuance | call on `x509.CreateCertificate` |
| 18 | `golang.org/x/crypto/curve25519.*` | X25519 (legacy pkg) | call on `curve25519.*` |
| 19 | `golang.org/x/crypto/chacha20poly1305.New(key)` | ChaCha20-Poly1305 | call on `chacha20poly1305.New` |
| 20 | `crypto/mlkem.GenerateKey768/1024` | ML-KEM (FIPS 203) | call on `mlkem.GenerateKey*`, `mlkem.NewDecapsulationKey*` |

**JWT** (`github.com/golang-jwt/jwt`): `jwt.NewWithClaims(jwt.SigningMethodRS256, claims)` — capture the `SigningMethod*` selector to extract algorithm.

---

### 2.2 Python

| Priority | Module / Function | Algorithm / Parameter | tree-sitter capture |
|---|---|---|---|
| 1 | `cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key(public_exponent, key_size, backend)` | RSA; `key_size` → keylen | call on `rsa.generate_private_key`, keyword arg `key_size` |
| 2 | `cryptography.hazmat.primitives.asymmetric.ec.generate_private_key(curve, backend)` | ECDSA/ECDH; `curve` → EC curve | call on `ec.generate_private_key`, arg[0] class instantiation |
| 3 | `cryptography.hazmat.primitives.hashes.SHA256()` / `SHA384()` / `SHA512()` | Hash algorithm | class instantiation of `hashes.SHA*` |
| 4 | `cryptography.hazmat.primitives.hashes.MD5()` / `SHA1()` | MD5/SHA-1 (deprecated) | class instantiation of `hashes.MD5` or `hashes.SHA1` |
| 5 | `cryptography.hazmat.primitives.ciphers.algorithms.AES(key)` | AES; len(key)*8 → keylen | call on `algorithms.AES`, arg[0] byte literal |
| 6 | `cryptography.hazmat.primitives.ciphers.algorithms.TripleDES(key)` | 3DES (deprecated) | call on `algorithms.TripleDES` |
| 7 | `cryptography.hazmat.primitives.ciphers.modes.GCM(iv)` | AES-GCM | call on `modes.GCM` |
| 8 | `cryptography.hazmat.primitives.ciphers.modes.CBC(iv)` | AES-CBC | call on `modes.CBC` |
| 9 | `cryptography.hazmat.primitives.ciphers.modes.ECB()` | AES-ECB (dangerous) | call on `modes.ECB` |
| 10 | `cryptography.hazmat.primitives.ciphers.Cipher(algorithm, mode, backend)` | Cipher construction | call on `Cipher`, capture both args |
| 11 | `Crypto.PublicKey.RSA.generate(bits)` (pycryptodome) | RSA; `bits` → keylen | call on `RSA.generate`, arg[0] int literal |
| 12 | `Crypto.PublicKey.ECC.generate(curve='P-256')` (pycryptodome) | ECC; `curve` kwarg → curve | call on `ECC.generate`, keyword arg `curve` string |
| 13 | `Crypto.Cipher.AES.new(key, mode)` (pycryptodome) | AES; mode constant → mode | call on `AES.new`, arg[1] AES.MODE_* selector |
| 14 | `Crypto.Cipher.DES.new(key, mode)` (pycryptodome) | DES (deprecated) | call on `DES.new` |
| 15 | `Crypto.Cipher.DES3.new(key, mode)` (pycryptodome) | 3DES (deprecated) | call on `DES3.new` |
| 16 | `hashlib.md5(data)` / `hashlib.new('md5', data)` | MD5 | call on `hashlib.md5` or string arg `'md5'` to `hashlib.new` |
| 17 | `hashlib.sha1(data)` / `hashlib.new('sha1', data)` | SHA-1 | call on `hashlib.sha1` or string arg |
| 18 | `ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)` | TLS; protocol selector | call on `ssl.SSLContext`, arg[0] `ssl.PROTOCOL_*` selector |
| 19 | `ssl.SSLContext.set_ciphers(cipherlist)` | TLS cipher suite | call on `ctx.set_ciphers`, string arg (OpenSSL cipher string) |
| 20 | `hmac.new(key, msg, digestmod)` | HMAC; `digestmod` → hash | call on `hmac.new`, arg[2] or keyword `digestmod` |

**JWT** (`import jwt` / `PyJWT`): `jwt.encode(payload, key, algorithm='HS256')` — capture keyword arg `algorithm` string literal.

**hashlib.new safety**: Python 3.9+ `hashlib.md5(usedforsecurity=False)` is a legitimate non-security use (e.g., checksums). Emit with lower confidence when `usedforsecurity=False` is present.

---

### 2.3 Java

Java crypto is heavily string-driven. The key insight is that `getInstance(String)` methods accept a cipher specification string literal like `"AES/GCM/NoPadding"` or `"RSA"`. Detection requires both the call-site match AND string-literal parsing.

| Priority | Class + Method | Algorithm / Parameter | tree-sitter capture |
|---|---|---|---|
| 1 | `javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")` | AES-GCM; full spec string | call on `Cipher.getInstance`, string literal arg → parse `/`-separated spec |
| 2 | `javax.crypto.Cipher.getInstance("RSA/ECB/PKCS1Padding")` | RSA-PKCS1 | same; extract algo/mode/padding from string |
| 3 | `javax.crypto.Cipher.getInstance("DES/CBC/PKCS5Padding")` | DES-CBC | same |
| 4 | `java.security.KeyPairGenerator.getInstance("RSA")` | RSA keygen | call on `KeyPairGenerator.getInstance`, string arg |
| 5 | `java.security.KeyPairGenerator.getInstance("EC")` | EC keygen | same; curve from subsequent `initialize(new ECGenParameterSpec("secp256r1"))` |
| 6 | `java.security.KeyGenerator.getInstance("AES")` | AES key gen | call on `KeyGenerator.getInstance`, string arg |
| 7 | `java.security.MessageDigest.getInstance("MD5")` | MD5 | call on `MessageDigest.getInstance`, string arg |
| 8 | `java.security.MessageDigest.getInstance("SHA-1")` | SHA-1 | same |
| 9 | `java.security.MessageDigest.getInstance("SHA-256")` | SHA-256 | same |
| 10 | `java.security.Signature.getInstance("SHA256withRSA")` | RSA-PKCS1v15-SHA256 | call on `Signature.getInstance`, string arg → parse algorithm |
| 11 | `javax.net.ssl.SSLContext.getInstance("TLSv1")` | TLS 1.0 (deprecated) | call on `SSLContext.getInstance`, string arg |
| 12 | `javax.net.ssl.SSLContext.getInstance("TLSv1.2")` | TLS 1.2 | same |
| 13 | `javax.net.ssl.SSLContext.getInstance("SSL")` | SSL (deprecated) | same |
| 14 | `java.security.AlgorithmParameters.getInstance("RSA")` | RSA params | call on `AlgorithmParameters.getInstance` |
| 15 | `org.bouncycastle.crypto.generators.RSAKeyPairGenerator.init(RSAKeyGenerationParameters(..., 2048, ...))` | RSA 2048 (BC) | call on BC `RSAKeyPairGenerator.init`, parameter extraction |
| 16 | `org.bouncycastle.crypto.engines.AESEngine` (constructor) | AES (BC) | constructor call on BC AES types |
| 17 | `org.bouncycastle.crypto.modes.GCMBlockCipher.newInstance(engine)` | AES-GCM (BC) | call on `GCMBlockCipher.newInstance` |
| 18 | `org.bouncycastle.jce.provider.BouncyCastleProvider` registration | BC provider | `Security.addProvider(new BouncyCastleProvider())` |
| 19 | `com.auth0.jwt.JWT.create().withHeader(alg)` | JWT algorithm | method chain `JWT.create()...sign(Algorithm.*)` |
| 20 | `javax.crypto.Mac.getInstance("HmacSHA256")` | HMAC-SHA256 | call on `Mac.getInstance`, string arg |

**Cipher spec parsing**: A string argument to `Cipher.getInstance` is a `/`-delimited spec: `ALGORITHM/MODE/PADDING`. Parse to extract three fields. When the string is a variable (not a literal), classify as `confidence: medium`.

---

### 2.4 JavaScript / TypeScript

| Priority | Module / Function | Algorithm / Parameter | tree-sitter capture |
|---|---|---|---|
| 1 | `crypto.createCipheriv(algorithm, key, iv)` (node:crypto) | Cipher; `algorithm` string → algo/mode | call on `createCipheriv`, string literal arg[0] |
| 2 | `crypto.createDecipheriv(algorithm, key, iv)` (node:crypto) | Decipher | same |
| 3 | `crypto.createHash(algorithm)` (node:crypto) | Hash | call on `createHash`, string literal arg |
| 4 | `crypto.createHmac(algorithm, key)` (node:crypto) | HMAC | call on `createHmac`, string literal arg[0] |
| 5 | `crypto.generateKeyPair(type, options, callback)` (node:crypto) | Asymmetric keygen; `type` string → algo | call on `generateKeyPair`, string arg[0], options object |
| 6 | `crypto.generateKeyPairSync(type, options)` (node:crypto) | Same (sync) | same |
| 7 | `crypto.createSign(algorithm)` (node:crypto) | Signature | call on `createSign`, string arg |
| 8 | `crypto.createVerify(algorithm)` (node:crypto) | Signature verification | call on `createVerify`, string arg |
| 9 | `crypto.randomBytes(n)` (node:crypto) | CSPRNG (positive signal: using correct RNG) | call on `randomBytes` |
| 10 | `crypto.scrypt(password, salt, keylen, ...)` (node:crypto) | KDF-scrypt | call on `scrypt` |
| 11 | `subtle.generateKey({name: "RSA-OAEP", modulusLength: 2048, ...}, ...)` (Web Crypto) | RSA-OAEP; modulusLength → keylen | call on `subtle.generateKey`, object arg, extract `name` and `modulusLength` |
| 12 | `subtle.generateKey({name: "AES-GCM", length: 256}, ...)` (Web Crypto) | AES-GCM; `length` → keylen | same; extract `name` and `length` |
| 13 | `subtle.generateKey({name: "ECDSA", namedCurve: "P-256"}, ...)` (Web Crypto) | ECDSA P-256 | same; extract `namedCurve` |
| 14 | `subtle.encrypt({name: "AES-GCM", iv: ...}, key, data)` (Web Crypto) | AES-GCM encrypt | call on `subtle.encrypt`, object arg[0] `name` field |
| 15 | `subtle.sign({name: "ECDSA", hash: {name: "SHA-256"}}, ...)` (Web Crypto) | ECDSA-SHA256 | object arg extraction |
| 16 | `subtle.importKey("pkcs8", keyData, {name: "RSA-OAEP", ...}, ...)` (Web Crypto) | Key import | call on `subtle.importKey` |
| 17 | `tls.createSecureContext({ciphers: "...", secureProtocol: "..."})` (node:tls) | TLS config | call on `tls.createSecureContext`, object fields |
| 18 | `tls.connect({...minVersion: 'TLSv1.2'...})` (node:tls) | TLS connection | call on `tls.connect`, `minVersion` field |
| 19 | `jwt.sign(payload, secret, {algorithm: 'RS256'})` (jsonwebtoken) | JWT; `algorithm` option → signing alg | call on `jwt.sign`, options object `algorithm` field |
| 20 | `jwt.verify(token, secret, {algorithms: ['RS256']})` (jsonwebtoken) | JWT verification | call on `jwt.verify`, options `algorithms` array |

---

### 2.5 C / C++

| Priority | Library / Function | Algorithm / Parameter | tree-sitter capture |
|---|---|---|---|
| 1 | `RSA_generate_key_ex(rsa, bits, e, cb)` (OpenSSL legacy) | RSA; `bits` → keylen | call on `RSA_generate_key_ex`, arg[1] int literal |
| 2 | `EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL)` + `EVP_PKEY_keygen_init` + `EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits)` | RSA keygen (EVP); `bits` → keylen | call chain on `EVP_PKEY_CTX_set_rsa_keygen_bits` |
| 3 | `EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL)` | EC keygen | call on `EVP_PKEY_CTX_new_from_name`, string arg `"EC"` |
| 4 | `EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), ...)` | AES-256-GCM | call on `EVP_EncryptInit_ex`, arg[1] function call → captures cipher type |
| 5 | `EVP_EncryptInit_ex(ctx, EVP_des_cbc(), ...)` | DES-CBC (deprecated) | same; `EVP_des_cbc` selector |
| 6 | `EVP_DigestInit_ex(ctx, EVP_md5(), NULL)` | MD5 | call on `EVP_DigestInit_ex`, arg[1] `EVP_md5` |
| 7 | `EVP_DigestInit_ex(ctx, EVP_sha1(), NULL)` | SHA-1 | same; `EVP_sha1` selector |
| 8 | `EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)` | SHA-256 | same |
| 9 | `SSL_CTX_new(TLS_method())` / `SSL_CTX_new(SSLv23_method())` | TLS context | call on `SSL_CTX_new`, arg selector |
| 10 | `SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL:!MD5")` | TLS cipher suite string | call on `SSL_CTX_set_cipher_list`, string arg[1] (OpenSSL cipher string) |
| 11 | `SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)` | TLS min version | call on `SSL_CTX_set_min_proto_version`, constant arg[1] |
| 12 | `X509_new()` / `X509_sign(cert, pkey, digest)` | Certificate | call on `X509_sign`, capture digest arg |
| 13 | `crypto_box_keypair(pk, sk)` (libsodium) | X25519 + XSalsa20-Poly1305 | call on `crypto_box_keypair` |
| 14 | `crypto_sign_keypair(pk, sk)` (libsodium/NaCl) | Ed25519 **only if the file includes a NaCl header** (`sodium.h`, `sodium/*`, `tweetnacl.h`, `nacl/*`, `crypto_sign*.h`); otherwise no algorithm is asserted | call on `crypto_sign_keypair`, qualified by the file's `#include` set — the same name is the NIST PQC reference API, so ML-DSA and SLH-DSA reference code answers to it |
| 15 | `crypto_secretbox_easy(c, m, mlen, n, k)` (libsodium) | XSalsa20-Poly1305 AEAD | call on `crypto_secretbox_easy` |
| 16 | `crypto_kx_server_session_keys` / `crypto_kx_client_session_keys` (libsodium) | X25519 key exchange | call on `crypto_kx_*` |
| 17 | `mbedtls_rsa_init(ctx, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256)` (mbedTLS) | RSA-OAEP-SHA256 | call on `mbedtls_rsa_init`, padding + hash constants |
| 18 | `mbedtls_pk_setup(ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA))` (mbedTLS) | RSA PK | call on `mbedtls_pk_setup`, constant arg |
| 19 | `mbedtls_ssl_config_defaults(conf, endpoint, transport, preset)` (mbedTLS) | TLS config | call on `mbedtls_ssl_config_defaults` |
| 20 | `mbedtls_ssl_conf_min_version(conf, major, minor)` (mbedTLS) | TLS min version | call on `mbedtls_ssl_conf_min_version`, int args |

---

### 2.6 Rust

| Priority | Crate / Item | Algorithm / Parameter | tree-sitter capture |
|---|---|---|---|
| 1 | `ring::signature::EcdsaKeyPair::generate_pkcs8(alg, rng)` | ECDSA; `alg` → curve (ECDSA_P256_SHA256, etc.) | call on `EcdsaKeyPair::generate_pkcs8`, path arg |
| 2 | `ring::signature::Ed25519KeyPair::generate_pkcs8(rng)` | Ed25519 | call on `Ed25519KeyPair::generate_pkcs8` |
| 3 | `ring::aead::Aad` + `ring::aead::AES_256_GCM` / `ring::aead::CHACHA20_POLY1305` | AEAD; algorithm constant | use of `ring::aead::AES_256_GCM` or `CHACHA20_POLY1305` path |
| 4 | `ring::digest::digest(ring::digest::SHA256, data)` | SHA-256 | call on `ring::digest::digest`, constant arg |
| 5 | `ring::pbkdf2::derive(ring::pbkdf2::PBKDF2_HMAC_SHA256, ...)` | PBKDF2-HMAC-SHA256 | call on `ring::pbkdf2::derive`, algorithm path arg |
| 6 | `ring::agreement::agree_ephemeral(private_key, peer_public, ...)` | Key agreement | call on `ring::agreement::agree_ephemeral` |
| 7 | `rsa::RsaPrivateKey::new(rng, bits)` (rsa crate) | RSA; `bits` → keylen | call on `RsaPrivateKey::new`, int arg |
| 8 | `rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(key)` | RSA-PKCS1v15-SHA256 | type path captures algorithm from generic param |
| 9 | `ed25519_dalek::SigningKey::generate(rng)` (ed25519-dalek) | Ed25519 | call on `SigningKey::generate` in ed25519_dalek |
| 10 | `x25519_dalek::EphemeralSecret::random_from_rng(rng)` (x25519-dalek) | X25519 | call on `EphemeralSecret::random_from_rng` in x25519_dalek |
| 11 | `aes::Aes256::new(key)` (aes crate, RustCrypto) | AES-256 | call on `Aes256::new` or `Aes128::new`; type name encodes key size |
| 12 | `aes_gcm::Aes256Gcm::new(key)` (aes-gcm crate) | AES-256-GCM | call on `Aes256Gcm::new` or `Aes128Gcm::new` |
| 13 | `chacha20poly1305::ChaCha20Poly1305::new(key)` | ChaCha20-Poly1305 | call on `ChaCha20Poly1305::new` |
| 14 | `sha2::Sha256::digest(data)` / `Sha512::digest(data)` | SHA-2 | call on `sha2::Sha256::digest` or type-qualified variant |
| 15 | `sha1::Sha1::digest(data)` | SHA-1 (deprecated) | call on `sha1::Sha1::digest` |
| 16 | `md5::compute(data)` / `md5::Md5::new()` | MD5 (deprecated) | call on `md5::compute` |
| 17 | `hmac::Hmac::<sha2::Sha256>::new_from_slice(key)` | HMAC-SHA256 | type path — generic parameter encodes hash |
| 18 | `rustls::ClientConfig::builder()...with_safe_defaults()` | TLS (rustls) | method chain on `rustls::ClientConfig::builder()` |
| 19 | `rustls::ServerConfig::builder()...with_no_client_auth()` | TLS server | method chain on `rustls::ServerConfig::builder()` |
| 20 | `openssl::rsa::Rsa::generate(bits)` (openssl crate) | RSA; `bits` → keylen | call on `openssl::rsa::Rsa::generate`, int arg |

**Rust-specific note**: RustCrypto crates encode algorithm name and key size directly in the type name (`Aes256Gcm`, `Sha256`, etc.). The tree-sitter capture is a type path, not a call argument. This gives high-confidence detection without argument extraction.

---

### 2.7 C#

| Priority | Namespace / Class | Algorithm / Parameter | tree-sitter capture |
|---|---|---|---|
| 1 | `RSA.Create(keySize)` / `RSA.Create()` | RSA; `keySize` int arg | call on `RSA.Create`, int literal arg |
| 2 | `new RSACryptoServiceProvider(keySize)` | RSA; `keySize` constructor arg | constructor call, int arg[0] |
| 3 | `ECDsa.Create(ECCurve.NamedCurves.nistP256)` | ECDSA P-256 | call on `ECDsa.Create`, curve arg |
| 4 | `ECDiffieHellman.Create(ECCurve.NamedCurves.nistP384)` | ECDH P-384 | call on `ECDiffieHellman.Create` |
| 5 | `Aes.Create()` | AES (key size from `KeySize` property) | call on `Aes.Create` |
| 6 | `new AesManaged()` | AES (legacy) | constructor call on `AesManaged` |
| 7 | `TripleDES.Create()` / `new TripleDESCryptoServiceProvider()` | 3DES (deprecated) | call on `TripleDES.Create` |
| 8 | `DES.Create()` / `new DESCryptoServiceProvider()` | DES (deprecated) | call on `DES.Create` |
| 9 | `MD5.Create()` / `MD5.HashData(data)` | MD5 | call on `MD5.Create` or `MD5.HashData` |
| 10 | `SHA1.Create()` / `SHA1.HashData(data)` | SHA-1 | call on `SHA1.Create` or `SHA1.HashData` |
| 11 | `SHA256.Create()` / `SHA256.HashData(data)` | SHA-256 | call on `SHA256.Create` or `SHA256.HashData` |
| 12 | `SHA384.Create()` / `SHA384.HashData(data)` | SHA-384 | same |
| 13 | `SHA512.Create()` / `SHA512.HashData(data)` | SHA-512 | same |
| 14 | `RandomNumberGenerator.Create()` / `RandomNumberGenerator.GetBytes(n)` | CSPRNG | call on `RandomNumberGenerator.Create` |
| 15 | `new RNGCryptoServiceProvider()` | CSPRNG (deprecated) | constructor call |
| 16 | `HMACSHA256(key)` / `HMACSHA512(key)` | HMAC; type name → hash | constructor call on `HMAC*` |
| 17 | `new CspParameters { ProviderType = 1 }` | CAPI provider type (legacy) | constructor with `ProviderType` field |
| 18 | `RSA.ImportSubjectPublicKeyInfo(spki, out _)` | RSA key import | call on `RSA.Import*` |
| 19 | `JwtSecurityTokenHandler.CreateToken(new SecurityTokenDescriptor { SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256) })` | JWT RSA-SHA256 | `SecurityAlgorithms.*` constant capture |
| 20 | `new X509Certificate2(path, password)` | X.509 cert load | constructor call on `X509Certificate2` |

---

## 3. Parameter Extraction Patterns

### 3.1 Key Size from Integer Literal

**Why**: The single most important parameter for RSA/DH vulnerability assessment.

**Signal**: Call with an integer literal in the position known to be key size.

**Example**: `rsa.GenerateKey(rand.Reader, 2048)`

**tree-sitter query (Go)**:
```scheme
(call_expression
  function: (selector_expression
    operand: (identifier) @pkg (#eq? @pkg "rsa")
    field: (field_identifier) @fn (#eq? @fn "GenerateKey"))
  arguments: (argument_list
    (_)
    (int_literal) @keylen))
```

**Confidence**: `high` — integer literal is definitively known at scan time.

**Tradeoff**: If key size is a constant (`const RSAKeySize = 2048`) or variable, this query misses it. A secondary lower-confidence query should capture variable references.

**Variable-reference fallback (lower confidence)**:
```scheme
(call_expression
  function: (selector_expression
    operand: (identifier) @pkg (#eq? @pkg "rsa")
    field: (field_identifier) @fn (#eq? @fn "GenerateKey"))
  arguments: (argument_list
    (_)
    (identifier) @keylen_var))
```
This produces `confidence: medium` — we know a key size parameter is passed but cannot resolve its value statically.

---

### 3.2 Curve Name from Selector / Argument

**Why**: Curve name determines quantum vulnerability (P-256 is quantum-vulnerable; X25519 provides PFS but is still quantum-vulnerable).

**Example**: `ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`

**tree-sitter query (Go)**:
```scheme
(call_expression
  function: (selector_expression
    operand: (identifier) @pkg (#eq? @pkg "ecdsa")
    field: (field_identifier) @fn (#eq? @fn "GenerateKey"))
  arguments: (argument_list
    (call_expression
      function: (selector_expression
        operand: (identifier) @curve_pkg
        field: (field_identifier) @curve)) @curve_call
    (_)))
```

Captures `@curve_pkg` = `elliptic` and `@curve` = `P256`, `P384`, `P521`, `X25519`. `confidence: high` when the curve is a direct call like `elliptic.P256()`.

**Python equivalent** (`ec.generate_private_key(ec.SECP256R1(), backend)`):
```scheme
(call
  function: (attribute
    object: (identifier) @mod (#eq? @mod "ec")
    attribute: (identifier) @fn (#eq? @fn "generate_private_key"))
  arguments: (argument_list
    (call
      function: (attribute
        object: (identifier) @curve_mod
        attribute: (identifier) @curve)) @curve_call))
```

---

### 3.3 Cipher Spec String Parsing (Java)

**Why**: Java crypto is string-driven. The cipher specification string `"AES/GCM/NoPadding"` encodes algorithm, mode, and padding in one literal.

**tree-sitter query (Java)**:
```scheme
(method_invocation
  object: (identifier) @cls (#eq? @cls "Cipher")
  name: (identifier) @fn (#eq? @fn "getInstance")
  arguments: (argument_list
    (string_literal) @spec))
```

**Post-capture parsing**: Split `@spec` on `/`:
- index 0 → `algo` (e.g., `"AES"`, `"RSA"`, `"DES"`)
- index 1 → `mode` (e.g., `"GCM"`, `"CBC"`, `"ECB"`)
- index 2 → `padding` (e.g., `"NoPadding"`, `"PKCS1Padding"`, `"PKCS5Padding"`)

**Confidence levels**:
- String literal argument: `high`
- Named constant (e.g., `CIPHER_ALGO` from same file): `medium` (requires constant propagation)
- Variable argument: `low` (pattern fires, value unknown)

**Important strings to flag by algorithm component**:

| Algo | Mode | Padding | Risk |
|---|---|---|---|
| AES | GCM | NoPadding | safe AEAD |
| AES | CBC | PKCS5Padding | safe (check IV randomness separately) |
| AES | ECB | * | dangerous (deterministic) |
| AES | CBC | NoPadding | dangerous (CBC without MAC if no AEAD) |
| DES | * | * | deprecated algorithm |
| DESede | * | * | deprecated algorithm |
| RSA | ECB | PKCS1Padding | RSA-PKCS1v1.5 (vulnerable to Bleichenbacher) |
| RSA | ECB | OAEPWithSHA-256AndMGF1Padding | safe |
| Blowfish | * | * | deprecated algorithm |

---

### 3.4 Web Crypto API Algorithm Object (JavaScript)

**Why**: Web Crypto passes algorithm as a `{name: "...", ...}` object literal with optional `modulusLength`, `namedCurve`, `length` fields.

**tree-sitter query**:
```scheme
(call_expression
  function: (member_expression
    object: (identifier) @subtle (#eq? @subtle "subtle")
    property: (property_identifier) @fn)
  arguments: (arguments
    (object
      (pair
        key: (property_identifier) @key (#eq? @key "name")
        value: (string) @alg_name)
      (pair
        key: (property_identifier) @size_key (#any-of? @size_key "modulusLength" "length")
        value: (number) @key_size)?) @algo_obj))
```

Captures `@alg_name` (e.g., `"AES-GCM"`, `"RSA-OAEP"`, `"ECDSA"`), `@size_key`, and `@key_size`. This approach requires the object to be an inline literal; when it's a variable, confidence drops to `medium`.

---

### 3.5 Rust Type-Path Algorithm Detection

**Why**: RustCrypto crates encode algorithm name and parameters in the type name. No runtime string parsing needed.

**tree-sitter query (Rust)**:
```scheme
(call_expression
  function: (scoped_identifier
    path: (scoped_identifier) @crate_path
    name: (identifier) @method (#eq? @method "new"))
  arguments: (arguments (_) @key))
```

Match `@crate_path` against known patterns:
- `aes::Aes128` → AES-128
- `aes::Aes192` → AES-192
- `aes::Aes256` → AES-256
- `aes_gcm::Aes128Gcm` → AES-128-GCM
- `aes_gcm::Aes256Gcm` → AES-256-GCM
- `chacha20poly1305::ChaCha20Poly1305` → ChaCha20-Poly1305
- `sha1::Sha1` → SHA-1 (deprecated)
- `sha2::Sha256` → SHA-256

Confidence: `high` always — type identity is determined at compile time.

---

### 3.6 TLS Config Field Extraction

**Why**: TLS `MinVersion` and cipher suite configuration determine protocol vulnerability independently of the algorithm used.

**Go struct literal example**:
```go
tls.Config{
    MinVersion:   tls.VersionTLS12,
    CipherSuites: []uint16{tls.TLS_AES_128_GCM_SHA256},
}
```

**tree-sitter query (Go)**:
```scheme
(composite_literal
  type: (selector_expression
    operand: (identifier) @pkg (#eq? @pkg "tls")
    field: (field_identifier) @type (#eq? @type "Config"))
  body: (literal_value
    (keyed_element
      key: (literal_element (field_identifier) @field)
      value: (literal_element) @value)))
```

Captures each field-value pair. Fields of interest: `MinVersion`, `MaxVersion`, `CipherSuites`, `Certificates`, `InsecureSkipVerify`.

`InsecureSkipVerify: true` is high-confidence, high-severity regardless of algorithm.

---

## 4. Cross-Language Considerations

### 4.1 Hardcoded String Tables (Java / JS)

Many frameworks pass crypto algorithm selection through string constants. Beyond inline string literals, check:

1. **Enum-like constant classes**: Java code like `private static final String ALGORITHM = "AES/ECB/NoPadding"` → propagate the value when used in `Cipher.getInstance(ALGORITHM)`.
2. **Config files read at construction**: Correlate `properties.getProperty("cipher.algo")` patterns — emit as `confidence: low` with note about external configuration.
3. **Switch/case over algorithm names**: In custom crypto selector code, flag the entire set of possible strings.

### 4.2 JWT `alg:` Header Detection

JWT algorithm confusion is a critical class of vulnerability. Detection targets:

| Pattern | Risk |
|---|---|
| `algorithm: 'none'` | No signature — critical |
| `algorithm: 'HS256'` with asymmetric key input | Algorithm confusion attack |
| `algorithms: ['RS256', 'HS256']` in verify allowlist | Confusion attack surface |
| Missing `algorithms` option in `jwt.verify()` | Accepts any algorithm |

**Why**: Neither Semgrep nor CodeQL fully detect the RS256→HS256 confusion case. This requires checking that the `algorithms` allowlist in `verify()` does NOT include both an asymmetric algorithm and its HMAC equivalent simultaneously.

### 4.3 TLS Configuration Patterns

Track these across all languages:

| Field / Option | Language | Risk when set to |
|---|---|---|
| `InsecureSkipVerify` | Go | `true` — no cert validation |
| `ssl.check_hostname = False` | Python | insecure cert validation |
| `ssl.verify_mode = ssl.CERT_NONE` | Python | no cert validation |
| `MinVersion < TLS1_2_VERSION` | All | TLS 1.0 / 1.1 in use |
| `CipherSuites` includes RC4, DES, 3DES | All | weak cipher |
| `ALLOW_TLSv1` / `ALLOW_TLSv1_1` | OpenSSL | deprecated TLS |
| `rejectUnauthorized: false` | Node.js | no cert validation |
| `ServerCertificateValidationCallback = (...) => true` | C# | no cert validation |

### 4.4 Vendored Crypto Detection

Some projects vendor crypto libraries (copying source, not using package manager). Signal:

1. File paths matching `vendor/`, `third_party/`, `deps/`, `external/` containing crypto library headers or source (OpenSSL `include/openssl/rsa.h`, libsodium `src/libsodium/`)
2. Version comments in vendored headers (grep for `OPENSSL_VERSION_TEXT`, `SODIUM_VERSION_STRING`)
3. Emit both the vendored version AND the usage site when calling into vendored crypto — two findings per site

### 4.5 CA Bundle and Certificate Handling

Detect custom CA bundle injection (potentially weakening cert validation):

| Pattern | Language |
|---|---|
| `ssl.SSLContext.load_verify_locations(cafile=...)` | Python |
| `ssl.SSLContext.load_verify_locations(capath=...)` | Python |
| `x509.CertPool.AppendCertsFromPEM(pemBytes)` | Go |
| `SSL_CTX_load_verify_locations(ctx, cafile, capath)` | C/OpenSSL |
| `new X509Certificate2(customCaPath)` + add to store | C# |
| `tls.createSecureContext({ca: customCaBuffer})` | Node.js |

Emit as `confidence: medium`, severity `note` — custom CA bundles are not inherently wrong but warrant review.

---

## 5. State of Crypto Detection Beyond CBOMkit

### 5.1 Semgrep (semgrep-rules public repo)

**Coverage by language** (rule IDs from `github.com/semgrep/semgrep-rules`):

**Java** (`java/lang/security/audit/crypto/`):
- `des-is-deprecated`, `desede-is-deprecated` (CWE-326)
- `ecb-cipher`, `use-of-aes-ecb`, `use-of-default-aes` (CWE-327)
- `use-of-md5`, `use-of-sha1`, `use-of-sha224` (CWE-327/328)
- `use-of-blowfish`, `use-of-rc2`, `use-of-rc4` (CWE-327)
- `use-of-weak-rsa-key` (CWE-326)
- `rsa-no-padding` (CWE-326)
- `weak-random` (CWE-330)
- `no-static-initialization-vector`, `gcm-nonce-reuse` (CWE-329/323)
- `no-null-cipher`, `md5-used-as-password` (CWE-327)
- TLS/SSL: `insecure-hostname-verifier`, `insecure-trust-manager` (CWE-295), `weak-ssl-context`

**Python** (`python/lang/security/`):
- `insecure-hash-algorithm-sha1`, `insecure-hash-algorithm-md5` (CWE-327)
- `insecure-hash-function`, `sha224-hash`
- `unverified-ssl-context`, `weak-ssl-version` (CWE-295/326)
- `md5-used-as-password`

**Go** (`go/lang/security/audit/crypto/`):
- `use-of-md5`, `use-of-sha1`, `use-of-DES`, `use-of-rc4` (CWE-327/328)
- `use-of-weak-rsa-key` (CWE-326)
- `missing-ssl-minversion`, `tls-with-insecure-cipher` (CWE-327)
- `insecure-module-used`, `insecure_ssh`, `math-random`

**JavaScript**: Very sparse — `detect-pseudoRandomBytes` (CWE-338), `md5-used-as-password`.

**Semgrep severity / confidence encoding**:
```yaml
metadata:
  severity: WARNING           # ERROR | WARNING | INFO (almost all crypto = WARNING)
  subcategory:
  - vuln                      # "vuln" = confirmed vulnerable; "audit" = needs review
  likelihood: MEDIUM
  impact: MEDIUM
  confidence: HIGH            # LOW | MEDIUM | HIGH (independent axis)
  functional-categories:
  - 'crypto::search::symmetric-algorithm::javax.crypto'
```

Key signal: `subcategory: audit` with `confidence: LOW` = flag for manual review. `subcategory: vuln` with `confidence: HIGH` = directly actionable. Python's MD5 rule includes `pattern-not: hashlib.md5(..., usedforsecurity=False, ...)` as a precision guard.

### 5.2 CodeQL

**Java** (from `codeql/java-queries/Security/`):

| Query ID | Precision | Security Severity | Notes |
|---|---|---|---|
| `java/weak-cryptographic-algorithm` | high | 7.5 | Data-flow from getInstance string |
| `java/potentially-weak-cryptographic-algorithm` | medium | 7.5 | Variables, not only literals |
| `java/insufficient-key-size` | high | 7.5 | Tracks keysize through flow |
| `java/insecure-trustmanager` | high | 7.5 | TrustManager returning without checking |
| `java/missing-jwt-signature-check` | high | 7.8 | JWT verify without signature |
| `java/android/missing-certificate-pinning` | medium | 5.9 | Android-specific |

**Python**:

| Query ID | Precision | Security Severity |
|---|---|---|
| `py/weak-cryptographic-algorithm` | high | 7.5 |
| `py/insecure-protocol` | high | 7.5 |
| `py/insecure-default-protocol` | high | 7.5 |
| `py/weak-sensitive-data-hashing` | high | 7.5 |
| `py/weak-crypto-key` | high | 7.5 |
| `py/request-without-cert-validation` | medium | 7.5 |

**JavaScript**:

| Query ID | Precision |
|---|---|
| `js/weak-cryptographic-algorithm` | high |
| `js/insufficient-key-size` | high |
| `js/disabling-certificate-validation` | very-high |
| `js/jwt-missing-verification` | high |

**Go**:

| Query ID | Precision |
|---|---|
| `go/weak-cryptographic-algorithm` | high |
| `go/insecure-tls` | very-high |
| `go/weak-sensitive-data-hashing` | high |
| `go/missing-jwt-signature-check` | high |
| `go/disabled-certificate-check` | high |

**CodeQL query header format**:
```ql
/**
 * @name Use of a broken or risky cryptographic algorithm
 * @problem.severity warning           // error | warning | recommendation
 * @security-severity 7.5              // CVSS-style float
 * @precision high                     // low | medium | high | very-high
 * @id java/weak-cryptographic-algorithm
 * @tags security
 *       external/cwe/cwe-327
 */
```

`@precision` is the operative gate for GitHub Advanced Security default scans (only `high`/`very-high` appear).

### 5.3 What Semgrep and CodeQL Miss (quipuu's Opportunity Space)

1. **Post-Quantum Cryptography migration readiness**: Both tools have zero coverage of CNSA 2.0. Code using X25519, ECDH, or ECDSA passes clean despite quantum vulnerability. No checks for ML-KEM, ML-DSA, SLH-DSA adoption or absence.

2. **Algorithm confusion in JWT**: Both detect signature verification disabled. Neither detects the RS256→HS256 confusion attack (HMAC with public RSA key as secret), which requires checking that the `algorithms` allowlist in `verify()` does not contain both asymmetric and HMAC variants simultaneously.

3. **Unauthenticated encryption**: Neither flags AES-CBC without accompanying HMAC (vulnerable to padding oracle). Requires correlating a positive pattern (CBC mode) with an absent negative (no integrity check), which is beyond syntactic matching.

4. **Network context correlation**: `missing-ssl-minversion` fires on any `tls.Config{}` including test servers. Neither tool knows if an insecure TLS config is internet-facing. This is inherently hard with static analysis but can be partially addressed by detecting `localhost` / `127.0.0.1` in adjacent address strings.

5. **Dependency version awareness**: `missing-ssl-minversion` is a false positive for Go 1.22+ (TLS 1.2 is the new default). Neither tool reads `go.mod` or `pom.xml` to adjust expectations based on runtime defaults.

6. **Key lifecycle and reuse**: Neither detects keys derived from predictable seeds, keys reused across sessions (requires state analysis), or keys loaded from environment variables / config files (requires cross-file taint).

7. **Certificate revocation and chain depth**: Both detect obvious trust bypass (`return true` in `HostnameVerifier`, empty `checkServerTrusted`). Neither detects OCSP/CRL skipping, or chain validation stopping at the leaf cert.

8. **Crypto in dependencies vs. usage**: Neither tool produces a unified view correlating `pom.xml`/`go.mod` dependency (library version) with the actual API usage site and the resulting combined risk.

---

## 6. Confidence Scoring

### 6.1 The Three-Level Model

| Level | Meaning | Example |
|---|---|---|
| `high` | Argument is a literal constant known at parse time | `rsa.GenerateKey(rand, 2048)`, `Cipher.getInstance("AES/ECB/NoPadding")` |
| `medium` | Argument is a named constant or same-file variable with a traceable literal definition | `Cipher.getInstance(ALGO)` where `final String ALGO = "DES"` is in the same class |
| `low` | Argument is a runtime variable, function return value, or external input | `Cipher.getInstance(algoFromConfig)` |

### 6.2 How CodeQL Encodes This

CodeQL uses `@precision` with four levels: `low`, `medium`, `high`, `very-high`. The `java/potentially-weak-cryptographic-algorithm` query (`medium` precision) fires when the algorithm string flows through variables; `java/weak-cryptographic-algorithm` (`high` precision) fires only when the literal is directly traced.

Precision affects gate membership: GitHub Advanced Security includes only `high`/`very-high` by default.

### 6.3 How Semgrep Encodes This

Semgrep uses three separate orthogonal fields in `metadata`:
- `confidence: HIGH | MEDIUM | LOW` — how certain is this a true positive
- `likelihood: HIGH | MEDIUM | LOW` — how often is this pattern actually exploitable
- `impact: HIGH | MEDIUM | LOW` — severity of exploitation

The `subcategory: audit` value signals lower-confidence findings that require human review.

### 6.4 Proposed quipuu Confidence Encoding

```yaml
confidence: high    # literal-argument detection
confidence: medium  # constant/same-scope variable, requires light value propagation
confidence: low     # runtime variable, external config, taint sink only
```

Store in the SARIF `result.properties` map as `"confidence": "high"` alongside `"quipuu/keylen": "2048"` and `"quipuu/algo": "RSA"`.

Map confidence to SARIF `level`:
- `high` → `level: warning` (actionable)
- `medium` → `level: warning` (actionable with review note)
- `low` → `level: note` (informational)

---

## 7. Proposed quipuu Rule Schema

Based on the above research, the recommended rule format combines:
- **Detection layer** (tree-sitter): which call to match and how to extract values — not declarative in cryptobom-forge (it uses CodeQL for this), so we define our own
- **Classification layer** (YAML patterns): cryptobom-forge-compatible `(field, operator, value)` tuples applied to extracted values

### 7.1 Detection Rule Fields

```yaml
id: go-rsa-generate-key                    # unique kebab-case identifier
name: "RSA key generation (Go)"
languages: [go]
severity: warning                          # error | warning | note (maps to SARIF level)
confidence: high                           # high | medium | low (default for this rule)
cwe: [CWE-326]
tags: [asymmetric, keygen, quantum-vulnerable]
context: key_generation                    # cipher | key_generation | signature | tls | digest | mac | kem | kdf

# Detection: tree-sitter query
match:
  tree_sitter:
    language: go
    query: |
      (call_expression
        function: (selector_expression
          operand: (identifier) @pkg (#eq? @pkg "rsa")
          field: (field_identifier) @fn (#eq? @fn "GenerateKey"))
        arguments: (argument_list
          (_)
          [(int_literal) @keylen
           (identifier) @keylen_var])) @call
    require_import: "crypto/rsa"           # only fire if this import is present

# Value extraction: what to pull from captures
extract:
  algo:
    value: "RSA"                           # fixed string
  keylen:
    from_capture: "@keylen"
    type: integer
    confidence_if_present: high
    fallback_capture: "@keylen_var"
    fallback_confidence: medium

# Post-extraction classification patterns (cryptobom-forge compatible)
classify:
  - pattern: [('keylen', 'lt', 2048), ('algo', 'eq', 'RSA')]
    finding:
      type: error
      severity: 8.0
      message: "RSA key size {keylen} is below the 2048-bit minimum."
  - pattern: [('keylen', 'lt', 4096), ('algo', 'eq', 'RSA')]
    finding:
      type: warning
      severity: 4.0
      message: "RSA key size {keylen} is below the recommended 4096-bit size for new code."
  - pattern: [('algo', 'eq', 'RSA')]
    finding:
      type: note
      severity: 2.0
      message: "RSA is quantum-vulnerable; plan migration to ML-KEM or ML-DSA."

# CBOM output mapping
cbom:
  type: cryptographic-asset
  asset_type: related-crypto-material
  algorithm_type: signature               # CycloneDX cryptoProperties.algorithmProperties.primitive
  oid_base: "1.2.840.113549.1.1"         # RSA OID prefix
```

### 7.2 Multi-Language String-Driven Rule (Java Cipher.getInstance)

```yaml
id: java-cipher-getinstance
name: "Java Cipher.getInstance (all algorithms)"
languages: [java]
severity: warning
confidence: high
cwe: [CWE-327, CWE-326]
context: cipher

match:
  tree_sitter:
    language: java
    query: |
      (method_invocation
        object: (identifier) @cls (#eq? @cls "Cipher")
        name: (identifier) @fn (#eq? @fn "getInstance")
        arguments: (argument_list
          [(string_literal) @spec
           (identifier) @spec_var])) @call

extract:
  algo:
    from_capture: "@spec"
    parse: split("/", index=0)
    confidence_if_present: high
    fallback_capture: "@spec_var"
    fallback_confidence: low
  mode:
    from_capture: "@spec"
    parse: split("/", index=1)
    confidence_if_present: high
  padding:
    from_capture: "@spec"
    parse: split("/", index=2)
    confidence_if_present: high

classify:
  - pattern: [('mode', 'eq', 'ECB')]
    finding:
      type: error
      severity: 9.0
      message: "ECB mode is deterministic and leaks patterns."
  - pattern: [('algo', 'r', '(?i)DES')]
    finding:
      type: error
      severity: 9.0
      message: "DES/3DES is deprecated; use AES."
  - pattern: [('algo', 'eq', 'RSA'), ('padding', 'eq', 'PKCS1Padding')]
    finding:
      type: warning
      severity: 7.0
      message: "RSA PKCS1v1.5 padding is vulnerable to Bleichenbacher attacks; use OAEP."
```

### 7.3 Rule Library Organisation

```
quipuu/rules/
  go/
    crypto-rsa.yaml
    crypto-ecdsa-ecdh.yaml
    crypto-aes.yaml
    crypto-hash.yaml
    crypto-tls.yaml
    crypto-mlkem.yaml
  python/
    hazmat-asymmetric.yaml
    hazmat-ciphers.yaml
    hashlib.yaml
    ssl-context.yaml
    jwt.yaml
  java/
    javax-cipher.yaml
    java-security-keygen.yaml
    java-security-digest.yaml
    javax-ssl.yaml
    bouncy-castle.yaml
    jwt-auth0.yaml
  javascript/
    node-crypto.yaml
    web-crypto.yaml
    tls-config.yaml
    jwt-jsonwebtoken.yaml
  c-cpp/
    openssl-evp.yaml
    openssl-ssl.yaml
    libsodium.yaml
    mbedtls.yaml
  rust/
    ring.yaml
    rustcrypto.yaml
    rustls.yaml
    openssl-crate.yaml
  csharp/
    system-security-crypto.yaml
    jwt-microsoft.yaml
    x509.yaml
  classify/
    weak-algorithms.yaml    # shared cryptobom-forge-compatible classification rules
    key-sizes.yaml
    tls-versions.yaml
    pqc-migration.yaml      # quantum-vulnerability classification
```

---

## Sources and References

| Source | URL / Path | Notes |
|---|---|---|
| PQCA/cbomkit | `github.com/PQCA/cbomkit` | No declarative rules; OPA policy for compliance only |
| IBM/sonar-cryptography | `github.com/IBM/sonar-cryptography` | Java builder DSL; reference for rule expressiveness |
| sonar-cryptography docs | `.../docs/DETECTION_RULE_STRUCTURE.md` | Builder API documentation |
| cryptobom-forge | `github.com/Santandersecurityresearch/cryptobom-forge` | Declarative YAML schema; borrow classification layer |
| cryptobom-forge schema | `.../cbom/resources/cryptocheck_schema.json` | JSON Schema for rule validation |
| cryptobom-forge library | `.../cbom/resources/library.yml` | Canonical algorithm taxonomy |
| BF-CBOM paper (Boegli 2026) | `romanboegli.ch/assets/pdf/Boegli_2026_BFCBOM_ICPC.pdf` | Framework paper; no new rule format |
| semgrep-rules crypto | `github.com/semgrep/semgrep-rules` | 30+ rules Java/Python/Go; sparse JS |
| CodeQL queries | `github.com/github/codeql` | 5–8 queries per language; `@precision` gating |
| CycloneDX CBOM 1.6 | `bom-1.6.schema.json` (local) | Output schema for quipuu CBOM |

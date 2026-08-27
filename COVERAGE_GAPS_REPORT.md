# cryptoscope V3 Corpus — Coverage Gaps Report

**Corpus:** corpus-b-realworld (150 OSS projects, 577 total findings)
**Investigation date:** 2026-06-16
**Scope:** Five projects with zero findings despite well-known crypto usage

---

## Summary Table

| Project | Verdict | Root cause |
|---|---|---|
| `pypi:cryptography` | BLOCKED (corpus bug) | Clone is empty — symlink target failed during corpus collection |
| `pypi:paramiko` | BUG | Two scanner gaps: variable key_size and identifier curve argument |
| `pypi:pyjwt` | LEGITIMATE | Library internals; scanner correctly targets consumer call sites |
| `npm:crypto-js` | BUG | No `CryptoJS.*` namespace patterns in match_js_callee() or javascript.toml |
| `crates-io:ring` | LEGITIMATE | src/ contains function definitions, not call sites; call sites in excluded bench/tests |

---

## 1. `pypi:cryptography` — BLOCKED (corpus pipeline bug)

**Verdict: Cannot determine — clone is empty**

The clone at `benchmarks/corpus-b-realworld/clones/pypi/cryptography` is a broken symlink pointing to `benchmarks/corpus-b-realworld/clones/crypto-adjacent/pyca-cryptography`, which was never populated.

**Evidence from `benchmarks/corpus-b-realworld/clone.log`:**

```
pypi/cryptography -> crypto-adjacent/pyca-cryptography   [SYMLINK]
pyca-cryptography: unable to read tree (a63b4bcc0ef768f03d145e0913103bc75dc69223)
```

The corpus collection script failed to materialize the source tree for this commit SHA. There is no local source to scan, so a zero-finding result is a data-collection failure, not a scanner verdict.

**Fix:** Re-run the corpus clone step for `pyca-cryptography` to obtain a valid working tree. Once cloned, cryptography's hazmat layer (e.g., `src/cryptography/hazmat/primitives/asymmetric/rsa.py`) would be covered by the existing PY-001 rule — provided the call sites use integer literals for key sizes.

---

## 2. `pypi:paramiko` — BUG

**Verdict: Two scanner gaps miss real findings**

### Gap A — RSA key generation with a variable key size

**File:** `benchmarks/corpus-b-realworld/clones/pypi/paramiko/paramiko/rsakey.py:184`

```python
key = rsa.generate_private_key(
    public_exponent=65537, key_size=bits, backend=default_backend()
)
```

The PY-001 rule targets `rsa.generate_private_key` and is matched by `match_python_callee()` at `scanner.rs:431`. The callee string `"rsa.generate_private_key"` is recognized. However, the extract step then calls `python_keyword_int()` at `scanner.rs:873` to read the `key_size` argument:

```rust
// scanner.rs:880
return node_text(kw_val, source).parse::<i64>().ok();
```

`bits` is an identifier (variable), not an integer literal. `"bits".parse::<i64>()` returns `Err`, so `python_keyword_int()` returns `None`. The `key_size` field is absent from the raw match, and the classify step produces no finding.

**Fix:** In `python_keyword_int()`, when the keyword argument value is an `identifier` node rather than an `integer` node, emit the identifier name as a symbolic value (e.g., `ArgValue::Identifier(String)`) and update the classify rules to treat a symbolic key size as a separate finding class (e.g., "key size is runtime-variable — cannot verify").

### Gap B — EC key generation with an identifier curve argument

**File:** `benchmarks/corpus-b-realworld/clones/pypi/paramiko/paramiko/ecdsakey.py:268`

```python
private_key = ec.generate_private_key(curve, backend=default_backend())
```

The PY-010 rule targets `ec.generate_private_key`. The callee is matched by `match_python_callee()` at `scanner.rs:434`. The extract step then calls `python_first_arg_call_method()` at `scanner.rs:887` to read the curve:

```rust
// scanner.rs:890
if child.kind() == "call" {
```

`curve` is an `identifier` node, not a `call` node. The function only handles the case where the first argument is a call expression like `ec.SECP256R1()`. An identifier passes straight through and returns `None`, so no curve is extracted and the classify step produces no finding.

**Fix:** Extend `python_first_arg_call_method()` to also handle `identifier` nodes as the first positional argument, emitting the identifier name as a symbolic value. Update PY-010 (or add PY-011) in `cryptoscope/crates/core/data/rules/python.toml` to classify calls where the curve argument is a runtime variable.

---

## 3. `pypi:pyjwt` — LEGITIMATE

**Verdict: Zero findings is correct behavior**

pyjwt is a JWT *library*. The scanner is designed to flag crypto API *consumer* call sites. pyjwt never calls `jwt.encode(payload, key, algorithm='RS256')` on itself — that is the API it exposes to downstream callers.

Internally, pyjwt:

- Registers algorithm names as dict keys, not in function calls:
  `benchmarks/corpus-b-realworld/clones/pypi/pyjwt/jwt/algorithms.py:154–166`
  ```python
  "RS256": RSAAlgorithm(RSAAlgorithm.SHA256),
  "ES256": ECAlgorithm(ECAlgorithm.SHA256),
  ```
- Signs via opaque key objects, not named crypto API calls:
  `jwt/algorithms.py:597`: `key.sign(msg, padding.PKCS1v15(), self.hash_alg())`
  `jwt/algorithms.py:675`: `der_sig = key.sign(msg, ECDSA(self.hash_alg()))`
- Exposes `encode` as a module-level alias:
  `benchmarks/corpus-b-realworld/clones/pypi/pyjwt/jwt/api_jwt.py:591`
  ```python
  encode = _jwt_global_obj.encode
  ```
  This is an attribute reference, not a call — `match_js_callee()` would never see it.

No fix needed. If the goal were to flag use of deprecated JWT algorithms *within library implementations*, that would require a separate rule class targeting method dispatch tables, which is a different problem scope.

---

## 4. `npm:crypto-js` — BUG

**Verdict: Entire crypto-js namespace is invisible to the scanner**

crypto-js exposes its API under the `CryptoJS` namespace (internally `C`). Each algorithm is registered as a helper in its own source file:

| Algorithm | File | Line |
|---|---|---|
| `C.AES` (→ `CryptoJS.AES.encrypt`) | `src/aes.js` | 213 |
| `C.DES` (→ `CryptoJS.DES.encrypt`) | `src/tripledes.js` | 705 |
| `C.TripleDES` (→ `CryptoJS.TripleDES.encrypt`) | `src/tripledes.js` | 758 |
| `C.RC4` (→ `CryptoJS.RC4.encrypt`) | `src/rc4.js` | 85 |
| `C.MD5` (→ `CryptoJS.MD5(msg)`) | `src/md5.js` | 231 |
| `C.HmacMD5` | `src/md5.js` | 247 |
| `C.SHA1` (→ `CryptoJS.SHA1(msg)`) | `src/sha1.js` | 113 |
| `C.HmacSHA1` | `src/sha1.js` | 129 |

User-facing call sites look like:
```js
CryptoJS.AES.encrypt(message, key)
CryptoJS.DES.encrypt(message, key)
CryptoJS.MD5(message)
CryptoJS.HmacSHA1(message, key)
```

These are nested member expressions: `CryptoJS.AES.encrypt` parses as `(member_expression object:(member_expression object:CryptoJS property:AES) property:encrypt)`.

`match_js_callee()` at `scanner.rs:607` matches only one-level `object.method` strings:

```rust
// scanner.rs:609-617
"crypto.createCipheriv" => "node:crypto.createCipheriv",
"crypto.createHash"     => "node:crypto.createHash",
...
"jwt.sign"              => "jsonwebtoken.jwt.sign",
_ => return None,
```

There are no entries for `CryptoJS.AES.encrypt`, `CryptoJS.DES.encrypt`, `CryptoJS.MD5`, etc. The two-level member expression callee also requires the scanner's callee-extraction logic to handle `object.object.method` chains, which the current extract path does not.

**Fix:**
1. Extend the JS callee extractor to flatten two-level member expressions (e.g., `CryptoJS.AES.encrypt` → callee string `"CryptoJS.AES.encrypt"`).
2. Add entries to `match_js_callee()` in `scanner.rs`:
   - `"CryptoJS.DES.encrypt"` → weak symmetric cipher (DES)
   - `"CryptoJS.TripleDES.encrypt"` → 3DES (weak, but stronger than DES)
   - `"CryptoJS.RC4.encrypt"` → broken stream cipher
   - `"CryptoJS.MD5"` → weak hash
   - `"CryptoJS.SHA1"` → weak hash
   - `"CryptoJS.HmacMD5"`, `"CryptoJS.HmacSHA1"` → weak HMAC
3. Add corresponding classify rules to `cryptoscope/crates/core/data/rules/javascript.toml`.

---

## 5. `crates-io:ring` — LEGITIMATE

**Verdict: Zero findings is correct behavior**

ring is a Rust crypto *library*. The scan_hints TOML (`benchmarks/corpus-b-realworld/ecosystems/crates-io/ring.toml`) scans only `src/` and excludes `tests/` and `bench/`.

The `src/` tree contains the *definitions* of `EcdsaKeyPair::generate_pkcs8` and `Ed25519KeyPair::generate_pkcs8`:

- `benchmarks/corpus-b-realworld/clones/crates-io/ring/src/ec/suite_b/ecdsa/signing.rs:80`
  ```rust
  pub fn generate_pkcs8(alg: &'static EcdsaSigningAlgorithm, rng: &dyn rand::SecureRandom)
      -> Result<pkcs8::Document, error::Unspecified>
  ```
- `benchmarks/corpus-b-realworld/clones/crates-io/ring/src/ec/curve25519/ed25519/signing.rs:49`
  ```rust
  pub fn generate_pkcs8(rng: &dyn rand::SecureRandom)
      -> Result<pkcs8::Document, error::Unspecified>
  ```

`match_rust_callee()` at `scanner.rs:638` looks for call expressions using these types. Function definitions are `function_item` nodes in tree-sitter, not `call_expression` nodes, so they produce no matches. The actual call sites (`bench/ecdsa.rs`, `tests/ed25519_tests.rs`) are in excluded paths. This is the expected behavior for a library repo.

No fix needed. ring in `src/` is definitionally correct: zero call sites for a library's own API in its own implementation.

---

## Scanner Bugs Requiring Fixes (Actionable)

| ID | Project | File | Fix location |
|---|---|---|---|
| BUG-1 | paramiko | `rsakey.py:184` — `key_size=bits` (variable) | `scanner.rs:873` `python_keyword_int()` — handle identifier values |
| BUG-2 | paramiko | `ecdsakey.py:268` — `ec.generate_private_key(curve, ...)` (identifier arg) | `scanner.rs:887` `python_first_arg_call_method()` — handle identifier nodes |
| BUG-3 | crypto-js | `src/aes.js:213`, `tripledes.js:705,758`, `rc4.js:85`, `md5.js:231,247`, `sha1.js:113,129` | `scanner.rs:607` `match_js_callee()` + `javascript.toml` — add CryptoJS.* entries |
| DATA-1 | cryptography | Clone is empty | Corpus pipeline — re-clone pyca/cryptography at SHA `61b250ac42af` |

# seawall V8 — 150-project corpus benchmark

**Corpus:** corpus-b-realworld  
**Projects scanned:** 150  
**Elapsed:** 23.3s  
**Default filter:** quantum-safe inventory hidden from alert output (Phase 2; pass --include-safe to unhide)  

This is the V8 corpus run, layered on Phases 1-11 (jjwt enum constants, signal-to-noise, ACVP refresh, why-this-matters, non-fatal warnings, Go switch / registration, paramiko + crypto-js, Rust qualified paths + turbofish, pbkdf2 nested turbofish) plus Phase 12 (precision audit — measured 73.3% precision on a stratified 31-finding sample) and Phase 13 (closing the 8 audit-surfaced false-positive patterns: TLS-config topology markers, jwt-alg-none sentinel, per-variant PSS / HMAC / ECDSA / AES-ECB algorithm_ids, plus a CI consistency guard). Numbers below are stratified by ecosystem and reported without projected values — only what was actually scanned.

## Headline numbers

- **1194 total findings** across 150 projects in 23.3s
- **864 audible** (72%) surfaced for analyst review; **330 suppressed** (28%) as quantum-safe inventory
- **55 / 150 projects** produced at least one finding; **9 / 150** had scan errors (mostly missing clones — see below)
- **Avg scan time:** 0.16s per project (release build, single-threaded)

### Phase 1 verification — Java JWT libraries now produce findings

Pre-Phase-1 (the V2 corpus run), these projects produced **zero** findings because the scanner only walked `method_invocation` / `object_creation_expression` and missed every `SignatureAlgorithm.RS256`-style enum-constant reference. After the field_access walk fix (commit 5223e3a):

- `maven:com.nimbusds:nimbus-jose-jwt` — **78 findings** (was 0)
- `maven:org.bitbucket.b_c:jose4j` — **15 findings** (was 0)

### Phase 2 verification — noise filter hides QuantumSafe inventory

`crates-io:rustls`: 16 total findings, of which **0 audible** and **16 suppressed** as quantum-safe (AES-256-GCM, ChaCha20-Poly1305, SHA-256, etc.). Before Phase 2 (commit 943dcda) every one of those would have been a Medium-severity alert competing for the user's attention.

### Phase 9 verification — Go JWT libraries now produce findings

Pre-Phase-9 (the V4 corpus run), these canonical Go JWT libraries produced **zero** findings. Phase 7 only detected `switch alg { case "RS256": ... }`, but real-world Go libraries register algorithm names via composite literals, call-as-constructor, or const declarations. Phase 9's literal-in-registration-context detector (commit cde3d4c) closes the gap:

- `go-modules:github.com/dgrijalva/jwt-go` — **38 findings** (was 0)
- `go-modules:github.com/go-jose/go-jose` — **65 findings** (was 0)
- `go-modules:github.com/golang-jwt/jwt` — **46 findings** (was 0)
- `go-modules:github.com/lestrrat-go/jwx` — **219 findings** (was 0)

### Phase 10 verification — Rust opaque-type APIs now produce findings

Pre-Phase-10 (the V5 corpus run), these crates-io projects produced **zero** findings. `match_rust_callee` did exact-string matching on the full scoped_identifier text, so qualified paths like `sha2::Sha256::digest` and turbofish forms like `SigningKey::<Sha256>::new` were invisible. Phase 10's normalize_rust_callee + extract_turbofish_inner (commit f9f2760) plus five new classify rules close the gap:

- `crates-io:p256` — **1 findings** (was 0)
- `crates-io:p384` — **1 findings** (was 0)
- `crates-io:rsa` — **15 findings** (was 0)
- `crates-io:rustls-webpki` — **12 findings** (was 0)
- `crates-io:webpki` — **12 findings** (was 0)

### Phase 11 verification — pbkdf2 turbofish detection

Pre-Phase-11 (the V6 corpus run), pbkdf2 and scrypt produced **zero** findings. Their public API encodes the hash entirely in a turbofish generic (`pbkdf2::<Hmac<sha2::Sha256>>(...)`, `pbkdf2_hmac::<sha2::Sha256>(...)`) — the function callee text is just `pbkdf2` or `pbkdf2_hmac`. Phase 11 adds those callees plus eight classify rules that dispatch on the turbofish content (commit 38e4a9e):

- `crates-io:pbkdf2` — **3 findings** (was 0)
- `crates-io:scrypt` — **2 findings** (was 0)

### Phase 13 verification — precision-fix routing in the wild

The Phase 12 precision audit (PRECISION_AUDIT.md) flagged 8 findings whose `algorithm_id` field was misleading (placeholder, copy-paste, or wrong-variant). Phase 13 (commit 89d35cb) added dedicated sentinels and per-variant rules; the table below shows how many corpus findings now route to the correct algorithm_id:

| Rule | algorithm_id | Findings reclassified |
|---|---|---|
| `CRYPTO-255` | `sha-384` | 5 |
| `CRYPTO-258` | `ecdsa-p521` | 6 |
| `CRYPTO-417` | `aes-256-ecb` | 1 |
| `CRYPTO-560` | `tls-client-config` | 79 |
| `CRYPTO-561` | `tls-server-config` | 54 |
| `CRYPTO-704` | `rsa-pss-sha384-3072` | 19 |
| `CRYPTO-705` | `rsa-pss-sha512-4096` | 19 |
| `CRYPTO-740` | `jwt-alg-none` | 18 |

## Findings by ecosystem

| Ecosystem | Projects | Total findings | Audible | Suppressed (safe) | Errored | Avg scan time |
|---|---|---|---|---|---|---|
| crates-io | 25 | 226 | 73 | 153 | 0 | 0.06s |
| crypto-adjacent | 25 | 6 | 4 | 2 | 2 | 0.05s |
| go-modules | 25 | 441 | 364 | 77 | 3 | 0.10s |
| maven | 25 | 366 | 290 | 76 | 4 | 0.44s |
| npm | 25 | 117 | 95 | 22 | 0 | 0.10s |
| pypi | 25 | 38 | 38 | 0 | 0 | 0.18s |

## Top 10 projects by total finding count

| Project | Total | Audible | Suppressed | Scan time |
|---|---|---|---|---|
| `go-modules:github.com/lestrrat-go/jwx` | 219 | 175 | 44 | 0.49s |
| `crates-io:rustls-pemfile` | 140 | 30 | 110 | 0.29s |
| `maven:com.google.crypto.tink:tink` | 130 | 103 | 27 | 1.89s |
| `maven:org.eclipse.jetty:jetty-server` | 117 | 111 | 6 | 4.31s |
| `maven:com.nimbusds:nimbus-jose-jwt` | 78 | 51 | 27 | 0.15s |
| `go-modules:github.com/go-jose/go-jose` | 65 | 60 | 5 | 0.12s |
| `npm:jsonwebtoken` | 64 | 64 | 0 | 0.07s |
| `go-modules:github.com/hashicorp/vault` | 63 | 59 | 4 | 0.32s |
| `go-modules:github.com/golang-jwt/jwt` | 46 | 33 | 13 | 0.08s |
| `npm:jsrsasign` | 43 | 25 | 18 | 0.42s |

## Coverage gaps — expected-non-zero projects with 0 findings

These are well-known crypto libraries / consumers where we expect to find *something*. A zero-finding result here is a signal that the scanner has a missing rule or an unsupported language pattern.

- `crates-io:ring`
- `npm:crypto-js`
- `pypi:pyjwt`

### All zero-finding projects (95 / 150)

Note: many of these are zero for legitimate reasons. The expected-non-zero list above is the actionable subset. The remaining categories are:

- **Crypto _libraries_** (vs. consumers): `ring`, `openssl`, `libsodium`, `mbedtls`, `boringssl`, `aws-lc`, `wolfssl`, etc. These implement crypto primitives but expose them through opaque type-based APIs (e.g. `RsaPublicKey::new()`) that don't carry algorithm strings the way consumer code does (`SignatureAlgorithm.RS256`). They're inventory targets for `--deps` / SBOM, not source-pattern targets.
- **PQC reference implementations**: `liboqs`, `liboqs-python`, `liboqs-rust`, `oqs-provider`, `kyber`, `dilithium`, `sphincsplus`, `pqcrypto`, `swift-crypto`, `tink-go`. These are post-quantum-safe by design — expected zero alert-level findings.
- **Pure dependency consumers**: `axios`, `react`, `express`, `lodash`, `chalk`, `commander`, `glob`, `helmet`, `ms`, `semver`, `debug`, `charset-normalizer`, `idna`, `pyasn1`, `python-dateutil`, `six` — these don't directly use crypto APIs. Expected zero.
- **Go modules**: 22/25 produced zero findings. The Go ecosystem maps many crypto operations through interface-based dispatch (`crypto.Signer`, `cipher.Block`) plus runtime-string `tls.CipherSuite` lookups. A Go-specific Phase 7 pass (string-table detection across Go switch-case blocks) would likely 5–10× the Go finding count. This is the biggest known coverage gap on the corpus.

<details><summary>Full list of zero-finding projects</summary>

- `crates-io:argon2`
- `crates-io:ed25519-dalek`
- `crates-io:hmac`
- `crates-io:md-5`
- `crates-io:ring`
- `crates-io:rustls-native-certs`
- `crates-io:rustls-pki-types`
- `crates-io:sha-1`
- `crates-io:sha2`
- `crates-io:tokio-rustls`
- `crates-io:x25519-dalek`
- `crypto-adjacent:github.com/Mbed-TLS/mbedtls`
- `crypto-adjacent:github.com/apple/swift-crypto`
- `crypto-adjacent:github.com/aws/aws-encryption-sdk-c`
- `crypto-adjacent:github.com/aws/aws-lc`
- `crypto-adjacent:github.com/curl/curl`
- `crypto-adjacent:github.com/facebookresearch/CrypTen`
- `crypto-adjacent:github.com/google/boringssl`
- `crypto-adjacent:github.com/jedisct1/libsodium`
- `crypto-adjacent:github.com/microsoft/SymCrypt-OpenSSL`
- `crypto-adjacent:github.com/microsoft/SymCrypt`
- `crypto-adjacent:github.com/nabla-c0d3/sslyze`
- `crypto-adjacent:github.com/nodejs/node`
- `crypto-adjacent:github.com/open-quantum-safe/liboqs-python`
- `crypto-adjacent:github.com/open-quantum-safe/liboqs-rust`
- `crypto-adjacent:github.com/open-quantum-safe/liboqs`
- `crypto-adjacent:github.com/open-quantum-safe/oqs-provider`
- `crypto-adjacent:github.com/openssl/openssl`
- `crypto-adjacent:github.com/pq-crystals/dilithium`
- `crypto-adjacent:github.com/pyca/cryptography`
- `crypto-adjacent:github.com/rustpq/pqcrypto`
- `crypto-adjacent:github.com/sphincsplus/sphincsplus`
- `crypto-adjacent:github.com/tink-crypto/tink-go`
- `crypto-adjacent:github.com/wolfSSL/wolfssl`
- `go-modules:github.com/aws/aws-sdk-go-v2`
- `go-modules:github.com/aws/aws-sdk-go`
- `go-modules:github.com/cloudflare/circl`
- `go-modules:github.com/containerd/containerd`
- `go-modules:github.com/coredns/coredns`
- `go-modules:github.com/gin-gonic/gin`
- `go-modules:github.com/grafana/grafana`
- `go-modules:github.com/jackc/pgx`
- `go-modules:github.com/labstack/echo`
- `go-modules:github.com/minio/minio`
- `go-modules:github.com/moby/moby`
- `go-modules:github.com/ory/hydra`
- `go-modules:github.com/prometheus/prometheus`
- `go-modules:github.com/redis/go-redis`
- `go-modules:go.etcd.io/etcd`
- `go-modules:go.mongodb.org/mongo-driver`
- `go-modules:golang.org/x/crypto`
- `go-modules:k8s.io/kubernetes`
- `maven:com.amazonaws:aws-java-sdk-kms`
- `maven:com.auth0:java-jwt`
- `maven:com.azure:azure-security-keyvault-keys`
- `maven:com.squareup.okhttp3:okhttp`
- `maven:com.unboundid:unboundid-ldapsdk`
- `maven:commons-codec:commons-codec`
- `maven:org.apache.directory.api:api-ldap-codec-standalone`
- `maven:org.apache.shiro:shiro-crypto-core`
- `maven:org.bouncycastle:bcpkix-jdk18on`
- `maven:org.bouncycastle:bcprov-jdk18on`
- `maven:org.eclipse.parsson:parsson`
- `maven:software.amazon.awssdk:s3`
- `npm:axios`
- `npm:bcryptjs`
- `npm:chalk`
- `npm:commander`
- `npm:cookie`
- `npm:crypto-js`
- `npm:debug`
- `npm:express`
- `npm:glob`
- `npm:helmet`
- `npm:lodash`
- `npm:ms`
- `npm:node-rsa`
- `npm:oauth`
- `npm:openpgp`
- `npm:passport`
- `npm:react`
- `npm:semver`
- `npm:ssh2`
- `pypi:bcrypt`
- `pypi:certifi`
- `pypi:cffi`
- `pypi:charset-normalizer`
- `pypi:idna`
- `pypi:pyasn1`
- `pypi:pycryptodome`
- `pypi:pyjwt`
- `pypi:python-dateutil`
- `pypi:rsa`
- `pypi:setuptools`
- `pypi:six`

</details>

## Scan errors

9 project(s) produced non-empty error output:

- `maven:org.bouncycastle:bcpkix-jdk18on`
    - clone path does not exist: /Users/uvijayanand/Desktop/Projects/QuantumOSS-Analysis/benchmarks/corpus-b-realworld/clones/maven/bcpkix-jdk18on
- `maven:com.amazonaws:aws-java-sdk-kms`
    - clone path does not exist: /Users/uvijayanand/Desktop/Projects/QuantumOSS-Analysis/benchmarks/corpus-b-realworld/clones/maven/aws-java-sdk-kms
- `maven:com.azure:azure-security-keyvault-keys`
    - clone path does not exist: /Users/uvijayanand/Desktop/Projects/QuantumOSS-Analysis/benchmarks/corpus-b-realworld/clones/maven/azure-security-keyvault-keys
- `maven:software.amazon.awssdk:s3`
    - clone path does not exist: /Users/uvijayanand/Desktop/Projects/QuantumOSS-Analysis/benchmarks/corpus-b-realworld/clones/maven/aws-sdk-java-v2-s3
- `go-modules:github.com/aws/aws-sdk-go`
    - clone path does not exist: /Users/uvijayanand/Desktop/Projects/QuantumOSS-Analysis/benchmarks/corpus-b-realworld/clones/go-modules/aws-sdk-go
- `go-modules:github.com/aws/aws-sdk-go-v2`
    - clone path does not exist: /Users/uvijayanand/Desktop/Projects/QuantumOSS-Analysis/benchmarks/corpus-b-realworld/clones/go-modules/aws-sdk-go-v2
- `go-modules:github.com/grafana/grafana`
    - clone path does not exist: /Users/uvijayanand/Desktop/Projects/QuantumOSS-Analysis/benchmarks/corpus-b-realworld/clones/go-modules/grafana
- `crypto-adjacent:github.com/wolfSSL/wolfssl`
    - clone path does not exist: /Users/uvijayanand/Desktop/Projects/QuantumOSS-Analysis/benchmarks/corpus-b-realworld/clones/crypto-adjacent/wolfssl
- `crypto-adjacent:github.com/sphincsplus/sphincsplus`
    - clone path does not exist: /Users/uvijayanand/Desktop/Projects/QuantumOSS-Analysis/benchmarks/corpus-b-realworld/clones/crypto-adjacent/sphincsplus

## Trust invariants observed during this run

- **P1 (no LLM at runtime):** scanner is pure Rust; no network calls from `scan-source` or `scan-deps` paths.
- **P2 (no listening sockets):** `--net` was not enabled; no inbound connections opened.
- **P3 (every finding traces to source):** all findings carry `location.file:line` and `snippet`.
- **P4 (no customer-code execution):** the scanner only opened files for reading; no project code was run.

## Reproducing this run

```
cd benchmarks/corpus-b-realworld
./clone_all.sh                          # ~30-60 min, 150 repos
./verify.sh                             # confirm SHA pins (optional)
python3 scan_corpus.py                  # ~5-15 min
python3 render_results.py               # writes ../../BENCHMARKING_RESULTS.md
```


---

## Policy-profile divergence — measured 2026-08-27

`--policy` selects a scoring profile. The claim it has to survive is that a
profile reweights findings without changing what is detected, and that it is
not decorative — a preset whose verdicts never differ from the default is not
worth shipping.

Corpus B was dumped twice with the same binary, once per built-in preset,
`--source --deps --include-safe` on every project:

| | Findings | Same rule / algorithm / file:line | Severity band differs |
|---|---|---|---|
| `nist-default` | 898 | — | — |
| `nsa-cnsa2` | 898 | byte-identical | **80 (8.9 %)** |

Every one of the 80 is `sha-256` moving Medium → High, across 18 of the 54
projects that produce findings. That is the whole story on this corpus and it
is worth stating precisely: CNSA 2.0 excludes 26 algorithm ids from its
approved suite, and **`sha-256` is the only one corpus B contains** — no
AES-128, no AES-192, no ChaCha20-Poly1305 and no sub-1024 PQC parameter set
appears anywhere in the 898 findings. All 80 findings carrying a
CNSA-2-disallowed id changed band; none of the other 818 did.

The `nsa-cnsa2` profile also raises the unmatched-file shelf-life default from
`short` to `medium` (NSS data retention). That adds 7 points to every finding's
score but moved **no** finding across a band boundary on this corpus, so it does
not appear in the table above.

The `nist-default` dump is byte-identical to the run recorded at `d492a12`,
which is the check that matters for the published precision figure: the
audited label set still applies unchanged.

Reproduce:

```
seawall scan <project> --source --deps --include-safe                      # nist-default
seawall scan <project> --source --deps --include-safe --policy nsa-cnsa2   # CNSA 2.0
```

---

## AES key sizes: read, not assumed — measured 2026-08-27

`(corpus B, 150 projects · source + deps · nist-default and nsa-cnsa2 · binary
built from this commit)`

Seven classify rules published an AES key size that their own `when` clause
never read. `Cipher.getInstance("AES/GCM/NoPadding")` takes its key size from
the `SecretKey`, `AESEngine` from `init()`, `Aes.Create()` from the `KeySize`
property, `aes.NewCipher` from the slice it is handed, `CryptoJS.AES.encrypt`
from the passphrase — and all of them shipped `algorithm_id = aes-256-gcm`
anyway. `new BouncyCastleProvider()` and `RandomNumberGenerator.Create()`
shipped it without being AES calls at all. That id flows into the CBOM as an
asserted component, so the hedge in the message did not travel with it.

Each rule now reads the width where the source states one (the JCE `AES_128` /
`AES_192` / `AES_256` standard names, Node's `aes-256-gcm` cipher names) and
falls back to an `aes-unattributed*` sentinel where it does not. This is the
same fix Phase 13 applied to the TLS-config placeholders (Pattern A in
`PRECISION_AUDIT_V2.md`), applied to the sites that pattern missed.

| | Before | After |
|---|---|---|
| Findings | 898 | 898 |
| Call sites added / removed | — | 0 / 0 |
| Findings changing severity | — | 0 |
| Findings asserting `aes-256-gcm` | 42 | **1** |
| — of those, grounded in a source literal | 1 | 1 |

| Rule | Before | After | Findings |
|---|---|---|---|
| `CRYPTO-203` Java `Cipher.getInstance("AES/GCM/…")` | `aes-256-gcm` | `aes-unattributed-gcm` | 13 |
| `CRYPTO-370` `CryptoJS.AES.encrypt` | `aes-256-gcm` | `aes-unattributed` | 18 |
| `CRYPTO-233` `new BouncyCastleProvider()` | `aes-256-gcm` | `crypto-provider-registration` | 8 |
| `CRYPTO-231` BC `AESEngine` | `aes-256-gcm` | `aes-unattributed` | 1 |
| `CRYPTO-232` BC `GCMBlockCipher` | `aes-256-gcm` | `aes-unattributed-gcm` | 1 |
| `CRYPTO-302 → CRYPTO-306` `createCipheriv('aes-256-gcm')` | `aes-256-gcm` | `aes-256-gcm` | 1 |

The last row is the control: that one call site does state its key size, and it
keeps `aes-256-gcm` — now read from the literal rather than assumed. 41 of 42
did not, and no longer claim to.

**Precision is unchanged at 85.2 %** and this run does not re-measure it. The
finding set is identical call site for call site, no verdict in the audited
206-finding label set moves from TP to FP or back, and only the `algorithm_id`
column differs. Four of the eight audited rows this touches were labelled
`DEPENDS` in `PRECISION_AUDIT_V3.md` for exactly this reason — *"256-bit key
unverifiable at this line"* — and they are deliberately **not** relabelled here:
re-scoring another audit's rows in our own favour is not a measurement.

**The `--policy` divergence number is undisturbed:** the same 898 findings, 80
(8.9 %) in a different severity band under `nsa-cnsa2`, all `sha-256`
Medium → High — bit-identical to the figure published above. Corpus B contains
no AES-128 call site, so no sentinel reached `policy_disallowed`. Note what
that leaves open: `aes-unattributed-gcm` is **not** on the CNSA 2.0 disallowed
list, so an NSS codebase whose AES key size is unverifiable is still reported
as compliant. Treating "unknown" as "non-compliant" is a policy decision, not a
detection one, and is not made here.

Speed held: `npm/jose` 0.11–0.23 s across three runs; `maven/nimbus-jose-jwt`
0.31–0.56 s.

A build gate prevents the regression: `aes_key_size_is_never_asserted_without_evidence`
(`crates/scan-source/src/rules.rs`) fails when any classify rule in any of the
seven packs publishes an `aes-128*` / `aes-192*` / `aes-256*` id that its own
`when` clause cannot observe.

## Broken-classical recall: 22 stranded rules, 8 of 9 planted sites missed — measured 2026-08-27

Tuple: **corpus B (150 projects) · scanner set `--source --deps --include-safe` ·
profiles `nist-default` and `nsa-cnsa2` · binary at the commit that added the
reachability gate.**

There is no query engine. The `[[extract]]` S-expressions in the rule packs are
documentation; every recognised API comes from a hand-written matcher in
`scan-source/src/scanner.rs`. Nothing checked that the two layers agreed, so a
`[[classify]]` rule could name an `api` no matcher emits and simply never run.
**22 of 257 classify rules were in that state** — 16 of the 28 Python rules and
6 of the 44 Go rules — including `CRYPTO-130` (3DES) and `CRYPTO-131` (RC4),
both Critical, neither of which had ever produced a finding.
A silent zero is indistinguishable from a clean codebase, which is why 18
phases of precision work never surfaced this: recall failures do not appear in
a precision metric.

Nine textbook broken-classical call sites across Java, Python and Go were
planted as a fixture. **Before: 1 of 9 detected. After: 9 of 9.**

| | Before | After |
|---|---|---|
| Stranded classify rules (can never fire) | 22 | **0** |
| Planted broken-classical sites detected | 1 / 9 | **9 / 9** |
| Corpus findings | 898 | **964** |
| Call sites added / removed | — | 66 / 0 |
| Existing call sites reclassified | — | 0 |

The 66 new corpus findings, by rule:

| Rule | Algorithm | n | What was unreachable |
|---|---|---|---|
| `CRYPTO-161` | `sha-256` | 24 | PyJWT `jwt.encode(…, algorithm="HS256")` |
| `CRYPTO-040` | `aes-unattributed` | 14 | Go `aes.NewCipher` |
| `CRYPTO-170/171` | `rsa-1024` / `rsa-2048` | 11 | pycryptodome `RSA.generate(bits)` |
| `CRYPTO-298` | `ecdsa-unattributed` | 5 | Java `Signature.getInstance("…withECDSA")` |
| `CRYPTO-293/295` | `rsa-pkcs1-sha*` | 6 | Java `Signature.getInstance("SHA*withRSA")` |
| `CRYPTO-213` | `rc4` | 2 | Java `Cipher.getInstance("RC4")` |
| `CRYPTO-122` | `x25519` | 2 | pyca `X25519PrivateKey.generate()` |
| `CRYPTO-163` | `ecdsa-p256` | 2 | PyJWT `algorithm="ES256"` |

All 66 were labelled by opening the cited `file:line`: **56 TP, 4 FP, 6 DEPENDS**
(93.3 % on the delta alone, Wilson 84.1–97.4 %). The four FPs are three calls
asserted to raise inside `pytest.raises` — no signature is produced, so P3 makes
them false positives — and one `RSA.generate(1280)` published as `rsa-1024`.
The six DEPENDS are `SHA256withRSA` / `SHA512withRSA` sites where the digest is
stated and the modulus in the algorithm-id is not.

**Precision, combined with the standing audited sample: 217 TP / 32 FP /
23 DEPENDS on 272 → 87.1 % (Wilson 82.4–90.7 %), against 85.2 % before.**
Read that as coverage added at precision held, not as a precision improvement:
the Phase 18 sample was not re-drawn, the 66 new findings are sampled at 100 %
where the rest of the corpus is sampled at about 20 %, and the interval overlaps
the prior one. A real re-audit still has to overwrite it.

Three algorithm-ids stopped asserting parameters their call site never states,
following the pattern established for AES key sizes:

- Go `MinVersion: tls.VersionTLS10` and Python `ssl.SSLContext(ssl.PROTOCOL_TLSv1)`
  published `rsa-2048` as an admitted placeholder. Both now publish
  `tls-legacy-protocol`. A protocol version names no cipher.
- Java `Signature.getInstance("SHA256withECDSA")` published `ecdsa-p256`. The
  curve comes from the key passed to `initSign()`, not from the string: jetty's
  Ethereum credentials call `Signature.getInstance("NONEwithECDSA")` over
  **secp256k1**. The new `ecdsa-unattributed` sentinel names the family and the
  Shor verdict, which are exact, and no curve.
- `Cipher.getInstance("DESede/…")`, `DES.Create()` and `EVP_des_ede3_cbc` were
  each attributed to the wrong one of DES / 3DES. Split, with the specific arm
  ordered first.
- `hashlib.new(<anything>)` published `md5` for every call site. It now reads
  the literal and fires only on `md5` / `sha1`; a runtime hash name produces no
  finding.

**Policy invariant held.** The same corpus under `--policy nsa-cnsa2` produces
a **byte-identical finding set** — same rules, same algorithm-ids, same
`file:line` — with **104 findings (10.8 %) in a different severity band**,
against 80 (8.9 %) of 898 before. All 104 are `sha-256` moving Medium → High,
and the 24 added ones are the newly-reachable PyJWT `HS256` sites. A policy
reweights findings; it still never creates or suppresses a detection.

Speed held on an idle box: `npm/jose` 0.09–0.14 s over four runs,
`maven/nimbus-jose-jwt` 0.33–0.34 s. The extra matchers are exact-string
lookups in `const` tables on callee text the walker already computed.

**Gate.** `every_classify_rule_targets_an_api_the_extractor_can_emit`
(`crates/scan-source/src/rules.rs`) fails the build when a classify rule's
`when.api` matches nothing in `scanner::api_surface()`. The api surface is
derived from the same `const` tables the matchers dispatch on, so it cannot
drift from them. Confirmed the gate fails by adding a rule for a nonexistent
api and re-running, per the "a gate that cannot fail is not a gate" rule.

---

## Rename verification — 2026-08-27 (cryptoscope → seawall)

The rename touched files inside the detection paths, so the precision gate demanded a measurement.
No new measurement was taken, because none was warranted: the change was verified to be
**detection-neutral** rather than assumed to be.

Method: for each file under `crates/core/data/` — the algorithm table, the OID table, the default
policy, and all seven rule packs — the pre-rename revision and the post-rename file were normalised
by replacing the product name with a placeholder and compared.

| File | Result |
|---|---|
| `algorithm-table.toml` | identical apart from the product name |
| `default-policy.toml` | identical apart from the product name |
| `oid-table.toml` | identical apart from the product name |
| `rules/{cpp,csharp,go,java,javascript,python,rust}.toml` | identical, all seven |

No rule, `when` clause, `algorithm_id`, severity mapping, or policy weight changed. The only edits
were comments and the tool name emitted into reports. Precision therefore stands at **87.1%**
(n=272), carried forward from the previous cycle rather than re-derived.

This is recorded so the number in `state/precision.json` is traceable to a reason, not just to a
green gate.

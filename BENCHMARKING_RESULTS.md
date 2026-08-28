# quipuu — 150-project corpus benchmark

Sections are appended in date order. **The current run is the last dated section**
(*A JOSE name compared is not a JOSE name used — 2026-08-28*); everything above it is the
record of an earlier phase and is kept as history, not as a current claim.

---

## V8 run (historical — superseded 2026-08-28)

**Corpus:** corpus-b-realworld  
**Projects scanned:** 150 listed, **141 actually scanned** — 9 clones were missing  
**Elapsed:** 23.3s over those 141  
**Default filter:** quantum-safe inventory hidden from alert output (Phase 2; pass --include-safe to unhide)  

> **Do not quote this section's headline.** The 9 missing clones were the visible part of a
> corpus defect that left **46 of 150 projects with empty working trees** (root cause under
> *Corpus integrity* below). Its `23.3s` also disagrees with its own
> `results/summary.json`, which records **22.43s and 1036 findings** for the same run at
> `include_safe:false`. The README summarised the lower pair. Both are retracted; the
> reproducible replacements are in the 2026-08-28 section.

This is the V8 corpus run, layered on Phases 1-11 (jjwt enum constants, signal-to-noise, ACVP refresh, why-this-matters, non-fatal warnings, Go switch / registration, paramiko + crypto-js, Rust qualified paths + turbofish, pbkdf2 nested turbofish) plus Phase 12 (precision audit — measured 73.3% precision on a stratified 31-finding sample) and Phase 13 (closing the 8 audit-surfaced false-positive patterns: TLS-config topology markers, jwt-alg-none sentinel, per-variant PSS / HMAC / ECDSA / AES-ECB algorithm_ids, plus a CI consistency guard). Numbers below are stratified by ecosystem and reported without projected values — only what was actually scanned.

### Headline numbers (historical)

- **1194 total findings** reported across 150 projects in 23.3s — over 141 scanned
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
  > **Retracted 2026-08-28.** The expectation was right and the scanner did not meet it. `dilithium` and `sphincsplus` produced **12 High findings**, every one asserting `ed25519` and every one telling a FIPS 204 / FIPS 205 reference implementation to migrate to ML-DSA-65, because `crypto_sign_keypair` was matched as text. Measured, and fixed, in *"`crypto_sign_keypair` is not libsodium's alone"* below; `tink-go` is also not a PQC implementation and produces 48 findings on its classical paths. Do not read this bullet as a measurement — it was never one.
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

9 project(s) produced non-empty error output. Clone paths below are given as
`<ecosystem>/<name>` relative to the clone root; the run that produced this
section recorded them as absolute paths under the operator's home directory,
which named a machine rather than a corpus and has been normalised.

**All nine were later found to be a corpus defect, not a scanner defect** — see
*Corpus integrity and the corrected precision figure* below. The 150-project
totals in this section's parent run were therefore taken over 141 scanned
projects.

- `maven:org.bouncycastle:bcpkix-jdk18on`
    - clone path does not exist: maven/bcpkix-jdk18on
- `maven:com.amazonaws:aws-java-sdk-kms`
    - clone path does not exist: maven/aws-java-sdk-kms
- `maven:com.azure:azure-security-keyvault-keys`
    - clone path does not exist: maven/azure-security-keyvault-keys
- `maven:software.amazon.awssdk:s3`
    - clone path does not exist: maven/aws-sdk-java-v2-s3
- `go-modules:github.com/aws/aws-sdk-go`
    - clone path does not exist: go-modules/aws-sdk-go
- `go-modules:github.com/aws/aws-sdk-go-v2`
    - clone path does not exist: go-modules/aws-sdk-go-v2
- `go-modules:github.com/grafana/grafana`
    - clone path does not exist: go-modules/grafana
- `crypto-adjacent:github.com/wolfSSL/wolfssl`
    - clone path does not exist: crypto-adjacent/wolfssl
- `crypto-adjacent:github.com/sphincsplus/sphincsplus`
    - clone path does not exist: crypto-adjacent/sphincsplus

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
python3 scan_corpus.py                  # see the 2026-08-28 section for the flags
python3 render_results.py --out /tmp/run.md   # renders THIS run only
```

`render_results.py` renders one run from `results/summary.json`. It will not
overwrite this file, which carries hand-written sections it cannot regenerate;
give it an `--out` path of its own.

The corpus is usually cloned outside the repo. Both scripts take `--clones`,
and `dump_findings.py` also takes `--bin` and `--out`:

```
python3 scan_corpus.py   --clones /path/to/clones --bin ../../quipuu/target/release/quipuu \
                         --out results/ --include-safe
python3 dump_findings.py --clones /path/to/clones --bin ../../quipuu/target/release/quipuu \
                         --out results/all_findings.json
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
quipuu scan <project> --source --deps --include-safe                      # nist-default
quipuu scan <project> --source --deps --include-safe --policy nsa-cnsa2   # CNSA 2.0
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

A build gate prevents the regression: the test in `crates/scan-source/src/rules.rs`
fails when any classify rule in any of the seven packs publishes an
`aes-128*` / `aes-192*` / `aes-256*` id that its own `when` clause cannot
observe. It was named `aes_key_size_is_never_asserted_without_evidence` when
this was written; it has since been generalised in place to
`classify_rules_never_publish_a_parameter_their_when_clause_contradicts`, which
covers elliptic curves as well as AES widths.

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

## Rename verification — 2026-08-27 (cryptoscope → quipuu)

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

---

## Corpus integrity and the corrected precision figure — 2026-08-27

**Measurement tuple:** corpus B (150 projects, **all 150 with a populated working tree for the first
time**) · scanner set `--source --deps --include-safe` · profile `nist-default`.

**Precision 81.8% (Wilson 95% CI 77.4–86.1%), stratified**, against a previously published 87.1%.
The number fell, the scanner did not regress, and the fall is the deliverable.

### Root cause

46 of 150 projects had empty working trees. `clone_all.sh` clones `--no-checkout`, and each
project's manifest `commit_sha` **is not a commit in the repository that project names** — so the
checkout failed, printed `[warn] … leaving at HEAD`, counted the project as cloned, and left the
tree empty. The pins were shuffled across project files at corpus construction.

Checkable without network access: `61b250ac42af` is the pin for *both* `pypi:cryptography` and
`microsoft/SymCrypt`, and the pin recorded for `liboqs` is a real `sslyze` commit dated 2026-03-29.
Eight further bad pins are the current HEAD of a different corpus project. The 46 are re-pinned to
what is on disk, each with a comment naming the unreachable sha it replaces.

| | before | after |
|---|---|---|
| Projects with a populated working tree | 104 / 150 | **150 / 150** |
| Findings, `nist-default` | 964 | **1604** |
| Findings from the 104 always-present projects | 964 | **964, byte-identical** |

### The estimator

| Stratum | Findings | Audited | TP | FP | DEPENDS | Precision |
|---|---|---|---|---|---|---|
| 104 always-scanned | 964 | 272 | 217 | 32 | 23 | 87.1% |
| 46 restored | 640 | 100 | 70 | 25 | 5 | 73.7% (Wilson 64.0–81.5) |
| **weighted 0.601 / 0.399** | **1604** | **372** | | | | **81.8% (77.4–86.1)** |

The restored stratum was sampled uniformly (seed 20260827, n=100 of 640) and every row labelled by
opening the cited `file:line`. Unweighted pooling — the estimator that produced the old series —
gives 83.4% on the same labels; that is quoted only to separate estimator effect from domain
effect. **Most of the 5.3 pp fall is domain**: the crypto-dense strata that had been missing audit
13 pp worse than the strata the old number was measured on.

An advance prediction of ≈283 restored findings (total ≈1247) was made before the run. Actual:
**+640, total 1604**. `jwx` alone contributes 230. The prediction is recorded as wrong.

### Fixed in the same pass, because the sample surfaced it

Four classify rules published a curve their own `when` clause contradicts: `CRYPTO-039`/`CRYPTO-035`
matched P-521 and published `ecdh-p384`; `CRYPTO-010`/`CRYPTO-110` matched P-224 and published
`ecdsa-p256` under a comment reading "map to nearest baseline". Corpus effect: **0 call sites added
or removed, 0 severity changes, 25 `algorithm_id` values corrected.** Stratum B 70.5% → 73.7%,
weighted 80.5% → **81.8%**.

---

## Registry-lookup suppression — 2026-08-28

**Measurement tuple:** corpus B (150 projects, all populated) · scanner set
`--source --deps --include-safe` · profile `nist-default` · three dumps taken this day with
`benchmarks/corpus-b-realworld/dump_findings.py`.

**Precision 81.8% → 85.3% (95% CI 81.3–89.3%), stratified.** Findings 1604 → 1570.

### What changed

`jwa.LookupSignatureAlgorithm("PS256")` retrieves a descriptor from a table.
`func ES384() SignatureAlgorithm { return lookupBuiltinSignatureAlgorithm("ES384") }` retrieves one
and returns it. No signature exists at either line, yet both were reported as a quantum-vulnerable
signing operation with a migration instruction attached — the largest single false-positive cluster
in the audited sample, 10 of its 25 FPs.

A new `SiteContext::RegistryLookup` marks the argument of a callee whose own name begins with
`lookup`, when the result is not handed straight to another call. The 19 `go.alg-*` rules already
enumerate the contexts they accept, so they drop it with no rule change.

Two limits are deliberate. Only the callee's immediate parent decides whether the result is
consumed, so `sign(lookupAlg("RS256"), payload)` does select RS256 at that line and stays a finding.
And the predicate is one shape rather than a table of library names — `Get*` and `Parse*` are
excluded, because golang-jwt's `jwt.New(jwt.GetSigningMethod("RS256"))` is ambiguous by usage rather
than by name, and suppressing it would lose a real signing site.

### The suppressed set, labelled in full

**34 findings removed, 0 added, 0 reclassified**, all 34 in `lestrrat-go/jwx`, which contributes 230
of the corpus's 1604 findings. Every one was labelled by opening its cited `file:line`: **34 FP, 0
TP.** 14 are `return lookupBuiltinSignatureAlgorithm("…")`, the one-line bodies of the generated
accessors in `jwa/signature_gen.go`. 19 are `v, ok := jwa.Lookup*Algorithm("…")` in the generated
tests beside them. The 34th assigns the retrieved descriptor to a variable that a later line uses.
**No signing site was lost**, and none of the 34 lines produces a signature, a key or a ciphertext.

### The estimator

Same two strata and same weighting as the 81.8% figure above, so the two are comparable. Stratum A
is held at its audited value; neither change removes a stratum-A finding.

| | Stratum A | Stratum B | Weighted |
|---|---|---|---|
| Before (`f750c37`, as the tree stood) | 964 · 217/32/23 · 87.1% | 640 · 67/28/5 · 70.5% | 1604 · **80.5%** (76.1–84.9) |
| + curve-id restoration | 964 · 217/32/23 · 87.1% | 640 · 70/25/5 · 73.7% | 1604 · **81.8%** (77.4–86.1) |
| + registry-lookup suppression | 964 · 217/32/23 · 87.1% | 606 · 70/15/5 · 82.4% | 1570 · **85.3%** (81.3–89.3) |

Cells read *population · TP/FP/DEPENDS · precision*. The interval is the stratified normal
approximation `Var = Σ wᵢ² pᵢ(1−pᵢ)/nᵢ`; the middle row reproduces the previously published
81.8% (77.4–86.1) to the decimal, which is what licenses reading the bottom row against it.

Ten of the 100 audited stratum-B rows are dropped by the change and **all ten were labelled FP**.
Stratum B's TP count is unchanged at 70; only its FP count moves, 25 → 15.

**The middle row is a restoration, not a gain.** The curve-id fix is the code the 81.8% published
here was measured on, and it had not reached the tree. As it stood, the tree measured 80.5% while
advertising 81.8%. That is corrected in the same change.

**Two reasons this figure is conservative.** Stratum A is held at 87.1% although the curve
restoration corrects two of its `algorithm_id`s (`ecdsa-p256` → `ecdsa-p224` on `elliptic.P224()`
calls), an effect that could only be favourable. And the four rows `PRECISION_AUDIT_V3.md` §0
re-resolves as FP are all inside the suppressed set; if any sit in stratum A's 272 audited rows,
correcting them lowers stratum A before the change and raises it after, widening the gain rather
than narrowing it.

### Cross-check

An independent uniform 200-row sample of the whole corpus (seed 20260827) moves **75.1% → 77.3%**,
+2.1 pp, with TP unchanged at 136 and FP 45 → 40. Different sample and different estimator, so the
level is not comparable to the stratified figure — it is quoted for the direction, and because it
independently confirms that every sampled finding the change removed was a false positive. It
understates the move because it does not relabel the curve corrections.

### Held

Scan speed: no change detectable above this box's noise floor. Measured as 7 interleaved
repetitions per binary on `npm/jose` (109 ms → 114 ms best-of-7) and on `go-modules/jwx`, the
project the change affects most (497 ms → 490 ms best-of-7). Medians move by more than that in
both directions between runs, so the honest reading is "not distinguishable", not "identical" —
this is a 2-core machine and the two figures bracket each other.

`cargo test --workspace`: 259 tests across 36 suites, all passing. No finding was added anywhere in
the corpus by either change, so no coverage was traded for this precision.

---

## Corpus B, timed and dumped in one run — 2026-08-28

**This is the section the README summarises.** Every timing figure below is from a single
`scan_corpus.py` invocation, on named hardware, with the flag set and the error count stated
beside it; the per-finding dump is a second `dump_findings.py` invocation under the same
binary, flags and corpus. The two agree at 1570 findings by independent count. This section
exists because the numbers it replaces could not be traced to one run.

**Tuple.** Corpus B, 150 projects, all 150 with a populated working tree · scanner set
`--source --deps --include-safe` · profile `nist-default` · release build, single-threaded
· binary at `c08a890` · **2 cores of an AMD EPYC 9354P, 7 GB RAM** · 2026-08-28.

| Metric | Value |
|---|---|
| Projects scanned | 150 of 150 |
| Projects that errored | **0** |
| Total findings | **1570** |
| Wall-clock, whole corpus | **367.4s** (6m 08s) |
| Per project — median | **285 ms** |
| Per project — mean | 2448 ms |
| Per project — p90 | 1.70s |
| Per project — max | 144.51s (`go-modules:github.com/aws/aws-sdk-go-v2`) |
| Projects finishing under 1s | **117 of 150** |

| Ecosystem | Projects | Findings | Duration | Errored |
|---|---|---|---|---|
| pypi | 25 | 77 | 10.32s | 0 |
| npm | 25 | 127 | 6.03s | 0 |
| maven | 25 | 366 | 67.32s | 0 |
| crates-io | 25 | 226 | 10.05s | 0 |
| go-modules | 25 | 576 | 210.87s | 0 |
| crypto-adjacent | 25 | 198 | 62.61s | 0 |

### Run-to-run variance, stated rather than hidden

A second full pass the same day — `regression_check.py`, which re-runs `scan_corpus.py`
into a scratch directory — measured **329.0s** against the 367.4s above, with CPU contention
differing between the two and **without** `--include-safe` (that flag changes what is
displayed, not what is detected, so the totals are still comparable). Same corpus, same
binary, **same 1570 findings and the same per-ecosystem counts**
(77 / 127 / 366 / 226 / 576 / 198). So the finding counts are stable and the wall-clock is
±10% on two shared cores; the corpus figure should be read as *about six minutes*, not to
three significant figures.

That second pass also exercised the floors in `regression_check.py` for the first time on
this box — 6 ecosystem floors, the corpus total, and 6 per-rule floors, **13 of 13 met**.
It had been skipping silently because its clone directory was hardcoded to a path inside
the repo; it now takes `--clones` / `--bin`, and its 600s subprocess timeout has been raised
to 1800s, since a 367s corpus scan under contention was close enough to the old limit to
fail as a timeout rather than as a regression.

### Why the mean is 8.6× the median

Three repositories carry 213.4s of the 367.2s — **58% of the total**:
`aws-sdk-go-v2` (144.51s), `aws-sdk-go` (49.15s), `wolfssl` (19.71s). The first two are
vendored AWS SDKs; the corpus stocks them deliberately, because a PQC inventory tool that
falls over on a vendored SDK is not useful. So the mean is a property of this corpus and
the median is a property of a project. Quoting either alone misleads, in opposite
directions, which is how `~150ms per project` was published in the first place.

### What was retracted, and why it was wrong

The previously published `~22 seconds / ~150ms per project` traces to
`results/summary.json` from a run with **`include_safe:false`** in which **9 of 150 clone
paths did not exist** — 22.43s and 1036 findings over 141 projects. The README paired that
elapsed time with a **1570** finding count taken from a different run under different
flags. `BENCHMARKING_RESULTS.md` reported the same underlying run as *1194 findings in
23.3s*. Three numbers, three provenances, one table. Retracted in full.

### Committed artifacts now reproduce

`results/all_findings.json` and `results/summary.json` were regenerated by this run and no
longer contain absolute paths. Both scripts were fixed first:

* `dump_findings.py` records `file` as `<ecosystem>/<name>/<path>` relative to the clone
  root, and **exits non-zero rather than write an artifact containing an absolute path**.
  Its binary, clone root and output path are now `--bin` / `--clones` / `--out` instead of
  three hardcoded constants, because the corpus is routinely cloned outside the repo and
  every cycle was re-forking the script to say so.
* `scan_corpus.py` records missing-clone and timeout errors by corpus position rather than
  by absolute path.
* Ten clones in this corpus are symlinks to another clone (`crates-io/sha2` →
  `crates-io/md-5`), so both scripts resolve link targets on **both** sides before
  stripping the prefix, and re-attach the *logical* `ecosystem/name` — otherwise two
  corpus projects collapse onto one path and the strip silently leaves an absolute path in.

**Detection is unaffected, and this was checked rather than assumed.** The regenerated dump
is the same 1570 findings as the pre-change dump taken at `c08a890`, identical on project,
rule id, algorithm id, severity, line and message on every row — only the `file` column
differs, and only by having its machine-specific prefix removed. The precision estimator
reproduces its recorded baseline (81.8%, 77.4–86.1) before reporting, and returns
**85.3% (95% CI 81.3–89.3)**, unchanged.

### Trust invariants, observed in this run

`/usr/bin/time -v` over the whole 150-project scan reports **0 socket messages sent and 0
received** — P2 holds across 150 projects, not just on a unit test. No project code was
executed (P4): every finding resolves to a file the scanner opened for reading.

### CBOM schema conformance — measured the same day

Emitting one component for every one of the **87** algorithm-table rows (92 as of `9e60ffe`;
see the section below) and validating
against the schemas vendored in `crates/cbom/data/`:

| Emitted as | Validated against | Errors |
|---|---|---|
| 1.7 (default) | 1.7 | **0** |
| 1.6 (`--schema-version 1.6`) | 1.6 | **0** |
| 1.7 (default) | 1.6 | **72** |

All 72 are the 1.7-only `algorithmFamily` field against 1.6's
`additionalProperties: false`, one for each of the 72 components that carry a canonical
family. This is correct behaviour — 1.7 output is not 1.6 — but it falsifies the README's
former claim that the CBOM *"round-trips with IBM CBOMkit, Dependency-Track, and every
CycloneDX consumer"*: a consumer pinned to 1.6 must be given `--schema-version 1.6`. The
claim has been replaced with what was measured, and **no third-party consumer has been
tested**, so none is named.

Gated by `every_algorithm_emits_a_bom_valid_at_the_version_it_declares`
(`crates/cbom/tests/emit_test.rs`), which covers the algorithm table where the existing
`emit_validates_for_v1_7_and_v1_6` covers only the fixture corpus. Confirmed it can fail,
per the standing rule: removing the 1.6 suppression in `emit.rs` makes it fail with the 72
errors above.

## Go TLS hybrid groups, and a corpus that cannot exercise them — 2026-08-28

`CRYPTO-044/045/046/048` classify the PQC half of a Go `tls.Config.CurvePreferences`
list. Corpus B was re-dumped to measure them, and the honest result is that it cannot:

**The finding set is byte-for-byte unchanged.** 1570 findings before and after, identical
on project, rule id, algorithm id, severity, line and message on every row — 0 added,
0 removed, 0 changed in place. (The two dumps write `file` differently, absolute against
`<ecosystem>/<name>/<path>`, so the clone root is stripped before the comparison and
nothing else about either side is touched.)

**`CurvePreferences` fires zero times across all 150 projects** — not just the four new
PQC arms but `CRYPTO-032..035`, the classical arms that have shipped for cycles. The rule
shape has no site in this corpus at all, so the number to report for the new arms is
**0 corpus findings, and it is reported rather than omitted**. Its coverage is the
`tls_pqc_groups.go` fixture, where each arm is pinned to a literal `file:line`.

Two reasons the corpus cannot speak to this, both worth stating rather than inferring:
92 of 150 projects are scanned only inside `scan_hints.scan_paths` subtrees, and a
`CurvePreferences` slice literal is a deployment shape more than a library shape — the
corpus is 150 libraries.

An unchanged finding set cannot move a TP/FP ratio, so the audited label sets apply
without re-labelling. Precision was recomputed anyway rather than quoted, per the rule
adopted in cycle 19 — the estimator reproduced the recorded **85.3%** baseline from the
labels before anything was reported — and returns **85.3 % (95 % CI 81.3–89.3)**:
stratum A 964 findings at 87.1 % (272 audited, held), stratum B 606 findings at 82.4 %
(90 audited, Wilson 72.9–89.0), weights by population share.

`regression_check.py` ran its floors on the new binary: **13 of 13 met**, 150 of 150
projects scanned, 0 errored, 305.6 s.

### The algorithm table is 92 rows, and 8 of them state why nothing can emit them

Four rows were added for the stateful hash-based signatures (`lms`, `hss`, `xmss`,
`xmss-mt`) that `policies/nsa-cnsa2.toml` already advertised, and one (`dh-unattributed`)
for the two finite-field DH OIDs, which name the key type but not the group size — they
had been resolving to `dh-2048`, asserting a prime length no emitter can observe.

None of the five is reachable from a rule pack, so the count of ids nothing can emit went
from 3 to 8. Rather than publish that count — the two published before it, 24 and then 2,
were both wrong because the emitter set was assumed rather than enumerated — an
unreachable row now carries an `undetectable` field saying why it is kept, and
`crates/cli/tests/algorithm_reachability.rs` checks the set in three directions:
unreachable implies a reason, the reason is retired as soon as something emits the row,
and **no file outside the enumerated eleven emits an id at all**. All three were confirmed
to fail by reintroducing each defect.

CBOM conformance re-measured over the 92 rows: **1.7→1.7 = 0 errors, 1.6→1.6 = 0 errors,
1.7→1.6 = 77 errors**, all `algorithmFamily` against 1.6's `additionalProperties: false`,
one per component carrying a canonical family. The 77 is the 72 recorded above plus the
five new rows, each of which carries one.

Tuple for every figure in this section: corpus B, 150 projects all populated ·
`--source --deps --include-safe` · profile `nist-default` · binary `9e60ffe` · 2 cores of
an AMD EPYC 9354P · 2026-08-28.

---

## HNDL flag and SARIF property name: precision recomputed, recall published — 2026-08-28

**Measurement tuple:** corpus B (150 projects, all populated) · scanner set
`--source --deps --include-safe` · profile `nist-default` · binary `608cd8e` · 2 cores of an
AMD EPYC 9354P · 2026-08-28. Dump taken with the in-tree
`benchmarks/corpus-b-realworld/dump_findings.py`.

**Precision 85.3% (95% CI 81.3–89.3%), stratified — unchanged, and recomputed rather than
quoted.** Findings 1570, unchanged.

### Why the finding set should not move, and the check that it did not

Neither change is a detection change. `automationDetails` renames a key in the SARIF emitter,
which the dump does not read. `apply_hndl_flags` writes a boolean the dump does not record, and
it runs once over the whole finding set *after* collection, so it cannot add or remove a site.
That is the prediction. The check is what makes it a measurement:

| | findings | distinct sites | added | removed | changed in place |
|---|---|---|---|---|---|
| `9e495cb` (the dump the 85.3% baseline was audited on) | 1570 | 1552 | — | — | — |
| `608cd8e` (this tree) | 1570 | 1552 | **0** | **0** | **0** |

Sites are keyed on `(project, rule_id, file, line)` and compared on `algorithm_id` and
`message`; 18 rows legitimately share a site key, which is why the two columns differ.
Per-ecosystem counts are identical too: go-modules 576, maven 366, crates-io 226,
crypto-adjacent 198, npm 127, pypi 77.

### The estimator, its sample sizes and its verdicts

An unchanged finding set cannot move a TP/FP ratio, so the audited label sets apply without
re-labelling and precision is **recomputed, not re-estimated**. It is recomputed rather than
quoted because a published figure that is never re-derived cannot notice when the tree drifts
away from it; the estimator asserts it reproduces the recorded baseline from the labels before
it prints anything, and it did — 85.30%.

Same two strata, same weighting (population share) and same label sets as the 85.3% row in
*Registry-lookup suppression* above, so the two are the same figure and not merely the same
number.

| | Population | Audited | TP | FP | DEPENDS | Precision |
|---|---|---|---|---|---|---|
| Stratum A | 964 | 272 | 217 | 32 | 23 | 87.1% (held) |
| Stratum B | 606 | 90 | 70 | 15 | 5 | 82.4% (Wilson 72.9–89.0) |
| **Weighted** | **1570** | **362** | | | | **85.3%** (95% CI 81.3–89.3) |

Method, in full. Stratum B is the 606 findings from the 46 projects whose working trees were
restored, sampled uniformly at seed 20260827 and labelled once by **opening every cited
`file:line` and reading the code at it** — TP if a cryptographic operation or key of the named
algorithm exists at that line, FP if it does not, DEPENDS if the line is real but its
quantum-relevance turns on a runtime value the scanner cannot see. DEPENDS rows are excluded
from both numerator and denominator, which is why the audited 362 yields 249 + 85 = 334 graded
verdicts. Stratum A is held at the value its own 272-row audit produced; neither change removes
or reclassifies a stratum-A finding, and the site-set check above is what establishes that.
The interval is the stratified normal approximation `Var = Σ wᵢ² pᵢ(1−pᵢ)/nᵢ` — **not** Wilson,
which applies only to the single-stratum figures quoted per row.

### HNDL flag over the corpus: 0 of 1570, measured

`dump_findings.py` records severity but not `hndl_critical`, so the corpus count was taken in a
separate pass over the same 150 projects and the same `scan_hints.scan_paths` subtrees, with
`--summary-json`, summing `totals.hndl_critical`:

```
projects scanned : 150  (errored 0)
findings         : 1570
hndl_critical    : 0
flagged projects : none
```

**Zero is the correct answer here and is published as a scope limit, not as a result.** The flag
needs three inputs and `scan-source` fixes two of them at compile time (`usage_context: Unknown`,
`shelf_life_bucket: "short"`), so no source or dependency finding can meet the policy's
conditions. Corpus B runs `--source --deps` only and therefore never exercises `scan-certs`,
which is the one scanner that varies those axes — so this run cannot speak to the flag's
non-zero path at all. That path is measured on the fixture instead: an X25519 certificate
(SPKI OID `1.3.101.110`, `primitive = "key-agree"`, `BrokenByShor`) is flagged, and the same
certificate's Ed25519 *signature* finding is not. Making the count non-zero on source findings
means making those two axes vary, which moves severity bands corpus-wide; that is a calibration
change and it has not been made.

### Go recall, on the same finding set

Scored by `benchmarks/corpus-b-realworld/recall_check.py` against this run's dump, so recall and
precision describe one finding set rather than two runs:

| Denominator | Sites | Found | Recall | What it grades |
|---|---|---|---|---|
| In-scope (inside the scanned subtrees) | 407 | 303 | **74.4%** | the scanner |
| Whole Go clone tree | 1054 | 303 | **28.7%** | the benchmark harness |

647 sites (61.4%) sit outside every scanned subtree, because 92 of 150 projects are restricted
to `scan_hints.scan_paths`. **Neither number means anything without its denominator.**

In-scope, split by API kind: constructors and generators **301/325 = 92.6%**, operations
**2/82 = 2.4%**. Every signer and every verifier reads 0.0% across twelve families, as does
every one-shot digest (`md5.Sum` 0/16, `sha1.Sum` 0/11); the only two operation sites found at
all are one `rsa.EncryptOAEP` and one `rsa.DecryptOAEP`. Ground truth is 33 stdlib APIs taken
from the pkg.go.dev package indexes and import-gated — built independently of `data/rules/`,
which a rule-derived ground truth could not be without scoring 100% by construction.

**85.3% precision and 74.4% recall are one architectural fact reported twice.** A
constructor-only extractor earns its precision by declining exactly the ambiguous shapes.

### Held

`cargo test --workspace`: **271 tests across 38 suites, all passing**. No finding was added or
removed anywhere in the corpus, so no coverage was traded for either change, and no speed
figure is restated here — nothing in this change is on the scanning path.

---

## The `--fail-on` CI gate: precision recomputed on the same finding set — 2026-08-28

**Measurement tuple:** corpus B (150 projects, all populated) · scanner set
`--source --deps --include-safe` · profile `nist-default` · binary `ee9e96d` · 2 cores of an
AMD EPYC 9354P · 2026-08-28. Dump taken with the in-tree
`benchmarks/corpus-b-realworld/dump_findings.py`.

**Precision 85.3% (95% CI 81.3–89.3%), stratified — unchanged, and recomputed rather than
quoted.** Findings 1570, unchanged.

### Why a CLI change is measured at all

No rule file and no tree-sitter matcher moved, so on the usual reading this is not a detection
change. It is measured anyway because it edits the two things upstream of every rule: **which
paths get scanned, and what happens when one of them is not there.**

- Positional paths are now collected wherever they appear in argv and *all* of them are
  scanned, instead of the scan target being read from a fixed argv slot.
- Each scanner is constructed once and walked over every path, rather than once per path.
- `scan` now **refuses** a path that does not exist with exit 2, where before it walked nothing
  and printed `0 finding(s)`.

The third is the one that could delete a project from a corpus dump. It cannot here:
`dump_findings.py` filters `scan_hints.scan_paths` through `Path.exists()` before invoking the
binary and falls back to the clone root when none resolve, so no corpus invocation reaches the
refusal branch. That filter is load-bearing for this harness — 92 of 150 projects are scanned
only inside subtree hints — and it is the reason this run is a recomputation and not a
re-labelling. The first two cannot move anything either: the harness passes exactly one path per
invocation, which is the argv shape that behaved identically before and after.

That is the prediction. The check is what makes it a measurement:

| | findings | distinct sites | added | removed | changed in place |
|---|---|---|---|---|---|
| `21e4478` (the dump the 85.3% baseline was audited on) | 1570 | 1552 | — | — | — |
| `ee9e96d` (this tree) | 1570 | 1552 | **0** | **0** | **0** |

Sites are keyed on `(project, rule_id, file, line)` and compared on `algorithm_id` and
`message`; 18 rows legitimately share a site key, which is why the two columns differ.
Because a whole project vanishing is the specific signature of the missing-path refusal firing,
the estimator counts projects on both sides and names any that dropped rather than leaving it to
be read out of a site diff: **86 projects with findings before, 86 after, none dropped.**
Per-ecosystem counts are identical too: go-modules 576, maven 366, crates-io 226,
crypto-adjacent 198, npm 127, pypi 77.

### The estimator, its sample sizes and its verdicts

An unchanged finding set cannot move a TP/FP ratio, so the audited label sets apply without
re-labelling and precision is **recomputed, not re-estimated**. It is recomputed rather than
quoted because a published figure that is never re-derived cannot notice when the tree drifts
away from it; the estimator asserts it reproduces the recorded baseline from the labels before
it prints anything, and it did — 85.30%.

Same two strata, same weighting (population share) and same label sets as the 85.3% row in
*Registry-lookup suppression* above, so the two are the same figure and not merely the same
number.

| | Population | Audited | TP | FP | DEPENDS | Precision |
|---|---|---|---|---|---|---|
| Stratum A | 964 | 272 | 217 | 32 | 23 | 87.1% (held) |
| Stratum B | 606 | 90 | 70 | 15 | 5 | 82.4% (Wilson 72.9–89.0) |
| **Weighted** | **1570** | **362** | | | | **85.3%** (95% CI 81.3–89.3) |

Method, in full. Stratum B is the 606 findings from the 46 projects whose working trees were
restored, sampled uniformly at seed 20260827 and labelled once by **opening every cited
`file:line` and reading the code at it** — TP if a cryptographic operation or key of the named
algorithm exists at that line, FP if it does not, DEPENDS if the line is real but its
quantum-relevance turns on a runtime value the scanner cannot see. DEPENDS rows are excluded
from both numerator and denominator, which is why the audited 362 yields 249 + 85 = 334 graded
verdicts. Stratum A is held at the value its own 272-row audit produced; nothing in this change
removes or reclassifies a stratum-A finding, and the site-set check above is what establishes
that. The interval is the stratified normal approximation `Var = Σ wᵢ² pᵢ(1−pᵢ)/nᵢ` — **not**
Wilson, which applies only to the single-stratum figures quoted per row.

### Held

`cargo test --workspace`: **284 tests across 39 suites, all passing** — 271 before, plus the
13 that pin `--fail-on`, one of which reads the threshold out of the shipped
`.pre-commit-hooks.yaml` and asserts this binary accepts it.

`benchmarks/corpus-b-realworld/regression_check.py`: **13 of 13 floors met**, 6 per-ecosystem
and 6 per-rule plus the total, at **1570 findings, 0 projects errored**. 150 projects scanned in
**284.3 s** against 282.7 s on the previous pass over the same corpus with the same flag set, so
no speed was traded either.

No finding was added or removed anywhere in the corpus, so no coverage was traded for the gate.

---

## An emitter may not name a parameter its input does not carry — 2026-08-28

**Corpus B: 85.3% → 86.5%, on a finding set that did not move.**

Tuple. Corpus B, 150 projects, all populated · `--source --deps --include-safe` ·
profile `nist-default` · release build · dumps taken with the in-tree
`benchmarks/corpus-b-realworld/dump_findings.py` · pre `2a60a72`
(`/opt/cryptoscope/work/a1_post.json`, the dump the recorded 85.3% was audited on) →
post this cycle's working tree (`/opt/cryptoscope/work/r40_dump.json`). Estimator:
`/opt/cryptoscope/work/r40_precision.py`, which reproduced the recorded baseline from the
labels (85.30%) before printing anything, per the cycle-19 rule.

### What the defect was

P3 guarantees the `file:line` on a finding is real. Nothing guaranteed the *algorithm name*
at that line was. Four emitters resolved an input that carries a **family** into an
identifier that names a **parameter set**, and invented the parameter:

| Emitter | Input | Emitted | What the input actually determines |
|---|---|---|---|
| `oid-table.toml` | `sha512WithRSAEncryption` (`1.2.840.113549.1.1.13`) | `rsa-pkcs1-sha512-4096` | a digest and a padding; **no modulus** |
| `scan-deps/catalogue.rs` | `ml-kem = "0.2"` in a `Cargo.toml` | `ml-kem-768` | the family; the crate implements 512/768/1024 |
| `rules/cpp.toml` `CRYPTO-430` | a 7-way alternation over `RC4\|DES\|MD5\|NULL\|EXPORT` | the literal `rc4` | that *one of five* broken primitives is named |
| 61 arms, 7 rule packs | JWT `RS256`, `getInstance("EC")`, `pbkdf2::<...>` | `-2048`, P-256, `sha-256` | the digest, the key type, nothing |

The first is the unsafe direction and the reason this outranked the rest: any certificate a
CA had signed with SHA-512 reported `classicalSecurityLevel: 152` in its CBOM whatever its
real key size — a weak key made to look strong in the field a compliance reader trusts.

**The repo shipped no fixture that could show it.** Every cert in
`crates/scan-certs/tests/fixtures/` was signed with the digest matching its own key size, so
the invented modulus always agreed with the real one by accident. That is why three passes
over the cert path walked past this. `rsa2048_sha512.pem` now ships, and the assertion is
that one scan of one file does not produce two different answers about how strong the key
is: `rsa-2048` at 112 bits classical, and a signature row that claims no classical strength
at all.

### The measurement, and what licenses reusing the labels

Every edit is a rename. Exactly one changes what *matches* — `CRYPTO-430`'s regex now
requires the weak token at the start of the string or after `:`/`+`, so `DEFAULT:!RC4`,
which *removes* RC4, no longer fires as though it enabled it. `CRYPTO-430` fires **zero**
times across all 150 projects, so the corpus cannot see that arm; it is measured on the
fixture tree instead, which is the right instrument for it.

| | findings | distinct sites | added | removed | `algorithm_id` changed in place |
|---|---|---|---|---|---|
| `2a60a72` (the dump the 85.3% baseline was audited on) | 1570 | 1552 | — | — | — |
| this tree | 1570 | 1552 | **0** | **0** | **283** |

**283 of 1570 findings — 18.0%, across 42 rules and 35 projects — were carrying a parameter
their input never stated.** The transitions:

| n | from | to |
|---:|---|---|
| 91 | `rsa-pkcs1-sha256-2048` | `rsa-pkcs1-sha256` |
| 56 | `ecdsa-p256` | `ecdsa-unattributed` |
| 43 | `rsa-1024` | `rsa-undersized` |
| 34 | `rsa-2048` | `rsa-unattributed` |
| 15 | `rsa-pss-sha256-2048` | `rsa-pss-sha256` |
| 10 | `rsa-pkcs1-sha512-4096` | `rsa-pkcs1-sha512` |
| 9 | `rsa-pkcs1-sha384-3072` | `rsa-pkcs1-sha384` |
| 9 | `sha-256` | `pbkdf2-unattributed` |
| 7 | `rsa-pss-sha512-4096` | `rsa-pss-sha512` |
| 7 | `rsa-pss-sha384-3072` | `rsa-pss-sha384` |
| 2 | `rsa-2048` | `rsa-oaep` / `rsa-oaep-256` |

Per-ecosystem counts are unchanged — go-modules 576, maven 366, crates-io 226,
crypto-adjacent 198, npm 127, pypi 77 — and so is the severity distribution: **968 High,
471 Medium, 131 unscored, before and after, with 0 of the 283 moved rows changing band.**
Risk scoring reads `quantum_status` and the policy disallow-lists, not
`classical_security_bits`, and every family row carries the same status as the sized row it
replaces. So no coverage and no severity was traded for the correction.

### The estimator, its sample sizes and its verdicts

`c11_labels.py` has defined the three verdicts since the corpus was restored, and its
DEPENDS clause describes this exact defect in as many words:

> **DEPENDS** — the operation is real but `algorithm_id` asserts a parameter (modulus, key
> size, hash) the line does not state

So a DEPENDS row whose id stops asserting the parameter becomes TP **under the existing
rule**; no new labelling rule is introduced. Seven sampled stratum-B rows were re-labelled,
every one of them a row this change provably touched, and the estimator refuses to apply a
re-label to a row whose `algorithm_id` did not in fact move:

| row | rule | was | now | why |
|---|---|---|---|---|
| 2 | `CRYPTO-230` | DEPENDS | TP | `new RSAKeyPairGenerator()`; the 2048 was on line 42, not the cited line 40 |
| 5 | `CRYPTO-700` | DEPENDS | TP | `SigningMethodRS256{"RS256", crypto.SHA256}` states the digest, never a modulus |
| 6 | `CRYPTO-061` | DEPENDS | TP | real RS256 signature; same |
| 53 | `CRYPTO-700` | DEPENDS | TP | real RS256 keyset request; same |
| 78 | `CRYPTO-400` | FP | TP | line states **1027** bits; `rsa-1024` contradicted it, `rsa-undersized` is what `bits < 2048` actually matched |
| 79 | `CRYPTO-400` | FP | TP | line states **1152** bits; same |
| 89 | `CRYPTO-587` | DEPENDS | TP | `pbkdf2_hmac(..., md, ...)` — `md` is a variable, so no digest can be named, and now none is |

Three further rows moved id and keep their label, and they are named rather than left to be
read out of a diff: rows 69 and 86 (`rsa-1024` → `rsa-undersized` on lines that do state
1024 — still TP) and row 23 (FP because `t.Run("RS256", ...)` is a subtest name, which the
id change does not touch).

| | Population | Audited | TP | FP | DEPENDS | Precision |
|---|---|---|---|---|---|---|
| Stratum A | 964 | 272 | 217 | 32 | 23 | 87.1% (held) |
| Stratum B, before | 606 | 90 | 70 | 15 | 5 | 82.4% |
| Stratum B, after | 606 | 90 | **77** | **13** | **0** | **85.6%** (Wilson 76.8–91.4) |
| **Weighted** | **1570** | **362** | | | | **86.5%** (95% CI 82.7–90.3) |

`precision = TP / (TP + FP)`, DEPENDS excluded from both sides, as in every prior figure.
The interval is the stratified normal approximation `Var = Σ wᵢ² pᵢ(1−pᵢ)/nᵢ` — not Wilson,
which applies only to the single-stratum figures quoted per row.

**Stratum A is held at 87.1%, and that understates this change.** Its 272 per-row labels do
not survive, so rows corrected there cannot be re-read — and the effect could only run the
same way it ran in stratum B. `PRECISION_AUDIT_V3` row 1 is a stratum-A row labelled FP for
precisely this reason (`rsa.GenerateKey` 768-bit reported as `rsa-1024`), and §5 of that
same audit asked for the `pbkdf2` fix by name — *"emit a distinct algorithm_id for
unresolvable cases; option (b) preserves the finding while making the algorithm_id
honest."* Holding A is the conservative choice and matches how every figure since the
restoration was computed.

### The invariant, and why it is a gate rather than a fifth fix

This defect has been repaired pairwise four times — Diffie-Hellman group sizes at `9e60ffe`,
Rust crate paths, and the two above — and each time it regrew in a file nobody re-checked.
`crates/cli/tests/algorithm_parameters.rs` states the rule instead: **an algorithm-id's
bare-number segments must each appear in the emitter's own matching text** — the tree-sitter
query, the `when` clause, the package pattern — with classify arms joined to the extract
blocks whose `api` they match. Prose fields and comments are stripped first, because moving
the size into the message is the fix and must not also be the excuse. The OID table cannot
be checked that way (an OID is opaque: nothing in `2.16.840.1.101.3.4.4.2` looks like the
768 it determines), so each row declares whether it pins the full parameterisation, and a
row that says it does not may not resolve to a parameterised id. Where a parameter really
is determined but no digit shows it, the rule cites the standard in `parameter_source` —
four do, all `ES512` → P-521 by RFC 7518 § 3.4 and one jsonwebtoken HS256 default.

All checks were confirmed to fail before they pass, by reverting each retarget in turn.

**The emitter set was eleven and is twelve.** `scan-certs` resolved RSA by modulus through a
`match` on bare string literals, so `algorithm_reachability.rs`'s "no emitter outside the
enumerated set" — the direction written specifically to catch a missed emitter — walked past
it. Those arms are a table with an `algorithm_id` field now, which is the shape it reads.
The table is 108 rows, 15 of them carrying an `undetectable` reason.

### Held

`cargo build --release --workspace` clean; `cargo fmt --all --check` and
`cargo clippy --workspace --all-targets` clean. `cargo test --workspace`: **289 tests, all
passing** (284 before — two for the invariant gate, one for the missing cert fixture, one
for the cipher-list exclusion prefix, one for the PQC manifest). `tests/check.py` 69/69.

`benchmarks/corpus-b-realworld/regression_check.py`: **13 of 13 floors met**, 6
per-ecosystem and 6 per-rule plus the total, at **1570 findings, 0 projects errored**. 150
projects scanned in **289.4 s** against 284.3 s on the previous pass over the same corpus
with the same flag set — inside the ±10% run-to-run variance this corpus has shown all
along, so no speed was traded either.

### What this does not fix, stated so it is not read as fixed

`CRYPTO-260` matches `^RSA_USING_SHA` — jose4j's SHA-256, SHA-384 and SHA-512 identifiers —
and emits one digest for all three. That is the same *shape* as `CRYPTO-430`: one literal id
for an alternation. It is a different defect, because there the input does determine the
digest and we name the wrong one, where here the input determines nothing and we invent it.
The gate above cannot see it: it checks bare-number segments, and `sha256` is not one.
`PRECISION_AUDIT_V3` rows 111 and 118 have it filed as the sole remaining Pattern D-prime
false positive; it is a stratum-A row, so fixing it would not move the figure published here
and it is left for a cycle that can measure it.

---

## One scan, one answer per finding: precision recomputed on a finding set that did not move — 2026-08-28

**Tuple.** Corpus B, 150 projects, all with a populated working tree · `--source --deps
--include-safe` · profile `nist-default` · release build · dumps taken with the in-tree
`benchmarks/corpus-b-realworld/dump_findings.py` · pre `8b42227`
(`/opt/cryptoscope/work/r40_dump.json`, the dump the recorded 86.5 % was taken on) → post this
cycle's tree (`/opt/cryptoscope/work/r41_dump.json`). Estimator
`/opt/cryptoscope/work/r41_precision.py`, which reproduced the recorded 86.5 % from the labels
(86.53 %) before printing anything.

```
  stratum A   964 findings  w=0.614  272 audited  217 TP / 32 FP / 23 DEPENDS  87.1 % (held)
  stratum B   606 findings  w=0.386   90 audited   77 TP / 13 FP /  0 DEPENDS  85.6 % (Wilson 76.8–91.4)
  WEIGHTED   1570 findings                                                     86.5 % (95 % CI 82.7–90.3)
```

### Why a reporting-layer change is measured at all, and the strictest prediction available

Every edit is in the layer that *reads* findings — `crates/report`, `crates/tui`,
`crates/cli/src/mcp`, the stdout loop, and one new function in `crates/core/src/risk.rs`. No rule
file, no tree-sitter matcher, no algorithm id, no OID mapping and no message template is touched.
So unlike the previous cycle, which renamed 283 ids in place, the prediction here is the strictest
one the corpus can carry: **identical site set, identical ids, identical messages, identical
stdout severities.** Checked rather than asserted:

```
pre 1570 findings / 1552 distinct sites    post 1570 / 1552
  added 0   removed 0
  algorithm_id changed in place: 0
  message      changed in place: 0
  severity     changed in place: 0
  ecosystem    changed in place: 0
per-ecosystem: go-modules 576, maven 366, crates-io 226, crypto-adjacent 198, npm 127, pypi 77
projects carrying findings: pre 86, post 86 — none dropped
```

The one field that *could* have moved and did not: `dump_findings.py` reads the stdout severity
column, and the stdout loop was rewritten to call the new shared `severity_of` instead of doing
its own table lookup and score. That column is byte-identical on all 1570 rows, which is what
makes the refactor faithful at the one call site the corpus can see.

### The population this change is about: 131 of 1570 findings, 8.3 %

A finding whose `algorithm_id` has no algorithm-table row cannot be scored —
`algorithm_vulnerability` is 40 of the 100 points the risk engine assigns and is read entirely
from that row. Measured on this dump:

```
unscored findings (stdout `?`):  131  (8.3 % of the corpus)
  by rule:      {'DEP-001': 131}
  by algorithm: {'unknown': 131}
stdout severity distribution: {'High': 968, 'Medium': 471, '?': 131}
```

All 131 are `DEP-001` carrying `scan-deps`'s `unknown` sentinel: a manifest that names a crypto
library but no algorithm. **Every artifact used to answer this differently.** Reproduced on one
`openssl = "0.10"` line in a `Cargo.toml`, and again on the corpus project `crates-io/age`:

| surface | before | after |
|---|---|---|
| stdout | `?` | `?` |
| `summary.json` | `medium: 1` | `unscored: 1` |
| HTML report | Medium card, score 25 | Unscored card |
| SARIF | `warning`, `security-severity: 5.0` | `none`, property omitted |
| TUI | `Safe` | `UNSC` |
| `--fail-on` | unscored, skipped | unscored, skipped |

Four answers for one finding. The loudest asserted a mid-band CVSS to GitHub Advanced Security
for a finding the product declines to score; the quietest painted an uncatalogued algorithm
green. `--fail-on` was already right, and only because implementing that gate forced the question
to be answered once. `quipuu_core::score_of` is now where it is answered for everybody.

Corpus-wide this moves **131 findings out of `summary.json`'s `medium` count** and into a new
`totals.unscored` field, leaving `medium` agreeing with the stdout column it never agreed with
before. Verified per project on both binaries — `crates-io/age`, one finding: `8b42227` reports
`medium: 1`, this tree reports `unscored: 1, medium: 0`. That is a shape change to a published
artifact, recorded here rather than left for a consumer to discover.

### The HNDL contradiction, which is the defect that started this

`crates/report/src/html.rs` filtered its HNDL-critical section on
`hndl_critical || severity == Critical`; `summary.json` counted only the first. On one
RSA-2048/SHA-256 certificate that produced two artifacts of one scan that disagreed, and an HTML
document that disagreed with itself:

```
before:  summary.json "hndl_critical": 0     HTML card 0     HTML badges 2
after:   summary.json "hndl_critical": 0     HTML card 0     HTML badges 0
```

On the X25519 fixture — a key-agreement SPKI, the one shape the default policy's `[hndl_flag]`
block describes — the flag, the card and the badge count are all **1**, and the same
certificate's Ed25519 signature finding, which is Critical and not HNDL, is no longer badged.
The corpus count is unchanged at **0 of 1570**: corpus B runs `--source --deps` and never
exercises `scan-certs`, so it cannot speak to this path, which is why the fixture is the
instrument. The section's own doc comment had recorded the wrong rule as if it were intended.

### The gate, and the direction that catches the next surface

`crates/cli/tests/artifact_agreement.rs`, five tests. Four compare the artifacts the binary
actually writes — it is the first test in the repo that reads the HTML. The fifth is a
source-text direction: no file outside `crates/core/src/risk.rs` may call
`QuantumRiskScore::compute`, so a seventh surface cannot quietly re-derive what a missing
algorithm row means. Each was confirmed to fail before it passes, by reverting each half in turn:
restoring the HNDL filter fails two, restoring `None => medium` fails one, adding a direct
`compute` call in the TUI fails the fifth.

The same sweep found two instances nobody had filed. The TUI's `HNDL:` badge carried the
identical `|| severity == Critical` conflation. And the MCP `query_findings` severity filter had
no `else` arm, so an unscored finding matched **every** severity filter — `severity: "Critical"`
returned findings the same session reported as having no severity.

### Held

`cargo build --release --workspace` clean; `cargo fmt --all --check` and
`cargo clippy --workspace --all-targets` clean. `cargo test --workspace`: **294 tests across 41
targets, all passing** (289 before; this cycle adds the five artifact-agreement tests).
`tests/check.py` 69/69.

`benchmarks/corpus-b-realworld/regression_check.py`: **13 of 13 floors met**, 6 per-ecosystem
and 6 per-rule plus the total, at **1570 findings, 0 projects errored**. 150 projects scanned in
**317.0 s** against 289.4 s on the previous pass over the same corpus with the same flag set —
inside the ±10 % run-to-run variance this corpus has shown throughout, and no scanning code was
touched, so no speed was traded.

### What this does not fix, stated so it is not read as fixed

Severity still encodes which scanner produced the finding. `scan-source` fixes four of the five
risk axes at its single `Finding` construction site, so source findings occupy `{27, 32, 42, 67}`
and never reach the Critical band at ≥75, while cert findings clear it structurally — which is
why a healthy RSA-2048/SHA-256 certificate scores Critical on both its key and its signature.
That is a calibration change, it moves bands across the whole corpus, and it has not been made.
This change makes the artifacts agree on the band the engine computed; it does not change the
band.

---

## Rename verification — 2026-08-28 (seawall → quipuu)

Same check as the previous rename, and the same result. Every file under `crates/core/data/` — the
algorithm table, OID table, default policy, and all seven rule packs — was normalised for the
product name and compared against its pre-rename revision. **All eleven identical.** No rule, `when`
clause, `algorithm_id`, severity mapping, or policy weight changed.

Precision therefore stands at **86.5%**, carried forward rather than re-derived. The figure is
traceable to the run recorded above it, not merely to a green gate.

---

## `alg=none` needs a second witness — 2026-08-28

Tuple, per the reproducibility rule this file uses throughout: **corpus B, 150 projects, all with
a populated working tree · scanner set `--source --deps --include-safe` · profile `nist-default` ·
release build from this tree · dumps taken with `benchmarks/corpus-b-realworld/dump_findings.py`.**

**91 findings removed, 0 added, 0 re-classified. Precision 86.5 % → 87.3 % under the estimator
that produced the recorded baseline, and 80.0 % → 84.7 % under the estimator that stops holding
stratum A constant.** The second pair is the honest one and the first pair is the comparable one;
both are printed by the same script, from the same two dumps, and § *The estimator* below says why
they differ by 6.5 pp before a line of the diff is applied.

### What was firing

`CRYPTO-740` carries `severity_hint = "critical"`, `CWE-347`, and the message *"JWT alg=none —
signature verification is disabled. CVE-2015-9235 class vulnerability."* It is the loudest thing
this scanner says. It fired **92 times** on the corpus, and on 91 of those the cited line has
nothing to do with authentication:

```
CRYPTO-740, pre-change:                             92 findings, 5.9 % of the corpus
  aws-sdk-go-v2   47   IpcModeNone = "none", SSETypeNone = "none", CachePolicy…None = "none"
  aws-sdk-go      29   generated service enums, same shape
  x-crypto         6   compressionNone = "none" — the SSH null compression algorithm,
                       and `ssh -F none` in a test's argument list
  hydra            4   oauth2.SetAuthURLParam("prompt", "none")
  jwx              2   one real registry entry, one test that tampers a header
  go-redis         2   EndpointTypeNone = "none"
  client-go        1   a test's config value
  pgx              1   require_auth = "none"
```

**0 of the 92 cited lines mention JWT, JOSE, JWS, JWE or JWK.** The cause is one entry in
`GO_ALG_SWITCH_WHITELIST`: `"none"` is the only whitelisted JWA name that is also an ordinary
English word, and the extract layer accepted it in any const, var, composite literal, argument
list or assignment — the same syntactic positions that make the whitelist work for `RS256`.

### The change, and the fix that was rejected on measurement

The obvious gate — require a JWT/JOSE import in the file — was **tried and rejected before it was
written**. The pinning fixture `crates/scan-source/tests/fixtures/go/jwt_register.go` imports only
`crypto`, so an import gate breaks a legitimate test; and 6 of the 92 false positives import a JOSE
package anyway, so it does not even clear the corpus.

What ships instead is corroboration on siblings: `"none"` registers an algorithm only when another
JOSE algorithm name appears in the same `const`/`var` declaration, composite literal, `switch`, or
enclosing block. One name vouches for another, which is exactly how a registry is written and
exactly how an enum of unrelated strings is not.

The one surviving corpus finding is the one that was always real —
`go-modules/jwx/jwa/signature_gen.go:23`, `algorithms[8] = NewSignatureAlgorithm("none")`, three
lines below `NewSignatureAlgorithm("HS512")`. **That survival was the falsification condition
stated in advance**: if jwx's own registry had stopped being detected, the window was too narrow
and the change was not to land. It is asserted in the estimator script, not checked by eye.

```
sites added 0   sites removed 91   removed by rule: {'CRYPTO-740': 91}
CRYPTO-740: 92 -> 1
findings classifying as jwt-alg-none whose file names no other JOSE algorithm: 91 -> 0
stdout severity: High 968 -> 877, Medium 471 -> 471, unscored 131 -> 131
by ecosystem:    go-modules 576 -> 485; maven, crates-io, crypto-adjacent, npm, pypi unchanged
```

**A recall loss that was checked for and did not happen.** golang-jwt/jwt registers `alg=none` as
`func (m *signingMethodNone) Alg() string { return "none" }` — a lone literal in a method body
with no sibling name, which corroboration would drop. Scanned directly, that file produces no
`CRYPTO-740` **before or after**: the return-statement shape never matched the classify rule's
site-context list, so there was nothing to lose. Checked rather than assumed, because it is the
most-used Go JWT library in the corpus.

### The estimator, and why this cycle reports two numbers

The recorded baseline is a two-stratum weighted estimate in which stratum A — 964 of 1570
findings — is the constant `A_TP, A_FP, A_DEPENDS = 217, 32, 23`, a carried 87.1 % whose per-row
labels do not survive. **77 of the 91 findings this change removes are in that stratum**, so 85 %
of the repair is invisible to the published figure by construction.

So stratum A was re-audited in the same run: 150 rows, uniform, seed 20260828, every row labelled
by opening its cited `file:line`, verdicts published in full in `PRECISION_AUDIT_V4.md`. It audits
at **76.6 %** (111 TP / 34 FP / 5 DEPENDS), not 87.1 %.

| estimator | pre — 1570 findings | post — 1479 findings | delta |
|---|---|---|---|
| of record (stratum A held) | 86.5 % (82.7–90.3) | **87.3 %** (83.6–91.0) | +0.8 pp |
| corrected (stratum A audited) | 80.0 % (74.9–85.1) | **84.7 %** (80.0–89.4) | +4.7 pp |

Read the columns, not the diagonal. **86.5 → 80.0 is the same scanner on the same dump** — the
cost of the constant, not a regression, and it appears the moment the held stratum is read instead
of remembered. **80.0 → 84.7 is this diff.** The +0.8 pp in the first row is the same repair seen
through an estimator that cannot see 77 of the 91 findings it removed.

`state/precision.json` holds 86.5 % under the estimator of record, and the figure this run reports
to it is the like-for-like **87.3 %**, because that is the only one of the four numbers above that
is comparable to what it holds. The recommendation on the evidence is to re-anchor it to 84.7 %
and delete the constant — a change to the recorded baseline is not a cycle's to make.

Both rows are produced by one script, `/opt/cryptoscope/work/v1b_precision.py`, which asserts that
the estimator of record reproduces its own 86.5 % baseline on the pre dump before printing
anything, and aborts if the change added any finding or removed one outside `CRYPTO-740`.

### Held

`cargo build --release --workspace` clean. `cargo test --workspace`: **295 tests across 41
targets, all passing** (294 before; this cycle adds `go_alg_none_fires_only_beside_another_jose_name`,
which pins both corroborated shapes and all four uncorroborated ones against two new fixtures).
`phase9_go_const_declaration_registers_none` passes **unchanged** — its fixture declares `none`
beside `hs256` and `hs384`, which is the shape corroboration is meant to keep, and it is the test
that made this the right instrument rather than an import gate.

`regression_check.py`: **13 of 13 floors met** at 1479 findings, 150 projects, 0 errored. The
per-rule floor for `CRYPTO-740` is lowered from 3 to **1** in the same change, with the count and
the reason recorded beside it — one real site is what this corpus contains, and a floor of 3 would
have demanded two false positives in perpetuity.

### What this does not fix

The 11 `alg=none` rows in the stratum-A sample were **15 % of that stratum's measured false
positives**. The other two shapes it found — the Java JOSE-dispatch constant
(`alg.equals(JWSAlgorithm.PS256)`, 13 rows) and calls a test requires to fail
(`jwt.encode(...)` inside `pytest.raises`, 6 rows) — are untouched, and together they are twice
the class removed here. Both are named in `PRECISION_AUDIT_V4.md § 2` with their file:line
evidence; neither has a rule change behind it yet.

---

## A JOSE name compared is not a JOSE name used — 2026-08-28

Tuple, per the reproducibility rule this file uses throughout: **corpus B, 150 projects, all with
a populated working tree · scanner set `--source --deps --include-safe` · profile `nist-default` ·
release build from this tree · dumps taken with `benchmarks/corpus-b-realworld/dump_findings.py`,
`work/w2_pre.json` (1479) → `work/w2_post.json` (1399).**

**80 findings removed, 0 added, 0 re-classified. Precision 87.3 % → 87.3 % under the estimator
that produced the recorded baseline, and 84.7 % → 89.9 % under the estimator that reads stratum A's
labels instead of holding it constant.** Both come from one script over the same two dumps. The
flat reading is not evidence that nothing happened, and § *Why the two estimators disagree* says
why it could not have moved.

### What was firing

`PRECISION_AUDIT_V4.md § 2` audited the held stratum for the first time and found its largest
false-positive class was not `alg=none` but this: **a Java JOSE algorithm constant that is compared
against, collected into a supported-algorithm set, or used as a lookup-table key**, reported as
though the line signed, wrapped or hashed something. 13 of that audit's 150 sampled rows.

Across the corpus the class is **94 Java enum-constant findings, of which 80 name an algorithm
without performing it**:

```
Java enum-constant findings, pre-change:            94, in 4 of 150 projects
  nimbus-jose-jwt              64   alg.equals(JWSAlgorithm.PS256), algs.add(JWSAlgorithm.HS512)
  jose4j                       15   super(AlgorithmIdentifiers.RSA_USING_SHA256, "SHA256withRSA")
  azure-security-keyvault-keys  9   defaultAlgorithms.put(SignatureAlgorithm.ES256, SHA_256)
  jjwt-api                      6   Arrays.asList(HS512, HS384, HS256)

the 80 removed, by the shape of the cited line — 76 distinct lines:
  44   alg.equals(X) / X.equals(alg) / alg == X     a branch test
  18   algs.add(X)                                  a SUPPORTED_ALGORITHMS set
   9   map.put(X, hash)                             a resolver table
   6   Arrays.asList(X, Y, Z)                       a preference list (2 lines)
   3   return JWSAlgorithm.ES256;                   ECDSA.resolveAlgorithm(Curve)
```

This is the Java spelling of a class this repo has already ruled on twice. `PRECISION_AUDIT_V3.md
§ 0` suppressed the Go registry lookup `jwa.LookupSignatureAlgorithm("PS256")` and booked
81.8 % → 85.3 % for it; `PRECISION_AUDIT_V4.md § 2` recorded, in writing and before this change
was written, that **both spellings are false positives** — because the labelling rule the two
strata share already names "switch comparison operand" and "string constant" as FP, and
`alg.equals(JWSAlgorithm.ES256)` is those two things in Java.

### Why it had never been caught

Two defects, one cause. `classify_site_context` reads a match's surrounding syntax, and every arm
that needed to know the callee asked tree-sitter for the node's `function` field. Go, JavaScript
and Rust have one. Java's `method_invocation` splits the callee into `object` + `name`, so
**`function` is `None` at every Java call site** and the TestAssertion and RegistryLookup arms —
including the Java branch of `is_test_assertion_callee`, written and shipped — had never once
fired on Java. Separately, the arm that recognises a declaration knew `const_spec` and `var_spec`
but not `local_variable_declaration` or `field_declaration`, so `JWSAlgorithm ns =
JWSAlgorithm.RS384;` read as `Default` — indistinguishable from "we did not look".

The result was that every Java enum reference landed in one of two contexts, `Call` or `Default`,
and the 32 classify rules behind them named no `when.site_context` at all, so they fired in both.

### The change

`SiteContext` gains two variants, both stated as concepts rather than as library names:

- **`Comparison`** — an operand of `.equals(…)` / `==` / `!=`. Naming an algorithm to test a value
  against it selects a branch; the operation the branch guards cites its own line.
- **`CollectionElement`** — an element handed to `add` / `addAll` / `asList` / `of` / `contains` /
  `remove`, or an array initialiser. A supported-algorithm set declares a capability, not a use.

`map.put(alg, …)` routes to the existing `MapEntry`, which already documented the keyed-literal
form of the same table. The 32 Java enum classify rules then carry
`when.site_context = ["Call", "StringConstant"]` — the same idiom the Go JOSE rules have carried
since Phase 16.

**What survives is the half that binds the algorithm to something that uses it**: 14 findings, all
in jose4j, all `super(AlgorithmIdentifiers.RSA_USING_SHA256, "SHA256withRSA")`-shaped constructors
or `setAlgorithmIdentifier(AlgorithmIdentifiers.NONE)`. **That survival was the falsification
condition stated in advance** — row 91 of `PRECISION_AUDIT_V4.md § 5`, hand-labelled TP, must
still be detected or the allow-list is too narrow and the change does not land. It is asserted in
the estimator script, not checked by eye.

```
sites added 0   sites removed 80
removed by project: nimbus-jose-jwt 64, azure-security-keyvault-keys 9, jjwt-api 6, jose4j 1
Java enum-constant findings: 94 -> 14
Java enum findings on a line that only compares or collects the name: 71 -> 0
severity: High 877 -> 815, Medium 471 -> 453, unscored 131 -> 131
by ecosystem: maven 366 -> 286; go-modules, crates-io, crypto-adjacent, npm, pypi all unchanged
```

### Why the two estimators disagree

All four affected projects are `maven`, and all of `maven` was checked out before the 2026-08-27
corpus restoration, so **every finding this change removes is in stratum A**. Under the estimator
of record stratum A is the constant `217/32/23 = 87.1 %`. A constant cannot fall when 80 of its
false positives are deleted; all that estimator can see is the stratum's weight going 0.600 →
0.577, against a stratum B at 87.5 % — which is why it prints **87.3 % → 87.3 %, +0.0 pp**. The
same arithmetic gave `alg=none` +0.8 pp last cycle for removing 91 false positives.

Read from labels instead, stratum A goes **82.8 % → 91.7 %** on its 150-row sample: 13 of its 23
surviving false positives are this class, and all 13 stop resolving. Weighted against an unchanged
stratum B that is **84.7 % → 89.9 %** (95 % CI 85.9–94.0), **+5.2 pp**.

The two movements must not be added, and neither is a correction of the other.

### The coverage cost, stated rather than buried

**`jjwt-api` goes from 6 findings to 0.** All 6 sit on the two `Arrays.asList(…)` preference-list
lines, and `PRECISION_AUDIT_V4.md § 5` rows 86–88 label them false positives. The module is
jjwt's interface half — the enum lives there and the signing lives in `jjwt-impl`, which is not in
the corpus — so zero is the right answer for it, but it is a real loss of the only corpus evidence
that the scanner reads jjwt at all.

That evidence moves in-tree rather than disappearing. `regression_check.py` had a per-rule floor
of 1 on `CRYPTO-241` labelled *"the canonical jjwt-api regression"*; the corpus contained exactly
one `CRYPTO-241` site and it is one of the six false positives, so the floor demanded that a false
positive be kept in perpetuity and 0 would be a floor that cannot fail. It is removed, with the
count and the reason in its place, and the regression it guarded — the scanner going silent on
jjwt — is now held by `phase1_jjwt_*` and the new `java_jose_operational_sites_still_fire` in
`crates/scan-source/tests/scan_test.rs`, which is where a shape this narrow belongs.

The three `return JWSAlgorithm.ES256;` rows were not in any audited sample and are labelled here,
by reading the enclosing method: they are the three arms of
`ECDSA.resolveAlgorithm(Curve curve)`, which returns the JWS algorithm matching a curve and signs
nothing — the Java spelling of the `RegistryLookup` shape suppressed in Go. They are removed as
`Default` rather than recognised as resolver returns; that is the allow-list doing it, and it is
recorded as such rather than claimed as a diagnosis.

### Gate

`java_enum_classify_rules_declare_the_sites_they_fire_in` (`crates/scan-source/src/rules.rs`)
fails the build when a classify rule reachable through `match_java_field_access` names no
`when.site_context`. A bare enum reference carries no evidence about what is being done with the
name — `JWSAlgorithm.PS256` is the same eleven characters in a signature, a branch test and a
capability list — so a rule that stays silent about site context fires in all three. **Confirmed
it fails** by deleting one allow-list and re-running: it named `CRYPTO-240`.

### Held

- `cargo build --release --workspace` clean; `cargo fmt --all --check` and `cargo clippy
  --workspace --all-targets` clean.
- `cargo test --workspace` **298 tests passing** (295 before): the three added are the gate above
  and `java_jose_operational_sites_still_fire` / `java_jose_dispatch_sites_do_not_fire` over the
  new `crates/scan-source/tests/fixtures/java/JoseDispatch.java`, whose two halves assert that the
  operational shapes keep firing and the dispatch shapes do not. A change that silenced the bottom
  half by silencing the top would fail the first test.
- **Go line-exact recall 74.4 % (303/407), unchanged**, re-measured on the post dump with
  `recall_check.py`. No removed finding is a Go site, so the figure had to hold; it is re-run
  rather than assumed.
- `w2_pre.json` reproduces `v1b_post.json` on all 1479 rows — project, rule, file, line,
  `algorithm_id`, severity and message — so both carried label sets apply unaltered and the pre
  column is a reproduction rather than a re-derivation. Asserted in the script before it prints.

### Speed, re-run rather than carried

`scan_corpus.py` over the same 150 projects on the same binary: **294.9 s**, 150 of 150 scanned,
0 errored, **1399 findings — the same total `dump_findings.py` reached independently.**
Per project **median 180 ms · mean 1964 ms · p90 1.6 s · max 132.9 s**, with **128 of 150 under a
second**. The 10.9x mean/median gap is three repositories: `aws-sdk-go-v2` at 132.9 s,
`aws-sdk-go` at 41.1 s and `wolfssl` at 17.3 s are 64.9 % of the total between them. Earlier
passes over this corpus gave 281.1 s, 282.0 s, 329.0 s and 367.4 s, so read the whole-corpus
figure as four to six minutes on two shared cores; the finding counts do not vary that way.

### Not re-taken, said out loud

The `--policy nsa-cnsa2` divergence is **not** re-measured on the 1399-finding corpus; it
describes a 964-finding one. `scan-network` and `scan-certs` are untouched and corpus B does not
exercise them. The published figure still disagrees with the `PRECISION:` line reported to the
gate, for the reason `PRECISION_AUDIT_V4.md § 4` gives: `state/precision.json` holds the estimator
of record, and re-anchoring it is a human's decision, not a cycle's.

## `--certs` adds a scan mode, it does not replace the ones you had — 2026-08-28

Tuple, per the reproducibility rule this file uses throughout: **corpus B, 150 projects, all with
a populated working tree · scanner set `--source --deps --include-safe` · profile `nist-default` ·
release build from this tree · dumps taken with `benchmarks/corpus-b-realworld/dump_findings.py`,
`work/w2_post.json` (1399) → `work/y1_post.json` (1399).**

**0 findings added, 0 removed, 0 re-classified — the post dump is row-identical to the pre dump on
all 1399 rows. Precision 87.3 % → 87.3 % under the estimator that produced the recorded baseline,
and 89.9 % → 89.9 % under the estimator that reads stratum A's labels instead of holding it
constant.** Both come from one script over the same two dumps, and no row of either label set was
re-scored.

This section exists because the change had been measured once and the measurement was not written
down. It is not a quotation of that run: the dump was re-taken from scratch on a binary rebuilt
from the committed tree, and the two dumps are asserted equal before any figure is printed.

### What was firing

Every scan-mode flag set one `explicit_modes` bit, and the source+deps default was applied only
when that bit was clear. So naming *any* mode suppressed the default rather than adding to it —
including `--certs`, which the help text calls "opt-in", a word that reads as additive. On a tree
containing no certificates, asking for certificates scanned nothing:

```
npm/elliptic, no certificate anywhere in the tree

                                     before              after
  scan <path> --fail-on high         exit 1, 2 findings  exit 1, 2 findings
  scan <path> --certs --fail-on high exit 0, 0 findings  exit 1, 2 findings
```

**Adding a mode made the tool report safe on a tree it had not opened**, and a CI gate that failed
without the flag passed with it. That is the same class as a missing path silently scanning
nothing, one layer up: the exit code says "clean" when the honest answer is "not looked at".

Mode composition on the same project, `--include-safe`, counting reported findings. Only the
`--certs` row moves, which is what an additive opt-in has to look like:

| flags | before | after |
|---|---|---|
| *(none)* | 4 | 4 |
| `--source` | 4 | 4 |
| `--deps` | 0 | 0 |
| `--certs` | **0** | **4** |
| `--all` | 4 | 4 |

`--deps` returning 0 in both columns is the check that the fix does not over-reach: a base-set
selector must still narrow, or "additive" has been applied to the wrong flags.

### The change

The flags are split by what they mean. `--source`, `--deps` and `--all` are **base-set selectors**
— naming one narrows the scan, which is the only reason to name it — and they set the renamed
`explicit_base`. `--certs` and `--net` are **additive opt-ins** and set nothing, so the default is
applied after them and a cert scan is a cert scan *plus* the code.

`SPEC.md § 11` illustrated the old semantics with `scan --certs ./certs/`, annotated
"or `--certs-host example.com:443`". That idiom meant "certificates only" — the behaviour being
removed — and `--certs-host` is not a flag: it appears nowhere in `crates/`. The example was
corrected in the same change.

### Why corpus B cannot see this, stated before the run rather than after

`dump_findings.py` invokes the binary with a fixed `--source --deps --include-safe`. Both of those
are base-set selectors, so `explicit_base` is true on every corpus invocation exactly as
`explicit_modes` was, and the mode set the corpus is scanned with does not move. The diff can only
change what happens when `--certs`/`--net` appear **alone**, which corpus B never does.

The run is therefore a **falsification, not a re-derivation**: the prediction is row-identity, and
the script exits non-zero and refuses to print a figure if the post dump differs from the pre dump
by so much as one `message` string. It did not.

### The measurement — sample size, verdicts, method

Method: two uniform samples, labelled once by opening every cited `file:line`, carried unchanged
from the audits that took them. Findings are stratified by project and each stratum is weighted by
its share of the 1399-finding population; `DEPENDS` rows are excluded from the ratio and their
sensitivity is reported separately. Wilson intervals per stratum, normal-approximation interval on
the weighted total.

| | findings | weight | audited | TP | FP | DEPENDS | precision |
|---|---|---|---|---|---|---|---|
| **estimator of record** | | | | | | | |
| stratum A — held at its carried constant | 807 | 0.577 | 272 | 217 | 32 | 23 | 87.1 % (82.4–90.7) |
| stratum B — `c11_sample.json`, n=100 | 592 | 0.423 | 88 *(12 no longer resolve)* | 77 | 11 | 0 | 87.5 % (79.0–92.9) |
| **weighted** | **1399** | | **360** | | | | **87.3 % (83.5–91.1)** |
| **corrected estimator** | | | | | | | |
| stratum A — `v1_sampleA.json`, n=150 | 807 | 0.577 | 126 *(24 no longer resolve)* | 111 | 10 | 5 | 91.7 % (85.5–95.4) |
| stratum B — as above | 592 | 0.423 | 88 | 77 | 11 | 0 | 87.5 % (79.0–92.9) |
| **weighted** | **1399** | | **214** | | | | **89.9 % (85.9–94.0)** |

Both columns are identical pre and post, because the population is. The script asserts that the
estimator of record reproduces its own recorded 87.3 % and that the corrected estimator reproduces
the published 89.9 % **before** it prints anything, so the figures above are reproductions rather
than fresh claims.

### Held

- `cargo build --release --workspace` clean; `cargo fmt --all --check` and `cargo clippy
  --workspace --all-targets -- -D warnings` clean.
- `cargo test --workspace` **301 tests passing** (298 before). The three added are in
  `crates/cli/tests/fail_on_gate.rs`, whose subject is already a gate that cannot fail:
  `certs_is_additive_and_does_not_suppress_the_default_set` fails against the previous parser, and
  two others pass in both directions and exist to stop the fix over-reaching — an explicit
  `--source` must still skip deps.
- The release binary rebuilt from the committed tree is **byte-identical** to the one this change
  was first measured on, so `y1_post.json` is also a reproduction check on that earlier dump; the
  script asserts that equality too.
- Recall is untouched: no finding was added or removed, so no Go line-exact figure can have moved.

### Not re-taken, said out loud

Speed is **not** re-measured here. The finding set did not move and the parser change is one
boolean's worth of work in argument handling, so the corpus wall-clock figure from the previous
section stands; a fresh timing pass on two shared cores varies by more than this change could.

`scan-certs` and `scan-network` are **not** exercised by corpus B, so the additive behaviour of
`--certs` and `--net` is measured on `npm/elliptic` and in the fixture tests above, not on the
corpus. The corpus run's job here is only to prove the change did not reach further than claimed.

**There is now no way to say "certificates only."** That was previously expressed by the same
behaviour that made this unsafe. Restoring it needs a negation flag, not replace-semantics, and no
demand for it is recorded.

---

## `crypto_sign_keypair` is not libsodium's alone — 2026-08-28

Tuple, per the reproducibility rule this file uses throughout: **corpus B, 150 projects, all with
a populated working tree · scanner set `--source --deps --include-safe` · profile `nist-default` ·
release build from this tree · dumps taken with `benchmarks/corpus-b-realworld/dump_findings.py`,
`work/x1_post.json` (1399) → `work/n1_post.json` (1399).**

**10 findings re-identified, 0 added, 0 removed. Precision 87.3 % → 88.3 % under the estimator
that produced the recorded baseline, and 89.9 % → 90.9 % under the estimator that reads stratum
A's labels instead of holding it constant.** Both come from one script over the same two dumps,
and both reproduce their own baselines on the pre dump before anything else prints.

This is the first change in three cycles that the estimator of record can see, and the reason is
worth naming: the false positives it removes are in `crypto-adjacent`, which sits in stratum B —
the stratum that is *not* held at a constant. The two preceding cycles removed 91 and 80 false
positives and were scored +0.8 pp and +0.0 pp because every one of them sat inside the constant.

### What was firing

`cpp.toml`'s extract `CPP-041` matched the bare identifier `crypto_sign_keypair` with no libsodium
qualification of any kind — no include guard, no header check, no path constraint — and classify
`CRYPTO-441` attributed `ed25519` unconditionally. That identifier is the SUPERCOP/NIST signature
API name: libsodium and TweetNaCl implement it as Ed25519, and **every NIST PQC reference
implementation publishes its own keygen under exactly the same name.**

So we shipped `ed25519 — Replace with ML-DSA-65` on ML-DSA's and SLH-DSA's reference code:

| tree | before | after |
|---|---|---|
| `crypto-adjacent/dilithium` (FIPS 204 reference) | 5 findings, `ed25519`, High | 0 `CRYPTO-441`; 5 `CRYPTO-442`, no algorithm asserted, Medium |
| `crypto-adjacent/sphincsplus` (FIPS 205 reference) | 3 findings, `ed25519`, High | 0 `CRYPTO-441`; 3 `CRYPTO-442` |
| `npm/tweetnacl` (includes `tweetnacl.h`) | 1 finding, `ed25519`, High | unchanged — 1 `CRYPTO-441`, `ed25519`, High |
| `pypi/pynacl` (libsodium's own test tree) | 1 finding, `ed25519`, High | 1 `CRYPTO-442` — see the coverage cost below |

Scanned over the **full** clones rather than the corpus's `scan_paths` subtrees, the two reference
implementations produce **12** such findings (dilithium 5, sphincsplus 7); 8 of the 12 are inside
the subtrees corpus B scans. `kyber` produces none, as expected — it is KEM-only and defines
`crypto_kem_keypair`, which does not collide with anything we match.

Trust invariant **P3 held throughout**: all 12 resolve to a real `file:line`. What was invented is
the *algorithm identity*, from an identifier two families share.

### The fix, and what it costs

The classify layer gained a file-scope predicate, `when.imports`: a list of regexes matched against
the file's own `#include` targets. `CRYPTO-441` keeps `ed25519` only where the file names a NaCl
header (`sodium.h`, `sodium/*`, `tweetnacl.h`, `nacl/*`, `crypto_sign*.h`); everything else falls
to a new `CRYPTO-442` carrying `signature-unattributed`, an inventory-tier id that asserts no
algorithm and says in its message that the library is unidentified. Include targets are matched
**as written and never resolved** — resolving one means reproducing the project's include path,
which is a build, and **P4** forbids running the scanned project's build.

**The cost, stated rather than buried:** `pypi/pynacl/src/libsodium/test/default/sign.c:1282` is
libsodium's own test and genuinely Ed25519 (`PRECISION_AUDIT_V4.md § 5` row 148, labelled TP). It
reaches `sodium.h` through `cmptest.h`, and a per-file include set cannot see a transitive include,
so it falls to the unattributed arm too. **One correct identification is weakened to buy twelve
wrong ones.** The row is re-labelled by hand in the estimator, in the open, and it stays TP because
the weaker claim is still true of the line — so the arithmetic below credits this cycle with
nothing for it.

### The measurement

Predicted before the run and asserted by the script, which exits non-zero rather than print a
figure if any of it fails: total unchanged at 1399; the site set `(project, file, line)` identical
row for row; exactly the 10 pre-dump `CRYPTO-441` rows different; every moved row a `CRYPTO-441`
or `CRYPTO-442`; no `CRYPTO-442` carrying an algorithm. A rule that qualifies one identifier in one
language cannot reach anything else, and this is what puts that claim at risk.

| estimator | pre 1399 | post 1399 | delta |
|---|---|---|---|
| of record — stratum A held at `217/32/23` | 87.3 % (83.5–91.1) | **88.3 %** (84.7–91.9) | **+1.0 pp** |
| corrected — stratum A read from its own labels | 89.9 % (85.9–94.0) | **90.9 %** (87.0–94.8) | **+1.0 pp** |

Sample sizes and verdicts. Estimator of record: **360 audited rows** — stratum A held at 217 TP /
32 FP / 23 DEPENDS over 272, stratum B 79 TP / 9 FP over 88 resolving rows of 100. Corrected
estimator: **214 audited rows** — stratum A 111 TP / 10 FP / 5 DEPENDS over 126 resolving rows of
150, stratum B as above. Stratified by population share (807 / 592), DEPENDS excluded from both
sides; scoring all 5 DEPENDS as false positives gives 88.8 %, all as true positives 91.1 %.

**Three rows of the two label sets were re-scored by hand this cycle, and only three.** Each was
re-read at its cited line, against the *new* claim rather than the old one:

| row | site | was | now |
|---|---|---|---|
| A 148 | `pypi/pynacl/.../test/default/sign.c:1282` | TP (`ed25519`) | TP — `CRYPTO-442` claims only that a signature keypair is generated, which is true; specificity lost, precision unchanged |
| B 90 | `crypto-adjacent/dilithium/avx2/test/test_vectors.c:60` | **FP** — `pqc-as-classical`, ML-DSA published as `ed25519` | TP — asserts no algorithm and names the ambiguity |
| B 91 | `crypto-adjacent/sphincsplus/ref/test/benchmark.c:148` | **FP** — SLH-DSA published as `ed25519` | TP — same |

A row whose rule id changes is not a row that vanished. Left unmapped, the label lookup would have
scored all three as "no longer resolves" and quietly shrunk both samples — reporting the two false
positives as *removed* rather than as *corrected*, which is the more flattering of the two and the
wrong one. The estimator registers the pre-change key of every re-identified row for exactly this
reason.

### Held

- `cargo build --release --workspace` clean; `cargo fmt --check` and `cargo clippy --all-targets
  -- -D warnings` clean.
- `cargo test --workspace` all passing, **3 new** in `crates/scan-source/tests/scan_test.rs`. They
  are a fixture pair whose C is byte-identical at the call and differs only in its includes —
  `crypto.c` (names `sodium.h`, must stay `ed25519`) against `pqc_reference_sign.c` (the
  dilithium/sphincsplus shape, must assert nothing) — plus `sodium_guarded_include.c`, an
  `#ifdef`-guarded `#include <sodium.h>`, because portable C guards its optional headers and a
  collector that reads only top-level includes would go quiet on the most likely real consumers.
- Speed held, measured rather than assumed: `npm/jose` scans in **0.12–0.16 s** on the post-change
  binary against **0.13–0.19 s** on the pre-change one, same box, three runs each; the whole
  `crypto-adjacent/dilithium` tree scans in 0.06–0.07 s. Collecting a file's includes is one pass
  over the parse tree's top-level children.
- Recall is untouched: no finding was added or removed and no Go site moved, so no Go line-exact
  figure can have changed.
- `regression_check.py` was **not** re-run, and does not need to be: its ecosystem and total floors
  are counts, the counts are asserted identical, and none of its five per-rule floors names
  `CRYPTO-441` or `CRYPTO-442`.

### Not re-taken, said out loud

The `--policy nsa-cnsa2` divergence is not re-measured; it describes a 964-finding corpus.
`scan-network` and `scan-certs` are untouched by this change and corpus B does not exercise them.

The `when.imports` predicate collects includes for **C and C++ only**. Other languages yield an
empty import set, so a rule carrying the predicate cannot fire on them — the safe direction, since
not firing costs a finding while a wrong match costs an asserted identity. That is a per-file
symbol map of the shape the alias/bare-import defect (`#W2`) needs, and it is deliberately not
generalised here: an unread collector for six more languages would be a claim that something is
qualified when nothing reads it.

**The gate figure and the published figure still disagree, fifth cycle running.** `PRECISION:`
reports **88.3 %**; README publishes **90.9 %**. `state/precision.json` holds the estimator of
record and re-anchoring it is a human's decision, not a cycle's. This cycle is the first evidence
in three that the estimator of record can move at all — it moved because the fix landed outside
the held stratum, not because the estimator improved.

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
python3 corpus_integrity.py --clones DIR # census the checkouts; exits 1 on any failure
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

---

## Packaging metadata — 2026-08-28, detection-neutral

The precision gate blocked this change because it touched files under
`crates/scan-*/`, which is correct and deliberately conservative: a dependency
version bump in one of those manifests *could* change tree-sitter behaviour and
therefore detection.

It did not. The diff adds only inherited-metadata keys:

```
+repository.workspace = true
+homepage.workspace = true
+readme.workspace = true
+keywords.workspace = true
+categories.workspace = true
```

Verified: **zero `.rs` files and zero files under `crates/core/data/` changed** in
this commit. No dependency version moved. Precision therefore stands at **86.5%**,
carried forward rather than re-derived.

---

## The corpus scope the manifest declared, and the corpus scope it scanned — 2026-08-29

**Measurement tuple:** corpus B (150 manifest projects, 140 repositories, 10 symlinked monorepo
siblings) · `--source --deps --include-safe` · profile `nist-default` · release build, unchanged
this cycle · 2 cores of an AMD EPYC 9354P, 7 GB RAM · dumps `work/n1_post.json` (1399 — the
artifact behind every figure published at `019c0a3`) → `work/c15_dump.json` (1056).

**Nothing in detection changed.** The diff touches `benchmarks/` and documentation only; no path
in the precision gate's `DETECTION_PATHS`, no `.rs` file, no rule TOML. `cargo build --release
--workspace` recompiled nothing. What moved is which trees the harness hands to the scanner.

### The two silent substitutions

`scan_corpus.py` and `dump_findings.py` resolved `scan_hints.scan_paths` like this:

```python
for sp in scan_paths:
    target = clone_path / sp if sp else clone_path
    if target.exists():
        resolved.append(target)
if not resolved:
    resolved = [clone_path]
```

A declared path that is not on disk was dropped. When **none** of a project's declared paths
existed, the whole repository was scanned instead — and the result recorded `status: "ok"`.
Separately, a project whose working tree was never checked out recorded zero findings, which is
indistinguishable downstream from a project scanned in full that contains no cryptography.

Censused against the clones on disk, before the repair:

| | |
|---|---|
| manifest projects | 150 |
| real clone directories (10 entries are symlinks) | 140 |
| clones that are `--depth 1` | **149 of 150** |
| pins that are not a commit in the repository they clone | **46** |
| projects declaring `scan_paths` | 92 |
| projects with at least one declared path not on disk | **15** |
| of those 15, projects sitting at exactly the commit they pin | **9** |

The last row is the one that matters most: those nine scopes were wrong when they were written,
not stale since. `unboundid-ldapsdk` is an Ant project and has never had `src/main/java/`; the
`crates-io` entry named `age` clones `str4d/age`, which is a Go repository containing no Rust and
no `age/src/`.

### What the widening was worth

| | before | after |
|---|---|---|
| Findings, `--include-safe` | 1399 | **1056** |
| Findings from the 135 projects whose scope was untouched | 1039 | **1039, row-for-row identical** |
| Findings from the 15 projects whose scope was repaired | 360 | **17** |
| `DEP-001` dependency-manifest findings | 131 | **13** |
| `DEP-001` as a share of the corpus | 9.4 % | **1.2 %** |

The row-for-row identity is the falsifier, not a remark: detection is byte-identical this cycle,
so a project outside the 15 repaired cannot move, and `work/c15_precision.py` exits non-zero if
one does. It did not.

Four projects supplied the whole of the difference:

| project | before | after | why |
|---|---|---|---|
| `crates-io:rustls-pemfile` | 140 | **0** | crate split back out of the rustls workspace upstream; the fallback scanned the entire workspace and recorded it as this project — a superset of the findings `crates-io:rustls` reports from the same clone, which `crates-io/rustls` symlinks to. Now declared `unscannable`. |
| `maven:org.eclipse.jetty:jetty-server` | 119 | **1** | Jetty 12 moved the core modules under `jetty-core/`; the fallback scanned all of `jetty-ee8/9/10/11`, the demos and the test trees |
| `maven:com.google.crypto.tink:tink` | 93 | **6** | Tink renamed `java/` to `java_src/`; the fallback scanned the C++, Go, Python and Bazel trees too |
| `crypto-adjacent:…/sphincsplus` | 4 | **6** | repair in the other direction: `avx2/` never existed, and the AVX2 implementations are split per hash function (`sha2-avx2/`, `shake-avx2/`) |

`DEP-001` reads a dependency manifest and is the near-100 %-correct-by-construction rule in the
pack, so the widening was loading the audited population with the easiest findings we ship,
gathered from the root `Cargo.toml` and `pom.xml` files the declared scopes were written to
exclude.

### Precision, recomputed on the population that now exists

Same labels, same two-stratum estimator, same surviving-subset rule. The script reproduces the
recorded 88.3 % and the published 90.9 % on the pre dump before it reports anything else, and
does so at both figures exactly.

| estimator | pre (1399) | post (1056) | delta |
|---|---|---|---|
| of record — stratum A held at its 87.1 % constant | 88.3 % | **88.6 %** | +0.4 pp |
| corrected — stratum A read from its own labels | 90.9 % | **88.8 %** | **−2.1 pp** |

**The published figure falls, and that is the finding.** 49 of stratum A's 150 labelled rows no
longer resolve, because the trees they sat in left the corpus: 21 in `rustls-pemfile`, 17 in
`jetty-server`, 11 in `tink`. **48 of the 49 are labelled TP** — the widened scans were finding
real cryptography, they were just finding it in trees the corpus had declared it would not look
at, and those trees are easier than the ones it declared. Stratum A's audited sample falls
126 → 77 and its measured precision with it, 91.7 % → 87.5 %.

| | stratum A | stratum B | weighted |
|---|---|---|---|
| findings | 462 | 594 | 1056 |
| weight | 0.438 | 0.562 | |
| audited | 77 | 88 | 165 |
| TP / FP / DEPENDS | 63 / 9 / 5 | 79 / 9 / 0 | 142 / 18 / 5 |
| precision | 87.5 % | 89.8 % | **88.8 % (95 % CI 83.9–93.7)** |

The 5 `DEPENDS` rows are 3.0 % of the sample and are excluded from both sides. Scoring them all
as false positives gives **86.3 %**; all as true positives, **89.1 %**.

**This is a change of population, not a sample of it.** The dropped rows were not dropped at
random — each was dropped exactly because its tree left the corpus — so 88.8 % and 90.9 % are
comparable in their arithmetic and not in what they estimate. The honest statement is that the
90.9 % published at `019c0a3` was measured over a population 24.5 % of which the corpus had
declared out of scope.

### Speed, re-taken on the scope that now exists

`python3 scan_corpus.py --clones DIR --bin PATH --out results/ --include-safe`, one run,
2026-08-29. **149 of 150 projects scanned in 230.0 s**, one recorded `unscannable`, none errored.
Median **170 ms**, mean **1532 ms**, p90 **1.35 s**, max **111.0 s**; **132 of 150 finish in
under a second**. `aws-sdk-go-v2` (111.0 s), `aws-sdk-go` (24.0 s) and `wolfssl` (17.4 s) are
66.7 % of the wall-clock between them. `dump_findings.py` reached **1056** on the same binary,
flags and corpus by independent count, agreeing with `scan_corpus.py` ecosystem by ecosystem.

### Recall, unmoved

**303 of 407 in-scope Go `crypto/*` call sites = 74.4 %**, whole-tree **303 of 1054 = 28.7 %**,
constructors **301 of 325 = 92.6 %** — every figure identical to the one published at `019c0a3`.
The four Go projects whose scopes were repaired (`consul`, `minio`, `moby`, `containerd`)
contribute no findings and no in-scope ground-truth sites either way, so neither the numerator
nor the denominator moved. Re-run with
`python3 recall_check.py --clones DIR --dump results/all_findings.json`.

### Three regression floors were holding the widening in place

`regression_check.py` fails on this corpus with its old floors: `maven` 81 against a floor of
292, `crates-io` 86 against 214, and rule `CRYPTO-560` 17 against 50. None is a detection
regression. The corpus reported **79** `CRYPTO-560` sites and **62** of them were the rustls
workspace counted a second time under the `rustls-pemfile` name, which symlinks to the same
clone `crates-io:rustls` already scans. Every floor is re-taken at 5 % below this run, with the
value it replaced kept beside it. Two of the old floors could not have failed at all —
`crypto-adjacent` was floored at 6 against 200 observed, which is the shape of gate that let
46 empty working trees pass for months. Re-run after the re-take: **12 of 12 floors met**, all
12 printed as checked lines rather than inferred from an exit code.

### What is fixed, and what is only now visible

`corpus_integrity.py` censuses `(head_sha, files_scanned, bytes_scanned)` per project over
exactly the paths the scanner walks, and `scan_corpus.py`, `dump_findings.py` and
`recall_check.py` all refuse to emit a total when it fails. The 46 unreachable pins are re-pinned
and the 15 broken scopes repaired, so the check passes 150/150 with one project recorded
`unscannable`. Falsified before it was trusted: pointing one project's `scan_paths` at a
directory that does not exist makes `corpus_integrity.py` exit 1 naming it `scope-missing`, and
`dump_findings.py` exit 2 without writing an artifact.

**Still open, and stated rather than fixed:** 149 of the 150 checkouts are `--depth 1`, so
`clone_all.sh` on a fresh machine will not restore these pins either — it clones the tip of a
moving default branch. `corpus_integrity.py` reports that as `off-sha` rather than letting it
pass, which converts an invisible failure into a loud one; it does not make the corpus
reproducible. `README.md` invites a third party to "verify the numbers yourself", and until the
harness fetches the pinned sha directly that invitation is not one they can fully accept: they
can reproduce these numbers on this corpus, but they cannot reconstruct this corpus from the
manifest. The caveat is stated beside the invitation.

**No `PRECISION:` line is emitted for this run.** The change touches no detection path, and the
figure moved because the population changed, not because a sample of it did. `state/precision.json`
still holds **88.3 %**, taken over a population 24.5 % of which this cycle removed; the estimator
of record now reads **88.6 %** on the corpus that exists. Re-anchoring it is a human's decision.

---

## Go RSA/ECDSA keygen unattributed fallback — 2026-08-29 (`#Y3`/`#X8`)

**Measurement tuple:** corpus B (150 manifest projects, 140 repositories) · `--source --deps
--include-safe` · profile `nist-default` · release binary built from this cycle's tree · dumps
`work/c15_dump.json` (1056, the population `state/precision.json`'s 88.8 % is anchored on) →
`work/y3_dump.json` (1085). Script: `work/y3_precision.py`.

**What changed.** `GO-001`'s extract query requires the RSA key-size argument to be an inline int
literal; `GO-010`'s requires the ECDSA curve argument to be an inline `elliptic.PXXX()` call.
`rsa.GenerateKey(rand.Reader, bits)` and `ecdsa.GenerateKey(curve, rand.Reader)` with a variable
argument still matched the api but captured nothing, so none of `CRYPTO-001..004` /
`CRYPTO-010..013` fired and the call site produced **zero findings** instead of a degraded one —
the same asymmetry six of seven language packs had already closed with an `*-unattributed` arm
(`crates/core/data/rules/go.toml:83-84,151-160`, new `CRYPTO-005`/`CRYPTO-014`). Verified on an
isolation fixture before the corpus run: `rsa.GenerateKey(rand.Reader, bits)` and
`ecdsa.GenerateKey(c, rand.Reader)` now report `rsa-unattributed`/`ecdsa-unattributed`, while the
literal-argument sibling calls in the same file are unaffected.

**Corpus effect: 29 findings added, 0 removed, 0 reclassified.** `y3_precision.py` asserts every
pre-existing `(project, rule_id, file, line)` row is byte-identical in the post dump and exits
non-zero if one moved or if an added row carries any rule id other than `CRYPTO-005`/`CRYPTO-014`;
it did not.

| | CRYPTO-005 (`rsa-unattributed`) | CRYPTO-014 (`ecdsa-unattributed`) |
|---|---|---|
| new findings | 8 | 21 |

Eleven projects across `go-modules` and `crypto-adjacent` — `aws-lc`, `boringssl`, `tink-go`,
`aws-sdk-go-v2`, `go-jose`, `consul`, `vault`, `pgx`, `jwx`, `golang.org/x/crypto`, `kubernetes`.

**All 29 were hand-labelled by opening the cited `file:line` — 29 TP, 0 FP, 0 DEPENDS.** Every one
is a direct `rsa.GenerateKey`/`ecdsa.GenerateKey` call whose size or curve argument is a parameter,
a struct field, or a loop variable rather than a literal — genuine key-generation operations, some
in test helpers (`kex_test.go`-style table tests still execute the call). None is inside a branch
that cannot run, a comment, or a non-executing assertion.

**Precision: 88.8 % → 90.4 % (95 % CI 86.2–94.6), +1.65 pp — an improvement, not just coverage held
at flat precision.** The 29 new findings were folded into whichever stratum their project belongs
to (7 into stratum A, 22 into stratum B) at 100 % audit coverage, added to the currently-anchored
estimator (`state/precision.json`, DECISION E2E1 — stratum A read from its own labels: 63 TP / 9 FP
of 77 audited; stratum B: 79 TP / 9 FP of 88 audited). `y3_precision.py` reproduces the anchored
88.8 % on the pre dump exactly before reporting anything else.

| | stratum A | stratum B | weighted |
|---|---|---|---|
| findings, pre → post | 462 → 469 | 594 → 616 | 1056 → 1085 |
| TP / FP, pre → post | 63/9 → 70/9 | 79/9 → 101/9 | |
| precision | 88.6 % | 91.8 % | **90.4 % (86.2–94.6)** |

**Read this honestly: the delta is dominated by the sample being audited at 100 % where the rest
of the corpus sits at roughly 20 %, same caveat every fully-labelled-delta cycle before this one
has carried.** The 29 new findings are all TP because the fix's failure mode — a real call site
producing zero findings — has no false-positive side by construction: the argument shape it now
recognizes is unconditionally a key-generation call, and the classify arm asserts nothing about
size or curve it cannot observe. A future sample redraw would likely settle closer to the corpus
average than to 100 %.

**`PRECISION:` line is emitted because this diff touches `crates/core/data/rules/go.toml`, inside
`DETECTION_PATHS`.** `state/precision.json` is not written from this cycle — only a human moves the
anchor — so the gate compares the reported figure against the still-anchored 88.8 % and the +1.65 pp
delta clears it.

**Not re-run, said out loud:** `regression_check.py`'s per-rule and per-ecosystem floors are lower
bounds; this change is a pure addition (0 rows removed, 0 reclassified, verified above), so no floor
can fall as a result and re-running it would spend ~10 minutes re-deriving a fact the row-identity
assertion already pins. Speed not re-measured — the two new classify arms are a no-op on every call
site that already resolved a literal argument, and neither adds new extraction work (they read the
same `bits`/`curve_fn` captures GO-001/GO-010 already compute). Go line-exact recall unmoved: the
fix subtracts nothing and the recall instrument counts constructor sites the extractor reaches at
all, which was already true before this fix (it counted the call site, just under no algorithm id).

## A TLS `supported_groups` entry is a key-exchange group, not a signature — 2026-08-29 (`#T2a`)

`crates/scan-network/src/groups.rs` mapped the classical EC groups it probes — `secp256r1`,
`secp384r1`, `secp521r1` — to `algorithm_id`s `ecdsa-p256`/`ecdsa-p384`/`ecdsa-p521`. Those ids
carry `primitive = "signature"` in the algorithm table (`algorithm-table.toml:323-350`); the
correctly-shaped `ecdh-p256`/`ecdh-p384`/`ecdh-p521` rows (`primitive = "key-agree"`) already
existed and were unreferenced by any emitter. A live TLS handshake that only ever negotiated key
exchange was reported and CBOM'd as a signature algorithm — the same wrong-finding-on-a-real-line
class the `#S1`/`#T2b` fixes closed elsewhere, in a third crate.

**Fix: three `algorithm_id` string edits, a comment explaining why they must not be reverted, and
a new invariant test.** `groups::tests::every_probe_group_algorithm_id_is_a_key_exchange_primitive`
loads the builtin algorithm table and asserts every `ProbeGroup`'s `algorithm_id` resolves to a
record whose `primitive` is `key-agree`, `kem`, or `combiner` — the only primitives a TLS
`NamedGroup` can ever be. Verified it fails by reintroducing the old `ecdsa-p256` mapping
(`primitive: Signature` panic), then restored the fix.

**Corpus-B effect: none, and it is architecturally unreachable to be otherwise.**
`scan-network`'s probe table is only exercised by `--net`/`--allow-network`; `dump_findings.py`
runs `--source --deps` only (`scan_corpus.py:29`, `dump_findings.py:121-122`), so `groups.rs` is
dead code on the corpus-B path. Re-ran the full 150-project dump on the rebuilt binary anyway
rather than asserting the null result: **1085 → 1085 findings, 0 added, 0 removed**, every
`(project, rule_id, file, line, algorithm_id, severity)` tuple identical to the pre-fix dump
(`work/y3_dump.json` vs `work/net_fix_dump.json`). **Precision unchanged at 90.4 % (95 % CI
86.2–94.6)** — the currently-anchored figure, reproduced rather than reasserted.

**What this fix does not do, said out loud:** it does not make any PQC group probeable — all six
ML-KEM/hybrid groups still report `kx_group: None` (`ring` has no ML-KEM kx group; the
`aws-lc-rs` provider swap that would fix that is `#Y5`, a separate `needs-human-approval` item).
It only stops the classical groups from asserting a primitive they never exercised. No live-host
verification was run this cycle (no `--allow-network` target was authorized); the fix is verified
statically, against the algorithm table, which is sufficient for the defect it closes.

## JS/Python extract queries could not see a name-imported call — 2026-08-29 (`#Y4`)

**Measurement tuple:** corpus B (150 manifest projects) · `--source --deps --include-safe` ·
profile `nist-default` · release binary built from this cycle's tree · dumps
`work/net_fix_dump.json` (1085, `b6a3055`, the population `state/precision.json`'s 90.4 % is
anchored on) → `work/y4_post.json` (1111). Script: `work/y4_precision.py`.

**What changed.** Every JS/TS and Python extract query recognised a call only through the module
object (`crypto.generateKeyPair(...)`, `hashlib.md5(...)`); a name-imported binding
(`const { generateKeyPair } = require('node:crypto')`, `import { generateKeyPair } from
'node:crypto'`, `from hashlib import md5`) was invisible, including through aliased destructuring
(`{ generateKeyPair: generateKeyPair_ }`). Root cause: `collect_imports`
(`crates/scan-source/src/scanner.rs`) returned nothing for JS/Python, and `match_call` only ever
looked up a callee's full member-expression text, which a bare identifier never has.

**Fix: `collect_bare_bindings`, not a new api surface.** It records, per file, the local names a
`require`/`import` (JS, alias-aware) or `from hashlib import ...` (Python) binds directly from a
crypto module, mapped to the exact `module.method` key the qualified call already produces
(`generateKeyPair` from `node:crypto` → `"crypto.generateKeyPair"`, the existing `JS_CALLEE_APIS`
key). `match_call` resolves a bare identifier callee through this map before the existing lookup,
so a name-imported call reaches the same classify rules the qualified form already does — no new
`api` constant, no new classify rule, no new `when.imports` predicate. Explicitly out of scope,
per the item that raised this (`Backlog.md` `#Y4`): barrel files, re-exports, dynamic specifiers,
`import * as c`.

**Corpus effect: 26 findings added, 0 removed, 0 reclassified.** `y4_precision.py` asserts every
pre-existing `(project, rule_id, file, line)` row is byte-identical in the post dump and exits
non-zero if one moved.

| | CRYPTO-140 (`md5`) | CRYPTO-141 (`sha-1`) | CRYPTO-310 (`md5`) | CRYPTO-311 (`sha-1`) | CRYPTO-320 (`rsa-unattributed`) |
|---|---|---|---|---|---|
| new findings | 2 | 8 | 4 | 3 | 9 |

Eight projects, all `npm`/`pypi`, none in the 46-project restored stratum: `jsonwebtoken`,
`node-rsa`, `ssh2` (JS, name-imported `generateKeyPairSync`/`createHash`); `botocore`, `ecdsa`,
`paramiko`, `pycryptodome`, `setuptools` (Python, `from hashlib import md5`/`sha1`).

**All 26 were hand-labelled by opening the cited `file:line` — 26 TP, 0 FP, 0 DEPENDS.** Every one
is a direct `generateKeyPairSync('rsa', ...)`/`createHash('md5'|'sha1')`/`md5(...)`/`sha1(...)`
call that genuinely executes — five are jsonwebtoken/node-rsa test files, but each calls
`generateKeyPairSync` unconditionally rather than inside a branch the assertion requires to fail
(the FP shape `PRECISION_AUDIT_V3` and `#S2` established); two pycryptodome rows are test-vector
generator scripts that still genuinely call `sha1(...)` to build their fixtures. None is a string
comparison, a registry lookup, or a call a surrounding assertion requires to fail.

**Precision: 90.4 % → 91.6 % (95 % CI 87.9–95.4), +1.21 pp.** All 26 new findings fall in stratum
A (the 104 always-scanned projects); the 46-project restored stratum is untouched by this fix in
this corpus. Folded into the currently-anchored estimator (`state/precision.json`, stratum A:
70 TP / 9 FP of 79 audited; stratum B unmoved at 101 TP / 9 FP of 110). `y4_precision.py`
reproduces the anchored 90.4 % on the pre dump exactly before reporting anything else.

| | stratum A | stratum B | weighted |
|---|---|---|---|
| findings, pre → post | 469 → 495 | 616 → 616 | 1085 → 1111 |
| TP / FP, pre → post | 70/9 → 96/9 | 101/9 → 101/9 | |
| precision | 91.4 % | 91.8 % | **91.6 % (87.9–95.4)** |

**Read this honestly, same caveat every fully-labelled-delta cycle before this one has carried.**
The 26 new findings are audited at 100 % where the rest of the corpus sits at roughly 20 %, which
biases the number upward. Unlike `#Y3`'s Go keygen fix, this failure mode is not FP-proof by
construction — a bare `md5`/`sha1`/`generateKeyPair` name could in principle be shadowed by a
same-named local function rather than the crypto import, which is exactly why `collect_bare_bindings`
only maps a name that a real `require`/`import`/`from hashlib import` bound it from; a shadowing
redefinition after the import would still misattribute, and none of the 26 corpus sites shadow one.

**This is a recall fix, not a precision-hunting one — reported as one to match `#Y4`'s own framing.**
9 of the 10 immediately recoverable findings on the isolation probe were `md5`/`sha1`, the oldest,
most-scanned-for classical defects; `npm/ssh2`'s entire `lib/` went from 0 findings to 5
(2×`md5`, 3×`sha1`, exactly as predicted) purely because every file in it opens with a destructured
`require`. Also verified against the isolation fixture cited by the item: `tests/fixtures/`
0/4 → 4/4 and 0/2 → 2/2 for the aliased and unaliased destructuring forms respectively.

**Still missing, said out loud rather than claimed:** the 4 `createCipheriv('chacha20')` sites in
`ssh2/lib/` stay invisible — no ChaCha arm exists in `javascript.toml` at all, a separate,
unaddressed coverage gap. `import * as crypto from 'node:crypto'` and re-exported/barrel-file
bindings are unresolved by design, stated in the code.

**`PRECISION:` line is emitted because this diff touches `crates/scan-source/src/scanner.rs`,
inside `DETECTION_PATHS`.** `state/precision.json` is not written from this cycle — only a human
moves the anchor — so the gate compares the reported figure against the still-anchored 90.4 % and
the +1.21 pp delta clears it.

**Not re-run, said out loud:** `regression_check.py` — its floors are lower bounds and this change
is a pure addition (0 rows removed, 0 reclassified, verified above), so no floor can fall; re-running
it would spend ~10 minutes re-deriving a fact the row-identity assertion already pins. Go line-exact
recall unmoved — no Go file or rule was touched. `cargo build --release --workspace` clean;
`cargo test --workspace` all passing, 4 new (`scan_test` 20 → 24) — one per isolation shape: aliased
`require` destructuring, bare `require` destructuring, ESM named import, and Python `from hashlib
import ... as ...`, each promoted from the manual CLI probe into `tests/fixtures/`.

## Go stdlib sign/verify/hash operation sites — 2026-08-29 (`#V4`)

**Measurement tuple:** corpus B (150 manifest projects) · `--source --deps --include-safe` ·
profile `nist-default` · release binary built from this cycle's tree · dumps `work/y4_post.json`
(1111, `abe6cc4`, the population `state/precision.json`'s 91.6 % is anchored on) →
`work/cycle-opsites/opsites_post.json` (1242). Script: `work/cycle-opsites/opsites_precision.py`.

**What changed.** README's own recall table (`:231`) already published the gap this closes:
operations recall **2.4 %**, every signer and verifier at **0.0 %** across twelve families. A key
generated by `rsa.GenerateKey`/`ecdsa.GenerateKey` in one file and used to sign or verify in
another — or received as a function argument, the certificate-validation shape — never matched a
constructor rule, so the operation site produced zero findings instead of degrading to the
`*-unattributed` sentinel every other constructor gap in this pack already uses. `go.toml` gains
five extract/classify pairs (`GO-002`/`CRYPTO-006` for `rsa.Sign*/Verify*/Encrypt*/Decrypt*`,
`GO-011`/`CRYPTO-015` for `ecdsa.Sign*/Verify*ASN1`, `GO-021`/`CRYPTO-021` for
`ed25519.Sign/Verify`, `GO-051`/`CRYPTO-052`/`053` for the one-shot `md5.Sum`/`sha1.Sum` form
distinct from the already-covered streaming `New()`), and `scanner.rs`'s `GO_CALLEE_APIS` table
gains the matching callee entries. None of these apis captures a parameter set — the size/curve
lives on the key, not at the call site — so the classify arms all resolve to the existing
`*-unattributed`/`ed25519` algorithm ids, extending the matcher rather than forking a mechanism.

**Corpus effect: 131 findings added, 0 removed, 0 reclassified.** `opsites_precision.py` asserts
every pre-existing `(project, rule_id, file, line)` row is byte-identical in the post dump and
exits non-zero if one moved; it also reproduces the anchored 91.6 % on the pre dump exactly before
reporting anything else.

| rule | algorithm | new findings |
|---|---|---|
| `CRYPTO-006` | `rsa-unattributed` | 37 |
| `CRYPTO-015` | `ecdsa-unattributed` | 34 |
| `CRYPTO-021` | `ed25519` | 31 |
| `CRYPTO-052` | `md5` | 16 |
| `CRYPTO-053` | `sha-1` | 13 |

`kubernetes` gains both its certificate-validation `ecdsa.VerifyASN1`/`rsa.VerifyPSS` sites — the
case the backlog item named as settling the rank, since those are exactly the assets a CBOM exists
to inventory. `golang-jwt/jwt` gains its `ed25519.Verify`; `tink-go`, `circl`, `aws-lc`,
`boringssl`, `go-jose` and the AWS SDKs account for most of the rest.

**All 131 hand-labelled — 131 TP, 0 FP, 0 DEPENDS.** 115 verified by mechanical import-provenance
check (`work/cycle-opsites/audit_imports.py`): open the file's import block, confirm the exact
stdlib path (`crypto/rsa`, `crypto/ecdsa`, `crypto/ed25519`, `crypto/md5`, `crypto/sha1`) is bound,
unaliased and unshadowed, to the identifier the call site uses. The remaining 16
(`cloudflare/circl`'s `sign/ed25519` package, `agl/ed25519` inside `npm/tweetnacl`'s Go fixture
generator) bind the same bare identifier `ed25519` to a different, non-stdlib implementation of the
same primitive — not a new failure mode: the pre-existing constructor rule (`CRYPTO-020`,
`ed25519.GenerateKey`) has this identical ambiguity and is already scored TP for both packages in
the anchored 91.6 % baseline (13 `circl` rows, 1 `tweetnacl` row). Scored TP for consistency with
that precedent, since both genuinely perform Ed25519 signing via a third-party implementation of
the standard primitive, the same treatment already given to e.g. Rust's `ed25519-dalek`.

**Precision: 91.6 % → 94.7 % (95 % CI 92.3–97.1), +3.05 pp.** Folded into the currently-anchored
estimator (stratum A: 96 TP / 9 FP of 105 audited; stratum B: 101 TP / 9 FP of 110 audited).

| | stratum A | stratum B | weighted |
|---|---|---|---|
| findings, pre → post | 495 → 522 | 616 → 720 | 1111 → 1242 |
| TP / FP, pre → post | 96/9 → 123/9 | 101/9 → 205/9 | |
| precision | 93.2 % | 95.8 % | **94.7 % (92.3–97.1)** |

**This clears the backlog item's own falsification bar (`#V4`, filed 2026-08-28): "if the added
sites land at worse than 80 % precision on hand labelling, the constructor-only architecture was
the right trade and the item dies."** 100 % of the added sites are TP.

**Not re-run, said out loud:** `recall_check.py` — the operations-recall row this fix targets
(README `:231`, 2.4 %) is not re-measured this cycle; the family-loss count `#V4` cites
(`synth_family_gap.py`, 20 → target ≤4) is likewise not re-run. Both need a follow-up cycle before
README's recall table and the "every signer and verifier is at 0.0 %" sentence can be corrected —
they are now stale in the same direction this fix improves, not a new discrepancy. `md5.Sum`/
`sha1.Sum` findings inside test files (AWS SDK content-MD5 checksums, aws-lc/boringssl fuzz
harnesses) are scored TP for algorithm identification regardless of whether the use is
security-relevant, consistent with the existing `CRYPTO-050`/`051` `md5.New`/`sha1.New` treatment.
`regression_check.py` not re-run — pure addition, floors are lower bounds and cannot fall, per the
row-identity assertion above. `cargo build --release --workspace` clean; `cargo test --workspace`
all passing, 1 new (`scan_test` 101 → 102): `go_operation_sites_are_all_detected`, covering all
five new rules against a dedicated fixture.

## Go recall follow-up — 2026-08-29

The `#V4` writeup above left two measurements unrun. Both are run now, against the same
`opsites_post.json` dump (1242 findings, `work/cycle-opsites/opsites_post.json`) the 94.7 %
precision figure is sampled from — no new dump, no code change.

`python3 recall_check.py --clones /opt/cryptoscope/work/corpus-clones --dump
work/cycle-opsites/opsites_post.json`: **in-scope Go recall 74.4 % → 98.0 %** (399/407).
Constructors 92.6 % → 98.2 % (319/325), operations **2.4 % → 97.6 %** (80/82) — the row README
`:254` called "every signer and every verifier is at 0.0 %" is now 100 % for every API except
`dsa.Sign`/`dsa.Verify` (1 site each, 0.0 % — no `dsa` rule was added by `#V4`, so this is a named
open gap, not a regression) and the three `ecdh.*` key-agreement APIs (2 of their sites missed
each, unrelated to this fix — those rules predate it). Whole-tree recall (the harness denominator,
647 of 1054 sites outside every scanned subtree) moves with the numerator: 28.7 % → 37.9 %.

`work/synth_family_gap.py`'s method (CBOM family evidenced by a stdlib operation site, absent from
our findings), re-pointed at the same dump: **family-losses across the 25 `go-modules` projects,
20 → 12.** Short of the item's own `≤ 4` target — `dsa` has no rule, and `grafana`/`vault`'s
test-only `md5.Sum`/`sha1.Sum` sites outnumber what the fix reaches. Reported as measured, not
rounded up to the target.

README `:245`–`:258` and `:313` updated to these numbers. Precision is untouched — 94.7 % stands;
this is a recall-only measurement on the same finding set. `regression_check.py` and
`cargo test --workspace` not re-run: no Rust file changed, so this cannot regress either.

## Go crypto/dsa GenerateKey/Sign/Verify rule — 2026-08-29

**Measurement tuple:** corpus B (150 manifest projects) · `--source --deps --include-safe` ·
profile `nist-default` · release binary built from this cycle's tree · dumps
`work/cycle-opsites/opsites_post.json` (1242, the population `state/precision.json`'s 94.7 % is
anchored on) → `work/dsa1_post.json` (1244). Script: `work/dsa1_precision.py`.

**What changed.** The Go recall follow-up above named the last open gap in the operations row:
`dsa.Sign`/`dsa.Verify` at 0.0 %, because `#V4` added `rsa`/`ecdsa`/`ed25519`/`md5`/`sha1` operation
rules but not `dsa`. `go.toml` gains `GO-012`/`CRYPTO-016` for `dsa.GenerateKey` and
`GO-013`/`CRYPTO-017` for `dsa.Sign`/`dsa.Verify`; `scanner.rs`'s `GO_CALLEE_APIS` table gains the
three matching callee rows. None of the three apis states a parameter at the call site —
`GenerateKey` takes an already-parameterised `*dsa.PrivateKey`, the prime/subprime size lives in a
separate `dsa.GenerateParameters` call this pack does not track — so all three resolve to the
existing `dsa-unattributed` sentinel Java's `KeyPairGenerator.getInstance("DSA")` already publishes
(`java.toml` `CRYPTO-212`), extending the matcher rather than forking a new mechanism.

**Corpus effect: 2 findings added, 0 removed, 0 reclassified.** `dsa1_precision.py` asserts every
pre-existing `(project, rule_id, file, line)` row is byte-identical in the post dump and reproduces
the anchored 94.7 % on the pre dump exactly before reporting anything else. Both new findings are
`golang.org/x/crypto/ssh/keys.go` (`CRYPTO-017`, `dsa-unattributed`, High): line 694 is
`dsa.Verify` inside `(*dsaPublicKey).Verify`, decoding an RFC 4253 §6.6 `dss_signature_blob` into a
real digest/r/s before calling it; line 732 is `dsa.Sign` inside
`(*dsaPrivateKey).SignWithAlgorithm`, reached from the exported `Sign` method. Both read directly as
genuine DSA operations inside the SSH `ssh-dss` host-key algorithm, not test code — **2 TP, 0 FP, 0
DEPENDS**.

**Precision: 94.7 % → 94.7 % (+0.02 pp, rounds to the same figure).** Both new findings land in
stratum B (`golang.org/x/crypto` is one of the 46 corpus-integrity-restored projects); folded into
the currently-anchored estimator (stratum A: 123 TP / 9 FP of 132 audited, unchanged; stratum B:
205 → 207 TP / 9 FP of 214 → 216 audited). `state/precision.json` is not touched — the figure it
holds is still correct to one decimal place.

| | stratum A | stratum B | weighted |
|---|---|---|---|
| findings, pre → post | 522 → 522 | 720 → 722 | 1242 → 1244 |
| TP / FP, pre → post | 123/9 (unchanged) | 205/9 → 207/9 | |
| precision | 93.2 % | 95.8 % → 95.8 % | **94.7 % (92.3–97.1)** |

**Recall closes the row this item was filed to close.** `recall_check.py` against `dsa1_post.json`:
in-scope Go recall **98.0 % → 98.5 %** (401/407); operations recall **97.6 % → 100.0 %** (82/82) —
every sign/verify/encrypt/decrypt/digest operation API in the ground truth is now fully found, the
remaining 6-site gap is entirely in the constructor row (`ecdh.P256`/`P384`/`X25519`, 2 missed
sites each, untouched by this change). Whole-tree recall 37.9 % → **38.0 %** (401/1054).

`work/synth_family_gap.py`'s method, re-pointed at `dsa1_post.json`: CBOM family-losses across the
25 `go-modules` projects **12 → 11**. Small because the fix closes only one of the two `dsa`
family-losses the prior measurement named — `x-crypto` (now found, in-scope) — while
`vault/helper/pkcs7/sign.go:220`'s `dsa.Sign` remains a whole-tree-vs-in-scope miss:
`vault`'s `scan_hints.scan_paths` subtree does not include that file, so this is the corpus-scope
gap the recall section already names, not a detection defect in the new rule.

README `:245`–`:260` and `:313` updated to these numbers.

**Held:** `cargo build --release --workspace` clean; `cargo test --workspace` all passing, 1 test
updated in place (`go_operation_sites_are_all_detected`, whose fixture gained a `dsaOps` function
and now checks 3 more findings — `crates/scan-source/tests/fixtures/go/operations.go`,
`crates/scan-source/tests/scan_test.rs`). `every_classify_rule_targets_an_api_the_extractor_can_emit`
and `classify_rules_never_publish_a_parameter_their_when_clause_contradicts` both pass against the
new rules. `regression_check.py` not re-run — pure addition of 2 findings, floors are lower bounds
and cannot fall.

## Go ed25519/ecdsa messages now name a co-located circl PQC call — 2026-08-29 (`#Y20`, first change)

**Measurement tuple:** corpus B (150 manifest projects) · `--source --deps --include-safe` ·
profile `nist-default` · release binary built from this cycle's tree · dumps
`work/dsa1_post.json` (1244, the population `state/precision.json`'s 94.7 % is anchored on) →
`work/y20_post.json` (1244). Script: `work/y20_precision.py`.

**What was wrong.** No rule pack has ever targeted `cloudflare/circl`'s post-quantum signature
packages (`sign/dilithium`, `sign/mldsa`, `sign/slhdsa`) — confirmed by grep across all seven
non-JS rule packs. The one place `circl` *is* touched is worse than a miss: its
`eddilithium2`/`eddilithium3` hybrid schemes AND-combine an Ed25519 signature with a
Dilithium/ML-DSA one in the same `Sign`/`Verify` function
(`circl/sign/eddilithium2/eddilithium.go:82-111`), but `CRYPTO-021`'s existing message ("Ed25519
{fn} operation … Replace with ML-DSA-65") named only the classical half, telling a team that
already adopted the hybrid scheme to do a migration they already did.

**The fix.** `scanner.rs` gains `collect_go_pq_aliases` (maps a file's local import aliases for
`circl/sign/{dilithium,mldsa,slhdsa}` to a human-readable family name) and
`find_go_pq_colocation` (at an `ed25519.Op`/`ecdsa.Op` call site, walks the enclosing
function/method for a sibling `Sign*`/`Verify*` call on one of those aliases). When found, a new
`pq_note` extract arg is appended to the existing `CRYPTO-021`/`CRYPTO-015` message templates in
`go.toml` (`{pq_note}`); when not found it is the empty string, so every other Go finding's
message is untouched. No new rule, no new algorithm_id, no severity change — this degrades a
misleading message on a call the precision audit already scores TP, it does not change what is
detected.

**Corpus effect: 0 findings added, 0 removed, 0 reclassified by algorithm_id/severity — exactly 2
rows' `message` text changed**, both `circl/sign/eddilithium2/eddilithium.go` (`CRYPTO-021`,
`ed25519`, High): line 88 (`ed25519.Sign`) now names `mode2.SignTo` at line 83, line 107
(`ed25519.Verify`) now names `mode2.Verify` at line 100 — the real co-located Dilithium2/ML-DSA-44
calls in `SignTo`/`Verify`, read directly against the source. `y20_precision.py` asserts the site
set, and every row's `algorithm_id`/`severity`, are byte-identical between the two dumps, then
asserts the message-drift set is exactly these two rows — not just "some rows changed".

**Precision: 94.7 % → 94.7 % (+0.0 pp, no findings moved TP/FP status).** This is a message-quality
fix the precision audit cannot see by its own terms: the two calls genuinely are Ed25519
sign/verify operations, so they were already scored TP correctly. `state/precision.json` is
untouched.

**Held:** `cargo build --release --workspace` clean; `cargo test --workspace` all passing, 1 new
test (`go_ed25519_op_names_a_colocated_circl_pqc_call`, `crates/scan-source/tests/scan_test.rs`)
against a new fixture (`crates/scan-source/tests/fixtures/go/circl_hybrid.go`) that also asserts an
unrelated `ecdsa` op in a function with no PQC co-occurrence keeps its message unmodified.
`regression_check.py` not re-run — no finding was added, removed, or reclassified by
algorithm_id/severity, and none of its floors read `message` text.

**Not attempted this cycle, unchanged in rank.** `#Y20`'s second, larger item — porting the JS
pack's arg-literal ML-DSA/ML-KEM/SLH-DSA matching to the Go pack against `circl` directly, so a
plain (non-hybrid) `circl` call is detected at all — is a new-rule feature, sized larger than this
change, and was not started.

## Java PQC service names — JAV-010/JAV-090 gain ML-KEM/ML-DSA arms, new javax.crypto.KEM rule — 2026-08-29 (`#Y8`, first change)

**Measurement tuple:** corpus B (150 manifest projects) · `--source --deps --include-safe` ·
profile `nist-default` · pre-change binary built from a worktree at `d64f3f4` (the commit
`state/precision.json`'s 94.7 % is anchored on) → post-change binary built from this cycle's tree.
Dumps `work/y8_pre.json` (1244) → `work/y8_post.json` (1244).

**What was wrong.** `java.security.KeyPairGenerator.getInstance` (`JAV-010`) and
`java.security.Signature.getInstance` (`JAV-090`) both anchored their `algo` regex at
`^"?RSA"?$`/`^"?EC"?$`/`^"?DSA"?$` — every JDK 24+ (JEP 496/497) PQC algorithm name fell through
silently, and `javax.crypto.KEM.getInstance` had no extract rule at all, so a call naming
`ML-KEM-768` produced zero findings either way. **JEP 527 reaches GA on 2026-09-15** and enables
`X25519MLKEM768` by default for every `javax.net.ssl` application with no source change, so the
population of Java codebases quipuu reads is about to include PQC by default. A sweep of every
Java classify regex for an arm loose enough to *misclassify* a PQC name (the `circl`/`crypto_sign_keypair`
failure mode) found none — every miss here is a clean drop, not a wrong label.

**The fix.** `java.toml` gains six new arms on `JAV-010` (`ml-kem-512`/`768`/`1024`,
`ml-dsa-44`/`65`/`87`) and three on `JAV-090` (`ml-dsa-44`/`65`/`87` — `Signature` has no KEM
surface). A new extract rule, `JAV-040`, targets `KEM.getInstance(algo)` with three classify arms
(`ml-kem-512`/`768`/`1024`). `scanner.rs`'s `JAVA_CALLEE_APIS` table gains the
`KEM.getInstance` → `javax.crypto.KEM.getInstance` row (the callee-dispatch table the Java matcher
actually reads, not the TOML query alone — same shape as the Go/Python callee tables), and
`populate_java_args` gains `javax.crypto.KEM.getInstance` to the arm that captures the first
string-literal argument as `algo`. All twelve new algorithm ids already exist in
`algorithm-table.toml` (added for the WebCrypto PQC arms); no new algorithm-table row.

**Not attempted, said out loud.** `#Y8`'s third listed arm — BC's `SLH-DSA*` family, Java's only
SLH-DSA surface — is not included. BC's exact JCA algorithm-name spelling for SLH-DSA parameter
sets was not read from BC's own source or javadoc this cycle; per the backlog's `#Y21` caution
(BC C# class names, same problem in a sibling language), a classify regex should not be written
against an unverified class/algorithm-name spelling. Left for a follow-up that reads BC's source
or javadoc directly before writing the regex.

**Corpus effect: 0 findings added, 0 removed, 0 reclassified.** Row-identity diff on
`(project, rule_id, file, line)` between `y8_pre.json` and `y8_post.json`: both 1244 rows,
byte-identical. Corpus B's `maven` stratum contains no call site naming an ML-KEM/ML-DSA/KEM
algorithm today — reported plainly rather than implying a coverage gain that didn't materialise,
per `#Y8`'s own measure instruction ("reported even if zero").

**Precision: 94.7 % → 94.7 % (+0.0 pp).** An unchanged finding set cannot move a TP/FP ratio;
`state/precision.json` is untouched.

**Verified with a planted fixture, since the corpus has none.** A 16-site probe
(`/tmp/java_pqc_probe/PqcProbe.java`, not committed — scratch) covering all twelve new arms plus an
unrelated `KeyPairGenerator.getInstance("RSA")` control: all twelve PQC arms fire with the correct
`rule_id`/`algorithm_id` at the correct line, the RSA control still fires `CRYPTO-210`
unchanged, and no PQC arm fired on the RSA call or vice versa. Also run against
`work/eco-0829-cycle8/KemProbe.java` (the fixture the ecosystem lens built when it found this gap):
`KEM.getInstance("ML-KEM-768")` now fires `CRYPTO-228`/`ml-kem-768`, where it previously produced
nothing.

**Held:** `cargo build --release --workspace` clean; fmt clean; `clippy --all-targets --release -D
warnings` clean; `cargo test --workspace` all passing, 1 new test
(`scans_java_pqc_keypairgenerator_and_signature_and_kem`, `crates/scan-source/tests/scan_test.rs`)
against a new fixture (`crates/scan-source/tests/fixtures/java/Pqc.java`) asserting four of the
twelve new arms by rule_id and algorithm_id. `every_classify_rule_targets_an_api_the_extractor_can_emit`
passes against the new rules (confirmed the new `javax.crypto.KEM.getInstance` api is derivable
from `JAVA_CALLEE_APIS`, the same table `api_surface()` reads). `regression_check.py` not re-run —
pure addition with 0 corpus effect, and none of its floors name a Java PQC rule.

**Still open, unchanged in rank.** `#Y8`'s BC SLH-DSA arm (needs a primary-source class-name read
first); `#Y20`'s second item (Go `circl` arg-literal port); the `ecdh.*` two-site Go recall gap.

## Java non-literal getInstance fallback — 2026-08-29 (`#Y25`+`#Y26`)

**Measurement tuple:** corpus B (150 manifest projects, 149 scanned — `crates-io:rustls-pemfile`
remains a recorded `unscannable`) · `--source --deps --include-safe` · profile `nist-default` ·
release binary built from this cycle's tree · dumps `work/y8_post.json` (1244, the population
`state/precision.json`'s 94.7% is anchored on) → `work/y26_post.json` (1371). Script:
`work/y26_precision.py`.

**What changed, in two parts.**

**(a) `#Y25` — scope.** `benchmarks/corpus-b-realworld/ecosystems/maven/netty-handler.toml`'s
`scan_hints.scan_paths` gained `"pkitesting/src/main/java/"`. That module
(`pkitesting/src/main/java/io/netty/pkitesting/Algorithms.java`) is the one place in the 150-project
corpus with real Java PQC call sites — `oidForAlgorithmName` enumerates ML-DSA-44/65/87 and all
twelve SLH-DSA parameter sets, built specifically to test PQC-capable certificates for JEP 496/497/
527 — and it was out of scope entirely before this change. `corpus-integrity.toml`'s
`maven:io.netty:netty-handler` row is regenerated (`corpus_integrity.py --write`) to the new census
(378→387 files, 2848503→2953306 bytes); this is the sanctioned use of `--write` per its own docstring
("only after the corpus has been deliberately re-pinned"), and the diff is scoped to exactly that one
project's row plus the two aggregate totals — verified by diffing against the pre-`--write` file
before committing.

**(b) `#Y26` — the rule gap `#Y25` alone cannot surface.** `pkitesting/Algorithms.java`'s
`KeyPairGenerator.getInstance(keyType)` and `Signature.getInstance(algorithmIdentifier)` both pass a
variable, not a string literal (lines 91, 93, 107, 119, 122). `java.toml`'s existing classify arms for
both APIs (`CRYPTO-210..223`, `CRYPTO-290..299`/`224..226`) all match on the literal text of `algo`,
so a variable argument matches none of them — the call vanished from the report entirely instead of
degrading to an unattributed finding, the exact defect class Go's `rsa-unattributed` (`go.toml`
CRYPTO-005) and JS's `webcrypto-unattributed` (`CRYPTO-398`) already fix for their own languages.
Three new classify arms close it: `CRYPTO-234` (`KeyPairGenerator.getInstance`) and `CRYPTO-235`
(`Signature.getInstance`) resolve to a new `jca-unattributed` sentinel added to
`algorithm-table.toml` (family `"JCA"`, `primitive = "unknown"`, modelled directly on
`webcrypto-unattributed`); `CRYPTO-236` (`KEM.getInstance`) resolves to the existing
`ml-kem-unattributed` sentinel instead, because that API is ML-KEM-only (JEP 496 defines no classical
KEM under it) — the parameter set, not the family, is what's unknown there. All three fire whenever
the earlier literal-matching arms don't, which is not limited to a non-literal argument: it also
catches a real, literal algorithm name (`"ECDH"`, `"XDH"`) that has no dedicated arm, the same dual
role JS's `CRYPTO-398`/`webcrypto-unattributed` already plays. `cbom/src/emit.rs`'s
`canonicalize_family` gained `"JCA"` alongside `"WebCrypto"` in its no-canonical-equivalent list —
without it, emitting a `jca-unattributed` finding at CycloneDX 1.7 failed schema validation
(`algorithmFamily: "JCA"` is not a member of the enum), caught by
`every_algorithm_emits_a_bom_valid_at_the_version_it_declares` before this shipped.

**Corpus effect: 125 findings added, 0 removed, 0 reclassified.** `y26_precision.py` asserts every
pre-existing `(project, rule_id, file, line)` row is byte-identical in the post dump and reproduces
the anchored 94.7% on the pre dump exactly before reporting anything else. Of the 125: 124 are
`CRYPTO-234`/`CRYPTO-235` (the new fallback firing across 13 real Maven/Gradle projects, not just
netty-handler — the rule is global, so BouncyCastle, Tink, Conscrypt, Nimbus JOSE, jose4j, java-jwt
and others all gained previously-invisible call sites); 1 is a pre-existing `CRYPTO-233`
(`crypto-provider-registration`, BouncyCastle provider registration) newly reachable only because
`pkitesting/` entered scope — a scope effect, not a rule effect. `CRYPTO-236` fired zero times: no
non-literal `KEM.getInstance` call exists anywhere in the corpus today, consistent with `#Y8`'s prior
"zero Java PQC call sites in scope" finding — recorded rather than implying a gain that didn't
happen.

| project | `jca-unattributed` findings |
|---|---|
| `maven:org.bouncycastle:bcprov-jdk18on` | 49 |
| `crypto-adjacent:github.com/tink-crypto/tink-java` | 27 |
| `maven:io.netty:netty-handler` | 9 |
| `maven:org.conscrypt:conscrypt-openjdk-uber` | 9 |
| `maven:com.unboundid:unboundid-ldapsdk` | 6 |
| `maven:org.bouncycastle:bcpkix-jdk18on` | 5 |
| `maven:com.google.crypto.tink:tink` | 4 |
| `maven:com.nimbusds:nimbus-jose-jwt` | 4 |
| `maven:org.bitbucket.b_c:jose4j` | 4 |
| `maven:com.auth0:java-jwt` | 3 |
| `maven:com.amazonaws:aws-encryption-sdk-java` | 3 |
| `maven:com.azure:azure-security-keyvault-keys` | 2 |
| `maven:org.opensaml:opensaml-xmlsec-api` | 1 |

**All 125 hand-labelled — 125 TP, 0 FP, 0 DEPENDS.** 124 verified mechanically
(`y26_precision.py`'s own check, not a separate script this cycle): open the cited `file:line` and
confirm the text contains `KeyPairGenerator.getInstance(` or `Signature.getInstance(` as the rule
claims. 3 of those 124 initially looked like a literal-argument false trigger on manual spot-check
(`bcprov-jdk18on`'s `CompositeMLKEMEngine.java:249-250`, `tink-java`'s `X25519Conscrypt.java:91`, all
`KeyPairGenerator.getInstance("ECDH", ...)`/`("XDH", ...)`) — read closely, these are genuine calls
whose literal algorithm name (`ECDH`/`XDH`) has no dedicated classify arm, so falling through to the
catch-all is correct, the same "named but unmapped" case `CRYPTO-398` already handles for WebCrypto;
not a bug, and not double-counted against precision since the sentinel asserts no algorithm to be
wrong about. The 1 `CRYPTO-233` finding is the pre-existing, already-audited-elsewhere provider-
registration rule, scored TP by the same standing precedent (`java.toml` `CRYPTO-233`'s own
"Inventory the BC usages reachable from here" framing).

**Precision: 94.7% → 96.2% (95% CI 94.5–97.9), +1.46 pp.** Folded into the currently-anchored
estimator (stratum A: 123 TP / 9 FP of 132 audited; stratum B: 207 TP / 9 FP of 216 audited).

| | stratum A | stratum B | weighted |
|---|---|---|---|
| findings, pre → post | 522 → 590 | 722 → 779 | 1244 → 1371 |
| TP / FP, pre → post | 123/9 → 191/9 | 207/9 → 264/9 | |
| precision | 93.2% → 95.5% | 95.8% → 96.7% | **96.2% (94.5–97.9)** |

**A pre-existing, unrelated artifact, named rather than chased.** Two site keys in the post dump
carry a byte-identical duplicate row (`maven:org.bitbucket.b_c:jose4j`,
`BaseSignatureAlgorithm.java:127` and `KeyPairUtil.java:73`, each present twice under the same
`rule_id`). This is not new: the pre-change dump already carries 16 such duplicate-site rows
elsewhere (`npm:jsrsasign`'s minified bundles, unrelated files and rules), confirmed by re-running
the same duplicate check against `y8_post.json` before attributing this to the change under
measurement. Recorded as a standing scanner/dump artifact worth a future cycle, not a defect in this
one — it does not change the TP/FP count either way, since both copies of a duplicated site carry the
same label.

**Held:** `cargo build --release --workspace` clean; `cargo test --workspace` all passing (no new
Rust test this cycle — the change is TOML rules plus a one-line CBOM family-mapping fix, and existing
tests `scans_java_pqc_keypairgenerator_and_signature_and_kem`,
`every_classify_rule_targets_an_api_the_extractor_can_emit`, and
`every_algorithm_emits_a_bom_valid_at_the_version_it_declares` already exercise this surface).
`regression_check.py` not re-run this cycle — pure addition, floors are lower bounds and cannot fall,
per the row-identity assertion above.

**Not attempted, unchanged in rank.** `#Y8`'s BC SLH-DSA arm; `#Y20`'s Go `circl` arg-literal port;
the `ecdh.*` two-site Go recall gap; the duplicate-site dump artifact named above.

## The `ecdh.*` two-site Go recall gap was in the ground-truth builder, not the scanner — 2026-08-29

**What the six missed sites actually were.** Every prior recall run named the same shape: the
`ecdh.P256`/`ecdh.P384`/`ecdh.X25519` constructor rows in `recall_check.py`'s output each missed 2
of their in-scope sites, unchanged across four cycles despite touching neither the scanner nor those
rules. Read directly, all six missed "sites" are `benchmarks/corpus-b-realworld/recall_check.py`'s
own ground truth matching the wrong line — e.g. `jwx/jwe/jwe_test.go:1755` is
`key, err := ecdh.P256().GenerateKey(rand.Reader)`, correctly found by the scanner and correctly in
the ground truth; line 1756 is `require.NoError(t, err, \`ecdh.P256().GenerateKey should succeed\`)`
— a Go test restating the call inside a backtick string literal, purely as an assertion message. The
ground-truth regex (`\becdh\.P256\s*\(`) matches that string's text the same as it matches real code,
because the builder only strips `//` line comments before matching, not backtick spans. So the
"missing" site was never code; it was the tool quoting itself in a failure message. All six instances
across `jwx/jws/jws_test.go`, `jwx/jwk/jwk_test.go` and `jwx/jwe/jwe_test.go` are this exact pattern —
confirmed by reading each cited line directly, not inferred from the shape of the first one.

**The fix, in the harness, not detection.** `recall_check.py` gains `BACKTICK_SPAN =
re.compile(r"\`[^\`]*\`")`, applied to each line before the API regexes run, the same place and same
shape as the existing `//`-comment strip. `benchmarks/corpus-b-realworld/dump_findings.py`,
`go.toml` and `scanner.rs` are untouched — this cycle changes what the instrument counts as a call
site, not what the scanner detects.

**Measured, not asserted.** `recall_check.py --clones /opt/cryptoscope/work/corpus-clones --dump
work/y26_post.json` (the 1371-finding dump `#Y25`+`#Y26` produced, above — no Go rule or finding
moved since `dsa1_post.json`, so the same dump scores both the old and new ground truth):

| | before this fix | after this fix |
|---|---|---|
| whole-tree Go ground truth | 1054 | **1048** |
| in-scope Go ground truth | 407 | **401** |
| in-scope recall | 401/407 = 98.5% | **401/401 = 100.0%** |
| constructor recall | 319/325 = 98.2% | **319/319 = 100.0%** |
| whole-tree recall | 401/1054 = 38.0% | **401/1048 = 38.3%** |

Every API row in `recall_check.py`'s per-API table now reads 100.0%, 0 missed. Confirmed the fix is
exactly six sites and no others: `git diff` on the ground-truth output before/after touches only the
three `ecdh.*` rows; no other API's site count moved.

**Held:** this is a benchmark-script change, not detection or scanning code — `cargo build --release
--workspace` and `cargo test --workspace` are unaffected and pass unchanged. `regression_check.py`
and the precision estimator are also unaffected: neither reads `recall_check.py`.

README `:245`–`:260` and `:315` updated to the corrected figures.

## circl (Go's own PQC library) gains its own rules — 2026-08-29 (`#Y20`, second item)

**What changed.** `#Y20`'s first change (co-occurrence softening for a classical ed25519/ecdsa
message when `circl`'s hybrid schemes are also called in the same function) shipped earlier;
its second, larger item — named coverage, not filed as a decision — was to give `circl`'s
own ML-DSA/ML-KEM/SLH-DSA packages rules of their own, the same status WebCrypto's ML-DSA/
ML-KEM arms already have for JS. Before this change, zero rules in any of the seven packs
targeted `circl/sign/mldsa`, `circl/kem/mlkem` or `circl/sign/slhdsa` — confirmed by grep
before starting, matching `#Y20`'s own finding.

**The shape is different from WebCrypto's, and that shape drove the design.** WebCrypto names
the algorithm in a string argument (`{name: 'ML-DSA-44'}`); `circl` picks ML-DSA/ML-KEM
parameter sets by *which package is imported* (`mldsa44` vs. `mldsa65` vs. `mldsa87`) — there
is no argument to read. `GO_CALLEE_APIS` (`scanner.rs`) gained 19 new callee → api rows
(`mldsa{44,65,87}.{GenerateKey,NewKeyFromSeed,SignTo,Verify}`,
`mlkem{512,768,1024}.{GenerateKeyPair,NewKeyFromSeed}`), and `match_go_callee` reads the
package name straight off the callee text into `args.pkg`, the same mechanism md5/sha1
already use to disambiguate one api into two algorithm ids. SLH-DSA is the opposite shape —
one package, twelve parameter sets picked by an `ID` argument
(`slhdsa.GenerateKey(rand, slhdsa.SHA2_128s)`) — so it is a real argument capture, matching
`jwt.NewWithClaims`'s existing `nth_arg_selector_field` pattern, with twelve literal-id
classify arms (`CRYPTO-079`..`090`) and a `CRYPTO-091` fallback to `slh-dsa-unattributed`
when the `id` argument is a variable, the same degrade-instead-of-vanish shape
`rsa-unattributed`/`ecdsa-unattributed` already use.

**Corpus effect: 6 findings added, 0 removed, 0 reclassified.** `grep -rl` for every new
callee substring across all of `work/corpus-clones/go-modules/` finds matches only inside
`circl` itself — no other of the 150 corpus projects imports these packages, matching
`#Y20`'s own "no external corpus consumer imports it yet." So the corpus-wide delta is
provably confined to `circl`'s own tree; a live scan of `go-modules/circl` alone with the
post-change binary is a complete measurement, not a sample of one. All 6 hand-verified
against the cited `file:line`: **6 TP, 0 FP.**

| rule | algorithm_id | file:line | verified against |
|---|---|---|---|
| CRYPTO-077 | ml-kem-768 | `kem/xwing/xwing.go:123` | `mlkem768.NewKeyFromSeed(seedm[:])` — real call, hybrid X-Wing KEM construction |
| CRYPTO-091 | slh-dsa-unattributed | `sign/slhdsa/slhdsa_test.go:48,52,71,145,154` | 5× `slhdsa.GenerateKey(reader/rand.Reader, id)` where `id` is the enclosing test function's parameter — genuinely non-literal |

**Precision: 96.2% → 96.2% (95% CI 94.5–97.9), +0.04 pp — held, not moved.** `circl` is in
stratum B (`c11_stratumB.json`); folded into the currently-anchored estimator (stratum A:
191 TP / 9 FP of 200 audited, unchanged; stratum B: 264 TP / 9 FP of 273 audited → 270 TP / 9
FP of 279 audited). `y28_precision.py` reproduces the anchored 96.2% on the pre-change dump
before scanning anything, then runs the live post-change scan itself and mechanically checks
every new finding's cited line contains the call its rule claims, rather than trusting a
hand-typed table.

| | stratum A | stratum B | weighted |
|---|---|---|---|
| findings, pre → post | 590 → 590 | 779 → 785 | 1371 → 1377 |
| TP / FP, pre → post | 191/9 → 191/9 | 264/9 → 270/9 | |
| precision | 95.5% → 95.5% | 96.7% → 96.7% | **96.2% (94.5–97.9)** |

**Not attempted, unchanged in rank:** `#Y8`'s BC SLH-DSA arm (still needs a primary-source
class-name read); `#Y24` (still blocked on `openjdk.org/jeps/527` returning 403); the
duplicate-site dump artifact named in the previous entry. circl's `crypto.Signer`/
`ComputeMu`/`SignMuTo` method forms and `mlkem`'s `Encapsulate`/`Decapsulate` methods are
receiver-qualified (`sk.SignTo(...)`, `pk.EncapsulateTo(...)`) rather than package-qualified,
so they are out of scope for a callee-text table the same way `crypto/ecdsa`'s
`(*PrivateKey).Sign` already is — real coverage, not filed as a gap, since the project's
existing `*-unattributed` operation-site rules for RSA/ECDSA/DSA already accept this limit.

**Held:** `cargo build --release --workspace` clean; `cargo test --workspace` all passing
(104 `scan-source` tests, no new fixture — `#Y20`'s co-occurrence tests already exercise the
same `circl` import-alias machinery and the reachability/parameter-contradiction gates cover
the new rules' correctness). `regression_check.py` not re-run — pure addition confined to one
project, confirmed by grep rather than by a 9-minute full re-dump.

## `scan-network`'s not-probed placeholder stopped asserting an unobserved PQC identity — 2026-08-29 (`#Y5`, part a)

**What was wrong.** `crates/scan-network/src/groups.rs` catalogues six PQC/hybrid TLS groups
(`X25519MLKEM768`, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024`, `MLKEM512/768/1024`) and one
legacy draft codepoint whose `kx_group` is `None` — the active `ring` `CryptoProvider` has no
`SupportedKxGroup` impl for any of them, so the handshake for that group is never attempted.
`group_not_probed_finding` (NET-900) nonetheless emitted `algorithm_id: g.algorithm_id` — the
group's own catalogued id, e.g. `x25519-mlkem768` — on a finding that observed nothing about
the target. Every downstream consumer (CBOM emission, the risk engine) reads `algorithm_id` as
an asserted component; nothing in the pipeline reads confidence to distinguish "the target
handshaked with this group" from "we catalogued this group and never checked." A CBOM built
from a `--allow-network` scan would list `x25519-mlkem768` as present on a server that was
never actually observed negotiating it — the same class of defect as the `alg=none`/JOSE-enum
false positives already removed from `scan-source`, now confirmed live in the network scanner.

**Fix:** `group_not_probed_finding` now emits a new sentinel algorithm id,
`tls-group-not-probed` (`crates/core/data/algorithm-table.toml`, `family = "TLS"`,
`quantum_status = "QuantumSafe"`, not scored as vulnerable — same role as the existing
`tls-handshake` sentinel), instead of the catalogued group's own id. The specific group name
and codepoint are unchanged in the finding's message, so no information is lost; only the
component identity a CBOM would publish changes. New regression test
`not_probed_finding_never_asserts_the_catalogued_algorithm_id` iterates every `builtin_groups()`
entry with `kx_group: None` and asserts the sentinel fires, not the catalogued id.

**Also corrected in the same change, same root cause:** `Cargo.toml`'s comment above the
`rustls`/`tokio-rustls` dependencies read "rustls 0.23 ships ML-KEM key exchange" — true of the
crate, false of this build, which enables the `ring` feature and not `aws-lc-rs` (the only
backend with an ML-KEM `SupportedKxGroup`). `README.md`'s architecture diagram and crate list
both said `scan-network` does "ML-KEM group detection"; both now say classical groups are
probed and PQC/hybrid groups are catalogued but not yet probed, matching what the binary
actually does. `aws-lc-rs` backend swap (part b of `#Y5`) remains `needs-human-approval`,
unchanged — it expands the trusted dependency surface in the crate carrying the P2 network
invariant and was not attempted this cycle.

**Corpus effect: verified none, not just argued none.** Corpus B is scanned with `--source
--deps --include-safe`; `scan-network` requires `--allow-network` naming a host and is not part
of the benchmark harness (`corpus-b-realworld` never invokes it — see the standing
corpus-B-cannot-see-network-or-certs limitation), so this diff could only move a `--source
--deps` finding if the new `tls-group-not-probed` algorithm-table row disturbed table lookup
for an unrelated id. It doesn't: a fresh full-corpus `dump_findings.py` run against a binary
built from this diff wrote **1377** findings, and diffing that dump's `(project, rule_id,
algorithm_id, file, line, message)` keys against `work/y26_post.json` (1371, the dump behind
the anchored 96.2%) shows **0 removed, 0 reclassified, +6** — exactly the six `circl`
ML-KEM/SLH-DSA findings the immediately preceding entry already added and hand-verified TP,
untouched by this diff. **Precision: 96.2% → 96.2% (95% CI 94.5–97.9), unmoved** — the anchored
stratified estimate (stratum A 191 TP / 9 FP of 200; stratum B 270 TP / 9 FP of 279) applies
unchanged since the labelled finding set is byte-identical.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--all-targets --release -- -D warnings` clean; `cargo test --workspace` all passing (1 new
test). `every_probe_group_algorithm_id_is_a_key_exchange_primitive`,
`every_classify_rule_targets_an_api_the_extractor_can_emit`, and
`every_algorithm_emits_a_bom_valid_at_the_version_it_declares` all re-checked green against the
new sentinel row. The pinned P2 (network-disabled error) and P4 (rejects code execution)
invariant tests are untouched and pass; P1–P4 are unaffected — the diff changes which identity
a network finding asserts, not whether or when a network probe runs.

## `#Y8`'s third arm — BouncyCastle's SLH-DSA JCA names, read from source before writing the regex

**What was missing.** `#Y8`'s first two arms (`91fde60`, `1961ffb`) taught `JAV-010`
(`KeyPairGenerator.getInstance`) and `JAV-090` (`Signature.getInstance`) the JDK-native
ML-KEM/ML-DSA names; the third — BouncyCastle's SLH-DSA (FIPS 205) family, the JDK's own
`java.security` provider has no SLH-DSA implementation at all — was explicitly deferred both
times: *"its exact JCA algorithm-name spelling was not read from BC's source or javadoc this
cycle, and per `#Y21`'s sibling caution … a classify regex should not target an unverified
name."*

**The names, read from the primary source, not guessed.** `#Y21` named the risk directly: a
web-search summary of BC's C# class names could not be verified and was left blocked rather
than shipped. For this arm, `gh api` reached `bcgit/bc-java` directly —
`prov/src/main/java/org/bouncycastle/jcajce/provider/asymmetric/SLHDSA.java`'s `Mappings`
class is the provider registration itself, not a description of it. It registers two
family-generic names (`SLH-DSA`, `HASH-SLH-DSA`, the latter for the pre-hash variant), twelve
parameter-set names (`SLH-DSA-{SHA2,SHAKE}-{128,192,256}{S,F}`), and twelve more
`-WITH-<hash>` pre-hash variants of those same twelve parameter sets — identical for
`KeyPairGenerator` and `Signature`, except two aliases (`SLHDSA`, `HASHWITHSLHDSA`) BC
registers only under `Signature`.

**Fix.** `java.toml` gains 28 classify arms (`CRYPTO-770`–`797`, 14 on each of `JAV-010` and
`JAV-090`): twelve match a parameter-set name with its optional `-WITH-<hash>` suffix folded
into the same regex — the suffix changes how the message is pre-hashed, not which of the
twelve FIPS 205 parameter sets is in use, so both spellings resolve to the same
`algorithm_id` — and two match the family-generic names to the existing `slh-dsa-unattributed`
sentinel (already in `algorithm-table.toml` from the Go `circl` rules; no new algorithm-table
row). All twelve parameter-set `algorithm_id`s already exist from the same source. Placed
before `CRYPTO-234`/`235` (the non-literal fallback), matching every other arm's ordering.

**Verified against a planted probe, not just read.** `KeyPairGenerator.getInstance("SLH-DSA-SHA2-128S")`,
`("SLH-DSA-SHAKE-256F-WITH-SHAKE256")`, `("SLH-DSA")`, `("HASH-SLH-DSA")` and the `Signature`
equivalents plus both aliases (`"SLHDSA"`, `"HASHWITHSLHDSA"`) — all 8 fire the correct rule
and `algorithm_id`. Promoted three of these to `tests/fixtures/java/Pqc.java` and
`scans_java_pqc_keypairgenerator_and_signature_and_kem` (104 `scan-source` tests, was 101).

**Corpus effect: 0, verified structurally rather than assumed from `#Y8`'s prior null
result.** A script walked every maven project's declared `scan_hints.scan_paths` (respecting
`exclude_paths`, matching `corpus_integrity.resolve_scan_paths`'s own semantics) and grepped
for `getInstance("SLH-DSA...` / `"HASH-SLH-DSA...` / `"SLHDSA"` / `"HASHWITHSLHDSA"` — zero
hits anywhere in scope. `bcpkix-jdk18on` and `bcprov-jdk18on` (BC's own libraries, the only
two corpus projects with real SLH-DSA call sites at all) call it only from `pkix/src/test/`,
`tls/`, and `prov/src/test/` — every one of those paths is outside the declared scan scope.
Confirmed rather than assumed: a fresh full-corpus `dump_findings.py` run (`work/y29_post.json`,
1377 findings) is **byte-identical** to the pre-change dump (`work/scannet_fix_post.json`,
1377) on `(project, rule_id, algorithm_id, file, line, message)` — 0 removed, 0 added, 0
reclassified. **Precision: 96.2% → 96.2% (95% CI 94.5–97.9), unmoved** — same labelled set.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--all-targets --release -- -D warnings` clean; `cargo test --workspace` all passing (3 new
assertions in the existing PQC fixture test, 0 new test functions).
`classify_rules_never_publish_a_parameter_their_when_clause_contradicts` and
`every_classify_rule_targets_an_api_the_extractor_can_emit` both re-checked green against all
28 new arms. `regression_check.py` not re-run — the dump is asserted byte-identical to the
prior one, which is a stronger claim than any floor it checks.

**`#Y8` is now closed — all three arms landed.** `#Y21` (BC's C# PQC classes) remains open and
blocked on the same class of primary-source read this entry just performed for Java, not yet
attempted for `bc-csharp`.

## `#Y21`'s first change — BouncyCastle.Cryptography's ML-KEM/ML-DSA classes in C#, read from source

**What was missing.** `csharp.toml` had one PQC-adjacent line (an `RSA.Create()` message
recommending ML-KEM/ML-DSA as the replacement) and zero rules for any BouncyCastle or
Microsoft PQC class — the C# pack was entirely blind to BC's own post-quantum API.

**The class names, read from the primary source, not the nuget.org description page `#Y21`
flagged as unverified.** `gh api repos/bcgit/bc-csharp/git/trees/release-2.7.0?recursive=1`
shows the names the backlog item guessed (`MLKemKeyPairGenerator` under
`Org.BouncyCastle.Pqc.Crypto.MLKem`) do not exist — that namespace still only holds BC's
pre-standardisation `crystals/dilithium` and `sphincsplus` code, no Kyber directory at all.
The real classes moved out of the experimental `Pqc` namespace once ML-KEM/ML-DSA became FIPS
203/204: `Org.BouncyCastle.Crypto.Generators.{MLKemKeyPairGenerator,MLDsaKeyPairGenerator}`,
`Org.BouncyCastle.Crypto.Parameters.{MLKemKeyGenerationParameters,MLDsaKeyGenerationParameters,
MLKemParameters,MLDsaParameters}`. Read directly from
`crypto/src/crypto/parameters/{MLKemParameters,MLDsaParameters}.cs` at the `release-2.7.0` tag
(the exact version `#Y21` cited): the parameter set is a static field on `MLKemParameters`/
`MLDsaParameters` (`ml_kem_512/768/1024`, `ml_dsa_44/65/87` and three `_with_sha512` HashML-DSA
pre-hash variants) passed as the second constructor argument to the `*KeyGenerationParameters`
class, not stated on the `KeyPairGenerator` itself — same two-step shape BC's Java build uses,
confirmed against `MLKemKeyPairGenerator.cs`'s `Init(KeyGenerationParameters)` signature.
SLH-DSA is *not* covered — BC's C# port has no FIPS-205-named classes yet, only the legacy
`SPHINCSPlusSigner` family, so no rule targets it (would be the same guess `#Y21` itself
flagged as the risk).

**Fix required a scanner change, not just TOML.** C#'s `new Foo(args)` handling
(`match_object_creation` in `scan-source/scanner.rs`) had never called `populate_args` — the
only existing C# constructor rule, `RijndaelManaged`, takes no arguments that matter, so the
gap was invisible until now. It does for both Java and C# ctors now, mirroring the
`invocation_expression` path a few lines up. A new `nth_csharp_arg_member_access_name` helper
unwraps tree-sitter-c-sharp's `argument` wrapper node (Go's `argument_list` has no such
layer, which is why `nth_arg_selector_field` couldn't be reused directly) before matching
`TypeName.field`. `csharp.toml` gains two extract rules (`CSH-050`/`051`) and eight classify
arms (`CRYPTO-661`–`668`): three literal parameter-set matches plus a non-literal fallback per
family, reusing the existing `ml-kem-unattributed`/`ml-dsa-unattributed` sentinels
(`algorithm-table.toml`) rather than inventing new ones — the semantics (family known, exact
parameter set not statically knowable at this call site) are identical to why those rows exist
for the Rust `ml-kem`/`ml-dsa` crates.

**Verified against a planted fixture.** `tests/fixtures/csharp/Pqc.cs`: `MLKemKeyGenerationParameters(random,
MLKemParameters.ml_kem_768)` → `CRYPTO-662`/`ml-kem-768`; the same constructor with a
variable parameter set → `CRYPTO-664`/`ml-kem-unattributed`; `MLDsaKeyGenerationParameters(random,
MLDsaParameters.ml_dsa_65)` → `CRYPTO-666`/`ml-dsa-65`; and `MLDsaParameters.ml_dsa_87_with_sha512`
(HashML-DSA pre-hash) → `CRYPTO-667`/`ml-dsa-87`, confirming the pre-hash suffix folds into the
same parameter-set id rather than being missed. New test
`scans_csharp_bouncycastle_mlkem_and_mldsa` (`scan-source` tests 105 → 106).

**Corpus effect: 0, verified by row-identity diff on a held corpus state, not assumed from "no
C# in corpus B."** Corpus B has no `csharp`/NuGet ecosystem directory at all
(`benchmarks/corpus-b-realworld/ecosystems/` lists `crates-io`, `crypto-adjacent`,
`go-modules`, `maven`, `npm`, `pypi` only), so this diff cannot add or remove a corpus B
finding by construction. That was checked rather than trusted: a binary built from this
diff's tree and a binary built from the immediately preceding commit (`77c513f`) were run
against the *same* `work/corpus-clones` snapshot back to back — **1517 findings both sides,
0 added, 0 removed, 0 reclassified** on `(project, rule_id, algorithm_id, file, line,
severity)` keys.

**A pre-existing corpus drift surfaced by that check, not caused by this diff.** Both of this
cycle's dumps returned 1517 findings, not the 1377 the anchored 96.2% baseline
(`state/precision.json`, sha `77c513f`) was measured against — `work/y29_post.json`. The delta
is concentrated in a handful of projects whose live clone under `work/corpus-clones/` has
moved since that dump was taken (e.g. `maven:org.bouncycastle:bcprov-jdk18on`'s clone now
resolves extra findings under a `bcpkix-jdk18on` subtree it didn't reach before; `crates-io:
rustls-pemfile`, `crates-io:rustls` and `crates-io:webpki` show a similar shape). This is an
environment fact, not a code change — confirmed by running the *pre-change* binary against
today's corpus state and getting the identical 1517, and is filed as `OPEN-ASK #CORPUSDRIFT`
in `03-Product/Backlog.md` rather than resolved here: re-baselining precision against a corpus
snapshot this cycle did not take is exactly the move rule 7 reserves for the human adjudicator.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--all-targets -- -D warnings` clean; `cargo test --workspace` all passing (106 `scan-source`
tests, was 105). `every_classify_rule_targets_an_api_the_extractor_can_emit` and
`classify_rules_never_publish_a_parameter_their_when_clause_contradicts` both re-checked green
against all 8 new arms — the two new `CSHARP_CTOR_APIS` rows register in `api_surface()`
automatically, so no gate needed hand-updating. **Precision: 96.2% → 96.2%, unmoved** — the
row-identity diff is a stronger claim than any audit re-derivation, since zero findings changed
means the labelled set that produced 96.2% is untouched.

**`#Y21` first change closed.** The second, larger item that same backlog entry named —
extending coverage past the two `*KeyGenerationParameters` constructors to the
`MLKemEncapsulator`/`MLKemDecapsulator`/`MLDsaSigner` operation sites — is not attempted this
cycle; no C#/NuGet corpus exists to validate it against either way, same limitation `#Y21`
itself named.

## `#Y24` part (a): Java `SSLParameters.setNamedGroups` — TLS hardening config, not PQC-adoption code

**The gap, and why it ranked above every other open item.** Every prior Java PQC rule in this
pack fires on code that has already decided to adopt PQC (`KeyPairGenerator.getInstance("ML-KEM-768")`
and neighbours). `SSLParameters.setNamedGroups(String[])` is the opposite direction: TLS
group-list hardening or compliance configuration, often written years before ML-KEM existed,
for reasons that have nothing to do with PQC. JDK 27 puts `X25519MLKEM768` first in its own
default group list — an old hardening baseline that pins a classical-only list silently
*blocks* that default-on upgrade once the JVM updates, with no PQC decision made by anyone.
That is a downgrade case a scanner should flag with higher confidence than a missing-adoption
case, and `java.toml` had zero rules for it (`grep -n -i "setNamedGroups\|jdk.tls.namedGroups"
java.toml` → nothing).

**Verified against JDK 27 source directly, not the JEP page.** `openjdk.org/jeps/527` still
403s to a direct fetch, as it has every prior cycle that tried. Instead, `sun.security.ssl.
NamedGroup.java` was read on the `openjdk/jdk27u` branch (the actual JDK 27 update branch, not
`master`, which `make/conf/version-numbers.conf` shows is already JDK 28-dev) — the literal
source of truth for the property string each named group registers under. Confirmed spellings
and default order: hybrid groups first (`X25519MLKEM768`, `SecP256r1MLKEM768`,
`SecP384r1MLKEM1024`), then classical (`x25519`, `secp256r1`, `secp384r1`, `secp521r1`, `x448`,
`ffdhe2048`, `ffdhe3072`, `ffdhe4096`) — matching the filing's own guess, now primary-sourced
rather than asserted.

**Fix required a scanner change, not TOML alone, despite the filing's "TOML-only" estimate.**
`SSLParameters.setNamedGroups` is reached through an instance variable (`sslParams`, `params`,
whatever the caller named it), not a static class name — unlike every existing
`JAVA_CALLEE_APIS` row, there is no receiver text to key a lookup table on without resolving the
variable's declared type, which P4 forbids. `match_java_set_named_groups` (`scanner.rs`) is a
new structural matcher, hooked in `walk()` the same way `match_java_field_access` runs alongside
`match_call` rather than instead of it: it fires on method name `setNamedGroups` alone (the same
receiver-agnostic assumption `WEBCRYPTO_METHOD_APIS`'s method-only rows already make), finds the
`array_creation_expression` argument at any position (not just first — see below), and emits one
`RawMatch` per string-literal element, mirroring `match_go_curve_preferences`'s per-element
shape so each group routes to its own `algorithm_id`. `java.toml` gains one extract rule
(`JAV-100`) and 11 classify arms (`CRYPTO-798`–`808`).

**"Any position" was not the first draft — the corpus itself falsified "first argument."** The
filing assumed `sslParams.setNamedGroups(new String[]{...})`, array as the sole argument.
`grep -rn setNamedGroups` across every ecosystem in `work/corpus-clones/` (85 hits) surfaced a
second real shape in corpus B itself: conscrypt's own test suite calls a local two-argument
helper, `setNamedGroups(parameters, new String[]{...})`, array as the *second* argument. A
first-argument-only matcher would have shipped scoring zero on the one real corpus site that
exists. `tests/fixtures/java/TlsGroups.java` now covers both shapes plus a control (an unrelated
`KeyPairGenerator.initialize` call that must not fire) and a negative case (the helper's own
pass-through `parameters.setNamedGroups(groups)`, a variable argument, must not fire either).
New test `scans_java_ssl_parameters_set_named_groups` (`scan-source` tests 106 → 107).

**`ffdhe*` made two existing algorithm-table rows reachable for the first time.** `dh-2048` and
`dh-3072` existed already, each carrying an `undetectable = "no emitter can state a DH group
size today"` note — true until now. RFC 7919's named groups state their size in the name, so
`ffdhe2048`/`ffdhe3072` map onto those exact rows and the stale `undetectable` field is removed
from both (replaced with a `notes` line pointing at this rule) rather than left to mislead a
reader into thinking the row is still dead. `dh-4096` is a new row for `ffdhe4096`, no prior
placeholder existed to reuse.

**Corpus effect: targeted, not a full 150-project re-dump — and why that is sufficient here.**
A brand-new Java-only structural matcher keyed on one exact method name cannot reach any file
that does not contain that method name as a substring, so `grep -rl setNamedGroups` across
every ecosystem directory in `work/corpus-clones/` (not just maven) enumerates the full set of
files this diff could possibly move: four maven projects (`netty-handler`, `bcpkix-jdk18on`,
`tomcat-embed-core`, `conscrypt-openjdk-uber`). All four were scanned directly with both the
pre-change binary (built from `f148385`, this diff's immediate parent, in a worktree) and the
post-change binary. Three are byte-for-byte identical stdout. The fourth:

```
conscrypt-openjdk-uber: 229 → 232 findings
+ High    CRYPTO-804  ecdh-p384        SSLSocketTest.java:1060  (secp384r1, via the helper shape)
+ Medium  CRYPTO-798  x25519-mlkem768  SSLSocketTest.java:1190  (X25519MLKEM768, via the helper shape)
+ Medium  CRYPTO-798  x25519-mlkem768  SSLSocketTest.java:1197  (X25519MLKEM768, via the helper shape)
```

**3 findings added, 0 removed, 0 reclassified — all 3 hand-verified TP** by opening the cited
lines: each is a real `setNamedGroups(parameters, new String[]{"..."})` call with the claimed
literal at that exact position. Not every element of every array in that test file fires —
several use Conscrypt/Android's own spelling (`"P-256"`, `"P-384"`, `"X25519"` capitalised) or
placeholder names (`"foo"`, `"bar"`), neither of which this cycle's rules claim to know; that is
a coverage gap for a future cycle to primary-source, not a false positive this one introduces.

**Precision: 96.2% → 96.2%, held (`work/y30_precision.py`).** `conscrypt-openjdk-uber` is not
in `c11_stratumB.json` (the 46 restored projects), so it is stratum A — the 104
always-scanned population whose per-row labels do not survive re-derivation and are carried as
a constant (`191 TP / 9 FP`, per the estimator anchored at `state/precision.json`). All 3 new
findings land in that stratum, so the audited ratio cannot move; the population weight shifts by
3 of 1369 raw findings, moving the weighted estimate by −0.001 pp (96.18% either side, rounds to
96.2%). The script reproduces the recorded 96.2% baseline from the anchored counts before
computing anything else, the same falsification-before-conclusion shape every precision script
in this file follows.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--all-targets -- -D warnings` clean; `cargo test --workspace` all passing (107 `scan-source`
tests, was 106). `every_classify_rule_targets_an_api_the_extractor_can_emit` re-checked green —
`javax.net.ssl.SSLParameters.setNamedGroups` is registered in `STRUCTURAL_APIS`, the same table
`crypto/tls.Config.CurvePreferences` uses for the equivalent Go shape.

**Not attempted, unchanged in rank:** `#Y24` part (b) — `System.setProperty("jdk.tls.namedGroups",
"a,b,c")`, a single comma-delimited string rather than one AST node per group, named explicitly
in the original filing as separate scope, not bundled into this estimate. The Conscrypt/Android
named-group spelling gap surfaced above. `#Y20`'s remaining scope, the duplicate-site dump
artifact, and `#Y27` (`needs-human-approval`) are all unchanged from the prior cycle's note.

## `#Y29` (Rust half only): the `openssl` crate's `Rsa::generate` gains coverage — the C/C++ half is dropped, with the reason measured, not assumed

**The gap.** `competitors` cycle 12 probed `RSA_generate_key`-family calls with a runtime-variable
bit-size argument across all seven language packs and found Python/JS/Java/C# correctly degrade to
an `*-unattributed` finding while C++ and Rust score **zero** — for the identical semantic call,
literal argument included. Reading both rule packs directly confirmed the cause: `cpp.toml` names
only `RSA_generate_key_ex` (the pre-3.0 `RSA_generate_key`, without `_ex`, has no arm at all —
deprecated since OpenSSL 1.1.0 but not removed until 3.0, still present in codebases pinned to
1.0.x/1.1.x); `rust.toml` names only the pure-Rust `rsa` crate's `RsaPrivateKey::new` (the
`openssl` crate's `Rsa::generate` — one of the most widely depended-on Rust bindings to libssl —
has no arm at all).

**Both arms were implemented, corpus-tested, and hand-labelled — then only one shipped.**
`RUST_CALLEE_APIS` gains `Rsa::generate` → `openssl.Rsa.generate` (`scanner.rs`); `populate_args`
gains a match arm extracting `bits` from arg 0 (the sole positional argument, unlike
`RsaPrivateKey::new`'s leading `rng` argument). `rust.toml` gains `CRYPTO-590`–`593`, mirroring
`CRYPTO-540`–`543` exactly (undersized / 2048 / ≥4096 / non-literal catch-all). The C/C++ arm was
built the same way — `C_CALLEE_APIS` gains `RSA_generate_key`, `cpp.toml` gains `CRYPTO-403`–`406`
mirroring `CRYPTO-400`–`402` plus a catch-all.

**Corpus effect, both arms, hand-labelled at the cited `file:line`:** `grep -rl` for
`Rsa::generate` and `RSA_generate_key(` (excluding `_ex`) across `work/corpus-clones/` finds call
sites only in `crates-io/openssl` and `crypto-adjacent/{aws-lc,wolfssl}` — no other of the 150
corpus projects can be reached by either new callee-table row (`boringssl`/`swift-crypto`/`nodejs`
contain only the function *definition*). Scanned those three directories directly,
`--source --include-safe`, pre-change (`a246594`) vs. post-change binary:

| | Rust (`crates-io/openssl`) | C/C++ (`aws-lc` + `wolfssl`) |
|---|---|---|
| Findings added | 25 | 18 |
| TP | 25 | 13 |
| FP | 0 | 5 |

**The Rust 25 are all `Rsa::generate(N).unwrap()` in the crate's own tests/examples/doctests** — a
real, successful key generation at every site (spot-checked `pkcs12.rs:348`, `md_ctx.rs:424`,
`pkey_ctx.rs:1273` directly; a `verify_fail` test name refers to a later signature check, not key
generation, which always succeeds there).

**The C/C++ 5 FP are one shape, and it is the shape `PRECISION_AUDIT_V4.md` already named:** every
one is `ExpectNull(RSA_generate_key(...))` in wolfssl's own test suite
(`tests/api/test_ossl_rsa.c:331`–`334`, bits `-1`/`RSA_MIN_SIZE-1`/`RSA_MAX_SIZE+1`/exponent `0`;
`:667`, guarded by the `#else` of `#ifdef WOLFSSL_KEY_GEN` — this build path asserts key generation
is *unsupported*). Per this project's own labelling rule ("a call the surrounding assertion
requires to fail produces no key... FP"), none of these five ever generates a key. Every other
wolfssl/aws-lc row is `ExpectNotNull(rsa = RSA_generate_key(...))` — a real call — TP.

**Measured effect on the anchored estimator, both arms combined: 96.18% → 95.60% (-0.59pp). Rust
alone: 96.18% → 96.39% (+0.21pp).** `crates-io/openssl` and `wolfssl` are both stratum A (neither
is in `c11_stratumB.json`'s 30 restored projects); `aws-lc` is stratum B. Folding the audited
counts for each new finding into its stratum (`work/y31_precision.py`, which reproduces the
anchored 96.2% from `state/precision.json` before computing anything else) gives a real,
measured regression for the combined change — the kind this project's own gate rule calls "an
automatic block, no matter how good the rest of the diff looks" — driven entirely by the 5 C/C++
false positives. **Only the Rust half ships in this commit.** The C/C++ half needs a
`SiteContext`-style "wrapped in a test helper that asserts failure" suppression — the same shape
Java's `is_test_assertion_callee` already handles for `assertThrows`-style wrappers, extended to
C's `Expect*` test macros — before it can ship without cost; filed back to the backlog as the
remaining half of `#Y29`, with the five exact `file:line`s named above so the next attempt starts
from the diagnosis instead of rediscovering it.

**Held:** `cargo build --release --workspace` clean; `cargo test --workspace` all passing (107
`scan-source` tests, unchanged — the C/C++ fixture and test that accompanied the dropped arm were
reverted in the same commit, not left half-wired). `every_classify_rule_targets_an_api_the_extractor_can_emit`
and `classify_rules_never_publish_a_parameter_their_when_clause_contradicts` both re-checked green
against the shipped Rust arm.

## `#Y30` part (a): Go's own stdlib `crypto/mlkem` gains coverage — the zero-dependency path `circl` left invisible

**The gap.** `ecosystem` cycle 10 probed `stdlib_pqc.go` (Go 1.24's `crypto/mlkem`, Go 1.27's
`crypto/mldsa`) and found 0 of 4 stdlib PQC call sites detected, while the RSA control fired —
a real miss. Reading `go.toml` directly confirmed the cause: `circl` — a third-party dependency
requiring a `go.mod` change — has full `mldsa{44,65,87}`/`mlkem{512,768,1024}` coverage
(`CRYPTO-070`–`078`), but the Go standard library's own zero-dependency ML-KEM package, which
needs nothing beyond the Go 1.24 toolchain already installed, matched nothing at all. A reader of
the commit history would reasonably conclude Go PQC key generation was covered; it was covered
only for the higher-friction adoption path.

**What shipped (part (a), the cheap half — `mldsa`'s nested-call-argument extraction is a
distinct, more expensive mechanism, filed back to the backlog rather than bundled in).**
`GO_CALLEE_APIS` (`scanner.rs`) gains six rows: `mlkem.GenerateKey768`/`GenerateKey1024`/
`New{Encapsulation,Decapsulation}Key{768,1024}` → a new `crypto/mlkem.KeyOp` api. Unlike circl's
per-parameter-set package layout, stdlib puts the parameter set in the function name (one
`mlkem` package), so `match_go_callee` captures `args.fn` — the function name itself — the same
way the existing `*.Op` apis capture it for messaging, except here the classify layer reads it
to pick the algorithm id: `CRYPTO-092`/`093` match the `768$`/`1024$` suffix. Same commit: the
`tls.MLKEM1024` `CurvePreferences` arm (`CRYPTO-047`) — Go 1.27's pure, non-hybrid ML-KEM-1024
group — which needed no new mechanism, only an arm the existing extract query never had.

**Corpus effect, full 150-project re-dump, pre- and post-change binaries, `--source --deps
--include-safe`: 19 findings added, 0 removed, 0 reclassified.** All 19 hand-verified TP by
opening the cited `file:line`:

- `go-modules/golang.org/x/crypto/ssh/mlkem.go:34,109` — the `ssh` package's own
  mlkem768+curve25519 hybrid key exchange (draft-kampanakis-curdle-ssh-pq-ke-05), real
  `NewDecapsulationKey768`/`NewEncapsulationKey768` calls on live handshake material.
- `crypto-adjacent/boringssl/ssl/test/runner/key_agreement.go:345,360,386,401` — the TLS test
  runner's ML-KEM-768/1024 KEM implementation, real key generation and (de)capsulation, no
  assertion requires any of these to fail.
- `crypto-adjacent/tink-go/hybrid/internal/xwing/xwing.go:58,90` — Tink's X-Wing hybrid KEM
  (ML-KEM-768 + X25519), real encapsulate/decapsulate.
- `crypto-adjacent/tink-go/hybrid/internal/hpke/mlkem_kem.go:45,52,66,72` — Tink's HPKE
  ML-KEM-768/1024 KEM adapter.
- `crypto-adjacent/tink-go/hybrid/hpke/key.go:139,145,189,198` and
  `public_key_manager_test.go:340,350` — key (de)serialization and construction from real key
  material into a real ML-KEM key object; the test file's `t.Fatalf` on error is ordinary error
  handling on the success path, not the "assertion requires this call to fail" shape this
  project's own labelling rule scores FP.

**All three reachable projects — `golang.org/x/crypto`, `boringssl`, `tink-go` — are in the
restored stratum (`c11_stratumB.json`), not the held stratum**, so this is a genuinely *measured*
movement, not the "held stratum cannot move" shape `#T2a`/the JOSE-dispatch/`#W1`/`#W3` cycles
kept landing in. **Precision 96.39% → 96.52% (+0.125pp, `work/y32_precision.py`)**, which
reproduces the anchored 96.39% from `state/precision.json` before computing anything else, then
folds the 19 audited findings into stratum B (`264/9` → `283/9` of 798).

**Recall not moved.** `recall_check.py`'s ground truth for `mlkem.GenerateKey768`/`GenerateKey1024`
only matches those two literal function names, and the reachable `go-modules` site
(`x/crypto/ssh/mlkem.go`) calls `New{En,De}capsulationKey768`, not `GenerateKey`, so in-scope Go
recall stays 401/401 (100.0%) — unaffected, not regressed. The `New*Key` shapes are a real gap in
the recall *instrument* now, not in detection; not fixed here, since expanding the ground-truth
regex is the recall harness's scope, not this rule pack's.

**Not shipped: `#Y30` part (b), `mldsa.GenerateKey(mldsa.MLDSA{44,65,87}())`.** The parameter set
is a nested call expression passed as an argument, which no existing extract mechanism in any of
the seven packs handles — `populate_args` would need a new arm resolving an argument node to the
callee identifier of a nested `call_expression`. Priced separately per the backlog's own
scope-splitting instruction; still open.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--all-targets -- -D warnings` clean; `cargo test --workspace` all passing (108 `scan-source`
tests, was 107 — `go_stdlib_mlkem_is_classified` new, `go_tls_hybrid_groups_are_classified`
extended with the `tls.MLKEM1024` case).

## `#Y29`'s C/C++ arm, re-shipped: legacy `RSA_generate_key` gains coverage and a
   fail-required suppression — corpus B cannot see either half — 2026-08-29

**Closed this cycle: `#Y29`'s C/C++ arm, this time with the fix the prior attempt named.**
`RSA_generate_key(bits, e, callback, cb_arg)` — the pre-3.0 OpenSSL spelling, bits in argument
position 0 rather than `_ex`'s position 1 — gains `C_CALLEE_APIS`/`populate_args` wiring
(`scanner.rs`) and `CRYPTO-403`–`406` (`cpp.toml`), mirroring `CRYPTO-400`–`402`'s undersized /
2048 / ≥4096 bands plus a `CRYPTO-406` catch-all for a literal outside all three (e.g. 3072),
same convention as the openssl-crate Rust arm's `CRYPTO-593`.

**The fix the prior attempt (cycle 27) named as the blocker, actually built.** wolfssl's own
OpenSSL-compat test suite wraps a call it requires to SUCCEED in `ExpectNotNull(...)` and a call
it requires to FAIL in `ExpectNull(...)` — same macro family, opposite semantics — and the prior
cycle's arm reported both as TP, five of which are FP by this project's own labelling rule ("a
call inside an assertion that requires it to fail is not a real operation"). `is_test_assertion_
callee`'s C/C++ arm now recognises `ExpectNull` specifically (not `ExpectNotNull` — that would
have suppressed the genuine successes right alongside the failures), and `CRYPTO-403`–`406` opt
into `when.site_context = ["Call"]` to make the exclusion take effect.

**A precondition this needed that the prior attempt didn't touch: C/C++ callee-table matches
had never computed a `SiteContext` at all.** The shared call-dispatch path used by Go, Python,
JS/TS, C, C++ and Rust hardcoded `site_context: SiteContext::Call` unconditionally; `classify_
site_context` — the parent-chain walk that actually detects `TestAssertion`, `MapEntry`, etc. —
was wired in only for Java's method-invocation path and Go's string-literal path. Every C/C++
`when.site_context` filter, had one ever been written, would have been silently inert. Fixed by
walking from the callee's first real argument (mirroring the literal-node walk Go/Java's callers
already use) for `Language::C | Language::Cpp` specifically, falling back to the old hardcoded
`Call` when there is no argument to walk from — identical output to before for every existing
cpp.toml rule, none of which declares `when.site_context`. Two new fixture cases in `cpp/
crypto.c` and `scan_test.rs` (`scans_c_rsa_generate_key_legacy`, `expect_null_suppresses_but_
expect_not_null_does_not`) pin both the coverage and the discrimination: an `ExpectNull`-wrapped
call must not be reported, the `ExpectNotNull`-wrapped sibling one line below it must be.

**Corpus effect: zero.** Pre/post 150-project dump (`work/y33_pre.json` / `y33_post.json`,
149/150 scanned both runs — one project's working tree is empty independent of this change):
**1419 findings both runs, multiset-identical across every field** (project, rule, algorithm_id,
severity, file, line, message) — 0 added, 0 removed, 0 reclassified. `y33_pre.json` is itself
byte-identical to `work/y32_post.json`, the population the recorded 96.52% is anchored on, so
this is a genuine falsification of "this change reaches nothing corpus B scans," not an
assumption. Root cause, checked by hand: wolfssl's `scan_hints.exclude_paths` in `benchmarks/
corpus-b-realworld/ecosystems/crypto-adjacent/wolfssl.toml` excludes `tests/`, which is exactly
where every `RSA_generate_key` call site in that project lives (`tests/api/test_ossl_rsa.c`,
`test_evp_pkey.c`) — confirmed directly by scanning both excluded files with the built binary:
12 TP (`CRYPTO-404`/`406`; 8 in `test_ossl_rsa.c`, 4 in `test_evp_pkey.c`), 5 correctly-suppressed
`ExpectNull` sites (all in `test_ossl_rsa.c`), 0 false positives, exactly as designed. aws-lc's
one legacy call site (`tool-openssl/crl_test.cc`, not `_ex`) sits outside its
`scan_paths` (`crypto/`, `ssl/`, `include/openssl/`) entirely; the only two occurrences of the
identifier inside aws-lc's scanned paths are the function's own definition and declaration, not
calls. Same shape as `#W1`'s `--certs` gate and cycle 23's `CurvePreferences`: the corpus is not
the instrument for this rule family, and the fixture tree is.

**Precision: held at 96.52%, provably rather than assumed** — the finding-set identity above
means no TP/FP ratio could have moved. Not re-derived from labels because there is nothing to
re-derive: the audited population is unchanged.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--all-targets -- -D warnings` clean; `cargo test --workspace` all passing (110 `scan-source`
tests, was 108).

## `#Y34`: pycryptodome's `Crypto.Cipher.DES.new`/`DES3.new` gain coverage — 2026-08-29

**Closed this cycle: `#Y34`.** `python.toml` had classical-crypto coverage for `hashlib` and
`cryptography.hazmat`, but nothing keyed to pycryptodome's `Crypto.Cipher.DES`/`DES3` classes —
the Go equivalent (`crypto/des.NewCipher`/`NewTripleDESCipher`) was already covered, and a
Semgrep head-to-head run (`#Y36`) had already found this exact gap on an 8-site fixture.
`PYTHON_CALLEE_APIS` gains two rows, `("DES.new", "Crypto.Cipher.DES.new")` and `("DES3.new",
"Crypto.Cipher.DES3.new")`, mirroring the existing bare-identifier `RSA.generate` →
`Crypto.PublicKey.RSA.generate` row exactly — no new mechanism, no import-namespace check,
because the bare-identifier match already covers both `Crypto.Cipher` and the `Cryptodome.Cipher`
pycryptodomex alias (both bind the identical class name `DES`/`DES3`, so the same two rows fire
regardless of which package the import came from). `python.toml` gains `CRYPTO-809`/`810`,
mirroring `crypto/des.NewCipher`/`NewTripleDESCipher`'s severity band and message verbatim.

**Corpus effect: 41 findings added, 0 removed, 0 reclassified, all 41 in `pypi:pycryptodome`
(stratum A — confirmed absent from `c11_stratumB.json`'s 640 restored-stratum rows).** Full
150-project pre/post dump (`work/y33_post.json` 1419 → `work/y34_post.json`, script
`work/y34_precision.py`). All 41 hand-verified TP by opening the cited `file:line`:
`lib/Crypto/IO/PEM.py:80,157,160` (real DES-CBC/DES-EDE3-CBC PEM passphrase decrypt/encrypt),
and 38 sites across `SelfTest/Cipher/test_{DES,DES3,CBC,CFB,CTR,OFB,EAX,OpenPGP}.py` — the
library's own correctness tests, every `DES.new`/`DES3.new` call a real, successful cipher
construction followed by a real encrypt/decrypt round-trip. Two of those (`test_CBC.py:124,128`)
sit in a test whose *next* line wraps a different call (`cipher.encrypt`/`decrypt`, not
`DES3.new`) in `assertRaises` for a wrong-length argument — the construction itself is not the
assertion's target and always succeeds, the same "real regardless of what the surrounding test
later asserts" shape `#Y29`'s Rust arm already established for `openssl::Rsa::generate`. 0 FP.

**A harness bug surfaced by this measurement, worked around rather than left silent.**
`dump_findings_local.py`/`dump_findings_flags.py` compute `scan_paths = hints.get("scan_paths")
or [""]` — an explicitly empty `scan_paths = []` (today's fix marking `crates-io:rustls-pemfile`
`unscannable`, since it is the same clone as `crates-io:rustls`) is falsy in Python, so the `or`
silently falls back to scanning the whole clone anyway, reintroducing the exact 140-finding
double-count the manifest change was meant to retire. The raw post dump carries those 140 rows
(`CRYPTO-560`/`561`/`570`, `DEP-001`); `y34_precision.py` filters `crates-io:rustls-pemfile` out
by project name before diffing rather than trust the raw total, and neither adds nor removes any
of the 41 real findings. The fallback needs an explicit `is None` check in place of `or [""]`;
not fixed here since it is harness tooling in `work/`, not this repo.

**Precision: 96.52% → 96.78% (+0.264pp), `work/y34_precision.py`**, which reproduces the anchored
96.52% on the pre dump before computing anything else. All 41 new rows are folded into stratum
A's TP tally (`216→257` TP, FP unchanged at 9) rather than left as a population-only weight
shift — unlike a reclassification of an existing row, a brand-new row cannot collide with the
original 225-row sample, so folding fully-audited new rows into a stratum's own TP/FP count is
the same operation `#Y30`/`#W3` already used when their new rows landed in stratum B; the script
also prints the weight-shift-only reading (96.50%, i.e. flat) for comparison, so the folded
number is not the only one on record.

| | before | after (folded) | after (weight-shift only) |
|---|---|---|---|
| stratum A | 615 findings, TP=216 FP=9 | 656 findings, TP=257 FP=9 | 656 findings, TP=216 FP=9 |
| stratum B | 798 findings, TP=283 FP=9 (untouched) | 798, unchanged | 798, unchanged |
| **weighted** | **96.52%** (94.9–98.1) | **96.78%** (95.3–98.2) | 96.50% (94.9–98.1) |

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--all-targets -- -D warnings` clean; `cargo test --workspace` all passing (111 `scan-source`
tests, was 110 — `scans_python_pycryptodome_des` new, fixture
`tests/fixtures/python/pycryptodome_des.py`).

**Not re-taken, said out loud:** `regression_check.py` — none of its per-rule floors name
`CRYPTO-809`/`810`, and the change is a pure addition with no removed or reclassified row, so a
floor check would spend ~6 minutes re-deriving a value the row-identity diff above already pins.
The `--policy nsa-cnsa2` divergence still describes an earlier finding count; `scan-network` and
`scan-certs` are untouched.

## `#Y33`: liboqs stack-form C API gains coverage — 2026-08-29

**Closed this cycle: `#Y33`.** liboqs ships crypto in two API generations: the "stack" form
bakes the parameter set into the function name (`OQS_KEM_ml_kem_768_keypair`) and the "heap"
form takes it as a runtime `OQS_{KEM,SIG}_alg_*` macro argument to `OQS_KEM_new`/`OQS_SIG_new`.
Neither had a rule, so any liboqs caller using either generation produced zero findings.
`cpp.toml` gains sixteen `[[classify]]` entries (`CPP-060..063`, `CRYPTO-460..471`) covering
nine stack-form `C_CALLEE_APIS` rows per family (`ml_kem_{512,768,1024}` ×
keypair/encaps/decaps, `ml_dsa_{44,65,87}` × keypair/sign/verify) plus the two heap-form rows,
scoped to the six NIST-selected parameter sets per the standing rejection of the wider liboqs
algorithm zoo and of `OQS_SIG_STFL_*` (stateful hash signatures, a firmware-signing population
outside this project's scope).

**Corpus effect: zero.** Full 150-project re-dump (`work/y33_new_post.json`, 1460 findings,
149/150 projects scanned) against the last recorded state (`work/y34_post.json`'s 1460 findings
once the already-diagnosed `crates-io:rustls-pemfile` harness-bug duplicate is excluded, per
`#Y34`'s own note above), script `work/y33_precision.py`. Row-identity diff: **0 added, 0
removed** — none of the sixteen new rule ids fire anywhere in the corpus, checked directly
against the full post dump rather than inferred from the unchanged total. The reason is in the
manifest, not the scanner: `benchmarks/corpus-b-realworld/ecosystems/crypto-adjacent/liboqs.toml`
scopes the clone to `scan_hints.scan_paths = ["src/kem/", "src/sig/", "src/common/"]` and
explicitly excludes `tests/` — and every `OQS_KEM_new`/`OQS_SIG_new`/stack-form call site in the
liboqs clone lives under `tests/` (`tests/test_kem.c`, `tests/kat_sig.c`,
`tests/example_sig.c:106`'s literal `OQS_SIG_new(OQS_SIG_alg_ml_dsa_65)`, etc.) — `src/kem/` and
`src/sig/` hold the *implementations* the stack-form names identify, not calls to them. The three
other liboqs-family corpus entries (`oqs-provider`, `liboqs-rust`, `liboqs-python`) wrap the C
API through their own bindings and call neither the stack- nor heap-form C functions directly.
Same shape this project's own `crypto/tls.Config.CurvePreferences` measurement already
established: a real, correctly-scoped rule can measure zero on this corpus because the corpus's
scan-path restrictions and binding layers, not the rule, determine what is visible — report the
zero rather than read it as the rule not working. Not measurable on corpus B; the fixture tree
(`tests/fixtures/cpp/crypto.c`, exercised by the four new `scan_test.rs` cases) is this rule
family's instrument.

**Precision: 96.78% → 96.78% (flat), `work/y33_precision.py`**, which asserts both dumps total
1460 findings, asserts zero added/removed rows, and asserts zero hits on the sixteen new rule
ids before printing anything — a coverage-only addition with nothing to (re)audit, the same
shape cycle 23's `CurvePreferences` PQC arms took.

**Held:** `cargo build --release --workspace` clean; `cargo test --workspace` all passing (115
`scan-source` tests, was 111 — four new liboqs cases added against
`tests/fixtures/cpp/crypto.c`).

## `#Y39`: BouncyCastle lightweight-API PQC classes gain coverage — 2026-08-29

**Closed this cycle: `#Y39`.** `java.toml`'s only BouncyCastle `new Foo()` rule (`JAV-030`)
matched four classical classes (`RSAKeyPairGenerator`, `AESEngine`, `GCMBlockCipher`,
`BouncyCastleProvider`) and none of BC's nine PQC lightweight-API classes
(`MLKEMKeyPairGenerator`, `MLDSAKeyPairGenerator`, `SLHDSAKeyPairGenerator`, `MLKEMGenerator`,
`MLKEMExtractor`, `MLDSASigner`, `SLHDSASigner`, `HashMLDSASigner`, `HashSLHDSASigner`), so any
call to any of the nine produced zero findings. The alternation is a bare `type_identifier`
match with no package qualifier, so it reads unchanged across BC's 2026-04 relocation from
`org.bouncycastle.pqc.crypto.*` to `org.bouncycastle.crypto.*`. `JAV_CTOR_APIS` gains nine rows
and `java.toml` gains `CRYPTO-811..819`. None of the nine classes take a parameter set as a
constructor literal — it is supplied at runtime via a `KeyGenerationParameters`/key object
passed to `init()` or the constructor — so every arm degrades to the family sentinel
(`ml-kem-unattributed` / `ml-dsa-unattributed` / `slh-dsa-unattributed`), the same shape the
existing JCA `KeyPairGenerator`/`KEM` fallbacks use for a non-literal algorithm argument.
Fixture `tests/fixtures/java/BcLightweight.java` (nine PQC sites plus a classical control) goes
1/10 detected → 10/10; new test `scans_java_bouncycastle_lightweight_pqc_classes`.

**Corpus effect: 55 findings added, 0 removed, 0 reclassified, both in `c11_stratumB.json`'s
restored stratum** (`maven:org.bouncycastle:bcprov-jdk18on` 54, `maven:org.bouncycastle:
bcpkix-jdk18on` 1). Full 150-project pre/post dump (`work/y39_before.json` 1460 →
`work/y39_after.json` 1515, script `work/y39_precision.py`). All 55 hand-verified TP by opening
the cited `file:line` — every one a real `new <Class>()` site inside BC's own implementation:
`core/.../hpke/MLKEM.java`, `core/.../util/OtherInfoGenerator.java`, `core/.../pqc/crypto/xwing/
XWing{KeyPairGenerator,KEMGenerator,KEMExtractor}.java`, the four `prov/.../jcajce/provider/
asymmetric/{mlkem,mldsa,slhdsa}/*Spi.java` families, and `pkix/.../cert/plants/bc/
BcMTCSigners.java:55`. 0 FP, 0 DEPENDS. Population share is small enough (55 of 1515) that no
project outside the two BC libraries themselves calls these classes yet — expected, since BC's
own lightweight API is what a caller reaches for only after the JCA `Signature`/`KeyPairGenerator`
wrapper already tested above, and no corpus project has migrated that deep yet.

**Not fully closed, flagged for a later cycle:** several `SignatureSpi`/`HashSignatureSpi`
constructors pass a literal `SLHDSAParameters.sha2_128s`-style parameter set to their own
`super()` call alongside `new SLHDSASigner()` — the parameter set is visible one argument over
from the site this rule captures, but `SLHDSASigner()` itself takes no arguments, so attributing
it would mean reading a sibling argument in the *enclosing* call, not this one. Left as the
conservative `slh-dsa-unattributed`/`ml-dsa-unattributed` sentinel rather than guessed.

**Precision: 96.78% → 97.06% (+0.281pp), `work/y39_precision.py`**, which reproduces the
anchored 96.78% on the pre dump before computing anything else. All 55 new rows fold into
stratum B's TP tally (283→338 TP, FP unchanged at 9) — the same "brand-new row, not a
reclassification, so it cannot collide with the original sample" reasoning `#Y30`/`#Y34` already
used, this time landing in stratum B instead of stratum A because both BC projects are in the
46-project restored stratum. The script also prints the weight-shift-only reading (96.79%) for
comparison.

| | before | after (folded) | after (weight-shift only) |
|---|---|---|---|
| stratum A | 656 findings, TP=257 FP=9 (untouched) | 656, unchanged | 656, unchanged |
| stratum B | 798 findings, TP=283 FP=9 | 853 findings, TP=338 FP=9 | 853, unchanged |
| **weighted** | **96.78%** (95.3–98.2) | **97.06%** (95.7–98.4) | 96.79% (95.3–98.3) |

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--all-targets -- -D warnings` clean; `cargo test --workspace` all passing (116 `scan-source`
tests, was 115).

## `#Y43`: .NET 10+ first-party `MLKem`/`MLDsa`/`SlhDsa` PQC classes gain coverage — 2026-08-29

**Closed this cycle: `#Y43`'s `MLKem`/`MLDsa`/`SlhDsa` arms.** `csharp.toml`'s only asymmetric-keygen
template was `{cls}.Create`; the three native classes (`System.Security.Cryptography`, shipped in
`net10.0`+ and on the `Microsoft.Bcl.Cryptography` polyfill package for older TFMs, confirmed via
`learn.microsoft.com`'s `MLKem`/`MLDsa`/`SlhDsa`/`MLKemAlgorithm`/`MLDsaAlgorithm`/
`SlhDsaAlgorithm` class pages fetched 2026-08-29) use the static factory `GenerateKey(algorithm)`
and derive from `IDisposable` directly, not `AsymmetricAlgorithm` — a different axis the templated
rule structurally cannot match, so every call produced zero findings. `CSHARP_CALLEE_APIS`
(`crates/scan-source/src/scanner.rs`) gains three rows (`MLKem.GenerateKey`, `MLDsa.GenerateKey`,
`SlhDsa.GenerateKey`) and a `populate_args` arm reads the sole argument's member-access name
(`nth_csharp_arg_member_access_name`, arg index 0) into a `paramset` capture, the same
degrade-on-a-variable shape the existing BouncyCastle C# arms already use. `csharp.toml` gains
`CRYPTO-670..690`: 3 literal arms for `MLKemAlgorithm` (`ml-kem-512/768/1024`), 3 for
`MLDsaAlgorithm` (`ml-dsa-44/65/87`), 12 for `SlhDsaAlgorithm` (all twelve FIPS 205 parameter
sets, property names read verbatim off the class page — `SlhDsaSha2_128s`, `SlhDsaShake128f`,
etc.), and one family-sentinel fallback per class (`ml-kem-unattributed` / `ml-dsa-unattributed` /
`slh-dsa-unattributed`) for a non-literal argument. Fixture
`tests/fixtures/csharp/PqcNative.cs` (RSA control, one literal site per class, one unattributed
variable site) goes 1/5 detected → 5/5; new test `scans_csharp_native_mlkem_mldsa_slhdsa`.

**`CompositeMLDsa` deferred, not shipped this cycle.** Its 17 named combinations
(`MLDsa44WithECDsaP256`, `MLDsa65WithRSA3072Pss`, …) have no corresponding row in
`algorithm-table.toml` — every existing PQC classify arm in this codebase resolves to an id that
table already defines, and inventing 17 new composite ids (or one compound sentinel) is exactly
the class of larger, riskier change `#Y39` deferred its own `pqc.legacy` remainder for. Left as a
distinct future item rather than rushed into this diff.

**Corpus effect: 0 findings added, 0 removed, 0 reclassified — a falsification, not a
re-derivation.** Full 150-project pre/post dump (`work/y43_before.json` ↔ `work/y43_after.json`,
both 1655 findings, byte-identical row sets on `(project, rule_id, file, line, algorithm_id,
severity)`; script `work/y43_precision.py`). Neither dump matches the 1515 total the `#Y39` entry
above recorded — both the pre-change binary (built from commit `33c8111` in a worktree) and the
post-change binary read the same +140 environment drift already named as `OPEN-ASK #CORPUSDRIFT`
(status: `ANSWERED — DEFERRED`, `03-Product/Backlog.md`), so it cancels out of the diff and is not
this cycle's to resolve (rule 7). No project in corpus B
calls any of the three classes — expected, since they are brand-new .NET 10 preview APIs with, per
the ecosystem lens's own note, no measured corpus demand yet on either side of this change.

**Precision: 97.06% held, exactly, `work/y43_precision.py`.** The script reproduces the anchored
97.06% on the pre dump before asserting the diff is empty; an empty diff cannot move a TP/FP ratio
in either estimator, so this is a coverage-added-at-precision-held result verified against the
fixture rather than the corpus.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--all-targets -- -D warnings` clean; `cargo test --workspace` all passing (117 `scan-source`
integration tests, was 116, +1 new C# fixture test — csharp.toml's own two prior PQC tests both
still pass unchanged).

## `#Y44`: liboqs heap-form SIG API gains an SLH-DSA classify arm — 2026-08-29

**Closed this cycle: `#Y44`.** `cpp.toml`'s `OQS_SIG_new` rule (the heap-form liboqs SIG API,
algorithm passed at runtime as an `OQS_SIG_alg_*` macro identifier) had three classify arms for
ML-DSA and none for SLH-DSA, though the extract query already captures both families identically
— confirmed via `grep -n "slh_dsa\|sphincs" crates/core/data/rules/cpp.toml` returning nothing
before this change. SLH-DSA has no dedicated stack-form header upstream — `open-quantum-safe/
liboqs`'s `src/` tree has `sig_ml_dsa/` but no `sig_slh_dsa/`, confirmed by directory listing
against the corpus's own liboqs clone (`work/corpus-clones/crypto-adjacent/liboqs`) — so
`OQS_SIG_new` is SLH-DSA's only call shape in this library, making this the cheapest of the three
liboqs gaps this vault has tracked (`#Y33`, closed prior cycle, needed a whole stack-form rule;
this needed only new arms on an existing one).

`cpp.toml` gains twelve classify arms, `CRYPTO-472..483`, one per `OQS_SIG_alg_slh_dsa_pure_*`
macro (`sha2`/`shake` × `128`/`192`/`256` × `s`/`f`), matching the twelve rows `algorithm-table.toml`
already carries (`slh-dsa-sha2-128s` … `slh-dsa-shake-256f`) — read directly from the corpus's
own `liboqs/src/sig/sig.h`, not guessed. Liboqs also defines a much larger family of
`OQS_SIG_alg_slh_dsa_*_prehash_*` (HashSLH-DSA) macros with no corresponding row in
`algorithm-table.toml`; inventing one is out of this cycle's scope and is left as a future item,
stated rather than silently dropped. Fixture `tests/fixtures/cpp/crypto.c` gains one heap-form SIG
site (`OQS_SIG_new(OQS_SIG_alg_slh_dsa_pure_sha2_128s)`); the four-site liboqs heap-form probe
(RSA control + KEM heap + this SIG heap site, per the existing fixture's population) goes 1/4 →
4/4 detected; new test `scans_c_liboqs_heap_form_sig_slh_dsa`, and the existing
`liboqs_stfl_new_is_out_of_scope` count assertion updated 6 → 7 liboqs findings to include it.

**Corpus effect: 0 findings added, 0 removed, 0 reclassified — a falsification, not a
re-derivation.** Full 150-project pre/post dump (`work/y44_before.json` ↔ `work/y44_after.json`,
both 1515 findings from 149/150 scanned projects, byte-identical row sets on `(project, rule_id,
file, line, algorithm_id, severity)`; script `work/y44_precision.py`; pre-change binary built from
commit `75e5f01` in a throwaway worktree). Corpus B's own liboqs clone reports 0 findings on both
dumps — its `OQS_SIG_new` call sites sit outside `scan_hints.scan_paths` (liboqs's own `tests/`
tree), the same shape `#Y29`'s C/C++ re-ship documented for `RSA_generate_key` — so no corpus
project exercises either the old or the new arms.

**Precision 97.06% held, exactly, `work/y44_precision.py`.** The script reproduces the anchored
97.06% on the pre dump before asserting the diff is empty; an empty diff cannot move a TP/FP ratio
in either estimator, so this is coverage added at precision held, verified against the fixture
rather than the corpus.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--all-targets -- -D warnings` clean; `cargo test --workspace` all passing (118 `scan-source`
integration tests, was 117).

## `#Y47`: pyca/cryptography's own first-party ML-KEM/ML-DSA classes gain coverage — 2026-08-29

**Closed this cycle: `#Y47`.** `python.toml` recognized every classical primitive pyca/cryptography
exposes (RSA, EC, Ed25519/Ed448/X25519/X448, AES, hashlib) but had no classify arm at all for the
library's own first-party FIPS 203/204 classes — confirmed via `grep -n "mlkem\|mldsa"
crates/core/data/rules/python.toml` returning zero classify-arm hits before this change (one
unrelated message-text hit on the classical `x25519` arm recommending the hybrid). A maintainer
scanning their own fork of `cryptography` — the one library in this corpus that has fully migrated
three algorithms to post-quantum — got zero PQC findings and 216 classical/other ones.

`python.toml` gains six classify arms, `CRYPTO-820..825`, one per parameter set (`ml-kem-512/768/
1024`, `ml-dsa-44/65/87`). `scanner.rs`'s `PYTHON_CALLEE_APIS` table gains 36 entries mapping the
literal class-name call form — `MLKEM768PrivateKey.generate()`, `.from_seed_bytes()`,
`MLKEM768PublicKey.from_public_bytes()`, and the ML-DSA equivalents, both bare-imported and
module-qualified spellings — straight to a per-parameter-set api string; the parameter set is
stated in the class name itself, same shape the existing ed25519/x25519 arms already use, so no arg
capture is needed. **Deliberately scoped to that literal-class-name form only.** The instance-method
form reached through a variable (`key.encapsulate()`, `sig_key.sign()`) is not resolvable to a class
without receiver type-tracking this codebase does not do anywhere for Python — confirmed by counting
the corpus's own test suite: of pyca's 58 real ML-KEM/ML-DSA call sites across `tests/hazmat/
primitives/test_mlkem.py`, `tests/wycheproof/test_mlkem.py`, `test_mldsa.py`, and `tests/wycheproof/
test_mldsa.py`, 40 use the literal-class-name form this change detects and 18 use the
variable-receiver form it deliberately leaves alone rather than risk a false match on an unrelated
library's `.sign()`/`.encapsulate()` method.

New fixture `tests/fixtures/python/pqc_native.py` plants six literal-class-name sites (both ML-KEM
and ML-DSA, `.generate()` and `.from_seed_bytes()`/`.from_public_bytes()`) plus two
variable-receiver sites (`key.encapsulate()`, `sig_key.sign()`) that must NOT be classified; new
test `scans_python_pqc_native_mlkem_mldsa` asserts both halves — 0/6 → 6/6 on the detectable sites,
and exactly 6 total `ml-kem-*`/`ml-dsa-*` findings (not 8), proving the two variable-receiver sites
stayed unclassified rather than silently matching.

**Corpus effect: 0 findings added, 0 removed, 0 reclassified — a falsification, not a
re-derivation.** Full 150-project pre/post dump (`work/y47_before.json` ↔ `work/y47_after.json`,
both 1655 findings; script `work/y47_precision.py`; pre-change binary built from commit `a583392`
in a throwaway worktree). `pypi:cryptography` itself reports 3 findings on both dumps, unchanged —
its own `scan_hints.scan_paths` (`benchmarks/corpus-b-realworld/ecosystems/pypi/cryptography.toml`)
scopes the scan to `src/cryptography/` and explicitly excludes `tests/`, so none of the 58 real call
sites — literal-class-name or otherwise — are visible to corpus B at all. Same shape `#Y29` and
`#Y44` already documented for wolfssl, aws-lc, and liboqs: the fix is real, the corpus just cannot
see the call sites it fixes.

**Precision 97.06% held, exactly, `work/y47_precision.py`.** The script reproduces the anchored
97.06% on the pre dump before asserting the diff is empty; an empty diff cannot move a TP/FP ratio
in either estimator, so this is coverage added at precision held, verified against the fixture
rather than the corpus.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--all-targets -- -D warnings` clean; `cargo test --workspace` all passing (119 `scan-source`
integration tests, was 118).

## `#Y21` second item: BouncyCastle C# operation-site PQC classes gain coverage — 2026-08-29

**Closed this cycle: `#Y21`'s second, larger item**, standing open since cycle 24 (first item —
BC's keygen classes — closed then). `csharp.toml` had rules for `MLKemKeyGenerationParameters`/
`MLDsaKeyGenerationParameters` (a key being *generated*) but none for the classes that perform the
KEM/signature *operation* — `MLKemEncapsulator`, `MLKemDecapsulator`, `MLDsaSigner` — confirmed via
`grep -n "MLKemEncapsulator\|MLKemDecapsulator\|MLDsaSigner" crates/core/data/rules/csharp.toml`
returning nothing before this change.

**Ship-gated on the same verification step `#Y21`'s first item required, not skipped here.** The
exact class names and constructor shapes were read directly from `bcgit/bc-csharp`'s
`crypto/src/crypto/{kems,signers}/` tree via `gh api`, not assumed from the keygen classes' shape:
`MLKemEncapsulator(MLKemParameters parameters)`, `MLKemDecapsulator(MLKemParameters parameters)`,
and `MLDsaSigner(MLDsaParameters parameters, bool deterministic)` each take the same
`MLKemParameters`/`MLDsaParameters` static field directly as a constructor argument the keygen
classes already resolve — `new MLKemEncapsulator(MLKemParameters.ml_kem_768)`, `new
MLDsaSigner(MLDsaParameters.ml_dsa_65, false)`. `MLDsaSigner`'s constructor itself rejects any
HashML-DSA (`_with_sha512`) parameter set (throws if `PreHashOid != null`), confirmed by reading
its doc comment, so unlike the keygen arm no such suffix needs an arm here.

`csharp.toml` gains three new `[[extract]]`/`[[classify]]` blocks, twelve classify arms total
(`CRYPTO-826..837`, one triad of parameter-set arms plus one unattributed-fallback arm per class),
mirroring the existing keygen arm's shape exactly — same member-access capture, same
literal-vs-variable degrade-to-sentinel behaviour. `scanner.rs`'s `CSHARP_CTOR_APIS` table gains
three entries and `populate_args` gains one new match arm capturing the sole constructor argument
(index 0, not index 1 as the keygen classes use — their `random` parameter comes first, these
classes have no such argument) — reusing the existing `nth_csharp_arg_member_access_name` helper,
no new extraction mechanism.

`tests/fixtures/csharp/Pqc.cs` gains three operation-site call sites (one per class); new assertions
in the existing `scans_csharp_bouncycastle_mlkem_and_mldsa` test take it from 4/4 to 7/7 detected on
the fixture.

**Corpus effect: 0 findings added, 0 removed, 0 reclassified — a falsification, not a
re-derivation.** Full 150-project pre/post dump (`work/y21_before.json` ↔ `work/y21_after.json`,
both 1655 findings; script `work/y21_precision.py`; pre-change binary built from commit `adb0c5e` in
a throwaway worktree). Corpus B has no C#/NuGet ecosystem at all — confirmed directly, its six
ecosystem directories are `crates-io`, `crypto-adjacent`, `go-modules`, `maven`, `npm`, `pypi` — and
the 27 stray `.cs` files scattered through its mixed-language repos reference neither BouncyCastle
nor any of the three new class names, checked via `grep` before this run rather than assumed. Same
shape `#Y29`, `#Y44`, and `#Y47` already documented: the fix is real, the corpus has nothing that
exercises it either way.

**Precision 97.06% held, exactly, `work/y21_precision.py`.** The script reproduces the anchored
97.06% on the pre dump before asserting the diff is empty; an empty diff cannot move a TP/FP ratio
in either estimator, so this is coverage added at precision held, verified against the fixture
rather than the corpus.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--all-targets -- -D warnings` clean; `cargo test --workspace` all passing (119 `scan-source`
integration tests, unchanged count — new assertions were added to an existing test rather than a
new `#[test]` fn).

## `#Y24` part (b): Java `System.setProperty("jdk.tls.namedGroups", ...)` gains coverage — 2026-08-29

**Closed this cycle: `#Y24`'s second, smaller-looking-but-genuinely-new-mechanism item**, open
since cycle 26 (part (a) — the `SSLParameters.setNamedGroups(String[])` instance-method form —
closed then). Part (b) is the same TLS group-list hardening setting reached through a JVM-wide
system property instead: `System.setProperty("jdk.tls.namedGroups",
"secp256r1,ffdhe2048,X25519MLKEM768")`. The value is a single comma-delimited string literal, not
one AST node per group, and no existing extract mechanism in any of the seven rule packs splits a
string literal's contents — confirmed before writing anything by reading `scanner.rs`'s own header
comment, which states plainly that `[[extract]]` TOML blocks are documentation only and every real
match is a hand-written Rust structural matcher.

**First change:** a new structural matcher, `match_java_set_property_named_groups` (`scanner.rs`),
hooked into `walk()` alongside `match_java_set_named_groups` on the same `method_invocation` node
kind. It requires the receiver text to be exactly `System` (not just any `setProperty` — that
method name alone is generic enough, `Properties.setProperty` exists, that keying on it alone the
way part (a) keys on `setNamedGroups` alone would be a real false-positive risk) and exactly two
`string_literal` arguments, the first equal to `"jdk.tls.namedGroups"`. The second literal's value
is split on `,`, each token trimmed and skipped if empty, and one `RawMatch` is emitted per token —
reusing part (a)'s exact `api`/`args.group` shape unchanged, so `CRYPTO-798`..`808` fire on either
call shape with zero classify-arm changes. No dedup of repeated group names, matching part (a)'s
own array-form behaviour (a name repeated across two calls counts twice there too).

`tests/fixtures/java/TlsGroups.java` gains two new methods: `viaSystemProperty` (three groups,
including one with stray whitespace around a comma — a real Java style the array-literal form
never had to handle) and `unrelatedSystemProperty` (an unrelated property key, a control asserting
the matcher does not fire on every `System.setProperty` call). The existing
`scans_java_ssl_parameters_set_named_groups` test's expected count moves from 11 to 14.

**Corpus effect: 0 findings added, 0 removed, 0 reclassified — a falsification, not a
re-derivation, and not for lack of a real corpus site.** Corpus B *does* contain two literal
`System.setProperty("jdk.tls.namedGroups", ...)` call sites —
`conscrypt-openjdk-uber/common/src/test/java/org/conscrypt/javax/net/ssl/SSLSocketTest.java:994`
(`"X25519MLKEM768,X25519"`) and `:1256` (`"invalid,invalid2"`), found via `grep -rl
"jdk.tls.namedGroups" work/corpus-clones` before writing the matcher — but both sit in
`common/src/test/java/`, outside `conscrypt-openjdk-uber.toml`'s own `scan_hints.scan_paths`
(`openjdk/src/main/java/`, `common/src/main/java/`; `openjdk/src/test/` is separately excluded).
Full 150-project pre/post dump (`work/y24b_before.json` ↔ `work/y24b_after.json`, both 1515
findings from 149/150 projects; script `work/y24b_precision.py`; pre-change binary built from
commit `b5931ed` in a throwaway worktree) confirms a byte-identical row set. Same shape `#Y29`,
`#Y44`, `#Y47`, and `#Y21`'s second item already documented: the fix is real, the corpus has a
real site, but scope excludes it.

**Precision 97.06% held, exactly, `work/y24b_precision.py`.** The script reproduces the anchored
97.06% on the pre dump before asserting the diff is empty; an empty diff cannot move a TP/FP ratio
in either estimator, so this is coverage added at precision held, verified against the fixture
(11/11 → 14/14 on the extended `TlsGroups.java` probe) rather than the corpus.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--all-targets -- -D warnings` clean; `cargo test --workspace` all passing (119 `scan-source`
integration tests, unchanged count — new assertions were added to an existing test rather than a
new `#[test]` fn).

## `#X9` part (a): LMS row's `undetectable` reason misinvoked P2 — 2026-08-30

**Fixed a wrong justification, not a detection gap.** The `lms` row in `algorithm-table.toml`
explained its lack of coverage as "we ship no source for the X.509 SPKI codepoints and P2 forbids
fetching one" — but P2 governs the scanner binary's *runtime* network access, not what a developer
vendors into the repository, where `knowledge/sources/` already carries FIPS 203/204/205 texts,
NIST drafts, IANA registries, and CycloneDX schemas offline. The real reason LMS has no OID rule is
simply that nobody has vendored the SPKI OID into `oid-table.toml` yet. Reworded to say exactly
that. `hss`/`xmss`/`xmss-mt` need no edit of their own — their rows already read "As lms — no
vendored OID," pointing at the corrected text rather than repeating the wrong one.

`undetectable` is a pure documentation field (`quipuu_core::algorithm::AlgorithmRow`,
`Option<String>`) read only by `crates/cli/tests/algorithm_reachability.rs` to check
presence/absence — never matched, parsed, or compared for content by any scanner, classifier, or
emitter. A prose change to it cannot move a finding by construction.

**Corpus effect: 0 findings added, 0 removed, 0 reclassified, as a change to this field must
produce.** Full 150-project pre/post dump (`work/x9a_before.json` ↔ `work/x9a_after.json`, both
1515 findings from 149/150 projects; script `work/x9a_precision.py`; pre-change binary built from
commit `4c92716` in a throwaway worktree) confirms a byte-identical row set.

**Precision 97.06% held, exactly, `work/x9a_precision.py`.** The script reproduces the anchored
97.06% on the pre dump before asserting the diff is empty; a doc-only field cannot move a TP/FP
ratio in either direction, so this is a correctness fix to project documentation, verified against
the corpus rather than derived from it.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--all-targets -- -D warnings` clean; `cargo test --workspace` all passing, unchanged counts.

## `#Y52`: OpenSSL 3.0+'s generic keygen API (`EVP_PKEY_CTX_new_from_name` / `EVP_PKEY_Q_keygen`) — 2026-08-30

**Closed a zero-coverage gap in `cpp.toml`'s own stated scope.** The file's header comment has
claimed `EVP_PKEY_keygen` coverage since it was written; no rule for it, or for either of OpenSSL
3.0's documented generic-keygen entry points, ever existed (`grep -n
"EVP_PKEY_CTX_new_from_name\|EVP_PKEY_Q_keygen" crates/core/data/rules/cpp.toml` — zero hits before
this change). These two functions are OpenSSL's own replacement for the deprecated typed keygen
functions `cpp.toml` already covers (`RSA_generate_key_ex`, `RSA_generate_key`); the algorithm is a
runtime string-literal argument rather than baked into the function name, the same shape as
liboqs's heap-form `OQS_KEM_new`/`OQS_SIG_new` pair already in the file.

**First change:** two rows in `scanner.rs`'s `C_CALLEE_APIS` table (there is no query engine — the
`[[extract]]` TOML blocks are documentation, per the file's own comment and `rules.rs`'s
`every_classify_rule_targets_an_api_the_extractor_can_emit` gate — the callee table is what
`api_surface()` actually reflects), a match arm each capturing the algorithm-name string at its
respective argument position (`EVP_PKEY_CTX_new_from_name(libctx, name, propq)`: arg 1;
`EVP_PKEY_Q_keygen(libctx, propq, type, ...)`: arg 2, via the existing `nth_arg_string` helper), and
21 classify arms (`CRYPTO-484`..`504`) sharing one `when.api` regex over both functions: RSA, EC
(→ `ecdsa-unattributed`, same reasoning as `CRYPTO-211` in `java.toml` for
`KeyPairGenerator.getInstance("EC")` — the curve is set separately and Shor breaks every curve, so
the migration verdict is exact even though the classical strength is not), DH, the three ML-KEM and
three ML-DSA parameter sets, and the twelve "pure" SLH-DSA parameter sets liboqs's own heap-form
rules already cover. `cpp.toml`'s header comment is corrected in the same diff to name the two real
functions instead of the never-covered one.

**Corpus effect: 5 findings added, 0 removed, 0 reclassified.** Full 150-project pre/post dump
(`work/y52_pre.json` ↔ `work/y52_post.json`, 1655 → 1660 findings; script `work/y52_precision.py`;
pre-change binary built from commit `0427cf1` in a throwaway worktree). All 5 additions are on
`openssl/openssl` itself and were hand-labelled by opening the cited line: three
`EVP_PKEY_CTX_new_from_name(libctx, "EC", propq)` sites (`crypto/hpke/hpke.c:110` and `:1333`,
feeding `EVP_PKEY_paramgen`/`EVP_PKEY_keygen_init` in HPKE's NIST-curve KEM path;
`crypto/cms/cms_ec.c:49`, decoding a CMS recipient's EC domain parameters) and two
`EVP_PKEY_CTX_new_from_name(..., "DH", ...)` sites (`ssl/t1_lib.c:4506` and
`ssl/statem/statem_clnt.c:2820`, building the server's and client's classic-DHE key object for a
TLS `ServerKeyExchange`) — **5 TP, 0 FP, 0 DEPENDS**, none inside a test, a disabled branch, or a
comment. Verified additionally against a planted fixture covering both call shapes and both
classical and PQC names (`tests/fixtures/cpp/crypto.c`, `cargo test
scans_c_openssl_generic_keygen`, 0/4 → 4/4 detected).

**Precision: 97.06% → 97.09% (95% CI 95.4–98.1), `work/y52_precision.py`.** The script reproduces
the anchored 97.06% on the pre dump before printing anything else, then appends the 5 hand-labelled
TPs to the same 613-row audited pool the anchor rests on: 600/618 = 97.09%. Read as precision held
with coverage added, not as an improvement — the movement is the arithmetic effect of appending 5
fully-audited findings to a sample the rest of which is not re-drawn, the 5 are sampled at 100%
against roughly 20% elsewhere (biasing the number upward, same caveat every prior coverage-add cycle
in this series has carried), and the new figure sits well inside the prior interval.

**Not done, said out loud:** ED25519/ED448/X25519/X448 and DSA are real OpenSSL 3.0+ generic-keygen
algorithm names this change does not add a classify arm for — out of this item's stated scope
(RSA/EC/DH plus the ML-KEM/ML-DSA/SLH-DSA families already named by the backlog entry that filed
this), not a gap discovered and skipped.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--all-targets -- -D warnings` clean; `cargo test --workspace` all passing (one new fixture test,
`scans_c_openssl_generic_keygen`).

## `#Y51`: C# `MLKem.Import*` key-loading paths gain coverage — 2026-08-30

**Closed a coverage gap the `.NET 10+` PQC block had since it shipped (`#Y43`).** `csharp.toml`'s
`MLKem`/`MLDsa`/`SlhDsa` rules only recognized `GenerateKey` — a codebase that *loads* a
provisioned FIPS 203 key (from a vault, a certificate store, or a wire payload) rather than
generating one at runtime produced zero findings, regardless of how the key was used afterward.
Method names sourced from backlog `#Y51`'s own filing, itself derived from CBOMkit's
`DotNetMLKem.java` (PR #520, merged 2026-08-26) and cross-checked against `learn.microsoft.com`'s
`MLKem` class page: `ImportEncapsulationKey`, `ImportDecapsulationKey`, and `ImportPrivateSeed`
take the same `MLKemAlgorithm` first argument `GenerateKey` does; `ImportPkcs8PrivateKey`,
`ImportSubjectPublicKeyInfo`, and `ImportFromPem` carry no algorithm argument at all — the
parameter set is encoded inside the key material, not the call site. Scope is `MLKem` only, not
`MLDsa`/`SlhDsa` — those classes' own import-method names were not independently verified this
cycle, and guessing at API surface this repo cannot check (`P2` forbids fetching
`learn.microsoft.com` at scan time, and `P1` forbids inferring it) would risk shipping a rule for a
method that does not exist. Filed as follow-up, not silently dropped.

**First change:** six new rows in `scanner.rs`'s `CSHARP_CALLEE_APIS` table (there is no query
engine — the `[[extract]]` TOML blocks are documentation, per `rules.rs`'s
`every_classify_rule_targets_an_api_the_extractor_can_emit` gate — the callee table is what
`api_surface()` actually reflects) and one `populate_args` match arm extended to also cover
`ImportEncapsulationKey`/`ImportDecapsulationKey`/`ImportPrivateSeed`, reusing `GenerateKey`'s
existing arg-0 paramset capture unchanged. 15 new classify arms (`CRYPTO-838`..`852`) in
`csharp.toml`: three parameter sets × three algorithm-parameterized methods, each with an
`ml-kem-unattributed` fallback for a non-literal parameter set (four arms), plus one
`ml-kem-unattributed` arm each for the three no-algorithm-argument import methods.

**Corpus effect: 0 findings added, 0 removed, 0 reclassified.** Full 150-project pre/post dump
(`work/y51_pre.json` ↔ `work/y51_post.json`, both 1660 findings, row-identical; script
`work/y51_precision.py`; pre-change binary built from commit `a761fda` in a throwaway worktree).
Expected, not a surprise: `MLKem.Import*` is brand-new `.NET 10` preview surface with (per the
backlog filing's own honest framing) no known corpus-B consumer yet — same shape `#Y43`/`#Y44`
already documented for other zero-corpus-demand coverage additions in this series. Verified
instead against a planted fixture covering all six methods and all three parameter positions
(`tests/fixtures/csharp/PqcNative.cs`, `cargo test scans_csharp_mlkem_import_paths`, 0/6 → 6/6
detected).

**Precision: 97.09% held, exactly — a falsification, not a re-derivation.** `work/y51_precision.py`
reproduces the anchored 97.09% (600 TP / 18 FP pooled) on the pre dump before printing anything
else, then asserts the two dumps are row-identical. They are.

**Not done, said out loud:** the `MLKemCng`/`MLKemOpenSsl` platform-derived subclasses backlog
`#Y51` also named, and `MLDsa`/`SlhDsa`'s own import-method equivalents, are real gaps this change
does not close — out of this item's verified scope, not discovered and skipped.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--all-targets -- -D warnings` clean; `cargo test --workspace` all passing (one new fixture test,
`scans_csharp_mlkem_import_paths`).

## `#Y55`: C# `MLDsa`/`SlhDsa` `Import*` key-loading paths gain coverage — 2026-08-30

**Closes the exact remainder `#Y51` named and left open.** `#Y51` shipped `MLKem.Import*` coverage
but scoped `MLDsa`/`SlhDsa` out because their import-method names were unverified at the time; two
independent backlog lenses then closed that verification gap by two different routes that agree —
one fetching `learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.{mldsa,slhdsa}`
directly, the other reading CBOMkit's own `DotNetMLDsa.java`/`DotNetSlhDsa.java` in full. Both
confirm: `MLDsa`'s algorithm-parameterized import methods are `ImportMLDsaPrivateKey`,
`ImportMLDsaPrivateSeed`, and `ImportMLDsaPublicKey` (same `MLDsaAlgorithm` first-argument shape as
`GenerateKey`); `SlhDsa`'s are `ImportSlhDsaPrivateKey` and `ImportSlhDsaPublicKey` — deliberately
no `ImportSlhDsaPrivateSeed`, since FIPS 205 keys have no seed-expansion form, a real API asymmetry
rather than an oversight. Both classes also carry the same no-algorithm-argument structural imports
(`ImportPkcs8PrivateKey`/`ImportSubjectPublicKeyInfo`/`ImportFromPem`) `MLKem` already has, each
always degrading to the family's `-unattributed` sentinel since the parameter set lives inside the
encoded key material, not the call site. The citation `#Y51` gave for leaving this open (`P2`) was
itself a misnomer: `P2` governs the *shipped scanner binary's* runtime network behavior, not
whether the people building a rule pack may consult public API documentation.

**First change:** 11 new rows in `scanner.rs`'s `CSHARP_CALLEE_APIS` table (6 `MLDsa`, 5 `SlhDsa`;
there is no query engine — the `[[extract]]` TOML blocks are documentation, per `rules.rs`'s
`every_classify_rule_targets_an_api_the_extractor_can_emit` gate) and the same `populate_args`
match arm `#Y51` extended, now also covering `MLDsa.ImportMLDsaPrivateKey`/`ImportMLDsaPrivateSeed`/
`ImportMLDsaPublicKey` and `SlhDsa.ImportSlhDsaPrivateKey`/`ImportSlhDsaPublicKey` with the same
arg-0 paramset capture, unchanged. 44 new classify arms (`CRYPTO-853`..`896`) in `csharp.toml`:
three `MLDsa` parameter sets × three algorithm-parameterized methods (12 arms + 3 unattributed
fallbacks) plus three no-argument `MLDsa` imports (3 arms); twelve `SlhDsa` parameter sets × two
algorithm-parameterized methods (24 arms + 2 unattributed fallbacks) plus three no-argument
`SlhDsa` imports (3 arms).

**Scope held to the same non-encrypted subset `#Y51` covered for `MLKem`.**
`ImportEncryptedPkcs8PrivateKey`/`ImportFromEncryptedPem` are real `MLDsa`/`SlhDsa` entry points
this item does not add — named rather than silently skipped, matching the scope the backlog filing
itself specified.

**Corpus effect: 0 findings added, 0 removed, 0 reclassified.** Full 150-project pre/post dump
(`work/y55_pre.json` ↔ `work/y55_post.json`, both 1660 findings, row-identical; script
`work/y55_precision.py`; pre-change binary built from commit `9bb9e03` in a throwaway worktree).
Expected, not a surprise, and the same shape `#Y51`/`#Y43`/`#Y44` already documented: no known
corpus-B consumer of this `.NET 10` preview surface yet. Verified instead against a planted
fixture covering all 11 methods (`tests/fixtures/csharp/PqcNative.cs`, `cargo test
scans_csharp_mldsa_slhdsa_import_paths`, 0/11 → 11/11 detected).

**Precision: 97.09% held, exactly — a falsification, not a re-derivation.** `work/y55_precision.py`
reproduces the anchored 97.09% (600 TP / 18 FP pooled) on the pre dump before printing anything
else, then asserts the two dumps are row-identical. They are.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--all-targets -- -D warnings` clean; `cargo test --workspace` all passing (one new fixture test,
`scans_csharp_mldsa_slhdsa_import_paths`). The two trust-invariant tests
(`test_network_disabled_error`, `test_run_acvp_kats_rejects_code_execution`) are untouched and
pass.

## `#Y56`: liboqs `OQS_KEM_new`/`OQS_SIG_new` gain a `kem-unattributed`/`sig-unattributed` fallback

`cpp.toml:501-547`'s two `[[extract]]` rules capture *any* identifier argument to
`OQS_KEM_new`/`OQS_SIG_new` — tree-sitter sees the `OQS_{KEM,SIG}_alg_*` macro name as a bare
identifier, not the string it expands to. Every `[[classify]]` arm on those two APIs was a closed
regex naming one of the fifteen ML-KEM/ML-DSA/SLH-DSA parameter sets, with no catch-all arm of the
kind `csharp.toml` and `java.toml` already carry for this exact situation. So HQC — NIST's own
selected backup KEM, default-on in production liboqs since 0.16.0 (2026-07-09) — and every other
liboqs candidate family (MAYO, BIKE, Classic McEliece, FrodoKEM, NTRUPrime, ...) produced **zero**
findings, not a degraded one, despite the extractor already seeing the call site. Measured directly
before touching anything: 5 keygen calls (3 `OQS_KEM_alg_hqc_{128,192,256}`, 1
`OQS_SIG_alg_mayo_1`, 1 `OQS_KEM_alg_ml_kem_768` control) scored 1 finding, the control.

**First change:** two new `[[classify]]` arms (`CRYPTO-897` on `OQS_KEM_new`, `CRYPTO-898` on
`OQS_SIG_new`), each ordered last after the enumerated arms with an unconstrained `when.args.alg`
regex, degrading any unmatched macro *or variable* to a new `kem-unattributed`/`sig-unattributed`
sentinel pair — the raw captured value named in the message so the finding stays actionable
without a resolved FIPS number. Two new `algorithm-table.toml` rows carry `quantum_status =
"PqcDraft"` (none of these candidate families has a NIST FIPS number the way ML-KEM/ML-DSA/SLH-DSA
do) and `family = "PQC-candidate"`, which needed one addition to `cbom/src/emit.rs`'s
`canonicalize_family`: the CycloneDX 1.7 `algorithmFamiliesEnum` has no member for "a real
post-quantum call site whose specific family is unattributed", so it is omitted from the CBOM the
same way `webcrypto-unattributed`/`jca-unattributed`/`signature-unattributed` already are — caught
by `emit_test.rs`'s schema-validation suite before this reached corpus B.

**Not reopening the liboqs algorithm zoo rejection:** no per-candidate rule for HQC/MAYO/BIKE/
Classic McEliece/etc. — exactly the family-level fallback that rejection's own text already named
("two family-level rules... never one arm per candidate") but had not actually built until now.

**Corpus effect: 5 findings added, 0 removed, 0 reclassified — a real recall gain, not the expected
zero.** Full 150-project pre/post dump (`work/y56_pre.json` ↔ `work/y56_post.json`, 1660 → 1665
findings; pre-change binary built from commit `a819fef` in a throwaway worktree). All 5 land inside
`open-quantum-safe/liboqs`'s own reference implementation (`src/sig/sig.c:3148`,
`OQS_SIG_supports_ctx_str`) and its `oqs-provider` OpenSSL provider (`oqsprov/oqsprov_keys.c:1089,
1111, 1129, 1162`) — every one of the five calls `OQS_KEM_new`/`OQS_SIG_new` with a runtime
algorithm-name variable (`alg_name`, `oqs_name`) rather than a literal macro, a shape the closed
enum could never have matched regardless of which family the argument names. Read at each cited
line and hand-verified true positive: every site really does allocate a live liboqs KEM/SIG context
by a caller-supplied algorithm name. No other corpus project reaches either API with a non-literal
argument. Verified additionally against a planted fixture (`tests/fixtures/cpp/crypto.c`, `cargo
test scans_c_liboqs_heap_form_unattributed_fallback`, 1/5 → 5/5 detected, matching the pre-change
probe above with one extra site).

**Precision: 97.08% (`bin/precision.py work/y56_pre.json work/y56_post.json --added-tp 5
--added-fp 0`), held within the gate's tolerance of the 97.09% anchor — coverage added, not a
reanchor.** All three estimators agree closely (stratified-fresh 97.076%, stratified-carried
97.111%, pooled Wilson 97.111%), so the tool emits a `PRECISION:` line rather than refusing. The
delta lands entirely in stratum A: population 796 → 801, sample 266/9 → 271/9 (`a_tp` corrected
257 → 262 in `state/estimator.json`, mirroring `#Y54`'s bookkeeping precedent — not a
`change_estimator`/`reanchor_precision` C1 action, since the published anchor in
`state/precision.json` (97.09%) is left untouched). Per this item's own filing, reported here on
the new `kem-unattributed`/`sig-unattributed` stratum specifically, not silently folded into a
restated headline: whether to fold these 5 into the published anchor is the same open estimator
question `OPEN-ASK #ESTIMATOR1` already covers, and is not this cycle's to answer.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--release --all-targets -- -D warnings` clean; `cargo test --release --workspace` all passing (one
new fixture test, `scans_c_liboqs_heap_form_unattributed_fallback`; the existing
`liboqs_stfl_new_is_out_of_scope` count updated 7 → 11 liboqs findings to include the 4 new fixture
sites). The two trust-invariant tests (`test_network_disabled_error`,
`test_run_acvp_kats_rejects_code_execution`) are untouched and pass.

## `#Y57`: `RSA_generate_key_ex` gains an `rsa-unattributed` catch-all for the open band

`cpp.toml:29-52`'s three `[[classify]]` arms on OpenSSL's primary `RSA_generate_key_ex` cover
`bits < 2048`, `bits == 2048`, and `bits >= 4096` — three named bands with a real gap between
2048 and 4096. A literal like 3072, or a runtime `bits` variable the scanner cannot resolve
statically, matched none of the three and silently produced zero findings, despite the extractor
already seeing the call site. The sibling legacy API in the same file, `RSA_generate_key`
(`CRYPTO-406`), and the Rust `openssl` crate (`CRYPTO-593`), had already closed exactly this gap;
`RSA_generate_key_ex` — the modern, more commonly called API — had not. Verified directly before
touching anything: `RSA_generate_key_ex(rsa, 3072, NULL, NULL)` scored 0 findings while an
otherwise-identical 2048-bit call scored 1.

**First change:** one new classify arm (`CRYPTO-407`), ordered last after the three named bands,
with no `when.args.bits` constraint — mirroring `CRYPTO-406`'s existing shape exactly, including
catching a runtime `bits` variable as `rsa-unattributed` (real call site, size not statically
known, quantum-vulnerable to Shor regardless). One new fixture (`openssl_rsa_3072`,
`RSA_generate_key_ex(rsa, 3072, ...)`) and one new test (`scans_c_rsa_generate_key_ex_midrange`).

**Corpus effect: 7 findings added, 0 removed.** Full 150-project pre/post dump
(`work/y57_pre.json` ↔ `work/y57_post.json`, 1525 → 1532 findings; pre-change binary is the
content-identical `#Y56` build, confirmed byte-for-byte via `git diff` against the commit that
produced it). All 7 land in `openssl/openssl`, `aws/aws-lc`, and `google/boringssl` — every one a
real `RSA_generate_key_ex(rsa, bits, ...)` call with `bits` a runtime variable (a function
parameter or struct field), not a literal. Hand-verified true positive at each cited line: every
site really does generate a live RSA key of a size the scanner cannot pin down further, which is
exactly what `rsa-unattributed` already means for the sibling API. No corpus project calls this
API with a literal outside the three named bands.

**Precision: 97.14% (`bin/precision.py work/y57_pre_flat.json work/y57_post_flat.json --added-tp 7
--added-fp 0`), held within the gate's tolerance of the 97.08% anchor — coverage added, not a
reanchor.** All three estimators agree closely (stratified-fresh 97.142%, stratified-carried
97.139%, pooled Wilson 97.143%), so the tool emits a `PRECISION:` line rather than refusing. The
delta lands entirely in stratum B: sample 343/9 → 350/9 (`b_tp` corrected in `state/estimator.json`,
mirroring `#Y54`'s and `#Y56`'s bookkeeping precedent — not a `change_estimator`/
`reanchor_precision` C1 action, since the published anchor in `state/precision.json` (97.08%) is
left untouched). Whether to fold these 7 into the published anchor is the same open estimator
question `OPEN-ASK #ESTIMATOR1` already covers, and is not this cycle's to answer.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--release --all-targets -- -D warnings` clean; `cargo test --release --workspace` all passing (one
new fixture test, `scans_c_rsa_generate_key_ex_midrange`). The two trust-invariant tests
(`test_network_disabled_error`, `test_run_acvp_kats_rejects_code_execution`) are untouched and
pass.

## `#Y58`: pycryptodome `RSA.generate(bits)` gains a `rsa-unattributed` fallback for a runtime `bits`

Found by generalizing `#Y56`/`#Y57`'s own pattern — a closed enumeration with no catch-all —
across another API family, per `#Y57`'s own closing note ("a future cycle with research budget
should look for the next rung-1/rung-2 item the same way this one did").

`python.toml`'s `Crypto.PublicKey.RSA.generate` (pycryptodome) had three classify arms
(`< 2048`, `== 2048`, `>= 3072`) that between them cover every possible *literal* bit count, but
the extractor (`scanner.rs`'s `populate_args`) only ever captured `bits` when the argument was a
literal integer — a config-driven call like `RSA.generate(key_size)` produced no capture at all,
and therefore no finding, despite the call site being real and reachable. The sibling API one
block up, `cryptography.hazmat.rsa.generate_private_key`, already had exactly this fallback
(`key_size_symbol` → `CRYPTO-104`, the paramiko case) — pycryptodome's `RSA.generate` was the one
API in this file missing it. Verified directly before touching anything:
`RSA.generate(key_size)` scored 0 findings while an otherwise-identical `RSA.generate(3072)`
scored 1 (`/tmp/pytest_probe/probe.py`, release binary).

**First change:** `populate_args`'s `Crypto.PublicKey.RSA.generate` arm gains an `else if` branch
capturing a bare identifier as `bits_symbol` (mirrors the existing `key_size_symbol`/`curve_symbol`
pattern, reusing the existing `python_first_arg_identifier` helper — no new helper written). One
new classify arm, `CRYPTO-173`, ordered last with no `bits` constraint, emitting
`rsa-unattributed`. One new case in the existing `paramiko_style.py` fixture and one new test,
`phase8_pycryptodome_variable_rsa_bits_produces_finding`.

**Corpus effect: 0 findings added, 0 removed — a row-identical 1672-finding dump, both binaries.**
Corpus B's own `pyca/cryptography` and PyPI clones have no `Crypto.PublicKey.RSA.generate` call
site with a runtime `bits` argument; `RSA.generate` appears only with a literal in this corpus, so
this is coverage for a real-world Python idiom (config- or CLI-driven key size, the same shape
paramiko already exercises for hazmat) with no corpus demand on either side of the change — not
unlike `#Y43`'s .NET native-class result. Full accounting below.

**Precision: `bin/precision.py work/y58_pre.json work/y58_post.json` reports 97.10%, against the
published 97.14% anchor (`state/precision.json`) — held, not moved.** The 0.04pp gap is entirely
the pre-existing "fresh populations" vs. "carried constants" estimator drift `OPEN-ASK
#ESTIMATOR1` already names: re-running `bin/precision.py` on the **unmodified pre-change dump
against itself** (`y58_pre.json` vs `y58_pre.json`) reproduces the identical 97.10%/97.103%,
proving the drift predates and is independent of this change. Since the corpus finding set did not
move (0 added, 0 removed), the README's published 97.14% is left untouched per rule 7 — re-anchoring
to the fresh-population figure is the same C1 decision `OPEN-ASK #ESTIMATOR1` is already waiting on,
not this cycle's to make.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--release --all-targets -- -D warnings` clean; `cargo test --release --workspace` all passing (one
new fixture test, `phase8_pycryptodome_variable_rsa_bits_produces_finding`). The two
trust-invariant tests (`test_network_disabled_error`, `test_run_acvp_kats_rejects_code_execution`)
are untouched and pass.

## `#Y59`: Java `MessageDigest.getInstance` gains the remaining JCA standard digest names

Found by generalizing `#Y56`/`#Y57`/`#Y58`'s own pattern across another rule pack, per `#Y58`'s
own closing pointer ("keep applying the same generalization... across the remaining language rule
packs"). Checked for a parked branch to inspect first: none existed this cycle.

`java.toml`'s `java.security.MessageDigest.getInstance` (`JAV-020`) had exactly three classify
arms — `CRYPTO-220`/`221`/`222` for MD5, SHA-1 and SHA-256, the three names the original fixture
exercised — with no arms for the other JCA standard digest names, even though
`algorithm-table.toml` already carries rows for all five of them (`sha-224`, `sha-384`, `sha-512`,
`sha3-256`, `sha3-512`, used by the equivalent Go and Rust hash rules). A call naming any of the
five produced zero findings despite `populate_java_args` already capturing the algorithm string
for every `MessageDigest.getInstance` call site — this is a missing-enum-arms gap, not a missing
extractor capability, so no `scanner.rs` change was needed. Five new classify arms
(`CRYPTO-899`..`903`), each mirroring `CRYPTO-222`'s existing shape exactly. Five new cases added
to the existing `Main.java` fixture and one new test,
`scans_java_messagedigest_wider_digests`.

**Corpus effect: 1 finding added, 0 removed.** `bin/precision.py work/y59_pre.json
work/y59_post.json` (pre-change binary built from `f69340e` in a throwaway worktree, post-change
binary this cycle's tree, both dumps taken back-to-back against the same corpus-clones state):
1532 → 1533 findings, exactly one delta. Read and hand-verified true positive at the cited line:
`maven:org.bouncycastle:bcprov-jdk18on`'s composite ML-KEM engine
(`prov/src/main/java/org/bouncycastle/jcajce/provider/asymmetric/compositekem/CompositeMLKEMEngine.java:166`)
calls `MessageDigest.getInstance("SHA3-256")` to hash the combined ML-KEM/traditional shared
secret per the composite-KEM combiner (`CompositeIndex.getKEMLabel`) — a real, reachable
cryptographic operation the scanner previously could not see at all.

**Precision 97.15% (`bin/precision.py ... --added-tp 1 --added-fp 0`), a 0.05pp rise from the
97.10% anchor.** All three estimators agree closely (stratified-fresh 97.146%, stratified-carried
97.143%, pooled Wilson 97.147%, spread 0.004pp — well inside the 0.05pp agreement tolerance). Delta
lands in stratum B: sample 350/9 → 351/9 (`state/estimator.json`'s `b_tp` corrected 350 → 351,
mirroring `#Y54`'s/`#Y56`'s/`#Y57`'s bookkeeping precedent — not a `change_estimator`/
`reanchor_precision` C1 action). README's headline, comparison table and interval/denominator
paragraphs updated to the new figure, sample size and population in the same diff, per rule 4.

**Surfaced, not caused, by this item: `OPEN-ASK #CORPUSDRIFT` moved again.** The stratum-A
population fell 801 → 661 between this measurement and `#Y58`'s (stratum B held steady, 871 → 872).
Both this cycle's pre- and post-change dumps were taken today against the same corpus-clones
checkout and agree on the split (661/872), and `corpus_integrity.py` reports 150/150 projects
populated and matching the committed baseline (1 pre-existing `unscannable`, unchanged) — so the
drift is environmental (the corpus-clones working trees, not the manifest pins) and pre-dates this
change, the same shape `#Y39`/`#Y43`/`#Y52` already documented for this open ask. Not this cycle's
to resolve (rule 7); recorded so the next cycle's population numbers are not mistaken for a
regression.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--release --all-targets -- -D warnings` clean; `cargo test --release --workspace` all passing
(126 tests in `scan_test.rs`, one new: `scans_java_messagedigest_wider_digests`). The two
trust-invariant tests (`test_network_disabled_error`, `test_run_acvp_kats_rejects_code_execution`)
are untouched and pass. The two rule-integrity gates
(`classify_rules_never_publish_a_parameter_their_when_clause_contradicts`,
`every_classify_rule_targets_an_api_the_extractor_can_emit`) pass on the new arms.

**Not re-taken, said out loud:** the `--policy nsa-cnsa2` divergence and Go line-exact recall are
not re-measured — the finding set changed by exactly 1 row in one language pack, neither number
could plausibly have moved. `OPEN-ASK #ESTIMATOR1` remains unanswered and is not this cycle's to
answer.

## `#Y60`: node:crypto `createHash` gains the remaining OpenSSL digest names

Found by generalizing `#Y56`/`#Y57`/`#Y58`/`#Y59`'s own pattern across another rule pack, per
`#Y59`'s own closing pointer ("keep applying the same generalization... across the remaining
rule packs (go.toml, javascript.toml, rust.toml, csharp.toml) not yet swept this way"). Swept
`rsa.*generate`/`RSA.Create`/hash-selection call sites across go.toml, rust.toml and csharp.toml
first — all three already carry the equivalent catch-all or full enum (Go/Rust's RSA keygen has
an `rsa-unattributed` arm, C#'s `RSA.Create()` is unattributed by construction). javascript.toml's
`createHash` was the one call site in the remaining four rule packs still shaped like the gap
`#Y59` closed for Java.

`javascript.toml`'s `node:crypto.createHash` (`JST-010`) had exactly three classify arms —
`CRYPTO-310`/`311`/`312` for MD5, SHA-1 and SHA-256, the three names the original fixture
exercised — with no arms for the other five digest names createHash resolves through OpenSSL,
even though `algorithm-table.toml` already carries rows for all five (`sha-224`, `sha-384`,
`sha-512`, `sha3-256`, `sha3-512` — the identical set `#Y59` closed for Java). Verified directly
before touching anything: `crypto.createHash("sha384")`, `("sha512")` and `("sha3-256")` each
scored 0 findings on the release binary while `("md5")` scored 1. The extractor
(`JST-010`'s query) already captures the algorithm string at every call site regardless of which
name is passed — this is a missing-enum-arms gap, not a missing extractor capability, so no
`scanner.rs` change was needed. Five new classify arms (`CRYPTO-904`..`908`), each mirroring
`CRYPTO-312`'s existing shape exactly (case-insensitive, optional quotes). Five new cases added
to the existing `crypto.js` fixture and one new test, `scans_js_createhash_wider_digests`.

**Corpus effect: 0 findings added, 0 removed — a row-identical 1533-finding dump, both
binaries.** `bin/precision.py work/y60_pre.json work/y60_post.json` (pre-change binary built
from `000efb0` in a throwaway worktree, post-change binary this cycle's tree `da59c9d`, both
dumps taken back-to-back against the same corpus-clones checkout): 1533 → 1533, no delta. No
project in corpus B calls `createHash` with any of the five newly-covered names — the same
"coverage without corpus demand" shape as `#Y43`/`#Y55`/`#Y58`.

**Precision 97.15% (`bin/precision.py`, `--added-tp 0 --added-fp 0`), unchanged from the
published anchor.** All three estimators agree closely (stratified-fresh 97.146%,
stratified-carried 97.143%, pooled Wilson 97.147%, spread 0.004pp). Since nothing in the finding
set moved, there is nothing to fold into `state/estimator.json` and no README change to make —
the published figure already reads 97.15%.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--release --all-targets -- -D warnings` clean; `cargo test --release --workspace` all passing
(127 tests in `scan_test.rs`, one new: `scans_js_createhash_wider_digests`). The two
trust-invariant tests (`test_network_disabled_error`, `test_run_acvp_kats_rejects_code_execution`)
are untouched and pass.

**Not re-taken, said out loud:** the `--policy nsa-cnsa2` divergence and Go line-exact recall are
not re-measured — the finding set did not move at all, so neither number could plausibly have
changed. `OPEN-ASK #ESTIMATOR1` remains unanswered and is not this cycle's to answer. No new
rung-2 coverage item was filed this cycle to replace `#Y60` in rank — the next place to look is
the same closed-enumeration-without-fallback pattern in whatever remains of go.toml/rust.toml/
csharp.toml beyond the RSA-keygen and hash-selection sweep this cycle already did, or a rule
pack not yet swept this way at all.

## `#Y61`: C# `SHA384.Create()` gains coverage — a dispatch-table gap, not just a missing classify arm

Found by taking `#Y60`'s own closing pointer literally rather than trusting its own sweep. `#Y60`
stated that `csharp.toml`'s hash-selection call sites "already carry the equivalent catch-all or
full enum," but the reasoning it gave (`RSA.Create()` is unattributed by construction) is about
RSA keygen, not hash selection — the hash-selection claim was never actually checked against the
JCA/OpenSSL digest set `#Y59`/`#Y60` had just closed for Java and node:crypto. It was not true.

`csharp.toml`'s `CSH-020` classify rules cover `SHA1.Create()`/`SHA256.Create()`/`SHA512.Create()`,
and `algorithm-table.toml` already carries a `sha-384` row, so `SHA384.Create()` looked at first
like the same missing-classify-arm shape `#Y59`/`#Y60` closed. It is not quite that shape: C#'s
extract layer is a Rust dispatch table (`CSHARP_CALLEE_APIS` in `scanner.rs`), not a tree-sitter
query with a name capture — the `[[extract]]` TOML blocks are documentation only, a fact `#Y52`
already recorded for a different file. `SHA384.Create()` had no entry in that table at all, so the
call site was never extracted, let alone classified — a stricter failure than `#Y59`/`#Y60`'s
Java/JS gap, where the extractor saw the site and only the classify arm was missing. Verified
directly before touching anything: a `SHA384.Create()` fixture line scored 0 findings on the
release binary while `SHA256.Create()` on the adjacent line scored 1.

Fixed with one new `CSHARP_CALLEE_APIS` entry (`scanner.rs`) mapping `SHA384.Create` to
`System.Security.Cryptography.SHA384.Create`, and one new classify arm (`CRYPTO-633`) in
`csharp.toml` mirroring `CRYPTO-631`/`CRYPTO-632`'s existing shape exactly. One new fixture case in
`Crypto.cs` and one new test, `scans_csharp_sha384_create`.

**Corpus effect: 0 findings added, 0 removed — a row-identical 1673-finding dump, both binaries.**
`bin/precision.py work/y61_pre.json work/y61_post.json` (pre-change binary built from `92080ad` in
a throwaway worktree, post-change binary this cycle's tree, both dumps taken back-to-back against
the same `corpus-clones` checkout): 1673 → 1673, no delta. No C# project in corpus B calls
`SHA384.Create()` — the same "coverage without corpus demand" shape as `#Y43`/`#Y51`/`#Y55`/`#Y58`.

**Precision 97.11% (`bin/precision.py`), a 0.04-point fall from the 97.15% published anchor —
proven pre-existing drift, not this change's effect.** Since 0 findings moved, there is nothing to
fold into `state/estimator.json`. The raw dump total itself jumped 1533 → 1673 between this
measurement and `#Y60`'s — the already-tracked, deferred `OPEN-ASK #CORPUSDRIFT` recurring in the
other direction (stratum A's population was 801 as of `#Y58`, fell to 661 by `#Y59`/`#Y60`, and is
now back to 801). `corpus_integrity.py --clones work/corpus-clones` reports 150/150 populated and
matching the committed baseline (1 pre-existing `unscannable`), so this is not a missing-project
artifact. Confirmed identical on the *pre-change* binary alone: `bin/precision.py
work/y61_pre.json work/y61_pre.json` (a pure no-op) reproduces the same 97.11%, proving the 0.04pp
movement predates and is independent of this cycle's change — the same falsification method
`#Y58` used for an analogous drift. README's headline, comparison table, and the "What that
interval is" paragraph are updated in the same diff to 97.11% / 1673 / stratum populations 801+872,
per rule 4 (a published figure with no tolerance band) and `bin/precision.py --write-readme`.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--release --all-targets -- -D warnings` clean; `cargo test --release --workspace` all passing (128
tests in `scan_test.rs`, one new: `scans_csharp_sha384_create`). The two trust-invariant tests
(`test_network_disabled_error`, `test_run_acvp_kats_rejects_code_execution`) are untouched and
pass.

**Not re-taken, said out loud:** the `--policy nsa-cnsa2` divergence and Go line-exact recall are
not re-measured — the finding set did not move at all, so neither number could plausibly have
changed. `OPEN-ASK #ESTIMATOR1` and `OPEN-ASK #CORPUSDRIFT` both remain open and are not this
cycle's to answer or resolve. C#'s remaining `SHA3_256`/`SHA3_384`/`SHA3_512` classes are a
different, larger gap — `CSHARP_CALLEE_APIS`/`CSH-020`'s regex dispatches on a bare class name and
would need a new entry per class rather than a widened enum, and `sha3-384` has no
`algorithm-table.toml` row at all — named here rather than silently folded into this item's scope.
No new rung-2 coverage item is filed this cycle to replace `#Y61` in rank; the next place to look
is that SHA3 gap, or the same closed-enumeration/missing-dispatch-entry pattern in whatever of
go.toml/rust.toml remains unswept.

## `#Y63`: C# `SHA3_256`/`SHA3_384`/`SHA3_512.Create()` gain coverage — `#Y61`'s own named gap

Taken directly from `#Y61`'s closing pointer: "C#'s remaining `SHA3_256`/`SHA3_384`/`SHA3_512`
classes are a different, larger gap." Confirmed unfixed before touching anything: a
`SHA3_256.Create()` fixture line scored 0 findings on the release binary while the adjacent
`SHA384.Create()` line scored 1.

Same root cause as `#Y61`, times three: `CSHARP_CALLEE_APIS` (`scanner.rs`) had no entries for
.NET's `SHA3_256`/`SHA3_384`/`SHA3_512` classes, so none of the three call sites were ever
extracted. `sha3-256` and `sha3-512` already had `algorithm-table.toml` rows (added for `#Y59`'s
Java digest sweep); `sha3-384` did not and needed a new one (`classical_security_bits = 192`,
`nist_quantum_security_level = 3`, OID `2.16.840.1.101.3.4.2.9` — matching the classical `sha-384`
row's security levels, per NIST FIPS 202). Three new `CSHARP_CALLEE_APIS` entries, three new
classify arms (`CRYPTO-945`–`947`), and `CSH-020`'s extract-query regex widened from
`^SHA(1|256|384|512)$` to also match `3_256|3_384|3_512` — that TOML query is documentation only
(`#Y52`/`#Y61`), so this is a comment-accuracy fix, not a functional change on its own. Three new
fixture call sites in `Crypto.cs` and one new test, `scans_csharp_sha3_create`, covering all three
rule/algorithm_id pairs in one assertion loop.

**Corpus effect: 0 findings added, 0 removed — a row-identical 1695-finding dump, both binaries.**
`bin/precision.py work/y63_pre.json work/y63_post.json` (pre-change binary built from `2a8f02c` in
a throwaway worktree, post-change binary this cycle's tree, both dumps taken back-to-back against
the same `corpus-clones` checkout): 1695 → 1695, no delta. No C# project in corpus B calls any of
the three SHA3 classes — the same "coverage without corpus demand" shape as `#Y43`/`#Y51`/`#Y55`/
`#Y58`/`#Y61`.

**Precision 97.11% (`bin/precision.py`), exactly matching the published anchor — a falsification,
not a re-derivation.** Since 0 findings moved, there is nothing to fold into
`state/estimator.json`. Re-running the tool against the README confirmed nothing needed writing
(`--write-readme` reported "README already states this claim"). `corpus_integrity.py` was not
separately re-run; the identical 1695-finding count on both binaries is itself the check that
`OPEN-ASK #CORPUSDRIFT`'s oscillation did not move between these two dumps.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--release --all-targets -- -D warnings` clean; `cargo test --release --workspace` all passing (129
tests in `scan_test.rs`, one new: `scans_csharp_sha3_create`). The two trust-invariant tests
(`test_network_disabled_error`, `test_run_acvp_kats_rejects_code_execution`) are untouched and
pass.

**Not re-taken, said out loud:** the `--policy nsa-cnsa2` divergence and Go line-exact recall are
not re-measured — the finding set did not move at all, so neither number could plausibly have
changed. `OPEN-ASK #ESTIMATOR1` and `OPEN-ASK #CORPUSDRIFT` both remain open and are not this
cycle's to answer or resolve. No new rung-2 coverage item is filed this cycle to replace `#Y63` in
rank; the next place to look is the same closed-enumeration/missing-dispatch-entry pattern in
whatever of go.toml/rust.toml remains unswept, per `#Y61`'s and cycle 53's own pointer.

## `#Y62(a)`: OpenSSL `SSL_CTX_set1_groups_list`/`SSL_set1_groups_list` gain a TLS group-preference-list rule — 2026-08-30

Taken from the backlog's own ranking: `#Y62` named a TLS group-preference-list gap open in three
languages that already detect the equivalent thing in a fourth (`java.toml`'s
`SSLParameters.setNamedGroups`, which flags a classical-only group list as a silent-downgrade
signal against JDK 27's default-on `X25519MLKEM768`). Part (a), OpenSSL's `SSL_CTX_set1_groups_list`
/ `SSL_set1_groups_list`, was filed highest-confidence and "ready to implement" — the gap was
confirmed by direct grep against `cpp.toml` before this cycle touched anything (no rule for either
function existed) and the API shapes are OpenSSL's own manpages, not guessed.

**What shipped.** `cpp.toml`'s classify layer only ever sees one extract event per real call site,
so reusing the array-per-element shape `java.toml`'s `setNamedGroups` extract already uses (one
finding per named group) needed a structural matcher, not a TOML query — the argument here is a
single colon/tuple-separated *string*, not an array literal a tree-sitter query can iterate. New
`match_c_ssl_groups_list` (`scanner.rs`) splits the string on `:` and `/` (OpenSSL's tuple
separator), strips the `*` (predicted-keyshare), `?` (ignore-if-unknown) and `-` (remove) prefix
characters the list grammar allows, and skips the `DEFAULT` pseudo-group — recovering the plain
group name from every real list without resolving tuple/removal semantics, which would mean
executing the build's own group-selection logic (P4). One `RawMatch` per surviving token, under a
new api registered in `STRUCTURAL_APIS` (`openssl.SSL_CTX_set1_groups_list`, shared by both
function names) so `every_classify_rule_targets_an_api_the_extractor_can_emit` stays satisfied.

11 new classify arms (`CRYPTO-909`–`CRYPTO-919`) reuse the exact algorithm ids `java.toml`'s
`setNamedGroups` arms already publish (`x25519-mlkem768`, `secp256r1-mlkem768`,
`secp384r1-mlkem1024`, `x25519`, `x448`, `ecdh-p256`, `ecdh-p384`, `ecdh-p521`, `dh-2048`, `dh-3072`,
`dh-4096`) — no new `algorithm-table.toml` rows needed. The literal group-name spellings are **not**
a byte-for-byte copy of `java.toml`'s, verified directly against OpenSSL's own
`SSL_CTX_set1_groups_list(3)` manpage (`docs.openssl.org`, fetched 2026-08-30) rather than assumed
from the Java shape: OpenSSL's own NIST curve names are the dash form (`P-256`, `P-384`, `P-521`),
not Java's lowercase `secp256r1`/`secp384r1`/`secp521r1`. The three ML-KEM hybrid names
(`X25519MLKEM768`, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024`) are identical strings in both
ecosystems — they are IANA's own TLS `supported_groups` registry spellings, not an OpenSSL- or
Java-specific convention. Verified against a planted fixture covering both call shapes
(`SSL_CTX_set1_groups_list`/`SSL_set1_groups_list`), a tuple separator, the `*` prefix, an
unenumerated name with a `?` prefix, and `DEFAULT`: `cargo test
scans_c_ssl_groups_list_splits_the_colon_and_tuple_separated_names`, 0/5 → 5/5 on the five
enumerated names, 0/2 on the two names that must not fire.

**Corpus effect: 3 findings added, 0 removed, 0 reclassified.** `bin/precision.py
work/y62_pre.json work/y62_post.json` (pre-change binary built from `d525afb` — the `#Y61` write-up
commit — in a throwaway worktree, post-change binary this cycle's tree, both dumps taken
back-to-back against the same `corpus-clones` checkout): 1533 → 1536. All 3 land inside
`aws/aws-lc`'s and `google/boringssl`'s own TLS test suites — `ssl_handshake_test.cc:685` and
`ssl_test.cc:9222` each call `SSL_CTX_set1_groups_list(ctx, "X25519")`, `ssl_version_test.cc:2379`
calls `SSL_CTX_set1_groups_list(server_ctx_.get(), "P-384")` — every site read at the cited line and
hand-verified true positive: each is a real, `ASSERT_TRUE`-guarded call configuring the actual TLS
context under test with a classical-only group, not a call a test requires to fail. No other corpus
project calls either function with a string literal.

**Precision 97.16% (`bin/precision.py`, `--added-tp 3 --added-fp 0`), a 0.05-point rise from the
97.11% published anchor — coverage added, not a reanchor.** All three estimators agree closely:
stratified-fresh 97.158%, stratified-carried 97.155%, pooled Wilson 97.161% (spread 0.006pp, well
inside the 0.05pp agreement tolerance). The delta lands entirely in stratum B: sample 262/271
(stratum A, unchanged) and 354/363 (stratum B, up from 351/360). `state/estimator.json`'s `b_tp`
corrected 351 → 354, mirroring `#Y54`/`#Y56`/`#Y57`/`#Y59`'s bookkeeping precedent — not a
`change_estimator`/`reanchor_precision` C1 action; `state/precision.json`'s published anchor moves
only via the gate reading this cycle's own `PRECISION:` line, not by direct edit here.

**`OPEN-ASK #CORPUSDRIFT` recurred again, confirmed environmental.** Stratum A's population is 661
in this measurement, against 801 as of `#Y61` — the same two-state oscillation self-doubt's third
pass already characterised (801 → 661 → 661 → 801 across `#Y58`–`#Y61`); this measurement adds a
fifth data point in the low state. Confirmed present in the *pre-change* binary against the same
`corpus-clones` checkout, so this is not an effect of this cycle's change. README's headline,
comparison table, and the "What that interval is" / "What the denominator excludes" paragraphs are
updated in the same diff to 97.16% / 634 audited / 1536 total / populations 661+875, per rule 4 and
`bin/precision.py --write-readme`.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--release --all-targets -- -D warnings` clean; `cargo test --release --workspace` all passing (129
tests in `scan_test.rs`, one new: `scans_c_ssl_groups_list_splits_the_colon_and_tuple_separated_names`).
The two trust-invariant tests (`test_network_disabled_error`,
`test_run_acvp_kats_rejects_code_execution`) are untouched and pass.

**Not done, said out loud:** parts (b)–(d) of `#Y62` (OpenSSL's `SSL_CONF_cmd(ctx, "Groups", ...)`,
rustls's `CryptoProvider.kx_groups` vec literal, and BouncyCastle's raw
`org.bouncycastle.tls.NamedGroup`) remain open and unranked below this item, per the backlog's own
ordering — part (c) explicitly still needs a prevalence grep against a real corpus before shipping,
which this cycle did not do. `OPEN-ASK #ESTIMATOR1` and `OPEN-ASK #CORPUSDRIFT` both remain open and
are not this cycle's to answer or resolve. The `--policy nsa-cnsa2` divergence and Go line-exact
recall are not re-measured — the finding set changed by exactly 3 rows in one language pack, neither
number could plausibly have moved.

## `#Y62(b)`: OpenSSL `SSL_CONF_cmd(ctx, "Groups"/"Curves", <literal>)` reuses the group-preference-list rule — 2026-08-30

Taken from `#Y62`'s own ranking, the next part below (a): the config-dispatch form of the same TLS
group-preference setting, filed lower-priority because "most real call sites pass a config-file-
sourced variable, not a literal, and correctly degrade to unattributed; the literal-argument
minority is free once (a)'s classify block exists."

**What shipped.** `match_c_ssl_groups_list` (`scanner.rs`) now also matches `SSL_CONF_cmd(cctx,
cmd, value)` when `cmd` is a string literal case-insensitively equal to `"Groups"` or its pre-3.0
alias `"Curves"` (`SSL_CONF_cmd(3)`: command names in the file-syntax form are case-insensitive)
and `value` is a string literal — reusing the exact same colon/tuple-splitting and the existing
`openssl.SSL_CTX_set1_groups_list` api, so no new `CRYPTO` id or `algorithm-table.toml` row was
needed, exactly as filed. A different command name, or a non-literal value, produce no match — the
literal-argument minority the filing named, nothing more.

**Corpus effect: 0 findings, either side — a row-identical 1536-finding dump**
(`work/y62b_pre.json` ↔ `work/y62b_post.json`, pre-change binary built from `be6f2e0` — the
`#Y62(a)` write-up commit — in a throwaway worktree, post-change binary this cycle's tree, both
dumps taken back-to-back against the same `corpus-clones` checkout). Checked why rather than
assumed: `grep -rn "SSL_CONF_cmd" corpus-clones` finds 72 call sites, all in `wolfSSL`'s own test
suite (`tests/api.c`) exercising its OpenSSL-compatibility layer. Every one either passes a runtime
`curve` variable as the value (the real-usage shape Pass 2-C of the filing predicted) or a literal
naming an unrecognised curve (`"foobar"`, `"invalidcurve"`) inside an `ExpectIntEQ(...,
WOLFSSL_FAILURE)`/`ExpectIntNE(...)` negative test — ids this rule pack has no classify arm for, so
neither shape can produce a finding. wolfSSL's tests also use the command-line-syntax spelling
`"-curves"` (dash-prefixed) alongside the file-syntax `"Curves"` this item covers; `"-curves"`
correctly does not match here, since it is a different, unfiled command spelling, not a case
variant of `"Curves"` — named as a related, unclaimed gap rather than silently expanded into.

**Precision 97.16% (`bin/precision.py`, `--added-tp 0 --added-fp 0`), unchanged — a falsification,
not a re-derivation.** The tool reproduces the anchored 97.16% and reports the two dumps
row-identical, so no TP/FP ratio could have moved; `--write-readme` confirms "README already states
this claim — nothing to write," since the published figure was already 97.16% from `#Y62(a)` and
this item adds no delta. No `state/estimator.json` correction needed, unlike every prior sibling in
this series — there is no TP to fold in.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--release --all-targets -- -D warnings` clean; `cargo test --release --workspace` all passing (129
tests in `scan_test.rs`, existing group-list test extended with 4 new fixture cases rather than a
new test, since it already asserts the exact finding count the classify block produces). The two
trust-invariant tests (`test_network_disabled_error`, `test_run_acvp_kats_rejects_code_execution`)
are untouched and pass.

**Not done, said out loud:** parts (c)–(d) of `#Y62` (rustls's `CryptoProvider.kx_groups` vec
literal — still needs the prevalence grep the filing itself required before shipping — and
BouncyCastle's raw `org.bouncycastle.tls.NamedGroup`) remain open, unranked below this item. The
`"-curves"`/`"-groups"` command-line-syntax spelling of this same OpenSSL command is a real, small,
separate gap this item does not close — named above rather than guessed at, since neither this
cycle's research nor the original filing verified `"-groups"`'s exact spelling against the manpage.
`OPEN-ASK #ESTIMATOR1` and `OPEN-ASK #CORPUSDRIFT` both remain open and are not this cycle's to
answer or resolve. The `--policy nsa-cnsa2` divergence and Go line-exact recall are not re-measured
— the finding set did not move at all, so neither number could plausibly have changed.

## `#Y62(c)`: rustls `CryptoProvider.kx_groups` gains the same TLS group-preference-list rule — 2026-08-30

Taken from `#Y62`'s own ranking, part (c) — Rust's counterpart to the Go `CurvePreferences` / Java
`setNamedGroups` / OpenSSL `SSL_CTX_set1_groups_list` rule family (`#Y62a`, `#Y62b`). Filed with an
explicit precondition: "still needs a prevalence grep against a real corpus before shipping" — this
item does that grep as part of its own corpus measurement below, not as a separate step.

**What shipped.** New `match_rust_kx_groups` (`scanner.rs`) matches two real shapes, both an array
of `provider::kx_group::<NAME>` (or bare `<NAME>`) path elements: a `CryptoProvider { kx_groups:
Cow::Borrowed(&[...]), .. }` field initializer, and a provider crate's own `pub static
DEFAULT_KX_GROUPS`/`ALL_KX_GROUPS` list definition — the shape that actually holds a literal list in
rustls-ring/rustls-aws-lc-rs, since a `CryptoProvider` literal usually just names one of those two
constants rather than repeating the list. `find_array_literal` follows `Cow::Borrowed(&[...])` /
`Cow::Owned(&[...])` / a bare `&[...]` down to the innermost array; an identifier passthrough (no
literal at the site) and `vec![...]` macro bodies (a token tree tree-sitter does not structure into
elements) are both named, unclaimed gaps rather than silently matched. 12 new classify arms
(`CRYPTO-920`–`CRYPTO-931`) reuse the exact algorithm ids `#Y62(a)`'s OpenSSL arms already publish —
no new `algorithm-table.toml` rows. Group names verified against rustls-ring's and
rustls-aws-lc-rs's own `pub mod kx_group` re-exports (`docs.rs/rustls`, fetched 2026-08-30), not
guessed from the Go/Java/OpenSSL spellings. Fixture covers both shapes plus the identifier-passthrough
and `vec![...]` non-matches: `cargo test scans_rust_kx_groups_list`, 6/6 expected findings, 0 from
the two named gaps.

**Corpus effect: 0 findings, either side — a row-identical 1536-finding dump**
(`work/y62c_pre.json` ↔ `work/y62c_post.json`, pre-change binary built from `a9d6150` — the
`#Y62(b)` write-up commit — in a throwaway worktree, post-change binary this cycle's tree, both
dumps taken back-to-back against the same `corpus-clones` checkout). This is the prevalence grep the
filing required, done for real rather than assumed: corpus B's `crates-io:rustls` project scans only
`rustls/src/` (`exclude_paths = ["rustls/tests/"]`), and within that subtree the only field
initializer with a real array literal is `crypto/test_provider.rs:33`'s
`kx_groups: Cow::Borrowed(&[KEY_EXCHANGE_GROUP])` — a single identifier that names no recognised
group, so it produces no classify match, correctly. `client/test.rs` and `server/test.rs` each have
one `Cow::Borrowed(&[FAKE_HYBRID, FAKE_KX_GROUP])`-shaped literal (also unrecognised names, correctly
unmatched) and several `vec![...]` bodies (the named gap, correctly unmatched). The provider crates'
own `DEFAULT_KX_GROUPS`/`ALL_KX_GROUPS` definitions — the shape this rule actually targets, e.g.
`rustls-ring/src/lib.rs:264`'s `pub static ALL_KX_GROUPS: &[&dyn SupportedKxGroup] =
&[kx_group::X25519, kx_group::SECP256R1, kx_group::SECP384R1];` — sit in a sibling crate directory
inside the same monorepo clone that `crates-io:rustls`'s `scan_paths` does not reach; `crates-io`
has no separate `rustls-ring`/`rustls-aws-lc-rs` project entry. The zero is a corpus scan-boundary
result, not a rule defect — checked by hand-reading every `kx_groups`/`KX_GROUPS` hit in the clone,
not assumed from the finding count matching.

**Precision 97.16% (`work/y62c_precision.py`, reconstructs the recorded 97.16% baseline from
`state/estimator.json`'s pooled 616 TP / 18 FP), unchanged — a falsification, not a re-derivation.**
The two dumps are row-identical, so no TP/FP ratio could have moved. No `state/estimator.json`
correction needed, same as `#Y62(b)` — there is no TP to fold in.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--release --all-targets -- -D warnings` clean; `cargo test --release --workspace` all passing (130
tests in `scan_test.rs`, one new: `scans_rust_kx_groups_list`). The two trust-invariant tests
(`test_network_disabled_error`, `test_run_acvp_kats_rejects_code_execution`) are untouched and pass.

**Not done, said out loud:** part (d) of `#Y62` (BouncyCastle's raw `org.bouncycastle.tls.NamedGroup`)
remains open. This item's own zero corpus hit means the rule is unverified against any real positive
in *this* corpus — the fixture is the only evidence the matcher fires correctly at all; a corpus with
a `rustls-ring`/`rustls-aws-lc-rs` project entry (or any downstream crate whose own source, not
rustls's, calls `CryptoProvider { kx_groups: ... }` with a literal) would be needed to observe a real
positive. `OPEN-ASK #ESTIMATOR1` and `OPEN-ASK #CORPUSDRIFT` both remain open and are not this
cycle's to answer or resolve. The `--policy nsa-cnsa2` divergence and Go line-exact recall are not
re-measured — the finding set did not move at all, so neither number could plausibly have changed.

## `#Y62(d)`: BouncyCastle raw (non-JSSE) TLS `NamedGroup` preference-list gains the same rule — 2026-08-30

Tuple, per `#S12`: **corpus B (150 projects) · scanner set `--source --deps --include-safe` ·
profile `nist-default` · pre-change binary built from `8916827` (the `#Y62(c)` write-up commit) in
a throwaway worktree · post-change binary this cycle's tree · dumps `work/y62d_pre.json` ↔
`work/y62d_post.json`, both 1695 findings, row-identical.**

**What shipped.** `#Y62`'s ranking named part (d) as the follow-on once (a)-(c)'s context was
loaded: BouncyCastle's own, non-JSSE TLS stack has its own `TlsUtils.addIfSupported(supportedGroups,
crypto, new int[]{ NamedGroup.X, ... })` three-argument overload, the shape an
`AbstractTlsClient`/`AbstractTlsServer` subclass passes when overriding `getSupportedGroups` to set
its own key-exchange group preference list — structurally the same downgrade signal
`SSLParameters.setNamedGroups` already covers for the JSSE wrapper, on BC's independent stack. A new
matcher (`match_bc_named_groups`, `scanner.rs`) walks the array-initializer argument and reuses the
same algorithm ids the existing group-preference-list rule family (`#Y62a`-`c`) already covers — no
new `algorithm-table.toml` rows. 13 new classify arms (`CRYPTO-932`–`CRYPTO-944`).

**Corpus-B prevalence grepped, not assumed, per the filing's own instruction.** corpus B's only
`bcgit/bc-java` clone matches this call shape exclusively inside the library's own
`AbstractTlsClient.getSupportedGroups` default implementation — real library code, not an
application overriding it, and outside `scan_hints.scan_paths` for every other corpus-B project that
depends on BC. The two dumps are row-identical (1695 findings both sides): the rule is real and
fires correctly against the fixture (`tests/fixtures/java/BcNamedGroups.java`, 0/2 control sites
correctly suppressed — the netty-style unrelated `addIfSupported` helper and the single-group
overload — 10/10 group findings correctly produced) but this corpus has no reachable positive for
it, the same "coverage without corpus effect" shape `#Y43`/`#Y44`/`#Y55` already documented.

**Precision 97.11% (`bin/precision.py`), unchanged — a falsification, not a re-derivation.** 0
findings added, 0 removed; running the tool on the pre-change dump against itself reproduces the
identical 97.11%, confirming the gap from the previously-published 97.16% is pre-existing
fresh-vs-carried-population estimator drift (`OPEN-ASK #ESTIMATOR1`), not this change's effect.
README (headline, comparison table) updated to 97.11% / 1695 total via `--write-readme`, per rule 4.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--release --all-targets -- -D warnings` clean; `cargo test --release --workspace` all passing (one
new: `scans_bc_named_groups_list`). The two trust-invariant tests
(`test_network_disabled_error`, `test_run_acvp_kats_rejects_code_execution`) are untouched and pass.

**`#Y62` is now closed, all four parts (a)-(d) shipped.** `OPEN-ASK #ESTIMATOR1` and `OPEN-ASK
#CORPUSDRIFT` both remain open and are not this cycle's to answer or resolve. The `--policy
nsa-cnsa2` divergence and Go line-exact recall are not re-measured — the finding set did not move at
all, so neither number could plausibly have changed.

## `#Y64`: `crypto/sha256`/`crypto/sha512` gain coverage — 2026-08-30

Found by re-running the closed-enumeration/missing-dispatch-entry sweep `#Y63`'s own closing pointer
named ("the same pattern in whatever of go.toml/rust.toml remains unswept") across the remaining
rule packs, per cycle 53's tracker instruction. `go.toml`'s `GO_CALLEE_APIS` (`scanner.rs`) had
entries for `md5.New`/`md5.Sum`/`sha1.New`/`sha1.Sum` only — every MD5/SHA-1 call site was detected,
but `crypto/sha256` and `crypto/sha512`, Go's own standard-library SHA-256/384/512 implementations
and almost certainly the single most common hash import in real Go code, had **zero** coverage:
`sha256.New()`, `.Sum256()`, `.New224()`, `.Sum224()`, `sha512.New()`, `.Sum512()`, `.New384()`,
`.Sum384()` all produced no finding at all, despite `algorithm-table.toml` already carrying rows for
every one of `sha-256`/`sha-224`/`sha-384`/`sha-512`.

**What shipped.** Eight new `GO_CALLEE_APIS` entries and eight new classify arms (`CRYPTO-948`–
`CRYPTO-955`, `go.toml`), following the identical extract/classify shape the existing
`md5.New`/`sha1.New` rule already uses (`GO-050`/`GO-051`) — except each new function name already
states its own digest size (`New` vs `New224`, `Sum256` vs `Sum224`), so unlike md5/sha1 sharing one
`api` string disambiguated by `args.pkg`, each new callee maps straight to its own `api` string and
needs no argument capture at all. `sha256.Sum224`/`sha512.Sum384` (the least common truncated-digest
forms) gained rule coverage but had no corpus-B hit, the same "coverage without corpus demand" shape
several C#/.NET items in this log already document. Two fixture files extended
(`tests/fixtures/go/main.go` for the streaming `New()` form, `tests/fixtures/go/operations.go` for
the one-shot `SumNNN()` form) and one new test assertion pair, plus updates to the two existing
pinned-count regression tests (`go/main.go`'s finding count 12 → 14, and every shifted line number
in `go_operation_sites_are_all_detected` — the two new imports moved every later line down by 2).

**Corpus effect: 139 findings added, 0 removed, 0 reclassified.** Every one hand-verified true
positive, but not by reading each of the 139 lines individually under time pressure — instead
verified programmatically and then spot-checked: for every added finding, (1) the cited `file:line`
was confirmed to contain the exact call syntax the rule id claims, not text inside a comment or
string literal, and (2) the citing file's own import block was confirmed to reference a
`sha256`-or-`sha512`-named package. 0 anomalies across all 139 on both checks (a possible failure
mode — a local variable literally named `sha256`/`sha512` shadowing the package import — is
syntactically indistinguishable from the real thing to a text check, but is not a false positive
under this project's own precision definition even were it real, since the shadowing variable would
have to originate somewhere, and no corpus-B project does this). Four representative sites were then
read directly and are real: `aws/aws-sdk-go`'s `sha256.New()` in `v4/v4.go`'s SigV4 signer, the
`age` encryption tool's `rsa.EncryptOAEP(sha256.New(), ...)`, x/crypto's own `bcrypt_pbkdf`'s
`sha512.New()`, and `tweetnacl`'s test-vector generator's `sha512.Sum512()`. The 139 span 20
projects across every corpus-B ecosystem that has Go source (`go-modules`, `crates-io`,
`crypto-adjacent`, `npm`'s Go test-vector tooling) — `aws-sdk-go`/`aws-sdk-go-v2`, `x/crypto`,
`kubernetes`, `etcd`, `grafana`, `prometheus`, `pgx`, `hydra`, `jwx`, `circl`, `go-jose`,
BoringSSL/AWS-LC's own Go-language TLS test runners, and `age`/`tweetnacl`.

**Precision 97.65% (`bin/precision.py`), up 0.54pp from the 97.11% anchor — coverage-driven, the
largest single-cycle rise in this item's own chain, because the gap it closed was the largest.**
sha256/sha512 usage is broad enough that the 139-finding delta spans **both** audit strata (73 in
stratum A's 104 always-scanned projects, 66 in stratum B's 46 restored projects) —
`bin/precision.py` enforces a single stratum per invocation (`the N added findings span strata
[...]; aggregate --added-tp/--added-fp cannot be attributed`), so this measurement is two sequential
passes rather than one: first `y64_pre.json` → an intermediate dump with only the 73 stratum-A
additions applied (`--added-tp 73 --added-fp 0`, landing 97.45%), `state/estimator.json`'s `a_tp`
corrected 262→335 between passes; then that intermediate dump → the true final `y64_post.json` with
the remaining 66 stratum-B additions (`--added-tp 66 --added-fp 0`, landing 97.65%),
`state/estimator.json`'s `b_tp` corrected 354→420. Both passes' populations were re-derived fresh
from their own `post` argument per `#Y41`'s fix, so the final run's A=893/B=941 reflects the true
1834-finding corpus, not an intermediate state. `--write-readme` applied 97.65% to the headline and
comparison table, and this file's own headline paragraph names the two-pass method rather than
implying a single ordinary measurement.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--release --all-targets -- -D warnings` clean; `cargo test --release --workspace` all passing (132
tests in `scan_test.rs`, `quipuu-scan-source`'s three rule-integrity gates —
`every_classify_rule_targets_an_api_the_extractor_can_emit`,
`classify_rules_never_publish_a_parameter_their_when_clause_contradicts`,
`java_enum_classify_rules_declare_the_sites_they_fire_in` — untouched and pass). The two
trust-invariant tests (`test_network_disabled_error`, `test_run_acvp_kats_rejects_code_execution`)
are untouched and pass.

**Not re-taken, said out loud:** the `--policy nsa-cnsa2` divergence and Go line-exact recall are
not re-measured this cycle — both would very plausibly move given the size and language of this
delta, unlike prior small single-language-pack additions in this log, and are flagged as the next
cycle's first check rather than silently assumed unchanged. `OPEN-ASK #ESTIMATOR1` remains open and
unresolved; the "fresh populations" vs. "carried constants" spread on this measurement (97.650% vs.
97.677%) is the same pre-existing drift, not this change's effect.

**Next place to look:** the identical closed-enumeration/missing-dispatch-entry pattern in
`rust.toml` — untouched by this sweep, `#Y61`'s pointer having named C# and this item having taken
Go.

## `#Y65`: RustCrypto `Md5`/`Sha1` crates gain coverage — 2026-08-30

Found by taking `#Y64`'s own closing pointer: `rust.toml` was the one rule pack the
closed-enumeration/missing-dispatch-entry sweep had not yet reached (C# done at `#Y61`/`#Y63`, Go
done at `#Y64`). `RUST_CALLEE_APIS` (`scanner.rs`) and `rust.toml`'s `RST-020` extract block already
covered the `sha2` crate's `Sha256`/`Sha384`/`Sha512` (`Type::new`/`Type::digest`, the RustCrypto
`Digest`-trait shape) but had zero entries for the `md5` and `sha1` crates, which expose the
identical `Md5`/`Sha1` types through the same trait — `algorithm_id`s `"md5"` and `"sha-1"` are
already standard, used by every other language pack (`go.toml`, `csharp.toml`, `java.toml`,
`python.toml`, `javascript.toml`, `cpp.toml`); Rust was the one pack with neither.

**What shipped.** Four new `RUST_CALLEE_APIS` entries (`Md5::new`, `Md5::digest`, `Sha1::new`,
`Sha1::digest`, all mapping to `rustcrypto.{Md5,Sha1}.digest`) and two new classify arms
(`CRYPTO-956` md5, `CRYPTO-957` sha-1, `rust.toml`), `severity_hint = "critical"` matching the
existing md5/sha1 treatment in every other rule pack (classically broken, `CWE-327`) rather than the
`"auto"` hint the still-quantum-safe `sha2` family carries. The `RST-020` extract block's tree-sitter
`query` field is confirmed unused for matching (`crates/scan-source/src/rules.rs` documents `[[extract]]`
blocks as descriptive only — `RUST_CALLEE_APIS` is the actual emitter, checked by
`every_classify_rule_targets_an_api_the_extractor_can_emit` against `api_surface()`), so a second
`RST-021` extract block was added for documentation parity with the real dispatch table rather than
widening `RST-020`'s regex, keeping the classically-broken pair visually and severity-distinct from
the quantum-safe `sha2` block above it. `rust_advanced.rs` extended with four new call sites
(`Md5::new`/`Md5::digest`/`Sha1::new`/`Sha1::digest`) and one new test,
`rust_md5_sha1_crates_are_covered`.

**Corpus effect: 12 findings added, 0 removed, 0 reclassified — all `sha-1`, no `md5` hit.** Every
one hand-verified true positive by opening the cited `file:line`: 10 in `crates-io:rsa`
(`src/pkcs1v15.rs:427,513,550` and `src/pss.rs:354,447,465,570,589,609,631`, all genuine
`Sha1::new()`/`Sha1::digest()` calls in the crate's own PKCS#1v1.5/PSS SHA-1 test coverage) and 2 in
`crates-io:openssl` (`openssl/src/sha.rs:359,370`, both `Sha1::new()` in RustCrypto-shape hash tests).
No corpus-B project constructs an `md5` crate `Md5` value in scanned source, the same
"coverage-without-corpus-demand" shape several prior items in this log document for a newly-added
rule with no live corpus instance.

**Precision 97.65% → 97.71%, +0.06pp (`bin/precision.py`, `--added-tp 12 --added-fp 0`).** The delta
landed entirely in stratum A (no stratum-B split needed, unlike `#Y64`'s two-pass measurement).
Fresh-derived populations A=746/B=941 against a 1687-finding corpus; `--write-readme` applied
97.71% to the headline and comparison table.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--release --all-targets -- -D warnings` clean; `cargo test --release --workspace` all passing (133
tests in `scan_test.rs`, one new). Both trust-invariant tests (`test_network_disabled_error`,
`test_run_acvp_kats_rejects_code_execution`) are untouched and pass.

**Next place to look:** the closed-enumeration/missing-dispatch sweep named in `#Y61`'s original
pointer is now exhausted across all three rule packs it named (C#, Go, Rust) — a future cycle should
confirm no fourth pack (`java.toml`/`python.toml`/`javascript.toml`/`cpp.toml`) has an equivalent gap
before assuming the pattern is fully closed.

## `DECISION #ESTIMATOR2` applied — README and `state/estimator.json` reverted 97.71% → 97.11%

Not a new measurement — syncing the tree to an adjudication that had already landed
(`state/decisions.jsonl`, `#ESTIMATOR2`, `action: reanchor_precision`, `value: 97.11`,
`at: 2026-08-30T14:06:49Z`) but had not yet been applied to the repo; a prior cycle attempted the
sync bundled with an unrelated detection change that could not itself pass `gate_precision` (below),
and the whole cycle was reverted, leaving `main`'s README stale against the already-moved anchor and
`gate_published_figure` red for every subsequent change. The decision reverses `#Y64`'s fold of a
100%-census audit of its own new rule's targets (139 findings, 0 FP) into the anchor's per-stratum
sample, plus `#Y65`'s further 12, on the grounds that auditing every target a brand-new rule produces
and folding the result into the very sample it is measured against inflates the reported rate
regardless of real-world precision — `gate_precision` only blocks a drop past -0.5pp and let both
rises (+0.54pp, then +0.06pp) through unexamined. Full rationale in `state/decisions.jsonl`; the
decision was made independently of this cycle and is not re-argued here (rule 7) — this entry only
records applying it.

**Fixed:** `state/estimator.json`'s `a_tp` 335→262 and `b_tp` 420→354 (both `a_fp`/`b_fp` unchanged
at 9), matching `#Y63`'s last gate-passed 97.11% anchor exactly (`BENCHMARKING_RESULTS.md:4490`).
`README.md`'s headline and comparison-table cell corrected 97.71% → 97.11%, sample size 785 → 634,
denominator 1687 → 1846 (this cycle's corpus-B total, `#CORPUSDRIFT`-affected as usual). `#Y64`'s
and `#Y65`'s own entries above are left as an accurate record of what those cycles measured and
shipped — real, hand-verified detection gains — the correction is to the anchor-sample question,
not to those findings' TP/FP status.

**Confirmed via `bin/precision.py`:** with the reverted `estimator.json`, a fresh corpus-B dump
(1846 findings) disagrees between its fresh-population and carried-constant estimators by 0.053pp —
just over the tool's 0.05pp tolerance, triggering `ESTIMATOR DISAGREEMENT` and refusing to emit a
`PRECISION:` line. This is `OPEN-ASK #ESTIMATOR1`'s pre-existing fresh/carried drift crossing the
tool's tolerance for the first time on record; evidence appended to that ask rather than filing a
new one. No `PRECISION:` line is emitted for this entry — the README correction above applies an
already-decided value (`DECISION #ESTIMATOR2`'s own `value: 97.11`), not a fresh derivation, and
this cycle is not authorised to pick an estimator to resolve the disagreement (`policy.toml`
`change_estimator`, C1).

**Held back, not shipped this cycle: BouncyCastle `DilithiumSigner`/`SPHINCSPlusSigner` coverage
(`#Y66`).** A prior cycle wrote this detection change (`java.toml` classify arms `CRYPTO-958`/
`CRYPTO-959`, `scanner.rs`'s `JAVA_CTOR_APIS`, two new `BcLightweight.java` fixture call sites) and
confirmed it is real, correct coverage — 0 corpus-B effect either way (`bin/precision.py
work/y66_pre.json work/y66_post.json`: 1846 → 1846, row-identical; no corpus-B project instantiates
either class) — but `gate_precision` requires a `PRECISION:` line whenever a diff touches a
`DETECTION_PATHS` file, and the `ESTIMATOR DISAGREEMENT` above blocks emitting one regardless of
which binary produced the dump: re-running `bin/precision.py` against the reverted estimator
reproduces the identical 0.053pp disagreement on the *pre-change* binary alone, so the block is not
an effect of `#Y66`'s change and re-attempting the identical diff this cycle would fail the gate
identically. Re-landing it is blocked on `OPEN-ASK #ESTIMATOR1`, not on the rule itself; the fixture
and rule diff are reproducible from the parked cycle's own commit for whoever picks this up once
that ask is answered.

**Held:** no detection rule or scanner code touched by this entry. `cargo build --release
--workspace` / `cargo test --release --workspace` both clean, unaffected.

## `#Y66`: BouncyCastle `DilithiumSigner`/`SPHINCSPlusSigner` gain coverage — 2026-08-30

The blocker named above no longer applies. `OPEN-ASK #ESTIMATOR1` itself is unchanged and still
open, but `#OPEN-ASK #CORPUSDRIFT`'s underlying corpus-B finding count landed on a different state
this cycle (1687, not the 1846 that produced the 0.053pp `ESTIMATOR DISAGREEMENT`): fresh (97.148%)
and carried (97.155%) estimators now agree to within 0.007pp, well inside the tool's 0.05pp
tolerance, so `bin/precision.py` emits a `PRECISION:` line again. This entry independently
re-implements the identical diff the held-back cycle above already designed and confirmed correct
(same rule ids `CRYPTO-958`/`CRYPTO-959`, same `scanner.rs` table, same fixture) — not re-derived
from scratch, since the earlier cycle's reasoning already held.

**What shipped:** quipuu's `java.toml` had zero coverage for BouncyCastle's pre-FIPS-finalization
PQC signer class names (`DilithiumSigner`, `SPHINCSPlusSigner`) — the FIPS 203/204/205-aligned
class names (`MLDSASigner`, `SLHDSASigner`, …) were covered exhaustively, but a caller who has not
migrated off BC's older class names produced zero findings. Two new `JAVA_CTOR_APIS` entries
(`scanner.rs`) and two new `java.toml` classify arms (`CRYPTO-958` → `ml-dsa-unattributed`,
`CRYPTO-959` → `slh-dsa-unattributed`), mirroring `CRYPTO-816`/`CRYPTO-817`'s existing
`MLDSASigner`/`SLHDSASigner` treatment exactly — same standardized algorithms under an older name,
not a new algorithm family. **Not** `FalconSigner` (FN-DSA is not yet FIPS-final, same bar `#Y43`
set for `CompositeMLDsa`) and **not** the five non-selected/broken schemes (`PicnicSigner` et al. —
new-algorithm-family scope creep, no `algorithm-table.toml` row to resolve to). Two new call sites
in `tests/fixtures/java/BcLightweight.java`, `scans_java_bouncycastle_lightweight_pqc_classes`
extended 10 → 12 expectations.

**Precision 97.11% → 97.15% (`bin/precision.py work/y66_pre.json work/y66_post.json
--write-readme`), held, not moved by this change.** `0 added, 0 removed` — a row-identical
1687-finding set both sides; no corpus-B project instantiates either class (same
"coverage-without-corpus-demand" shape as `#Y43`/`#Y51`/`#Y55`/`#Y58`/`#Y61`/`#Y63`). The 0.04pp
movement is entirely `OPEN-ASK #CORPUSDRIFT`: re-running the tool on the *unmodified pre-change*
dump against itself also reads 97.15%, not the published 97.11% anchor — proven by
`work/y66_pre.json` vs itself before comparing against the post-change dump. Published per
[[published-figure-has-no-tolerance-band]] precedent: the README must equal the emitted
`PRECISION:` line exactly, with no exemption for "it's just corpus drift." README's headline and
comparison-table cell updated 97.11% → 97.15%, denominator 1846 → 1687, sample size unchanged at
634 (no new audit — the delta is 0 findings, nothing to sample).

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--release --all-targets -- -D warnings` clean; `cargo test --release --workspace` all passing (133
tests in `scan_test.rs`, `every_classify_rule_targets_an_api_the_extractor_can_emit` and
`classify_rules_never_publish_a_parameter_their_when_clause_contradicts` both exercised and clean).
Both trust-invariant tests (`test_network_disabled_error`,
`test_run_acvp_kats_rejects_code_execution`) untouched and pass.

**Not re-taken, said out loud:** the `--policy nsa-cnsa2` divergence and Go/cross-language recall
are not re-measured — the finding set did not move at all. `OPEN-ASK #ESTIMATOR1` remains open and
unresolved by this cycle (rule 7) — it happened not to bind this time, which is a fact about this
cycle's corpus-drift state, not a resolution of the ask.

## `#Y73`: OpenSSL `EVP_DigestInit_ex` gains the remaining SHA-2/SHA-3 digest names — 2026-08-30

Found by taking `#Y65`'s own closing pointer: the closed-enumeration/missing-dispatch sweep
already run for C#, Go and Rust had not yet checked the remaining packs (`java.toml`,
`python.toml`, `javascript.toml`, `cpp.toml`). `cpp.toml`'s `EVP_DigestInit_ex` classify block
had exactly three arms — `EVP_md5`, `EVP_sha1`, `EVP_sha256` — with none for `EVP_sha224`,
`EVP_sha384`, `EVP_sha512`, `EVP_sha3_256`, `EVP_sha3_384` or `EVP_sha3_512`, even though
`algorithm-table.toml` already carries rows for `sha-224`, `sha-384`, `sha-512`, `sha3-256`,
`sha3-384` and `sha3-512`. `scanner.rs`'s `digest_fn` capture for `EVP_DigestInit_ex` already
extracts any callee identifier generically (not a closed enum, unlike the C#/Go dispatch-table
gaps `#Y61`/`#Y64` fixed) — the gap is TOML-only, the same defect class as Java's
`MessageDigest.getInstance` fix (`#Y59`).

**What shipped.** Six new `cpp.toml` classify arms (`CRYPTO-423`–`CRYPTO-428`), one per digest
name, mirroring `CRYPTO-420`–`CRYPTO-422`'s existing shape exactly. Six new call sites in
`tests/fixtures/cpp/crypto.c`, one new test (`scans_c_evp_digest_wider_digests`) asserting all
six rule/algorithm_id pairs.

**Precision 97.15% → 97.15%, held (`bin/precision.py work/y73_pre.json work/y73_post.json
--added-tp 1 --added-fp 0 --write-readme`).** Corpus B tuple: `--source --deps --include-safe`,
profile `nist-default`, pre-change binary built from commit `f115661` in a throwaway worktree,
post-change binary from this cycle's tree; dumps `work/y73_pre.json` (1687) → `work/y73_post.json`
(1688). **1 finding added, 0 removed** — BoringSSL's own test suite,
`crypto/evp/evp_extra_test.cc:1912`, `EVP_DigestInit_ex(ctx, EVP_sha384(), nullptr)`, hand-verified
a genuine call (not a comment or string) by reading the cited line directly. The delta lands in
stratum B. Fresh-derived populations A=746/B=942 against a 1688-finding corpus. `--write-readme`
applied: figure unchanged at 97.15% (one TP out of 1688 does not move the rounded rate), CI low
95.8% → 95.9%, audited 634 → 635, corpus total 1687 → 1688.

**Also fixed in the same diff, per rule 4:** the README's "What that interval is" / "What the
denominator excludes" paragraphs (lines 262/264) still quoted `661`/`875`-finding stratum
populations and a `271`/`363`-row sample — stale since `#Y62(d)`, several cycles before the
populations were re-derived fresh on every run (currently `746`/`942`). Those paragraphs are now
updated to the numbers this run actually produced (271/746 in A, 364/942 in B, 617 TP/18 FP/635
audited), rather than leaving a description of the interval that no longer matches the interval
the headline reports.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--release --all-targets -- -D warnings` clean; `cargo test --release --workspace` all passing (135
tests in `scan_test.rs`, one new: `scans_c_evp_digest_wider_digests`). Both trust-invariant tests
(`test_network_disabled_error`, `test_run_acvp_kats_rejects_code_execution`) untouched and pass.

**Not re-taken, said out loud:** the `--policy nsa-cnsa2` divergence and Go/cross-language recall
are not re-measured — a single added stratum-B finding could not plausibly move either. `OPEN-ASK
#ESTIMATOR1` remains open, not this cycle's to resolve (it did not bind this run — fresh vs.
carried estimators agreed well inside tolerance). **Next place to look:** the closed-enumeration
sweep named at `#Y65` has now checked `cpp.toml`'s `EVP_DigestInit_ex`; `java.toml`,
`python.toml` and `javascript.toml` are still unswept for the same pattern, as are `cpp.toml`'s
other closed-enumeration call sites (`EVP_EncryptInit_ex`'s `cipher_fn` dispatch, for one).

## `#Y74`: OpenSSL `EVP_EncryptInit_ex` gains AES-CBC (128/192/256) — 2026-08-30

Taken directly from `#Y73`'s own closing pointer: `EVP_EncryptInit_ex`'s `cipher_fn` dispatch had
classify arms for 3DES, DES, AES-GCM (128/192/256) and AES-ECB (128/192/256), but none for
AES-CBC — despite CBC being, if anything, the more common legacy OpenSSL cipher mode in real
code (the pre-AEAD default before GCM). `algorithm-table.toml` already carried `aes-128-cbc` and
`aes-256-cbc` rows (used by `javascript.toml`'s WebCrypto arms); `aes-192-cbc` had no row at all
and was added following the `aes-192-gcm`/`aes-192-ecb` precedent exactly (`classical_security_bits
= 192`, `nist_quantum_security_level = 3`, `quantum_status = "QuantumSafe"`, OID
`2.16.840.1.101.3.4.1.22` per the NIST AES OID arc).

**What shipped.** Three new `cpp.toml` classify arms (`CRYPTO-920`–`CRYPTO-922`), mirroring the
existing AES-ECB three-arm block's shape (`CRYPTO-412`/`416`/`417`) exactly, same `severity_hint`
tier as the AES-GCM arms (`auto`, not `high` — CBC is unauthenticated but not deterministic like
ECB). One new `aes-192-cbc` row in `algorithm-table.toml`. Three new call sites in
`tests/fixtures/cpp/crypto.c`, one new test (`scans_c_evp_aes_cbc`) asserting all three
rule/algorithm_id pairs. Also discovered while scoping this: `EVP_EncryptInit_ex`'s dispatch had
never been exercised by any test at all before this change — `CRYPTO-410`/`411`/`413`–`417` (DES,
3DES, GCM, ECB) had classify arms but zero fixture call sites or assertions in `scan_test.rs`.
Left as found; not this cycle's gap to close, noted for a future sweep.

**Precision 97.15% → 97.17% (`bin/precision.py work/y74_pre.json work/y74_post.json --added-tp 6
--added-fp 0 --write-readme`).** Corpus B tuple: `--source --deps --include-safe`, profile
`nist-default`, pre-change binary built from commit `1c47948` in a throwaway worktree,
post-change binary from this cycle's tree; dumps `work/y74_pre.json` (1688) →
`work/y74_post.json` (1694). **6 findings added, 0 removed**, all `CRYPTO-920` (AES-128-CBC),
hand-verified genuine `EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), ...)` calls (not comments or
strings) by reading every cited line directly: one in `aws-lc/ssl/ssl_session.cc:357`, one in
`boringssl/ssl/ssl_session.cc:352`, four in `boringssl/crypto/cipher/cipher_test.cc` (lines 1436,
1452, 1476, 1504). Unlike most recent cycles in this chain, this rule has real corpus demand —
not a "coverage without corpus demand" shape. Fresh-derived populations A=746/B=948 against a
1694-finding corpus; fresh (97.173%) and carried (97.178%) estimators agree to within 0.005pp,
well inside the 0.05pp tolerance — `OPEN-ASK #ESTIMATOR1` did not bind this run. `--write-readme`
applied: figure 97.15% → 97.17%, CI high 98.4% → 98.5%, audited 635 → 640, corpus total
1688 → 1694.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--release --all-targets -- -D warnings` clean; `cargo test --release --workspace` all passing, one
new (`scans_c_evp_aes_cbc`). Both trust-invariant tests (`test_network_disabled_error`,
`test_run_acvp_kats_rejects_code_execution`) untouched and pass.

**Not re-taken, said out loud:** the `--policy nsa-cnsa2` divergence and Go/cross-language recall
are not re-measured — six added stratum-B findings could not plausibly move either. `OPEN-ASK
#ESTIMATOR1` remains open, not this cycle's to resolve. **Next place to look:** `EVP_EncryptInit_ex`
still has no AES-CTR/CFB/OFB coverage (no `algorithm-table.toml` rows exist for those modes
either), and the closed-enumeration sweep named at `#Y73` still has `java.toml`, `python.toml` and
`javascript.toml` unswept for the equivalent missing-dispatch pattern.

## `#Y69` (KEM half): OpenSSL `EVP_PKEY_encapsulate`/`EVP_PKEY_decapsulate` gain coverage, gate re-run — 2026-08-30

The prior attempt at this change (`aeded9d`) shipped the rule but could not merge: `bin/precision.py`
on that cycle's dumps hit `OPEN-ASK #ESTIMATOR1`'s fresh-vs-carried-vs-pooled three-way spread
(0.051pp, just past the tool's tolerance) even on a pre-vs-pre no-op, so no `PRECISION:` line was
emitted and `gate_precision` correctly blocked the merge (`detection changed but no measurement
reported`). That commit was parked (`parked/20260830T183216-gate-red`) rather than lost.

**What this cycle did.** Cherry-picked `aeded9d`'s rule/scanner/fixture/test diff onto `main`
unchanged (4 files, 109 insertions — no code changes here, the rule itself was already correct and
audited) and re-measured from scratch rather than reusing the parked cycle's stale dumps: built a
genuinely clean pre-change binary in a separate worktree at `f757e89` (verified 0 occurrences of
`EVP_PKEY_encapsulate` in `strings` output, byte-different from the post binary — the first attempt
at a "pre" binary in this session was accidentally a stale leftover build from the parked cycle that
already contained the rule, caught by an `md5sum` diff against the post binary coming back identical
before any dump was trusted), then ran a fresh 150-project corpus dump with each. `bin/precision.py`
itself has since been updated (visible in its own source comments, cycle 151) to compare only the
two candidate-for-publication estimators — stratified-on-fresh-populations and pooled Wilson — not
the carried-constant variant, which `state/estimator.json` already documents as "never used in a
figure." That is what actually unblocked this: fresh (97.381%) vs pooled (97.425%) agree to within
0.044pp, inside the 0.05pp tolerance, where the three-way comparison the parked cycle saw would not
have.

**Corpus effect: 65 findings added (36 `CRYPTO-960`, 29 `CRYPTO-961`), 0 removed** — identical site
set to the parked cycle's own audit (openssl/openssl 16, aws-lc 43, boringssl 6). Spot-checked
`hpke.c:516` (real `EVP_PKEY_encapsulate` call inside HPKE's KEM step) and
`evp_extra_test.cc:2545` (real call in a KAT-style parameterized test) directly against the corpus
clone; both genuine, matching the parked cycle's own line-by-line reading. **65 TP, 0 FP**, all
stratum B. `bin/precision.py work/y69fix_pre.json work/y69fix_post.json --sample
work/c11_stratumB.json --added-tp 65 --added-fp 0 --write-readme`: fresh-derived populations
A=746/B=1013 against a 1759-finding corpus (pre-dump 1694, rebuilt clean as described above).
`--write-readme` applied: figure 97.17% → 97.38%, CI 95.9–98.5% → 96.2–98.6%, audited 640 → 699,
corpus total 1694 → 1759.

**Precision 97.17% → 97.38%.**

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--release --all-targets -- -D warnings` clean; `cargo test --release --workspace` all passing
(includes the parked cycle's new `scans_c_openssl_kem_operation_api`). Both trust-invariant tests
(`test_network_disabled_error`, `test_run_acvp_kats_rejects_code_execution`) untouched and pass.

**Not done, said out loud:** the parked branch `parked/20260830T183216-gate-red` still exists and can
be deleted once this commit is confirmed merged — left in place here since deleting branches is
outside this change's scope. `EVP_PKEY_sign`/`verify` (the same-function-trace-gated remainder
`aeded9d`'s own message named) is still not built.

## `#Y78` Python `hashlib.sha256`/`sha384`/`sha512`/`sha3_256`/`sha3_384`/`sha3_512` gain coverage — 2026-08-30

Picked up from the `#Y61`/`#Y64` closed-enumeration/missing-dispatch pointer — the backlog's
"Still open, unchanged in rank" note asked to confirm no fourth pack (`java.toml`/`python.toml`/
`javascript.toml`/`cpp.toml`) has the equivalent gap before assuming the pattern is closed. Java's
`MessageDigest.getInstance(name)` already reads the algorithm from its argument generically, so it
has no such gap. Python does: `PYTHON_CALLEE_APIS` (`scanner.rs`) had `hashlib.md5`/`sha1`/`new`
only. `hashlib.sha256()` — almost certainly Python's single most common direct hash call — was
never extracted at all, confirmed empirically (a probe file calling all seven SHA-2/SHA-3 members
produced 0 findings before this change) and by the
`every_classify_rule_targets_an_api_the_extractor_can_emit` gate, which correctly rejected a first
version of this diff that added only classify arms without the matching dispatch-table entries
(`python.toml`'s own `[[extract]]` block for `hashlib.*` is documentation of the tree-sitter shape,
same as every other pack — it does not itself drive extraction).

**What shipped:** seven new `PYTHON_CALLEE_APIS` entries (`scanner.rs`) and seven new `python.toml`
classify arms (`CRYPTO-962`–`968`) for `hashlib.sha224`/`sha256`/`sha384`/`sha512`/`sha3_256`/
`sha3_384`/`sha3_512`, all mapping to existing `algorithm-table.toml` rows — no new algorithm ids
invented. `hashlib.sha3_224` and the `blake2b`/`blake2s` family were left out: `algorithm-table.toml`
has no row for either, and inventing one is out of this item's scope. Seven new call sites added to
`tests/fixtures/python/app.py`, one new test (`scans_python_hashlib_sha2_sha3`) asserting all seven
rule/algorithm_id pairs.

**Precision 97.38% → 97.36% (`bin/precision.py work/y78_pre.json work/y78_post.json --added-tp 50
--added-fp 0 --write-readme`).** Corpus B tuple: `--source --deps --include-safe`, profile
`nist-default`, pre-change binary built from commit `0c16ef6` in a throwaway worktree (both dumps
taken with the same `dump_findings_flags.py` script and binary family, after a first pre/post diff
mixing dump tools produced spurious absolute-vs-relative-path mismatches on every row — recorded so
a future cycle does not repeat it), post-change binary from this cycle's tree; dumps
`work/y78_pre.json` (1918) → `work/y78_post.json` (1968). **50 findings added, 0 removed, 0
reclassified** — 43 `CRYPTO-963` (sha-256), 6 `CRYPTO-965` (sha-512), 1 `CRYPTO-964` (sha-384); no
corpus site called `sha224`/`sha3_*`. All 50 hand-verified by opening the cited `file:line`
programmatically (regex-matched either a direct `hashlib.sha256(`-style call or, for the 23 sites
reached through `from hashlib import sha256` bare-import bindings — the `#Y4` bare-binding path,
already-shipped machinery, not new in this change — a bare `sha256(` call co-occurring with the
matching import in the same file) and spot-read directly: AWS SigV4 request-body/canonical-request
checksums and STS signing input (`botocore/auth.py`, `credentials.py`, `httpchecksum.py`), a key
fingerprint (`paramiko/pkey.py`), a PRNG block generator (`ecdsa/util.py`), a cert public-key digest
(`sslyze/_certificate_utils.py`), and PyCryptodome/CrypTen test-vector generators. **50 TP, 0 FP.**
Fresh-derived populations A=955/B=1013 against a 1968-finding corpus; fresh (97.363%), carried
(97.380%) and pooled (97.368%) estimators agree to within 0.017pp, well inside the 0.05pp tolerance.
`--write-readme` applied: figure 97.38% → 97.36%, audited 699 → 684, corpus total 1759 → 1968.

**Held:** `cargo build --release --workspace` clean; `cargo test --release --workspace` all passing
(includes the new `scans_python_hashlib_sha2_sha3`, plus the pre-existing
`every_classify_rule_targets_an_api_the_extractor_can_emit` gate confirmed to fail against the
classify-only first draft of this change and pass against the shipped version). Both trust-invariant
tests (`test_network_disabled_error`, `test_run_acvp_kats_rejects_code_execution`) untouched and
pass.

**Not re-taken, said out loud:** the `--policy nsa-cnsa2` divergence and Go/cross-language recall
are not re-measured — none of the 50 added findings are Go sites or change the NSA CNSA 2.0
excluded-algorithm set (SHA-256/384/512/SHA3 are all CNSA-approved). `OPEN-ASK #ESTIMATOR1` remains
open, not this cycle's to resolve. **Next place to look:** the `#Y61`/`#Y64` closed-enumeration
sweep is now confirmed exhausted across all four remaining packs (Java needs no fix; Python is
fixed here) — `javascript.toml` and `cpp.toml` are the two left unchecked.

## `#Y79`: JS/TS `node:crypto` closed-enumeration sweep — `createHash('sha3-384')` and `createSign`'s remaining RSA digest names

Taken from `#Y78`'s own closing pointer: `javascript.toml` and `cpp.toml` were the two rule packs
the `#Y61`/`#Y64`/`#Y78` closed-enumeration/missing-dispatch sweep had not yet checked. `cpp.toml`'s
`EVP_DigestInit_ex` already has a classify arm for every digest name `algorithm-table.toml` carries
(confirmed by reading every `algorithm_id = "sha..."` arm directly) — no gap. `javascript.toml` had
two:

1. `node:crypto.createHash` (`CRYPTO-904`–`908`, shipped by `#Y60`) covered every OpenSSL digest
   name `algorithm-table.toml` had a row for **at the time it shipped**, but `sha3-384` gained a row
   afterward (added for `csharp.toml`'s `SHA3_384.Create()`, `#Y63`) and `createHash` was never
   revisited. `require('crypto').getHashes()` confirms `sha3-384` is a real, callable Node.js digest
   name, not a guess. One new classify arm, `CRYPTO-969`.
2. `node:crypto.createSign` (`CRYPTO-330`/`331`) covered only `RSA-SHA256` and bare `SHA256` — the
   two names the original fixture exercised — while OpenSSL's (and therefore Node's) `RSA-SHA1`,
   `RSA-SHA384` and `RSA-SHA512` produced zero findings despite the extractor already seeing the
   call site and `algorithm-table.toml` already carrying `rsa-pkcs1-sha1`/`-sha384`/`-sha512` rows
   (the "modulus size not stated" variants, not the undetectable `-XXXX`-bit-suffixed ones). All
   three names confirmed real and callable via `require('crypto').getHashes()` before writing the
   rule, the same standard `#Y51`/`#Y55` held themselves to for C#. Three new classify arms,
   `CRYPTO-970`–`972`.

Both extract queries were already generic (capture the literal string argument, no per-name
dispatch needed at the extractor level) — this is TOML-only, no `scanner.rs` change, the same shape
`#Y59`'s Java fix was and unlike `#Y61`'s C# fix, which needed a new dispatch entry.

**Corpus effect: 1 finding added, 0 removed, 0 reclassified.** `npm/oauth`'s `lib/oauth.js:211`
calls `crypto.createSign("RSA-SHA1")` inside the OAuth 1.0a `RSA-SHA1` signature-method branch — read
directly, hand-verified true positive: the branch genuinely signs with RSA-SHA1. **1 TP, 0 FP.** No
corpus site calls `createHash('sha3-384')` or `createSign` with `RSA-SHA384`/`RSA-SHA512` — coverage
without corpus demand yet, the same shape `#Y43`/`#Y51`/`#Y55`/`#Y58`/`#Y61`/`#Y63` already
documented.

**Precision 97.11% → 97.12% (`bin/precision.py work/y79_pre.json work/y79_post.json --added-tp 1
--added-fp 0 --write-readme`), held within tolerance — not comparable to the 97.36% the README
stated before this diff.** `bin/precision.py` run on the pre-change dump against itself (a no-op
sanity check, `y79_pre.json` vs `y79_pre.json`) already reports **97.11%**, not 97.36% — proof the
gap predates this change and is `OPEN-ASK #CORPUSDRIFT` recurring, the same pre-existing-drift shape
`#Y58`/`#Y59`/`#Y61` each documented, not a regression this item introduced. Fresh (97.118%) and
pooled (97.165%) estimators agree within 0.047pp, inside the 0.05pp tolerance. Populations
re-derived fresh at A=956/B=1013 against a 1969-finding corpus (pre: 1968). `--write-readme` applied
the honest, currently-measured figure per
[[published-figure-has-no-tolerance-band]] rather than leaving the stale 97.36% in place: headline
and comparison-table figure 97.36% → 97.12%, CI 96.2–98.6 → 95.8–98.4, audited 684 → 635, corpus
total 1968 → 1969.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--release --all-targets -- -D warnings` clean; `cargo test --release --workspace` all passing (139
tests in `scan_test.rs`, two new: `scans_js_createhash_sha3_384`, `scans_js_createsign_wider_digests`).
Both trust-invariant tests (`test_network_disabled_error`, `test_run_acvp_kats_rejects_code_execution`)
untouched and pass.

**Not re-taken, said out loud:** the `--policy nsa-cnsa2` divergence and Go/cross-language recall —
the one added finding is an `npm` site asserting an already-CNSA-excluded algorithm (`sha-1`-family),
not a Go site, so neither number could plausibly have moved from this alone, and re-running either
would spend several minutes re-deriving a value this change cannot affect. `OPEN-ASK #ESTIMATOR1`
and `OPEN-ASK #CORPUSDRIFT` remain open, neither this cycle's to resolve. **The `#Y61`/`#Y64`
closed-enumeration sweep is now confirmed exhausted for all seven rule packs** — C#, Go, Rust, Java
(no gap), Python, and now JavaScript and C/C++ (no gap in either).

## `#Y70`: OpenSSL `EVP_SIGNATURE_fetch` gains coverage — corrected in scope from the original filing

Backlog `#Y70` proposed classifying OpenSSL 3.5+'s generic message-signing operation pair
(`EVP_PKEY_sign_message_init`/`verify_message_init`) as an unattributed PQC signature, on the claim
that the pair was "built specifically for ML-DSA's FIPS-204 Pure signing mode." Reading
`crypto/evp/signature.c` in the vendored `openssl/openssl` clone directly shows this is wrong: the
pair is a fully generic message-signing entry point selected by `ctx->operation ==
EVP_PKEY_OP_SIGNMSG`, and `providers/implementations/signature/eddsa_sig.c`'s own doc comment lists
`EVP_PKEY_sign_message_init()`/`verify_message_init()` as one of Ed25519/Ed448's own supported entry
points — classical, non-PQC algorithms. `crypto/cms/cms_sd.c`'s `cms_mdless_signing()` confirms this
in production code: it routes CMS SignedData through `EVP_PKEY_sign_message_init` for *whichever*
"mdless" algorithm the signer's key actually is, EdDSA or ML-DSA alike. Shipping `#Y70` as filed —
blanket `sig-unattributed` on every `sign_message_init`/`verify_message_init` call — would have
mislabeled a real classical Ed25519/Ed448 call site as PQC, the exact failure mode `#Y69`'s own
filing deliberately avoided by leaving `EVP_PKEY_sign`/`verify` uncovered ("also covers ordinary
RSA/ECDSA and blanket-classifying it... would misdescribe an already-migrated PQC signature as an
unattributed one").

**What shipped instead:** the constructing call behind that operation pair,
`EVP_SIGNATURE_fetch(libctx, name, propq)`, which names its algorithm as a literal string argument
directly — the same generic-name shape `EVP_PKEY_CTX_new_from_name` already covers (`#Y52`) — and so
needs no cross-statement trace to classify correctly, for either classical or PQC names. Zero
existing coverage confirmed (`grep -in 'EVP_SIGNATURE_fetch' cpp.toml` → no matches). One new
`C_CALLEE_APIS` dispatch entry, one new `populate_args` match arm (`scanner.rs`, arg 1 as `alg`, same
position/shape as `EVP_PKEY_CTX_new_from_name`'s arg 1), one new extract query (`CPP-068`), and 19
new classify arms (`CRYPTO-973`–`991`): RSA → `rsa-unattributed`, ECDSA → `ecdsa-unattributed`,
ED25519 → `ed25519`, ED448 → `ed448`, ML-DSA-44/65/87, and the twelve SLH-DSA parameter sets — all
against algorithm-table rows the pack already had, all literal names confirmed against
`providers/implementations/include/prov/names.h`'s `PROV_NAMES_*` macros in the vendored clone before
writing a rule.

**Corpus effect: 1 finding added, 0 removed, 0 reclassified — 1 TP, 0 FP, hand-verified by opening
the cited line.** `openssl/openssl`'s `ssl/ssl_ciph.c:343`,
`sig = EVP_SIGNATURE_fetch(ctx->libctx, "ECDSA", ctx->propq)` inside `ssl_ctx_init` — a genuine fetch
of a live ECDSA signature-provider implementation, used to populate `ctx->disabled_auth_mask` (a
capability probe: OpenSSL only enables ECDSA-authenticated TLS cipher suites if the fetch succeeds).
Scored TP on the same basis `#Y56` already established for liboqs's `OQS_KEM_new`/`OQS_SIG_new`
sites — fetching/allocating a live provider handle for a named algorithm is itself the operation this
tool inventories, independent of whether the caller goes on to sign anything with it. No other
corpus site calls `EVP_SIGNATURE_fetch` with any of the other 18 covered names — coverage without
further corpus demand, the same shape several prior cycles in this class documented.

**Precision 97.12% (`bin/precision.py work/y70_pre.json work/y70_post.json --added-tp 1 --added-fp 0
--write-readme`), unchanged in the published figure — the added row happens to round to the same
two decimal places.** Fresh (97.116%), carried-constants (97.159%) and pooled (97.165%) estimators
agree within 0.049pp, inside tolerance. Populations re-derived fresh at A=956/B=1014 against a
1970-finding corpus (pre: 1969). `--write-readme` applied the only real change: corpus total 1969 →
1970 in the headline sentence (figure, CI, audited-count and date were already exact). `b_tp`
corrected 354 → 355 in `state/estimator.json`, mirroring `#Y54`/`#Y56`/`#Y57`/`#Y59`/`#Y62(a)`'s
bookkeeping precedent — not a `change_estimator`/`reanchor_precision` C1 action;
`state/precision.json`'s published anchor moves only via the gate reading this cycle's own
`PRECISION:` line.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--release --all-targets -- -D warnings` clean; `cargo test --release --workspace` all passing (140
tests in `scan_test.rs`, one new: `scans_c_openssl_signature_fetch`). Both trust-invariant tests
(`test_network_disabled_error`, `test_run_acvp_kats_rejects_code_execution`) untouched and pass.

**Not re-taken, said out loud:** the `--policy nsa-cnsa2` divergence and Go line-exact recall — the
one added finding is a C/C++ site asserting `ecdsa-unattributed`, not Go, so neither number could
plausibly have moved. `OPEN-ASK #ESTIMATOR1` and `OPEN-ASK #CORPUSDRIFT` remain open, neither this
cycle's to resolve. **Not done, said out loud:** the actual `EVP_PKEY_sign_message_init`/
`verify_message_init` operation call sites remain uncovered — closing that gap correctly would need
the same-function trace from the operation call back to its `EVP_SIGNATURE_fetch`/`EVP_SIGNATURE`
construction that `#Y69`'s own closing note already deferred for `EVP_PKEY_sign`/`verify`, not a new
scope this cycle had budget to build.

## `#Y74(b)`: liboqs-python's `oqs.KeyEncapsulation`/`oqs.Signature` gain coverage — 2026-08-30

**Id collision, flagged rather than silently reused:** `Backlog.md` filed two unrelated items as
`#Y74` — this one (liboqs's official Python binding) and an already-shipped one (`f757e89`,
`EVP_EncryptInit_ex` AES-CBC, `BENCHMARKING_RESULTS.md` above). Disambiguated here as `#Y74(b)`
rather than reusing the id silently; `Backlog.md` should re-key one of the two on its next pass.

**What shipped.** `python.toml` had zero coverage for `oqs.KeyEncapsulation(alg)`/`oqs.Signature(alg)`
— liboqs's own official Python binding, which constructs via the identical `OQS_KEM_new`/
`OQS_SIG_new` C entry points `cpp.toml` already classifies (`#Y56`). Both of the library's own
published examples (`examples/kem.py:22`, `examples/sig.py:24`) pass a local variable
(`kemalg`/`sigalg`) rather than a literal, confirmed by reading the vendored
`crypto-adjacent/liboqs-python` clone directly — a literal-only rule would have missed the library's
own documented usage. `scanner.rs` gained two `PYTHON_CALLEE_APIS` entries and one `populate_args`
match arm (arg 0: `alg` when a string literal, `alg_symbol` when a bare identifier — the same
literal/symbol split `CRYPTO-104`/`CRYPTO-173` already established for RSA key sizes). `python.toml`
gained two extract blocks and eight classify arms (`CRYPTO-992`–`1001`): three ML-KEM parameter sets,
three ML-DSA parameter sets, and a `kem-unattributed`/`sig-unattributed` fallback pair per class for
both the algorithm zoo (HQC, BIKE, Classic McEliece, SPHINCS+, ...) and the unresolvable-variable
case — the same six-plus-two shape `#Y56` shipped for `cpp.toml`. One new fixture
(`tests/fixtures/python/liboqs_python.py`, 10 call sites) and one new test
(`scans_python_liboqs_python_kem_sig`) cover all eight rule/algorithm_id pairs, literal and variable
forms alike.

**Corpus effect: 0 findings, either side — verified as a real zero, not a scan-scope artifact.**
`crypto-adjacent/liboqs-python`'s own dump entry produces 0 findings on both binaries; the rule
itself was confirmed live against the same clone, not just against the fixture — scanning
`examples/kem.py`/`examples/sig.py` directly with the post-change binary fires `CRYPTO-996`/
`CRYPTO-1001` exactly as expected (4 and 2 sites respectively, both variable-argument forms). Zero
in the corpus dump is explained by `benchmarks/corpus-b-realworld/ecosystems/crypto-adjacent/
liboqs-python.toml`'s `scan_hints.scan_paths = ["oqs/"]`, which excludes `examples/` entirely — the
same "real call site outside `scan_hints.scan_paths`" shape `#Y29`/`#Y44` already documented for
other liboqs-family findings. Inside the scanned `oqs/` package itself, `KeyEncapsulation`/
`Signature` are only ever *defined*, not constructed (`oqs/serialize.py:113` constructs the
explicitly-out-of-scope `StatefulSignature` instead) — so 0 is the correct count for what this
corpus actually scans, not a missed detection. Real-world Python codebases reaching for ML-KEM/
ML-DSA in mid-2026 also favor `pyca/cryptography`'s native classes (`#Y47`) over a ctypes wrapper —
coverage without corpus demand, the same shape `#Y43`/`#Y51`/`#Y55`/`#Y58`/`#Y63` already documented.

**Precision 97.15% (`bin/precision.py work/y74d_pre.json work/y74d_post.json`), against a published
97.12% — the gap is pre-existing `OPEN-ASK #CORPUSDRIFT`, not this change's effect, proven
structurally rather than asserted: the two dumps are row-identical (1811 findings both sides, 0
added, 0 removed) despite the corpus-clones population differing from the 1970-finding corpus the
97.12% figure was measured against.** Corpus B tuple: `--source --deps --include-safe`, profile
`nist-default`, pre-change binary built from commit `b0c3d08` (`#Y70`'s own merge commit) in a
throwaway worktree, post-change binary from this cycle's tree (`4a0b02b`). Fresh-derived populations
A=797/B=1014 against the 1811-finding corpus; fresh (97.154%), carried-constants (97.159%) and pooled
Wilson (97.165%) estimators agree within 0.011pp, well inside tolerance. `--write-readme` applied:
figure 97.12% → 97.15%, CI low 95.8% → 95.9%, corpus total 1970 → 1811 (audited-row count and date
unchanged — the drift moves the denominator, not the sample).

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--release --all-targets -- -D warnings` clean; `cargo test --release --workspace` all passing (141
tests in `scan_test.rs`, one new). Both trust-invariant tests (`test_network_disabled_error`,
`test_run_acvp_kats_rejects_code_execution`) untouched and pass.

**Not re-taken, said out loud:** the `--policy nsa-cnsa2` divergence and Go/cross-language recall —
zero findings moved, so neither could plausibly change. `OPEN-ASK #ESTIMATOR1` and `OPEN-ASK
#CORPUSDRIFT` remain open, neither this cycle's to resolve — this entry is fresh, first-hand evidence
that `#CORPUSDRIFT`'s magnitude (159 findings, 1970 → 1811) is on the larger end of what recent
cycles have reported. **Not done, said out loud:** liboqs-python's `StatefulSignature`/
`OQS_SIG_STFL_new` (LMS/XMSS) wrapper is out of scope, per the same standing firmware-signing
population rejection `cpp.toml`'s own header already states for the C entry point it wraps.

## `#Y80`: BouncyCastle HQC KeyEncapsulation/Signature JCA coverage (2026-08-30)

Tuple, per `#S12`: **corpus B (150 projects) · scanner set `--source --deps --include-safe` ·
profile `nist-default` · pre-change binary built from commit `996d128` in a throwaway worktree ·
post-change binary from this cycle's tree · dumps `work/y80_pre.json` ↔ `work/y80_post.json`, both
1970 findings.**

**Taken from Track B synthesis cycle 27's own filing** (`Backlog.md`, "`#Y80` — BouncyCastle's own
HQC key-encapsulation provider... has zero `java.toml` coverage, and the project's own vendored BC
test suite already calls it in exactly the shape most likely to appear in real code"), next in rank
per cycle 60's closing note.

**What shipped:** `org.bouncycastle.pqc.jcajce.provider.HQC`'s `Mappings.configure()` (read in
full) registers both the family-generic `"HQC"` string and the qualified `"HQC-128"/"HQC-192"/
"HQC-256"` spellings across `KeyPairGenerator`, `KEM`, and `Cipher` — the same breadth ML-KEM
already gets in `java.toml`. Twelve new classify arms (`CRYPTO-1002`–`1013`, four per API × three
APIs) close it: the three qualified names map directly to new `hqc-128`/`hqc-192`/`hqc-256`
algorithm-table rows, and the generic `"HQC"` name degrades to a new `hqc-unattributed` sentinel
(mirroring `CRYPTO-782`'s SLH-DSA family-generic treatment) rather than falling through to the
pre-existing `jca-unattributed`/`ml-kem-unattributed` catch-alls, which would have named the wrong
family. All three extract queries already existed and already captured the literal generically —
TOML-only change, no `scanner.rs` change. `algorithm-table.toml` gained `hqc-128`/`192`/`256`/
`-unattributed` rows, `family = "PQC-candidate"` (no FIPS number exists for HQC yet, selected
2025-03-11), which `cbom/src/emit.rs`'s existing `canonicalize_family` already omits from CycloneDX
1.7's `algorithmFamiliesEnum` — no emitter change needed, confirmed by the existing `kem-unattributed`/
`sig-unattributed` rows sharing the same family string.

**Corpus effect: 0 findings, either side — verified as a real zero against a real, non-fixture
call site, not an untested assumption.** `bcpkix-jdk18on`'s own vendored test suite,
`pkix/src/test/java/org/bouncycastle/cert/cmp/test/PQCTest.java:776`, calls exactly
`KeyPairGenerator.getInstance("HQC", "BCPQC")` followed by `kybKpGen.initialize(HQCParameterSpec.
hqc128)` one line later — read directly from the vendored clone, not assumed from the filing's
citation. Scanning that file directly with the post-change binary fires `CRYPTO-1009`
(`hqc-unattributed`) at line 776 exactly as expected. The corpus dump shows 0 because
`benchmarks/corpus-b-realworld/ecosystems/maven/bcpkix-jdk18on.toml`'s `scan_hints.exclude_paths =
["pkix/src/test/"]` excludes the file entirely — the same "real site outside `scan_hints`" shape
`#Y29`/`#Y44`/`#Y74(b)` already documented. Coverage also verified against a planted fixture
(`tests/fixtures/java/Pqc.java`, `cargo test scans_java_pqc_keypairgenerator_and_signature_and_kem`),
which now asserts all four new HQC arms alongside the existing ML-KEM/ML-DSA/SLH-DSA cases.

**Precision 97.12% (`bin/precision.py work/y80_pre.json work/y80_post.json --write-readme`), held —
0 findings added, 0 removed, dumps row-identical.** The published anchor was 97.15%; the 0.03pp gap
is the same pre-existing `OPEN-ASK #CORPUSDRIFT` `#Y74(b)` already measured on this exact pair of
dumps (corpus total 1811 → 1970 between that cycle's post-dump and this cycle's pre-dump, both
built from the same commit range) — not this change's effect, since the finding-set identity check
means nothing in the diff could have moved it. `--write-readme` applied the honestly-measured
figure: 97.15% → 97.12%, CI low 95.9% → 95.8%, corpus total 1811 → 1970.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--release --all-targets -- -D warnings` clean; `cargo test --release --workspace` all passing (141
tests in `scan_test.rs`, one extended: `scans_java_pqc_keypairgenerator_and_signature_and_kem` now
asserts 11 rule/algorithm-id pairs, up from 7). Both trust-invariant tests
(`test_network_disabled_error`, `test_run_acvp_kats_rejects_code_execution`) untouched and pass.

**Not done, said out loud:** the two-hop trace from `KeyPairGenerator.getInstance("HQC", ...)`
through a later `.initialize(HQCParameterSpec.hqc128)` call — which would resolve the generic
`"HQC"` site to its actual parameter set rather than `hqc-unattributed` — is not built here; no
such cross-statement trace exists anywhere in `java.toml`/`scanner.rs` today (EC's own curve is
left similarly unattributed for the identical reason), and building one is a larger scanner change
than this item's scope, matching how `#Y80`'s own filing scoped its "first concrete change." BC's
other fourth-round PQC-candidate providers (BIKE, Classic McEliece) are untouched — the filing
checked only HQC's own shape. `#ESTIMATOROFRECORD` applied 2026-08-30 (`state/precision.json`'s `estimator_by`
field); `#ESTIMATOR1` was superseded and resolved via `#ESTIMATOR2`. `OPEN-ASK
#CORPUSDRIFT` remains open, not this cycle's to resolve.

## `#Y81`: BouncyCastle BIKE/Classic McEliece JCA coverage (2026-08-30)

Tuple, per `#S12`: **corpus B (150 projects) · scanner set `--source --deps --include-safe` ·
profile `nist-default` · pre-change binary built from commit `43c7b54` in a throwaway worktree ·
post-change binary from this cycle's tree · dumps `work/y81_pre.json` ↔ `work/y81_post.json`, both
1811 findings, taken back-to-back against the same corpus-clones state to rule out
`OPEN-ASK #CORPUSDRIFT` rather than reuse a same-day dump from a prior cycle.**

**What shipped:** `#Y80`'s own closing note named the gap directly — BC's other fourth-round
PQC-candidate providers (BIKE, Classic McEliece) were untouched. `org.bouncycastle.pqc.jcajce.
provider.BIKE` registers the qualified `"BIKE128"/"BIKE192"/"BIKE256"` strings under
`Cipher.getInstance` and the family-generic `"BIKE"` string under both `Cipher.getInstance` and
`KeyPairGenerator.getInstance` (no `KEM.getInstance` registration exists for BIKE, unlike HQC/CMCE).
`org.bouncycastle.jcajce.provider.asymmetric.CMCE` registers 16 base parameter sets × 2 name
variants across `KeyPairGenerator`, `Cipher` and (JDK 21+) `KEM.getInstance`, plus the
family-generic `"CMCE"` string — 32+ distinct literal names. Given near-zero measured corpus
prevalence, Classic McEliece ships one family-level sentinel (`classic-mceliece-unattributed`)
matching any of them rather than 32 per-parameter rows, the same "resolve by hand once a family
matters enough for its own row" deferral `#Y80`'s own `hqc-unattributed`/`kem-unattributed` rows
already use. Seven new classify arms (`CRYPTO-1014`–`1020`) and four new `algorithm-table.toml`
rows (`bike-128`/`192`/`256`/`-unattributed`, `classic-mceliece-unattributed`), `family =
"PQC-candidate"` (neither has a FIPS number or OID — both are unselected 4th-round candidates,
HQC was picked as the backup KEM 2025-03-11), matching the existing `kem-unattributed`/
`sig-unattributed` family string `cbom/src/emit.rs`'s `canonicalize_family` already omits from
CycloneDX 1.7's `algorithmFamiliesEnum` — no emitter change needed. Coverage verified against a
planted fixture (`tests/fixtures/java/Pqc.java`, `cargo test
scans_java_pqc_keypairgenerator_and_signature_and_kem`), now asserting 15 rule/algorithm-id pairs
(up from 11).

**Corpus effect: 0 findings, either side.** The dump diff between `y81_pre.json` and
`y81_post.json` shows 0 added, 0 removed, dumps row-identical — expected, since BIKE and Classic
McEliece are both unselected 4th-round candidates with materially lower real-world adoption than
HQC (the standardized backup), and the corpus's one BouncyCastle project
(`bcprov-jdk18on`/`bcpkix-jdk18on`) does not call either provider anywhere in its own source,
including its vendored test suite. Not measured elsewhere in the corpus either, so this is a
genuine zero, not a `scan_hints`-excluded site the way `#Y80`'s HQC finding was.

**Precision 97.15% (`bin/precision.py work/y81_pre.json work/y81_post.json --write-readme`), held —
0 findings added, 0 removed, dumps row-identical.** This pair was taken back-to-back today rather
than reusing `#Y80`'s `y80_post.json` (which the README already flags as 1970 findings, not
today's 1811) specifically to avoid re-measuring across the drift `#Y74(b)`/`#Y80` both hit.
`--write-readme` applied the honestly-measured figure: 97.12% → 97.15%, CI low 95.8% → 95.9%,
corpus total 1970 → 1811 (audited-row count and date unchanged — the drift moves the denominator,
not the sample, same as every prior cycle that has hit this).

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--release --all-targets -- -D warnings` clean; `cargo test --workspace` all passing (141 tests in
`scan_test.rs`, one extended: `scans_java_pqc_keypairgenerator_and_signature_and_kem` now asserts
15 rule/algorithm-id pairs, up from 11). Both trust-invariant tests
(`test_network_disabled_error`, `test_run_acvp_kats_rejects_code_execution`) untouched and pass.

**Not done, said out loud:** the two-hop trace resolving BIKE's family-generic
`KeyPairGenerator.getInstance("BIKE", ...)` back to its actual size via a later
`Cipher.getInstance("BIKE128")` call is not built, same standing gap `#Y80` already named for HQC
— no cross-statement trace exists anywhere in `java.toml`/`scanner.rs` today. Classic McEliece's
32+ parameter sets are not individually attributed, per this entry's own stated policy.
`#ESTIMATOROFRECORD` applied 2026-08-30 (`state/precision.json`'s `estimator_by`
field); `#ESTIMATOR1` was superseded and resolved via `#ESTIMATOR2`. `OPEN-ASK
#CORPUSDRIFT` remains open, not this cycle's to resolve.

## `#Y83`: BouncyCastle XMSS/XMSS^MT (NIST SP 800-208 stateful hash-based signatures) gain coverage — 2026-08-31

Self-filed and shipped in the same cycle, from the closed-enumeration sweep's own methodology
(`#Y58`–`#Y64`, `#Y78`/`#Y79`) applied to a family the sweep never reached: `algorithm-table.toml`
has carried `lms`/`hss`/`xmss`/`xmss-mt` rows since the CNSA 2.0 policy work, each with an
`undetectable` reason naming a missing X.509 OID — but `grep -c` against every `data/rules/*.toml`
showed **zero** classify rules anywhere naming any of the four ids. Unlike BIKE/CMCE/HQC (unselected
or newly-selected 4th-round PQC candidates), XMSS and single-tree LMS are **already NIST-approved**
(RFC 8391/RFC 8554, NIST SP 800-208) and CNSA 2.0-approved for firmware/software signing — a
standardized algorithm family with no detection path at all, ranked above another PQC-candidate
filler for that reason.

**What shipped, and what did not.** BouncyCastle's vendored `LMS.java`/`XMSS.java` (read directly
from the corpus's own `maven/bcprov-jdk18on` clone) show the JCA `KeyPairGenerator`/`Signature`
service name **"LMS" is registered once for both single-tree LMS and multi-tree HSS keys** — HSS is
selected later via a `LMSHSSKeyGenParameterSpec` passed to `.initialize()`, a call this table cannot
trace across statements — so shipping either `lms` or `hss` for a bare `getInstance("LMS")` call
would risk exactly the misattribution class `#S2`'s
`classify_rules_never_publish_a_parameter_their_when_clause_contradicts` gate exists to catch (even
though that specific gate does not check this pair). LMS/HSS is therefore left unclassified, named
here rather than silently skipped. XMSS has no such ambiguity: **"XMSS" and "XMSSMT" are two
distinct, unambiguous JCA service names**, and BC's low-level API (`org.bouncycastle.pqc.crypto.xmss`)
has two distinct classes, `XMSSSigner`/`XMSSMTSigner`, mirroring `#Y66`'s `DilithiumSigner`/
`SPHINCSPlusSigner` shape exactly. Two new `JAVA_CTOR_APIS` entries (`scanner.rs`) plus 14 new
`java.toml` classify arms: 2 low-level ctor arms (`CRYPTO-1033`/`1034`), 2 `KeyPairGenerator`
arms (`CRYPTO-1021`/`1022`), and 10 `Signature.getInstance` arms (`CRYPTO-1023`–`1032`, the bare
names plus the four digest-qualified names — `XMSS-SHA256`/`SHAKE128`/`SHA512`/`SHAKE256` and their
`XMSSMT-` siblings — BC registers directly). **Not done, named rather than silently skipped:** BC
also registers a `<DIGEST>WITHXMSS(MT)` alias family and the fully-qualified
`<DIGEST>WITHXMSS(MT)-<DIGEST>` names those resolve to; enumerating that alias set correctly is a
`#Y61`-sized job of its own, not a quick addition to this one. Two new fixture call sites each in
`tests/fixtures/java/BcLightweight.java` (ctor forms) and `tests/fixtures/java/Pqc.java` (JCA
forms), extending `scans_java_bouncycastle_lightweight_pqc_classes` 12→14 expectations and
`scans_java_pqc_keypairgenerator_and_signature_and_kem` 15→19.

**The reachability gate caught a real staleness this cycle introduced, not a pre-existing one.**
`algorithm_reachability.rs`'s `every_algorithm_id_is_emitted_or_says_why_not` failed on the first
build: making `xmss`/`xmss-mt` reachable left their `undetectable = "As lms — no vendored OID."`
rows stale (direction 2 — "no row carries an `undetectable` reason once something emits it"). Fixed
in the same commit by removing the field from both rows and recording how each is now reached;
`lms`/`hss`'s own `undetectable` reasons are untouched and still accurate.

**Corpus effect: 26 findings added, 0 removed, 0 reclassified — all `CRYPTO-1033`/`1034`, all in
`maven/bcprov-jdk18on`'s own vendored source, all hand-verified true positive by opening the cited
line.** Every one is a real `new XMSSSigner()`/`new XMSSMTSigner()` inside BC's own XMSS/XMSSMT
signing implementation (`core/.../xmss/XMSS.java:179,217`, `XMSSMT.java:116,154`) and its 12
prehash/no-prehash `SignatureSpi` nested-class constructors (`XMSSSignatureSpi.java`,
`XMSSMTSignatureSpi.java`) — genuinely instantiates a live signer object in every case, no test
mock or assertion-required-to-fail shape among them. **26 TP, 0 FP.** None of the 10
`Signature.getInstance`/`KeyPairGenerator.getInstance` JCA arms fired — no corpus project calls
either service by name — the same "coverage without corpus demand" shape as `#Y43`/`#Y51`/`#Y55`/
`#Y58`/`#Y61`/`#Y63`/`#Y66`.

**Precision 97.15% → 97.25% (`bin/precision.py work/xmss_pre.json work/xmss_post.json --added-tp 26
--added-fp 0 --write-readme`).** Fresh (97.253%) and carried (97.252%) stratified estimators agree
to within 0.001pp; pooled Wilson reads 97.277%. `bin/precision.py` reports the delta landing
entirely in stratum B — `bcprov-jdk18on` is one of the 46 restored projects (same stratum `#Y59`'s
`CompositeMLKEMEngine.java` finding landed in); the 26 are appended directly to the existing audited pool
rather than re-stratified — sample A 262/271, B 381/390, fresh populations A=797/B=1040 — the same
upward-bias caveat every coverage-add cycle in this log carries. `--write-readme` applied: figure
97.15%→97.25%, CI 95.9–98.4%→96.0–98.5%, audited 635→661, corpus total 1811→1837, measured date
2026-08-30→2026-08-31.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--release --all-targets -- -D warnings` clean; `cargo test --release --workspace` all passing (141
tests in `scan_test.rs`, two extended; the reachability gate — `every_algorithm_id_is_emitted_or_says_why_not`,
`every_emitted_id_resolves_to_a_table_row`, `no_emitter_exists_outside_the_enumerated_set` — all
exercised and clean after the `algorithm-table.toml` fix above). Both trust-invariant tests
(`test_network_disabled_error`, `test_run_acvp_kats_rejects_code_execution`) untouched and pass.

**Not done, said out loud:** LMS/HSS remain unclassified for the call-site ambiguity reason given
above — the two-hop trace from `getInstance("LMS")` to a later `LMSHSSKeyGenParameterSpec` would
resolve it, the same structural gap `#Y80`/`#Y81` already named for HQC/BIKE's own generic-name
cases. The `<DIGEST>WITHXMSS(MT)` alias family is a real, smaller remaining gap, named above.
`#ESTIMATOROFRECORD` applied 2026-08-30 (`state/precision.json`'s `estimator_by`
field); `#ESTIMATOR1` was superseded and resolved via `#ESTIMATOR2`. `OPEN-ASK
#CORPUSDRIFT` remains open, not this cycle's to resolve.

## `#Y86`: pyca `MLDSAMuHasher` (FIPS 204 external-mu incremental hashing) gains coverage — 2026-08-31

Backlog item filed by the ecosystem lens: pyca/cryptography 50.0.0 shipped `MLDSAMuHasher`
(`cryptography.hazmat.primitives.asymmetric.mldsa`), the library's own implementation of FIPS 204's
external-mu mode — the same feature `#Y85` found missing from OpenSSL's `EVP_MD_fetch("ML-DSA-MU")`.
`python.toml`'s existing `PY-081`/`CRYPTO-823`–`825` arms cover `MLDSA*(Private|Public)Key.generate`/
`from_seed_bytes`/`from_public_bytes`, all class-name-qualified static-method calls; `MLDSAMuHasher`
is a direct constructor call instead (`MLDSAMuHasher(public_key)` / `mldsa.MLDSAMuHasher(public_key,
context)`, both spellings confirmed against pyca's own `docs/hazmat/primitives/asymmetric/mldsa.rst`
and `tests/hazmat/primitives/test_mldsa.py` in this project's own corpus-B clone), and had zero rules
for either spelling.

**What shipped.** Two new `PYTHON_CALLEE_APIS` entries (`scanner.rs`) — `MLDSAMuHasher` and
`mldsa.MLDSAMuHasher`, the same "module-qualified and bare-imported" pairing every other
`mlkem`/`mldsa` entry already uses, since `match_call`'s callee text is the literal source span of
the call's `function` node regardless of node shape. One new extract (`PY-082`) and one classify
arm (`CRYPTO-1035`), degrading to `ml-dsa-unattributed` — the parameter set lives in the
`public_key` argument's runtime type, which this table does not trace, the identical reasoning
`csharp.toml`'s `MLDsa.ImportPkcs8PrivateKey`/`ImportSubjectPublicKeyInfo`/`ImportFromPem` arms
already use for the same "encoded elsewhere" shape. Fixture: `tests/fixtures/python/pqc_native.py`
gained both spellings; `scans_python_pqc_native_mlkem_mldsa` extended 6→8 expected PQC findings.

**Corpus effect: 0 added, 0 removed, 0 reclassified — dumps byte-identical, 1837 findings both
sides.** `crypto-adjacent/pyca-cryptography`'s own `scan_hints.scan_paths` is
`["src/cryptography/hazmat/primitives/", "src/rust/src/"]` with `exclude_paths = ["tests/"]`; the
library's only real `MLDSAMuHasher(...)` call sites are in `tests/hazmat/primitives/test_mldsa.py`,
outside scan scope, and `src/cryptography/hazmat/primitives/asymmetric/mldsa.py`'s own reference
(`MLDSAMuHasher = rust_openssl.mldsa.MLDSAMuHasher`) is an assignment, not a call. Coverage verified
against the fixture only, same "coverage without corpus demand" shape as `#Y43`/`#Y51`/`#Y55`/`#Y83`
— expected in advance, not a surprise found after the fact.

**Precision 97.25% -> 97.16%, and this fall is not attributable to this change.**
`bin/precision.py work/mu_pre.json work/mu_post.json --write-readme` (pre built from `4be3eb7`, post
from this cycle's tree; both dumps 1837 findings, 0 added/removed) reproduces the same 97.159%
whether run on the pre or the post dump — the number cannot have moved because of this diff, since
there is no diff in the finding set for it to move on. The fall is `state/estimator.json` reading
`b_tp: 355`, not `bcprov-jdk18on`'s `#Y83`-audited `381` (see its entry above: "sample A 262/271, B
381/390"). `state/estimator.json` is harness state outside this repo's git tree, hand-edited on a
documented convention (six prior entries, most recently `#Y70`) — this cycle did not hand-edit it,
because `OPEN-ASK #ESTIMATORPERSIST` (filed 2026-08-31, unresolved as of this commit) is already
adjudicating exactly this drift, across three coverage cycles (`#Y73`, `#Y74`, `#Y83`) whose real,
audited TPs were never folded back into the persisted sample. Overwriting the ask's own working
number without its answer would be a second guess, not a fix. `gate_precision`'s regression
tolerance is 0.5pp; this cycle's -0.09pp is within it and the gate reads it as held, not regressed.
`gate_published_figure` requires the README figure to equal the reported one exactly, so
`--write-readme` was run and README now states 97.16% / 635 audited findings — a real drop in the
*displayed* audited-sample size from 661, not because any evidence was un-audited, but because the
persisted state the tool reads from does not yet contain three cycles' worth of already-published
folds. Full corroborating detail (population math, exact stale-vs-correct sample counts) added to
`OPEN-ASK #ESTIMATORPERSIST` in the vault backlog this cycle, without answering it.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--release --all-targets -- -D warnings` clean; `cargo test --workspace` all passing (141 tests in
`scan_test.rs`, one extended). Both trust-invariant tests (`test_network_disabled_error`,
`test_run_acvp_kats_rejects_code_execution`) untouched and pass. `readme_rule_pack_counts` (the
build gate `#Y76`/cycle 66 added) required a same-diff update: 115→116 extract blocks, 689→690
classify arms.

**Not done, said out loud:** `#Y85` (OpenSSL `EVP_MD_fetch`'s `"ML-DSA-MU"` pseudo-digest, the same
FIPS 204 external-mu feature on the C++ side) is unclaimed follow-up, not in this cycle's scope —
it requires a new `[[extract]]` shape (`EVP_MD_fetch`'s string-literal second argument) that this
cycle did not build. `OPEN-ASK #ESTIMATORPERSIST` remains open; this cycle strengthens its evidence
but does not answer it.

## `#Y85`: OpenSSL `EVP_MD_fetch` (fetch-by-name digest API, plus FIPS 204's `"ML-DSA-MU"` pseudo-digest) gains coverage — 2026-08-31

Picked up as `#Y86`'s own named follow-up: OpenSSL 4.0.0 (2026-04-14) added `EVP_MD_fetch(libctx,
name, propq)`, the documented fetch-by-name replacement for the typed
`EVP_DigestInit_ex(ctx, EVP_sha256(), ...)` form `cpp.toml` already covers (`CRYPTO-420`–`428`), and
overloads the same entry point for a pseudo-digest: `EVP_MD_fetch(libctx, "ML-DSA-MU", propq)`
computes FIPS 204's external-mu message representative for HSM-split ML-DSA signing. Confirmed
before touching anything: `grep -n "EVP_MD_fetch" crates/core/data/rules/cpp.toml` returned no
output — zero coverage, classical or PQC, for a call shape 130 files in this project's own vendored
`crypto-adjacent/openssl` clone use with a literal string name, including
`crypto/ml_dsa/ml_dsa_key.c` and `crypto/slh_dsa/slh_dsa_key.c`.

**What shipped.** One new `[[extract]]` (`CPP-069`), matching `EVP_MD_fetch`'s second argument as a
string literal — the identical shape `CPP-064`'s `EVP_PKEY_CTX_new_from_name` already uses, arg
position 1 (0-indexed) of the same 3-argument `(libctx, name, propq)` OpenSSL 3.0+ fetch-API
signature. Ten new classify arms (`CRYPTO-1036`–`1045`): nine reuse the algorithm ids
`EVP_DigestInit_ex`'s existing digest coverage already established (md5, sha-1, sha-224, sha-256,
sha-384, sha-512, sha3-256, sha3-384, sha3-512), reworded to name the actual call site
(`EVP_MD_fetch("{alg}")`) rather than copying `EVP_DigestInit_ex`'s message text onto a different
API verbatim — a wrong-attribution defect P0's "no wrong finding on a real file:line" bar exists to
catch, not a corner worth cutting for a shorter diff. The tenth (`CRYPTO-1045`) degrades
`"ML-DSA-MU"` to `ml-dsa-unattributed`, the same graceful-degradation convention `#Y86`'s
`MLDSAMuHasher` arm and `csharp.toml`'s `MLDsa.Import*` arms already use: the parameter set is
carried by the signing/verification context this call site does not expose. `scanner.rs` gained the
matching `C_CALLEE_APIS` entry and a `populate_args` arm (arg 1, same as `EVP_PKEY_CTX_new_from_name`
and `EVP_SIGNATURE_fetch`). Fixture: `tests/fixtures/cpp/crypto.c` gained an `openssl_md_fetch`
function (MD5, SHA1, SHA256, SHA3-512, ML-DSA-MU); new test `scans_c_openssl_md_fetch` in
`scan_test.rs` (141→142).

**Corpus effect: 16 added, 0 removed, 0 reclassified** (`work/y85_pre.json` 1837 →
`work/y85_post.json` 1853; pre-change binary built from `6af6b0c`, post-change binary from this
cycle's tree). All 16 land in `crypto-adjacent:github.com/openssl/openssl` (24 → 40 findings),
every one hand-verified against the corpus clone: 6 `CRYPTO-1037` (sha-1) in `ocsp_srv.c`,
`x509_cmp.c`, `srp_lib.c` (×2), `rsa_enc.c`; 6 `CRYPTO-1039` (sha-256) in `rsa_pk1.c`, `rsa_ossl.c`,
`ts_rsp_sign.c`, `quic_record_util.c`, `self_test_kats.c`, `scrypt.c`; 2 `CRYPTO-1041` (sha-512) in
`bn_rand.c`, `ecx_kmgmt.c`; 1 `CRYPTO-1042` (sha3-256) and 1 `CRYPTO-1044` (sha3-512), both in
`ml_kem.c`. Every cited line is a genuine `EVP_MD_fetch(ctx, "<NAME>", ...)` call with a literal
digest name — real coverage, not a rule tautologically matching its own fixture. No `"ML-DSA-MU"`
finding: this corpus's pinned OpenSSL checkout does not yet call `EVP_MD_fetch` with that name
anywhere in-tree, a genuine zero (checked, not assumed) reported per rule 5, not implied as
recall. `SN_md5`/`OSSL_DIGEST_NAME_MD5` macro-argument forms (also present in `x509_cmp.c`) do not
fire — out of scope, same literal-string-argument limitation `EVP_PKEY_CTX_new_from_name` already
has.

**Precision 97.16% -> 97.22%** (`bin/precision.py work/y85_pre.json work/y85_post.json --added-tp 16
--added-fp 0 --write-readme`). `--write-readme` applied: headline 97.16%→97.22%, CI 95.9–98.5%→
96.0–98.5%, audited findings 635→651 of 1837→1853, comparison table row and the classify-arm-count
sentences (117 extract / 700 classify total; C/C++ 114→124) all updated in the same diff.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--release --all-targets -- -D warnings` clean; `cargo test --workspace` all passing (142 tests in
`scan_test.rs`, one new). Both trust-invariant tests (`test_network_disabled_error`,
`test_run_acvp_kats_rejects_code_execution`) untouched and pass. `readme_rule_pack_counts` (the
build gate `#Y76`/cycle 66 added) required the same-diff update it exists to force.

**Not done, said out loud:** `OPEN-ASK #ESTIMATORPERSIST` is unresolved and not this cycle's to
touch (`bin/precision.py` is outside this track's write authority) — this cycle's `--added-tp 16`
run folds cleanly on top of whatever base `state/estimator.json` currently holds, so it neither
worsens nor resolves the ask. The `SHAKE128`/`SHAKE256` `EVP_MD_fetch` names seen live in
`ml_kem.c` alongside the two SHA3 calls that did fire are not covered — no existing algorithm-table
id for bare SHAKE as a digest — left as a smaller possible follow-up, not filed as its own item
absent a second corpus site.

## `#Y84`, README benchmark table re-run — docs/artifact-only, no `PRECISION:` line

No source, rule, or gate touched. `README.md:179`'s "Benchmark numbers" table still read **1056**
total findings and a 2026-08-29 wall-clock, while the precision paragraph 38 lines below (kept
current by `bin/precision.py --write-readme` on every coverage cycle) had climbed to **1853** —
`#Y84`, filed 2026-08-31 and re-evidenced the same day after two more coverage cycles (`#Y85`,
`#Y86`) landed on top of it un-refreshed, widening the gap 74% → 75.5%. Root cause, per the
filing: ten commits since the 08-29 table run each correctly advanced the precision paragraph,
none re-ran the table, and nothing greps the two against each other.

**What ran, in the foreground, per `#Y84`'s own "first change" spec:** `scan_corpus.py --clones
/opt/cryptoscope/work/corpus-clones --include-safe` (277.3s, 149/150 projects, one `unscannable`),
then `dump_findings.py --clones /opt/cryptoscope/work/corpus-clones` to regenerate the committed
`results/all_findings.json` independently — both against the release binary built from this
cycle's tree (`2ba189c`, unchanged by this diff). **Both agree at 1853**, matching the precision
paragraph's already-published denominator exactly; this diff does not change what quipuu detects,
only what the table reports about the same corpus the paragraph already describes.

**Table replaced wholesale, not patched:** total findings 1056→1853, wall-clock 230.0s→277.3s,
median 170ms→205ms, mean 1532ms→1847ms, p90 1.35s→1.23s, max 111.0s→149.6s (still `aws-sdk-go-v2`,
still the same three-repository shape behind the mean/median gap — `aws-sdk-go-v2` 149.6s,
`aws-sdk-go` 31.1s, `wolfssl` 15.4s, 70.8% of total wall-clock; 129/150 projects finish under a
second, was 132/150). **Every other copy of the same two numbers grepped and fixed in the same
diff, per rule 4** — the README's own lede (`Median project scans in 170ms; the mean is 1532ms`)
and the comparison table's `Scan speed` row both quoted the same stale pair and are now 205ms/
277s. `llms.txt`/`llms-full.txt` carry no copy of either figure — checked, not assumed.

**Precision: no claim, no `PRECISION:` line.** Nothing in `crates/` or `crates/core/data/rules/`
changed; the 97.22% headline and its 651-of-1853 audited sample are untouched by this diff and
were already current before it ran — `#Y84`'s gap was between two numbers *in the same document*,
not between the published figure and reality. Re-running `bin/precision.py` over two identical
dumps would measure nothing this diff did not already prove: the finding population is 1853 either
side, because no side is different.

**Held:** `cargo build --release --workspace` clean; `cargo test --release --workspace` all
passing (142 `scan_test.rs` cases, unchanged). Both trust-invariant tests untouched and pass.
`readme_rule_pack_counts` unaffected — extract/classify counts unchanged. No gate reads the
benchmark table's own numbers today (grepped for one; none exists), which is exactly the process
gap `#Y84` diagnosed — left as a follow-up rather than built here, to keep this change the same
size as the one it fixes.

## `#Y87`: .NET `MLKemCng`/`MLDsaCng` (Windows-CNG-backed PQC wrappers) gain coverage — 2026-08-31

Tuple: **corpus B (150 projects) · scanner set `--source --deps --include-safe` · profile
`nist-default` · pre-change dump `work/y85_post.json` (1853, `2ba189c`, unchanged by this diff) ·
post-change binary from this cycle's tree · dump `work/y87_post.json` (1853).**

**What shipped.** `#Y51` named `MLKemCng`/`MLKemOpenSsl` as a known-open remainder but never
verified their constructor shape. Independently confirmed this cycle: `MLKemCng` is a
`sealed class MLKemCng : MLKem` with exactly one constructor, `MLKemCng(CngKey)` — the
algorithm/parameter set lives on the `CngKey` argument, not the constructor call, the same
receiver-carries-the-identity shape `#Y86`'s `MLDSAMuHasher` and Java's `Signature`/
`KeyPairGenerator` operation classes already degrade gracefully for. `MLDsaCng(CngKey)` has the
identical shape. `csharp.toml` had zero coverage for either — in fact zero coverage for any `*Cng`
class of any kind, classical or PQC, confirmed by grep before writing a rule. Two new
`[[extract]]`/`[[classify]]` pairs (`CSH-075`/`CRYPTO-1046`, `CSH-076`/`CRYPTO-1047`) match bare
`new MLKemCng(...)`/`new MLDsaCng(...)` construction with no argument inspection, emitting
`ml-kem-unattributed`/`ml-dsa-unattributed` with message text naming the CNG interop path
explicitly. `RSACng`/`DSACng`/`ECDsaCng` (classical CNG) are explicitly out of scope, kept as a
fixture control that must *not* fire. Because the extract layer's queries are not executed
(matching is a hand-written walker per `scanner.rs`), `CSHARP_CTOR_APIS` also gained the two new
`(class_name, api)` entries — the same two-sided change every prior `CSH-0xx`/`CRYPTO-10xx` ctor
rule in this file required, caught immediately by the new fixture returning nothing on first run.

**Corpus effect: 0 findings added, 0 removed, dumps byte-identical (1853 both sides) — a real
zero, not a `scan_hints`-excluded site.** Independently verified against a fixture instead
(`tests/fixtures/csharp/PqcNative.cs`, extended with `MlKemCng`/`MlDsaCng`/`RsaCngControl`
methods; `scans_csharp_native_mlkem_mldsa_slhdsa` extended to assert `CRYPTO-1046`/`CRYPTO-1047`
fire and that no finding's message contains `"RSACng"`). This project's `crypto-adjacent/`
corpus is Maven/npm/pip-weighted and contains no Windows-targeting C# project, so a zero corpus
delta was the stated expectation going in, not a surprise found after the fact.

**Precision 97.22% → 97.16% (`bin/precision.py work/y85_post.json work/y87_post.json
--write-readme`), and this diff caused none of it — a falsification, not a re-derivation.** 0
findings added, 0 removed, so no TP/FP ratio could have moved. The fall is `state/estimator.json`
never having persisted `#Y85`'s own `--added-tp 16` fold (`b_tp` still reads 355, not 371) —
exactly the gap `OPEN-ASK #ESTIMATORPERSIST` already names and the same shape `#Y86`'s cycle hit
one cycle before this one. `--write-readme` applied the honest figure: 97.22% → 97.16%, CI
96.0–98.5% → 95.9–98.5%, audited 651 → 635 (271 stratum A, 364 stratum B). The two prose sentences
describing sample composition (README.md, "What that interval is" / "What the denominator
excludes") were hand-corrected in the same diff per rule 4 — `--write-readme` only rewrites the
mechanical headline/CI/audited-count fields, not narrative prose quoting the prior cycle's
composition.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--release --all-targets --workspace -- -D warnings` clean; `cargo test --release --workspace` all
passing (142 `scan_test.rs` cases, one extended). Both trust-invariant tests untouched and pass.
`readme_rule_pack_counts` required updating 117→119 extract / 700→702 classify (total) and C#'s
115→117 (per-language); confirmed failing before the README fix, passing after, per "a gate that
cannot fail is not a gate."

**Not done, said out loud:** the Win32 CNG native layer (`BCryptGenerateKeyPair` against
`BCRYPT_MLKEM_ALG_HANDLE`) remains uncovered, per the second-pass synthesis's own finding that a
broader corpus check (beyond the one vendored `symcrypt` clone) found no literal call site —
blocked, not ready to build. `OPEN-ASK #ESTIMATORPERSIST` and `OPEN-ASK #CORPUSDRIFT` remain open,
neither this cycle's to resolve.

## `#Y77`: liboqs-go's `oqs.KeyEncapsulation{}`/`oqs.Signature{}` gain coverage — 2026-08-31

Picked as the highest-value unclaimed item: every other Track A candidate in the backlog was either
`needs-human-approval` (doc/policy items) or explicitly blocked pending a broader corpus (the Win32
CNG native layer, filed alongside `#Y87`). `#Y77` was the one remaining fully-specified, buildable
coverage item, filed by the ecosystem lens as "weakest-evidenced, lowest-ranked" specifically
because it had not yet been vendored and read directly — the filing's own first concrete change was
"vendor `liboqs-go` into `corpus-clones/crypto-adjacent/` ... before finalizing the capture query."
Done this cycle: `git clone --depth 1 --branch v0.16.0 https://github.com/open-quantum-safe/liboqs-go`
into `work/corpus-clones/crypto-adjacent/liboqs-go`, then `examples/kem/kem.go` and
`examples/sig/sig.go` read directly rather than trusted from the `pkg.go.dev` fetch the filing
quoted.

**What the vendored source actually shows, and why the filing's premise was half right.** liboqs-go
constructs a zero-value struct and initialises it on a separate statement:
`client := oqs.KeyEncapsulation{}` then `client.Init(kemName, nil)`, and both examples pass the
algorithm name as a variable (`kemName`/`sigName`), never a literal, at the `.Init` call site
itself. The filing characterised this as needing new "declared-receiver-type tracking" — the same
capability `OPEN-ASK #SIGNVERIFY` deferred as unbuilt. That capability is genuinely absent and
still is. But it is only needed to resolve the *algorithm name*, which lives on `.Init`, not on the
construction. The construction itself — `oqs.KeyEncapsulation{}` / `oqs.Signature{}`, a
`composite_literal` with a `qualified_type` whose package is `oqs` — is a strong, self-contained
signal with no other information needed, the same "flag the constructor, not the eventual algorithm"
degradation `#Y87`'s `MLKemCng`/`MLDsaCng` and `python.toml`'s own liboqs-python fallback rows
already use. So this ships the safe subset without building the deferred capability: `scanner.rs`
gained one new structural matcher (`match_go_oqs_construction`, hooked on Go's `composite_literal`
node kind) and two `STRUCTURAL_APIS` entries; `go.toml` gained two extract blocks (`GO-075`/`GO-076`)
and two classify arms (`CRYPTO-1048`/`CRYPTO-1049`), each unconditional (no `when.args` predicate —
there is no argument to read) emitting the generic `kem-unattributed`/`sig-unattributed` sentinel,
not `ml-kem-unattributed`/`ml-dsa-unattributed` — liboqs supports HQC, BIKE, Classic McEliece,
SPHINCS+, and more beyond ML-KEM/ML-DSA, and the construction site names none of them, so claiming
the narrower family would be exactly the "id asserts a parameter the call site never states" defect
`classify_rules_never_publish_a_parameter_their_when_clause_contradicts` exists to catch.

**Coverage verified against the vendored clone directly, not only a fixture — confirmed a real
detection, not a scan-scope artifact.** Scanning `work/corpus-clones/crypto-adjacent/liboqs-go`
directly with the post-change binary: **9 findings**, all real — both official examples
(`examples/kem/kem.go:18`, `examples/sig/sig.go:17`), the client/server KEM example
(`examples/client_server_kem/{client,server}_kem.go`, 3 sites), and liboqs-go's own test suite
(`oqstests/kem_test.go:147`, `oqstests/sig_test.go:345`) — every one a genuine `KeyEncapsulation{}`/
`Signature{}` construction, none inside a branch a test requires to fail. A new fixture
(`tests/fixtures/go/liboqs_go.go`, transcribed from the two official examples) and one new test
(`go_liboqs_go_construction_is_classified`) pin both rule/algorithm_id pairs.

**Corpus B effect: 0 findings, either side — the expected zero, not a surprise.** `liboqs-go` has no
entry in `benchmarks/corpus-b-realworld/manifest.toml` (unlike `liboqs`/`liboqs-python`, which
already do), so the 150-project corpus dump cannot see it regardless of this change; the filing's
own `grep -rl` across `go-modules/`'s 20 vendored projects already established zero prevalence
there too. Adding `liboqs-go` as a 151st corpus project is a separate, larger decision (a new
manifest entry, a pinned commit, `scan_hints`) this item's own filing did not ask for — the vendored
clone under `crypto-adjacent/` exists to verify the rule against real source, the same role
`liboqs`/`liboqs-python`'s clones already serve, not to add corpus coverage.

**Precision 97.16%, held exactly — a falsification, not a re-derivation, and a second, unrelated
bug caught in the process.** First pass used `work/dump_findings_flags.py` (the same scratch script
several recent cycles cite) and got **2012 findings both sides**, which looked like a 159-finding
`OPEN-ASK #CORPUSDRIFT` jump against the published 1853 — until `benchmarks/corpus-b-realworld/
scan_corpus.py` was run against the same binary and same `--clones` root and returned **1853**, not
2012, on an unchanged corpus. Diffing the two tools' per-project counts isolated the entire 159-row
gap to one project: `crates-io:rustls-pemfile`, a manifest entry `corpus-integrity.toml` and
`scan_corpus.py` both correctly mark `unscannable` — its pinned commit has no directory of its own,
its clone is the symlinked tree `crates-io:rustls` already scans (`README.md`'s own corpus-B note
states this) — but `work/dump_findings_flags.py` has no integrity check at all, so it fell through
to scanning *something* at that path and added 159 spurious rows no other tool would ever produce.
This is not a re-measurement of `#CORPUSDRIFT`; it is a distinct scratch-script defect that happened
to land in the same 159-row size class, caught here only because a second, independent tool was run
over the same binary instead of trusting the first number. Re-dumped with the repo's own
integrity-checked `dump_findings.py` instead (`work/y77_pre_clean.json` ↔ `work/y77_post_clean.json`,
pre-change binary built from commit `8296cdf` — `#Y87`'s own commit — in a throwaway worktree,
post-change binary from this cycle's tree): **1853 findings both sides, row-identical, 0 added, 0
removed** — matching `scan_corpus.py` exactly and matching the published anchor's own denominator
exactly, so `bin/precision.py work/y77_pre_clean.json work/y77_post_clean.json --write-readme`
reproduces **97.16%** (95% CI 95.9–98.5%) with no change to the figure, the interval, or the
corpus total. Fresh (97.163%), carried-constants (97.159%) and pooled Wilson (97.165%) estimators
agree within 0.006pp.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--release --all-targets --workspace -- -D warnings` clean; `cargo test --release --workspace` all
passing (143 `scan_test.rs` cases, one new). Both trust-invariant tests untouched and pass.
`readme_rule_pack_counts` required updating 119→121 extract / 702→704 classify (total) and Go's
93→95 (per-language) in the same diff — confirmed failing before the fix, passing after.

**Not done, said out loud:** the declared-receiver-type trace from `oqs.KeyEncapsulation{}`/
`oqs.Signature{}` to its later `.Init(name, ...)` call, which would resolve this past the generic
sentinel to a specific parameter set, is not built — the same standing capability gap `OPEN-ASK
#SIGNVERIFY` already named and deferred. `liboqs-go` is not added as a corpus B project, per the
scope note above. `work/dump_findings_flags.py`'s `rustls-pemfile` defect is not fixed — it is a
scratch script outside this repo, flagged here rather than silently worked around, and any cycle
still using it for a whole-corpus total should cross-check against `scan_corpus.py`/`dump_findings.py`
first. Checked rather than assumed whether this explains any prior `OPEN-ASK #CORPUSDRIFT` evidence:
`work/y74d_pre.json`/`y74d_post.json` (the dumps `#Y74(b)`'s own 1970→1811 jump cites) carry the
`{corpus, projects, findings}` shape only the canonical `dump_findings.py` produces, with
`rustls-pemfile` correctly recorded `unscannable`/0 findings in both — so that jump is not this bug,
and this cycle does not generalize its own finding beyond the one scratch-script run it caught it in.
`OPEN-ASK #ESTIMATORPERSIST` and `OPEN-ASK #CORPUSDRIFT` remain open, neither this cycle's to
resolve.

## Measurement, 2026-09-01 (Track A cycle 73 — Windows CNG native layer, `BCryptGenerateKeyPair`/
## `BCryptOpenAlgorithmProvider`/`BCryptImportKeyPair`/`NCryptIsAlgSupported` against ML-KEM/ML-DSA)

Tuple, per `#S12`: **corpus B (150 projects) · scanner set `--source --deps --include-safe` ·
profile `nist-default` · pre-change dump `work/y77_post_clean.json` (1853, matching commit
`52a567f`, unchanged by the intervening `1738dc3` docs-only test commit) · post-change binary from
this cycle's tree · dump `work/cng_post.json` (1853).**

**Picked as the item the Backlog's own blocking condition named:** every other remaining item was
`needs-human-approval` or an `OPEN-ASK` this track lacks authority to resolve. The Win32 CNG native
layer was filed "blocked, not ready-to-build" pending exactly one condition — "a corpus grep
broader than the single vendored `symcrypt` repo... returning at least one literal call site" —
and that condition is now met. A GitHub code search for `BCRYPT_MLDSA_ALGORITHM` (61 results, read
in full, not sampled) surfaced a real, independent, non-Microsoft call site: Chromium's own
`net/ssl/ssl_platform_key_win_unittest.cc` calls `NCryptIsAlgSupported(prov.get(),
BCRYPT_MLDSA_ALGORITHM, NCRYPT_SILENT_FLAG)` guarding its ML-DSA client-certificate test path
(`status = NCryptIsAlgSupported(...); if (status == NTE_NOT_SUPPORTED) GTEST_SKIP()...`), fetched
and read directly from `raw.githubusercontent.com`, not taken on the search snippet alone. A
parallel search for `BCRYPT_MLKEM_ALG_HANDLE` (25 results, also read in full) found none beyond
Microsoft's own docs/generated-bindings repos — confirming, not merely repeating, the original
symcrypt-only negative for the KEM side specifically.

**What shipped:** four `C_CALLEE_APIS` entries in `scanner.rs` (`BCryptGenerateKeyPair`,
`BCryptImportKeyPair`, `BCryptOpenAlgorithmProvider`, `NCryptIsAlgSupported`) plus matching
`cpp.toml` extract/classify pairs (`CPP-070`..`073`, `CRYPTO-1050`/`1051`). Scoping decision, stated
so a future cycle doesn't re-derive it: `BCryptGenerateKeyPair`/`BCryptImportKeyPair` classify only
when their algorithm-handle argument is literally `BCRYPT_MLKEM_ALG_HANDLE` (Microsoft's own
cng-mlkem-examples idiom — the ML-KEM pseudo-handle is passed directly, no separate
`BCryptOpenAlgorithmProvider` step); `BCryptOpenAlgorithmProvider`/`NCryptIsAlgSupported` classify
only when their algorithm-id argument is literally `BCRYPT_MLDSA_ALGORITHM` (cng-mldsa-examples,
and the Chromium call site). None of these four functions is PQC-specific — all four are the
general-purpose CNG entry points used constantly for classical algorithms — so every other
algorithm identifier passed through them is extracted but produces no classify match, the same
"extract broadly, classify narrowly" shape `EVP_PKEY_CTX_new_from_name`'s RSA/EC arms already use.
No `BCryptSetProperty(BCRYPT_PARAMETER_SET_NAME, ...)` trace to the specific parameter set — the
same "no argument inspection" scoping `#Y87`'s `MLKemCng`/`MLDsaCng` rule already used — so both
degrade to the `ml-kem-unattributed`/`ml-dsa-unattributed` sentinel. Verified against a new fixture
(`tests/fixtures/cpp/crypto.c`, four new functions transcribing Microsoft's own code samples and the
Chromium call shape) and a new test (`scans_c_windows_cng_mlkem_mldsa`), which also asserts the
fixture's classical `BCryptOpenAlgorithmProvider(&hRsaAlg, BCRYPT_RSA_ALGORITHM, ...)` sibling call
produces no finding.

**Corpus B effect: 0 findings, either side — the expected zero, not a surprise.** None of the 150
corpus projects, including the vendored `symcrypt`/`symcrypt-openssl` clones, call any of these four
functions with either PQC constant; Chromium and `dotnet/runtime` (the other real usage this cycle's
search surfaced, via C# CNG interop already covered by `#Y87`'s `MLKemCng`/`MLDsaCng` rule) are not
corpus B projects. `bin/precision.py work/y77_post_clean.json work/cng_post.json --write-readme`
reproduces **97.16%** (95% CI 95.9–98.5%) with 0 added, 0 removed — a falsification, not a
re-derivation, matching the same zero-corpus-effect shape `#Y77`/`#Y87` both had.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--release --all-targets --workspace -- -D warnings` clean; `cargo test --workspace` all passing
(144 `scan_test.rs` cases, one new). Both trust-invariant tests untouched and pass.
`readme_rule_pack_counts` required updating 121→125 extract / 704→706 classify (total) and C/C++'s
124→126 (per-language) in the same diff — confirmed failing before the fix, passing after.

**Not done, said out loud:** no `BCryptSetProperty` trace to the parameter set, per the scoping
decision above — a future cycle wanting 512/768/1024 or 44/65/87 attribution needs the two-call
trace the original filing described, which this cycle did not build. `BCryptEncapsulate`/
`BCryptDecapsulate` (named in the original filing alongside `BCryptGenerateKeyPair`) are not
covered — neither takes an algorithm argument of its own (the algorithm lives on the key handle
built earlier), the same shape `EVP_PKEY_encapsulate`/`decapsulate` already left as a stated gap
rather than a traced one. `NCryptImportKey`/`BCryptSignHash`/`BCryptVerifySignature` (also present
in the Microsoft examples and the Chromium test) are not covered — none names the algorithm in its
own arguments either. `OPEN-ASK #ESTIMATORPERSIST` and `OPEN-ASK #CORPUSDRIFT` remain open, neither
this cycle's to resolve.

## Measurement, 2026-09-01 (Track A cycle 74 — rcgen `generate_for` signature-algorithm recovery)

**Not new work — recovery of a lost commit.** `03-Product/Precision-Tracker.md`'s 2026-08-28
`#T2a`/`#T2b` entry describes a fix reading the rcgen `KeyPair::generate_for(SIG_ALG)` argument
instead of always publishing `ecdsa-unattributed`, built from tree range `e072c3e..6ed6e1f`. That
range was absent from `main` — `git merge-base --is-ancestor 6ed6e1f HEAD` failed, and `git fsck
--lost-found` found it dangling — the same vault/tree divergence pattern
[[cryptoscope-vault-tree-divergence]] already named: a cycle's commits recorded as done in the vault
while `main` had been reset behind them. `d39a09c` ("rules: read the rcgen signature algorithm
instead of assuming ECDSA") is the actual code commit; `6ed6e1f` is a benchmarks-only doc commit
whose own numbers describe a corpus state (1570 findings) this repo no longer has, so only
`d39a09c` was recovered, via `git cherry-pick -n d39a09c`, resolving one textual conflict in
`scanner.rs` (an adjacent, unrelated `match` arm added after `d39a09c` was cut — both arms kept,
no logic changed) and no conflict in `rust.toml` or the tests.

**The bug this restores a fix for:** `rcgen::KeyPair::generate_for(SIG_ALG)` selects ECDSA (three
curves), Ed25519, RSA (three digests) or ML-DSA (three parameter sets) from one associated
constant argument; the un-recovered code on `main` read only the callee name and always published
`ecdsa-unattributed`, so `generate_for(&rcgen::PKCS_ML_DSA_44)` — a site that has already migrated
to FIPS 204 — was reported as a quantum-vulnerable ECDSA finding. `rust_arg_const_name` (new,
`scanner.rs`) reads the constant's final path segment from `&rcgen::PKCS_ML_DSA_44`,
`rcgen::PKCS_ML_DSA_44` and a bare imported `PKCS_ML_DSA_44` alike, exposed as `sig_alg`; eleven new
`rust.toml` classify arms (`CRYPTO-571`–`579`, `588`, `589`) consume it, ordered before the
pre-existing `CRYPTO-570` fallback, which still fires — now correctly labelled — when the argument
is a variable, a field, or another form the matcher cannot read a name from. Fixture
`tests/fixtures/rust/rcgen_keypair.rs` and `rcgen_generate_for_reads_the_signature_algorithm_argument`
cover all eleven identified shapes plus three unresolvable ones.

**Tuple, per `#S12`: corpus B (150 projects) · scanner set `--source --deps --include-safe` ·
profile `nist-default` · pre-change dump `work/cng_post.json` (1853, matching commit `28e88c3`) ·
post-change binary from this cycle's tree · dump `work/rcgen_post.json` (1853).**

**Precision 97.16% → 97.17% (`bin/precision.py work/cng_post.json work/rcgen_post.json --added-tp 2
--added-fp 0 --write-readme`).** 0 call sites added or removed; **2 locations re-classified** (this
corpus's current state carries only 2 of the original 4 rcgen call sites the `#T2a` measurement
found — the other two are corpus drift, `OPEN-ASK #CORPUSDRIFT`, not this change's). Both are the
same source line in `crates-io/webpki` and `crates-io/rustls-webpki` (both vendor the same test
helper): `crates-io/webpki/src/trust_anchor.rs:145` and `crates-io/rustls-webpki/src/trust_anchor.rs:145`,
`KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)` — read directly, genuinely ECDSA P-256, so
`CRYPTO-570 ecdsa-unattributed → CRYPTO-575 ecdsa-p256` is a true-positive re-identification, not a
new detection. `bin/precision.py` reproduces the anchored 97.16% on the pre dump before printing
anything else; CI 95.9–98.5% unchanged, audited count 635 → 637.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--release --all-targets --workspace -- -D warnings` clean; `cargo test --release --workspace` all
passing (145 `scan_test.rs` cases, one recovered). Both trust-invariant tests untouched and pass.
`readme_rule_pack_counts` required updating 706→717 classify (total; extract unchanged at 125) —
confirmed failing before the fix, passing after.

**Not done, said out loud:** the twenty-six rcgen sites that still publish `ecdsa-unattributed`
from an argument the matcher cannot read (a local variable, a struct field, a re-exported alias)
remain unattributed by design — `rust_arg_const_name` returns `None` rather than guess, the same
"do not smuggle a number through a method change" discipline the estimator-of-record ask already
established. `6ed6e1f`'s own recorded gap — a family-agnostic marker for those twenty-six sites,
since one is demonstrably reachable for Ed25519 as well — is not built here either; it was that
commit's own stated future work, not part of the fix this cycle restored. `OPEN-ASK
#ESTIMATORPERSIST` and `OPEN-ASK #CORPUSDRIFT` remain open, neither this cycle's to resolve.

## Measurement, 2026-09-01 (Track A cycle 75 — .NET `SlhDsaCng` gains coverage, `#Y87`'s own
## direct sibling)

**What shipped.** `#Y87` (2026-08-31) shipped `MLKemCng`/`MLDsaCng` — .NET 10's Windows-CNG-backed
FIPS 203/204 wrapper classes — but its own filing only named those two, leaving FIPS 205's
identical CNG interop path, `SlhDsaCng`, uncovered. Confirmed via `learn.microsoft.com`'s
`SlhDsaCng` API page that it is the same shape: a sealed wrapper class whose algorithm/parameter
set lives on the `CngKey` constructor argument, not the call site. Shipped one `[[extract]]`/
`[[classify]]` pair (`CSH-077`/`CRYPTO-1052`) in `csharp.toml`, copy-pasted from `#Y87`'s
`MLDsaCng` pair with the class name and `slh-dsa-unattributed` swapped in — `slh-dsa-unattributed`
already exists in `algorithm-table.toml` (used by the existing `SlhDsa.ImportFromPem` rule), so no
new algorithm-table row was needed. Also added the identifier to `CSHARP_CALLEE_APIS` in
`scanner.rs` — the declarative `[[extract]]` query documents the shape but is not itself executed
(matching is a hand-written walker), and `every_classify_rule_targets_an_api_the_extractor_can_emit`
correctly failed the build until this was done, catching the omission rather than missing it.
Extended the `#Y87` fixture (`tests/fixtures/csharp/PqcNative.cs`) with `new SlhDsaCng(key)` and the
`scans_csharp_native_mlkem_mldsa_slhdsa` test with `("CRYPTO-1052", "slh-dsa-unattributed")`.

**Tuple, per `#S12`: corpus B (150 projects) · scanner set `--source --deps --include-safe` ·
profile `nist-default` · pre-change binary built from commit `249df5f` in a throwaway worktree ·
post-change binary from this cycle's tree · dumps `work/slhdsacng_pre.json` ↔
`work/slhdsacng_post.json`, both 1853 findings.**

**Precision held exactly, 97.16% — a falsification, not a re-derivation.** `bin/precision.py
work/slhdsacng_pre.json work/slhdsacng_post.json --write-readme` reports **0 findings added, 0
removed**: none of the 150 corpus projects (including vendored `microsoft/SymCrypt`) construct
`SlhDsaCng`, matching the expectation the synthesis note that surfaced this item stated in advance
(Windows-specific C#, under-represented in this corpus's Maven/npm/pip-weighted composition).
Coverage is verified against the fixture, not the corpus. Fresh (97.163%), carried-constants
(97.159%) and pooled Wilson (97.165%) estimators agree within 0.006pp, same spread as the prior
cycle's re-derivation.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--release --all-targets --workspace -- -D warnings` clean; `cargo test --workspace` all passing
(145 `scan_test.rs` cases, one new). Both trust-invariant tests untouched and pass.
`readme_rule_pack_counts` required updating 717→718 classify (total; extract 125→126) and C#'s
117→118 (per-language) — confirmed failing before the fix, passing after.

**Not done, said out loud:** the `BCryptSetProperty`/`NCryptImportKey` parameter-set trace named
in cycle 73's Win32 CNG entry is unrelated to this item and remains unbuilt for the same reason —
none of the three CNG wrapper classes carry the parameter set at the constructor call. No further
.NET CNG-backed PQC class is known to be missing after this; `RSACng`/`DSACng`/`ECDsaCng` remain
explicitly out of scope as classical. `OPEN-ASK #ESTIMATORPERSIST` and `OPEN-ASK #CORPUSDRIFT`
remain open, neither this cycle's to resolve.

## Measurement, 2026-09-01 (Track A cycle 77 — Go stdlib `crypto/mldsa`, `#V5`'s remaining half)

**What shipped.** `#V5` named two gaps: `crypto/mlkem` (shipped by `#Y30` part (a), already covered)
and its FIPS 204 sibling `crypto/mldsa` (Go 1.27), which had zero coverage in either `go.toml` or
`scanner.rs`. Unblocked this cycle because `#T3` (cycle 76) made `Severity::Safe` reachable — `#V5`
was explicitly sequenced behind it so a migrated codebase would not score worse than an unmigrated
one. Verified before writing any rule that the real-world call shape differs from `crypto/mlkem`'s:
`GenerateKey`/`NewPrivateKey`/`NewPublicKey`/`Verify` take a `Parameters` value as an argument
rather than baking the parameter set into the function name, and the only way to construct one is
`MLDSA44()`/`MLDSA65()`/`MLDSA87()` — checked against `lestrrat-go/jwx`'s real `crypto/mldsa`
integration (`jws/mldsa.go`, `jwk/mldsa.go`), which stores the `Parameters` value in a variable
and passes it on, never inlining the constructor inside `GenerateKey`. A query anchored on
`GenerateKey`'s argument list (the `crypto/mlkem` shape) would have missed every real site the
corpus has, so the rule keys on the `MLDSA44/65/87()` constructor call itself — one `GO_CALLEE_APIS`
row per parameter set (`crypto/mldsa.ParamSet`) plus a matching `[[extract]]`/`[[classify]]` triple
in `go.toml` (`GO-077`/`CRYPTO-1053..1055`), following the same reasoning circl's per-package rows
already use: the constructor call is the signal, not the operation it is later passed into.

**Caught by the corpus, not assumed:** boringssl's `ssl/test/runner` imports `"filippo.io/mldsa"`
under the local name `mldsa` — a third-party package with an identical API, predating the stdlib
one. The callee-text matcher cannot distinguish it from `crypto/mldsa`, so the classify messages
were written to assert the `algorithm_id` (correct either way — both packages genuinely construct
FIPS 204 ML-DSA-44/65/87 parameter sets) without claiming a specific import or Go version; the
first draft said "Go stdlib (1.27+)" unconditionally and was corrected before commit.

**Tuple, per `#S12`: corpus B (150 projects) · scanner set `--source --deps --include-safe` ·
profile `nist-default` · pre-change binary built from commit `d1c0e99` in a worktree · post-change
binary from this cycle's tree · dumps `work/v5_pre.json` (1853) → `work/v5_post2.json` (1911).**

**58 findings added, 0 removed, 0 reclassified** — `CRYPTO-1053` (ml-dsa-44) 18, `CRYPTO-1054`
(ml-dsa-65) 26, `CRYPTO-1055` (ml-dsa-87) 14, across two projects: `go-modules:lestrrat-go/jwx` (43,
its own `crypto/mldsa` integration, both production files and their tests) and
`crypto-adjacent:google/boringssl` (15, the `filippo.io/mldsa` sites above). **All 58 hand-labelled
by opening the cited `file:line`: 58 TP, 0 FP, 0 DEPENDS.** Every site is a real call to
`MLDSA44()`/`MLDSA65()`/`MLDSA87()` — key generation (`mldsa.GenerateKey(mldsa.MLDSA65())` in jwx's
tests), signer/verifier registration (`jws/mldsa.go`'s `init()`), and X.509 signature-algorithm /
OID dispatch (boringssl's `certs.go`) — none inside a branch a test requires to fail; the parameter-
set constructor is a pure accessor that cannot fail independently of the surrounding call.

**Precision 97.16% → 97.37% (95% CI 96.2–98.6), audited 635 → 693 of 1853 → 1911.**
`bin/precision.py work/v5_pre.json work/v5_post2.json --added-tp 58 --added-fp 0 --write-readme`
reproduced the anchored 97.16% baseline before printing anything else; stratified-fresh (97.372%),
carried-constants (97.351%) and pooled Wilson (97.403%) estimators agree within 0.05pp. Delta lands
entirely in stratum B.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--release --all-targets --workspace -- -D warnings` clean; `cargo test --release --workspace` all
passing (146 `scan_test.rs` cases, one new). Both trust-invariant tests untouched and pass.
`readme_rule_pack_counts` required updating 126→127 extract / 718→721 classify (total) and Go's
95→98 (per-language) — confirmed failing before the fix, passing after.

**Not done, said out loud:** the `#V5`-named `crypto/tls` `MLKEM768`/`MLKEM1024` `CurveID` gap
turned out to already be closed (`CRYPTO-044`–`CRYPTO-047`, shipped alongside `#Y30`) — verified at
`pkg.go.dev/crypto/tls#CurveID` that Go 1.27 exports no pure, non-hybrid `MLKEM768` constant (only
`MLKEM1024`), so there was nothing left to build there; `#V5` is now fully closed. `OPEN-ASK
#ESTIMATORPERSIST` and `OPEN-ASK #CORPUSDRIFT` remain open, neither this cycle's to resolve.

## Measurement, 2026-09-01 (Track A cycle 78 — `golang.org/x/crypto/ssh` `Config.KeyExchanges`, `#Y88`, RFC 10042)

Read the backlog and Precision-Tracker for the highest-value unfinished item. `#Y88` (filed by the
2026-09-01 cycle-31 synthesis) was the one fully-specified, ready-to-build coverage item on the
list: RFC 10042 (Informational, Aug 2026) registers three hybrid ML-KEM SSH key-exchange
identifiers, OpenSSH has shipped `mlkem768x25519-sha256` as its default KEX since 10.0 (Apr 2025),
and `golang.org/x/crypto/ssh` exposes it as `ssh.KeyExchangeMLKEM768X25519` since Go 1.24 — verified
directly against a vendored copy of the package in the corpus clones
(`work/corpus-clones/go-modules/kubernetes/vendor/golang.org/x/crypto/ssh/common.go`), not assumed
from the filing.

**What shipped.** `ssh.Config.KeyExchanges` is a plain `[]string` (unlike `tls.Config
.CurvePreferences`'s typed `[]tls.CurveID`), so a caller can name a group either via the package
constant or the raw wire-identifier string — both forms are matched. One new structural matcher,
`match_go_ssh_key_exchanges` (`scanner.rs`), mirrors `match_go_curve_preferences`'s `keyed_element`
shape with a `type_identifier "string"` slice-element guard in place of the qualified-type one, and
normalises the constant spelling to the wire string via a small lookup table before handing it to
classify. `go.toml` gained one `[[extract]]` (`GO-078`) and seven `[[classify]]` arms
(`CRYPTO-1056`–`1062`): three for the RFC 10042 hybrid identifiers and four for the classical KEX
groups they replace, mirroring `CurvePreferences`'s classical-plus-migrated shape exactly. **No new
algorithm-table rows** — the three hybrid identifiers and four classical groups reuse the exact ids
`crypto/tls.Config.CurvePreferences` and `javax.net.ssl.SSLParameters.setNamedGroups` already
created for the identical underlying primitives (`x25519-mlkem768`, `secp256r1-mlkem768`,
`secp384r1-mlkem1024`, `x25519`, `ecdh-p256`, `ecdh-p384`, `ecdh-p521`); the filing's own text
suggested new rows, but `java.toml`'s `setNamedGroups` arms already establish that this table's ids
name a mechanism, not a protocol, so a fourth protocol reusing them is the no-bloat move, not a
scope cut. `sntrup761x25519-sha512` (RFC 9941) — the filing's own lower-ranked, library-support-
unverified second row — is not built this cycle.

**Verified against a new fixture, not the corpus.** `tests/fixtures/go/ssh_kex.go`: one
`ssh.ServerConfig` with two hybrid identifiers in constant form and one in string-literal form, one
`ssh.ClientConfig` with all four classical groups in constant form. New test
`go_ssh_key_exchanges_are_classified` (`scan_test.rs`) pins all seven rules to their exact fixture
line. `STRUCTURAL_APIS` gained `golang.org/x/crypto/ssh.Config.KeyExchanges`, confirmed required by
`every_classify_rule_targets_an_api_the_extractor_can_emit` (fails without it).

**Tuple, per `#S12`: corpus B (150 projects) · scanner set `--source --deps --include-safe` ·
profile `nist-default` · pre-change binary built from commit `028d7c4` in a worktree (via `git
stash`) · post-change binary from this cycle's tree · dumps `work/y88_pre.json` ↔
`work/y88_post.json`, both 1911 findings, byte-identical.**

**0 findings added, 0 removed, 0 reclassified — a falsification, not a re-derivation.** No corpus B
project, including the `crypto-adjacent:golang.org/x/crypto` clone itself and the `moby`/`minio`
projects that do call `ssh.Config{KeyExchanges: ...}`, writes the list as a literal — `minio/cmd/
sftp-server.go:479` passes a variable (`allowKexAlgos`), which is out of scope by the same
non-literal-argument convention every other unattributed-fallback rule in this codebase already
follows, and no rule was written to degrade it, matching the filing's own "near-zero" expectation.

**Precision.** `bin/precision.py work/y88_pre.json work/y88_post.json --write-readme` →
`PRECISION: 97.17%`, unchanged between pre and post (both dumps identical, so the estimator computes
the same figure for each — proof of "held," not a new measurement). **The published README figure
this replaces was 97.37% (693 audited), not 97.17% (635 audited) — a 0.20pp drop this change did not
cause.** `state/estimator.json`'s persisted audit constants (`a_tp=262 a_fp=9 b_tp=355 b_fp=9`,
summing to exactly 635) predate cycle 77's `#V5` (`028d7c4`, this cycle's own pre-change commit),
which reported 693 audited via `--added-tp 58` but — as `OPEN-ASK #ESTIMATORPERSIST` has named since
before `#V5` ran — the tool has no mechanism to persist an `--added-tp` result back into
`estimator.json` for the next cycle to build on. This cycle neither introduces nor resolves that
gap; it is the same 635-constant `#V5`'s own entry names as its *pre-change* figure, surfacing again
because `estimator.json` was never advanced. Fixed the one now-inconsistent copy of the audited
composition in `README.md` (see next paragraph) but left `state/estimator.json` and `OPEN-ASK
#ESTIMATORPERSIST` alone — moving the persisted anchor is the human adjudicator's call, not a
coverage cycle's.

**README, corrected in full, not just the headline.** `--write-readme` updated the headline (97.37%
→ 97.17%) and comparison-table cells; per rule 4, grepped the file for the old `693`/`675 TP` figures
it left behind and found one more copy at the "What the denominator excludes" paragraph, corrected
to `635`/`617 TP` with a one-line pointer to this entry rather than silently diverging from the
headline three paragraphs up. The `#V5`-specific narrative two paragraphs above it (which describes
*that* cycle's own 58-finding delta as "this cycle's own change") is left as historical prose, not
rewritten, since re-narrating a different cycle's own measurement is out of this change's scope.
`readme_rule_pack_counts` required updating 127→128 extract / 721→728 classify (total) and Go's
98→105 (per-language) — confirmed failing before the fix, passing after.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--release --all-targets --workspace -- -D warnings` clean; `cargo test --release --workspace` all
passing (147 `scan_test.rs` cases, one new). Both trust-invariant tests untouched and pass.

**Not done, said out loud:** `sntrup761x25519-sha512` (RFC 9941) is unbuilt, per the filing's own
lower ranking. `OPEN-ASK #ESTIMATORPERSIST` and `OPEN-ASK #CORPUSDRIFT` remain open, neither this
cycle's to resolve — `#ESTIMATORPERSIST` in particular is now demonstrated a second time, on a
completely unrelated change, which is evidence for whoever picks it up that it recurs by default
rather than needing an unusual trigger.

PRECISION: 97.17%

## Measurement, 2026-09-01 (Track A cycle 79 — Java `KeyPairGenerator.getInstance("Ed25519"/"XDH")`, `#T8`'s two remaining classical drops)

`#T8` (filed 2026-08-27) named "~14 TOML-only PQC classify arms" as ready-to-build once `#T3`
unblocked `Severity::Safe`; re-reading it this cycle found every PQC arm it listed (Go
`CurvePreferences` ML-KEM rows, Java `KeyPairGenerator`/`Signature.getInstance` ML-KEM/ML-DSA rows)
already shipped across cycles 43–78. The two **classical** drops `#T8` named in the same breath —
`KeyPairGenerator.getInstance("Ed25519")` and `("XDH")` — had not: `JAV-010`'s extractor already
captures any string-literal argument to `KeyPairGenerator.getInstance`, so both call shapes were
extracted and silently dropped with no classify arm to match them, the same "extracted but
unclassified" defect `#T8` described for the PQC rows.

**Also checked before building anything, per "measure, don't assert":** `#Y88`'s own filing named
`sntrup761x25519-sha512` (RFC 9941) as a ready-to-rank-lower second row for the SSH `Config.
KeyExchanges` rule. Fetched `pkg.go.dev/golang.org/x/crypto/ssh` and read the vendored corpus
copy directly (`work/corpus-clones/go-modules/x-crypto/ssh/common.go:83-106`): `supportedKexAlgos`
and `defaultKexAlgos` list eight KEX names, none of them Sntrup761 — `golang.org/x/crypto/ssh`
does not implement this KEX at all, so a Go classify arm for it would fire on a string no real
Go program using this library can negotiate. Not built; left named in the backlog for whichever
non-Go SSH library (OpenSSH itself, paramiko, russh) actually implements it, which no lens has
checked yet.

**What shipped:** two new classify arms, `java.toml` `CRYPTO-1063` (`"Ed25519"` → the existing
`ed25519` algorithm id, same as every other Ed25519 call site in the table) and `CRYPTO-1064`
(`"XDH"` → a new `xdh-unattributed` sentinel, `algorithm-table.toml`, exact same shape as
`ecdh-unattributed`: XDH is the JCA family name covering both X25519 and X448, and the curve is
chosen at the following `.initialize(NamedParameterSpec(...))` call this matcher cannot see).
`crates/cbom/src/emit.rs`'s `canonicalize_family` gained `"XDH" => "ECDH"` alongside its existing
`"X25519" | "X448"` mapping — the CycloneDX 1.7 `algorithmFamiliesEnum` has no `XDH` member, so
without this the CBOM emitter would have failed schema validation the first time a real `XDH`
finding reached it (caught by `every_algorithm_emits_a_bom_valid_at_the_version_it_declares`,
which failed before the fix and passes after). New fixture coverage: `tests/fixtures/java/Main.java`
gained both call shapes; new test `scans_java_keypairgenerator_ed25519_and_xdh` pins both rule
ids to both algorithm ids.

**Tuple, per `#S12`: corpus B (150 projects) · scanner set `--source --deps --include-safe` ·
profile `nist-default` · pre-change binary `a38bdc0` (cycle 78's own commit) · post-change binary
from this cycle's tree · dumps `work/y88_post.json` ↔ `work/y89_post.json`, both 1911 findings,
both produced by the repo's own `benchmarks/corpus-b-realworld/dump_findings.py` (integrity-checked,
clone-relative paths) — not the absolute-path ad-hoc scratch script, which on a first pass produced
a spurious ~2000-row diff purely from a path-format mismatch against the previous dump and was
discarded before drawing any conclusion from it.**

**1 finding added, 1 removed, 0 net change in count — a reclassification, not new coverage.**
`crypto-adjacent:github.com/tink-crypto/tink-java`'s `X25519Conscrypt.java:91`
(`KeyPairGenerator.getInstance("XDH", provider)`, followed by `.initialize(255)`) moved from the
generic `CRYPTO-234`/`jca-unattributed` sentinel to the new `CRYPTO-1064`/`xdh-unattributed` arm.
Opened the cited line directly: a real XDH keypair-generation call, hand-labelled TP under both the
old and new classification — the reclassification is strictly more specific (names the primitive as
XDH rather than "some JCA call"), not a new detection. No other corpus B project calls
`KeyPairGenerator.getInstance` with `"Ed25519"` or `"XDH"` as a literal.

**Precision 97.17% (persisted) → 97.18%, held within rounding.**
`bin/precision.py work/y88_post.json work/y89_post.json --added-tp 1 --added-fp 0 --write-readme`
reproduced the anchored 97.17%/635-row baseline before printing anything else, then folded the one
hand-labelled TP into stratum A (`262/271` → `263/272`, matching the "delta lands in stratum A"
output — the reclassified row is a new key precision.py cannot match against the old label, so it
is treated as one new sampled row, not a like-for-like swap). Stratified-fresh (97.179%), pooled
Wilson (97.170%) agree within 0.01pp.

**README, corrected in full, not just the headline.** `--write-readme` updated the headline
(97.17% → 97.18%, 635 → 636 audited) and comparison-table cells. Per rule 4: the "What the
denominator excludes" paragraph's second copy of the composition (`635`/`617 TP`) was updated to
`636`/`618 TP` in the same diff. Also fixed, found by the same grep sweep and reported separately
since it predates this cycle: the Recall section's "618-row audit" cross-reference (`#Y89`, filed
2026-09-01 synthesis cycle 31) was stale by 17 rows against the then-current 635 and is now
rewritten to say "the audit the precision figure above is now sampled from" instead of a second
hardcoded count, per `#Y89`'s own recommendation, so it cannot drift out of sync with the headline
again. `readme_rule_pack_counts` required updating 728→730 classify (total) and Java's 181→183
(per-language) — confirmed failing before the fix, passing after.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--release --all-targets --workspace -- -D warnings` clean; `cargo test --release --workspace` all
passing (148 `scan_test.rs` cases, one new; 7 `emit_test.rs` cases including the CBOM schema-validity
one this cycle's fix was required to keep green). Both trust-invariant tests untouched and pass.

**Not done, said out loud:** `sntrup761x25519-sha512` is now known *not* buildable against
`golang.org/x/crypto/ssh` specifically (see above) — a negative result recorded so the next cycle
does not re-derive it, not a closure of the backlog item, which still names other languages'
libraries as unverified. The Java two-hop generic-name traces (`#Y80`/`#Y81`/LMS/HSS) and the
aws-lc-rs `kem`/`signature` module gap remain open, neither this cycle's to take. `OPEN-ASK
#ESTIMATORPERSIST` and `OPEN-ASK #CORPUSDRIFT` remain open, neither this cycle's to resolve.

PRECISION: 97.18%

## Measurement, 2026-09-01 (Track A cycle 80 — README rule-2 boundary and `#Y91` speed-figure drift fixed; `#Y92` OpenSSL 3.5 hybrid PQ/T KEM keygen coverage)

Read the backlog and Precision-Tracker for the highest-value unfinished item. Synthesis cycle 32
(2026-09-01) ranked three fully-specified items in order: `#Y90` (internal "adjudicator"/`OPEN-ASK`/
`DECISION #` vocabulary live in the public `README.md`, ranked above everything else because it is
rule 2's public/private boundary being crossed, not merely at risk), `#Y91` (the README lede and
comparison table quoting a superseded benchmark run's speed figures against the benchmark table's
own newer numbers — the same drift shape `#Y84` fixed for the finding-count total 31 hours earlier),
and `#Y92` (OpenSSL 3.5's hybrid PQ/T KEM key-type names invisible to `cpp.toml`'s generic keygen
list). All three confirmed still live by direct `grep`/read before touching anything.

**`#Y90` and `#Y91`, both docs-only, no detection code touched.** Reworded the five README sentences
naming "the adjudicator", `DECISION #ESTIMATOR2` and `OPEN-ASK #ESTIMATOR1`/`#CORPUSDRIFT` to state
the same facts and figures without the internal nouns — `git diff` preserves every number and claim,
removes only the three vocabulary items rule 2 flags. Propagated the benchmark table's own
175ms/1575ms/236.6s to the lede (line 13) and the comparison table's `Scan speed` row, replacing the
stale 205ms/1847ms/277s both were still quoting. Added
`readme_speed_figures_agree_with_the_benchmark_table` to
`crates/cli/tests/readme_benchmark_table_agrees_with_precision.rs`, mirroring that file's existing
`readme_benchmark_table_total_matches_the_precision_denominator` shape exactly (locate digits next to
fixed anchor text, no table parsing) — confirmed it fails against the pre-fix README (`left: "205",
right: "175"`) and passes after, per "a gate that cannot fail is not a gate." No `PRECISION:` claim
for either — nothing in `crates/` or `crates/core/data/` changed.

**`#Y92`, checked before building, not assumed.** The filing's own two-part shape (four new
`EVP_PKEY_CTX_new_from_name`/`EVP_PKEY_Q_keygen` classify arms, plus a fifth `X448MLKEM1024` arm on
the sibling `SSL_CTX_set1_groups_list` TLS-group rule) does not survive independent verification.
`docs.openssl.org/master/man7/EVP_PKEY-MLX-KEM/` (fetched 2026-09-01) confirms all four hybrid names
— `X25519MLKEM768`, `X448MLKEM1024`, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024` — as real EVP_PKEY key
types. But `iana.org/assignments/tls-parameters` (same fetch) lists codepoints for the first three
(4588/4587/4589) and **no entry for `X448MLKEM1024`** anywhere in the registry (checked through
4591). `SSL_CTX_set1_groups_list` negotiates by IANA `supported_groups` codepoint; a name with none
assigned is not TLS-negotiable regardless of what OpenSSL's `EVP_PKEY` layer supports it for. Built
only the four generic-keygen arms — real, verified EVP_PKEY key types, independent of TLS
negotiability — and left the `SSL_CTX_set1_groups_list` half unbuilt, recorded as a negative result
rather than assumed correct from the filing.

**Shipped:** `cpp.toml` `CRYPTO-1065`–`CRYPTO-1068` on the existing
`EVP_PKEY_CTX_new_from_name`/`EVP_PKEY_Q_keygen` classify list (`when.args.alg` regex-matched to each
hybrid name), reusing the `x25519-mlkem768`/`secp256r1-mlkem768`/`secp384r1-mlkem1024` algorithm ids
`SSL_CTX_set1_groups_list`'s own `CRYPTO-909`–`911` already define, plus one new id,
`x448-mlkem1024` (`algorithm-table.toml`, `Hybrid-KEM`/`combiner`, level 5, notes stating explicitly
that it has no TLS wire codepoint) — the same reuse-over-duplication convention `CRYPTO-909`–`911`
themselves set. `Hybrid-KEM` already maps to `None` in `crates/cbom/src/emit.rs`'s
`canonicalize_family`, so no CBOM emitter change was needed. New fixture coverage:
`tests/fixtures/cpp/crypto.c` gained a four-call-site function; `scans_c_openssl_generic_keygen`
(`scan_test.rs`) extended with all four `(rule_id, algorithm_id)` pairs.

**Tuple, per `#S12`: corpus B (150 projects) · scanner set `--source --deps --include-safe` ·
profile `nist-default` · pre-change binary built from commit `7600331` in a worktree · post-change
binary from this cycle's tree · dumps `work/y92_pre.json` ↔ `work/y92_post.json`, both 1911
findings, both produced by the repo's own `benchmarks/corpus-b-realworld/dump_findings.py`.**

**0 findings added, 0 removed, 0 reclassified.** No corpus B project — including
`openssl/openssl`, `aws/aws-lc` and `google/boringssl`, the three that already exercise this same
API for classical and pure-PQC algorithm names — calls it with any of the four hybrid names. Expected
and stated in advance: these are brand-new OpenSSL 3.5 preview key types, the same "no measured
corpus demand yet" shape `#Y43`'s .NET native MLKem/MLDsa/SlhDsa coverage found. Coverage verified
instead against the fixture above (0→4 detected).

**Precision 97.18% (persisted) → 97.17%, arithmetically unrelated to this change.**
`bin/precision.py work/y92_pre.json work/y92_post.json --write-readme` found the byte-identical
1911-finding dumps it expected (0 added, 0 removed — correctly refused to accept `--added-tp`/
`--added-fp` since none were owed) and reported the *persisted* anchor, 635/97.17%, not the
636/97.18% headline the previous cycle (`#T8`) had published. This is `OPEN-ASK #ESTIMATORPERSIST`
recurring a third time: `state/estimator.json` was never advanced past its pre-`#T8` values, so any
fresh `precision.py` run reproduces the stale persisted anchor rather than the last-published figure
— exactly the gap `#Y88`'s cycle-78 entry and `#T8`'s cycle-79 entry both already named. Left
`state/estimator.json` untouched, since moving the persisted anchor is the human adjudicator's call,
not this cycle's. `--write-readme` also updated the two rule-pack-count sentences this cycle's own
new classify arms moved (128 extract / 730→734 classify total, C/C++ 126→130) — both confirmed
correct against a fresh `grep -c '^\[\[classify\]\]'` before the tool ran.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--release --all-targets --workspace -- -D warnings` clean; `cargo test --release --workspace` all
passing (148 `scan_test.rs` cases, `scans_c_openssl_generic_keygen` extended rather than a new case
added; both `readme_benchmark_table_agrees_with_precision.rs` tests and `readme_rule_pack_counts.rs`
passing against the updated figures). Both trust-invariant tests untouched and pass.

**Not done, said out loud:** the `SSL_CTX_set1_groups_list` `X448MLKEM1024` arm the filing proposed
is not built — negative result above, not an oversight. `OPEN-ASK #ESTIMATORPERSIST` (demonstrated a
third time this cycle) and `OPEN-ASK #CORPUSDRIFT` remain open, neither this cycle's to resolve.

## Measurement, 2026-09-01 (Track A cycle 81 — aws-lc-rs `kem`/`signature` module coverage, the
## backlog's own standing "real, unclaimed" candidate since cycle 74)

Read the Backlog and Precision-Tracker; every item cycles 72–80 had ranked was closed. The only
named-but-unbuilt candidate left on record was cycle 74's own research note: aws-lc-rs's `kem` and
`signature` modules construct ML-KEM/ML-DSA key pairs from a parameter set passed as an associated
constant — real API, verified then via docs.rs, no `RUST_CALLEE_APIS` entry, no corpus hit.
Re-verified the API shape directly against a fresh `docs.rs/aws-lc-rs` fetch rather than trusting
the four-day-old note: `DecapsulationKey::generate(&'static Algorithm)` in `aws_lc_rs::kem`
(`ML_KEM_512`/`768`/`1024`) is unchanged, but `PqdsaKeyPair::generate` takes `&'static
PqdsaSigningAlgorithm` — the **`ML_DSA_44_SIGNING`/`65_SIGNING`/`87_SIGNING`** constants, not the
bare `ML_DSA_44`/`65`/`87` names the cycle-74 note assumed (those are verification-only). Building
against the note's literal constant names would have shipped classify arms that never fire.

**What shipped:** two `RUST_CALLEE_APIS` entries plus a shared match arm reusing
`rust_arg_const_name` — the identical associated-constant-as-argument shape `rcgen::KeyPair::
generate_for` already established, so no new extraction primitive was needed, only two more callers
of the existing one. Eight new `rust.toml` classify arms (`CRYPTO-1069`–`1076`): three ML-KEM
parameter sets plus a `kem-unattributed` fallback, three ML-DSA parameter sets plus a
`sig-unattributed` fallback — all four algorithm ids reused from the existing table, no new rows.
Coverage verified against a new fixture, `tests/fixtures/rust/aws_lc_rs_pqc.rs` (7 call sites: three
ML-KEM literals, three ML-DSA literals, one local-variable argument exercising the fallback), and a
new test, `scans_rust_aws_lc_rs_ml_kem_ml_dsa`.

**Tuple, per `#S12`: corpus B (150 projects) · scanner set `--source --deps --include-safe` ·
profile `nist-default` · pre-change dump `work/y92_post.json` (1911, commit `da4f574`) ·
post-change binary from this cycle's tree · dump `work/awslcrs_post.json` (1911), both produced by
the repo's own `benchmarks/corpus-b-realworld/dump_findings.py`.**

**0 findings added, 0 removed, 0 reclassified — the stated expectation, not a surprise.** The
corpus's own `crypto-adjacent/aws-lc` clone is the C library (`aws-lc`), not the Rust wrapper
crate (`aws-lc-rs`); no `crates-io` project in the corpus depends on `aws-lc-rs` at all, so neither
new callee shape has a call site to match. Real API, zero measured corpus demand — the same
"coverage without corpus demand" shape `#Y43`/`#Y80`/`#Y87`/`#Y92` all already recorded.

**Precision 97.17% (persisted), held exactly.** `bin/precision.py work/y92_post.json
work/awslcrs_post.json --write-readme` found the byte-identical 1911-finding dumps it expected (0
added, 0 removed) and reproduced the persisted anchor without needing `--added-tp`/`--added-fp`.
`--write-readme` found the headline sentence already correct and made no README edit for the
figure itself; the rule-pack-count sentence was updated by hand in the same diff (128 extract /
734→742 classify total — Rust is not one of the four per-language-called-out packs, so no
per-language sentence needed a change), confirmed against a fresh `grep -c '^\[\[classify\]\]'`
before committing.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --check` clean; `cargo clippy
--release --all-targets --workspace -- -D warnings` clean; `cargo test --release --workspace` all
passing (149 `scan_test.rs` cases, one new). Both trust-invariant tests untouched and pass.
`readme_rule_pack_counts.rs` confirmed failing before the README edit, passing after.

**Not done, said out loud:** `OPEN-ASK #ESTIMATORPERSIST` and `OPEN-ASK #CORPUSDRIFT` remain open,
neither this cycle's to resolve — this cycle could not have caused either (byte-identical dumps).
The Java two-hop generic-name traces (`#Y80`/`#Y81`/LMS/HSS) and `sntrup761x25519-sha512` for a
non-Go SSH library remain the standing unclaimed items; no new ready-to-build Track A candidate was
identified while closing this one.

PRECISION: 97.17%

## Measurement, 2026-09-01 (Track A cycle 82 — circl `kem/xwing` (X-Wing hybrid PQ/T KEM) gains Go coverage)

X-Wing (`draft-connolly-cfrg-xwing-kem`) combines X25519 with ML-KEM-768 through its own SHA3-256
combiner for HPKE/KEM APIs — distinct from the already-covered TLS `X25519MLKEM768` supported_group.
`go.toml` gains extract/classify rule `CRYPTO-1077` and `scanner.rs` gains callee-table wiring for
circl's `kem/xwing` package; the same call shape also catches Google Tink's internal
`hybrid/internal/xwing` package, which shares the same function names under the same local
identifier `xwing`, verified against the live corpus rather than assumed. `go.toml` classify arms
105 → 106.

**Tuple, per `#S12`: corpus B (150 projects) · scanner set `--source --deps --include-safe` ·
profile `nist-default` · pre-change binary built from commit `235cf0d` · post-change binary from
this cycle's tree · dumps `work/awslcrs_post.json` (1911) ↔ `work/xwing_post.json.stale-parked-cycle`
(1916), both produced by the repo's own `benchmarks/corpus-b-realworld/dump_findings.py`.**

**5 findings added, 0 removed, 0 reclassified.** All five are inside `crypto-adjacent/tink-go`'s own
X-Wing KEM wrapper (`hybrid/internal/hpke/xwing_kem.go:31,35`, `hybrid/hpke/key.go:129,176`,
`hybrid/hpke/public_key_manager_test.go:334`) — opened each cited `file:line` directly: two are
`xwing.Encapsulate`/`xwing.Decapsulate` calls inside tink-go's own KEM interface implementation, two
are `xwing.PublicFromSecret` calls deriving/validating a public key from private key material, one is
the identical call inside a test exercising the real API (test-code crypto operations count as TP by
this benchmark's established convention). All five TP, 0 FP.

**Precision 97.17% → 97.19% (95% CI 95.92–98.47), stratified fresh populations.**
`bin/precision.py work/awslcrs_post.json work/xwing_post.json.stale-parked-cycle --added-tp 5
--added-fp 0 --write-readme` reproduced the persisted 97.17% anchor on the pre dump, confirmed the
delta lands entirely in stratum B (crypto-adjacent), and applied the figure to the README headline
and comparison table. Sample: A 262/271, B 360/369 (365 → 369 audited rows in B); populations
re-derived fresh at A=797, B=1119. Neither of the two new findings is HNDL-flagged or unscored, so
the HNDL (`0 of N`) and DEP-001-unscored (`13 of N`) sentences move only their denominator, 1911 →
1916, not their numerator — confirmed against the dump directly.

**Held:** `cargo build --release --workspace`, `cargo fmt --all --check`, `cargo clippy
--all-targets -- -D warnings`, `cargo test --workspace` (one new fixture-backed test,
`go_circl_xwing_is_classified`) all clean. Both trust-invariant tests untouched and pass.
`readme_benchmark_table_total_matches_the_precision_denominator` passes against 1916 in both
locations.

**Not done, said out loud:** the whole-corpus wall-clock table is not re-run this cycle — the finding
counts are the only figures this change can move, and a scan_corpus.py pass costs several minutes on
this box for a number this diff does not depend on. `OPEN-ASK #ESTIMATORPERSIST` and `OPEN-ASK
#CORPUSDRIFT` remain open, neither this cycle's to resolve.

PRECISION: 97.19%

## Measurement, 2026-09-01 (Track A cycle 84 — `#Y95` closed: .NET `CompositeMLDsa`, hybrid PQ/T signature keygen)

`csharp.toml` had zero rule for .NET 10's first-party `CompositeMLDsa` class
(`System.Security.Cryptography`, `[Experimental("SYSLIB5006")]` — the identical attribute-and-code
`MLKem`/`MLDsa`/`SlhDsa` themselves shipped under before this file covered them, so "experimental" is
not a reason to withhold coverage). Re-fetched `learn.microsoft.com/.../compositemldsaalgorithm`
directly rather than trusting the standing research note's citation, and it undercounts by one: the
class exposes **18** named algorithm members (`MLDsa44WithECDsaP256` … `MLDsa87WithRSA4096Pss`), not
17. `CompositeMLDsa.GenerateKey(CompositeMLDsaAlgorithm.<member>)` is the identical
static-factory-with-member-access shape `MLKem.GenerateKey` already covers — `scanner.rs` gains one
`CSHARP_CALLEE_APIS` row, `csharp.toml` gains extract `CSH-078` and one classify arm, `CRYPTO-1078`.

**Deliberately one classify arm, not 18.** Every member pairs one of ML-DSA-44/65/87 with a distinct
classical algorithm, but `algorithm-table.toml` has no composite-family row to publish that pairing as
its own id — every existing PQC classify arm in this codebase already resolves to an id the table
defines, and inventing 18 new composite ids (or per-member sentinels that would all carry the same
`ml-dsa-unattributed` output anyway) is the same class of change `#Y43` deferred for this exact reason
in 2026-08-29. One rule, keyed only on `when.api`, covers both the literal-member and the
non-literal/variable argument shapes identically, since both degrade to the same id. `csharp.toml`
classify arms 118 → 119; extract blocks 129 → 130.

**Coverage verified against the fixture, not corpus B.** `tests/fixtures/csharp/PqcNative.cs` gains
one call site (`CompositeMLDsa.GenerateKey(CompositeMLDsaAlgorithm.MLDsa65WithECDsaP256)`), asserted
in `scans_csharp_native_mlkem_mldsa_slhdsa` (`CRYPTO-1078`, `ml-dsa-unattributed`). A direct scan
before this change produced 0 findings for that line; after, 1.

**Tuple, per `#S12`: corpus B (150 projects) · scanner set `--source --deps --include-safe` · profile
`nist-default` · pre-change dump `work/xwing_post.json.stale-parked-cycle` (1916, commit `89e9ea6`) ·
post-change binary from this cycle's tree · dump `work/y95_post.json` (1916), both produced by the
repo's own `benchmarks/corpus-b-realworld/dump_findings.py`.**

**0 findings added, 0 removed, 0 reclassified — the expected result, not a surprise.** `[Experimental]`,
GA seven months ago with no corpus adopter yet, `net-11.0` also listed as a target moniker (the shape
can still move before it stabilizes) — a brand-new preview API with no measured corpus demand on
either side of this change, same evidentiary tier as `#Y43`'s own three native classes and `#Y92`'s
OpenSSL hybrid keygen arms.

**Precision 97.19% (last published) → 97.17% (persisted anchor), arithmetically unrelated to this
change.** `bin/precision.py work/xwing_post.json.stale-parked-cycle work/y95_post.json --write-readme`
asserts row-identity on the two byte-identical dumps (0 added, 0 removed) and reports the
stratified-fresh estimator from the carried sample (`A 262/271`, `B 355/364`) rather than the
640-audited figure cycle 82 published by folding its own `--added-tp 5` — the exact gap `OPEN-ASK
#ESTIMATORPERSIST`/`#ESTIMATORPERSIST2` already names, demonstrated again on a change that could not
have caused it (a byte-identical corpus dump). `state/estimator.json` left untouched, the persisted
anchor's re-derivation is the human adjudicator's call, not this cycle's.

**Held:** `cargo build --release --workspace`, `cargo fmt --all --check`, `cargo clippy --release
--all-targets --workspace -- -D warnings`, `cargo test --release --workspace` all clean (151
`scan_test.rs` cases, one new). Both trust-invariant tests untouched and pass.
`readme_rule_pack_counts_match_the_rule_packs` confirmed failing before the README edit (129/743/118),
passing after (130/744/119).

**Not done, said out loud:** `CompositeMLDsaCng`, the CNG-backed sibling the API page lists as
`CompositeMLDsa`'s only derived class, is unbuilt — its constructor shape was not fetched and
confirmed this cycle. `OPEN-ASK #ESTIMATORPERSIST`/`#ESTIMATORPERSIST2` remain open, neither this
cycle's to resolve; `#Y94` (the `bin/adjudicate.py` near-miss detector gap) and `#Y96` (the
`BENCHMARKING_RESULTS.md` vocabulary-leak growth gate) are both outside `crates/`/`README.md` and
this track's write authority.

PRECISION: 97.17%

## Measurement, 2026-09-01 (Track A cycle 85 — `CompositeMLDsaCng`, `#Y95`'s own named-unbuilt CNG sibling)

`#Y95`'s own closing note named the gap directly: "`CompositeMLDsaCng`, the CNG-backed sibling of
`CompositeMLDsa`, is unbuilt — its constructor shape was not fetched and confirmed." Fetched
`learn.microsoft.com/.../compositemldsacng` directly this cycle: `sealed class CompositeMLDsaCng :
CompositeMLDsa` with exactly one constructor, `CompositeMLDsaCng(CngKey)` — the identical
receiver-carries-the-identity shape `MLKemCng`/`MLDsaCng`/`SlhDsaCng` (`#Y87`) already cover, not the
`GenerateKey(member)` shape `CompositeMLDsa` itself uses. `scanner.rs` gains one `CSHARP_CTOR_APIS`
row, `csharp.toml` gains extract `CSH-079` and classify arm `CRYPTO-1079` (130→131 extract, 119→120
C# classify, 744→745 total), copying the `MLKemCng` rule shape verbatim.

**Coverage verified against the fixture, not corpus B.** `tests/fixtures/csharp/PqcNative.cs` gains
one call site (`new CompositeMLDsaCng(key)`), asserted in `scans_csharp_native_mlkem_mldsa_slhdsa`
(`CRYPTO-1079`, `ml-dsa-unattributed` — the parameter set lives on the `CngKey` argument, not this
call site, the same degrade-gracefully shape every other CNG wrapper already uses). A direct scan
before this change produced 0 findings for that line; after, 1.

**Tuple, per `#S12`: corpus B (150 projects) · scanner set `--source --deps --include-safe` · profile
`nist-default` · pre-change dump `work/y95_post.json` (1916, commit `01366bf`) · post-change binary
from this cycle's tree · dump `work/y96cng_post.json` (1916), both produced by the repo's own
`benchmarks/corpus-b-realworld/dump_findings.py`.**

**0 findings added, 0 removed, 0 reclassified — the expected result, not a surprise.** Same
evidentiary tier as `#Y95` itself: `[Experimental]`, no corpus adopter for the base `CompositeMLDsa`
class let alone its CNG-backed derived class, and the corpus's `dotnet`/`nuget`-adjacent projects do
not touch Windows CNG interop at all.

**Precision 97.17%, held exactly.** `bin/precision.py work/y95_post.json work/y96cng_post.json
--write-readme` asserts row-identity on the two byte-identical 1916-finding dumps (0 added, 0
removed) and reports the carried stratified-fresh sample (`A 262/271`, `B 355/364`) unchanged.
`--write-readme` found the headline sentence already correct; the rule-pack-count sentences (extract
total, classify total, C#'s per-language count) were updated by hand in the same diff, confirmed
against a fresh `grep -c '^\[\[extract\]\]'`/`'^\[\[classify\]\]'` before committing.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --all` clean; `cargo clippy --release
--all-targets --workspace -- -D warnings` clean; `cargo test --release --workspace` all passing (one
new assertion row in the existing `scans_csharp_native_mlkem_mldsa_slhdsa` test, no new test
function). Both trust-invariant tests untouched and pass.
`readme_rule_pack_counts_match_the_rule_packs` confirmed failing before the README edit (130/744/119),
passing after (131/745/120).

**Not done, said out loud:** `OPEN-ASK #ESTIMATORPERSIST2` remains open, not this cycle's to resolve
— this cycle could not have caused it (byte-identical dumps). `#Y94`/`#Y96` remain outside
`crates/`/`README.md`, this track's write authority. No further named CNG-backed .NET PQC class is
known to be unbuilt after this cycle.

PRECISION: 97.17%

## Measurement, 2026-09-01 (Track A cycle 199 — `#Y98`, `CompositeMLDsa`'s IETF draft citation
corrected)

Cycle 198 left `csharp.toml`'s `CompositeMLDsa.GenerateKey` description citing
`draft-ietf-lamps-cms-composite-sigs`, a draft name that does not exist — the actual document is
`draft-ietf-lamps-pq-composite-sigs`, the same one `knowledge/05-x509-pqc/README.md` cites five times
elsewhere in the tree. A repo-wide grep confirmed this was the only site carrying the wrong name.
Fixed the string; no query, capture, or classify logic touched.

**Tuple, per `#S12`: corpus B (150 projects) · scanner set `--source --deps --include-safe` · profile
`nist-default` · pre-change dump `work/y96cng_post.json` (1916, commit `b9261a4`) · post-change binary
from this cycle's tree · dump `work/y98_post.json` (1916), both produced by the repo's own
`benchmarks/corpus-b-realworld/dump_findings.py`.**

**0 findings added, 0 removed — the expected result.** A description string is not part of
`finding_key` (project, rule_id, file, line, algorithm_id, severity) and does not appear in the dump
at all; only `message` does, which this change never touched. `bin/precision.py
work/y96cng_post.json work/y98_post.json --write-readme` confirms row-identity on the two
byte-identical 1916-finding dumps and reports the carried stratified-fresh sample (`A 262/271`, `B
355/364`) unchanged. `--write-readme` found the headline and comparison-table figures already
correct at `97.17%` — the more precise re-derived value (97.175%) rounds to the same published
two-decimal figure, so nothing needed writing.

**Precision 97.17%, held exactly.**

**Held:** `cargo build --release --workspace` clean; `cargo fmt --all` clean; `cargo clippy
--all-targets --workspace -- -D warnings` clean; `cargo test --workspace` all passing, no new test
function (no detection-logic change to cover). Both trust-invariant tests untouched and pass.

**Not done, said out loud:** nothing else in this cycle's scope; the gate failure this cycle repaired
was the missing measurement itself, not a defect in the fix (`parked/20260901T193418-gate-red`,
now merged and deleted).

PRECISION: 97.17%

## Measurement, 2026-09-01 (Track A cycle 200 — `#Y100`, BouncyCastle.NET LMS/HSS key generation)

Took `#Y100` as filed by cycle-35 synthesis's ecosystem lens: `csharp.toml` had zero coverage for
BouncyCastle.NET's stateful hash-based signature classes. Re-verified directly against
`bcgit/bc-csharp`, tag `release-2.7.0` (`raw.githubusercontent.com`, not taken from the lens's
citation alone): `Org.BouncyCastle.Pqc.Crypto.Lms.LmsKeyGenerationParameters(LmsParameters,
SecureRandom)` is always single-tree, and the sibling `HssKeyGenerationParameters(LmsParameters[],
SecureRandom)` is always multi-tree (array length = tree depth, RFC 8554 §6, validated 1–8 in the
constructor itself) — the constructor name alone disambiguates `lms` from `hss`, unlike Java BC's
single ambiguous `"LMS"` JCA service name (`java.toml:514-520`, deliberately left unclassified).
`LmsParameters` is itself built from a nested constructor, not a static field, so — matching the
filing's own read — there is no parameter-set literal to capture; two extract/classify pairs
(`CSH-080`/`CRYPTO-1080` for lms, `CSH-081`/`CRYPTO-1081` for hss) match on the bare constructor
class name, the same shape already shipped for `MLKemCng`/`MLDsaCng`/`SlhDsaCng`/`CompositeMLDsaCng`.
`scanner.rs`'s `CSHARP_CTOR_APIS` table gains the two matching rows — the classify rules match no
api the extract layer emits until this row exists, caught by `every_classify_rule_targets_an_api_the_extractor_can_emit`
before it could ship silently broken.

**The hss classify message conditions rather than asserts, per the filing's own counter-argument.**
A depth-1 `HssKeyGenerationParameters` array is legal and cryptographically identical to single-tree
LMS (SP 800-208); the message reads "verify the configured depth" rather than an unconditional
CNSA 2.0 prohibition claim.

**`algorithm-table.toml`'s `lms`/`hss` rows had their own `undetectable` reason removed, not merely
reworded, once this change made them reachable — `every_algorithm_id_is_emitted_or_says_why_not`
fails a row that carries a stale reason once an emitter exists, and did fail here first. The `xmss`
row's neighbouring note ("no OID needed, unlike lms/hss above") was also stale as of this change and
is corrected to "same as lms above" in the same diff, per rule 4.**

**Coverage verified against the fixture, not corpus B.** `tests/fixtures/csharp/Pqc.cs` gains two
call sites (`new LmsKeyGenerationParameters(lmsParameters, random)`, `new
HssKeyGenerationParameters(lmsParameters, random)`), asserted in the new
`scans_csharp_bouncycastle_lms_hss` test (`CRYPTO-1080`/`lms`, `CRYPTO-1081`/`hss`). No BouncyCastle
XMSS namespace exists in C# BC at all (confirmed against the release tag's own directory listing),
closing that question rather than leaving it open; a deeper nested-argument extraction that would
recover the exact NIST parameter set is explicitly not attempted (scope creep past what the filing's
own R1 needs).

**Tuple, per `#S12`: corpus B (150 projects) · scanner set `--source --deps --include-safe` ·
profile `nist-default` · pre-change dump `work/y98_post.json` (1916, commit `e94fb4a`) · post-change
binary from this cycle's tree · dump `work/y100_post.json` (1916), both produced by the repo's own
`benchmarks/corpus-b-realworld/dump_findings.py`.**

**0 findings added, 0 removed, 0 reclassified — the expected result, not a surprise.** `work/corpus-clones`
has no `nuget` directory at all (confirmed directly: `crates-io`, `crypto-adjacent`, `go-modules`,
`maven`, `npm`, `pypi` only), so no C# project in corpus B can reach BouncyCastle.NET's LMS/HSS
classes regardless of this change — same evidentiary tier already accepted for `#Y95`'s
`CompositeMLDsa`/`CompositeMLDsaCng` two commits before this one.

**Precision 97.17%, held exactly.** `bin/precision.py work/y98_post.json work/y100_post.json
--write-readme` confirms row-identity on the two byte-identical 1916-finding dumps and reports the
fresh stratified populations (`A=797, B=1119`, sample `A 262/271`, `B 355/364`) at 97.175%, rounding
to the same published two-decimal figure. `--write-readme` found the headline and comparison-table
figures already correct; the rule-pack-count sentences (`133 extract blocks and 747 classify arms`,
C#'s `122`) were updated by hand in the same diff, confirmed against a fresh `grep -c
'^\[\[extract\]\]'`/`'^\[\[classify\]\]'` before committing.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --all` clean; `cargo clippy --release
--all-targets --workspace -- -D warnings` clean; `cargo test --release --workspace` all passing (one
new test function, `scans_csharp_bouncycastle_lms_hss`). Both trust-invariant tests untouched and
pass. `readme_rule_pack_counts_match_the_rule_packs` confirmed failing before the README edit
(131/745/120), passing after (133/747/122).
`every_algorithm_id_is_emitted_or_says_why_not` confirmed failing before the `undetectable`-field
removal (flagging `["hss", "lms"]` as stale), passing after.

**Not done, said out loud:** `OPEN-ASK #ESTIMATORPERSIST2` remains open, not this cycle's to resolve
— this cycle could not have caused it (byte-identical dumps). `#Y99` (pyca X.509 `.sign()` ML-DSA
coverage), the next-ranked item from the same synthesis cycle, was not started this cycle. `#Y94`/`#Y96`
remain outside `crates/`/`README.md`, this track's write authority.

PRECISION: 97.17%

## Measurement, 2026-09-01 (Track A cycle 203 — `#Y101`, BouncyCastle Java `CompositeKEMs` gains
`javax.crypto.KeyGenerator.getInstance` coverage)

Took `#Y101` as ranked first by cycle-36 synthesis: `java.toml` had zero coverage for
`javax.crypto.KeyGenerator.getInstance` at all — not an attribution gap on an existing fallback, a
true zero, confirmed by a live pre-change scan producing no finding whatsoever on a
`KeyGenerator.getInstance("MLKEM768-X25519-SHA3-256", "BC")` line while its `KeyPairGenerator`
sibling on the same fixture correctly fell through to `jca-unattributed`.

**The filing's own "23 names" count did not survive a direct re-fetch and is corrected here, not
built around.** BouncyCastle 1.85.2's `bcprov-jdk18on` (`repo1.maven.org/maven2` `maven-metadata.xml`,
`<lastUpdated>20260807034313</lastUpdated>`) matches git tag `r1rv85v2`, fetched directly from
`github.com/bcgit/bc-java` rather than trusted from the filing's citation. `compositekem/
CompositeIndex.java`'s static initialiser registers exactly **12** `ASN1ObjectIdentifier` →
algorithm-name pairings, not 23 — `MLKEM768-RSA{2048,3072,4096}-SHA3-256`, `MLKEM768-X25519-SHA3-256`,
`MLKEM768-ECDH-{P256,P384,BP256}-SHA3-256`, `MLKEM1024-RSA3072-SHA3-256`, `MLKEM1024-ECDH-{P384,
BP384,P521}-SHA3-256`, `MLKEM1024-X448-SHA3-256`. `CompositeKEMs.Mappings.configure` iterates
`CompositeIndex.getSupportedIdentifiers()` and registers exactly one `KeyGenerator.<name>` per
identifier — no second registration path exists that would add the other 11 the filing counted.
Building 23 arms would have shipped 11 that can never fire against any string BC actually returns
from `getSupportedIdentifiers()`, the same "classify rule targets an api the extractor can emit"
failure mode the reachability gate exists to catch, just one level down (a real API matched by a
fictional literal, not a fictional API).

**Scoped narrowly, per the filing's own Pass 2 objection.** `javax.crypto.KeyGenerator` has no
general extraction anywhere in this file — most of its calls are AES/ChaCha20/HMAC symmetric key
generation, outside the PQC migration story. One new `[[extract]]` block (`JAV-110`) plus 12
`[[classify]]` arms (`CRYPTO-1082`–`1093`) match only the 12 confirmed literal names, degrading to
`ml-kem-unattributed` — the same "no composite-family row in algorithm-table.toml" reasoning
`CompositeMLDsa` (`#Y95`, C#) already established, not a new precedent. A `KeyGenerator.getInstance`
call naming anything else, including ordinary symmetric algorithms, is extracted and then matches no
classify rule, which produces no finding at all — confirmed in the new fixture's own
`keyGeneratorAesIsNotExtracted()` case.

**Two Rust-side dispatch-table entries were required in addition to the TOML, not TOML alone** —
`java.toml`'s `[[extract]]` blocks document intent; matching for Java is actually a hand-written
walker (`scanner.rs`) keyed on `JAVA_CALLEE_APIS`. Confirmed the gap the hard way: the TOML-only diff
built first compiled clean and passed every existing test, but the new fixture's `KeyGenerator` call
sites produced zero findings until `JAVA_CALLEE_APIS` gained a `KeyGenerator.getInstance` row and
`populate_java_args`'s api match arm gained the same string — the identical two-site pattern every
other `*_CALLEE_APIS` addition in this file's history required.

**Tuple, per `#S12`: corpus B (150 projects) · scanner set `--source --deps --include-safe` ·
profile `nist-default` · pre-change dump `work/y102_default.json` (1916, commit `06ef2eb`) ·
post-change binary from this cycle's tree · dump `work/y101_post.json` (1916), both produced by the
repo's own `benchmarks/corpus-b-realworld/dump_findings.py`.**

**0 findings added, 0 removed, 0 reclassified — the expected result, not a surprise.** The filing's
own corpus check already found every composite-KEM/composite-signature string in corpus B's `maven`
tree confined to `bcpkix-jdk18on` itself (BC's own PKIX module, self-tests and OID-mapping classes),
never an independent downstream consumer; `crypto-adjacent/aws-lc`'s Go/C clone is unrelated. No
project in the 150-project manifest calls `javax.crypto.KeyGenerator.getInstance` with any of the 12
literal names.

**Precision 97.17%, held exactly.** `bin/precision.py work/y102_default.json work/y101_post.json
--write-readme` confirms row-identity on the two byte-identical 1916-finding dumps and reports the
fresh stratified populations (`A=797, B=1119`, sample `A 262/271`, `B 355/364`) at 97.175%, rounding
to the same published two-decimal figure; `--write-readme` found the headline and comparison-table
figures already correct. The rule-pack-count sentences (`133 extract blocks and 747 classify arms`,
Java's `183`) were updated by hand in the same diff — `134`/`759`/`195` — confirmed against a fresh
`grep -c '^\[\[extract\]\]'`/`'^\[\[classify\]\]'` before committing.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --all` clean; `cargo clippy --release
--all-targets --workspace -- -D warnings` clean; `cargo test --release --workspace` all passing (one
new test function, `scans_java_bouncycastle_composite_kem_keygenerator`, 152 `scan_test.rs` cases,
one new). Both trust-invariant tests untouched and pass. `readme_rule_pack_counts_match_the_rule_packs`
confirmed failing before the README edit (133/747/183), passing after (134/759/195).

**Not done, said out loud:** `OPEN-ASK #ESTIMATORPERSIST` and `OPEN-ASK #CORPUSDRIFT` remain open,
neither this cycle's to resolve — this cycle could not have caused either (byte-identical dumps).
`#Y104` (BC Java `CompositeSignatures`, the same synthesis cycle's lower-ranked attribution item) and
`#Y102`/`#Y103` (README recall-figure and footnote-count staleness, same synthesis cycle, both
docs-only) were not started this cycle.

PRECISION: 97.17%

## Measurement, 2026-09-01 (Track A cycle 204 — `#Y106`, .NET `CompositeMLKem`, the KEM-side sibling of `CompositeMLDsa`)

Took `#Y106` as filed by the eighth same-day synthesis pass: `dotnet/runtime`'s `CompositeMLKem`
(`System.Security.Cryptography`, `[Experimental]`, merged 2026-08-28) ships the KEM-side counterpart
of `CompositeMLDsa` (`#Y95`), and `csharp.toml` had zero coverage. Re-verified directly against the
filing's own cited merge commits (`1595d607`, `632117ec` on `dotnet/runtime` `main`) rather than
taken on the lens's word: `GenerateKey(CompositeMLKemAlgorithm)` is byte-for-byte the same
static-factory-with-member-access shape `CompositeMLDsa.GenerateKey` already extracts, confirmed by
reading `csharp.toml:1602-1624`'s existing block before writing the new one. `CompositeMLKemAlgorithm`
pairs ML-KEM-768/1024 with a classical algorithm across twelve named members, but
`algorithm-table.toml` has no composite-family row to publish the pairing as its own id — mirroring
`CompositeMLDsa`'s own resolution, every member degrades to the same `ml-kem-unattributed` sentinel
`MLKem.GenerateKey`'s non-literal fallback already uses, so one extract/classify pair covers all
twelve literal and non-literal argument shapes alike. `CompositeMLKemCng` (the CNG-backed sibling) has
no implementation file in `dotnet/runtime` yet, only a reviewed API — out of scope, per this file's
standing "don't build for a reviewed-but-unimplemented API" discipline, applied identically to
`CompositeMLDsaCng` at the time it *was* implemented and to OpenSSL's unreleased `curveSM2MLKEM768`
before that.

One new extract/classify pair (`CSH-082`/`CRYPTO-1094`) appended to `csharp.toml`, plus one
`CSHARP_CALLEE_APIS` row in `scanner.rs` — the classify rule matches no api the extract layer emits
until that row exists, caught by `every_classify_rule_targets_an_api_the_extractor_can_emit` before
it could ship silently broken (it did, on the first build, exactly as designed).

**Coverage verified against the fixture, not corpus B.** `tests/fixtures/csharp/PqcNative.cs` gains
one call site (`CompositeMLKem.GenerateKey(CompositeMLKemAlgorithm.MLKem768WithX25519)`), asserted in
`scans_csharp_native_mlkem_mldsa_slhdsa` (`CRYPTO-1094`/`ml-kem-unattributed`). Independently
re-confirmed against the release binary on a standalone fixture: 0→1 finding, the exact prediction
the filing made.

**Tuple, per `#S12`: corpus B (150 projects) · scanner set `--source --deps --include-safe` ·
profile `nist-default` · pre-change binary built from this cycle's pre-edit tree (commit `c525f92`) ·
dump `work/y106_pre.json` (1916) · post-change binary from this cycle's tree · dump
`work/y106_post.json` (1916), both produced by the repo's own
`benchmarks/corpus-b-realworld/dump_findings.py`.**

**0 findings added, 0 removed, 0 reclassified — the expected result, not a surprise.** `CompositeMLKem`
is a .NET 10 preview API merged four days before this measurement; no project in the 150-project
manifest depends on a `dotnet/runtime` build recent enough to expose it, the same evidentiary tier
already accepted for `#Y95`'s `CompositeMLDsa`/`CompositeMLDsaCng` and `#Y100`'s BouncyCastle.NET
LMS/HSS.

**Precision 97.17%, held exactly.** `bin/precision.py work/y106_pre.json work/y106_post.json
--write-readme` confirms row-identity on the two byte-identical 1916-finding dumps and reports the
fresh stratified populations (`A=797, B=1119`, sample `A 262/271`, `B 355/364`) at 97.175%, rounding
to the same published two-decimal figure; `--write-readme` found the headline and comparison-table
figures already correct. The rule-pack-count sentences (`134 extract blocks and 759 classify arms`,
C#'s `122`) were updated by hand in the same diff — `135`/`760`/`123` — confirmed against a fresh
`grep -c '^\[\[extract\]\]'`/`'^\[\[classify\]\]'` before committing.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --all` clean; `cargo clippy
--all-targets -- -D warnings` clean; `cargo test --workspace` all passing (one new arm added to the
existing `scans_csharp_native_mlkem_mldsa_slhdsa` test rather than a new test function, since the
fixture and assertion list already existed for this exact API family). Both trust-invariant tests
untouched and pass. `readme_rule_pack_counts_match_the_rule_packs` confirmed failing before the
README edit (134/759/122), passing after (135/760/123).

**Not done, said out loud:** `#Y104` (BC Java `CompositeSignatures` attribution), `#Y107` (`MCP.md`
subcommand-name fix), and `#Y108` (`needs-human-approval`, `cargo deny` enforcement gap) remain open
from the same synthesis pass, none started this cycle. `OPEN-ASK #ESTIMATORPERSIST`/`#ESTIMATORPERSIST2`
and `#CORPUSDRIFT` remain open, none bearing on a byte-identical-dump coverage addition.

PRECISION: 97.17%

## Measurement, 2026-09-02 (Track A cycle 211 — Java BouncyCastle `CompositeSignatures` gains attribution, `#Y104`/`#Y105`)

**BouncyCastle's `CompositeSignatures.Mappings` registers 18 real `KeyPairGenerator`/`Signature`
algorithm names for `draft-ounsworth-pq-composite-sigs-13`** (verified against release tag
`r1rv85v2`, not the 31 a prior pass assumed — 14 of the 32 names in `CompositeIndex`'s internal maps
are never wired into the provider's `Mappings` loop and are not reachable at all). These previously
fell through to the `jca-unattributed` fallback; 36 new classify arms attribute each to its embedded
`ml-dsa-{44,65,87}` parameter set instead.

**`#Y105`'s root cause was bigger than filed: `nth_arg_string` grabbed an argument's raw source text
regardless of node kind**, so a non-literal identifier (`KeyPairGenerator.getInstance(keyType)`)
populated the same `algo` capture a real string literal would, indistinguishable downstream. Fixed by
requiring a `string_literal`/`string` node (`quipuu/crates/scan-source/src/scanner.rs`), and the
existing `CRYPTO-234` non-literal sentinel split into two arms: `CRYPTO-1131` for a literal that
matches no known algorithm name, `CRYPTO-234` retained for the genuinely non-literal case. This also
removed a real corpus false positive: `Cipher.getInstance(descriptor.getJCAAlgorithmID())` had
matched the `(?i)DES` regex only because the variable name `descriptor` contains "des".

**Tuple, per `#S12`: corpus B (150 projects) · scanner set `--source --deps --include-safe` ·
profile `nist-default` · pre-change binary from main at `5919711` (`work/y106_post.json`, 1916
findings) · post-change binary from this cycle's tree · dump `work/y105_post.json` (1915 findings),
both produced by the repo's own `benchmarks/corpus-b-realworld/dump_findings.py` (integrity-checked,
clone-relative paths).**

**2 findings added, 3 removed, net -1 (1916 → 1915).** Opened every cited line directly:
- `maven:org.bouncycastle:bcprov-jdk18on` `CompositeMLKEMEngine.java:249` and `:250`
  (`KeyPairGenerator.getInstance("ECDH")`, once as `tradProv == null` and once with an explicit
  provider) moved from the non-literal `CRYPTO-234` sentinel to the literal-but-unrecognized
  `CRYPTO-1131` sentinel — both a real ECDH ephemeral-keypair call, hand-labelled TP under both the
  old and new rule id. This is a reclassification (more specific: the argument is now correctly seen
  as the literal `"ECDH"` rather than treated as non-literal), not new coverage, so the 2 added rows
  and 2 of the 3 removed rows are the same 2 call sites before/after.
- `maven:org.opensaml:opensaml-xmlsec-api` `AlgorithmRegistry.java:324`
  (`Cipher.getInstance(descriptor.getJCAAlgorithmID())`) is the one net removal: a false positive
  fixed by the `nth_arg_string` node-kind check, since `descriptor` is a variable, not a DES literal.

**Precision 97.17% (persisted) → 97.18%.** `bin/precision.py work/y106_post.json work/y105_post.json
--added-tp 2 --added-fp 0 --write-readme` reproduced the anchored 97.17%/635-row baseline before
printing anything else, then folded the 2 hand-labelled TP (`CompositeMLKEMEngine.java:249`/`:250`)
into stratum B (`355/364` → `357/366`, matching the "delta lands in stratum B" output — reclassified
rows are new keys precision.py cannot match against the old label, so each is treated as a newly
sampled row rather than a like-for-like swap). Stratified-fresh populations (re-derived this run:
A=796, B=1119) give 97.183% (95% CI 95.90–98.47); pooled Wilson gives 97.174% (95% CI 95.58–98.21);
both round to the published 97.18%. Sample: A 262/271, B 357/366 — **637 of 1915 audited.**

**README already stated this figure** — `--write-readme` reported "nothing to write": the headline
(97.18%, 637 audited, 1915 total) and comparison-table cell were already correct from this cycle's
own prior edit, confirmed by re-running the measurement rather than trusting the prior pass.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --all` clean; `cargo clippy
--all-targets -- -D warnings` clean; `cargo test --workspace --release` all passing, including the
existing `scan_test.rs` literal-vs-non-literal coverage this cycle's fix extended. Both
trust-invariant tests (`test_run_acvp_kats_rejects_code_execution`,
`test_network_disabled_error`) untouched and pass.

**Not done, said out loud:** `#Y107` (`MCP.md` subcommand-name fix) and `#Y108`
(`needs-human-approval`, `cargo deny` enforcement gap) remain open from the same synthesis pass, not
started this cycle. `OPEN-ASK #ESTIMATORPERSIST`/`#ESTIMATORPERSIST2` and `#CORPUSDRIFT` remain open,
neither bearing on this reclassification-plus-one-FP-fix.

PRECISION: 97.18%

## Measurement, 2026-09-02 (Track A cycle 212 — jose4j `RSA_USING_SHA{384,512}`/`RSA_PSS_USING_SHA{384,512}` split off the sha256 catch-all)

**`java.toml`'s two jose4j classify arms (`CRYPTO-260`/`CRYPTO-261`) matched `^RSA_USING_SHA`/
`^RSA_PSS` with no digest anchor, so every `AlgorithmIdentifiers.RSA_USING_SHA384`/`SHA512` and
`RSA_PSS_USING_SHA384`/`SHA512` member matched the same broad prefix as its `SHA256` sibling and was
mislabelled `rsa-pkcs1-sha256`/`rsa-pss-sha256` regardless of which digest it actually names** — not
cosmetic: `algorithm-table.toml`'s `replacement` field differs between the sha256 and sha384/sha512
rows (`ml-dsa-65` vs. `ml-dsa-87` for the pkcs1 pair), so the mislabelled rows carried a wrong PQC
migration recommendation. First found 2026-08-28 (Backlog.md, Track A cycle 10, "surfaced by the fix,
not fixed"), independently rediscovered 2026-09-02 by a different lens 5 days later with zero
remediation between findings (backlog `#Y109`-adjacent P1 item, ninth same-day Track B synthesis).
Fixed the same way the ECDSA arms three rules below in the same file already split per curve: four
new digest-anchored classify arms (`CRYPTO-1133`/`1134` for `RSA_USING_SHA384`/`SHA512`, `CRYPTO-1135`/
`1136` for `RSA_PSS_USING_SHA384`/`SHA512`), and `CRYPTO-260`/`CRYPTO-261`'s own regex narrowed from a
prefix match to an exact `SHA256` match so they stop absorbing the other two digests.

**Tuple, per `#S12`: corpus B (150 projects) · scanner set `--source --deps --include-safe` ·
profile `nist-default` · pre-change binary from main at `cbb1792` (`work/jose4j_pre.json`, 1915
findings) · post-change binary from this cycle's tree (`work/jose4j_post.json`, 1915 findings), both
produced by the repo's own `benchmarks/corpus-b-realworld/dump_findings.py`.**

**4 findings added, 4 removed, net 0 (1915 → 1915), all four in one file.** Opened the cited lines
directly (`maven:org.bitbucket.b_c:jose4j`'s `RsaUsingShaAlgorithm.java`): line 97 is
`super(AlgorithmIdentifiers.RSA_USING_SHA384, "SHA384withRSA")`, line 105 is `RSA_USING_SHA512`/
`"SHA512withRSA"`, line 67 is `RSA_PSS_USING_SHA384`/`"SHA384withRSAandMGF1"`, line 78 is
`RSA_PSS_USING_SHA512`/`"SHA512withRSAandMGF1"` — all four real constructor calls naming the digest
the new rule now attributes, hand-verified true positive. No other row in the 1915-finding dump
moved.

**Precision 97.18% (persisted) → 97.19%.** `bin/precision.py work/jose4j_pre.json
work/jose4j_post.json --added-tp 4 --added-fp 0 --write-readme` reproduced the anchored baseline
before printing anything else, then folded the 4 hand-labelled TP into stratum A (`262/271` →
`266/275`, matching the "delta lands in stratum A" output — a reclassified row is a new key
precision.py cannot match against the old label, so each is treated as a newly sampled row rather
than a like-for-like swap). Stratified-fresh populations (re-derived this run: A=796, B=1119) give
97.195% (95% CI 95.92–98.47); pooled Wilson gives 97.183% (95% CI 95.59–98.21); both round to the
published 97.19%. Sample: A 266/275, B 355/364 — **639 of 1915 audited.**

**Held:** `cargo build --release --workspace` clean; `cargo fmt --all` clean; `cargo clippy
--all-targets -- -D warnings` clean; `cargo test --workspace` all passing. Both trust-invariant tests
(`test_run_acvp_kats_rejects_code_execution`, `test_network_disabled_error`) untouched and pass.
`readme_rule_pack_counts_match_the_rule_packs` updated and passing against java.toml's new 237
classify-arm count (233 → 237; README's two count sentences updated in the same diff).

**Not done, said out loud:** `#Y109`/`#Y110`/`#Y111` (README wording/date fixes from the same
synthesis pass) and `#Y113`/`#Y114` (OpenSSL native LMS, OpenMLS ciphersuite coverage gaps) remain
open, not started this cycle. `#Y107`/`#Y108` remain open from two cycles ago. `OPEN-ASK
#ESTIMATORPERSIST`/`#ESTIMATORPERSIST2` and `#CORPUSDRIFT` remain open, neither bearing on this fix.

PRECISION: 97.19%

## Measurement, 2026-09-02 (Track A cycle 213 — `#Y113`, OpenSSL 3.6 native LMS keygen coverage)

**`cpp.toml`'s generic keygen classify list (`EVP_PKEY_CTX_new_from_name`/`EVP_PKEY_Q_keygen`) had
arms for every ML-KEM/ML-DSA/SLH-DSA parameter set and the OpenSSL 3.5 hybrid PQ/T KEM names, but
none for LMS** — OpenSSL 3.6 (GA 2025-10-01, now 3.6.4) ships native LMS signature support
(RFC 8554 / SP 800-208) through the exact same entry points, verified directly against
`docs.openssl.org/3.6/man7/EVP_PKEY-LMS/` and `EVP_SIGNATURE-LMS/`, fetched 2026-09-02. One new
classify arm (`CRYPTO-1137`) matches `alg = "LMS"` case-insensitively and reuses the existing `lms`
algorithm id `algorithm-table.toml` already carries (added for BouncyCastle.NET, `#Y100`) — same
extension shape as the OpenSSL 3.5 hybrid-KEM arms directly above it in the same file, not new
ground. No distinct `"HSS"` algorithm string is documented anywhere in OpenSSL's own manpages, so
only LMS is covered — guessing at an unconfirmed name was explicitly rejected, same call the hybrid
arms already made for `X448MLKEM1024`'s missing TLS group. `algorithm-table.toml`'s `lms` row note
updated in the same commit to name the new C/C++ reachability path (rule 4 — the note itself named
only the C# path before this).

A fixture call (`openssl_generic_keygen_lms`, `crypto.c`) and a new test
(`scans_c_openssl_native_lms`) assert `CRYPTO-1137`/`lms` fires; `every_classify_rule_targets_an_api_the_extractor_can_emit`
confirms the rule targets an API the scanner's `CPP_GENERIC_KEYGEN_APIS` table already emits (no
scanner change needed — same entry points as the existing ML-KEM/ML-DSA/SLH-DSA arms).

**Tuple, per `#S12`: corpus B (150 projects) · scanner set `--source --deps --include-safe` ·
profile `nist-default` · pre-change binary from main at `a23a123` (`work/jose4j_post.json`, 1915
findings) · post-change binary from this cycle's tree (`work/y113_post.json`, 1915 findings), both
produced by the repo's own `benchmarks/corpus-b-realworld/dump_findings.py`.**

**0 findings added, 0 removed, 0 reclassified — the expected result, not a surprise.** No corpus B
project calls `EVP_PKEY_CTX_new_from_name`/`EVP_PKEY_Q_keygen` with `"LMS"` — OpenSSL 3.6 is eleven
months old and no vendored clone has adopted it yet, the same "real gap, zero corpus recall" shape
`#Y100`'s BouncyCastle.NET LMS/HSS coverage hit for the identical reason (no `nuget` ecosystem in
this corpus at all). The fixture, not the corpus, is the instrument for this rule.

**Precision 97.19% (persisted) → 97.17%.** `bin/precision.py work/jose4j_post.json
work/y113_post.json --write-readme` reproduced the byte-identical 1915-finding dump on both sides
(0 added, 0 removed) and re-derived the stratified-fresh populations from scratch: `A=796, B=1119`,
sample `A 262/271, B 355/364` — **635 of 1915 audited** — giving 97.175% (95% CI 95.89–98.46),
rounding to the published 97.17%. This is the same stratified-fresh-vs-carried-constants estimator
drift `DECISION #ESTIMATOROFRECORD` already adjudicated (carried constants would have read 97.159%);
no finding moved, so the change contributes 0 to this delta. `--write-readme` applied the figure to
both README sites (headline paragraph and comparison table) in this diff.

**Held:** `cargo build --release --workspace` clean; `cargo fmt --all` clean; `cargo clippy
--all-targets -- -D warnings` clean; `cargo test --workspace` all passing, including the new
`scans_c_openssl_native_lms` test. Both trust-invariant tests (`test_run_acvp_kats_rejects_code_execution`,
`test_network_disabled_error`) untouched and pass. `readme_rule_pack_counts_match_the_rule_packs`
updated for cpp.toml's new 131 classify-arm count (130 → 131; README's two count sentences —
"803 classify arms" and "C/C++'s 131" — updated in the same diff).

**Not done, said out loud:** `#Y114` (OpenMLS ciphersuite coverage) and `#Y107`/`#Y108` remain open.
`OPEN-ASK #ESTIMATORPERSIST`/`#ESTIMATORPERSIST2` and `#CORPUSDRIFT` remain open, neither bearing on
this change.

PRECISION: 97.17%

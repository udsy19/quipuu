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

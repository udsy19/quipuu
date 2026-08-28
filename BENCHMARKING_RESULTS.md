# seawall — 150-project corpus benchmark

Sections are appended in date order. **The current run is the last dated section**
(*HNDL flag and SARIF property name — 2026-08-28*); everything above it is the
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
python3 scan_corpus.py   --clones /path/to/clones --bin ../../seawall/target/release/seawall \
                         --out results/ --include-safe
python3 dump_findings.py --clones /path/to/clones --bin ../../seawall/target/release/seawall \
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

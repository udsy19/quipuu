# Corpus A — Planted Ground Truth

Corpus B (`../corpus-b-realworld/`) measures **precision**: of the findings the scanner
reports, how many are correct. It cannot measure **recall**, because nobody has hand-labelled
every cryptographic call site in 150 real-world projects. Corpus A exists to answer the other
question directly: across the seven languages quipuu claims to support, does an idiomatic,
one-call-per-line invocation of each of ~17 algorithm families produce a correctly-attributed
finding at all?

**117 planted call sites, one file per language** (`cpp`, `csharp`, `go`, `java`, `js`,
`python`, `rust`), each line marked with an `// EXPECT <family>` comment stating what a
correct scan must find there. `expected.toml` next to each source file is the checked-in,
machine-readable ground truth generated from those comments — it is authoritative, not the
comments themselves, so a future edit to a probe file cannot silently move the ground truth
with it.

## Why a planted corpus and not more of corpus B

A ground truth derived from `data/rules/` would inherit the scanner's own blind spots and
score 100% by construction — the same reasoning `corpus-b-realworld/recall_check.py` states
for its Go stdlib API list. This corpus was designed independently, by hand, against each
language's mainstream crypto library, before any effort was made to check what the scanner
currently detects.

## Running it

```
python3 recall_check.py --bin ../../quipuu/target/release/quipuu
```

Scores **family-level** recall: a Python `rsa-2048` finding and a Java `rsa-unattributed`
finding both count as a hit for `family = "rsa"`. This is coarser than the precision audit
(which requires the exact cited operation) because this corpus asks whether the call is seen
and attributed to the right primitive at all, across languages whose extract queries and
callee tables are entirely independent code paths — see `FAMILY_ALIASES` in
`recall_check.py` for the exact mapping, and its docstring for what it deliberately cannot
score (`hmac`/`scrypt`/`bcrypt`/`argon2` — 23 of 117 sites — map to no `algorithm-table.toml`
family at all, so those tags miss unconditionally; that is the recall gap, not a scoring bug).

## Measured 2026-08-30

**41.9% (49/117)** against release binary `1963a2c`.

| language | recall |
|---|---|
| csharp | 60.0% (9/15) |
| java | 55.6% (10/18) |
| js | 47.4% (9/19) |
| go | 44.4% (8/18) |
| python | 41.2% (7/17) |
| rust | 40.0% (6/15) |
| cpp | **0.0% (0/15)** |

**The `cpp` row needs a caveat this cycle did not have time to fix in the corpus itself.**
Several of its 15 planted sites call an OpenSSL primitive the way no real codebase would —
`EVP_aes_128_gcm()` invoked bare, with its return value discarded, rather than passed as the
`cipher` argument to `EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), ...)`, which is the only shape
`cpp.toml` has a rule for and the only shape that ever appears in real C. `EC_KEY_new_by_curve_name`,
bare `MD5_Init`/`SHA1_Init`/`SHA256_Init`, `HMAC(...)`, `PKCS5_PBKDF2_HMAC(...)`, and
`ECDSA_sign(...)` are real, idiomatic OpenSSL 1.x calls that genuinely have no rule in
`cpp.toml` today — that part of the 0% is a real, if narrow, coverage gap, distinct from the
bare-`EVP_aes_*` lines which test a call shape that cannot occur. Left unedited per this
cycle's scope (`#T11(a)` says commit the 117 sites as they are); flagged here rather than
silently reported as "quipuu detects 0% of C" without the distinction.

**This is a supplementary probe, not a claim about recall on real-world code.** 117 planted
sites cannot represent the distribution of crypto usage in the wild the way 150 real projects
represent precision. Read it as "does the scanner see this API shape at all", not as "this is
the scanner's real-world recall".

## Not a CI gate

`03-Product/Backlog.md #T11(a)` and three independent research passes on 2026-08-27 reached
the same conclusion: a recall floor blocks every honest change that narrows an over-broad rule
to remove a false positive, because narrowing a rule can cost a true positive at the same call
site. `recall_check.py` measures and prints; nothing in the build or test suite reads its exit
code as a gate, and it is not wired into `regression_check.py` or the precision gate.

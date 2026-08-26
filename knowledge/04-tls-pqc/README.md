# TLS PQC Reference for cryptoscope

**Scope:** Live TLS endpoint scanning — cipher suite, key-exchange group, and signature algorithm enumeration.
**Snapshot date:** June 2026.
**Audience:** cryptoscope/scan-network module authors.

Items marked **[DRAFT]** are not yet an RFC; codepoints may change before standardisation.
Items marked **[VERIFY]** require a fresh registry lookup before shipping.

---

## 1. PQC Hybrid Key-Exchange Groups in Production

### Governing IETF document

`draft-ietf-tls-ecdhe-mlkem` (formerly `draft-kwiatkowski-tls-ecdhe-mlkem`).
As of mid-2026 the draft is at revision -05 (May 2026, expires Nov 2026); IESG approved the hybrid-design framework via RFC 9794 (Sep 2025).

| Group name | Decimal | Hex | DTLS-OK | Recommended | Notes |
|---|---|---|---|---|---|
| `SecP256r1MLKEM768` | 4587 | `0x11EB` | Y | N | FIPS-compliant hybrid (P-256 + ML-KEM-768); not Chrome default |
| `X25519MLKEM768` | 4588 | `0x11EC` | Y | **Y** | The production standard; ~95 % of all PQ handshakes on Cloudflare |
| `SecP384r1MLKEM1024` | 4589 | `0x11ED` | Y | — | Higher security level; rare in production |

Source: [IANA TLS Supported Groups registry](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8); [draft-ietf-tls-ecdhe-mlkem](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/)

### Legacy / pre-standard codepoints

| Group name | Hex | Status | Reference |
|---|---|---|---|
| `X25519Kyber768Draft00` | `0x6399` | Deprecated; Recommended: **N** | `draft-tls-westerbaan-xyber768d00-03` |
| `SecP256r1Kyber768Draft00` | `0x639A` | Deprecated | same draft |

`0x6399` is formally registered in IANA with the note "Pre-standards version of Kyber768". Chrome 116–130 (Apr 2024 – Oct 2024) used this codepoint; Chrome 131 (Nov 2024) switched to `0x11EC`.
Source: [draft-tls-westerbaan-xyber768d00](https://datatracker.ietf.org/doc/draft-tls-westerbaan-xyber768d00/)

### Pure ML-KEM groups

No pure ML-KEM (non-hybrid) group is Recommended in the IANA registry as of mid-2026. `rustls-post-quantum` exposes a `MLKEM768` constant for local API completeness but no server is expected to negotiate a pure ML-KEM group in production — the hybrid is the deployment path. **[VERIFY: check IANA for a pure MLKEM768 row]**

### Deployment status (mid-2026)

| Implementor | Default group | Since |
|---|---|---|
| **Chrome 131+** | `X25519MLKEM768` (0x11EC) | Nov 2024 (Chrome 131) — superseded 0x6399 |
| **Firefox 132+** | `X25519MLKEM768` (0x11EC) | Firefox 132 desktop; QUIC/HTTP3 Firefox 135+ |
| **Apple (iOS/macOS 26)** | `X25519MLKEM768` (0x11EC) | Sep 2025; URLSession + Network.framework |
| **Cloudflare edge** | Accepts all three 0x11E{B,C,D}; server-side PQC universal | 2024 onwards |
| **AWS (non-FIPS endpoints)** | ML-KEM hybrid; CRYSTALS-Kyber support ends 2026 | 2025–2026 |
| **Java JDK 24+** | `X25519MLKEM768` prioritised first | JDK 24 **[VERIFY]** |

Wire note: `X25519MLKEM768` key share = **1,216 bytes** (1,184 ML-KEM + 32 X25519). Oversized ClientHello triggers path-MTU issues and faulty middlebox rejection — a scanner must handle TCP fragmentation and connection resets gracefully.

---

## 2. TLS 1.3 Signature Algorithm IANA Codepoints

### Classical schemes (RFC 8446, stable)

Source: [RFC 8446 §4.2.3](https://www.rfc-editor.org/rfc/rfc8446#section-4.2.3); [IANA TLS SignatureScheme registry](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-16)

| Algorithm | Hex | Notes |
|---|---|---|
| `rsa_pkcs1_sha256` | `0x0401` | TLS 1.3: certificate-verify only |
| `rsa_pkcs1_sha384` | `0x0501` | Same caveat |
| `rsa_pkcs1_sha512` | `0x0601` | Same caveat |
| `ecdsa_secp256r1_sha256` | `0x0403` | |
| `ecdsa_secp384r1_sha384` | `0x0503` | |
| `ecdsa_secp521r1_sha512` | `0x0603` | |
| `rsa_pss_rsae_sha256` | `0x0804` | rsaEncryption OID |
| `rsa_pss_rsae_sha384` | `0x0805` | |
| `rsa_pss_rsae_sha512` | `0x0806` | |
| `ed25519` | `0x0807` | |
| `ed448` | `0x0808` | |
| `rsa_pss_pss_sha256` | `0x0809` | RSASSA-PSS OID |
| `rsa_pss_pss_sha384` | `0x080A` | |
| `rsa_pss_pss_sha512` | `0x080B` | |

### PQC signature schemes — **[DRAFT]** codepoints, not yet RFC

All codepoints below are draft-requested values. They MUST NOT be used in TLS 1.2. No production server is expected to negotiate these in mid-2026.

#### ML-DSA (FIPS 204) — `draft-ietf-tls-mldsa`

| Algorithm | Hex |
|---|---|
| `mldsa44` | `0x0904` |
| `mldsa65` | `0x0905` |
| `mldsa87` | `0x0906` |

Source: [draft-ietf-tls-mldsa](https://datatracker.ietf.org/doc/draft-ietf-tls-mldsa/)

#### SLH-DSA (FIPS 205) — `draft-reddy-tls-slhdsa`

| Algorithm | Hex |
|---|---|
| `slhdsa_sha2_128s` | `0x0911` |
| `slhdsa_sha2_128f` | `0x0912` |
| `slhdsa_sha2_192s` | `0x0913` |
| `slhdsa_sha2_192f` | `0x0914` |
| `slhdsa_sha2_256s` | `0x0915` |
| `slhdsa_sha2_256f` | `0x0916` |
| `slhdsa_shake_128s` | `0x0917` |
| `slhdsa_shake_128f` | `0x0918` |
| `slhdsa_shake_192s` | `0x0919` |
| `slhdsa_shake_192f` | `0x091A` |
| `slhdsa_shake_256s` | `0x091B` |
| `slhdsa_shake_256f` | `0x091C` |

Source: [draft-reddy-tls-slhdsa](https://datatracker.ietf.org/doc/draft-reddy-tls-slhdsa/)

#### Composite ML-DSA — `draft-reddy-tls-composite-mldsa`

Proposed `0x0907`–`0x0910` range (ML-DSA paired with RSA/ECDSA/EdDSA). **[VERIFY exact assignments — draft only]**
Source: [draft-reddy-tls-composite-mldsa](https://datatracker.ietf.org/doc/draft-reddy-tls-composite-mldsa/)

---

## 3. rustls Capabilities (mid-2026)

### Version milestones

| Version | PQC milestone |
|---|---|
| 0.23.0 | `CryptoProvider` trait stabilised; external `kx_groups` possible |
| 0.23.22 | ML-KEM (`X25519MLKEM768` + `MLKEM768`) **moved from `rustls-post-quantum` into rustls core** |
| 0.23.27 | ML-KEM **enabled by default** in the default `CryptoProvider` |
| **0.23.40** | Latest stable (2026-04-28) |
| 0.24.0-dev.0 | Pre-release (2026-01-28); API stabilisation |

Sources: [crates.io/crates/rustls](https://crates.io/crates/rustls); [docs.rs/rustls](https://docs.rs/rustls/latest/rustls/)

### `rustls-post-quantum` crate

- Before rustls 0.23.22 this crate provided `X25519MLKEM768` and `MLKEM768` over `aws-lc-rs`.
- After 0.23.22 its ML-KEM role is subsumed by rustls core; the crate remains published but is no longer the primary integration point.
- Latest: **0.2.1** **[VERIFY on crates.io]**

Source: [crates.io/crates/rustls-post-quantum](https://crates.io/crates/rustls-post-quantum)

### Building a TLS prober with rustls

rustls supports a custom `kx_groups` list per connection via `CryptoProvider`. The first entry in `kx_groups` becomes the key_share sent in ClientHello.

```rust
use std::sync::Arc;
use rustls::crypto::{aws_lc_rs, CryptoProvider};
use rustls::ClientConfig;

// Build a single-group probe for X25519MLKEM768
let provider = CryptoProvider {
    kx_groups: vec![
        aws_lc_rs::kx_group::X25519_MLKEM768,  // 0x11EC, in rustls core since 0.23.22
    ],
    ..aws_lc_rs::default_provider()
};

let config = ClientConfig::builder_with_provider(Arc::new(provider))
    .with_safe_default_protocol_versions()?
    .with_root_cert_store(root_store)
    .with_no_client_auth();
```

To advertise **unknown / synthetic codepoints** (e.g., `0x6399` for legacy probing):

```rust
// Implement SupportedKxGroup as a stub that advertises the codepoint
// but returns an error if the server selects it (handshake will fail — that's OK,
// the scanner only needs to record which ServerHello the server sent).
struct StubKxGroup(rustls::NamedGroup);
impl rustls::crypto::SupportedKxGroup for StubKxGroup {
    fn name(&self) -> rustls::NamedGroup { self.0 }
    fn start(&self) -> Result<Box<dyn rustls::crypto::ActiveKeyExchange>, rustls::Error> {
        Err(rustls::Error::General("stub — enumeration only".into()))
    }
}
```

**Limitations:**
- rustls validates that every `cipher_suite` in the config has a compatible `kx_group`. Keep cipher_suites consistent with your stub NamedGroup category.
- For truly arbitrary byte-level ClientHello construction (malformed records, codepoints rustls cannot model), use raw `tokio::net::TcpStream` + hand-assembled TLS record bytes (see §4).

---

## 4. Building a TLS Prober in Rust

### Approach comparison

| Approach | Why to use | Why not to use |
|---|---|---|
| **rustls + custom `CryptoProvider`** | Real full handshake; accurate negotiation results; PQC groups handled natively | Cannot send malformed/arbitrary bytes; requires at least one plausible cipher suite |
| **Raw `tokio::TcpStream` + manual TLS bytes** | Full byte-level control; any codepoint; middlebox probing | Must marshal TLS record/handshake layers manually; no crypto without extra deps; complex |
| **`tls-parser`** | Zero-copy nom-based parsing of received TLS records (ServerHello, Alert, HRR) | **Parse-only — cannot construct or send messages** |

### Recommended two-tier architecture

**Tier 1 — real handshakes** (for all production and near-standard groups):
Use `rustls 0.23.x` + `tokio-rustls` with a per-probe `CryptoProvider` whose `kx_groups` contains exactly one entry. One `TcpStream` per probe; reconnect for each group under test. Parse the negotiated parameters from the completed `ClientConnection`.

**Tier 2 — synthetic codepoints** (for legacy `0x6399`, exotic groups, middlebox testing):
Allocate a raw `tokio::net::TcpStream`; write a hand-assembled TLS 1.3 `ClientHello` record with the target codepoint in `supported_groups` and a minimal `key_share`. Read the server response; use `tls-parser` to decode the `ServerHello` or `Alert`.

### testssl.sh enumeration method (for comparison)

testssl.sh uses **one TCP connection + one ClientHello per cipher/group**:

- Uses bash raw `/dev/tcp` sockets (not `openssl s_client`) with pre-generated key material in `etc/tls_data.txt`.
- Per probe: establishes TCP, sends ClientHello with **a single candidate entry**, reads ServerHello (= supported) or `handshake_failure` alert (= not supported).
- Up to ~370 ciphers tested via `-e/--each-cipher`, each requiring a separate connection.
- `MAX_SOCKET_FAIL=2`, `MAX_OSSL_FAIL=2` before aborting the run.

The core insight: **servers always pick from the advertised list** — the only reliable enumeration strategy is one candidate per connection.
Source: [github.com/drwetter/testssl.sh](https://github.com/drwetter/testssl.sh)

### Useful parsing crates

- `tls-parser 0.12.2` — parse `ServerHello`, `Alert`, `Certificate`, `HelloRetryRequest`; no construction.
- `x509-parser 0.18.0` — decode certificate chain; extract subject, SANs, signature algorithm.

---

## 5. Rate Limiting and Responsible Use

### Reference defaults from existing scanners

| Tool | Max concurrent conns/target | Connect timeout | Retries | Notes |
|---|---|---|---|---|
| **sslyze 3.x** | **5** (hard limit) | **5 s** | **3** | `--slow_connection` reduces further; all values configurable via Python API |
| **testssl.sh** | 1 (sequential) | N/A (bash; no explicit config) | `MAX_SOCKET_FAIL=2` | Sequential by design |
| **nmap ssl-enum-ciphers** | 1 per host (sequential probes) | **5,000 ms** | None built-in | Nmap `-T` timing flags apply |

Sources: sslyze docs; testssl.sh source; nmap scripting engine source.

### Recommended defaults for cryptoscope

```
concurrent_connections_per_host = 5        # matches sslyze 3.x
connect_timeout_ms               = 5_000
handshake_timeout_ms             = 5_000
max_retries_per_probe            = 2        # matches testssl.sh MAX_SOCKET_FAIL
retry_backoff_initial_ms         = 25       # with jitter
inter_probe_delay_ms             = 0        # no delay by default; expose as --rate-limit flag
global_concurrent_hosts          = 10       # configurable
```

Include scanner name + version in the TLS SNI or as a comment in TCP options for network transparency. Log which probes were skipped/timed-out so reports are auditable.

---

## 6. PQC Production Rollout Status (Mid-2026)

### Cloudflare

| Period | PQ hybrid share of TLS 1.3 traffic |
|---|---|
| Early 2024 | ~2 % |
| March 2025 | ~38 % |
| End of 2025 | **52 %** |
| Mid-2026 (Phase 2 target) | PQC-only mode (no classical downgrade) under active rollout |

- ~95 % of Cloudflare's PQ connections use `X25519MLKEM768` (0x11EC).
- "Post-quantum for all" server-side coverage: complete across all Cloudflare-proxied sites.
- PQC at origin server level began being tested automatically in Q4 2025.
- PQ digital signatures in certificates: pending standardisation; not yet deployed.

Source: [blog.cloudflare.com/tag/post-quantum](https://blog.cloudflare.com/tag/post-quantum/)

### Google Chrome

- Chrome 116 (2023): first experimental Kyber support.
- Chrome 124 (Apr 2024): `X25519Kyber768Draft00` (0x6399) on by default.
- **Chrome 131 (Nov 2024): switched to `X25519MLKEM768` (0x11EC); 0x6399 retired.**
- Chrome 131+ is the stable branch as of mid-2026; X25519MLKEM768 on by default.

Source: [chromestatus.com feature 5257822742249472](https://chromestatus.com/feature/5257822742249472)

### Firefox

- Firefox 132+ (desktop): `X25519MLKEM768` default for TLS.
- Firefox 135+: `X25519MLKEM768` also default for QUIC/HTTP3.
- Prior versions (124+) had it behind `security.tls.enable_kyber` pref.

Source: [mozilla.org Firefox 132 release notes](https://www.mozilla.org/en-US/firefox/132.0/releasenotes/)

### Apple

- **iOS/macOS 26 (Sep 2025):** X25519MLKEM768 on by default in URLSession and Network.framework.
- CryptoKit exposes `ML-KEM-768`, `ML-KEM-1024` (KEM), `ML-DSA-65`, `ML-DSA-87` (signatures).
- 4 days after iOS 26 launch: iOS PQ-capable share of Cloudflare traffic jumped from <2 % to 11 %.

### AWS

- ML-KEM hybrid on all non-FIPS endpoint regions: KMS, ACM, Secrets Manager, S3, CloudFront, ELB, API Gateway.
- CRYSTALS-Kyber (0x6399/0x639A) support ends across all AWS endpoints in 2026; ML-KEM only thereafter.
- Handshake overhead: ~1,600 additional bytes; ~80–150 µs extra compute.

Source: [AWS security blog — post-quantum TLS](https://aws.amazon.com/blogs/security/post-quantum-tls-now-supported-in-aws-kms/)

### Microsoft Azure

- SymCrypt (platform crypto library): ML-KEM, ML-DSA, LMS, XMSS shipped through 2024.
- Windows 11 / Windows Server 2025 (Nov 2025): ML-KEM + ML-DSA built-in.
- .NET 10: ML-KEM and ML-DSA included.
- ADCS ML-DSA certificates (ML-DSA-44/65/87): GA May 2026.
- TLS PQ hybrid (X25519MLKEM768) on Windows 11/Server 2025: available via Windows Insider as of mid-2026; GA status **[VERIFY]**.

Source: [Microsoft Security Blog — quantum-safe roadmap](https://techcommunity.microsoft.com/t5/microsoft-security-blog/microsoft-s-quantum-safe-roadmap/ba-p/3936433)

---

## 7. OpenSSL 3.x PQC Status

### OpenSSL 3.5.0 (LTS, released 8 Apr 2025 — supported until Apr 2030)

**First upstream release with native PQC — no external provider required for:**

| Algorithm | FIPS standard | Type |
|---|---|---|
| ML-KEM | FIPS 203 | KEM |
| ML-DSA | FIPS 204 | Signature (implementation derived from BoringSSL) |
| SLH-DSA | FIPS 205 | Signature |

Default TLS group list in OpenSSL 3.5 **prioritises hybrid PQC KEMs** (`X25519MLKEM768` first, then `X25519`). Legacy groups removed from defaults.

Distribution availability as of mid-2025: Fedora 42, Ubuntu 25.04, Debian unstable. RHEL 10 and Ubuntu 24.04 LTS require backports or source build.

Source: [openssl.org/news/openssl-3.5-notes.html](https://www.openssl.org/news/openssl-3.5-notes.html)

### OpenSSL 3.4.x

No native PQC. PQC before 3.5 required oqs-provider exclusively.

### oqs-provider (Open Quantum Safe)

- Latest: **0.10.0** (aligned with liboqs 0.14.0, released 29 Jul 2025).
- When loaded with **OpenSSL ≥ 3.5.0**, oqs-provider **automatically disables ML-KEM and ML-DSA** (native in core).
- Still provides: BIKE, Classic McEliece, FrodoKEM, HQC, NTRU-Prime, CROSS, Falcon, MAYO, SNOVA, UOV, XMSS, LMS.
- **Not FIPS-validated. Not suitable for regulated-environment production use.**
- liboqs 0.15.0 (upcoming): removes legacy Dilithium; last version to support old SPHINCS+ name (→ SLH-DSA).

Source: [github.com/open-quantum-safe/oqs-provider](https://github.com/open-quantum-safe/oqs-provider)

### Detection pattern implications for cryptoscope

A codebase using `EVP_KEM_*` or `EVP_PKEY_ML_KEM_*` APIs from OpenSSL headers indicates OpenSSL 3.5+ native PQC.
A codebase loading `oqs-provider` via `OSSL_PROVIDER_load(ctx, "oqs")` indicates pre-3.5 or experimental PQC.
A codebase calling `EVP_PKEY_CTX_kem_set_name(ctx, "kyber768")` via oqs-provider indicates legacy Kyber naming.

---

## 8. Relevant Rust Crates

| Crate | Latest stable (mid-2026) | Role | Why / Evidence |
|---|---|---|---|
| `rustls` | **0.23.40** (2026-04-28) | Async-safe TLS 1.2/1.3; primary handshake engine | PQC groups in core since 0.23.22; `CryptoProvider` trait enables per-probe group control. [crates.io](https://crates.io/crates/rustls) |
| `rustls-post-quantum` | **0.2.1** [VERIFY] | Was the PQC plugin; now superseded by rustls core | Kept for pre-0.23.22 compat reference; do not add as new dependency. [crates.io](https://crates.io/crates/rustls-post-quantum) |
| `tokio-rustls` | **0.26.4** | Async TLS streams (rustls over Tokio) | Bridges rustls `ClientConfig` to `tokio::net::TcpStream`; required for async probing. [crates.io](https://crates.io/crates/tokio-rustls) |
| `tls-parser` | **0.12.2** | Parse-only TLS record/handshake structures | nom-based; zero-copy; decode ServerHello/Alert/HRR bytes from Tier 2 raw probes. [crates.io](https://crates.io/crates/tls-parser) |
| `x509-parser` | **0.18.0** | X.509 v3 certificate parsing | Decode cert chain from TLS handshake; extract SAN, signature algorithm OID, public key type. [crates.io](https://crates.io/crates/x509-parser) |
| `rustls-webpki` | **0.103.12** | Web PKI cert verification | Active fork of original `webpki`; used internally by rustls; add directly if custom chain validation needed. [crates.io](https://crates.io/crates/rustls-webpki) |
| `webpki` | (deprecated) | — | Do **not** add as new dependency; use `rustls-webpki` instead. |
| `webpki-roots` | **1.0.5** | Mozilla root CA bundle | Stable 1.0 API since May 2025; use as `RootCertStore` source when no system trust store is desired. [crates.io](https://crates.io/crates/webpki-roots) |
| `ring` | **0.17.14** | Low-level crypto (BoringSSL-derived) | 517M+ downloads; used by older rustls; no native ML-KEM. [crates.io](https://crates.io/crates/ring) |
| `aws-lc-rs` | **1.16.3** | AWS-LC bindings; ring-compatible API | Default crypto provider for rustls 0.23+; ships ML-KEM natively; FIPS feature flag available. [crates.io](https://crates.io/crates/aws-lc-rs) |
| `boring` | **5.1.0** | Cloudflare BoringSSL Rust bindings | v5: `pq-experimental` feature removed; PQC on by default; `set_curves_list()` for group control. Useful for probing via a BoringSSL code path. [crates.io](https://crates.io/crates/boring) |
| `openssl` | **0.10.x** (openssl-sys 0.9.116, 2026-05-16) | OpenSSL 1.0.2–4.x FFI bindings | `openssl-src` feature bundles OpenSSL 3.6.2; ML-KEM accessible if using 3.5+ headers. [crates.io](https://crates.io/crates/openssl) |

---

## DECISIONS for cryptoscope/scan-network

### (a) Crate dependencies

**Required:**

```toml
[dependencies]
rustls          = { version = "0.23", features = ["aws_lc_rs"] }
tokio-rustls    = "0.26"
tokio           = { version = "1", features = ["net", "rt-multi-thread"] }
tls-parser      = "0.12"
x509-parser     = "0.18"
rustls-webpki   = "0.103"
webpki-roots    = "1"
aws-lc-rs       = "1"
```

**Do NOT add:**
- `rustls-post-quantum` — superseded by rustls 0.23.22+ core.
- `webpki` — deprecated; use `rustls-webpki`.
- `ring` — only if you need ring-specific APIs; `aws-lc-rs` covers the same surface and is the rustls default.

**Optional / future:**
- `boring = "5"` — if you add a BoringSSL probe code path (e.g., to confirm BoringSSL-specific negotiation behaviour).
- `openssl = "0.10"` — only if scanning for OpenSSL oqs-provider indicators via FFI.

### (b) Prober strategy

Use the **two-tier approach**:

**Tier 1 (real handshakes) — for all production groups:**

Build one `ClientConfig` per probe with a `CryptoProvider` whose `kx_groups` contains exactly one `SupportedKxGroup`. Iterate through the canonical probe list (see §c). Use `tokio-rustls` to run the handshake asynchronously. Record what was negotiated from the completed `ClientConnection`. Reconnect for each group; do not reuse connections across group probes.

**Tier 2 (raw bytes) — for synthetic/legacy codepoints:**

Allocate a raw `tokio::net::TcpStream`. Manually assemble a TLS 1.3 `ClientHello` record with the target codepoint in `supported_groups`/`key_share`. Read the raw response bytes. Use `tls-parser` to decode the `ServerHello` or `handshake_failure` `Alert`. This covers `0x6399` and any future draft codepoints that rustls does not model.

**Do NOT pursue:**
- A fully custom TLS stack. testssl.sh's approach is reasonable for a bash tool; in Rust, the two-tier design gives you real cryptographic results at Tier 1 and synthetic probing at Tier 2 with much less implementation surface.

### (c) Default enumeration list

#### Key-exchange groups (probe in this order)

| Priority | Group | Hex | Tier | Rationale |
|---|---|---|---|---|
| 1 | `X25519MLKEM768` | `0x11EC` | 1 | Production standard; Chrome/Firefox/Apple default |
| 2 | `SecP256r1MLKEM768` | `0x11EB` | 1 | FIPS-compliant hybrid; AWS/gov deployments |
| 3 | `SecP384r1MLKEM1024` | `0x11ED` | 1 | High-security hybrid |
| 4 | `X25519Kyber768Draft00` | `0x6399` | 2 (raw) | Legacy Chrome 116–130; older server configs |
| 5 | `x25519` | `0x001D` | 1 | Classical baseline |
| 6 | `secp256r1` | `0x0017` | 1 | Classical baseline |
| 7 | `secp384r1` | `0x0018` | 1 | Classical baseline |

#### Cipher suites (TLS 1.3 only for PQC relevance)

All three TLS 1.3 mandatory suites; PQC does not add new cipher suite codepoints (KEM is orthogonal):

- `TLS_AES_128_GCM_SHA256` (`0x1301`)
- `TLS_AES_256_GCM_SHA384` (`0x1302`)
- `TLS_CHACHA20_POLY1305_SHA256` (`0x1303`)

#### Signature algorithms to advertise in ClientHello

Advertise the full classical list (see §2) plus the **[DRAFT]** PQC schemes as a lower-priority tail. Recording whether the server selects a PQC signature algorithm prepares cryptoscope for imminent RFC publication.

---

*End of TLS PQC reference. Re-check IANA registry and draft revision numbers before any release.*

# Corpus B — npm Ecosystem (25 projects)

## Selection Methodology

Projects were selected as the top-25 most-downloaded packages on npm (measured by weekly downloads via npmjs.com stats, snapshot June 2026) that meet all quality gates:
- OSS with permissive license (MIT, Apache-2.0, BSD, or similar)
- > 1,000 lines of code
- At least one commit in the last 12 months (or archived but high-install-base legacy code)
- Cryptographically relevant: direct use of crypto primitives, TLS, JWT/JOSE, SSH, OAuth, or security middleware

## Ranking (by weekly downloads, June 2026)

| Rank | Package | canonical_id | Primary Crypto Surface |
|------|---------|--------------|------------------------|
| 1 | lodash | `npm:lodash` | Utility (minimal crypto, negative control) |
| 2 | react | `npm:react` | UI framework (minimal crypto, negative control) |
| 3 | axios | `npm:axios` | HTTPS requests, TLS |
| 4 | express | `npm:express` | HTTP server framework, HTTPS |
| 5 | debug | `npm:debug` | Debugging utility (negative control) |
| 6 | ms | `npm:ms` | Time parsing (negative control) |
| 7 | semver | `npm:semver` | Version parsing (negative control) |
| 8 | chalk | `npm:chalk` | Terminal styling (negative control) |
| 9 | commander | `npm:commander` | CLI framework (negative control) |
| 10 | glob | `npm:glob` | File globbing (negative control) |
| 11 | jsonwebtoken | `npm:jsonwebtoken` | JWT HS256/RS256/ES256 |
| 12 | node-forge | `npm:node-forge` | RSA/AES/TLS/X.509 pure JS |
| 13 | crypto-js | `npm:crypto-js` | AES/SHA/HMAC/RSA pure JS |
| 14 | bcryptjs | `npm:bcryptjs` | bcrypt pure JS implementation |
| 15 | tweetnacl | `npm:tweetnacl` | Curve25519/Ed25519/XSalsa20 |
| 16 | elliptic | `npm:elliptic` | EC cryptography (P256/secp256k1) |
| 17 | jsrsasign | `npm:jsrsasign` | RSA/ECDSA/DSA/JWT/X.509 JS |
| 18 | node-rsa | `npm:node-rsa` | RSA encryption/signing JS |
| 19 | ssh2 | `npm:ssh2` | SSH-2 client/server |
| 20 | jose | `npm:jose` | JWK/JWS/JWE/JWT full suite |
| 21 | openpgp | `npm:openpgp` | OpenPGP RSA/ECC encryption |
| 22 | oauth | `npm:oauth` | OAuth 1.0 HMAC-SHA1/RSA-SHA1 |
| 23 | passport | `npm:passport` | Authentication middleware |
| 24 | helmet | `npm:helmet` | HTTP security headers |
| 25 | cookie | `npm:cookie` | Cookie parsing (CSRF adjacent) |

## Notes

- Ranks 1-10 include several non-crypto packages; they serve as negative controls to test scanner false-positive rates.
- `node-forge` (rank 12) repository moved from `digitalbazaar/node-forge` to `digitalbazaar/forge`; `substituted_for` is set accordingly.
- `jsrsasign` (rank 17) correct repository is `kjur/jsrsasign`; original candidate `nicowillis/jsrsasign` did not exist.
- `oauth` (rank 22) correct repository is `ciaranj/node-oauth`; original candidate `oauthjs/node-oauth` returned 404.

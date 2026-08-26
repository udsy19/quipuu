# Corpus B — PyPI Ecosystem (25 projects)

## Selection Methodology

Projects were selected as the top-25 most-downloaded packages on PyPI (measured by monthly downloads via pypistats.org, snapshot June 2026) that meet all quality gates:
- OSS with permissive license (MIT, Apache-2.0, BSD, or similar)
- > 1,000 lines of code
- At least one commit in the last 12 months (or intentionally-archived but high-usage legacy code)
- Cryptographically relevant: direct use of crypto primitives, TLS, PKI, JWT/JOSE, or SSH

## Ranking (by monthly downloads, June 2026)

| Rank | Package | canonical_id | Primary Crypto Surface |
|------|---------|--------------|------------------------|
| 1 | boto3 | `pypi:boto3` | AWS SigV4, KMS client, HTTPS |
| 2 | urllib3 | `pypi:urllib3` | TLS 1.2/1.3, certificate verification |
| 3 | requests | `pypi:requests` | HTTPS, mutual TLS |
| 4 | charset-normalizer | `pypi:charset-normalizer` | Encoding (minimal crypto) |
| 5 | certifi | `pypi:certifi` | CA certificate bundle |
| 6 | idna | `pypi:idna` | IDNA encoding for TLS SNI |
| 7 | setuptools | `pypi:setuptools` | Package distribution integrity |
| 8 | six | `pypi:six` | Python 2/3 compat (legacy) |
| 9 | python-dateutil | `pypi:python-dateutil` | Timestamp parsing for JWT/tokens |
| 10 | s3transfer | `pypi:s3transfer` | S3 multipart, SSE |
| 11 | botocore | `pypi:botocore` | SigV4, HTTPS, credential management |
| 12 | cryptography | `pypi:cryptography` | RSA/EC/AES/X.509/TLS (full stack) |
| 13 | pyOpenSSL | `pypi:pyOpenSSL` | OpenSSL Python bindings |
| 14 | paramiko | `pypi:paramiko` | SSH-2 protocol implementation |
| 15 | pyjwt | `pypi:pyjwt` | JWT encoding/decoding |
| 16 | pyasn1 | `pypi:pyasn1` | ASN.1 parsing for X.509/CMS |
| 17 | rsa | `pypi:rsa` | RSA encryption/signing |
| 18 | pynacl | `pypi:pynacl` | Curve25519, Ed25519, XSalsa20 |
| 19 | pycryptodome | `pypi:pycryptodome` | AES/RSA/ECC/hashes |
| 20 | bcrypt | `pypi:bcrypt` | bcrypt password hashing |
| 21 | ecdsa | `pypi:ecdsa` | ECDSA signing (pure Python) |
| 22 | cffi | `pypi:cffi` | C FFI (enables crypto C bindings) |
| 23 | oauthlib | `pypi:oauthlib` | OAuth 1.0/2.0 HMAC signing |
| 24 | authlib | `pypi:authlib` | JWT/JWK/JOSE/OpenID Connect |
| 25 | python-jose | `pypi:jose` | JOSE/JWT implementation |

## Notes

- `cryptography` (rank 12) is the canonical Python crypto library and is also cross-listed in the `crypto-adjacent` tier under `pyca/cryptography`.
- `paramiko` (rank 14) includes a full SSH-2 implementation with RSA/ECDSA/Ed25519 host keys.
- Packages with minimal crypto relevance (charset-normalizer, six, python-dateutil) are included because they appear in the dependency trees of all crypto-using packages and the scanner must correctly report them as non-crypto.

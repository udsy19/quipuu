# Corpus B — Go Modules Ecosystem (25 projects)

## Selection Methodology

Projects were selected as the top-25 most-downloaded Go modules (measured by pkg.go.dev and proxy.golang.org download metrics, snapshot June 2026) that meet all quality gates:
- OSS with permissive license (Apache-2.0, MIT, BSD, or similar)
- > 1,000 lines of code
- At least one commit in the last 12 months
- Cryptographically relevant: TLS, PKI, JWT/JOSE, cipher/hash/MAC/KEM/signature primitives, key management, or cloud auth

## Ranking (by Go module downloads, June 2026)

| Rank | Module | canonical_id | Primary Crypto Surface |
|------|--------|--------------|------------------------|
| 1 | aws-sdk-go | `go-modules:github.com/aws/aws-sdk-go` | SigV4/HMAC-SHA256, HTTPS |
| 2 | aws-sdk-go-v2 | `go-modules:github.com/aws/aws-sdk-go-v2` | SigV4a, KMS, HTTPS |
| 3 | client-go | `go-modules:k8s.io/client-go` | mTLS, X.509, RBAC tokens |
| 4 | vault | `go-modules:github.com/hashicorp/vault` | PKI engine, Transit, JWT auth |
| 5 | consul | `go-modules:github.com/hashicorp/consul` | mTLS service mesh, CA mgmt |
| 6 | golang-jwt/jwt | `go-modules:github.com/golang-jwt/jwt` | JWT HS/RS/ES/EdDSA |
| 7 | jwt-go | `go-modules:github.com/dgrijalva/jwt-go` | JWT (archived, legacy) |
| 8 | go-jose | `go-modules:github.com/go-jose/go-jose` | JWK/JWS/JWE/JWT |
| 9 | circl | `go-modules:github.com/cloudflare/circl` | ML-KEM/ML-DSA/SPHINCS+/PQC |
| 10 | jwx | `go-modules:github.com/lestrrat-go/jwx` | JWK/JWS/JWE/JWT |
| 11 | hydra | `go-modules:github.com/ory/hydra` | OIDC/OAuth2, JWT key mgmt |
| 12 | coredns | `go-modules:github.com/coredns/coredns` | DNSSEC, DoT/DoH |
| 13 | minio | `go-modules:github.com/minio/minio` | SSE-C/SSE-S3/SSE-KMS, TLS |
| 14 | grafana | `go-modules:github.com/grafana/grafana` | TLS, JWT/SAML SSO, DB encryption |
| 15 | prometheus | `go-modules:github.com/prometheus/prometheus` | TLS, bearer tokens |
| 16 | etcd | `go-modules:go.etcd.io/etcd` | mTLS cluster, JWT auth |
| 17 | kubernetes | `go-modules:k8s.io/kubernetes` | X.509 bootstrap, TLS, RBAC |
| 18 | moby | `go-modules:github.com/moby/moby` | TLS API, content trust, Notary |
| 19 | containerd | `go-modules:github.com/containerd/containerd` | mTLS gRPC, image encryption |
| 20 | gin | `go-modules:github.com/gin-gonic/gin` | HTTPS, JWT middleware |
| 21 | echo | `go-modules:github.com/labstack/echo` | HTTPS, JWT middleware |
| 22 | go-redis | `go-modules:github.com/redis/go-redis` | TLS Redis, ACL auth |
| 23 | pgx | `go-modules:github.com/jackc/pgx` | TLS PostgreSQL, SCRAM-SHA-256 |
| 24 | mongo-go-driver | `go-modules:go.mongodb.org/mongo-driver` | TLS MongoDB, CSFLE, SCRAM |
| 25 | x-crypto | `go-modules:golang.org/x/crypto` | SSH, bcrypt, argon2, PBKDF2 |

## Notes

- `circl` (rank 9) is the PQC-forward entry for this ecosystem; it contains ML-KEM (Kyber), ML-DSA (Dilithium), SPHINCS+, FrodoKEM, and experimental algorithms. Scanners should detect PQC-ready usage here.
- `jwt-go` (rank 7) is archived but is included due to its extremely high legacy install base in production Go services.
- `moby` (rank 18) was historically `docker/docker`; `substituted_for` field documents the rename.
- `x-crypto` (rank 25) is `golang.org/x/crypto`, sourced from `github.com/golang/crypto`.

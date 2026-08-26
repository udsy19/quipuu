# Corpus B — Maven Ecosystem (25 projects)

## Selection Methodology

Projects were selected as the top-25 most-downloaded crypto-relevant artifacts on Maven Central (measured by download counts, snapshot June 2026) that meet all quality gates:
- OSS with permissive license (Apache-2.0, MIT, LGPL, EPL, or similar)
- > 1,000 lines of code
- At least one commit in the last 12 months
- Cryptographically relevant: TLS, PKI, JWT/JOSE, cipher APIs, digest/MAC, key management, or authentication

## Ranking (by Maven Central downloads, June 2026)

| Rank | Artifact | canonical_id | Primary Crypto Surface |
|------|---------|--------------|------------------------|
| 1 | bcprov-jdk18on | `maven:org.bouncycastle:bcprov-jdk18on` | Full JCE provider: RSA/EC/AES/X.509 |
| 2 | bcpkix-jdk18on | `maven:org.bouncycastle:bcpkix-jdk18on` | PKIX/CMS/PKCS#8/X.509/OCSP |
| 3 | java-jwt | `maven:com.auth0:java-jwt` | JWT RS256/HS256/ES256 |
| 4 | jjwt-api | `maven:io.jsonwebtoken:jjwt-api` | JWT HS/RS/EC algorithms |
| 5 | netty-handler | `maven:io.netty:netty-handler` | TLS handler, X.509 |
| 6 | httpclient5 | `maven:org.apache.httpcomponents.client5:httpclient5` | HTTPS client, TLS |
| 7 | okhttp | `maven:com.squareup.okhttp3:okhttp` | HTTPS client, TLS (Kotlin) |
| 8 | spring-security-crypto | `maven:org.springframework.security:spring-security-crypto` | BCrypt, PBKDF2, AES |
| 9 | commons-codec | `maven:commons-codec:commons-codec` | Base64, Hex, MD5/SHA digests |
| 10 | jetty-server | `maven:org.eclipse.jetty:jetty-server` | HTTPS server, TLS |
| 11 | tomcat-embed-core | `maven:org.apache.tomcat.embed:tomcat-embed-core` | HTTPS server, TLS |
| 12 | tink | `maven:com.google.crypto.tink:tink` | AEAD, hybrid crypto, JWT |
| 13 | conscrypt-openjdk-uber | `maven:org.conscrypt:conscrypt-openjdk-uber` | BoringSSL JCE provider |
| 14 | aws-java-sdk-kms | `maven:com.amazonaws:aws-java-sdk-kms` | AWS KMS client |
| 15 | nimbus-jose-jwt | `maven:com.nimbusds:nimbus-jose-jwt` | JWK/JWS/JWE/JWT full suite |
| 16 | shiro-crypto-core | `maven:org.apache.shiro:shiro-crypto-core` | AES/hash/bcrypt |
| 17 | unboundid-ldapsdk | `maven:com.unboundid:unboundid-ldapsdk` | LDAP TLS/SASL, X.509 |
| 18 | api-ldap-codec-standalone | `maven:org.apache.directory.api:api-ldap-codec-standalone` | LDAP ASN.1, TLS |
| 19 | jose4j | `maven:org.bitbucket.b_c:jose4j` | JWE/JWS/JWT (Java) |
| 20 | parsson | `maven:org.eclipse.parsson:parsson` | JSON-P (JWT/JSON adjacent) |
| 21 | cryptacular | `maven:org.cryptacular:cryptacular` | Java crypto utilities |
| 22 | aws-encryption-sdk-java | `maven:com.amazonaws:aws-encryption-sdk-java` | Envelope encryption |
| 23 | azure-security-keyvault-keys | `maven:com.azure:azure-security-keyvault-keys` | Azure KMS, RSA/EC keys |
| 24 | aws-sdk-java-v2-s3 | `maven:software.amazon.awssdk:s3` | S3 SSE, SigV4 |
| 25 | opensaml-xmlsec-api | `maven:org.opensaml:opensaml-xmlsec-api` | XML Signature/Encryption |

## Notes

- `bcprov-jdk18on` (rank 1) and `bcpkix-jdk18on` (rank 2) share the same repository (`bcgit/bc-java`) but are separate Maven artifacts with different scan paths.
- `nimbus-jose-jwt` (rank 15) and `jose4j` (rank 19) are hosted on Bitbucket; HTTPS git URLs were verified with `git ls-remote`.
- `opensaml-xmlsec-api` (rank 25) is hosted on `git.shibboleth.net`; URL was verified.

// Fixture: Go JWT algorithm string-table dispatch patterns.
// These switch statements are how golang-jwt, go-jose, lestrrat-go/jwx, and
// similar libraries route JWT algorithm choices at runtime. The scanner must
// detect these in addition to direct API calls (rsa.GenerateKey, etc.).
package main

// parseAlgorithm dispatches JWT algorithm strings, typical of
// github.com/golang-jwt/jwt and github.com/dgrijalva/jwt-go consumers.
func parseAlgorithm(alg string) {
	switch alg {
	case "RS256": // CRYPTO-700 → rsa-pkcs1-sha256-2048
		// use RSA-PKCS1-SHA256
	case "RS384": // CRYPTO-701 → rsa-pkcs1-sha384-3072
		// use RSA-PKCS1-SHA384
	case "RS512": // CRYPTO-702 → rsa-pkcs1-sha512-4096
		// use RSA-PKCS1-SHA512
	case "PS256": // CRYPTO-703 → rsa-pss-sha256-2048
		// use RSA-PSS-SHA256
	case "ES256": // CRYPTO-710 → ecdsa-p256
		// use ECDSA P-256
	case "ES384": // CRYPTO-711 → ecdsa-p384
		// use ECDSA P-384
	case "ES512": // CRYPTO-712 → ecdsa-p521
		// use ECDSA P-521
	case "EdDSA": // CRYPTO-720 → ed25519
		// use EdDSA / Ed25519
	case "HS256": // CRYPTO-730 → sha-256 (HMAC, low severity)
		// use HMAC-SHA256
	case "HS384": // CRYPTO-731 → sha-384 (HMAC, low severity)
		// use HMAC-SHA384
	case "HS512": // CRYPTO-732 → sha-512 (HMAC, low severity)
		// use HMAC-SHA512
	case "none": // CRYPTO-740 → critical CWE-347
		// signature verification disabled — dangerous
	}
}

// encryptionAlgorithm dispatches JWE key-wrap algorithms.
func encryptionAlgorithm(alg string) {
	switch alg {
	case "RSA-OAEP": // CRYPTO-750 → rsa-2048
		// use RSA-OAEP
	case "RSA-OAEP-256": // CRYPTO-751 → rsa-2048
		// use RSA-OAEP-SHA256
	case "A256GCM": // CRYPTO-760 → aes-256-gcm
		// use AES-256-GCM content encryption
	}
}

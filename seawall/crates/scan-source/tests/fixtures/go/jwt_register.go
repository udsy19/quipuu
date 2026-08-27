// Fixture: Go JWT-library algorithm registration patterns.
//
// Pre-Phase-9 fix, scanning this produced ZERO findings. The Phase 7 switch
// detector required `case "RS256":` syntax, but the canonical Go JWT
// libraries (golang-jwt-jwt, go-jose, lestrrat-go/jwx) don't dispatch on
// raw strings — they REGISTER algorithm names via composite literals,
// call-as-constructor, or const declarations. All three shapes are below.

package fixture

import "crypto"

// Shape A — composite_literal first positional element.
// golang-jwt-jwt's actual pattern: &SigningMethodHMAC{"HS256", crypto.SHA256}.
type SigningMethodRSA struct {
	Name string
	Hash crypto.Hash
}

var (
	SigningMethodRS256 = &SigningMethodRSA{"RS256", crypto.SHA256} // CRYPTO-700
	SigningMethodRS384 = &SigningMethodRSA{"RS384", crypto.SHA384} // CRYPTO-701
	SigningMethodRS512 = &SigningMethodRSA{"RS512", crypto.SHA512} // CRYPTO-702
)

// Shape B — call-as-constructor (go-jose / jwx pattern).
type SignatureAlgorithm string

func NewSignatureAlgorithm(s string) SignatureAlgorithm { return SignatureAlgorithm(s) }

var (
	ES256 = NewSignatureAlgorithm("ES256") // CRYPTO-710
	ES384 = SignatureAlgorithm("ES384")    // CRYPTO-711
	EdDSA = NewSignatureAlgorithm("EdDSA") // CRYPTO-720
)

// Shape C — const declarations (jwx pattern).
const (
	hs256 = "HS256" // CRYPTO-730
	hs384 = "HS384" // CRYPTO-731
	none  = "none"  // CRYPTO-740 (critical)
)

// Negative — the string "RS256" inside a comment or doc string MUST NOT fire.
// Doc reference: "RS256" — should not produce a finding.
var docNote = `the algorithm name "RS256" appears here as documentation`

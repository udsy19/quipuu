// Fixture: `"none"` in the two shapes where it IS a JWA algorithm name.
//
// Both are real registry shapes taken from lestrrat-go/jwx: a run of
// constructor calls in one function body, and a dispatch switch. In each the
// name sits beside other JOSE names, which is what makes it an algorithm and
// not the English word.

package fixture

type SignatureAlgorithm string

func NewSignatureAlgorithm(s string) SignatureAlgorithm { return SignatureAlgorithm(s) }

var algorithms [4]SignatureAlgorithm

// Shape A — sibling constructor calls in one function body (jwx's
// jwa/signature_gen.go, where the real CRYPTO-740 on the corpus lives).
func register() {
	algorithms[0] = NewSignatureAlgorithm("HS256")
	algorithms[1] = NewSignatureAlgorithm("ES512")
	algorithms[2] = NewSignatureAlgorithm("none") // CRYPTO-740 (critical)
	algorithms[3] = NewSignatureAlgorithm("PS512")
}

// Shape B — dispatch switch listing the algorithms a verifier accepts.
func verifierFor(alg string) string {
	switch alg {
	case "RS256":
		return "rsa"
	case "none": // CRYPTO-740 (critical)
		return "unsigned"
	}
	return ""
}

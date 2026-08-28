// Fixture: JOSE algorithm-registry retrieval versus algorithm selection.
// Modelled on lestrrat-go/jwx, which contributes 230 of corpus B's findings
// and whose generated jwa package is entirely retrieval.
package jwa

type SignatureAlgorithm string

func lookupBuiltinSignatureAlgorithm(s string) SignatureAlgorithm { return SignatureAlgorithm(s) }
func LookupSignatureAlgorithm(s string) (SignatureAlgorithm, bool) {
	return SignatureAlgorithm(s), true
}
func NewSignatureAlgorithm(s string) SignatureAlgorithm { return SignatureAlgorithm(s) }
func sign(alg SignatureAlgorithm, payload []byte) []byte { return payload }

// Retrieval only — naming an algorithm to fetch its descriptor signs nothing.
// None of these lines may produce a finding.

func ES384() SignatureAlgorithm { return lookupBuiltinSignatureAlgorithm("ES384") }

func lookupInTest() {
	v, ok := LookupSignatureAlgorithm("PS256")
	_, _ = v, ok
}

// Selection — these still configure a real operation and must fire.

// CRYPTO-720: registers EdDSA as a usable signature algorithm.
var eddsa = NewSignatureAlgorithm("EdDSA")

// CRYPTO-700: the retrieved descriptor is handed straight to a signing call,
// so this line does select RS256 for a signature.
func signWithRS256(payload []byte) []byte {
	return sign(lookupBuiltinSignatureAlgorithm("RS256"), payload)
}

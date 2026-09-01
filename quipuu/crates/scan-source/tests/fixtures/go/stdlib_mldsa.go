// Fixture: Go's own stdlib crypto/mldsa (Go 1.27) — the sibling #V5 named
// alongside crypto/mlkem and #Y30 did not ship. Unlike crypto/mlkem,
// GenerateKey/NewPrivateKey/NewPublicKey/Verify take a Parameters value as an
// argument, and the only way to construct one is to call
// MLDSA44()/MLDSA65()/MLDSA87() — real usage (lestrrat-go/jwx) stores that
// value in a variable rather than inlining it, so both shapes are covered
// here. A same-API third-party package (filippo.io/mldsa, found live in
// boringssl's ssl/test/runner) shares this callee text, which is why the
// rule's message does not name a specific import.

package fixtures

import "crypto/mldsa"

func generate44() (*mldsa.PrivateKey, error) {
	return mldsa.GenerateKey(mldsa.MLDSA44())
}

func generate87() (*mldsa.PrivateKey, error) {
	return mldsa.GenerateKey(mldsa.MLDSA87())
}

func registerParams() []mldsa.Parameters {
	return []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()}
}

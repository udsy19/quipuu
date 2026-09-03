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

import (
	"crypto"
	"crypto/mldsa"
)

func generate44() (*mldsa.PrivateKey, error) {
	return mldsa.GenerateKey(mldsa.MLDSA44())
}

func generate87() (*mldsa.PrivateKey, error) {
	return mldsa.GenerateKey(mldsa.MLDSA87())
}

func registerParams() []mldsa.Parameters {
	return []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()}
}

// #Y140(a) / CRYPTO-1208 — crypto.MLDSAMu, Go 1.27's external-mu signalling
// constant: pkg.go.dev/crypto documents PrivateKey.Sign as requiring a
// pre-hashed mu representative when opts.HashFunc() returns this value, and
// crypto.Hash itself satisfies SignerOpts by returning itself, so the real
// call shape passes the bare constant as the opts argument directly.
func signExternalMu(sk *mldsa.PrivateKey, mu []byte) ([]byte, error) {
	return sk.Sign(nil, mu, crypto.MLDSAMu)
}

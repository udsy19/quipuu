// Fixture: X-Wing (draft-connolly-cfrg-xwing-kem), the X25519+ML-KEM-768
// hybrid KEM combiner used by HPKE. Both circl's own `kem/xwing` package and
// Google Tink's internal `hybrid/internal/xwing` package export the same
// function names under the local identifier "xwing" — this fixture uses
// circl's own signatures, but the rule matches on callee text alone, the same
// as the crypto/mldsa vs. filippo.io/mldsa ambiguity elsewhere in this pack.
package main

import (
	"crypto/rand"

	"github.com/cloudflare/circl/kem/xwing"
)

func xwingKeygen() {
	_, _, _ = xwing.GenerateKeyPair(rand.Reader)
}

func xwingEncap(pk, seed []byte) ([]byte, []byte, error) {
	return xwing.Encapsulate(pk, seed)
}

func xwingDecap(ct, sk []byte) []byte {
	return xwing.Decapsulate(ct, sk)
}

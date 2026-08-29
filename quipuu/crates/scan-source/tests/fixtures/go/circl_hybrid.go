// Fixture: a `circl`-style hybrid signature scheme that AND-combines an
// Ed25519/ECDSA signature with a post-quantum one in the same Sign/Verify
// function — the shape `cloudflare/circl/sign/eddilithium2` and
// `eddilithium3` actually use. Backlog #Y20: without the co-occurrence
// check, quipuu tells a team that already migrated to keep migrating.
package main

import (
	"crypto/ecdsa"
	"crypto/rand"

	"github.com/cloudflare/circl/sign/dilithium/mode2"
	"github.com/cloudflare/circl/sign/ed25519"
)

func hybridSign(dsk *mode2.PrivateKey, esk ed25519.PrivateKey, msg, sig []byte) []byte {
	mode2.SignTo(dsk, msg, sig[:mode2.SignatureSize])
	esig := ed25519.Sign(esk, msg)
	return append(sig, esig...)
}

func hybridVerify(dpk *mode2.PublicKey, epk ed25519.PublicKey, msg, sig []byte) bool {
	if !mode2.Verify(dpk, msg, sig[:mode2.SignatureSize]) {
		return false
	}
	return ed25519.Verify(epk, msg, sig[mode2.SignatureSize:])
}

// A plain ECDSA operation in a function that never touches a PQC package —
// the message must stay unmodified.
func plainEcdsaVerify(pub *ecdsa.PublicKey, hash, sig []byte) bool {
	return ecdsa.VerifyASN1(pub, hash, sig)
}

var _ = rand.Reader

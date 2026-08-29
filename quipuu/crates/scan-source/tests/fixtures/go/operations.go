// Fixture: Go stdlib sign/verify/hash *operation* sites, distinct from the
// constructor sites in main.go. These reach us with no key argument shape at
// all, so the family is known from the callee but the parameter set is not.
package main

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"math/big"
)

func ecdsaOps(priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey, hash, sig []byte) {
	_, _, _ = ecdsa.Sign(rand.Reader, priv, hash)
	_, _ = ecdsa.SignASN1(rand.Reader, priv, hash)
	_ = ecdsa.VerifyASN1(pub, hash, sig)
}

func rsaOps(priv *rsa.PrivateKey, pub *rsa.PublicKey, digest, sig []byte) {
	_, _ = rsa.SignPKCS1v15(rand.Reader, priv, 0, digest)
	_ = rsa.VerifyPKCS1v15(pub, 0, digest, sig)
}

func ed25519Ops(priv ed25519.PrivateKey, pub ed25519.PublicKey, message, sig []byte) {
	_ = ed25519.Sign(priv, message)
	_ = ed25519.Verify(pub, message, sig)
}

func hashSums(data []byte) {
	_ = md5.Sum(data)
	_ = sha1.Sum(data)
}

func dsaOps(priv *dsa.PrivateKey, pub *dsa.PublicKey, hash []byte, r, s *big.Int) {
	_ = dsa.GenerateKey(priv, rand.Reader)
	_, _, _ = dsa.Sign(rand.Reader, priv, hash)
	_ = dsa.Verify(pub, hash, r, s)
}

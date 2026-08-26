// Fixture: known crypto API call sites for scanner integration tests.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
)

func keys() {
	// RSA-1024 — below the 2048-bit floor.
	rsa1024, _ := rsa.GenerateKey(rand.Reader, 1024)
	_ = rsa1024

	// RSA-2048 — quantum-vulnerable.
	rsa2048, _ := rsa.GenerateKey(rand.Reader, 2048)
	_ = rsa2048

	// RSA-4096 — still quantum-vulnerable.
	rsa4096, _ := rsa.GenerateKey(rand.Reader, 4096)
	_ = rsa4096

	// ECDSA P-256.
	ec256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_ = ec256

	// ECDSA P-384.
	ec384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	_ = ec384
}

func hashes() {
	_ = md5.New()
	_ = sha1.New()
}

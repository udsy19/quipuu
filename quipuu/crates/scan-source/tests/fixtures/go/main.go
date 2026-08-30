// Fixture: known crypto API call sites for scanner integration tests.
package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
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
	_ = sha256.New()
	_ = sha512.New()
}

// TLS key-exchange — exercises GO-032 / CRYPTO-032..035.
func tlsCurves() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
		},
	}
}

// crypto/ecdh — exercises GO-033 / CRYPTO-036..039.
func ecdhCurves() {
	_ = ecdh.X25519()
	_ = ecdh.P256()
}

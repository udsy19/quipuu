// Fixture: the control case for `#Y160`'s CRYPTO-1251 — a file where the
// ML-DSA key is constructed locally (`mldsa.MLDSA65()`) and then passed
// straight into x509.CreateCertificate in the same file. GO-077 already
// covers the construction call; CRYPTO-1251 must NOT also fire on the
// x509.CreateCertificate call here, or every file GO-077 already scores
// would be double-counted. The `go_mldsa_external_key_marker` file-scope
// gate (scanner.rs) is what suppresses it: the file imports crypto/mldsa
// but also calls the constructor, so the marker is absent.
package fixtures

import (
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
)

func issueLocallyGenerated() ([]byte, error) {
	priv, _ := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65())
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example"},
	}
	return x509.CreateCertificate(rand.Reader, template, template, priv.Public(), priv)
}

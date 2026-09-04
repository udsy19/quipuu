// Fixture: crypto/x509 certificate issuance/parsing on an externally-sourced
// ML-DSA key — `#Y160`. Go 1.27's crypto/x509 gained ML-DSA certificate
// support, but a key loaded from a KMS/HSM/vault and only ever touched
// through x509.CreateCertificate/.ParseCertificate/.CreateCertificateRequest
// produces no finding from GO-077/GO-081 (go.toml), both of which require a
// local `mldsa.MLDSA{44,65,87}()` construction call in the file. The key
// here comes from `loadFromVault` (never a local constructor call), so
// CRYPTO-1251 should fire at both x509 call sites.
//
// See `x509_mldsa_local_key.go` for the sibling fixture proving this rule
// does NOT double-count a file GO-077 already covers.
package fixtures

import (
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
)

func loadFromVault() []byte { return nil }

func loadKeyFromVault() *mldsa.PrivateKey {
	der := loadFromVault()
	priv, _ := x509.ParsePKCS8PrivateKey(der)
	return priv.(*mldsa.PrivateKey)
}

func issueFromVault(priv *mldsa.PrivateKey) ([]byte, error) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example"},
	}
	return x509.CreateCertificate(rand.Reader, template, template, priv.Public(), priv)
}

func parseIssued(raw []byte) (*x509.Certificate, error) {
	return x509.ParseCertificate(raw)
}

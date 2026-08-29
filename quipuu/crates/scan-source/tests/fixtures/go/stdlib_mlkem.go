// Fixture: Go's own stdlib crypto/mlkem (Go 1.24) — the zero-dependency
// path to ML-KEM that shipped hours before circl's third-party equivalent
// gained full coverage (backlog #Y30). Before GO-074/CRYPTO-079/080
// existed, every call here reported nothing at all.

package fixtures

import "crypto/mlkem"

func generate768() (*mlkem.DecapsulationKey768, error) {
	return mlkem.GenerateKey768()
}

func generate1024() (*mlkem.DecapsulationKey1024, error) {
	return mlkem.GenerateKey1024()
}

func rebuildDecap768(seed []byte) (*mlkem.DecapsulationKey768, error) {
	return mlkem.NewDecapsulationKey768(seed)
}

func rebuildEncap1024(encoded []byte) (*mlkem.EncapsulationKey1024, error) {
	return mlkem.NewEncapsulationKey1024(encoded)
}

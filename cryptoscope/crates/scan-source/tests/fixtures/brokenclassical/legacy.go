// Broken-classical Go stdlib call sites. crypto/des and crypto/rc4 exist only
// for legacy interop; neither had a rule before, and crypto/aes.NewCipher had
// a rule with no matcher to feed it.
package brokenclassical

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rc4"
)

// CRYPTO-042
func TripleDES(key []byte) (cipher.Block, error) {
	return des.NewTripleDESCipher(key)
}

// CRYPTO-043
func RC4(key []byte) (*rc4.Cipher, error) {
	return rc4.NewCipher(key)
}

// CRYPTO-040
func AES(key []byte) (cipher.Block, error) {
	return aes.NewCipher(key)
}

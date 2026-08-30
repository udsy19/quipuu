package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

func probe() {
	rsa.GenerateKey(rand.Reader, 2048)                                  // EXPECT rsa
	ecdsa.GenerateKey(elliptic.P256(), rand.Reader)                     // EXPECT ecdsa
	curve25519.X25519(nil, nil)                                         // EXPECT ecdh
	dsa.GenerateKey(nil, rand.Reader)                                   // EXPECT dsa
	md5.New()                                                           // EXPECT md5
	sha1.New()                                                          // EXPECT sha1
	sha256.New()                                                        // EXPECT sha256
	sha512.New384()                                                     // EXPECT sha384
	hmac.New(sha256.New, nil)                                           // EXPECT hmac
	pbkdf2.Key(nil, nil, 4096, 32, sha256.New)                          // EXPECT pbkdf2
	scrypt.Key(nil, nil, 32768, 8, 1, 32)                               // EXPECT scrypt
	bcrypt.GenerateFromPassword(nil, 10)                                // EXPECT bcrypt
	argon2.IDKey(nil, nil, 1, 64*1024, 4, 32)                           // EXPECT argon2
	b, _ := aes.NewCipher(make([]byte, 16))                             // EXPECT aes128
	cipher.NewGCM(b)                                                    // EXPECT aesgcm
	des.NewTripleDESCipher(make([]byte, 24))                            // EXPECT 3des
	rc4.NewCipher(nil)                                                  // EXPECT rc4
	chacha20poly1305.New(nil)                                           // EXPECT chacha20
}

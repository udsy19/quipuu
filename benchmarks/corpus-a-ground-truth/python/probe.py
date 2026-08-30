import hashlib, hmac, bcrypt
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, dh, x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from argon2 import PasswordHasher

def probe():
    rsa.generate_private_key(public_exponent=65537, key_size=2048)       # EXPECT rsa
    ec.generate_private_key(ec.SECP256R1())                              # EXPECT ecdsa
    x25519.X25519PrivateKey.generate()                                   # EXPECT ecdh
    dsa.generate_private_key(key_size=2048)                              # EXPECT dsa
    hashlib.md5()                                                        # EXPECT md5
    hashlib.sha1()                                                       # EXPECT sha1
    hashlib.sha256()                                                     # EXPECT sha256
    hashlib.sha384()                                                     # EXPECT sha384
    hmac.new(b"k", b"m", hashlib.sha256)                                 # EXPECT hmac
    PBKDF2HMAC(algorithm=hashlib.sha256, length=32, salt=b"s", iterations=600000)  # EXPECT pbkdf2
    Scrypt(salt=b"s", length=32, n=2**14, r=8, p=1)                      # EXPECT scrypt
    bcrypt.hashpw(b"pw", bcrypt.gensalt())                               # EXPECT bcrypt
    PasswordHasher()                                                     # EXPECT argon2
    Cipher(algorithms.AES(b"0"*16), modes.GCM(b"0"*12))                  # EXPECT aes128
    Cipher(algorithms.TripleDES(b"0"*24), modes.CBC(b"0"*8))             # EXPECT 3des
    Cipher(algorithms.ARC4(b"0"*16), None)                               # EXPECT rc4
    ChaCha20Poly1305(b"0"*32)                                            # EXPECT chacha20

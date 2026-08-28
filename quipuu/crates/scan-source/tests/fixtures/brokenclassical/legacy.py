"""Broken-classical pyca/cryptography call sites.

CRYPTO-130/131/132 have existed since the first Python rule pack and had
never fired: no matcher emitted `cryptography.hazmat.ciphers.Cipher`.
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def triple_des(key, iv):
    # CRYPTO-130
    return Cipher(algorithms.TripleDES(key), modes.CBC(iv))


def arc4(key):
    # CRYPTO-131
    return Cipher(algorithms.ARC4(key), modes.ECB())


def aes_ecb(key):
    # CRYPTO-132
    return Cipher(algorithms.AES(key), modes.ECB())

"""Fixture: known crypto API call sites for scanner integration tests."""
import hashlib

from cryptography.hazmat.primitives.asymmetric import ec, rsa


def keys():
    # RSA-1024 — below the 2048-bit floor.
    rsa.generate_private_key(public_exponent=65537, key_size=1024)
    # RSA-2048 — quantum-vulnerable.
    rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # RSA-3072.
    rsa.generate_private_key(public_exponent=65537, key_size=3072)

    # ECDSA P-256.
    ec.generate_private_key(ec.SECP256R1())
    # ECDSA P-384.
    ec.generate_private_key(ec.SECP384R1())


def hashes():
    hashlib.md5()
    hashlib.sha1()
    hashlib.sha224()
    hashlib.sha256()
    hashlib.sha384()
    hashlib.sha512()
    hashlib.sha3_256()
    hashlib.sha3_384()
    hashlib.sha3_512()

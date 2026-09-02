"""Fixture: pyca HPKE Suite(kem, kdf, aead), KEM import aliased (#Y125).

`#Y123`'s own rule required the argument's object be literally `KEM`; an
ordinary `as`-import alias defeats that exact-identifier check even though
the call site is real and quantum-relevant.
"""
from cryptography.hazmat.primitives.hpke import AEAD, KDF, KEM as KemEnum, Suite


def aliased_site():
    Suite(KemEnum.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

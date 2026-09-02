"""Fixture: pyca HPKE Suite(kem, kdf, aead) call sites (#Y123)."""
from cryptography.hazmat.primitives.hpke import AEAD, KDF, KEM, Suite


def classical_sites():
    Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)
    Suite(KEM.P256, KDF.HKDF_SHA256, AEAD.AES_128_GCM)
    Suite(KEM.P384, KDF.HKDF_SHA256, AEAD.AES_128_GCM)
    Suite(KEM.P521, KDF.HKDF_SHA256, AEAD.AES_128_GCM)


def pqc_and_hybrid_sites():
    Suite(KEM.MLKEM768, KDF.HKDF_SHA256, AEAD.AES_128_GCM)
    Suite(KEM.MLKEM1024, KDF.HKDF_SHA256, AEAD.AES_128_GCM)
    Suite(KEM.MLKEM768_X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)
    Suite(KEM.MLKEM1024_P384, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

"""Fixture: liboqs's official Python binding (`liboqs-python`, PyPI) (#Y74).

Both classes construct via the identical OQS_KEM_new/OQS_SIG_new C entry
points cpp.toml already classifies. Both official examples (examples/kem.py,
examples/sig.py) pass a local variable rather than a literal — the variable
sites below reproduce that shape.
"""

import oqs


def kem_literal_sites():
    oqs.KeyEncapsulation("ML-KEM-512")  # CRYPTO-992
    oqs.KeyEncapsulation("ML-KEM-768")  # CRYPTO-993
    oqs.KeyEncapsulation("ML-KEM-1024")  # CRYPTO-994
    oqs.KeyEncapsulation("HQC-128")  # CRYPTO-995, kem-unattributed


def kem_variable_site():
    kemalg = "ML-KEM-768"
    with oqs.KeyEncapsulation(kemalg) as client:  # CRYPTO-996, kem-unattributed
        client.generate_keypair()


def sig_literal_sites():
    oqs.Signature("ML-DSA-44")  # CRYPTO-997
    oqs.Signature("ML-DSA-65")  # CRYPTO-998
    oqs.Signature("ML-DSA-87")  # CRYPTO-999
    oqs.Signature("SPHINCS+-SHA2-128s-simple")  # CRYPTO-1000, sig-unattributed


def sig_variable_site():
    sigalg = "ML-DSA-44"
    with oqs.Signature(sigalg) as signer:  # CRYPTO-1001, sig-unattributed
        signer.generate_keypair()

"""Fixture: a locally-defined, HPKE-unrelated `Suite` must not match #Y123's
pyca rule (`CRYPTO-1171`-`1178`). No `cryptography` import anywhere in this
file; `Suite` and the enum-like `Algo` class are both defined locally and
have nothing to do with HPKE.
"""


class Algo:
    X25519 = "x25519"
    MLKEM768 = "mlkem768"


class Suite:
    def __init__(self, kem, kdf, aead):
        self.kem = kem
        self.kdf = kdf
        self.aead = aead


def decoy_sites():
    Suite(Algo.X25519, Algo.MLKEM768, Algo.MLKEM768)

"""Fixture: pyca ML-KEM / ML-DSA call sites (#Y47)."""
from cryptography.hazmat.primitives.asymmetric.mlkem import (
    MLKEM768PrivateKey,
    MLKEM768PublicKey,
    MLKEM1024PrivateKey,
)
from cryptography.hazmat.primitives.asymmetric.mldsa import (
    MLDSA44PrivateKey,
    MLDSA65PrivateKey,
    MLDSA65PublicKey,
    MLDSAMuHasher,
)
from cryptography.hazmat.primitives.asymmetric import mldsa


def mlkem_sites():
    key = MLKEM768PrivateKey.generate()
    MLKEM1024PrivateKey.from_seed_bytes(b"0" * 64)
    MLKEM768PublicKey.from_public_bytes(b"0" * 1184)

    # Instance-method call through a variable — cannot be resolved to a
    # class without receiver type-tracking, so this deliberately does NOT
    # produce an ml-kem finding.
    key.encapsulate()


def mldsa_sites():
    sig_key = MLDSA65PrivateKey.generate()
    MLDSA44PrivateKey.generate()
    MLDSA65PublicKey.from_public_bytes(b"0" * 1952)

    # Same unresolvable-receiver shape as above.
    sig_key.sign(b"test data")


def mldsa_external_mu_sites():
    # #Y86: MLDSAMuHasher — bare-imported and module-qualified spellings.
    # Direct construction call; the parameter set lives in `public_key`'s
    # runtime type, which is not statically knowable here.
    public_key = load_signer_public_key()
    MLDSAMuHasher(public_key)
    mldsa.MLDSAMuHasher(public_key, b"context")

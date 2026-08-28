"""Fixture for paramiko-style runtime-variable arguments to crypto APIs.

paramiko/rsakey.py:184 calls rsa.generate_private_key with key_size=<var>;
paramiko/ecdsakey.py:268 calls ec.generate_private_key with a curve variable.
Pre-Phase-8 fix, scanning this produced ZERO findings — the extract layer
required literal integers / call expressions and rejected bare identifiers.

Phase 8 (paramiko fix): identifier values now flow through as symbolic
captures (key_size_symbol, curve_symbol) and trigger CRYPTO-104 / CRYPTO-115.
"""
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, rsa


def make_rsa_key(bits):
    return rsa.generate_private_key(
        public_exponent=65537, key_size=bits, backend=default_backend()
    )  # CRYPTO-104


def make_ec_key(curve):
    return ec.generate_private_key(curve, backend=default_backend())  # CRYPTO-115

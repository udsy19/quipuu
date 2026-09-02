"""Fixture: pyca HPKE Suite(kem, kdf, aead), module-qualified dotted access
(#Y125).

`#Y123`'s own rule only recognised a bare `KEM.<member>` attribute; a
module-qualified access (the more common style for a module a codebase
imports once and references qualified) defeats it even though the call site
is real and quantum-relevant.
"""
import cryptography.hazmat.primitives.hpke as hpke


def dotted_site():
    hpke.Suite(hpke.KEM.X25519, hpke.KDF.HKDF_SHA256, hpke.AEAD.AES_128_GCM)

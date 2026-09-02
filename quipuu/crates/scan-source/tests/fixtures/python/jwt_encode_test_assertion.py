# Fixture: PyJWT test suites wrap a call the test requires to FAIL in
# `with pytest.raises(...):` (or unittest's `with self.assertRaises(...):`).
# That is low-signal (SiteContext::TestAssertion); a jwt.encode call outside
# any such wrapper is a genuine positive and must still be reported,
# mirroring the C/C++ ExpectNull/ExpectNotNull split.

import jwt
import pytest


def test_wrong_curve_rejected():
    # suppressed — the test requires this call to raise
    with pytest.raises(InvalidKeyError):
        jwt.encode({"hello": "world"}, p384_key, algorithm="ES256")


class LegacyCase:
    def test_wrong_curve_rejected_unittest_style(self):
        # suppressed — unittest's context-manager spelling of the same idiom
        with self.assertRaises(InvalidKeyError):
            jwt.encode({"hello": "world"}, p384_key, algorithm="RS256")


def sign_token():
    # real positive — no raises assertion wraps this call
    return jwt.encode({"hello": "world"}, p256_key, algorithm="ES256")


def test_wrong_key_rejected_on_decode():
    # real positive — the encode() call here succeeds; only the decode() call
    # one line below it is the one the assertion requires to raise (`#Y119`)
    with pytest.raises(InvalidSignatureError):
        token = jwt.encode({"hello": "world"}, hs_key, algorithm="HS256")
        jwt.decode(token, wrong_key, algorithms=["HS256"])

"""Fixture: `from hashlib import ...` bare calls — `#Y4`."""
from hashlib import md5, sha1 as s1


def hashes():
    md5(b"x")
    s1(b"x")

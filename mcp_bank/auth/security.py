"""Secret hashing (PBKDF2-HMAC-SHA256) and PKCE verification, stdlib only."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os

_ITERATIONS = 390_000  # OWASP recommendation (2023) for PBKDF2-HMAC-SHA256.
_SALT_BYTES = 16


def hash_secret(secret: str) -> str:
    """Return a ``salt$digest`` fingerprint to persist instead of the secret."""
    salt = os.urandom(_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt, _ITERATIONS)
    return f"{salt.hex()}${digest.hex()}"


def verify_secret(secret: str, hashed: str) -> bool:
    """Check a plaintext secret against a `hash_secret` fingerprint."""
    try:
        salt_hex, digest_hex = hashed.split("$", 1)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except ValueError:
        return False

    candidate = hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt, _ITERATIONS)
    # Constant time: never compare secret-derived bytes with `==`.
    return hmac.compare_digest(candidate, expected)


def verify_pkce(code_verifier: str, code_challenge: str) -> bool:
    """Check a PKCE verifier against its challenge, S256 only (RFC 7636).

    No salt or stretching here, unlike `verify_secret`: the verifier is random
    and single-use, so a plain SHA-256 is the standard, sufficient construction.
    """
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return hmac.compare_digest(computed, code_challenge)

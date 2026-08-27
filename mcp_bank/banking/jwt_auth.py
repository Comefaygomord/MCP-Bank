"""RS256 JWTs for the Enable Banking API, signed with the application key."""
from __future__ import annotations

import time
from functools import lru_cache

import jwt

from ..config import settings

_TTL_SECONDS = 3600  # Enable Banking allows up to 24h; short-lived is enough.


@lru_cache(maxsize=1)
def _private_key() -> bytes:
    """Read and cache the PEM private key pointed at by PRIVATE_KEY_ENABLE."""
    with open(settings.require("eb_private_key_path"), "rb") as f:
        return f.read()


def make_jwt() -> str:
    """Return a fresh, disposable bearer token for the Enable Banking API."""
    now = int(time.time())
    payload = {
        "iss": "enablebanking.com",  # issuer and audience are both imposed
        "aud": "api.enablebanking.com",
        "iat": now,
        "exp": now + _TTL_SECONDS,
    }
    headers = {
        "typ": "JWT",
        "alg": "RS256",
        "kid": settings.require("eb_app_id"),  # tells EB which public key to use
    }
    return jwt.encode(payload, _private_key(), algorithm="RS256", headers=headers)


def auth_headers() -> dict[str, str]:
    """Authorization header with a freshly minted JWT.

    Rebuilt on every call on purpose: the server is long-running, so a header
    frozen at import time would start returning 401 after an hour.
    """
    return {"Authorization": f"Bearer {make_jwt()}"}

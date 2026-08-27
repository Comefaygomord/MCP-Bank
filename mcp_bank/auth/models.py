"""Data structures of the authentication subsystem (no logic here)."""
from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass(frozen=True)
class RegisteredClient:
    """An OAuth client known to this server. Secrets are stored hashed only."""

    client_id: str
    hashed_secret: str
    scopes: tuple[str, ...]
    name: str


@dataclass(frozen=True)
class AuthorizationCode:
    """A short-lived, single-use code issued by ``/authorize`` (RFC 6749 4.1).

    ``code_challenge`` is the PKCE fingerprint supplied by the client, checked
    against the ``code_verifier`` presented at the token exchange.
    """

    code: str
    client_id: str
    redirect_uri: str
    code_challenge: str
    scopes: tuple[str, ...]
    expires_at: int


@dataclass(frozen=True)
class TokenClaims:
    """Decoded payload of an access token whose signature has been verified."""

    client_id: str
    scopes: tuple[str, ...]
    issued_at: int
    expires_at: int
    issuer: str
    audience: str

    def is_expired(self) -> bool:
        return time.time() >= self.expires_at

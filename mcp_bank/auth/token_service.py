"""Access token issuance and verification (JWT, RFC 7519).

Self-contained JWTs rather than opaque tokens, so verification needs no extra
round trip. HS256 is enough while issuer and verifier are the same process;
split them and this should become RS256.
"""
from __future__ import annotations

import time

import jwt

from .models import TokenClaims


class TokenService:
    """Creates and validates JWT access tokens."""

    def __init__(self, signing_key: str, issuer: str, audience: str, ttl_seconds: int) -> None:
        self.signing_key = signing_key
        self.issuer = issuer
        self.audience = audience
        self.ttl_seconds = ttl_seconds

    def issue_token(self, client_id: str, scopes: tuple[str, ...]) -> tuple[str, int]:
        """Mint a token for an already-authenticated client."""
        now = int(time.time())
        payload = {
            "iss": self.issuer,
            "aud": self.audience,
            "sub": client_id,
            "client_id": client_id,
            "scope": " ".join(scopes),
            "iat": now,
            "exp": now + self.ttl_seconds,
        }
        return jwt.encode(payload, self.signing_key, algorithm="HS256"), self.ttl_seconds

    def verify_token(self, token: str) -> TokenClaims | None:
        """Validate signature, expiry, audience and issuer; None if any fails."""
        try:
            payload = jwt.decode(
                token,
                self.signing_key,
                algorithms=["HS256"],
                audience=self.audience,
                issuer=self.issuer,
            )
        except jwt.PyJWTError:
            return None

        scope_claim = payload.get("scope", "")
        return TokenClaims(
            client_id=payload["client_id"],
            scopes=tuple(scope_claim.split()) if scope_claim else (),
            issued_at=payload["iat"],
            expires_at=payload["exp"],
            issuer=payload["iss"],
            audience=payload["aud"],
        )

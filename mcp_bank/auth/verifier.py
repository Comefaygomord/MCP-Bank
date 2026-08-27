"""Bridge between `TokenService` and the `TokenVerifier` protocol of FastMCP."""
from __future__ import annotations

try:
    from fastmcp.server.auth import AccessToken, TokenVerifier
except ImportError:  # pragma: no cover - depends on the installed fastmcp
    from mcp.server.auth.provider import AccessToken, TokenVerifier

from .token_service import TokenService


class ClientCredentialsTokenVerifier(TokenVerifier):
    """Passed as ``auth=`` to ``FastMCP(...)``.

    Subclassing `TokenVerifier` matters: the base class supplies the
    ``get_middleware()``/``get_routes()`` hooks FastMCP calls to wire token
    checking into the HTTP app. A bare object makes startup fail.
    """

    def __init__(self, token_service: TokenService, base_url: str | None = None) -> None:
        super().__init__(base_url=base_url, required_scopes=["mcp:invoke"])
        self._token_service = token_service

    async def verify_token(self, token: str) -> AccessToken | None:
        claims = self._token_service.verify_token(token)
        if claims is None:
            return None
        return AccessToken(
            token=token,
            client_id=claims.client_id,
            scopes=list(claims.scopes),
            expires_at=claims.expires_at,
        )

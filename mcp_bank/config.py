"""Single place where environment variables are read.

``SERVER_URL`` doubles as the JWT issuer *and* audience, which is what stops a
token minted for another server from being replayed here (confused deputy).
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(__file__).resolve().parent / "banking" / "data"

load_dotenv(ROOT_DIR / ".env")


def _required(name: str) -> str:
    """Read a mandatory variable, or fail at startup rather than mid-request."""
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(
            f"Missing environment variable: {name}. See the configuration table in README.md."
        )
    return value


@dataclass(frozen=True)
class Settings:
    """Immutable configuration, loaded once at import time."""

    # MCP server / OAuth2
    server_url: str
    host: str
    port: int
    jwt_secret: str
    access_token_ttl_seconds: int
    demo_client_id: str
    demo_client_secret: str
    oauth_redirect_uri: str

    # Enable Banking. Optional because the onboarding flow is what produces
    # `eb_session_id`, and the server is what consumes it.
    eb_base_url: str
    eb_app_id: str
    eb_private_key_path: str
    eb_session_id: str
    eb_aspsp_name: str
    eb_aspsp_country: str
    eb_redirect_url: str

    def require(self, field: str) -> str:
        """Return an optional setting, raising if it was never configured."""
        value = getattr(self, field)
        if not value:
            raise RuntimeError(
                f"Setting '{field}' is empty. Fill the matching variable in .env."
            )
        return value


settings = Settings(
    server_url=os.environ.get("SERVER_URL", "http://127.0.0.1:8000").rstrip("/"),
    host=os.environ.get("HOST", "127.0.0.1"),
    port=int(os.environ.get("PORT", "8000")),
    jwt_secret=_required("JWT_SECRET"),
    access_token_ttl_seconds=int(os.environ.get("ACCESS_TOKEN_TTL_SECONDS", "3600")),
    demo_client_id=_required("DEMO_CLIENT_ID"),
    demo_client_secret=_required("DEMO_CLIENT_SECRET"),
    # Exact-match allowlist: without it, an attacker-supplied redirect_uri
    # would carry the authorization code off to a third-party site.
    oauth_redirect_uri=os.environ.get(
        "OAUTH_REDIRECT_URI", "https://claude.ai/api/mcp/auth_callback"
    ),
    eb_base_url=os.environ.get("EB_BASE_URL", "https://api.enablebanking.com"),
    eb_app_id=os.environ.get("EB_APP_ID", ""),
    eb_private_key_path=os.environ.get("PRIVATE_KEY_ENABLE", ""),
    eb_session_id=os.environ.get("SESSION_ID", ""),
    eb_aspsp_name=os.environ.get("EB_ASPSP_NAME", ""),
    eb_aspsp_country=os.environ.get("EB_ASPSP_COUNTRY", ""),
    eb_redirect_url=os.environ.get(
        "EB_REDIRECT_URL", "http://127.0.0.1:8080/callback"
    ),
)

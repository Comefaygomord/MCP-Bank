"""In-memory registries: OAuth clients and pending authorization codes.

Both are thread-safe and reset on restart. The demo client is re-seeded from
the environment at startup (see `server.py`); a real deployment would swap
these for a persistent store.
"""
from __future__ import annotations

import secrets
import threading
import time

from .models import AuthorizationCode, RegisteredClient
from .security import hash_secret, verify_secret

# RFC 6749 sets no value; a couple of minutes is ample for a browser redirect.
_CODE_TTL_SECONDS = 120


class ClientStore:
    """Registry of the OAuth clients allowed to reach this server."""

    def __init__(self) -> None:
        self._clients: dict[str, RegisteredClient] = {}
        self._lock = threading.Lock()

    def register_client(
        self,
        client_id: str,
        client_secret: str,
        scopes: tuple[str, ...],
        name: str,
    ) -> RegisteredClient:
        """Register a client, replacing any existing one with the same id."""
        client = RegisteredClient(
            client_id=client_id,
            hashed_secret=hash_secret(client_secret),
            scopes=scopes,
            name=name,
        )
        with self._lock:
            self._clients[client_id] = client
        return client

    def get_client(self, client_id: str) -> RegisteredClient | None:
        with self._lock:
            return self._clients.get(client_id)

    def authenticate(self, client_id: str, client_secret: str) -> RegisteredClient | None:
        """Validate a client_id/secret pair.

        An unknown id and a wrong secret are indistinguishable, on purpose.
        """
        client = self.get_client(client_id)
        if client is None or not verify_secret(client_secret, client.hashed_secret):
            return None
        return client


class AuthorizationCodeStore:
    """Registry of authorization codes waiting to be exchanged for a token.

    Codes are not hashed, unlike client secrets: they are random, single-use
    and expire within two minutes.
    """

    def __init__(self) -> None:
        self._codes: dict[str, AuthorizationCode] = {}
        self._lock = threading.Lock()

    def issue(
        self,
        client_id: str,
        redirect_uri: str,
        code_challenge: str,
        scopes: tuple[str, ...],
    ) -> str:
        """Mint and store a new authorization code."""
        code = secrets.token_urlsafe(32)
        entry = AuthorizationCode(
            code=code,
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            scopes=scopes,
            expires_at=int(time.time()) + _CODE_TTL_SECONDS,
        )
        with self._lock:
            self._codes[code] = entry
        return code

    def consume(self, code: str) -> AuthorizationCode | None:
        """Return the code and invalidate it at once; None if unknown or stale."""
        with self._lock:
            entry = self._codes.pop(code, None)
        if entry is None or entry.expires_at < time.time():
            return None
        return entry

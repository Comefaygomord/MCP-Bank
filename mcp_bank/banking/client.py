"""Read-only access to the account behind the configured Enable Banking session."""
from __future__ import annotations

from datetime import datetime, timedelta

import httpx

from ..config import settings
from .jwt_auth import auth_headers

_TIMEOUT = 30.0
_DEFAULT_WINDOW_DAYS = 120


def get_session(session_id: str) -> dict:
    """Fetch a session, which carries the list of accounts it grants access to."""
    r = httpx.get(
        f"{settings.eb_base_url}/sessions/{session_id}",
        headers={"Accept": "application/json", **auth_headers()},
        timeout=_TIMEOUT,
    )
    r.raise_for_status()
    return r.json()


def get_details(
    kind: str,
    date_from: str | None = None,
    date_to: str | None = None,
) -> dict:
    """Fetch ``balances`` or ``transactions`` for the session's first account.

    Dates are ISO ``YYYY-MM-DD`` and only apply to transactions; they default
    to the last 120 days.
    """
    if kind not in ("balances", "transactions"):
        raise ValueError(f"Unknown kind: {kind!r}. Use 'balances' or 'transactions'.")

    session = get_session(settings.require("eb_session_id"))
    account_uid = session["accounts"][0]

    params: dict[str, str] = {}
    if kind == "transactions":
        now = datetime.now()
        params = {
            "date_from": date_from
            or (now - timedelta(days=_DEFAULT_WINDOW_DAYS)).strftime("%Y-%m-%d"),
            "date_to": date_to or now.strftime("%Y-%m-%d"),
        }

    r = httpx.get(
        f"{settings.eb_base_url}/accounts/{account_uid}/{kind}",
        headers={"Accept": "application/json", **auth_headers()},
        params=params,
        timeout=_TIMEOUT,
    )
    r.raise_for_status()
    return r.json()

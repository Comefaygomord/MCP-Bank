"""One-shot consent flow that produces a durable Enable Banking session.

Replaces the former three-script dance (link / callback / session). Because
everything now runs in a single process, the CSRF ``state`` and the returned
code stay in memory instead of being handed over through files on disk.

Run once, then copy the printed session id into ``SESSION_ID`` in ``.env``::

    python -m mcp_bank.banking.onboarding
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import requests

from ..config import DATA_DIR, settings
from .jwt_auth import auth_headers

_TIMEOUT = 30
_ACCESS_VALID_DAYS = 100
_SESSION_FILE = DATA_DIR / "session.json"


def _callback_target() -> tuple[str, int, str]:
    """Host, port and path to listen on, taken from EB_REDIRECT_URL.

    Derived rather than hardcoded so the local server always answers wherever
    the bank has been told to send the user back.
    """
    url = urlparse(settings.eb_redirect_url)
    return url.hostname or "127.0.0.1", url.port or 80, url.path or "/callback"


def check_aspsp_name() -> bool:
    """Confirm the configured bank name matches the API listing exactly."""
    name = settings.require("eb_aspsp_name")
    country = settings.require("eb_aspsp_country")

    r = requests.get(
        f"{settings.eb_base_url}/aspsps",
        params={"country": country},
        headers=auth_headers(),
        timeout=_TIMEOUT,
    )
    if r.status_code != 200:
        print(f"[error] GET /aspsps -> {r.status_code}\n{r.text}")
        return False

    names = [a["name"] for a in r.json()["aspsps"]]
    if name in names:
        print(f"[ok] ASPSP found: {name}")
        return True

    print(f"[error] Unknown ASPSP name: {name!r}. Available in {country}:")
    for candidate in names:
        print(f"    {candidate!r}")
    return False


def request_authorization_url(state: str) -> str | None:
    """Ask Enable Banking for the bank's consent URL, bound to ``state``."""
    body = {
        "access": {
            "valid_until": (
                datetime.now(timezone.utc) + timedelta(days=_ACCESS_VALID_DAYS)
            ).isoformat()
        },
        "aspsp": {
            "name": settings.require("eb_aspsp_name"),
            "country": settings.require("eb_aspsp_country"),
        },
        "state": state,
        "redirect_url": settings.eb_redirect_url,
        "psu_type": "personal",
    }

    r = requests.post(
        f"{settings.eb_base_url}/auth",
        json=body,
        headers=auth_headers(),
        timeout=_TIMEOUT,
    )
    if r.status_code != 200:
        print(f"[error] POST /auth -> {r.status_code}\n{r.text}")
        return None

    url = r.json().get("url")
    if url is None:
        print(f"[error] No 'url' field in response:\n{json.dumps(r.json(), indent=2)}")
    return url


def wait_for_code(expected_state: str) -> str | None:
    """Serve the callback path locally until the bank redirects back with a code."""
    host, port, path = _callback_target()
    captured: dict[str, str] = {}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass  # the default log would print the full URL, code included

        def reply(self, status: int, message: str) -> None:
            body = f"<html><body><h2>{message}</h2></body></html>".encode()
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802 - name imposed by BaseHTTPRequestHandler
            parsed = urlparse(self.path)
            if parsed.path != path:
                self.reply(404, "Nothing here.")
                return

            params = parse_qs(parsed.query)
            error = params.get("error", [None])[0]
            if error:
                print(f"[error] {error} - {params.get('error_description', [''])[0]}")
                self.reply(400, "Authorization refused or cancelled.")
                return

            if params.get("state", [None])[0] != expected_state:
                print("[reject] unexpected state")
                self.reply(403, "Request rejected.")
                return

            code = params.get("code", [None])[0]
            if not code:
                self.reply(400, "No code received.")
                return

            captured["code"] = code
            self.reply(200, "Done, you can close this page.")

    server = HTTPServer((host, port), Handler)
    print(f"[..] listening on {host}:{port}{path}, waiting for the callback")
    while "code" not in captured:
        server.handle_request()  # one request at a time, then loop
    return captured["code"]


def create_session(code: str) -> dict:
    """Exchange the one-shot code for a session valid for months."""
    r = requests.post(
        f"{settings.eb_base_url}/sessions",
        json={"code": code},
        headers=auth_headers(),
        timeout=_TIMEOUT,
    )
    if r.status_code != 200:
        raise SystemExit(f"[error] POST /sessions -> {r.status_code}\n{r.text}")

    session = r.json()
    # Persist before interpreting: some fields are never returned again.
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    _SESSION_FILE.write_text(json.dumps(session, indent=2, ensure_ascii=False))
    _SESSION_FILE.chmod(0o600)
    print(f"[ok] full response saved to {_SESSION_FILE}")
    return session


def main() -> None:
    if not check_aspsp_name():
        raise SystemExit(1)

    state = str(uuid.uuid4())
    url = request_authorization_url(state)
    if url is None:
        raise SystemExit(1)

    print(f"\nOpen this URL in a browser:\n\n{url}\n")
    print(f"Expected redirect: {settings.eb_redirect_url}")

    code = wait_for_code(state)
    if code is None:
        raise SystemExit(1)

    session = create_session(code)
    print(f"\nSESSION_ID={session.get('session_id')}")
    print(f"valid until: {session.get('access', {}).get('valid_until', '?')}")
    print(f"accounts: {len(session.get('accounts', []))}")
    print("\nCopy SESSION_ID into your .env file.")


if __name__ == "__main__":
    main()

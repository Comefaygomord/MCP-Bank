"""Assembles the MCP server: FastMCP, token auth, and the OAuth2 endpoints.

This one process is both Authorization Server (it mints tokens) and Resource
Server (it checks them), because a single public URL is all that is available.
Routes are told apart by path, not by host or port.
"""
from __future__ import annotations

import html
from urllib.parse import urlencode

from fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse

from .auth.security import verify_pkce, verify_secret
from .auth.stores import AuthorizationCodeStore, ClientStore
from .auth.token_service import TokenService
from .auth.verifier import ClientCredentialsTokenVerifier
from .config import settings
from .tools import register

# --- Authentication services -------------------------------------------------

client_store = ClientStore()
authorization_store = AuthorizationCodeStore()

# Re-seeded from the environment at every start. A real deployment would use a
# registration flow backed by persistent storage.
client_store.register_client(
    client_id=settings.demo_client_id,
    client_secret=settings.demo_client_secret,
    scopes=("mcp:invoke",),
    name="Demo client",
)

token_service = TokenService(
    signing_key=settings.jwt_secret,
    issuer=settings.server_url,
    audience=settings.server_url,
    ttl_seconds=settings.access_token_ttl_seconds,
)

# `auth=` guards /mcp: every request must carry a valid `Authorization: Bearer`.
mcp = FastMCP(
    name="mcp-bank",
    auth=ClientCredentialsTokenVerifier(token_service, base_url=settings.server_url),
)

register(mcp)


# --- /authorize: authorization code grant with PKCE --------------------------
#
# Claude.ai will not accept a pure machine-to-machine grant for connectors:
# every connection needs explicit user consent. The client_credentials grant
# further down stays available for command-line testing.


def _consent_page(
    client_name: str, scopes: tuple[str, ...], hidden_fields: dict[str, str]
) -> str:
    """Render the consent screen. Every injected value comes from the request,
    so all of them are escaped."""
    inputs = "\n".join(
        f'<input type="hidden" name="{html.escape(k)}" value="{html.escape(v)}">'
        for k, v in hidden_fields.items()
    )
    scope_items = "".join(f"<li>{html.escape(s)}</li>" for s in scopes)
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Authorize access</title></head>
<body style="font-family: sans-serif; max-width: 420px; margin: 4rem auto;">
  <h2>Authorize {html.escape(client_name)}?</h2>
  <p>This application is requesting the following scopes:</p>
  <ul>{scope_items}</ul>
  <form method="POST" action="/authorize" style="display:flex; gap:1rem;">
    {inputs}
    <button type="submit" name="decision" value="allow">Allow</button>
    <button type="submit" name="decision" value="deny">Deny</button>
  </form>
</body></html>"""


def _validate_authorize_params(params) -> tuple[dict, JSONResponse | None]:
    """Validate the parameters shared by GET and POST /authorize.

    Errors are returned as JSON rather than as a redirect: until client_id and
    redirect_uri are known good, redirecting anywhere would hand the
    authorization code to whatever address the caller supplied.
    """
    if params.get("response_type") != "code":
        return {}, JSONResponse(
            {
                "error": "unsupported_response_type",
                "error_description": "Only response_type=code is supported.",
            },
            status_code=400,
        )

    client_id = params.get("client_id")
    client = client_store.get_client(str(client_id)) if client_id else None
    if client is None:
        return {}, JSONResponse(
            {"error": "invalid_client", "error_description": "Unknown client_id."},
            status_code=400,
        )

    redirect_uri = params.get("redirect_uri")
    if redirect_uri != settings.oauth_redirect_uri:
        return {}, JSONResponse(
            {
                "error": "invalid_request",
                "error_description": "redirect_uri is not allowed for this client.",
            },
            status_code=400,
        )

    code_challenge = params.get("code_challenge")
    if not code_challenge or params.get("code_challenge_method") != "S256":
        return {}, JSONResponse(
            {
                "error": "invalid_request",
                "error_description": "code_challenge with PKCE method S256 is required.",
            },
            status_code=400,
        )

    return {
        "client": client,
        "redirect_uri": str(redirect_uri),
        "code_challenge": str(code_challenge),
        "state": str(params.get("state", "")),
        "scope": str(params.get("scope") or " ".join(client.scopes)),
    }, None


@mcp.custom_route("/authorize", methods=["GET"])
async def authorize_prompt(request: Request) -> HTMLResponse | JSONResponse:
    """Show the consent screen, or an error if the OAuth parameters are bad."""
    parsed, error = _validate_authorize_params(request.query_params)
    if error is not None:
        return error

    # response_type and code_challenge_method have to survive into the POST:
    # the decision is revalidated exactly like the initial display, so dropping
    # them makes even an "Allow" click fail with unsupported_response_type.
    hidden_fields = {
        "response_type": "code",
        "client_id": parsed["client"].client_id,
        "redirect_uri": parsed["redirect_uri"],
        "code_challenge": parsed["code_challenge"],
        "code_challenge_method": "S256",
        "state": parsed["state"],
        "scope": parsed["scope"],
    }
    return HTMLResponse(
        _consent_page(
            parsed["client"].name, tuple(parsed["scope"].split()), hidden_fields
        )
    )


@mcp.custom_route("/authorize", methods=["POST"])
async def authorize_decision(request: Request) -> RedirectResponse | JSONResponse:
    """Handle the consent decision and redirect back with a code or an error."""
    form = await request.form()
    parsed, error = _validate_authorize_params(form)
    if error is not None:
        return error

    redirect_uri = parsed["redirect_uri"]
    state = parsed["state"]

    if form.get("decision") != "allow":
        query = urlencode({"error": "access_denied", "state": state})
        return RedirectResponse(f"{redirect_uri}?{query}", status_code=302)

    code = authorization_store.issue(
        client_id=parsed["client"].client_id,
        redirect_uri=redirect_uri,
        code_challenge=parsed["code_challenge"],
        scopes=tuple(parsed["scope"].split()),
    )
    return RedirectResponse(
        f"{redirect_uri}?{urlencode({'code': code, 'state': state})}", status_code=302
    )


# --- /oauth/token ------------------------------------------------------------


def _token_response(access_token: str, expires_in: int, scopes: tuple[str, ...]):
    return JSONResponse(
        {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": expires_in,
            "scope": " ".join(scopes),
        }
    )


@mcp.custom_route("/oauth/token", methods=["POST"])
async def issue_token(request: Request) -> JSONResponse:
    """Token endpoint: authorization_code (Claude.ai) or client_credentials."""
    form = await request.form()
    grant_type = form.get("grant_type")

    if grant_type == "authorization_code":
        return _issue_token_authorization_code(form)
    if grant_type == "client_credentials":
        return _issue_token_client_credentials(form)

    return JSONResponse(
        {
            "error": "unsupported_grant_type",
            "error_description": "Supported grants: authorization_code, client_credentials.",
        },
        status_code=400,
    )


def _issue_token_client_credentials(form) -> JSONResponse:
    """Client credentials grant (RFC 6749 4.4), for command-line testing only."""
    client_id = form.get("client_id")
    client_secret = form.get("client_secret")
    if not client_id or not client_secret:
        return JSONResponse(
            {
                "error": "invalid_request",
                "error_description": "client_id and client_secret are required.",
            },
            status_code=400,
        )

    client = client_store.authenticate(str(client_id), str(client_secret))
    if client is None:
        # Deliberately vague: does not reveal which half was wrong.
        return JSONResponse(
            {
                "error": "invalid_client",
                "error_description": "Invalid client_id or client_secret.",
            },
            status_code=401,
        )

    access_token, expires_in = token_service.issue_token(client.client_id, client.scopes)
    return _token_response(access_token, expires_in, client.scopes)


def _issue_token_authorization_code(form) -> JSONResponse:
    """Authorization code + PKCE grant (RFC 6749 4.1, RFC 7636), used by Claude.ai."""
    code = form.get("code")
    redirect_uri = form.get("redirect_uri")
    client_id = form.get("client_id")
    code_verifier = form.get("code_verifier")
    if not code or not redirect_uri or not client_id or not code_verifier:
        return JSONResponse(
            {
                "error": "invalid_request",
                "error_description": "code, redirect_uri, client_id and code_verifier are required.",
            },
            status_code=400,
        )

    entry = authorization_store.consume(str(code))
    if entry is None or entry.client_id != client_id or entry.redirect_uri != redirect_uri:
        # Unknown, already spent, expired, or bound to a different client:
        # all indistinguishable from the outside.
        return JSONResponse(
            {
                "error": "invalid_grant",
                "error_description": "Invalid or expired authorization code.",
            },
            status_code=400,
        )

    client = client_store.get_client(str(client_id))
    if client is None:
        return JSONResponse({"error": "invalid_client"}, status_code=401)

    # The secret is optional (RFC 6749 calls that a public client) because
    # Claude.ai may omit it; when absent, PKCE is the proof of possession.
    client_secret = form.get("client_secret")
    if client_secret and not verify_secret(str(client_secret), client.hashed_secret):
        return JSONResponse({"error": "invalid_client"}, status_code=401)

    if not verify_pkce(str(code_verifier), entry.code_challenge):
        return JSONResponse(
            {
                "error": "invalid_grant",
                "error_description": "code_verifier does not match code_challenge.",
            },
            status_code=400,
        )

    access_token, expires_in = token_service.issue_token(client.client_id, entry.scopes)
    return _token_response(access_token, expires_in, entry.scopes)


# --- Discovery metadata (RFC 8414 / RFC 9728) --------------------------------


@mcp.custom_route("/.well-known/oauth-authorization-server", methods=["GET"])
async def oauth_authorization_server_metadata(request: Request) -> JSONResponse:
    """Authorization Server metadata (RFC 8414).

    Claude.ai checks `code_challenge_methods_supported` and
    `grant_types_supported` before starting the flow; without both, it does not
    treat this as a PKCE-capable authorization server.
    """
    return JSONResponse(
        {
            "issuer": settings.server_url,
            "authorization_endpoint": f"{settings.server_url}/authorize",
            "token_endpoint": f"{settings.server_url}/oauth/token",
            "grant_types_supported": ["authorization_code", "client_credentials"],
            "response_types_supported": ["code"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["client_secret_post", "none"],
        }
    )


@mcp.custom_route("/.well-known/oauth-protected-resource", methods=["GET"])
async def oauth_protected_resource_metadata(request: Request) -> JSONResponse:
    """Resource Server metadata (RFC 9728)."""
    return JSONResponse(
        {
            "resource": f"{settings.server_url}/mcp",
            "authorization_servers": [settings.server_url],
        }
    )

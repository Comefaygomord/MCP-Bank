"""OAuth2 authentication subsystem: who may connect, and how that is checked.

Modules, in dependency order:

    models.py         plain data structures, no logic
    security.py       secret hashing (PBKDF2) and PKCE verification
    stores.py         in-memory registries: OAuth clients, authorization codes
    token_service.py  JWT issuance and verification
    verifier.py       adapter to the ``TokenVerifier`` protocol FastMCP expects
"""

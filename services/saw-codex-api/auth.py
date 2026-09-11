"""OIDC token validation against Keycloak JWKS."""

import time

import httpx
from fastapi import HTTPException, Request
from jose import JWTError, jwt

from . import config

_jwks_cache: dict | None = None
_jwks_fetched_at: float = 0.0


async def _fetch_jwks() -> dict:
    global _jwks_cache, _jwks_fetched_at
    now = time.time()
    if _jwks_cache and (now - _jwks_fetched_at) < config.OIDC_JWKS_CACHE_TTL:
        return _jwks_cache

    discovery_url = f"{config.OIDC_ISSUER_URL}/.well-known/openid-configuration"
    async with httpx.AsyncClient(verify=False) as client:
        resp = await client.get(discovery_url, timeout=10)
        resp.raise_for_status()
        jwks_uri = resp.json()["jwks_uri"]
        resp = await client.get(jwks_uri, timeout=10)
        resp.raise_for_status()
        _jwks_cache = resp.json()
        _jwks_fetched_at = now
        return _jwks_cache


async def get_current_user(request: Request) -> str:
    """Extract and validate the Bearer token, return the username."""
    auth_header = request.headers.get("authorization", "")
    if not auth_header.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")

    token = auth_header[7:]
    try:
        jwks = await _fetch_jwks()
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")

        rsa_key = None
        for key in jwks.get("keys", []):
            if key.get("kid") == kid:
                rsa_key = key
                break

        if not rsa_key:
            raise HTTPException(status_code=401, detail="Token signing key not found")

        payload = jwt.decode(
            token,
            rsa_key,
            algorithms=["RS256"],
            audience=config.OIDC_CLIENT_ID,
            issuer=config.OIDC_ISSUER_URL,
            options={"verify_at_hash": False},
        )
        username = payload.get("preferred_username") or payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="No username in token")
        return username

    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}") from e

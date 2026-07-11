"""API key and JWT authentication for SentraGuard Lite.

P1 priority: no route in main.py should be reachable without passing
through get_principal (or one of the two single-method variants below).
Wired via Depends(), same pattern as registry/policy in main.py, so tests
can override with app.dependency_overrides to bypass auth or inject a
fixed Principal (e.g. a specific app_id to exercise rate limiting).

Two auth paths are supported and can be used independently or together:
  - API key (X-API-Key header)  -> simple service-to-service deployments
  - JWT (Authorization: Bearer) -> multi-tenant / user-facing deployments
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Optional

import jwt
from fastapi import Header, HTTPException, status

API_KEYS_ENV = "SENTRAGUARD_API_KEYS"  # comma-separated "app_id:key" pairs
JWT_SECRET_ENV = "SENTRAGUARD_JWT_SECRET"
JWT_ALGORITHM = "HS256"


@dataclass(frozen=True)
class Principal:
    """Identity resolved from either an API key or a JWT.

    Used downstream for rate limiting (per app_id / per user_id) and for
    audit logging in analyzer.py if desired.
    """

    app_id: str
    user_id: Optional[str] = None
    auth_method: str = "api_key"  # "api_key" | "jwt"


def _load_api_keys() -> dict[str, str]:
    """Parses SENTRAGUARD_API_KEYS="app1:key1,app2:key2" into {key: app_id}.

    Swap this for a DB/secrets-manager lookup in production; kept as an
    env-parsed dict here to match the rest of this submission's
    "wire dependencies, don't hardcode infra" style.
    """
    raw = os.environ.get(API_KEYS_ENV, "")
    pairs: dict[str, str] = {}
    for entry in filter(None, raw.split(",")):
        app_id, _, key = entry.partition(":")
        if app_id and key:
            pairs[key] = app_id
    return pairs


_API_KEYS = _load_api_keys()


def get_api_key_principal(
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> Principal:
    """Simple single-tenant / service-to-service auth path."""
    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-Key header",
        )
    app_id = _API_KEYS.get(x_api_key)
    if app_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key"
        )
    return Principal(app_id=app_id, auth_method="api_key")


def get_jwt_principal(
    authorization: Optional[str] = Header(default=None),
) -> Principal:
    """Multi-tenant auth path.

    Expects `Authorization: Bearer <jwt>` where the payload carries
    `app_id` (tenant) and optionally `sub` (user_id).
    """
    secret = os.environ.get(JWT_SECRET_ENV)
    if not secret:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="JWT auth not configured (SENTRAGUARD_JWT_SECRET unset)",
        )
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token"
        )
    token = authorization.removeprefix("Bearer ").strip()
    try:
        payload = jwt.decode(token, secret, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired"
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
        )

    app_id = payload.get("app_id")
    if not app_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing app_id claim",
        )
    return Principal(app_id=app_id, user_id=payload.get("sub"), auth_method="jwt")


def get_principal(
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
    authorization: Optional[str] = Header(default=None),
) -> Principal:
    """Unified auth dependency: tries API key first, falls back to JWT.

    Use this on routes rather than the two single-method functions above,
    unless a route is deliberately restricted to one auth method.
    """
    if x_api_key:
        return get_api_key_principal(x_api_key)
    if authorization:
        return get_jwt_principal(authorization)
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Missing credentials: provide X-API-Key or Authorization: Bearer <jwt>",
    )
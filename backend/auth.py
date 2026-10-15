import os
from typing import Optional

import jwt
from fastapi import HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from db import get_driver
from ingest import _now

ALGORITHMS = ["ES256", "RS256"]

issuer = ""
audience = ""
jwks_client: Optional[jwt.PyJWKClient] = None

bearer = HTTPBearer(auto_error=False)

UPSERT_USER = """
MERGE (u:User {id: $id})
ON CREATE SET u.first_seen = $now, u.provider = $provider
SET u.email = $email,
    u.name = coalesce($name, u.name),
    u.last_seen = $now
RETURN u { .id, .email, .name } AS user
"""


def init_auth() -> None:
    global issuer, audience, jwks_client
    supabase_url = os.getenv("SUPABASE_URL", "").rstrip("/")
    if not supabase_url:
        raise RuntimeError("SUPABASE_URL is not set")
    issuer = f"{supabase_url}/auth/v1"
    audience = os.getenv("SUPABASE_JWT_AUDIENCE", "authenticated")
    jwks_client = jwt.PyJWKClient(f"{issuer}/.well-known/jwks.json", cache_keys=True, lifespan=600)


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(bearer),
) -> dict:
    if credentials is None:
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = credentials.credentials
    try:
        key = jwks_client.get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token,
            key,
            algorithms=ALGORITHMS,
            audience=audience,
            issuer=issuer,
            options={"require": ["exp", "sub"]},
        )
    except jwt.PyJWKClientConnectionError:
        raise HTTPException(status_code=503, detail="Could not fetch Supabase signing keys")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    metadata = claims.get("user_metadata") or {}
    with get_driver().session() as session:
        record = session.execute_write(
            lambda tx: tx.run(
                UPSERT_USER,
                id=claims["sub"],
                email=claims.get("email"),
                provider=(claims.get("app_metadata") or {}).get("provider"),
                name=metadata.get("full_name") or metadata.get("name"),
                now=_now(),
            ).single()
        )
    return record["user"]

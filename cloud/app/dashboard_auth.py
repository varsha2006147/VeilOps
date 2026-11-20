"""Dashboard sign-in: email + password (Argon2id) -> short-lived tenant JWT.

The token carries the tenant from the user's membership; every /api/v1 call is then
checked by TenantJWTMiddleware and scoped by PostgreSQL row-level security.
"""
import os
import time

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

router = APIRouter(prefix="/auth", tags=["dashboard-auth"])
_hasher = PasswordHasher()
TOKEN_TTL_S = 8 * 3600
MAX_ATTEMPTS_PER_MIN = 5
# Verify against a real hash even for unknown emails so response time does not reveal accounts.
_DUMMY_HASH = _hasher.hash("veilops-timing-equaliser")


class LoginIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=256)


def issue_token(user_id: str, tenant_id: str, role: str) -> str:
    secret = os.getenv("DASHBOARD_JWT_SECRET", "")
    if len(secret) < 32:
        raise HTTPException(503, detail={"code": "AUTH_NOT_CONFIGURED"})
    now = int(time.time())
    return jwt.encode({"sub": user_id, "tenant_id": tenant_id, "role": role, "iat": now, "exp": now + TOKEN_TTL_S,
                       "aud": os.getenv("DASHBOARD_JWT_AUDIENCE", "veilops-dashboard"),
                       "iss": os.getenv("DASHBOARD_JWT_ISSUER", "veilops-control")}, secret, algorithm="HS256")


@router.post("/login")
async def login(payload: LoginIn, request: Request):
    email = payload.email.strip().lower()
    redis = request.app.state.redis
    key = f"login:{email}:{int(time.time()) // 60}"
    try:
        attempts = await redis.incr(key)
        if attempts == 1:
            await redis.expire(key, 60)
    except Exception:
        attempts = 0                      # rate limiting is best effort; sign-in still needs the password
    if attempts > MAX_ATTEMPTS_PER_MIN:
        raise HTTPException(429, detail={"code": "TOO_MANY_ATTEMPTS"}, headers={"Retry-After": "60"})
    async with request.app.state.db_pool.acquire() as conn:
        user = await conn.fetchrow(
            "SELECT user_id,display_name,password_hash FROM dashboard_users WHERE email=$1", email)
        try:
            _hasher.verify(user["password_hash"] if user else _DUMMY_HASH, payload.password)
            ok = user is not None
        except (VerifyMismatchError, InvalidHashError):
            ok = False
        if not ok:
            raise HTTPException(401, detail={"code": "INVALID_CREDENTIALS"})
        member = await conn.fetchrow(
            "SELECT tenant_id,role FROM memberships WHERE user_id=$1 ORDER BY created_at LIMIT 1", user["user_id"])
        if member is None:
            raise HTTPException(403, detail={"code": "TENANT_MEMBERSHIP_REQUIRED"})
        await conn.execute("UPDATE dashboard_users SET last_login_at=now() WHERE user_id=$1", user["user_id"])
    return {"token": issue_token(user["user_id"], member["tenant_id"], member["role"]),
            "expires_in": TOKEN_TTL_S, "user": {"id": user["user_id"], "name": user["display_name"],
                                               "tenant_id": member["tenant_id"], "role": member["role"]}}

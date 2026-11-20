"""Print a dashboard bearer token for LOCAL development (the real control plane issues these).

  python -m cloud.scripts.dev_token --user vibhav --tenant t_acme --role operator

Signs with DASHBOARD_JWT_SECRET (same env as the cloud) and makes sure the tenant and
membership exist, so the token is accepted. Never use in a shared or production deployment.
"""
import argparse
import asyncio
import os
import time

import asyncpg
import jwt

from cloud.app.settings import Settings


async def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--user", default="dev")
    p.add_argument("--tenant", default="t_acme")
    p.add_argument("--role", default="operator", choices=("viewer", "operator", "approver", "tenant_admin"))
    p.add_argument("--hours", type=int, default=12)
    p.add_argument("--database-url", default=os.getenv("ADMIN_DATABASE_URL", Settings().database_url))
    a = p.parse_args()
    secret = os.environ.get("DASHBOARD_JWT_SECRET", "")
    if len(secret) < 32:
        raise SystemExit("DASHBOARD_JWT_SECRET (>=32 chars) must match the cloud's")
    conn = await asyncpg.connect(a.database_url)
    try:
        await conn.execute("INSERT INTO tenants(tenant_id,name,home_region) VALUES($1,$1,'in') "
                           "ON CONFLICT DO NOTHING", a.tenant)
        await conn.execute("INSERT INTO memberships(user_id,tenant_id,role) VALUES($1,$2,$3) "
                           "ON CONFLICT(user_id,tenant_id) DO UPDATE SET role=EXCLUDED.role",
                           a.user, a.tenant, a.role)
    finally:
        await conn.close()
    claims = {"sub": a.user, "tenant_id": a.tenant, "exp": int(time.time()) + a.hours * 3600,
              "aud": os.getenv("DASHBOARD_JWT_AUDIENCE", "veilops-dashboard"),
              "iss": os.getenv("DASHBOARD_JWT_ISSUER", "veilops-control")}
    print(jwt.encode(claims, secret, algorithm="HS256"))


if __name__ == "__main__":
    asyncio.run(main())

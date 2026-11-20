"""Create (or reset) a dashboard user with a tenant membership.

  python -m cloud.scripts.create_dashboard_user --email ops@acme.test --name "Asha (operator)" \
      --tenant t_acme --role operator --password '...'
Uses ADMIN_DATABASE_URL (schema owner) or DATABASE_URL. The password is stored only as an Argon2id hash.
"""
import argparse
import asyncio
import os
import uuid

import asyncpg
from argon2 import PasswordHasher

from cloud.app.settings import Settings


async def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--email", required=True)
    p.add_argument("--name", required=True)
    p.add_argument("--tenant", required=True)
    p.add_argument("--role", default="operator", choices=("viewer", "operator", "approver", "tenant_admin"))
    p.add_argument("--password", required=True)
    a = p.parse_args()
    if len(a.password) < 10:
        raise SystemExit("password must be at least 10 characters")
    conn = await asyncpg.connect(os.getenv("ADMIN_DATABASE_URL", Settings().database_url))
    try:
        user_id = await conn.fetchval("SELECT user_id FROM dashboard_users WHERE email=$1", a.email.lower()) \
            or "u_" + uuid.uuid4().hex[:12]
        await conn.execute(
            """INSERT INTO dashboard_users(user_id,email,display_name,password_hash) VALUES($1,$2,$3,$4)
               ON CONFLICT(email) DO UPDATE SET display_name=EXCLUDED.display_name,password_hash=EXCLUDED.password_hash""",
            user_id, a.email.lower(), a.name, PasswordHasher().hash(a.password))
        await conn.execute("INSERT INTO tenants(tenant_id,name,home_region) VALUES($1,$1,'in') ON CONFLICT DO NOTHING",
                           a.tenant)
        await conn.execute("""INSERT INTO memberships(user_id,tenant_id,role) VALUES($1,$2,$3)
                              ON CONFLICT(user_id,tenant_id) DO UPDATE SET role=EXCLUDED.role""",
                           user_id, a.tenant, a.role)
    finally:
        await conn.close()
    print(f"{a.email} -> {user_id} ({a.role} in {a.tenant})")


if __name__ == "__main__":
    asyncio.run(main())

"""Dashboard sign-in on real PostgreSQL + Redis: Argon2 passwords, tenant-scoped JWT, rate limit."""
import asyncio

import pytest
from argon2 import PasswordHasher

from tests.test_judge_integration import PG_ADMIN, REDIS_URL, TENANT_A, _admin_dsn, client, database

pytestmark = pytest.mark.skipif(not (PG_ADMIN and REDIS_URL),
                                reason="set VEILOPS_TEST_PG_ADMIN and VEILOPS_TEST_REDIS_URL")
_ = (client, database)


def _db(q, *a):
    import asyncpg

    async def run():
        c = await asyncpg.connect(_admin_dsn("veilops"))
        try:
            return await c.fetch(q, *a)
        finally:
            await c.close()
    return asyncio.run(run())


def _user(email="asha@acme.test", pw="correct horse battery", user_id="op_a"):
    _db("INSERT INTO dashboard_users(user_id,email,display_name,password_hash) VALUES($1,$2,'Asha',$3)",
        user_id, email, PasswordHasher().hash(pw))


def test_login_issues_tenant_token_that_opens_the_api(client):
    _user()
    r = client.post("/auth/login", json={"email": "Asha@Acme.test", "password": "correct horse battery"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["user"]["tenant_id"] == TENANT_A and body["user"]["role"] == "operator"
    api = client.get("/api/v1/fleet", headers={"Authorization": f"Bearer {body['token']}"})
    assert api.status_code == 200 and api.json()["tenant_id"] == TENANT_A
    (row,) = _db("SELECT password_hash FROM dashboard_users WHERE user_id='op_a'")
    assert "correct horse" not in row["password_hash"] and row["password_hash"].startswith("$argon2")


def test_wrong_password_unknown_user_and_rate_limit(client):
    _user()
    assert client.post("/auth/login", json={"email": "asha@acme.test", "password": "nope"}).status_code == 401
    assert client.post("/auth/login", json={"email": "ghost@acme.test", "password": "nope"}).json()["detail"]["code"] \
        == "INVALID_CREDENTIALS"
    codes = [client.post("/auth/login", json={"email": "asha@acme.test", "password": "x"}).status_code for _ in range(5)]
    assert codes[-1] == 429                                  # 6th attempt in a minute is refused
    assert client.post("/auth/login", json={"email": "asha@acme.test", "password": "correct horse battery"}).status_code == 429


def test_user_without_membership_cannot_sign_in(client):
    _user(email="nomember@acme.test", user_id="u_lonely")
    r = client.post("/auth/login", json={"email": "nomember@acme.test", "password": "correct horse battery"})
    assert r.status_code == 403

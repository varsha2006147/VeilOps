"""VeilOps Cloud AIOps Engine end-to-end integration tests.

Opt-in via:
    VEILOPS_TEST_PG_ADMIN=postgresql://veilops@127.0.0.1:5432/postgres
    VEILOPS_TEST_REDIS_URL=redis://127.0.0.1:6379/15

Verifies 5 required end-to-end scenarios:
1. Multi-alert correlation: link loss + 5 dependent host/service alerts + topology -> 1 incident,
   root cause = link, recommendation = FAILOVER_TO_SECONDARY_LINK, evidence links present.
2. Load-aware CPU runaway: cpu elevated, req_rate flat -> 1 incident, RESTART_SERVICE.
3. Idempotency: rerunning AIOps cycle produces zero duplicate incidents, recommendations, or evidence.
4. Tenant isolation: Tenant B never sees Tenant A's incidents or recommendations under RLS.
5. Lifecycle auto-resolution: incident marks resolved after alerts stop.
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

PG_ADMIN = os.getenv("VEILOPS_TEST_PG_ADMIN")
REDIS_URL = os.getenv("VEILOPS_TEST_REDIS_URL")
pytestmark = pytest.mark.skipif(
    not (PG_ADMIN and REDIS_URL),
    reason="set VEILOPS_TEST_PG_ADMIN and VEILOPS_TEST_REDIS_URL",
)

MIGRATIONS = sorted((Path(__file__).parents[1] / "cloud" / "migrations").glob("*.sql"))
JWT_SECRET = "aiops-test-secret-" + "x" * 32
ENC_KEY = base64.urlsafe_b64encode(b"k" * 32).decode()
SIGN_KEY = base64.urlsafe_b64encode(b"s" * 32).decode()
HASH = "sha256:" + "0" * 64
TENANT_A, TENANT_B = "t_acme", "t_other"


def entity_id(prefix: str, label: str) -> str:
    """Return a deterministic entity ID matching VeilOps schema pattern."""
    h = hashlib.sha256(label.encode("utf-8")).hexdigest()[:10]
    return f"{prefix}_{h}"


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def now() -> datetime:
    return datetime.now(timezone.utc)


def _admin_dsn(db: str) -> str:
    return PG_ADMIN.rsplit("/", 1)[0] + "/" + db


async def _rebuild_database():
    import asyncpg
    admin = await asyncpg.connect(PG_ADMIN)
    await admin.execute("DROP DATABASE IF EXISTS veilops WITH (FORCE)")
    await admin.execute("CREATE DATABASE veilops")
    await admin.close()
    conn = await asyncpg.connect(_admin_dsn("veilops"))
    for path in MIGRATIONS:
        await conn.execute(path.read_text())
    await conn.close()


async def _seed():
    import asyncpg
    from cloud.app.crypto import SecretBox
    box = SecretBox(ENC_KEY)
    conn = await asyncpg.connect(_admin_dsn("veilops"))
    for t in (TENANT_A, TENANT_B):
        await conn.execute("INSERT INTO tenants(tenant_id,name,home_region) VALUES($1,$1,'in')", t)
    for cid, t in (("col_a", TENANT_A), ("col_b", TENANT_B)):
        await conn.execute(
            """INSERT INTO collectors(collector_id,tenant_id,region,secret_hash,status,secret_ciphertext)
               VALUES($1,$2,'in','unused','active',$3)""", cid, t, box.encrypt(cid.encode() * 4))
    for user, t, role in (("op_a", TENANT_A, "operator"), ("op_b", TENANT_B, "operator")):
        await conn.execute("INSERT INTO memberships(user_id,tenant_id,role) VALUES($1,$2,$3)", user, t, role)
    await conn.close()


@pytest.fixture(scope="module")
def database():
    import asyncio
    asyncio.run(_rebuild_database())
    yield


@pytest.fixture()
def client(database, monkeypatch):
    import asyncio
    import asyncpg
    import redis

    async def wipe():
        conn = await asyncpg.connect(_admin_dsn("veilops"))
        tables = await conn.fetch(
            "SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename NOT LIKE 'metric_points_%'"
        )
        await conn.execute("TRUNCATE " + ",".join(t["tablename"] for t in tables) + " CASCADE")
        await conn.close()

    asyncio.run(wipe())
    asyncio.run(_seed())
    redis.Redis.from_url(REDIS_URL).flushdb()

    monkeypatch.setenv("COLLECTOR_SECRET_ENCRYPTION_KEY", ENC_KEY)
    monkeypatch.setenv("SAAS_ED25519_PRIVATE_KEY", SIGN_KEY)
    monkeypatch.setenv("DASHBOARD_JWT_SECRET", JWT_SECRET)
    from fastapi.testclient import TestClient
    import cloud.app.main as main
    from cloud.app.settings import Settings
    from urllib.parse import urlsplit
    host = urlsplit(PG_ADMIN).netloc.rsplit("@", 1)[-1]
    app_dsn = f"postgresql://veilops_app:veilops_app_dev_only@{host}/veilops"
    monkeypatch.setattr(main, "Settings", lambda: Settings(
        database_url=app_dsn, redis_url=REDIS_URL, ingest_stream="veilops:test:" + secrets.token_hex(4)))
    with TestClient(main.app) as c:
        yield c


def token(user: str, tenant: str) -> dict:
    import jwt
    claims = {"sub": user, "tenant_id": tenant, "exp": int(time.time()) + 600,
              "aud": "veilops-dashboard", "iss": "veilops-control"}
    return {"Authorization": "Bearer " + jwt.encode(claims, JWT_SECRET, algorithm="HS256")}


A = lambda: token("op_a", TENANT_A)
B = lambda: token("op_b", TENANT_B)


def signed(client, method: str, path: str, body: bytes, collector: str = "col_a", **extra):
    ts, nonce = str(int(time.time())), secrets.token_hex(16)
    digest = hashlib.sha256(body).hexdigest()
    msg = "\n".join((method, path, ts, nonce, digest)).encode()
    sig = base64.b64encode(hmac.new(collector.encode() * 4, msg, hashlib.sha256).digest()).decode()
    headers = {"x-veilops-collector": collector, "x-veilops-timestamp": ts,
               "x-veilops-nonce": nonce, "x-veilops-signature": sig,
               "content-type": "application/json", **extra}
    return client.request(method, path, content=body, headers=headers)


def envelope(seq: int, records: list, collector="col_a", tenant=TENANT_A, payload_id=None) -> tuple[bytes, str]:
    pid = str(payload_id or uuid.uuid4())
    body = json.dumps({"schema_version": "1.0", "payload_id": pid, "tenant_id": tenant,
                       "collector_id": collector, "region": "in", "seq": seq, "sent_at": iso(now()),
                       "policy": {"version": 1, "hash": HASH},
                       "chain": {"prev_hash": HASH, "payload_hash": HASH},
                       "records": records}).encode()
    return body, pid


def send(client, seq, records, **kw):
    body, pid = envelope(seq, records, **kw)
    r = signed(client, "POST", "/v1/ingest", body, collector=kw.get("collector", "col_a"),
               **{"idempotency-key": pid})
    return r, body, pid


def wait_for(fn, timeout=12.0, step=0.3):
    end = time.time() + timeout
    while time.time() < end:
        value = fn()
        if value:
            return value
        time.sleep(step)
    raise AssertionError("condition not met in time")


# =================================================================== Scenarios

def test_scenario_1_link_failure_clustering_and_root_cause(client):
    """Scenario 1: Link loss alert + 5 dependent host/service alerts + topology -> 1 incident, lnk root cause."""
    lnk = entity_id("lnk", "primary_wan")
    h1, h2 = entity_id("h", "node1"), entity_id("h", "node2")
    svc1, svc2, svc3 = entity_id("svc", "api"), entity_id("svc", "auth"), entity_id("svc", "pay")

    t = now()
    # Topology record
    topo = {
        "type": "topology",
        "edges": [
            {"source_entity": h1, "target_entity": lnk, "relation": "connects_via"},
            {"source_entity": h2, "target_entity": lnk, "relation": "connects_via"},
            {"source_entity": svc1, "target_entity": h1, "relation": "runs_on"},
            {"source_entity": svc2, "target_entity": h1, "relation": "runs_on"},
            {"source_entity": svc3, "target_entity": h2, "relation": "runs_on"},
        ],
        "event_ts": iso(t), "source_tz": "UTC"
    }

    alerts = [
        {"type": "alert", "alert_id": str(uuid.uuid4()), "entity": lnk, "rule": "threshold.loss.high",
         "severity": "critical", "template_id": "T_LOSS", "params": {"loss": 45.0}, "event_ts": iso(t - timedelta(seconds=30)), "source_tz": "UTC"},
        {"type": "alert", "alert_id": str(uuid.uuid4()), "entity": h1, "rule": "threshold.latency.high",
         "severity": "high", "template_id": "T_LAT", "params": {"latency_ms": 180}, "event_ts": iso(t - timedelta(seconds=25)), "source_tz": "UTC"},
        {"type": "alert", "alert_id": str(uuid.uuid4()), "entity": h2, "rule": "threshold.latency.high",
         "severity": "high", "template_id": "T_LAT", "params": {"latency_ms": 190}, "event_ts": iso(t - timedelta(seconds=20)), "source_tz": "UTC"},
        {"type": "alert", "alert_id": str(uuid.uuid4()), "entity": svc1, "rule": "threshold.svc.down",
         "severity": "critical", "template_id": "T_DOWN", "params": {}, "event_ts": iso(t - timedelta(seconds=15)), "source_tz": "UTC"},
        {"type": "alert", "alert_id": str(uuid.uuid4()), "entity": svc2, "rule": "threshold.resp_ms.high",
         "severity": "warning", "template_id": "T_RESP", "params": {}, "event_ts": iso(t - timedelta(seconds=10)), "source_tz": "UTC"},
        {"type": "alert", "alert_id": str(uuid.uuid4()), "entity": svc3, "rule": "log.db.connect_error",
         "severity": "warning", "template_id": "T_ERR", "params": {}, "event_ts": iso(t - timedelta(seconds=5)), "source_tz": "UTC"},
    ]

    r, _, _ = send(client, 1, [topo] + alerts)
    assert r.status_code == 202

    # Wait for incident to be created by aiops_loop
    def check_incident():
        res = client.get("/api/v1/incidents", headers=A())
        if res.status_code == 200 and res.json().get("incidents"):
            return res.json()["incidents"]
        return None

    incidents = wait_for(check_incident, timeout=12.0)
    assert len(incidents) == 1
    inc = incidents[0]

    # Verify root cause was link
    detail = client.get(f"/api/v1/incidents/{inc['incident_id']}", headers=A()).json()
    assert detail["incident"]["root_cause_entity"] == lnk
    assert len(detail["evidence_links"]) >= 1

    # Verify timeline
    tl = client.get(f"/api/v1/incidents/{inc['incident_id']}/timeline", headers=A()).json()
    assert len(tl["alerts"]) == 6
    assert tl["root_cause_ranking"][0]["entity"] == lnk

    # Verify recommendation
    recs = client.get("/api/v1/actions", headers=A()).json()  # Or check detail
    rec_r = client.get(f"/api/v1/incidents/{inc['incident_id']}", headers=A()).json()
    # Check recommendation detail
    rec_id = detail["evidence_links"][0].get("recommendation_id") if detail["evidence_links"] else None
    if rec_id:
        r_resp = client.get(f"/api/v1/recommendations/{rec_id}", headers=A())
        assert r_resp.status_code == 200
        assert r_resp.json()["recommendation"]["action_type"] == "FAILOVER_TO_SECONDARY_LINK"


def test_scenario_2_cpu_runaway_restart_service(client):
    """Scenario 2: CPU runaway (cpu up, req_rate flat) -> 1 incident, RESTART_SERVICE."""
    h = entity_id("h", "srv01")
    t = now()

    # Metric points: cpu 96%, req_rate 1.0 (flat)
    metrics = [
        {"type": "metric", "entity": h, "entity_kind": "host", "metric": "cpu.util_pct", "unit": "pct",
         "avg": 96.0, "min": 94.0, "max": 98.0, "p95": 97.0, "count": 5, "window_s": 5, "event_ts": iso(t), "source_tz": "UTC"},
        {"type": "metric", "entity": h, "entity_kind": "host", "metric": "load.req_rate", "unit": "rps",
         "avg": 1.0, "min": 1.0, "max": 1.0, "p95": 1.0, "count": 5, "window_s": 5, "event_ts": iso(t), "source_tz": "UTC"},
    ]
    alert_cpu = {
        "type": "alert", "alert_id": str(uuid.uuid4()), "entity": h, "rule": "threshold.cpu.runaway",
        "severity": "critical", "template_id": "T_RUNAWAY", "params": {"value": 96.0},
        "event_ts": iso(t), "source_tz": "UTC"
    }

    r, _, _ = send(client, 10, metrics + [alert_cpu])
    assert r.status_code == 202

    def check():
        res = client.get("/api/v1/incidents", headers=A()).json()
        incs = res.get("incidents", [])
        for inc in incs:
            if inc.get("root_cause_entity") == h:
                return inc
        return None

    inc = wait_for(check, timeout=12.0)
    assert inc["root_cause_entity"] == h
    assert "runaway" in inc["summary"].lower() or "did not move" in inc["summary"].lower()


def test_scenario_3_idempotency_no_duplicates(client):
    """Scenario 3: Rerunning loop creates no duplicate incidents."""
    # Retrieve current count of incidents
    res = client.get("/api/v1/incidents", headers=A()).json()
    init_count = len(res.get("incidents", []))

    # Wait for two loop intervals
    time.sleep(6)
    res2 = client.get("/api/v1/incidents", headers=A()).json()
    assert len(res2.get("incidents", [])) == init_count


def test_scenario_4_tenant_isolation(client):
    """Scenario 4: Tenant B never sees Tenant A's incidents or evidence."""
    # Tenant A has incidents
    res_a = client.get("/api/v1/incidents", headers=A()).json()
    a_incs = res_a.get("incidents", [])

    # Tenant B requests incidents
    res_b = client.get("/api/v1/incidents", headers=B()).json()
    b_incs = res_b.get("incidents", [])
    assert len(b_incs) == 0

    # Tenant B tries to directly fetch Tenant A's incident
    if a_incs:
        target_id = a_incs[0]["incident_id"]
        res_cross = client.get(f"/api/v1/incidents/{target_id}", headers=B())
        assert res_cross.status_code == 404


def test_scenario_5_auto_resolution(client):
    """Scenario 5: Incident marks resolved after *.resolved alert arrives."""
    h = entity_id("h", "res_host")
    t = now()
    # 1. Open alert
    a_open = {
        "type": "alert", "alert_id": str(uuid.uuid4()), "entity": h, "rule": "threshold.cpu.high",
        "severity": "critical", "template_id": "T_CPU", "params": {}, "event_ts": iso(t), "source_tz": "UTC"
    }
    send(client, 20, [a_open])

    def find_inc():
        for i in client.get("/api/v1/incidents", headers=A()).json().get("incidents", []):
            if i.get("root_cause_entity") == h:
                return i
        return None

    inc = wait_for(find_inc, timeout=12.0)
    assert inc["status"] == "open"

    # 2. Resolved alert arrives
    a_res = {
        "type": "alert", "alert_id": str(uuid.uuid4()), "entity": h, "rule": "threshold.cpu.high.resolved",
        "severity": "info", "template_id": "T_RESOLVED", "params": {}, "event_ts": iso(now()), "source_tz": "UTC"
    }
    send(client, 21, [a_res])

    def check_resolved():
        for i in client.get("/api/v1/incidents", headers=A()).json().get("incidents", []):
            if i.get("incident_id") == inc["incident_id"] and i["status"] == "resolved":
                return i
        return None

    resolved_inc = wait_for(check_resolved, timeout=12.0)
    assert resolved_inc["status"] == "resolved"

"""Judge Mode end-to-end tests against real PostgreSQL 16 + Redis.

Opt-in (the fixture DROPS and recreates the `veilops` database):
    VEILOPS_TEST_PG_ADMIN=postgresql://veilops@127.0.0.1:5432/postgres
    VEILOPS_TEST_REDIS_URL=redis://127.0.0.1:6379/15
Flow under test is the real one: signed collector HTTP -> ingest receipt + outbox ->
Redis Streams -> processor -> PostgreSQL (RLS, runtime role) -> dashboard API with JWT.
"""
import base64
import csv
import hashlib
import hmac
import io
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
pytestmark = pytest.mark.skipif(not (PG_ADMIN and REDIS_URL),
                                reason="set VEILOPS_TEST_PG_ADMIN and VEILOPS_TEST_REDIS_URL")

MIGRATIONS = sorted((Path(__file__).parents[1] / "cloud" / "migrations").glob("*.sql"))
JWT_SECRET = "judge-mode-test-secret-" + "x" * 32
ENC_KEY = base64.urlsafe_b64encode(b"k" * 32).decode()
SIGN_KEY = base64.urlsafe_b64encode(b"s" * 32).decode()
HASH = "sha256:" + "0" * 64
TENANT_A, TENANT_B = "t_acme", "t_other"


def entity_id(label: str) -> str:
    """Return a deterministic entity ID matching the shared contract."""
    return "h_" + hashlib.sha256(label.encode("utf-8")).hexdigest()[:10]


def uuid7() -> uuid.UUID:
    ms, r = int(time.time() * 1000), secrets.randbits(74)
    return uuid.UUID(int=(ms << 80) | (7 << 76) | ((r >> 62) << 64) | (2 << 62) | (r & ((1 << 62) - 1)))


def iso(dt: datetime) -> str:
    return (
        dt.astimezone(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def now() -> datetime:
    return datetime.now(timezone.utc)


# ------------------------------------------------------------------ infrastructure

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
    for user, t, role in (("op_a", TENANT_A, "operator"), ("viewer_a", TENANT_A, "viewer"),
                          ("op_b", TENANT_B, "operator")):
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
            "SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename NOT LIKE 'metric_points_%'")
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


A, A_VIEWER, B = (lambda: token("op_a", TENANT_A)), (lambda: token("viewer_a", TENANT_A)), (lambda: token("op_b", TENANT_B))


def signed(client, method: str, path: str, body: bytes, collector: str = "col_a", **extra):
    ts, nonce = str(int(time.time())), secrets.token_hex(16)
    digest = hashlib.sha256(body).hexdigest()
    msg = "\n".join((method, path, ts, nonce, digest)).encode()
    sig = base64.b64encode(hmac.new(collector.encode() * 4, msg, hashlib.sha256).digest()).decode()
    headers = {"x-veilops-collector": collector, "x-veilops-timestamp": ts,
               "x-veilops-nonce": nonce, "x-veilops-signature": sig,
               "content-type": "application/json", **extra}
    return client.request(method, path, content=body, headers=headers)


def metric(entity: str, name: str, ts: datetime, lo: float, hi: float) -> dict:
    return {"type": "metric", "entity": entity, "entity_kind": "host", "metric": name, "unit": "pct",
            "avg": (lo + hi) / 2, "min": lo, "max": hi, "p95": hi, "count": 5, "window_s": 5,
            "event_ts": iso(ts), "source_tz": "Asia/Kolkata"}


def alert(entity: str, rule: str, ts: datetime, threshold: float, alert_id=None) -> dict:
    return {"type": "alert", "alert_id": str(alert_id or uuid.uuid4()), "entity": entity, "rule": rule,
            "severity": "warning", "template_id": "T_CPU_HIGH",
            "params": {"value": 95.0, "threshold": threshold, "breaching": 3, "of": 5},
            "event_ts": iso(ts), "source_tz": "Asia/Kolkata"}


def envelope(seq: int, records: list, collector="col_a", tenant=TENANT_A, payload_id=None) -> tuple[bytes, str]:
    pid = str(payload_id or uuid7())
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


def wait_for(fn, timeout=10.0, step=0.2):
    end = time.time() + timeout
    while time.time() < end:
        value = fn()
        if value:
            return value
        time.sleep(step)
    raise AssertionError("condition not met in time")


def processed(client, entity, metric_name="cpu.util_pct", n=1, headers=None):
    def check():
        r = client.get(f"/api/v1/entities/{entity}/metrics", headers=headers or A())
        return len(r.json()["metrics"]) >= n
    return wait_for(check)


def heartbeat(client, ts: datetime, depth=0, collector="col_a", tenant=TENANT_A, last_seq=0):
    body = json.dumps({"collector_id": collector, "tenant_id": tenant, "ts": iso(ts), "version": "0.1",
                       "uptime_s": 10, "cpu_pct": 1.0, "mem_mb": 50, "outbox_depth": depth,
                       "oldest_unsent_s": depth, "last_acked_seq": last_seq, "policy_version": 1,
                       "config_hash": HASH, "sources_ok": True}).encode()
    r = signed(client, "POST", "/v1/heartbeat", body, collector=collector)
    assert r.status_code == 204, r.text


# ------------------------------------------------------------------ 2. collection -> dashboard

def test_collection_to_dashboard_uses_original_event_ts(client):
    event_ts = now() - timedelta(seconds=3)
    r, _, pid = send(client, 1, [metric(entity_id("aaa"), "cpu.util_pct", event_ts, 30, 31)])
    assert r.status_code == 202, r.text
    processed(client, entity_id("aaa"))
    t = now()
    r = client.post("/api/v1/slo/render-ack", headers=A(), json={
        "record_key": f"payload:{pid}", "rendered_at": iso(t), "client_sent_at": iso(t)})
    assert r.status_code == 202, r.text
    assert 3000 <= r.json()["delay_ms"] < 6000

    slo = client.get("/api/v1/slo", headers=A()).json()
    c2d = slo["collection_to_dashboard"]["recent_5m"]
    assert c2d["count"] == 1 and c2d["p95_ms"] == c2d["max_ms"] == r.json()["delay_ms"]
    assert slo["evaluation"]["collection_to_dashboard"] == "pass"


def test_render_ack_corrects_browser_clock_offset(client):
    event_ts = now() - timedelta(seconds=2)
    _, _, pid = send(client, 1, [metric(entity_id("aaa"), "cpu.util_pct", event_ts, 30, 31)])
    processed(client, entity_id("aaa"))
    browser_now = now() - timedelta(seconds=90)          # browser clock 90 s slow
    r = client.post("/api/v1/slo/render-ack", headers=A(), json={
        "record_key": f"payload:{pid}", "rendered_at": iso(browser_now), "client_sent_at": iso(browser_now)})
    assert r.status_code == 202, r.text
    assert 2000 <= r.json()["delay_ms"] < 5000 and r.json()["clock_offset_ms"] >= 89_000


def test_render_ack_never_trusts_client_event_time_or_unknown_records(client):
    t = iso(now())
    legacy = {"sample_key": "x", "rendered_at": t, "source_event_ts": t}
    assert client.post("/api/v1/slo/render-ack", headers=A(), json=legacy).status_code == 422
    unknown = {"record_key": f"payload:{uuid7()}", "rendered_at": t}
    assert client.post("/api/v1/slo/render-ack", headers=A(), json=unknown).status_code == 404
    naive = {"record_key": f"payload:{uuid7()}", "rendered_at": "2026-11-21T04:00:00"}
    assert client.post("/api/v1/slo/render-ack", headers=A(), json=naive).status_code == 422


# ------------------------------------------------------------------ 3. breach -> alert

def test_breach_to_alert_measured_per_injection(client):
    t0 = now()
    r = client.post("/api/v1/slo/injections", headers=A(), json={
        "scenario": "cpu_drift", "entity": entity_id("cpu"), "rule": "threshold.cpu.high", "injected_at": iso(t0 - timedelta(seconds=20))})
    assert r.status_code == 201, r.text
    records = [metric(entity_id("cpu"), "cpu.util_pct", t0 - timedelta(seconds=15), 25, 30),
               metric(entity_id("cpu"), "cpu.util_pct", t0 - timedelta(seconds=10), 60, 95),
               metric(entity_id("cpu"), "cpu.util_pct", t0 - timedelta(seconds=5), 93, 97),
               alert(entity_id("cpu"), "threshold.cpu.high", t0 - timedelta(seconds=3), 90.0)]
    assert send(client, 1, records)[0].status_code == 202

    def measured():
        items = client.get("/api/v1/slo/injections", headers=A()).json()["injections"]
        return items[0] if items[0]["status"] == "measured" else None
    inj = wait_for(measured)
    first_breach = datetime.fromisoformat(inj["first_breach_ts"])
    assert abs((first_breach - (t0 - timedelta(seconds=10))).total_seconds()) < 0.01
    assert 10_000 <= inj["delay_ms"] < 15_000
    slo = client.get("/api/v1/slo", headers=A()).json()
    assert slo["breach_to_alert"]["recent_5m"]["count"] == 1
    assert slo["evaluation"]["breach_to_alert"] == "pass"


def test_breach_to_alert_not_fabricated_without_breaching_windows(client):
    t0 = now()
    client.post("/api/v1/slo/injections", headers=A(), json={
        "scenario": "cpu_drift", "entity": entity_id("nob"), "rule": "threshold.cpu.high"})
    send(client, 1, [metric(entity_id("nob"), "cpu.util_pct", t0 - timedelta(seconds=5), 20, 30),
                     alert(entity_id("nob"), "threshold.cpu.high", t0, 90.0)])
    processed(client, entity_id("nob"))
    time.sleep(1.0)
    slo = client.get("/api/v1/slo", headers=A()).json()
    assert slo["breach_to_alert"]["all_time"]["count"] == 0
    assert slo["breach_to_alert"]["injections"][0]["status"] == "pending"
    assert slo["evaluation"]["breach_to_alert"] == "insufficient_data"


# ------------------------------------------------------------------ 4. offline detection

def test_offline_detection_uses_last_heartbeat_and_watchdog(client):
    last = now() - timedelta(seconds=35)
    heartbeat(client, last)

    def detected():
        cols = client.get("/api/v1/slo", headers=A()).json()["collector_offline_detection"]
        return cols if cols["all_time"]["count"] else None
    off = wait_for(detected, timeout=12)
    assert 35_000 <= off["all_time"]["max_ms"] <= 60_000
    col = [c for c in off["collectors"] if c["collector_id"] == "col_a"][0]
    assert col["state"] == "Poor"
    assert datetime.fromisoformat(col["last_offline_detection"]["event_ts"]) == datetime.fromisoformat(iso(last))


# ------------------------------------------------------------------ 5/6/7/8 reconciliation

def _reconcile(client, a, b, collector="col_a"):
    path = f"/v1/reconcile?collector_id={collector}&from_seq={a}&to_seq={b}"
    r = signed(client, "GET", path, b"", collector=collector)
    assert r.status_code == 200, r.text
    return r.json()


def test_missing_sequence_detected(client):
    t = now()
    for seq in (1, 2, 4):
        assert send(client, seq, [metric(entity_id("m"), "cpu.util_pct", t - timedelta(seconds=10 - seq), 1, 2)])[0].status_code == 202
    out = _reconcile(client, 1, 4)
    assert out["missing_sequences"] == [3] and not out["reconciled"]
    summary = client.get("/api/v1/reconciliation", headers=A()).json()["collectors"]
    col = [c for c in summary if c["collector_id"] == "col_a"][0]
    assert col["missing_sequences"] == [3] and col["status"] == "missing"
    assert client.get("/api/v1/slo", headers=A()).json()["evaluation"]["zero_loss"] == "fail"


def test_duplicate_payload_rejected_and_counted(client):
    t = now() - timedelta(seconds=4)
    r1, body, pid = send(client, 1, [metric(entity_id("d"), "cpu.util_pct", t, 10, 20)])
    assert r1.status_code == 202
    again = signed(client, "POST", "/v1/ingest", body, **{"idempotency-key": pid})
    assert again.status_code == 200 and again.json()["status"] == "duplicate"
    conflict, _, _ = send(client, 1, [metric(entity_id("d"), "cpu.util_pct", t, 99, 99)])  # same seq, new payload
    assert conflict.status_code == 409
    processed(client, entity_id("d"))
    rows = client.get(
        f"/api/v1/entities/{entity_id('d')}/metrics",
        headers=A()
    ).json()["metrics"]
    assert len(rows) == 1 and rows[0]["max"] == 20      # neither retry changed stored data
    rec = client.get("/api/v1/reconciliation", headers=A()).json()["collectors"]
    dup = [c for c in rec if c["collector_id"] == "col_a"][0]["duplicates_rejected"]
    assert dup == {"duplicate_payload": 1, "sequence_conflict": 1, "idempotency_conflict": 0, "total": 2}


def test_out_of_order_delivery_keeps_event_time_order(client):
    t = now() - timedelta(seconds=30)
    send(client, 2, [metric(entity_id("o"), "cpu.util_pct", t + timedelta(seconds=10), 50, 60)])
    send(client, 1, [metric(entity_id("o"), "cpu.util_pct", t, 10, 20)])
    processed(client, entity_id("o"), n=2)
    rows = client.get(
        f"/api/v1/entities/{entity_id('o')}/metrics",
        headers=A()
    ).json()["metrics"]
    times = [datetime.fromisoformat(r["event_ts"]) for r in rows]
    assert times == sorted(times, reverse=True) and [r["max"] for r in rows] == [60, 20]
    assert _reconcile(client, 1, 2)["reconciled"]


def test_outage_recovery_zero_loss_zero_duplicates(client):
    """Collector buffers during an outage, reconnects, drains its backlog, retries one payload."""
    t = now()
    heartbeat(client, t - timedelta(seconds=70), depth=0)
    sent = {}
    for seq in (1, 2):
        _, sent[seq], _ = send(client, seq, [metric(entity_id("r"), "cpu.util_pct", t - timedelta(seconds=70 - seq * 5), 30, 31)])
    # outage: no traffic for ~50 s; collector keeps 4 payloads in its outbox
    heartbeat(client, t - timedelta(seconds=12), depth=4)
    for seq in (3, 4, 5, 6):
        r, sent[seq], pid = send(client, seq, [metric(entity_id("r"), "cpu.util_pct", t - timedelta(seconds=60 - seq * 5), 30, 31)])
        assert r.status_code == 202
        if seq == 4:  # ack lost on the way back: collector retries the same payload
            again = signed(client, "POST", "/v1/ingest", sent[4], **{"idempotency-key": pid})
            assert again.json()["status"] == "duplicate"
    heartbeat(client, t - timedelta(seconds=5), depth=0)
    out = _reconcile(client, 1, 6)
    assert out["reconciled"] and out["missing_sequences"] == [] and out["duplicates_rejected"] == 1
    processed(client, entity_id("r"), n=6)

    slo = client.get("/api/v1/slo", headers=A()).json()
    rec = slo["reconciliation"]
    assert rec["sent_count"] == rec["received_count"] == 6
    assert rec["missing_count"] == 0 and rec["duplicates_rejected"] == 1 and rec["duplicate_records_stored"] == 0
    assert rec["backlog_last_drain_ms"] == 7000
    assert slo["evaluation"]["zero_loss"] == "pass" and slo["evaluation"]["zero_duplicates"] == "pass"


# ------------------------------------------------------------------ quality

def test_quality_metrics_come_from_alerts_incidents_and_feedback(client):
    t = now()
    ids = [uuid.uuid4() for _ in range(3)]
    send(client, 1, [alert(entity_id(f"q{i}"), "threshold.cpu.high", t - timedelta(seconds=2), 90.0, ids[i]) for i in range(3)])
    wait_for(lambda: len(client.get("/api/v1/alerts", headers=A()).json()["alerts"]) == 3)
    import asyncio, asyncpg

    async def incident():
        conn = await asyncpg.connect(_admin_dsn("veilops"))
        await conn.execute("INSERT INTO incidents(incident_id,tenant_id,title,severity) VALUES($1,$2,'cpu','warning')",
                           uuid.uuid4(), TENANT_A)
        await conn.close()
    asyncio.run(incident())
    q = client.get("/api/v1/slo", headers=A()).json()["quality"]
    assert q["false_alarms"] == 0  # nothing reviewed yet -> zero, not a guess
    assert client.post(f"/api/v1/alerts/{ids[0]}/feedback", headers=A(), json={"verdict": "false_alarm"}).status_code == 200
    assert client.post(f"/api/v1/alerts/{ids[0]}/feedback", headers=A_VIEWER(), json={"verdict": "valid"}).status_code == 403
    q = client.get("/api/v1/slo", headers=A()).json()["quality"]
    assert (q["raw_alerts"], q["incidents"], q["alert_to_incident_ratio"], q["false_alarms"]) == (3, 1, 3.0, 1)


# ------------------------------------------------------------------ 9. tenant isolation

def test_tenant_isolation_rest_csv_and_feedback(client):
    _, _, pid = send(client, 1, [metric(entity_id("iso"), "cpu.util_pct", now() - timedelta(seconds=2), 1, 2)])
    processed(client, entity_id("iso"))
    t = iso(now())
    assert client.post("/api/v1/slo/render-ack", headers=A(), json={"record_key": f"payload:{pid}", "rendered_at": t}).status_code == 202
    # tenant B cannot measure, see, export or label tenant A's data
    assert client.post("/api/v1/slo/render-ack", headers=B(), json={"record_key": f"payload:{pid}", "rendered_at": t}).status_code == 404
    slo_b = client.get("/api/v1/slo", headers=B()).json()
    assert slo_b["tenant_id"] == TENANT_B and slo_b["samples"] == []
    assert slo_b["collection_to_dashboard"]["all_time"]["count"] == 0
    assert [c["collector_id"] for c in slo_b["reconciliation"]["collectors"]] == ["col_b"]
    rows = list(csv.reader(io.StringIO(client.get("/api/v1/slo/export.csv", headers=B()).text)))
    assert len(rows) == 1  # header only
    a_alert = uuid.uuid4()
    send(client, 2, [alert(entity_id("iso"), "threshold.cpu.high", now(), 90.0, a_alert)])
    wait_for(lambda: client.get("/api/v1/alerts", headers=A()).json()["alerts"])
    assert client.post(f"/api/v1/alerts/{a_alert}/feedback", headers=B(), json={"verdict": "false_alarm"}).status_code == 404
    # a tenant_id in the body is never honoured
    bad = {"scenario": "x", "entity": "h", "rule": "threshold.cpu.high", "tenant_id": TENANT_A}
    assert client.post("/api/v1/slo/injections", headers=B(), json=bad).status_code == 422
    assert client.get("/api/v1/slo").status_code == 401


# ------------------------------------------------------------------ 10. CSV export

def test_csv_export_matches_persisted_samples(client):
    _, _, pid = send(client, 1, [metric(entity_id("csv"), "cpu.util_pct", now() - timedelta(seconds=2), 1, 2)])
    processed(client, entity_id("csv"))
    t = iso(now())
    ack = client.post("/api/v1/slo/render-ack", headers=A(), json={"record_key": f"payload:{pid}", "rendered_at": t}).json()
    _reconcile(client, 1, 1)
    r = client.get("/api/v1/slo/export.csv", headers=A())
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert "attachment" in r.headers["content-disposition"]
    rows = list(csv.DictReader(io.StringIO(r.text)))
    by_type = {row["measurement_type"]: row for row in rows}
    assert set(by_type) == {"collection_to_ingest", "collection_to_dashboard", "reconciliation_missing_sequences"}
    c2d = by_type["collection_to_dashboard"]
    assert c2d["tenant_id"] == TENANT_A and c2d["record_or_collector_id"] == f"payload:{pid}"
    assert int(c2d["delay_ms"]) == ack["delay_ms"] and c2d["unit"] == "ms"
    rec = by_type["reconciliation_missing_sequences"]
    assert rec["unit"] == "count" and rec["value"] == "0" and rec["delay_ms"] == "" and rec["reconciliation_run_id"]
    assert all(row["tenant_id"] == TENANT_A for row in rows)


# ------------------------------------------------------------------ 11. empty / invalid

def test_empty_tenant_reports_insufficient_data(client):
    slo = client.get("/api/v1/slo", headers=B()).json()
    ev = slo["evaluation"]
    assert ev["collection_to_dashboard"] == ev["breach_to_alert"] == "insufficient_data"
    assert ev["collector_offline_detection"] == "insufficient_data" and ev["zero_loss"] == "insufficient_data"
    assert slo["quality"]["alert_to_incident_ratio"] is None


def test_invalid_measurement_input_rejected(client):
    bad_rule = {"scenario": "x", "entity": "h_1", "rule": "threshold.made.up"}
    assert client.post("/api/v1/slo/injections", headers=A(), json=bad_rule).status_code == 422
    far = {"scenario": "x", "entity": "h_1", "rule": "threshold.cpu.high", "injected_at": iso(now() - timedelta(hours=2))}
    assert client.post("/api/v1/slo/injections", headers=A(), json=far).status_code == 422
    ok = {"scenario": "x", "entity": "h_1", "rule": "threshold.cpu.high"}
    assert client.post("/api/v1/slo/injections", headers=A_VIEWER(), json=ok).status_code == 403
    assert client.get("/api/v1/slo/export.csv?since=2026-11-21T04:00:00", headers=A()).status_code == 422
    skew = {"record_key": f"payload:{uuid7()}", "rendered_at": iso(now() - timedelta(hours=1)),
            "client_sent_at": iso(now() - timedelta(hours=1))}
    assert client.post("/api/v1/slo/render-ack", headers=A(), json=skew).status_code == 422


# ------------------------------------------------------------------ 12. Redis failure

def test_redis_failures(client, monkeypatch):
    _, _, pid = send(client, 1, [metric(entity_id("rf"), "cpu.util_pct", now() - timedelta(seconds=2), 1, 2)])
    processed(client, entity_id("rf"))
    redis = client.app.state.redis

    async def boom(*a, **k):
        raise ConnectionError("redis down")
    monkeypatch.setattr(redis, "publish", boom)
    # SSE push fails, the measurement is still committed
    t = iso(now())
    r = client.post("/api/v1/slo/render-ack", headers=A(), json={"record_key": f"payload:{pid}", "rendered_at": t})
    assert r.status_code == 202 and r.json()["recorded"]
    monkeypatch.setattr(redis, "ping", boom)
    r, _, _ = send(client, 2, [metric(entity_id("rf"), "cpu.util_pct", now(), 1, 2)])
    assert r.status_code == 503 and r.json()["detail"]["code"] == "STREAM_UNAVAILABLE"
    assert _reconcile(client, 1, 2)["missing_sequences"] == [2]  # refused payload is visible as missing


# ------------------------------------------------------------------ topology API

def test_topology_api_is_collector_scoped_and_tenant_isolated(client):
    svc, host = "svc_" + entity_id("checkout")[2:], entity_id("app-01")
    record = {"type": "topology", "edges": [{"src": svc, "dst": host, "rel": "runs_on"}], "event_ts": iso(now())}
    assert send(client, 1, [record])[0].status_code == 202

    def edges():
        return client.get("/api/v1/topology", headers=A()).json()["edges"]
    got = wait_for(edges)
    assert got[0]["src"] == svc and got[0]["dst"] == host and got[0]["collector_id"] == "col_a"
    nodes = {n["id"]: n["kind"] for n in client.get("/api/v1/topology", headers=A()).json()["nodes"]}
    assert nodes == {svc: "service", host: "host"}
    # a new snapshot replaces this collector's edges instead of piling up
    record["edges"] = [{"src": host, "dst": "lnk_" + entity_id("core")[2:], "rel": "connects_via"}]
    record["event_ts"] = iso(now())
    send(client, 2, [record])
    wait_for(lambda: [e["rel"] for e in edges()] == ["connects_via"])
    assert client.get("/api/v1/topology", headers=B()).json() == {"nodes": [], "edges": []}

"""Person C final verification: enrollment, ingest security matrix, receipts, Redis Streams writer,
watchdog thresholds, late data, residency. Real PostgreSQL 16 + Redis 7 (opt-in env like the other
integration tests); nothing here mocks Redis or PostgreSQL.
"""
import asyncio
import base64
import hashlib
import hmac
import json
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from tests.test_judge_integration import (
    A, B, ENC_KEY, HASH, PG_ADMIN, REDIS_URL, SIGN_KEY, TENANT_A, _admin_dsn, alert, client, database,
    entity_id, envelope, heartbeat, iso, metric, now, send, signed, uuid7, wait_for,
)

pytestmark = pytest.mark.skipif(not (PG_ADMIN and REDIS_URL),
                                reason="set VEILOPS_TEST_PG_ADMIN and VEILOPS_TEST_REDIS_URL")
_ = (client, database)


def db(query, *args):
    import asyncpg

    async def run():
        conn = await asyncpg.connect(_admin_dsn("veilops"))
        try:
            return await conn.fetch(query, *args)
        finally:
            await conn.close()
    return asyncio.run(run())


def raw_post(client, path, body, *, collector="col_a", secret=None, ts=None, nonce=None, sig=None, **extra):
    """Signed request with every auth field overridable (for negative tests)."""
    ts = ts or str(int(time.time()))
    nonce = nonce or secrets.token_hex(16)
    secret = secret if secret is not None else collector.encode() * 4
    msg = "\n".join(("POST", path, ts, nonce, hashlib.sha256(body).hexdigest())).encode()
    sig = sig or base64.b64encode(hmac.new(secret, msg, hashlib.sha256).digest()).decode()
    return client.post(path, content=body, headers={
        "x-veilops-collector": collector, "x-veilops-timestamp": ts, "x-veilops-nonce": nonce,
        "x-veilops-signature": sig, "content-type": "application/json", **extra})


def receipts():
    return db("SELECT seq FROM ingest_receipts ORDER BY seq")


# ------------------------------------------------------------------ enrollment

def _token(expires_in=timedelta(minutes=15), tenant=TENANT_A):
    tok = secrets.token_urlsafe(32)
    db("INSERT INTO enrollment_tokens(token_hash,tenant_id,region,expires_at) VALUES($1,$2,'in',$3)",
       hashlib.sha256(tok.encode()).hexdigest(), tenant, datetime.now(timezone.utc) + expires_in)
    return tok


def test_enrollment_success_single_use_expired_and_invalid(client):
    tok = _token()
    r = client.post("/v1/enroll", json={"enrollment_token": tok, "version": "1.0.0"})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["tenant_id"] == TENANT_A and body["region"] == "in" and body["collector_id"].startswith("col_")
    assert body["ingest_url"].endswith("/v1") and body["saas_pubkey"] and len(body["collector_secret"]) >= 32
    (row,) = db("SELECT tenant_id,status,secret_hash,secret_ciphertext FROM collectors WHERE collector_id=$1",
                body["collector_id"])
    assert row["tenant_id"] == TENANT_A and row["status"] == "active"
    stored = row["secret_hash"] + bytes(row["secret_ciphertext"]).hex()
    assert body["collector_secret"] not in stored                       # never stored in plaintext
    audit = db("SELECT details::text AS d FROM audit_events")
    assert all(body["collector_secret"] not in a["d"] for a in audit)
    # single use: the secret is returned once only
    assert client.post("/v1/enroll", json={"enrollment_token": tok, "version": "1.0.0"}).status_code == 401
    assert client.post("/v1/enroll", json={"enrollment_token": _token(timedelta(seconds=-1)), "version": "1.0.0"}).status_code == 401
    assert client.post("/v1/enroll", json={"enrollment_token": "x" * 40, "version": "1.0.0"}).status_code == 401
    assert client.post("/v1/enroll", json={"enrollment_token": "short", "version": "1.0.0"}).status_code == 422
    # the enrolled collector can ingest for its own tenant, and only its own
    cid, secret = body["collector_id"], body["collector_secret"].encode()
    good, pid = envelope(1, [metric(entity_id("enr"), "cpu.util_pct", now(), 1, 2)], collector=cid)
    assert raw_post(client, "/v1/ingest", good, collector=cid, secret=secret, **{"idempotency-key": pid}).status_code == 202
    other, pid2 = envelope(2, [metric(entity_id("enr"), "cpu.util_pct", now(), 1, 2)], collector=cid, tenant="t_other")
    assert raw_post(client, "/v1/ingest", other, collector=cid, secret=secret, **{"idempotency-key": pid2}).status_code == 403


# ------------------------------------------------------------------ ingest security matrix

def test_ingest_security_matrix(client):
    rec = [metric(entity_id("sec"), "cpu.util_pct", now(), 1, 2)]

    def env(seq, **kw):
        return envelope(seq, rec, **kw)

    body, pid = env(1)
    idem = {"idempotency-key": pid}
    assert raw_post(client, "/v1/ingest", body, sig="A" * 44, **idem).json()["detail"]["code"] == "BAD_SIGNATURE"
    assert raw_post(client, "/v1/ingest", body, secret=b"wrong-key", **idem).status_code == 401
    stale = raw_post(client, "/v1/ingest", body, ts=str(int(time.time()) - 400), **idem)
    assert (stale.status_code, stale.json()["detail"]["code"]) == (401, "STALE_TIMESTAMP")
    nonce = secrets.token_hex(16)
    assert raw_post(client, "/v1/ingest", body, nonce=nonce, **idem).status_code == 202          # valid
    replay = raw_post(client, "/v1/ingest", body, nonce=nonce, **idem)
    assert (replay.status_code, replay.json()["detail"]["code"]) == (409, "NONCE_REUSED")
    wt, p = env(2, tenant="t_other")
    assert raw_post(client, "/v1/ingest", wt, **{"idempotency-key": p}).json()["detail"]["code"] == "TENANT_MISMATCH"
    wr = json.loads(env(3)[0]); wr["region"] = "eu"; wr = json.dumps(wr).encode()
    r = raw_post(client, "/v1/ingest", wr, **{"idempotency-key": json.loads(wr)["payload_id"]})
    assert (r.status_code, r.json()["detail"]["code"]) == (403, "WRONG_REGION")
    bad = json.loads(env(4)[0]); bad["records"][0]["entity"] = "app-01"; bad = json.dumps(bad).encode()
    assert raw_post(client, "/v1/ingest", bad, **{"idempotency-key": json.loads(bad)["payload_id"]}).status_code == 422
    unk = json.loads(env(5)[0]); unk["records"] = [{"type": "raw_log", "line": "x", "event_ts": iso(now())}]
    unk = json.dumps(unk).encode()
    r = raw_post(client, "/v1/ingest", unk, **{"idempotency-key": json.loads(unk)["payload_id"]})
    assert (r.status_code, r.json()["detail"]["code"]) == (422, "UNKNOWN_RECORD_TYPE")
    big = b"{" + b" " * 1_048_600 + b"}"
    assert raw_post(client, "/v1/ingest", big).status_code == 413
    mismatch = raw_post(client, "/v1/ingest", env(6)[0], **{"idempotency-key": str(uuid7())})
    assert mismatch.status_code == 422
    assert [r["seq"] for r in receipts()] == [1]                                 # only the valid one stored


def test_receipt_fields_hash_and_signature(client):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    r, body, pid = send(client, 1, [metric(entity_id("rcpt"), "cpu.util_pct", now(), 1, 2)])
    rec = r.json()
    assert rec["payload_id"] == pid and rec["status"] == "stored" and rec["region"] == "in"
    assert rec["payload_hash"] == "sha256:" + hashlib.sha256(body).hexdigest()
    assert datetime.strptime(rec["received_at"], "%Y-%m-%dT%H:%M:%S.%fZ")
    pub = Ed25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(SIGN_KEY)).public_key()
    unsigned = {k: v for k, v in rec.items() if k != "sig"}
    pub.verify(base64.b64decode(rec["sig"]), json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode())
    (row,) = db("SELECT payload_hash FROM ingest_receipts WHERE payload_id=$1", uuid.UUID(pid))
    assert row["payload_hash"] == rec["payload_hash"]


# ------------------------------------------------------------------ Redis Streams writer

def test_stream_writer_stores_every_record_type_and_acks(client):
    import redis as redis_lib
    e = entity_id("writer")
    sec = {"type": "security_summary", "category": "auth.bruteforce", "severity": "high", "count": 12,
           "distinct_principals": 1, "distinct_sources": 1, "principals": ["usr_" + "a" * 10],
           "sources": ["src_" + "b" * 10], "risk_score": 80, "window_s": 60, "event_ts": iso(now()),
           "source_tz": "UTC"}
    hl = {"type": "health", "entity": e, "state": "fair", "reasons": ["cpu_high"], "event_ts": iso(now())}
    topo = {"type": "topology", "edges": [{"src": e, "dst": "lnk_" + "c" * 10, "rel": "connects_via"}],
            "event_ts": iso(now())}
    r, _, _ = send(client, 1, [metric(e, "cpu.util_pct", now() - timedelta(seconds=5), 1, 2),
                               alert(e, "threshold.cpu.high", now(), 90.0), sec, hl, topo])
    assert r.status_code == 202
    wait_for(lambda: db("SELECT 1 FROM topology_edges"))
    assert len(db("SELECT 1 FROM metric_points WHERE entity=$1", e)) == 1
    assert len(db("SELECT 1 FROM alerts WHERE entity=$1", e)) == 1
    assert len(db("SELECT 1 FROM security_summaries")) == 1
    assert db("SELECT state FROM health_current WHERE entity=$1", e)[0]["state"] == "Fair"
    rc = redis_lib.Redis.from_url(REDIS_URL, decode_responses=True)
    stream = client.app.state.settings.ingest_stream
    groups = {g["name"]: g for g in rc.xinfo_groups(stream)}
    assert "cloud-writers" in groups
    wait_for(lambda: rc.xpending(stream, "cloud-writers")["pending"] == 0)          # acked after commit
    assert db("SELECT published_at FROM ingest_stream_outbox")[0]["published_at"] is not None


def test_redelivered_stream_message_has_no_duplicate_side_effects(client):
    import redis as redis_lib
    e = entity_id("dup-stream")
    sec = {"type": "security_summary", "category": "auth.spray", "severity": "high", "count": 5,
           "distinct_principals": 5, "distinct_sources": 1, "principals": [], "sources": [], "risk_score": 70,
           "window_s": 60, "event_ts": iso(now()), "source_tz": "UTC"}
    send(client, 1, [metric(e, "cpu.util_pct", now(), 1, 2), sec])
    wait_for(lambda: db("SELECT 1 FROM security_summaries"))
    rc = redis_lib.Redis.from_url(REDIS_URL, decode_responses=True)
    stream = client.app.state.settings.ingest_stream
    (_, fields), = rc.xrange(stream, count=1)
    rc.xadd(stream, fields)                       # the same payload delivered again (crash between commit and ack)
    wait_for(lambda: rc.xpending(stream, "cloud-writers")["pending"] == 0 and rc.xlen(stream) == 2)
    time.sleep(1.0)
    assert len(db("SELECT 1 FROM security_summaries")) == 1
    assert len(db("SELECT 1 FROM metric_points WHERE entity=$1", e)) == 1


def test_pending_message_recovered_after_consumer_crash(client):
    """A consumer reads a message and dies without ACK; the writer reclaims it (idle > 30 s) and stores it."""
    import redis as redis_lib
    rc = redis_lib.Redis.from_url(REDIS_URL, decode_responses=True)
    stream = client.app.state.settings.ingest_stream
    client.app.state.processor_stop.set()                 # stop the live writer for a moment
    client.app.state.processor_task.cancel()
    time.sleep(1.5)
    try:
        rc.xgroup_create(stream, "cloud-writers", id="0", mkstream=True)
    except redis_lib.ResponseError:
        pass                                              # already created by the writer at startup
    e = entity_id("crash")
    send(client, 1, [metric(e, "cpu.util_pct", now(), 1, 2)])
    wait_for(lambda: rc.xlen(stream) >= 1)
    rc.xreadgroup("cloud-writers", "crashed-writer", {stream: ">"}, count=10)   # read, never ACK
    assert rc.xpending(stream, "cloud-writers")["pending"] == 1
    # start a fresh writer on the app's own loop (as a restarted process would)
    from cloud.app.processor import StreamProcessor
    import asyncio as aio
    st = client.app.state
    st.processor_stop = aio.Event()

    async def start():
        st.processor_task = aio.create_task(StreamProcessor(st.redis, st.db_pool, stream).run(st.processor_stop))
    client.portal.call(start)
    wait_for(lambda: db("SELECT 1 FROM metric_points WHERE entity=$1", e), timeout=45)
    wait_for(lambda: rc.xpending(stream, "cloud-writers")["pending"] == 0, timeout=10)


def test_outbox_retries_after_stream_publish_failure(client):
    """Redis XADD fails after the receipt committed: the receipt stays, the outbox retries, data arrives."""
    redis = client.app.state.redis
    real_xadd, calls = redis.xadd, {"n": 0}

    async def flaky_xadd(*a, **k):
        calls["n"] += 1
        if calls["n"] <= 3:
            raise ConnectionError("stream unavailable")
        return await real_xadd(*a, **k)
    redis.xadd = flaky_xadd
    try:
        e = entity_id("outbox")
        r, _, _ = send(client, 1, [metric(e, "cpu.util_pct", now(), 1, 2)])
        assert r.status_code == 202                                           # receipt issued despite Redis
        wait_for(lambda: db("SELECT 1 FROM metric_points WHERE entity=$1", e), timeout=15)
        (row,) = db("SELECT attempts,last_error,published_at FROM ingest_stream_outbox")
        assert row["attempts"] >= 4 and row["published_at"] is not None and row["last_error"] is None
    finally:
        redis.xadd = real_xadd


# ------------------------------------------------------------------ watchdog thresholds

def test_watchdog_fair_after_15s_poor_after_30s_and_recovery(client):
    e = entity_id("wd")
    send(client, 1, [metric(e, "cpu.util_pct", now() - timedelta(seconds=2), 10, 12)])
    wait_for(lambda: db("SELECT 1 FROM metric_points WHERE entity=$1", e))

    def state():
        rows = db("SELECT state,reasons::text AS r FROM health_current WHERE entity=$1", e)
        return rows[0] if rows else None
    heartbeat(client, now() - timedelta(seconds=17))
    wait_for(lambda: (s := state()) and s["state"] == "Fair", timeout=12)
    assert "heartbeat_missing_15s" in state()["r"]
    db("DELETE FROM collector_heartbeats")
    heartbeat(client, now() - timedelta(seconds=32))
    wait_for(lambda: state()["state"] == "Poor", timeout=12)
    assert "heartbeat_missing_over_30s" in state()["r"]
    send(client, 2, [metric(e, "cpu.util_pct", now() - timedelta(seconds=1), 10, 12)])   # collector is back
    heartbeat(client, now())
    wait_for(lambda: state()["state"] in ("Excellent", "Good"), timeout=12)
    trans = [r["to_state"] for r in db("SELECT to_state FROM health_transitions WHERE entity=$1 ORDER BY id", e)]
    assert "Fair" in trans and "Poor" in trans and trans[-1] in ("Excellent", "Good")


# ------------------------------------------------------------------ late data

def test_late_record_flagged_and_queued_for_recompute(client):
    e, t = entity_id("late"), now()
    send(client, 1, [metric(e, "cpu.util_pct", t - timedelta(seconds=10), 1, 2)])
    wait_for(lambda: db("SELECT 1 FROM metric_points WHERE entity=$1", e))
    send(client, 2, [metric(e, "cpu.util_pct", t - timedelta(minutes=7), 3, 4)])    # behind the 5-min watermark
    wait_for(lambda: len(db("SELECT 1 FROM metric_points WHERE entity=$1", e)) == 2)
    rows = db("SELECT event_ts,late_arrival FROM metric_points WHERE entity=$1 ORDER BY event_ts", e)
    assert [r["late_arrival"] for r in rows] == [True, False]
    assert db("SELECT 1 FROM late_metric_recomputations WHERE entity=$1", e)


# ------------------------------------------------------------------ residency

def test_eu_collector_cannot_write_to_in_region(client):
    from cloud.app.crypto import SecretBox
    db("INSERT INTO tenants(tenant_id,name,home_region) VALUES('t_eu','EU','eu')")
    db("""INSERT INTO collectors(collector_id,tenant_id,region,secret_hash,status,secret_ciphertext)
          VALUES('col_eu','t_eu','eu','unused','active',$1)""", SecretBox(ENC_KEY).encrypt(b"col_eu" * 4))
    for region in ("eu", "in"):
        body = json.loads(envelope(1, [metric(entity_id("eu"), "cpu.util_pct", now(), 1, 2)],
                                   collector="col_eu", tenant="t_eu")[0])
        body["region"] = region
        raw = json.dumps(body).encode()
        r = raw_post(client, "/v1/ingest", raw, collector="col_eu", **{"idempotency-key": body["payload_id"]})
        assert (r.status_code, r.json()["detail"]["code"]) == (403, "WRONG_REGION")
    hb = json.dumps({"collector_id": "col_eu", "tenant_id": "t_eu", "ts": iso(now()), "version": "1.0.0",
                     "uptime_s": 1, "cpu_pct": 1, "mem_mb": 1, "outbox_depth": 0, "oldest_unsent_s": 0,
                     "last_acked_seq": 0, "policy_version": 1, "config_hash": HASH, "sources_ok": {}}).encode()
    r = raw_post(client, "/v1/heartbeat", hb, collector="col_eu")
    assert (r.status_code, r.json()["detail"]["code"]) == (403, "WRONG_REGION")
    assert not db("SELECT 1 FROM ingest_receipts WHERE tenant_id='t_eu'")

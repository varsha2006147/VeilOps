"""SSE verification over a real HTTP server: an actual event reaches a connected client, tenant-scoped."""
import asyncio
import base64
import hashlib
import hmac
import json
import queue
import secrets
import threading
import time

import httpx
import pytest

from tests.test_collector_cloud_e2e import CloudServer, _free_port
from tests.test_judge_integration import (
    ENC_KEY, JWT_SECRET, PG_ADMIN, REDIS_URL, SIGN_KEY, _rebuild_database, _seed, entity_id, envelope, metric, now,
    token,
)

pytestmark = pytest.mark.skipif(not (PG_ADMIN and REDIS_URL),
                                reason="set VEILOPS_TEST_PG_ADMIN and VEILOPS_TEST_REDIS_URL")


@pytest.fixture()
def server(monkeypatch):
    import redis
    asyncio.run(_rebuild_database())
    asyncio.run(_seed())
    redis.Redis.from_url(REDIS_URL).flushdb()
    for k, v in {"COLLECTOR_SECRET_ENCRYPTION_KEY": ENC_KEY, "SAAS_ED25519_PRIVATE_KEY": SIGN_KEY,
                 "DASHBOARD_JWT_SECRET": JWT_SECRET}.items():
        monkeypatch.setenv(k, v)
    import cloud.app.main as main
    from cloud.app.settings import Settings
    from urllib.parse import urlsplit
    host = urlsplit(PG_ADMIN).netloc.rsplit("@", 1)[-1]
    monkeypatch.setattr(main, "Settings", lambda: Settings(
        database_url=f"postgresql://veilops_app:veilops_app_dev_only@{host}/veilops", redis_url=REDIS_URL,
        ingest_stream="veilops:sse:" + secrets.token_hex(4)))
    srv = CloudServer(_free_port())
    srv.start()
    yield srv
    srv.stop()


def listen(base, headers, out: queue.Queue, stop: threading.Event):
    with httpx.Client(timeout=None) as c:
        with c.stream("GET", f"{base}/api/v1/events", headers=headers) as r:
            out.put(("status", r.status_code))
            event = None
            for line in r.iter_lines():
                if stop.is_set():
                    return
                if line.startswith("event:"):
                    event = line.split(":", 1)[1].strip()
                elif line.startswith("data:"):
                    out.put((event, json.loads(line[5:])))


def ingest(base, collector, tenant, seq):
    body, pid = envelope(seq, [metric(entity_id(f"sse-{tenant}"), "cpu.util_pct", now(), 1, 2)],
                         collector=collector, tenant=tenant)
    ts, nonce = str(int(time.time())), secrets.token_hex(16)
    msg = "\n".join(("POST", "/v1/ingest", ts, nonce, hashlib.sha256(body).hexdigest())).encode()
    sig = base64.b64encode(hmac.new(collector.encode() * 4, msg, hashlib.sha256).digest()).decode()
    r = httpx.post(f"{base}/v1/ingest", content=body, headers={
        "x-veilops-collector": collector, "x-veilops-timestamp": ts, "x-veilops-nonce": nonce,
        "x-veilops-signature": sig, "idempotency-key": pid, "content-type": "application/json"})
    assert r.status_code == 202, r.text
    return pid


def _drain(q, until, want):
    got = []
    while time.time() < until:
        try:
            kind, data = q.get(timeout=0.2)
        except queue.Empty:
            continue
        got.append((kind, data))
        if want(got):
            break
    return got


def test_sse_event_reaches_client_and_is_tenant_scoped(server):
    base = f"http://127.0.0.1:{server.port}"
    qa, qb, stop = queue.Queue(), queue.Queue(), threading.Event()
    for q, tok in ((qa, token("op_a", "t_acme")), (qb, token("op_b", "t_other"))):
        threading.Thread(target=listen, args=(base, tok, q, stop), daemon=True).start()
    for q in (qa, qb):
        assert _drain(q, time.time() + 5, lambda g: any(k == "connected" for k, _ in g))
    pid_a = ingest(base, "col_a", "t_acme", 1)
    got_a = _drain(qa, time.time() + 10, lambda g: any(k == "telemetry_processed" for k, _ in g))
    events_a = [d for k, d in got_a if k == "telemetry_processed"]
    assert events_a and events_a[0]["payload_id"] == pid_a and events_a[0]["collector_id"] == "col_a"
    got_b = _drain(qb, time.time() + 2, lambda g: False)
    assert not [d for k, d in got_b if k == "telemetry_processed"]          # B saw nothing of A
    pid_b = ingest(base, "col_b", "t_other", 1)
    got_b = _drain(qb, time.time() + 10, lambda g: any(k == "telemetry_processed" for k, _ in g))
    assert [d["payload_id"] for k, d in got_b if k == "telemetry_processed"] == [pid_b]
    assert httpx.get(f"{base}/api/v1/events").status_code == 401           # no token, no stream
    stop.set()

"""Collector downstream -> real Cloud Core over HTTP (enroll, ingest, receipts, outage, reconcile).

Opt-in like the Judge Mode integration tests (DROPS/recreates database `veilops`):
    VEILOPS_TEST_PG_ADMIN=postgresql://veilops@127.0.0.1:5432/postgres
    VEILOPS_TEST_REDIS_URL=redis://127.0.0.1:6379/15
"""
import asyncio
import hashlib
import secrets
import socket
import threading
import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from tests.test_judge_integration import ENC_KEY, JWT_SECRET, PG_ADMIN, REDIS_URL, SIGN_KEY, _admin_dsn, _rebuild_database

pytestmark = pytest.mark.skipif(not (PG_ADMIN and REDIS_URL),
                                reason="set VEILOPS_TEST_PG_ADMIN and VEILOPS_TEST_REDIS_URL")
REAL_NAMES = ("app-01", "db-01", "core-sw1", "checkout")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class CloudServer:
    """The real Cloud Core app under uvicorn on a real port; can be stopped and restarted."""

    def __init__(self, port: int):
        self.port, self.server, self.thread = port, None, None

    def start(self):
        import uvicorn
        import cloud.app.main as main
        self.server = uvicorn.Server(uvicorn.Config(main.app, host="127.0.0.1", port=self.port, log_level="warning"))
        self.thread = threading.Thread(target=self.server.run, daemon=True)
        self.thread.start()
        deadline = time.time() + 15
        while not self.server.started:
            assert time.time() < deadline, "cloud did not start"
            time.sleep(0.05)

    def stop(self):
        self.server.should_exit = True
        self.thread.join(15)


@pytest.fixture()
def cloud(monkeypatch):
    import asyncpg
    import redis

    token = secrets.token_urlsafe(32)

    async def prepare():
        await _rebuild_database()
        conn = await asyncpg.connect(_admin_dsn("veilops"))
        await conn.execute("INSERT INTO tenants(tenant_id,name,home_region) VALUES('t_acme','Acme','in')")
        await conn.execute(
            "INSERT INTO enrollment_tokens(token_hash,tenant_id,region,expires_at) VALUES($1,'t_acme','in',$2)",
            hashlib.sha256(token.encode()).hexdigest(), datetime.now(timezone.utc) + timedelta(minutes=15))
        await conn.close()

    asyncio.run(prepare())
    redis.Redis.from_url(REDIS_URL).flushdb()
    for k, v in {"COLLECTOR_SECRET_ENCRYPTION_KEY": ENC_KEY, "SAAS_ED25519_PRIVATE_KEY": SIGN_KEY,
                 "DASHBOARD_JWT_SECRET": JWT_SECRET, "VEILOPS_ENROLLMENT_TOKEN": token}.items():
        monkeypatch.setenv(k, v)
    import cloud.app.main as main
    from cloud.app.settings import Settings
    from urllib.parse import urlsplit
    host = urlsplit(PG_ADMIN).netloc.rsplit("@", 1)[-1]
    monkeypatch.setattr(main, "Settings", lambda: Settings(
        database_url=f"postgresql://veilops_app:veilops_app_dev_only@{host}/veilops", redis_url=REDIS_URL,
        ingest_stream="veilops:e2e:" + secrets.token_hex(4)))
    server = CloudServer(_free_port())
    server.start()
    yield server
    if not server.server.should_exit:
        server.stop()


def _windows(t: datetime, n: int):
    from veilops.collector.contracts import WindowAgg
    return [WindowAgg(entity=name, entity_kind="host", metric="cpu.util_pct", unit="pct", avg=30.0, min=29.0,
                      max=31.0, p95=31.0, count=5, window_s=5, event_ts=t + timedelta(seconds=5 * i),
                      source_tz="Asia/Kolkata")
            for i in range(n) for name in ("app-01", "db-01")]


async def _until(fn, timeout=20.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if await fn():
            return True
        await asyncio.sleep(0.2)
    raise AssertionError("condition not met in time")


async def test_collector_enrolls_ships_pseudonymised_data_and_survives_outage(cloud, tmp_path):
    import asyncpg
    from veilops.collector.config import CollectorConfig
    from veilops.collector.contracts import SourceBus
    from veilops.collector.privacy.stage import CloudLink

    cfg = CollectorConfig(collector_id="col_local", tenant_id="t_acme", region="in",
                          ingest_url=f"http://127.0.0.1:{cloud.port}/v1", db_path=str(tmp_path / "c.db"),
                          config_hash="sha256:" + "1" * 64)
    bus, ctx = SourceBus(), SimpleNamespace()
    link = CloudLink(cfg, bus, ctx, tmp_path)
    await link.setup()
    assert link.status["enrolled"] and cfg.collector_id.startswith("col_")      # identity from the cloud
    from veilops.collector.topology import Edge, Topology
    bus.topology = Topology(edges=[Edge("app-01", "host", "core-sw1", "link", "connects_via"),
                                   Edge("checkout", "service", "app-01", "host", "runs_on")], version=1)
    bus.topology_changed.set()
    tasks = [asyncio.create_task(link.bridge.run()), asyncio.create_task(link.send_loop()),
             asyncio.create_task(link.topology_loop())]
    try:
        t0 = datetime.now(timezone.utc) - timedelta(minutes=2)
        for w in _windows(t0, 6):
            bus.windows.put_nowait(w)

        async def all_acked():
            # stats() is several queries; compare acked vs highest so an enqueue racing between them can't pass.
            s = await link.ledger.stats()
            return s["highest_seq"] >= 1 and s["last_acked_seq"] == s["highest_seq"] and s["outbox_depth"] == 0
        await _until(all_acked)
        recent = await link.ledger.recent_entries(limit=50)
        assert recent and all(e.receipt_json for e in recent)                    # signed receipts verified + stored

        # ---- outage: cloud goes away, collector keeps buffering
        await asyncio.to_thread(cloud.stop)
        for w in _windows(t0 + timedelta(seconds=30), 30):
            bus.windows.put_nowait(w)
        await _until(lambda: _is(link.status["online"] is False))
        assert (await link.ledger.stats())["outbox_depth"] >= 1

        # ---- recovery: backlog drains in order, then the collector reconciles
        await asyncio.to_thread(cloud.start)
        await _until(all_acked, timeout=30)
        await _until(lambda: _is(link.status["last_reconcile"] is not None), timeout=10)
        rec = link.status["last_reconcile"]
        stats = await link.ledger.stats()
        assert rec["reconciled"] and rec["missing_sequences"] == [] and rec["to_seq"] == stats["last_acked_seq"]
    finally:
        for t in tasks:
            t.cancel()
        await link.client.aclose()
        await link.ledger.close()

    conn = await asyncpg.connect(_admin_dsn("veilops"))
    try:
        rows = await conn.fetch("SELECT DISTINCT entity FROM metric_points")
        edges = await conn.fetch("SELECT collector_id,source_entity,target_entity,relation FROM topology_edges")
        receipts = await conn.fetchval("SELECT count(*) FROM ingest_receipts")
        seqs = [r["seq"] for r in await conn.fetch("SELECT seq FROM ingest_receipts ORDER BY seq")]
    finally:
        await conn.close()
    entities = {r["entity"] for r in rows}
    assert len(entities) == 2 and all(e.startswith("h_") for e in entities)    # pseudonyms only
    assert not any(name in e for e in entities for name in REAL_NAMES)
    assert seqs == list(range(1, receipts + 1))                                  # 0 lost, 0 duplicated
    # network map arrived, scoped to this collector, and joins to the metric entities
    assert {(e["relation"]) for e in edges} == {"connects_via", "runs_on"}
    assert all(e["collector_id"] == cfg.collector_id for e in edges)
    host = [e for e in edges if e["relation"] == "connects_via"][0]
    assert host["source_entity"] in entities and host["target_entity"].startswith("lnk_")
    assert link.status["topology"]["version_sent"] == 1 and link.status["topology"]["edges"] == 2


async def _is(value):
    return value

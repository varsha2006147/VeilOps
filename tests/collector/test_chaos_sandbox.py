"""Member A: chaos forwarding (Docker mode), remediation sandbox, safe executor, extra streams."""
from __future__ import annotations

import functools

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from veilops.collector.remediation import SandboxExecutor
from veilops.sandbox.app import SandboxState, create_app


# ---------- chaos forwarding to the shared sim server ----------
def _fake_sim() -> tuple[FastAPI, list]:
    calls: list = []
    app = FastAPI()

    @app.post("/inject/{scenario}")
    async def inject(scenario: str, tenant: str, target: str | None = None):
        if scenario == "nope":
            from fastapi import HTTPException
            raise HTTPException(404, "choose from ...")
        calls.append((scenario, tenant, target))
        return [{"tenant": tenant, "scenario": scenario, "injected_at": "2026-11-20T10:00:00.000Z",
                 "target": target, "duration_s": 60}]

    @app.get("/injections")
    async def injections():
        return {"t_acme": [{"scenario": s} for s, t, _ in calls if t == "t_acme"], "t_globex": []}
    return app, calls


@pytest.fixture
def ui_remote(monkeypatch, tmp_path):
    from veilops.collector.config import CollectorConfig
    from veilops.collector.contracts import SourceBus
    from veilops.collector.pipeline.rawstore import RawStore
    from veilops.collector.pipeline.runner import Pipeline
    from veilops.collector.ui import app as ui_mod

    sim_app, calls = _fake_sim()
    monkeypatch.setenv("SIM_CONTROL_URL", "http://sim:9000")
    monkeypatch.setattr(ui_mod.httpx, "AsyncClient",
                        functools.partial(httpx.AsyncClient, transport=httpx.ASGITransport(app=sim_app),
                                          base_url="http://sim:9000"))
    cfg = CollectorConfig("col_blr_01", "t_acme", "in", "x", db_path=str(tmp_path / "c.db"), demo_mode=True)
    store = RawStore(cfg.db_path)
    ctx = ui_mod.UIContext(cfg, Pipeline(cfg, SourceBus(), store), store, sources={})
    app = ui_mod.create_app(ctx)
    with TestClient(app) as client:
        client.portal.call(store.open)
        yield client, calls
        client.portal.call(store.close)


def test_chaos_forwards_with_own_tenant_and_lists_injections(ui_remote):
    client, calls = ui_remote
    r = client.post("/local/chaos/failed_logins")
    assert r.status_code == 200 and calls == [("failed_logins", "t_acme", None)]
    listing = client.get("/local/chaos").json()
    assert listing["enabled"] and listing["mode"] == "remote" and listing["injections"] == [{"scenario": "failed_logins"}]
    assert client.post("/local/chaos/nope").status_code == 404


# ---------- sandbox ----------
@pytest.fixture
def sandbox():
    st = SandboxState()
    yield st, create_app(st)
    st.burner.stop()


def test_runaway_is_real_and_restart_fixes_it(sandbox):
    st, app = sandbox
    c = TestClient(app)
    assert c.get("/health").json()["runaway"] is False
    c.post("/chaos/runaway")
    h = c.get("/health").json()
    assert h["runaway"] and h["cpu_pct"] >= 60, h          # genuinely burning CPU
    dry = c.post("/actions/RESTART_SERVICE", params={"dry_run": "true"}).json()
    assert dry["dry_run"] and c.get("/health").json()["runaway"]   # dry-run changes nothing
    done = c.post("/actions/RESTART_SERVICE").json()
    assert done["health_after"] in ("excellent", "good") and not c.get("/health").json()["runaway"]
    assert c.post(f"/rollback/{done['action_id']}").json()["rolled_back"] and st.burner.running


def test_block_failover_rollback_and_validation(sandbox):
    _, app = sandbox
    c = TestClient(app)
    assert c.post("/actions/TEMP_BLOCK_SOURCE_15M").status_code == 422
    blk = c.post("/actions/TEMP_BLOCK_SOURCE_15M", params={"source": "203.0.113.50"}).json()
    assert c.get("/health").json()["blocked_sources"] == ["203.0.113.50"]
    c.post(f"/rollback/{blk['action_id']}")
    assert c.get("/health").json()["blocked_sources"] == []
    fo = c.post("/actions/FAILOVER_TO_SECONDARY_LINK").json()
    assert c.get("/health").json()["link"] == "secondary"
    c.post(f"/rollback/{fo['action_id']}")
    assert c.get("/health").json()["link"] == "primary"
    assert c.post("/actions/DELETE_EVERYTHING").status_code == 404
    assert c.post("/rollback/unknown").status_code == 404


def test_metrics_feed_maps_through_the_collector(sandbox):
    from veilops.collector.pipeline.normalize import normalize
    from veilops.collector.sources.stream import StreamMapper
    _, app = sandbox
    recs = TestClient(app).get("/metrics").json()
    m = StreamMapper({"tenant_filter": "t_acme"})
    samples = [s for r in recs for s in normalize(m.map(r, "{}"))]
    assert {s.metric for s in samples} == {"cpu.util_pct", "svc.up", "svc.resp_ms"}


# ---------- safe executor ----------
async def test_run_safe_restart_executes_and_verifies(sandbox):
    st, app = sandbox
    st.burner.start()
    ex = SandboxExecutor("http://sandbox", verify_timeout_s=5, poll_s=0.1, transport=httpx.ASGITransport(app=app))
    res = await ex.run_safe("RESTART_SERVICE")
    assert res["status"] == "executed" and res["health_before"] == "poor"
    assert res["health_after"] in ("excellent", "good")
    assert [s["step"] for s in res["steps"]] == ["snapshot", "dry_run", "execute", "verify"]
    from veilops.schema import ActionResult             # B's wire contract
    ActionResult.model_validate({k: res[k] for k in ("status", "local_policy_decision", "health_before",
                                                     "health_after", "ts")})


async def test_run_safe_veto_does_nothing(sandbox):
    st, app = sandbox
    st.burner.start()
    ex = SandboxExecutor("http://sandbox", transport=httpx.ASGITransport(app=app))
    res = await ex.run_safe("RESTART_SERVICE", local_policy_decision="veto")
    assert res["status"] == "vetoed" and st.burner.running


async def test_run_safe_rolls_back_when_health_does_not_improve(sandbox, monkeypatch):
    st, app = sandbox
    st.burner.start()
    monkeypatch.setattr("veilops.sandbox.app._apply", lambda *a, **k: None)   # a 'restart' that fixes nothing
    ex = SandboxExecutor("http://sandbox", verify_timeout_s=1, poll_s=0.2, transport=httpx.ASGITransport(app=app))
    res = await ex.run_safe("RESTART_SERVICE")
    assert res["status"] == "rolled_back" and res["steps"][-1]["step"] == "rollback"

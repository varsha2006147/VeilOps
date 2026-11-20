"""Local collector UI (port 8100, customer LAN only).

Member A: Overview, Raw (masked unless revealed + audited), Local signals, Windows, Chaos, Resolve hook.
Member B mounts the Egress Proof Panel router at /egress and sets ctx.resolver for pseudonym lookups.
"""
from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from ..timeutil import iso


class UIContext:
    def __init__(self, cfg, pipeline, store, sources: dict[str, Any]) -> None:
        self.cfg, self.pipeline, self.store, self.sources = cfg, pipeline, store, sources
        self.resolver: Callable[[str], dict | None] | None = None    # set by Member B


def _ser(obj) -> dict:
    d = asdict(obj)
    for k, v in d.items():
        if hasattr(v, "isoformat"):
            d[k] = iso(v)
    return d


def create_app(ctx: UIContext) -> FastAPI:
    app = FastAPI(title="VeilOps Collector (local)", docs_url="/local/docs")
    page = (Path(__file__).parent / "index.html").read_text()

    @app.get("/", response_class=HTMLResponse)
    async def index() -> str:
        return page

    @app.get("/local/status")
    async def status() -> dict:
        cfg = ctx.cfg
        return {"collector_id": cfg.collector_id, "tenant_id": cfg.tenant_id, "region": cfg.region,
                "environment": cfg.environment, "config_hash": cfg.config_hash, "demo_mode": cfg.demo_mode,
                "downstream": cfg.downstream,
                "sources": {n: {"ok": s.status.ok, "events": s.events, "detail": s.status.detail,
                                "last_event_ts": iso(s.status.last_event_ts) if s.status.last_event_ts else None}
                            for n, s in ctx.sources.items()},
                "pipeline": ctx.pipeline.snapshot(), "raw_rows": await ctx.store.count()}

    @app.get("/local/raw")
    async def raw(limit: int = 100, reveal: bool = False, source: str | None = None,
                  q: str | None = None) -> list[dict]:
        if reveal:
            await ctx.store.audit("local-admin", "raw.reveal", f"limit={limit} source={source} q={q}")
        return await ctx.store.recent(min(limit, 500), reveal, source or None, q or None)

    @app.get("/local/signals")
    async def signals(limit: int = 100) -> list[dict]:
        return [_ser(s) for s in list(ctx.pipeline.recent_signals)[-limit:]][::-1]

    @app.get("/local/windows")
    async def windows(limit: int = 100) -> list[dict]:
        return [_ser(w) for w in list(ctx.pipeline.recent_windows)[-limit:]][::-1]

    @app.get("/local/chaos")
    async def chaos_list() -> dict:
        from veilops.sim import SCENARIOS
        sim = ctx.sources.get("sim")
        return {"enabled": bool(ctx.cfg.demo_mode and sim), "scenarios": list(SCENARIOS),
                "injections": sim.sim.injections if sim else []}

    @app.post("/local/chaos/{scenario}")
    async def chaos(scenario: str, target: str | None = None) -> dict:
        sim = ctx.sources.get("sim")
        if not ctx.cfg.demo_mode or sim is None:
            raise HTTPException(403, "chaos disabled (set DEMO_MODE=1 and enable the sim source)")
        try:
            rec = sim.inject(scenario, target)
        except ValueError as e:
            raise HTTPException(404, str(e)) from e
        await ctx.store.audit("local-admin", "chaos.inject", f"{scenario} target={target}")
        return rec

    @app.get("/local/resolve/{pseudo}")
    async def resolve(pseudo: str) -> dict:
        if ctx.resolver is None:
            raise HTTPException(501, "pseudonym resolver not wired yet (Member B)")
        hit = ctx.resolver(pseudo)
        await ctx.store.audit("local-admin", "pseudonym.resolve", pseudo)
        if not hit:
            raise HTTPException(404, "unknown pseudonym")
        return hit

    return app

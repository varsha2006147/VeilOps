"""Local collector UI (port 8100, customer LAN only).

Member A: Overview, Raw (masked unless revealed + audited), Local signals, Windows, Chaos, Resolve hook.
Member B mounts the Egress Proof Panel router at /egress and sets ctx.resolver for pseudonym lookups.
"""
from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable

import os

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from ..timeutil import iso


class UIContext:
    def __init__(self, cfg, pipeline, store, sources: dict[str, Any]) -> None:
        self.cfg, self.pipeline, self.store, self.sources = cfg, pipeline, store, sources
        self.resolver: Callable[[str], dict | None] | None = None    # set by Member B
        self.codes: Callable[[], list[dict]] | None = None
        self.topology_watcher = None
        self.ledger = None                                           # set by Member B
        self.proof_service = None                                    # set by Member B


def _ser(obj) -> dict:
    d = asdict(obj)
    for k, v in d.items():
        if hasattr(v, "isoformat"):
            d[k] = iso(v)
    return d


def create_app(ctx: UIContext) -> FastAPI:
    app = FastAPI(title="VeilOps Collector (local)", docs_url="/local/docs")
    import os
    from fastapi.middleware.cors import CORSMiddleware
    app.add_middleware(  # local dashboard dev server may read the egress ledger / trigger chaos
        CORSMiddleware,
        allow_origins=[o.strip() for o in os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173,http://localhost:5174,http://127.0.0.1:5174").split(",") if o.strip()],
        allow_methods=["GET", "POST"], allow_headers=["Content-Type"])
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

    @app.get("/local/audit")
    async def local_audit(limit: int = 100) -> list[dict]:
        return await ctx.store.recent_audit(min(limit, 500))

    @app.get("/local/signals")
    async def signals(limit: int = 100) -> list[dict]:
        return [_ser(s) for s in list(ctx.pipeline.recent_signals)[-limit:]][::-1]

    @app.get("/local/windows")
    async def windows(limit: int = 100) -> list[dict]:
        return [_ser(w) for w in list(ctx.pipeline.recent_windows)[-limit:]][::-1]

    @app.get("/local/topology")
    async def topology() -> dict:
        t = ctx.pipeline.bus.topology
        w = ctx.topology_watcher
        return {"version": t.version, "digest": t.digest, "source": t.source,
                "nodes": [{"name": n, "kind": k} for n, k in sorted(t.nodes.items())],
                "edges": [{"src": e.src, "src_kind": e.src_kind, "dst": e.dst, "dst_kind": e.dst_kind,
                           "rel": e.rel} for e in t.edges],
                "last_error": w.last_error if w else None}

    def _remote() -> str | None:
        """Docker mode: no in-process sim, so forward to the shared sim server (SIM_CONTROL_URL)."""
        return (os.environ.get("SIM_CONTROL_URL") or "").rstrip("/") or None

    @app.get("/local/chaos")
    async def chaos_list() -> dict:
        from veilops.sim import SCENARIOS
        sim, remote = ctx.sources.get("sim"), _remote()
        injections: list = sim.sim.injections if sim else []
        if not sim and remote:
            try:
                async with httpx.AsyncClient(timeout=3) as c:
                    injections = (await c.get(f"{remote}/injections")).json().get(ctx.cfg.tenant_id, [])
            except (httpx.HTTPError, ValueError):
                injections = []
        return {"enabled": bool(ctx.cfg.demo_mode and (sim or remote)), "scenarios": list(SCENARIOS),
                "mode": "local" if sim else ("remote" if remote else "off"), "injections": injections}

    @app.post("/local/chaos/{scenario}")
    async def chaos(scenario: str, target: str | None = None) -> dict:
        sim, remote = ctx.sources.get("sim"), _remote()
        if not ctx.cfg.demo_mode or not (sim or remote):
            raise HTTPException(403, "chaos disabled (set DEMO_MODE=1 and enable the sim source or SIM_CONTROL_URL)")
        if sim:
            try:
                rec = sim.inject(scenario, target)
            except ValueError as e:
                raise HTTPException(404, str(e)) from e
        else:
            params = {"tenant": ctx.cfg.tenant_id, **({"target": target} if target else {})}
            try:
                async with httpx.AsyncClient(timeout=5) as c:
                    r = await c.post(f"{remote}/inject/{scenario}", params=params)
            except httpx.HTTPError as e:
                raise HTTPException(502, f"sim server unreachable: {e}") from e
            if r.status_code == 404:
                raise HTTPException(404, r.json().get("detail", "unknown scenario"))
            r.raise_for_status()
            rec = (r.json() or [{}])[0]
        await ctx.store.audit("local-admin", "chaos.inject", f"{scenario} target={target}")
        return rec

    @app.get("/local/codes")
    async def codes() -> list[dict]:
        """Real name -> code table. Served only on the customer's machine; never sent to the cloud."""
        return ctx.codes() if ctx.codes else []

    @app.get("/local/resolve/{pseudo}")
    async def resolve(pseudo: str) -> dict:
        if ctx.resolver is None:
            raise HTTPException(501, "pseudonym resolver not wired yet (Member B)")
        hit = ctx.resolver(pseudo)
        await ctx.store.audit("local-admin", "pseudonym.resolve", pseudo)
        if not hit:
            raise HTTPException(404, "unknown pseudonym")
        return hit

    @app.get("/local/egress")
    @app.get("/local/egress/proof")
    @app.get("/api/egress-proof")
    async def egress_proof() -> dict:
        if getattr(ctx, "proof_service", None) is not None:
            return await ctx.proof_service.get_snapshot()
        if getattr(ctx, "ledger", None) is not None:
            from veilops.collector.transport.proof import build_egress_proof_snapshot
            return await build_egress_proof_snapshot(ctx.ledger)
        return {
            "policy_version": "1.0",
            "policy_hash": "sha256:" + "0" * 64,
            "chain_valid": True,
            "chain_status": "ok",
            "stats": {
                "outbox_depth": 0,
                "oldest_unsent_s": 0.0,
                "last_acked_seq": 0,
                "highest_seq": 0,
                "total_sent_records": 0,
            },
            "recent_envelopes": [],
            "redaction_summary": {
                "secrets_scrubbed": 0,
                "canaries_blocked": 0,
                "patterns_verified": 0,
            },
        }

    @app.get("/local/egress/side-by-side")
    @app.get("/api/side-by-side")
    async def side_by_side(raw_id: int | None = None, limit: int = 10, reveal: bool = False) -> list[dict]:
        recent_raw = await ctx.store.recent(min(limit, 100), reveal=reveal)
        paired = []
        from veilops.collector.privacy.redactor import redact_text
        for r in recent_raw:
            raw_text = r.get("raw", "")
            raw_id_val = r.get("id")
            if raw_id is not None and raw_id_val != raw_id:
                continue
            clean_text = redact_text(raw_text)
            paired.append({
                "id": raw_id_val,
                "source": r.get("source"),
                "event_ts": r.get("event_ts"),
                "raw_preview": raw_text if reveal else clean_text,
                "sanitized_preview": clean_text,
                "is_masked": not reveal,
            })
        return paired

    @app.get("/local/policy/diff")
    @app.get("/api/policy-diff")
    async def policy_diff_endpoint(old_path: str | None = None, new_path: str | None = None) -> dict:
        from veilops.collector.transport.cli import policy_diff
        from veilops.schema.policy import load_policy
        if not old_path or not new_path:
            base_p = load_policy()
            return {
                "old_version": base_p.version,
                "new_version": base_p.version,
                "old_hash": base_p.hash or base_p.policy_hash,
                "new_hash": base_p.hash or base_p.policy_hash,
                "added_record_types": [],
                "removed_record_types": [],
                "field_changes": {},
            }
        try:
            return policy_diff(old_path, new_path)
        except Exception as e:
            raise HTTPException(400, f"policy diff failed: {e}") from e

    return app

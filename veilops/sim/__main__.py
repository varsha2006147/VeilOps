"""veilops-sim CLI.

  python -m veilops.sim stdout                       # JSONL to stdout, 1 tick/s
  python -m veilops.sim file data/stream.jsonl       # append JSONL (collector driver: file)
  python -m veilops.sim serve --port 9000            # SSE at /stream, POST /inject/<scenario>
  python -m veilops.sim dump out.jsonl --seconds 600 # fast offline dump for replay/tests

Multiple tenants share one stream (like the organizer feed): --tenants t_acme,t_globex
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import datetime, timedelta, timezone

from .generator import SCENARIOS, Simulator


def build(tenants: str, seed: int) -> dict[str, Simulator]:
    envs = {"t_acme": ("blr-dc1", "Asia/Kolkata"), "t_globex": ("fra-dc1", "Europe/Berlin")}
    sims = {}
    for i, t in enumerate(tenants.split(",")):
        env, tz = envs.get(t, (f"{t}-env", "UTC"))
        sims[t] = Simulator(t, env, tz, seed=seed + i)
    return sims


async def loop_out(sims: dict[str, Simulator], write) -> None:
    while True:
        now = datetime.now(timezone.utc)
        for s in sims.values():
            for r in s.tick(now):
                write(json.dumps(r))
        await asyncio.sleep(1.0)


def serve(sims: dict[str, Simulator], port: int) -> None:
    import uvicorn
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import StreamingResponse

    from contextlib import asynccontextmanager

    subscribers: set[asyncio.Queue] = set()

    @asynccontextmanager
    async def lifespan(_app):
        async def pump() -> None:
            while True:
                now = datetime.now(timezone.utc)
                batch = [r for s in sims.values() for r in s.tick(now)]
                for q in list(subscribers):
                    for r in batch:
                        if not q.full():
                            q.put_nowait(r)
                await asyncio.sleep(1.0)
        task = asyncio.create_task(pump())
        yield
        task.cancel()

    app = FastAPI(title="veilops-sim", lifespan=lifespan)

    @app.get("/stream")
    async def stream():
        q: asyncio.Queue = asyncio.Queue(20_000)
        subscribers.add(q)

        async def gen():
            try:
                while True:
                    r = await q.get()
                    yield f"data: {json.dumps(r)}\n\n"
            finally:
                subscribers.discard(q)
        return StreamingResponse(gen(), media_type="text/event-stream")

    @app.post("/inject/{scenario}")
    async def inject(scenario: str, tenant: str | None = None, target: str | None = None,
                     duration_s: float | None = None):
        if scenario not in SCENARIOS:
            raise HTTPException(404, f"choose from {SCENARIOS}")
        out = []
        for t, s in sims.items():
            if tenant in (None, t):
                out.append({"tenant": t, **s.inject(scenario, target=target, duration_s=duration_s)})
        return out

    @app.get("/injections")
    async def injections():
        return {t: s.injections for t, s in sims.items()}

    uvicorn.run(app, host="0.0.0.0", port=port, log_level="warning")


def main() -> None:
    p = argparse.ArgumentParser(prog="veilops-sim")
    p.add_argument("mode", choices=["stdout", "file", "serve", "dump"])
    p.add_argument("path", nargs="?")
    p.add_argument("--port", type=int, default=9000)
    p.add_argument("--tenants", default="t_acme,t_globex")
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--seconds", type=int, default=300)
    p.add_argument("--inject", action="append", default=[], help="dump mode: scenario@second, e.g. cpu_drift@120")
    a = p.parse_args()
    sims = build(a.tenants, a.seed)
    if a.mode == "serve":
        serve(sims, a.port)
    elif a.mode == "dump":
        start = datetime.now(timezone.utc) - timedelta(seconds=a.seconds)
        plan = {int(x.split("@")[1]): x.split("@")[0] for x in a.inject}
        with open(a.path or "stream.jsonl", "w") as fh:
            for i in range(a.seconds):
                now = start + timedelta(seconds=i)
                for s in sims.values():
                    if i in plan:
                        s.inject(plan[i], now=now)
                    for r in s.tick(now):
                        fh.write(json.dumps(r) + "\n")
    elif a.mode == "file":
        fh = open(a.path or "data/stream.jsonl", "a", buffering=1)
        asyncio.run(loop_out(sims, lambda s: fh.write(s + "\n")))
    else:
        asyncio.run(loop_out(sims, lambda s: (sys.stdout.write(s + "\n"), sys.stdout.flush())))


if __name__ == "__main__":
    main()

"""In-process simulator source: lets the collector's Chaos tab inject the guide's scenarios live."""
from __future__ import annotations

import asyncio
import json

from ..contracts import utcnow
from .base import Emit, Source
from .stream import StreamMapper


class SimSource(Source):
    name = "sim"

    def __init__(self, spec: dict, tenant: str, source_tz: str, mapper: StreamMapper) -> None:
        super().__init__()
        from veilops.sim import Simulator  # optional package (pip install -e sim)
        self.sim = Simulator(tenant=tenant, env=spec.get("env", "blr-dc1"), tz=source_tz,
                             seed=int(spec.get("seed", 7)))
        self.mapper = mapper
        self.interval = float(spec.get("interval_s", 1))

    def inject(self, scenario: str, target: str | None = None) -> dict:
        return self.sim.inject(scenario, target=target)

    async def run(self, emit: Emit) -> None:
        while True:
            for rec in self.sim.tick(utcnow()):
                ev = self.mapper.map(rec, json.dumps(rec))
                if ev is not None:
                    ev.source = "sim"
                    await emit(ev)
            await asyncio.sleep(self.interval)

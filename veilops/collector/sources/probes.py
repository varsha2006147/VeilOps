"""Network probes: latency, packet loss, reachability per target (entity kind = link).

Uses unprivileged ICMP (icmplib) when the OS allows it, else falls back to TCP-connect timing so the
demo works on any laptop without root.
"""
from __future__ import annotations

import asyncio
import json
import time

from ..contracts import RawEvent, utcnow
from .base import Emit, Source


async def tcp_probe(host: str, port: int, count: int, timeout: float) -> tuple[float | None, float]:
    rtts: list[float] = []
    for _ in range(count):
        t0 = time.perf_counter()
        try:
            _, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
            rtts.append((time.perf_counter() - t0) * 1000)
            w.close()
        except (OSError, asyncio.TimeoutError):
            pass
    loss = 100.0 * (count - len(rtts)) / count
    return (sum(rtts) / len(rtts) if rtts else None), loss


async def icmp_probe(host: str, count: int, timeout: float) -> tuple[float | None, float]:
    from icmplib import async_ping
    r = await async_ping(host, count=count, interval=0.2, timeout=timeout, privileged=False)
    return (r.avg_rtt if r.is_alive else None), r.packet_loss * 100.0


class ProbeSource(Source):
    name = "probes"

    def __init__(self, spec: dict, source_tz: str) -> None:
        super().__init__()
        self.targets = spec.get("targets", [])      # [{name, host, port?}]
        self.interval = float(spec.get("interval_s", 2))
        self.count = int(spec.get("count", 5))
        self.timeout = float(spec.get("timeout_s", 1))
        self.mode = spec.get("mode", "auto")         # auto | icmp | tcp
        self.tz = source_tz

    async def _one(self, t: dict) -> tuple[float | None, float]:
        if self.mode in ("auto", "icmp"):
            try:
                return await icmp_probe(t["host"], self.count, self.timeout)
            except Exception:  # noqa: BLE001 - no ICMP permission -> tcp fallback
                if self.mode == "icmp":
                    raise
                self.mode = "tcp"
        return await tcp_probe(t["host"], int(t.get("port", 443)), self.count, self.timeout)

    async def run(self, emit: Emit) -> None:
        while True:
            results = await asyncio.gather(*(self._one(t) for t in self.targets), return_exceptions=True)
            ts = utcnow()
            for t, res in zip(self.targets, results):
                if isinstance(res, BaseException):
                    rtt, loss = None, 100.0
                else:
                    rtt, loss = res
                name = t.get("name", t["host"])
                vals = {"net.loss_pct": round(loss, 2), "net.reachable": 0.0 if rtt is None else 1.0}
                if rtt is not None:
                    vals["net.latency_ms"] = round(rtt, 2)
                items = [{"kind": "metric", "entity": name, "entity_kind": "link", "metric": k, "value": v}
                         for k, v in vals.items()]
                await emit(RawEvent("probe", ts, self.tz,
                                    json.dumps({"target": name, "host": t["host"], "mode": self.mode, **vals}),
                                    {"kind": "multi", "items": items}))
            await asyncio.sleep(self.interval)

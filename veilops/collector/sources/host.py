"""Real host metrics via psutil (proves the collector is real, alongside the organizer stream)."""
from __future__ import annotations

import asyncio
import json
import socket
import time

import psutil

from ..contracts import RawEvent, utcnow
from .base import Emit, Source


class HostSource(Source):
    name = "host"

    def __init__(self, spec: dict, source_tz: str) -> None:
        super().__init__()
        self.interval = float(spec.get("interval_s", 1))
        self.entity = spec.get("entity") or socket.gethostname()
        self.disk_path = spec.get("disk_path", "/")
        self.tz = source_tz

    async def run(self, emit: Emit) -> None:
        psutil.cpu_percent(None)
        last = psutil.net_io_counters()
        last_t = time.monotonic()
        while True:
            await asyncio.sleep(self.interval)
            now_t = time.monotonic()
            net = psutil.net_io_counters()
            dt = max(1e-3, now_t - last_t)
            vals = {
                "cpu.util_pct": psutil.cpu_percent(None),
                "mem.util_pct": psutil.virtual_memory().percent,
                "disk.util_pct": psutil.disk_usage(self.disk_path).percent,
                "net.bw_in_mbps": round((net.bytes_recv - last.bytes_recv) * 8 / dt / 1e6, 4),
                "net.bw_out_mbps": round((net.bytes_sent - last.bytes_sent) * 8 / dt / 1e6, 4),
            }
            last, last_t = net, now_t
            ts = utcnow()
            items = [{"kind": "metric", "entity": self.entity, "entity_kind": "host", "metric": k, "value": v}
                     for k, v in vals.items()]
            await emit(RawEvent("host", ts, self.tz, json.dumps({"host": self.entity, **vals}),
                                {"kind": "multi", "items": items}))

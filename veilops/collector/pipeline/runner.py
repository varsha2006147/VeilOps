"""Wires collector stages 1-6 (Member A) and hands WindowAgg / LocalSignal to Member B via SourceBus."""
from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from dataclasses import dataclass, field

from ..config import CollectorConfig
from ..contracts import AuthEvent, LocalSignal, LogEvent, MetricSample, RawEvent, SourceBus, WindowAgg, utcnow
from .aggregate import Aggregator
from .detect import AuthDetector, LogCategoryDetector, ThresholdDetector
from .normalize import normalize
from .rawstore import RawStore

log = logging.getLogger("veilops.pipeline")


@dataclass
class Stats:
    raw_in: int = 0
    samples: int = 0
    auth_events: int = 0
    log_events: int = 0
    windows_out: int = 0
    late_windows: int = 0
    signals_out: int = 0
    bus_drops: int = 0
    ingest_lag_ms: deque = field(default_factory=lambda: deque(maxlen=2000))   # arrival - event_ts

    def lag_p95(self) -> float | None:
        if not self.ingest_lag_ms:
            return None
        s = sorted(self.ingest_lag_ms)
        return s[int(0.95 * (len(s) - 1))]


class Pipeline:
    def __init__(self, cfg: CollectorConfig, bus: SourceBus, store: RawStore) -> None:
        self.cfg, self.bus, self.store = cfg, bus, store
        self.agg = Aggregator(cfg.window_s, grace_s=1.0, lateness_s=cfg.allowed_lateness_s)
        self.thr = ThresholdDetector(cfg.thresholds)
        self.auth = AuthDetector(cfg.auth)
        self.logs = LogCategoryDetector()
        self.stats = Stats()
        self.recent_windows: deque[WindowAgg] = deque(maxlen=300)
        self.recent_signals: deque[LocalSignal] = deque(maxlen=300)
        self._dirty = False

    async def ingest(self, ev: RawEvent) -> None:
        self.stats.raw_in += 1
        self.stats.ingest_lag_ms.append((ev.received_at - ev.event_ts).total_seconds() * 1000)
        raw_id = await self.store.insert(ev)
        self._dirty = True
        for item in normalize(ev, raw_id):
            if isinstance(item, MetricSample):
                self.stats.samples += 1
                for sig in self.thr.observe(item):
                    self._signal(sig)
                for w in self.agg.add(item):          # late sample -> merged window re-emitted now
                    self.stats.late_windows += 1
                    self._window(w)
            elif isinstance(item, AuthEvent):
                self.stats.auth_events += 1
                for sig in self.auth.observe(item):
                    self._signal(sig)
            elif isinstance(item, LogEvent):
                self.stats.log_events += 1
                for sig in self.logs.observe(item):
                    self._signal(sig)

    def _put(self, q: asyncio.Queue, obj) -> None:
        try:
            q.put_nowait(obj)
        except asyncio.QueueFull:
            self.stats.bus_drops += 1

    def _window(self, w: WindowAgg) -> None:
        self.stats.windows_out += 1
        self.recent_windows.append(w)
        self._put(self.bus.windows, w)

    def _signal(self, s: LocalSignal) -> None:
        self.stats.signals_out += 1
        self.recent_signals.append(s)
        self._put(self.bus.signals, s)           # priority signals are never batched here
        log.info("signal %s %s %s %s", s.rule, s.severity, s.entity, s.params)

    async def flusher(self) -> None:
        while True:
            await asyncio.sleep(0.5)
            for w in self.agg.flush():
                self._window(w)
            if self._dirty:
                await self.store.commit()
                self._dirty = False

    async def janitor(self) -> None:
        while True:
            await asyncio.sleep(3600)
            n = await self.store.purge(self.cfg.raw_retention_h)
            await self.store.audit("system", "raw.purge", f"deleted {n} rows older than {self.cfg.raw_retention_h} h")

    async def drain_without_downstream(self) -> None:
        """Until Member B's privacy stage is wired in, keep the bus from filling up."""
        while True:
            await asyncio.sleep(1)
            for q in (self.bus.windows, self.bus.signals):
                while not q.empty():
                    q.get_nowait()

    def snapshot(self) -> dict:
        s = self.stats
        return {"raw_in": s.raw_in, "samples": s.samples, "auth_events": s.auth_events,
                "log_events": s.log_events, "windows_out": s.windows_out, "late_windows": s.late_windows,
                "signals_out": s.signals_out, "bus_drops": s.bus_drops,
                "ingest_lag_p95_ms": s.lag_p95(), "open_windows": len(self.agg.open),
                "late_samples": self.agg.late_count, "too_late_samples": self.agg.too_late_count,
                "bus_windows_depth": self.bus.windows.qsize(), "bus_signals_depth": self.bus.signals.qsize(),
                "ts": utcnow().isoformat(), "uptime_s": int(time.monotonic() - _START)}


_START = time.monotonic()

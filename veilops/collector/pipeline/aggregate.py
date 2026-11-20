"""Stage 5: event-time tumbling windows per (entity, metric).

* Windows are keyed by floor(event_ts) - placement is by EVENT time, never arrival time.
* A window closes when the watermark (max event_ts seen - grace) passes its end, or when it has not
  been updated for window_s + grace of wall time (a silent source must not hold windows open).
* A late sample for an already-closed window (within allowed lateness) re-emits the merged window with
  the same event_ts and a larger count. Cloud upserts on (tenant, entity, metric, event_ts) keeping the
  row with the larger count, so re-delivery is idempotent and trends are never corrupted.
"""
from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from ..contracts import MetricSample, WindowAgg
from ..timeutil import floor_ts


def p95(values: list[float]) -> float:
    s = sorted(values)
    return s[max(0, math.ceil(0.95 * len(s)) - 1)]


@dataclass
class _Win:
    entity: str
    entity_kind: str
    metric: str
    unit: str
    start: datetime
    source_tz: str
    values: list[float] = field(default_factory=list)
    last_update_wall: float = field(default_factory=time.monotonic)

    def agg(self, window_s: int) -> WindowAgg:
        v = self.values
        return WindowAgg(self.entity, self.entity_kind, self.metric, self.unit,  # type: ignore[arg-type]
                         round(sum(v) / len(v), 4), min(v), max(v), p95(v), len(v),
                         window_s, self.start, self.source_tz)


class Aggregator:
    def __init__(self, window_s: int = 5, grace_s: float = 1.0, lateness_s: int = 300) -> None:
        self.window_s = window_s
        self.grace = timedelta(seconds=grace_s)
        self.grace_s = grace_s
        self.lateness = timedelta(seconds=lateness_s)
        self.open: dict[tuple[str, str, datetime], _Win] = {}
        self.closed: dict[tuple[str, str, datetime], _Win] = {}
        self.max_seen: datetime | None = None
        self.late_count = 0
        self.too_late_count = 0

    def add(self, s: MetricSample) -> list[WindowAgg]:
        start = floor_ts(s.event_ts, self.window_s)
        key = (s.entity, s.metric, start)
        if self.max_seen is None or s.event_ts > self.max_seen:
            self.max_seen = s.event_ts
        if key in self.closed:                       # late, but within allowed lateness
            w = self.closed[key]
            w.values.append(s.value)
            self.late_count += 1
            return [w.agg(self.window_s)]
        w = self.open.get(key)
        if w is None:
            if self.max_seen and start + timedelta(seconds=self.window_s) < self.max_seen - self.lateness:
                # beyond allowed lateness: still delivered once, as its own window, never silently dropped
                self.too_late_count += 1
                lone = _Win(s.entity, s.entity_kind, s.metric, s.unit, start, s.source_tz, [s.value])
                return [lone.agg(self.window_s)]
            w = self.open[key] = _Win(s.entity, s.entity_kind, s.metric, s.unit, start, s.source_tz)
        w.values.append(s.value)
        w.last_update_wall = time.monotonic()
        return []

    def flush(self, force: bool = False) -> list[WindowAgg]:
        out: list[WindowAgg] = []
        now_wall = time.monotonic()
        wm = (self.max_seen - self.grace) if self.max_seen else None
        span = timedelta(seconds=self.window_s)
        for key, w in list(self.open.items()):
            end = w.start + span
            if force or (wm is not None and end <= wm) or \
                    (now_wall - w.last_update_wall) > self.window_s + self.grace_s:
                out.append(w.agg(self.window_s))
                self.closed[key] = self.open.pop(key)
        if self.max_seen:
            horizon = self.max_seen - self.lateness
            for key in [k for k, w in self.closed.items() if w.start + span < horizon]:
                del self.closed[key]
        out.sort(key=lambda a: a.event_ts)
        return out

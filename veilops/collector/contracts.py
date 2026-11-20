"""Internal collector contract between Member A (sources/pipeline) and Member B (privacy/transport).

Objects here still carry REAL identifiers (hostnames, usernames, IPs). They must never be serialized to
the network directly; Member B's privacy stage pseudonymizes them and builds wire records from policy.yaml.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

EntityKind = Literal["host", "service", "link"]
Severity = Literal["info", "warning", "high", "critical"]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(slots=True)
class RawEvent:
    """Exactly what a source produced. Lives only in the local raw store."""
    source: str                    # "stream" | "host" | "probe" | "syslog" | "sim"
    event_ts: datetime             # UTC, from the source (NOT arrival time)
    source_tz: str                 # IANA zone of the source
    raw: str                       # original line / JSON text
    fields: dict[str, Any] = field(default_factory=dict)
    received_at: datetime = field(default_factory=utcnow)


@dataclass(slots=True)
class MetricSample:
    """One normalized numeric observation (real entity name)."""
    entity: str
    entity_kind: EntityKind
    metric: str                    # canonical name, e.g. cpu.util_pct
    unit: str
    value: float
    event_ts: datetime
    source_tz: str
    raw_id: int | None = None      # row id in raw_events, for local evidence


@dataclass(slots=True)
class AuthEvent:
    """One normalized authentication event (real principal / source)."""
    outcome: Literal["failure", "success"]
    principal: str
    source_addr: str
    target_entity: str
    event_ts: datetime
    source_tz: str
    raw_id: int | None = None


@dataclass(slots=True)
class LogEvent:
    """A non-auth log line reduced to a category. The message text stays local."""
    entity: str
    category: str                  # e.g. db.connect_error
    level: str
    event_ts: datetime
    source_tz: str
    raw_id: int | None = None


@dataclass(slots=True)
class WindowAgg:
    """5 s tumbling-window aggregate per (entity, metric). A -> B."""
    entity: str
    entity_kind: EntityKind
    metric: str
    unit: str
    avg: float
    min: float
    max: float
    p95: float
    count: int
    window_s: int
    event_ts: datetime             # window start, UTC
    source_tz: str


@dataclass(slots=True)
class LocalSignal:
    """Locally detected condition. A -> B. `priority=True` must skip batching (breach -> alert < 15 s)."""
    kind: Literal["threshold", "security", "log_category"]
    rule: str                      # e.g. threshold.cpu.high, auth.bruteforce
    severity: Severity
    entity: str
    event_ts: datetime
    source_tz: str
    params: dict[str, float | int] = field(default_factory=dict)
    subjects: list[str] = field(default_factory=list)   # real principals (security only)
    sources: list[str] = field(default_factory=list)    # real source addresses (security only)
    risk_score: int = 0
    window_s: int = 0
    priority: bool = False
    raw_ids: list[int] = field(default_factory=list)


@dataclass(slots=True)
class SourceStatus:
    name: str
    ok: bool
    last_event_ts: datetime | None = None
    detail: str = ""


class SourceBus:
    """Queues that connect A's pipeline to B's privacy stage."""

    def __init__(self, maxsize: int = 10_000) -> None:
        self.windows: asyncio.Queue[WindowAgg] = asyncio.Queue(maxsize)
        self.signals: asyncio.Queue[LocalSignal] = asyncio.Queue(maxsize)
        self.status: dict[str, SourceStatus] = {}
        # Dependency graph with REAL names (A loads it; B pseudonymizes and sends a `topology` record).
        # B: wait on `topology_changed`, clear it, then send `self.topology` (version bumps on every change).
        from .topology import Topology
        self.topology: Topology = Topology()
        self.topology_changed: asyncio.Event = asyncio.Event()

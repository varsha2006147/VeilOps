"""Stage 6: local detection on raw samples (fast path) - runs BEFORE aggregation.

ThresholdDetector  - static guardrails with persistence (3 of last 5) and hysteresis; one alert per
                     episode plus a resolve. Breach alerts are priority=True (target: breach -> alert < 15 s).
AuthDetector       - brute force, password spray, credential stuffing over a sliding event-time window.
                     Only counts + identities (pseudonymized later by B) leave; raw auth lines never do.
LogCategoryDetector- error categories per entity (message text stays local).
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from ..config import AuthRules, Thresholds
from ..contracts import AuthEvent, LocalSignal, LogEvent, MetricSample

_SHORT = {"cpu.util_pct": "cpu.high", "mem.util_pct": "mem.high", "disk.util_pct": "disk.high",
          "net.loss_pct": "loss.high", "net.latency_ms": "latency.high", "svc.up": "svc.down",
          "net.reachable": "net.unreachable"}


@dataclass
class _TState:
    window: deque = field(default_factory=lambda: deque(maxlen=5))
    fired: bool = False
    healthy_streak: int = 0
    peak: float = 0.0


class ThresholdDetector:
    def __init__(self, cfg: Thresholds) -> None:
        self.cfg = cfg
        self.state: dict[tuple[str, str], _TState] = defaultdict(lambda: _TState(deque(maxlen=cfg.of_last)))

    def observe(self, s: MetricSample) -> list[LocalSignal]:
        rule = self.cfg.rules.get(s.metric)
        if not rule:
            return []
        limit = float(rule["limit"])
        below = bool(rule.get("below"))
        breach = s.value < limit if below else s.value >= limit
        if below:
            healthy = not breach
        else:
            healthy = s.value < limit * (1 - self.cfg.hysteresis_pct / 100)
        st = self.state[(s.entity, s.metric)]
        st.window.append(breach)
        name = f"threshold.{_SHORT.get(s.metric, s.metric)}"
        if breach:
            if not st.fired:
                st.peak = s.value
            else:
                st.peak = min(st.peak, s.value) if below else max(st.peak, s.value)
        if not st.fired and sum(st.window) >= self.cfg.persistence:
            st.fired, st.healthy_streak = True, 0
            return [LocalSignal("threshold", name, rule.get("severity", "warning"), s.entity, s.event_ts,
                                s.source_tz, params={"value": round(s.value, 3), "threshold": limit,
                                                     "breaching": int(sum(st.window)),
                                                     "of": self.cfg.of_last},
                                priority=True, raw_ids=[s.raw_id] if s.raw_id else [])]
        if st.fired:
            st.healthy_streak = st.healthy_streak + 1 if healthy else 0
            if st.healthy_streak >= self.cfg.clear_after:
                st.fired, st.healthy_streak = False, 0
                st.window.clear()
                return [LocalSignal("threshold", name + ".resolved", "info", s.entity, s.event_ts, s.source_tz,
                                    params={"value": round(s.value, 3), "threshold": limit,
                                            "peak": round(st.peak, 3)})]
        return []


class AuthDetector:
    def __init__(self, cfg: AuthRules) -> None:
        self.cfg = cfg
        self.events: deque[AuthEvent] = deque()
        self.last_emit: dict[tuple, tuple[datetime, int]] = {}

    def _prune(self, now: datetime) -> None:
        horizon = now - timedelta(seconds=self.cfg.window_s)
        while self.events and self.events[0].event_ts < horizon:
            self.events.popleft()

    def _should_emit(self, key: tuple, now: datetime, count: int) -> bool:
        prev = self.last_emit.get(key)
        if prev is None or (now - prev[0]).total_seconds() >= self.cfg.cooldown_s or count >= 2 * prev[1]:
            self.last_emit[key] = (now, count)
            return True
        return False

    def observe(self, e: AuthEvent) -> list[LocalSignal]:
        # keep deque ordered by event time even with out-of-order arrival
        if self.events and e.event_ts < self.events[-1].event_ts:
            items = list(self.events) + [e]
            items.sort(key=lambda x: x.event_ts)
            self.events = deque(items)
            now = items[-1].event_ts
        else:
            self.events.append(e)
            now = e.event_ts
        self._prune(now)
        out: list[LocalSignal] = []
        fails = [x for x in self.events if x.outcome == "failure"]
        w = self.cfg.window_s

        if e.outcome == "failure":
            pair = [x for x in fails if x.principal == e.principal and x.source_addr == e.source_addr]
            if len(pair) >= self.cfg.bruteforce_failures and \
                    self._should_emit(("bf", e.principal, e.source_addr), now, len(pair)):
                risk = min(100, 50 + 2 * len(pair))
                out.append(self._sig("auth.bruteforce", "high" if risk < 90 else "critical", e, now,
                                     count=len(pair), principals=[e.principal], sources=[e.source_addr],
                                     risk=risk, raw_ids=[x.raw_id for x in pair if x.raw_id]))
            from_src = [x for x in fails if x.source_addr == e.source_addr]
            principals = sorted({x.principal for x in from_src})
            if len(principals) >= self.cfg.spray_principals and \
                    self._should_emit(("spray", e.source_addr), now, len(principals)):
                risk = min(100, 55 + 3 * len(principals))
                out.append(self._sig("auth.spray", "high" if risk < 90 else "critical", e, now,
                                     count=len(from_src), principals=principals[:20], sources=[e.source_addr],
                                     risk=risk, raw_ids=[x.raw_id for x in from_src if x.raw_id]))
        else:
            pair = [x for x in fails if x.principal == e.principal and x.source_addr == e.source_addr]
            if len(pair) >= self.cfg.stuffing_min_failures and \
                    self._should_emit(("stuff", e.principal, e.source_addr), now, len(pair)):
                out.append(self._sig("auth.stuffing", "critical", e, now, count=len(pair),
                                     principals=[e.principal], sources=[e.source_addr], risk=95,
                                     raw_ids=[x.raw_id for x in pair if x.raw_id]))
        for s in out:
            s.window_s = w
        return out

    def _sig(self, rule, sev, e, now, count, principals, sources, risk, raw_ids) -> LocalSignal:
        return LocalSignal("security", rule, sev, e.target_entity, now, e.source_tz,
                           params={"count": count, "distinct_principals": len(set(principals)),
                                   "distinct_sources": len(set(sources))},
                           subjects=list(principals), sources=list(sources), risk_score=risk,
                           priority=True, raw_ids=raw_ids[-50:])


class LogCategoryDetector:
    def __init__(self, window_s: int = 60) -> None:
        self.window_s = window_s
        self.seen: dict[tuple[str, str], deque[datetime]] = defaultdict(deque)
        self.emitted: dict[tuple[str, str], int] = {}

    def observe(self, e: LogEvent) -> list[LocalSignal]:
        key = (e.entity, e.category)
        dq = self.seen[key]
        dq.append(e.event_ts)
        horizon = e.event_ts - timedelta(seconds=self.window_s)
        while dq and dq[0] < horizon:
            dq.popleft()
        n = len(dq)
        last = self.emitted.get(key, 0)
        if n == 1 and last and n < last:
            self.emitted[key] = 0
            last = 0
        if last == 0 or n >= 2 * last:
            self.emitted[key] = n
            sev = {"critical": "high", "error": "warning"}.get(e.level, "info")
            return [LocalSignal("log_category", f"log.{e.category}", sev, e.entity, e.event_ts, e.source_tz,
                                params={"count": n}, window_s=self.window_s, priority=e.level == "critical",
                                raw_ids=[e.raw_id] if e.raw_id else [])]
        return []

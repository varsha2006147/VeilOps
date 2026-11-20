"""Remediation sandbox (Member A) - a tiny stand-in for a customer service that remediation can REALLY act on.

Safe-remediation demo (SAD 21.3): an approved RESTART_SERVICE stops a genuine CPU runaway, so the
collector's CPU reading for `sandbox-app` actually falls. Every action supports dry-run, returns
before/after health, and can be rolled back. Nothing here touches the host: it only changes its own state.

  python -m veilops.sandbox --port 9100
  GET  /health                      current state + health
  GET  /metrics                     telemetry records (collector reads this with the http_poll driver)
  POST /chaos/runaway               start a real CPU burn (1 busy thread)
  POST /actions/{type}?dry_run=1    INVESTIGATE_TOP_PROCESSES | RESTART_SERVICE |
                                    TEMP_BLOCK_SOURCE_15M (?source=) | FAILOVER_TO_SECONDARY_LINK
  POST /rollback/{action_id}        undo a previous action
"""
from __future__ import annotations

import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

import psutil
from fastapi import FastAPI, HTTPException

ACTIONS = ("INVESTIGATE_TOP_PROCESSES", "RESTART_SERVICE", "TEMP_BLOCK_SOURCE_15M", "FAILOVER_TO_SECONDARY_LINK")
REVERSIBLE = {"RESTART_SERVICE", "TEMP_BLOCK_SOURCE_15M", "FAILOVER_TO_SECONDARY_LINK"}


def _iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class Burner:
    """A real CPU runaway: one thread spinning. Stopping it is what 'restart' fixes."""

    def __init__(self) -> None:
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self.running:
            return
        self._stop.clear()

        def spin() -> None:
            x = 0
            while not self._stop.is_set():
                for _ in range(20_000):
                    x = (x * 31 + 7) % 1_000_003

        self._thread = threading.Thread(target=spin, name="runaway-worker", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
        self._thread = None


@dataclass
class SandboxState:
    service: str = "sandbox-app"
    link: str = "primary"                       # primary | secondary
    blocked: dict[str, float] = field(default_factory=dict)   # source -> unblock epoch
    restarts: int = 0
    started_at: float = field(default_factory=time.time)
    history: dict[str, dict] = field(default_factory=dict)    # action_id -> record (for rollback)
    burner: Burner = field(default_factory=Burner)
    proc: psutil.Process = field(default_factory=lambda: psutil.Process(os.getpid()))

    def cpu_pct(self) -> float:
        # this process only; a spinning thread pins ~100% of one core
        return round(self.proc.cpu_percent(interval=0.2), 1)

    def health(self) -> dict:
        now = time.time()
        self.blocked = {s: t for s, t in self.blocked.items() if t > now}
        cpu = self.cpu_pct()
        state = "poor" if cpu >= 90 else "fair" if cpu >= 75 else "good" if cpu >= 60 else "excellent"
        return {"service": self.service, "state": state, "cpu_pct": cpu, "runaway": self.burner.running,
                "link": self.link, "blocked_sources": sorted(self.blocked), "restarts": self.restarts,
                "uptime_s": int(now - self.started_at), "ts": _iso()}


def create_app(state: SandboxState | None = None, tenant: str = "t_acme", tz: str = "Asia/Kolkata") -> FastAPI:
    st = state or SandboxState()
    app = FastAPI(title="VeilOps remediation sandbox")
    app.state.sandbox = st

    @app.get("/health")
    async def health() -> dict:
        return st.health()

    @app.get("/metrics")
    async def metrics() -> list[dict]:
        h = st.health()
        t0 = time.perf_counter()
        _ = sum(range(2000))                    # a tiny unit of work, timed as response latency
        resp_ms = round((time.perf_counter() - t0) * 1000 + (40 if h["runaway"] else 8), 2)
        base = {"ts": h["ts"], "tz": tz, "tenant": tenant, "kind": "metric", "origin": "SANDBOX"}
        return [
            {**base, "host": st.service, "entity_kind": "host", "metric": "cpu", "value": h["cpu_pct"]},
            {**base, "host": st.service, "entity_kind": "service", "metric": "up", "value": 1},
            {**base, "host": st.service, "entity_kind": "service", "metric": "response_ms", "value": resp_ms},
        ]

    @app.post("/chaos/runaway")
    async def runaway() -> dict:
        st.burner.start()
        return {"runaway": True, "ts": _iso()}

    @app.post("/actions/{action_type}")
    async def act(action_type: str, dry_run: bool = False, source: str | None = None) -> dict:
        if action_type not in ACTIONS:
            raise HTTPException(404, f"unknown action; allowed: {ACTIONS}")
        before = st.health()
        plan, undo = _plan(st, action_type, source)
        record = {"action_id": str(uuid.uuid4()), "type": action_type, "dry_run": dry_run, "plan": plan,
                  "reversible": action_type in REVERSIBLE, "health_before": before["state"],
                  "cpu_before": before["cpu_pct"], "ts": _iso()}
        if action_type == "INVESTIGATE_TOP_PROCESSES":
            record["top_processes"] = _top(st)
        elif not dry_run:
            _apply(st, action_type, source)
            record["undo"] = undo
            st.history[record["action_id"]] = record
        after = st.health()
        record.update(health_after=after["state"], cpu_after=after["cpu_pct"])
        return record

    @app.post("/rollback/{action_id}")
    async def rollback(action_id: str) -> dict:
        rec = st.history.pop(action_id, None)
        if rec is None:
            raise HTTPException(404, "unknown or already rolled back action")
        u = rec["undo"]
        if u["op"] == "restore_runaway" and u["value"]:
            st.burner.start()
        elif u["op"] == "unblock":
            st.blocked.pop(u["value"], None)
        elif u["op"] == "set_link":
            st.link = u["value"]
        return {"action_id": action_id, "rolled_back": True, "undo": u, "health": st.health()}

    return app


def _plan(st: SandboxState, action_type: str, source: str | None) -> tuple[str, dict]:
    if action_type == "RESTART_SERVICE":
        return (f"restart {st.service}: stop runaway worker={st.burner.running}",
                {"op": "restore_runaway", "value": st.burner.running})
    if action_type == "TEMP_BLOCK_SOURCE_15M":
        if not source:
            raise HTTPException(422, "source is required")
        return f"block {source} for 15 min", {"op": "unblock", "value": source}
    if action_type == "FAILOVER_TO_SECONDARY_LINK":
        return f"switch link {st.link} -> secondary", {"op": "set_link", "value": st.link}
    return "read-only: list top processes", {"op": "none", "value": None}


def _apply(st: SandboxState, action_type: str, source: str | None) -> None:
    if action_type == "RESTART_SERVICE":
        st.burner.stop()
        st.restarts += 1
    elif action_type == "TEMP_BLOCK_SOURCE_15M":
        st.blocked[source] = time.time() + 900          # type: ignore[index]
    elif action_type == "FAILOVER_TO_SECONDARY_LINK":
        st.link = "secondary"


def _top(st: SandboxState) -> list[dict]:
    threads = [{"name": t.name, "alive": t.is_alive()} for t in threading.enumerate()]
    return [{"pid": st.proc.pid, "name": st.service, "cpu_pct": st.cpu_pct(), "threads": threads}]

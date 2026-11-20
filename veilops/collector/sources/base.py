from __future__ import annotations

import asyncio
import logging
from typing import Awaitable, Callable

from ..contracts import RawEvent, SourceStatus

Emit = Callable[[RawEvent], Awaitable[None]]
log = logging.getLogger("veilops.source")


class Source:
    name = "source"

    def __init__(self) -> None:
        self.status = SourceStatus(self.name, ok=False, detail="not started")
        self.events = 0

    async def run(self, emit: Emit) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    async def supervise(self, emit: Emit) -> None:
        """Run forever; restart with backoff on failure so one bad source never kills the collector."""
        backoff = 1.0
        while True:
            try:
                await self.run(self._counting(emit))
                return
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                self.status.ok, self.status.detail = False, f"{type(exc).__name__}: {exc}"[:200]
                log.warning("source %s failed: %s; retry in %.0fs", self.name, exc, backoff)
                await asyncio.sleep(backoff)
                backoff = min(30.0, backoff * 2)

    def _counting(self, emit: Emit) -> Emit:
        async def inner(ev: RawEvent) -> None:
            self.events += 1
            self.status.ok, self.status.last_event_ts, self.status.detail = True, ev.event_ts, "ok"
            await emit(ev)
        return inner

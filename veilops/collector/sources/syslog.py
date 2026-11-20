"""Syslog over UDP (RFC 3164/5424-ish) + log file tailing (e.g. /var/log/auth.log)."""
from __future__ import annotations

import asyncio
import re
from pathlib import Path

from ..contracts import RawEvent, utcnow
from .base import Emit, Source

# <PRI>Mmm dd hh:mm:ss host tag: msg      |  <PRI>1 2026-11-21T04:12:00Z host app - - - msg
_RFC3164 = re.compile(r"^(?:<\d+>)?(?:[A-Z][a-z]{2}\s+\d+\s[\d:]{8})\s+(?P<host>\S+)\s+(?P<msg>.*)$")
_RFC5424 = re.compile(r"^<\d+>\d\s+\S+\s+(?P<host>\S+)\s+(?P<msg>.*)$")


def split_host(line: str, default_host: str) -> tuple[str, str]:
    for pat in (_RFC5424, _RFC3164):
        m = pat.match(line)
        if m:
            return m["host"], m["msg"]
    return default_host, line


class SyslogSource(Source):
    name = "syslog"

    def __init__(self, spec: dict, source_tz: str, default_host: str = "localhost") -> None:
        super().__init__()
        self.port = spec.get("udp_port")
        self.files = spec.get("files", [])
        self.tz = source_tz
        self.default_host = default_host

    async def run(self, emit: Emit) -> None:
        tasks = [asyncio.create_task(self._tail(Path(p), emit)) for p in self.files if Path(p).exists()]
        if self.port:
            tasks.append(asyncio.create_task(self._udp(emit)))
        self.status.ok = True
        self.status.detail = f"listening udp/{self.port}" if self.port else "tailing files"
        if not tasks:
            self.status.detail = "no syslog inputs available"
            await asyncio.Event().wait()
        await asyncio.gather(*tasks)

    async def _line(self, line: str, emit: Emit) -> None:
        host, msg = split_host(line.strip(), self.default_host)
        if msg:
            await emit(RawEvent("syslog", utcnow(), self.tz, line.strip(),
                                {"kind": "line", "entity": host, "line": msg}))

    async def _udp(self, emit: Emit) -> None:
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue[str] = asyncio.Queue(10_000)

        class Proto(asyncio.DatagramProtocol):
            def datagram_received(self, data, addr):  # noqa: ANN001
                try:
                    queue.put_nowait(data.decode(errors="replace"))
                except asyncio.QueueFull:
                    pass

        transport, _ = await loop.create_datagram_endpoint(Proto, local_addr=("0.0.0.0", int(self.port)))
        try:
            while True:
                await self._line(await queue.get(), emit)
        finally:
            transport.close()

    async def _tail(self, path: Path, emit: Emit) -> None:
        with path.open(errors="replace") as fh:
            fh.seek(0, 2)
            while True:
                line = fh.readline()
                if not line:
                    await asyncio.sleep(0.5)
                    continue
                await self._line(line, emit)

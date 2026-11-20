"""Organizer stream adapter.

The organizer's format is unknown until the event, so: transport drivers (file/JSONL replay, SSE,
WebSocket, Kafka, HTTP poll) are separated from a declarative field mapping (stream_map.yaml). Adapting
to the real stream should be a config change, not code.

Every record keeps the organizer's own event timestamp - all real-time targets are measured from it.
"""
from __future__ import annotations

import asyncio
import csv
import io
import json
from pathlib import Path
from typing import Any, AsyncIterator

import yaml

from ..contracts import RawEvent
from ..pipeline.normalize import METRIC_ALIASES
from ..timeutil import parse_ts
from .base import Emit, Source

DEFAULT_MAP: dict[str, Any] = {
    "fields": {
        "ts": ["ts", "timestamp", "time", "@timestamp", "event_time", "eventTime"],
        "tz": ["tz", "source_tz", "timezone"],
        "tenant": ["tenant", "tenant_id", "customer", "org"],
        "environment": ["env", "environment", "site", "region"],
        "kind": ["kind", "type", "event_type", "category"],
        "entity": ["host", "hostname", "entity", "device", "node", "service", "link", "source"],
        "entity_kind": ["entity_kind", "entityType"],
        "metric": ["metric", "metric_name", "name"],
        "value": ["value", "val", "reading"],
        "message": ["message", "msg", "log", "line"],
        "level": ["level", "severity", "log_level"],
        "principal": ["user", "username", "principal", "account"],
        "source_addr": ["src_ip", "source_ip", "client_ip", "ip", "remote_addr"],
        "outcome": ["outcome", "result", "auth_result"],
    },
    "kind_aliases": {
        "metric": ["metric", "metrics", "gauge", "telemetry"],
        "log": ["log", "logs", "syslog", "event"],
        "auth": ["auth", "login", "authentication", "security"],
    },
    "wide_metrics": True,
    "tenant_filter": None,
}


def _first(rec: dict, keys: list[str]):
    for k in keys:
        if k in rec and rec[k] not in (None, ""):
            return rec[k]
    return None


class StreamMapper:
    def __init__(self, spec: dict | None = None, default_tz: str = "UTC") -> None:
        spec = {**DEFAULT_MAP, **(spec or {})}
        self.fields = {**DEFAULT_MAP["fields"], **(spec.get("fields") or {})}
        self.kinds = {**DEFAULT_MAP["kind_aliases"], **(spec.get("kind_aliases") or {})}
        self.wide = bool(spec.get("wide_metrics", True))
        self.tenant_filter = spec.get("tenant_filter")
        self.default_tz = default_tz
        self.skipped_other_tenant = 0
        self.unmapped = 0

    @classmethod
    def from_file(cls, path: str | None, default_tz: str = "UTC") -> "StreamMapper":
        if path and Path(path).exists():
            return cls(yaml.safe_load(Path(path).read_text()) or {}, default_tz)
        return cls(None, default_tz)

    def _kind(self, rec: dict) -> str | None:
        raw = _first(rec, self.fields["kind"])
        if raw is None:
            return None
        r = str(raw).lower()
        for canon, aliases in self.kinds.items():
            if r in aliases:
                return canon
        return None

    def map(self, rec: dict, raw_text: str) -> RawEvent | None:
        tenant = _first(rec, self.fields["tenant"])
        if self.tenant_filter and tenant is not None and str(tenant) != str(self.tenant_filter):
            self.skipped_other_tenant += 1
            return None
        tz = str(_first(rec, self.fields["tz"]) or self.default_tz)
        ts_raw = _first(rec, self.fields["ts"])
        ts = parse_ts(ts_raw, tz) if ts_raw is not None else None
        if ts is None:
            from ..contracts import utcnow
            ts = utcnow()                      # flagged: organizer record without timestamp
        entity = str(_first(rec, self.fields["entity"]) or "unknown")
        kind = self._kind(rec)
        items: list[dict] = []
        if kind == "metric" or (kind is None and _first(rec, self.fields["metric"]) is not None
                                 and _first(rec, self.fields["value"]) is not None):
            items.append({"kind": "metric", "entity": entity, "metric": _first(rec, self.fields["metric"]),
                          "value": _first(rec, self.fields["value"]),
                          "entity_kind": _first(rec, self.fields["entity_kind"])})
        elif kind == "auth":
            items.append({"kind": "auth", "entity": entity,
                          "principal": _first(rec, self.fields["principal"]),
                          "source_addr": _first(rec, self.fields["source_addr"]),
                          "outcome": _first(rec, self.fields["outcome"]) or "failure"})
        elif kind == "log" or (kind is None and _first(rec, self.fields["message"]) is not None):
            items.append({"kind": "log", "entity": entity, "message": _first(rec, self.fields["message"]),
                          "level": _first(rec, self.fields["level"])})
        if self.wide:                               # {"host":"a","cpu":91,"memory":60,...}
            ek = _first(rec, self.fields["entity_kind"])
            for k, v in rec.items():
                if k in METRIC_ALIASES and not isinstance(v, (dict, list)) and k not in self.fields["value"]:
                    items.append({"kind": "metric", "entity": entity, "metric": k, "value": v, "entity_kind": ek})
        if not items:
            self.unmapped += 1
            return None
        fields = items[0] if len(items) == 1 else {"kind": "multi", "items": items}
        if tenant is not None:
            fields["tenant"] = str(tenant)
        return RawEvent("stream", ts, tz, raw_text, fields)

    def parse_text(self, text: str) -> list[tuple[dict, str]]:
        """A transport chunk -> list of (record, raw_text). Accepts JSON object, JSON array or JSONL."""
        text = text.strip()
        if not text:
            return []
        try:
            obj = json.loads(text)
            if isinstance(obj, list):
                return [(o, json.dumps(o)) for o in obj if isinstance(o, dict)]
            if isinstance(obj, dict):
                for key in ("records", "events", "data", "items"):
                    if isinstance(obj.get(key), list):
                        return [(o, json.dumps(o)) for o in obj[key] if isinstance(o, dict)]
                return [(obj, text)]
        except json.JSONDecodeError:
            pass
        out = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                o = json.loads(line)
                if isinstance(o, dict):
                    out.append((o, line))
            except json.JSONDecodeError:
                out.append(({"message": line}, line))   # plain text line -> log
        return out


class StreamSource(Source):
    """driver: file | sse | websocket | kafka | http_poll | csv"""
    name = "stream"

    def __init__(self, spec: dict, mapper: StreamMapper) -> None:
        super().__init__()
        self.spec = spec
        self.mapper = mapper
        self.driver = spec.get("driver", "file")

    async def run(self, emit: Emit) -> None:
        async for rec, raw in self._records():
            ev = self.mapper.map(rec, raw)
            if ev is not None:
                await emit(ev)

    async def _records(self) -> AsyncIterator[tuple[dict, str]]:
        d = self.driver
        if d == "file":
            async for x in self._file():
                yield x
        elif d == "csv":
            async for x in self._csv():
                yield x
        elif d == "sse":
            async for x in self._sse():
                yield x
        elif d == "websocket":
            async for x in self._ws():
                yield x
        elif d == "http_poll":
            async for x in self._poll():
                yield x
        elif d == "kafka":
            async for x in self._kafka():
                yield x
        else:
            raise ValueError(f"unknown stream driver {d}")

    async def _file(self):
        path = Path(self.spec["path"])
        follow = self.spec.get("follow", True)
        with path.open() as fh:
            if self.spec.get("from_end"):
                fh.seek(0, 2)
            while True:
                line = fh.readline()
                if not line:
                    if not follow:
                        return
                    await asyncio.sleep(0.2)
                    continue
                for x in self.mapper.parse_text(line):
                    yield x
                rate = self.spec.get("replay_rate")      # records/s when replaying a dump
                if rate:
                    await asyncio.sleep(1.0 / float(rate))

    async def _csv(self):
        text = Path(self.spec["path"]).read_text()
        rate = float(self.spec.get("replay_rate", 0) or 0)
        for row in csv.DictReader(io.StringIO(text)):
            yield dict(row), json.dumps(row)
            if rate:
                await asyncio.sleep(1.0 / rate)

    async def _sse(self):
        import httpx
        headers = {"Accept": "text/event-stream", **(self.spec.get("headers") or {})}
        async with httpx.AsyncClient(timeout=None, verify=self.spec.get("verify_tls", True)) as client:
            async with client.stream("GET", self.spec["url"], headers=headers) as resp:
                resp.raise_for_status()
                buf: list[str] = []
                async for line in resp.aiter_lines():
                    if line.startswith("data:"):
                        buf.append(line[5:].lstrip())
                    elif line == "" and buf:
                        for x in self.mapper.parse_text("\n".join(buf)):
                            yield x
                        buf = []
                    elif line and not line.startswith((":", "event:", "id:", "retry:")):
                        for x in self.mapper.parse_text(line):     # plain chunked JSONL also works
                            yield x

    async def _ws(self):
        import websockets
        async with websockets.connect(self.spec["url"], max_size=None) as ws:
            async for msg in ws:
                for x in self.mapper.parse_text(msg if isinstance(msg, str) else msg.decode()):
                    yield x

    async def _poll(self):
        import httpx
        interval = float(self.spec.get("interval_s", 1))
        async with httpx.AsyncClient(timeout=10, verify=self.spec.get("verify_tls", True)) as client:
            while True:
                r = await client.get(self.spec["url"], headers=self.spec.get("headers") or {})
                r.raise_for_status()
                for x in self.mapper.parse_text(r.text):
                    yield x
                await asyncio.sleep(interval)

    async def _kafka(self):
        from aiokafka import AIOKafkaConsumer  # optional dependency, only if the organizer uses Kafka
        consumer = AIOKafkaConsumer(self.spec["topic"], bootstrap_servers=self.spec["bootstrap"],
                                    group_id=self.spec.get("group_id", "veilops-collector"))
        await consumer.start()
        try:
            async for msg in consumer:
                for x in self.mapper.parse_text(msg.value.decode()):
                    yield x
        finally:
            await consumer.stop()

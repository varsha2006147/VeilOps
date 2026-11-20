"""Stage 3: local raw store. The ONLY place raw lines and secrets live. Never read by the egress path."""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone

import aiosqlite

from ..contracts import RawEvent
from ..timeutil import iso

SCHEMA = """
CREATE TABLE IF NOT EXISTS raw_events (
  id INTEGER PRIMARY KEY, source TEXT, event_ts TEXT, source_tz TEXT,
  raw TEXT, parsed_json TEXT, ingested_at TEXT);
CREATE INDEX IF NOT EXISTS ix_raw_ts ON raw_events(event_ts);
CREATE INDEX IF NOT EXISTS ix_raw_ingested ON raw_events(ingested_at);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY, ts TEXT, actor TEXT, action TEXT, detail TEXT);
"""

# Display-only masking for the local UI (B's redactor is the egress control; this just avoids
# shoulder-surfing secrets on a projector unless a local admin explicitly reveals them).
_MASKS = [
    re.compile(r"(?i)(password|passwd|pwd|secret|token|api[_-]?key)(\s*[=:]\s*)\S+"),
    re.compile(r"(?i)(bearer\s+)\S+"),
    re.compile(r"(\w+://[^:/\s]+:)[^@\s]+(@)"),
    re.compile(r"(AKIA)[0-9A-Z]{16}"),
    re.compile(r"(eyJ)[\w-]+\.[\w-]+\.[\w-]+"),
]


def mask(text: str) -> str:
    out = _MASKS[0].sub(lambda m: m.group(1) + m.group(2) + "••••••", text)
    out = _MASKS[1].sub(lambda m: m.group(1) + "••••••", out)
    out = _MASKS[2].sub(lambda m: m.group(1) + "••••••" + m.group(2), out)
    out = _MASKS[3].sub(lambda m: m.group(1) + "••••••••", out)
    out = _MASKS[4].sub(lambda m: m.group(1) + "••••••", out)
    return out


class RawStore:
    def __init__(self, path: str) -> None:
        self.path = path
        self.db: aiosqlite.Connection | None = None

    async def open(self) -> None:
        import os
        if self.path != ":memory:":
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        self.db = await aiosqlite.connect(self.path)
        await self.db.execute("PRAGMA journal_mode=WAL")
        await self.db.execute("PRAGMA synchronous=NORMAL")
        await self.db.executescript(SCHEMA)
        await self.db.commit()

    async def close(self) -> None:
        if self.db:
            await self.db.close()

    async def insert(self, ev: RawEvent) -> int:
        assert self.db
        cur = await self.db.execute(
            "INSERT INTO raw_events(source,event_ts,source_tz,raw,parsed_json,ingested_at) VALUES(?,?,?,?,?,?)",
            (ev.source, iso(ev.event_ts), ev.source_tz, ev.raw, json.dumps(ev.fields, default=str),
             iso(ev.received_at)))
        return cur.lastrowid or 0

    async def commit(self) -> None:
        assert self.db
        await self.db.commit()

    async def recent(self, limit: int = 100, reveal: bool = False, source: str | None = None,
                     contains: str | None = None) -> list[dict]:
        assert self.db
        q = "SELECT id,source,event_ts,source_tz,raw,ingested_at FROM raw_events"
        where, args = [], []
        if source:
            where.append("source=?")
            args.append(source)
        if contains:
            where.append("raw LIKE ?")
            args.append(f"%{contains}%")
        if where:
            q += " WHERE " + " AND ".join(where)
        q += " ORDER BY id DESC LIMIT ?"
        rows = await (await self.db.execute(q, (*args, limit))).fetchall()
        return [{"id": r[0], "source": r[1], "event_ts": r[2], "source_tz": r[3],
                 "raw": r[4] if reveal else mask(r[4]), "ingested_at": r[5]} for r in rows]

    async def count(self) -> int:
        assert self.db
        return (await (await self.db.execute("SELECT count(*) FROM raw_events")).fetchone())[0]

    async def purge(self, retention_h: int) -> int:
        assert self.db
        cutoff = iso(datetime.now(timezone.utc) - timedelta(hours=retention_h))
        cur = await self.db.execute("DELETE FROM raw_events WHERE ingested_at < ?", (cutoff,))
        await self.db.commit()
        return cur.rowcount

    async def recent_audit(self, limit: int = 100) -> list[dict]:
        assert self.db
        cur = await self.db.execute("SELECT ts,actor,action,detail FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))
        return [{"ts": r[0], "actor": r[1], "action": r[2], "detail": r[3]} for r in await cur.fetchall()]

    async def audit(self, actor: str, action: str, detail: str) -> None:
        assert self.db
        await self.db.execute("INSERT INTO audit_log(ts,actor,action,detail) VALUES(?,?,?,?)",
                              (iso(datetime.now(timezone.utc)), actor, action, detail))
        await self.db.commit()

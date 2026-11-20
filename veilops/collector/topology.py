"""Topology loader (Member A) -> SourceBus.topology for Member B to pseudonymize and send.

The dependency graph (service -> host -> link) is what lets the cloud correlate alerts into one incident
and rank root causes (SAD 20.3) without ever learning real names: B maps every node to the same HMAC
pseudonym used for metrics, so `h_7f3a...` in a CPU window and in a topology edge are the same host.

topology.yaml accepts either form (mix freely):

    edges:
      - "service:checkout -> host:app-01 : runs_on"          # compact
      - { src: app-01, src_kind: host, dst: core-sw1, dst_kind: link, rel: connects_via }

Kinds: host | service | link.  Relations: runs_on | connects_via | depends_on.
The file is re-read when it changes; each change bumps `version` and sets `bus.topology_changed`.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

log = logging.getLogger("veilops.topology")

KINDS = ("host", "service", "link")
RELATIONS = ("runs_on", "connects_via", "depends_on")
_COMPACT = re.compile(r"^\s*(\w+):(\S+)\s*->\s*(\w+):(\S+)\s*:\s*(\w+)\s*$")
_KIND_ALIAS = {"svc": "service", "srv": "service", "h": "host", "node": "host", "lnk": "link", "net": "link"}


class TopologyError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class Edge:
    src: str
    src_kind: str
    dst: str
    dst_kind: str
    rel: str


@dataclass
class Topology:
    edges: list[Edge] = field(default_factory=list)
    version: int = 0
    digest: str = ""
    source: str = "none"          # file path, "sim" or "none"

    @property
    def nodes(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for e in self.edges:
            out.setdefault(e.src, e.src_kind)
            out.setdefault(e.dst, e.dst_kind)
        return out

    def neighbors(self, name: str) -> set[str]:
        return {e.dst for e in self.edges if e.src == name} | {e.src for e in self.edges if e.dst == name}

    def downstream_of(self, name: str) -> set[str]:
        """Everything that depends on `name` (walks edges backwards: who runs on / connects via / depends on it)."""
        seen, stack = set(), [name]
        while stack:
            cur = stack.pop()
            for e in self.edges:
                if e.dst == cur and e.src not in seen:
                    seen.add(e.src)
                    stack.append(e.src)
        return seen

    def as_tuples(self) -> list[tuple[str, str, str, str, str]]:
        return [(e.src, e.src_kind, e.dst, e.dst_kind, e.rel) for e in self.edges]


def _kind(k: str) -> str:
    k = _KIND_ALIAS.get(k.lower(), k.lower())
    if k not in KINDS:
        raise TopologyError(f"unknown kind '{k}' (use one of {KINDS})")
    return k


def parse_edges(items: list) -> list[Edge]:
    edges: list[Edge] = []
    for i, item in enumerate(items or []):
        try:
            if isinstance(item, str):
                m = _COMPACT.match(item)
                if not m:
                    raise TopologyError(f"expected 'kind:name -> kind:name : relation', got '{item}'")
                sk, s, dk, d, rel = m.groups()
            elif isinstance(item, dict):
                s, d, rel = str(item["src"]), str(item["dst"]), str(item.get("rel", "depends_on"))
                sk, dk = str(item.get("src_kind", "host")), str(item.get("dst_kind", "host"))
            else:
                raise TopologyError(f"unsupported edge type {type(item).__name__}")
            rel = rel.lower()
            if rel not in RELATIONS:
                raise TopologyError(f"unknown relation '{rel}' (use one of {RELATIONS})")
            if s == d:
                raise TopologyError(f"self-loop on '{s}'")
            edges.append(Edge(s, _kind(sk), d, _kind(dk), rel))
        except (KeyError, TopologyError) as exc:
            raise TopologyError(f"edge #{i + 1}: {exc}") from exc
    # a node must keep one kind everywhere
    kinds: dict[str, str] = {}
    for e in edges:
        for n, k in ((e.src, e.src_kind), (e.dst, e.dst_kind)):
            if kinds.setdefault(n, k) != k:
                raise TopologyError(f"node '{n}' declared as both {kinds[n]} and {k}")
    return sorted(set(edges), key=lambda e: (e.src, e.dst, e.rel))


def _digest(edges: list[Edge]) -> str:
    text = "\n".join("|".join(t) for t in (Topology(edges).as_tuples()))
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()[:16]


def load_file(path: str | Path) -> list[Edge]:
    data = yaml.safe_load(Path(path).read_text()) or {}
    return parse_edges(data.get("edges", []))


def from_sim() -> list[Edge]:
    from veilops.sim import TOPOLOGY
    kinds = {"checkout": "service", "auth-api": "service", "core-sw1": "link", "wan-1": "link"}
    return parse_edges([{"src": s, "src_kind": kinds.get(s, "host"), "dst": d, "dst_kind": kinds.get(d, "host"),
                         "rel": r} for s, d, r in TOPOLOGY])


class TopologyWatcher:
    """Keeps bus.topology current. Never crashes the collector on a bad file: keeps the last good graph."""

    def __init__(self, bus, path: str | None, use_sim: bool = False, interval_s: float = 5.0) -> None:
        self.bus, self.path, self.use_sim, self.interval = bus, path, use_sim, interval_s
        self.last_error: str | None = None
        self._mtime: float | None = None

    def _apply(self, edges: list[Edge], source: str) -> bool:
        digest = _digest(edges)
        cur = self.bus.topology
        if cur.digest == digest:
            return False
        self.bus.topology = Topology(edges, cur.version + 1, digest, source)
        self.bus.topology_changed.set()
        log.info("topology v%d from %s: %d edges, %d nodes", self.bus.topology.version, source, len(edges),
                 len(self.bus.topology.nodes))
        return True

    def refresh(self) -> bool:
        try:
            if self.path and Path(self.path).exists():
                mtime = Path(self.path).stat().st_mtime
                if mtime == self._mtime:
                    return False
                self._mtime = mtime
                changed = self._apply(load_file(self.path), self.path)
            elif self.use_sim:
                changed = self._apply(from_sim(), "sim")
            else:
                return False
            self.last_error = None
            return changed
        except (TopologyError, yaml.YAMLError, OSError) as exc:
            self.last_error = str(exc)
            log.warning("topology not updated, keeping v%d: %s", self.bus.topology.version, exc)
            return False

    async def run(self) -> None:
        while True:
            self.refresh()
            await asyncio.sleep(self.interval)

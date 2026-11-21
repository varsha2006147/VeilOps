"""Protocol matrix proof: the same secret-bearing logs through every ingestion protocol.

Per protocol we report: raw secret kept local, outbound payload count, leaked markers,
tripwire hits, category still observed, security summary still observed.
Evaluation is centralised in evaluate(), so a runner cannot declare its own PASS.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
import re
from dataclasses import dataclass, field
from typing import Awaitable, Callable

CANARY_VALUE = "AKIAVEILOPSCANARY01"  # fake secret planted locally (harmless)

_SCAN_RULES = (
    ("canary", re.compile(r"VEILOPSCANARY", re.IGNORECASE)),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("jwt", re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")),
    ("aws_access_key", re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])")),
    ("bearer_token", re.compile(r"\bBearer[ \t]+[A-Za-z0-9._~+/=-]{6,}", re.IGNORECASE)),
    ("secret_assignment", re.compile(
        r"""(?:password|passwd|pwd|secret|token|api[_-]?key)["']?[ \t]*[=:][ \t]*["']?\S+""",
        re.IGNORECASE)),
    ("conn_string", re.compile(r"(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]*://[^\s:/@]+:[^\s@]+@\S+")),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("ipv4", re.compile(
        r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?!\d)(?!\.\d)")),
)


def scan_bytes(body: bytes) -> list:
    """Independent secret scan of outbound bytes (also checks JSON-unescaped strings)."""
    text = body.decode("utf-8", errors="replace")
    views = [text]
    try:
        views.append("\n".join(_walk_strings(json.loads(text))))
    except (ValueError, RecursionError):
        pass
    hits = []
    for rule, pattern in _SCAN_RULES:
        if any(pattern.search(v) for v in views):
            hits.append(rule)
    return hits

MARKERS = {
    "db_password": "S3cr3t!",
    "db_host": "db-prod-02",
    "db_conn": "postgres://app:S3cr3t!@db-prod-02:5432",
    "username": "priya.sharma",
    "source_ip": "10.2.3.4",
    "canary": CANARY_VALUE,
}
PROTOCOLS = ("file_tail", "syslog_udp", "http_sse", "websocket", "kafka")
RUN_TIMEOUT_S = 10


def _walk_strings(obj):
    stack = [obj]
    while stack:
        cur = stack.pop()
        if isinstance(cur, str):
            yield cur
        elif isinstance(cur, dict):
            for k, v in cur.items():
                if isinstance(k, str):
                    yield k
                stack.append(v)
        elif isinstance(cur, list):
            stack.extend(cur)


def find_markers(data: bytes) -> dict:
    """Count each marker in raw bytes and in the JSON-unescaped strings. Only counts > 0 returned."""
    views = [data]
    try:
        obj = json.loads(data.decode("utf-8", errors="replace"))
    except (ValueError, RecursionError):
        obj = None
    if obj is not None:
        views.append("\n".join(_walk_strings(obj)).encode("utf-8"))
    hits = {}
    for name, value in MARKERS.items():
        needle = value.encode("utf-8")
        n = max(view.count(needle) for view in views)
        if n:
            hits[name] = n
    return hits


def tripwire_count(data: bytes) -> int:
    return len(scan_bytes(data))


@dataclass
class ProtocolResult:
    name: str
    status: str = "PENDING"  # PENDING -> PASS | FAIL ; or SKIPPED | NOT_SUPPORTED
    reason: str = ""
    raw_secret_stored_locally: bool = False
    outbound_payloads: int = 0
    marker_hits: dict = field(default_factory=dict)
    tripwire_hits: int = 0
    category_seen: bool = False
    auth_checked: bool = False
    security_summary_seen: bool = False
    ms: int = 0


def evaluate(r: ProtocolResult) -> "tuple[str, list[str]]":
    problems = []
    if not r.raw_secret_stored_locally:
        problems.append("raw secret was not stored locally")
    if r.outbound_payloads < 1:
        problems.append("no outbound payload reached the outbox")
    if any(v > 0 for v in r.marker_hits.values()):
        problems.append("real identifier or secret found in outbound payload")
    if r.tripwire_hits:
        problems.append("tripwire scanner found secret-like content in outbound bytes")
    if not r.category_seen:
        problems.append("no log-category signal reached the outbox")
    if r.auth_checked and not r.security_summary_seen:
        problems.append("no security summary reached the outbox")
    return ("PASS" if not problems else "FAIL", problems)


def _scrub(text: str) -> str:
    for name, value in MARKERS.items():
        text = text.replace(value, f"<{name}>")
    return text


# name -> async function returning a ProtocolResult (status PENDING, evidence filled in).
RUNNERS: "dict[str, Callable[[], Awaitable[ProtocolResult]]]" = {}


async def run_matrix(only: "list[str] | None" = None) -> "list[ProtocolResult]":
    names = list(only) if only else list(PROTOCOLS)
    results = []
    for name in names:
        runner = RUNNERS.get(name)
        if runner is None:
            results.append(ProtocolResult(name, "NOT_SUPPORTED", "no runner for this protocol yet"))
            continue
        t0 = time.monotonic()
        try:
            res = await asyncio.wait_for(runner(), timeout=RUN_TIMEOUT_S)
        except asyncio.TimeoutError:
            res = ProtocolResult(name, "FAIL", f"timed out after {RUN_TIMEOUT_S} s")
        except Exception as exc:  # type name only: messages could carry data
            res = ProtocolResult(name, "FAIL", f"runner error: {type(exc).__name__}")
        res.ms = int((time.monotonic() - t0) * 1000)
        if res.status == "PENDING":
            res.status, problems = evaluate(res)
            res.reason = "; ".join(problems)
        res.reason = _scrub(res.reason)
        results.append(res)
    return results


def _yn(value: bool) -> str:
    return "YES" if value else "NO"


def format_table(results: "list[ProtocolResult]") -> str:
    header = ["Protocol", "Status", "Raw kept local", "Payloads", "Leaked markers",
              "Tripwire", "Category", "Security summary", "ms"]
    rows, notes = [], []
    for r in results:
        if r.status in ("NOT_SUPPORTED", "SKIPPED"):
            rows.append([r.name, r.status] + ["-"] * 7)
        else:
            rows.append([
                r.name, r.status, _yn(r.raw_secret_stored_locally), str(r.outbound_payloads),
                str(sum(r.marker_hits.values())), str(r.tripwire_hits), _yn(r.category_seen),
                _yn(r.security_summary_seen) if r.auth_checked else "n/a", str(r.ms),
            ])
        if r.reason:
            notes.append(f"  {r.name}: {_scrub(r.reason)}")
    widths = [max(len(header[i]), *(len(row[i]) for row in rows)) if rows else len(header[i])
              for i in range(len(header))]
    line = "  ".join(h.ljust(w) for h, w in zip(header, widths))
    out = [line, "  ".join("-" * w for w in widths)]
    out += ["  ".join(c.ljust(w) for c, w in zip(row, widths)) for row in rows]
    out += notes
    supported = [r for r in results if r.status not in ("NOT_SUPPORTED", "SKIPPED")]
    passed = sum(1 for r in supported if r.status == "PASS")
    leaks = sum(sum(r.marker_hits.values()) for r in supported)
    skipped = len(results) - len(supported)
    out.append(f"{passed}/{len(supported)} supported protocols PASS, {leaks} leaks, "
               f"{skipped} not supported/skipped")
    return "\n".join(out)


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(prog="protocol_proof")
    parser.add_argument("--only", nargs="*", choices=PROTOCOLS)
    args = parser.parse_args(argv)
    results = asyncio.run(run_matrix(args.only))
    print(format_table(results))
    return 1 if any(r.status == "FAIL" for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
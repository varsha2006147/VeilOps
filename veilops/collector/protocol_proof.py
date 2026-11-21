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
PROTOCOLS = ("file_tail", "syslog_udp", "http_sse", "websocket", "http_poll", "kafka")
RUN_TIMEOUT_S = 15


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
    errors: list = field(default_factory=list)


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

def _describe(exc: BaseException) -> str:
    """Exception type + field paths/error types + function names. Never values."""
    detail = type(exc).__name__
    errs = getattr(exc, "errors", None)
    if callable(errs):
        try:
            detail += " [" + "; ".join(
                ".".join(str(p) for p in e["loc"]) + ":" + e["type"]
                for e in errs(include_input=False, include_url=False, include_context=False)
            )[:500] + "]"
        except Exception:
            pass
    frames, tb = [], exc.__traceback__
    while tb is not None:
        frames.append(f"{tb.tb_frame.f_code.co_name}:{tb.tb_lineno}")
        tb = tb.tb_next
    return detail + " @ " + " > ".join(frames[-3:])

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
            res = ProtocolResult(name, "FAIL", f"runner error: {_describe(exc)}")
        res.ms = int((time.monotonic() - t0) * 1000)
        if res.status == "PENDING":
            res.status, problems = evaluate(res)
            res.reason = "; ".join(problems + list(res.errors))
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

# ---------------------------------------------------------------------------------------------
# Real runners: real sources -> real Pipeline/RawStore -> real pseudonymizer/serializer ->
# schema-validated envelope (what the outbox would hold). Evidence = that envelope's bytes.
# ---------------------------------------------------------------------------------------------
import contextlib
import hashlib
import socket
import tempfile
from datetime import datetime, timezone
from pathlib import Path

TZ = "Asia/Kolkata"
HOST = "db-prod-02"
EXAMPLE_CFG = Path(__file__).with_name("collector.example.yaml")
L1 = f"ERROR db connect failed {MARKERS['db_conn']} key={MARKERS['canary']}"


def _deps():
    from types import SimpleNamespace as NS
    from veilops.collector.config import CollectorConfig
    from veilops.collector.contracts import SourceBus
    from veilops.collector.pipeline.rawstore import RawStore
    from veilops.collector.pipeline.runner import Pipeline
    from veilops.collector.privacy.pseudonymizer import Pseudonymizer, PseudonymStore
    from veilops.collector.privacy.serializer import RecordSerializer, SerializationError
    from veilops.collector.sources.stream import StreamMapper, StreamSource
    from veilops.collector.sources.syslog import SyslogSource
    from veilops.schema.envelope import Envelope
    from veilops.schema.policy import load_policy
    return NS(CollectorConfig=CollectorConfig, SourceBus=SourceBus, RawStore=RawStore,
              Pipeline=Pipeline, Pseudonymizer=Pseudonymizer, PseudonymStore=PseudonymStore,
              RecordSerializer=RecordSerializer, SerializationError=SerializationError,
              StreamMapper=StreamMapper, StreamSource=StreamSource, SyslogSource=SyslogSource,
              Envelope=Envelope, load_policy=load_policy)


def _cfg(d):
    return d.CollectorConfig.load(str(EXAMPLE_CFG))


def _n_auth(cfg) -> int:
    return int(cfg.auth.bruteforce_failures) + 3


def _syslog_lines(cfg):
    out = [f"<14>Nov 21 04:12:07 {HOST} app[1]: {L1}"]
    for i in range(_n_auth(cfg)):
        out.append(f"<14>Nov 21 04:12:07 {HOST} sshd[1]: Failed password for "
                   f"{MARKERS['username']} from {MARKERS['source_ip']} port {5000 + i} ssh2")
    return out


def _stream_records(cfg):
    recs = [{"kind": "log", "host": HOST, "message": L1, "level": "error"}]
    for _ in range(_n_auth(cfg)):
        recs.append({"kind": "auth", "host": HOST, "user": MARKERS["username"],
                     "src_ip": MARKERS["source_ip"], "outcome": "failure"})
    return recs


def _drain(q):
    items = []
    while not q.empty():
        items.append(q.get_nowait())
    return items


def _envelope_bytes(d, records, res) -> bytes:
    import uuid_utils
    policy = d.load_policy()
    dumped = [r.model_dump(mode="json") for r in records]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    env = {
        "schema_version": "1.0", "payload_id": str(uuid_utils.uuid7()), "tenant_id": "t_acme",
        "collector_id": "col_blr_01", "region": "in", "seq": 1, "sent_at": now,
        "policy": {"version": policy.version, "hash": policy.hash},
        "chain": {"prev_hash": "sha256:" + "0" * 64,
                  "payload_hash": "sha256:" + hashlib.sha256(json.dumps(dumped).encode()).hexdigest()},
        "records": dumped,
    }
    # strict validation from JSON, exactly as the cloud would parse it
    body = json.dumps(env).encode("utf-8")
    try:
        d.Envelope.model_validate_json(body)
    except Exception as exc:
        res.errors.append("envelope check skipped: " + _describe(exc))
    return body


def _fill_evidence(res, d, signals, windows) -> None:
    ser = d.RecordSerializer(d.load_policy(), d.Pseudonymizer(b"\x07" * 32, d.PseudonymStore()))
    records = []
    for w in windows:
        try:
            records.append(ser.serialize_window(w))
        except d.SerializationError as exc:
            res.errors.append(f"{exc.record_type}: {';'.join(exc.problems)}")
    for s in signals:
        try:
            records.append(ser.serialize_signal(s))
        except d.SerializationError as exc:
            res.errors.append(f"{exc.record_type}: {';'.join(exc.problems)}")
    res.auth_checked = True
    res.category_seen = any(r.type == "alert" and r.template_id == "T_LOG_CATEGORY" for r in records)
    res.security_summary_seen = any(r.type == "security_summary" for r in records)
    if records:
        body = _envelope_bytes(d, records, res)
        res.outbound_payloads = len(records)
        res.marker_hits = find_markers(body)
        res.tripwire_hits = len(scan_bytes(body))


async def _noop():
    return None


async def _collect(name, d, cfg, source, feed, tmp):
    n_raw = 1 + _n_auth(cfg)
    bus = d.SourceBus()
    store = d.RawStore(str(Path(tmp) / "raw.db"))
    await store.open()
    pipe = d.Pipeline(cfg, bus, store)
    tasks = [asyncio.create_task(pipe.flusher()), asyncio.create_task(source.run(pipe.ingest))]
    res = ProtocolResult(name)
    try:
        await asyncio.sleep(0.6)  # let the source start listening / seek to end of file
        await feed()
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            for t in tasks:
                if t.done() and not t.cancelled() and t.exception() is not None:
                    raise t.exception()
            if await store.count() >= n_raw and bus.signals.qsize() >= 2:
                break
            await asyncio.sleep(0.1)
        await asyncio.sleep(0.7)  # let the flusher commit and the last signals land
        rows = await store.recent(limit=1000, reveal=True)
        res.raw_secret_stored_locally = any(
            MARKERS["db_password"] in r["raw"] or MARKERS["canary"] in r["raw"] for r in rows)
        _fill_evidence(res, d, _drain(bus.signals), _drain(bus.windows))
    finally:
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await store.close()
    return res


async def run_file_tail() -> ProtocolResult:
    d = _deps()
    cfg = _cfg(d)
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        log_path = Path(tmp) / "auth.log"
        log_path.write_text("", encoding="utf-8")
        src = d.SyslogSource({"files": [str(log_path)]}, TZ, HOST)

        async def feed():
            with log_path.open("a", encoding="utf-8") as fh:
                for line in _syslog_lines(cfg):
                    fh.write(line + "\n")

        return await _collect("file_tail", d, cfg, src, feed, tmp)


async def run_syslog_udp() -> ProtocolResult:
    d = _deps()
    cfg = _cfg(d)
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        src = d.SyslogSource({"udp_port": port, "files": []}, TZ, HOST)

        async def feed():
            sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                for line in _syslog_lines(cfg):
                    sender.sendto(line.encode("utf-8"), ("127.0.0.1", port))
                    await asyncio.sleep(0.01)
            finally:
                sender.close()

        return await _collect("syslog_udp", d, cfg, src, feed, tmp)


def _http_handler(mode, records, writers):
    async def handler(reader, writer):
        writers.append(writer)
        try:
            await reader.readuntil(b"\r\n\r\n")
            if mode == "sse":
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
                             b"Cache-Control: no-cache\r\nConnection: close\r\n\r\n")
                for rec in records:
                    writer.write(b"data: " + json.dumps(rec).encode("utf-8") + b"\n\n")
                await writer.drain()
                await reader.read()  # keep the stream open until the client disconnects
            else:
                body = json.dumps(records).encode("utf-8")
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                             b"Content-Length: " + str(len(body)).encode() +
                             b"\r\nConnection: close\r\n\r\n" + body)
                await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
    return handler


async def _run_http(name, mode, driver) -> ProtocolResult:
    try:
        import httpx  # noqa: F401
    except ImportError:
        return ProtocolResult(name, "NOT_SUPPORTED", "httpx not installed")
    d = _deps()
    cfg = _cfg(d)
    writers: list = []
    server = await asyncio.start_server(_http_handler(mode, _stream_records(cfg), writers),
                                        "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            spec = {"driver": driver, "url": f"http://127.0.0.1:{port}/stream"}
            if driver == "http_poll":
                spec["interval_s"] = 30
            src = d.StreamSource(spec, d.StreamMapper(None, TZ))
            return await _collect(name, d, cfg, src, _noop, tmp)
    finally:
        for w in writers:
            w.close()
        server.close()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(server.wait_closed(), 2)


async def run_http_sse() -> ProtocolResult:
    return await _run_http("http_sse", "sse", "sse")


async def run_http_poll() -> ProtocolResult:
    return await _run_http("http_poll", "poll", "http_poll")


async def run_websocket() -> ProtocolResult:
    try:
        try:
            from websockets.asyncio.server import serve
        except ImportError:
            from websockets import serve
    except ImportError:
        return ProtocolResult("websocket", "NOT_SUPPORTED", "websockets not installed")
    d = _deps()
    cfg = _cfg(d)
    records = _stream_records(cfg)

    async def handler(ws):
        for rec in records:
            await ws.send(json.dumps(rec))
        await asyncio.sleep(1.5)

    async with serve(handler, "127.0.0.1", 0) as server:
        port = next(iter(server.sockets)).getsockname()[1]
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            src = d.StreamSource({"driver": "websocket", "url": f"ws://127.0.0.1:{port}"},
                                 d.StreamMapper(None, TZ))
            return await _collect("websocket", d, cfg, src, _noop, tmp)


async def run_kafka() -> ProtocolResult:
    try:
        import aiokafka  # noqa: F401
    except ImportError:
        return ProtocolResult("kafka", "NOT_SUPPORTED",
                              "aiokafka not installed (collector has a kafka driver)")
    return ProtocolResult("kafka", "SKIPPED",
                          "aiokafka installed but no Kafka broker is available in this environment")


RUNNERS.update({
    "file_tail": run_file_tail, "syslog_udp": run_syslog_udp, "http_sse": run_http_sse,
    "websocket": run_websocket, "http_poll": run_http_poll, "kafka": run_kafka,
})

def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(prog="protocol_proof")
    parser.add_argument("--only", nargs="*", choices=PROTOCOLS)
    args = parser.parse_args(argv)
    results = asyncio.run(run_matrix(args.only))
    print(format_table(results))
    return 1 if any(r.status == "FAIL" for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
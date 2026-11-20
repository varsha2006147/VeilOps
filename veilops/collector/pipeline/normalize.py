"""Stage 2: RawEvent -> MetricSample | AuthEvent | LogEvent.

Sources put canonical keys into RawEvent.fields:
  metric: {"kind":"metric","entity","entity_kind","metric","value","unit"?}
  auth:   {"kind":"auth","entity","outcome","principal","source_addr"}   or a raw syslog line
  log:    {"kind":"log","entity","level","message"}                     or a raw syslog line
  line:   {"kind":"line","entity","line"}  -> parsed here (sshd/PAM/app logs)
"""
from __future__ import annotations

import re
from typing import Iterable

from ..contracts import AuthEvent, LogEvent, MetricSample, RawEvent

# Aliases seen in common feeds -> canonical name, unit
METRIC_ALIASES: dict[str, tuple[str, str]] = {
    "cpu": ("cpu.util_pct", "pct"), "cpu_pct": ("cpu.util_pct", "pct"), "cpu_usage": ("cpu.util_pct", "pct"),
    "cpu.util_pct": ("cpu.util_pct", "pct"),
    "mem": ("mem.util_pct", "pct"), "memory": ("mem.util_pct", "pct"), "mem_pct": ("mem.util_pct", "pct"),
    "memory_usage": ("mem.util_pct", "pct"), "mem.util_pct": ("mem.util_pct", "pct"),
    "disk": ("disk.util_pct", "pct"), "disk_pct": ("disk.util_pct", "pct"), "disk_usage": ("disk.util_pct", "pct"),
    "disk.util_pct": ("disk.util_pct", "pct"), "iowait": ("disk.io_wait_pct", "pct"),
    "disk.io_wait_pct": ("disk.io_wait_pct", "pct"),
    "latency": ("net.latency_ms", "ms"), "latency_ms": ("net.latency_ms", "ms"), "rtt": ("net.latency_ms", "ms"),
    "net.latency_ms": ("net.latency_ms", "ms"),
    "packet_loss": ("net.loss_pct", "pct"), "loss": ("net.loss_pct", "pct"), "loss_pct": ("net.loss_pct", "pct"),
    "net.loss_pct": ("net.loss_pct", "pct"),
    "bw_in": ("net.bw_in_mbps", "mbps"), "bandwidth_in": ("net.bw_in_mbps", "mbps"),
    "net.bw_in_mbps": ("net.bw_in_mbps", "mbps"),
    "bw_out": ("net.bw_out_mbps", "mbps"), "bandwidth_out": ("net.bw_out_mbps", "mbps"),
    "net.bw_out_mbps": ("net.bw_out_mbps", "mbps"),
    "up": ("svc.up", "bool"), "status": ("svc.up", "bool"), "availability": ("svc.up", "bool"),
    "svc.up": ("svc.up", "bool"),
    "response_ms": ("svc.resp_ms", "ms"), "resp_ms": ("svc.resp_ms", "ms"), "svc.resp_ms": ("svc.resp_ms", "ms"),
    "reachable": ("net.reachable", "bool"), "connectivity": ("net.reachable", "bool"),
    "net.reachable": ("net.reachable", "bool"),
    "req_rate": ("load.req_rate", "rps"), "rps": ("load.req_rate", "rps"), "requests": ("load.req_rate", "rps"),
    "load.req_rate": ("load.req_rate", "rps"),
}

_TRUE = {"up", "true", "ok", "1", "yes", "online", "reachable"}
_FALSE = {"down", "false", "fail", "failed", "0", "no", "offline", "unreachable"}

# --- auth parsing (sshd, PAM, generic app JSON-ish lines) ---
_AUTH_FAIL = [
    re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<src>[\d.:a-fA-F]+)"),
    re.compile(r"authentication failure;.*rhost=(?P<src>\S+)\s+user=(?P<user>\S+)"),
    re.compile(r"Invalid user (?P<user>\S+) from (?P<src>[\d.:a-fA-F]+)"),
    re.compile(r"login failed.*user[=: ]+(?P<user>[^\s,]+).*(?:ip|src|from)[=: ]+(?P<src>[\d.:a-fA-F]+)", re.I),
]
_AUTH_OK = [
    re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<src>[\d.:a-fA-F]+)"),
    re.compile(r"login (?:succeeded|success).*user[=: ]+(?P<user>[^\s,]+).*(?:ip|src|from)[=: ]+(?P<src>[\d.:a-fA-F]+)", re.I),
]

# --- log categorization: message text never leaves; only the category does ---
_CATEGORIES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(db|database|postgres|mysql|jdbc).*(connect|connection).*(fail|refused|error|timeout)", re.I),
     "db.connect_error"),
    (re.compile(r"out of memory|oom[- ]?kill", re.I), "sys.oom"),
    (re.compile(r"no space left|disk full", re.I), "sys.disk_full"),
    (re.compile(r"timed? ?out|timeout", re.I), "app.timeout"),
    (re.compile(r"(connection )?refused|unreachable", re.I), "net.conn_refused"),
    (re.compile(r"\b5\d\d\b.*(error|status)|internal server error", re.I), "app.http_5xx"),
    (re.compile(r"segfault|panic|fatal|core dumped", re.I), "app.crash"),
    (re.compile(r"certificate|tls|ssl", re.I), "sec.tls_error"),
    (re.compile(r"permission denied|unauthori[sz]ed|forbidden", re.I), "sec.access_denied"),
]
_LEVEL = re.compile(r"\b(EMERG|ALERT|CRIT(?:ICAL)?|ERR(?:OR)?|WARN(?:ING)?|NOTICE|INFO|DEBUG)\b", re.I)


def categorize(message: str) -> str | None:
    for pat, cat in _CATEGORIES:
        if pat.search(message):
            return cat
    return None


def _level(message: str, default: str = "info") -> str:
    m = _LEVEL.search(message)
    if not m:
        return default
    v = m.group(1).upper()
    return {"ERR": "error", "ERROR": "error", "WARN": "warning", "WARNING": "warning",
            "CRIT": "critical", "CRITICAL": "critical", "EMERG": "critical", "ALERT": "critical"}.get(v, v.lower())


def to_float(metric: str, value) -> float | None:
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, (int, float)):
        return float(value)
    s = str(value).strip().lower().rstrip("%")
    if s in _TRUE:
        return 1.0
    if s in _FALSE:
        return 0.0
    try:
        return float(s)
    except ValueError:
        return None


def parse_line(entity: str, line: str, ev: RawEvent) -> list[AuthEvent | LogEvent]:
    for pat in _AUTH_FAIL:
        m = pat.search(line)
        if m:
            return [AuthEvent("failure", m["user"], m["src"], entity, ev.event_ts, ev.source_tz)]
    for pat in _AUTH_OK:
        m = pat.search(line)
        if m:
            return [AuthEvent("success", m["user"], m["src"], entity, ev.event_ts, ev.source_tz)]
    lvl = _level(line)
    cat = categorize(line)
    if cat is None and lvl in ("error", "critical"):
        cat = "app.error"
    if cat is None:
        return []          # routine info lines stay local, produce nothing
    return [LogEvent(entity, cat, lvl, ev.event_ts, ev.source_tz)]


def normalize(ev: RawEvent, raw_id: int | None = None) -> list[MetricSample | AuthEvent | LogEvent]:
    f = ev.fields
    kind = f.get("kind")
    entity = str(f.get("entity") or "unknown")
    out: list[MetricSample | AuthEvent | LogEvent] = []

    if kind == "multi":
        for item in f.get("items", []):
            sub = RawEvent(ev.source, ev.event_ts, ev.source_tz, ev.raw, item, ev.received_at)
            out.extend(normalize(sub, raw_id))
        return out
    if kind == "metric":
        name = str(f.get("metric", "")).strip()
        canon = METRIC_ALIASES.get(name) or METRIC_ALIASES.get(name.lower())
        if not canon:
            return []          # unknown metrics are dropped (default deny)
        metric, unit = canon
        value = to_float(metric, f.get("value"))
        if value is None:
            return []
        if unit == "pct" and 0 <= value <= 1.0 and f.get("fraction"):
            value *= 100
        ek = f.get("entity_kind") or ("link" if metric.startswith("net.") and f.get("link") else "host")
        if metric.startswith("svc."):
            ek = "service"
        out.append(MetricSample(entity, ek, metric, unit, value, ev.event_ts, ev.source_tz, raw_id))
    elif kind == "auth":
        outcome = str(f.get("outcome", "failure")).lower()
        outcome = "success" if outcome in ("success", "ok", "accepted", "true") else "failure"
        out.append(AuthEvent(outcome, str(f.get("principal", "?")), str(f.get("source_addr", "?")),
                             entity, ev.event_ts, ev.source_tz, raw_id))
    elif kind == "log":
        msg = str(f.get("message", ""))
        # a log line may itself be an auth line
        parsed = parse_line(entity, msg, ev)
        if parsed and isinstance(parsed[0], AuthEvent):
            out.extend(parsed)
        else:
            lvl = str(f.get("level") or _level(msg)).lower()
            lvl = {"err": "error", "warn": "warning", "crit": "critical"}.get(lvl, lvl)
            cat = f.get("category") or categorize(msg) or ("app.error" if lvl in ("error", "critical") else None)
            if cat:
                out.append(LogEvent(entity, str(cat), lvl, ev.event_ts, ev.source_tz))
    elif kind == "line":
        out.extend(parse_line(entity, str(f.get("line", "")), ev))

    for o in out:
        o.raw_id = raw_id
    return out


def normalize_many(events: Iterable[RawEvent]) -> list:
    res = []
    for e in events:
        res.extend(normalize(e))
    return res

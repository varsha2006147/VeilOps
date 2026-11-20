"""Canary tripwire: a self-contained, high-confidence secret scanner shared by BOTH tiers.

* Collector side: the egress guard (Gate 3) can use it as an extra check on outbound bytes.
* SaaS side: regional ingest runs it on the raw request body of every authenticated payload,
  BEFORE schema validation. A hit means something secret-looking crossed the trust boundary.

Design rules:
* Independent of veilops.collector.privacy.redactor on purpose (defence in depth: a bug in one
  scanner must not blind the other).
* Near-zero false positives: a hit rejects a payload and raises a security alert, so the rule
  set is deliberately limited to high-confidence patterns. There is NO generic entropy rule
  (UUIDs and hashes in every payload could trip it).
* Results carry only a rule name and a canary id. Matched text is never returned or logged.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Iterator

CANARY_MARKER = "VEILOPSCANARY"


@dataclass(frozen=True)
class Canary:
    canary_id: str    # "c01" .. "c05"; the two digits also appear after the marker in `value`
    value: str        # the fake secret planted in the local environment
    plant_point: str  # where it is planted == which leak path it tests


CANARIES: "tuple[Canary, ...]" = (
    Canary("c01", "AKIAVEILOPSCANARY01", "cloud access key inside a log message body"),
    Canary(
        "c02",
        "postgres://canary:VEILOPSCANARY02@canary-db.internal:5432/app",
        "connection string inside a log message body",
    ),
    Canary("c03", "canary-VEILOPSCANARY03@example.invalid", "username field of failed-login events"),
    Canary("c04", "Bearer VEILOPSCANARY04", "Authorization header text inside a log line"),
    Canary("c05", "canary-host-VEILOPSCANARY05.internal", "hostname field"),
)


def canary_by_id(canary_id: str) -> "Canary | None":
    for canary in CANARIES:
        if canary.canary_id == canary_id:
            return canary
    return None


def canary_values() -> "tuple[str, ...]":
    return tuple(c.value for c in CANARIES)


@dataclass(frozen=True)
class TripwireHit:
    rule: str                        # rule name only; never the matched text
    canary_id: "str | None" = None   # set only when rule == "canary" and an id was present


_RULES: "tuple[tuple[str, re.Pattern[str]], ...]" = (
    ("canary", re.compile(r"VEILOPSCANARY(\d{2})?", re.IGNORECASE)),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    (
        "jwt",
        re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"),
    ),
    (
        "aws_access_key",
        re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])"),
    ),
    (
        "github_token",
        re.compile(
            r"(?<![A-Za-z0-9_])(?:(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}"
            r"|github_pat_[A-Za-z0-9_]{22,255})(?![A-Za-z0-9_])"
        ),
    ),
    ("slack_token", re.compile(r"(?<![A-Za-z0-9])xox[abprs]-[A-Za-z0-9-]{10,}")),
    ("bearer_token", re.compile(r"\bBearer[ \t]+[A-Za-z0-9._~+/=-]{6,}", re.IGNORECASE)),
    (
        "secret_assignment",
        re.compile(
            r"""(?:password|passwd|pwd|secret|token|api[_-]?key)["']?[ \t]*[=:][ \t]*["']?\S+""",
            re.IGNORECASE,
        ),
    ),
    (
        "conn_string",
        re.compile(r"(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]*://[^\s:/@]+:[^\s@]+@\S+"),
    ),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    (
        "ipv4",
        re.compile(
            r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?!\d)(?!\.\d)"
        ),
    ),
)

TRIPWIRE_RULES: "tuple[str, ...]" = tuple(name for name, _ in _RULES)


def scan_text(text: str) -> "list[TripwireHit]":
    """Return de-duplicated hits in rule order (the canary rule is first)."""
    hits: "list[TripwireHit]" = []
    seen: "set[TripwireHit]" = set()
    for rule, pattern in _RULES:
        for match in pattern.finditer(text):
            canary_id = None
            if rule == "canary" and match.group(1):
                canary_id = "c" + match.group(1)
            hit = TripwireHit(rule, canary_id)
            if hit not in seen:
                seen.add(hit)
                hits.append(hit)
    return hits


def _walk_strings(obj: object) -> "Iterator[str]":
    stack = [obj]
    while stack:
        current = stack.pop()
        if isinstance(current, str):
            yield current
        elif isinstance(current, dict):
            for key, value in current.items():
                if isinstance(key, str):
                    yield key
                stack.append(value)
        elif isinstance(current, list):
            stack.extend(current)


def scan_bytes(body: bytes) -> "list[TripwireHit]":
    """Scan a raw request/payload body. Also scans the JSON-unescaped strings, so a secret
    hidden behind \\uXXXX escapes is still found."""
    text = body.decode("utf-8", errors="replace")
    hits = scan_text(text)
    try:
        obj = json.loads(text)
    except (ValueError, RecursionError):
        return hits
    extra = "\n".join(_walk_strings(obj))
    if extra:
        for hit in scan_text(extra):
            if hit not in hits:
                hits.append(hit)
    return hits


def first_hit(body: bytes) -> "TripwireHit | None":
    hits = scan_bytes(body)
    return hits[0] if hits else None

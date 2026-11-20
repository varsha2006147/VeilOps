"""Gate 1: fail-closed local secret and sensitive-data redactor.

Scans and scrubs private keys, JWTs, cloud/API tokens, connection strings,
password assignments, emails, and financial/PII identifiers from text and objects
before egress.
"""
from __future__ import annotations

import re
from typing import Any

# Ordered redaction patterns
# Each tuple is (Category, Compiled Regex, Replacement Format or Marker)
_SECRET_RULES: list[tuple[str, re.Pattern[str]]] = [
    # 1. Private keys / PEM blocks
    ("private_key", re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"
    )),
    # 2. Connection strings with credentials (e.g., postgres://user:password@host:port/db)
    ("connection_string", re.compile(
        r"\b([a-zA-Z][a-zA-Z0-9+.-]*://[^:\s/]+):[^@\s/]+(@[^\s]+)"
    )),
    # 3. AWS Access Keys
    ("aws_key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    # 4. Bearer tokens in headers or strings
    ("bearer_token", re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/-]{10,}")),
    # 5. JWT tokens
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    # 6. GitHub / Slack / Generic API tokens
    ("api_token", re.compile(
        r"\b(?:gh[pousr]_[A-Za-z0-9_]{36,}|xox[baprs]-[A-Za-z0-9_-]{10,}|glpat-[A-Za-z0-9_-]{20,})\b"
    )),
    # 7. Password / secret / token assignments (e.g. password=secret, api_key: "abc")
    ("password_assignment", re.compile(
        r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|client[_-]?secret|auth[_-]?token)(\s*[=:]\s*[\"']?)[^\s,\"';]{4,}([\"']?)"
    )),
    # 8. Email addresses
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")),
    # 9. Credit card / payment numbers (13-19 digits, formatted with spaces or dashes)
    ("credit_card", re.compile(r"\b(?:\d{4}[ -]?){3}\d{4}\b")),
    # 10. SSN patterns
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
]


def redact_text(text: str, marker: str = "[REDACTED]") -> str:
    """Scrub secrets and sensitive strings from a text value, replacing them with marker."""
    if not isinstance(text, str) or not text:
        return text

    out = text
    for name, pattern in _SECRET_RULES:
        if name == "connection_string":
            out = pattern.sub(rf"\1:{marker}\2", out)
        elif name == "password_assignment":
            out = pattern.sub(rf"\1\2{marker}\3", out)
        elif name == "bearer_token":
            out = pattern.sub(rf"\1{marker}", out)
        else:
            out = pattern.sub(marker, out)
    return out


def redact_with_report(text: str, marker: str = "[REDACTED]") -> tuple[str, dict[str, int]]:
    """Scrub secrets and return a tuple of (redacted_text, {category: count})."""
    if not isinstance(text, str) or not text:
        return text, {}

    counts: dict[str, int] = {}
    out = text
    for name, pattern in _SECRET_RULES:
        matches = len(pattern.findall(out))
        if matches > 0:
            counts[name] = counts.get(name, 0) + matches
            if name == "connection_string":
                out = pattern.sub(rf"\1:{marker}\2", out)
            elif name == "password_assignment":
                out = pattern.sub(rf"\1\2{marker}\3", out)
            elif name == "bearer_token":
                out = pattern.sub(rf"\1{marker}", out)
            else:
                out = pattern.sub(marker, out)
    return out, counts


def contains_secret(text: str) -> bool:
    """Return True if text contains any recognized secret or sensitive pattern."""
    if not isinstance(text, str) or not text:
        return False
    return any(pattern.search(text) is not None for _, pattern in _SECRET_RULES)


def redact_obj(obj: Any, marker: str = "[REDACTED]") -> Any:
    """Recursively scrub secrets from strings, dictionaries, lists, sets, and tuples."""
    if isinstance(obj, str):
        return redact_text(obj, marker=marker)
    if isinstance(obj, dict):
        cleaned: dict[Any, Any] = {}
        for k, v in obj.items():
            cleaned_key = redact_text(k, marker=marker) if isinstance(k, str) else k
            cleaned[cleaned_key] = redact_obj(v, marker=marker)
        return cleaned
    if isinstance(obj, list):
        return [redact_obj(elem, marker=marker) for elem in obj]
    if isinstance(obj, tuple):
        return tuple(redact_obj(elem, marker=marker) for elem in obj)
    if isinstance(obj, set):
        return {redact_obj(elem, marker=marker) for elem in obj}
    return obj

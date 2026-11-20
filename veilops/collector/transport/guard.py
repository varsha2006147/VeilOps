"""Fail-closed pre-egress payload scanner and canary detector."""
from __future__ import annotations

import json
from typing import Any, Iterable

from veilops.collector.privacy.redactor import contains_secret, redact_text

DEFAULT_CANARY_TOKENS: tuple[str, ...] = (
    "AKIA",
    "ghp_",
    "sk_live_",
    "-----BEGIN",
    "eyJhbGciOi",
    "postgres://",
    "password=",
)


class EgressGuardError(ValueError):
    """Raised when an outbound payload fails sensitive pattern or canary verification.

    Error messages contain category details only—never raw secret content.
    """


class EgressGuard:
    """Pre-egress verification guard rail preventing network leakage of sensitive data."""

    def __init__(
        self,
        canary_tokens: Iterable[str] | None = None,
        *,
        enforce_secret_patterns: bool = True,
    ) -> None:
        self.canary_tokens: set[str] = set(canary_tokens or DEFAULT_CANARY_TOKENS)
        self.enforce_secret_patterns = enforce_secret_patterns
        self.blocked_counter = 0

    def add_canary(self, token: str) -> None:
        """Register a canary marker string for detection."""
        if token:
            self.canary_tokens.add(str(token))

    def _check_string(self, text: str, path: str = "root") -> None:
        """Check a single string for canary tokens or secret patterns."""
        if not text:
            return

        for canary in self.canary_tokens:
            if canary in text:
                self.blocked_counter += 1
                raise EgressGuardError(
                    f"Egress blocked: canary token detected at {path} (fail-closed)"
                )

        if self.enforce_secret_patterns and contains_secret(text):
            self.blocked_counter += 1
            raise EgressGuardError(
                f"Egress blocked: secret pattern detected at {path} (fail-closed)"
            )

    def _traverse(self, obj: Any, path: str = "payload") -> None:
        """Recursively scan data structures for sensitive content."""
        if isinstance(obj, str):
            self._check_string(obj, path)
        elif isinstance(obj, dict):
            for k, v in obj.items():
                k_str = str(k)
                self._check_string(k_str, f"{path}.key[{k_str}]")
                self._traverse(v, f"{path}.{k_str}")
        elif isinstance(obj, (list, tuple, set)):
            for i, item in enumerate(obj):
                self._traverse(item, f"{path}[{i}]")

    def scan_and_guard_payload(self, payload_obj: Any) -> None:
        """Inspect a payload object, dict, or JSON string before network egress.

        Raises EgressGuardError if any forbidden pattern or canary token is present.
        """
        if isinstance(payload_obj, (bytes, bytearray)):
            try:
                payload_str = payload_obj.decode("utf-8")
                self._check_string(payload_str, "payload_bytes")
                try:
                    parsed = json.loads(payload_str)
                    self._traverse(parsed, "payload_json")
                except Exception:
                    pass
            except UnicodeDecodeError:
                pass
            return

        if isinstance(payload_obj, str):
            self._check_string(payload_obj, "payload_text")
            try:
                parsed = json.loads(payload_obj)
                self._traverse(parsed, "payload_json")
            except Exception:
                pass
            return

        self._traverse(payload_obj, "payload")

    def scrub_or_reject_text(self, text: str, *, reject: bool = True) -> str:
        """Verify text; either reject immediately on secret or return scrubbed text."""
        for canary in self.canary_tokens:
            if canary in text:
                self.blocked_counter += 1
                raise EgressGuardError("Egress blocked: canary token in text")

        if contains_secret(text):
            self.blocked_counter += 1
            if reject:
                raise EgressGuardError("Egress blocked: secret pattern detected in text")
            return redact_text(text)

        return text

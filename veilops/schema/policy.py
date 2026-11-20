"""Policy definition and loader for default-deny outbound record serialization."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import rfc8785
import yaml


class PolicyError(ValueError, KeyError):
    """Raised when a policy is invalid, malformed, or references unknown record types."""


@dataclass(frozen=True)
class RecordTypePolicy:
    """Allow-list configuration for a specific record type."""

    fields: tuple[str, ...]
    constraints: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Policy:
    """Loaded and validated outbound egress policy."""

    version: str
    record_types: dict[str, RecordTypePolicy]
    redaction: dict[str, Any] = field(default_factory=dict)
    egress: dict[str, Any] = field(default_factory=dict)
    hash: str = ""
    policy_hash: str = ""

    def allowed_fields(self, record_type: str, include_type: bool = False) -> tuple[str, ...]:
        """Return the allowed fields for the specified record type.

        By default, excludes 'type' because record builders (e.g. RecordSerializer)
        pre-populate 'type' on the record and only look up producers for data fields.
        """
        if record_type not in self.record_types:
            raise PolicyError(f"unknown or disallowed record type: {record_type!r}")
        raw = self.record_types[record_type].fields
        if include_type:
            return raw
        return tuple(f for f in raw if f != "type")


def _compute_policy_hash(raw_text: str | bytes, data: dict[str, Any]) -> str:
    """Compute deterministic SHA-256 digest of normalized policy content."""
    try:
        norm = {
            "version": str(data.get("version", "")),
            "record_types": {
                k: list(v.get("fields", []))
                for k, v in sorted(data.get("record_types", {}).items())
            },
        }
        b = rfc8785.dumps(norm)
    except Exception:
        b = raw_text.encode("utf-8") if isinstance(raw_text, str) else raw_text
    return "sha256:" + hashlib.sha256(b).hexdigest()


def load_policy(path: str | Path | None = None) -> Policy:
    """Safely load and validate an egress policy YAML file."""
    if path is None:
        p = Path(__file__).parent / "policy.yaml"
    else:
        p = Path(path)

    if not p.is_file():
        raise FileNotFoundError(f"policy file not found: {p}")

    try:
        raw_text = p.read_text(encoding="utf-8")
        data = yaml.safe_load(raw_text)
    except Exception as exc:
        raise PolicyError(f"failed to read or parse policy file {p}: {exc}") from exc

    if not isinstance(data, dict):
        raise PolicyError(f"policy file {p} must define a YAML mapping, got {type(data).__name__}")

    if "version" not in data or not data["version"]:
        raise PolicyError("missing required policy key: 'version'")

    if "record_types" not in data or not isinstance(data["record_types"], dict) or not data["record_types"]:
        raise PolicyError("missing or empty required policy key: 'record_types'")

    record_types: dict[str, RecordTypePolicy] = {}
    for rt_name, rt_spec in data["record_types"].items():
        if not isinstance(rt_spec, dict):
            raise PolicyError(f"record type {rt_name!r} specification must be a mapping")
        fields_raw = rt_spec.get("fields")
        if not isinstance(fields_raw, (list, tuple)) or not fields_raw:
            raise PolicyError(f"record type {rt_name!r} must define a non-empty 'fields' list")
        record_types[rt_name] = RecordTypePolicy(
            fields=tuple(str(f) for f in fields_raw),
            constraints=dict(rt_spec.get("constraints") or {}),
        )

    digest = _compute_policy_hash(raw_text, data)
    return Policy(
        version=str(data["version"]),
        record_types=record_types,
        redaction=dict(data.get("redaction") or {}),
        egress=dict(data.get("egress") or {}),
        hash=digest,
        policy_hash=digest,
    )

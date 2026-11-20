"""Gate 2: positive-construction serializer.

Outbound wire records are BUILT field by field from the allow-list in policy.yaml
(default deny) -- never filtered from a raw object. Each record is then validated
by the strict Pydantic model (extra="forbid", strict=True). Any failure raises
SerializationError (fail closed). Error messages contain field names and error
types ONLY, never input values.
"""
from __future__ import annotations

import math
import re
from datetime import datetime, timezone
from typing import Any, Callable

import uuid_utils
from pydantic import ValidationError

from veilops.collector.contracts import LocalSignal, WindowAgg
from veilops.collector.privacy.pseudonymizer import PseudonymError, Pseudonymizer
from veilops.schema.policy import Policy
from veilops.schema.records import AlertRecord, MetricRecord, SecuritySummaryRecord, TopologyRecord

_PARAM_KEY_RE = re.compile(r"^[a-z_]{1,32}$")
_SECURITY_COUNT_KEYS = ("count", "failures", "failure_count", "attempts")
_MAX_LIST = 20
_MAX_EDGES = 500
# Collector (detect.py) rule names -> canonical schema categories. Canonical names pass through.
_SECURITY_CATEGORY_MAP = {
    "auth.spray": "auth.password_spray",
    "auth.stuffing": "auth.credential_stuffing",
}


class SerializationError(ValueError):
    def __init__(self, record_type: str, problems: "list[str]") -> None:
        self.record_type = record_type
        self.problems = list(problems)
        super().__init__(f"cannot serialize {record_type}: " + "; ".join(self.problems))


def _ts(record_type: str, dt: Any) -> str:
    if not isinstance(dt, datetime) or dt.tzinfo is None:
        raise SerializationError(record_type, ["event_ts:timezone_aware_datetime_required"])
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _template_id(rule: str) -> str:
    base = rule[len("threshold."):] if rule.startswith("threshold.") else rule
    return "T_" + re.sub(r"[^A-Z0-9]+", "_", base.upper()).strip("_")


def _clean_params(params: "dict[str, Any]") -> "dict[str, Any]":
    out: "dict[str, Any]" = {}
    for key, value in params.items():
        if not isinstance(key, str) or not _PARAM_KEY_RE.match(key):
            raise ValueError("bad param key")
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("bad param value")
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("non-finite param value")
        out[key] = value
    return out


def _security_count(params: "dict[str, Any]") -> int:
    for key in _SECURITY_COUNT_KEYS:
        value = params.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            return value
        if (
            isinstance(value, float)
            and math.isfinite(value)
            and value >= 0
            and value == int(value)
        ):
            return int(value)
    raise ValueError("no usable count param")


class RecordSerializer:
    def __init__(
        self,
        policy: Policy,
        pseudonymizer: Pseudonymizer,
        entity_kinds: "dict[str, str] | None" = None,
    ) -> None:
        self._policy = policy
        self._ps = pseudonymizer
        # real entity name -> "host" | "service" | "link"; learned from windows.
        self._kinds: "dict[str, str]" = dict(entity_kinds or {})

    def _build(
        self, record_type: str, sources: "dict[str, Callable[[], Any]]"
    ) -> "dict[str, Any]":
        record: "dict[str, Any]" = {"type": record_type}
        for name in self._policy.allowed_fields(record_type):
            producer = sources.get(name)
            if producer is None:
                raise SerializationError(record_type, [f"{name}:no_producer"])
            try:
                record[name] = producer()
            except SerializationError:
                raise
            except PseudonymError:
                raise SerializationError(record_type, [f"{name}:pseudonymization_failed"]) from None
            except (TypeError, ValueError, OverflowError):
                raise SerializationError(record_type, [f"{name}:bad_value"]) from None
        return record

    @staticmethod
    def _validate(model: Any, record_type: str, record: "dict[str, Any]") -> Any:
        try:
            return model.model_validate(record)
        except ValidationError as exc:
            problems = [
                ".".join(str(part) for part in err["loc"]) + ":" + err["type"]
                for err in exc.errors(
                    include_url=False, include_context=False, include_input=False
                )
            ]
            raise SerializationError(record_type, problems) from None

    def serialize_window(self, w: WindowAgg) -> MetricRecord:
        self._kinds[w.entity] = w.entity_kind
        sources: "dict[str, Callable[[], Any]]" = {
            "entity": lambda: self._ps.pseudonymize(w.entity_kind, w.entity),
            "entity_kind": lambda: w.entity_kind,
            "metric": lambda: w.metric,
            "unit": lambda: w.unit,
            "avg": lambda: float(w.avg),
            "min": lambda: float(w.min),
            "max": lambda: float(w.max),
            "p95": lambda: float(w.p95),
            "count": lambda: w.count,
            "window_s": lambda: w.window_s,
            "event_ts": lambda: _ts("metric", w.event_ts),
            "source_tz": lambda: w.source_tz,
        }
        record = self._build("metric", sources)
        return self._validate(MetricRecord, "metric", record)

    def serialize_signal(
        self, s: LocalSignal, alert_id: "str | None" = None
    ) -> "AlertRecord | SecuritySummaryRecord":
        if s.kind == "security":
            return self._security(s)
        if s.kind in ("threshold", "log_category"):
            return self._alert(s, alert_id)
        raise SerializationError("alert", ["kind:unsupported"])

    def _alert(self, s: LocalSignal, alert_id: "str | None") -> AlertRecord:
        # Unknown entity kinds fall back to "host" (documented limitation: a link/service
        # alert seen before any of its windows would get a different pseudonym).
        kind = (s.entity_kind if (s.entity_kind and s.entity_kind != "host") else None) or self._kinds.get(s.entity, "host")
        if s.kind == "log_category":
            rule = s.rule if s.rule.startswith("log.") else "log." + s.rule
            template = "T_LOG_CATEGORY"
        else:
            rule = s.rule
            template = s.template_id or _template_id(s.rule)
        sources: "dict[str, Callable[[], Any]]" = {
            "alert_id": lambda: alert_id or str(uuid_utils.uuid7()),
            "entity": lambda: self._ps.pseudonymize(kind, s.entity),
            "rule": lambda: rule,
            "severity": lambda: s.severity,
            "template_id": lambda: template,
            "params": lambda: _clean_params(s.params),
            "event_ts": lambda: _ts("alert", s.event_ts),
            "source_tz": lambda: s.source_tz,
        }
        record = self._build("alert", sources)
        return self._validate(AlertRecord, "alert", record)

    def _security(self, s: LocalSignal) -> SecuritySummaryRecord:
        sources: "dict[str, Callable[[], Any]]" = {
            "category": lambda: _SECURITY_CATEGORY_MAP.get(s.rule, s.rule),
            "severity": lambda: s.severity,
            "count": lambda: _security_count(s.params),
            "distinct_principals": lambda: len(set(s.subjects)),
            "distinct_sources": lambda: len(set(s.sources)),
            "principals": lambda: sorted(
                {self._ps.pseudonymize("principal", x) for x in s.subjects}
            )[:_MAX_LIST],
            "sources": lambda: sorted(
                {self._ps.pseudonymize("source", x) for x in s.sources}
            )[:_MAX_LIST],
            "risk_score": lambda: int(s.risk_score),
            "window_s": lambda: int(s.window_s),
            "event_ts": lambda: _ts("security_summary", s.event_ts),
            "source_tz": lambda: s.source_tz,
        }
        record = self._build("security_summary", sources)
        return self._validate(SecuritySummaryRecord, "security_summary", record)

    def serialize_topology(self, topo: Any, event_ts: datetime) -> TopologyRecord:
        """Dependency graph with every node pseudonymised exactly like its metrics (same kind + key)."""
        def edges() -> list:
            out = []
            for e in topo.edges:
                for name, kind in ((e.src, e.src_kind), (e.dst, e.dst_kind)):
                    self._kinds.setdefault(name, kind)  # alerts seen before metrics get the right prefix
                out.append({"src": self._ps.pseudonymize(e.src_kind, e.src),
                            "dst": self._ps.pseudonymize(e.dst_kind, e.dst), "rel": e.rel})
            if len(out) > _MAX_EDGES:
                raise ValueError("too many edges")
            return out
        sources: "dict[str, Callable[[], Any]]" = {
            "edges": edges,
            "event_ts": lambda: _ts("topology", event_ts),
        }
        record = self._build("topology", sources)
        return self._validate(TopologyRecord, "topology", record)

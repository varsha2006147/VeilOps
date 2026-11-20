"""The five record types that can appear inside an envelope."""
from typing import Annotated, Literal, Union

from pydantic import Field, field_validator

from .common import (
    EntityId, EntityKind, HealthState, MetricName, Num, ParamValue,
    PrincipalId, SafeText, Severity, SourceId, StrictModel, TimezoneName,
    UtcTimestamp, Uuid,
)
import re

_KEY_RE = re.compile(r"^[a-z_]{1,32}$")


class MetricRecord(StrictModel):
    type: Literal["metric"]
    entity: EntityId
    entity_kind: EntityKind
    metric: MetricName
    unit: Literal["pct", "ms", "mbps", "count", "bool", "rps"]
    avg: Num
    min: Num
    max: Num
    p95: Num
    count: int = Field(ge=1)
    window_s: int = Field(gt=0, le=3600)
    event_ts: UtcTimestamp
    source_tz: TimezoneName


class SecuritySummaryRecord(StrictModel):
    type: Literal["security_summary"]
    category: Literal["auth.bruteforce", "auth.password_spray",
                      "auth.credential_stuffing"]
    severity: Severity
    count: int = Field(ge=0)
    distinct_principals: int = Field(ge=0)
    distinct_sources: int = Field(ge=0)
    principals: list[PrincipalId] = Field(max_length=20)
    sources: list[SourceId] = Field(max_length=20)
    risk_score: int = Field(ge=0, le=100)
    window_s: int = Field(gt=0, le=3600)
    event_ts: UtcTimestamp
    source_tz: TimezoneName


class AlertRecord(StrictModel):
    type: Literal["alert"]
    alert_id: Uuid
    entity: EntityId
    rule: str = Field(pattern=r"^[a-z0-9_.]{1,64}$")
    severity: Severity
    template_id: str = Field(pattern=r"^T_[A-Z0-9_]{1,48}$")
    params: dict[str, ParamValue] = Field(max_length=16)  # numbers only
    event_ts: UtcTimestamp
    source_tz: TimezoneName

    @field_validator("params")
    @classmethod
    def _param_keys_safe(cls, v):
        for k in v:
            if not _KEY_RE.match(k):
                raise ValueError(f"unsafe param key: {k!r}")
        return v


class HealthRecord(StrictModel):
    type: Literal["health"]
    entity: EntityId
    state: HealthState
    reasons: list[SafeText] = Field(max_length=8)
    event_ts: UtcTimestamp


class TopologyEdge(StrictModel):
    src: EntityId
    dst: EntityId
    rel: Literal["runs_on", "depends_on", "routes_via"]


class TopologyRecord(StrictModel):
    type: Literal["topology"]
    edges: list[TopologyEdge] = Field(max_length=500)
    event_ts: UtcTimestamp


Record = Annotated[
    Union[MetricRecord, SecuritySummaryRecord, AlertRecord, HealthRecord,
          TopologyRecord],
    Field(discriminator="type"),
]

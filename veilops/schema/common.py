"""Shared building blocks for every VeilOps wire model.

Every model is STRICT (no type coercion), FORBIDS unknown fields and is
FROZEN (immutable). Identifier and timestamp types are regex-constrained so
that real hostnames, usernames, IPs or free text cannot validate.
"""
from typing import Annotated, Literal, Union

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

SCHEMA_VERSION = "1.0"
GENESIS_HASH = "sha256:" + "0" * 64  # prev_hash of the first ledger entry


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


# --- Pseudonymous identifiers (prefix + 10 hex chars of an HMAC) -----------
EntityId = Annotated[str, StringConstraints(pattern=r"^(h|svc|lnk)_[0-9a-f]{10}$")]
PrincipalId = Annotated[str, StringConstraints(pattern=r"^usr_[0-9a-f]{10}$")]
SourceId = Annotated[str, StringConstraints(pattern=r"^src_[0-9a-f]{10}$")]

# --- Platform identifiers ---------------------------------------------------
TenantId = Annotated[str, StringConstraints(pattern=r"^t_[a-z0-9_]{1,32}$")]
CollectorId = Annotated[str, StringConstraints(pattern=r"^col_[a-z0-9_]{1,32}$")]
Uuid = Annotated[str, StringConstraints(
    pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")]
UuidV7 = Annotated[str, StringConstraints(
    pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")]
Sha256Hash = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
Base64Sig = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9+/=_-]{16,200}$")]
VersionStr = Annotated[str, StringConstraints(pattern=r"^\d{1,3}\.\d{1,3}\.\d{1,3}$")]

# --- Time: RFC 3339 UTC with 'Z' and millisecond precision, plus IANA zone --
UtcTimestamp = Annotated[str, StringConstraints(
    pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")]
TimezoneName = Annotated[str, StringConstraints(
    pattern=r"^[A-Za-z][A-Za-z0-9_+\-]*(/[A-Za-z0-9_+\-]+){0,2}$")]

# --- Templated, charset-limited text (health reasons etc.) ------------------
# No '@', '!', quotes, '{', '}' ... so a connection string or token can't fit.
SafeText = Annotated[str, StringConstraints(
    pattern=r"^[A-Za-z0-9_.:<>=%/ ,()\-]{1,160}$")]

# --- Numbers: no NaN / Infinity ---------------------------------------------
Num = Annotated[float, Field(allow_inf_nan=False)]
ParamValue = Union[int, float]

# --- Enums -------------------------------------------------------------------
Region = Literal["in", "eu"]
Severity = Literal["info", "warning", "high", "critical"]
HealthState = Literal["excellent", "good", "fair", "poor"]
EntityKind = Literal["host", "service", "link"]
MetricName = Literal[
    "cpu.util_pct", "mem.util_pct", "disk.util_pct", "disk.io_wait_pct",
    "svc.up", "svc.resp_ms", "net.latency_ms", "net.loss_pct",
    "net.bw_in_mbps", "net.bw_out_mbps", "net.reachable", "load.req_rate",
]

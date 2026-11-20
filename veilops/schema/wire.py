"""Heartbeat, receipt and action contracts."""
from typing import Literal

from pydantic import Field

from .common import (
    Base64Sig, CollectorId, Num, Region, Sha256Hash, StrictModel, TenantId,
    UtcTimestamp, Uuid, UuidV7, VersionStr,
)


class SourcesOk(StrictModel):
    stream: bool
    host: bool
    probes: bool
    syslog: bool


class Heartbeat(StrictModel):
    collector_id: CollectorId
    tenant_id: TenantId
    ts: UtcTimestamp
    version: VersionStr
    uptime_s: int = Field(ge=0)
    cpu_pct: Num
    mem_mb: Num
    outbox_depth: int = Field(ge=0)
    oldest_unsent_s: Num
    last_acked_seq: int = Field(ge=0)
    policy_version: int = Field(ge=1)
    config_hash: Sha256Hash
    sources_ok: SourcesOk


class Receipt(StrictModel):
    payload_id: UuidV7
    payload_hash: Sha256Hash
    status: Literal["stored", "duplicate"]
    received_at: UtcTimestamp
    region: Region
    highest_contiguous_seq: int = Field(ge=0)
    sig: Base64Sig  # Ed25519 signature by the SaaS


ActionType = Literal[
    "INVESTIGATE_TOP_PROCESSES", "RESTART_SERVICE",
    "FAILOVER_TO_SECONDARY_LINK", "TEMP_BLOCK_SOURCE_15M",
]


class Action(StrictModel):
    action_id: Uuid
    type: ActionType
    target: str = Field(pattern=r"^(h|svc|lnk|src)_[0-9a-f]{10}$")
    params: dict[str, int | float] = Field(max_length=8)
    policy_ref: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,64}$")
    approved_by: Uuid
    expires_at: UtcTimestamp
    sig: Base64Sig  # Ed25519 signature by the SaaS


class ActionResult(StrictModel):
    status: Literal["dry_run_ok", "executed", "rolled_back", "vetoed"]
    local_policy_decision: Literal["allow", "veto"]
    health_before: str = Field(pattern=r"^(excellent|good|fair|poor)$")
    health_after: str = Field(pattern=r"^(excellent|good|fair|poor)$")
    ts: UtcTimestamp

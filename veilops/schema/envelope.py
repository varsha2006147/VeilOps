"""The envelope: the one JSON body POSTed to /v1/ingest."""
from pydantic import Field

from .common import (
    CollectorId, Region, Sha256Hash, StrictModel, TenantId, UtcTimestamp,
    UuidV7,
)
from .records import Record


class PolicyRef(StrictModel):
    version: int = Field(ge=1)
    hash: Sha256Hash


class ChainInfo(StrictModel):
    prev_hash: Sha256Hash      # GENESIS_HASH for seq == 1
    payload_hash: Sha256Hash   # sha256 of canonical JSON of the envelope
                               # WITHOUT this 'chain' block (see Step 7)


class Envelope(StrictModel):
    schema_version: str = Field(pattern=r"^\d{1,2}\.\d{1,2}$")
    payload_id: UuidV7
    tenant_id: TenantId
    collector_id: CollectorId
    region: Region
    seq: int = Field(ge=1)
    sent_at: UtcTimestamp
    policy: PolicyRef
    chain: ChainInfo
    records: list[Record] = Field(min_length=1, max_length=500)

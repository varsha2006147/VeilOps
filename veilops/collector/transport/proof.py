"""Egress Proof Panel backend service and snapshot generator."""
from __future__ import annotations

from typing import Any

from veilops.collector.transport.outbox import OutboxEntry, OutboxLedger


async def build_egress_proof_snapshot(
    ledger: OutboxLedger,
    *,
    redaction_metrics: dict[str, int] | None = None,
    recent_limit: int = 20,
) -> dict[str, Any]:
    """Inspect OutboxLedger and compile a structured, JSON-serializable egress proof snapshot."""
    chain_valid, chain_status = await ledger.verify_chain()
    stats = await ledger.stats()
    recent = await ledger.recent_entries(limit=recent_limit)

    recent_envelopes = [
        {
            "seq": e.seq,
            "payload_id": e.payload_id,
            "sent_at": e.sent_at,
            "record_count": e.record_count,
            "payload_hash": e.payload_hash,
            "prev_hash": e.prev_hash,
            "status": e.status,
            "attempts": e.attempts,
            "acked_at": e.acked_at,
            "has_receipt": bool(e.receipt_json),
        }
        for e in recent
    ]

    safe_redactions = {
        "secrets_scrubbed": 0,
        "canaries_blocked": 0,
        "patterns_verified": 0,
        **dict(redaction_metrics or {}),
    }

    return {
        "policy_version": ledger.policy_version,
        "policy_hash": ledger.policy_hash,
        "chain_valid": chain_valid,
        "chain_status": chain_status,
        "stats": stats,
        "recent_envelopes": recent_envelopes,
        "redaction_summary": safe_redactions,
    }


class EgressProofService:
    """Manages egress proof generation and safe telemetry counter accounting."""

    def __init__(
        self,
        ledger: OutboxLedger,
        *,
        redaction_metrics: dict[str, int] | None = None,
    ) -> None:
        self.ledger = ledger
        self.redaction_metrics = dict(
            redaction_metrics
            or {
                "secrets_scrubbed": 0,
                "canaries_blocked": 0,
                "patterns_verified": 0,
            }
        )

    def record_redaction(self, category: str = "secrets_scrubbed", count: int = 1) -> None:
        """Increment safe redaction/guard counter (never stores raw secret values)."""
        self.redaction_metrics[category] = self.redaction_metrics.get(category, 0) + count

    async def get_snapshot(self, limit: int = 20) -> dict[str, Any]:
        """Generate current immutable egress proof snapshot."""
        return await build_egress_proof_snapshot(
            self.ledger,
            redaction_metrics=self.redaction_metrics,
            recent_limit=limit,
        )

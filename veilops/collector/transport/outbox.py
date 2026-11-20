"""Async SQLite WAL outbox and tamper-evident hash-chained egress ledger."""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiosqlite
import uuid_utils
from pydantic import BaseModel

from veilops.collector.config import CollectorConfig
from veilops.collector.transport.signer import (
    EnvelopeSigner,
    canonical_bytes,
    compute_payload_hash,
)
from veilops.schema.common import GENESIS_HASH
from veilops.schema.envelope import ChainInfo, Envelope, PolicyRef
from veilops.schema.policy import Policy, load_policy
from veilops.schema.wire import Receipt

# Aliases for compatibility
IngestEnvelope = Envelope
ChainRef = ChainInfo
IngestReceipt = Receipt


@dataclass
class OutboxEntry:
    seq: int
    payload_id: str
    tenant_id: str
    collector_id: str
    region: str
    sent_at: str
    policy_version: str
    policy_hash: str
    prev_hash: str
    payload_hash: str
    envelope_json: str
    signature: str
    status: str  # "pending" | "acked"
    attempts: int
    created_at: str
    acked_at: str | None
    receipt_json: str | None
    record_count: int
    priority: bool


class OutboxLedger:
    """Manages transactional outbox queuing and immutable cryptographic chain verification."""

    def __init__(
        self,
        db_path: str | Path,
        signer: EnvelopeSigner,
        *,
        tenant_id: str | None = None,
        collector_id: str | None = None,
        region: str | None = None,
        policy_version: int | None = None,
        policy_hash: str | None = None,
        schema_version: str = "1.0",
        config: CollectorConfig | None = None,
        policy: Policy | None = None,
    ) -> None:
        self.db_path = str(db_path)
        self.signer = signer
        self.schema_version = schema_version
        self._db: aiosqlite.Connection | None = None

        # Configuration fallbacks
        if config:
            self.tenant_id = tenant_id or config.tenant_id
            self.collector_id = collector_id or config.collector_id
            self.region = region or config.region
        else:
            self.tenant_id = tenant_id or "t_default"
            self.collector_id = collector_id or "col_default"
            self.region = region or "in"

        # Policy fallbacks
        loaded_policy = policy
        if loaded_policy is None and policy_hash is None:
            try:
                loaded_policy = load_policy()
            except Exception:
                loaded_policy = None

        if loaded_policy:
            self.policy_version = str(policy_version or loaded_policy.version)
            self.policy_hash = policy_hash or loaded_policy.hash or loaded_policy.policy_hash
        else:
            self.policy_version = str(policy_version or 1)
            self.policy_hash = policy_hash or ("sha256:" + "0" * 64)

        if not self.policy_hash.startswith("sha256:"):
            self.policy_hash = f"sha256:{self.policy_hash}"

    async def __aenter__(self) -> OutboxLedger:
        await self.open()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.close()

    async def open(self) -> None:
        """Open SQLite connection and ensure schema and WAL mode."""
        if self._db is not None:
            return

        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        self._db = await aiosqlite.connect(self.db_path)
        self._db.row_factory = aiosqlite.Row

        # SQLite PRAGMAs
        if self.db_path != ":memory:":
            await self._db.execute("PRAGMA journal_mode=WAL")
            await self._db.execute("PRAGMA synchronous=FULL")
        await self._db.execute("PRAGMA foreign_keys=ON")

        # Table schema
        await self._db.execute(
            """
            CREATE TABLE IF NOT EXISTS outbox_ledger (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                payload_id TEXT NOT NULL UNIQUE,
                tenant_id TEXT NOT NULL,
                collector_id TEXT NOT NULL,
                region TEXT NOT NULL,
                sent_at TEXT NOT NULL,
                policy_version TEXT NOT NULL,
                policy_hash TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                payload_hash TEXT NOT NULL,
                envelope_json TEXT NOT NULL,
                signature TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                attempts INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                acked_at TEXT,
                receipt_json TEXT,
                record_count INTEGER NOT NULL,
                priority INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        await self._db.execute(
            "CREATE INDEX IF NOT EXISTS idx_outbox_status_seq ON outbox_ledger(status, seq)"
        )
        await self._db.commit()

    async def close(self) -> None:
        """Close database connection."""
        if self._db is not None:
            await self._db.close()
            self._db = None

    def _ensure_open(self) -> aiosqlite.Connection:
        if self._db is None:
            raise RuntimeError("OutboxLedger database is not open")
        return self._db

    async def enqueue(
        self,
        records: list[BaseModel | dict[str, Any]],
        *,
        sent_at: datetime | None = None,
        priority: bool = False,
    ) -> OutboxEntry:
        """Enqueue records into outbox within an atomic locked transaction."""
        if not records:
            raise ValueError("records list cannot be empty")

        db = self._ensure_open()

        record_dicts: list[dict[str, Any]] = []
        for r in records:
            if isinstance(r, BaseModel):
                record_dicts.append(r.model_dump(mode="json"))
            elif isinstance(r, dict):
                record_dicts.append(dict(r))
            else:
                raise ValueError(f"unsupported record type: {type(r)}")

        now_utc = sent_at.astimezone(timezone.utc) if sent_at else datetime.now(timezone.utc)
        sent_at_str = now_utc.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        created_at_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

        # Begin transaction
        await db.execute("BEGIN IMMEDIATE")
        try:
            cursor = await db.execute(
                "SELECT seq, payload_hash FROM outbox_ledger ORDER BY seq DESC LIMIT 1"
            )
            last_row = await cursor.fetchone()
            if last_row is None:
                prev_hash = GENESIS_HASH
                next_seq = 1
            else:
                prev_hash = last_row["payload_hash"]
                next_seq = int(last_row["seq"]) + 1

            raw_payload_hash = compute_payload_hash(record_dicts)
            payload_hash = (
                raw_payload_hash
                if raw_payload_hash.startswith("sha256:")
                else f"sha256:{raw_payload_hash}"
            )
            prev_hash_for_chain = (
                prev_hash if prev_hash.startswith("sha256:") else f"sha256:{prev_hash}"
            )

            payload_id = str(uuid_utils.uuid7())

            policy_ver_int = int(self.policy_version) if self.policy_version.isdigit() else 1
            envelope_data = {
                "schema_version": self.schema_version,
                "payload_id": payload_id,
                "tenant_id": self.tenant_id,
                "collector_id": self.collector_id,
                "region": self.region,
                "seq": next_seq,
                "sent_at": sent_at_str,
                "policy": {
                    "version": policy_ver_int,
                    "hash": self.policy_hash,
                },
                "chain": {
                    "prev_hash": prev_hash_for_chain,
                    "payload_hash": payload_hash,
                },
                "records": record_dicts,
            }

            validated_envelope = Envelope.model_validate(envelope_data)
            envelope_json = validated_envelope.model_dump_json()

            envelope_dict_for_sig = json.loads(envelope_json)
            signature = self.signer.sign_envelope_dict(envelope_dict_for_sig)

            priority_int = 1 if priority else 0
            cursor = await db.execute(
                """
                INSERT INTO outbox_ledger (
                    seq, payload_id, tenant_id, collector_id, region, sent_at,
                    policy_version, policy_hash, prev_hash, payload_hash,
                    envelope_json, signature, status, attempts, created_at,
                    acked_at, receipt_json, record_count, priority
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', 0, ?, NULL, NULL, ?, ?)
                """,
                (
                    next_seq,
                    payload_id,
                    self.tenant_id,
                    self.collector_id,
                    self.region,
                    sent_at_str,
                    self.policy_version,
                    self.policy_hash,
                    prev_hash_for_chain,
                    payload_hash,
                    envelope_json,
                    signature,
                    created_at_str,
                    len(record_dicts),
                    priority_int,
                ),
            )
            await db.commit()

            return OutboxEntry(
                seq=next_seq,
                payload_id=payload_id,
                tenant_id=self.tenant_id,
                collector_id=self.collector_id,
                region=self.region,
                sent_at=sent_at_str,
                policy_version=self.policy_version,
                policy_hash=self.policy_hash,
                prev_hash=prev_hash_for_chain,
                payload_hash=payload_hash,
                envelope_json=envelope_json,
                signature=signature,
                status="pending",
                attempts=0,
                created_at=created_at_str,
                acked_at=None,
                receipt_json=None,
                record_count=len(record_dicts),
                priority=priority,
            )
        except Exception:
            await db.execute("ROLLBACK")
            raise

    async def next_pending(self, limit: int = 50) -> list[OutboxEntry]:
        """Fetch pending outbox entries in strict monotonic seq order."""
        db = self._ensure_open()
        cursor = await db.execute(
            """
            SELECT seq, payload_id, tenant_id, collector_id, region, sent_at,
                   policy_version, policy_hash, prev_hash, payload_hash,
                   envelope_json, signature, status, attempts, created_at,
                   acked_at, receipt_json, record_count, priority
            FROM outbox_ledger
            WHERE status = 'pending'
            ORDER BY seq ASC
            LIMIT ?
            """,
            (limit,),
        )
        rows = await cursor.fetchall()
        return [self._row_to_entry(row) for row in rows]

    async def mark_acked(
        self,
        payload_id: str,
        receipt: Receipt | dict[str, Any] | None = None,
    ) -> None:
        """Mark an entry acknowledged with optional server receipt."""
        db = self._ensure_open()
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        receipt_json = None
        if isinstance(receipt, BaseModel):
            receipt_json = receipt.model_dump_json()
        elif isinstance(receipt, dict):
            receipt_json = json.dumps(receipt)

        await db.execute(
            """
            UPDATE outbox_ledger
            SET status = 'acked', acked_at = ?, receipt_json = ?
            WHERE payload_id = ?
            """,
            (now_str, receipt_json, payload_id),
        )
        await db.commit()

    async def record_attempt(self, payload_id: str) -> None:
        """Increment transmission attempt counter."""
        db = self._ensure_open()
        await db.execute(
            "UPDATE outbox_ledger SET attempts = attempts + 1 WHERE payload_id = ?",
            (payload_id,),
        )
        await db.commit()

    async def stats(self) -> dict[str, Any]:
        """Calculate telemetry statistics for outbox and egress ledger."""
        db = self._ensure_open()

        # Depth
        cur = await db.execute("SELECT COUNT(*) FROM outbox_ledger WHERE status = 'pending'")
        row = await cur.fetchone()
        depth = int(row[0]) if row else 0

        # Oldest unsent seconds
        cur = await db.execute(
            "SELECT sent_at FROM outbox_ledger WHERE status = 'pending' ORDER BY seq ASC LIMIT 1"
        )
        row = await cur.fetchone()
        oldest_unsent_s = 0.0
        if row and row[0]:
            try:
                oldest_dt = datetime.fromisoformat(str(row[0]).replace("Z", "+00:00"))
                now = datetime.now(timezone.utc)
                oldest_unsent_s = max(0.0, (now - oldest_dt).total_seconds())
            except Exception:
                oldest_unsent_s = 0.0

        # Last acked seq
        cur = await db.execute("SELECT MAX(seq) FROM outbox_ledger WHERE status = 'acked'")
        row = await cur.fetchone()
        last_acked_seq = int(row[0]) if (row and row[0] is not None) else 0

        # Highest seq
        cur = await db.execute("SELECT MAX(seq) FROM outbox_ledger")
        row = await cur.fetchone()
        highest_seq = int(row[0]) if (row and row[0] is not None) else 0

        # Total sent records
        cur = await db.execute("SELECT SUM(record_count) FROM outbox_ledger WHERE status = 'acked'")
        row = await cur.fetchone()
        total_sent_records = int(row[0]) if (row and row[0] is not None) else 0

        return {
            "outbox_depth": depth,
            "oldest_unsent_s": oldest_unsent_s,
            "last_acked_seq": last_acked_seq,
            "highest_seq": highest_seq,
            "total_sent_records": total_sent_records,
        }

    async def verify_chain(self) -> tuple[bool, str]:
        """Verify unbroken sequential cryptographic ledger integrity."""
        db = self._ensure_open()
        cur = await db.execute(
            "SELECT seq, prev_hash, payload_hash, envelope_json FROM outbox_ledger ORDER BY seq ASC"
        )
        rows = await cur.fetchall()
        if not rows:
            return True, "ok"

        for idx, row in enumerate(rows):
            seq = int(row["seq"])
            expected_seq = idx + 1
            if seq != expected_seq:
                return False, f"Sequence broken at row {expected_seq}: got seq {seq}"

            prev_hash = str(row["prev_hash"])
            payload_hash = str(row["payload_hash"])
            envelope_json = str(row["envelope_json"])

            # Verify prev_hash
            if idx == 0:
                expected_prev = GENESIS_HASH
                if prev_hash.removeprefix("sha256:") != expected_prev.removeprefix("sha256:"):
                    return (
                        False,
                        f"Genesis hash mismatch at seq 1: expected {expected_prev}, got {prev_hash}",
                    )
            else:
                prev_row_payload = str(rows[idx - 1]["payload_hash"])
                if prev_hash.removeprefix("sha256:") != prev_row_payload.removeprefix("sha256:"):
                    return (
                        False,
                        f"Hash link broken at seq {seq}: prev_hash {prev_hash} != {prev_row_payload}",
                    )

            # Recompute payload hash from envelope records
            try:
                env_dict = json.loads(envelope_json)
                records = env_dict.get("records", [])
                recomputed_hash = compute_payload_hash(records)
                if (
                    recomputed_hash.removeprefix("sha256:")
                    != payload_hash.removeprefix("sha256:")
                ):
                    return (
                        False,
                        f"Payload tampering detected at seq {seq}: computed {recomputed_hash} != recorded {payload_hash}",
                    )
            except Exception as exc:
                return False, f"Malformed envelope at seq {seq}: {exc}"

        return True, "ok"

    async def recent_entries(self, limit: int = 20) -> list[OutboxEntry]:
        """Fetch most recent outbox entries in reverse seq order."""
        db = self._ensure_open()
        cur = await db.execute(
            """
            SELECT seq, payload_id, tenant_id, collector_id, region, sent_at,
                   policy_version, policy_hash, prev_hash, payload_hash,
                   envelope_json, signature, status, attempts, created_at,
                   acked_at, receipt_json, record_count, priority
            FROM outbox_ledger
            ORDER BY seq DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = await cur.fetchall()
        return [self._row_to_entry(row) for row in rows]

    @staticmethod
    def _row_to_entry(row: Any) -> OutboxEntry:
        return OutboxEntry(
            seq=int(row["seq"]),
            payload_id=str(row["payload_id"]),
            tenant_id=str(row["tenant_id"]),
            collector_id=str(row["collector_id"]),
            region=str(row["region"]),
            sent_at=str(row["sent_at"]),
            policy_version=str(row["policy_version"]),
            policy_hash=str(row["policy_hash"]),
            prev_hash=str(row["prev_hash"]),
            payload_hash=str(row["payload_hash"]),
            envelope_json=str(row["envelope_json"]),
            signature=str(row["signature"]),
            status=str(row["status"]),
            attempts=int(row["attempts"]),
            created_at=str(row["created_at"]),
            acked_at=str(row["acked_at"]) if row["acked_at"] else None,
            receipt_json=str(row["receipt_json"]) if row["receipt_json"] else None,
            record_count=int(row["record_count"]),
            priority=bool(row["priority"]),
        )

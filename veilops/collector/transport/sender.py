"""Async HTTP transport sender and SourceBus consumer bridge with priority bypass."""
from __future__ import annotations

import asyncio
import json
import time
from typing import Any

import httpx

from veilops.collector.contracts import LocalSignal, SourceBus, WindowAgg
from veilops.collector.privacy.serializer import RecordSerializer, SerializationError
from veilops.collector.transport.guard import EgressGuard, EgressGuardError
from veilops.collector.transport.outbox import OutboxEntry, OutboxLedger
from veilops.collector.transport.signer import EnvelopeSigner, canonical_bytes
from veilops.schema.envelope import Envelope
from veilops.schema.wire import Heartbeat, Receipt

# Aliases
IngestReceipt = Receipt
HeartbeatPayload = Heartbeat


def compute_backoff_s(
    attempt: int,
    base_s: float = 0.25,
    max_s: float = 10.0,
    factor: float = 2.0,
) -> float:
    """Compute exponential backoff delay with upper cap."""
    return min(max_s, base_s * (factor ** max(0, attempt)))


class TransportSender:
    """Delivers outbox envelopes and periodic heartbeats via HTTP/S."""

    def __init__(
        self,
        base_url: str,
        outbox: OutboxLedger,
        signer: EnvelopeSigner,
        *,
        client: httpx.AsyncClient | None = None,
        ingest_url: str | None = None,
        heartbeat_url: str | None = None,
        timeout: float = 10.0,
        egress_guard: EgressGuard | None = None,
        verify_key_bytes: bytes | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.outbox = outbox
        self.signer = signer
        self.ingest_url = ingest_url or f"{self.base_url}/v1/ingest"
        self.heartbeat_url = heartbeat_url or f"{self.base_url}/v1/heartbeat"
        self.egress_guard = egress_guard
        self.verify_key_bytes = verify_key_bytes
        self._external_client = client is not None
        self._client = client or httpx.AsyncClient(timeout=timeout)

    @staticmethod
    def compute_backoff_s(
        attempt: int,
        base_s: float = 0.25,
        max_s: float = 10.0,
        factor: float = 2.0,
    ) -> float:
        return compute_backoff_s(attempt, base_s, max_s, factor)

    async def close(self) -> None:
        """Close HTTP client if owned internally."""
        if not self._external_client and self._client:
            await self._client.aclose()

    async def flush_once(self, limit: int = 50) -> int:
        """Flush pending outbox envelopes to SaaS ingest endpoint in strict seq order.

        Stops on first retryable network/server error to preserve head-of-line ordering.
        """
        pending = await self.outbox.next_pending(limit=limit)
        if not pending:
            return 0

        acked_count = 0
        for entry in pending:
            # Pre-egress fail-closed canary and secret scan
            if self.egress_guard:
                try:
                    self.egress_guard.scan_and_guard_payload(entry.envelope_json)
                except EgressGuardError:
                    # Halt egress queue immediately (fail-closed)
                    break

            await self.outbox.record_attempt(entry.payload_id)

            headers = {
                "Content-Type": "application/json",
                "X-VeilOps-Collector-Id": entry.collector_id,
                "X-VeilOps-Tenant-Id": entry.tenant_id,
                "X-VeilOps-Signature": entry.signature,
                "X-VeilOps-Key-Id": self.signer.public_key_hex[:16],
                "Idempotency-Key": entry.payload_id,
            }

            try:
                resp = await self._client.post(
                    self.ingest_url,
                    content=entry.envelope_json,
                    headers=headers,
                )
            except httpx.HTTPError:
                # Stop immediately, preserving head-of-line queue order
                break

            if resp.status_code in (200, 201, 202):
                receipt = None
                try:
                    data = resp.json()
                    if isinstance(data, dict):
                        receipt = Receipt.model_validate(data)
                except Exception:
                    receipt = None

                # Verify receipt cryptographic signature if key is configured
                if self.verify_key_bytes and receipt and receipt.sig:
                    receipt_dict = receipt.model_dump(mode="json")
                    receipt_no_sig = {k: v for k, v in receipt_dict.items() if k != "sig"}
                    canonical = canonical_bytes(receipt_no_sig)
                    if not EnvelopeSigner.verify_signature(
                        self.verify_key_bytes, canonical, receipt.sig
                    ):
                        # Invalid SaaS receipt signature: fail-closed, do not ack
                        break

                await self.outbox.mark_acked(entry.payload_id, receipt)
                acked_count += 1
            elif resp.status_code == 429 or resp.status_code >= 500:
                # Transient/rate error: stop immediately and wait for next interval
                break
            else:
                # Other 4xx client errors - do not crash transport, pause queue
                break

        return acked_count

    async def flush_with_backoff(
        self,
        *,
        max_retries: int = 4,
        base_s: float = 0.25,
        max_s: float = 10.0,
        limit: int = 50,
    ) -> int:
        """Flush pending entries with exponential backoff on transient errors."""
        total_acked = 0
        for attempt in range(max_retries):
            acked = await self.flush_once(limit=limit)
            total_acked += acked

            pending = await self.outbox.next_pending(limit=1)
            if not pending:
                break

            if attempt < max_retries - 1:
                delay = compute_backoff_s(attempt, base_s=base_s, max_s=max_s)
                await asyncio.sleep(delay)

        return total_acked

    async def send_heartbeat(self, heartbeat: Heartbeat) -> bool:
        """Sign and transmit a heartbeat payload."""
        hb_dict = heartbeat.model_dump(mode="json")
        canonical = canonical_bytes(hb_dict)
        signature = self.signer.sign_bytes(canonical)

        headers = {
            "Content-Type": "application/json",
            "X-VeilOps-Collector-Id": heartbeat.collector_id,
            "X-VeilOps-Tenant-Id": heartbeat.tenant_id,
            "X-VeilOps-Signature": signature,
            "X-VeilOps-Key-Id": self.signer.public_key_hex[:16],
        }

        try:
            resp = await self._client.post(
                self.heartbeat_url,
                content=heartbeat.model_dump_json(),
                headers=headers,
            )
            return resp.is_success
        except httpx.HTTPError:
            return False
        except Exception:
            return False


class BusBridge:
    """Bridges internal SourceBus queues to serialized outbox entries with priority bypass."""

    def __init__(
        self,
        bus: SourceBus,
        serializer: RecordSerializer,
        outbox: OutboxLedger,
        sender: TransportSender | None = None,
        *,
        batch_size: int = 25,
        flush_interval_s: float = 2.0,
    ) -> None:
        self.bus = bus
        self.serializer = serializer
        self.outbox = outbox
        self.sender = sender
        self.batch_size = batch_size
        self.flush_interval_s = flush_interval_s

        self.buffer: list[Any] = []
        self.last_flush_time = time.monotonic()
        self.dropped_invalid = 0
        self.total_enqueued = 0

    async def flush_buffer(self, *, priority: bool = False) -> OutboxEntry | None:
        """Enqueue current buffer into OutboxLedger and optionally flush sender."""
        if not self.buffer:
            return None

        records_to_flush = list(self.buffer)
        self.buffer.clear()
        self.last_flush_time = time.monotonic()

        entry = await self.outbox.enqueue(records_to_flush, priority=priority)
        self.total_enqueued += len(records_to_flush)

        if self.sender:
            await self.sender.flush_once()

        return entry

    async def step(self) -> int:
        """Process all currently available bus items and flush if conditions met."""
        processed = 0
        flush_immediately = False

        # Drain signals first
        while not self.bus.signals.empty():
            try:
                sig = self.bus.signals.get_nowait()
                processed += 1
                try:
                    wire_rec = self.serializer.serialize_signal(sig)
                    self.buffer.append(wire_rec)
                    if getattr(sig, "priority", False):
                        flush_immediately = True
                except SerializationError:
                    self.dropped_invalid += 1
            except asyncio.QueueEmpty:
                break

        # Drain windows
        while not self.bus.windows.empty():
            try:
                win = self.bus.windows.get_nowait()
                processed += 1
                try:
                    wire_rec = self.serializer.serialize_window(win)
                    self.buffer.append(wire_rec)
                except SerializationError:
                    self.dropped_invalid += 1
            except asyncio.QueueEmpty:
                break

        now = time.monotonic()
        should_flush = (
            flush_immediately
            or len(self.buffer) >= self.batch_size
            or (self.buffer and (now - self.last_flush_time >= self.flush_interval_s))
        )

        if should_flush:
            await self.flush_buffer(priority=flush_immediately)

        return processed

    async def run(self, stop_event: asyncio.Event | None = None) -> None:
        """Continuous background consumer loop."""
        while stop_event is None or not stop_event.is_set():
            await self.step()
            await asyncio.sleep(0.05)

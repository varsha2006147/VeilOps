"""Async HTTP transport sender and SourceBus consumer bridge with priority bypass."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

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


@dataclass(frozen=True)
class CollectorCredentials:
    """Per-collector HMAC key issued by the cloud at enrollment (POST /v1/enroll)."""
    collector_id: str
    secret: bytes

    def __repr__(self) -> str:
        return f"CollectorCredentials(collector_id={self.collector_id!r}, secret=<hidden>)"


def hmac_headers(creds: CollectorCredentials, method: str, url: str, body: bytes) -> dict[str, str]:
    """Cloud §13 request auth: HMAC-SHA256 over METHOD, PATH(+query), TIMESTAMP, NONCE, sha256(body)."""
    parts = urlsplit(url)
    path = parts.path + (("?" + parts.query) if parts.query else "")
    ts, nonce = str(int(time.time())), secrets.token_hex(16)
    msg = "\n".join((method.upper(), path, ts, nonce, hashlib.sha256(body).hexdigest())).encode()
    sig = base64.b64encode(hmac.new(creds.secret, msg, hashlib.sha256).digest()).decode("ascii")
    return {"X-VeilOps-Collector": creds.collector_id, "X-VeilOps-Timestamp": ts,
            "X-VeilOps-Nonce": nonce, "X-VeilOps-Signature": sig}


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
        credentials: CollectorCredentials | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.credentials = credentials
        self.last_status: int | None = None
        self.last_error: str | None = None
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

            body = entry.envelope_json.encode("utf-8")
            if self.credentials is not None:
                # Cloud authenticates with HMAC; the Ed25519 envelope signature stays as evidence.
                headers.pop("X-VeilOps-Signature", None)
                headers["X-VeilOps-Envelope-Signature"] = entry.signature
                headers.update(hmac_headers(self.credentials, "POST", self.ingest_url, body))
            try:
                resp = await self._client.post(
                    self.ingest_url,
                    content=body,
                    headers=headers,
                )
            except httpx.HTTPError as exc:
                # Stop immediately, preserving head-of-line queue order
                self.last_status, self.last_error = None, type(exc).__name__
                break
            self.last_status = resp.status_code
            self.last_error = None if resp.status_code < 300 else resp.text[:200]

            if resp.status_code in (200, 201, 202):
                receipt = None
                data = None
                try:
                    data = resp.json()
                    if isinstance(data, dict):
                        receipt = Receipt.model_validate(data)
                except Exception:
                    receipt = None

                # Verify the SaaS signature over the receipt exactly as received
                # (re-serialising a parsed model could change bytes and break verification).
                if self.verify_key_bytes and isinstance(data, dict) and data.get("sig"):
                    receipt_no_sig = {k: v for k, v in data.items() if k != "sig"}
                    canonical = canonical_bytes(receipt_no_sig)
                    if not EnvelopeSigner.verify_signature(
                        self.verify_key_bytes, canonical, data["sig"]
                    ):
                        self.last_error = "receipt signature invalid"
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

        body = heartbeat.model_dump_json().encode("utf-8")
        if self.credentials is not None:
            headers.pop("X-VeilOps-Signature", None)
            headers.update(hmac_headers(self.credentials, "POST", self.heartbeat_url, body))
        try:
            resp = await self._client.post(
                self.heartbeat_url,
                content=body,
                headers=headers,
            )
            return resp.is_success
        except httpx.HTTPError:
            return False
        except Exception:
            return False


async def reconcile(sender: "TransportSender", from_seq: int, to_seq: int) -> dict | None:
    """Ask the cloud which sequence numbers in [from_seq, to_seq] it has stored (§17)."""
    if sender.credentials is None:
        return None
    url = (f"{sender.base_url}/v1/reconcile?collector_id={sender.credentials.collector_id}"
           f"&from_seq={from_seq}&to_seq={to_seq}")
    headers = hmac_headers(sender.credentials, "GET", url, b"")
    try:
        resp = await sender._client.get(url, headers=headers)
    except httpx.HTTPError:
        return None
    return resp.json() if resp.status_code == 200 else None


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

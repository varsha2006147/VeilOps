"""Tests for HeartbeatBuilder, TransportSender, and BusBridge with priority bypass."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest

from veilops.collector.contracts import LocalSignal, SourceBus, SourceStatus, WindowAgg
from veilops.collector.privacy.pseudonymizer import Pseudonymizer
from veilops.collector.privacy.serializer import RecordSerializer
from veilops.collector.transport.heartbeat import HeartbeatBuilder
from veilops.collector.transport.outbox import OutboxLedger
from veilops.collector.transport.sender import BusBridge, TransportSender
from veilops.collector.transport.signer import EnvelopeSigner, load_or_create_signing_key
from veilops.schema.wire import Heartbeat, Receipt, SourcesOk


def _sample_record(avg: float = 70.0) -> dict:
    return {
        "type": "metric",
        "entity": "h_7f3a21c90b",
        "entity_kind": "host",
        "metric": "cpu.util_pct",
        "unit": "pct",
        "avg": avg,
        "min": 65.0,
        "max": 75.0,
        "p95": 74.0,
        "count": 5,
        "window_s": 5,
        "event_ts": "2026-11-21T04:12:00.000Z",
        "source_tz": "UTC",
    }


def test_heartbeat_builder_source_mapping_and_validation():
    builder = HeartbeatBuilder(
        collector_id="col_blr_01",
        tenant_id="t_acme",
        version="1.0.0",
        policy_version=1,
        config_hash="sha256:" + "0" * 64,
    )

    # Collector source "sim" maps to "stream"
    sources_input = {
        "sim": SourceStatus(name="sim", ok=True),
        "host": True,
        "probe": False,
        "syslog": True,
    }
    hb = builder.build(
        outbox_depth=3,
        oldest_unsent_s=12.5,
        last_acked_seq=42,
        cpu_pct=15.4,
        mem_mb=128.0,
        sources=sources_input,
    )

    assert isinstance(hb, Heartbeat)
    assert hb.collector_id == "col_blr_01"
    assert hb.tenant_id == "t_acme"
    assert hb.outbox_depth == 3
    assert hb.sources_ok.stream is True  # Mapped from "sim"
    assert hb.sources_ok.host is True
    assert hb.sources_ok.probes is False  # Mapped from "probe"
    assert hb.sources_ok.syslog is True


@pytest.mark.asyncio
async def test_transport_sender_flush_once_success(tmp_path: Path):
    sk = load_or_create_signing_key(tmp_path / "k.key")
    signer = EnvelopeSigner(sk)
    db_file = tmp_path / "outbox.db"

    captured_requests: list[httpx.Request] = []

    def mock_handler(request: httpx.Request) -> httpx.Response:
        captured_requests.append(request)
        body = json.loads(request.content)
        receipt = {
            "payload_id": body["payload_id"],
            "payload_hash": body["chain"]["payload_hash"],
            "status": "stored",
            "received_at": "2026-11-21T04:12:10.000Z",
            "region": "in",
            "highest_contiguous_seq": body["seq"],
            "sig": "dGVzdC1zaWduYXR1cmUtZGF0YQ==",
        }
        return httpx.Response(200, json=receipt)

    client = httpx.AsyncClient(transport=httpx.MockTransport(mock_handler))

    async with OutboxLedger(db_file, signer, tenant_id="t_acme", collector_id="col_01") as outbox:
        entry = await outbox.enqueue([_sample_record()])

        sender = TransportSender("https://ingest.veilops.internal", outbox, signer, client=client)
        acked = await sender.flush_once()
        assert acked == 1

        stats = await outbox.stats()
        assert stats["outbox_depth"] == 0
        assert stats["last_acked_seq"] == entry.seq

        assert len(captured_requests) == 1
        req = captured_requests[0]
        assert req.headers["x-veilops-collector-id"] == "col_01"
        assert req.headers["x-veilops-tenant-id"] == "t_acme"
        assert req.headers["x-veilops-signature"] == entry.signature
        assert req.headers["x-veilops-key-id"] == signer.public_key_hex[:16]


@pytest.mark.asyncio
async def test_transport_outage_recovery_and_head_of_line_order(tmp_path: Path):
    sk = load_or_create_signing_key(tmp_path / "k.key")
    signer = EnvelopeSigner(sk)
    db_file = tmp_path / "outbox.db"

    server_status = 503
    captured_seqs: list[int] = []

    def outage_handler(request: httpx.Request) -> httpx.Response:
        if server_status != 200:
            return httpx.Response(server_status, text="Service Unavailable")
        body = json.loads(request.content)
        captured_seqs.append(body["seq"])
        receipt = {
            "payload_id": body["payload_id"],
            "payload_hash": body["chain"]["payload_hash"],
            "status": "stored",
            "received_at": "2026-11-21T04:12:10.000Z",
            "region": "in",
            "highest_contiguous_seq": body["seq"],
            "sig": "c2lnbmF0dXJl",
        }
        return httpx.Response(200, json=receipt)

    client = httpx.AsyncClient(transport=httpx.MockTransport(outage_handler))

    async with OutboxLedger(db_file, signer, tenant_id="t_acme", collector_id="col_01") as outbox:
        e1 = await outbox.enqueue([_sample_record(10.0)])
        e2 = await outbox.enqueue([_sample_record(20.0)])
        e3 = await outbox.enqueue([_sample_record(30.0)])

        sender = TransportSender("https://ingest.veilops.internal", outbox, signer, client=client)

        # 1. Attempt flush during outage: 503 error stops flush immediately
        acked = await sender.flush_once()
        assert acked == 0
        stats = await outbox.stats()
        assert stats["outbox_depth"] == 3
        # Attempt count recorded on head-of-line
        pending = await outbox.next_pending()
        assert pending[0].attempts == 1

        # 2. Server recovers to 200 OK
        server_status = 200
        acked = await sender.flush_once()
        assert acked == 3

        stats = await outbox.stats()
        assert stats["outbox_depth"] == 0
        assert stats["last_acked_seq"] == 3

        # Exactly 3 delivered in strict sequential order with zero duplicates
        assert captured_seqs == [1, 2, 3]


@pytest.mark.asyncio
async def test_bus_bridge_priority_bypass(tmp_path: Path):
    sk = load_or_create_signing_key(tmp_path / "k.key")
    signer = EnvelopeSigner(sk)
    db_file = tmp_path / "outbox.db"

    bus = SourceBus()
    from veilops.collector.privacy.pseudonymizer import PseudonymStore
    from veilops.schema.policy import load_policy
    pseudonymizer = Pseudonymizer(b"k" * 32, PseudonymStore())
    policy = load_policy()
    serializer = RecordSerializer(policy, pseudonymizer)

    async with OutboxLedger(db_file, signer, tenant_id="t_acme", collector_id="col_01") as outbox:
        bridge = BusBridge(bus, serializer, outbox, batch_size=10, flush_interval_s=60.0)

        now = datetime.now(timezone.utc)
        normal_win = WindowAgg(
            entity="host-alpha",
            entity_kind="host",
            metric="cpu.util_pct",
            unit="pct",
            avg=45.0,
            min=40.0,
            max=50.0,
            p95=49.0,
            count=5,
            window_s=5,
            event_ts=now,
            source_tz="UTC",
        )
        await bus.windows.put(normal_win)

        # Step 1: Normal window should be buffered, NOT flushed yet (batch_size=10, interval=60s)
        await bridge.step()
        assert len(bridge.buffer) == 1
        stats = await outbox.stats()
        assert stats["outbox_depth"] == 0

        # Step 2: Push a priority=True signal -> MUST bypass batching immediately
        priority_sig = LocalSignal(
            kind="threshold",
            rule="threshold.cpu.high",
            severity="warning",
            entity="host-alpha",
            event_ts=now,
            source_tz="UTC",
            params={"value": 95.0, "threshold": 90.0},
            priority=True,
        )
        await bus.signals.put(priority_sig)

        await bridge.step()
        # Buffer was flushed to outbox
        assert len(bridge.buffer) == 0
        stats = await outbox.stats()
        assert stats["outbox_depth"] == 1
        assert stats["highest_seq"] == 1

        pending = await outbox.next_pending()
        assert pending[0].record_count == 2  # buffered window + priority signal
        assert pending[0].priority is True

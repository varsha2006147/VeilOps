"""Tests for Egress Proof, Egress Guard, Receipt Verification, Backoff, and Action Poller."""
from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from veilops.collector.contracts import SourceBus
from veilops.collector.transport.actions import ActionPoller, LocalVetoPolicy
from veilops.collector.transport.guard import DEFAULT_CANARY_TOKENS, EgressGuard, EgressGuardError
from veilops.collector.transport.outbox import OutboxLedger
from veilops.collector.transport.proof import EgressProofService, build_egress_proof_snapshot
from veilops.collector.transport.sender import TransportSender, compute_backoff_s
from veilops.collector.transport.signer import (
    EnvelopeSigner,
    canonical_bytes,
    load_or_create_signing_key,
)
from veilops.collector.ui.app import UIContext, create_app
from veilops.schema.wire import Action, ActionResult


def _sample_record(avg: float = 65.0) -> dict:
    return {
        "type": "metric",
        "entity": "h_7f3a21c90b",
        "entity_kind": "host",
        "metric": "cpu.util_pct",
        "unit": "pct",
        "avg": avg,
        "min": 60.0,
        "max": 70.0,
        "p95": 69.0,
        "count": 5,
        "window_s": 5,
        "event_ts": "2026-11-21T04:12:00.000Z",
        "source_tz": "UTC",
    }


@pytest.mark.asyncio
async def test_egress_proof_snapshot_and_ui_endpoint(tmp_path: Path):
    sk = load_or_create_signing_key(tmp_path / "k.key")
    signer = EnvelopeSigner(sk)
    db_file = tmp_path / "outbox.db"

    async with OutboxLedger(db_file, signer, tenant_id="t_proof", collector_id="col_01") as ledger:
        e1 = await ledger.enqueue([_sample_record(10.0)])
        e2 = await ledger.enqueue([_sample_record(20.0)])

        service = EgressProofService(ledger)
        service.record_redaction("secrets_scrubbed", 3)
        service.record_redaction("canaries_blocked", 1)

        snapshot = await service.get_snapshot()
        assert snapshot["chain_valid"] is True
        assert snapshot["chain_status"] == "ok"
        assert snapshot["stats"]["highest_seq"] == 2
        assert len(snapshot["recent_envelopes"]) == 2
        assert snapshot["redaction_summary"]["secrets_scrubbed"] == 3
        assert snapshot["redaction_summary"]["canaries_blocked"] == 1

        # Test UI endpoint integration
        class DummyPipeline:
            bus = SourceBus()
            recent_signals = []
            recent_windows = []
            def snapshot(self): return {}

        class DummyStore:
            async def count(self): return 0
            async def recent(self, *a, **k): return []
            async def audit(self, *a, **k): pass

        class DummyConfig:
            collector_id = "col_01"
            tenant_id = "t_proof"
            region = "in"
            environment = "test"
            config_hash = "sha256:" + "0" * 64
            demo_mode = False
            downstream = "none"

        ctx = UIContext(DummyConfig(), DummyPipeline(), DummyStore(), {})
        ctx.proof_service = service
        app = create_app(ctx)
        client = TestClient(app)

        resp = client.get("/api/egress-proof")
        assert resp.status_code == 200
        data = resp.json()
        assert data["chain_valid"] is True
        assert data["stats"]["highest_seq"] == 2


def test_egress_guard_blocks_canaries_and_secrets():
    guard = EgressGuard(canary_tokens=["CANARY_SECRET_TOKEN", "AKIA"])

    # Clean payload passes
    clean_payload = {
        "entity": "h_7f3a21c90b",
        "metric": "cpu.util_pct",
        "unit": "pct",
        "avg": 55.4,
    }
    guard.scan_and_guard_payload(clean_payload)
    assert guard.blocked_counter == 0

    # Payload with canary token fails closed
    canary_payload = {
        "entity": "h_7f3a21c90b",
        "note": "debug trace with CANARY_SECRET_TOKEN inside",
    }
    with pytest.raises(EgressGuardError) as exc:
        guard.scan_and_guard_payload(canary_payload)
    assert "CANARY_SECRET_TOKEN" not in str(exc.value)
    assert "canary token detected" in str(exc.value)
    assert guard.blocked_counter == 1

    # Payload with high-risk secret pattern (e.g. AWS key or password) fails closed
    secret_payload = {
        "error": "Failed connecting to postgres://admin:hunter2@db:5432/orders",
    }
    with pytest.raises(EgressGuardError):
        guard.scan_and_guard_payload(secret_payload)
    assert guard.blocked_counter == 2

    # scrub_or_reject_text
    assert guard.scrub_or_reject_text("clean text") == "clean text"
    with pytest.raises(EgressGuardError):
        guard.scrub_or_reject_text("Contains AKIAIOSFODNN7EXAMPLE")


@pytest.mark.asyncio
async def test_receipt_signature_verification_and_backoff_replay(tmp_path: Path):
    sk = load_or_create_signing_key(tmp_path / "col.key")
    signer = EnvelopeSigner(sk)

    # Server signing key
    saas_sk = load_or_create_signing_key(tmp_path / "saas.key")
    saas_signer = EnvelopeSigner(saas_sk)
    saas_pub_bytes = saas_signer.public_key_bytes

    db_file = tmp_path / "outbox.db"

    # Test 1: Valid receipt signature is accepted
    def valid_handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        receipt_dict = {
            "payload_id": body["payload_id"],
            "payload_hash": body["chain"]["payload_hash"],
            "status": "stored",
            "received_at": "2026-11-21T04:12:10.000Z",
            "region": "in",
            "highest_contiguous_seq": body["seq"],
        }
        sig = saas_signer.sign_bytes(canonical_bytes(receipt_dict))
        receipt_dict["sig"] = sig
        return httpx.Response(200, json=receipt_dict)

    client = httpx.AsyncClient(transport=httpx.MockTransport(valid_handler))

    async with OutboxLedger(db_file, signer, tenant_id="t_test", collector_id="col_01") as outbox:
        e1 = await outbox.enqueue([_sample_record(1.0)])
        sender = TransportSender(
            "https://ingest.veilops.internal",
            outbox,
            signer,
            client=client,
            verify_key_bytes=saas_pub_bytes,
        )
        acked = await sender.flush_once()
        assert acked == 1
        stats = await outbox.stats()
        assert stats["outbox_depth"] == 0

    # Test 2: Tampered receipt signature is rejected (fail-closed, entry remains pending)
    db_file2 = tmp_path / "outbox2.db"
    def forged_handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        receipt_dict = {
            "payload_id": body["payload_id"],
            "payload_hash": body["chain"]["payload_hash"],
            "status": "stored",
            "received_at": "2026-11-21T04:12:10.000Z",
            "region": "in",
            "highest_contiguous_seq": body["seq"],
            "sig": "dGFtcGVyZWQtZm9yZ2VkLXNpZ25hdHVyZQ==",
        }
        return httpx.Response(200, json=receipt_dict)

    client_forged = httpx.AsyncClient(transport=httpx.MockTransport(forged_handler))

    async with OutboxLedger(db_file2, signer, tenant_id="t_test", collector_id="col_01") as outbox2:
        e2 = await outbox2.enqueue([_sample_record(2.0)])
        sender2 = TransportSender(
            "https://ingest.veilops.internal",
            outbox2,
            signer,
            client=client_forged,
            verify_key_bytes=saas_pub_bytes,
        )
        acked = await sender2.flush_once()
        assert acked == 0
        stats2 = await outbox2.stats()
        assert stats2["outbox_depth"] == 1  # Entry remained pending!

    # Test 3: compute_backoff_s progression
    assert compute_backoff_s(0, base_s=0.25) == 0.25
    assert compute_backoff_s(1, base_s=0.25) == 0.50
    assert compute_backoff_s(2, base_s=0.25) == 1.00
    assert compute_backoff_s(10, base_s=0.25, max_s=5.0) == 5.0


@pytest.mark.asyncio
async def test_action_poller_local_veto_and_execution(tmp_path: Path):
    saas_sk = load_or_create_signing_key(tmp_path / "saas.key")
    saas_signer = EnvelopeSigner(saas_sk)

    now = datetime.now(timezone.utc)
    future_iso = (now + timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    expired_iso = (now - timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    # Action 1: Valid RESTART_SERVICE action
    act1_dict = {
        "action_id": "0193b7c2-5e1a-7c3d-9f00-1a2b3c4d5e6f",
        "type": "RESTART_SERVICE",
        "target": "svc_7f3a21c90b",
        "params": {"timeout_s": 15},
        "policy_ref": "policy-v1",
        "approved_by": "0193b7c2-5e1a-7c3d-9f00-1a2b3c4d5e6f",
        "expires_at": future_iso,
    }
    act1_dict["sig"] = saas_signer.sign_bytes(canonical_bytes(act1_dict))

    # Action 2: Expired action
    act2_dict = {
        "action_id": "0193b7c2-5e1a-7c3d-9f00-2a2b3c4d5e6f",
        "type": "INVESTIGATE_TOP_PROCESSES",
        "target": "h_7f3a21c90b",
        "params": {"limit": 5},
        "policy_ref": "policy-v1",
        "approved_by": "0193b7c2-5e1a-7c3d-9f00-1a2b3c4d5e6f",
        "expires_at": expired_iso,
    }
    act2_dict["sig"] = saas_signer.sign_bytes(canonical_bytes(act2_dict))

    # Action 3: Disallowed action type
    act3_dict = {
        "action_id": "0193b7c2-5e1a-7c3d-9f00-3a2b3c4d5e6f",
        "type": "FAILOVER_TO_SECONDARY_LINK",
        "target": "lnk_7f3a21c90b",
        "params": {},
        "policy_ref": "policy-v1",
        "approved_by": "0193b7c2-5e1a-7c3d-9f00-1a2b3c4d5e6f",
        "expires_at": future_iso,
    }
    act3_dict["sig"] = saas_signer.sign_bytes(canonical_bytes(act3_dict))

    async def fetch_actions():
        return [act1_dict, act2_dict, act3_dict]

    veto_policy = LocalVetoPolicy(
        disallowed_types={"FAILOVER_TO_SECONDARY_LINK"},
    )

    poller = ActionPoller(
        fetch_actions,
        veto_policy=veto_policy,
        verify_key_bytes=saas_signer.public_key_bytes,
    )

    results = await poller.poll_and_execute_once()
    assert len(results) == 3

    # Action 1: executed
    assert results[0].status == "executed"
    assert results[0].local_policy_decision == "allow"

    # Action 2: expired -> vetoed
    assert results[1].status == "vetoed"
    assert results[1].local_policy_decision == "veto"

    # Action 3: disallowed type -> vetoed
    assert results[2].status == "vetoed"
    assert results[2].local_policy_decision == "veto"

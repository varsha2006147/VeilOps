"""Tests for collector key management, RFC 8785 signing, and OutboxLedger."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import aiosqlite
import pytest

from veilops.collector.transport.outbox import OutboxEntry, OutboxLedger
from veilops.collector.transport.signer import (
    GENESIS_HASH,
    EnvelopeSigner,
    SignerError,
    canonical_bytes,
    compute_payload_hash,
    load_or_create_signing_key,
    sha256_hex,
)
from veilops.schema.envelope import Envelope


def _sample_record(avg: float = 50.0) -> dict:
    return {
        "type": "metric",
        "entity": "h_7f3a21c90b",
        "entity_kind": "host",
        "metric": "cpu.util_pct",
        "unit": "pct",
        "avg": avg,
        "min": 45.0,
        "max": 55.0,
        "p95": 54.0,
        "count": 5,
        "window_s": 5,
        "event_ts": "2026-11-21T04:12:00.000Z",
        "source_tz": "UTC",
    }


def test_signing_key_creation_persistence_and_reload(tmp_path: Path):
    key_path = tmp_path / "keys" / "collector.key"
    sk1 = load_or_create_signing_key(key_path)
    assert key_path.exists()
    assert len(key_path.read_text(encoding="ascii").strip()) == 64

    # Reload from disk produces identical key
    sk2 = load_or_create_signing_key(key_path)
    assert bytes(sk1) == bytes(sk2)
    assert bytes(sk1.verify_key) == bytes(sk2.verify_key)


def test_malformed_key_file_rejected(tmp_path: Path):
    key_path = tmp_path / "bad.key"
    key_path.write_text("not-a-valid-hex-seed-too-short", encoding="ascii")
    with pytest.raises(SignerError):
        load_or_create_signing_key(key_path)

    key_path.write_text("z" * 64, encoding="ascii")
    with pytest.raises(SignerError):
        load_or_create_signing_key(key_path)


def test_signer_repr_hides_private_key(tmp_path: Path):
    key_path = tmp_path / "sec.key"
    sk = load_or_create_signing_key(key_path)
    signer = EnvelopeSigner(sk)
    rep = repr(signer)
    raw_seed_hex = bytes(sk).hex()
    assert raw_seed_hex not in rep
    assert signer.public_key_hex[:8] in rep


def test_canonical_signing_and_verification(tmp_path: Path):
    key_path = tmp_path / "signer.key"
    sk = load_or_create_signing_key(key_path)
    signer = EnvelopeSigner(sk)

    payload = {"b": 2, "a": 1, "nested": {"y": "val", "x": 10}}
    sig = signer.sign_envelope_dict(payload)
    assert isinstance(sig, str)
    assert len(sig) > 0

    canonical = canonical_bytes(payload)
    assert signer.verify_signature(signer.public_key_bytes, canonical, sig) is True

    # Tampered byte verification fails
    tampered = canonical + b" "
    assert signer.verify_signature(signer.public_key_bytes, tampered, sig) is False
    assert signer.verify_signature(signer.public_key_bytes, canonical, "bad_sig") is False
    assert signer.verify_signature(b"wrong_key_32_bytes_length_123456", canonical, sig) is False


@pytest.mark.asyncio
async def test_outbox_rejects_empty_records(tmp_path: Path):
    sk = load_or_create_signing_key(tmp_path / "k.key")
    signer = EnvelopeSigner(sk)
    db_file = tmp_path / "outbox.db"

    async with OutboxLedger(db_file, signer) as outbox:
        with pytest.raises(ValueError):
            await outbox.enqueue([])


@pytest.mark.asyncio
async def test_outbox_enqueue_persistence_and_chain(tmp_path: Path):
    sk = load_or_create_signing_key(tmp_path / "k.key")
    signer = EnvelopeSigner(sk)
    db_file = tmp_path / "outbox.db"

    async with OutboxLedger(db_file, signer, tenant_id="t_test", collector_id="col_test") as outbox:
        entry1 = await outbox.enqueue([_sample_record(10.0)])
        assert entry1.seq == 1
        assert entry1.status == "pending"
        assert entry1.prev_hash.removeprefix("sha256:") == GENESIS_HASH.removeprefix("sha256:")

        entry2 = await outbox.enqueue([_sample_record(20.0)])
        assert entry2.seq == 2
        assert entry2.prev_hash == entry1.payload_hash

        entry3 = await outbox.enqueue([_sample_record(30.0)])
        assert entry3.seq == 3
        assert entry3.prev_hash == entry2.payload_hash

        valid, reason = await outbox.verify_chain()
        assert valid is True
        assert reason == "ok"

    # Reopen ledger from disk and confirm chain and monotonicity persist
    async with OutboxLedger(db_file, signer, tenant_id="t_test", collector_id="col_test") as outbox2:
        valid, reason = await outbox2.verify_chain()
        assert valid is True

        entry4 = await outbox2.enqueue([_sample_record(40.0)])
        assert entry4.seq == 4
        assert entry4.prev_hash == entry3.payload_hash

        valid, reason = await outbox2.verify_chain()
        assert valid is True

        recent = await outbox2.recent_entries(limit=10)
        assert len(recent) == 4
        assert [r.seq for r in recent] == [4, 3, 2, 1]


@pytest.mark.asyncio
async def test_outbox_tamper_detection(tmp_path: Path):
    sk = load_or_create_signing_key(tmp_path / "k.key")
    signer = EnvelopeSigner(sk)
    db_file = tmp_path / "outbox.db"

    async with OutboxLedger(db_file, signer) as outbox:
        await outbox.enqueue([_sample_record(10.0)])
        await outbox.enqueue([_sample_record(20.0)])
        valid, _ = await outbox.verify_chain()
        assert valid is True

    # Tamper with row 2 payload_hash in the database
    async with aiosqlite.connect(db_file) as conn:
        await conn.execute("UPDATE outbox_ledger SET payload_hash = 'sha256:1111111111111111111111111111111111111111111111111111111111111111' WHERE seq = 2")
        await conn.commit()

    async with OutboxLedger(db_file, signer) as outbox:
        valid, reason = await outbox.verify_chain()
        assert valid is False
        assert "seq 2" in reason


@pytest.mark.asyncio
async def test_mark_acked_and_stats(tmp_path: Path):
    sk = load_or_create_signing_key(tmp_path / "k.key")
    signer = EnvelopeSigner(sk)
    db_file = tmp_path / "outbox.db"

    async with OutboxLedger(db_file, signer) as outbox:
        s0 = await outbox.stats()
        assert s0["outbox_depth"] == 0
        assert s0["last_acked_seq"] == 0

        e1 = await outbox.enqueue([_sample_record(1.0)])
        e2 = await outbox.enqueue([_sample_record(2.0)])

        s1 = await outbox.stats()
        assert s1["outbox_depth"] == 2
        assert s1["last_acked_seq"] == 0
        assert s1["highest_seq"] == 2

        receipt = {
            "payload_id": e1.payload_id,
            "payload_hash": e1.payload_hash,
            "status": "stored",
            "received_at": "2026-11-21T04:12:10.000Z",
            "region": "in",
            "highest_contiguous_seq": 1,
            "sig": "dGVzdC1zaWduYXR1cmUtZGF0YQ==",
        }
        await outbox.mark_acked(e1.payload_id, receipt)

        s2 = await outbox.stats()
        assert s2["outbox_depth"] == 1
        assert s2["last_acked_seq"] == 1
        assert s2["highest_seq"] == 2
        assert s2["total_sent_records"] == 1

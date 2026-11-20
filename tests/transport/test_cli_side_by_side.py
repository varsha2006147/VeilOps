"""Tests for ledger verification CLI, policy diff CLI, and side-by-side UI views."""
from __future__ import annotations

import json
from pathlib import Path

import aiosqlite
import pytest
from fastapi.testclient import TestClient

from veilops.collector.contracts import SourceBus
from veilops.collector.transport.cli import main, policy_diff, verify_ledger
from veilops.collector.transport.outbox import OutboxLedger
from veilops.collector.transport.signer import EnvelopeSigner, load_or_create_signing_key
from veilops.collector.ui.app import UIContext, create_app


def _sample_record(avg: float = 88.0) -> dict:
    return {
        "type": "metric",
        "entity": "h_7f3a21c90b",
        "entity_kind": "host",
        "metric": "cpu.util_pct",
        "unit": "pct",
        "avg": avg,
        "min": 85.0,
        "max": 90.0,
        "p95": 89.0,
        "count": 5,
        "window_s": 5,
        "event_ts": "2026-11-21T04:12:00.000Z",
        "source_tz": "UTC",
    }


@pytest.mark.asyncio
async def test_cli_verify_ledger_valid_and_tampered(tmp_path: Path):
    sk = load_or_create_signing_key(tmp_path / "k.key")
    signer = EnvelopeSigner(sk)
    db_file = tmp_path / "outbox.db"

    # 1. Valid ledger
    async with OutboxLedger(db_file, signer) as ledger:
        await ledger.enqueue([_sample_record(10.0)])
        await ledger.enqueue([_sample_record(20.0)])

    code = main(["verify-ledger", "--db", str(db_file)])
    assert code == 0

    # 2. Tampered ledger: alter payload_hash directly
    async with aiosqlite.connect(db_file) as conn:
        await conn.execute(
            "UPDATE outbox_ledger SET payload_hash = 'sha256:0000000000000000000000000000000000000000000000000000000000000000' WHERE seq = 2"
        )
        await conn.commit()

    code_tampered = main(["verify-ledger", "--db", str(db_file)])
    assert code_tampered == 1

    # 3. Missing database
    code_missing = main(["verify-ledger", "--db", str(tmp_path / "missing.db")])
    assert code_missing == 1


def test_cli_policy_diff_detection(tmp_path: Path):
    policy1_path = tmp_path / "policy1.yaml"
    policy2_path = tmp_path / "policy2.yaml"

    p1 = """
version: "1.0"
record_types:
  metric:
    fields: [type, entity, entity_kind, metric, unit, avg, min, max, p95, count, window_s, event_ts, source_tz]
  alert:
    fields: [type, alert_id, entity, rule, severity, template_id, params, event_ts, source_tz]
"""
    p2 = """
version: "2.0"
record_types:
  metric:
    fields: [type, entity, entity_kind, metric, unit, avg, min, max, p95, count, window_s, event_ts, source_tz, custom_tag]
  security_summary:
    fields: [type, category, severity, count, distinct_principals, distinct_sources, principals, sources, risk_score, window_s, event_ts, source_tz]
"""
    policy1_path.write_text(p1.strip(), encoding="utf-8")
    policy2_path.write_text(p2.strip(), encoding="utf-8")

    diff = policy_diff(policy1_path, policy2_path)
    assert diff["old_version"] == "1.0"
    assert diff["new_version"] == "2.0"
    assert "security_summary" in diff["added_record_types"]
    assert "alert" in diff["removed_record_types"]
    assert "custom_tag" in diff["field_changes"]["metric"]["added"]

    code = main(["policy-diff", "--old", str(policy1_path), "--new", str(policy2_path)])
    assert code == 0


@pytest.mark.asyncio
async def test_ui_side_by_side_and_policy_diff_views(tmp_path: Path):
    class DummyPipeline:
        bus = SourceBus()
        recent_signals = []
        recent_windows = []
        def snapshot(self): return {}

    class DummyStore:
        async def count(self): return 1
        async def recent(self, limit: int = 10, reveal: bool = False, *a, **k):
            return [
                {
                    "id": 101,
                    "source": "syslog",
                    "event_ts": "2026-11-21T04:12:00.000Z",
                    "raw": "login failed user=alice password=super_secret_hunter2 from 192.168.1.5",
                }
            ]
        async def audit(self, *a, **k): pass

    class DummyConfig:
        collector_id = "col_01"
        tenant_id = "t_test"
        region = "in"
        environment = "test"
        config_hash = "sha256:" + "0" * 64
        demo_mode = False
        downstream = "none"

    ctx = UIContext(DummyConfig(), DummyPipeline(), DummyStore(), {})
    app = create_app(ctx)
    client = TestClient(app)

    # 1. Side-by-side masked default view
    resp = client.get("/api/side-by-side")
    assert resp.status_code == 200
    rows = resp.json()
    assert len(rows) == 1
    assert rows[0]["id"] == 101
    assert "super_secret_hunter2" not in rows[0]["sanitized_preview"]
    assert "[REDACTED]" in rows[0]["sanitized_preview"]
    assert rows[0]["is_masked"] is True

    # 2. Policy diff self-comparison endpoint
    p_resp = client.get("/api/policy-diff")
    assert p_resp.status_code == 200
    diff_data = p_resp.json()
    assert diff_data["old_version"] == "1.0"
    assert diff_data["new_version"] == "1.0"
    assert diff_data["field_changes"] == {}

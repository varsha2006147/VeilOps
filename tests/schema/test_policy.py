"""Tests for policy loading, structure validation, and allow-list rules."""
from __future__ import annotations

from pathlib import Path

import pytest

from veilops.schema.policy import Policy, PolicyError, load_policy


def test_load_default_policy():
    policy = load_policy()
    assert isinstance(policy, Policy)
    assert policy.version == "1.0"
    assert "metric" in policy.record_types
    assert "alert" in policy.record_types
    assert "security_summary" in policy.record_types
    assert "health" in policy.record_types
    assert "topology" in policy.record_types
    assert policy.hash.startswith("sha256:")
    assert policy.policy_hash == policy.hash


def test_allowed_fields_for_known_record_types():
    policy = load_policy()
    metric_fields = policy.allowed_fields("metric")
    assert "entity" in metric_fields
    assert "metric" in metric_fields
    assert "avg" in metric_fields
    assert "event_ts" in metric_fields

    alert_fields = policy.allowed_fields("alert")
    assert "alert_id" in alert_fields
    assert "rule" in alert_fields
    assert "severity" in alert_fields


def test_allowed_fields_unknown_record_type_denied():
    policy = load_policy()
    with pytest.raises((KeyError, PolicyError)):
        policy.allowed_fields("unknown_record_type")


def test_policy_hash_is_deterministic():
    p1 = load_policy()
    p2 = load_policy()
    assert p1.hash == p2.hash
    assert len(p1.hash) == 7 + 64


def test_missing_file_raises_filenotfound():
    with pytest.raises(FileNotFoundError):
        load_policy("non_existent_policy_file.yaml")


def test_malformed_yaml_raises_policy_error(tmp_path: Path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("invalid: yaml: [", encoding="utf-8")
    with pytest.raises(PolicyError):
        load_policy(bad)


def test_missing_required_keys_raises_policy_error(tmp_path: Path):
    no_ver = tmp_path / "no_ver.yaml"
    no_ver.write_text("record_types: {metric: {fields: [a]}}", encoding="utf-8")
    with pytest.raises(PolicyError, match="version"):
        load_policy(no_ver)

    no_records = tmp_path / "no_records.yaml"
    no_records.write_text("version: '1.0'", encoding="utf-8")
    with pytest.raises(PolicyError, match="record_types"):
        load_policy(no_records)


def test_empty_fields_raises_policy_error(tmp_path: Path):
    empty_fields = tmp_path / "empty_fields.yaml"
    empty_fields.write_text("version: '1.0'\nrecord_types:\n  metric:\n    fields: []", encoding="utf-8")
    with pytest.raises(PolicyError, match="fields"):
        load_policy(empty_fields)

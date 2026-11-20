import json
import secrets

import pytest
import uuid_utils
from hypothesis import given, settings
from hypothesis import strategies as st

from veilops.schema.tripwire import (
    CANARIES,
    CANARY_MARKER,
    TripwireHit,
    canary_by_id,
    canary_values,
    first_hit,
    scan_bytes,
    scan_text,
)

JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)
GITHUB = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"


def test_registry_shape():
    assert [c.canary_id for c in CANARIES] == ["c01", "c02", "c03", "c04", "c05"]
    assert len(canary_values()) == 5
    for c in CANARIES:
        assert c.value.upper().count(CANARY_MARKER) == 1
        assert (CANARY_MARKER + c.canary_id[1:]) in c.value
        assert canary_by_id(c.canary_id) == c
    assert canary_by_id("c99") is None


def test_each_canary_is_detected_with_its_id_first():
    for c in CANARIES:
        hits = scan_text(c.value)
        assert hits[0] == TripwireHit("canary", c.canary_id), c.canary_id


def test_canary_is_case_insensitive_and_digits_optional():
    assert scan_text("x veilopscanary02 y") == [TripwireHit("canary", "c02")]
    assert scan_text("VEILOPSCANARY") == [TripwireHit("canary", None)]


@pytest.mark.parametrize(
    "text, rule",
    [
        ("-----BEGIN RSA PRIVATE KEY-----", "private_key"),
        ("t " + JWT, "jwt"),
        ("key AKIAIOSFODNN7EXAMPLE end", "aws_access_key"),
        ("tok " + GITHUB + " end", "github_token"),
        ("hook xoxb-1234567890-abcdefghij end", "slack_token"),
        ("Authorization: Bearer abcdef1234567890", "bearer_token"),
        ("login ok password=hunter2 retry", "secret_assignment"),
        ("ERROR postgres://app:S3cr3t!@db-prod-02:5432", "conn_string"),
        ("contact priya@acme.in now", "email"),
        ("from 10.2.3.4 port", "ipv4"),
    ],
)
def test_each_rule_fires(text, rule):
    assert TripwireHit(rule) in scan_text(text)


def test_clean_text_has_no_hits():
    assert scan_text("event 2026-11-21T04:12:07.512Z cpu high on svc_1b9e0a count=5") == []


def _envelope():
    h = lambda: "h_" + secrets.token_hex(5)  # noqa: E731
    return {
        "schema_version": "1.0",
        "payload_id": str(uuid_utils.uuid7()),
        "tenant_id": "t_acme",
        "collector_id": "col_blr_01",
        "region": "in",
        "seq": 1042,
        "sent_at": "2026-11-21T04:12:07.530Z",
        "policy": {"version": 1, "hash": "sha256:" + secrets.token_hex(32)},
        "chain": {
            "prev_hash": "sha256:" + secrets.token_hex(32),
            "payload_hash": "sha256:" + secrets.token_hex(32),
        },
        "records": [
            {"type": "metric", "entity": h(), "entity_kind": "host", "metric": "cpu.util_pct",
             "unit": "pct", "avg": 91.2, "min": 88.0, "max": 94.1, "p95": 93.8, "count": 5,
             "window_s": 5, "event_ts": "2026-11-21T04:12:00.000Z", "source_tz": "Asia/Kolkata"},
            {"type": "security_summary", "category": "auth.password_spray", "severity": "high",
             "count": 37, "distinct_principals": 8, "distinct_sources": 1,
             "principals": ["usr_" + secrets.token_hex(5)], "sources": ["src_" + secrets.token_hex(5)],
             "risk_score": 82, "window_s": 60, "event_ts": "2026-11-21T04:12:05.000Z",
             "source_tz": "Asia/Kolkata"},
            {"type": "alert", "alert_id": str(uuid_utils.uuid7()), "entity": h(),
             "rule": "log.sec.access_denied", "severity": "warning", "template_id": "T_LOG_CATEGORY",
             "params": {"count": 3}, "event_ts": "2026-11-21T04:12:04.000Z",
             "source_tz": "Asia/Kolkata"},
            {"type": "health", "entity": h(), "state": "fair",
             "reasons": ["cpu.util_pct 93.8 % (threshold 90 %) for 15 s"],
             "event_ts": "2026-11-21T04:12:05.000Z"},
        ],
    }


def test_realistic_envelopes_never_false_positive():
    for _ in range(300):
        body = json.dumps(_envelope()).encode("utf-8")
        assert scan_bytes(body) == []


def test_json_escaped_canary_is_found_after_unescaping():
    body = b'{"u":"\\u0056EILOPSCANARY02"}'
    assert scan_bytes(body) == [TripwireHit("canary", "c02")]


def test_non_json_and_invalid_utf8_are_safe():
    assert scan_bytes(b"\xff\xfe\x00") == []
    assert TripwireHit("secret_assignment") in scan_bytes(b"not json password=hunter2")


def test_hits_never_contain_matched_text():
    hits = scan_text("password=hunter2 postgres://app:S3cr3t!@db:5432")
    assert hits
    assert "hunter2" not in repr(hits) and "S3cr3t" not in repr(hits)


def test_first_hit():
    assert first_hit(b"{}") is None
    body = json.dumps({"u": CANARIES[2].value}).encode("utf-8")
    assert first_hit(body) == TripwireHit("canary", "c03")


SAMPLES = list(canary_values()) + [
    JWT,
    "AKIAIOSFODNN7EXAMPLE",
    GITHUB,
    "xoxb-1234567890-abcdefghij",
    "Bearer abcdef1234567890",
    "password=hunter2",
    "postgres://app:S3cr3t!@db-prod-02:5432",
    "priya@acme.in",
    "10.2.3.4",
    "-----BEGIN PRIVATE KEY-----",
]
_FILLER = st.text(alphabet=st.characters(whitelist_categories=("L",)), max_size=20)


@settings(max_examples=200, deadline=None)
@given(prefix=_FILLER, suffix=_FILLER, sample=st.sampled_from(SAMPLES))
def test_fuzz_secret_inside_json_string_is_always_detected(prefix, suffix, sample):
    body = json.dumps({"msg": f"{prefix} {sample} {suffix}"}).encode("utf-8")
    assert scan_bytes(body)

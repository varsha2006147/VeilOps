import copy
import json

import pytest
from pydantic import ValidationError

from veilops.schema import GENESIS_HASH, Envelope

H64 = "0" * 64
GOOD = {
    "schema_version": "1.0",
    "payload_id": "0193b7c2-5e1a-7c3d-9f00-1a2b3c4d5e6f",
    "tenant_id": "t_acme",
    "collector_id": "col_blr_01",
    "region": "in",
    "seq": 1042,
    "sent_at": "2026-11-21T04:12:07.530Z",
    "policy": {"version": 3, "hash": "sha256:" + "a" * 64},
    "chain": {"prev_hash": GENESIS_HASH, "payload_hash": "sha256:" + "b" * 64},
    "records": [
        {"type": "metric", "entity": "h_7f3a21c90b", "entity_kind": "host",
         "metric": "cpu.util_pct", "unit": "pct", "avg": 91.2, "min": 88.0,
         "max": 94.1, "p95": 93.8, "count": 5, "window_s": 5,
         "event_ts": "2026-11-21T04:12:00.000Z", "source_tz": "Asia/Kolkata"},
        {"type": "security_summary", "category": "auth.bruteforce",
         "severity": "high", "count": 37, "distinct_principals": 1,
         "distinct_sources": 1, "principals": ["usr_4f1a9c02de"],
         "sources": ["src_9c1e44aa01"], "risk_score": 82, "window_s": 60,
         "event_ts": "2026-11-21T04:12:05.000Z", "source_tz": "Asia/Kolkata"},
        {"type": "alert", "alert_id": "0193b7c2-5e1a-7c3d-9f00-1a2b3c4d5e6f",
         "entity": "h_7f3a21c90b", "rule": "threshold.cpu.high",
         "severity": "warning", "template_id": "T_CPU_HIGH",
         "params": {"value": 93.8, "threshold": 90},
         "event_ts": "2026-11-21T04:12:04.000Z", "source_tz": "Asia/Kolkata"},
        {"type": "health", "entity": "h_7f3a21c90b", "state": "fair",
         "reasons": ["cpu.util_pct 93.8 % (threshold 90 %) for 15 s"],
         "event_ts": "2026-11-21T04:12:05.000Z"},
    ],
}


def parse(d):
    return Envelope.model_validate_json(json.dumps(d))


def mutated(fn):
    d = copy.deepcopy(GOOD)
    fn(d)
    return d


def test_valid_envelope_roundtrips():
    e = parse(GOOD)
    assert Envelope.model_validate_json(e.model_dump_json()) == e


def test_extra_field_is_rejected():
    d = mutated(lambda d: d["records"][0].update(raw_message="secret"))
    with pytest.raises(ValidationError):
        parse(d)


def test_real_hostname_is_rejected():
    d = mutated(lambda d: d["records"][0].update(entity="db-prod-02"))
    with pytest.raises(ValidationError):
        parse(d)


def test_secret_in_alert_params_is_rejected():
    d = mutated(lambda d: d["records"][2]["params"].update(value="AKIAVEILOPSCANARY01"))
    with pytest.raises(ValidationError):
        parse(d)


def test_connection_string_in_health_reason_is_rejected():
    d = mutated(lambda d: d["records"][3].update(
        reasons=["db connect failed postgres://app:S3cr3t!@db-prod-02:5432"]))
    with pytest.raises(ValidationError):
        parse(d)


def test_unknown_record_type_is_rejected():
    d = mutated(lambda d: d["records"][0].update(type="raw_log"))
    with pytest.raises(ValidationError):
        parse(d)


def test_non_utc_timestamp_is_rejected():
    d = mutated(lambda d: d["records"][0].update(event_ts="2026-11-21T09:42:00+05:30"))
    with pytest.raises(ValidationError):
        parse(d)


def test_string_instead_of_number_is_rejected_in_strict_mode():
    d = mutated(lambda d: d["records"][0].update(avg="91.2"))
    with pytest.raises(ValidationError):
        parse(d)


def test_empty_records_rejected():
    d = mutated(lambda d: d.update(records=[]))
    with pytest.raises(ValidationError):
        parse(d)


def test_metric_record_rps_unit_allowed():
    d = mutated(lambda d: d["records"][0].update(metric="load.req_rate", unit="rps"))
    e = parse(d)
    assert e.records[0].unit == "rps"
    assert e.records[0].metric == "load.req_rate"


def test_security_summary_spray_and_stuffing_categories_allowed():
    for cat in ["auth.spray", "auth.stuffing"]:
        d = mutated(lambda d, c=cat: d["records"][1].update(category=c))
        e = parse(d)
        assert e.records[1].category == cat


def test_topology_edge_connects_via_allowed():
    d = mutated(lambda d: d["records"].append({
        "type": "topology",
        "edges": [{"src": "svc_1a2b3c4d5e", "dst": "lnk_9a8b7c6d5e", "rel": "connects_via"}],
        "event_ts": "2026-11-21T04:12:00.000Z",
    }))
    e = parse(d)
    assert e.records[-1].type == "topology"
    assert e.records[-1].edges[0].rel == "connects_via"

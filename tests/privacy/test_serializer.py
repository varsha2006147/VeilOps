import re
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from veilops.collector.contracts import LocalSignal, WindowAgg
from veilops.collector.privacy.pseudonymizer import Pseudonymizer, PseudonymStore
from veilops.collector.privacy.serializer import RecordSerializer, SerializationError
from veilops.schema.policy import load_policy
from veilops.schema.records import AlertRecord, MetricRecord, SecuritySummaryRecord

T0 = datetime(2026, 11, 21, 4, 12, 0, tzinfo=timezone.utc)
KEY = b"\x01" * 32


def make_serializer(entity_kinds=None, policy=None):
    ps = Pseudonymizer(KEY, PseudonymStore())
    return RecordSerializer(policy or load_policy(), ps, entity_kinds), ps


def window(**over):
    base = dict(
        entity="db-prod-02", entity_kind="host", metric="cpu.util_pct", unit="pct",
        avg=91.2, min=88.0, max=94.1, p95=93.8, count=5, window_s=5,
        event_ts=T0, source_tz="Asia/Kolkata",
    )
    base.update(over)
    return WindowAgg(**base)


def signal(**over):
    base = dict(
        kind="threshold", rule="threshold.cpu.high", severity="warning",
        entity="db-prod-02", event_ts=T0, source_tz="Asia/Kolkata",
        params={"value": 93.8, "threshold": 90}, priority=True,
    )
    base.update(over)
    return LocalSignal(**base)


def security_signal(**over):
    base = dict(
        kind="security", rule="auth.bruteforce", severity="high",
        entity="auth-host", event_ts=T0, source_tz="Asia/Kolkata",
        params={"count": 37}, subjects=["priya"], sources=["10.2.3.4"],
        risk_score=82, window_s=60, priority=True,
    )
    base.update(over)
    return LocalSignal(**base)


def test_metric_record_is_pseudonymized_and_well_formed():
    ser, ps = make_serializer()
    rec = ser.serialize_window(window())
    assert isinstance(rec, MetricRecord) and rec.type == "metric"
    assert re.fullmatch(r"h_[0-9a-f]{10}", rec.entity)
    assert rec.event_ts == "2026-11-21T04:12:00.000Z"
    assert "db-prod-02" not in rec.model_dump_json()
    assert ps.resolve(rec.entity) == ("host", "db-prod-02")


def test_non_utc_aware_datetime_is_converted_to_utc():
    ist = timezone(timedelta(hours=5, minutes=30))
    ser, _ = make_serializer()
    rec = ser.serialize_window(window(event_ts=datetime(2026, 11, 21, 9, 42, 0, tzinfo=ist)))
    assert rec.event_ts == "2026-11-21T04:12:00.000Z"


def test_naive_datetime_and_nan_fail_closed():
    ser, _ = make_serializer()
    with pytest.raises(SerializationError):
        ser.serialize_window(window(event_ts=datetime(2026, 11, 21, 4, 12, 0)))
    with pytest.raises(SerializationError) as info:
        ser.serialize_window(window(avg=float("nan")))
    assert any(p.startswith("avg") for p in info.value.problems)


def test_error_messages_never_contain_input_values():
    ser, _ = make_serializer()
    with pytest.raises(SerializationError) as info:
        ser.serialize_window(window(unit="SECRET-UNIT-xyz"))
    assert "SECRET-UNIT-xyz" not in str(info.value)
    assert "unit" in str(info.value)


def test_threshold_alert():
    ser, _ = make_serializer()
    metric = ser.serialize_window(window())
    alert = ser.serialize_signal(signal())
    assert isinstance(alert, AlertRecord)
    assert alert.template_id == "T_CPU_HIGH"
    assert alert.rule == "threshold.cpu.high"
    assert alert.params == {"value": 93.8, "threshold": 90}
    assert alert.entity == metric.entity
    assert re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", alert.alert_id)


def test_alert_id_override():
    ser, _ = make_serializer()
    fixed = "0193b7c2-5e1a-7c3d-9f00-1a2b3c4d5e6f"
    assert ser.serialize_signal(signal(), alert_id=fixed).alert_id == fixed


def test_log_category_alert_uses_service_kind_when_known():
    ser, _ = make_serializer(entity_kinds={"svc-checkout": "service"})
    alert = ser.serialize_signal(
        signal(kind="log_category", rule="db.connect_error", entity="svc-checkout",
               params={"count": 1})
    )
    assert alert.rule == "log.db.connect_error"
    assert alert.template_id == "T_LOG_CATEGORY"
    assert alert.params == {"count": 1}
    assert alert.entity.startswith("svc_")


def test_invalid_alert_rule_and_params_fail_closed():
    ser, _ = make_serializer()
    with pytest.raises(SerializationError):
        ser.serialize_signal(signal(rule="Threshold.CPU"))
    with pytest.raises(SerializationError):
        ser.serialize_signal(signal(params={"Bad-Key": 1}))
    with pytest.raises(SerializationError):
        ser.serialize_signal(signal(params={"value": float("inf")}))


def test_security_summary_hides_usernames_and_addresses():
    ser, ps = make_serializer()
    rec = ser.serialize_signal(security_signal())
    assert isinstance(rec, SecuritySummaryRecord)
    assert rec.category == "auth.bruteforce"
    assert rec.count == 37 and rec.distinct_principals == 1 and rec.distinct_sources == 1
    assert rec.principals[0].startswith("usr_") and rec.sources[0].startswith("src_")
    dumped = rec.model_dump_json()
    assert "priya" not in dumped and "10.2.3.4" not in dumped
    assert ps.resolve(rec.principals[0]) == ("principal", "priya")


def test_security_lists_are_capped_at_20_but_distinct_counts_stay_true():
    ser, _ = make_serializer()
    rec = ser.serialize_signal(
        security_signal(subjects=[f"REAL-u{i}" for i in range(25)], rule="auth.password_spray")
    )
    assert len(rec.principals) == 20
    assert rec.distinct_principals == 25
    assert list(rec.principals) == sorted(rec.principals)


def test_security_missing_count_or_unknown_category_fail_closed():
    ser, _ = make_serializer()
    with pytest.raises(SerializationError):
        ser.serialize_signal(security_signal(params={}))
    with pytest.raises(SerializationError):
        ser.serialize_signal(security_signal(rule="auth.foo"))


def test_unsupported_signal_kind_fails_closed():
    ser, _ = make_serializer()
    with pytest.raises(SerializationError):
        ser.serialize_signal(signal(kind="mystery"))


def test_field_missing_from_policy_is_never_sent_and_fails_closed():
    base = load_policy()
    rp = base.record_types["metric"]
    trimmed = replace(
        base,
        record_types={
            **base.record_types,
            "metric": replace(rp, fields=tuple(f for f in rp.fields if f != "p95")),
        },
    )
    ser, _ = make_serializer(policy=trimmed)
    with pytest.raises(SerializationError) as info:
        ser.serialize_window(window())
    assert any(p.startswith("p95") for p in info.value.problems)


def test_allowed_field_without_producer_fails_closed():
    base = load_policy()
    rp = base.record_types["metric"]
    widened = replace(
        base,
        record_types={
            **base.record_types,
            "metric": replace(rp, fields=rp.fields + ("hostname",)),
        },
    )
    ser, _ = make_serializer(policy=widened)
    with pytest.raises(SerializationError) as info:
        ser.serialize_window(window())
    assert info.value.problems == ["hostname:no_producer"]


_NAME = st.text(alphabet=st.characters(blacklist_categories=("Cs", "Cc")), min_size=1, max_size=30)


@settings(max_examples=100, deadline=None)
@given(host=_NAME, user=_NAME, addr=_NAME)
def test_fuzz_real_identifiers_never_appear_in_wire_json(host, user, addr):
    ser, _ = make_serializer()
    metric = ser.serialize_window(window(entity="REAL-" + host))
    summary = ser.serialize_signal(
        security_signal(subjects=["REAL-" + user], sources=["REAL-" + addr])
    )
    alert = ser.serialize_signal(signal(entity="REAL-" + host))
    for rec in (metric, summary, alert):
        assert "REAL-" not in rec.model_dump_json()


def test_collector_security_rule_names_map_to_canonical_categories():
    ser, _ = make_serializer()
    spray = ser.serialize_signal(security_signal(rule="auth.spray"))
    stuffing = ser.serialize_signal(security_signal(rule="auth.stuffing", severity="critical"))
    brute = ser.serialize_signal(security_signal(rule="auth.bruteforce"))
    assert spray.category == "auth.password_spray"
    assert stuffing.category == "auth.credential_stuffing"
    assert brute.category == "auth.bruteforce"


def test_load_rate_metric_with_rps_unit_is_accepted():
    ser, _ = make_serializer()
    rec = ser.serialize_window(
        window(metric="load.req_rate", unit="rps", entity="app-01", entity_kind="host")
    )
    assert rec.unit == "rps" and rec.metric == "load.req_rate"


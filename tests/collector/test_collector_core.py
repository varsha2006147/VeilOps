"""Member A: collector core tests (normalize, stream mapping, aggregation, detectors, raw store, sim)."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from veilops.collector.config import AuthRules, Thresholds
from veilops.collector.contracts import AuthEvent, MetricSample, RawEvent, SourceBus
from veilops.collector.pipeline.aggregate import Aggregator
from veilops.collector.pipeline.detect import AuthDetector, LogCategoryDetector, ThresholdDetector
from veilops.collector.pipeline.normalize import normalize
from veilops.collector.pipeline.rawstore import RawStore, mask
from veilops.collector.sources.stream import StreamMapper
from veilops.collector.timeutil import parse_ts

T0 = datetime(2026, 11, 21, 4, 12, 0, tzinfo=timezone.utc)


def ms(v, sec, metric="cpu.util_pct", entity="app-01"):
    return MetricSample(entity, "host", metric, "pct", v, T0 + timedelta(seconds=sec), "Asia/Kolkata")


# ---------- time ----------
def test_naive_timestamp_uses_source_zone():
    assert parse_ts("2026-11-21 09:42:00", "Asia/Kolkata") == T0.replace(minute=12)
    assert parse_ts(1795230720000).tzinfo is not None


# ---------- stream mapping ----------
def test_mapper_long_and_wide_formats_and_tenant_filter():
    m = StreamMapper({"tenant_filter": "t_acme"}, "UTC")
    ev = m.map({"ts": "2026-11-21T04:12:00Z", "tenant": "t_acme", "host": "app-01", "kind": "metric",
                "metric": "cpu", "value": 91}, "{}")
    assert [s.metric for s in normalize(ev)] == ["cpu.util_pct"]
    wide = m.map({"timestamp": 1795230720, "hostname": "db-01", "cpu": 40, "memory": "71%", "latency": 3}, "{}")
    assert {s.metric for s in normalize(wide)} == {"cpu.util_pct", "mem.util_pct", "net.latency_ms"}
    assert m.map({"tenant": "t_globex", "host": "x", "cpu": 1}, "{}") is None
    assert m.skipped_other_tenant == 1


def test_parse_text_accepts_array_envelope_jsonl_and_plain_lines():
    m = StreamMapper()
    assert len(m.parse_text('[{"a":1},{"b":2}]')) == 2
    assert len(m.parse_text('{"records":[{"a":1}]}')) == 1
    assert len(m.parse_text('{"a":1}\n{"b":2}\nplain text')) == 3


# ---------- normalize ----------
def test_auth_and_log_parsing_keeps_message_local():
    ev = RawEvent("syslog", T0, "UTC", "x", {"kind": "line", "entity": "bastion-01",
                                             "line": "sshd[1]: Failed password for invalid user admin from 203.0.113.5 port 22 ssh2"})
    (a,) = normalize(ev)
    assert isinstance(a, AuthEvent) and a.principal == "admin" and a.source_addr == "203.0.113.5"
    ev2 = RawEvent("stream", T0, "UTC", "x", {"kind": "log", "entity": "app-01", "level": "ERROR",
                                              "message": "db connect failed: postgres://u:p@db:5432 timeout"})
    (lg,) = normalize(ev2)
    assert lg.category == "db.connect_error"
    assert not hasattr(lg, "message")          # no message text field exists on LogEvent


def test_unknown_metric_dropped_and_bool_values():
    assert normalize(RawEvent("s", T0, "UTC", "", {"kind": "metric", "entity": "e", "metric": "weird", "value": 1})) == []
    (s,) = normalize(RawEvent("s", T0, "UTC", "", {"kind": "metric", "entity": "checkout", "metric": "up", "value": "down"}))
    assert s.metric == "svc.up" and s.value == 0.0 and s.entity_kind == "service"


# ---------- aggregation ----------
def test_tumbling_windows_by_event_time_and_late_reemit():
    agg = Aggregator(window_s=5, grace_s=1, lateness_s=300)
    for i, v in enumerate([10, 20, 30, 40, 50]):
        agg.add(ms(v, i))
    agg.add(ms(99, 7))                         # watermark 7 - 1 = 6 >= window end 5
    (w,) = agg.flush()
    assert (w.count, w.min, w.max, w.avg, w.p95) == (5, 10, 50, 30, 50)
    assert w.event_ts == T0
    late = agg.add(ms(60, 3))                  # out-of-order sample for the closed window
    assert len(late) == 1 and late[0].count == 6 and late[0].event_ts == T0
    assert agg.late_count == 1


def test_silent_source_window_closes_by_wall_clock():
    agg = Aggregator(window_s=5, grace_s=0)
    agg.add(ms(10, 0))
    assert agg.flush(force=True)[0].count == 1


# ---------- detectors ----------
def test_threshold_persistence_single_alert_and_resolve():
    d = ThresholdDetector(Thresholds())
    out = []
    for i, v in enumerate([95, 40, 96, 97, 98, 99]):
        out += d.observe(ms(v, i))
    fired = [s for s in out if not s.rule.endswith("resolved")]
    assert len(fired) == 1 and fired[0].priority and fired[0].rule == "threshold.cpu.high"
    for i in range(5):
        out += d.observe(ms(30, 10 + i))
    assert out[-1].rule == "threshold.cpu.high.resolved" and out[-1].params["peak"] == 99


def test_threshold_below_rule_for_service_down():
    d = ThresholdDetector(Thresholds())
    sigs = []
    for i in range(3):
        sigs += d.observe(MetricSample("auth-api", "service", "svc.up", "bool", 0.0, T0 + timedelta(seconds=i), "UTC"))
    assert sigs and sigs[0].rule == "threshold.svc.down" and sigs[0].severity == "critical"


def auth(i, user="admin", ip="203.0.113.50", outcome="failure"):
    return AuthEvent(outcome, user, ip, "bastion-01", T0 + timedelta(seconds=i), "UTC")


def test_bruteforce_then_stuffing():
    d = AuthDetector(AuthRules())
    sigs = []
    for i in range(12):
        sigs += d.observe(auth(i))
    bf = [s for s in sigs if s.rule == "auth.bruteforce"]
    assert len(bf) == 1 and bf[0].params["count"] == 10 and bf[0].risk_score == 70
    sigs = d.observe(auth(13, outcome="success"))
    assert sigs and sigs[0].rule == "auth.stuffing" and sigs[0].severity == "critical"


def test_spray_detection_and_window_expiry():
    d = AuthDetector(AuthRules())
    sigs = []
    for i in range(9):
        sigs += d.observe(auth(i, user=f"u{i}", ip="198.51.100.23"))
    assert any(s.rule == "auth.spray" and s.params["distinct_principals"] == 8 for s in sigs)
    d2 = AuthDetector(AuthRules())
    for i in range(9):                         # spread over > 60 s: never 10 inside the window
        assert not d2.observe(auth(i * 8))


def test_log_category_emits_on_first_and_doubling():
    from veilops.collector.contracts import LogEvent
    d = LogCategoryDetector()
    counts = [len(d.observe(LogEvent("app-01", "db.connect_error", "error", T0 + timedelta(seconds=i), "UTC")))
              for i in range(5)]
    assert counts == [1, 1, 0, 1, 0]           # n = 1, 2, 4


# ---------- raw store ----------
async def test_rawstore_masks_by_default_reveals_on_request():
    st = RawStore(":memory:")
    await st.open()
    await st.insert(RawEvent("stream", T0, "UTC", "conn postgres://app:S3cr3t@db:5432 password=hunter2", {}))
    await st.commit()
    (row,) = await st.recent()
    assert "S3cr3t" not in row["raw"] and "hunter2" not in row["raw"]
    (row,) = await st.recent(reveal=True)
    assert "S3cr3t" in row["raw"]
    assert "Bearer ••••••" in mask("Authorization: Bearer eyJabc.def.ghi")
    await st.close()


# ---------- end to end through the pipeline with the simulator ----------
async def test_pipeline_with_simulator_scenarios(tmp_path):
    from veilops.collector.config import CollectorConfig
    from veilops.collector.pipeline.runner import Pipeline
    from veilops.sim import Simulator

    cfg = CollectorConfig("col_t", "t_acme", "in", "https://x", db_path=str(tmp_path / "c.db"))
    store = RawStore(cfg.db_path)
    await store.open()
    bus = SourceBus()
    p = Pipeline(cfg, bus, store)
    mapper = StreamMapper({"tenant_filter": "t_acme"}, "Asia/Kolkata")
    sim = Simulator("t_acme")
    for scen in ("cpu_drift", "failed_logins", "secret", "latency"):
        sim.inject(scen, now=T0)
    for i in range(80):
        for rec in sim.tick(T0 + timedelta(seconds=i)):
            ev = mapper.map(rec, json.dumps(rec))
            await p.ingest(ev)
        for w in p.agg.flush():
            p._window(w)
    rules = {s.rule for s in p.recent_signals}
    assert {"threshold.cpu.high", "auth.bruteforce", "auth.stuffing", "threshold.loss.high"} <= rules
    assert any(r.startswith("log.db.connect_error") for r in rules)
    assert p.stats.windows_out > 50 and bus.windows.qsize() == p.stats.windows_out
    # nothing on the bus carries raw log text
    blob = repr(list(bus.signals._queue)) + repr(list(bus.windows._queue))
    assert "S3cr3t" not in blob and "hunter2" not in blob and "AKIA" not in blob
    await store.close()


async def test_load_spike_does_not_breach_but_drift_does():
    from veilops.sim import Simulator
    sim = Simulator("t_acme")
    sim.inject("load_spike", now=T0, duration_s=60)
    peak = max(r["value"] for i in range(60) for r in sim.tick(T0 + timedelta(seconds=i))
               if r.get("metric") == "cpu" and r["host"] == "app-01")
    assert peak < 90                           # load-driven: rises but stays proportional


def test_every_signal_carries_entity_kind_and_template():
    """B needs entity_kind (pseudonym prefix) and template_id (numbers-only alert) on every LocalSignal."""
    from veilops.collector.contracts import LogEvent
    sigs = []
    d = ThresholdDetector(Thresholds())
    for i, v in enumerate([300, 300, 300] + [10] * 5):
        sigs += d.observe(MetricSample("core-sw1", "link", "net.latency_ms", "ms", v, T0 + timedelta(seconds=i), "UTC"))
    a = AuthDetector(AuthRules())
    for i in range(10):
        sigs += a.observe(auth(i))
    sigs += LogCategoryDetector().observe(LogEvent("app-01", "db.connect_error", "error", T0, "UTC"))
    assert [(s.rule, s.entity_kind, s.template_id) for s in sigs] == [
        ("threshold.latency.high", "link", "T_LATENCY_HIGH"),
        ("threshold.latency.high.resolved", "link", "T_LATENCY_HIGH_RESOLVED"),
        ("auth.bruteforce", "host", "T_AUTH_BRUTEFORCE"),
        ("log.db.connect_error", "host", "T_LOG_CATEGORY"),
    ]


def test_config_hash_is_full_sha256():
    """Heartbeat.config_hash in B's schema requires ^sha256:[0-9a-f]{64}$."""
    import re
    from veilops.collector.config import CollectorConfig
    h = CollectorConfig.load("veilops/collector/collector.example.yaml").config_hash
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", h)

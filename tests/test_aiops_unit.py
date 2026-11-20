"""Unit tests for VeilOps Cloud AIOps algorithms (offline, pure logic, zero DB).

Covers:
1. BFS topology reachability and sliding 5m incident grouping
2. Root-cause multi-factor candidate ranking (upstream + earliness + severity)
3. Load-aware CPU surge vs. CPU runaway classification
4. Rolling baselines and robust z-score statistics
5. Multivariate IsolationForest anomaly detection on multidimensional vectors
6. Evidence citations [n] in generated explanations
7. Catalog action recommendation mapping and confidence bounds
"""
from datetime import datetime, timedelta, timezone
import pytest

from cloud.app.aiops.baseline import compute_baseline, compute_robust_z, check_baseline_anomalies
from cloud.app.aiops.anomaly import (
    IsolationForestAnomalyDetector,
    is_load_driven_cpu,
    classify_cpu_behavior,
)
from cloud.app.aiops.correlate import (
    are_entities_connected,
    group_alerts_into_incidents,
    is_incident_resolved,
)
from cloud.app.aiops.rootcause import rank_root_cause
from cloud.app.aiops.explain import generate_incident_explanation
from cloud.app.aiops.recommend import generate_recommendation, ACTION_CATALOG


def test_baseline_and_robust_z_score():
    """Verify median, MAD, EWMA and robust z calculation."""
    # Data centered around 10.0 with known variation
    values = [10.0, 10.5, 9.5, 10.0, 10.2, 9.8, 10.0, 10.1, 9.9, 10.0]
    med, mad, ewma = compute_baseline(values)

    assert 9.9 <= med <= 10.1
    assert mad >= 0.0
    assert 9.9 <= ewma <= 10.1

    # Exact normal consistency test: z-score of median is 0
    z_zero = compute_robust_z(med, med, mad)
    assert abs(z_zero) < 1e-6

    # Extreme value: 100.0 with MAD ~ 0.1 gives |z| > 50
    z_extreme = compute_robust_z(100.0, med, mad)
    assert z_extreme > 10.0

    # Zero MAD handling: no division by zero
    z_flat = compute_robust_z(10.0, 10.0, 0.0)
    assert z_flat == 0.0

    # 3 of 5 windows anomaly threshold
    anom_vals = [10.0, 10.0, 50.0, 60.0, 70.0]
    is_anom, latest_z = check_baseline_anomalies(anom_vals, med, mad, threshold=4.0, min_breaches=3)
    assert is_anom is True
    assert latest_z > 4.0


def test_load_aware_cpu_classification():
    """Verify load-aware detection suppresses surge and isolates runaway."""
    # Scenario A: CPU high (88%), but load.req_rate rose 80% (baseline 10 -> current 18)
    assert is_load_driven_cpu(cpu_val=88.0, cpu_baseline=30.0, req_val=18.0, req_baseline=10.0) is True
    assert classify_cpu_behavior(cpu_val=88.0, cpu_baseline=30.0, req_val=18.0, req_baseline=10.0) == "load_driven"

    # Scenario B: CPU high (92%), but load.req_rate flat (baseline 20 -> current 20.5, rose 2.5%)
    assert is_load_driven_cpu(cpu_val=92.0, cpu_baseline=25.0, req_val=20.5, req_baseline=20.0) is False
    assert classify_cpu_behavior(cpu_val=92.0, cpu_baseline=25.0, req_val=20.5, req_baseline=20.0) == "cpu_runaway"

    # Scenario C: Normal CPU (35%), normal load
    assert classify_cpu_behavior(cpu_val=35.0, cpu_baseline=30.0, req_val=10.0, req_baseline=10.0) == "normal"


def test_bfs_connectivity():
    """Verify undirected BFS path finding up to depth 3."""
    edges = [
        ("svc_A", "h_1"),
        ("h_1", "lnk_1"),
        ("lnk_1", "h_2"),
        ("h_2", "svc_B"),
    ]
    # svc_A -> h_1 -> lnk_1 is distance 2 (<= 3) -> connected
    assert are_entities_connected("svc_A", "lnk_1", edges, max_depth=3) is True

    # svc_A -> h_1 -> lnk_1 -> h_2 is distance 3 (<= 3) -> connected
    assert are_entities_connected("svc_A", "h_2", edges, max_depth=3) is True

    # svc_A -> h_1 -> lnk_1 -> h_2 -> svc_B is distance 4 (> 3) -> not connected with depth=3
    assert are_entities_connected("svc_A", "svc_B", edges, max_depth=3) is False

    # Disconnected entity
    assert are_entities_connected("svc_A", "h_isolated", edges, max_depth=3) is False


def test_correlate_alert_grouping():
    """Verify alerts within 5m sliding window and topology graph group into single incident."""
    now = datetime.now(timezone.utc)
    edges = [
        ("svc_checkout", "h_app1"),
        ("h_app1", "lnk_core"),
        ("h_db1", "lnk_core"),
    ]

    alerts = [
        {
            "alert_id": "a1",
            "entity": "lnk_core",
            "rule": "threshold.loss.high",
            "severity": "critical",
            "first_ts": now - timedelta(seconds=60),
            "last_ts": now - timedelta(seconds=10),
            "status": "open",
        },
        {
            "alert_id": "a2",
            "entity": "h_app1",
            "rule": "threshold.latency.high",
            "severity": "high",
            "first_ts": now - timedelta(seconds=50),
            "last_ts": now - timedelta(seconds=10),
            "status": "open",
        },
        {
            "alert_id": "a3",
            "entity": "svc_checkout",
            "rule": "threshold.svc.down",
            "severity": "critical",
            "first_ts": now - timedelta(seconds=40),
            "last_ts": now - timedelta(seconds=10),
            "status": "open",
        },
        # Unconnected alert
        {
            "alert_id": "a4",
            "entity": "h_other",
            "rule": "threshold.disk.full",
            "severity": "warning",
            "first_ts": now - timedelta(seconds=30),
            "last_ts": now - timedelta(seconds=10),
            "status": "open",
        },
    ]

    clusters = group_alerts_into_incidents(alerts, edges, window_seconds=300)
    assert len(clusters) == 2

    # Group 1 has 3 connected alerts (lnk_core, h_app1, svc_checkout)
    c1 = next(c for c in clusters if any(a["alert_id"] == "a1" for a in c))
    assert len(c1) == 3
    assert {a["alert_id"] for a in c1} == {"a1", "a2", "a3"}

    # Group 2 has unconnected alert (h_other)
    c2 = next(c for c in clusters if any(a["alert_id"] == "a4" for a in c))
    assert len(c2) == 1
    assert c2[0]["alert_id"] == "a4"


def test_root_cause_ranking_link_failure():
    """Verify link loss ranked as #1 probable cause when hosts and services depend on it."""
    now = datetime.now(timezone.utc)
    # Directed dependency relations: svc depends on host; host connects via link
    edges = [
        {"source_entity": "svc_checkout", "target_entity": "h_node1", "relation": "runs_on"},
        {"source_entity": "svc_payment", "target_entity": "h_node2", "relation": "runs_on"},
        {"source_entity": "h_node1", "target_entity": "lnk_wan", "relation": "connects_via"},
        {"source_entity": "h_node2", "target_entity": "lnk_wan", "relation": "connects_via"},
    ]

    alerts = [
        # lnk_wan breached earliest with critical loss
        {
            "entity": "lnk_wan",
            "rule": "threshold.loss.high",
            "severity": "critical",
            "first_ts": now - timedelta(seconds=100),
        },
        # Dependent hosts alerted next with high latency
        {
            "entity": "h_node1",
            "rule": "threshold.latency.high",
            "severity": "high",
            "first_ts": now - timedelta(seconds=80),
        },
        {
            "entity": "h_node2",
            "rule": "threshold.latency.high",
            "severity": "high",
            "first_ts": now - timedelta(seconds=75),
        },
        # Dependent services alerted last
        {
            "entity": "svc_checkout",
            "rule": "threshold.svc.down",
            "severity": "critical",
            "first_ts": now - timedelta(seconds=50),
        },
        {
            "entity": "svc_payment",
            "rule": "threshold.resp_ms.high",
            "severity": "warning",
            "first_ts": now - timedelta(seconds=40),
        },
    ]

    candidates = rank_root_cause(alerts, edges)
    assert len(candidates) == 5

    # lnk_wan must be ranked #1
    top = candidates[0]
    assert top["entity"] == "lnk_wan"
    assert top["upstream"] == 1.0  # 4/4 other entities depend on lnk_wan
    assert top["earliness"] == 1.0  # Earliest breach
    assert top["score"] >= 0.85


def test_isolation_forest_flags_anomaly():
    """Verify IsolationForest detects injected multidimensional metric anomaly."""
    detector = IsolationForestAnomalyDetector(contamination=0.04)

    # 40 baseline normal samples: [cpu, mem, req_rate, resp_ms, loss, latency]
    normal_samples = []
    for i in range(40):
        normal_samples.append([
            25.0 + (i % 5),
            40.0 + (i % 3),
            120.0 + (i % 10),
            20.0 + (i % 4),
            0.0,
            15.0 + (i % 2),
        ])

    fitted = detector.fit(normal_samples)
    assert fitted is True

    # Normal vector should not be an anomaly
    is_anom, score = detector.predict_anomaly([26.0, 41.0, 125.0, 22.0, 0.0, 16.0])
    assert is_anom is False

    # Outlier vector (extreme loss and latency spike) must be flagged
    outlier = [95.0, 90.0, 5.0, 850.0, 48.0, 650.0]
    is_outlier, o_score = detector.predict_anomaly(outlier)
    assert is_outlier
    assert o_score < 0.0


def test_explanation_and_evidence_citations():
    """Verify plain English explanation embeds numbered citations [n] linked to evidence."""
    root_cause = {"entity": "lnk_abc1234567", "rule": "threshold.loss.high", "score": 0.95}
    alerts = [
        {"entity": "lnk_abc1234567", "rule": "threshold.loss.high", "alert_id": "a_root"},
        {"entity": "svc_cart", "rule": "threshold.svc.down", "alert_id": "a_down"},
    ]

    summary, evidence = generate_incident_explanation(
        incident_id="inc_test_1",
        root_cause=root_cause,
        alerts=alerts,
    )

    assert "[1]" in summary
    assert "[2]" in summary
    assert len(evidence) >= 2
    assert evidence[0]["evidence_number"] == 1
    assert evidence[0]["reference"] == "a_root"


def test_recommendation_catalog_mapping():
    """Verify action catalog mapping and confidence boundaries."""
    # Link loss -> FAILOVER_TO_SECONDARY_LINK
    rec_link = generate_recommendation("inc_1", {"entity": "lnk_100", "rule": "threshold.loss.high", "score": 0.90}, [])
    assert rec_link["action_type"] == "FAILOVER_TO_SECONDARY_LINK"
    assert rec_link["target_entity"] == "lnk_100"
    assert 0.0 <= rec_link["confidence"] <= 1.0

    # CPU runaway -> RESTART_SERVICE
    rec_cpu = generate_recommendation(
        "inc_2",
        {"entity": "h_100", "rule": "threshold.cpu.high", "score": 0.85},
        [{"entity": "svc_order", "rule": "threshold.cpu.high"}],
        cpu_runaway=True,
    )
    assert rec_cpu["action_type"] == "RESTART_SERVICE"
    assert rec_cpu["target_entity"] == "svc_order"
    assert 0.0 <= rec_cpu["confidence"] <= 1.0

    # Brute force -> TEMP_BLOCK_SOURCE_15M
    rec_sec = generate_recommendation("inc_3", {"entity": "h_auth", "rule": "auth.bruteforce", "score": 0.95}, [])
    assert rec_sec["action_type"] == "TEMP_BLOCK_SOURCE_15M"
    assert 0.0 <= rec_sec["confidence"] <= 1.0


def test_incident_resolution_lifecycle():
    """Verify auto-resolution on silence or *.resolved rule."""
    now = datetime.now(timezone.utc)

    # 1. Active incident with open alert 30s ago -> not resolved
    active_alerts = [{"rule": "threshold.cpu.high", "status": "open", "last_ts": now - timedelta(seconds=30)}]
    assert is_incident_resolved(active_alerts, now_ts=now, silence_threshold_seconds=120) is False

    # 2. Silent incident with last alert 150s ago (> 120s) -> resolved
    silent_alerts = [{"rule": "threshold.cpu.high", "status": "open", "last_ts": now - timedelta(seconds=150)}]
    assert is_incident_resolved(silent_alerts, now_ts=now, silence_threshold_seconds=120) is True

    # 3. Explicit *.resolved alert -> resolved immediately
    resolved_alerts = [{"rule": "threshold.cpu.high.resolved", "status": "open", "last_ts": now - timedelta(seconds=5)}]
    assert is_incident_resolved(resolved_alerts, now_ts=now, silence_threshold_seconds=120) is True

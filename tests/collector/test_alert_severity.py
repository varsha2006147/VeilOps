"""Alert severities on the wire must match the cloud contract (info | warning | critical)."""
from datetime import datetime, timezone

from veilops.collector.config import Thresholds
from veilops.collector.contracts import LogEvent
from veilops.collector.pipeline.detect import LogCategoryDetector, _alert_sev

CLOUD_ALERT_SEV = {"info", "warning", "critical"}


def test_threshold_rule_severities_are_cloud_valid():
    for rule in Thresholds().rules.values():
        assert _alert_sev(rule.get("severity", "warning")) in CLOUD_ALERT_SEV


def test_high_maps_to_critical():
    assert _alert_sev("high") == "critical"
    assert _alert_sev("warning") == "warning"


def test_critical_log_emits_critical():
    det = LogCategoryDetector()
    ev = LogEvent(entity="app-01", level="critical", category="sys.oom",
                  event_ts=datetime(2026, 11, 21, tzinfo=timezone.utc), source_tz="UTC", raw_id=1)
    sigs = det.observe(ev)
    assert sigs and sigs[0].severity == "critical"

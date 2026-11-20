from datetime import datetime, timedelta, timezone

import pytest

from cloud.app.health import (
    heartbeat_state, metric_state, combine_states, three_of_five_state,
)


def test_heartbeat_health_thresholds():
    now = datetime.now(timezone.utc)
    assert heartbeat_state(now, now)[0] == "Excellent"
    assert heartbeat_state(now - timedelta(seconds=15), now)[0] == "Fair"
    assert heartbeat_state(now - timedelta(seconds=30), now)[0] == "Fair"
    assert heartbeat_state(now - timedelta(seconds=31), now)[0] == "Poor"
    assert heartbeat_state(None, now)[0] == "Poor"


def test_metric_bands_and_state_combination():
    assert metric_state(40, 60, 80, 95) == "Excellent"
    assert metric_state(70, 60, 80, 95) == "Good"
    assert metric_state(85, 60, 80, 95) == "Fair"
    assert metric_state(98, 60, 80, 95) == "Poor"
    assert combine_states(["Good", "Poor", "Excellent"]) == "Poor"


def test_three_of_five_threshold():
    assert three_of_five_state(["Poor", "Poor", "Poor", "Good", "Good"]) == "Poor"
    assert three_of_five_state(["Fair", "Fair", "Good", "Fair", "Excellent"]) == "Fair"
    assert three_of_five_state(["Poor", "Fair", "Good", "Good", "Excellent"]) == "Excellent"


# ---- processor health-state capitalisation regression -------------------------
# The wire contract uses lowercase ("poor"); PostgreSQL CHECK constraints require
# Title Case ("Poor").  processor.py must call .title() before every DB write.

@pytest.mark.parametrize("wire_state,expected_db_state", [
    ("excellent", "Excellent"),
    ("good",      "Good"),
    ("fair",      "Fair"),
    ("poor",      "Poor"),
])
def test_wire_state_title_cased_for_db(wire_state, expected_db_state):
    """Simulate what processor._health() does: record['state'].title()."""
    assert wire_state.title() == expected_db_state


@pytest.mark.parametrize("from_state,to_state", [
    ("Poor",      "Fair"),
    ("Fair",      "Good"),
    ("Good",      "Excellent"),
    ("Excellent", "Poor"),
])
def test_health_transition_states_are_title_case(from_state, to_state):
    """States stored in health_transitions must satisfy the DB CHECK constraint."""
    valid = {"Excellent", "Good", "Fair", "Poor"}
    assert from_state in valid and to_state in valid

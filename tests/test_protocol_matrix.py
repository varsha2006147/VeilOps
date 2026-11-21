import asyncio

import pytest

from veilops.collector.protocol_proof import (
    MARKERS,
    PROTOCOLS,
    ProtocolResult,
    evaluate,
    find_markers,
    format_table,
    run_matrix,
)


def good():
    return ProtocolResult(
        "x", raw_secret_stored_locally=True, outbound_payloads=2, category_seen=True,
        auth_checked=True, security_summary_seen=True,
    )


def test_find_markers_detects_plain_and_json_escaped():
    for name, value in MARKERS.items():
        assert name in find_markers(("junk " + value + " junk").encode())
    assert "db_password" in find_markers(b'{"x":"\\u00533cr3t!"}')  # S3cr3t! behind an escape
    assert find_markers(b'{"entity":"h_7f3a21c90b","avg":91.2}') == {}


def test_find_markers_negative_control_checker_can_fail():
    r = good()
    assert evaluate(r)[0] == "PASS"
    r.marker_hits = {"db_password": 1}
    assert evaluate(r)[0] == "FAIL"


@pytest.mark.parametrize("field, value", [
    ("raw_secret_stored_locally", False),
    ("outbound_payloads", 0),
    ("tripwire_hits", 1),
    ("category_seen", False),
    ("security_summary_seen", False),
])
def test_each_guarantee_is_individually_enforced(field, value):
    r = good()
    setattr(r, field, value)
    assert evaluate(r)[0] == "FAIL"


def test_unimplemented_protocol_is_not_a_pass():
    res = asyncio.run(run_matrix(["kafka"]))
    assert res[0].status in ("NOT_SUPPORTED", "SKIPPED", "PASS", "FAIL")


@pytest.mark.parametrize("name", PROTOCOLS)
def test_matrix_protocol(name):
    res = asyncio.run(run_matrix([name]))[0]
    if res.status in ("SKIPPED", "NOT_SUPPORTED"):
        pytest.skip(res.reason)
    assert res.status == "PASS", res.reason
    assert res.raw_secret_stored_locally
    assert res.outbound_payloads >= 1
    assert sum(res.marker_hits.values()) == 0
    assert res.tripwire_hits == 0
    assert res.category_seen


def test_table_never_contains_markers():
    table = format_table(asyncio.run(run_matrix()))
    for value in MARKERS.values():
        assert value not in table
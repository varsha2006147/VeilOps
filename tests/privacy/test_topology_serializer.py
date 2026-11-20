"""Topology egress: pseudonymised graph whose node ids match the metric entity ids."""
from datetime import datetime, timezone

import pytest

from veilops.collector.contracts import WindowAgg
from veilops.collector.privacy.pseudonymizer import Pseudonymizer, PseudonymStore
from veilops.collector.privacy.serializer import RecordSerializer, SerializationError
from veilops.collector.topology import Edge, Topology
from veilops.schema.policy import load_policy

TS = datetime(2026, 11, 21, 4, 0, tzinfo=timezone.utc)
REAL = ("checkout", "app-01", "core-sw1", "db-01")


def make():
    return RecordSerializer(load_policy(), Pseudonymizer(b"k" * 32, PseudonymStore()))


def topo(*edges):
    return Topology(edges=[Edge(*e) for e in edges], version=1)


GRAPH = topo(("checkout", "service", "app-01", "host", "runs_on"),
             ("app-01", "host", "core-sw1", "link", "connects_via"),
             ("checkout", "service", "db-01", "host", "depends_on"))


def test_topology_nodes_use_the_same_pseudonyms_as_metrics():
    ser = make()
    rec = ser.serialize_topology(GRAPH, TS)
    metric = ser.serialize_window(WindowAgg("app-01", "host", "cpu.util_pct", "pct", 1, 1, 1, 1, 5, 5, TS, "UTC"))
    link = ser.serialize_window(WindowAgg("core-sw1", "link", "net.loss_pct", "pct", 0, 0, 0, 0, 5, 5, TS, "UTC"))
    assert rec.edges[0].dst == metric.entity and rec.edges[1].dst == link.entity
    assert rec.edges[0].src.startswith("svc_") and rec.edges[1].dst.startswith("lnk_")
    assert [e.rel for e in rec.edges] == ["runs_on", "connects_via", "depends_on"]


def test_topology_record_has_no_real_names():
    wire = make().serialize_topology(GRAPH, TS).model_dump_json()
    assert not any(name in wire for name in REAL)


def test_topology_teaches_entity_kind_for_later_alerts():
    ser = make()
    ser.serialize_topology(GRAPH, TS)
    assert ser._kinds["core-sw1"] == "link" and ser._kinds["checkout"] == "service"


def test_oversized_or_invalid_topology_fails_closed():
    big = Topology(edges=[Edge(f"h{i}", "host", "core", "link", "connects_via") for i in range(501)], version=1)
    with pytest.raises(SerializationError):
        make().serialize_topology(big, TS)
    with pytest.raises(SerializationError):
        make().serialize_topology(topo(("a", "host", "b", "host", "talks_to")), TS)   # unknown relation

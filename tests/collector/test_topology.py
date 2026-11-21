"""Member A: topology loader + watcher."""
from __future__ import annotations

import os
import time

import pytest

from veilops.collector.contracts import SourceBus
from veilops.collector.topology import TopologyError, TopologyWatcher, from_sim, load_file, parse_edges


def test_compact_and_dict_forms_and_aliases():
    edges = parse_edges(["svc:checkout -> host:app-01 : runs_on",
                         {"src": "app-01", "src_kind": "node", "dst": "core-sw1", "dst_kind": "net", "rel": "connects_via"}])
    assert [(e.src, e.src_kind, e.dst, e.dst_kind, e.rel) for e in edges] == [
        ("app-01", "host", "core-sw1", "link", "connects_via"), ("checkout", "service", "app-01", "host", "runs_on")]


@pytest.mark.parametrize("bad, msg", [
    ("checkout -> app-01", "expected"),
    ("svc:a -> host:b : owns", "unknown relation"),
    ("pod:a -> host:b : runs_on", "unknown kind"),
    ("host:a -> host:a : depends_on", "self-loop"),
])
def test_invalid_edges_rejected_with_position(bad, msg):
    with pytest.raises(TopologyError, match=f"edge #1: .*{msg}"):
        parse_edges([bad])


def test_node_must_keep_one_kind():
    with pytest.raises(TopologyError, match="both"):
        parse_edges(["svc:x -> host:y : runs_on", "host:x -> link:z : connects_via"])


def test_example_file_and_graph_queries():
    path = os.path.join(os.path.dirname(__file__), "../../veilops/collector/topology.example.yaml")
    from veilops.collector.topology import Topology
    t = Topology(load_file(path))
    assert t.nodes["core-sw1"] == "link" and len(t.edges) == 10   # 9 site edges + the remediation sandbox
    # everything that is hurt if the core switch degrades: hosts behind it and the services on them
    assert {"app-01", "app-02", "db-01", "checkout", "auth-api"} <= t.downstream_of("core-sw1")
    assert t.neighbors("app-02") == {"checkout", "auth-api", "core-sw1"}


def test_sim_topology_is_valid():
    assert len(from_sim()) == 9


def test_watcher_versions_events_and_keeps_last_good(tmp_path):
    f = tmp_path / "topology.yaml"
    f.write_text('edges: ["svc:a -> host:b : runs_on"]\n')
    bus = SourceBus()
    w = TopologyWatcher(bus, str(f))
    assert w.refresh() and bus.topology.version == 1 and bus.topology_changed.is_set()
    bus.topology_changed.clear()
    assert not w.refresh()                                   # unchanged file: no new version
    time.sleep(0.01)
    f.write_text('edges: ["svc:a -> host:b : owns"]\n')     # bad edit
    os.utime(f, (time.time() + 1, time.time() + 1))
    assert not w.refresh() and bus.topology.version == 1 and "unknown relation" in w.last_error
    f.write_text('edges: ["svc:a -> host:b : runs_on", "host:b -> link:c : connects_via"]\n')
    os.utime(f, (time.time() + 2, time.time() + 2))
    assert w.refresh() and bus.topology.version == 2 and len(bus.topology.edges) == 2
    assert w.last_error is None and bus.topology_changed.is_set()


def test_watcher_falls_back_to_sim():
    bus = SourceBus()
    w = TopologyWatcher(bus, None, use_sim=True)
    assert w.refresh() and bus.topology.source == "sim"

"""Person C handover validation on real PostgreSQL + Redis, through the real ingest -> stream -> processor path.

Covers: lowercase wire health states persisted as Title Case, no duplicate transitions, tenant isolation,
and collector-scoped topology snapshots (one collector cannot delete another's edges).
Opt-in with VEILOPS_TEST_PG_ADMIN / VEILOPS_TEST_REDIS_URL (see test_judge_integration.py).
"""
import asyncio
from datetime import timedelta

import pytest

from tests.test_judge_integration import (
    A, B, ENC_KEY, PG_ADMIN, REDIS_URL, TENANT_A, _admin_dsn, client, database, entity_id, iso, now, send, wait_for,
)

pytestmark = pytest.mark.skipif(not (PG_ADMIN and REDIS_URL),
                                reason="set VEILOPS_TEST_PG_ADMIN and VEILOPS_TEST_REDIS_URL")
_ = (client, database)  # fixtures re-exported for pytest


def _db(query, *args):
    import asyncpg

    async def run():
        conn = await asyncpg.connect(_admin_dsn("veilops"))
        try:
            return await conn.fetch(query, *args)
        finally:
            await conn.close()
    return asyncio.run(run())


def _add_collector(cid: str, tenant: str = TENANT_A):
    from cloud.app.crypto import SecretBox
    _db("""INSERT INTO collectors(collector_id,tenant_id,region,secret_hash,status,secret_ciphertext)
           VALUES($1,$2,'in','unused','active',$3)""", cid, tenant, SecretBox(ENC_KEY).encrypt(cid.encode() * 4))


def health(entity, state, t):
    return {"type": "health", "entity": entity, "state": state, "reasons": ["svc_unreachable"], "event_ts": iso(t)}


def history(client, entity, headers=None):
    return client.get(f"/api/v1/entities/{entity}/health-history", headers=headers or A()).json()["transitions"]


def test_lowercase_wire_health_states_stored_title_case_without_duplicate_transitions(client):
    e, t = entity_id("checkout-host"), now() - timedelta(seconds=40)
    states = ["good", "good", "poor", "poor", "fair", "excellent"]
    for i, s in enumerate(states):
        r, _, _ = send(client, i + 1, [health(e, s, t + timedelta(seconds=5 * i))])
        assert r.status_code == 202, r.text
    wait_for(lambda: len(history(client, e)) == 4)
    got = [(h["from_state"], h["to_state"]) for h in reversed(history(client, e))]
    assert got == [(None, "Good"), ("Good", "Poor"), ("Poor", "Fair"), ("Fair", "Excellent")]  # repeats add nothing
    (cur,) = _db("SELECT state FROM health_current WHERE tenant_id=$1 AND entity=$2", TENANT_A, e)
    assert cur["state"] == "Excellent"
    assert history(client, e, headers=B()) == []                                               # tenant isolation


def test_capitalised_wire_state_still_rejected_by_contract(client):
    r, _, _ = send(client, 1, [health(entity_id("x"), "Poor", now())])
    assert r.status_code == 422


def test_topology_snapshots_are_independent_per_collector(client):
    _add_collector("col_a2")
    h1, h2, lnk = entity_id("host-1"), entity_id("host-2"), "lnk_" + entity_id("core")[2:]
    topo = lambda edges: [{"type": "topology", "edges": edges, "event_ts": iso(now())}]
    send(client, 1, topo([{"src": h1, "dst": lnk, "rel": "connects_via"}]), collector="col_a")
    send(client, 1, topo([{"src": h2, "dst": lnk, "rel": "connects_via"}]), collector="col_a2")
    edges = lambda: client.get("/api/v1/topology", headers=A()).json()["edges"]
    wait_for(lambda: {e["collector_id"] for e in edges()} == {"col_a", "col_a2"})
    # col_a replaces its own snapshot (even with an empty edge list); col_a2's edges must survive
    send(client, 2, topo([]), collector="col_a")
    wait_for(lambda: [e["collector_id"] for e in edges()] == ["col_a2"])
    assert edges()[0]["src"] == h2
    rows = _db("SELECT collector_id FROM topology_edges")
    assert [r["collector_id"] for r in rows] == ["col_a2"]

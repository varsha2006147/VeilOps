# Integration contracts (freeze at H2)

These are the seams between members. Change only with all four agreeing.

## 1. A -> B (inside the collector): `SourceBus`

Member A's pipeline pushes three kinds of objects onto asyncio queues that Member B's privacy stage consumes.
Defined in `veilops/collector/contracts.py`.

| Queue | Type | Contains real identifiers? | Notes |
| --- | --- | --- | --- |
| `bus.windows` | `WindowAgg` | YES (raw host/link/service names) | 5 s tumbling window per (entity, metric) |
| `bus.signals` | `LocalSignal` | YES (raw usernames / IPs in `subjects`) | threshold breaches + security summaries; `priority=True` must bypass batching |
| `bus.heartbeat_info` | `SourceStatus` | no | per-source health for the heartbeat |

B pseudonymizes `entity`, `subjects`, `sources` and builds outbound records from `policy.yaml`.
A never sends anything over the network to SaaS.

## 2. Collector -> Cloud: envelope

`veilops/schema/models.py` — see SAD section 12.

## 3. Cloud API -> Dashboard

OpenAPI at `cloud/api/openapi.json` (Member C publishes, Member D mocks).

## 4. Notes from Member A for C and B (late data)

- A late sample for an already-closed window re-emits the **merged** `WindowAgg` with the **same `event_ts`** and a
  larger `count`. Cloud (C) must upsert metric points:
  `INSERT ... ON CONFLICT (tenant_id, entity, metric, event_ts) DO UPDATE SET avg=EXCLUDED.avg, min=EXCLUDED.min,
  max=EXCLUDED.max, p95=EXCLUDED.p95, count=EXCLUDED.count WHERE EXCLUDED.count > metric_points.count`.
  This keeps re-delivery idempotent and lets out-of-order data correct a window instead of duplicating it.
- `LocalSignal.priority=True` (threshold breaches, security summaries, critical log categories) must skip
  B's batching. Measured locally: breach -> signal on the bus in ~2 s (3-of-5 persistence at 1 Hz).
- `LocalSignal.raw_ids` point into the local `raw_events` table, so the Egress Proof Panel can show the
  source lines behind a payload in its side-by-side view. Never transmit them.
- Topology (real names) for B to pseudonymize: `veilops.sim.TOPOLOGY` in demo; `topology.yaml` in production.

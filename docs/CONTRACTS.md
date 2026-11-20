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

`veilops/schema/` (B: `common.py`, `records.py`, `envelope.py`, `wire.py`; `models.py` re-exports all) — see SAD section 12.

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

## 5. Topology (A -> B)

- `bus.topology` is a `veilops.collector.topology.Topology` with REAL names: `edges` of
  `Edge(src, src_kind, dst, dst_kind, rel)`; kinds `host|service|link`; relations `runs_on|connects_via|depends_on`.
- A loads it from `topology_file` (default `veilops/collector/topology.example.yaml`; falls back to the simulator's
  graph when the sim source is on) and re-reads on change. Each change bumps `version` and sets `bus.topology_changed`.
- B: `await bus.topology_changed.wait(); bus.topology_changed.clear()`, then pseudonymize every node with the SAME
  HMAC used for metrics (host -> `h_`, service -> `svc_`, link -> `lnk_`) and send one `topology` record.
- A bad file never breaks the collector: the last good graph is kept and the error shows in the local UI (Topology tab).

## 6. String catalog (authoritative — generated from detect.py / normalize.py / config.py)

B's schema enums must accept exactly these strings. Units on the wire: `pct`, `ms`, `mbps`, `bool`, `rps`.
**Always use the `entity_kind` given on `WindowAgg` / `LocalSignal`; never infer it from the metric name**
(a stream may report latency per host).

| Canonical metric | Unit | Entity kind |
| --- | --- | --- |
| `cpu.util_pct` | `pct` | host |
| `disk.io_wait_pct` | `pct` | host |
| `disk.util_pct` | `pct` | host |
| `load.req_rate` | `rps` | host |
| `mem.util_pct` | `pct` | host |
| `net.bw_in_mbps` | `mbps` | host |
| `net.bw_out_mbps` | `mbps` | host |
| `net.latency_ms` | `ms` | link |
| `net.loss_pct` | `pct` | link |
| `net.reachable` | `bool` | link |
| `svc.resp_ms` | `ms` | service |
| `svc.up` | `bool` | service |

| Rule (`LocalSignal.rule`) | kind | template_id | severity | priority | params |
| --- | --- | --- | --- | --- | --- |
| `threshold.cpu.high` | threshold | `T_CPU_HIGH` | warning | yes | value, threshold, breaching, of |
| `threshold.cpu.high.resolved` | threshold | `T_CPU_HIGH_RESOLVED` | info | no | value, threshold, peak |
| `threshold.mem.high` | threshold | `T_MEM_HIGH` | warning | yes | value, threshold, breaching, of |
| `threshold.mem.high.resolved` | threshold | `T_MEM_HIGH_RESOLVED` | info | no | value, threshold, peak |
| `threshold.disk.high` | threshold | `T_DISK_HIGH` | high | yes | value, threshold, breaching, of |
| `threshold.disk.high.resolved` | threshold | `T_DISK_HIGH_RESOLVED` | info | no | value, threshold, peak |
| `threshold.loss.high` | threshold | `T_LOSS_HIGH` | high | yes | value, threshold, breaching, of |
| `threshold.loss.high.resolved` | threshold | `T_LOSS_HIGH_RESOLVED` | info | no | value, threshold, peak |
| `threshold.latency.high` | threshold | `T_LATENCY_HIGH` | warning | yes | value, threshold, breaching, of |
| `threshold.latency.high.resolved` | threshold | `T_LATENCY_HIGH_RESOLVED` | info | no | value, threshold, peak |
| `threshold.svc.down` | threshold | `T_SVC_DOWN` | critical | yes | value, threshold, breaching, of |
| `threshold.svc.down.resolved` | threshold | `T_SVC_DOWN_RESOLVED` | info | no | value, threshold, peak |
| `threshold.net.unreachable` | threshold | `T_UNREACHABLE` | critical | yes | value, threshold, breaching, of |
| `threshold.net.unreachable.resolved` | threshold | `T_UNREACHABLE_RESOLVED` | info | no | value, threshold, peak |
| `auth.bruteforce` | security | `T_AUTH_BRUTEFORCE` | high or critical (risk>=90) | yes | count, distinct_principals, distinct_sources (+ risk_score, window_s=60, subjects, sources) |
| `auth.spray` | security | `T_AUTH_SPRAY` | high or critical (risk>=90) | yes | count, distinct_principals, distinct_sources (+ risk_score, window_s=60, subjects, sources) |
| `auth.stuffing` | security | `T_AUTH_STUFFING` | critical | yes | count, distinct_principals, distinct_sources (+ risk_score, window_s=60, subjects, sources) |
| `log.db.connect_error` | log_category | `T_LOG_CATEGORY` | warning (error) / high (critical) / info | only if level critical | count (window_s=60) |
| `log.sys.oom` | log_category | `T_LOG_CATEGORY` | warning (error) / high (critical) / info | only if level critical | count (window_s=60) |
| `log.sys.disk_full` | log_category | `T_LOG_CATEGORY` | warning (error) / high (critical) / info | only if level critical | count (window_s=60) |
| `log.app.timeout` | log_category | `T_LOG_CATEGORY` | warning (error) / high (critical) / info | only if level critical | count (window_s=60) |
| `log.net.conn_refused` | log_category | `T_LOG_CATEGORY` | warning (error) / high (critical) / info | only if level critical | count (window_s=60) |
| `log.app.http_5xx` | log_category | `T_LOG_CATEGORY` | warning (error) / high (critical) / info | only if level critical | count (window_s=60) |
| `log.app.crash` | log_category | `T_LOG_CATEGORY` | warning (error) / high (critical) / info | only if level critical | count (window_s=60) |
| `log.sec.tls_error` | log_category | `T_LOG_CATEGORY` | warning (error) / high (critical) / info | only if level critical | count (window_s=60) |
| `log.sec.access_denied` | log_category | `T_LOG_CATEGORY` | warning (error) / high (critical) / info | only if level critical | count (window_s=60) |
| `log.app.error` | log_category | `T_LOG_CATEGORY` | warning (error) / high (critical) / info | only if level critical | count (window_s=60) |

Severities: `info`, `warning`, `high`, `critical`. Entity kinds: `host`, `service`, `link`.

### Wire mapping agreed with B (Zainab)

| LocalSignal kind | Wire record(s) |
| --- | --- |
| `threshold` (incl. `.resolved`) | `AlertRecord(rule, severity, template_id, params)` |
| `security` | `SecuritySummaryRecord` (category = rule, counts, `usr_`/`src_` pseudonyms, risk_score) + `AlertRecord` |
| `log_category` | `AlertRecord(rule="log.<category>", template_id="T_LOG_CATEGORY", params={"count": n})` — numbers only, no schema change |

### Late data — decision for C

Collector re-emits a corrected window with the **same `event_ts`**, a **larger `count`** and a **new `payload_id`**.
Cloud must **upsert** (keep the larger count). `DO NOTHING` would silently discard the correction and the
out-of-order scenario would show wrong numbers. Ingest still dedupes exact retries on `payload_id`.

```sql
INSERT INTO metric_points (...) VALUES (...)
ON CONFLICT (tenant_id, entity, metric, event_ts) DO UPDATE
SET avg = EXCLUDED.avg, min = EXCLUDED.min, max = EXCLUDED.max, p95 = EXCLUDED.p95,
    count = EXCLUDED.count, payload_id = EXCLUDED.payload_id, received_at = EXCLUDED.received_at
WHERE EXCLUDED.count > metric_points.count;
```

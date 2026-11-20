# Dashboard developer guide (Vibhav)

## Design source of truth
`ui-reference/` = the final screens: **Live**, **Recorder** (Incidents), **Summary**, **Overview** (How it works).
They are `.dc.html` design-canvas sources: open them in an editor for exact text, sizes, colours and the
behaviour in each `<script>` block (sparklines, boundary animation, Replay, gauge maths). They need the canvas
runtime to render, so for the rendered view use the mockup link Varsha shares. The older
`veilops_ui_prototype.zip` (overview/incidents/egress/remediation/SLO) is superseded — ignore it.

## Run the backend locally
```bash
# cloud (Postgres 16 + Redis 7 + API on :8000) — fresh volume so all migrations apply
docker compose -f deploy/docker-compose.yml down -v && docker compose -f deploy/docker-compose.yml up --build
# bearer token: export the SAME DASHBOARD_JWT_SECRET you gave compose, then
python -m cloud.scripts.dev_token --user vibhav --tenant t_acme --role operator
python -m cloud.scripts.dev_token --user zainab --tenant t_acme --role approver   # 2nd person for approvals
```
- Cloud API base: `http://localhost:8000` · header `Authorization: Bearer <token>` · tenant comes only from the token.
- Collector-local API (Live screen ledger, demo buttons): `http://localhost:8100` (no token; it's on the customer side).
- CORS: both allow `http://localhost:5173` (override with `CORS_ORIGINS=a,b`).
- Live updates: `GET /api/v1/events` (SSE). Event `telemetry_processed` carries `payload_id` → refetch, then
  `POST /api/v1/slo/render-ack` with `record_key: "payload:<payload_id>"` so Judge Mode measures real latency.

## Endpoint map (old mock name → real endpoint). Real responses in `api-samples/`.
| Screen need | Real endpoint | Sample |
|---|---|---|
| fleet / collectors | `GET /api/v1/fleet` | `cloud_fleet.json` |
| ledger (Live, right) | `GET :8100/api/egress-proof` (collector) · detail `GET /api/v1/payloads/{payload_id}` | `collector_egress_proof.json`, `cloud_payload_receipt.json` |
| cloud link state (online / outage / backlog / reconcile / executed actions) | `GET :8100/local/cloud` | `collector_cloud_link.json` |
| demo buttons (`/demo/inject`) | `POST :8100/local/chaos/{scenario}` | `collector_chaos.json` |
| alerts | `GET /api/v1/alerts` · false alarm: `POST /api/v1/alerts/{id}/feedback {"verdict":"false_alarm"}` | `cloud_alerts.json` |
| incidents | `GET /api/v1/incidents`, `GET /api/v1/incidents/{id}` | `cloud_incidents.json` (**empty until incident correlation lands — use fixtures**) |
| entity lanes (Recorder) | `GET /api/v1/entities/{id}/metrics?since=&limit=` · `/health-history` | `cloud_entity_metrics.json` |
| approve / dry run | `POST /api/v1/actions` then `POST /api/v1/actions/{id}/approve` by a different approver | `cloud_actions_create.json` |
| summary / judge rings (`/summary/today`) | `GET /api/v1/slo` (+ `/api/v1/reconciliation`, `/api/v1/slo/export.csv`) | `cloud_slo.json`, `cloud_reconciliation.json` |

Values in the samples come from a real local run (simulator + sandbox): entity ids are pseudonyms (`h_…`),
so show them as-is in the cloud UI; real names exist only on the collector UI (`:8100`).

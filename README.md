# VeilOps

**Secure, local-first AIOps observability. The SaaS sees the shape of operations, never the secrets.**

CICADA 2026 · TechForcz x Atria Institute of Technology · 24-hour hackathon.

- **Tier 1 — Collector** (`veilops/collector/`): runs in the customer environment; collects, normalizes, redacts,
  pseudonymizes, aggregates and analyzes locally. Raw data never leaves.
- **Tier 2 — Cloud** (`veilops/cloud/`, `dashboard/`): multi-tenant, metadata-only; regional ingest, health,
  explainable AIOps, Judge Mode.

| Path | What | Owner |
| --- | --- | --- |
| `veilops/schema/` | Wire contracts (envelope, records) | B |
| `veilops/collector/contracts.py` | A -> B seam inside the collector (SourceBus) | A + B |
| `veilops/collector/sources/`, `pipeline/`, `ui/` | Stream adapter, sources, normalize, aggregate, local detectors, local UI | A |
| `veilops/collector/privacy/`, `transport/` | Redact, pseudonymize, egress guard, outbox, ledger, sender | B |
| `veilops/sim/` | Scenario simulator | A |
| `veilops/cloud/` | Control plane, ingest, processors, API, AIOps | C, D |
| `tests/<area>/` | Tests per area | each owner |

## Quick start (collector)

```bash
pip install -r requirements.txt
python -m veilops.sim serve --port 9000                      # simulated organizer stream (SSE)
python -m veilops.collector                                   # local UI on http://localhost:8100
pytest -q
```
Use the organizer stream instead: `STREAM_ENABLED=true STREAM_DRIVER=sse STREAM_URL=<url> python -m veilops.collector`
(edit only `veilops/collector/stream_map.yaml` to map their field names).

## Run the collector in Docker

```bash
docker build -f deploy/Dockerfile.collector -t veilops-collector .
docker compose -f deploy/collector.compose.yml up --build   # acme :8100 (IN), globex :8101 (EU), sim :9000
```
At the event: `STREAM_URL=<organizer feed> docker compose -f deploy/collector.compose.yml up`.
The image contains only `veilops/collector`, `veilops/schema` and `veilops/sim` — no cloud code ships to customers.

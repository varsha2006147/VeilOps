# Two-laptop demo — run sheet

**Laptop A = customer site.** It runs the collector, the simulator, the sandbox and the collector console (real names).
**Laptop B = VeilOps cloud.** It runs Postgres, Redis, the API on :8000 and the dashboard (codes only).
The only traffic between them is A → B on port 8000.

## 0. Both laptops (10 min before)

1. Join the same network. Venue Wi-Fi often blocks laptop-to-laptop traffic. If the ping in step B4 fails, switch both laptops to one phone hotspot.
2. Sync clocks. Requests are signed and rejected if the clocks differ by more than 5 minutes.
   - macOS: `sudo sntp -sS time.apple.com`
   - Linux: `sudo timedatectl set-ntp true`
3. On a Mac, if the macOS firewall is on, allow incoming connections for Docker (B) when prompted.

## Laptop B — cloud

```bash
cd VeilOps
python3 -m cloud.scripts.generate_local_secrets > deploy/.env   # first time only (compose reads deploy/.env)
export CLOUD_BIND=0.0.0.0       # expose :8000 on the LAN (default is localhost only)
docker compose -f deploy/docker-compose.yml up -d --build postgres redis cloud-api
ipconfig getifaddr en0          # macOS — note B's IP, e.g. 192.168.43.20   (Linux: hostname -I)
```

B1. Create the demo accounts (password `veilops-demo-1`):

```bash
for u in "operator@acme.test|Asha · Acme operator|t_acme|operator" \
         "approver@acme.test|Ravi · Acme approver|t_acme|approver" \
         "operator@globex.test|Mia · Globex operator|t_globex|operator"; do
  IFS='|' read e n t r <<<"$u"
  docker compose -f deploy/docker-compose.yml exec -e ADMIN_DATABASE_URL=postgresql://veilops:veilops_dev_only@postgres:5432/veilops \
    cloud-api python -m cloud.scripts.create_dashboard_user --email "$e" --name "$n" --tenant $t --role $r --password veilops-demo-1
done
```

B2. Make a one-time enrollment token for laptop A. Use either the dashboard (Collectors → Add collector, as the approver) or:

```bash
docker compose -f deploy/docker-compose.yml exec cloud-api python -m cloud.scripts.create_enrollment_token --tenant t_acme --region in
```

B3. Start the dashboard:

```bash
cd web && npm install && npm run dev        # http://localhost:5173 — signs in as Asha automatically
```

B4. Check that A can reach B. From laptop A run `curl http://<B-ip>:8000/health/ready`; it must answer.

## Laptop A — customer site

```bash
cd VeilOps
export INGEST_URL_IN=http://<B-ip>:8000/v1
export ENROLL_TOKEN_ACME=<token from B2>
docker compose -f deploy/collector.compose.yml up -d --build sim sandbox collector-acme
cd web && npm install && VITE_COLLECTOR_URL=http://localhost:8100 npm run dev:site   # http://localhost:5174
```

Within about 10 seconds, A's Cloud link page shows **online**, and B's Explorer shows 8 entities and 9 connections.
The token is single-use. If you rebuild A from scratch (`down -v`), make a new token.

## The demo, in order

| # | Action | Where it shows |
|---|--------|----------------|
| 1 | A: Local feed — the raw event on the left, the coded summary on the right | A only sees real names |
| 2 | B: Explorer — the same hosts, as codes only | B never sees real names |
| 3 | A: Simulate → **Link failure** | B: an issue appears within about 15 s, root cause `lnk_…`, suggested fix `FAILOVER_TO_SECONDARY_LINK` |
| 4 | B: Asha clicks **Request fix**, then switches account to Ravi and clicks **Approve** | A: Cloud link → the fix is received and executed, with its steps |
| 5 | **Pull A's network** (Wi-Fi off) for about 30 s | A: Cloud link shows offline with payloads held. B: Collectors shows the collector offline |
| 6 | Reconnect | A drains the backlog. B: Boundary & proof shows 0 missing and duplicates rejected, not stored |
| 7 | A: Simulate → **Secret in log** | A: Boundary shows the secret scrubbed. Nothing reaches B |
| 8 | A: Look up a code — paste a code from B | The real name appears on A, and the lookup is written to A's audit |
| 9 | B: Reliability — measured p95s against their targets | Export CSV |

## If something breaks

- **Ingest is rejected with `STALE_TIMESTAMP` or `CLOCK_SKEW_TOO_LARGE`:** clocks differ. Redo step 0.2.
- **A can't reach B:** Wi-Fi client isolation or the firewall. Use the hotspot, allow Docker, and check `CLOUD_BIND=0.0.0.0`.
- **The dashboard shows "cloud unreachable":** B's API is down. Run `docker compose -f deploy/docker-compose.yml ps` and check `logs cloud-api`.
- **Enrollment fails with `BAD_OR_EXPIRED_ENROLLMENT_TOKEN`:** the token lasts 15 minutes and works once. Make a new token (B2) and restart `collector-acme`.

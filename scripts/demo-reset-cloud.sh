#!/usr/bin/env bash
# Reset the VeilOps cloud to zero for a demo: wipe data, start, create demo accounts, print a collector token.
# Usage (Mac/Linux, from the repo root):  bash scripts/demo-reset-cloud.sh
set -euo pipefail
C="docker compose -f deploy/docker-compose.yml"
[ -f deploy/.env ] || python3 -m cloud.scripts.generate_local_secrets > deploy/.env
export CLOUD_BIND="${CLOUD_BIND:-0.0.0.0}"
$C down -v
$C up -d --build postgres redis cloud-api
printf "waiting for the cloud"; until curl -sf http://localhost:8000/health/ready >/dev/null; do printf "."; sleep 2; done; echo " ready"
DB=postgresql://veilops:veilops_dev_only@postgres:5432/veilops
for u in "operator@acme.test|Asha - Acme operator|t_acme|operator" "approver@acme.test|Ravi - Acme approver|t_acme|approver" "operator@globex.test|Mia - Globex operator|t_globex|operator"; do
  IFS='|' read -r e n t r <<<"$u"
  $C exec -T -e ADMIN_DATABASE_URL=$DB cloud-api python -m cloud.scripts.create_dashboard_user --email "$e" --name "$n" --tenant "$t" --role "$r" --password veilops-demo-1
done
TOKEN=$($C exec -T cloud-api python -m cloud.scripts.create_enrollment_token --tenant t_acme --region in | tail -1 | tr -d '\r')
IP=$( (ipconfig getifaddr en0 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}') )
echo
echo "Cloud is ready (from zero). Dashboard: cd web && npm run dev  ->  http://localhost:5173"
echo "Collector token (one use, 15 min): $TOKEN"
echo "Cloud address for the collector:   http://${IP:-<this-laptop-ip>}:8000/v1"

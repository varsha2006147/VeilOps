#!/usr/bin/env bash
# Reset the collector to zero and enrol it.  Usage:  bash scripts/demo-reset-collector.sh <cloud-url> <token>
#   same laptop as the cloud:  bash scripts/demo-reset-collector.sh http://host.docker.internal:8000/v1 <token>
set -euo pipefail
[ $# -eq 2 ] || { echo "usage: $0 <cloud-url e.g. http://192.168.1.23:8000/v1> <token>"; exit 1; }
export INGEST_URL_IN="$1" ENROLL_TOKEN_ACME="$2"
C="docker compose -f deploy/collector.compose.yml"
$C down -v
$C up -d --build sim sandbox collector-acme
printf "waiting for enrolment"
for i in $(seq 1 45); do
  S=$(curl -sf http://localhost:8100/local/cloud || true)
  echo "$S" | grep -q '"enrolled":true' && { echo " enrolled"; echo "Console: cd web && npm run dev:site  ->  http://localhost:5174"; exit 0; }
  printf "."; sleep 2
done
echo; echo "Not enrolled yet. Collector says:"; curl -s http://localhost:8100/local/cloud; echo

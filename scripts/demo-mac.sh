#!/bin/bash
# Whole VeilOps demo on ONE Mac. Run from the repo root (the VeilOps folder):
#   bash scripts/demo-mac.sh start     # wipe to zero, start cloud + collector + both web apps, open browsers
#   bash scripts/demo-mac.sh cut       # "pull the network": stop the cloud (collector keeps data)
#   bash scripts/demo-mac.sh restore   # bring the cloud back (collector sends what it held)
#   bash scripts/demo-mac.sh restart   # start everything again WITHOUT wiping data
#   bash scripts/demo-mac.sh stop      # stop everything, keep data
#   bash scripts/demo-mac.sh status    # quick health check
cd "$(dirname "$0")/.." || exit 1
CLOUD="docker compose -f deploy/docker-compose.yml"
SITE="docker compose -f deploy/collector.compose.yml"
DB=postgresql://veilops:veilops_dev_only@postgres:5432/veilops
export CLOUD_BIND=0.0.0.0
export INGEST_URL_IN=http://host.docker.internal:8000/v1

say()  { printf "\n\033[1m==> %s\033[0m\n" "$1"; }
fail() { printf "\n\033[31mSTOPPED: %s\033[0m\n" "$1"; exit 1; }

wait_cloud() {
  printf "waiting for the cloud"
  for i in $(seq 1 60); do
    curl -sf http://localhost:8000/health/ready >/dev/null && { echo " ready"; return 0; }
    printf "."; sleep 2
  done
  echo; $CLOUD logs --tail 30 cloud-api; fail "cloud did not become ready (logs above)"
}

wait_collector() {
  printf "waiting for the collector to connect"
  for i in $(seq 1 60); do
    S=$(curl -s http://localhost:8100/local/cloud)
    echo "$S" | grep -q '"enrolled":true' && { echo " connected"; return 0; }
    printf "."; sleep 2
  done
  echo; echo "Collector says: $S"; fail "collector did not connect"
}

web() {
  say "Starting the two web apps"
  pkill -f vite 2>/dev/null; sleep 1
  [ -d web/node_modules ] || (cd web && npm install)
  (cd web && nohup npm run dev > /tmp/veilops-web-cloud.log 2>&1 &)
  (cd web && nohup npm run dev:site > /tmp/veilops-web-site.log 2>&1 &)
  sleep 6
  open http://localhost:5174 2>/dev/null; open http://localhost:5173 2>/dev/null
}

case "${1:-}" in
start)
  docker info >/dev/null 2>&1 || fail "Docker Desktop is not running. Open it, wait for 'Engine running', try again."
  [ -f deploy/.env ] || python3 -m cloud.scripts.generate_local_secrets > deploy/.env
  say "1/5  Wiping old data"
  $SITE down -v; $CLOUD down -v
  say "2/5  Starting the cloud"
  $CLOUD up -d --build postgres redis cloud-api || fail "cloud did not start"
  wait_cloud
  say "3/5  Creating demo accounts (password veilops-demo-1)"
  for u in "operator@acme.test|Asha|t_acme|operator" "approver@acme.test|Ravi|t_acme|approver" "operator@globex.test|Mia|t_globex|operator"; do
    IFS='|' read -r e n t r <<<"$u"
    $CLOUD exec -T -e ADMIN_DATABASE_URL=$DB cloud-api python -m cloud.scripts.create_dashboard_user \
      --email "$e" --name "$n" --tenant "$t" --role "$r" --password veilops-demo-1 || fail "could not create $e"
  done
  say "4/5  Starting the collector (customer site) and enrolling it"
  TOKEN=$($CLOUD exec -T cloud-api python -m cloud.scripts.create_enrollment_token --tenant t_acme --region in | tail -1 | tr -d '\r ')
  [ -n "$TOKEN" ] || fail "could not create an enrollment token"
  ENROLL_TOKEN_ACME="$TOKEN" $SITE up -d --build sim sandbox collector-acme || fail "collector did not start"
  wait_collector
  say "5/5  Web apps"
  web
  say "READY.  Cloud: http://localhost:5173   Collector: http://localhost:5174   (Guided demo -> Restart in both)"
  ;;
restart)
  $CLOUD up -d && wait_cloud
  $SITE up -d && wait_collector
  web
  say "READY (data kept).  Cloud: http://localhost:5173   Collector: http://localhost:5174"
  ;;
cut)
  $CLOUD stop cloud-api
  say "Cloud stopped. Collector now holds payloads. Run 'bash scripts/demo-mac.sh restore' after ~30 s."
  ;;
restore)
  $CLOUD start cloud-api && wait_cloud
  say "Cloud back. Held payloads drain in a few seconds; check Boundary & proof for 0 missing."
  ;;
stop)
  pkill -f vite 2>/dev/null; $SITE stop; $CLOUD stop
  say "Stopped. Data kept. 'restart' brings it back, 'start' wipes to zero."
  ;;
status)
  printf "cloud:     "; curl -s http://localhost:8000/health/ready || echo "DOWN"; echo
  printf "collector: "; curl -s http://localhost:8100/local/cloud | cut -c1-120 || echo "DOWN"; echo
  ;;
*)
  sed -n 2,8p "$0"
  ;;
esac

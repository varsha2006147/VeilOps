# Collector laptop (Windows). Run in PowerShell from the VeilOps folder:
#   powershell -ExecutionPolicy Bypass -File scripts\collector-windows.ps1 <MAC-IP> <TOKEN>
# Wipes this laptop's old collector login, connects to the cloud, starts the collector screen.
param([Parameter(Mandatory=$true)][string]$MacIp, [Parameter(Mandatory=$true)][string]$Token)

function Stop-Here($msg) { Write-Host ""; Write-Host "STOPPED: $msg" -ForegroundColor Red; exit 1 }

Write-Host "1/6 Checking Docker..." -ForegroundColor Cyan
docker info *> $null
if ($LASTEXITCODE -ne 0) { Stop-Here "Docker Desktop is not running. Open it, wait for 'Engine running', run again." }

Write-Host "2/6 Checking this laptop can reach the cloud at $MacIp ..." -ForegroundColor Cyan
$ok = $false
try { $r = Invoke-RestMethod -Uri "http://$($MacIp):8000/health/ready" -TimeoutSec 5; if ($r.status -eq "ready") { $ok = $true } } catch {}
if (-not $ok) { Stop-Here "Cannot reach http://$($MacIp):8000. Same Wi-Fi? Mac firewall off? Did the Mac run 'bash scripts/demo-mac.sh remote'?" }

Write-Host "3/6 Removing the old collector login (it belongs to an older cloud)..." -ForegroundColor Cyan
docker compose -f deploy/collector.compose.yml down -v

Write-Host "4/6 Starting the collector..." -ForegroundColor Cyan
$env:INGEST_URL_IN = "http://$($MacIp):8000/v1"
$env:ENROLL_TOKEN_ACME = $Token
docker compose -f deploy/collector.compose.yml up -d --build sim sandbox collector-acme
if ($LASTEXITCODE -ne 0) { Stop-Here "docker compose failed (message above)." }

Write-Host "5/6 Waiting for it to connect" -NoNewline -ForegroundColor Cyan
$s = $null
for ($i = 0; $i -lt 45; $i++) {
  Start-Sleep 2; Write-Host "." -NoNewline
  try { $s = Invoke-RestMethod -Uri "http://localhost:8100/local/cloud" -TimeoutSec 3; if ($s.enrolled -and $s.online) { break } } catch {}
}
Write-Host ""
if (-not ($s -and $s.enrolled)) {
  if ($s) { Stop-Here "Not connected. Collector says: $($s.last_error)" }
  docker compose -f deploy/collector.compose.yml logs --tail 20 collector-acme
  Stop-Here "Collector did not start (log above)."
}
Write-Host "   Connected. Parcels confirmed by the cloud: $($s.outbox.last_acked_seq)" -ForegroundColor Green

Write-Host "6/6 Starting the collector screen..." -ForegroundColor Cyan
Get-Process node -ErrorAction SilentlyContinue | Stop-Process -Force
Set-Location web
if (-not (Test-Path node_modules)) { npm install }
Start-Process "http://localhost:5174"
Write-Host "READY. Keep this window open. Collector screen: http://localhost:5174" -ForegroundColor Green
npm run dev:site

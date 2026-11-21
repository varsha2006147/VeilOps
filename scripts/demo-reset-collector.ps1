# Reset the collector to zero and enrol it (Windows PowerShell, from the repo root):
#   powershell -ExecutionPolicy Bypass -File scripts\demo-reset-collector.ps1 http://<cloud-ip>:8000/v1 <token>
#   same laptop as the cloud: use http://host.docker.internal:8000/v1
param([Parameter(Mandatory=$true)][string]$CloudUrl, [Parameter(Mandatory=$true)][string]$Token)
$ErrorActionPreference = "Stop"
$env:INGEST_URL_IN = $CloudUrl; $env:ENROLL_TOKEN_ACME = $Token
$C = @("compose", "-f", "deploy/collector.compose.yml")
docker @C down -v
docker @C up -d --build sim sandbox collector-acme
Write-Host -NoNewline "waiting for enrolment"
for ($i = 0; $i -lt 45; $i++) {
  try { $s = Invoke-RestMethod http://localhost:8100/local/cloud; if ($s.enrolled) { Write-Host " enrolled"; Write-Host "Console: cd web; npm run dev:site  ->  http://localhost:5174"; exit 0 } } catch {}
  Write-Host -NoNewline "."; Start-Sleep 2
}
Write-Host ""; Write-Host "Not enrolled yet. Collector says:"; try { Invoke-RestMethod http://localhost:8100/local/cloud | ConvertTo-Json } catch { Write-Host $_ }

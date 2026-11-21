# Reset the VeilOps cloud to zero for a demo (Windows PowerShell, from the repo root):
#   powershell -ExecutionPolicy Bypass -File scripts\demo-reset-cloud.ps1
$ErrorActionPreference = "Stop"
$C = @("compose", "-f", "deploy/docker-compose.yml")
if (-not (Test-Path deploy/.env)) { python -m cloud.scripts.generate_local_secrets | Out-File -Encoding ascii deploy/.env }
if (-not $env:CLOUD_BIND) { $env:CLOUD_BIND = "0.0.0.0" }
docker @C down -v
docker @C up -d --build postgres redis cloud-api
Write-Host -NoNewline "waiting for the cloud"
while ($true) { try { Invoke-RestMethod http://localhost:8000/health/ready | Out-Null; break } catch { Write-Host -NoNewline "."; Start-Sleep 2 } }
Write-Host " ready"
$DB = "postgresql://veilops:veilops_dev_only@postgres:5432/veilops"
$users = @(@("operator@acme.test","Asha - Acme operator","t_acme","operator"), @("approver@acme.test","Ravi - Acme approver","t_acme","approver"), @("operator@globex.test","Mia - Globex operator","t_globex","operator"))
foreach ($u in $users) { docker @C exec -T -e ADMIN_DATABASE_URL=$DB cloud-api python -m cloud.scripts.create_dashboard_user --email $u[0] --name $u[1] --tenant $u[2] --role $u[3] --password veilops-demo-1 }
$token = (docker @C exec -T cloud-api python -m cloud.scripts.create_enrollment_token --tenant t_acme --region in | Select-Object -Last 1).Trim()
$ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -match "Wi-Fi|Ethernet" -and $_.IPAddress -notmatch "^169\." } | Select-Object -First 1).IPAddress
Write-Host ""
Write-Host "Cloud is ready (from zero). Dashboard: cd web; npm run dev  ->  http://localhost:5173"
Write-Host "Collector token (one use, 15 min): $token"
Write-Host "Cloud address for the collector:   http://$($ip):8000/v1"

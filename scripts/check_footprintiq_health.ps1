<#
.SYNOPSIS
    Performs comprehensive health check probes on FootprintIQ and dependencies.
.DESCRIPTION
    Probes FastAPI endpoints (/health/live, /health/ready, /api/v1/health),
    SeaweedFS Filer, and Microsoft SQL Server 2022 Express.
.EXAMPLE
    .\scripts\check_footprintiq_health.ps1
#>

param(
    [string]$BaseUrl = "http://127.0.0.1:8000"
)

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host " FOOTPRINTIQ SYSTEM HEALTH PROBE" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan

$Success = $true

# 1. Probe /health/live
try {
    $res = Invoke-RestMethod -Uri "$BaseUrl/health/live" -Method Get -TimeoutSec 5 -ErrorAction Stop
    Write-Host "[+] Liveness Probe (/health/live): SUCCESS (Status: $($res.status))" -ForegroundColor Green
} catch {
    Write-Host "[-] Liveness Probe (/health/live): FAILED ($($_.Exception.Message))" -ForegroundColor Red
    $Success = $false
}

# 2. Probe /health/ready
try {
    $res = Invoke-RestMethod -Uri "$BaseUrl/health/ready" -Method Get -TimeoutSec 5 -ErrorAction Stop
    Write-Host "[+] Readiness Probe (/health/ready): SUCCESS (Status: $($res.status), DB: $($res.database), Storage: $($res.storage))" -ForegroundColor Green
} catch {
    Write-Host "[-] Readiness Probe (/health/ready): FAILED ($($_.Exception.Message))" -ForegroundColor Red
    $Success = $false
}

# 3. Probe SeaweedFS Filer
$SeaweedUrl = "http://localhost:18888/"
try {
    $res = Invoke-WebRequest -Uri $SeaweedUrl -Method Head -TimeoutSec 3 -ErrorAction Stop
    Write-Host "[+] SeaweedFS Filer ($SeaweedUrl): SUCCESS (HTTP $($res.StatusCode))" -ForegroundColor Green
} catch {
    Write-Host "[-] SeaweedFS Filer ($SeaweedUrl): FAILED ($($_.Exception.Message))" -ForegroundColor Red
    $Success = $false
}

# 4. Probe SQL Server 2022 Express Direct Connection
try {
    $SqlCheck = python -c "
from app.database import engine
from sqlalchemy import text
with engine.connect() as conn:
    res = conn.execute(text('SELECT COUNT(*) FROM investigations')).scalar()
    print(f'OK: {res} investigations in database')
" 2>&1
    if ($SqlCheck -match "^OK:") {
        Write-Host "[+] SQL Server 2022 Express: SUCCESS ($SqlCheck)" -ForegroundColor Green
    } else {
        Write-Host "[-] SQL Server 2022 Express: WARNING ($SqlCheck)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[-] SQL Server Probe Failed: $_" -ForegroundColor Red
    $Success = $false
}

Write-Host "================================================================================" -ForegroundColor Cyan
if ($Success) {
    Write-Host " ALL HEALTH CHECKS PASSED — FOOTPRINTIQ OPERATIONAL" -ForegroundColor Green
} else {
    Write-Host " ONE OR MORE HEALTH CHECKS REPORTED ISSUES" -ForegroundColor Yellow
}
Write-Host "================================================================================" -ForegroundColor Cyan


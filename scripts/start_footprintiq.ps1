<#
.SYNOPSIS
    Starts the FootprintIQ application server.
.DESCRIPTION
    Validates infrastructure prerequisites (SQL Server, SeaweedFS, Alembic),
    and starts the FastAPI application using Uvicorn.
.EXAMPLE
    .\scripts\start_footprintiq.ps1 -Host "127.0.0.1" -Port 8000
#>

param(
    [string]$HostAddress = "127.0.0.1",
    [int]$Port = 8000,
    [switch]$Reload = $false
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
Set-Location $RepoRoot

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host " STARTING FOOTPRINTIQ PLATFORM" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan

# 1. Check Python
$PythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $PythonExe) {
    Write-Error "Python executable not found in PATH. Please install Python 3.11."
    exit 1
}
Write-Host "[+] Python runtime: $PythonExe" -ForegroundColor Green

# 2. Check SeaweedFS Filer
$SeaweedUrl = "http://localhost:18888/"
try {
    $res = Invoke-WebRequest -Uri $SeaweedUrl -Method Head -TimeoutSec 3 -ErrorAction Stop
    Write-Host "[+] SeaweedFS Filer is active on $SeaweedUrl (Status: $($res.StatusCode))" -ForegroundColor Green
} catch {
    Write-Warning "[-] SeaweedFS Filer not responding on $SeaweedUrl. Evidence storage operations may fail."
}

# 3. Check SQL Server
try {
    $SqlCheck = python -c "
from app.database import engine, check_database_connection
with engine.connect() as conn:
    print('CONNECTED')
" 2>&1
    if ($SqlCheck -match "CONNECTED") {
        Write-Host "[+] SQL Server 2022 Express connected successfully." -ForegroundColor Green
    } else {
        Write-Warning "[-] SQL Server check returned: $SqlCheck"
    }
} catch {
    Write-Warning "[-] SQL Server connectivity warning: $_"
}

# 4. Apply Database Migrations
Write-Host "[*] Verifying and applying database migrations..." -ForegroundColor Yellow
try {
    alembic upgrade head
    Write-Host "[+] Database migrations up to date." -ForegroundColor Green
} catch {
    Write-Warning "[-] Alembic upgrade warning: $_"
}

# 5. Launch Uvicorn Server
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host " Launching FootprintIQ on http://${HostAddress}:${Port}" -ForegroundColor Green
Write-Host " Press Ctrl+C to terminate the application server." -ForegroundColor Yellow
Write-Host "================================================================================" -ForegroundColor Cyan

$ReloadArg = if ($Reload) { "--reload" } else { "" }
python -m uvicorn app.main:app --host $HostAddress --port $Port $ReloadArg


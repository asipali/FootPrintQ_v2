# FOOTPRINTIQ — LOCAL & PRODUCTION DEPLOYMENT GUIDE

**Document ID:** `docs/FOOTPRINTIQ_DEPLOYMENT_GUIDE.md`  
**Date:** November 3, 2026  
**Version:** 2.0.0  
**Target Platform:** Windows 10/11 / Windows Server 2022 (with cross-platform Linux/WSL notes)  

---

## 1. System Requirements & Prerequisites

### 1.1 Software & Runtimes
- **Python:** Python 3.11.x (tested on 3.11.9) 64-bit with `pip` and virtual environment support.
- **Relational Database:** Microsoft SQL Server 2022 Express or Standard/Enterprise (`localhost\SQLEXPRESS`).
- **ODBC Driver:** Microsoft ODBC Driver 17 or 18 for SQL Server.
- **Evidence Storage:** SeaweedFS Filer v4.50+ (`localhost:18888` HTTP endpoint).
- **Network Reconnaissance Tools:**
  - Nmap 7.94+ installed and available on system `PATH` (or configured via `NMAP_BIN`).
  - Optional: Greenbone / OpenVAS GMP daemon (port 9390 or Unix domain socket).

---

## 2. Infrastructure Setup

### 2.1 Microsoft SQL Server 2022 Express
1. Ensure SQL Server is running:
   ```powershell
   Get-Service -Name "MSSQL$SQLEXPRESS"
   ```
2. Verify connection via sqlcmd or PowerShell:
   ```powershell
   sqlcmd -S "localhost\SQLEXPRESS" -E -Q "SELECT @@VERSION;"
   ```
3. Initialize the `footprintiq` database:
   ```powershell
   python scripts/init_mssql_db.py
   ```
4. Run Alembic database migrations:
   ```powershell
   alembic upgrade head
   ```

### 2.2 SeaweedFS Filer Setup
1. Launch SeaweedFS master, volume, and filer on port 18888:
   ```powershell
   weed server -dir="D:\seaweedfs_data" -filer=true -filer.port=18888 -master.port=9333 -volume.port=8080
   ```
2. Verify Filer HTTP connectivity:
   ```powershell
   Invoke-RestMethod -Uri "http://localhost:18888/" -Method Get
   ```

---

## 3. Environment Configuration (`.env`)

Create your `.env` file by copying `.env.example`:
```powershell
Copy-Item .env.example .env
```

Key production parameters:
```ini
# Application Mode
APP_NAME="FootprintIQ - Digital Footprint Investigator"
APP_ENV="production"
DEBUG=False
APP_VERSION="2.0.0"

# Host & Binding
HOST="127.0.0.1"
PORT=8000
ALLOWED_HOSTS='["127.0.0.1", "localhost"]'

# Database Connection (ODBC Driver 18)
DATABASE_URL="mssql+pyodbc://localhost/footprintiq?driver=ODBC+Driver+18+for+SQL+Server&TrustServerCertificate=yes"
DB_FALLBACK_TO_SQLITE=False

# Cryptography & Secret Keys (Generate via: python -c "import secrets; print(secrets.token_hex(32))")
SECRET_KEY="<YOUR_32+_CHARACTER_HIGH_ENTROPY_HEX_KEY>"

# Evidence Storage Backend
STORAGE_BACKEND="seaweedfs"
SEAWEEDFS_FILER_URL="http://localhost:18888"
SEAWEEDFS_COLLECTION="evidence"
SEAWEEDFS_TIMEOUT_SECONDS=10.0
SEAWEEDFS_MAX_RETRIES=3
SEAWEEDFS_FALLBACK_TO_FILESYSTEM=False

# Active Scanning
NMAP_BIN="C:\Program Files (x86)\Nmap\nmap.exe"
NMAP_DEFAULT_TIMEOUT_SECONDS=120
NMAP_MAX_CONCURRENCY=2

# Security Policies
SESSION_MAX_AGE_SECONDS=14400
SESSION_COOKIE_SECURE=True
SESSION_COOKIE_SAMESITE="lax"
MAX_FAILED_LOGIN_ATTEMPTS=5
LOCKOUT_DURATION_MINUTES=15
```

---

## 4. Initial User & Administrator Provisioning

To bootstrap the system administrator account:
```powershell
python scripts/create_admin.py --username admin --email admin@organization.local --password "SuperSecureAdminPassword123!#"
```

---

## 5. Starting & Managing FootprintIQ

Use the automated management scripts provided in `scripts/`:

### 5.1 Start Application
```powershell
.\scripts\start_footprintiq.ps1
```
This script checks SQL Server and SeaweedFS pre-flight health, validates Python dependencies, applies pending migrations, and launches the FastAPI application with Uvicorn on `http://127.0.0.1:8000`.

### 5.2 Health Inspection
```powershell
.\scripts\check_footprintiq_health.ps1
```
Performs end-to-end probing of `/health/live`, `/health/ready`, SQL Server connectivity, and SeaweedFS status.

### 5.3 Stop Application
```powershell
.\scripts\stop_footprintiq.ps1
```
Gracefully terminates the FootprintIQ Uvicorn server processes.

---

## 6. Verification Checklist

- [x] SQL Server 2022 Express database `footprintiq` exists and responds.
- [x] Alembic revision is at `0009_evidence_storage_backend`.
- [x] SeaweedFS Filer is responding on port 18888.
- [x] Health checks (`/health/live` and `/health/ready`) return HTTP 200 `status: OK`.
- [x] Security headers (`CSP`, `X-Content-Type-Options`, `X-Frame-Options`) are verified.
- [x] Admin login succeeds with session and CSRF cookies issued.
- [x] Investigation workflow dispatches, updates state, and generates PDF / GraphML artifacts.


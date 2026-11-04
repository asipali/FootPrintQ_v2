# FOOTPRINTIQ — INSTALLATION & SETUP GUIDE

**Document ID:** `docs/setup/INSTALLATION_AND_SETUP.md`  
**Date:** November 3, 2026  
**Status:** COMPLETE & AUTHORITATIVE  

---

## 1. Prerequisites & System Requirements

### 1.1 Software Dependencies
- **Python:** Version 3.11.x (tested on Python 3.11.9, 64-bit).
- **Database:** Microsoft SQL Server 2022 Express (`localhost\SQLEXPRESS`).
- **ODBC Driver:** Microsoft ODBC Driver 17 or 18 for SQL Server.
- **Object Storage:** SeaweedFS Filer v4.50+ (HTTP REST endpoint on port 18888).
- **Scanning Tools:** Nmap 7.94+ on system `PATH`.
- **Optional Tools:** Greenbone / OpenVAS GMP daemon (port 9390 or Unix socket).

---

## 2. Step-by-Step Installation

### Step 1: Clone Repository & Create Virtual Environment
```powershell
cd D:\Desktop\HackShift\footprint
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### Step 2: Install Python Dependencies
```powershell
python -m pip install --upgrade pip setuptools wheel
python -m pip install -e ".[dev]"
```

### Step 3: Configure Environment Variables
Copy the template configuration:
```powershell
Copy-Item .env.example .env
```
Key settings in `.env`:
```ini
APP_NAME="FootprintIQ - Digital Footprint Investigator"
APP_ENV="development"
DEBUG=True

# Database (SQL Server 2022 Express)
DATABASE_URL="mssql+pyodbc://localhost/footprintiq?driver=ODBC+Driver+18+for+SQL+Server&TrustServerCertificate=yes"
DB_FALLBACK_TO_SQLITE=True

# Evidence Storage
STORAGE_BACKEND="seaweedfs"
SEAWEEDFS_FILER_URL="http://localhost:18888"
SEAWEEDFS_COLLECTION="evidence"

# Security
SECRET_KEY="dev-insecure-secret-key-change-in-production-only"
```

### Step 4: Initialize SQL Server Database & Apply Migrations
```powershell
# Create the footprintiq database in SQL Server
python scripts/init_mssql_db.py

# Apply all Alembic schema migrations (0001 through 0009)
alembic upgrade head
```

### Step 5: Start SeaweedFS Filer
If SeaweedFS is not already running:
```powershell
weed server -dir="D:\seaweedfs_data" -filer=true -filer.port=18888 -master.port=9333 -volume.port=8080
```

---

## 3. Account Provisioning

### 3.1 Provision Administrator Identity
Use the secure administrator CLI tool:
```powershell
python scripts/create_admin.py --username admin --email admin@organization.local --password "AdminSecurePassword123!#"
```

### 3.2 Provision Local Demonstration Accounts (Optional)
If `DEMO_ACCOUNTS_ENABLED=True` in `.env`:
```powershell
# Bulk provision configured identities:
python scripts/provision_demo_accounts.py

# Or provision a single test analyst interactively:
python scripts/provision_demo_account.py --username test_analyst --role analyst
```

---

## 4. Running FootprintIQ

### Automated Platform Startup
```powershell
.\scripts\start_footprintiq.ps1
```
This script checks SQL Server and SeaweedFS preflight health, verifies migrations, and starts the FastAPI server with Uvicorn on `http://127.0.0.1:8000`.

### Manual Startup
```powershell
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

---

## 5. Verification & Health Probing

Run the automated health probe:
```powershell
.\scripts\check_footprintiq_health.ps1
```
Expected output:
- `Liveness Probe (/health/live): SUCCESS (Status: ok)`
- `Readiness Probe (/health/ready): SUCCESS (Status: ok, DB: True, Storage: True)`
- `SeaweedFS Filer: SUCCESS (HTTP 200)`
- `SQL Server 2022 Express: SUCCESS`


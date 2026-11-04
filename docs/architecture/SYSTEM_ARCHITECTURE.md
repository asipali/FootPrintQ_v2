# FOOTPRINTIQ — SYSTEM ARCHITECTURE SPECIFICATION

**Document ID:** `docs/architecture/SYSTEM_ARCHITECTURE.md`  
**Date:** November 3, 2026  
**Status:** COMPLETE & AUTHORITATIVE  
**Architecture Version:** 2.0.0  

---

## 1. Architectural Overview

FootprintIQ is an enterprise-grade digital footprint investigator and cybersecurity reconnaissance platform. The application is designed around modular, asynchronous Python services, strict tenant boundaries, durable background job scheduling, and high-performance dual-tier persistence (relational metadata in Microsoft SQL Server 2022 Express and forensic object storage in SeaweedFS Filer).

```
+-----------------------------------------------------------------------------------+
|                                 CLIENT LAYER                                      |
|   Browser UI (Jinja2 + HTMX)   |   REST API Clients (cURL / Python SDK / Script)  |
+-----------------------------------------------------------------------------------+
                                         |
                                         v HTTP / HTTPS (JSON & HTML)
+-----------------------------------------------------------------------------------+
|                            FASTAPI APPLICATION RUNTIME                            |
|  +-----------------------------------------------------------------------------+  |
|  | Middleware Pipeline:                                                        |  |
|  | - TrustedHostMiddleware (Host header validation)                            |  |
|  | - correlation_id_middleware (X-Request-ID, duration, security headers, CSP)|  |
|  | - RBAC & Authentication Barrier (Session token, CSRF cookie verification)   |  |
|  +-----------------------------------------------------------------------------+  |
|  | API & Dashboard Routers:                                                    |  |
|  | - /api/v1/auth, /api/v1/investigations, /api/v1/recon, /api/v1/nmap_scans    |  |
|  | - /api/v1/vulnerability, /api/v1/audit, /dashboard, /admin/dashboard       |  |
|  +-----------------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------------+
         |                                                 |
         v                                                 v
+-------------------------------+      +-------------------------------------------+
|    DURABLE JOB QUEUE          |      |  WORKFLOW ORCHESTRATION PIPELINE          |
|  - SQL Server 'jobs' Table    |      |  - 11-State Deterministic State Machine   |
|  - Heartbeat Leases (120s)    | ---> |  - Cooperative Inter-Stage Cancellation   |
|  - Worker Lease Recovery      |      |  - Multi-Stage Automated Execution Engine |
|  - Duplicate Prevention       |      +-------------------------------------------+
+-------------------------------+                          |
                                                           v
+-----------------------------------------------------------------------------------+
|                        5-STAGE INVESTIGATION WORKFLOW                             |
|  [Stage 1: Passive Recon] -> RDAP, crt.sh, DNS resolution, entity harvesting      |
|  [Stage 2: Active Scan]   -> Nmap subprocess execution (shell=False, tokenized)   |
|  [Stage 3: Vuln Assess]   -> Greenbone/OpenVAS GMP (Graceful offline degradation) |
|  [Stage 4: Correlation]   -> Multi-source entity resolution & GraphML graph       |
|  [Stage 5: Scoring & Doc] -> 5-factor exposure calculation & PDF dossier report   |
+-----------------------------------------------------------------------------------+
         |                                                 |
         v (Relational Metadata & Audit)                   v (Forensic Evidence Binaries)
+-------------------------------+      +-------------------------------------------+
|  MICROSOFT SQL SERVER 2022    |      |  SEAWEEDFS FILER OBJECT STORAGE           |
|  - Database: [footprintiq]    |      |  - Port 18888 HTTP REST API               |
|  - Alembic Revisions (0001-09)|      |  - Collection: 'evidence'                 |
|  - Read Committed Snapshot    |      |  - Content-Addressable SHA-256 Storage    |
|  - Native Checksum Backups    |      |  - Pluggable EvidenceStorageAdapter       |
+-------------------------------+      +-------------------------------------------+
```

---

## 2. Core Subsystems & Components

### 2.1 Web & Presentation Layer
- **Templates:** Jinja2 server-rendered views under `app/templates/` styled with a modern cybersecurity aesthetic.
- **Dynamic Interaction:** Powered by HTMX for lightweight real-time polling of investigation status, progress bars, and execution timelines without heavy JavaScript SPAs.
- **Static Assets:** CSS, JS, and vendor icons served via `app/static/`.

### 2.2 Workflow Orchestration & State Machine
The investigation lifecycle is governed by an 11-state deterministic state machine defined in `app/services/workflow/state_machine.py`:
- **States:** `draft`, `ready`, `queued`, `running`, `cancelling`, `cancelled`, `partially_completed`, `completed`, `failed`, `paused`, `archived`.
- **Guards:** Transitions are enforced programmatically. For example, a `draft` investigation cannot execute until its scope and authorization boundaries are marked `ready`.
- **Cooperative Inter-Stage Cancellation:** Before each workflow stage, the orchestrator executes `_check_cancellation()`. If a user cancels the job, execution halts in sub-second time, marking the durable job and investigation as `cancelled`.
- **Graceful Fault Degradation:** If external scanners (such as Greenbone/OpenVAS) are offline or unreachable, Stage 3 logs `SKIPPED_UNAVAILABLE`, marks `is_partial = True`, and the investigation cleanly completes in the `partially_completed` state rather than crashing.

### 2.3 Durable Background Job Queue (`jobs` table)
- **Lease Mechanism:** Active workers lease jobs by writing a `worker_id` and timestamping `lease_expires_at = utc_now() + timedelta(seconds=120)`.
- **Heartbeat Protocol:** Running workers periodically refresh the lease timestamp.
- **Restart & Crash Recovery:** Upon application startup, `JobRecoveryService` sweeps for claimed or running jobs with expired leases and safely resets them to `QUEUED` or `FAILED`.
- **Duplicate Prevention:** Prevents dispatching overlapping workflows on the same investigation target.

### 2.4 Entity Correlation & Knowledge Graph Construction
- **Service:** `InvestigationCorrelationService` in `app/services/workflow/correlation.py`.
- **Normalization:** Cleanses domains, hostnames, IPv4/IPv6 addresses, CIDRs, and port records.
- **Graph Generation:** Exports structured GraphML XML (`<graphml>`) representing relationships between domains, subdomains, open ports, IP infrastructure, certificates, and discovered vulnerabilities.

### 2.5 5-Factor Exposure Scoring Engine
- **Service:** `ExposureScoringEngine` computes calibrated risk metrics:
  1. **External Attack Surface Factor:** Number of responsive public IP addresses and open ports.
  2. **Service Vulnerability Factor:** CVSS base score aggregation of detected CVEs.
  3. **Configuration & Banner Exposure:** Information disclosure in HTTP server headers and SSL certificates.
  4. **Domain & DNS Hygiene Factor:** Missing SPF, DKIM, DMARC records, or expired WHOIS/RDAP data.
  5. **Network Topology & Scope Factor:** Exposure of non-standard management ports (e.g., SSH, RDP, SMB).
- **Output:** Normalized composite exposure score from 0.0 (Minimal Exposure) to 100.0 (Critical Threat).

### 2.6 Cryptographic PDF Dossier Generation
- **Service:** `InvestigationReportGenerator` using ReportLab.
- **Structure:** Multi-page executive and technical dossier including target scope, timeline, discovered assets, open ports, vulnerability severity breakdown, and cryptographic SHA-256 evidence chain of custody.

---

## 3. Storage & Persistence Architecture

### 3.1 Dual-Tier Persistence
1. **Primary Relational Store (SQL Server 2022 Express):**
   - Tables: `users`, `user_sessions`, `audit_events`, `investigations`, `target_authorizations`, `recon_entities`, `recon_artifacts`, `nmap_scans`, `nmap_ports`, `vulnerability_scans`, `vulnerability_findings`, `jobs`, `evidence`.
   - Managed via Alembic migrations (revisions `0001` through `0009_evidence_storage_backend`).
2. **Forensic Evidence Store (SeaweedFS Filer HTTP):**
   - High-throughput distributed object storage exposing a REST API on port 18888.
   - Storage path: `/evidence/{investigation_id}/{sha256_prefix}/{evidence_id}.bin`.
   - Complete storage abstraction implemented in `app/storage/`.

### 3.2 Data Preservation Guarantees
- 264 local filesystem evidence files (102,076 bytes) are preserved bit-for-bit.
- 7 authoritative evidence items migrated to SeaweedFS are verified via SHA-256 checksum parity.
- Legacy SQLite database (`footprintiq.db`, 565,248 bytes) remains intact as an immutable offline baseline.


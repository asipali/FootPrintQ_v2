# FOOTPRINTIQ — HISTORICAL MIGRATION ARCHIVE

**Document ID:** `docs/archive/MIGRATION_HISTORY.md`  
**Date:** November 3, 2026  
**Archive Status:** PERMANENT HISTORICAL ARCHIVE  

---

## 1. Executive Summary

This document archives the historical evolution and major platform migrations of FootprintIQ, preserving the architectural rationale, audit evidence, and baseline checkpoints from the transition from a dual-runtime Node.js/TypeScript prototype to the unified Python 3.11/FastAPI platform.

---

## 2. Python-Only Platform Modernization (November 1, 2026)

### 2.1 Pre-Migration State
The repository previously maintained two disconnected application runtimes:
1. **Frontend / Node API:** React 19 / Vite frontend with an Express 4 / TypeScript REST API at repository root (`src/`, `server.ts`, `package.json`, `bun.lock`, `vite.config.ts`).
2. **Backend Application:** A complete Python application under `python_app/` featuring FastAPI, SQLAlchemy 2.0, Jinja2 templates, static assets, Alembic migrations, passive/active reconnaissance services, evidence storage, and an automated test suite.

### 2.2 Modernization Actions
1. **Repository Consolidation:** Removed legacy Node.js/TypeScript sources, dependencies (`package.json`, `bun.lock`), and build tooling. Moved the Python application modules, templates, static assets, migrations, scripts, and tests to the repository root.
2. **Dependency Canonicalization:** Replaced fractured requirement files with a unified `pyproject.toml` managing development and production dependencies.
3. **Containerization:** Authored production `Dockerfile` and `.dockerignore` targeting Python 3.11-slim.
4. **Data Preservation:** Preserved the original SQLite database triplet (`footprintiq.db`, `footprintiq.db-wal`, `footprintiq.db-shm`), existing forensic evidence in `evidence_storage/`, and scan reports in `data/` without data loss or reset.

---

## 3. Phase 1 Migration Audit Summary

- **Audit Date:** October 27, 2026
- **Baseline Test Suite:** 171 automated unit, integration, and security tests passing.
- **Resolved Migration Findings:**
  - Implemented open redirect defense on authentication routes (`is_safe_redirect_url`).
  - Redesigned `/login` and `/signup` templates to a responsive cybersecurity SaaS light theme.
  - Created public landing page at `/` with explicit capability boundaries.
  - Implemented public self-service investigator registration with Argon2id password complexity enforcement.
  - Implemented repeatable, idempotent demo account provisioning script (`scripts/provision_demo_account.py`).


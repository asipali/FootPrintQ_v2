# FOOTPRINTIQ — KNOWN ISSUES & OPERATIONAL CONSIDERATIONS

**Document ID:** `docs/FOOTPRINTIQ_KNOWN_ISSUES.md`  
**Date:** November 3, 2026  
**Version:** 2.0.0  

---

## 1. Operational & Environmental Considerations

### 1.1 Greenbone / OpenVAS Vulnerability Scanner Availability
- **Context:** Greenbone Vulnerability Manager (`gvmd` / GMP) runs natively on Linux/Unix systems or containerized environments. On native Windows development hosts, a local Greenbone daemon may not be active.
- **System Behavior:** FootprintIQ's `GreenboneVulnerabilityRunner` inspects GMP connectivity via `check_availability()`. If Greenbone is unreachable or unconfigured:
  - Stage 3 records `SKIPPED_UNAVAILABLE`.
  - The workflow marks `is_partial = True`.
  - The investigation transitions cleanly to `partially_completed` (rather than failing).
  - An audit event is logged.
- **Resolution:** When full vulnerability scanning is required, configure `GVM_HOST`, `GVM_PORT`, `GVM_USERNAME`, and `GVM_PASSWORD` targeting a running Greenbone instance or container.

### 1.2 Upstream RDAP Registry Throttling
- **Context:** The passive reconnaissance RDAP collector queries public bootstrap servers (`rdap.org`). Certain top-level registries (e.g., Verisign for `.com` domains) may return HTTP 302 redirects or HTTP 400/429 responses if queries lack domain prefixes or exceed rate limits.
- **System Behavior:** FootprintIQ treats external intelligence queries with isolated fault tolerance. If an RDAP endpoint fails, the error is isolated, and other collectors (Certificate Transparency, DNS, Nmap) continue uninterrupted.

### 1.3 Nmap Raw Socket Privileges on Windows
- **Context:** Advanced Nmap scanning flags such as SYN stealth (`-sS`), UDP scanning (`-sU`), or OS detection (`-O`) require raw packet capture drivers (Npcap) with administrative privileges.
- **System Behavior:** FootprintIQ's default scan profile utilizes unprivileged TCP connect (`-sT`) and service version detection (`-sV`) with bounded concurrency (`NMAP_MAX_CONCURRENCY=2`), ensuring reliable execution under standard user accounts.

### 1.4 SQLite Fallback Lockout in Production
- **Context:** FootprintIQ supports SQLite fallback (`footprintiq.db`) for developer convenience and isolated testing.
- **Security Constraint:** In staging and production environments (`APP_ENV=production`), `DB_FALLBACK_TO_SQLITE` and `SEAWEEDFS_FALLBACK_TO_FILESYSTEM` are enforced to `False` by Pydantic model validators. If SQL Server or SeaweedFS is unreachable, the application fails fast to prevent split-brain state or unencrypted local data storage.

### 1.5 Upstream Test Library Deprecation Notices
- **Context:** Pytest test runs output Starlette deprecation warnings regarding `httpx` with `starlette.testclient` and `HTTP_422_UNPROCESSABLE_ENTITY` name changes.
- **Impact:** Strictly cosmetic warnings from upstream third-party dependencies; zero runtime impact.


# FOOTPRINTIQ — APPLICATION SECURITY & DEFENSE-IN-DEPTH GUIDE

**Document ID:** `docs/security/SECURITY_GUIDE.md`  
**Date:** November 3, 2026  
**Status:** COMPLETE & AUTHORITATIVE  
**Security Standard:** RFC 9106, OWASP Top 10 2021, NIST SP 800-63B  

---

## 1. Security Architecture Overview

FootprintIQ processes sensitive reconnaissance targets, network scanning telemetry, and vulnerability findings. Security is enforced through defense-in-depth across the web layer, API boundaries, background workers, storage adapters, and database engines.

```
+-----------------------------------------------------------------------------------+
|                         DEFENSE-IN-DEPTH SECURITY LAYERS                          |
+-----------------------------------------------------------------------------------+
| 1. Network & Host   | TrustedHostMiddleware (Host header allowlisting)            |
| 2. HTTP Headers     | CSP, Anti-Clickjacking (DENY), nosniff, Permissions-Policy  |
| 3. Cache Control    | Cache-Control: no-store, no-cache on all operational/APIs   |
| 4. Rate Limiting    | In-memory sliding-window limiter on /login and /signup      |
| 5. Authentication   | RFC 9106 Argon2id hashing, stateful SHA-256 session tokens  |
| 6. CSRF Defense     | Double-submit cookie pattern with constant-time HMAC verify |
| 7. Access Control   | Granular RBAC permissions and strict tenant data isolation  |
| 8. Input Validation | Target regex / IP validation rejecting command injection    |
| 9. Subprocess Exec  | asyncio.create_subprocess_exec with tokenized args, shell=0 |
| 10. Persistence     | SQLAlchemy 2.0 parameterized queries; SQL Server least priv |
+-----------------------------------------------------------------------------------+
```

---

## 2. Authentication & Credential Security

### 2.1 Password Hashing (Argon2id)
Passwords are encrypted using Argon2id via `argon2-cffi` configured to RFC 9106 recommendations:
- **Algorithm:** `argon2id` (hybrid resistant to side-channel and GPU cracking attacks)
- **Time Cost:** `3` iterations
- **Memory Cost:** `65536` KiB (64 MiB)
- **Parallelism:** `4` parallel threads
- **Hash Format:** `$argon2id$v=19$m=65536,t=3,p=4$...`

### 2.2 Server-Side Session Management
- Tokens are 32-byte cryptographically secure random values generated via `secrets.token_urlsafe(32)`.
- **Database Storage:** Raw tokens are never persisted. Only the SHA-256 hash digest (`token_hash`) is stored in `user_sessions`.
- **Session Revocation:** Logout immediately deletes the session record, invalidating all associated cookies.
- **Cookies:** Issued with `HttpOnly=True`, `SameSite=Lax`, and `Secure=True` (enforced in staging/production).

### 2.3 Account Lockout & Throttling
- **Failed Login Limit:** 5 consecutive invalid password attempts.
- **Lockout Duration:** 15 minutes.
- **Behavior:** The user account is automatically locked, and subsequent login attempts (even with valid credentials) return generic invalid credentials errors until the lockout window expires.

---

## 3. Sliding-Window Rate Limiting

Implemented in `app/core/rate_limit.py` using thread-safe sliding-window tracking:
- **`/api/v1/auth/login`:** Capped at 20 requests per 60 seconds per IP address.
- **`/api/v1/auth/signup`:** Capped at 10 requests per 60 seconds per IP address.
- **Response:** Exceeding thresholds returns `HTTP 429 Too Many Requests` with a standard `Retry-After: <seconds>` header.

---

## 4. HTTP Security Headers & Content-Security-Policy (CSP)

Universal headers injected by `correlation_id_middleware` across all HTTP responses:

```http
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'; object-src 'none';
Strict-Transport-Security: max-age=31536000; includeSubDomains (Production only)
```

---

## 5. Subprocess Execution & Command Injection Defense

Active reconnaissance (`NmapRunner` in `app/services/active/runner.py`) uses strict subprocess boundaries:
- **No Shell Interpreter:** Calls `asyncio.create_subprocess_exec(*cmd, ...)` with `shell=False`.
- **Target Sanitization:** Inputs are pre-validated by `classify_target()` in `app/services/target_authorization.py`.
- **Injection Rejection:** Target strings containing `;`, `&&`, `|`, `` ` ``, `$()`, `\n`, or `\r` are immediately classified as `UNKNOWN` and rejected before any command can be constructed.

---

## 6. Role-Based Access Control (RBAC) & Tenant Isolation

### 6.1 Role Hierarchy & Permissions
| Role | Capabilities |
|:---|:---|
| **`administrator`** | Full platform access, user management, scope approvals, audit log inspection, server settings. |
| **`investigator`** | Create and manage owned investigations, dispatch passive/active scans, generate PDF/GraphML reports. |
| **`analyst`** | Execute reconnaissance workflows, view findings, add investigation notes, export reports. |
| **`viewer`** | Read-only access to assigned investigations, findings, and reports. Cannot dispatch scans or mutate scopes. |

### 6.2 Tenant Isolation
- Investigations record `owner_user_id` and an allowlist of `team_members`.
- Investigators and analysts cannot view or execute workflows on investigations owned by other users unless explicitly assigned to the team. Unauthorized attempts yield `HTTP 403 Forbidden` or `HTTP 404 Not Found`.

---

## 7. SQL Server Least Privilege Configuration

In production, FootprintIQ connects using a dedicated database user rather than `sa`:
```sql
USE [footprintiq];
CREATE LOGIN [footprintiq_app] WITH PASSWORD = '<StrongRandomPassword123!#>';
CREATE USER [footprintiq_app] FOR LOGIN [footprintiq_app];

-- Grant minimal required operational roles
ALTER ROLE [db_datareader] ADD MEMBER [footprintiq_app];
ALTER ROLE [db_datawriter] ADD MEMBER [footprintiq_app];
GRANT EXECUTE TO [footprintiq_app];

-- Explicitly deny schema modification and administrative privileges
DENY ALTER ANY SCHEMA TO [footprintiq_app];
DENY CONTROL TO [footprintiq_app];
```
Alembic migrations are executed using administrative deployment credentials prior to service startup.


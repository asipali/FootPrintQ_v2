# FOOTPRINTIQ — TASK 01B SQLITE PRESERVATION & REPOSITORY HYGIENE REPORT

**Document Reference:** `docs/FOOTPRINTIQ_TASK_01B_SQLITE_PRESERVATION_REPORT.md`  
**Execution Date:** 2026-11-02 (Local System Time: Asia/Calcutta)  
**Author / Lead Architect:** Antigravity (Google DeepMind)  
**Status:** **COLD BACKUP COMPLETE — AWAITING CHECKPOINT & GIT HYGIENE APPROVAL (GATE 1)**  
**Target Files:** `footprintiq.db`, `footprintiq.db-wal`, `footprintiq.db-shm`, `footprintiq.db.backup*`

---

## 1. Executive Summary

During previous test runs by OpenAI Codex, the tracked binary file `footprintiq.db-shm` was modified on disk when test processes triggered SQLite Write-Ahead Logging (WAL) initialization prior to test fixture isolation. The Task 01A review flagged this issue, noting that `footprintiq.db` and `footprintiq.db-wal` were gitignored, but `footprintiq.db-shm` was tracked, posing a desynchronization and corruption risk.

In accordance with Phase 1 directives:
1. **Zero Data Loss:** All SQLite files and sidecars have been safely preserved in an isolated, non-versioned cold backup directory prior to executing any modifications.
2. **Cryptographic Parity Confirmed:** All original database files and their backup counterparts have been verified via SHA-256 digests.
3. **Quiescent State:** Process audits confirmed zero active processes accessing SQLite.
4. **Git Hygiene Plan Ready:** The exact plan to untrack binary database artifacts from Git without deleting local copies is formulated and presented for Gate 1 approval.
5. **Safe Checkpoint Strategy Defined:** A safe, non-destructive `PRAGMA wal_checkpoint(PASSIVE)` procedure is documented to safely flush 3.66 MB of WAL frames into the primary database once approved.

---

## 2. SQLite Physical State & Backup Verification Evidence

### 2.1 Cold Backup Execution
An isolated cold backup was created at:
`.data/backups/cold_preservation_20261102/`

### 2.2 Cryptographic Verification Matrix (Original vs. Backup)

| File Name | File Size | Original Path SHA-256 | Cold Backup Path SHA-256 | Parity Status |
|---|---|---|---|---|
| `footprintiq.db` | 516,096 B | `8A76DE892695600F09CDBC6627A381279134B63FF393BA4D94789E9C3F7D4F57` | `8A76DE892695600F09CDBC6627A381279134B63FF393BA4D94789E9C3F7D4F57` | **100% IDENTICAL** |
| `footprintiq.db-wal` | 3,666,832 B | `089871B42AB9B84058D884B3577A7BA543758B2309ADFA036960E661ED301232` | `089871B42AB9B84058D884B3577A7BA543758B2309ADFA036960E661ED301232` | **100% IDENTICAL** |
| `footprintiq.db-shm` | 32,768 B | `28BF8315C97B5A74E4B1AE61DC44F54B94AAF9034A9C37CFC08DC124D12D77C9` | `28BF8315C97B5A74E4B1AE61DC44F54B94AAF9034A9C37CFC08DC124D12D77C9` | **100% IDENTICAL** |
| `footprintiq.db.backup` | 466,944 B | `B11B4F58EB092DF7F3C8CDCC0DDEC4E0B9672C3358C66C093DBC78E75421F0D6` | `B11B4F58EB092DF7F3C8CDCC0DDEC4E0B9672C3358C66C093DBC78E75421F0D6` | **100% IDENTICAL** |
| `footprintiq.db.backup-shm` | 32,768 B | `FD4C9FDA9CD3F9AE7C962B0DDF37232294D55580E1AA165AA06129B8549389EB` | `FD4C9FDA9CD3F9AE7C962B0DDF37232294D55580E1AA165AA06129B8549389EB` | **100% IDENTICAL** |
| `footprintiq.db.backup-wal` | 0 B | `E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855` | `E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855` | **100% IDENTICAL** |

### 2.3 Additional Pre-existing Backups
- `.data/backups/footprintiq-pre-module05-06-20261102-115349.db` (536,576 bytes) preserved.

---

## 3. Forensic Evidence Inventory

The `./evidence_storage` directory was audited:
- **Total Tracked Files:** 264 files across investigation directories (`inv-e2e-recon`, `inv-scan-*`, `inv-vuln-*`, `inv-dbddbcd3a4`).
- **File Types:**
  - Raw JSON DNS resolution dumps (`*.raw.json`)
  - RDAP registration logs (`*.raw.json`)
  - Certificate Transparency certificate chains (`*.raw.json`)
  - Raw Nmap scan outputs (`*.raw.txt`)
  - Greenbone OpenVAS vulnerability assessment reports (`*.raw.txt`)
- **Git Status:** 100% clean. Zero untracked or modified files in `evidence_storage`.

---

## 4. Root Cause & Git Tracking Issues

### 4.1 The Asymmetric Tracking Defect
Inspection of `.gitignore` lines 37–43 revealed:
```gitignore
# Database files
*.db
*.db-journal
*.db-wal
*.sqlite
*.sqlite3
```
**Defect:**
1. `*.db-shm` was omitted from `.gitignore`.
2. `*.db.backup*` was omitted from `.gitignore`.

When commit `f484b09` ("fix modules") was made, Git staged and committed `footprintiq.db-shm` and the `footprintiq.db.backup*` files, but ignored the main database `footprintiq.db` and WAL file `footprintiq.db-wal`.

### 4.2 The WAL / SHM Coupling Risk
In SQLite WAL mode:
- All database write transactions append frames to `footprintiq.db-wal`.
- `footprintiq.db-shm` maintains a memory-mapped index of which page versions reside in the WAL file vs the main database file.
- `footprintiq.db-wal` currently contains **3,666,832 bytes** (3.66 MB) of uncheckpointed data.
- If a developer or automated script ran `git checkout -- footprintiq.db-shm`, Git would revert the SHM file to its state at `f484b09` (hash: `0942234B...`), while the WAL file would remain at its current 3.66 MB state. This index mismatch causes SQLite readers to fail with `SQLITE_CORRUPT` or read stale pages.

---

## 5. Safe Remediation & Repository Hygiene Plan

To resolve this issue cleanly and permanently without data loss, the following steps are prepared:

### Step 1: Untrack Binary Artifacts from Git Index (Zero Local File Deletion)
Execute:
```bash
git rm --cached footprintiq.db-shm
git rm --cached footprintiq.db.backup
git rm --cached footprintiq.db.backup-shm
git rm --cached footprintiq.db.backup-wal
```
*Note:* The `--cached` flag ensures the files are removed from Git's tracking index while leaving the physical files on disk completely untouched.

### Step 2: Update `.gitignore`
Update `.gitignore` database exclusions:
```gitignore
# Database files & sidecars
*.db
*.db-journal
*.db-wal
*.db-shm
*.db.backup*
*.sqlite
*.sqlite3
```

### Step 3: Passive WAL Checkpoint
With the cold backup verified and processes halted, execute a non-blocking passive checkpoint:
```python
import sqlite3
con = sqlite3.connect("footprintiq.db")
con.execute("PRAGMA wal_checkpoint(PASSIVE);")
con.close()
```
*Rationale:* `PASSIVE` checkpoints as many frames as possible without blocking or waiting for other readers. Because all application processes are currently stopped, this will safely integrate committed transactions from `footprintiq.db-wal` into `footprintiq.db`.

---

## 6. Gate 1 Approval Request

Before executing Step 1 (untracking), Step 2 (`.gitignore` update), or Step 3 (WAL checkpoint), explicit confirmation is requested per the Phase 1 Approval Gate.


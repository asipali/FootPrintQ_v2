# Python-Only Migration Audit

Date: 2026-11-01  
Branch: `migration/python-only`  
Recovery point: `pre-python-only-2026-11-01`


## Original architecture

The repository contained two applications: a React/Vite frontend and Express/TypeScript API at the root (`src/`, `server.ts`, `package.json`, `bun.lock`, `vite.config.ts`), and a FastAPI application under `python_app/`. The Python app included Jinja templates, static assets, SQLAlchemy models, REST and HTML routes, Alembic migrations, security controls, reconnaissance integrations, evidence storage, reports, scripts, and tests.

## Final architecture

```text
.
├── app/                 # FastAPI app, API, models, services, templates, static
├── data/                # Retained scan outputs and evidence records
├── evidence_storage/    # Retained raw evidence
├── migrations/          # Alembic migrations
├── scripts/             # Admin and verification utilities
├── tests/               # Python test suite
├── .env.example
├── alembic.ini
├── Dockerfile
├── pyproject.toml       # Canonical dependency and package metadata
├── README.md
└── app.main:app         # Uvicorn entry point
```

The legacy root `.data/` and Python referenced `ui.mp4` asset were retained. The Python HTML UI and existing templates/static files were retained without redesign.

## Removed and migrated

- Removed React/Vite source (`src/`), Express entry point (`server.ts`), and Node/Bun manifests and build configuration.
- Moved the Python `app/`, `data/`, `evidence_storage/`, `migrations/`, `scripts/`, and `tests/` directories to the repository root.
- Moved Python config, docs, and local `.env` to root. The local `.env` remains ignored by Git.
- Removed duplicate `requirements.txt` files; `pyproject.toml` is the single dependency source. Corrected invalid package version `2.0.0-foundation` to PEP 440 version `2.0.0` and limited setuptools package discovery to `app*`.
- Added a conventional Python 3.11 Dockerfile and `.dockerignore`. No Vercel configuration was added.

## Preserved files and user data

The Python SQLite database, WAL/SHM files, database backup, `data/`, and `evidence_storage/` were moved without recreating or resetting them. The existing root `.data/` was left in place. The local `.env` was moved to root and was not displayed or added to Git. Database migrations were already at revision `0005_vuln` (head); no migration was applied during this move.

## Security and deployment review

- Existing authentication, RBAC, sessions, CSRF protections, audit logging, authorization checks, evidence hashing, Nmap, and Greenbone code were retained.
- `.env.example` remains a development template; production must provide a high-entropy `SECRET_KEY`, `APP_ENV=production`, `DEBUG=false`, appropriate `ALLOWED_HOSTS`, and secure cookie/origin settings. Public signup policy should be reviewed before exposure.
- The Docker image expects a persistent volume at `/var/lib/footprintiq` and an externally supplied production secret. Apply `python -m alembic upgrade head` as an explicit deployment step before serving traffic.
- Nmap and Greenbone are long-running workloads. Production should run scan execution in a separate worker deployment with a durable queue and shared persistent storage; do not dispatch them through serverless request lifetimes. Greenbone requires separately hosted GVM and credentials.
- SQLite is retained for this local migration. For multi-worker production, use a managed relational database and durable evidence storage.

## Validation performed

- `python -m pip install -e ".[dev]"`: passed after correcting the invalid project version.
- `python -m pytest tests -q`: **181 passed**, 6 warnings. The shell had an inherited `DEBUG=release` value that conflicts with the app's boolean setting; tests passed with process `DEBUG=true`, leaving `.env` unchanged.
- `python -m alembic current`: `0005_vuln (head)`.
- App import as `app.main:app`: passed.
- Local Uvicorn at `http://127.0.0.1:8000`: started successfully. `/health/live` and `/login` each returned HTTP 200.
- The retained local `.env` supplies `APP_VERSION=2.0.0-foundation`; it was preserved as-is. The package and example configuration now identify as `2.0.0`.
- Greenbone service connectivity and live external reconnaissance were not exercised. No active scans were launched.

## Known limitations and remaining work

- The inherited shell environment sets `DEBUG=release`; launch commands in that shell need a valid boolean override or the environment variable corrected.
- Docker image build/run was not executed. It requires a production secret and persistent volume; the existing host SQLite/evidence data is not copied into the image.
- Configure an external worker/queue before production active scanning. Verify production host/origin policy and signup policy for the actual deployment domain.
- Git changes remain local on `migration/python-only`; nothing was pushed or deployed.

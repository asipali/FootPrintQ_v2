"""Safely provisions the configured local FootprintIQ demo identities."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import get_settings
from app.core.auth import provision_demo_accounts
from app.database import SessionLocal


def main() -> int:
    settings = get_settings()
    if not settings.DEMO_ACCOUNTS_ENABLED:
        print("Demo accounts are disabled. Set DEMO_ACCOUNTS_ENABLED=true to provision local demo users.")
        return 1

    db = SessionLocal()
    try:
        result = provision_demo_accounts(db, settings)
    finally:
        db.close()

    print(
        "Demo account provisioning complete: "
        f"{len(result['created'])} created, {len(result['existing'])} already present."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Create the first administrator for a fresh, local TraceGate-R database.

This is an explicit command-line bootstrap utility, not an API route. It refuses
to run if any user records already exist and never prints the supplied password.
Do not use this utility to bootstrap a remote or production database.
"""
from __future__ import annotations

import os
import re
import sys
import uuid
from pathlib import Path

# Python sets sys.path[0] to scripts/ when this file is run directly.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.auth import hash_password, normalize_username, validate_password
from backend.app.main import _iso_now, _security_event, db_connect, init_db


def main() -> int:
    username_raw = os.environ.get("TRACEGATE_BOOTSTRAP_USERNAME", "")
    password = os.environ.get("TRACEGATE_BOOTSTRAP_PASSWORD", "")
    tenant_id = os.environ.get("TRACEGATE_BOOTSTRAP_TENANT_ID", "local-demo").strip().lower()
    tenant_name = os.environ.get("TRACEGATE_BOOTSTRAP_TENANT_NAME", "TraceGate-R Local Demo").strip()

    if not username_raw or not password:
        print(
            "Set TRACEGATE_BOOTSTRAP_USERNAME and TRACEGATE_BOOTSTRAP_PASSWORD "
            "in the environment before running this command.",
            file=sys.stderr,
        )
        return 2
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{1,63}", tenant_id):
        print("TRACEGATE_BOOTSTRAP_TENANT_ID must be 2-64 lowercase letters, digits, '_' or '-'.", file=sys.stderr)
        return 2
    if not tenant_name or len(tenant_name) > 120:
        print("TRACEGATE_BOOTSTRAP_TENANT_NAME must contain 1-120 characters.", file=sys.stderr)
        return 2

    try:
        username = normalize_username(username_raw)
        validate_password(password)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    init_db()
    now = _iso_now()
    user_id = str(uuid.uuid4())
    password_hash = hash_password(password)

    with db_connect() as db:
        existing_count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if existing_count:
            print(
                "Refusing to bootstrap: this database already contains user records. "
                "Use the existing administrator or configure a fresh TRACEGATE_DB_PATH.",
                file=sys.stderr,
            )
            return 3

        db.execute(
            "INSERT OR IGNORE INTO tenants(tenant_id, display_name, created_at) VALUES (?, ?, ?)",
            (tenant_id, tenant_name, now),
        )
        try:
            db.execute(
                """
                INSERT INTO users(
                    user_id, username, password_hash, role, tenant_id,
                    active, created_at, updated_at
                ) VALUES (?, ?, ?, 'admin', ?, 1, ?, ?)
                """,
                (user_id, username, password_hash, tenant_id, now, now),
            )
        except Exception:
            # The surrounding DB context rolls back if the transaction fails.
            raise
        _security_event(
            db,
            "bootstrap.initial_admin_created",
            actor_id=None,
            target=user_id,
            details={"tenant_id": tenant_id},
        )

    print(f"Created local administrator '{username}' in tenant '{tenant_id}'.")
    print("The password was not printed. Sign in through the local dashboard.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Interactively bootstrap the first TraceGate-R administrator account.

Run on a trusted host as the operating-system account that owns the configured
SQLite database: ``python scripts/manage_users.py USERNAME TENANT_ID``.
The password is entered without echo and is never accepted on the command line.
"""

from __future__ import annotations

import argparse
import getpass
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.app.auth import hash_password, normalize_username, validate_password
from backend.app.main import db_connect, init_db


TENANT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("username", help="Initial administrator's sign-in name")
    parser.add_argument("tenant_id", help="Tenant identifier for this installation")
    parser.add_argument("--tenant-name", help="Tenant display name; defaults to tenant_id")
    args = parser.parse_args()
    username = normalize_username(args.username)
    tenant_id = args.tenant_id.strip().lower()
    if not TENANT_RE.fullmatch(tenant_id):
        parser.error("tenant_id must be 2-64 lowercase letters, digits, underscores, or hyphens")

    password = getpass.getpass("Administrator password (15+ characters): ")
    confirmation = getpass.getpass("Confirm administrator password: ")
    if password != confirmation:
        parser.error("passwords do not match")
    try:
        validate_password(password)
    except ValueError as exc:
        parser.error(str(exc))

    init_db()
    now = datetime.now(timezone.utc).isoformat()
    with db_connect() as db:
        if db.execute("SELECT 1 FROM users WHERE active = 1 AND role = 'admin' LIMIT 1").fetchone():
            parser.error("an active administrator already exists; use the authenticated admin API instead")
        if db.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
            parser.error("username already exists")
        db.execute("INSERT OR IGNORE INTO tenants(tenant_id, display_name, created_at) VALUES (?, ?, ?)",
                   (tenant_id, (args.tenant_name or tenant_id).strip(), now))
        db.execute("INSERT INTO users(user_id, username, password_hash, role, tenant_id, active, created_at, updated_at) VALUES (?, ?, ?, 'admin', ?, 1, ?, ?)",
                   (str(uuid.uuid4()), username, hash_password(password), tenant_id, now, now))
        db.execute("INSERT INTO security_events(event_id, created_at, action, target, details_json) VALUES (?, ?, 'admin.bootstrap', ?, '{}')",
                   (str(uuid.uuid4()), now, username))
    print(f"Created administrator {username!r} for tenant {tenant_id!r} in {ROOT} configured SQLite database.")
    print("No password or reusable token was written to standard output.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

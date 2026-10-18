import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import backend.app.main as api
from scripts import manage_users


class ManageUsersBootstrapTests(unittest.TestCase):
    def test_bootstrap_creates_an_admin_after_initializing_role_schema(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database = Path(temp_dir) / "bootstrap.sqlite3"
            password = "Bootstrap secure phrase 2026! valid"
            with patch.object(api, "DB_PATH", database), patch.object(api, "_SCHEMA_READY_PATHS", set()), \
                    patch.object(manage_users.sys, "argv", ["manage_users.py", "first-admin", "bootstrap-tenant"]), \
                    patch.object(manage_users.getpass, "getpass", side_effect=[password, password]):
                self.assertEqual(manage_users.main(), 0)
                with api.db_connect() as db:
                    account = db.execute(
                        "SELECT username, role, active FROM users"
                    ).fetchone()
                    self.assertEqual(tuple(account), ("first-admin", "admin", 1))
                    self.assertEqual(db.execute(
                        "SELECT role FROM users WHERE username = 'first-admin'"
                    ).fetchone()[0], "admin")
                    self.assertEqual(db.execute(
                        "SELECT version FROM schema_migrations WHERE version = 3"
                    ).fetchone()[0], 3)
                    with self.assertRaises(sqlite3.IntegrityError):
                        db.execute("""INSERT INTO users(
                            user_id, username, role, tenant_id, active, created_at, updated_at
                        ) VALUES ('not-human', 'not-human', 'viewer', 'bootstrap-tenant', 1, 'now', 'now')""")


if __name__ == "__main__":
    unittest.main()

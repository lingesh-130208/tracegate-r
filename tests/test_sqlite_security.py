import os
import sqlite3
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.app import genai_explain, main
from backend.app.sqlite_security import prepare_sqlite_path, secure_new_sqlite_sidecars


class SQLiteStorageSecurityTests(unittest.TestCase):
    def test_new_api_database_uses_private_posix_permissions_and_remains_usable(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database = Path(temp_dir) / "private-store" / "audit.sqlite3"
            with patch.object(main, "DB_PATH", database):
                main.init_db()
                with main.db_connect() as connection:
                    self.assertEqual(connection.execute("SELECT 1").fetchone()[0], 1)

            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(database.parent.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(database.stat().st_mode), 0o600)

    def test_new_explanation_database_uses_private_posix_permissions(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database = Path(temp_dir) / "private-explanations" / "explanations.sqlite3"
            with patch.object(genai_explain, "EXPLANATION_DB", database):
                genai_explain._persist_explanation("test-event", "Recorded fields only.", "user-id", "tenant-id")

            connection = sqlite3.connect(database)
            try:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM explanations").fetchone()[0], 1)
            finally:
                connection.close()

            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(database.parent.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(database.stat().st_mode), 0o600)

    @unittest.skipUnless(os.name == "posix", "POSIX permission assertion")
    def test_existing_broad_storage_directory_fails_closed_without_creating_database(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir) / "broad-directory"
            directory.mkdir(mode=0o755)
            directory.chmod(0o755)
            database = directory / "audit.sqlite3"

            with patch.object(main, "DB_PATH", database):
                with self.assertRaisesRegex(RuntimeError, "storage directory"):
                    main.init_db()

            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o755)
            self.assertFalse(database.exists())

    @unittest.skipUnless(os.name == "posix", "POSIX permission assertion")
    def test_existing_broad_database_fails_closed_without_changing_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir) / "private"
            directory.mkdir(mode=0o700)
            directory.chmod(0o700)
            database = directory / "audit.sqlite3"
            original = b"pre-existing test-only database bytes"
            database.write_bytes(original)
            database.chmod(0o644)

            with patch.object(main, "DB_PATH", database):
                with self.assertRaisesRegex(RuntimeError, "Existing SQLite database"):
                    main.init_db()

            self.assertEqual(database.read_bytes(), original)
            self.assertEqual(stat.S_IMODE(database.stat().st_mode), 0o644)

    @unittest.skipUnless(os.name == "posix", "POSIX permission assertion")
    def test_existing_wal_sidecar_is_confined_by_private_directory_without_chmod(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir) / "private"
            directory.mkdir(mode=0o700)
            directory.chmod(0o700)
            database = directory / "audit.sqlite3"
            database.write_bytes(b"private database fixture")
            database.chmod(0o600)
            wal = Path(str(database) + "-wal")
            contents = b"pre-existing test-only WAL bytes"
            wal.write_bytes(contents)
            wal.chmod(0o644)

            existing = prepare_sqlite_path(database)

            self.assertIn(wal, existing)
            self.assertEqual(wal.read_bytes(), contents)
            self.assertEqual(stat.S_IMODE(wal.stat().st_mode), 0o644)

    @unittest.skipUnless(os.name == "posix", "POSIX permission assertion")
    def test_new_wal_and_shm_sidecars_are_restricted(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database = Path(temp_dir) / "private" / "audit.sqlite3"
            existing_sidecars = prepare_sqlite_path(database)
            connection = sqlite3.connect(database)
            try:
                self.assertEqual(
                    connection.execute("PRAGMA journal_mode=WAL").fetchone()[0].lower(),
                    "wal",
                )
                connection.execute("CREATE TABLE sample (value TEXT)")
                connection.execute("INSERT INTO sample VALUES ('test-only')")
                secure_new_sqlite_sidecars(database, existing_sidecars)
                for suffix in ("-wal", "-shm"):
                    sidecar = Path(str(database) + suffix)
                    self.assertTrue(sidecar.is_file())
                    self.assertEqual(stat.S_IMODE(sidecar.stat().st_mode), 0o600)
            finally:
                connection.close()


if __name__ == "__main__":
    unittest.main()

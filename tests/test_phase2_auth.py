"""
Phase 2 test suite: SQLite persistence + Argon2id authentication.

Run with:
    python -m unittest tests.test_phase2_auth -v
or, if pytest is installed:
    python -m pytest tests/test_phase2_auth.py -v

Written as unittest.TestCase so it runs with zero extra dependencies;
pytest, when available, collects and runs unittest.TestCase classes
natively too.

These tests exercise the auth_core / database layers directly -- no
Tkinter/GUI involved, so they run headlessly in CI or any environment
without a display.
"""

import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from auth_core.password import hash_password, verify_password, meets_minimum_requirements
from auth_core.user_service import register_user, authenticate_user, GENERIC_LOGIN_ERROR
from auth_core.migration import migrate_legacy_users
from database import db
from database import user_repository as repo


class SecureVaultTestCase(unittest.TestCase):
    """Base class giving every test an isolated, fresh SQLite database."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._tmpdir.name)
        self.db_path = self.tmp_path / "test_securevault.db"
        db.reset_for_tests(self.db_path)
        db.init_db(self.db_path)

    def tearDown(self):
        db.close_connection()
        self._tmpdir.cleanup()


class TestPasswordHashing(unittest.TestCase):

    def test_hash_is_not_plaintext(self):
        h = hash_password("CorrectHorse123!")
        self.assertNotEqual(h, "CorrectHorse123!")
        self.assertNotIn("CorrectHorse123!", h)

    def test_verify_correct_password(self):
        h = hash_password("CorrectHorse123!")
        self.assertTrue(verify_password("CorrectHorse123!", h))

    def test_verify_wrong_password(self):
        h = hash_password("CorrectHorse123!")
        self.assertFalse(verify_password("WrongPassword", h))

    def test_verify_rejects_malformed_hash(self):
        self.assertFalse(verify_password("anything", "not-a-real-hash"))

    def test_same_password_different_salts_produce_different_hashes(self):
        h1 = hash_password("SamePassword1!")
        h2 = hash_password("SamePassword1!")
        self.assertNotEqual(h1, h2)
        self.assertTrue(verify_password("SamePassword1!", h1))
        self.assertTrue(verify_password("SamePassword1!", h2))

    def test_minimum_requirements_reject_short_password(self):
        ok, _ = meets_minimum_requirements("short")
        self.assertFalse(ok)

    def test_minimum_requirements_accept_valid_password(self):
        ok, _ = meets_minimum_requirements("longenough1")
        self.assertTrue(ok)


class TestDatabaseLayer(SecureVaultTestCase):

    def test_database_initializes_users_table(self):
        conn = db.get_connection(self.db_path)
        tables = {
            row["name"]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        self.assertIn("users", tables)

    def test_create_and_retrieve_user(self):
        repo.create_user("alice", hash_password("Passw0rd!"))
        user = repo.get_user_by_username("alice")
        self.assertIsNotNone(user)
        self.assertEqual(user.username, "alice")
        self.assertNotEqual(user.password_hash, "Passw0rd!")

    def test_duplicate_username_raises_integrity_error(self):
        repo.create_user("bob", hash_password("Passw0rd!"))
        with self.assertRaises(sqlite3.IntegrityError):
            repo.create_user("bob", hash_password("Different1!"))

    def test_no_plaintext_passwords_stored(self):
        repo.create_user("carol", hash_password("SuperSecret1!"))
        conn = db.get_connection(self.db_path)
        row = conn.execute(
            "SELECT password_hash FROM users WHERE username = ?", ("carol",)
        ).fetchone()
        self.assertNotIn("SuperSecret1!", row["password_hash"])

    def test_failed_login_tracking_increments(self):
        repo.create_user("dave", hash_password("Passw0rd!"))
        self.assertEqual(repo.record_failed_login("dave"), 1)
        self.assertEqual(repo.record_failed_login("dave"), 2)

    def test_successful_login_resets_failed_attempts(self):
        repo.create_user("erin", hash_password("Passw0rd!"))
        repo.record_failed_login("erin")
        repo.record_failed_login("erin")
        repo.record_successful_login("erin")
        user = repo.get_user_by_username("erin")
        self.assertEqual(user.failed_attempts, 0)
        self.assertIsNotNone(user.last_login)

    def test_rename_user(self):
        repo.create_user("oldname", hash_password("Passw0rd!"))
        ok = repo.rename_user("oldname", "newname")
        self.assertTrue(ok)
        self.assertIsNone(repo.get_user_by_username("oldname"))
        self.assertIsNotNone(repo.get_user_by_username("newname"))

    def test_rename_user_rejects_existing_target(self):
        repo.create_user("userA", hash_password("Passw0rd!"))
        repo.create_user("userB", hash_password("Passw0rd!"))
        ok = repo.rename_user("userA", "userB")
        self.assertFalse(ok)


class TestAuthService(SecureVaultTestCase):

    def test_register_user_success(self):
        result = register_user("frank", "Passw0rd!", "Passw0rd!")
        self.assertTrue(result.success)
        self.assertTrue(repo.username_exists("frank"))

    def test_register_duplicate_username_fails(self):
        register_user("gina", "Passw0rd!", "Passw0rd!")
        result = register_user("gina", "Different1!", "Different1!")
        self.assertFalse(result.success)
        self.assertIn("already exists", result.message.lower())

    def test_register_password_mismatch_fails(self):
        result = register_user("henry", "Passw0rd!", "Mismatch1!")
        self.assertFalse(result.success)

    def test_register_weak_password_fails(self):
        result = register_user("iris", "short", "short")
        self.assertFalse(result.success)

    def test_register_invalid_username_fails(self):
        result = register_user("a", "Passw0rd!", "Passw0rd!")
        self.assertFalse(result.success)

    def test_login_success(self):
        register_user("jack", "Passw0rd!", "Passw0rd!")
        result = authenticate_user("jack", "Passw0rd!")
        self.assertTrue(result.success)
        self.assertEqual(result.username, "jack")

    def test_login_wrong_password_fails(self):
        register_user("karen", "Passw0rd!", "Passw0rd!")
        result = authenticate_user("karen", "WrongPassword")
        self.assertFalse(result.success)
        self.assertEqual(result.message, GENERIC_LOGIN_ERROR)

    def test_login_nonexistent_user_uses_generic_message(self):
        result = authenticate_user("does_not_exist", "whatever")
        self.assertFalse(result.success)
        self.assertEqual(result.message, GENERIC_LOGIN_ERROR)

    def test_login_failure_does_not_reveal_username_existence(self):
        register_user("laura", "Passw0rd!", "Passw0rd!")
        wrong_user = authenticate_user("nonexistent_user", "whatever")
        wrong_pass = authenticate_user("laura", "WrongPassword")
        self.assertEqual(wrong_user.message, wrong_pass.message)

    def test_failed_login_increments_counter_via_service(self):
        register_user("mallory", "Passw0rd!", "Passw0rd!")
        authenticate_user("mallory", "WrongPassword")
        authenticate_user("mallory", "WrongPassword")
        user = repo.get_user_by_username("mallory")
        self.assertEqual(user.failed_attempts, 2)


class TestLegacyMigration(SecureVaultTestCase):

    def test_migration_moves_legacy_plaintext_users(self):
        legacy_path = self.tmp_path / "users.json"
        legacy_path.write_text(json.dumps({"legacyuser": "plaintextpassword123"}))

        report = migrate_legacy_users(legacy_path)

        self.assertIn("legacyuser", report.migrated_usernames)
        self.assertEqual(report.failed_usernames, [])

        user = repo.get_user_by_username("legacyuser")
        self.assertIsNotNone(user)
        self.assertNotEqual(user.password_hash, "plaintextpassword123")
        self.assertTrue(verify_password("plaintextpassword123", user.password_hash))

    def test_migration_is_idempotent(self):
        legacy_path = self.tmp_path / "users.json"
        legacy_path.write_text(json.dumps({"repeatuser": "plaintextpassword123"}))

        first = migrate_legacy_users(legacy_path)
        second = migrate_legacy_users(legacy_path)

        self.assertIn("repeatuser", first.migrated_usernames)
        self.assertIn("repeatuser", second.skipped_existing)
        self.assertEqual(repo.count_users(), 1)

    def test_migration_does_not_delete_legacy_file(self):
        legacy_path = self.tmp_path / "users.json"
        legacy_path.write_text(json.dumps({"someone": "pw123456"}))

        migrate_legacy_users(legacy_path)

        self.assertTrue(legacy_path.exists())

    def test_migration_handles_missing_file_gracefully(self):
        missing_path = self.tmp_path / "does_not_exist.json"
        report = migrate_legacy_users(missing_path)
        self.assertFalse(report.legacy_file_found)
        self.assertEqual(report.migrated_usernames, [])

    def test_migration_handles_malformed_json_gracefully(self):
        bad_path = self.tmp_path / "users.json"
        bad_path.write_text("{not valid json")
        report = migrate_legacy_users(bad_path)
        self.assertEqual(report.migrated_usernames, [])
        self.assertTrue(bad_path.exists())


if __name__ == "__main__":
    unittest.main()

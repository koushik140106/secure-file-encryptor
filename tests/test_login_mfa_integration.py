"""Integration coverage for the real login/MFA security boundary."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from auth_core import mfa, mfa_service
from auth_core.session import create_session, get_session
from auth_core.user_service import authenticate_user, register_user
from database import db


class LoginMfaBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "test.db"
        db.reset_for_tests(self.db_path)
        db.init_db(self.db_path)
        register_user("alice", "Passw0rd!", "Passw0rd!")

    def tearDown(self):
        db.close_connection()
        self.tmp.cleanup()

    def test_password_login_without_mfa_can_create_session(self):
        result = authenticate_user("alice", "Passw0rd!")
        self.assertTrue(result.success)
        self.assertFalse(result.mfa_required)
        session = create_session("alice")
        self.assertEqual(get_session(session.id).state, "active")

    def test_password_success_with_mfa_does_not_create_session(self):
        secret, _ = mfa_service.begin_mfa_setup("alice")
        mfa_service.confirm_mfa_setup("alice", mfa.generate_totp(secret))

        result = authenticate_user("alice", "Passw0rd!")
        self.assertTrue(result.success)
        self.assertTrue(result.mfa_required)

        conn = db.get_connection(self.db_path)
        count = conn.execute("SELECT COUNT(*) AS c FROM sessions").fetchone()["c"]
        self.assertEqual(count, 0)

    def test_wrong_mfa_code_cannot_create_session(self):
        secret, _ = mfa_service.begin_mfa_setup("alice")
        mfa_service.confirm_mfa_setup("alice", mfa.generate_totp(secret))

        result = authenticate_user("alice", "Passw0rd!")
        self.assertTrue(result.mfa_required)
        self.assertFalse(mfa_service.verify_login_code("alice", "000000"))

        conn = db.get_connection(self.db_path)
        count = conn.execute("SELECT COUNT(*) AS c FROM sessions").fetchone()["c"]
        self.assertEqual(count, 0)

    def test_valid_totp_is_the_boundary_before_session_creation(self):
        secret, _ = mfa_service.begin_mfa_setup("alice")
        mfa_service.confirm_mfa_setup("alice", mfa.generate_totp(secret))

        result = authenticate_user("alice", "Passw0rd!")
        self.assertTrue(result.mfa_required)
        self.assertTrue(mfa_service.verify_login_code("alice", mfa.generate_totp(secret)))

        session = create_session("alice")
        self.assertEqual(get_session(session.id).state, "active")


if __name__ == "__main__":
    unittest.main()

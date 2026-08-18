"""
Phase 4/5/7/8 test suite: session enforcement, brute-force lockout,
structured audit logging, and the tamper-evident hash chain.

Run with:
    python -m unittest tests.test_phase4_5_7_8 -v
"""

import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from auth_core import session as session_service
from auth_core.password import hash_password
from auth_core.user_service import (
    authenticate_user,
    register_user,
    LOCKOUT_THRESHOLD,
    ACCOUNT_LOCKED_ERROR,
)
from audit import events as audit_events
from audit.logger import log_event, list_events
from audit.verifier import verify_audit_log
from database import db
from database import user_repository as repo


class SecureVaultDbTestCase(unittest.TestCase):
    def setUp(self):
        import tempfile

        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmpdir.name) / "test.db"
        db.reset_for_tests(self.db_path)
        db.init_db(self.db_path)

    def tearDown(self):
        db.close_connection()
        self._tmpdir.cleanup()


# ---------------------------------------------------------------------
# Phase 4: sessions
# ---------------------------------------------------------------------

class TestSessions(SecureVaultDbTestCase):

    def test_create_session(self):
        s = session_service.create_session("alice")
        self.assertTrue(s.is_active)
        self.assertEqual(s.username, "alice")

    def test_require_active_on_fresh_session_succeeds(self):
        s = session_service.create_session("alice")
        result = session_service.require_active(s.id)
        self.assertTrue(result.is_active)

    def test_locked_session_requires_reauth(self):
        s = session_service.create_session("alice")
        session_service.lock_session(s.id)
        with self.assertRaises(session_service.ReauthenticationRequired):
            session_service.require_active(s.id)

    def test_unlock_reactivates_session(self):
        s = session_service.create_session("alice")
        session_service.lock_session(s.id)
        session_service.unlock_session(s.id)
        result = session_service.require_active(s.id)
        self.assertTrue(result.is_active)

    def test_logout_ends_session(self):
        s = session_service.create_session("alice")
        session_service.end_session(s.id)
        with self.assertRaises(session_service.ReauthenticationRequired):
            session_service.require_active(s.id)

    def test_expired_session_requires_reauth(self):
        s = session_service.create_session("alice")
        # Force an immediate "expiry" with a timeout of 0 minutes.
        expired = session_service.expire_if_inactive(s.id, timeout_minutes=0)
        self.assertTrue(expired)
        with self.assertRaises(session_service.ReauthenticationRequired):
            session_service.require_active(s.id, timeout_minutes=0)

    def test_invalid_session_id_raises(self):
        with self.assertRaises(session_service.SessionError):
            session_service.get_session("not-a-real-session-id")

    def test_touch_extends_activity_window(self):
        s = session_service.create_session("alice")
        before = session_service.get_session(s.id).last_activity
        time.sleep(1.1)
        session_service.touch_session(s.id)
        after = session_service.get_session(s.id).last_activity
        self.assertNotEqual(before, after)


# ---------------------------------------------------------------------
# Phase 5: brute-force lockout
# ---------------------------------------------------------------------

class TestLockout(SecureVaultDbTestCase):

    def test_account_locks_after_threshold_failures(self):
        register_user("bob", "Passw0rd!", "Passw0rd!")
        result = None
        for _ in range(LOCKOUT_THRESHOLD):
            result = authenticate_user("bob", "WrongPassword")
        self.assertTrue(result.locked_out)
        self.assertEqual(result.message, ACCOUNT_LOCKED_ERROR)

    def test_locked_account_rejects_even_correct_password(self):
        register_user("carol", "Passw0rd!", "Passw0rd!")
        for _ in range(LOCKOUT_THRESHOLD):
            authenticate_user("carol", "WrongPassword")
        result = authenticate_user("carol", "Passw0rd!")
        self.assertFalse(result.success)
        self.assertTrue(result.locked_out)

    def test_successful_login_resets_counter_before_threshold(self):
        register_user("dave", "Passw0rd!", "Passw0rd!")
        authenticate_user("dave", "WrongPassword")
        authenticate_user("dave", "WrongPassword")
        result = authenticate_user("dave", "Passw0rd!")
        self.assertTrue(result.success)
        user = repo.get_user_by_username("dave")
        self.assertEqual(user.failed_attempts, 0)

    def test_lock_expiry_allows_login_again(self):
        register_user("erin", "Passw0rd!", "Passw0rd!")
        for _ in range(LOCKOUT_THRESHOLD):
            authenticate_user("erin", "WrongPassword")
        # Manually expire the lock (simulating time passing) rather than
        # sleeping 15 real minutes in a test.
        from database.db import get_connection, transaction

        conn = get_connection()
        with transaction(conn):
            conn.execute(
                "UPDATE users SET locked_until = datetime('now', '-1 minute') WHERE username = ?",
                ("erin",),
            )
        result = authenticate_user("erin", "Passw0rd!")
        self.assertTrue(result.success)


# ---------------------------------------------------------------------
# Phase 7/8: audit logging + tamper-evident hash chain
# ---------------------------------------------------------------------

class TestAuditLog(SecureVaultDbTestCase):

    def test_log_event_creates_entry(self):
        event = log_event(audit_events.LOGIN_SUCCESS, username="alice", result="success")
        self.assertEqual(event.event_type, audit_events.LOGIN_SUCCESS)
        self.assertEqual(event.username, "alice")

    def test_events_chain_together(self):
        e1 = log_event(audit_events.LOGIN_SUCCESS, username="alice")
        e2 = log_event(audit_events.FILE_ENCRYPTED, username="alice", object_id="report.pdf")
        self.assertEqual(e2.prev_hash, e1.event_hash)

    def test_metadata_never_contains_password_field_by_contract(self):
        # This test documents the contract, not an enforcement mechanism:
        # callers must never pass a password/secret in metadata.
        event = log_event(
            audit_events.FILE_SCANNED,
            username="alice",
            metadata={"filename": "invoice.pdf.exe", "risk": "HIGH"},
        )
        self.assertNotIn("password", event.metadata)

    def test_list_events_returns_most_recent_first(self):
        log_event(audit_events.LOGIN_SUCCESS, username="alice")
        log_event(audit_events.LOGOUT, username="alice")
        events = list_events(username="alice")
        self.assertEqual(events[0].event_type, audit_events.LOGOUT)


class TestAuditVerification(SecureVaultDbTestCase):

    def test_untouched_chain_verifies(self):
        log_event(audit_events.LOGIN_SUCCESS, username="alice")
        log_event(audit_events.FILE_ENCRYPTED, username="alice")
        log_event(audit_events.LOGOUT, username="alice")
        result = verify_audit_log()
        self.assertTrue(result.verified)
        self.assertEqual(result.status_label, "VERIFIED")

    def test_empty_log_verifies(self):
        result = verify_audit_log()
        self.assertTrue(result.verified)
        self.assertEqual(result.total_events, 0)

    def test_modified_historical_event_detected(self):
        log_event(audit_events.LOGIN_SUCCESS, username="alice")
        log_event(audit_events.FILE_ENCRYPTED, username="alice")
        log_event(audit_events.LOGOUT, username="alice")

        conn = db.get_connection(self.db_path)
        with db.transaction(conn):
            conn.execute(
                "UPDATE audit_events SET event_type = 'FILE_DECRYPTED' WHERE id = 1"
            )

        result = verify_audit_log()
        self.assertFalse(result.verified)
        self.assertEqual(result.status_label, "AUDIT INTEGRITY FAILURE")
        self.assertEqual(result.first_broken_event_id, 1)

    def test_deleted_event_detected(self):
        log_event(audit_events.LOGIN_SUCCESS, username="alice")
        log_event(audit_events.FILE_ENCRYPTED, username="alice")
        log_event(audit_events.LOGOUT, username="alice")

        conn = db.get_connection(self.db_path)
        with db.transaction(conn):
            conn.execute("DELETE FROM audit_events WHERE id = 2")

        result = verify_audit_log()
        self.assertFalse(result.verified)
        # Event 3 now points to event 1's hash as prev_hash, but event 1's
        # actual hash won't match what event 3 expects since event 2 (whose
        # hash event 3 was really chained to) is gone.
        self.assertEqual(result.first_broken_event_id, 3)

    def test_reordered_events_detected(self):
        log_event(audit_events.LOGIN_SUCCESS, username="alice")
        log_event(audit_events.FILE_ENCRYPTED, username="alice")

        conn = db.get_connection(self.db_path)
        with db.transaction(conn):
            # Swap the two events' primary content while keeping their
            # hash-chain fields exactly as originally computed -- this
            # simulates rewriting history without recomputing the chain.
            row1 = conn.execute("SELECT * FROM audit_events WHERE id = 1").fetchone()
            row2 = conn.execute("SELECT * FROM audit_events WHERE id = 2").fetchone()
            conn.execute(
                "UPDATE audit_events SET event_type = ? WHERE id = 1", (row2["event_type"],)
            )
            conn.execute(
                "UPDATE audit_events SET event_type = ? WHERE id = 2", (row1["event_type"],)
            )

        result = verify_audit_log()
        self.assertFalse(result.verified)


if __name__ == "__main__":
    unittest.main()

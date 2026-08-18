"""
Phase 14/15/18 test suite: Security Center posture + deterministic
score, and report generation (JSON/CSV/PDF).

Run with:
    python -m unittest tests.test_security_center_reports -v
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.security_center import build_report
from services import report_service as rs
from auth_core import mfa as totp
from auth_core import mfa_service
from auth_core.password import hash_password
from audit import events as audit_events
from audit.logger import log_event
from database import db
from database import user_repository as repo


class DbTestCase(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._tmpdir.name)
        self.db_path = self.tmp_path / "test.db"
        db.reset_for_tests(self.db_path)
        db.init_db(self.db_path)

    def tearDown(self):
        db.close_connection()
        self._tmpdir.cleanup()


class TestSecurityScore(DbTestCase):

    def test_score_increases_when_mfa_enabled(self):
        repo.create_user("alice", hash_password("Passw0rd!"))
        before = build_report("alice").score

        secret, _ = mfa_service.begin_mfa_setup("alice")
        mfa_service.confirm_mfa_setup("alice", totp.generate_totp(secret))

        after = build_report("alice").score
        self.assertGreater(after, before)

    def test_score_decreases_when_audit_chain_broken(self):
        repo.create_user("bob", hash_password("Passw0rd!"))
        log_event(audit_events.LOGIN_SUCCESS, username="bob")
        before = build_report("bob").score

        conn = db.get_connection(self.db_path)
        with db.transaction(conn):
            conn.execute("UPDATE audit_events SET event_type = 'TAMPERED' WHERE id = 1")

        after = build_report("bob").score
        self.assertLess(after, before)

    def test_score_decreases_with_unresolved_high_risk_quarantine(self):
        repo.create_user("carol", hash_password("Passw0rd!"))
        before = build_report("carol").score

        conn = db.get_connection(self.db_path)
        with db.transaction(conn):
            conn.execute(
                "INSERT INTO quarantine_items "
                "(quarantine_id, username, original_filename, quarantined_path, sha256, "
                " risk_level, reasons, state) "
                "VALUES ('q1', 'carol', 'bad.exe', '/tmp/q1', 'abc', 'HIGH', '[]', 'quarantined')"
            )

        after = build_report("carol").score
        self.assertLess(after, before)

    def test_score_never_negative(self):
        repo.create_user("dave", hash_password("Passw0rd!"))
        conn = db.get_connection(self.db_path)
        with db.transaction(conn):
            for i in range(20):
                conn.execute(
                    "INSERT INTO quarantine_items "
                    "(quarantine_id, username, original_filename, quarantined_path, sha256, "
                    " risk_level, reasons, state) "
                    f"VALUES ('q{i}', 'dave', 'bad{i}.exe', '/tmp/q{i}', 'abc', 'CRITICAL', '[]', 'quarantined')"
                )
        report = build_report("dave")
        self.assertGreaterEqual(report.score, 0)

    def test_recommendations_mention_disabled_mfa(self):
        repo.create_user("erin", hash_password("Passw0rd!"))
        report = build_report("erin")
        self.assertTrue(any("MFA" in r for r in report.recommendations))

    def test_no_recommendations_when_all_healthy(self):
        repo.create_user("frank", hash_password("Passw0rd!"))
        secret, _ = mfa_service.begin_mfa_setup("frank")
        mfa_service.confirm_mfa_setup("frank", totp.generate_totp(secret))
        report = build_report("frank")
        self.assertEqual(len(report.recommendations), 1)
        self.assertIn("healthy", report.recommendations[0].lower())

    def test_score_deterministic_for_same_state(self):
        repo.create_user("gina", hash_password("Passw0rd!"))
        r1 = build_report("gina").score
        r2 = build_report("gina").score
        self.assertEqual(r1, r2)


class TestReportGeneration(DbTestCase):

    def setUp(self):
        super().setUp()
        repo.create_user("alice", hash_password("Passw0rd!"))
        log_event(audit_events.LOGIN_SUCCESS, username="alice")
        log_event(audit_events.FILE_ENCRYPTED, username="alice", object_id="f.txt")
        log_event(audit_events.LOGIN_FAILURE, username="alice")

    def test_report_data_counts_are_accurate(self):
        data = rs.build_report_data("alice")
        self.assertEqual(data.login_success_count, 1)
        self.assertEqual(data.login_failure_count, 1)
        self.assertEqual(data.file_encrypted_count, 1)

    def test_json_export_is_valid_json(self):
        data = rs.build_report_data("alice")
        parsed = json.loads(rs.export_json(data))
        self.assertEqual(parsed["login_success_count"], 1)

    def test_csv_export_contains_key_fields(self):
        data = rs.build_report_data("alice")
        csv_text = rs.export_csv(data)
        self.assertIn("login_success_count", csv_text)
        self.assertIn("security_score", csv_text)

    def test_pdf_export_creates_valid_file(self):
        data = rs.build_report_data("alice")
        out = str(self.tmp_path / "report.pdf")
        rs.export_pdf(data, out)
        self.assertTrue(os.path.exists(out))
        with open(out, "rb") as f:
            header = f.read(5)
        self.assertEqual(header, b"%PDF-")

    def test_report_never_contains_password_field(self):
        data = rs.build_report_data("alice")
        json_text = rs.export_json(data)
        self.assertNotIn("Passw0rd!", json_text)
        self.assertNotIn("password_hash", json_text)

    def test_date_range_filters_events(self):
        data_all = rs.build_report_data("alice")
        data_future = rs.build_report_data("alice", start_date="2099-01-01")
        self.assertGreater(data_all.login_success_count, 0)
        self.assertEqual(data_future.login_success_count, 0)


if __name__ == "__main__":
    unittest.main()

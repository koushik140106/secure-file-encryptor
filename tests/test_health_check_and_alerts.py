"""
Tests for core/health_check.py and core/alerts.py, both real, added
as part of SecureVault v4.

Run with:
    python -m unittest tests.test_health_check_and_alerts -v
"""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from auth_core.password import hash_password
from audit import events as audit_events
from audit.logger import log_event
from core import health_check
from core import alerts as alerts_module
from database import db
from database import user_repository as repo


class HealthAlertsTestCase(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._tmpdir.name)
        self.db_path = self.tmp_path / "test.db"
        db.reset_for_tests(self.db_path)
        db.init_db(self.db_path)

    def tearDown(self):
        db.close_connection()
        self._tmpdir.cleanup()


class TestHealthCheck(HealthAlertsTestCase):

    def test_healthy_database_passes(self):
        report = health_check.run_health_check(quarantine_dir=self.tmp_path / "q")
        db_items = [i for i in report.items if i.name == "Database connectivity"]
        self.assertEqual(db_items[0].status, health_check.PASS)

    def test_schema_check_passes_after_init(self):
        report = health_check.run_health_check(quarantine_dir=self.tmp_path / "q")
        schema_items = [i for i in report.items if i.name == "Database schema"]
        self.assertEqual(schema_items[0].status, health_check.PASS)

    def test_audit_chain_check_passes_when_clean(self):
        log_event(audit_events.LOGIN_SUCCESS, username="alice")
        report = health_check.run_health_check(quarantine_dir=self.tmp_path / "q")
        chain_items = [i for i in report.items if i.name == "Audit chain integrity"]
        self.assertEqual(chain_items[0].status, health_check.PASS)

    def test_audit_chain_check_fails_when_tampered(self):
        log_event(audit_events.LOGIN_SUCCESS, username="alice")
        log_event(audit_events.LOGOUT, username="alice")
        conn = db.get_connection(self.db_path)
        with db.transaction(conn):
            conn.execute("UPDATE audit_events SET event_type = 'TAMPERED' WHERE id = 1")

        report = health_check.run_health_check(quarantine_dir=self.tmp_path / "q")
        chain_items = [i for i in report.items if i.name == "Audit chain integrity"]
        self.assertEqual(chain_items[0].status, health_check.FAIL)
        self.assertEqual(report.overall_status, health_check.FAIL)

    def test_missing_quarantine_dir_is_warning_not_failure(self):
        report = health_check.run_health_check(quarantine_dir=self.tmp_path / "does_not_exist")
        q_items = [i for i in report.items if i.name == "Quarantine directory"]
        self.assertEqual(q_items[0].status, health_check.WARNING)

    def test_existing_quarantine_dir_passes(self):
        qdir = self.tmp_path / "q"
        qdir.mkdir()
        report = health_check.run_health_check(quarantine_dir=qdir)
        q_items = [i for i in report.items if i.name == "Quarantine directory"]
        self.assertEqual(q_items[0].status, health_check.PASS)

    def test_overall_status_is_pass_when_all_pass(self):
        qdir = self.tmp_path / "q"
        qdir.mkdir()
        report = health_check.run_health_check(quarantine_dir=qdir)
        self.assertEqual(report.overall_status, health_check.PASS)

    def test_overall_status_downgrades_to_warning(self):
        report = health_check.run_health_check(quarantine_dir=self.tmp_path / "missing")
        self.assertIn(report.overall_status, (health_check.WARNING, health_check.PASS))
        statuses = {i.status for i in report.items}
        self.assertIn(health_check.WARNING, statuses)


class TestAlerts(HealthAlertsTestCase):

    def setUp(self):
        super().setUp()
        repo.create_user("alice", hash_password("Passw0rd!"))

    def test_mfa_disabled_generates_alert(self):
        result = alerts_module.run_alerts("alice")
        titles = [a.title for a in result]
        self.assertIn("MFA disabled", titles)

    def test_no_mfa_alert_once_enabled(self):
        conn = db.get_connection(self.db_path)
        with db.transaction(conn):
            conn.execute("UPDATE users SET mfa_enabled = 1 WHERE username = 'alice'")
        result = alerts_module.run_alerts("alice")
        titles = [a.title for a in result]
        self.assertNotIn("MFA disabled", titles)

    def test_repeated_failed_logins_generate_high_alert(self):
        for _ in range(4):
            log_event(audit_events.LOGIN_FAILURE, username="alice", result="failure")
        result = alerts_module.run_alerts("alice")
        matching = [a for a in result if a.title == "Multiple failed login attempts"]
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0].severity, alerts_module.HIGH)

    def test_few_failed_logins_do_not_trigger_alert(self):
        log_event(audit_events.LOGIN_FAILURE, username="alice", result="failure")
        result = alerts_module.run_alerts("alice")
        titles = [a.title for a in result]
        self.assertNotIn("Multiple failed login attempts", titles)

    def test_lockout_generates_alert(self):
        log_event(audit_events.ACCOUNT_LOCKED, username="alice", result="failure")
        result = alerts_module.run_alerts("alice")
        titles = [a.title for a in result]
        self.assertIn("Account was locked", titles)

    def test_integrity_failure_generates_alert(self):
        log_event(audit_events.INTEGRITY_FAILURE, username="alice", result="failure")
        result = alerts_module.run_alerts("alice")
        titles = [a.title for a in result]
        self.assertIn("File integrity failure detected", titles)

    def test_high_risk_quarantine_generates_alert(self):
        conn = db.get_connection(self.db_path)
        with db.transaction(conn):
            conn.execute(
                "INSERT INTO quarantine_items "
                "(quarantine_id, username, original_filename, quarantined_path, sha256, "
                " risk_level, reasons, state) "
                "VALUES ('q1', 'alice', 'bad.exe', '/tmp/q1', 'abc', 'CRITICAL', '[]', 'quarantined')"
            )
        result = alerts_module.run_alerts("alice")
        titles = [a.title for a in result]
        self.assertIn("High-risk file(s) in quarantine", titles)

    def test_broken_audit_chain_generates_critical_alert(self):
        log_event(audit_events.LOGIN_SUCCESS, username="alice")
        conn = db.get_connection(self.db_path)
        with db.transaction(conn):
            conn.execute("UPDATE audit_events SET event_type = 'TAMPERED' WHERE id = 1")
        result = alerts_module.run_alerts("alice")
        matching = [a for a in result if a.title == "Audit chain integrity failure"]
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0].severity, alerts_module.CRITICAL)

    def test_healthy_account_has_minimal_alerts(self):
        conn = db.get_connection(self.db_path)
        with db.transaction(conn):
            conn.execute("UPDATE users SET mfa_enabled = 1 WHERE username = 'alice'")
        result = alerts_module.run_alerts("alice")
        self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main()

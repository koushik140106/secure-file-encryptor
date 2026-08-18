"""
Targeted regression tests added while reviewing SecureVault v3.0 as the
v4.0 baseline:

1. Recovery-code single-use is exercised end-to-end (not just unit-level
   in mfa_service tests already elsewhere).
2. A source-level guard against the exact bypass that was found and
   removed twice now in this project's history: a dev `__main__` block
   in dashboard.py that constructed an authenticated Dashboard with a
   hardcoded username and no session/MFA check at all.
"""

import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from auth_core import mfa, mfa_service
from auth_core.user_service import authenticate_user, register_user
from database import db


class TestRecoveryCodeReuseDenied(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "test.db"
        db.reset_for_tests(self.db_path)
        db.init_db(self.db_path)
        register_user("alice", "Passw0rd!", "Passw0rd!")
        secret, _ = mfa_service.begin_mfa_setup("alice")
        self.recovery_codes = mfa_service.confirm_mfa_setup("alice", mfa.generate_totp(secret))

    def tearDown(self):
        db.close_connection()
        self.tmp.cleanup()

    def test_recovery_code_works_once_then_denied(self):
        result = authenticate_user("alice", "Passw0rd!")
        self.assertTrue(result.mfa_required)

        code = self.recovery_codes[0]
        self.assertTrue(mfa_service.verify_login_code("alice", code))
        self.assertFalse(mfa_service.verify_login_code("alice", code))

    def test_unused_recovery_codes_remain_valid_after_one_is_consumed(self):
        first, second = self.recovery_codes[0], self.recovery_codes[1]
        self.assertTrue(mfa_service.verify_login_code("alice", first))
        self.assertTrue(mfa_service.verify_login_code("alice", second))
        self.assertFalse(mfa_service.verify_login_code("alice", first))


class TestNoUnauthenticatedDashboardBypass(unittest.TestCase):
    """
    Source-level guard: dashboard.py must never contain a top-level
    execution path that constructs Dashboard() outside of an
    authenticated auth.py flow. This exact bug (a `__main__` block
    calling Dashboard(root, "Admin")) was found and removed from this
    codebase; this test exists so it can't silently come back.
    """

    def test_dashboard_module_has_no_main_block(self):
        source = (Path(__file__).resolve().parent.parent / "dashboard.py").read_text(encoding="utf-8", errors="ignore")
        self.assertNotIn('if __name__ == "__main__"', source)
        self.assertNotIn("if __name__ == '__main__'", source)

    def test_dashboard_module_never_hardcodes_admin_username(self):
        source = (Path(__file__).resolve().parent.parent / "dashboard.py").read_text(encoding="utf-8", errors="ignore")
        # A hardcoded "Admin" username passed straight into Dashboard(...)
        # is exactly the shape of the bug that was removed.
        self.assertNotRegex(source, r'Dashboard\(\s*root\s*,\s*"Admin"\s*\)')

    def test_create_session_has_a_small_bounded_set_of_callers(self):
        auth_source = (Path(__file__).resolve().parent.parent / "auth.py").read_text(encoding="utf-8", errors="ignore")
        call_sites = len(re.findall(r"create_session\(", auth_source))
        # Exactly the two legitimate call sites: the MFA-verified path and
        # the no-MFA path in auth.py's login(). Any additional call site
        # anywhere in auth.py is a signal a new bypass may have appeared.
        self.assertEqual(call_sites, 2)


if __name__ == "__main__":
    unittest.main()

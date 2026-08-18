"""GUI smoke tests for the real login -> protected workspace transition.

These tests are skipped automatically when no Tk display is available.
They are intended to catch the exact blank-window regression seen in the
original v2 package.
"""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from auth_core import mfa, mfa_service
from auth_core.user_service import register_user
from database import db

try:
    import tkinter as tk
    _TK_IMPORT_ERROR = None
except ImportError as exc:
    tk = None
    _TK_IMPORT_ERROR = exc


def _tk_available():
    if tk is None:
        return False
    try:
        root = tk.Tk()
        root.withdraw()
        root.destroy()
        return True
    except tk.TclError:
        return False


@unittest.skipUnless(_tk_available(), "Tkinter display is unavailable")
class LoginDashboardSmokeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "test.db"
        db.reset_for_tests(self.db_path)
        db.init_db(self.db_path)
        register_user("guiuser", "Passw0rd!", "Passw0rd!")
        self.root = tk.Tk()
        self.root.geometry("1200x800")

    def tearDown(self):
        try:
            self.root.destroy()
        except Exception:
            pass
        db.close_connection()
        self.tmp.cleanup()

    @staticmethod
    def _fill_login(app, username, password):
        app.user.delete(0, tk.END)
        app.user.insert(0, username)
        app.password.delete(0, tk.END)
        app.password.insert(0, password)

    def test_real_login_reaches_dashboard(self):
        from auth import LoginApp

        app = LoginApp(self.root)
        self._fill_login(app, "guiuser", "Passw0rd!")
        app.login()
        self.root.update_idletasks()

        self.assertTrue(hasattr(self.root, "securevault_session_id"))
        self.assertEqual(len(self.root.winfo_children()), 2)
        self.assertGreaterEqual(len(self.root.winfo_children()[0].winfo_children()), 10)

    def test_all_dashboard_pages_and_lock_do_not_leave_stale_callbacks(self):
        from auth import LoginApp
        from dashboard import Dashboard
        from auth_core.session import create_session

        session_id = create_session("guiuser")
        self.root.securevault_session_id = session_id
        self.root.session_start = __import__("time").time()
        dashboard = Dashboard(self.root, "guiuser")

        for page_name in (
            "dashboard", "encrypt", "decrypt", "file_scanner",
            "security_center", "mfa_setup", "activity",
            "quarantine_page", "reports_page", "history",
            "profile", "settings", "about",
        ):
            getattr(dashboard, page_name)()
            self.root.update_idletasks()
            self.root.update()

        dashboard.lock_screen()
        self.root.update_idletasks()
        self.root.update()
        self.assertTrue(self.root.winfo_exists())

    def test_real_mfa_login_requires_and_then_accepts_second_factor(self):
        secret, _ = mfa_service.begin_mfa_setup("guiuser")
        mfa_service.confirm_mfa_setup("guiuser", mfa.generate_totp(secret))

        from auth import LoginApp

        app = LoginApp(self.root)
        self._fill_login(app, "guiuser", "Passw0rd!")
        app.login()
        self.root.update_idletasks()

        self.assertFalse(hasattr(self.root, "securevault_session_id"))

        entries = []
        verify_buttons = []

        def walk(widget):
            for child in widget.winfo_children():
                if isinstance(child, tk.Entry):
                    entries.append(child)
                if isinstance(child, tk.Button) and "VERIFY" in child.cget("text"):
                    verify_buttons.append(child)
                walk(child)

        walk(self.root)
        self.assertEqual(len(entries), 1)
        self.assertEqual(len(verify_buttons), 1)

        entries[0].insert(0, mfa.generate_totp(secret))
        verify_buttons[0].invoke()
        self.root.update_idletasks()

        self.assertTrue(hasattr(self.root, "securevault_session_id"))


if __name__ == "__main__":
    unittest.main()

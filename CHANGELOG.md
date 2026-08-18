# Changelog

## SecureVault v4.0 (this pass)

**Scope note, stated plainly:** the request for this pass asked for a very
large set of changes (full visual redesign, batch encryption with threaded
progress UI, drag-and-drop, global search, dark/light theme system, GUI
automation testing, three new documentation guides, screenshots). Consistent
with an explicit instruction not to replace the working Tkinter application
with a different framework just to look modern, and to preserve the security
work already invested, this pass implements a smaller, real, fully-tested
slice rather than a superficial pass at the entire list. Everything listed
below is implemented, wired into the actual UI, and tested -- nothing here
is a stub or a claim without working code behind it.

- **Fixed a critical authentication bypass** (found during the required
  audit-first pass, present in the uploaded v3.0 baseline): `dashboard.py`
  had a dev `if __name__ == "__main__":` block constructing
  `Dashboard(root, "Admin")` with no authentication, MFA, or session check
  at all. Removed. Added source-level regression tests
  (`tests/test_security_regressions.py`) asserting this exact shape of bug
  can't silently reappear.
- **Fixed a baseline test-suite bug**: `tests/test_gui_login_smoke.py`
  imported `tkinter` unconditionally at module level, so the *entire* suite
  errored out (not just those two tests) in any headless environment
  instead of skipping the GUI-only tests. Fixed with a guarded import.
  Baseline went from 144 tests/1 error to 145 tests/0 errors/2 skipped.
- **Security Health Check** (`core/health_check.py`): real, deterministic
  PASS/WARNING/FAIL checks against database connectivity, required schema,
  audit chain integrity, and the quarantine directory. Wired into the
  Security Center page.
- **Security Alerts** (`core/alerts.py`): severity-tagged alerts (INFO
  through CRITICAL) generated purely from real audit events and current
  account state -- MFA disabled, repeated failed logins, account lockout,
  integrity failures, unresolved high-risk quarantine items, audit chain
  tampering. Wired into the Security Center page.
- Added explicit recovery-code single-use regression tests.
- 22 new tests (5 security regression + 17 health-check/alerts). 167/167
  tests passing project-wide (up from the corrected 145-test baseline).

**Deliberately not done in this pass** (see README.md Limitations for the
full list carried forward): full visual/design-system redesign, batch
encryption/decryption with threaded progress UI, drag-and-drop, global
search, dark/light theme *system* (a Dark/Light/Cyber/Ocean theme picker
already existed in v3.0 and still works), notification "center" as a
distinct persistent UI surface (alerts are shown live in Security Center
rather than stored/dismissable), GUI automation smoke testing beyond what
v3.0 already had (this sandbox still has no Tkinter display), and the three
additional documentation guides (USER_GUIDE.md, DEVELOPER_GUIDE.md,
DOCUMENTATION.md).

## SecureVault v3.0

- Fixed the post-login blank-window failure mode by making dashboard construction recoverable.
- Added enforced TOTP MFA at the real authentication boundary: no authenticated session is created until MFA succeeds for MFA-enabled accounts.
- Added five-attempt MFA challenge protection per login challenge.
- Added dedicated MFA challenge success/failure audit events.
- Added protected navigation/session checks and a recoverable page error screen.
- Cancelled stale page-specific Tkinter callbacks when navigating between views.
- Refined SecureVault branding, window titles, sidebar spacing, navigation styling, and session status indicator.
- Added login-flow integration tests covering the MFA/session boundary.
- Final regression suite: 143 tests passing.

## SecureVault v2.0

- SQLite + Argon2id authentication
- AES-256-GCM/SVLT encryption
- Session enforcement and lockout
- TOTP MFA services
- Tamper-evident audit chain
- File analyzer, risk scoring, quarantine, secure delete
- Security Center and reports

## SecureVault v4.0 Verified Release

- Fixed stale Tkinter `after()` callbacks when switching pages or locking/logging out.
- Added cancellation for session timer, inactivity monitor, and page-bound callbacks during protected workspace teardown.
- Added GUI regression coverage for navigating all dashboard pages followed by session lock.
- Updated remaining v3.0 UI branding/version labels to SecureVault v4.0.
- Verified 168 automated tests pass headlessly; GUI smoke coverage also passes under a virtual display.

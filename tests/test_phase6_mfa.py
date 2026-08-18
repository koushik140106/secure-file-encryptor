"""
Phase 6 test suite: TOTP/HOTP correctness (against official RFC 4226
vectors) and the MFA enrollment/login/disable service.

Run with:
    python -m unittest tests.test_phase6_mfa -v
"""

import base64
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from auth_core import mfa as totp
from auth_core import mfa_service
from auth_core.password import hash_password
from database import db
from database import user_repository as repo


class TestHotpRfc4226Vectors(unittest.TestCase):
    """
    Official test vectors from RFC 4226, Appendix D, for the ASCII
    secret "12345678901234567890", counters 0-9.
    """

    def setUp(self):
        self.secret_b32 = base64.b32encode(b"12345678901234567890").decode()
        self.expected = [
            "755224", "287082", "359152", "969429", "338314",
            "254676", "287922", "162583", "399871", "520489",
        ]

    def test_all_official_vectors(self):
        for counter, expected_code in enumerate(self.expected):
            actual = totp._hotp(self.secret_b32, counter)
            self.assertEqual(actual, expected_code, f"counter={counter}")


class TestTotp(unittest.TestCase):

    def test_generate_and_verify_current_code(self):
        secret = totp.generate_secret()
        code = totp.generate_totp(secret)
        self.assertTrue(totp.verify_totp(secret, code))

    def test_wrong_code_rejected(self):
        secret = totp.generate_secret()
        self.assertFalse(totp.verify_totp(secret, "000000"))

    def test_different_secrets_produce_different_codes(self):
        s1 = totp.generate_secret()
        s2 = totp.generate_secret()
        # Extremely unlikely to collide; if it ever does, secrets aren't random.
        self.assertNotEqual(
            totp.generate_totp(s1, for_time=1000000), totp.generate_totp(s2, for_time=1000000)
        )

    def test_code_valid_within_clock_drift_window(self):
        secret = totp.generate_secret()
        code = totp.generate_totp(secret, for_time=1000000)
        # One period (30s) earlier should still verify against "now" = 1000000 + 30
        self.assertTrue(totp.verify_totp(secret, code, for_time=1000030))

    def test_code_invalid_far_outside_drift_window(self):
        secret = totp.generate_secret()
        code = totp.generate_totp(secret, for_time=1000000)
        self.assertFalse(totp.verify_totp(secret, code, for_time=1000000 + 600))

    def test_malformed_code_rejected(self):
        secret = totp.generate_secret()
        self.assertFalse(totp.verify_totp(secret, "abcdef"))
        self.assertFalse(totp.verify_totp(secret, "123"))
        self.assertFalse(totp.verify_totp(secret, ""))

    def test_provisioning_uri_format(self):
        uri = totp.provisioning_uri("JBSWY3DPEHPK3PXP", "alice", issuer="SecureVault")
        self.assertTrue(uri.startswith("otpauth://totp/"))
        self.assertIn("secret=JBSWY3DPEHPK3PXP", uri)
        self.assertIn("issuer=SecureVault", uri)


class MfaServiceTestCase(unittest.TestCase):
    def setUp(self):
        import tempfile

        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmpdir.name) / "test.db"
        db.reset_for_tests(self.db_path)
        db.init_db(self.db_path)
        repo.create_user("alice", hash_password("Passw0rd!"))

    def tearDown(self):
        db.close_connection()
        self._tmpdir.cleanup()


class TestMfaService(MfaServiceTestCase):

    def test_setup_not_enabled_until_confirmed(self):
        mfa_service.begin_mfa_setup("alice")
        self.assertFalse(mfa_service.is_mfa_enabled("alice"))

    def test_confirm_with_valid_code_enables_mfa(self):
        secret, _ = mfa_service.begin_mfa_setup("alice")
        code = totp.generate_totp(secret)
        recovery_codes = mfa_service.confirm_mfa_setup("alice", code)
        self.assertTrue(mfa_service.is_mfa_enabled("alice"))
        self.assertEqual(len(recovery_codes), mfa_service.RECOVERY_CODE_COUNT)

    def test_confirm_with_invalid_code_fails_and_does_not_enable(self):
        mfa_service.begin_mfa_setup("alice")
        with self.assertRaises(mfa_service.MfaError):
            mfa_service.confirm_mfa_setup("alice", "000000")
        self.assertFalse(mfa_service.is_mfa_enabled("alice"))

    def test_login_verification_with_valid_totp(self):
        secret, _ = mfa_service.begin_mfa_setup("alice")
        mfa_service.confirm_mfa_setup("alice", totp.generate_totp(secret))
        self.assertTrue(mfa_service.verify_login_code("alice", totp.generate_totp(secret)))

    def test_login_verification_with_invalid_totp_fails(self):
        secret, _ = mfa_service.begin_mfa_setup("alice")
        mfa_service.confirm_mfa_setup("alice", totp.generate_totp(secret))
        self.assertFalse(mfa_service.verify_login_code("alice", "000000"))

    def test_login_rejected_before_mfa_confirmed(self):
        secret, _ = mfa_service.begin_mfa_setup("alice")
        # Never confirmed -- login-time verification must not succeed.
        self.assertFalse(mfa_service.verify_login_code("alice", totp.generate_totp(secret)))

    def test_recovery_code_works_once(self):
        secret, _ = mfa_service.begin_mfa_setup("alice")
        recovery_codes = mfa_service.confirm_mfa_setup("alice", totp.generate_totp(secret))
        code = recovery_codes[0]
        self.assertTrue(mfa_service.verify_login_code("alice", code))
        self.assertFalse(mfa_service.verify_login_code("alice", code))  # single-use

    def test_disable_mfa_requires_correct_password(self):
        secret, _ = mfa_service.begin_mfa_setup("alice")
        mfa_service.confirm_mfa_setup("alice", totp.generate_totp(secret))
        self.assertFalse(mfa_service.disable_mfa("alice", "WrongPassword"))
        self.assertTrue(mfa_service.is_mfa_enabled("alice"))

    def test_disable_mfa_with_correct_password_succeeds(self):
        secret, _ = mfa_service.begin_mfa_setup("alice")
        mfa_service.confirm_mfa_setup("alice", totp.generate_totp(secret))
        self.assertTrue(mfa_service.disable_mfa("alice", "Passw0rd!"))
        self.assertFalse(mfa_service.is_mfa_enabled("alice"))

    def test_disabled_mfa_clears_recovery_codes(self):
        secret, _ = mfa_service.begin_mfa_setup("alice")
        recovery_codes = mfa_service.confirm_mfa_setup("alice", totp.generate_totp(secret))
        mfa_service.disable_mfa("alice", "Passw0rd!")
        self.assertFalse(mfa_service.verify_login_code("alice", recovery_codes[1]))


if __name__ == "__main__":
    unittest.main()

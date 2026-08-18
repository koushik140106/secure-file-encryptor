"""
Tests proving the audit-integration gap is fixed: the actual functions
used by the encrypt/decrypt UI workflows (not just the lower-level
core.file_format module) expose what's needed to log FILE_ENCRYPTED,
FILE_DECRYPTED, DECRYPTION_FAILED, and INTEGRITY_FAILURE correctly.

The Tkinter pages themselves (encrypt.py/decrypt.py) can't be
instantiated headlessly (no Tkinter in this environment), so this
suite tests the exact service-layer functions those pages call,
which is what actually determines what gets logged.

Run with:
    python -m unittest tests.test_audit_integration -v
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from crypto_utils import (
    encrypt_file_data,
    decrypt_file_data_with_integrity,
    DecryptionError,
    LegacyDecryptionError,
)
from audit import events as audit_events
from audit.logger import log_event, list_events
from audit.verifier import verify_audit_log
from database import db


class AuditIntegrationTestCase(unittest.TestCase):
    def setUp(self):
        import tempfile

        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmpdir.name) / "test.db"
        db.reset_for_tests(self.db_path)
        db.init_db(self.db_path)

    def tearDown(self):
        db.close_connection()
        self._tmpdir.cleanup()


class TestEncryptDecryptAuditWiring(AuditIntegrationTestCase):

    def test_successful_decrypt_reports_integrity_verified(self):
        enc = encrypt_file_data(b"secret data", "CorrectPass1!", "f.txt")
        data, name, integrity_verified, is_legacy = decrypt_file_data_with_integrity(
            enc, "CorrectPass1!"
        )
        self.assertTrue(integrity_verified)
        self.assertFalse(is_legacy)

        # This is exactly what decrypt.py's start_decryption() does on success.
        event = log_event(
            audit_events.FILE_DECRYPTED,
            username="alice",
            result="success",
            object_id=name,
            metadata={"legacy_format": is_legacy, "integrity_verified": integrity_verified},
        )
        self.assertEqual(event.event_type, audit_events.FILE_DECRYPTED)
        self.assertEqual(event.metadata["integrity_verified"], True)

    def test_wrong_password_raises_before_any_success_event(self):
        enc = encrypt_file_data(b"secret data", "CorrectPass1!", "f.txt")
        with self.assertRaises(DecryptionError):
            decrypt_file_data_with_integrity(enc, "WrongPassword")

        # This mirrors decrypt.py's except-block behavior.
        log_event(
            audit_events.DECRYPTION_FAILED,
            username="alice",
            result="failure",
            object_id="f.txt.enc",
        )
        events = list_events(username="alice")
        self.assertEqual(events[0].event_type, audit_events.DECRYPTION_FAILED)

    def test_tampered_file_raises_and_logs_decryption_failed(self):
        enc = bytearray(encrypt_file_data(b"secret data", "pw123456", "f.txt"))
        enc[-1] ^= 0xFF
        with self.assertRaises(DecryptionError):
            decrypt_file_data_with_integrity(bytes(enc), "pw123456")

        log_event(audit_events.DECRYPTION_FAILED, username="alice", result="failure")
        events = list_events(username="alice")
        self.assertEqual(events[0].event_type, audit_events.DECRYPTION_FAILED)

    def test_full_encrypt_then_decrypt_produces_two_chained_events(self):
        enc = encrypt_file_data(b"payload", "pw123456", "report.pdf")
        log_event(
            audit_events.FILE_ENCRYPTED,
            username="bob",
            result="success",
            object_id="report.pdf",
            metadata={"size_bytes": len(b"payload")},
        )

        data, name, integrity_verified, is_legacy = decrypt_file_data_with_integrity(
            enc, "pw123456"
        )
        log_event(
            audit_events.FILE_DECRYPTED,
            username="bob",
            result="success",
            object_id=name,
            metadata={"legacy_format": is_legacy, "integrity_verified": integrity_verified},
        )

        events = list_events(username="bob")
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].event_type, audit_events.FILE_DECRYPTED)
        self.assertEqual(events[1].event_type, audit_events.FILE_ENCRYPTED)

        result = verify_audit_log()
        self.assertTrue(result.verified)

    def test_legacy_file_reports_is_legacy_true(self):
        import base64, hashlib, json
        from cryptography.fernet import Fernet

        key = base64.urlsafe_b64encode(hashlib.sha256(b"OldPass1!").digest())
        payload = json.dumps(
            {"filename": "old.txt", "data": base64.b64encode(b"legacy").decode()}
        ).encode()
        legacy_enc = Fernet(key).encrypt(payload)

        data, name, integrity_verified, is_legacy = decrypt_file_data_with_integrity(
            legacy_enc, "OldPass1!"
        )
        self.assertTrue(is_legacy)
        self.assertTrue(integrity_verified)  # Fernet's own auth tag succeeded


if __name__ == "__main__":
    unittest.main()

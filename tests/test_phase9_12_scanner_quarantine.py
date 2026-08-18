"""
Phase 9/10/11/12 test suite: file security analyzer, risk scoring,
quarantine, secure delete.

Run with:
    python -m unittest tests.test_phase9_12_scanner_quarantine -v
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.scanner import analyze_file, RISK_LOW, RISK_HIGH, RISK_CRITICAL
from core.secure_delete import secure_delete, SecureDeleteError
from services import quarantine_service as qsvc
from audit.logger import list_events
from audit.verifier import verify_audit_log
from database import db


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


# ---------------------------------------------------------------------
# Phase 9/10: scanner + risk scoring
# ---------------------------------------------------------------------

class TestFileScanner(unittest.TestCase):

    def test_safe_pdf_is_low_risk(self):
        result = analyze_file("invoice.pdf", b"%PDF-1.4 real pdf content here")
        self.assertEqual(result.risk_level, RISK_LOW)
        self.assertEqual(result.score, 0)

    def test_safe_jpeg_is_low_risk(self):
        result = analyze_file("photo.jpg", b"\xff\xd8\xffreal jpeg bytes")
        self.assertEqual(result.risk_level, RISK_LOW)

    def test_double_extension_pdf_exe_is_flagged(self):
        result = analyze_file("invoice.pdf.exe", b"MZ\x90\x00fake pe header")
        self.assertEqual(result.risk_level, RISK_CRITICAL)
        self.assertTrue(any("double extension" in r.lower() for r in result.reasons))

    def test_double_extension_docx_scr_is_flagged(self):
        result = analyze_file("resume.docx.scr", b"MZ\x90\x00fake pe header")
        self.assertEqual(result.risk_level, RISK_CRITICAL)

    def test_executable_disguised_with_document_extension(self):
        result = analyze_file("notes.txt", b"MZ\x90\x00fake pe header")
        self.assertEqual(result.risk_level, RISK_HIGH)
        self.assertTrue(any("executable" in r.lower() for r in result.reasons))

    def test_genuine_executable_named_exe_is_flagged_for_extension_alone(self):
        # A .exe whose content genuinely matches (no mismatch, no disguise)
        # is flagged for having an executable extension at all, but scores
        # lower than a *disguised* executable -- that's intentional: the
        # signature matching the extension is not itself suspicious.
        result = analyze_file("setup.exe", b"MZ\x90\x00fake pe header")
        self.assertGreater(result.score, 0)
        self.assertIn(result.risk_level, (RISK_HIGH, RISK_CRITICAL, "MEDIUM"))

    def test_sha256_is_computed(self):
        import hashlib

        data = b"some file content"
        result = analyze_file("f.txt", data)
        self.assertEqual(result.sha256, hashlib.sha256(data).hexdigest())

    def test_result_is_deterministic(self):
        data = b"MZ\x90\x00fake"
        r1 = analyze_file("app.exe", data)
        r2 = analyze_file("app.exe", data)
        self.assertEqual(r1.score, r2.score)
        self.assertEqual(r1.risk_level, r2.risk_level)
        self.assertEqual(r1.reasons, r2.reasons)

    def test_reasons_always_present(self):
        safe = analyze_file("f.txt", b"plain text")
        self.assertTrue(len(safe.reasons) >= 1)

    def test_empty_executable_flagged(self):
        result = analyze_file("empty.exe", b"")
        self.assertGreater(result.score, 0)

    def test_as_dict_structure(self):
        result = analyze_file("f.pdf", b"%PDF-1.4")
        d = result.as_dict()
        for key in ("filename", "risk_level", "score", "reasons", "sha256"):
            self.assertIn(key, d)


# ---------------------------------------------------------------------
# Phase 11: quarantine
# ---------------------------------------------------------------------

class TestQuarantine(DbTestCase):

    def setUp(self):
        super().setUp()
        self.quarantine_dir = self.tmp_path / "quarantine"

    def _make_file(self, name="suspicious.exe", content=b"MZ fake"):
        path = self.tmp_path / name
        path.write_bytes(content)
        return str(path)

    def test_quarantine_moves_file(self):
        src = self._make_file()
        item = qsvc.quarantine_file(
            src, "abc123", "HIGH", ["executable extension"],
            username="alice", quarantine_dir=self.quarantine_dir,
        )
        self.assertFalse(os.path.exists(src))
        self.assertTrue(os.path.exists(item.quarantined_path))
        self.assertEqual(item.state, "quarantined")

    def test_quarantine_missing_file_raises(self):
        with self.assertRaises(qsvc.QuarantineError):
            qsvc.quarantine_file(
                str(self.tmp_path / "nope.exe"), "abc", "HIGH", [],
                quarantine_dir=self.quarantine_dir,
            )

    def test_list_items(self):
        src = self._make_file()
        qsvc.quarantine_file(src, "abc", "HIGH", [], quarantine_dir=self.quarantine_dir)
        items = qsvc.list_items()
        self.assertEqual(len(items), 1)

    def test_inspect_returns_metadata(self):
        src = self._make_file("weird.pdf.exe")
        item = qsvc.quarantine_file(
            src, "abc", "CRITICAL", ["double extension"], quarantine_dir=self.quarantine_dir
        )
        fetched = qsvc.get_item(item.quarantine_id)
        self.assertEqual(fetched.original_filename, "weird.pdf.exe")
        self.assertEqual(fetched.reasons, ["double extension"])

    def test_invalid_quarantine_id_raises(self):
        with self.assertRaises(qsvc.QuarantineError):
            qsvc.get_item("not-a-real-id")

    def test_restore_moves_file_back(self):
        src = self._make_file()
        item = qsvc.quarantine_file(src, "abc", "HIGH", [], quarantine_dir=self.quarantine_dir)
        dest = str(self.tmp_path / "restored.exe")
        qsvc.restore_item(item.quarantine_id, dest, username="alice")
        self.assertTrue(os.path.exists(dest))
        self.assertEqual(qsvc.get_item(item.quarantine_id).state, "restored")

    def test_cannot_restore_twice(self):
        src = self._make_file()
        item = qsvc.quarantine_file(src, "abc", "HIGH", [], quarantine_dir=self.quarantine_dir)
        dest = str(self.tmp_path / "restored.exe")
        qsvc.restore_item(item.quarantine_id, dest)
        with self.assertRaises(qsvc.QuarantineError):
            qsvc.restore_item(item.quarantine_id, dest + "2")

    def test_permanent_delete_removes_file(self):
        src = self._make_file()
        item = qsvc.quarantine_file(src, "abc", "HIGH", [], quarantine_dir=self.quarantine_dir)
        path_on_disk = item.quarantined_path
        qsvc.delete_item(item.quarantine_id, username="alice")
        self.assertFalse(os.path.exists(path_on_disk))
        self.assertEqual(qsvc.get_item(item.quarantine_id).state, "deleted")

    def test_quarantine_operations_are_audited(self):
        src = self._make_file()
        item = qsvc.quarantine_file(
            src, "abc", "HIGH", [], username="alice", quarantine_dir=self.quarantine_dir
        )
        qsvc.restore_item(item.quarantine_id, str(self.tmp_path / "back.exe"), username="alice")
        events = list_events(username="alice")
        event_types = {e.event_type for e in events}
        self.assertIn("FILE_QUARANTINED", event_types)
        self.assertIn("FILE_RESTORED", event_types)
        self.assertTrue(verify_audit_log().verified)


# ---------------------------------------------------------------------
# Phase 12: secure delete
# ---------------------------------------------------------------------

class TestSecureDelete(DbTestCase):

    def test_deletes_existing_file(self):
        path = self.tmp_path / "secret.txt"
        path.write_bytes(b"sensitive content")
        secure_delete(str(path), username="alice")
        self.assertFalse(path.exists())

    def test_missing_file_raises(self):
        with self.assertRaises(SecureDeleteError):
            secure_delete(str(self.tmp_path / "does_not_exist.txt"))

    def test_generates_audit_event_on_success(self):
        path = self.tmp_path / "secret.txt"
        path.write_bytes(b"data")
        secure_delete(str(path), username="alice")
        events = list_events(username="alice")
        self.assertEqual(events[0].event_type, "SECURE_DELETE")
        self.assertEqual(events[0].result, "success")

    def test_generates_audit_event_on_failure(self):
        try:
            secure_delete(str(self.tmp_path / "nope.txt"), username="alice")
        except SecureDeleteError:
            pass
        events = list_events(username="alice")
        self.assertEqual(events[0].result, "failure")

    def test_empty_file_does_not_crash(self):
        path = self.tmp_path / "empty.txt"
        path.write_bytes(b"")
        secure_delete(str(path))  # should not raise
        self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()

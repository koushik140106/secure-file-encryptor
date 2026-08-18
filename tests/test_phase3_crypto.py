"""
Phase 3 test suite: AES-256-GCM + Argon2id file encryption, the SVLT
container format, integrity verification, and legacy-format backward
compatibility.

Run with:
    python -m unittest tests.test_phase3_crypto -v
"""

import base64
import hashlib
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography.fernet import Fernet

from core import kdf
from core.crypto import encrypt as aes_encrypt, decrypt as aes_decrypt, InvalidTag
from core.file_format import (
    encrypt_file,
    decrypt_file,
    is_svlt_container,
    DecryptionError,
    MAGIC,
)
from crypto_utils import (
    encrypt_file_data,
    decrypt_file_data,
    is_legacy_file,
    reencrypt_legacy_to_svlt,
    LegacyDecryptionError,
)


class TestAesGcmPrimitive(unittest.TestCase):

    def test_roundtrip(self):
        key = b"0" * 32
        nonce, ct = aes_encrypt(key, b"hello world")
        pt = aes_decrypt(key, nonce, ct)
        self.assertEqual(pt, b"hello world")

    def test_wrong_key_fails(self):
        key = b"0" * 32
        wrong_key = b"1" * 32
        nonce, ct = aes_encrypt(key, b"hello world")
        with self.assertRaises(InvalidTag):
            aes_decrypt(wrong_key, nonce, ct)

    def test_tampered_ciphertext_fails(self):
        key = b"0" * 32
        nonce, ct = aes_encrypt(key, b"hello world")
        tampered = bytearray(ct)
        tampered[0] ^= 0xFF
        with self.assertRaises(InvalidTag):
            aes_decrypt(key, nonce, bytes(tampered))

    def test_tampered_aad_fails(self):
        key = b"0" * 32
        nonce, ct = aes_encrypt(key, b"hello world", associated_data=b"context-A")
        with self.assertRaises(InvalidTag):
            aes_decrypt(key, nonce, ct, associated_data=b"context-B")

    def test_nonces_are_unique_per_call(self):
        key = b"0" * 32
        nonce1, _ = aes_encrypt(key, b"data")
        nonce2, _ = aes_encrypt(key, b"data")
        self.assertNotEqual(nonce1, nonce2)


class TestKdf(unittest.TestCase):

    def test_same_password_and_salt_give_same_key(self):
        salt = kdf.generate_salt()
        k1 = kdf.derive_key("password123", salt)
        k2 = kdf.derive_key("password123", salt)
        self.assertEqual(k1, k2)

    def test_different_salts_give_different_keys(self):
        salt1 = kdf.generate_salt()
        salt2 = kdf.generate_salt()
        k1 = kdf.derive_key("password123", salt1)
        k2 = kdf.derive_key("password123", salt2)
        self.assertNotEqual(k1, k2)

    def test_key_length_is_256_bits(self):
        salt = kdf.generate_salt()
        key = kdf.derive_key("password123", salt)
        self.assertEqual(len(key), 32)


class TestSvltContainerFormat(unittest.TestCase):

    def test_container_starts_with_magic(self):
        container = encrypt_file(b"data", "pw123456", "file.txt")
        self.assertTrue(container.startswith(MAGIC))
        self.assertTrue(is_svlt_container(container))

    def test_roundtrip_preserves_data_and_filename(self):
        original = b"The quick brown fox jumps over the lazy dog." * 50
        container = encrypt_file(original, "correct horse battery staple", "report.pdf")
        result = decrypt_file(container, "correct horse battery staple")
        self.assertEqual(result.data, original)
        self.assertEqual(result.filename, "report.pdf")
        self.assertTrue(result.integrity_verified)

    def test_wrong_password_raises_decryption_error(self):
        container = encrypt_file(b"secret", "RightPassword1!", "f.txt")
        with self.assertRaises(DecryptionError):
            decrypt_file(container, "WrongPassword1!")

    def test_modified_ciphertext_raises_decryption_error(self):
        container = encrypt_file(b"secret", "pw123456", "f.txt")
        tampered = bytearray(container)
        tampered[-1] ^= 0xFF  # last byte of ciphertext/tag
        with self.assertRaises(DecryptionError):
            decrypt_file(bytes(tampered), "pw123456")

    def test_modified_header_metadata_raises_decryption_error(self):
        container = encrypt_file(b"secret", "pw123456", "f.txt")
        tampered = bytearray(container)
        tampered[16] ^= 0xFF  # inside the salt region of the header
        with self.assertRaises(DecryptionError):
            decrypt_file(bytes(tampered), "pw123456")

    def test_truncated_file_raises_decryption_error(self):
        container = encrypt_file(b"secret", "pw123456", "f.txt")
        with self.assertRaises(DecryptionError):
            decrypt_file(container[:10], "pw123456")

    def test_non_svlt_file_raises_decryption_error(self):
        with self.assertRaises(DecryptionError):
            decrypt_file(b"not a securevault container at all", "pw123456")

    def test_empty_file(self):
        container = encrypt_file(b"", "pw123456", "empty.txt")
        result = decrypt_file(container, "pw123456")
        self.assertEqual(result.data, b"")
        self.assertTrue(result.integrity_verified)

    def test_binary_data(self):
        binary = bytes(range(256)) * 10
        container = encrypt_file(binary, "pw123456", "binary.bin")
        result = decrypt_file(container, "pw123456")
        self.assertEqual(result.data, binary)

    def test_unicode_filename(self):
        container = encrypt_file(b"data", "pw123456", "файл_日本語_ملف.txt")
        result = decrypt_file(container, "pw123456")
        self.assertEqual(result.filename, "файл_日本語_ملف.txt")

    def test_large_file(self):
        large = b"X" * (5 * 1024 * 1024)  # 5 MB
        container = encrypt_file(large, "pw123456", "large.bin")
        result = decrypt_file(container, "pw123456")
        self.assertEqual(result.data, large)

    def test_two_encryptions_of_same_data_produce_different_containers(self):
        # Different salt + nonce each time, even for identical input.
        c1 = encrypt_file(b"same content", "pw123456", "f.txt")
        c2 = encrypt_file(b"same content", "pw123456", "f.txt")
        self.assertNotEqual(c1, c2)

    def test_sha256_recorded_matches_plaintext(self):
        data = b"integrity check me"
        container = encrypt_file(data, "pw123456", "f.txt")
        result = decrypt_file(container, "pw123456")
        self.assertEqual(hashlib.sha256(result.data).hexdigest(), hashlib.sha256(data).hexdigest())


class TestCryptoUtilsPublicApi(unittest.TestCase):
    """Tests against crypto_utils.py -- the module encrypt.py/decrypt.py actually call."""

    def test_new_encryption_uses_svlt(self):
        enc = encrypt_file_data(b"data", "pw123456", "f.txt")
        self.assertFalse(is_legacy_file(enc))

    def test_roundtrip_through_public_api(self):
        enc = encrypt_file_data(b"hello", "pw123456", "f.txt")
        data, name = decrypt_file_data(enc, "pw123456")
        self.assertEqual(data, b"hello")
        self.assertEqual(name, "f.txt")

    def _make_legacy_file(self, password, filename, data):
        # Reproduces the OLD Phase-1 scheme exactly, to construct a
        # realistic pre-upgrade encrypted file for compatibility testing.
        key = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())
        payload = json.dumps(
            {"filename": filename, "data": base64.b64encode(data).decode()}
        ).encode("utf-8")
        return Fernet(key).encrypt(payload)

    def test_legacy_file_detected(self):
        legacy = self._make_legacy_file("OldPass1!", "old.txt", b"legacy data")
        self.assertTrue(is_legacy_file(legacy))

    def test_legacy_file_still_decrypts(self):
        legacy = self._make_legacy_file("OldPass1!", "old.txt", b"legacy data")
        data, name = decrypt_file_data(legacy, "OldPass1!")
        self.assertEqual(data, b"legacy data")
        self.assertEqual(name, "old.txt")

    def test_legacy_file_wrong_password_fails_safely(self):
        legacy = self._make_legacy_file("OldPass1!", "old.txt", b"legacy data")
        with self.assertRaises(LegacyDecryptionError):
            decrypt_file_data(legacy, "WrongPassword")

    def test_legacy_migration_to_svlt(self):
        legacy = self._make_legacy_file("OldPass1!", "old.txt", b"legacy data")
        migrated = reencrypt_legacy_to_svlt(legacy, "OldPass1!")
        self.assertTrue(is_svlt_container(migrated))
        data, name = decrypt_file_data(migrated, "OldPass1!")
        self.assertEqual(data, b"legacy data")
        self.assertEqual(name, "old.txt")


if __name__ == "__main__":
    unittest.main()

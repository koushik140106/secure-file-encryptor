# SecureVault Phase 3: file encryption is now AES-256-GCM with an
# Argon2id-derived key inside a versioned SVLT container (core/file_format.py),
# replacing the previous unsalted-SHA-256-as-Fernet-key scheme. The public
# function names/signatures below (encrypt_file_data, decrypt_file_data,
# password_strength) are unchanged so encrypt.py/decrypt.py need no edits.
#
# decrypt_file_data() also transparently reads files produced by the OLD
# Fernet-based scheme (LegacyDecryptionError below is never raised for a
# valid legacy file -- see decrypt_legacy_fernet) so existing users' already-
# encrypted files keep working; see PHASE3_MIGRATION_NOTES in this module's
# docstring area for the re-encryption path exposed via
# reencrypt_legacy_to_svlt().

import base64
import hashlib
import json

from cryptography.fernet import Fernet, InvalidToken

from core.file_format import encrypt_file, decrypt_file, is_svlt_container, DecryptionError
from auth_core.password import password_strength  # re-exported for encrypt.py/decrypt.py


class LegacyDecryptionError(Exception):
    """Raised when a legacy (pre-SVLT) Fernet-encrypted file fails to decrypt."""


def _legacy_generate_key(password):
    # Reproduces the OLD (Phase-1) key derivation exactly, so old files
    # remain readable. This unsalted-SHA256-as-key scheme is NOT used for
    # any new encryption -- only to decrypt files that already exist.
    return base64.urlsafe_b64encode(
        hashlib.sha256(password.encode("utf-8")).digest()
    )


def _decrypt_legacy_fernet(encrypted, password):
    cipher = Fernet(_legacy_generate_key(password))
    try:
        decrypted = cipher.decrypt(encrypted)
    except InvalidToken as exc:
        raise LegacyDecryptionError(
            "Unable to decrypt the file. The password may be incorrect or the "
            "encrypted file may have been modified."
        ) from exc

    payload = json.loads(decrypted.decode("utf-8"))
    original = base64.b64decode(payload["data"])
    filename = payload["filename"]
    return original, filename


# =======================

def encrypt_file_data(data, password, filename):
    """
    Encrypt file data into a SecureVault v1 (SVLT) container: AES-256-GCM
    with an Argon2id-derived key and a per-file random salt and nonce.
    """
    return encrypt_file(data, password, filename)


# =======================

def decrypt_file_data(encrypted, password):
    """
    Decrypt a SecureVault (SVLT) container. Transparently falls back to
    the legacy Fernet format for files encrypted before this upgrade, so
    existing encrypted files are not abandoned. Returns (data, filename).
    """
    if is_svlt_container(encrypted):
        result = decrypt_file(encrypted, password)
        return result.data, result.filename

    return _decrypt_legacy_fernet(encrypted, password)


def decrypt_file_data_with_integrity(encrypted, password):
    """
    Like decrypt_file_data(), but also reports whether the embedded
    SHA-256 integrity check passed (SVLT files only; legacy Fernet files
    have no such embedded hash, so integrity_verified is reported as
    True for them based on Fernet's own authentication succeeding).
    Returns (data, filename, integrity_verified, is_legacy).
    """
    if is_svlt_container(encrypted):
        result = decrypt_file(encrypted, password)
        return result.data, result.filename, result.integrity_verified, False

    data, filename = _decrypt_legacy_fernet(encrypted, password)
    return data, filename, True, True


def is_legacy_file(encrypted) -> bool:
    """True if `encrypted` is a pre-SVLT (Fernet) encrypted file."""
    return not is_svlt_container(encrypted)


def reencrypt_legacy_to_svlt(encrypted, password):
    """
    Decrypt a legacy Fernet file and re-encrypt it as a new SVLT
    container, returning the new container bytes. Used for an explicit,
    user-initiated migration -- never run automatically, since it
    requires the correct password and rewrites the file on disk.
    """
    data, filename = _decrypt_legacy_fernet(encrypted, password)
    return encrypt_file(data, password, filename)
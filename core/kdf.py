"""
Password-based key derivation for FILE ENCRYPTION.

This is intentionally separate from auth_core/password.py, which derives
the login *password verifier*. Reusing the same derived value as both an
authentication check and an encryption key is a well-known mistake: it
means anything that can compare against (or leak) the auth verifier can
also reconstruct the file encryption key. Here, every encryption
operation derives a fresh 256-bit key from the password using its own
random salt, stored alongside the ciphertext -- so the key exists only
transiently in memory and is never persisted or logged.
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

KDF_ID_ARGON2ID = 1

SALT_LENGTH = 16
KEY_LENGTH = 32          # 256-bit key for AES-256-GCM
DEFAULT_MEMORY_KIB = 65536
DEFAULT_ITERATIONS = 3
DEFAULT_LANES = 4


def generate_salt() -> bytes:
    return os.urandom(SALT_LENGTH)


def derive_key(
    password: str,
    salt: bytes,
    memory_kib: int = DEFAULT_MEMORY_KIB,
    iterations: int = DEFAULT_ITERATIONS,
    lanes: int = DEFAULT_LANES,
) -> bytes:
    """
    Derive a 256-bit encryption key from a password and salt using
    Argon2id. The caller supplies (and stores, in the file container's
    authenticated header) the salt and parameters used, so the same key
    can be re-derived at decryption time.
    """
    if not password:
        raise ValueError("password must not be empty")

    kdf = Argon2id(
        salt=salt,
        length=KEY_LENGTH,
        iterations=iterations,
        lanes=lanes,
        memory_cost=memory_kib,
    )
    return kdf.derive(password.encode("utf-8"))

"""
Low-level authenticated encryption primitives.

Thin wrapper around cryptography.hazmat.primitives.ciphers.aead.AESGCM.
No custom cryptography is implemented here -- this module only handles
nonce generation and calling into the vetted library correctly.

AES-256-GCM provides confidentiality, integrity, and authentication in
one step: a wrong key or any modification to the ciphertext or the
associated data (AAD) causes decryption to raise InvalidTag rather than
returning corrupted plaintext.
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_LENGTH = 32     # 256-bit key
NONCE_LENGTH = 12    # 96-bit nonce, standard for AES-GCM

__all__ = ["KEY_LENGTH", "NONCE_LENGTH", "InvalidTag", "generate_nonce", "encrypt", "decrypt"]


def generate_nonce() -> bytes:
    """
    A fresh cryptographically random nonce. Every encryption operation
    must call this -- nonces must never be reused with the same key.
    """
    return os.urandom(NONCE_LENGTH)


def encrypt(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> tuple[bytes, bytes]:
    """
    Encrypt plaintext with AES-256-GCM under `key`, authenticating
    `associated_data` (AAD) without encrypting it.

    Returns (nonce, ciphertext). ciphertext includes the GCM auth tag.
    """
    if len(key) != KEY_LENGTH:
        raise ValueError(f"key must be {KEY_LENGTH} bytes (got {len(key)})")

    nonce = generate_nonce()
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce, ciphertext


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes = b"") -> bytes:
    """
    Decrypt and authenticate ciphertext produced by encrypt().

    Raises cryptography.exceptions.InvalidTag if the key is wrong, or if
    the ciphertext or associated_data has been modified. Never returns
    plaintext for a failed authentication check.
    """
    if len(key) != KEY_LENGTH:
        raise ValueError(f"key must be {KEY_LENGTH} bytes (got {len(key)})")

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data)

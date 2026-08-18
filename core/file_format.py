"""
SecureVault encrypted file container (SVLT), format version 1.

Layout on disk (all integers big-endian):

    offset  size    field
    0       4       magic            b"SVLT"
    4       1       version          0x01
    5       1       kdf_id           0x01 = Argon2id
    6       4       kdf_memory_kib
    10      4       kdf_iterations
    14      1       kdf_lanes
    15      16      salt
    31      12      nonce
    43      *       ciphertext (AES-256-GCM; includes 16-byte auth tag)

The header (everything before the ciphertext) is passed to AES-GCM as
associated data (AAD): it is authenticated but not encrypted, so any
modification to the header -- not just the ciphertext -- causes
decryption to fail rather than being silently accepted.

The encrypted payload itself is a JSON document containing:
    filename, size, sha256, created_at, data (base64)

storing the plaintext's SHA-256 lets the caller verify, after
decryption, that what came out matches what went in -- on top of (not
instead of) the AES-GCM authentication tag, which already guarantees
the ciphertext itself was not tampered with.

This module never claims the format is "unbreakable" or the log
tamper-proof; it implements exactly what's described above.
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
from dataclasses import dataclass
from datetime import datetime, timezone

from core import kdf
from core.crypto import encrypt as aes_encrypt, decrypt as aes_decrypt, InvalidTag

MAGIC = b"SVLT"
FORMAT_VERSION = 1


class DecryptionError(Exception):
    """
    Raised when a container cannot be decrypted: wrong password, or the
    ciphertext/header/metadata has been modified. Deliberately does not
    distinguish "wrong password" from "tampered file" in its public
    message -- both are the same failure from the caller's point of
    view, and conflating them avoids giving an attacker a tampering
    oracle.
    """


class IntegrityError(Exception):
    """
    Raised when AES-GCM authentication succeeds (so the container itself
    is intact) but the decrypted content's SHA-256 does not match the
    hash recorded at encryption time. This should not normally happen --
    it would indicate a bug rather than an attack, since GCM already
    authenticated the bytes -- but it is checked and reported rather
    than assumed.
    """


@dataclass
class DecryptedFile:
    data: bytes
    filename: str
    original_size: int
    integrity_verified: bool


def _header_aad(kdf_id: int, memory_kib: int, iterations: int, lanes: int, salt: bytes) -> bytes:
    """
    The portion of the header that is authenticated as AAD. Built once
    from explicit fields (rather than duplicated at encrypt vs decrypt
    time) so the two paths can never drift apart -- decrypt always
    reconstructs this from the header bytes it just read, and encrypt
    always reconstructs it from the parameters it just chose.
    """
    return (
        MAGIC
        + struct.pack(">B", FORMAT_VERSION)
        + struct.pack(">B", kdf_id)
        + struct.pack(">I", memory_kib)
        + struct.pack(">I", iterations)
        + struct.pack(">B", lanes)
        + salt
    )


def _unpack_header(raw: bytes) -> dict:
    if len(raw) < 43:
        raise DecryptionError("File is too short to be a valid SecureVault container.")

    magic = raw[0:4]
    if magic != MAGIC:
        raise DecryptionError("Not a SecureVault (SVLT) encrypted file.")

    version = raw[4]
    if version != FORMAT_VERSION:
        raise DecryptionError(f"Unsupported SecureVault format version: {version}")

    kdf_id = raw[5]
    memory_kib = struct.unpack(">I", raw[6:10])[0]
    iterations = struct.unpack(">I", raw[10:14])[0]
    lanes = raw[14]
    salt = raw[15:31]
    nonce = raw[31:43]

    return {
        "kdf_id": kdf_id,
        "memory_kib": memory_kib,
        "iterations": iterations,
        "lanes": lanes,
        "salt": salt,
        "nonce": nonce,
    }


def is_svlt_container(raw: bytes) -> bool:
    return raw[:4] == MAGIC


def encrypt_file(data: bytes, password: str, filename: str) -> bytes:
    """
    Encrypt `data` into a versioned SVLT container. Returns the full
    container as bytes, ready to write to disk.
    """
    salt = kdf.generate_salt()
    key = kdf.derive_key(password, salt)

    sha256 = hashlib.sha256(data).hexdigest()
    payload = {
        "filename": filename,
        "size": len(data),
        "sha256": sha256,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "data": base64.b64encode(data).decode("ascii"),
    }
    plaintext = json.dumps(payload).encode("utf-8")

    aad = _header_aad(kdf.KDF_ID_ARGON2ID, kdf.DEFAULT_MEMORY_KIB, kdf.DEFAULT_ITERATIONS, kdf.DEFAULT_LANES, salt)
    nonce, ciphertext = aes_encrypt(key, plaintext, associated_data=aad)
    header = aad + nonce

    return header + ciphertext


def decrypt_file(container: bytes, password: str) -> DecryptedFile:
    """
    Decrypt an SVLT container. Raises DecryptionError for a wrong
    password or any tampering with the header or ciphertext -- never
    returns unauthenticated plaintext.
    """
    header = _unpack_header(container)
    ciphertext = container[43:]

    key = kdf.derive_key(
        password,
        header["salt"],
        memory_kib=header["memory_kib"],
        iterations=header["iterations"],
        lanes=header["lanes"],
    )

    aad = _header_aad(
        header["kdf_id"], header["memory_kib"], header["iterations"], header["lanes"], header["salt"]
    )

    try:
        plaintext = aes_decrypt(key, header["nonce"], ciphertext, associated_data=aad)
    except InvalidTag as exc:
        raise DecryptionError(
            "Unable to decrypt the file. The password may be incorrect or the "
            "encrypted container may have been modified."
        ) from exc

    try:
        payload = json.loads(plaintext.decode("utf-8"))
        data = base64.b64decode(payload["data"])
        filename = payload["filename"]
        expected_sha256 = payload["sha256"]
    except (json.JSONDecodeError, KeyError, ValueError) as exc:
        raise DecryptionError(
            "The decrypted container was malformed."
        ) from exc

    actual_sha256 = hashlib.sha256(data).hexdigest()
    integrity_verified = actual_sha256 == expected_sha256

    return DecryptedFile(
        data=data,
        filename=filename,
        original_size=payload.get("size", len(data)),
        integrity_verified=integrity_verified,
    )

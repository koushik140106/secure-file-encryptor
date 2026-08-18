"""
Password hashing and verification using Argon2id.

Uses cryptography.hazmat.primitives.kdf.argon2.Argon2id, which is part of
the already-vendored `cryptography` library (no extra dependency needed).

Stored hash format (single self-describing string, similar in spirit to
PHC string format so parameters can evolve without breaking old hashes):

    argon2id$<version>$m=<memory_kib>,t=<iterations>,p=<lanes>$<salt_b64>$<hash_b64>

Nothing in this module ever logs, prints, or returns the plaintext
password. Callers must not log it either.
"""

from __future__ import annotations

import base64
import hmac
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

# Argon2id parameters (OWASP-recommended baseline for interactive login).
# memory_cost is in KiB. These can be raised later; the version tag in the
# stored hash lets us support multiple parameter sets over time.
_ALGO_TAG = "argon2id"
_PARAM_VERSION = 1
_DEFAULT_MEMORY_KIB = 65536   # 64 MiB
_DEFAULT_ITERATIONS = 3
_DEFAULT_LANES = 4
_KEY_LENGTH = 32              # 256-bit derived key
_SALT_LENGTH = 16             # 128-bit random salt


class PasswordHashError(Exception):
    """Raised when a stored password hash is malformed or unreadable."""


@dataclass(frozen=True)
class _Params:
    memory_kib: int
    iterations: int
    lanes: int


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def hash_password(password: str) -> str:
    """
    Hash a plaintext password with Argon2id and a fresh random salt.

    Returns an opaque string safe to store in the database. The plaintext
    password is never stored or logged.
    """
    if not isinstance(password, str) or password == "":
        raise ValueError("password must be a non-empty string")

    salt = os.urandom(_SALT_LENGTH)
    kdf = Argon2id(
        salt=salt,
        length=_KEY_LENGTH,
        iterations=_DEFAULT_ITERATIONS,
        lanes=_DEFAULT_LANES,
        memory_cost=_DEFAULT_MEMORY_KIB,
    )
    derived = kdf.derive(password.encode("utf-8"))

    params = f"m={_DEFAULT_MEMORY_KIB},t={_DEFAULT_ITERATIONS},p={_DEFAULT_LANES}"
    return f"{_ALGO_TAG}${_PARAM_VERSION}${params}${_b64encode(salt)}${_b64encode(derived)}"


def _parse_hash(stored_hash: str) -> tuple[_Params, bytes, bytes]:
    try:
        algo, version_str, params_str, salt_b64, hash_b64 = stored_hash.split("$")
    except ValueError as exc:
        raise PasswordHashError("malformed password hash record") from exc

    if algo != _ALGO_TAG:
        raise PasswordHashError(f"unsupported password hash algorithm: {algo}")

    param_dict = {}
    for part in params_str.split(","):
        key, _, value = part.partition("=")
        param_dict[key] = int(value)

    try:
        params = _Params(
            memory_kib=param_dict["m"],
            iterations=param_dict["t"],
            lanes=param_dict["p"],
        )
    except KeyError as exc:
        raise PasswordHashError("malformed password hash parameters") from exc

    return params, _b64decode(salt_b64), _b64decode(hash_b64)


def verify_password(password: str, stored_hash: str) -> bool:
    """
    Verify a plaintext password against a stored Argon2id hash.

    Returns False (never raises) for wrong passwords or malformed/corrupt
    hash records, so callers can treat every failure path uniformly as
    "authentication failed" without leaking why.
    """
    if not password or not stored_hash:
        return False

    try:
        params, salt, expected = _parse_hash(stored_hash)
    except PasswordHashError:
        return False

    kdf = Argon2id(
        salt=salt,
        length=len(expected),
        iterations=params.iterations,
        lanes=params.lanes,
        memory_cost=params.memory_kib,
    )
    try:
        kdf.verify(password.encode("utf-8"), expected)
        return True
    except Exception:
        # cryptography's KDF.verify raises InvalidKey on mismatch; any other
        # unexpected failure is also treated as a failed verification rather
        # than propagating (fail closed, not open).
        return False


def password_strength(password: str) -> str:
    """
    Lightweight strength label, preserved from the original app for the UI.
    This is advisory only and never blocks a strong-enough password.
    """
    score = 0
    if len(password) >= 8:
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(not c.isalnum() for c in password):
        score += 1
    if len(password) >= 12:
        score += 1

    labels = ["Weak", "Medium", "Strong", "Very Strong"]
    return labels[min(score, 3)]


def meets_minimum_requirements(password: str) -> tuple[bool, str]:
    """
    Baseline registration requirement: not the whole complexity theater,
    just enough to block trivially weak passwords.
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    return True, ""

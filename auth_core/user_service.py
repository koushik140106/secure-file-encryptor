"""
Authentication service: the only layer the UI should call for
registration and login. Keeps SQL and password hashing out of Tkinter
callbacks (see auth.py for the UI, which now delegates here).
"""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from auth_core.password import hash_password, verify_password, meets_minimum_requirements
from database import user_repository as repo
from database.db import get_connection, transaction

GENERIC_LOGIN_ERROR = "Invalid username or password."
ACCOUNT_LOCKED_ERROR = "This account is temporarily locked due to repeated failed logins. Try again later."
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")

# Brute-force lockout policy: 5 consecutive failures locks the account
# for 15 minutes. A successful login resets the counter. This is a
# reasonable default, not a punitive one -- accounts are never
# permanently locked by this mechanism.
LOCKOUT_THRESHOLD = 5
LOCKOUT_DURATION_MINUTES = 15


@dataclass
class AuthResult:
    success: bool
    message: str
    username: Optional[str] = None
    locked_out: bool = False
    mfa_required: bool = False


def validate_username(username: str) -> tuple[bool, str]:
    if not username:
        return False, "Enter a username."
    if not _USERNAME_RE.match(username):
        return False, (
            "Username must be 3-32 characters and contain only letters, "
            "numbers, dots, dashes, or underscores."
        )
    return True, ""


def register_user(username: str, password: str, confirm_password: str) -> AuthResult:
    """
    Register a new user. Validates input, hashes the password with
    Argon2id, and inserts into SQLite. The plaintext password is never
    stored or logged.
    """
    username = (username or "").strip()

    ok, err = validate_username(username)
    if not ok:
        return AuthResult(False, err)

    if password != confirm_password:
        return AuthResult(False, "Passwords do not match.")

    ok, err = meets_minimum_requirements(password)
    if not ok:
        return AuthResult(False, err)

    if repo.username_exists(username):
        return AuthResult(False, "Username already exists.")

    password_hash = hash_password(password)

    try:
        repo.create_user(username, password_hash)
    except sqlite3.IntegrityError:
        # Handles a race where the username was taken between the check
        # above and the insert.
        return AuthResult(False, "Username already exists.")

    return AuthResult(True, "Account created successfully.", username=username)


def _is_locked(user, conn) -> bool:
    if not user.locked_until:
        return False
    locked_until = datetime.strptime(user.locked_until, "%Y-%m-%d %H:%M:%S").replace(
        tzinfo=timezone.utc
    )
    return datetime.now(timezone.utc) < locked_until


def _apply_lockout_if_threshold_reached(username: str, failed_attempts: int, conn) -> bool:
    """Returns True if this failure just triggered a new lockout."""
    if failed_attempts < LOCKOUT_THRESHOLD:
        return False
    locked_until = (
        datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
    ).strftime("%Y-%m-%d %H:%M:%S")
    with transaction(conn):
        conn.execute(
            "UPDATE users SET locked_until = ?, updated_at = datetime('now') WHERE username = ?",
            (locked_until, username),
        )
    return True


def authenticate_user(username: str, password: str) -> AuthResult:
    """
    Verify credentials against the Argon2id hash stored in SQLite.
    Enforces brute-force lockout: after LOCKOUT_THRESHOLD consecutive
    failures, the account is locked for LOCKOUT_DURATION_MINUTES.
    Always returns the same generic error message for "wrong password"
    and "unknown username" so the UI never reveals which one occurred.
    """
    username = (username or "").strip()
    conn = get_connection()
    user = repo.get_user_by_username(username, conn)

    if user is None:
        return AuthResult(False, GENERIC_LOGIN_ERROR)

    if user.account_status != "active":
        return AuthResult(False, GENERIC_LOGIN_ERROR)

    if _is_locked(user, conn):
        return AuthResult(False, ACCOUNT_LOCKED_ERROR, locked_out=True)

    if verify_password(password, user.password_hash):
        repo.record_successful_login(username, conn)
        # Password verification alone is not sufficient when MFA is enabled.
        return AuthResult(
            True,
            "Password verified.",
            username=username,
            mfa_required=bool(user.mfa_enabled),
        )

    failed_attempts = repo.record_failed_login(username, conn)
    just_locked = _apply_lockout_if_threshold_reached(username, failed_attempts, conn)
    if just_locked:
        return AuthResult(False, ACCOUNT_LOCKED_ERROR, locked_out=True)

    return AuthResult(False, GENERIC_LOGIN_ERROR)

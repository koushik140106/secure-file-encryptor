"""
MFA service: ties the RFC 6238 TOTP implementation (auth_core/mfa.py)
into SQLite and the authentication flow.

Enrollment flow:
  begin_mfa_setup(username)      -> secret + provisioning URI (not yet active)
  confirm_mfa_setup(username, code) -> verifies one code, activates MFA,
                                        returns recovery codes (shown once)

Login flow (once mfa_enabled is set on the user):
  authenticate_user() in user_service.py succeeds on password -> caller
  must then call verify_login_code(username, code) before granting
  access. This module never itself decides "login succeeded" -- it only
  answers "was this MFA proof valid," keeping password and MFA checks
  as two independently testable steps rather than one tangled function.

Recovery codes are stored as Argon2id hashes (reusing auth_core.password
functions), never in plaintext, and each one is single-use.
"""

from __future__ import annotations

import secrets
import string

from auth_core import mfa as totp
from auth_core.password import hash_password, verify_password
from database.db import get_connection, transaction

RECOVERY_CODE_COUNT = 8
RECOVERY_CODE_LENGTH = 10


class MfaError(Exception):
    pass


def _generate_recovery_code() -> str:
    alphabet = string.ascii_uppercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(RECOVERY_CODE_LENGTH))


def begin_mfa_setup(username: str, conn=None) -> tuple[str, str]:
    """
    Generate a new (unconfirmed) TOTP secret for the user and return
    (secret, provisioning_uri). MFA is not enabled until
    confirm_mfa_setup() verifies a code generated from this secret --
    this two-step flow prevents a user from locking themselves out by
    enabling MFA against an app they mistyped/misscanned.
    """
    connection = conn or get_connection()
    secret = totp.generate_secret()
    with transaction(connection):
        connection.execute(
            "INSERT INTO mfa_devices (username, secret, confirmed, created_at) "
            "VALUES (?, ?, 0, datetime('now')) "
            "ON CONFLICT(username) DO UPDATE SET secret = excluded.secret, confirmed = 0",
            (username, secret),
        )
    uri = totp.provisioning_uri(secret, username)
    return secret, uri


def confirm_mfa_setup(username: str, code: str, conn=None) -> list[str]:
    """
    Verify a setup code against the pending secret; on success, activate
    MFA for the user and return a fresh set of one-time recovery codes
    (plaintext, returned exactly once -- only their hashes are stored).
    """
    connection = conn or get_connection()
    row = connection.execute(
        "SELECT secret FROM mfa_devices WHERE username = ?", (username,)
    ).fetchone()
    if row is None:
        raise MfaError("No MFA setup in progress for this user.")

    if not totp.verify_totp(row["secret"], code):
        raise MfaError("Invalid verification code.")

    recovery_codes = [_generate_recovery_code() for _ in range(RECOVERY_CODE_COUNT)]

    with transaction(connection):
        connection.execute(
            "UPDATE mfa_devices SET confirmed = 1 WHERE username = ?", (username,)
        )
        connection.execute(
            "UPDATE users SET mfa_enabled = 1, updated_at = datetime('now') WHERE username = ?",
            (username,),
        )
        connection.execute("DELETE FROM recovery_codes WHERE username = ?", (username,))
        for code in recovery_codes:
            connection.execute(
                "INSERT INTO recovery_codes (username, code_hash, used, created_at) "
                "VALUES (?, ?, 0, datetime('now'))",
                (username, hash_password(code)),
            )

    return recovery_codes


def verify_login_code(username: str, code: str, conn=None) -> bool:
    """
    Verify a TOTP code (or a recovery code as fallback) during login.
    Only meaningful once MFA is confirmed/enabled for the user.
    """
    connection = conn or get_connection()
    row = connection.execute(
        "SELECT secret, confirmed FROM mfa_devices WHERE username = ?", (username,)
    ).fetchone()
    if row is None or not row["confirmed"]:
        return False

    if totp.verify_totp(row["secret"], code):
        return True

    return _try_consume_recovery_code(username, code, connection)


def _try_consume_recovery_code(username: str, code: str, conn) -> bool:
    rows = conn.execute(
        "SELECT id, code_hash FROM recovery_codes WHERE username = ? AND used = 0",
        (username,),
    ).fetchall()
    for row in rows:
        if verify_password(code, row["code_hash"]):
            with transaction(conn):
                conn.execute(
                    "UPDATE recovery_codes SET used = 1 WHERE id = ?", (row["id"],)
                )
            return True
    return False


def is_mfa_enabled(username: str, conn=None) -> bool:
    connection = conn or get_connection()
    row = connection.execute(
        "SELECT mfa_enabled FROM users WHERE username = ?", (username,)
    ).fetchone()
    return bool(row["mfa_enabled"]) if row else False


def disable_mfa(username: str, password: str, conn=None) -> bool:
    """
    Disable MFA. Requires the user's current password to be re-verified
    by the caller's auth layer before calling this -- this function
    itself re-checks the password hash as a defense-in-depth measure so
    it can't accidentally be called without that check.
    """
    from database import user_repository as repo

    connection = conn or get_connection()
    user = repo.get_user_by_username(username, connection)
    if user is None or not verify_password(password, user.password_hash):
        return False

    with transaction(connection):
        connection.execute("DELETE FROM mfa_devices WHERE username = ?", (username,))
        connection.execute("DELETE FROM recovery_codes WHERE username = ?", (username,))
        connection.execute(
            "UPDATE users SET mfa_enabled = 0, updated_at = datetime('now') WHERE username = ?",
            (username,),
        )
    return True

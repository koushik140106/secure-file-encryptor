"""
Data-access layer for the `users` table.

Every query here uses parameterized placeholders (`?`). No SQL string is
ever built by concatenating or formatting user-supplied values.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Optional

from database.db import get_connection, transaction


@dataclass
class UserRecord:
    id: int
    username: str
    password_hash: str
    created_at: str
    updated_at: str
    failed_attempts: int
    locked_until: Optional[str]
    last_login: Optional[str]
    account_status: str
    mfa_enabled: bool

    @staticmethod
    def from_row(row: sqlite3.Row) -> "UserRecord":
        return UserRecord(
            id=row["id"],
            username=row["username"],
            password_hash=row["password_hash"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            failed_attempts=row["failed_attempts"],
            locked_until=row["locked_until"],
            last_login=row["last_login"],
            account_status=row["account_status"],
            mfa_enabled=bool(row["mfa_enabled"]),
        )


def username_exists(username: str, conn: sqlite3.Connection | None = None) -> bool:
    connection = conn or get_connection()
    row = connection.execute(
        "SELECT 1 FROM users WHERE username = ?", (username,)
    ).fetchone()
    return row is not None


def get_user_by_username(
    username: str, conn: sqlite3.Connection | None = None
) -> Optional[UserRecord]:
    connection = conn or get_connection()
    row = connection.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    return UserRecord.from_row(row) if row else None


def create_user(
    username: str, password_hash: str, conn: sqlite3.Connection | None = None
) -> int:
    """Insert a new user. Raises sqlite3.IntegrityError on duplicate username."""
    connection = conn or get_connection()
    with transaction(connection):
        cursor = connection.execute(
            """
            INSERT INTO users (username, password_hash, created_at, updated_at)
            VALUES (?, ?, datetime('now'), datetime('now'))
            """,
            (username, password_hash),
        )
        return cursor.lastrowid


def rename_user(
    old_username: str, new_username: str, conn: sqlite3.Connection | None = None
) -> bool:
    """
    Rename a user's username in place. Returns False (no-op) if the new
    username is already taken or the old username doesn't exist.
    """
    connection = conn or get_connection()
    if not get_user_by_username(old_username, connection):
        return False
    if username_exists(new_username, connection):
        return False
    with transaction(connection):
        connection.execute(
            "UPDATE users SET username = ?, updated_at = datetime('now') "
            "WHERE username = ?",
            (new_username, old_username),
        )
    return True


def update_password_hash(
    username: str, new_hash: str, conn: sqlite3.Connection | None = None
) -> None:
    connection = conn or get_connection()
    with transaction(connection):
        connection.execute(
            "UPDATE users SET password_hash = ?, updated_at = datetime('now') "
            "WHERE username = ?",
            (new_hash, username),
        )


def record_successful_login(
    username: str, conn: sqlite3.Connection | None = None
) -> None:
    connection = conn or get_connection()
    with transaction(connection):
        connection.execute(
            """
            UPDATE users
            SET failed_attempts = 0,
                locked_until = NULL,
                last_login = datetime('now'),
                updated_at = datetime('now')
            WHERE username = ?
            """,
            (username,),
        )


def record_failed_login(
    username: str, conn: sqlite3.Connection | None = None
) -> int:
    """
    Increment failed_attempts for a user and return the new count.
    Full lockout policy (locked_until enforcement) lands in the next
    authentication phase -- this just tracks the counter so that policy
    has data to act on.
    """
    connection = conn or get_connection()
    with transaction(connection):
        connection.execute(
            """
            UPDATE users
            SET failed_attempts = failed_attempts + 1,
                updated_at = datetime('now')
            WHERE username = ?
            """,
            (username,),
        )
        row = connection.execute(
            "SELECT failed_attempts FROM users WHERE username = ?", (username,)
        ).fetchone()
        return row["failed_attempts"] if row else 0


def count_users(conn: sqlite3.Connection | None = None) -> int:
    connection = conn or get_connection()
    row = connection.execute("SELECT COUNT(*) AS c FROM users").fetchone()
    return row["c"]

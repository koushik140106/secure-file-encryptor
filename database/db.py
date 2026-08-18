"""
SQLite database layer for SecureVault.

Owns connection management, schema creation, and (in later phases) simple
migrations. Phase 2 only defines the `users` table; later phases add
sessions, audit_events, files, quarantine_items, etc. without breaking
this one.

All queries use parameterized SQL (`?` placeholders) -- never string
formatting/concatenation of user input into SQL text.
"""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "securevault.db"

_SCHEMA_USERS = """
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now')),
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    TEXT,
    last_login      TEXT,
    account_status  TEXT NOT NULL DEFAULT 'active',
    mfa_enabled     INTEGER NOT NULL DEFAULT 0
);
"""

_SCHEMA_MIGRATION_STATE = """
CREATE TABLE IF NOT EXISTS migration_state (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
"""

_SCHEMA_SESSIONS = """
CREATE TABLE IF NOT EXISTS sessions (
    id              TEXT PRIMARY KEY,
    username        TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    last_activity   TEXT NOT NULL DEFAULT (datetime('now')),
    state           TEXT NOT NULL DEFAULT 'active',
    ended_at        TEXT
);
"""

_SCHEMA_MFA_DEVICES = """
CREATE TABLE IF NOT EXISTS mfa_devices (
    username        TEXT PRIMARY KEY,
    secret          TEXT NOT NULL,
    confirmed       INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
"""

_SCHEMA_RECOVERY_CODES = """
CREATE TABLE IF NOT EXISTS recovery_codes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT NOT NULL,
    code_hash       TEXT NOT NULL,
    used            INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
"""

_SCHEMA_QUARANTINE_ITEMS = """
CREATE TABLE IF NOT EXISTS quarantine_items (
    quarantine_id       TEXT PRIMARY KEY,
    username             TEXT,
    original_filename    TEXT NOT NULL,
    original_path        TEXT,
    quarantined_path      TEXT NOT NULL,
    sha256                TEXT NOT NULL,
    risk_level            TEXT NOT NULL,
    reasons               TEXT NOT NULL,
    state                 TEXT NOT NULL DEFAULT 'quarantined',
    created_at            TEXT NOT NULL DEFAULT (datetime('now')),
    resolved_at           TEXT
);
"""

_SCHEMA_AUDIT_EVENTS = """
CREATE TABLE IF NOT EXISTS audit_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT NOT NULL DEFAULT (datetime('now')),
    event_type      TEXT NOT NULL,
    username        TEXT,
    result          TEXT NOT NULL DEFAULT 'info',
    object_id       TEXT,
    metadata        TEXT,
    prev_hash       TEXT NOT NULL,
    event_hash      TEXT NOT NULL
);
"""

# One lock per process is sufficient here: this is a single-user desktop
# app, and sqlite3 connections are not safely shared across threads without
# serializing access ourselves.
_lock = threading.Lock()
_connection: sqlite3.Connection | None = None


def get_connection(db_path: Path | str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Return a process-wide SQLite connection, creating it on first use."""
    global _connection
    with _lock:
        if _connection is None:
            _connection = sqlite3.connect(str(db_path), check_same_thread=False)
            _connection.row_factory = sqlite3.Row
            _connection.execute("PRAGMA foreign_keys = ON;")
        return _connection


def close_connection() -> None:
    """Close the process-wide connection (mainly for tests)."""
    global _connection
    with _lock:
        if _connection is not None:
            _connection.close()
            _connection = None


def reset_for_tests(db_path: Path | str) -> sqlite3.Connection:
    """Force a fresh connection bound to db_path. Test-only helper."""
    close_connection()
    return get_connection(db_path)


@contextmanager
def transaction(conn: sqlite3.Connection | None = None):
    """
    Context manager wrapping a block of writes in a transaction.
    Commits on success, rolls back on any exception.
    """
    owns_conn = conn is None
    connection = conn or get_connection()
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        if owns_conn:
            pass  # process-wide connection stays open


def init_db(db_path: Path | str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """
    Initialize the database schema. Safe to call on every startup --
    uses CREATE TABLE IF NOT EXISTS, so it's a no-op on an already
    initialized database.
    """
    conn = get_connection(db_path)
    with transaction(conn):
        conn.execute(_SCHEMA_USERS)
        conn.execute(_SCHEMA_MIGRATION_STATE)
        conn.execute(_SCHEMA_SESSIONS)
        conn.execute(_SCHEMA_MFA_DEVICES)
        conn.execute(_SCHEMA_RECOVERY_CODES)
        conn.execute(_SCHEMA_QUARANTINE_ITEMS)
        conn.execute(_SCHEMA_AUDIT_EVENTS)
    return conn


def get_migration_flag(key: str, conn: sqlite3.Connection | None = None) -> str | None:
    connection = conn or get_connection()
    row = connection.execute(
        "SELECT value FROM migration_state WHERE key = ?", (key,)
    ).fetchone()
    return row["value"] if row else None


def set_migration_flag(key: str, value: str, conn: sqlite3.Connection | None = None) -> None:
    connection = conn or get_connection()
    with transaction(connection):
        connection.execute(
            """
            INSERT INTO migration_state (key, value, updated_at)
            VALUES (?, ?, datetime('now'))
            ON CONFLICT(key) DO UPDATE SET value = excluded.value,
                                            updated_at = datetime('now')
            """,
            (key, value),
        )

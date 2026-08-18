"""
Session service: the enforcement point for "is this user actually
allowed to be looking at protected screens right now."

Sessions are persisted in SQLite (the `sessions` table) rather than kept
only as Tkinter/UI state, so a UI bug (e.g. a screen that forgets to
check a flag) can't silently grant access -- the UI is expected to call
is_session_valid()/require_active() before rendering protected content,
and the service is the source of truth for whether that's true.

States: active -> locked -> active (via unlock) -> ended (logout/expiry)
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from database.db import get_connection, transaction

DEFAULT_INACTIVITY_TIMEOUT_MINUTES = 15

_STATE_ACTIVE = "active"
_STATE_LOCKED = "locked"
_STATE_ENDED = "ended"


class SessionError(Exception):
    """Raised for operations on a session ID that doesn't exist."""


class ReauthenticationRequired(Exception):
    """
    Raised when a caller tries to use a locked or expired session for a
    protected operation. The UI should catch this and route to the
    login/unlock screen rather than rendering the protected content.
    """


@dataclass
class SessionInfo:
    id: str
    username: str
    created_at: str
    last_activity: str
    state: str
    ended_at: str | None

    @property
    def is_active(self) -> bool:
        return self.state == _STATE_ACTIVE


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _parse_db_timestamp(value: str) -> datetime:
    # SQLite datetime('now') yields "YYYY-MM-DD HH:MM:SS" in UTC.
    return datetime.strptime(value, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)


def create_session(username: str, conn=None) -> SessionInfo:
    connection = conn or get_connection()
    session_id = str(uuid.uuid4())
    with transaction(connection):
        connection.execute(
            "INSERT INTO sessions (id, username, created_at, last_activity, state) "
            "VALUES (?, ?, datetime('now'), datetime('now'), ?)",
            (session_id, username, _STATE_ACTIVE),
        )
    return get_session(session_id, connection)


def get_session(session_id: str, conn=None) -> SessionInfo:
    connection = conn or get_connection()
    row = connection.execute(
        "SELECT * FROM sessions WHERE id = ?", (session_id,)
    ).fetchone()
    if row is None:
        raise SessionError(f"No such session: {session_id}")
    return SessionInfo(
        id=row["id"],
        username=row["username"],
        created_at=row["created_at"],
        last_activity=row["last_activity"],
        state=row["state"],
        ended_at=row["ended_at"],
    )


def touch_session(session_id: str, conn=None) -> None:
    """Record activity, extending the inactivity timeout window."""
    connection = conn or get_connection()
    with transaction(connection):
        connection.execute(
            "UPDATE sessions SET last_activity = datetime('now') "
            "WHERE id = ? AND state = ?",
            (session_id, _STATE_ACTIVE),
        )


def is_expired(
    session_id: str,
    timeout_minutes: int = DEFAULT_INACTIVITY_TIMEOUT_MINUTES,
    conn=None,
) -> bool:
    session = get_session(session_id, conn)
    if session.state != _STATE_ACTIVE:
        return False  # locked/ended sessions have their own explicit state
    last_activity = _parse_db_timestamp(session.last_activity)
    return _now_utc() - last_activity > timedelta(minutes=timeout_minutes)


def expire_if_inactive(
    session_id: str,
    timeout_minutes: int = DEFAULT_INACTIVITY_TIMEOUT_MINUTES,
    conn=None,
) -> bool:
    """Mark the session ended if it's been inactive too long. Returns True if expired."""
    connection = conn or get_connection()
    if is_expired(session_id, timeout_minutes, connection):
        with transaction(connection):
            connection.execute(
                "UPDATE sessions SET state = ?, ended_at = datetime('now') WHERE id = ?",
                (_STATE_ENDED, session_id),
            )
        return True
    return False


def lock_session(session_id: str, conn=None) -> None:
    connection = conn or get_connection()
    with transaction(connection):
        connection.execute(
            "UPDATE sessions SET state = ? WHERE id = ? AND state = ?",
            (_STATE_LOCKED, session_id, _STATE_ACTIVE),
        )


def unlock_session(session_id: str, conn=None) -> None:
    """
    Re-activate a locked session. Callers MUST have already verified the
    user's password again before calling this -- this function only
    performs the state transition, not authentication.
    """
    connection = conn or get_connection()
    with transaction(connection):
        connection.execute(
            "UPDATE sessions SET state = ?, last_activity = datetime('now') "
            "WHERE id = ? AND state = ?",
            (_STATE_ACTIVE, session_id, _STATE_LOCKED),
        )


def end_session(session_id: str, conn=None) -> None:
    """Logout / explicit invalidation."""
    connection = conn or get_connection()
    with transaction(connection):
        connection.execute(
            "UPDATE sessions SET state = ?, ended_at = datetime('now') "
            "WHERE id = ? AND state != ?",
            (_STATE_ENDED, session_id, _STATE_ENDED),
        )


def require_active(
    session_id: str,
    timeout_minutes: int = DEFAULT_INACTIVITY_TIMEOUT_MINUTES,
    conn=None,
) -> SessionInfo:
    """
    The enforcement call for any protected screen/operation. Raises
    ReauthenticationRequired if the session is locked, ended, or has
    timed out from inactivity (auto-expiring it as a side effect).
    Returns the SessionInfo only if the session is genuinely usable.
    """
    connection = conn or get_connection()
    expire_if_inactive(session_id, timeout_minutes, connection)
    session = get_session(session_id, connection)
    if not session.is_active:
        raise ReauthenticationRequired(
            f"Session is {session.state}; re-authentication required."
        )
    touch_session(session_id, connection)
    return session

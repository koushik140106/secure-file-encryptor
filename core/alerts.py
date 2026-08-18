"""
Security Alerts.

Generates severity-tagged alerts purely from real state: recent audit
events and current account/MFA/quarantine state. No alert here is
fabricated or scheduled/simulated -- every one traces back to an
actual row in the database at the time run_alerts() is called.
"""

from __future__ import annotations

from dataclasses import dataclass

from audit.logger import search_events
from audit.verifier import verify_audit_log
from database.db import get_connection

INFO = "INFO"
LOW = "LOW"
MEDIUM = "MEDIUM"
HIGH = "HIGH"
CRITICAL = "CRITICAL"

REPEATED_FAILURE_THRESHOLD = 3


@dataclass
class SecurityAlert:
    severity: str
    title: str
    detail: str


def _count_recent(username, event_type, limit=50, conn=None):
    events = search_events(username=username, event_type=event_type, limit=limit, conn=conn)
    return len(events)


def run_alerts(username: str, conn=None) -> list[SecurityAlert]:
    connection = conn or get_connection()
    alerts: list[SecurityAlert] = []

    # --- MFA disabled ---
    row = connection.execute(
        "SELECT mfa_enabled FROM users WHERE username = ?", (username,)
    ).fetchone()
    if row is not None and not row["mfa_enabled"]:
        alerts.append(
            SecurityAlert(
                MEDIUM, "MFA disabled",
                "Multi-factor authentication is not enabled for this account."
            )
        )

    # --- Repeated recent failed logins ---
    failure_count = _count_recent(username, "LOGIN_FAILURE", limit=20, conn=connection)
    if failure_count >= REPEATED_FAILURE_THRESHOLD:
        alerts.append(
            SecurityAlert(
                HIGH, "Multiple failed login attempts",
                f"{failure_count} recent LOGIN_FAILURE event(s) recorded for this account."
            )
        )

    # --- Account lockout ---
    lock_count = _count_recent(username, "ACCOUNT_LOCKED", limit=5, conn=connection)
    if lock_count > 0:
        alerts.append(
            SecurityAlert(
                HIGH, "Account was locked",
                f"{lock_count} ACCOUNT_LOCKED event(s) recorded for this account recently."
            )
        )

    # --- Integrity failures ---
    integrity_failures = _count_recent(username, "INTEGRITY_FAILURE", limit=10, conn=connection)
    if integrity_failures > 0:
        alerts.append(
            SecurityAlert(
                HIGH, "File integrity failure detected",
                f"{integrity_failures} INTEGRITY_FAILURE event(s) recorded."
            )
        )

    # --- Unresolved high-risk quarantine items ---
    row = connection.execute(
        "SELECT COUNT(*) AS c FROM quarantine_items "
        "WHERE username = ? AND state = 'quarantined' AND risk_level IN ('HIGH', 'CRITICAL')",
        (username,),
    ).fetchone()
    if row["c"] > 0:
        alerts.append(
            SecurityAlert(
                HIGH, "High-risk file(s) in quarantine",
                f"{row['c']} unresolved HIGH/CRITICAL risk file(s) in quarantine."
            )
        )

    # --- Audit chain integrity (system-wide, not per-user) ---
    chain = verify_audit_log(connection)
    if not chain.verified:
        alerts.append(
            SecurityAlert(
                CRITICAL, "Audit chain integrity failure",
                chain.reason or "The audit hash chain failed verification."
            )
        )

    return alerts

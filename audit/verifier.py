"""
Verification for the tamper-evident audit hash chain.

See audit/logger.py's module docstring for the exact threat model this
does and does not cover.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from audit.logger import GENESIS_HASH, _compute_hash
from database.db import get_connection


@dataclass
class VerificationResult:
    verified: bool
    total_events: int
    first_broken_event_id: int | None = None
    reason: str = ""

    @property
    def status_label(self) -> str:
        return "VERIFIED" if self.verified else "AUDIT INTEGRITY FAILURE"


def verify_audit_log(conn=None) -> VerificationResult:
    """
    Walk the entire audit_events table in order and recompute each
    event's hash from its own fields and the previous event's hash.
    Returns VERIFIED only if every event's stored hash matches what
    that recomputation produces AND every event's prev_hash matches the
    prior event's actual event_hash.
    """
    connection = conn or get_connection()
    rows = connection.execute(
        "SELECT * FROM audit_events ORDER BY id ASC"
    ).fetchall()

    expected_prev = GENESIS_HASH
    for row in rows:
        if row["prev_hash"] != expected_prev:
            return VerificationResult(
                verified=False,
                total_events=len(rows),
                first_broken_event_id=row["id"],
                reason=(
                    f"Event {row['id']} references a previous hash that does not "
                    "match the actual prior event -- an event may have been "
                    "inserted, deleted, or reordered."
                ),
            )

        recomputed = _compute_hash(
            row["timestamp"],
            row["event_type"],
            row["username"],
            row["result"],
            row["object_id"],
            row["metadata"],
            row["prev_hash"],
        )
        if recomputed != row["event_hash"]:
            return VerificationResult(
                verified=False,
                total_events=len(rows),
                first_broken_event_id=row["id"],
                reason=f"Event {row['id']} has been modified: its stored hash no longer matches its content.",
            )

        expected_prev = row["event_hash"]

    return VerificationResult(verified=True, total_events=len(rows))

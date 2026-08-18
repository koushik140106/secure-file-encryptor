"""
Structured, tamper-evident audit logging.

Each event's hash is computed over its own fields plus the previous
event's hash, forming a hash chain: modifying, deleting, or reordering
any historical event changes the hash a later event was chained against,
so verify_audit_log() detects the break.

Threat model / limitations (state honestly, do not oversell):
  - This is TAMPER-EVIDENT, not tamper-proof. Anyone with write access
    to the SQLite database file can, in principle, rewrite the entire
    chain from a tampered point forward and it would once again verify
    internally -- the chain only proves internal consistency, not that
    the log wasn's rewritten wholesale by someone with full DB access.
  - It does not defend against an attacker who can also modify this
    application's code (e.g. to skip verification, or to recompute a
    fraudulent chain).
  - It has no external anchor (e.g. no append-only remote log, no
    digital signature from a separate key) in this version -- a
    genuinely tamper-proof design would need one.
  - What it DOES catch: accidental or casual modification/deletion of
    individual historical rows without also regenerating every
    subsequent hash correctly, which is the overwhelmingly common way
    logs actually get quietly altered.

Never log: passwords, OTP values, encryption keys, decrypted file
contents. Callers pass a `metadata` dict for safe, non-sensitive
context only (e.g. a filename, a risk level, a byte count).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Optional

from database.db import get_connection, transaction

GENESIS_HASH = "0" * 64


@dataclass
class AuditEvent:
    id: int
    timestamp: str
    event_type: str
    username: Optional[str]
    result: str
    object_id: Optional[str]
    metadata: dict
    prev_hash: str
    event_hash: str


def _compute_hash(
    timestamp: str,
    event_type: str,
    username: Optional[str],
    result: str,
    object_id: Optional[str],
    metadata_json: str,
    prev_hash: str,
) -> str:
    payload = "|".join(
        [
            timestamp,
            event_type,
            username or "",
            result,
            object_id or "",
            metadata_json,
            prev_hash,
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _get_last_hash(conn) -> str:
    row = conn.execute(
        "SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1"
    ).fetchone()
    return row["event_hash"] if row else GENESIS_HASH


def log_event(
    event_type: str,
    username: Optional[str] = None,
    result: str = "info",
    object_id: Optional[str] = None,
    metadata: Optional[dict] = None,
    conn=None,
) -> AuditEvent:
    """
    Append a new audit event, chained onto the previous event's hash.
    `metadata` must contain only safe, non-sensitive fields -- never a
    password, OTP, encryption key, or decrypted content.
    """
    connection = conn or get_connection()
    metadata = metadata or {}
    metadata_json = json.dumps(metadata, sort_keys=True)

    with transaction(connection):
        # Re-fetch the last hash inside the transaction so concurrent
        # writers can't both chain onto the same prev_hash.
        prev_hash = _get_last_hash(connection)
        cursor = connection.execute(
            "INSERT INTO audit_events "
            "(timestamp, event_type, username, result, object_id, metadata, prev_hash, event_hash) "
            "VALUES (datetime('now'), ?, ?, ?, ?, ?, ?, ?)",
            (event_type, username, result, object_id, metadata_json, prev_hash, "PENDING"),
        )
        event_id = cursor.lastrowid

        row = connection.execute(
            "SELECT timestamp FROM audit_events WHERE id = ?", (event_id,)
        ).fetchone()
        event_hash = _compute_hash(
            row["timestamp"], event_type, username, result, object_id, metadata_json, prev_hash
        )
        connection.execute(
            "UPDATE audit_events SET event_hash = ? WHERE id = ?", (event_hash, event_id)
        )

    return get_event(event_id, connection)


def get_event(event_id: int, conn=None) -> AuditEvent:
    connection = conn or get_connection()
    row = connection.execute(
        "SELECT * FROM audit_events WHERE id = ?", (event_id,)
    ).fetchone()
    return AuditEvent(
        id=row["id"],
        timestamp=row["timestamp"],
        event_type=row["event_type"],
        username=row["username"],
        result=row["result"],
        object_id=row["object_id"],
        metadata=json.loads(row["metadata"]),
        prev_hash=row["prev_hash"],
        event_hash=row["event_hash"],
    )


def list_events(username: Optional[str] = None, limit: int = 200, conn=None) -> list[AuditEvent]:
    connection = conn or get_connection()
    if username:
        rows = connection.execute(
            "SELECT * FROM audit_events WHERE username = ? ORDER BY id DESC LIMIT ?",
            (username, limit),
        ).fetchall()
    else:
        rows = connection.execute(
            "SELECT * FROM audit_events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [
        AuditEvent(
            id=r["id"],
            timestamp=r["timestamp"],
            event_type=r["event_type"],
            username=r["username"],
            result=r["result"],
            object_id=r["object_id"],
            metadata=json.loads(r["metadata"]),
            prev_hash=r["prev_hash"],
            event_hash=r["event_hash"],
        )
        for r in rows
    ]


def search_events(
    username: Optional[str] = None,
    event_type: Optional[str] = None,
    result: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    limit: int = 500,
    conn=None,
) -> list[AuditEvent]:
    """
    Filtered activity search backing the Activity Center. All filters
    are optional and combine with AND. Dates are "YYYY-MM-DD" strings
    (inclusive), compared against the stored UTC timestamp.
    """
    connection = conn or get_connection()
    clauses = []
    params: list = []

    if username:
        clauses.append("username = ?")
        params.append(username)
    if event_type:
        clauses.append("event_type = ?")
        params.append(event_type)
    if result:
        clauses.append("result = ?")
        params.append(result)
    if start_date:
        clauses.append("timestamp >= ?")
        params.append(f"{start_date} 00:00:00")
    if end_date:
        clauses.append("timestamp <= ?")
        params.append(f"{end_date} 23:59:59")

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    rows = connection.execute(
        f"SELECT * FROM audit_events {where} ORDER BY id DESC LIMIT ?",
        (*params, limit),
    ).fetchall()

    return [
        AuditEvent(
            id=r["id"],
            timestamp=r["timestamp"],
            event_type=r["event_type"],
            username=r["username"],
            result=r["result"],
            object_id=r["object_id"],
            metadata=json.loads(r["metadata"]),
            prev_hash=r["prev_hash"],
            event_hash=r["event_hash"],
        )
        for r in rows
    ]

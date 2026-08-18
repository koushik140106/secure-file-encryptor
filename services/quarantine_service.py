"""
Quarantine service.

Suspicious files are moved into SecureVault/quarantine/ under a
randomly generated ID (not their original name, so a quarantined
`invoice.pdf.exe` can't be double-clicked by muscle memory from a file
browser), with metadata recorded in SQLite. Every operation is audited.

Prevention of accidental execution here is a practical, not absolute,
measure: renaming + relocating the file removes it from its original,
expected location and its familiar name. This does not prevent a user
who deliberately renames the file back and runs it -- documented
honestly rather than oversold.
"""

from __future__ import annotations

import json
import os
import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path

from audit import events as audit_events
from audit.logger import log_event
from database.db import get_connection, transaction

DEFAULT_QUARANTINE_DIR = Path(__file__).resolve().parent.parent / "quarantine"


class QuarantineError(Exception):
    pass


@dataclass
class QuarantineItem:
    quarantine_id: str
    username: str | None
    original_filename: str
    original_path: str | None
    quarantined_path: str
    sha256: str
    risk_level: str
    reasons: list[str]
    state: str
    created_at: str
    resolved_at: str | None


def _row_to_item(row) -> QuarantineItem:
    return QuarantineItem(
        quarantine_id=row["quarantine_id"],
        username=row["username"],
        original_filename=row["original_filename"],
        original_path=row["original_path"],
        quarantined_path=row["quarantined_path"],
        sha256=row["sha256"],
        risk_level=row["risk_level"],
        reasons=json.loads(row["reasons"]),
        state=row["state"],
        created_at=row["created_at"],
        resolved_at=row["resolved_at"],
    )


def quarantine_file(
    source_path: str,
    sha256: str,
    risk_level: str,
    reasons: list[str],
    username: str | None = None,
    quarantine_dir: Path = DEFAULT_QUARANTINE_DIR,
    conn=None,
) -> QuarantineItem:
    """
    Move the file at source_path into the quarantine directory under a
    generated ID, and record its metadata. Raises QuarantineError if
    source_path doesn't exist.
    """
    connection = conn or get_connection()

    if not os.path.exists(source_path):
        raise QuarantineError(f"File not found: {source_path}")

    quarantine_dir.mkdir(parents=True, exist_ok=True)
    quarantine_id = str(uuid.uuid4())
    quarantined_path = str(quarantine_dir / quarantine_id)

    shutil.move(source_path, quarantined_path)

    with transaction(connection):
        connection.execute(
            """
            INSERT INTO quarantine_items
                (quarantine_id, username, original_filename, original_path,
                 quarantined_path, sha256, risk_level, reasons, state, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'quarantined', datetime('now'))
            """,
            (
                quarantine_id,
                username,
                os.path.basename(source_path),
                source_path,
                quarantined_path,
                sha256,
                risk_level,
                json.dumps(reasons),
            ),
        )

    log_event(
        audit_events.FILE_QUARANTINED,
        username=username,
        result="info",
        object_id=quarantine_id,
        metadata={"original_filename": os.path.basename(source_path), "risk_level": risk_level},
    )

    return get_item(quarantine_id, connection)


def get_item(quarantine_id: str, conn=None) -> QuarantineItem:
    connection = conn or get_connection()
    row = connection.execute(
        "SELECT * FROM quarantine_items WHERE quarantine_id = ?", (quarantine_id,)
    ).fetchone()
    if row is None:
        raise QuarantineError(f"No such quarantine item: {quarantine_id}")
    return _row_to_item(row)


def list_items(state: str | None = None, conn=None) -> list[QuarantineItem]:
    connection = conn or get_connection()
    if state:
        rows = connection.execute(
            "SELECT * FROM quarantine_items WHERE state = ? ORDER BY created_at DESC", (state,)
        ).fetchall()
    else:
        rows = connection.execute(
            "SELECT * FROM quarantine_items ORDER BY created_at DESC"
        ).fetchall()
    return [_row_to_item(r) for r in rows]


def restore_item(quarantine_id: str, destination_path: str, username: str | None = None, conn=None) -> None:
    connection = conn or get_connection()
    item = get_item(quarantine_id, connection)
    if item.state != "quarantined":
        raise QuarantineError(f"Item is not quarantined (state={item.state}); cannot restore.")

    shutil.move(item.quarantined_path, destination_path)

    with transaction(connection):
        connection.execute(
            "UPDATE quarantine_items SET state = 'restored', resolved_at = datetime('now') "
            "WHERE quarantine_id = ?",
            (quarantine_id,),
        )

    log_event(
        audit_events.FILE_RESTORED,
        username=username,
        result="info",
        object_id=quarantine_id,
        metadata={"destination": os.path.basename(destination_path)},
    )


def delete_item(quarantine_id: str, username: str | None = None, conn=None) -> None:
    """Permanently delete a quarantined file. Irreversible; caller should confirm with the user first."""
    connection = conn or get_connection()
    item = get_item(quarantine_id, connection)
    if item.state != "quarantined":
        raise QuarantineError(f"Item is not quarantined (state={item.state}); cannot delete.")

    if os.path.exists(item.quarantined_path):
        os.remove(item.quarantined_path)

    with transaction(connection):
        connection.execute(
            "UPDATE quarantine_items SET state = 'deleted', resolved_at = datetime('now') "
            "WHERE quarantine_id = ?",
            (quarantine_id,),
        )

    log_event(
        "FILE_DELETED",
        username=username,
        result="info",
        object_id=quarantine_id,
        metadata={"original_filename": item.original_filename},
    )

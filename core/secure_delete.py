"""
Local secure-delete workflow.

HONEST LIMITATION (state this to users, don't bury it):
Overwriting a file's bytes before removing it does NOT guarantee the
data is unrecoverable on:
  - SSDs (wear-leveling means the physical cells holding the old data
    are often not the ones overwritten)
  - Copy-on-write filesystems (Btrfs, ZFS, APFS with snapshots) --
    the old blocks may still exist elsewhere
  - Backups, snapshots, or cloud-synced copies of the file, which this
    tool has no visibility into or control over
  - Journaling filesystems, where metadata/data journals can retain
    copies

What this DOES provide: on a traditional filesystem on a spinning
disk (or similar non-wear-leveled, non-CoW storage), overwriting file
contents before unlinking makes casual recovery via standard
undelete/recovery tools significantly harder than a plain delete,
which leaves the original bytes on disk untouched until overwritten by
something else at the OS's convenience.
"""

from __future__ import annotations

import os
import secrets

from audit import events as audit_events
from audit.logger import log_event

LIMITATIONS_NOTICE = (
    "Secure delete overwrites the file's contents before removing it. "
    "This does not guarantee destruction on SSDs, copy-on-write filesystems, "
    "cloud-synced storage, snapshots, or backups -- those may retain a copy "
    "outside this application's control."
)


class SecureDeleteError(Exception):
    pass


def secure_delete(path: str, passes: int = 1, username: str | None = None) -> None:
    """
    Overwrite the file's contents with cryptographically random bytes
    (once by default; more passes add cost with no proven benefit on
    modern storage, so the default is intentionally low) and remove it.

    Raises SecureDeleteError for a missing file or on permission
    failure, rather than silently doing nothing.
    """
    if not os.path.exists(path):
        log_event(
            audit_events.SECURE_DELETE,
            username=username,
            result="failure",
            object_id=os.path.basename(path),
            metadata={"reason": "file_not_found"},
        )
        raise SecureDeleteError(f"File not found: {path}")

    try:
        size = os.path.getsize(path)
        with open(path, "r+b") as f:
            for _ in range(max(1, passes)):
                f.seek(0)
                f.write(secrets.token_bytes(size))
                f.flush()
                os.fsync(f.fileno())
        os.remove(path)
    except OSError as exc:
        log_event(
            audit_events.SECURE_DELETE,
            username=username,
            result="failure",
            object_id=os.path.basename(path),
            metadata={"reason": "os_error"},
        )
        raise SecureDeleteError(f"Unable to securely delete file: {exc}") from exc

    log_event(
        audit_events.SECURE_DELETE,
        username=username,
        result="success",
        object_id=os.path.basename(path),
        metadata={"size_bytes": size, "passes": passes},
    )

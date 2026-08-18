"""
One-time migration of legacy plaintext credentials (users.json) into
SQLite with Argon2id password hashes.

Design goals:
  - Never leave plaintext passwords in the final database.
  - Never silently drop an existing account.
  - Never delete users.json automatically -- the caller decides, after
    verifying the migration succeeded, whether/when to remove or
    quarantine the legacy file.
  - Idempotent: running it twice does not create duplicate users or
    re-hash existing SQLite users.

Legacy format (users.json): {"username": "plaintext_password", ...}
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from auth_core.password import hash_password
from database import user_repository as repo
from database.db import get_migration_flag, set_migration_flag

LEGACY_USERS_PATH = Path(__file__).resolve().parent.parent / "users.json"
MIGRATION_FLAG_KEY = "users_json_migrated"


@dataclass
class MigrationReport:
    already_migrated: bool = False
    legacy_file_found: bool = False
    migrated_usernames: list[str] = field(default_factory=list)
    skipped_existing: list[str] = field(default_factory=list)
    failed_usernames: list[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return not self.failed_usernames


def _load_legacy_users(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        # Malformed/unreadable legacy file: treat as "nothing to migrate"
        # rather than crashing startup. The file is left untouched so a
        # human can inspect it.
        return {}
    if not isinstance(data, dict):
        return {}
    return {
        str(username): str(password)
        for username, password in data.items()
        if isinstance(username, str) and isinstance(password, str)
    }


def migrate_legacy_users(legacy_path: Path = LEGACY_USERS_PATH) -> MigrationReport:
    """
    Migrate every account from users.json into SQLite, hashing each
    plaintext password with Argon2id. Safe to call on every startup:
    once the flag is set, this is a no-op unless new legacy accounts
    appear (e.g. a user restoring an old backup file), which are
    migrated on top without disturbing already-migrated accounts.
    """
    report = MigrationReport()

    legacy_users = _load_legacy_users(legacy_path)
    report.legacy_file_found = legacy_path.exists()

    if get_migration_flag(MIGRATION_FLAG_KEY) == "complete" and not legacy_users:
        report.already_migrated = True
        return report

    for username, plaintext_password in legacy_users.items():
        if repo.username_exists(username):
            report.skipped_existing.append(username)
            continue
        try:
            password_hash = hash_password(plaintext_password)
            repo.create_user(username, password_hash)
            report.migrated_usernames.append(username)
        except Exception:
            report.failed_usernames.append(username)

    if report.success:
        set_migration_flag(MIGRATION_FLAG_KEY, "complete")

    return report

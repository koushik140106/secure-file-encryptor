"""
Security Health Check.

Runs a fixed set of deterministic checks against the real application
state -- database connectivity, required schema, the quarantine
directory, and audit chain integrity. Every check returns PASS,
WARNING, or FAIL with a plain-English reason. No check here claims to
verify anything at the OS level (disk encryption, firewall state,
etc.) that this application cannot actually see.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from audit.verifier import verify_audit_log
from database.db import get_connection

PASS = "PASS"
WARNING = "WARNING"
FAIL = "FAIL"

REQUIRED_TABLES = {
    "users", "sessions", "mfa_devices", "recovery_codes",
    "quarantine_items", "audit_events", "migration_state",
}


@dataclass
class HealthCheckItem:
    name: str
    status: str
    detail: str


@dataclass
class HealthCheckReport:
    items: list = field(default_factory=list)

    @property
    def overall_status(self) -> str:
        statuses = {item.status for item in self.items}
        if FAIL in statuses:
            return FAIL
        if WARNING in statuses:
            return WARNING
        return PASS


def run_health_check(
    quarantine_dir: Path | None = None, conn=None
) -> HealthCheckReport:
    items = []

    # --- Database connectivity ---
    try:
        connection = conn or get_connection()
        connection.execute("SELECT 1").fetchone()
        items.append(HealthCheckItem("Database connectivity", PASS, "Database is reachable."))
    except Exception as exc:
        items.append(HealthCheckItem("Database connectivity", FAIL, f"Cannot reach database: {exc}"))
        # Nothing else below can be checked meaningfully without a connection.
        return HealthCheckReport(items=items)

    # --- Required schema ---
    try:
        rows = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        existing = {r["name"] for r in rows}
        missing = REQUIRED_TABLES - existing
        if missing:
            items.append(
                HealthCheckItem(
                    "Database schema", FAIL, f"Missing required tables: {', '.join(sorted(missing))}"
                )
            )
        else:
            items.append(HealthCheckItem("Database schema", PASS, "All required tables are present."))
    except Exception as exc:
        items.append(HealthCheckItem("Database schema", FAIL, f"Unable to inspect schema: {exc}"))

    # --- Audit chain integrity ---
    try:
        result = verify_audit_log(connection)
        if result.verified:
            items.append(
                HealthCheckItem(
                    "Audit chain integrity", PASS,
                    f"Verified across {result.total_events} event(s)."
                )
            )
        else:
            items.append(
                HealthCheckItem(
                    "Audit chain integrity", FAIL,
                    result.reason or "Audit chain verification failed."
                )
            )
    except Exception as exc:
        items.append(HealthCheckItem("Audit chain integrity", FAIL, f"Unable to verify audit chain: {exc}"))

    # --- Quarantine directory ---
    qdir = quarantine_dir
    if qdir is None:
        from services.quarantine_service import DEFAULT_QUARANTINE_DIR
        qdir = DEFAULT_QUARANTINE_DIR

    if qdir.exists():
        if qdir.is_dir():
            items.append(HealthCheckItem("Quarantine directory", PASS, f"{qdir} exists and is a directory."))
        else:
            items.append(HealthCheckItem("Quarantine directory", FAIL, f"{qdir} exists but is not a directory."))
    else:
        # Not yet created is a normal, healthy state (nothing has been
        # quarantined yet) -- it gets created on first use.
        items.append(
            HealthCheckItem(
                "Quarantine directory", WARNING,
                f"{qdir} does not exist yet (created automatically on first quarantine)."
            )
        )

    return HealthCheckReport(items=items)

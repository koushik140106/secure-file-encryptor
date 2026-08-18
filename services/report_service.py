"""
Security report generation. Every field comes from the database/audit
log -- never a placeholder or fabricated number. Reports never include
passwords, encryption keys, OTP values, MFA secrets, or decrypted file
contents; only event *metadata* that was itself already screened at
logging time (see audit/logger.py's docstring) is included.
"""

from __future__ import annotations

import csv
import io
import json
from dataclasses import asdict, dataclass

from audit.logger import search_events
from audit.verifier import verify_audit_log
from core.security_center import build_report as build_security_center_report
from database.db import get_connection


@dataclass
class ReportData:
    username: str | None
    start_date: str | None
    end_date: str | None
    security_score: int
    security_score_max: int
    recommendations: list[str]
    audit_chain_status: str
    login_success_count: int
    login_failure_count: int
    account_locked_count: int
    file_encrypted_count: int
    file_decrypted_count: int
    decryption_failed_count: int
    integrity_failure_count: int
    files_scanned_count: int
    files_quarantined_count: int
    files_restored_count: int


def _count(events, event_type: str) -> int:
    return sum(1 for e in events if e.event_type == event_type)


def build_report_data(
    username: str | None = None,
    start_date: str | None = None,
    end_date: str | None = None,
    conn=None,
) -> ReportData:
    connection = conn or get_connection()

    events = search_events(
        username=username, start_date=start_date, end_date=end_date, limit=100000, conn=connection
    )
    security = build_security_center_report(username, conn=connection)
    chain = verify_audit_log(connection)

    return ReportData(
        username=username,
        start_date=start_date,
        end_date=end_date,
        security_score=security.score,
        security_score_max=security.max_score,
        recommendations=security.recommendations,
        audit_chain_status=chain.status_label,
        login_success_count=_count(events, "LOGIN_SUCCESS"),
        login_failure_count=_count(events, "LOGIN_FAILURE"),
        account_locked_count=_count(events, "ACCOUNT_LOCKED"),
        file_encrypted_count=_count(events, "FILE_ENCRYPTED"),
        file_decrypted_count=_count(events, "FILE_DECRYPTED"),
        decryption_failed_count=_count(events, "DECRYPTION_FAILED"),
        integrity_failure_count=_count(events, "INTEGRITY_FAILURE"),
        files_scanned_count=_count(events, "FILE_SCANNED"),
        files_quarantined_count=_count(events, "FILE_QUARANTINED"),
        files_restored_count=_count(events, "FILE_RESTORED"),
    )


def export_json(report: ReportData) -> str:
    return json.dumps(asdict(report), indent=2)


def export_csv(report: ReportData) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["field", "value"])
    for key, value in asdict(report).items():
        if isinstance(value, list):
            value = "; ".join(value)
        writer.writerow([key, value])
    return buf.getvalue()


def export_pdf(report: ReportData, output_path: str) -> str:
    """
    Render the report as a PDF using reportlab. Returns output_path.
    """
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.units import inch
    from reportlab.pdfgen import canvas as pdf_canvas

    c = pdf_canvas.Canvas(output_path, pagesize=letter)
    width, height = letter
    y = height - inch

    def line(text, size=11, bold=False, gap=16):
        nonlocal y
        c.setFont("Helvetica-Bold" if bold else "Helvetica", size)
        c.drawString(inch, y, text)
        y -= gap

    line("SecureVault Security Report", size=18, bold=True, gap=28)
    line(f"User: {report.username or 'All users'}")
    period = f"{report.start_date or 'earliest'} to {report.end_date or 'latest'}"
    line(f"Report period: {period}")
    line(f"Security score: {report.security_score}/{report.security_score_max}")
    line(f"Audit chain status: {report.audit_chain_status}")
    y -= 10

    line("Authentication", size=13, bold=True, gap=18)
    line(f"  Successful logins: {report.login_success_count}")
    line(f"  Failed logins: {report.login_failure_count}")
    line(f"  Account lockouts: {report.account_locked_count}")
    y -= 10

    line("Encryption / Decryption", size=13, bold=True, gap=18)
    line(f"  Files encrypted: {report.file_encrypted_count}")
    line(f"  Files decrypted: {report.file_decrypted_count}")
    line(f"  Decryption failures: {report.decryption_failed_count}")
    line(f"  Integrity failures: {report.integrity_failure_count}")
    y -= 10

    line("File Security", size=13, bold=True, gap=18)
    line(f"  Files scanned: {report.files_scanned_count}")
    line(f"  Files quarantined: {report.files_quarantined_count}")
    line(f"  Files restored: {report.files_restored_count}")
    y -= 10

    line("Recommendations", size=13, bold=True, gap=18)
    for rec in report.recommendations:
        line(f"  - {rec}", size=10, gap=14)
        if y < inch:
            c.showPage()
            y = height - inch

    c.showPage()
    c.save()
    return output_path

"""
File Security Analyzer.

This is NOT antivirus software and makes no malware-detection claims.
It's a lightweight, defensive, deterministic heuristic analyzer: it
looks at a file's name, extension, size, and magic bytes (file
signature) and flags characteristics that are commonly associated with
disguised executables or mismatched content -- the same category of
checks a mail gateway or upload filter might apply before a real
antivirus engine even runs.

Every risk factor has an explicit, fixed point value and a
human-readable reason string. There is no randomness anywhere in this
module -- the same file always produces the same result.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

# Extensions commonly used to execute code directly.
EXECUTABLE_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".msi", ".vbs",
    ".vbe", ".js", ".jse", ".wsf", ".wsh", ".ps1", ".jar", ".app",
    ".dll", ".sh",
}

# Extensions that are common, "safe-looking" first extensions in a
# double-extension trick, e.g. invoice.pdf.exe
COMMON_DOCUMENT_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".jpg", ".jpeg", ".png", ".gif", ".txt", ".csv", ".zip",
}

# (signature bytes, offset, description, expected extensions)
_MAGIC_SIGNATURES = [
    (b"MZ", 0, "Windows/DOS executable (PE)", {".exe", ".dll", ".scr", ".com", ".msi"}),
    (b"%PDF", 0, "PDF document", {".pdf"}),
    (b"\x7fELF", 0, "Linux/Unix executable (ELF)", {".elf", ".so", ".bin"}),
    (b"PK\x03\x04", 0, "ZIP-based container (zip/docx/xlsx/pptx/jar)",
     {".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk"}),
    (b"\xff\xd8\xff", 0, "JPEG image", {".jpg", ".jpeg"}),
    (b"\x89PNG\r\n\x1a\n", 0, "PNG image", {".png"}),
    (b"GIF87a", 0, "GIF image", {".gif"}),
    (b"GIF89a", 0, "GIF image", {".gif"}),
    (b"\xd0\xcf\x11\xe0", 0, "Legacy Microsoft Office document (OLE2)", {".doc", ".xls", ".ppt"}),
]

RISK_LOW = "LOW"
RISK_MEDIUM = "MEDIUM"
RISK_HIGH = "HIGH"
RISK_CRITICAL = "CRITICAL"


@dataclass
class AnalysisResult:
    filename: str
    extensions: list[str]
    size_bytes: int
    sha256: str
    detected_format: str | None
    risk_level: str
    score: int
    reasons: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "filename": self.filename,
            "extensions": self.extensions,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "detected_format": self.detected_format,
            "risk_level": self.risk_level,
            "score": self.score,
            "reasons": self.reasons,
        }


def _split_extensions(filename: str) -> list[str]:
    """
    'invoice.pdf.exe' -> ['.pdf', '.exe']. Only the trailing dot-parts
    that look like plausible extensions (short, alphanumeric) are
    counted, so a filename with dots that aren't extensions doesn't
    produce a wall of false positives.
    """
    parts = filename.rsplit(".", filename.count("."))
    if "." not in filename:
        return []
    segments = filename.split(".")
    exts = []
    for seg in segments[1:]:
        if 1 <= len(seg) <= 5 and seg.isalnum():
            exts.append("." + seg.lower())
    return exts


def _detect_signature(data: bytes):
    for signature, offset, description, expected_exts in _MAGIC_SIGNATURES:
        if data[offset:offset + len(signature)] == signature:
            return description, expected_exts
    return None, None


def analyze_file(filename: str, data: bytes) -> AnalysisResult:
    """
    Analyze a file's name and content. Deterministic: the same
    (filename, data) always produces the same AnalysisResult.
    """
    reasons: list[str] = []
    score = 0

    extensions = _split_extensions(filename)
    final_ext = extensions[-1] if extensions else ""

    sha256 = hashlib.sha256(data).hexdigest()
    detected_format, expected_exts = _detect_signature(data)

    # --- Executable extension ---
    if final_ext in EXECUTABLE_EXTENSIONS:
        score += 40
        reasons.append(f"File has an executable extension ({final_ext}).")

    # --- Double extension: a document-looking extension immediately
    # followed by an executable one, e.g. invoice.pdf.exe ---
    if len(extensions) >= 2:
        second_to_last = extensions[-2]
        if second_to_last in COMMON_DOCUMENT_EXTENSIONS and final_ext in EXECUTABLE_EXTENSIONS:
            score += 35
            reasons.append(
                f"Suspicious double extension: appears as a {second_to_last} file "
                f"but actually ends in {final_ext}."
            )

    # --- Magic bytes vs. extension mismatch ---
    if detected_format and expected_exts and final_ext:
        if final_ext not in expected_exts:
            score += 25
            reasons.append(
                f"File content matches '{detected_format}' but the extension is "
                f"'{final_ext}', which doesn't match."
            )
            if final_ext in COMMON_DOCUMENT_EXTENSIONS and "executable" in detected_format.lower():
                score += 15
                reasons.append(
                    "File is named like a document but its content signature is an executable."
                )

    # --- Executable signature regardless of extension ---
    if detected_format in ("Windows/DOS executable (PE)", "Linux/Unix executable (ELF)"):
        if final_ext not in EXECUTABLE_EXTENSIONS:
            score += 20
            reasons.append(f"File content is an executable ({detected_format}) despite its extension.")

    # --- Empty or very small files with an executable extension ---
    if final_ext in EXECUTABLE_EXTENSIONS and len(data) == 0:
        score += 5
        reasons.append("File is empty, which is unusual for a real executable.")

    score = min(score, 100)

    if score >= 70:
        risk_level = RISK_CRITICAL
    elif score >= 45:
        risk_level = RISK_HIGH
    elif score >= 20:
        risk_level = RISK_MEDIUM
    else:
        risk_level = RISK_LOW

    if not reasons:
        reasons.append("No suspicious characteristics detected.")

    return AnalysisResult(
        filename=filename,
        extensions=extensions,
        size_bytes=len(data),
        sha256=sha256,
        detected_format=detected_format,
        risk_level=risk_level,
        score=score,
        reasons=reasons,
    )

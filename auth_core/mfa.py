"""
TOTP (RFC 6238) / HOTP (RFC 4226) implementation for MFA.

IMPORTANT NOTE ON "use a maintained library": this environment has no
network access, so a third-party library like `pyotp` cannot be
installed. Rather than skip MFA or fake it, this module implements the
standard algorithm directly against RFC 4226 (HOTP) and RFC 6238 (TOTP)
using only Python's stdlib `hmac`/`hashlib` -- the same primitives any
TOTP library uses internally. This is composing a published, widely
audited standard from vetted primitives, not inventing cryptography.
Correctness is verified in tests/test_phase6_mfa.py against the
official RFC 4226 Appendix D test vectors, not just self-consistency.
If network access is available later, swapping this module's internals
for `pyotp` is a drop-in replacement -- callers only depend on the
functions below, not on how they're implemented.

Secrets and OTP codes are never logged. Callers must not log them either.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
import time

DIGITS = 6
PERIOD_SECONDS = 30
SECRET_BYTES = 20  # 160-bit secret, matches RFC 4226's recommended length
# Number of adjacent time steps to accept, each direction, to tolerate
# clock drift between the server and the user's authenticator app.
CLOCK_DRIFT_WINDOW = 1


def generate_secret() -> str:
    """A fresh random base32-encoded TOTP secret."""
    raw = os.urandom(SECRET_BYTES)
    return base64.b32encode(raw).decode("ascii")


def _hotp(secret_b32: str, counter: int, digits: int = DIGITS) -> str:
    padding = "=" * (-len(secret_b32) % 8)
    key = base64.b32decode(secret_b32.upper() + padding)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code_int).zfill(digits)


def generate_totp(secret_b32: str, for_time: float | None = None) -> str:
    t = for_time if for_time is not None else time.time()
    counter = int(t // PERIOD_SECONDS)
    return _hotp(secret_b32, counter)


def verify_totp(secret_b32: str, code: str, for_time: float | None = None) -> bool:
    """
    Verify a submitted code, tolerating +/- CLOCK_DRIFT_WINDOW time steps
    of clock skew. Uses constant-time comparison to avoid a timing
    side-channel on the code itself.
    """
    if not code or not code.isdigit() or len(code) != DIGITS:
        return False

    t = for_time if for_time is not None else time.time()
    counter = int(t // PERIOD_SECONDS)

    for offset in range(-CLOCK_DRIFT_WINDOW, CLOCK_DRIFT_WINDOW + 1):
        candidate = _hotp(secret_b32, counter + offset)
        if hmac.compare_digest(candidate, code):
            return True
    return False


def provisioning_uri(secret_b32: str, username: str, issuer: str = "SecureVault") -> str:
    """
    Standard otpauth:// URI, the input any TOTP authenticator app (or a
    QR code generator) expects. QR image rendering itself is not
    implemented in this environment (the `qrcode` package isn't
    installable without network access) -- this URI is what a QR
    generator would encode, and can be displayed as text or a copyable
    link as a fallback in the UI.
    """
    from urllib.parse import quote

    label = quote(f"{issuer}:{username}")
    params = f"secret={secret_b32}&issuer={quote(issuer)}&algorithm=SHA1&digits={DIGITS}&period={PERIOD_SECONDS}"
    return f"otpauth://totp/{label}?{params}"

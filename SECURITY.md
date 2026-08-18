# SecureVault — Security Design

This document describes what is actually implemented. No claim here should be
taken as marketing language — "AES-256-GCM" means the standard `cryptography`
library's `AESGCM` primitive is used exactly as documented, not a custom
implementation.

## Password Storage

Passwords are hashed with **Argon2id** (`cryptography.hazmat.primitives.kdf.argon2.Argon2id`),
parameters: 64 MiB memory, 3 iterations, 4 lanes, 256-bit output, a fresh random
16-byte salt per password. The stored record is a self-describing string
(`argon2id$1$m=...,t=...,p=...$salt$hash`) so parameters can be strengthened in
the future without breaking existing hashes. Plaintext passwords are never
stored, logged, or compared directly — `hmac`-safe verification is used via the
KDF's own `verify()`.

## Legacy Migration

The original app stored `username -> plaintext password` in `users.json`. On
first startup, every account in that file is read once, hashed with Argon2id,
and inserted into SQLite. **The original `users.json` file is never deleted or
modified by this process** — it's left on disk as a backup, and no longer
consulted for authentication once migration completes (idempotency is tracked
in a `migration_state` table, so re-running startup doesn't re-hash or
duplicate accounts).

## Brute-Force Protection

5 consecutive failed login attempts for an account lock it for 15 minutes
(`auth_core/user_service.py`). A successful login resets the counter. Locked
accounts reject even a correct password until the lock expires. This is a
usability-preserving default, not a permanent lockout mechanism.

## Sessions

Session state (`auth_core/session.py`) lives in SQLite, not just in Tkinter
widget state: `active` / `locked` / `ended`. `require_active()` is the single
enforcement point — it auto-expires sessions idle past the timeout (default 15
minutes) and raises `ReauthenticationRequired` for locked/ended/expired
sessions, rather than letting a UI bug silently grant access.

## MFA

TOTP per **RFC 6238**, built on HOTP per **RFC 4226**. Because this environment
has no network access to install a third-party library like `pyotp`, the
algorithm is implemented directly against the published standard using only
Python's stdlib `hmac`/`hashlib` — verified correct against the official RFC
4226 Appendix D test vectors (not just internal self-consistency). Secrets are
generated with `os.urandom` (160-bit). Enrollment is two-step (generate →
confirm with a live code) so a mistyped/unscanned secret can't lock a user out.
8 single-use recovery codes are issued on confirmation, each stored as an
Argon2id hash (never plaintext). Disabling MFA re-verifies the current
password. **Never logged**: TOTP secrets, generated codes, or recovery codes.

## File Encryption

- **Algorithm**: AES-256-GCM (`cryptography.hazmat.primitives.ciphers.aead.AESGCM`),
  providing confidentiality, integrity, and authentication in one primitive.
- **Key derivation**: Argon2id, same algorithm as password hashing but a
  **deliberately separate derivation context** — a fresh random salt per file,
  and the derived key is never the same value as (or derivable from) the login
  password's stored hash. Reusing one hash for both authentication and
  encryption is a well-known anti-pattern this design avoids.
- **Nonce**: fresh 96-bit random nonce per encryption via `os.urandom`, never
  reused with the same key.
- **Container format (`SVLT`, version 1)**: magic + version + KDF id/params +
  salt + nonce, all passed to AES-GCM as **associated data (AAD)** so the
  header itself is authenticated — modifying salt, nonce, or KDF parameters
  breaks decryption exactly like modifying the ciphertext does. The encrypted
  payload includes the original filename, size, and a SHA-256 of the plaintext
  for a second, application-level integrity check on top of (not instead of)
  GCM's own authentication tag.
- **Wrong password / tampering**: both raise `DecryptionError` with the same
  message — the implementation deliberately does not distinguish "wrong
  password" from "tampered file" in what it tells the user, since that
  distinction would give an attacker a tampering oracle. Verified in tests:
  wrong password, tampered ciphertext, and tampered header/AAD all fail safely
  (never return corrupted plaintext).
- **Legacy compatibility**: files from the original Fernet-based scheme
  (`SHA-256(password)` used directly as the Fernet key — no salt, no KDF work
  factor) are still auto-detected and decrypted. This old scheme is used
  **only** for decrypting pre-existing files, never for new encryption.
  `reencrypt_legacy_to_svlt()` provides an explicit, user-initiated upgrade
  path; it is never run automatically/silently.

## Audit Logging & Tamper Evidence

Every security-relevant action logs a structured event (timestamp, type,
username, result, object id, safe metadata) to the `audit_events` table.
**Never logged**: passwords, OTP/recovery codes, encryption keys, decrypted
file contents.

Each event's stored hash covers its own fields **and** the previous event's
hash — a SHA-256 hash chain. `verify_audit_log()` walks the entire table and
recomputes every hash; a mismatch anywhere (a modified field, a deleted event
breaking the chain, or two events silently swapped) causes verification to
fail at the first broken link.

**Honest limitation — this is tamper-*evident*, not tamper-proof.** It proves
internal consistency: if a historical event was changed without also
recomputing every hash after it, verification fails. It does **not** defend
against an attacker with full write access to the SQLite database file who
regenerates the entire chain from a tampering point forward — that attacker
could produce a chain that verifies again. There is no external anchor
(remote append-only log, separate signing key) in this version. Anyone
presenting this project should describe the audit log exactly this way.

## File Security Analyzer

A deterministic, explainable heuristic scanner (`core/scanner.py`) — **not
antivirus, and it makes no malware-detection claim anywhere in the code or
UI**. It checks: executable extensions, double extensions (e.g.
`invoice.pdf.exe`), magic-byte/extension mismatches, and executable content
signatures regardless of extension. Every point in the risk score has a fixed
weight and a stated, human-readable reason — there is no randomness and no
machine-learning component.

## Quarantine

Quarantined files are moved (not copied) into `quarantine/` under a randomly
generated ID, not their original filename — this prevents *accidental*
execution via a familiar name/location in a file browser. It does **not**
prevent deliberate execution by a user who manually renames the file back;
that limitation is inherent to any local, non-privileged quarantine mechanism
and is stated plainly rather than oversold.

## Secure Delete

Overwrites file contents with cryptographically random bytes (`secrets.token_bytes`),
`fsync`s, then unlinks. **This does not guarantee destruction** on SSDs (wear
leveling), copy-on-write filesystems (Btrfs/ZFS/APFS snapshots), or any
backup/cloud-sync copy outside this application's control — see
`core/secure_delete.py`'s `LIMITATIONS_NOTICE`, which the UI should display
verbatim rather than paraphrase into a stronger claim.

## Database

SQLite via `database/db.py`. **All queries are parameterized (`?` placeholders)
— none are built via string concatenation or f-string interpolation of
user-supplied values.** Tables: `users`, `sessions`, `mfa_devices`,
`recovery_codes`, `quarantine_items`, `audit_events`, `migration_state`.

## What This Project Does Not Claim

- Not "unhackable," "100% secure," or "military-grade" anywhere.
- Not antivirus or malware detection.
- Not guaranteed secure deletion on modern storage.
- Not a tamper-*proof* audit log — tamper-*evident*, with a stated threat model.
